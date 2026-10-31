import json
import os
import pty
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from hil import wire
from hil.daemon import serve
from hil.policy import Policy, Violation
from hil.relay import Relay, open_raw
from hil.service import Config, HilError, Service
from stub_device import StubDevice

DTB = ROOT / "tests" / "fixtures" / "t8112-j473.dtb"
STUB_LINUX = ROOT / "tests" / "stub_linux.py"

# Blocks the deny-list must cover, as (reg base, size) in arch/arm64/boot/dts/apple/t8112.dtsi.
DTS_DENIED = {
    "pmgr": (0x23B700000, 0x14000),
    "pmgr_mini": (0x23D280000, 0x4000),
    "pmgr_dcp": (0x23B3D0000, 0x4000),
    "cpufreq_e": (0x210E20000, 0x1000),
    "cpufreq_p": (0x211E20000, 0x1000),
    "nub_spmi": (0x23D714000, 0x100),
    "smc": (0x23E400000, 0x4000),
    "smc_sram": (0x23FE00000, 0x100000),
    "smc_mbox": (0x23E408000, 0x4000),
    "spi1_nvram": (0x235104000, 0x4000),
    "sep": (0x25E400000, 0x6C000),
    "sep_mbox": (0x25E408000, 0x4000),
    "ans_mbox": (0x277408000, 0x4000),
    "sart": (0x27BC50000, 0x10000),
    "nvme": (0x27BCC0000, 0x40000),
}
DRAM = 0x10000000000
PINCTRL_AP = 0x23C100000


def policy():
    return Policy.from_dtb(DTB.read_bytes())


class DenyList(unittest.TestCase):
    def test_covers_power_pmu_smc_nvram_and_boot_policy_blocks(self):
        """Safety: every power, PMU, SMC, NVRAM and boot-policy block of the J473 DT is denied."""
        p = policy()
        for name, (addr, size) in DTS_DENIED.items():
            with self.subTest(name):
                with self.assertRaises(Violation):
                    p.check_range(addr, 4, "write")
                with self.assertRaises(Violation):
                    p.check_range(addr + size - 4, 4, "write")
        p.check_range(DRAM, 0x1000000, "write")
        p.check_range(PINCTRL_AP, 4, "write")


class GuardStream(unittest.TestCase):
    def test_denied_requests_are_never_forwarded(self):
        """Safety: a denied write raises before any of its bytes are returned for forwarding."""
        g = wire.Guard(policy())
        allowed = wire.proxy_frame(0x101, PINCTRL_AP, 1)
        self.assertEqual(g.feed(allowed[:10]), b"")
        self.assertEqual(g.feed(allowed[10:]), allowed)
        cases = {
            "write32 pmgr": wire.proxy_frame(0x101, 0x23B700010, 0),
            "set32 spmi": wire.proxy_frame(0x109, 0x23D714004, 1),
            "memset into smc": wire.proxy_frame(0x205, 0x23E3FF000, 0, 0x2000),
            "memwrite over nvram": wire.memwrite_frame(0x235100000, b"\0" * 0x8000),
            "gzdec into sep": wire.proxy_frame(0x401, DRAM, 100, 0x25E400000, 0x1000),
            "pmgr power opcode": wire.proxy_frame(0x800, 1),
            "nvme opcode": wire.proxy_frame(0xF00),
            "call": wire.proxy_frame(0x002, DRAM),
        }
        for name, raw in cases.items():
            with self.subTest(name):
                g = wire.Guard(policy())
                with self.assertRaises(Violation):
                    g.feed(raw)

    def test_memwrite_data_and_sentinel_pass_through(self):
        """Safety: payload bytes of an allowed write are not parsed as requests, so they cannot smuggle one."""
        g = wire.Guard(policy())
        data = wire.proxy_frame(0x101, 0x23B700010, 0) * 4
        stream = wire.memwrite_frame(DRAM, data) + data + (0xB0CACC10).to_bytes(4, "little")
        stream += wire.proxy_frame(0x700, DRAM)
        self.assertEqual(g.feed(stream), stream)

    def test_corrupt_frame_fails_closed(self):
        """Safety: a frame the guard cannot parse is not forwarded."""
        raw = bytearray(wire.proxy_frame(0x101, PINCTRL_AP, 1))
        raw[20] ^= 1
        with self.assertRaises(wire.ProtocolError):
            wire.Guard(policy()).feed(bytes(raw))


class Bench(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)
        self.dev_master, dev_slave = pty.openpty()
        self.dev_slave_path = os.ttyname(dev_slave)
        self.record = self.dir / "device.jsonl"
        self.device = StubDevice(self.dev_master, self.record)
        self.kernel = self.dir / "Image"
        self.kernel.write_bytes(os.urandom(4096))
        self.dtb = self.dir / "t8112-j473.dtb"
        self.dtb.write_bytes(DTB.read_bytes())
        self.config = Config(device=self.dev_slave_path, linux_py=str(STUB_LINUX), dtb=str(DTB),
                             runs_dir=str(self.dir / "runs"))
        self._slave = dev_slave

    def tearDown(self):
        self.device.close()
        os.close(self._slave)
        self.tmp.cleanup()

    def wait(self, service, run_id, limit=30):
        end = time.time() + limit
        while time.time() < end:
            if service.runs[run_id].status != "running":
                time.sleep(0.2)
                return service.runs[run_id]
            time.sleep(0.1)
        self.fail("run did not finish")

    def device_requests(self):
        if not self.record.exists():
            return []
        return [json.loads(line) for line in self.record.read_text().splitlines()]


class ServiceRuns(Bench):
    def test_boot_through_relay_records_logs(self):
        """Spec: a run boots through linux.py on the device and its logs and inputs are kept on disk."""
        s = Service(self.config)
        token = s.acquire("test")["token"]
        run_id = s.boot(token, str(self.kernel), str(self.dtb), bootargs="console=tty0", timeout=20)["run"]
        run = self.wait(s, run_id)
        self.assertEqual(run.status, "ok", s.log(run_id)["lines"])
        meta = json.loads((run.dir / "meta.json").read_text())
        self.assertEqual(meta["exit_code"], 0)
        self.assertIn("sha256", meta["inputs"]["kernel"])
        self.assertIn("stub linux.py: booted", "\n".join(s.log(run_id)["lines"]))
        reqs = self.device_requests()
        self.assertIn({"proxy": 0x700, "args": [DRAM, 0, 0, 0, 0, 0]}, reqs)
        self.assertTrue(any(r.get("memwrite") == DRAM for r in reqs))
        s.release(token)

    def test_denied_write_ends_run_and_never_reaches_device(self):
        """Safety: a PMGR write from the host is blocked, the run is stopped, the device never sees it."""
        s = Service(self.config)
        token = s.acquire("test")["token"]
        with mock.patch.dict(os.environ, {"STUB_DENIED_WRITE": "23b700000"}):
            run_id = s.boot(token, str(self.kernel), str(self.dtb), timeout=20)["run"]
            run = self.wait(s, run_id)
        self.assertEqual(run.status, "blocked")
        self.assertIn("power-management@23b700000", run.meta["violation"])
        self.assertFalse(any(r.get("args", [None])[0] == 0x23B700000 for r in self.device_requests()))
        self.assertFalse(any(r.get("proxy") == 0x700 for r in self.device_requests()))

    def test_timeout_kills_the_run(self):
        """Spec: a run that hangs is killed at its timeout."""
        s = Service(self.config)
        token = s.acquire("test")["token"]
        start = time.time()
        with mock.patch.dict(os.environ, {"STUB_SLEEP": "60"}):
            run_id = s.boot(token, str(self.kernel), str(self.dtb), timeout=2)["run"]
            run = self.wait(s, run_id)
        self.assertEqual(run.status, "timeout")
        self.assertLess(time.time() - start, 10)

    def test_serial_is_captured_until_timeout(self):
        """Spec: the serial console of the device is recorded with the run."""
        ser_master, ser_slave = pty.openpty()
        self.config.serial = os.ttyname(ser_slave)
        s = Service(self.config)
        token = s.acquire("test")["token"]
        run_id = s.boot(token, str(self.kernel), str(self.dtb), timeout=3)["run"]
        time.sleep(1)
        os.write(ser_master, b"[    0.000000] Linux version 7.3.0-bande\n")
        run = self.wait(s, run_id)
        os.close(ser_master)
        os.close(ser_slave)
        self.assertEqual(run.status, "ok")
        self.assertIn("Linux version", "\n".join(s.log(run_id, "serial")["lines"]))

    def test_one_lease_at_a_time(self):
        """Spec: the device has one exclusive lease holder."""
        s = Service(self.config)
        token = s.acquire("a")["token"]
        with self.assertRaises(HilError):
            s.acquire("b")
        with self.assertRaises(HilError):
            s.boot("not-the-token", str(self.kernel), str(self.dtb))
        s.release(token)
        s.acquire("b")


class Mcp(Bench):
    def call(self, proc, msg_id, method, params=None):
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": msg_id, "method": method,
                                     "params": params or {}}) + "\n")
        proc.stdin.flush()
        return json.loads(proc.stdout.readline())

    def tool(self, proc, msg_id, name, args):
        out = self.call(proc, msg_id, "tools/call", {"name": name, "arguments": args})["result"]
        return out["isError"], json.loads(out["content"][0]["text"])

    def test_agent_round_trip(self):
        """Spec: an agent leases, boots, reads logs and releases through the four MCP tools."""
        service = Service(self.config)
        server = serve(service, 0)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        url = "http://127.0.0.1:%d" % server.server_address[1]
        proc = subprocess.Popen([sys.executable, "-m", "hil.mcp", "--url", url], cwd=ROOT,
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        try:
            init = self.call(proc, 1, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                                    "clientInfo": {"name": "test", "version": "0"}})
            self.assertIn("tools", init["result"]["capabilities"])
            names = [t["name"] for t in self.call(proc, 2, "tools/list")["result"]["tools"]]
            self.assertEqual(names, ["hil_lease", "hil_boot", "hil_log", "hil_release"])
            err, lease = self.tool(proc, 3, "hil_lease", {"owner": "agent"})
            self.assertFalse(err)
            err, busy = self.tool(proc, 4, "hil_lease", {"owner": "other"})
            self.assertTrue(err)
            err, run = self.tool(proc, 5, "hil_boot", {"token": lease["token"], "kernel": str(self.kernel),
                                                        "dtb": str(self.dtb), "timeout": 20})
            self.assertFalse(err, run)
            for i in range(200):
                err, log = self.tool(proc, 10 + i, "hil_log", {"run": run["run"]})
                if log["status"] != "running":
                    break
                time.sleep(0.1)
            self.assertEqual(log["status"], "ok")
            self.assertIn("stub linux.py: booted", log["lines"])
            err, _ = self.tool(proc, 300, "hil_release", {"token": lease["token"]})
            self.assertFalse(err)
        finally:
            proc.stdin.close()
            proc.wait(timeout=5)
            proc.stdout.close()
            server.shutdown()
            server.server_close()


@unittest.skipUnless(os.environ.get("PROXYCLIENT"), "PROXYCLIENT is not set to the bootloader's proxyclient/")
class RealProxyclient(Bench):
    def test_proxyclient_writes_are_checked(self):
        """Safety: the guard parses the frames the real proxyclient sends, so its writes cannot bypass it."""
        sys.path.insert(0, os.environ["PROXYCLIENT"])
        from unboot.proxy import UartInterface, UartTimeout, UNBOOTProxy

        log = open(self.dir / "relay.log", "w")
        relay = Relay(policy(), open_raw(self.dev_slave_path), log).start()
        try:
            with mock.patch.dict(os.environ, {"UNBOOTTIMEOUT": "2"}):
                iface = UartInterface(relay.slave_path)
            p = UNBOOTProxy(iface)
            p.write32(PINCTRL_AP, 1)
            iface.writemem(DRAM, os.urandom(70000))
            with self.assertRaises(UartTimeout):
                p.write32(0x23D714000, 0)
            self.assertIn("spmi@23d714000", relay.violation)
            reqs = self.device_requests()
            self.assertIn({"proxy": 0x101, "args": [PINCTRL_AP, 1, 0, 0, 0, 0]}, reqs)
            self.assertIn({"memwrite": DRAM, "size": 70000}, reqs)
            self.assertFalse(any(r.get("args", [None])[0] == 0x23D714000 for r in reqs))
        finally:
            relay.stop()
            log.close()


if __name__ == "__main__":
    unittest.main()
