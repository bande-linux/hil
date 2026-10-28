import gzip
import hashlib
import json
import os
import select
import signal
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

from .policy import Policy
from .relay import Relay, open_raw


class HilError(Exception):
    pass


@dataclass
class Config:
    device: str
    linux_py: str
    dtb: str
    runs_dir: str
    serial: str = ""
    python: str = sys.executable
    lease_ttl: int = 1800
    max_timeout: int = 900

    @classmethod
    def load(cls, path):
        with open(path) as f:
            return cls(**json.load(f))


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


@dataclass
class Lease:
    token: str
    owner: str
    expires: float


@dataclass
class Run:
    id: str
    dir: Path
    status: str = "running"
    meta: dict = field(default_factory=dict)


class Service:
    def __init__(self, config):
        self.config = config
        self.policy = Policy.from_dtb(Path(config.dtb).read_bytes())
        self.runs_dir = Path(config.runs_dir)
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.lease = None
        self.runs = {}
        self.active = None

    def _valid(self, token):
        lease = self.lease
        if lease is None or lease.expires < time.time():
            return False
        return lease.token == token

    def acquire(self, owner):
        with self.lock:
            if self.lease and self.lease.expires >= time.time():
                raise HilError("device is leased by %s until %s" % (
                    self.lease.owner, time.strftime("%H:%M:%S", time.localtime(self.lease.expires))))
            if self.active and self.active.status == "running":
                raise HilError("run %s is still in progress" % self.active.id)
            self.lease = Lease(uuid.uuid4().hex, owner, time.time() + self.config.lease_ttl)
            return {"token": self.lease.token, "expires": self.lease.expires}

    def release(self, token):
        with self.lock:
            if not self._valid(token):
                raise HilError("not the lease holder")
            if self.active and self.active.status == "running":
                raise HilError("run %s is still in progress" % self.active.id)
            self.lease = None
            return {"released": True}

    def boot(self, token, kernel, dtb, initramfs=None, bootargs="earlycon console=tty0", timeout=300):
        with self.lock:
            if not self._valid(token):
                raise HilError("not the lease holder")
            if self.active and self.active.status == "running":
                raise HilError("run %s is still in progress" % self.active.id)
            for p in (kernel, dtb) + ((initramfs,) if initramfs else ()):
                if not Path(p).is_file():
                    raise HilError("no such file: %s" % p)
            timeout = min(int(timeout), self.config.max_timeout)
            run_id = time.strftime("%Y%m%d-%H%M%S-") + uuid.uuid4().hex[:6]
            run = Run(run_id, self.runs_dir / run_id)
            run.dir.mkdir()
            run.meta = {
                "id": run_id, "owner": self.lease.owner, "started": time.time(), "timeout": timeout,
                "bootargs": bootargs,
                "inputs": {k: {"path": str(v), "sha256": sha256(v)}
                           for k, v in (("kernel", kernel), ("dtb", dtb), ("initramfs", initramfs)) if v},
                "deny_ranges": len(self.policy.ranges),
            }
            self.runs[run_id] = run
            self.active = run
            self.lease.expires = max(self.lease.expires, time.time() + timeout + 60)
            self._write_meta(run)
        threading.Thread(target=self._execute, args=(run, kernel, dtb, initramfs, bootargs, timeout),
                         daemon=True).start()
        return {"run": run_id}

    def _write_meta(self, run):
        run.meta["status"] = run.status
        (run.dir / "meta.json").write_text(json.dumps(run.meta, indent=2) + "\n")

    def _execute(self, run, kernel, dtb, initramfs, bootargs, timeout):
        deadline = time.monotonic() + timeout
        proxy_log = open(run.dir / "proxy.log", "a", buffering=1)
        relay = proc = serial_thread = None
        stop_serial = threading.Event()
        try:
            payload = kernel
            if not kernel.endswith((".gz", ".xz")):
                payload = str(run.dir / "Image.gz")
                with open(kernel, "rb") as src, gzip.open(payload, "wb", compresslevel=1) as dst:
                    dst.write(src.read())
            device_fd = open_raw(self.config.device)
            relay = Relay(self.policy, device_fd, proxy_log).start()
            if self.config.serial:
                serial_thread = threading.Thread(
                    target=self._capture, args=(self.config.serial, run.dir / "serial.log", stop_serial),
                    daemon=True)
                serial_thread.start()
            argv = [self.config.python, self.config.linux_py, "-b", bootargs, payload, dtb]
            if initramfs:
                argv.append(initramfs)
            env = dict(os.environ, UNBOOTDEVICE=relay.slave_path)
            proc = subprocess.Popen(argv, stdout=proxy_log, stderr=subprocess.STDOUT, env=env,
                                    start_new_session=True)
            status = None
            while status is None:
                if relay.violation:
                    status = "blocked"
                elif proc.poll() is not None and (proc.returncode != 0 or not self.config.serial):
                    status = "ok" if proc.returncode == 0 else "failed"
                elif time.monotonic() >= deadline:
                    status = "timeout" if proc.poll() is None else (
                        "ok" if proc.returncode == 0 else "failed")
                else:
                    time.sleep(0.05)
            run.status = status
        except Exception as e:
            proxy_log.write("hil: %s\n" % e)
            run.status = "error"
        finally:
            if proc and proc.poll() is None:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
            stop_serial.set()
            if serial_thread:
                serial_thread.join(timeout=5)
            if relay:
                relay.stop()
                os.close(relay.device_fd)
                run.meta["violation"] = relay.violation
                run.meta["requests"] = len(relay.guard.requests)
            run.meta["exit_code"] = proc.returncode if proc else None
            run.meta["finished"] = time.time()
            proxy_log.close()
            with self.lock:
                self._write_meta(run)

    @staticmethod
    def _capture(path, out, stop):
        while not stop.is_set() and not os.path.exists(path):
            time.sleep(0.2)
        if stop.is_set():
            return
        fd = open_raw(path)
        try:
            with open(out, "ab") as f:
                while not stop.is_set():
                    ready, _, _ = select.select([fd], [], [], 0.2)
                    if ready:
                        data = os.read(fd, 65536)
                        if not data:
                            break
                        f.write(data)
                        f.flush()
        finally:
            os.close(fd)

    def log(self, run_id, which="proxy", tail=200):
        run = self.runs.get(run_id)
        if run is None:
            path = self.runs_dir / run_id
            if not (path / "meta.json").exists():
                raise HilError("no such run: %s" % run_id)
            run = Run(run_id, path, json.loads((path / "meta.json").read_text())["status"])
        if which not in ("proxy", "serial", "meta"):
            raise HilError("log must be proxy, serial or meta")
        name = "meta.json" if which == "meta" else which + ".log"
        path = run.dir / name
        text = path.read_text(errors="replace") if path.exists() else ""
        lines = text.splitlines()[-int(tail):]
        return {"run": run_id, "status": run.status, "log": which, "lines": lines}
