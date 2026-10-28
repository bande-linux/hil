import struct

from .policy import Violation

# Framing constants copied from the bootloader's proxyclient/unboot/proxy.py.
REQ_NOP = 0x00AA55FF
REQ_PROXY = 0x01AA55FF
REQ_MEMREAD = 0x02AA55FF
REQ_MEMWRITE = 0x03AA55FF
REQ_BOOT = 0x04AA55FF
REQ_EVENT = 0x05AA55FF
REQUESTS = {REQ_NOP, REQ_PROXY, REQ_MEMREAD, REQ_MEMWRITE, REQ_BOOT, REQ_EVENT}
CMD_LEN = 56
FRAME_LEN = 4 + CMD_LEN + 4
REPLY_LEN = 36
DATA_END_SENTINEL = 0xB0CACC10

WIDTH = {0: 8, 1: 4, 2: 2, 3: 1}


class ProtocolError(Exception):
    pass


def checksum(data):
    s = 0xDEADBEEF
    for c in data:
        s = (s * 31337 + (c ^ 0x5A)) & 0xFFFFFFFF
    return (s ^ 0xADDEDBAD) & 0xFFFFFFFF


def frame(cmd, payload=b""):
    body = struct.pack("<I", cmd) + payload.ljust(CMD_LEN, b"\0")
    return body + struct.pack("<I", checksum(body))


def proxy_frame(opcode, *args):
    args = list(args) + [0] * (6 - len(args))
    return frame(REQ_PROXY, struct.pack("<7Q", opcode, *args))


def memwrite_frame(addr, data, data_checksum=None):
    csum = checksum(data) if data_checksum is None else data_checksum
    return frame(REQ_MEMWRITE, struct.pack("<QQI", addr, len(data), csum))


def reply(cmd, status=0, data=b""):
    body = struct.pack("<Ii", cmd, status) + data.ljust(24, b"\0")
    return body + struct.pack("<I", checksum(body))


class Guard:
    def __init__(self, policy):
        self.policy = policy
        self.buf = b""
        self.data_left = 0
        self.after_data = False
        self.requests = []

    def feed(self, data):
        out = b""
        self.buf += data
        while True:
            if self.data_left:
                n = min(self.data_left, len(self.buf))
                if not n:
                    return out
                out += self.buf[:n]
                self.buf = self.buf[n:]
                self.data_left -= n
                if not self.data_left:
                    self.after_data = True
                continue
            if self.after_data and len(self.buf) >= 4:
                if struct.unpack("<I", self.buf[:4])[0] == DATA_END_SENTINEL:
                    out += self.buf[:4]
                    self.buf = self.buf[4:]
                self.after_data = False
                continue
            if len(self.buf) < FRAME_LEN:
                return out
            raw, self.buf = self.buf[:FRAME_LEN], self.buf[FRAME_LEN:]
            self.check(raw)
            out += raw

    def check(self, raw):
        (cmd,) = struct.unpack("<I", raw[:4])
        (csum,) = struct.unpack("<I", raw[-4:])
        if cmd not in REQUESTS:
            raise ProtocolError("unknown request 0x%08x" % cmd)
        if checksum(raw[:-4]) != csum:
            raise ProtocolError("bad checksum on request 0x%08x" % cmd)
        payload = raw[4:-4]
        if cmd == REQ_MEMWRITE:
            addr, size, _ = struct.unpack("<QQI", payload[:20])
            self.policy.check_range(addr, size, "memory write")
            self.requests.append(("memwrite", addr, size))
            self.data_left = size
            self.after_data = size == 0
        elif cmd == REQ_PROXY:
            opcode, *args = struct.unpack("<7Q", payload)
            self.check_proxy(opcode, args)
            self.requests.append(("proxy", opcode, *args))
        else:
            self.requests.append((hex(cmd),))

    def check_proxy(self, opcode, args):
        if 0x100 <= opcode <= 0x117 and not 0x104 <= opcode <= 0x107:
            self.policy.check_range(args[0], WIDTH[opcode & 3], "MMIO write 0x%x" % opcode)
        elif 0x200 <= opcode <= 0x207:
            self.policy.check_range(args[0], args[2] * WIDTH[opcode & 3], "memory fill 0x%x" % opcode)
        elif opcode in (0x400, 0x401):
            if args[2]:
                self.policy.check_range(args[2], args[3] or 1, "decompress 0x%x" % opcode)
        else:
            self.policy.check_opcode(opcode)


__all__ = ["Guard", "Violation", "ProtocolError"]
