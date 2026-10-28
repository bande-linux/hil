import json
import os
import select
import struct
import threading

from hil import wire


class StubDevice:
    def __init__(self, fd, record):
        self.fd = fd
        self.record = record
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def read(self, n):
        out = b""
        while len(out) < n:
            if self.stop.is_set():
                raise EOFError
            ready, _, _ = select.select([self.fd], [], [], 0.1)
            if ready:
                try:
                    chunk = os.read(self.fd, n - len(out))
                except OSError:
                    raise EOFError
                if not chunk:
                    raise EOFError
                out += chunk
        return out

    def run(self):
        with open(self.record, "a") as rec:
            try:
                while True:
                    raw = self.read(wire.FRAME_LEN)
                    (cmd,) = struct.unpack("<I", raw[:4])
                    payload = raw[4:-4]
                    if cmd == wire.REQ_PROXY:
                        opcode, *args = struct.unpack("<7Q", payload)
                        rec.write(json.dumps({"proxy": opcode, "args": args}) + "\n")
                        data = struct.pack("<QqQ", opcode, 0, 0)
                    elif cmd == wire.REQ_MEMWRITE:
                        addr, size, _ = struct.unpack("<QQI", payload[:20])
                        self.read(size)
                        rec.write(json.dumps({"memwrite": addr, "size": size}) + "\n")
                        data = b""
                    else:
                        rec.write(json.dumps({"cmd": cmd}) + "\n")
                        data = b""
                    rec.flush()
                    os.write(self.fd, wire.reply(cmd, 0, data))
            except EOFError:
                return

    def close(self):
        self.stop.set()
        self.thread.join(timeout=5)
