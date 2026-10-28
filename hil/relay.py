import os
import pty
import select
import termios
import threading
import tty

from .wire import Guard, ProtocolError, Violation


def open_raw(path):
    fd = os.open(path, os.O_RDWR | os.O_NOCTTY)
    tty.setraw(fd)
    return fd


def make_raw(fd):
    attrs = termios.tcgetattr(fd)
    tty.setraw(fd)
    return attrs


def write_all(fd, data):
    view = memoryview(data)
    while view:
        n = os.write(fd, view)
        view = view[n:]


class Relay:
    def __init__(self, policy, device_fd, log):
        self.guard = Guard(policy)
        self.device_fd = device_fd
        self.log = log
        self.master, slave = pty.openpty()
        make_raw(slave)
        self.slave_path = os.ttyname(slave)
        self.slave = slave
        self.violation = None
        self.stopped = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self.stopped.set()
        self.thread.join(timeout=5)
        for fd in (self.master, self.slave):
            try:
                os.close(fd)
            except OSError:
                pass

    def run(self):
        while not self.stopped.is_set():
            try:
                ready, _, _ = select.select([self.master, self.device_fd], [], [], 0.1)
            except (OSError, ValueError):
                return
            for fd in ready:
                try:
                    data = os.read(fd, 65536)
                except OSError:
                    data = b""
                if not data:
                    continue
                if fd == self.master:
                    try:
                        out = self.guard.feed(data)
                    except (Violation, ProtocolError) as e:
                        self.violation = str(e)
                        self.log.write("hil: blocked: %s\n" % e)
                        self.log.flush()
                        self.stopped.set()
                        return
                    if out:
                        write_all(self.device_fd, out)
                else:
                    write_all(self.master, data)
