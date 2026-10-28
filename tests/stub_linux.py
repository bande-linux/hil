import argparse
import os
import struct
import sys
import time
import tty

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from hil import wire

parser = argparse.ArgumentParser()
parser.add_argument("-b", "--bootargs")
parser.add_argument("payload")
parser.add_argument("dtb")
parser.add_argument("initramfs", nargs="?")
args = parser.parse_args()

fd = os.open(os.environ["UNBOOTDEVICE"], os.O_RDWR | os.O_NOCTTY)
tty.setraw(fd)


def expect_reply():
    buf = b""
    while len(buf) < wire.REPLY_LEN:
        chunk = os.read(fd, wire.REPLY_LEN - len(buf))
        if not chunk:
            sys.exit("device closed")
        buf += chunk


def send(data):
    os.write(fd, data)
    expect_reply()


print("stub linux.py: bootargs=%s" % args.bootargs, flush=True)
send(wire.frame(wire.REQ_NOP))
payload = open(args.payload, "rb").read()
os.write(fd, wire.memwrite_frame(0x10000000000, payload))
os.write(fd, payload)
expect_reply()
send(wire.proxy_frame(0x101, 0x23C100000, 1))
if os.environ.get("STUB_DENIED_WRITE"):
    print("writing 0x%s" % os.environ["STUB_DENIED_WRITE"], flush=True)
    send(wire.proxy_frame(0x101, int(os.environ["STUB_DENIED_WRITE"], 16), 0))
if os.environ.get("STUB_SLEEP"):
    time.sleep(float(os.environ["STUB_SLEEP"]))
send(wire.proxy_frame(0x700, 0x10000000000))
print("stub linux.py: booted", flush=True)
