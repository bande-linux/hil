import struct

FDT_MAGIC = 0xD00DFEED
FDT_BEGIN_NODE = 1
FDT_END_NODE = 2
FDT_PROP = 3
FDT_NOP = 4
FDT_END = 9


class Node:
    def __init__(self, name, parent=None):
        self.name = name
        self.parent = parent
        self.props = {}
        self.children = []

    @property
    def path(self):
        if self.parent is None:
            return "/"
        base = self.parent.path
        return (base if base.endswith("/") else base + "/") + self.name

    def u32s(self, name):
        data = self.props.get(name, b"")
        return list(struct.unpack(">%dI" % (len(data) // 4), data))

    def cells(self, name, default):
        values = self.u32s(name)
        return values[0] if values else default

    def compatible(self):
        data = self.props.get("compatible", b"")
        return [s.decode() for s in data.split(b"\0") if s]

    def walk(self):
        yield self
        for child in self.children:
            yield from child.walk()


def _join(cells):
    value = 0
    for c in cells:
        value = (value << 32) | c
    return value


def parse(blob):
    magic, _, off_struct, off_strings = struct.unpack(">IIII", blob[:16])
    if magic != FDT_MAGIC:
        raise ValueError("not a flattened device tree")
    pos = off_struct
    root = None
    stack = []
    while True:
        (token,) = struct.unpack(">I", blob[pos:pos + 4])
        pos += 4
        if token == FDT_BEGIN_NODE:
            end = blob.index(b"\0", pos)
            name = blob[pos:end].decode()
            pos = (end + 4) & ~3
            node = Node(name, stack[-1] if stack else None)
            if stack:
                stack[-1].children.append(node)
            else:
                root = node
            stack.append(node)
        elif token == FDT_END_NODE:
            stack.pop()
        elif token == FDT_PROP:
            length, nameoff = struct.unpack(">II", blob[pos:pos + 8])
            pos += 8
            end = blob.index(b"\0", off_strings + nameoff)
            name = blob[off_strings + nameoff:end].decode()
            stack[-1].props[name] = blob[pos:pos + length]
            pos = (pos + length + 3) & ~3
        elif token == FDT_NOP:
            continue
        elif token == FDT_END:
            return root
        else:
            raise ValueError("bad FDT token %d" % token)


def phandles(root):
    table = {}
    for node in root.walk():
        ph = node.u32s("phandle")
        if ph:
            table[ph[0]] = node
    return table


def _translate(node, addr):
    child = node.parent
    while child is not None and child.parent is not None:
        bus = child.parent
        if "ranges" not in child.props:
            return None
        ranges = child.u32s("ranges")
        if not ranges:
            child = bus
            continue
        ca = child.cells("#address-cells", 2)
        pa = bus.cells("#address-cells", 2)
        cs = child.cells("#size-cells", 1)
        step = ca + pa + cs
        for i in range(0, len(ranges), step):
            cbase = _join(ranges[i:i + ca])
            pbase = _join(ranges[i + ca:i + ca + pa])
            size = _join(ranges[i + ca + pa:i + step])
            if cbase <= addr < cbase + size:
                addr = addr - cbase + pbase
                break
        else:
            return None
        child = bus
    return addr


def regs(node):
    parent = node.parent
    ac = parent.cells("#address-cells", 2)
    sc = parent.cells("#size-cells", 1)
    values = node.u32s("reg")
    out = []
    step = ac + sc
    for i in range(0, len(values) - step + 1, step):
        addr = _translate(node, _join(values[i:i + ac]))
        size = _join(values[i + ac:i + step])
        if addr is not None and size:
            out.append((addr, size))
    return out
