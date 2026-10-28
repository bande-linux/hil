from dataclasses import dataclass

from . import fdt

COMPATIBLE_RULES = [
    ("apple,pmgr", "power management"),
    ("apple,cluster-cpufreq", "CPU voltage and frequency"),
    ("apple,spmi", "PMU and voltage regulators"),
    ("apple,smc", "SMC: fan, thermal, power"),
    ("apple,sep", "boot policy (SEP)"),
    ("apple,nvme-ans2", "boot policy (LocalPolicy on NVMe)"),
    ("-pmp-", "power manager coprocessor"),
]

NAME_RULES = [("power-management@", "power management")]

PHANDLE_RULES = ["mboxes", "apple,sart"]

NOR_FLASH = "jedec,spi-nor"

CALL_OPCODES = {0x002, 0x009, 0x00A, 0x00C, 0x00D, 0x012, 0x501, 0x502, 0x507, 0x508, 0x509, 0x50A}
DENIED_OPCODE_RANGES = [
    (0x800, 0x8FF, "power management"),
    (0xF00, 0xFFF, "NVMe, holds boot policy"),
]


@dataclass(frozen=True)
class Range:
    start: int
    size: int
    reason: str
    node: str

    @property
    def end(self):
        return self.start + self.size

    def overlaps(self, addr, size):
        return addr < self.end and self.start < addr + max(size, 1)


class Violation(Exception):
    pass


class Policy:
    def __init__(self, ranges):
        self.ranges = sorted(ranges, key=lambda r: r.start)

    @classmethod
    def from_dtb(cls, blob):
        root = fdt.parse(blob)
        table = fdt.phandles(root)
        found = {}

        def deny(node, reason):
            for addr, size in fdt.regs(node):
                found[(addr, size)] = Range(addr, size, reason, node.path)

        for node in root.walk():
            compat = node.compatible()
            for pattern, reason in COMPATIBLE_RULES:
                if any(pattern in c for c in compat):
                    deny(node, reason)
                    for prop in PHANDLE_RULES:
                        for ph in node.u32s(prop):
                            if ph in table:
                                deny(table[ph], reason)
            for prefix, reason in NAME_RULES:
                if node.name.startswith(prefix):
                    deny(node, reason)
            if NOR_FLASH in compat and node.parent is not None:
                deny(node.parent, "NVRAM (SPI NOR flash controller)")
        return cls(found.values())

    def check_range(self, addr, size, what):
        for r in self.ranges:
            if r.overlaps(addr, size):
                raise Violation(
                    "%s 0x%x+0x%x hits %s [0x%x-0x%x] (%s)"
                    % (what, addr, size, r.node, r.start, r.end, r.reason))

    def check_opcode(self, opcode):
        if opcode in CALL_OPCODES:
            raise Violation("opcode 0x%x runs code on the device, which cannot be checked" % opcode)
        for low, high, reason in DENIED_OPCODE_RANGES:
            if low <= opcode <= high:
                raise Violation("opcode 0x%x is denied (%s)" % (opcode, reason))
