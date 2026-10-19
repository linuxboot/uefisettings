#!/usr/bin/env python3
"""DO NOT MERGE: checks a 32-bit x86 guest's exception path in RAM dumps.

From the registers that ci-diag-qmp.py saved before the fault (QEMU's "info registers -a"),
walks each vCPU's page tables (legacy or PAE paging, or none) in the RAM dump taken before
the fault and in the one taken after it, and reports for both the translations, the
permissions and reserved bits on the way, and the bytes of what delivering an interrupt or
exception needs: the IDT gates of the vectors, the GDT descriptors they and TR name, the
TSS, the task of a task gate (walked under its own CR3), the handlers' first bytes, the
stack pages, and any linear address given on the command line, such as the fault's RIP from
the host trace.

How to read it: structures intact and deliverable in the dump after the fault mean that the
guest's memory allowed the delivery, so the failure lies in translation state outside it. A
difference does not by itself blame the guest: a stale nested mapping can send its writes to
the wrong page. Entries compare with their accessed and dirty bits masked, as walks between
the dumps set them; the stack pages may differ legitimately.
"""

import argparse
import mmap
import re
import struct
from dataclasses import dataclass, replace
from enum import Enum
from pathlib import Path

# The contributory faults and #PF, which escalate to #DF, #DF itself and the local timer.
VECTORS = (0x08, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0xEC)
PAGE_SIZE = 0x1000
INTERRUPT_FRAME_BYTES = 16
PAE_ADDRESS_MASK = 0x000F_FFFF_FFFF_F000
CR0_PG = 1 << 31
CR4_PSE = 1 << 4
CR4_PAE = 1 << 5
EFER_NXE = 1 << 11
PRESENT = 1 << 0
WRITABLE = 1 << 1
USER = 1 << 2
ACCESSED_DIRTY = (1 << 5) | (1 << 6)
PAGE_SIZE_BIT = 1 << 7
NO_EXECUTE = 1 << 63
TASK_GATE = 0x5
GATE_TYPES = {
    TASK_GATE: "task gate",
    0x6: "16-bit interrupt gate",
    0x7: "16-bit trap gate",
    0xE: "interrupt gate",
    0xF: "trap gate",
}
TSS_FIELDS = {
    "esp0": 0x04,
    "ss0": 0x08,
    "cr3": 0x1C,
    "eip": 0x20,
    "esp": 0x38,
    "cs": 0x4C,
    "ss": 0x50,
    "ds": 0x54,
    "fs": 0x58,
}


class PagewalkError(Exception):
    pass


class Paging(Enum):
    NONE = "none"
    LEGACY = "legacy"
    PAE = "PAE"


def bits(low: int, high: int) -> int:
    return ((1 << (high - low + 1)) - 1) << low


@dataclass(frozen=True)
class Cpu:
    index: int
    eip: int
    esp: int
    cr0: int
    cr3: int
    cr4: int
    efer: int
    gdt_base: int
    gdt_limit: int
    idt_base: int
    idt_limit: int
    tr_selector: int
    tr_base: int

    @property
    def paging(self) -> Paging:
        if not self.cr0 & CR0_PG:
            return Paging.NONE
        if self.cr4 & CR4_PAE:
            return Paging.PAE
        return Paging.LEGACY


@dataclass(frozen=True)
class Step:
    """One page-table entry read during a walk: where, what and its reserved bits set."""

    level: str
    address: int
    value: int
    reserved: int

    def compared(self) -> tuple[str, int, int]:
        return self.level, self.address, self.value & ~ACCESSED_DIRTY


@dataclass(frozen=True)
class Translation:
    steps: tuple[Step, ...]
    physical: int | None

    @property
    def permissions(self) -> str:
        """The effective W, U and NX of the leaf, from the entries that have them."""
        entries = [step.value for step in self.steps if step.level != "PDPTE"]
        if not entries:
            return "w u nx: no paging"
        writable = all(value & WRITABLE for value in entries)
        user = all(value & USER for value in entries)
        no_execute = any(value & NO_EXECUTE for value in entries)
        return f"w={int(writable)} u={int(user)} nx={int(no_execute)}"


def parse_registers(text: str) -> list[Cpu]:
    """Parses QEMU's "info registers -a" output of a 32-bit x86 guest."""
    cpus = []
    for index, block in enumerate(re.split(r"^CPU#\d+\n", text, flags=re.M)[1:]):
        def hex_field(name: str, block: str = block, index: int = index) -> int:
            found = re.search(rf"\b{name}=\s*([0-9a-f]+)", block)
            if found is None:
                raise PagewalkError(f"CPU#{index}: no {name} in the registers")
            return int(found.group(1), 16)

        gdt = re.search(r"^GDT=\s+([0-9a-f]+) ([0-9a-f]+)", block, re.M)
        idt = re.search(r"^IDT=\s+([0-9a-f]+) ([0-9a-f]+)", block, re.M)
        tr = re.search(r"^TR =([0-9a-f]+) ([0-9a-f]+)", block, re.M)
        if gdt is None or idt is None or tr is None:
            raise PagewalkError(f"CPU#{index}: no GDT, IDT or TR in the registers")
        cpus.append(
            Cpu(
                index=index,
                eip=hex_field("EIP"),
                esp=hex_field("ESP"),
                cr0=hex_field("CR0"),
                cr3=hex_field("CR3"),
                cr4=hex_field("CR4"),
                efer=hex_field("EFER"),
                gdt_base=int(gdt.group(1), 16),
                gdt_limit=int(gdt.group(2), 16),
                idt_base=int(idt.group(1), 16),
                idt_limit=int(idt.group(2), 16),
                tr_selector=int(tr.group(1), 16),
                tr_base=int(tr.group(2), 16),
            )
        )
    if not cpus:
        raise PagewalkError("no CPU#N blocks in the registers")
    return cpus


class Ram:
    """A raw dump of guest RAM from physical address 0, mapped rather than read: it is GBs."""

    def __init__(self, path: Path) -> None:
        with path.open("rb") as file:
            self.data = mmap.mmap(file.fileno(), 0, access=mmap.ACCESS_READ)

    def read(self, physical: int, size: int) -> bytes | None:
        if physical + size > len(self.data):
            return None
        return self.data[physical : physical + size]

    def u32(self, physical: int) -> int | None:
        raw = self.read(physical, 4)
        return None if raw is None else struct.unpack("<I", raw)[0]

    def u64(self, physical: int) -> int | None:
        raw = self.read(physical, 8)
        return None if raw is None else struct.unpack("<Q", raw)[0]


@dataclass(frozen=True)
class Walker:
    """Walks one vCPU's page tables; reserved bits as in Linux v7.0 arch/x86/kvm/mmu/mmu.c,
    __reset_rsvds_bits_mask, case PT32E_ROOT_LEVEL."""

    ram: Ram
    cpu: Cpu
    maxphyaddr: int

    def reserved_pae(self, level: str, value: int) -> int:
        high = bits(self.maxphyaddr, 62)
        if not self.cpu.efer & EFER_NXE:
            high |= NO_EXECUTE
        match level:
            case "PDPTE":
                mask = NO_EXECUTE | high | bits(5, 8) | bits(1, 2)
            case "PDE" if value & PAGE_SIZE_BIT:
                mask = high | bits(13, 20)
            case "PDE" | "PTE":
                mask = high
            case _:
                raise PagewalkError(f"no PAE level {level}")
        return value & mask

    def translate(self, linear: int) -> Translation:
        match self.cpu.paging:
            case Paging.NONE:
                return Translation((), linear)
            case Paging.PAE:
                return self.translate_pae(linear)
            case Paging.LEGACY:
                return self.translate_legacy(linear)

    def translate_pae(self, linear: int) -> Translation:
        steps: list[Step] = []
        table = self.cpu.cr3 & 0xFFFF_FFE0
        for level, shift, index_bits in (("PDPTE", 30, 2), ("PDE", 21, 9), ("PTE", 12, 9)):
            address = table + ((linear >> shift) & ((1 << index_bits) - 1)) * 8
            value = self.ram.u64(address)
            if value is None:
                return Translation(tuple(steps), None)
            steps.append(Step(level, address, value, self.reserved_pae(level, value)))
            if not value & PRESENT:
                return Translation(tuple(steps), None)
            if level == "PDE" and value & PAGE_SIZE_BIT:
                large = value & PAE_ADDRESS_MASK & ~0x1F_FFFF
                return Translation(tuple(steps), large | (linear & 0x1F_FFFF))
            table = value & PAE_ADDRESS_MASK
        return Translation(tuple(steps), table | (linear & 0xFFF))

    def translate_legacy(self, linear: int) -> Translation:
        pde_address = (self.cpu.cr3 & 0xFFFF_F000) + (linear >> 22) * 4
        pde = self.ram.u32(pde_address)
        if pde is None:
            return Translation((), None)
        steps = [Step("PDE", pde_address, pde, 0)]
        if not pde & PRESENT:
            return Translation(tuple(steps), None)
        if self.cpu.cr4 & CR4_PSE and pde & PAGE_SIZE_BIT:
            return Translation(tuple(steps), (pde & 0xFFC0_0000) | (linear & 0x3F_FFFF))
        pte_address = (pde & 0xFFFF_F000) + ((linear >> 12) & 0x3FF) * 4
        pte = self.ram.u32(pte_address)
        if pte is None:
            return Translation(tuple(steps), None)
        steps.append(Step("PTE", pte_address, pte, 0))
        if not pte & PRESENT:
            return Translation(tuple(steps), None)
        return Translation(tuple(steps), (pte & 0xFFFF_F000) | (linear & 0xFFF))

    def read(self, linear: int, size: int) -> tuple[Translation, bytes | None]:
        translation = self.translate(linear)
        if translation.physical is None:
            return translation, None
        return translation, self.ram.read(translation.physical, size)


def describe(translation: Translation, data: bytes | None) -> str:
    walk = " ".join(
        f"{step.level}@{step.address:#x}={step.value:#x}"
        + (f"(RESERVED {step.reserved:#x})" if step.reserved else "")
        for step in translation.steps
    )
    if translation.physical is None:
        return f"{walk} NOT MAPPED".strip()
    content = "" if data is None else f" bytes {data.hex()}"
    return f"{walk} -> {translation.physical:#x} {translation.permissions}{content}".strip()


def compared(translation: Translation, data: bytes | None) -> tuple:
    return tuple(step.compared() for step in translation.steps), translation.physical, data


def descriptor_base(raw: bytes) -> int:
    low, high = struct.unpack("<II", raw)
    return (low >> 16) | ((high & 0xFF) << 16) | (high & 0xFF00_0000)


class Report:
    """The report of one vCPU over all dumps."""

    def __init__(self, cpu: Cpu, dumps: dict[str, Ram], maxphyaddr: int) -> None:
        self.cpu = cpu
        self.dumps = dumps
        self.maxphyaddr = maxphyaddr
        self.lines = [
            f"CPU#{cpu.index}: paging {cpu.paging.value} CR3 {cpu.cr3:#x} CR4 {cpu.cr4:#x}"
            f" EFER {cpu.efer:#x} EIP {cpu.eip:#x} ESP {cpu.esp:#x}"
        ]

    def item(self, name: str, linear: int, size: int, cpu: Cpu | None = None) -> dict[str, bytes | None]:
        """Reports one structure in every dump, walked under cpu's (by default this vCPU's) CR3."""
        under = cpu or self.cpu
        results = {
            label: Walker(ram, under, self.maxphyaddr).read(linear, size) for label, ram in self.dumps.items()
        }
        same = len({compared(*result) for result in results.values()}) == 1
        self.lines.append(f"  {name} at {linear:#x}: {'same in all dumps' if same else 'DIFFERS'}")
        for label, (translation, data) in results.items():
            self.lines.append(f"    {label}: {describe(translation, data)}")
        return {label: data for label, (_, data) in results.items()}

    def first(self, results: dict[str, bytes | None]) -> bytes | None:
        return next((raw for raw in results.values() if raw is not None), None)

    def gdt_entry(self, name: str, selector: int) -> dict[str, bytes | None]:
        return self.item(f"{name}: GDT entry {selector:#x}", self.cpu.gdt_base + (selector & ~7), 8)

    def vector(self, vector: int) -> None:
        if vector * 8 + 7 > self.cpu.idt_limit:
            self.lines.append(f"  IDT vector {vector:#x}: beyond the IDT limit {self.cpu.idt_limit:#x}")
            return
        gate = self.first(self.item(f"IDT vector {vector:#x}", self.cpu.idt_base + vector * 8, 8))
        if gate is None:
            return
        low, high = struct.unpack("<II", gate)
        selector = low >> 16
        gate_type = (high >> 8) & 0xF
        kind = GATE_TYPES.get(gate_type, f"type {gate_type:#x}")
        self.lines.append(f"    {kind}, selector {selector:#x}, present {high >> 15 & 1}")
        descriptor = self.first(self.gdt_entry(f"vector {vector:#x}", selector))
        if gate_type != TASK_GATE:
            self.item(f"vector {vector:#x} handler", (high & 0xFFFF_0000) | (low & 0xFFFF), 16)
            return
        if descriptor is not None:
            self.task(vector, descriptor_base(descriptor))

    def task(self, vector: int, tss_base: int) -> None:
        """Reports a task gate's TSS and, under the TSS's CR3, its code and stack."""
        tss = self.item(f"vector {vector:#x} task's TSS", tss_base, 0x68)
        for label, raw in tss.items():
            if raw is None:
                continue
            fields = {name: struct.unpack_from("<I", raw, offset)[0] for name, offset in TSS_FIELDS.items()}
            self.lines.append(f"    {label} TSS: " + ", ".join(f"{name} {value:#x}" for name, value in fields.items()))
        raw = self.first(tss)
        if raw is None:
            return
        task_cpu = replace(self.cpu, cr3=struct.unpack_from("<I", raw, TSS_FIELDS["cr3"])[0])
        eip = struct.unpack_from("<I", raw, TSS_FIELDS["eip"])[0]
        esp = struct.unpack_from("<I", raw, TSS_FIELDS["esp"])[0]
        self.item(f"vector {vector:#x} task's code (its CR3)", eip, 16, task_cpu)
        self.item(f"vector {vector:#x} task's stack top (its CR3)", esp - INTERRUPT_FRAME_BYTES, 16, task_cpu)

    def run(self, addresses: dict[str, int]) -> list[str]:
        for vector in VECTORS:
            self.vector(vector)
        self.gdt_entry("TR", self.cpu.tr_selector)
        self.item("TR's TSS", self.cpu.tr_base, 0x68)
        self.item("stack at ESP", self.cpu.esp, 16)
        self.item("stack below ESP (interrupt frame)", self.cpu.esp - INTERRUPT_FRAME_BYTES, 16)
        self.item("code at EIP", self.cpu.eip, 16)
        for name, linear in addresses.items():
            self.item(name, linear, 16)
        return self.lines


def parse_address(text: str) -> tuple[str, int]:
    name, separator, value = text.partition("=")
    if not separator:
        raise argparse.ArgumentTypeError(f"{text}: not NAME=ADDRESS")
    return name, int(value, 16)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("registers", type=Path, help="registers-before.txt of ci-diag-qmp.py")
    parser.add_argument("dumps", type=Path, nargs="+", help="RAM dumps, before and after")
    parser.add_argument("--maxphyaddr", type=int, required=True, help="the guest's physical address bits")
    parser.add_argument(
        "--address",
        type=parse_address,
        action="append",
        default=[],
        help="NAME=ADDRESS (hex), a linear address to walk too",
    )
    args = parser.parse_args()

    dumps = {path.name: Ram(path) for path in args.dumps}
    print(f"MAXPHYADDR {args.maxphyaddr}; accessed and dirty bits masked in comparisons")
    for cpu in parse_registers(args.registers.read_text()):
        print("\n".join(Report(cpu, dumps, args.maxphyaddr).run(dict(args.address))))


if __name__ == "__main__":
    main()
