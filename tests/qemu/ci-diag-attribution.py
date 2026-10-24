#!/usr/bin/env python3
"""DO NOT MERGE: attributes each SHUTDOWN exit in a host trace to KVM (L1) or Hyper-V (L0).

KVM flushes the nested mappings of a root it loads (Linux v7.0 arch/x86/kvm/mmu/mmu.c,
kvm_mmu_load, then svm_flush_tlb_current, arch/x86/kvm/svm/svm.c:4031-4045, which calls
hyperv_flush_guest_mapping on that root when Hyper-V's enlightened NPT TLB is on). For the
vCPU that exits with SHUTDOWN, this takes its fatal entry (its last kvm_entry before the
exit), the root that it loaded last before that entry (the kvmdiag/load_mmu_pgd
kprobe on svm_load_mmu_pgd, svm.c:4442), the last event before the entry that drops the
vCPU's root (the anchor) and the hyperv_nested_flush_guest_mapping* hypercalls between the
anchor and the entry. Two events drop roots: kvm_mmu_zap_all_fast, which makes every root
obsolete (mmu.c:6787-6825) and runs in whichever thread changed the memory map, the dying
vCPU's own after its MMIO exit or another one, so it is matched by time across all threads;
and kvm_mmu_reset_context (the kvmdiag/mmu_reset kprobe), which unloads the roots of one vCPU
(mmu.c:6043-6047, 6083-6092), e.g. when userspace writes a PAE vCPU's PDPTRs back (Linux v7.0
arch/x86/kvm/x86.c:12449-12477), so it counts only for the dying vCPU. Either way the vCPU
loads a root before it enters again (kvm_mmu_load, mmu.c:6050-6080, which then flushes it).
A root load or a reset belongs to the vCPU of its vcpu_id field, which the BTF-typed kprobes
record, and else to the vCPU of its thread:

- events lost in the window (ftrace's overwrite mode keeps each CPU's newest events only, so a
  CPU whose oldest kept event is newer than the anchor may have lost a root load or a flush):
  undetermined;
- no root observed: undetermined;
- a root loaded before the anchor: L1 (the zap's own flushes target the old roots, so they do
  not count);
- no "Hyper-V enlightened NPT TLB flush enabled" in dmesg: undetermined, as KVM then flushes
  without the hypercall (svm.c:4041, svm_onhyperv.h:18-24);
- the flush hypercalls' events not traced (--flush-events not-traced): undetermined, as an
  absent flush then says nothing;
- a successful flush (ret 0) of that root in the window: L0, a matching flush preceded the
  fault;
- no flush, or flushes of other roots, failed ones or ones after the entry only: L1.
"""

import argparse
import gzip
import re
from dataclasses import dataclass
from pathlib import Path

LINE = re.compile(
    r"^\s*(?P<comm>.+?)-(?P<tid>\d+)\s+\[(?P<cpu>\d+)\]\s+\S+\s+(?P<time>\d+\.\d+):\s+(?P<event>\w+):\s?(?P<fields>.*)$"
)
HEADER = re.compile(r"^# entries-in-buffer/entries-written: (?P<kept>\d+)/(?P<written>\d+)")
SHUTDOWN = re.compile(r"^vcpu (?P<vcpu>\d+) reason shutdown\b")
ENTRY = re.compile(r"^vcpu (?P<vcpu>\d+),")
ROOT = re.compile(r"\broot_hpa=(?P<root>0x[0-9a-f]+)")
VCPU_ID = re.compile(r"\bvcpu_id=(?P<vcpu>-?\d+)")
FLUSH = re.compile(r"^address space (?P<space>[0-9a-f]+) ret (?P<ret>-?\d+)")
FLUSH_EVENTS = ("hyperv_nested_flush_guest_mapping", "hyperv_nested_flush_guest_mapping_range")
ZAP_EVENT = "kvm_mmu_zap_all_fast"
RESET_EVENT = "mmu_reset"
PROBE_LOG = "kprobe svm_load_mmu_pgd"
ENLIGHTENED_FLUSH = "Hyper-V enlightened NPT TLB flush enabled"


@dataclass(frozen=True)
class Event:
    tid: int
    cpu: int
    time: float
    name: str
    fields: str


@dataclass(frozen=True)
class Trace:
    events: list[Event]
    # entries-in-buffer and entries-written of the trace's header, None without it.
    kept_written: tuple[int, int] | None

    def losses(self) -> str | None:
        """How many events the trace lost, or None if none."""
        if self.kept_written is None:
            return "the trace has no entries-in-buffer/entries-written header"
        kept, written = self.kept_written
        return None if kept == written else f"the trace kept {kept} of {written} events"

    def lost_since(self, start: float) -> str | None:
        """Why events after start may be missing, or None if none can be."""
        if self.kept_written is None:
            return "the trace has no entries-in-buffer/entries-written header"
        kept, written = self.kept_written
        if kept == written:
            return None
        oldest: dict[int, float] = {}
        for event in self.events:
            oldest.setdefault(event.cpu, event.time)
        late = {cpu: time for cpu, time in oldest.items() if time > start}
        if not late:
            return None
        cpus = ", ".join(f"CPU {cpu} from {time:.6f}" for cpu, time in sorted(late.items()))
        return f"the trace kept {kept} of {written} events, {cpus} only"


def read_trace(path: Path) -> Trace:
    opener = gzip.open if path.suffix == ".gz" else open
    events = []
    kept_written = None
    with opener(path, "rt", errors="replace") as trace:
        for line in trace:
            if (header := HEADER.match(line)) is not None:
                kept_written = (int(header["kept"]), int(header["written"]))
            elif (found := LINE.match(line)) is not None:
                events.append(
                    Event(int(found["tid"]), int(found["cpu"]), float(found["time"]), found["event"], found["fields"])
                )
    return Trace(events, kept_written)


def probe_reason(probe_log: Path | None) -> str:
    """What host-trace.log says about placing the kprobe."""
    if probe_log is None or not probe_log.exists():
        return "no host-trace.log"
    lines = [line.strip() for line in probe_log.read_text(errors="replace").splitlines() if PROBE_LOG in line]
    return "; ".join(dict.fromkeys(lines)) or "host-trace.log has no kprobe line"


def belongs(event: Event, vcpu: int, thread: int) -> bool:
    """Whether a kprobe event of one vCPU, by its vcpu_id field or else its thread, is vcpu's."""
    if (found := VCPU_ID.search(event.fields)) is not None:
        return int(found["vcpu"]) == vcpu
    return event.tid == thread


def attribute(trace: Trace, shutdown: Event, vcpu: int, reason: str, enlightened: bool, flushes_traced: bool) -> str:
    """The verdict on one SHUTDOWN exit of vcpu, with the evidence it rests on."""
    events = trace.events
    before = [event for event in events if event.time <= shutdown.time]
    entries = [
        event
        for event in before
        if event.name == "kvm_entry" and (found := ENTRY.match(event.fields)) and int(found["vcpu"]) == vcpu
    ]
    if not entries:
        return f"vcpu {vcpu}: undetermined: no kvm_entry before its shutdown at {shutdown.time:.6f}"
    entry = entries[-1]
    roots = [
        (event, found["root"])
        for event in before
        if event.name == "load_mmu_pgd"
        and belongs(event, vcpu, entry.tid)
        and event.time <= entry.time
        and (found := ROOT.search(event.fields))
    ]
    if not roots:
        lost = trace.losses()
        return f"vcpu {vcpu}: undetermined: no root observed ({reason}{'; ' + lost if lost else ''})"
    load, root = roots[-1]
    anchors = [
        event
        for event in before
        if event.time <= entry.time
        and (event.name == ZAP_EVENT or (event.name == RESET_EVENT and belongs(event, vcpu, entry.tid)))
    ]
    if not anchors:
        return (
            f"vcpu {vcpu}: undetermined: no kvm_mmu_zap_all_fast, nor kvm_mmu_reset_context of it,"
            f" before its fatal entry at {entry.time:.6f}"
        )
    anchor = anchors[-1]
    kind = "zap" if anchor.name == ZAP_EVENT else "reset"
    if (lost := trace.lost_since(anchor.time)) is not None:
        return f"vcpu {vcpu}: undetermined: events may be lost after the {kind} at {anchor.time:.6f} ({lost})"
    if load.time < anchor.time:
        return (
            f"vcpu {vcpu}: L1: entered on a root loaded before the {kind} (root {root} loaded at"
            f" {load.time:.6f}, {kind} in thread {anchor.tid} at {anchor.time:.6f}, fatal entry in thread"
            f" {entry.tid} at {entry.time:.6f}, shutdown at {shutdown.time:.6f})"
        )
    if not enlightened:
        return f"vcpu {vcpu}: undetermined (no enlightened NPT flush, no flush expected)"
    if not flushes_traced:
        return f"vcpu {vcpu}: undetermined: flush events not traced"
    flushes = [
        (event, int(found["space"], 16), int(found["ret"]))
        for event in before
        if event.name in FLUSH_EVENTS
        and anchor.time <= event.time <= entry.time
        and (found := FLUSH.match(event.fields))
    ]
    listed = ", ".join(
        f"{space:#x} ret {ret} in thread {event.tid} at {event.time:.6f}" for event, space, ret in flushes
    )
    evidence = (
        f"{kind} in thread {anchor.tid} at {anchor.time:.6f}, root {root} loaded at {load.time:.6f},"
        f" fatal entry in thread {entry.tid}"
        f" at {entry.time:.6f}, shutdown at {shutdown.time:.6f}; flushes between {kind} and entry: {listed or 'none'}"
    )
    if any(space == int(root, 16) and ret == 0 for _, space, ret in flushes):
        return f"vcpu {vcpu}: L0: a matching flush preceded the fault ({evidence})"
    return f"vcpu {vcpu}: L1: missing/late/mismatched/failed flush ({evidence})"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("trace", type=Path, help="a host trace, plain or .gz")
    parser.add_argument("--probe-log", type=Path, help="host-trace.log, for why no root was observed")
    parser.add_argument("--dmesg", type=Path, required=True, help="the host's dmesg from before the boots")
    parser.add_argument(
        "--flush-events",
        choices=("traced", "not-traced"),
        required=True,
        help="whether the hyperv_nested_flush_guest_mapping* events were enabled",
    )
    args = parser.parse_args()

    trace = read_trace(args.trace)
    reason = probe_reason(args.probe_log)
    enlightened = ENLIGHTENED_FLUSH in args.dmesg.read_text(errors="replace")
    shutdowns = [
        (event, found) for event in trace.events if event.name == "kvm_exit" and (found := SHUTDOWN.match(event.fields))
    ]
    if not shutdowns:
        print("attribution: no SHUTDOWN exit in the trace")
    for event, found in shutdowns:
        verdict = attribute(trace, event, int(found["vcpu"]), reason, enlightened, args.flush_events == "traced")
        print(f"attribution: {verdict}")


if __name__ == "__main__":
    main()
