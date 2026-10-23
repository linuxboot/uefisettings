#!/bin/bash
# The runner user writes the output files; sudo only reads them.
# shellcheck disable=SC2024
# DO NOT MERGE: diagnostics for the i686 guests that reset on GitHub's AMD runners (EPYC 7763,
# 9V74 and 9V45; KVM nested under Hyper-V), fourth round. In the third (CI run 39936216534) a
# PAE vCPU whose page directory pointer table does not start a page died at its first entry
# after KVM reloaded its MMU, on a memory slot's deletion (memslot) and on QEMU's register
# write-back after a QMP stop and register read (sync); whole-page tables (pti=on; openSUSE's
# 7.2) and x86_64 survived. The runners' KVM (Ubuntu's linux-azure) clears the guest CR3's low
# 12 bits at each NPT root load for a vCPU without CR4.PCIDE, the PAE table's address bits 5-11
# among them (https://bugs.launchpad.net/bugs/2106673). This round decides what the third left
# open:
# - c3, Debian's 6.1 with two processes that ping-pong over FIFOs (sub-page tables, frequent
#   CR3 changes), under memslot, DIAG_REPS boots with host traces: one hang made the third
#   round's cell "harness";
# - tests/qemu/run.sh's i686 scenarios under pti=on, 3 times, and its aarch64 scenarios as
#   they are, as a control off the nested-KVM path (TCG), all through make as CI runs them
#   (run_suite); the job's own make step before this script is the i686 run without pti=on.
# A cell is a guest test and kernel command line, booted round-robin with the others, each
# boot with a verdict; the host traces of KVM, its MMU, Hyper-V's flush hypercalls and
# kprobes on svm_load_mmu_pgd, kvm_mmu_reset_context and shutdown_interception go through
# ci-diag-attribution.py.
# Decision rule, per cell of DIAG_REPS boots: "dies" if at least 8 in 10 die, "survives" if at
# most 1 in 10 dies and the others end their test, else "mixed"; a boot that its timeout ends
# after its test started its trigger (memslot printed its BAR, just before its first toggle;
# sync's first QMP stop), without a reset or the end of its test, "hung", is neither; a cell
# cut short by the deadline is "incomplete", one whose boots do not show their controls (the
# kernel's "Linux version" line, PTI as asked, the stressor's round trips) "invalid"; any other
# boot that neither dies nor ends its test fails the harness. pti=on is a containment candidate
# only if all 3 i686 runs under pti=on pass, every boot provably with pti=on.
# Writes everything to target/qemu-test/diag/.
#
# DIAG_REPS: boots per cell (default 10). DIAG_TRACE_KB: the host trace's buffer per CPU in
# KiB (default 131072). DIAG_SLOW: a factor for every boot's timeout and the deadline, for a
# run under emulation (default 1). DIAG_RUN_SH=no leaves out tests/qemu/run.sh, which builds
# with cargo; DIAG_ONLY does not limit those. DIAG_ONLY: the cells' boots to run, as ARCH/LABEL
# separated by commas or spaces (e.g. "i686/c3-memslot"; default all).
#
# Usage: tests/qemu/ci-diag-reset.sh

set -uo pipefail

here=$(realpath "$(dirname "$0")")
repo=$(realpath "$here/../..")
out=$repo/target/qemu-test/diag
tracing=/sys/kernel/tracing
reps=${DIAG_REPS:-10}
trace_kb=${DIAG_TRACE_KB:-131072}
slow=${DIAG_SLOW:-1}
for value in "$reps" "$trace_kb" "$slow"; do
    if [[ ! $value =~ ^[1-9][0-9]*$ ]]; then
        echo "ci-diag-reset.sh: DIAG_REPS, DIAG_TRACE_KB and DIAG_SLOW take positive integers, not '$value'" >&2
        exit 2
    fi
done
# The pauses of tests/sync, on the kernel command line of its boots.
sync_pauses=5
# No boot starts after 70 minutes, so that the job (120 minutes, of which the build and
# tests/qemu/run.sh take about 35) uploads what the boots found.
deadline=$((SECONDS + 4200 * slow))
rm -rf "$out"
mkdir -p "$out"

{
    uname -a
    id
    sudo --version | head -n 1
    readlink -f "$(command -v sudo)"
    sudo -n env | grep '^PATH='
    grep -m1 '^model name' /proc/cpuinfo
    grep -m1 '^flags' /proc/cpuinfo
    # Some parameters are root's only.
    sudo sh -c 'for p in /sys/module/kvm_amd/parameters/* /sys/module/kvm_intel/parameters/* \
        /sys/module/kvm/parameters/*; do [ -e "$p" ] && echo "$p=$(cat "$p")"; done'
    qemu-system-x86_64 --version
    dpkg-query -W -f='${Package} ${Version} ${Architecture}\n' qemu-system-x86 libc6 libglib2.0-0t64
    apt-cache policy qemu-system-x86
    sha256sum /usr/bin/qemu-system-i386 /usr/bin/qemu-system-x86_64
    python3 --version
    sudo ls "$tracing/events/hyperv" "$tracing/events/kvmmmu"
    sudo ls /sys/kernel/btf
    echo "kprobe targets: $(sudo grep -w -E 'svm_load_mmu_pgd|kvm_mmu_reset_context|shutdown_interception' \
        "$tracing/available_filter_functions" | tr '\n' ' ')"
} >"$out/facts.txt" 2>&1
sudo dmesg >"$out/dmesg-before.txt" 2>&1
# The host traces need sudo (GitHub's runners have it without a password); without, the
# boots run untraced and the summary says so. tracefs is root's only, so sudo looks at it.
host_traces=no
sudo -n true 2>>"$out/facts.txt" && sudo test -d "$tracing/events" && host_traces=yes
amd_host=no
[[ -d /sys/module/kvm_amd ]] && amd_host=yes
echo "host traces: $host_traces" >>"$out/facts.txt"

# harness_fail MESSAGE: a boot that does not produce what it should, which fails the diag
# rather than passing as a result.
harness_failures=0
boots=0
flush_events=not-traced
# KVM's message when it flushes nested mappings through Hyper-V's hypercall (Linux v7.0
# arch/x86/kvm/svm/svm_onhyperv.c), as ci-diag-attribution.py also looks for it.
enlightened_flush='Hyper-V enlightened NPT TLB flush enabled'
harness_fail() {
    echo "HARNESS FAIL: $1" | tee -a "$out/summary.txt" >&2
    harness_failures=$((harness_failures + 1))
}
# On an AMD host the attribution rests on the host traces, so their absence fails the diag
# there; elsewhere (an Intel machine without sudo) it is a note in facts.txt.
[[ $host_traces == no && $amd_host == yes ]] &&
    harness_fail "an AMD host, but no host traces (sudo or tracefs missing)"
# Dumps the VMCB to dmesg if a VMRUN fails.
[[ $host_traces == yes && $amd_host == yes ]] &&
    echo Y | sudo tee /sys/module/kvm_amd/parameters/dump_invalid_vmcb >>"$out/facts.txt"

# host_trace_start MODE: full (KVM, its MMU, Hyper-V's flush hypercalls and the kprobes below)
# or cr (KVM's control register accesses only, for the CR4 that the guest kernel set). A
# flush clears what a vCPU uses only if its address space (hyperv_nested_flush_guest_mapping*:
# "address space") is the root that the vCPU loaded.
host_trace_start() {
    # An array, so that the sh -c below gets the names on one line. Task switches have no event
    # of their own (Linux v7.0 arch/x86/kvm/trace.h): kvm_exit shows them, as "reason
    # task_switch" (arch/x86/include/uapi/asm/svm.h:212).
    local events=(kvm/kvm_cr) clock name
    [[ $1 == full ]] && events=(kvm/kvm_entry kvm/kvm_exit kvm/kvm_userspace_exit
        kvm/kvm_inj_exception kvm/kvm_inj_virq kvm/kvm_emulate_insn kvm/kvm_msr kvm/kvm_cr
        kvm/kvm_page_fault kvm/kvm_mmio kvm/kvm_pio
        kvmmmu/kvm_mmu_zap_all_fast kvmmmu/kvm_mmu_spte_requested kvmmmu/handle_mmio_page_fault
        kvmmmu/mark_mmio_spte kvmmmu/fast_page_fault hyperv)
    # 128 MiB per CPU by default: overwrite mode keeps each CPU's newest events only, and the
    # attribution declares a window that lost events undetermined (run 39281579400's write
    # boots wrote 0.5-1.1 million events, all kept in 64 MiB).
    # The global clock, as the attribution orders events of different threads, and so of
    # different CPUs, which the default local clock does not keep in sync (Linux v7.0
    # Documentation/trace/ftrace.rst:540-545). An event that this kernel lacks, such as
    # hyperv/* outside Hyper-V, is logged and left out.
    sudo sh -c "
        echo 0 >$tracing/tracing_on
        echo >$tracing/trace
        echo global >$tracing/trace_clock
        echo 1 >$tracing/options/overwrite
        echo $trace_kb >$tracing/buffer_size_kb
        echo 4096 >$tracing/saved_cmdlines_size
        echo 0 >$tracing/events/enable
        for e in ${events[*]}; do
            if [ -e $tracing/events/\$e/enable ]; then
                echo 1 >$tracing/events/\$e/enable
            else
                echo \"no trace event \$e\"
            fi
        done
        echo 1 >$tracing/tracing_on" >>"$out/host-trace.log" 2>&1
    clock=$(sudo cat "$tracing/trace_clock")
    echo "trace_clock: $clock" >>"$out/host-trace.log"
    [[ $clock == *"[global]"* ]] || harness_fail "trace_clock is not global: $clock"
    [[ $1 == full ]] || return 0
    for name in "${kprobes[@]}"; do
        kprobe_add "$name" && continue
        # On AMD each of them is part of the verdict; Intel lacks the svm_* ones.
        [[ $amd_host == no ]] || harness_fail "an AMD host, but no kvmdiag/$name kprobe"
    done
    flush_events=$(events_enabled hyperv/hyperv_nested_flush_guest_mapping hyperv/hyperv_nested_flush_guest_mapping_range)
    [[ $(events_enabled kvm/kvm_entry kvm/kvm_exit kvmmmu/kvm_mmu_zap_all_fast) == traced ]] ||
        harness_fail "KVM's entry, exit or root zap events are not traced"
    # On an AMD host with the enlightened NPT flush, the attribution needs the flushes.
    [[ $flush_events == traced || $amd_host == no ]] ||
        ! grep -q "$enlightened_flush" "$out/dmesg-before.txt" ||
        harness_fail "the Hyper-V flush events are not traced on a host that uses them"
}

# events_enabled EVENT...: logs each event's enable file as read back, and prints traced if
# all of them read 1, else not-traced.
events_enabled() {
    local event value state=traced
    for event; do
        if value=$(sudo cat "$tracing/events/$event/enable" 2>>"$out/host-trace.log"); then
            echo "event $event enable=$value" >>"$out/host-trace.log"
        else
            value=missing
            echo "event $event missing" >>"$out/host-trace.log"
        fi
        [[ $value == 1 ]] || state=not-traced
    done
    echo "$state"
}

# The kprobes of a full trace, kvmdiag/NAME, each placed by the first of its definitions that
# the kernel takes, every refusal logged. The BTF-typed ones (CONFIG_PROBE_EVENTS_BTF_ARGS,
# which the runners' 7.0.0-1017-azure has) name the vCPU; without, the event's thread does.
# - load_mmu_pgd: the NPT root that KVM loads for a vCPU, svm_load_mmu_pgd(vcpu, root_hpa,
#   root_level), Linux v7.0 arch/x86/kvm/svm/svm.c:4442, called from kvm_mmu_load_pgd
#   (arch/x86/kvm/mmu.h:148-157); no tracepoint carries the root. The BTF-typed one adds the
#   guest CR3 that the vCPU runs on (the VMCB's, svm.c:3606-3610), for each walk NPF after
#   the load to be set against the PDPT's place in its page.
# - mmu_reset: kvm_mmu_reset_context(vcpu), which unloads the vCPU's roots
#   (arch/x86/kvm/mmu/mmu.c:6043-6047, 6083-6092).
# - shutdown: shutdown_interception(vcpu), before it INITs the vCPU (svm.c:2081-2109), with
#   the CR3 that svm_handle_exit copied from the VMCB on this exit (svm.c:3606-3610). KVM
#   calls the VMCB undefined after a SHUTDOWN intercept (svm.c:2087-2088): a lead, not proof.
kprobes=(load_mmu_pgd mmu_reset shutdown)
kprobes_placed=()
kprobe_definitions() {
    # shellcheck disable=SC2016 # kprobe_events fetch arguments, not shell expansions
    case $1 in
    load_mmu_pgd)
        printf '%s\n' 'svm_load_mmu_pgd vcpu_id=vcpu->vcpu_id root_hpa=root_hpa:x64 root_level=root_level:s32 cr3=vcpu->arch.cr3:x64' \
            'svm_load_mmu_pgd root_hpa=$arg2:x64 root_level=$arg3:s32' \
            'svm_load_mmu_pgd root_hpa=%si:x64 root_level=%dx:s32'
        ;;
    mmu_reset) printf '%s\n' 'kvm_mmu_reset_context vcpu_id=vcpu->vcpu_id' 'kvm_mmu_reset_context' ;;
    shutdown) printf '%s\n' 'shutdown_interception vcpu_id=vcpu->vcpu_id cr3=vcpu->arch.cr3:x64' ;;
    esac
}

# kprobe_add NAME: places kvmdiag/NAME and enables it; false if no definition takes.
kprobe_add() {
    local name=$1 definition
    while read -r definition; do
        if sudo sh -c "echo 'p:kvmdiag/$name $definition' >>$tracing/kprobe_events" 2>>"$out/host-trace.log"; then
            kprobes_placed+=("$name")
            echo "kprobe ${definition%% *}: $definition" >>"$out/host-trace.log"
            sudo sh -c "echo 1 >$tracing/events/kvmdiag/$name/enable" >>"$out/host-trace.log" 2>&1
            [[ $(events_enabled "kvmdiag/$name") == traced ]] && return 0
            harness_fail "the kvmdiag/$name kprobe is placed but not enabled"
            return 1
        fi
        echo "kprobe ${definition%% *} refused: $definition: $(sudo tail -n 2 "$tracing/error_log" | tr '\n' ' ')" \
            >>"$out/host-trace.log"
    done < <(kprobe_definitions "$name")
    return 1
}

# kprobes_remove: removes the kprobes that kprobe_add placed, and checks that none is left.
kprobes_remove() {
    local name remaining
    for name in "${kprobes_placed[@]}"; do
        sudo sh -c "echo 0 >$tracing/events/kvmdiag/$name/enable; echo -:kvmdiag/$name >>$tracing/kprobe_events" \
            >>"$out/host-trace.log" 2>&1 || harness_fail "removing the kvmdiag/$name kprobe failed"
    done
    kprobes_placed=()
    remaining=$(sudo cat "$tracing/kprobe_events")
    echo "kprobe_events after removal: ${remaining:-empty}" >>"$out/host-trace.log"
    [[ $remaining != *kvmdiag/* ]] || harness_fail "kvmdiag kprobes are still registered: $remaining"
}

# host_trace_stop LABEL DIR MODE VCPUS: saves the trace as LABEL's and, for MODE full, writes
# ci-diag-attribution.py's verdict to DIR/attribution.txt, from the whole trace rather than
# from the tail that is kept (trace_tail lines, and vcpu_tail of each of the VCPUS vCPU
# threads' own).
trace_tail=2000000
vcpu_tail=500000
host_trace_stop() {
    local trace=$out/$1.host-kvm-trace.txt n tid
    sudo sh -c "echo 0 >$tracing/tracing_on; cat $tracing/trace" >"$trace" 2>>"$out/host-trace.log"
    kprobes_remove
    grep -a -q -E 'kvm_(exit|cr):' "$trace" || harness_fail "$1: host trace without KVM events"
    if [[ $3 == full ]]; then
        python3 "$here/ci-diag-attribution.py" --probe-log "$out/host-trace.log" --dmesg "$out/dmesg-before.txt" \
            --flush-events "$flush_events" "$trace" >"$2/attribution.txt" 2>&1 ||
            harness_fail "$1: ci-diag-attribution.py failed, see $2/attribution.txt"
    fi
    tail -n "$trace_tail" "$trace" | gzip >"$trace.gz" || harness_fail "$1: compressing the host trace failed"
    # Each vCPU thread's own tail too, which the other's lines cannot push out. The thread is
    # the one of the vCPU's kvm_exit lines, by its id, which a line has even when its name is
    # not known ("<...>"); kvm_inj_exception and others have no vCPU field.
    if [[ $3 == full ]]; then
        for ((n = 0; n < $4; n++)); do
            tid=$(grep -a -E "kvm_exit: vcpu $n " "$trace" | tail -n 1 |
                sed -E 's/^.*-([0-9]+) +\[[0-9]+\].*$/\1/')
            if [[ -z $tid ]]; then
                harness_fail "$1: no vCPU $n thread found in the host trace"
                continue
            fi
            grep -a -E -- "-$tid +\[[0-9]+\]" "$trace" | tail -n "$vcpu_tail" |
                gzip >"$out/$1.host-kvm-trace.vcpu$n.txt.gz" || harness_fail "$1: compressing vCPU $n's trace failed"
            require "$out/$1.host-kvm-trace.vcpu$n.txt.gz"
        done
    fi
    rm -f "$trace"
}

# select_arch ARCH: run.sh's table, for the architecture that this diag runs under KVM (i686).
select_arch() {
    arch=$1
    case $arch in
    i686)
        qemu_name='qemu-system-i386'
        firmware=usr/share/OVMF/OVMF32_CODE_4M.fd
        firmware_vars=usr/share/OVMF/OVMF32_VARS_4M.fd
        vmlinuz_pattern='boot/vmlinuz-*'
        ;;
    *)
        harness_fail "select_arch: no row for $arch"
        return 1
        ;;
    esac
    local runs=()
    mapfile -t runs < <(compgen -G "$repo/target/qemu-test/$arch/2*/hii/vars.json" | sort)
    if ((${#runs[@]} == 0)); then
        harness_fail "no tests/qemu/run.sh $arch run with a hii scenario"
        return 1
    fi
    run=$(dirname "$(dirname "${runs[-1]}")")
    guest=$repo/target/qemu-test/$arch/guest
    vmlinuz=$guest/$(cd "$guest" && compgen -G "$vmlinuz_pattern")
    apt_qemu=/usr/bin/$qemu_name
    mkdir -p "$out/$arch/binaries"
    {
        echo "run $run"
        sha256sum "$guest/$firmware" "$guest/$firmware_vars" "$vmlinuz" "$run"/esp/*.efi \
            "$run"/initramfs/bin/* "$run"/initramfs/tests/*
    } >"$out/$arch/facts.txt" 2>&1
    cp "$run"/esp/*.efi "$run/initramfs/bin/uefisettings" "$run"/initramfs/tests/* \
        "$out/$arch/binaries/"
    # The kernel's symbols, for the addresses in the traces (Debian's i686 package has them).
    if compgen -G "$guest/boot/System.map-*" >/dev/null; then
        cp "$guest"/boot/System.map-* "$out/$arch/binaries/" || harness_fail "$arch: copying System.map failed"
    else
        echo "no System.map in $guest/boot" >>"$out/$arch/facts.txt"
    fi
    stepwise_initrd "$out/$arch"
}

# stepwise_initrd DIR: DIR/stepwise-initrd.img, the run's initramfs with the tests of this
# diag, which mark each step on the terminal as they go (a reset loses anything buffered):
# - memslot toggles the memory decoding of the ivshmem-plain device 200 times, so QEMU deletes
#   and adds the memory slot of its BAR each time, no firmware involved;
# - sync prints the pause marker of ci-diag-qmp.py diag.pauses times, sleeping after each;
# - with diag.stress, memslot and sync first start two processes that ping-pong a byte over
#   two FIFOs, so the CPU switches between their address spaces at each round trip.
stepwise_initrd() {
    rm -rf "$1/stepwise-initramfs"
    cp -r "$run/initramfs" "$1/stepwise-initramfs"
    # Sourced by the tests, not run.
    cat >"$1/stepwise-initramfs/tests/step-and-stress" <<'EOF'
step() {
    read -r uptime _ < /proc/uptime
    echo "step $uptime: $*"
    sync
}
stress=
pauses=0
read -r cmdline < /proc/cmdline
for parameter in $cmdline; do
    case $parameter in
    diag.stress) stress=yes ;;
    diag.pauses=*) pauses=${parameter#*=} ;;
    esac
done
step "$(grep -m 1 '^address sizes' /proc/cpuinfo)"
stress_report() { :; }
if [ -n "$stress" ]; then
    mkfifo /tmp/ping /tmp/pong
    ( exec 3<>/tmp/ping 4<>/tmp/pong; while read -r _ <&3; do echo >&4; done ) &
    ( exec 3<>/tmp/ping 4<>/tmp/pong; n=0; echo >&3
      while read -r _ <&4; do n=$((n + 1)); [ $((n % 1000)) = 0 ] && echo $n > /tmp/round-trips; echo >&3; done ) &
    sleep 1
    step "stress: $(cat /tmp/round-trips 2>/dev/null || echo 0) round trips in about a second"
    stress_report() { step "stress: $(cat /tmp/round-trips 2>/dev/null || echo 0) round trips"; }
fi
EOF
    cat >"$1/stepwise-initramfs/tests/memslot" <<'EOF'
#!/bin/busybox sh
. /tests/step-and-stress
dev=
for d in /sys/bus/pci/devices/*; do
    [ "$(cat "$d/vendor")" = 0x1af4 ] && [ "$(cat "$d/device")" = 0x1110 ] && dev=$d
done
if [ -z "$dev" ]; then
    step "no ivshmem-plain device"
    exit 1
fi
set -- $(hexdump -s 4 -n 2 -e '2/1 "%u "' "$dev/config")
bar=$(sed -n 3p "$dev/resource")
step "ivshmem-plain $dev: command $1 $2, BAR 2 $bar"
start=${bar%% *}
if [ "$((start))" = 0 ]; then
    step "BAR 2 has no address"
    exit 1
fi
off=$(($1 & ~2))
on=$(($1 | 2))
i=0
while [ $i -lt 200 ]; do
    # dd's own messages, but not its errors, filtered out; boot_verdict catches a write that
    # does not take.
    printf "\\$(printf %o $off)" | dd of="$dev/config" bs=1 seek=4 count=1 conv=notrunc 2>&1 | grep -v -e 'records in' -e 'records out'
    printf "\\$(printf %o $on)" | dd of="$dev/config" bs=1 seek=4 count=1 conv=notrunc 2>&1 | grep -v -e 'records in' -e 'records out'
    i=$((i + 1))
    [ $((i % 50)) = 0 ] && step "toggled the memory decoding $i times"
done
stress_report
step "end"
EOF
    cat >"$1/stepwise-initramfs/tests/sync" <<'EOF'
#!/bin/busybox sh
. /tests/step-and-stress
i=1
while [ $i -le "$pauses" ]; do
    echo "diag: pause $i"
    sleep 2
    step "resumed $i"
    i=$((i + 1))
done
stress_report
step "end"
EOF
    chmod +x "$1/stepwise-initramfs/tests/memslot" "$1/stepwise-initramfs/tests/sync"
    (cd "$1/stepwise-initramfs" && find . | cpio --create --format=newc --quiet) \
        >"$1/stepwise-initrd.img"
}

# fresh_store FILE: the hii scenario's variable store, as run.sh seeds it.
fresh_store() {
    virt-fw-vars --input "$guest/$firmware_vars" --set-json "$run/hii/vars.json" \
        --output "$1" 2>>"$out/virt-fw-vars.log"
}

# boot LABEL STORE QEMU HOST_TRACE PAUSE KERNEL INITRD APPEND QEMU-ARG...: one guest boot of
# at most boot_timeout seconds, with its verdict in its DIR/verdict.txt (see boot_verdict).
# HOST_TRACE is no or a mode of host_trace_start. PAUSE is no or a --pause mode of
# ci-diag-qmp.py, which then serves the test terminal and QMP on sockets while QEMU pauses on
# a reset instead of ending.
boot_timeout=$((180 * slow))
boot() {
    local label=$1 store=$2 qemu=$3 host_trace=$4 pause=$5 kernel=$6 initrd=$7 append=$8
    local rc start end dir=$out/$arch/$label sockets supervisor='' terminal control test
    local trace=$out/$arch-${label//\//-}
    local traces=trace:kvm_run_exit,trace:kvm_run_exit_system_event,trace:qemu_system_shutdown_request,trace:qemu_system_powerdown_request,trace:kvm_set_user_memory,trace:kvm_vcpu_ioctl,trace:vm_state_notify
    shift 8
    mkdir -p "$dir"
    boots=$((boots + 1))
    if [[ $pause != no ]]; then
        # Unix socket paths have a limit of 108 bytes, which $dir can pass.
        sockets=$(mktemp -d /tmp/diag.XXXXXX)
        terminal=(-chardev "socket,id=tty,path=$sockets/terminal,server=on,wait=on")
        control=(-action 'reboot=shutdown,shutdown=pause' -qmp "unix:$sockets/qmp,server=on,wait=off")
        python3 "$here/ci-diag-qmp.py" --terminal-socket "$sockets/terminal" \
            --qmp-socket "$sockets/qmp" --terminal-log "$dir/test.log" --out "$dir" \
            --pause "$pause" >"$dir/qmp.log" 2>&1 &
        supervisor=$!
    else
        terminal=(-chardev "file,id=tty,path=$dir/test.log")
        control=(-no-reboot)
    fi
    [[ $host_traces == no ]] && host_trace=no
    [[ $host_trace != no ]] && host_trace_start "$host_trace"
    start=$(date +%s.%N)
    # debug-threads names the vCPU threads (CPU N/KVM) for the host trace's lines.
    timeout --foreground -k 10 "$boot_timeout" "$qemu" -machine q35 "$@" -name debug-threads=on \
        -nodefaults -no-user-config "${control[@]}" -display none -sandbox on -m 1024 \
        -drive "if=pflash,format=raw,unit=0,readonly=on,file=$guest/$firmware" \
        -drive "if=pflash,format=raw,unit=1,file=$store" \
        -drive "if=virtio,format=raw,readonly=on,file=fat:$run/esp" \
        -kernel "$kernel" -initrd "$initrd" -append "console=ttyS0 uefisettings.tty=ttyS1 $append" \
        -serial "file:$dir/console.log" \
        "${terminal[@]}" -serial chardev:tty \
        -d "guest_errors,unimp,$traces" -D "$dir/qemu.log" </dev/null >"$dir/qemu.stdout" 2>&1
    rc=$?
    end=$(date +%s.%N)
    [[ $host_trace != no ]] && host_trace_stop "${trace#"$out/"}" "$dir" "$host_trace" "$(vcpus "$@")"
    if [[ -n $supervisor ]]; then
        wait "$supervisor"
        echo "ci-diag-qmp.py exited with $?" >>"$dir/qmp.log"
        rm -rf "$sockets"
        require "$dir/qmp.log"
    fi
    [[ $host_trace != no ]] && require "$trace.host-kvm-trace.txt.gz"
    [[ $host_trace == full ]] && require "$dir/attribution.txt"
    # The artifacts of every boot; without them its lines below would read as a result.
    if ! require "$dir/qemu.stdout" "$dir/qemu.log" "$dir/console.log" "$dir/test.log"; then
        echo "  $arch $label: QEMU exited with $rc: $(tr '\n' ' ' <"$dir/qemu.stdout" | head -c 400)" |
            tee -a "$out/summary.txt" >&2
        return
    fi
    gzip "$dir/qemu.log" || harness_fail "$arch $label: gzip of qemu.log failed"
    require "$dir/qemu.log.gz" || return
    test=${append##*uefisettings.test=}
    test=${test%% *}
    boot_verdict "$dir" "$test" "$rc" >"$dir/verdict.txt"
    sregs2_writes "$dir/qemu.log.gz" >"$dir/sregs2.txt" ||
        harness_fail "$arch $label: counting the KVM_SET_SREGS2 calls failed"
    {
        echo "== $arch $label: $qemu -machine q35 $* -append ... $append; store $store"
        echo "firmware $guest/$firmware; kernel $kernel; initrd $initrd"
        echo "exit $rc after $(awk -v a="$start" -v b="$end" 'BEGIN { printf "%.1f", b - a }') s"
        tr -d '\r' <"$dir/console.log" | grep -a 'uefisettings-qemu-test: exit' || echo "no exit line"
        pti_line "$dir"
        tr -d '\r' <"$dir/test.log" | grep -a -E '^test result|^step ' | tail -4 || true
        # With -no-reboot, a reset (triple fault: KVM exit 8; reset port: exit 2) logs no
        # shutdown request; a guest poweroff logs reason=6.
        zcat "$dir/qemu.log.gz" | grep -a -E 'qemu_system_(shutdown|powerdown)_request|kvm_run_exit_system_event' | tail -3
        echo "memory slot changes: $(zcat "$dir/qemu.log.gz" | grep -a -c '^kvm_set_user_memory')"
        echo "last kvm_run_exit lines:"
        zcat "$dir/qemu.log.gz" | grep -a kvm_run_exit | tail -4
        echo "QEMU KVM_SET_SREGS2 per running period: $(cat "$dir/sregs2.txt")"
        [[ -f $dir/qmp.log ]] && echo "qmp: $(grep -c ': resumed$' "$dir/qmp.log") pauses resumed;" \
            "$(grep -a -E 'shutdown:|exited with' "$dir/qmp.log" | tr '\n' ' ')"
        # Each vCPU's CR3 when QMP read the registers, from "info registers -a".
        for registers in "$dir"/registers-*.txt; do
            [[ -f $registers ]] || continue
            awk -v pause="${registers##*registers-}" '/^CPU#/ { cpu = $1 }
                match($0, /CR3=[0-9a-f]+/) { cr3 = substr($0, RSTART + 4, RLENGTH - 4)
                    printf "registers at pause %s: %s CR3=%s (offset in its page 0x%s)\n", pause + 0, cpu, cr3, substr(cr3, length(cr3) - 2) }' "$registers"
        done
        [[ -f $dir/attribution.txt ]] && cat "$dir/attribution.txt"
        if [[ -f $trace.host-kvm-trace.txt.gz ]]; then
            zcat "$trace.host-kvm-trace.txt.gz" | awk '/ mmu_reset: / { n++ } END { print "host kvm_mmu_reset_context calls in the kept trace: " n + 0 }'
            zcat "$trace.host-kvm-trace.txt.gz" |
                sed -n -E 's/.* shutdown: .*vcpu_id=([0-9]+) cr3=0x([0-9a-f]+).*/shutdown probe: vcpu \1 VMCB CR3 0x\2/p'
            # The CR4 that each vCPU's kernel set last: a CPUID mask changes it only through Linux.
            zcat "$trace.host-kvm-trace.txt.gz" |
                sed -n -E 's/.*CPU ([0-9]+)\/KVM-.*kvm_cr: cr_write 4 = (0x[0-9a-f]+).*/vCPU \1 CR4 \2/p' | awk '{last[$2] = $0} END {for (c in last) print "last " last[c]}'
        fi
        echo "verdict: $(cat "$dir/verdict.txt")"
    } >>"$out/summary.txt"
}

# sregs2_writes QEMU_LOG_GZ: the register writes of QEMU (KVM_SET_SREGS2, which carries a PAE
# vCPU's PDPTRs: _IOW(KVMIO, 0xcd, struct kvm_sregs2) = 0x4140aecd,
# include/uapi/linux/kvm.h:1480) in each period that the VM ran, from its start to the first
# pause and on from each cont, as numbers separated by spaces; false if the log has no period.
sregs2_writes() {
    zcat "$1" | awk '/^vm_state_notify running 1 / { n[++runs] = 0 }
        /^kvm_vcpu_ioctl .* type 0x4140aecd,/ { n[runs]++ }
        END { if (runs == 0) exit 1; for (i = 1; i <= runs; i++) printf "%s%d", (i > 1 ? " " : ""), n[i]; print "" }'
}

# pti_line DIR: the first "page tables isolation" line of DIR's console, or a note that it has
# none. grep reads the file itself: at the end of a pipe, grep -m 1 would leave its writer to
# die of SIGPIPE, which pipefail reports as no match.
pti_line() {
    grep -a -m 1 'page tables isolation' "$1/console.log" | tr -d '\r' || echo "no page table isolation line"
}

# boot_verdict DIR TEST RC: "died", "hung", "survived" or "other", then why, for the boot in DIR
# of the guest test TEST, whose QEMU exited with RC. A guest that resets (a KVM exit 8) before
# the end of its test died; one that its timeout (RC 124) ended after its test started its
# trigger (memslot printed its BAR, just before its first toggle; sync's first QMP stop),
# without a reset or the end of its test, hung; one that ends its test survived if the test
# did what it should: memslot's 200 deletions of its BAR's slot, sync's pauses, a hii test's
# pass. Anything else (an unassigned BAR, a failed test, a hang before the trigger) is other.
# The deletions count the BAR's slot from the start: Debian's 6.1 makes 8 while it boots.
boot_verdict() {
    local dir=$1 test=$2 rc=$3 resets ended bar deletes=0 resumed
    resets=$(zcat "$dir/qemu.log.gz" | grep -a -c -E '^kvm_run_exit cpu_index [0-9]+, reason 8$')
    case $test in
    memslot | sync) ended=$(tr -d '\r' <"$dir/test.log" | grep -a -c '^step .*: end$') ;;
    *) ended=$(tr -d '\r' <"$dir/console.log" | grep -a -c '^uefisettings-qemu-test: exit 0 0$') ;;
    esac
    if [[ $test == memslot ]]; then
        bar=$(tr -d '\r' <"$dir/test.log" | sed -n -E 's/.*, BAR 2 (0x[0-9a-f]+) .*/\1/p' | head -n 1)
        # QEMU's trace prints the address without the resource file's leading zeros.
        [[ -n $bar ]] && bar=$(printf '0x%x' "$bar")
        [[ -n $bar ]] && ((bar != 0)) && deletes=$(zcat "$dir/qemu.log.gz" |
            grep -a -c -E "^kvm_set_user_memory AddrSpace#0 .* gpa=$bar size=0x0 ")
    fi
    if ((resets > 0 && ended == 0)); then
        case $test in
        memslot) echo "died: KVM exit 8 after $deletes deletions of the slot at BAR 2 ${bar:-none}" ;;
        sync) echo "died: KVM exit 8 after $(grep -c ': resumed$' "$dir/qmp.log") resumed pauses" ;;
        *) echo "died: KVM exit 8" ;;
        esac
        return
    fi
    if ((ended == 0 && rc == 124)) && { [[ $test == memslot ]] && ((deletes > 0)) ||
        { [[ $test == sync ]] && grep -q ': pause 1: stopped$' "$dir/qmp.log"; }; }; then
        echo "hung: timeout, no reset and no end, after $([[ $test == memslot ]] && echo "$deletes deletions of the slot at BAR 2 $bar" ||
            echo "$(grep -c ': resumed$' "$dir/qmp.log") resumed pauses") (last: $(tr -d '\r' <"$dir/test.log" | grep -a '^step ' | tail -n 1))"
        return
    fi
    if ((ended == 0)); then
        echo "other: no reset, and the test did not end well (last: $(tr -d '\r' <"$dir/test.log" |
            grep -a '^step ' | tail -n 1)$(tr -d '\r' <"$dir/console.log" | grep -a 'uefisettings-qemu-test: exit' | tail -n 1))"
        return
    fi
    case $test in
    memslot)
        if [[ -n $bar ]] && ((bar != 0 && deletes >= 200)); then
            echo "survived: $deletes deletions of the slot at BAR 2 $bar"
        else
            echo "other: vacuous: BAR 2 '${bar:-none}', $deletes deletions of its slot"
        fi
        ;;
    sync)
        resumed=$(grep -c ': resumed$' "$dir/qmp.log")
        if ((resumed == sync_pauses)); then
            echo "survived: $resumed pauses"
        else
            echo "other: vacuous: $resumed of $sync_pauses pauses"
        fi
        ;;
    *) echo "survived: the test passed" ;;
    esac
}

# in_time LABEL: false, with a line in the summary, once the deadline has passed.
in_time() {
    ((SECONDS <= deadline)) && return 0
    echo "skipped after the deadline: $1" | tee -a "$out/cells.txt" >>"$out/summary.txt"
    return 1
}

# vcpus QEMU-ARG...: the vCPU count of the -smp in QEMU-ARG.
vcpus() {
    while (($# > 1)); do
        [[ $1 == -smp ]] && echo "${2%%,*}" && return
        shift
    done
    echo 1
}

# require PATH...: false, with a MISSING line per absent path, unless all exist.
require() {
    local path missing=0
    for path; do
        if [[ ! -e $path ]]; then
            echo "MISSING $path" | tee -a "$out/summary.txt" >&2
            harness_failures=$((harness_failures + 1))
            missing=1
        fi
    done
    return "$missing"
}

# wanted LABEL: whether DIAG_ONLY names the arch's LABEL, or is empty.
wanted() {
    [[ -z ${DIAG_ONLY:-} || " ${DIAG_ONLY//,/ } " == *" $arch/$1 "* ]]
}

# verdict_of DIR: the verdict of DIR's boot, or "other: no verdict".
verdict_of() {
    if [[ -f $1/verdict.txt ]]; then
        cat "$1/verdict.txt"
    else
        echo "other: no verdict"
    fi
}

# The cells of the arch at hand: cell NAME TEST PAUSE KERNEL APPEND QEMU-ARGS registers one,
# run_cells boots each DIAG_REPS times round-robin, with full host traces; a cell whose first
# boot's verdict is other boots no more, and no cell starts a boot after the deadline.
cell_names=()
declare -A cell_test cell_pause cell_kernel cell_append cell_args cell_died cell_hung cell_survived cell_other cell_skipped
cell() {
    wanted "$1" || return 0
    cell_names+=("$1")
    cell_test[$1]=$2
    cell_pause[$1]=$3
    cell_kernel[$1]=$4
    cell_append[$1]=$5
    cell_args[$1]=$6
    cell_died[$1]=0
    cell_hung[$1]=0
    cell_survived[$1]=0
    cell_other[$1]=0
    cell_skipped[$1]=0
}

run_cells() {
    local n name label args verdict first
    for ((n = 1; n <= reps; n++)); do
        for name in "${cell_names[@]}"; do
            first=$(verdict_of "$out/$arch/$name/1")
            if ((n > 1)) && [[ $first == other* ]]; then
                echo "skipped, as its cell's first boot is other: $arch $name/$n" |
                    tee -a "$out/cells.txt" >>"$out/summary.txt"
                cell_skipped[$name]=$((cell_skipped[$name] + 1))
                continue
            fi
            if ! in_time "$arch $name/$n"; then
                cell_skipped[$name]=$((cell_skipped[$name] + 1))
                continue
            fi
            label=$name/$n
            read -r -a args <<<"${cell_args[$name]}"
            mkdir -p "$out/$arch/$label"
            fresh_store "$out/$arch/$label/vars.fd"
            # The whole trace of a cell's first boot; less of the others'.
            trace_tail=2000000 vcpu_tail=500000
            ((n > 1)) && trace_tail=200000 vcpu_tail=100000
            boot "$label" "$out/$arch/$label/vars.fd" "$apt_qemu" full "${cell_pause[$name]}" \
                "${cell_kernel[$name]}" "$out/$arch/stepwise-initrd.img" \
                "ignore_loglevel panic=-1 uefisettings.test=${cell_test[$name]} diag.pauses=$sync_pauses ${cell_append[$name]}" \
                "${args[@]}"
            verdict=$(verdict_of "$out/$arch/$label")
            case $verdict in
            died*) cell_died[$name]=$((cell_died[$name] + 1)) ;;
            hung*) cell_hung[$name]=$((cell_hung[$name] + 1)) ;;
            survived*) cell_survived[$name]=$((cell_survived[$name] + 1)) ;;
            *)
                cell_other[$name]=$((cell_other[$name] + 1))
                harness_fail "$arch $label: $verdict"
                ;;
            esac
        done
    done
    trace_tail=2000000 vcpu_tail=500000
    for name in "${cell_names[@]}"; do
        report_cell "$name"
    done
    cell_names=()
}

# kernel_release KERNEL: the release of a kernel image, from its path: Debian's
# boot/vmlinuz-RELEASE or lib/modules/RELEASE/vmlinuz.
kernel_release() {
    local base=${1##*/}
    if [[ $base == vmlinuz ]]; then
        base=${1%/vmlinuz}
        echo "${base##*/}"
    else
        echo "${base#vmlinuz-}"
    fi
}

# stress_round_trips DIR: the round trips that the stressor of DIR's boot made in about its
# first second, or nothing without that line.
stress_round_trips() {
    tr -d '\r' <"$1/test.log" |
        sed -n -E 's/^step [0-9.]+: stress: ([0-9]+) round trips in about a second$/\1/p' | head -n 1
}

# cell_boot_proof NAME K: why boot K of cell NAME does not show that what its verdict depends
# on took place, or nothing: the cell's kernel booted (its "Linux version" line); PTI is on
# with pti=on and off without (its "page tables isolation" line); the stressor made at least
# 1000 round trips in its first second with diag.stress; a death came after its test started
# its trigger (memslot printed its BAR; a QMP stop); QEMU's KVM_SET_SREGS2 counts exist for a
# cell with pauses, are all 0 for plain pauses, and show a write-back after a pause with a
# register read.
cell_boot_proof() {
    local name=$1 dir=$out/$arch/$1/$2 release trips count verdict after
    release=$(kernel_release "${cell_kernel[$name]}")
    # Each grep reads the file itself: grep -q at the end of a pipe exits at its first match, and
    # under pipefail the writer's SIGPIPE would make the match read as a failure.
    if ! grep -a -q -F "Linux version $release " "$dir/console.log"; then
        echo "boot $2: no 'Linux version $release' line"
        return
    fi
    if [[ " ${cell_append[$name]} " == *" pti=on "* ]]; then
        grep -a -q 'page tables isolation: .*enabled' "$dir/console.log" ||
            { echo "boot $2: no PTI line"; return; }
    elif grep -a -q 'page tables isolation: .*enabled' "$dir/console.log"; then
        echo "boot $2: PTI without pti=on"
        return
    fi
    if [[ " ${cell_append[$name]} " == *" diag.stress "* ]]; then
        trips=$(stress_round_trips "$dir")
        if [[ ! $trips =~ ^[0-9]+$ ]] || ((trips < 1000)); then
            echo "boot $2: the stressor did not run (round trips: ${trips:-no line})"
            return
        fi
    fi
    verdict=$(verdict_of "$dir")
    if [[ $verdict == died* ]]; then
        case ${cell_test[$name]} in
        memslot)
            if [[ ! $verdict =~ after\ ([0-9]+)\ deletions ]] || ((BASH_REMATCH[1] == 0)); then
                echo "boot $2: died before its test printed its BAR"
                return
            fi
            ;;
        sync)
            grep -q ': pause 1: stopped$' "$dir/qmp.log" || { echo "boot $2: died before the first pause"; return; }
            ;;
        esac
    fi
    [[ ${cell_pause[$name]} == no ]] && return
    count=missing
    [[ -f $dir/sregs2.txt ]] && count=$(<"$dir/sregs2.txt")
    if [[ ! $count =~ ^[0-9]+( [0-9]+)*$ ]]; then
        echo "boot $2: no KVM_SET_SREGS2 counts"
        return
    fi
    case ${cell_pause[$name]} in
    plain) [[ $count != *[1-9]* ]] || echo "boot $2: QEMU wrote registers back in a plain pause" ;;
    registers)
        # The periods from the first cont on: all but the first.
        if grep -q ': pause 1: resumed$' "$dir/qmp.log"; then
            after=
            [[ $count == *" "* ]] && after=${count#* }
            [[ $after == *[1-9]* ]] || echo "boot $2: no register write-back after a pause"
        fi
        ;;
    esac
}

# report_cell NAME: the counts of a cell and its class by the decision rule of the header: it
# decides only on all DIAG_REPS boots of a cell, and only if each of them proves what its
# verdict depends on (cell_boot_proof); with the KVM_SET_SREGS2 counts per running period of
# each boot of a cell with pauses, and the stressor's round trips of each of a stressed one.
report_cell() {
    local name=$1 died=${cell_died[$1]} hung=${cell_hung[$1]} survived=${cell_survived[$1]} other=${cell_other[$1]}
    local n=$((cell_died[$1] + cell_hung[$1] + cell_survived[$1] + cell_other[$1])) class proof='' details='' counts='' trips='' k count
    for ((k = 1; k <= reps; k++)); do
        [[ -f $out/$arch/$name/$k/verdict.txt ]] || continue
        [[ -z $proof ]] && proof=$(cell_boot_proof "$name" "$k")
        count=missing
        [[ -f $out/$arch/$name/$k/sregs2.txt ]] && count=$(<"$out/$arch/$name/$k/sregs2.txt")
        counts+="[$count]"
        trips+="[$(stress_round_trips "$out/$arch/$name/$k")]"
    done
    [[ ${cell_pause[$1]} != no ]] && details+="; KVM_SET_SREGS2 per running period: ${counts:-none}"
    [[ " ${cell_append[$1]} " == *" diag.stress "* ]] && details+="; stressor round trips in the first second: ${trips:-none}"
    if ((other > 0)); then
        class=harness
    elif ((n < reps)); then
        class="incomplete, $n of $reps boots"
    elif [[ -n $proof ]]; then
        class="invalid, $proof"
    elif ((died * 10 >= 8 * n)); then
        class=dies
    elif ((died * 10 <= n && died + survived == n)); then
        class=survives
    else
        class=mixed
    fi
    echo "cell $arch $name: $n boots: $died died, $hung hung, $survived survived, $other other, ${cell_skipped[$1]} skipped: $class$details" |
        tee -a "$out/cells.txt" >>"$out/summary.txt"
}

# The cells' QEMU, without the VMware backdoor port, whose handler reads the
# registers (QEMU v10.2.0 hw/i386/vmport.c:93-107), so that QEMU writes them back: openSUSE's
# and Fedora's kernels probe it (8 more KVM_SET_SREGS2 a boot here), Debian's 6.1 does not.
smp1=(-accel kvm -cpu host -smp 1 -machine vmport=off)
ivshmem='-object memory-backend-ram,id=shm,size=4M -device ivshmem-plain,memdev=shm'

# run_suite SUITE LABEL [pti]: tests/qemu/run.sh's scenarios on the architecture SUITE as CI
# runs them, through make test-e2e-qemu-SUITE, which pins the toolchain (Makefile:48-52; run.sh
# alone took the runner's default one, without i686-unknown-linux-musl, in CI run 39936216534),
# its output in LABEL.log. With pti, the QEMU of PATH is a wrapper that adds pti=on to the
# guest's kernel command line (run.sh allows a wrapper that execs QEMU) and logs each command
# line to LABEL-appends.log: run.sh's "quiet" guests print no PTI line, so each boot that
# run.sh started ("run.sh: NAME boot N: SPEC", run.sh:218, whose SPEC has no space; a failed
# boot adds "run.sh: NAME boot N: QEMU: ..." lines, run.sh:250) must have a logged command
# line ending in pti=on.
run_suite() {
    local suite=$1 label=$2 pti=${3:-} rc started lines with_pti wrapper='' qemu_bin
    in_time "$label" || return 0
    : >"$out/$label-appends.log"
    if [[ $pti == pti ]]; then
        case $suite in
        i686) qemu_bin='qemu-system-i386' ;;
        *)
            harness_fail "$label: no QEMU wrapper for $suite"
            return
            ;;
        esac
        wrapper=$(mktemp -d)
        # The wrapper's own text, with $qemu_bin filled in.
        cat >"$wrapper/$qemu_bin" <<WRAPPER
#!/bin/bash
args=()
while ((\$# > 0)); do
    if [[ \$1 == -append ]]; then
        args+=("\$1" "\$2 pti=on")
        echo "\$2 pti=on" >>"\$DIAG_APPEND_LOG"
        shift 2
    else
        args+=("\$1")
        shift
    fi
done
exec /usr/bin/$qemu_bin "\${args[@]}"
WRAPPER
        chmod +x "$wrapper/$qemu_bin"
    fi
    PATH=${wrapper:+$wrapper:}$PATH DIAG_APPEND_LOG=$out/$label-appends.log make -C "$repo" "test-e2e-qemu-$suite" \
        >"$out/$label.log" 2>&1
    rc=$?
    started=$(grep -c -E '^run.sh: [^ ]+ boot [0-9]+: [^ ]+$' "$out/$label.log")
    echo "== $label: make test-e2e-qemu-$suite exit $rc, $started boots started; $(grep -E '^run.sh: (FAILED|end)' "$out/$label.log" | tr '\n' ' ')" |
        tee -a "$out/cells.txt" >>"$out/summary.txt"
    ((started > 0)) || harness_fail "$label: run.sh started no boot, see $label.log"
    if [[ -n $wrapper ]]; then
        lines=$(grep -c . "$out/$label-appends.log")
        with_pti=$(grep -c ' pti=on$' "$out/$label-appends.log")
        echo "$label: $lines QEMU command lines, $with_pti with pti=on, for $started boots" |
            tee -a "$out/cells.txt" >>"$out/summary.txt"
        ((lines == started && with_pti == started)) || harness_fail "$label: not every boot got pti=on"
        rm -rf "$wrapper"
    fi
}

# The fourth round: c3 under memslot (DIAG_REPS boots), then run.sh's i686 suite 3 times under
# pti=on, and its aarch64 suite as it is.
if select_arch i686; then
    boot_timeout=$((90 * slow))
    cell c3-memslot memslot no "$vmlinuz" "diag.stress" "${smp1[*]} $ivshmem"
    run_cells
    boot_timeout=$((180 * slow))
fi
if [[ ${DIAG_RUN_SH:-yes} == yes ]]; then
    for n in 1 2 3; do
        run_suite i686 "run-sh-i686-pti-$n" pti
    done
    run_suite aarch64 run-sh-aarch64
fi

sudo dmesg >"$out/dmesg-after.txt" 2>&1
# However the variants above end, a diag that booted nothing has nothing to show.
((boots > 0)) || harness_fail "no boot ran"
cat "$out/summary.txt"
echo "== cells"
cat "$out/cells.txt"
if ((harness_failures > 0)); then
    echo "ci-diag-reset.sh: $harness_failures harness failures" >&2
    exit 1
fi
