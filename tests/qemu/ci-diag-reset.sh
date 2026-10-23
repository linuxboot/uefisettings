#!/bin/bash
# The runner user writes the output files; sudo only reads them.
# shellcheck disable=SC2024
# DO NOT MERGE: diagnostics for the i686 guests that reset on GitHub's AMD runners (EPYC 7763,
# 9V74 and 9V45; KVM nested under Hyper-V), fifth round. In the third (CI run 39936216534) a
# PAE vCPU whose page directory pointer table does not start a page died at its first entry
# after KVM reloaded its MMU, on a memory slot's deletion (memslot) and on QEMU's register
# write-back after a QMP stop and register read (sync): c1, Debian's 6.1, in 10 of 10 boots
# under each. The runners' KVM (Ubuntu's linux-azure) clears the guest CR3's low 12 bits at
# each NPT root load for a vCPU without CR4.PCIDE, the PAE table's address bits 5-11 among them
# (https://bugs.launchpad.net/bugs/2106673). This round tests that as the cause: c1 under
# memslot and sync, DIAG_REPS boots each, on a kvm-amd.ko built from the runners' exact source
# (ci-diag-kvm-amd.sh) as shipped ("stock", the control), then with a fix that leaves those
# bits alone in PAE paging ("poc"), then the shipped module is loaded again. If the cause is
# right, stock dies and poc survives; poc dying, or mixed, would falsify the mask as the cause;
# a poc whose VMRUN fails ("refused"), with stock not refused, would point to Hyper-V rejecting
# CR3 bits 5-11 of a PAE guest. Each boot's summary also gives the page offsets of the first
# guest page walk that faults after each root zap: the mask moves a PAE vCPU's PDPT to the
# start of its page (PDPTE[3] at offset 0x018), the fix leaves it where the guest put it.
# A cell is a guest test and kernel command line, booted round-robin with the others, each
# boot with a verdict, here with host traces of KVM's events but no kprobes (events): those of
# a full trace need BTF, which the rebuilt module lacks.
# Decision rule, per cell of DIAG_REPS boots: "dies" if at least 8 in 10 die, "survives" if at
# most 1 in 10 dies and the others end their test, else "mixed"; a boot that its timeout ends
# after its test started its trigger (memslot printed its BAR, just before its first toggle;
# sync's first QMP stop), without a reset or the end of its test, "hung", is neither; a cell
# with a boot whose VMRUN failed (KVM exit 9) is "refused" and boots no more, as that boot
# decides it (each such boot waits out its timeout); a cell cut short by the deadline is
# "incomplete", one whose boots do not show their controls (the kernel's "Linux version" line,
# PTI as asked, the stressor's round trips) "invalid"; any other boot that neither dies nor ends
# its test fails the harness.
# Writes everything to target/qemu-test/diag/.
#
# DIAG_REPS: boots per cell (default 10). DIAG_TRACE_KB: the host trace's buffer per CPU in
# KiB (default 131072). DIAG_SLOW: a factor for every boot's timeout and the deadline, for a
# run under emulation (default 1). DIAG_ONLY: the cells' boots to run, as ARCH/LABEL separated
# by commas or spaces (e.g. "i686/c1-memslot-poc"; default all).
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

# host_trace_start MODE: full (KVM, its MMU, Hyper-V's flush hypercalls and the kprobes below),
# events (the same without the kprobes) or cr (KVM's control register accesses only, for the
# CR4 that the guest kernel set). A
# flush clears what a vCPU uses only if its address space (hyperv_nested_flush_guest_mapping*:
# "address space") is the root that the vCPU loaded.
host_trace_start() {
    # An array, so that the sh -c below gets the names on one line. Task switches have no event
    # of their own (Linux v7.0 arch/x86/kvm/trace.h): kvm_exit shows them, as "reason
    # task_switch" (arch/x86/include/uapi/asm/svm.h:212).
    local events=(kvm/kvm_cr) clock name
    [[ $1 == full || $1 == events ]] && events=(kvm/kvm_entry kvm/kvm_exit kvm/kvm_userspace_exit
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
    [[ $1 == cr ]] && return 0
    if [[ $1 == full ]]; then
        for name in "${kprobes[@]}"; do
            kprobe_add "$name" && continue
            # On AMD each of them is part of the verdict; Intel lacks the svm_* ones.
            [[ $amd_host == no ]] || harness_fail "an AMD host, but no kvmdiag/$name kprobe"
        done
    fi
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
#   guest CR3 that the vCPU runs on (the VMCB's, svm.c:3606-3610; on linux-azure, only while
#   its CR3 intercepts are off), for each walk NPF after
#   the load to be set against the PDPT's place in its page.
# - mmu_reset: kvm_mmu_reset_context(vcpu), which unloads the vCPU's roots
#   (arch/x86/kvm/mmu/mmu.c:6043-6047, 6083-6092).
# - shutdown: shutdown_interception(vcpu), before it INITs the vCPU (svm.c:2081-2109), with
#   the CR3 that svm_handle_exit copied from the VMCB on this exit (svm.c:3606-3610; on
#   linux-azure, only while its CR3 intercepts are off). KVM
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
# from the tail that is kept (trace_tail lines, and for MODE full or events vcpu_tail of each
# of the VCPUS vCPU threads' own).
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
    if [[ $3 != cr ]]; then
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
            [[ $host_trace == full ]] &&
                zcat "$trace.host-kvm-trace.txt.gz" | awk '/ mmu_reset: / { n++ } END { print "host kvm_mmu_reset_context calls in the kept trace: " n + 0 }'
            echo "host first faulting guest page walk after each root zap, by offset in its page: $(walk_offsets "$trace.host-kvm-trace.txt.gz")"
            # linux-azure intercepts them after it changed the CR3 of a root load.
            zcat "$trace.host-kvm-trace.txt.gz" | awk '/ kvm_cr: cr_(read|write) 3 = / { n++ } END { print "host kvm_cr CR3 accesses in the kept trace: " n + 0 }'
            zcat "$trace.host-kvm-trace.txt.gz" |
                sed -n -E 's/.* shutdown: .*vcpu_id=([0-9]+) cr3=0x([0-9a-f]+).*/shutdown probe: vcpu \1 VMCB CR3 0x\2/p'
            # The CR4 that each vCPU's kernel set last: a CPUID mask changes it only through Linux.
            zcat "$trace.host-kvm-trace.txt.gz" |
                sed -n -E 's/.*CPU ([0-9]+)\/KVM-.*kvm_cr: cr_write 4 = (0x[0-9a-f]+).*/vCPU \1 CR4 \2/p' | awk '{last[$2] = $0} END {for (c in last) print "last " last[c]}'
        fi
        echo "verdict: $(cat "$dir/verdict.txt")"
    } >>"$out/summary.txt"
}

# walk_offsets TRACE_GZ: the offsets in their page of the first guest page walk that faults
# (PFERR_GUEST_PAGE, bit 33 of kvm_page_fault's error code) after each root zap
# (kvm_mmu_zap_all_fast) in TRACE_GZ, as 0xOFFSET:COUNT, or none. A PAE vCPU's walk starts at
# its PDPT; the error code's hex digit 8 holds bits 32-35, done in text as mawk has no strtonum.
# On SVM the error code is the #NPF's (Linux v7.0 arch/x86/kvm/svm/svm.c:1956); on VMX it is
# the EPT violation's exit qualification (vmx/vmx.c:6052), where no line counts.
walk_offsets() {
    local offsets
    offsets=$(zcat "$1" | awk '/ kvm_mmu_zap_all_fast: / { armed = 1; next }
        armed && / kvm_page_fault: / {
            code = $0; sub(/.* error_code 0x/, "", code)
            if (length(code) < 9 || substr(code, length(code) - 8, 1) !~ /[2367abef]/) next
            address = $0; sub(/.* address 0x/, "", address); sub(/ .*/, "", address)
            n[substr(address, length(address) - 2)]++
            armed = 0
        }
        END { for (o in n) print "0x" o ":" n[o] }' | sort | tr '\n' ' ')
    echo "${offsets:-none}"
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

# boot_verdict DIR TEST RC: "refused", "died", "hung", "survived" or "other", then why, for the
# boot in DIR of the guest test TEST, whose QEMU exited with RC. A guest whose VMRUN failed
# (KVM_EXIT_FAIL_ENTRY, 9: QEMU v10.2.0 prints "KVM: entry failed" and stops the VM,
# target/i386/kvm/kvm.c:6117-6133, accel/kvm/kvm-all.c:3337-3339) was refused. One that resets
# (a KVM exit 8) before the end of its test died; one that its timeout (RC 124) ended after its
# test started its trigger (memslot printed its BAR, just before its first toggle; sync's first
# QMP stop), without a reset or the end of its test, hung; one that ends its test survived if
# the test did what it should: memslot's 200 deletions of its BAR's slot, sync's pauses, a hii
# test's pass. Anything else (an unassigned BAR, a failed test, a hang before the trigger) is
# other.
# The deletions count the BAR's slot from the start: Debian's 6.1 makes 8 while it boots.
boot_verdict() {
    local dir=$1 test=$2 rc=$3 refusals resets ended bar deletes=0 resumed
    # grep -c reads to the end: grep -q would leave zcat to die of SIGPIPE (see pti_line).
    refusals=$(zcat "$dir/qemu.log.gz" | grep -a -c -E '^kvm_run_exit cpu_index [0-9]+, reason 9$')
    if ((refusals > 0)); then
        echo "refused: KVM exit 9 ($(grep -a -m 1 'KVM: entry failed' "$dir/qemu.stdout" || echo 'no QEMU message'))"
        return
    fi
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
# run_cells boots each DIAG_REPS times round-robin, with host traces of mode cell_trace (see
# host_trace_start); a cell whose first boot's verdict is other, or that had a refused boot,
# boots no more, and no cell starts a boot after the deadline.
cell_names=()
cell_trace=full
declare -A cell_test cell_pause cell_kernel cell_append cell_args cell_died cell_hung cell_survived cell_refused cell_other cell_skipped
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
    cell_refused[$1]=0
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
            if ((cell_refused[$name] > 0)); then
                echo "skipped, as its cell had a refused boot: $arch $name/$n" |
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
            boot "$label" "$out/$arch/$label/vars.fd" "$apt_qemu" "$cell_trace" "${cell_pause[$name]}" \
                "${cell_kernel[$name]}" "$out/$arch/stepwise-initrd.img" \
                "ignore_loglevel panic=-1 uefisettings.test=${cell_test[$name]} diag.pauses=$sync_pauses ${cell_append[$name]}" \
                "${args[@]}"
            verdict=$(verdict_of "$out/$arch/$label")
            case $verdict in
            died*) cell_died[$name]=$((cell_died[$name] + 1)) ;;
            hung*) cell_hung[$name]=$((cell_hung[$name] + 1)) ;;
            survived*) cell_survived[$name]=$((cell_survived[$name] + 1)) ;;
            refused*) cell_refused[$name]=$((cell_refused[$name] + 1)) ;;
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
    local name=$1 died=${cell_died[$1]} hung=${cell_hung[$1]} survived=${cell_survived[$1]} refused=${cell_refused[$1]} other=${cell_other[$1]}
    local n=$((cell_died[$1] + cell_hung[$1] + cell_survived[$1] + cell_refused[$1] + cell_other[$1])) class proof='' details='' counts='' trips='' k count
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
    elif ((refused > 0)); then
        class=refused
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
    echo "cell $arch $name: $n boots: $died died, $hung hung, $survived survived, $refused refused, $other other, ${cell_skipped[$1]} skipped: $class$details" |
        tee -a "$out/cells.txt" >>"$out/summary.txt"
}

# The cells' QEMU, without the VMware backdoor port, whose handler reads the
# registers (QEMU v10.2.0 hw/i386/vmport.c:93-107), so that QEMU writes them back: openSUSE's
# and Fedora's kernels probe it (8 more KVM_SET_SREGS2 a boot here), Debian's 6.1 does not.
smp1=(-accel kvm -cpu host -smp 1 -machine vmport=off)
ivshmem='-object memory-backend-ram,id=shm,size=4M -device ivshmem-plain,memdev=shm'

# kmod's modinfo, by its path: the runner user's PATH need not have /usr/sbin.
modinfo=/usr/sbin/modinfo

# kvm_amd_loadable: whether this runner can take kvm-amd.ko as built by ci-diag-kvm-amd.sh: the
# kernel it is for, with kvm_amd loaded, no lockdown and no signature enforcement (an unsigned
# module then loads and taints the kernel), each logged.
kvm_amd_loadable() {
    local lockdown sig_enforce
    lockdown=$(sudo cat /sys/kernel/security/lockdown 2>&1)
    sig_enforce=$(cat /sys/module/module/parameters/sig_enforce 2>&1)
    echo "kernel $(uname -r); lockdown: $lockdown; module.sig_enforce: $sig_enforce" |
        tee -a "$out/facts.txt" >>"$out/summary.txt"
    if [[ $(uname -r) != 7.0.0-1017-azure || ! -d /sys/module/kvm_amd ]]; then
        harness_fail "the kvm-amd.ko builds are for 7.0.0-1017-azure with kvm_amd loaded, not $(uname -r)"
        return 1
    fi
    if [[ $lockdown != *"[none]"* || $sig_enforce != N ]]; then
        harness_fail "this kernel may refuse an unsigned kvm-amd.ko"
        return 1
    fi
}

# kvm_amd_build: builds kvm-amd.ko as shipped and with the fix to $out/kvm-amd
# (ci-diag-kvm-amd.sh), comparing the first with the module that modprobe loads.
kvm_amd_build() {
    local shipped
    if ! shipped=$("$modinfo" -n kvm_amd 2>&1); then
        harness_fail "modinfo finds no kvm_amd: $shipped"
        return 1
    fi
    if ! TMPDIR=$repo/target/qemu-test "$here/ci-diag-kvm-amd.sh" "$repo/target/qemu-test/kvm-amd-downloads" \
        "$out/kvm-amd" "$shipped" >"$out/kvm-amd-build.log" 2>&1; then
        harness_fail "building kvm-amd.ko failed, see kvm-amd-build.log"
        return 1
    fi
    cat "$out/kvm-amd/comparison.txt" >>"$out/summary.txt"
}

# kvm_amd_params: kvm_amd's parameters as NAME=VALUE lines; some are root's only.
kvm_amd_params() {
    sudo sh -c 'cd /sys/module/kvm_amd/parameters && for p in *; do echo "$p=$(cat "$p")"; done'
}

# load_kvm_amd KO: replaces the running kvm_amd with KO, a kvm-amd.ko, or with the shipped one for
# "shipped", with the options that modprobe gives it (/etc/modprobe.d); true if the running
# module then is KO's (its srcversion), /dev/kvm is open to this user again, and, with
# dump_invalid_vmcb on again, the module has the parameters that the shipped one had
# (kvm_amd_shipped_params).
load_kvm_amd() {
    local ko=$1 options='' want running params
    if [[ -d /sys/module/kvm_amd ]] && ! sudo rmmod kvm_amd 2>>"$out/kvm-amd-load.log"; then
        harness_fail "kvm_amd: rmmod failed, see kvm-amd-load.log"
        return 1
    fi
    if [[ $ko == shipped ]]; then
        sudo modprobe kvm_amd 2>>"$out/kvm-amd-load.log"
        want=$("$modinfo" -F srcversion kvm_amd)
    else
        options=$(sudo modprobe -n -v kvm_amd | sed -n -E 's/^insmod [^ ]*\/kvm-amd\.ko[^ ]* *//p')
        # shellcheck disable=SC2086 # modprobe's options, a word each
        sudo insmod "$ko" $options 2>>"$out/kvm-amd-load.log"
        want=$("$modinfo" -F srcversion "$ko")
    fi
    running=$(cat /sys/module/kvm_amd/srcversion 2>&1)
    echo "kvm_amd: loaded ${ko#"$out/"}${options:+ with $options}: srcversion $running (want $want), taint '$(cat /sys/module/kvm_amd/taint 2>&1)'" |
        tee -a "$out/cells.txt" >>"$out/summary.txt"
    sudo dmesg | tail -n 5 >>"$out/kvm-amd-load.log"
    if [[ $running != "$want" ]]; then
        harness_fail "kvm_amd: the running module's srcversion is '$running', not $want"
        return 1
    fi
    # Unloading kvm_amd removes /dev/kvm and loading it adds the node again (kvm_exit and
    # kvm_init, Linux v7.0 virt/kvm/kvm_main.c:6547, 6583), root's only until udev applies
    # checks.yml's rule.
    sudo udevadm settle --timeout=30 2>>"$out/kvm-amd-load.log"
    if [[ ! -r /dev/kvm || ! -w /dev/kvm ]]; then
        harness_fail "kvm_amd: /dev/kvm is not open to $(id -un) after the load: $(ls -l /dev/kvm 2>&1)"
        return 1
    fi
    echo Y | sudo tee /sys/module/kvm_amd/parameters/dump_invalid_vmcb >/dev/null
    params=$(kvm_amd_params)
    if [[ $params != "$kvm_amd_shipped_params" ]]; then
        diff <(echo "$kvm_amd_shipped_params") <(echo "$params") >>"$out/kvm-amd-load.log"
        harness_fail "kvm_amd: ${ko#"$out/"} has other parameters than the shipped one, see kvm-amd-load.log"
        return 1
    fi
}

# The fifth round: c1 under memslot and sync on kvm-amd.ko as shipped (stock), then with the fix
# (poc), then the shipped module again.
if select_arch i686; then
    boot_timeout=$((90 * slow))
    cell_trace=events
    if kvm_amd_loadable && kvm_amd_build; then
        echo Y | sudo tee /sys/module/kvm_amd/parameters/dump_invalid_vmcb >/dev/null
        kvm_amd_shipped_params=$(kvm_amd_params)
        for variant in stock poc; do
            load_kvm_amd "$out/kvm-amd/$variant/kvm-amd.ko" || continue
            cell "c1-memslot-$variant" memslot no "$vmlinuz" "" "${smp1[*]} $ivshmem"
            cell "c1-sync-$variant" sync registers "$vmlinuz" "" "${smp1[*]}"
            run_cells
        done
        load_kvm_amd shipped
    fi
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
