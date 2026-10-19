#!/bin/bash
# The runner user writes the output files; sudo only reads them.
# shellcheck disable=SC2024
# DO NOT MERGE: diagnostics for the i686 guests that reset during hii_write on GitHub's AMD
# runners (EPYC 7763, 9V74 and 9V45; KVM nested under Hyper-V), second round: which layer
# fails. Boots the guests of the last tests/qemu/run.sh run of each x86 architecture, mostly
# as run.sh does (a hii boot, then the write boot, on one fresh copy of the hii scenario's
# variable store), with QEMU's KVM-exit and memory-slot tracing and a verbose guest kernel:
# - host traces (sudo) of KVM, its MMU and Hyper-V's flush hypercalls, also for -smp 1;
# - forensics: QEMU pauses on the reset instead of ending, and ci-diag-qmp.py saves every
#   vCPU's registers and guest RAM at a marker just before the first write and RAM again
#   after the reset, which ci-diag-pagewalk.py compares along the exception path;
# - writes to a memory slot without firmware: the guest toggles the memory decoding of an
#   ivshmem-plain device, so QEMU deletes and adds the slot of its BAR;
# - one write boot per guest kernel parameter or CPU feature left out.
# Writes everything to target/qemu-test/diag/.
#
# Usage: tests/qemu/ci-diag-reset.sh

set -uo pipefail

here=$(realpath "$(dirname "$0")")
repo=$(realpath "$here/../..")
out=$repo/target/qemu-test/diag
tracing=/sys/kernel/tracing
rm -rf "$out"
mkdir -p "$out"

{
    uname -a
    grep -m1 '^model name' /proc/cpuinfo
    grep -m1 '^flags' /proc/cpuinfo
    for p in /sys/module/kvm_amd/parameters/* /sys/module/kvm_intel/parameters/* \
        /sys/module/kvm/parameters/*; do
        [[ -r $p ]] && echo "$p=$(cat "$p")"
    done
    qemu-system-x86_64 --version
    dpkg-query -W -f='${Package} ${Version} ${Architecture}\n' qemu-system-x86 libc6 libglib2.0-0t64
    apt-cache policy qemu-system-x86
    sha256sum /usr/bin/qemu-system-i386 /usr/bin/qemu-system-x86_64
    python3 --version
    sudo ls "$tracing/events/hyperv" "$tracing/events/kvmmmu"
    echo "kprobe target: $(sudo grep -w svm_load_mmu_pgd "$tracing/available_filter_functions")"
} >"$out/facts.txt" 2>&1
sudo dmesg >"$out/dmesg-before.txt" 2>&1
# The host traces need sudo (GitHub's runners have it without a password); without, the
# boots run untraced and the summary says so.
host_traces=no
sudo -n true 2>>"$out/facts.txt" && [[ -d $tracing/events ]] && host_traces=yes
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

# host_trace_start MODE: full (KVM, its MMU, Hyper-V's flush hypercalls and, through a kprobe,
# each NPT root that KVM loads for a vCPU) or cr (KVM's control register accesses only, for
# the CR4 that the guest kernel set). A flush clears what a vCPU uses only if its address
# space (hyperv_nested_flush_guest_mapping*: "address space") is the root that the vCPU loaded:
# svm_load_mmu_pgd(vcpu, root_hpa, root_level), Linux v7.0 arch/x86/kvm/svm/svm.c:4442,
# called from kvm_mmu_load_pgd (arch/x86/kvm/mmu.h:148-157). No tracepoint carries the root.
host_trace_start() {
    # An array, so that the sh -c below gets the names on one line. Task switches have no event
    # of their own (Linux v7.0 arch/x86/kvm/trace.h): kvm_exit shows them, as "reason
    # task_switch" (arch/x86/include/uapi/asm/svm.h:212).
    local events=(kvm/kvm_cr)
    [[ $1 == full ]] && events=(kvm/kvm_entry kvm/kvm_exit kvm/kvm_userspace_exit
        kvm/kvm_inj_exception kvm/kvm_inj_virq kvm/kvm_emulate_insn kvm/kvm_msr kvm/kvm_cr
        kvm/kvm_page_fault kvm/kvm_mmio kvm/kvm_pio
        kvmmmu/kvm_mmu_zap_all_fast kvmmmu/kvm_mmu_spte_requested kvmmmu/handle_mmio_page_fault
        kvmmmu/mark_mmio_spte kvmmmu/fast_page_fault hyperv)
    local clock
    # 128 MiB per CPU: overwrite mode keeps each CPU's newest events only, and the attribution
    # declares a window that lost events undetermined (run 39281579400's write boots wrote
    # 0.5-1.1 million events, all kept in 64 MiB).
    # The global clock, as the attribution orders events of different threads, and so of
    # different CPUs, which the default local clock does not keep in sync (Linux v7.0
    # Documentation/trace/ftrace.rst:540-545). An event that this kernel lacks, such as
    # hyperv/* outside Hyper-V, is logged and left out.
    sudo sh -c "
        echo 0 >$tracing/tracing_on
        echo >$tracing/trace
        echo global >$tracing/trace_clock
        echo 1 >$tracing/options/overwrite
        echo 131072 >$tracing/buffer_size_kb
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
    load_mmu_pgd_kprobe add
    flush_events=$(events_enabled hyperv/hyperv_nested_flush_guest_mapping hyperv/hyperv_nested_flush_guest_mapping_range)
    [[ $(events_enabled kvm/kvm_entry kvm/kvm_exit kvmmmu/kvm_mmu_zap_all_fast) == traced ]] ||
        harness_fail "KVM's entry, exit or root zap events are not traced"
    [[ $kprobe_placed == yes ]] && events_enabled kvmdiag/load_mmu_pgd >/dev/null
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

# load_mmu_pgd_kprobe add|remove: the kprobe of host_trace_start, with each fetch syntax
# tried in turn and every refusal logged; without it, the root stays undetermined.
kprobe_placed=no
load_mmu_pgd_kprobe() {
    local fetch remaining
    if [[ $1 == remove ]]; then
        [[ $kprobe_placed == yes ]] || return 0
        sudo sh -c "echo 0 >$tracing/events/kvmdiag/load_mmu_pgd/enable; echo -:kvmdiag/load_mmu_pgd >>$tracing/kprobe_events" \
            >>"$out/host-trace.log" 2>&1 || harness_fail "removing the svm_load_mmu_pgd kprobe failed"
        kprobe_placed=no
        remaining=$(sudo cat "$tracing/kprobe_events")
        echo "kprobe_events after removal: ${remaining:-empty}" >>"$out/host-trace.log"
        [[ $remaining != *kvmdiag/load_mmu_pgd* ]] || harness_fail "the svm_load_mmu_pgd kprobe is still registered"
        return
    fi
    # shellcheck disable=SC2016 # kprobe_events fetch arguments, not shell expansions
    for fetch in 'root_hpa=$arg2:x64 root_level=$arg3:s32' 'root_hpa=%si:x64 root_level=%dx:s32'; do
        if sudo sh -c "echo 'p:kvmdiag/load_mmu_pgd svm_load_mmu_pgd $fetch' >>$tracing/kprobe_events" \
            2>>"$out/host-trace.log"; then
            kprobe_placed=yes
            sudo sh -c "echo 1 >$tracing/events/kvmdiag/load_mmu_pgd/enable" >>"$out/host-trace.log" 2>&1 &&
                echo "kprobe svm_load_mmu_pgd: $fetch" >>"$out/host-trace.log" && return
        fi
        echo "kprobe svm_load_mmu_pgd refused: $fetch: $(sudo tail -n 2 "$tracing/error_log" | tr '\n' ' ')" \
            >>"$out/host-trace.log"
    done
}

# host_trace_stop LABEL DIR MODE VCPUS: saves the trace as LABEL's and, for MODE full, writes
# ci-diag-attribution.py's verdict to DIR/attribution.txt, from the whole trace rather than
# from the tail that is kept, and keeps each of the VCPUS vCPU threads' own tail.
host_trace_stop() {
    local trace=$out/$1.host-kvm-trace.txt n tid
    sudo sh -c "echo 0 >$tracing/tracing_on; cat $tracing/trace" >"$trace" 2>>"$out/host-trace.log"
    load_mmu_pgd_kprobe remove
    grep -a -q -E 'kvm_(exit|cr):' "$trace" || harness_fail "$1: host trace without KVM events"
    if [[ $3 == full ]]; then
        python3 "$here/ci-diag-attribution.py" --probe-log "$out/host-trace.log" --dmesg "$out/dmesg-before.txt" \
            --flush-events "$flush_events" "$trace" >"$2/attribution.txt" 2>&1 ||
            harness_fail "$1: ci-diag-attribution.py failed, see $2/attribution.txt"
    fi
    tail -n 2000000 "$trace" | gzip >"$trace.gz" || harness_fail "$1: compressing the host trace failed"
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
            grep -a -E -- "-$tid +\[[0-9]+\]" "$trace" | tail -n 500000 |
                gzip >"$out/$1.host-kvm-trace.vcpu$n.txt.gz" || harness_fail "$1: compressing vCPU $n's trace failed"
            require "$out/$1.host-kvm-trace.vcpu$n.txt.gz"
        done
    fi
    rm -f "$trace"
}

# select_arch ARCH: run.sh's table, for the architectures that run under KVM.
select_arch() {
    arch=$1
    case $arch in
    x86_64)
        qemu_name='qemu-system-x86_64'
        firmware=usr/share/OVMF/OVMF_CODE_4M.fd
        firmware_vars=usr/share/OVMF/OVMF_VARS_4M.fd
        vmlinuz_pattern='lib/modules/*/vmlinuz'
        ;;
    i686)
        qemu_name='qemu-system-i386'
        firmware=usr/share/OVMF/OVMF32_CODE_4M.fd
        firmware_vars=usr/share/OVMF/OVMF32_VARS_4M.fd
        vmlinuz_pattern='boot/vmlinuz-*'
        ;;
    esac
    local runs=()
    mapfile -t runs < <(compgen -G "$repo/target/qemu-test/$arch/2*/hii/vars.json" | sort)
    if ((${#runs[@]} == 0)); then
        harness_fail "no tests/qemu/run.sh $arch run with a hii scenario"
        return 1
    fi
    run=$(dirname "$(dirname "${runs[-1]}")")
    hii_initrd=$run/hii/initrd.img
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
    # The kernel's symbols, for the addresses in the traces and the RAM dumps (Debian's i686
    # package has them, Fedora's x86_64 one does not).
    if compgen -G "$guest/boot/System.map-*" >/dev/null; then
        cp "$guest"/boot/System.map-* "$out/$arch/binaries/" || harness_fail "$arch: copying System.map failed"
    else
        echo "no System.map in $guest/boot" >>"$out/$arch/facts.txt"
    fi
    stepwise_initrd "$out/$arch"
}

# stepwise_initrd DIR: DIR/stepwise-initrd.img, a guest that marks each step of a write on
# its terminal before it takes it: writes without uefisettings first (a new variable and an
# update of Timeout, no chattr; then, if busybox has chattr, the ioctl alone and an update of
# DriverSample's variable), then uefisettings with debug logs for its write path; with
# diag.cpu=N, every step and the unbound workqueues (efi_rts_wq, which makes the runtime
# calls) run on CPU N; with diag.pause, it prints the marker of ci-diag-qmp.py and sleeps
# before the first write. Output goes straight to the terminal: a reset loses anything
# buffered. And DIR/stepwise-initrd.img's tests/memslot toggles the memory decoding of the
# ivshmem-plain device, so QEMU deletes and adds the memory slot of its BAR, no firmware
# involved.
stepwise_initrd() {
    rm -rf "$1/stepwise-initramfs"
    cp -r "$run/initramfs" "$1/stepwise-initramfs"
    cat >"$1/stepwise-initramfs/tests/stepwise" <<'EOF'
#!/bin/busybox sh
v=/sys/firmware/efi/efivars
driver_sample=$v/MyIfrNVData-a04a27f4-df00-4d42-b552-39511302113d
new=$v/ExecutorOneDiag-6a1e0f3c-2b7d-4c55-9e1a-0d3f2c4b5a69
step() {
    read -r uptime _ < /proc/uptime
    echo "step $uptime: $*"
    sync
}
cpu=
pause=
read -r cmdline < /proc/cmdline
for parameter in $cmdline; do
    case $parameter in
    diag.cpu=*) cpu=${parameter#*=} ;;
    diag.pause) pause=yes ;;
    esac
done
on_cpu() {
    if [ -n "$cpu" ]; then busybox taskset "$((1 << cpu))" "$@"; else "$@"; fi
}
if [ -n "$cpu" ]; then
    printf '%x\n' "$((1 << cpu))" > /sys/devices/virtual/workqueue/cpumask
    step "pinned to CPU $cpu; unbound workqueue cpumask $(cat /sys/devices/virtual/workqueue/cpumask)"
fi
step "efivarfs: $(ls $v | wc -l) variables; busybox chattr applets: $(busybox --list | grep -c -x -e chattr -e lsattr)"
step "$(grep -m 1 '^address sizes' /proc/cpuinfo)"
step "read the DriverSample variable"
hexdump -C "$driver_sample" | head -2
if [ -n "$pause" ]; then
    echo "diag: pause"
    sleep 3
fi
step "create a new 4-byte variable through efivarfs (SetVariable, no chattr)"
printf '\007\000\000\000ABCD' > /tmp/new
on_cpu dd if=/tmp/new of="$new" bs=8 count=1 2>&1
step "created: $(hexdump -C "$new" | head -1)"
# efivarfs makes the variables that it does not know immutable, a new one too, but not the
# global ones such as Timeout: an update without chattr.
timeout_var=$v/Timeout-8be4df61-93ca-11d2-aa0d-00e098032b8c
# efivarfs files do not seek, so hexdump reads them from a pipe.
old=0
if [ -e "$timeout_var" ]; then
    set -- $(cat "$timeout_var" | hexdump -s 4 -n 2 -e '2/1 "%u "')
    [ $# = 2 ] && old=$(($1 + 256 * $2))
fi
new_timeout=$(((old + 1) % 65536))
step "update Timeout $old -> $new_timeout through efivarfs dd (SetVariable update, no chattr)"
printf "\\007\\000\\000\\000\\$(printf %o $((new_timeout % 256)))\\$(printf %o $((new_timeout / 256)))" > /tmp/timeout
on_cpu dd if=/tmp/timeout of="$timeout_var" bs=6 count=1 2>&1
step "updated: $(hexdump -C "$timeout_var" | head -1)"
if busybox --list | grep -q -x chattr; then
    step "busybox chattr -i on the DriverSample variable (ioctl only)"
    busybox chattr -i "$driver_sample" 2>&1
    step "flags: $(busybox lsattr "$driver_sample" 2>&1)"
    cp "$driver_sample" /tmp/ds
    old=$(hexdump -s 96 -n 1 -e '1/1 "%u"' /tmp/ds)
    case $old in
    0 | 1)
        step "update the check box byte $old -> $((1 - old)) through efivarfs dd (no uefisettings)"
        printf "\\$((1 - old))" | dd of=/tmp/ds bs=1 seek=96 conv=notrunc 2>&1
        dd if=/tmp/ds of="$driver_sample" bs="$(wc -c < /tmp/ds)" count=1 2>&1
        step "updated: $(cat "$driver_sample" | hexdump -s 96 -n 1 -e '1/1 "%u"')"
        ;;
    *) step "check box byte is '$old', not 0 or 1: no dd update" ;;
    esac
fi
step "uefisettings identify"
on_cpu /bin/uefisettings identify --json 2>&1
step "uefisettings hii extract-db"
on_cpu /bin/uefisettings hii extract-db /tmp/hiidb.bin 2>&1
step "uefisettings set the check box to 0 (chattr + SetVariable)"
on_cpu /bin/uefisettings set "Activate this check box" 0 --json 2>&1
step "uefisettings set done"
hexdump -C "$driver_sample" | head -8
step "end"
EOF
    cat >"$1/stepwise-initramfs/tests/memslot" <<'EOF'
#!/bin/busybox sh
step() {
    read -r uptime _ < /proc/uptime
    echo "step $uptime: $*"
    sync
}
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
    # dd's own messages, but not its errors, filtered out; memslot_verdict catches a write
    # that does not take.
    printf "\\$(printf %o $off)" | dd of="$dev/config" bs=1 seek=4 count=1 conv=notrunc 2>&1 | grep -v -e 'records in' -e 'records out'
    printf "\\$(printf %o $on)" | dd of="$dev/config" bs=1 seek=4 count=1 conv=notrunc 2>&1 | grep -v -e 'records in' -e 'records out'
    i=$((i + 1))
    [ $((i % 50)) = 0 ] && step "toggled the memory decoding $i times"
done
step "end"
EOF
    chmod +x "$1/stepwise-initramfs/tests/stepwise" "$1/stepwise-initramfs/tests/memslot"
    (cd "$1/stepwise-initramfs" && find . | cpio --create --format=newc --quiet) \
        >"$1/stepwise-initrd.img"
}

# fresh_store FILE: the hii scenario's variable store, as run.sh seeds it.
fresh_store() {
    virt-fw-vars --input "$guest/$firmware_vars" --set-json "$run/hii/vars.json" \
        --output "$1" 2>>"$out/virt-fw-vars.log"
}

# boot LABEL STORE QEMU HOST_TRACE FORENSICS INITRD APPEND QEMU-ARG...: one guest boot.
# HOST_TRACE is no or a mode of host_trace_start. With FORENSICS=yes, QEMU pauses on a reset
# instead of ending, its test terminal and QMP are sockets that ci-diag-qmp.py serves, and
# ci-diag-pagewalk.py reports on the RAM dumps, walking also the RIPs of the host trace's
# shutdown exits.
boot() {
    local label=$1 store=$2 qemu=$3 host_trace=$4 forensics=$5 initrd=$6 append=$7
    local rc start end dir=$out/$arch/$label sockets supervisor='' terminal control
    local trace=$out/$arch-${label//\//-} rips guest_maxphyaddr
    local traces=trace:kvm_run_exit,trace:kvm_run_exit_system_event,trace:qemu_system_shutdown_request,trace:qemu_system_powerdown_request,trace:kvm_set_user_memory
    shift 7
    mkdir -p "$dir"
    boots=$((boots + 1))
    if [[ $forensics == yes ]]; then
        # Unix socket paths have a limit of 108 bytes, which $dir can pass.
        sockets=$(mktemp -d /tmp/diag.XXXXXX)
        terminal=(-chardev "socket,id=tty,path=$sockets/terminal,server=on,wait=on")
        control=(-action 'reboot=shutdown,shutdown=pause' -qmp "unix:$sockets/qmp,server=on,wait=off")
        python3 "$here/ci-diag-qmp.py" --terminal-socket "$sockets/terminal" \
            --qmp-socket "$sockets/qmp" --terminal-log "$dir/test.log" --out "$dir" \
            --ram-mib 1024 >"$dir/qmp.log" 2>&1 &
        supervisor=$!
    else
        terminal=(-chardev "file,id=tty,path=$dir/test.log")
        control=(-no-reboot)
    fi
    [[ $host_traces == no ]] && host_trace=no
    [[ $host_trace != no ]] && host_trace_start "$host_trace"
    start=$(date +%s.%N)
    # debug-threads names the vCPU threads (CPU N/KVM) for the host trace's lines.
    timeout --foreground -k 10 180 "$qemu" -machine q35 "$@" -name debug-threads=on \
        -nodefaults -no-user-config "${control[@]}" -display none -sandbox on -m 1024 \
        -drive "if=pflash,format=raw,unit=0,readonly=on,file=$guest/$firmware" \
        -drive "if=pflash,format=raw,unit=1,file=$store" \
        -drive "if=virtio,format=raw,readonly=on,file=fat:$run/esp" \
        -kernel "$vmlinuz" -initrd "$initrd" -append "console=ttyS0 uefisettings.tty=ttyS1 $append" \
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
        forensics_reports "$dir" "$trace"
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
    {
        echo "== $arch $label: $qemu -machine q35 $* -append ... $append; store $store"
        echo "firmware $guest/$firmware; kernel $vmlinuz; initrd $initrd"
        echo "exit $rc after $(awk -v a="$start" -v b="$end" 'BEGIN { printf "%.1f", b - a }') s"
        tr -d '\r' <"$dir/console.log" | grep -a 'uefisettings-qemu-test: exit' || echo "no exit line"
        tr -d '\r' <"$dir/test.log" | grep -a -E '^test result|^step ' | tail -4 || true
        # With -no-reboot, a reset (triple fault: KVM exit 8; reset port: exit 2) logs no
        # shutdown request; a guest poweroff logs reason=6.
        zcat "$dir/qemu.log.gz" | grep -a -E 'qemu_system_(shutdown|powerdown)_request|kvm_run_exit_system_event' | tail -3
        echo "memory slot changes: $(zcat "$dir/qemu.log.gz" | grep -a -c '^kvm_set_user_memory')"
        echo "last kvm_run_exit lines:"
        zcat "$dir/qemu.log.gz" | grep -a kvm_run_exit | tail -4
        [[ -f $dir/shutdown-reason.txt ]] && echo "forensics: shutdown $(cat "$dir/shutdown-reason.txt")"
        [[ -f $dir/pagewalk.txt ]] && grep -a -c DIFFERS "$dir/pagewalk.txt" | sed 's/^/forensics: structures that differ: /'
        [[ -f $dir/attribution.txt ]] && cat "$dir/attribution.txt"
        # The CR4 that each vCPU's kernel set last: a CPUID mask changes it only through Linux.
        [[ -f $trace.host-kvm-trace.txt.gz ]] && zcat "$trace.host-kvm-trace.txt.gz" |
            sed -n -E 's/.*CPU ([0-9]+)\/KVM-.*kvm_cr: cr_write 4 = (0x[0-9a-f]+).*/vCPU \1 CR4 \2/p' | awk '{last[$2] = $0} END {for (c in last) print "last " last[c]}'
        [[ $label == memslot* ]] && memslot_verdict "$dir"
    } >>"$out/summary.txt"
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

# forensics_reports DIR TRACE: checks what ci-diag-qmp.py saved for the boot in DIR, runs
# ci-diag-pagewalk.py on it (walking also the RIPs of TRACE's shutdown exits) and compresses
# the RAM dumps.
forensics_reports() {
    local dir=$1 trace=$2 rips guest_maxphyaddr dump
    require "$dir/qmp.log" "$dir/shutdown-reason.txt"
    tr -d '\r' <"$dir/test.log" | grep -a -q 'diag: pause' &&
        require "$dir/registers-before.txt" "$dir/ram-before.bin"
    [[ -f $dir/shutdown-reason.txt && $(<"$dir/shutdown-reason.txt") == guest-reset ]] &&
        require "$dir/ram-after.bin"
    if [[ -f $dir/registers-before.txt && -f $dir/ram-before.bin ]]; then
        rips=()
        [[ -f $trace.host-kvm-trace.txt.gz ]] && mapfile -t rips < <(zcat "$trace.host-kvm-trace.txt.gz" |
            sed -n -E 's/.*kvm_exit: vcpu ([0-9]+) reason shutdown rip (0x[0-9a-f]+).*/--address=shutdown-rip-vcpu\1=\2/p')
        # The guest's width, which QEMU sets to 36 bits for a CPU without long mode
        # (QEMU v10.2.0 target/i386/cpu.c:9475-9479), else the host's.
        guest_maxphyaddr=$(tr -d '\r' <"$dir/test.log" |
            sed -n -E 's/.*address sizes\s*: ([0-9]+) bits physical.*/\1/p' | head -n 1)
        python3 "$here/ci-diag-pagewalk.py" --maxphyaddr "${guest_maxphyaddr:-$host_maxphyaddr}" "${rips[@]}" \
            "$dir/registers-before.txt" "$dir"/ram-*.bin >"$dir/pagewalk.txt" 2>&1 ||
            harness_fail "$dir: ci-diag-pagewalk.py failed, see pagewalk.txt"
    fi
    for dump in "$dir"/ram-before.bin "$dir"/ram-after.bin; do
        [[ -f $dump ]] || continue
        gzip -1 "$dump" || harness_fail "$dir: gzip of $dump failed"
        require "$dump.gz"
    done
}

# pair LABEL QEMU HOST_TRACE FORENSICS INITRD APPEND QEMU-ARG...: a hii boot and then the
# given boot on one fresh store, as run.sh boots the hii scenario.
pair() {
    local label=$1 qemu=$2 host_trace=$3 forensics=$4 initrd=$5 append=$6
    shift 6
    mkdir -p "$out/$arch/$label"
    fresh_store "$out/$arch/$label/vars.fd"
    boot "$label/1-hii" "$out/$arch/$label/vars.fd" "$qemu" no no "$hii_initrd" \
        "uefisettings.test=hii panic=-1" "$@"
    boot "$label/2-write" "$out/$arch/$label/vars.fd" "$qemu" "$host_trace" "$forensics" \
        "$initrd" "$append" "$@"
}

# memslot_verdict DIR: whether DIR's tests/memslot boot changed memory slots at all: its BAR 2
# needs an address, and each of the 200 toggles a deletion of the BAR's slot.
memslot_verdict() {
    local bar deletes
    bar=$(tr -d '\r' <"$1/test.log" | sed -n -E 's/.*, BAR 2 (0x[0-9a-f]+) .*/\1/p' | head -n 1)
    deletes=0
    # QEMU's trace prints the address without the resource file's leading zeros.
    [[ -n $bar ]] && bar=$(printf '0x%x' "$bar")
    [[ -n $bar ]] && ((bar != 0)) && deletes=$(zcat "$1/qemu.log.gz" |
        grep -a -c -E "^kvm_set_user_memory AddrSpace#0 .* gpa=$bar size=0x0 ")
    if [[ -n $bar ]] && ((bar != 0 && deletes >= 200)); then
        echo "memslot: valid, $deletes deletions of the slot at BAR 2 $bar"
    else
        harness_fail "memslot $1: vacuous: BAR 2 '${bar:-none}', $deletes deletions of its slot"
    fi
}

# memslot LABEL HOST_TRACE QEMU-ARG...: one boot of tests/memslot, which toggles the memory
# decoding of an ivshmem-plain device with a 4 MiB RAM BAR.
memslot() {
    local label=$1 host_trace=$2
    shift 2
    mkdir -p "$out/$arch/$label"
    fresh_store "$out/$arch/$label/vars.fd"
    boot "$label" "$out/$arch/$label/vars.fd" "$apt_qemu" "$host_trace" no \
        "$out/$arch/stepwise-initrd.img" "ignore_loglevel panic=-1 uefisettings.test=memslot" "$@" \
        -object memory-backend-ram,id=shm,size=4M -device ivshmem-plain,memdev=shm
}

write="ignore_loglevel efi=debug uefisettings.test=hii_write uefisettings.filter=--nocapture panic=-1"
stepwise="ignore_loglevel panic=-1 uefisettings.test=stepwise RUST_LOG=info,uefisettings::chattr=debug,uefisettings::hii::efivarfs=debug,uefisettings::hii::extract=debug"
kvm=(-accel kvm -cpu host -smp 2)
# The physical address width for a guest that does not print its own: -cpu host with long
# mode passes the host's through.
host_maxphyaddr=$(sed -n -E 's/^address sizes\s*: ([0-9]+) bits physical.*/\1/p' /proc/cpuinfo | head -n 1)

if select_arch i686; then
    stepwise_img=$out/$arch/stepwise-initrd.img
    pair base-1 "$apt_qemu" full no "$hii_initrd" "$write" "${kvm[@]}"
    pair smp1 "$apt_qemu" full no "$hii_initrd" "$write" -accel kvm -cpu host -smp 1
    pair forensics-smp1 "$apt_qemu" full yes "$stepwise_img" "$stepwise diag.pause" -accel kvm -cpu host -smp 1
    pair forensics-smp2 "$apt_qemu" full yes "$stepwise_img" "$stepwise diag.pause" "${kvm[@]}"
    memslot memslot full "${kvm[@]}"
    memslot memslot-smp1 no -accel kvm -cpu host -smp 1
    # pti=on, as AMD needs no page table isolation, so the guest runs without it.
    for parameter in pti=on idle=poll nohz=off; do
        pair "param-$parameter" "$apt_qemu" cr no "$hii_initrd" "$write $parameter" "${kvm[@]}"
    done
    # The CR4 bits that Linux sets and the firmware does not: PSE, PGE, UMIP, FSGSBASE,
    # OSXSAVE, SMEP and SMAP.
    for features in -pge -smep,-smap -pse -umip -fsgsbase -xsave; do
        # No comma in the label, which ends up in paths in QEMU options.
        pair "cpu${features//,/}" "$apt_qemu" cr no "$hii_initrd" "$write" -accel kvm -cpu "host,$features" -smp 2
    done
    pair smm-off "$apt_qemu" cr no "$hii_initrd" "$write" "${kvm[@]}" -machine smm=off
fi
if select_arch x86_64; then
    pair base-1 "$apt_qemu" no no "$hii_initrd" "$write" "${kvm[@]}"
    memslot memslot no "${kvm[@]}"
fi

sudo dmesg >"$out/dmesg-after.txt" 2>&1
# However the variants above end, a diag that booted nothing has nothing to show.
((boots > 0)) || harness_fail "no boot ran"
cat "$out/summary.txt"
if ((harness_failures > 0)); then
    echo "ci-diag-reset.sh: $harness_failures harness failures" >&2
    exit 1
fi
