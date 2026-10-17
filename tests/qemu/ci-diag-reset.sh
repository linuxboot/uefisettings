#!/bin/bash
# The runner user writes the output files; sudo only reads them.
# shellcheck disable=SC2024
# DO NOT MERGE: diagnostics for the guests that reset during hii_write on GitHub's AMD
# runners (i686 on EPYC 7763 and 9V74, KVM nested under Azure). Boots the guests of the last
# tests/qemu/run.sh run of each x86 architecture in several QEMU configurations, mostly as
# run.sh does (a hii boot, then the write boot, on one fresh copy of the hii scenario's
# variable store), with QEMU's KVM-exit tracing and a verbose guest kernel; some boots also
# record the host's KVM tracepoints (sudo). Writes everything to target/qemu-test/diag/.
#
# Usage: tests/qemu/ci-diag-reset.sh

set -uo pipefail

here=$(realpath "$(dirname "$0")")
repo=$(realpath "$here/../..")
out=$repo/target/qemu-test/diag
tracing=/sys/kernel/tracing
rm -rf "$out"
mkdir -p "$out"

# Ubuntu's plain amd64 build of the QEMU that apt installs as its amd64v3 build here, for an
# A/B of the two builds (sha256 from resolute-updates main binary-amd64 Packages).
plain_deb='qemu-system-x86_10.2.1+ds-1ubuntu3.2_amd64.deb'
plain_sha256=46bfa5208c570f47d380bc68ff3988684dd016c629b75260776f469a67d7e116
curl --fail --silent --show-error --proto =https --proto-redir =https --retry 3 \
    --output "$out/$plain_deb" "https://archive.ubuntu.com/ubuntu/pool/main/q/qemu/$plain_deb" &&
    echo "$plain_sha256  $out/$plain_deb" | sha256sum --check --strict &&
    dpkg-deb -x "$out/$plain_deb" "$out/qemu-plain" >"$out/qemu-plain.log" 2>&1
rm -f "$out/$plain_deb"

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
    sha256sum /usr/bin/qemu-system-i386 /usr/bin/qemu-system-x86_64 \
        "$out"/qemu-plain/usr/bin/qemu-system-{i386,x86_64}
} >"$out/facts.txt" 2>&1
sudo dmesg >"$out/dmesg-before.txt" 2>&1
# Dumps the VMCB to dmesg if a VMRUN fails.
echo Y | sudo tee /sys/module/kvm_amd/parameters/dump_invalid_vmcb >/dev/null 2>&1

host_trace_start() {
    sudo sh -c "
        echo 0 >$tracing/tracing_on
        echo >$tracing/trace
        echo 1 >$tracing/options/overwrite
        echo 65536 >$tracing/buffer_size_kb
        echo 4096 >$tracing/saved_cmdlines_size
        for e in kvm_entry kvm_exit kvm_userspace_exit kvm_inj_exception kvm_inj_virq \
            kvm_emulate_insn kvm_msr kvm_cr kvm_page_fault kvm_mmio kvm_pio kvm_task_switch; do
            echo 1 >$tracing/events/kvm/\$e/enable
        done
        echo 1 >$tracing/tracing_on" >>"$out/host-trace.log" 2>&1
}

host_trace_stop() {
    local trace=$out/$1.host-kvm-trace.txt n tid
    sudo sh -c "echo 0 >$tracing/tracing_on; cat $tracing/trace" >"$trace" 2>>"$out/host-trace.log"
    tail -n 2000000 "$trace" | gzip >"$trace.gz"
    # Each vCPU thread's own tail too, which the other's lines cannot push out. The thread is
    # the one of the vCPU's kvm_exit lines, by its id, which a line has even when its name is
    # not known ("<...>"); kvm_inj_exception and others have no vCPU field.
    for n in 0 1; do
        tid=$(grep -a -E "kvm_exit: vcpu $n " "$trace" | tail -n 1 |
            sed -E 's/^.*-([0-9]+) +\[[0-9]+\].*$/\1/')
        [[ -n $tid ]] &&
            grep -a -E -- "-$tid +\[[0-9]+\]" "$trace" | tail -n 500000 |
            gzip >"$out/$1.host-kvm-trace.vcpu$n.txt.gz"
    done
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
    local runs
    mapfile -t runs < <(compgen -G "$repo/target/qemu-test/$arch/2*/hii/vars.json" | sort)
    if ((${#runs[@]} == 0)); then
        echo "no tests/qemu/run.sh $arch run with a hii scenario" >>"$out/summary.txt"
        return 1
    fi
    run=$(dirname "$(dirname "${runs[-1]}")")
    hii_initrd=$run/hii/initrd.img
    guest=$repo/target/qemu-test/$arch/guest
    vmlinuz=$guest/$(cd "$guest" && compgen -G "$vmlinuz_pattern")
    apt_qemu=/usr/bin/$qemu_name
    plain_qemu=$out/qemu-plain/usr/bin/$qemu_name
    mkdir -p "$out/$arch/binaries"
    {
        echo "run $run"
        sha256sum "$guest/$firmware" "$guest/$firmware_vars" "$vmlinuz" "$run"/esp/*.efi \
            "$run"/initramfs/bin/* "$run"/initramfs/tests/*
    } >"$out/$arch/facts.txt" 2>&1
    cp "$run"/esp/*.efi "$run/initramfs/bin/uefisettings" "$run"/initramfs/tests/* \
        "$out/$arch/binaries/"
    stepwise_initrd "$out/$arch"
}

# stepwise_initrd DIR: DIR/stepwise-initrd.img, a guest that marks each step of a write on
# its terminal before it takes it: writes without uefisettings first (a new variable and an
# update of Timeout, no chattr; then, if busybox has chattr, the ioctl alone and an update of
# DriverSample's variable), then uefisettings with debug logs for its write path; with
# diag.cpu=N, every step and the unbound workqueues (efi_rts_wq, which makes the runtime
# calls) run on CPU N. Output goes straight to the terminal: a reset loses anything buffered.
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
read -r cmdline < /proc/cmdline
for parameter in $cmdline; do
    case $parameter in diag.cpu=*) cpu=${parameter#*=} ;; esac
done
on_cpu() {
    if [ -n "$cpu" ]; then busybox taskset "$((1 << cpu))" "$@"; else "$@"; fi
}
if [ -n "$cpu" ]; then
    printf '%x\n' "$((1 << cpu))" > /sys/devices/virtual/workqueue/cpumask
    step "pinned to CPU $cpu; unbound workqueue cpumask $(cat /sys/devices/virtual/workqueue/cpumask)"
fi
step "efivarfs: $(ls $v | wc -l) variables; busybox chattr applets: $(busybox --list | grep -c -x -e chattr -e lsattr)"
step "read the DriverSample variable"
hexdump -C "$driver_sample" | head -2
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
    chmod +x "$1/stepwise-initramfs/tests/stepwise"
    (cd "$1/stepwise-initramfs" && find . | cpio --create --format=newc --quiet) \
        >"$1/stepwise-initrd.img"
}

# fresh_store FILE: the hii scenario's variable store, as run.sh seeds it.
fresh_store() {
    virt-fw-vars --input "$guest/$firmware_vars" --set-json "$run/hii/vars.json" \
        --output "$1" 2>>"$out/virt-fw-vars.log"
}

# boot LABEL STORE QEMU HOST_TRACE PFLASH_TRACE INITRD APPEND QEMU-ARG...: one guest boot.
boot() {
    local label=$1 store=$2 qemu=$3 host_trace=$4 pflash_trace=$5 initrd=$6 append=$7
    local rc start end dir=$out/$arch/$label
    local traces=trace:kvm_run_exit,trace:kvm_run_exit_system_event,trace:qemu_system_shutdown_request,trace:qemu_system_powerdown_request
    shift 7
    [[ $pflash_trace == yes ]] &&
        traces+=,trace:pflash_write,trace:pflash_write_start,trace:pflash_mode_read_array,trace:kvm_set_user_memory
    mkdir -p "$dir"
    [[ $host_trace == yes ]] && host_trace_start
    start=$(date +%s.%N)
    # debug-threads names the vCPU threads (CPU N/KVM) for the host trace's lines.
    timeout --foreground -k 10 90 "$qemu" -machine q35 "$@" -name debug-threads=on \
        -nodefaults -no-user-config -no-reboot -display none -sandbox on -m 1024 \
        -drive "if=pflash,format=raw,unit=0,readonly=on,file=$guest/$firmware" \
        -drive "if=pflash,format=raw,unit=1,file=$store" \
        -drive "if=virtio,format=raw,readonly=on,file=fat:$run/esp" \
        -kernel "$vmlinuz" -initrd "$initrd" -append "console=ttyS0 uefisettings.tty=ttyS1 $append" \
        -serial "file:$dir/console.log" \
        -chardev "file,id=tty,path=$dir/test.log" -serial chardev:tty \
        -d "guest_errors,unimp,$traces" -D "$dir/qemu.log" </dev/null >"$dir/qemu.stdout" 2>&1
    rc=$?
    end=$(date +%s.%N)
    [[ $host_trace == yes ]] && host_trace_stop "$arch-${label//\//-}"
    gzip "$dir/qemu.log"
    {
        echo "== $arch $label: $qemu -machine q35 $* -append ... $append; store $store"
        echo "firmware $guest/$firmware; kernel $vmlinuz; initrd $initrd"
        echo "exit $rc after $(awk -v a="$start" -v b="$end" 'BEGIN { printf "%.1f", b - a }') s"
        tr -d '\r' <"$dir/console.log" | grep -a 'uefisettings-qemu-test: exit' || echo "no exit line"
        tr -d '\r' <"$dir/test.log" | grep -a -E '^test result|^step ' | tail -4 || true
        # Whether the kernel writes SPEC_CTRL (IBRS) or PRED_CMD (IBPB) around firmware calls.
        tr -d '\r' <"$dir/console.log" | grep -a -E 'Spectre V2|Speculation|RETBleed|IBRS|IBPB' | head -6 || true
        # With -no-reboot, a reset (triple fault: KVM exit 8; reset port: exit 2) logs no
        # shutdown request; a guest poweroff logs reason=6.
        zcat "$dir/qemu.log.gz" | grep -a -E 'qemu_system_(shutdown|powerdown)_request|kvm_run_exit_system_event' | tail -3
        echo "last kvm_run_exit lines:"
        zcat "$dir/qemu.log.gz" | grep -a kvm_run_exit | tail -4
    } >>"$out/summary.txt"
}

# pair LABEL QEMU HOST_TRACE PFLASH_TRACE INITRD APPEND QEMU-ARG...: a hii boot and then the
# given boot on one fresh store, as run.sh boots the hii scenario.
pair() {
    local label=$1 qemu=$2 host_trace=$3 pflash_trace=$4 initrd=$5 append=$6
    shift 6
    mkdir -p "$out/$arch/$label"
    fresh_store "$out/$arch/$label/vars.fd"
    boot "$label/1-hii" "$out/$arch/$label/vars.fd" "$qemu" no no "$hii_initrd" \
        "uefisettings.test=hii panic=-1" "$@"
    boot "$label/2-write" "$out/$arch/$label/vars.fd" "$qemu" "$host_trace" "$pflash_trace" \
        "$initrd" "$append" "$@"
}

write="ignore_loglevel efi=debug uefisettings.test=hii_write uefisettings.filter=--nocapture"
stepwise="ignore_loglevel panic=-1 uefisettings.test=stepwise RUST_LOG=info,uefisettings::chattr=debug,uefisettings::hii::efivarfs=debug,uefisettings::hii::extract=debug"
kvm=(-accel kvm -cpu host -smp 2)
# The i686 guests under the 64-bit QEMU binary, whose KVM code syncs the 64-bit state too.
x86_64_qemu=/usr/bin/qemu-system-x86_64

if select_arch i686; then
    pair base-1 "$apt_qemu" yes yes "$hii_initrd" "$write panic=-1" "${kvm[@]}"
    pair x86_64-qemu "$x86_64_qemu" no no "$hii_initrd" "$write panic=-1" "${kvm[@]}"
    pair mitigations-off "$apt_qemu" no no "$hii_initrd" "$write panic=-1 mitigations=off" "${kvm[@]}"
    pair base-2 "$apt_qemu" no yes "$hii_initrd" "$write panic=-1" "${kvm[@]}"
    pair base-3 "$apt_qemu" no no "$hii_initrd" "$write panic=-1" "${kvm[@]}"
    mkdir -p "$out/$arch/fresh"
    fresh_store "$out/$arch/fresh/vars.fd"
    boot fresh "$out/$arch/fresh/vars.fd" "$apt_qemu" no no "$hii_initrd" \
        "$write panic=-1" "${kvm[@]}"
    pair stepwise "$apt_qemu" no no "$out/$arch/stepwise-initrd.img" "$stepwise" "${kvm[@]}"
    pair stepwise-cpu0 "$apt_qemu" no no "$out/$arch/stepwise-initrd.img" "$stepwise diag.cpu=0" "${kvm[@]}"
    pair stepwise-cpu1 "$apt_qemu" yes no "$out/$arch/stepwise-initrd.img" "$stepwise diag.cpu=1" "${kvm[@]}"
    pair smp1 "$apt_qemu" no no "$hii_initrd" "$write panic=-1" -accel kvm -cpu host -smp 1
    pair panic0 "$apt_qemu" no no "$hii_initrd" "$write panic=0" "${kvm[@]}"
    [[ -x $plain_qemu ]] &&
        pair plain-qemu "$plain_qemu" no no "$hii_initrd" "$write panic=-1" "${kvm[@]}"
    pair tcg-max "$apt_qemu" no no "$hii_initrd" "$write panic=-1" -accel tcg -cpu max -smp 2
fi
if select_arch x86_64; then
    pair base-1 "$apt_qemu" no no "$hii_initrd" "$write panic=-1" "${kvm[@]}"
    pair stepwise-cpu1 "$apt_qemu" no no "$out/$arch/stepwise-initrd.img" "$stepwise diag.cpu=1" "${kvm[@]}"
    # The x86_64 kernel and initrd on the i686 firmware and EFI drivers (EFI mixed mode):
    # 32-bit firmware, but a 64-bit kernel, which handles a double fault without a task switch.
    mixed_vmlinuz=$vmlinuz
    mixed_initrd=$hii_initrd
    if select_arch i686; then
        vmlinuz=$mixed_vmlinuz
        hii_initrd=$mixed_initrd
        pair mixed-mode "$x86_64_qemu" no no "$hii_initrd" "$write panic=-1" "${kvm[@]}"
    fi
fi
# Shadow paging instead of NPT, last, as it reloads kvm_amd: KVM then intercepts the guest's
# page faults, which the host trace shows.
if [[ -d /sys/module/kvm_amd ]] && sudo modprobe -r kvm_amd && sudo modprobe kvm_amd npt=0; then
    echo "kvm_amd reloaded: npt=$(cat /sys/module/kvm_amd/parameters/npt)" >>"$out/facts.txt"
    select_arch i686 && pair npt0 "$apt_qemu" yes no "$hii_initrd" "$write panic=-1" "${kvm[@]}"
    select_arch x86_64 && pair npt0 "$apt_qemu" no no "$hii_initrd" "$write panic=-1" "${kvm[@]}"
    sudo modprobe -r kvm_amd && sudo modprobe kvm_amd
    echo "kvm_amd reloaded: npt=$(cat /sys/module/kvm_amd/parameters/npt)" >>"$out/facts.txt"
fi

sudo dmesg >"$out/dmesg-after.txt" 2>&1
cat "$out/summary.txt"
