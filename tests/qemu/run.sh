#!/bin/bash
# Copyright 2023 Meta Platforms, Inc. and affiliates.
#
# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# Runs the QEMU tests: boots each scenario of tests/qemu/scenarios.tsv, or only the named
# ones, under EDK2's firmware and fails unless the guest tests and health checks of every
# boot pass. tests/qemu/README.md describes the requirements and the logs.
#
# Usage: tests/qemu/run.sh ARCH [SCENARIO...]
#
# ARCH is x86_64, i686 or aarch64. The guest's kernel, firmware and busybox are the
# packages of tests/qemu/guest-packages-ARCH. QEMU is the qemu-system-* of the table below
# from PATH, or a wrapper that execs it: the timeout of a boot signals that program, not
# its children.

set -euo pipefail

if (($# < 1)); then
    echo "usage: $0 ARCH [SCENARIO...]" >&2
    exit 2
fi
arch=$1
shift
# The test terminal is the second serial port, but QEMU's virt machine gives the guest one
# PL011 UART, so the aarch64 guests write to a virtio console. Debian's i686 kernel has
# efivarfs as a module. aarch64 runs under TCG, so it boots on x86_64 hosts like the others.
case $arch in
x86_64)
    qemu=(qemu-system-x86_64 -machine q35 -accel kvm -cpu host)
    firmware=usr/share/OVMF/OVMF_CODE_4M.fd
    firmware_vars=usr/share/OVMF/OVMF_VARS_4M.fd
    vmlinuz_pattern='lib/modules/*/vmlinuz'
    modules=()
    console=ttyS0
    tty=ttyS1
    tty_device=(-serial chardev:tty)
    edk2_arch=X64
    kernel_params=()
    ;;
i686)
    qemu=(qemu-system-i386 -machine q35 -accel kvm -cpu host)
    firmware=usr/share/OVMF/OVMF32_CODE_4M.fd
    firmware_vars=usr/share/OVMF/OVMF32_VARS_4M.fd
    vmlinuz_pattern='boot/vmlinuz-*'
    modules=('lib/modules/*/kernel/fs/efivarfs/efivarfs.ko')
    console=ttyS0
    tty=ttyS1
    tty_device=(-serial chardev:tty)
    edk2_arch=IA32
    # Containment: GitHub's AMD runners' KVM (linux-azure) clears CR3 bits 0-11 of a vCPU
    # without CR4.PCIDE at each NPT root load (https://bugs.launchpad.net/bugs/2106673);
    # in PAE paging bits 5-11 address the PDPT, which Debian 12's kernel takes from a
    # 32-byte slab unless pti=on (Linux v6.1 _pgd_alloc; SHARED_KERNEL_PMD is !PTI).
    kernel_params=(pti=on)
    ;;
aarch64)
    qemu=(qemu-system-aarch64 -machine virt -accel tcg -cpu cortex-a57)
    firmware=usr/share/AAVMF/AAVMF_CODE.fd
    firmware_vars=usr/share/AAVMF/AAVMF_VARS.fd
    vmlinuz_pattern='lib/modules/*/vmlinuz'
    modules=()
    console=ttyAMA0
    tty=hvc0
    tty_device=(-device virtio-serial-pci -device "virtconsole,chardev=tty")
    edk2_arch=AARCH64
    kernel_params=()
    # cc, the default, links for the host. Set the variable for another linker: it
    # overrides cargo's config files, as this default does.
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER-aarch64-linux-gnu-gcc}
    ;;
*)
    echo "unknown architecture $arch; the architectures are x86_64, i686 and aarch64" >&2
    exit 2
    ;;
esac

here=$(realpath "$(dirname "$0")")
repo=$(realpath "$here/../..")
out=$repo/target/qemu-test
driver_sample=$out/$arch/driver-sample
run=$out/$arch/$(date -u +%Y%m%dT%H%M%SZ)
# Unpacked again by every run, which keeps one copy per architecture.
guest=$out/$arch/guest
target=$arch-unknown-linux-musl

# Every row has the 4 columns that the header of scenarios.tsv lists and the loop below
# reads, none of them empty, so that no row silently boots nothing.
awk -F '\t' '$0 !~ /^(#|$)/ {
    ok = NF == 4
    for (i = 1; i <= NF; i++) if ($i == "") ok = 0
    if (!ok) { printf "scenarios.tsv line %d needs 4 non-empty columns: %s\n", NR, $0; bad = 1 }
} END { exit bad }' "$here/scenarios.tsv" >&2
mapfile -t known < <(awk -F '\t' '$1 !~ /^(#|$)/ { print $1 }' "$here/scenarios.tsv")
for name in "$@"; do
    if [[ " ${known[*]} " != *" $name "* ]]; then
        echo "unknown scenario $name; the scenarios are: ${known[*]}" >&2
        exit 2
    fi
done
# The test binaries that the boots of the scenarios name, the last column.
mapfile -t named < <(awk -F '\t' '$1 !~ /^(#|$)/ {
    n = split($NF, boots, ",")
    for (i = 1; i <= n; i++) { sub("/.*", "", boots[i]); print boots[i] }
}' "$here/scenarios.tsv")

echo "run.sh: start $(date -u +%FT%TZ), logs in $run"
mkdir -p "$run/initramfs/bin" "$run/initramfs/lib/modules" "$run/initramfs/tests" "$run/esp"
grep --max-count=1 '^model name' /proc/cpuinfo
"${qemu[0]}" --version

# virt-fw-vars has no --version option, so this asks the Python that its first line names,
# the one that runs it, for the version of virt-firmware. Another first line, or a failure,
# gives "unknown": the version line never fails the run.
virt_firmware_version() {
    local shebang python interpreter
    read -r shebang 2>/dev/null <"$(command -v virt-fw-vars)" || return 1
    [[ $shebang == '#!'* ]] || return 1
    read -r -a python <<<"${shebang#'#!'}"
    ((${#python[@]} > 0)) || return 1
    interpreter=${python[0]##*/}
    [[ $interpreter != env ]] || interpreter=${python[1]:-}
    [[ ${interpreter##*/} == python* ]] || return 1
    "${python[@]}" -c 'import importlib.metadata as m; print(m.version("virt-firmware"))' \
        2>/dev/null
}
echo "virt-firmware $(virt_firmware_version || echo unknown)"

# Prints "NAME PATH" for each executable that cargo reports building.
executables() {
    jq --raw-output 'select(.reason == "compiler-artifact" and .executable != null)
        | "\(.target.name) \(.executable)"'
}
cargo build --release --locked --target "$target" --bin uefisettings \
    --manifest-path "$repo/Cargo.toml" --message-format=json-render-diagnostics |
    executables >"$run/executables"
cargo build --release --locked --target "$arch-unknown-uefi" \
    --manifest-path "$here/publish-hiidb/Cargo.toml" --message-format=json-render-diagnostics |
    executables >>"$run/executables"
cargo test --release --locked --target "$target" --features test-vm --test '*' --no-run \
    --manifest-path "$here/guest/Cargo.toml" --message-format=json-render-diagnostics |
    executables | sed 's|^|tests/|' >>"$run/executables"
# The initramfs gets uefisettings, the test binaries, busybox and init. The ESP gets the
# HII fixture: publish-hiidb and EDK2's DriverSample.
unnamed=()
# read fails on a last line without a newline, which still counts.
while read -r name path || [[ -n $name ]]; do
    case $name in
    uefisettings) cp "$path" "$run/initramfs/bin/" ;;
    publish-hiidb) cp "$path" "$run/esp/" ;;
    tests/*)
        cp "$path" "$run/initramfs/$name"
        [[ " ${named[*]} " == *" ${name#tests/} "* ]] || unnamed+=("${name#tests/}")
        ;;
    esac
done <"$run/executables"
if ((${#unnamed[@]} > 0)); then
    echo "no scenario boots the test binaries ${unnamed[*]}; add them to scenarios.tsv" >&2
    exit 1
fi
cp "$here/init" "$run/initramfs/init"
if [[ ! -f $driver_sample/DriverSample.efi ]]; then
    "$here/build-driver-sample.sh" "$edk2_arch" "$driver_sample"
fi
cp "$driver_sample/DriverSample.efi" "$run/esp/"

rm -rf "$guest"
"$here/fetch-packages.sh" "$here/guest-packages-$arch" "$out/packages" "$guest"
# Prints the one file of the guest's packages that a pattern of the table matches.
guest_file() {
    local files
    # Only the pattern globs, not the path of the repository.
    mapfile -t files < <(cd "$guest" && compgen -G "$1")
    if ((${#files[@]} != 1)) || [[ ! -f $guest/${files[0]} ]]; then
        echo "expected exactly one $1 in $guest" >&2
        return 1
    fi
    echo "$guest/${files[0]}"
}
vmlinuz=$(guest_file "$vmlinuz_pattern")
for module in "${modules[@]}"; do
    cp "$(guest_file "$module")" "$run/initramfs/lib/modules/"
done
cp "$guest/usr/bin/busybox" "$run/initramfs/bin/busybox"

failed=()
# read fails on a last line without a newline, which still counts.
while IFS=$'\t' read -r -u 3 name drivers variables boots || [[ -n $name ]]; do
    [[ -z $name || $name == \#* ]] && continue
    (($# == 0)) || [[ " $* " == *" $name "* ]] || continue
    dir=$run/$name
    mkdir "$dir"
    cp -r "$run/initramfs" "$dir/"
    (cd "$dir/initramfs" && find . | cpio --create --format=newc --quiet) >"$dir/initrd.img"
    # The firmware runs the Driver#### load options before it starts the kernel.
    seed=()
    if [[ $drivers != - ]]; then
        IFS=';' read -r -a files <<<"$drivers"
        virt-fw-vars --input "$guest/$firmware_vars" "${files[@]/#/--append-boot-filepath=}" \
            --output-json "$dir/boot.json" 2>"$dir/virt-fw-vars.log"
        jq '.variables[].name |= sub("^Boot"; "Driver")' "$dir/boot.json" >"$dir/drivers.json"
        seed+=("$dir/drivers.json")
    fi
    [[ $variables == - ]] || seed+=("$here/vars/$variables")
    jq --null-input '{version: 2, variables: [inputs.variables[]]}' "${seed[@]}" \
        </dev/null >"$dir/vars.json"
    virt-fw-vars --input "$guest/$firmware_vars" --set-json "$dir/vars.json" \
        --output "$dir/vars.fd" 2>>"$dir/virt-fw-vars.log"
    boot=0
    IFS=, read -r -a specs <<<"$boots"
    for spec in "${specs[@]}"; do
        boot=$((boot + 1))
        test=${spec%%/*}
        filter=${spec#"$test"}
        filter=${filter#/}
        log=$dir/boot$boot
        echo "run.sh: $name boot $boot: $spec"
        # Without --foreground, timeout would move QEMU into a process group of its own,
        # which a timeout around make does not reach.
        # The QEMU log, empty if QEMU does not start, tells how the guest ended (QEMU 10.2):
        # a poweroff makes a shutdown request (reason=6); a reset, after which -no-reboot
        # just ends QEMU, and a kill by the timeout make none. A CPU's last KVM exit is 8
        # (KVM_EXIT_SHUTDOWN) after its triple fault and 2 (I/O) after a reset through a port.
        : >"$log.qemu.log"
        timeout --foreground -k 10 120 "${qemu[@]}" -nodefaults -no-user-config -no-reboot \
            -display none -sandbox on -m 1024 -smp 2 \
            -drive "if=pflash,format=raw,unit=0,readonly=on,file=$guest/$firmware" \
            -drive "if=pflash,format=raw,unit=1,file=$dir/vars.fd" \
            -drive "if=virtio,format=raw,readonly=on,file=fat:$run/esp" \
            -kernel "$vmlinuz" -initrd "$dir/initrd.img" \
            -append "console=$console quiet panic=-1${kernel_params[*]:+ ${kernel_params[*]}} uefisettings.tty=$tty uefisettings.test=$test${filter:+ uefisettings.filter=$filter}" \
            -serial "file:$log.console.log" \
            -chardev "file,id=tty,path=$log.test.log" "${tty_device[@]}" \
            -d guest_errors,trace:qemu_system_shutdown_request,trace:kvm_run_exit \
            -D "$log.qemu.log" </dev/null || echo "run.sh: QEMU exited with $?"
        # A line per KVM exit, some MB a boot, of which only each CPU's last tells the end;
        # the other CPUs keep running after one of them triple-faults.
        awk '!/^kvm_run_exit / { print; next }
            { cpu = $3 + 0; last[cpu] = $0; if (cpu > max) max = cpu }
            END { for (cpu = 0; cpu <= max; cpu++) if (cpu in last) print last[cpu] }' \
            "$log.qemu.log" >"$log.qemu.log.new"
        mv "$log.qemu.log.new" "$log.qemu.log"
        sed -n '/^uefisettings-qemu-test: start/,$p' "$log.test.log"
        # init prints the exit codes of the tests and the health checks last. A filter
        # that matches no test passes too, so the tests must also report a passed test.
        if ! tr -d '\r' <"$log.console.log" | grep --quiet --line-regexp 'uefisettings-qemu-test: exit 0 0' ||
            ! grep --quiet '^test result: ok\. [1-9]' "$log.test.log"; then
            failed+=("$name boot $boot")
            sed "s/^/run.sh: $name boot $boot: QEMU: /" "$log.qemu.log"
        fi
    done
done 3<"$here/scenarios.tsv"

echo "run.sh: end $(date -u +%FT%TZ), logs in $run"
if ((${#failed[@]} > 0)); then
    printf 'run.sh: FAILED: %s; see its console.log, test.log and qemu.log\n' "${failed[@]}"
    exit 1
fi
