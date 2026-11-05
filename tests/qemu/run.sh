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
# Linux boot pass, and check-shell-log.sh passes the console of every UEFI Shell boot.
# tests/qemu/README.md describes the requirements and the logs.
#
# Usage: tests/qemu/run.sh ARCH [SCENARIO...]
#
# ARCH is x86_64, i686 or aarch64. The guest's kernel, firmware and busybox are the
# packages of tests/qemu/guest-packages-ARCH, or of guest-packages-ARCH-unfixed or
# guest-packages-ARCH-unfixed-v5.8 for the scenarios whose guest= option asks for them. QEMU
# is the qemu-system-* of the table below from PATH, or a wrapper that execs it: the timeout
# of a boot signals that program, not its children.
# The Secure Boot scenarios, those with firmware= in their options, boot the secboot firmware
# of the table below, which has no UEFI Shell, so their Shell boots get the pinned one on the
# ESP. On i686 and aarch64, build-secboot-firmware.sh builds that firmware on the first run that
# needs it. Their variable store is a template copy, in Setup Mode, or, in User Mode, one where
# PK, KEK and db hold certificates of keys that openssl generates for the scenario, with
# SecureBootEnable cleared, so that the firmware verifies authenticated variable writes but no
# images: the pinned Shell refuses to run under Secure Boot outside Setup Mode.

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
# Fedora's kernel has that virtio console as a module. modules lists the modules of every guest
# of the architecture, and guest_modules the one more module of a guest, if any.
# vamap_args, the QEMU arguments of the vamap scenarios, make the kernel call
# SetVirtualAddressMap(), which x86 Linux does at every boot (Linux v6.11
# arch/x86/platform/efi/efi.c efi_enter_virtual_mode()).
declare -A guest_modules=()
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
    vamap_args=()
    # The secboot image needs SMM, as only SMM writes its variable store: QEMU refuses other
    # writes to a secure flash device.
    secboot_qemu=(qemu-system-x86_64 -machine q35,smm=on -accel kvm -cpu host
        -global driver=cfi.pflash01,property=secure,value=on)
    # where the secboot firmware comes from: guest, the guest's packages, or build,
    # build-secboot-firmware.sh
    secboot_source=guest
    secboot_firmware=usr/share/OVMF/OVMF_CODE_4M.secboot.fd
    secboot_vars=usr/share/OVMF/OVMF_VARS_4M.fd
    shell_efi=usr/share/efi-shell-x64/shellx64.efi
    # the file name of the UEFI Shell as the removable media boot loader (UEFI 2.11 §3.5.1.1)
    removable_loader=BOOTx64.EFI
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
    vamap_args=()
    # Built, as the pinned OVMF32_CODE_4M.secboot.fd page-faults before its first console line
    # under QEMU 10.1. Not with OvmfPkg/README's -cpu coreduo,-nx: without NX, Linux's EFI stub
    # cannot set EFI_MEMORY_RO on this firmware and stops ("Failed to decompress kernel").
    secboot_qemu=(qemu-system-i386 -machine q35,smm=on -accel kvm -cpu host
        -global driver=cfi.pflash01,property=secure,value=on)
    secboot_source=build
    secboot_firmware=OVMF_CODE.fd
    secboot_vars=OVMF_VARS.fd
    shell_efi=usr/share/efi-shell-ia32/shellia32.efi
    removable_loader=BOOTIA32.EFI
    ;;
aarch64)
    # With these devices, none of them virtio-rng unless the options column adds it, the firmware
    # has no EFI_RNG_PROTOCOL, so std's RandomState panics in uefisettings.efi: what lets the UEFI
    # Shell scenarios catch it.
    qemu=(qemu-system-aarch64 -machine virt -accel tcg -cpu cortex-a57)
    firmware=usr/share/AAVMF/AAVMF_CODE.fd
    firmware_vars=usr/share/AAVMF/AAVMF_VARS.fd
    vmlinuz_pattern='lib/modules/*/vmlinuz'
    modules=()
    guest_modules=([unfixed]='lib/modules/*/kernel/drivers/char/virtio_console.ko.xz')
    console=ttyAMA0
    tty=hvc0
    tty_device=(-device virtio-serial-pci -device "virtconsole,chardev=tty")
    edk2_arch=AARCH64
    kernel_params=()
    # For an eMAG processor, the EFI stub calls SetVirtualAddressMap() instead of setting
    # efi_novamap (Linux v6.11 drivers/firmware/efi/libstub/arm64.c system_needs_vamap()).
    vamap_args=(-smbios type=4,version=eMAG)
    # Built, as the pinned AAVMF_CODE.secboot.fd refuses every authenticated variable write
    # (build-secboot-firmware.sh).
    secboot_qemu=("${qemu[@]}")
    secboot_source=build
    secboot_firmware=AAVMF_CODE.fd
    secboot_vars=AAVMF_VARS.fd
    shell_efi=usr/share/efi-shell-aa64/shellaa64.efi
    removable_loader=BOOTAA64.EFI
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
source "$here/control-sequence.sh"
source "$here/scenario-options.sh"
repo=$(realpath "$here/../..")
out=$repo/target/qemu-test
driver_sample=$out/$arch/driver-sample
run=$out/$arch/$(date -u +%Y%m%dT%H%M%SZ)
# The guest of guest-packages-$arch, which every run unpacks again, as it does the guest of
# each guest= option of its scenarios into $guest-<guest>: one copy of each per architecture.
guest=$out/$arch/guest
target=$arch-unknown-linux-musl

# Every row has the 5 columns that the header of scenarios.tsv lists and the loop below
# reads, none of them empty, so that no row silently boots nothing, and options that
# scenario-options.sh parses, which its table test checks first.
awk -F '\t' '$0 !~ /^(#|$)/ {
    ok = NF == 5
    for (i = 1; i <= NF; i++) if ($i == "") ok = 0
    if (!ok) { printf "scenarios.tsv line %d needs 5 non-empty columns: %s\n", NR, $0; bad = 1 }
} END { exit bad }' "$here/scenarios.tsv" >&2
"$here/scenario-options-test.sh"
# Whether a scenario of the run boots the secboot firmware.
secboot=no
# The guest= options of the run's scenarios.
guests=()
# read fails on a last line without a newline, which still counts.
while IFS=$'\t' read -r name _ _ _ options || [[ -n $name ]]; do
    [[ -z $name || $name == \#* ]] && continue
    scenario_options "$name" "$options"
    if scenario_runs_on "$arch" && { (($# == 0)) || [[ " $* " == *" $name "* ]]; }; then
        [[ $option_firmware == default ]] || secboot=yes
        [[ -z $option_guest || " ${guests[*]} " == *" $option_guest "* ]] || guests+=("$option_guest")
    fi
done <"$here/scenarios.tsv"
mapfile -t known < <(awk -F '\t' '$1 !~ /^(#|$)/ { print $1 }' "$here/scenarios.tsv")
for name in "$@"; do
    if [[ " ${known[*]} " != *" $name "* ]]; then
        echo "unknown scenario $name; the scenarios are: ${known[*]}" >&2
        exit 2
    fi
done
# The test binaries that the Linux boots of the scenarios name, the fourth column.
mapfile -t named < <(awk -F '\t' '$1 !~ /^(#|$)/ {
    n = split($4, boots, ",")
    for (i = 1; i <= n; i++) if (boots[i] !~ /^shell:/) { sub("/.*", "", boots[i]); print boots[i] }
}' "$here/scenarios.tsv")

# One run of an architecture at a time, such as make -j's of its Linux and UEFI Shell
# scenarios: they unpack the guest's packages into one directory and build DriverSample.efi.
mkdir -p "$out/$arch"
exec {lock}>"$out/$arch/lock"
flock "$lock"
echo "run.sh: start $(date -u +%FT%TZ), logs in $run"
mkdir -p "$run/initramfs/bin" "$run/initramfs/lib/modules" "$run/initramfs/tests" "$run/esp" \
    "$run/shell-esp"
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
# std's RandomState, which HashMap uses, takes its keys from hashmap_random_keys, which panics
# on firmware without EFI_RNG_PROTOCOL unless the CPU has x86's RDRAND (Rust 1.93 std
# sys/random/uefi.rs). So the link map of uefisettings.efi must not name it. Each run asks for
# a map of its own, beside its logs, so cargo relinks uefisettings.efi and the map is that of the
# .efi that the run boots.
map=$run/uefisettings.efi.map
cargo rustc --release --locked --target "$arch-unknown-uefi" --bin uefisettings \
    --manifest-path "$repo/Cargo.toml" --message-format=json-render-diagnostics \
    -- -C "link-arg=/MAP:$map" |
    executables | sed 's|^|shell/|' >>"$run/executables"
found=0
grep --quiet hashmap_random_keys "$map" || found=$?
case $found in
0)
    echo "uefisettings.efi links std's hashmap_random_keys: see $map" >&2
    exit 1
    ;;
1) ;;
*)
    echo "no link map $map of uefisettings.efi" >&2
    exit 1
    ;;
esac
cargo test --release --locked --target "$target" --features test-vm --test '*' --no-run \
    --manifest-path "$here/guest/Cargo.toml" --message-format=json-render-diagnostics |
    executables | sed 's|^|tests/|' >>"$run/executables"
# The initramfs gets uefisettings, the test binaries, busybox and init. The ESP gets the
# HII fixture: publish-hiidb and EDK2's DriverSample; the UEFI Shell boots get
# uefisettings.efi on it too.
unnamed=()
# read fails on a last line without a newline, which still counts.
while read -r name path || [[ -n $name ]]; do
    case $name in
    uefisettings) cp "$path" "$run/initramfs/bin/" ;;
    publish-hiidb) cp "$path" "$run/esp/" ;;
    shell/uefisettings) cp "$path" "$run/shell-esp/" ;;
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

for each in "" "${guests[@]}"; do
    rm -rf "$guest${each:+-$each}"
    "$here/fetch-packages.sh" "$here/guest-packages-$arch${each:+-$each}" "$out/packages" \
        "$guest${each:+-$each}"
done
# Prints the one file of the packages in the directory $1 that a pattern $2 of the table matches.
guest_file() {
    local files
    # Only the pattern globs, not the path of the repository.
    mapfile -t files < <(cd "$1" && compgen -G "$2")
    if ((${#files[@]} != 1)) || [[ ! -f $1/${files[0]} ]]; then
        echo "expected exactly one $2 in $1" >&2
        return 1
    fi
    echo "$1/${files[0]}"
}
if [[ $secboot == yes ]]; then
    case $secboot_source in
    guest) secboot_dir=$guest ;;
    build)
        secboot_dir=$out/$arch/secboot-firmware
        if [[ ! -f $secboot_dir/$secboot_firmware ]]; then
            "$here/build-secboot-firmware.sh" "$edk2_arch" "$out/edk2-secboot" "$secboot_dir"
        fi
        ;;
    esac
fi
# The owner of the enrolled certificates and of the signature lists that the scenarios append:
# the tests' vendor GUID.
secboot_owner=de145b29-c3cd-455f-91de-a76237b67c52
# EFI_IMAGE_SECURITY_DATABASE_GUID, the vendor GUID of db
db_guid=d719b2cb-3d3a-4596-a3bc-dad00e67656f

# Generates the keys and payloads of a Secure Boot scenario in the new directory $1: PK, KEK and
# db to enroll, a foreign key that none of them holds, and for its Shell boots (shell/) and Linux
# boots (linux/) each a db append of a certificate of its own: signed with KEK, as
# db-append.auth; its copy with the last byte, in the certificate, flipped, as db-tampered.auth;
# and the same append signed with db's key, which KEK lacks, as db-unauthorized.auth, and with
# the foreign key, as db-foreign.auth.
secboot_files() {
    local keys=$1 each file size byte
    mkdir "$keys"
    for each in PK KEK db foreign shell-db linux-db; do
        openssl req -x509 -newkey rsa:2048 -noenc -days 2 -sha256 \
            -subj "/CN=uefisettings test $each" -keyout "$keys/$each.key" \
            -out "$keys/$each.crt" 2>>"$keys/openssl.log"
    done
    for each in shell linux; do
        mkdir "$keys/$each"
        "$here/auth-payload.sh" x509-esl "$secboot_owner" "$keys/$each-db.crt" "$keys/$each-db.esl"
        "$here/auth-payload.sh" sign db "$db_guid" 0x67 "$keys/$each-db.esl" "$keys/KEK.crt" \
            "$keys/KEK.key" "$keys/$each/db-append.auth"
        "$here/auth-payload.sh" sign db "$db_guid" 0x67 "$keys/$each-db.esl" "$keys/db.crt" \
            "$keys/db.key" "$keys/$each/db-unauthorized.auth"
        "$here/auth-payload.sh" sign db "$db_guid" 0x67 "$keys/$each-db.esl" "$keys/foreign.crt" \
            "$keys/foreign.key" "$keys/$each/db-foreign.auth"
        file=$keys/$each/db-tampered.auth
        cp "$keys/$each/db-append.auth" "$file"
        size=$(stat --format=%s "$file")
        byte=$(od --address-radix=n --format=u1 --skip-bytes=$((size - 1)) "$file")
        printf "\\$(printf %03o $((byte ^ 1)))" |
            dd of="$file" bs=1 seek=$((size - 1)) conv=notrunc status=none
    done
}

# Prints the guest tests' log of the Linux boot whose logs start with $1, and fails unless they
# and the health checks passed: init prints their exit codes last. A filter that matches no
# test passes too, so the tests must also report a passed test. The exit line can start with
# control sequences that the firmware left on the console, such as ESC[2J ESC[01;01H ESC[=3h.
linux_passed() {
    sed -n '/^uefisettings-qemu-test: start/,$p' "$1.test.log"
    tr -d '\r' <"$1.console.log" |
        LC_ALL=C grep --quiet --extended-regexp --line-regexp \
            "($control_sequence)*uefisettings-qemu-test: exit 0 0" &&
        grep --quiet '^test result: ok\. [1-9]' "$1.test.log"
}

failed=()
ran=0
# read fails on a last line without a newline, which still counts.
while IFS=$'\t' read -r -u 3 name drivers variables boots options || [[ -n $name ]]; do
    [[ -z $name || $name == \#* ]] && continue
    (($# == 0)) || [[ " $* " == *" $name "* ]] || continue
    scenario_options "$name" "$options"
    if ! scenario_runs_on "$arch"; then
        (IFS=, && echo "run.sh: $name: skipped, only ${option_arches[*]} boots it")
        continue
    fi
    ran=$((ran + 1))
    # the packages of the scenario's guest
    packages=$guest${option_guest:+-$option_guest}
    vmlinuz=$(guest_file "$packages" "$vmlinuz_pattern")
    # The firmware and the template of its variable store.
    code=$packages/$firmware
    code_vars=$packages/$firmware_vars
    dir=$run/$name
    mkdir "$dir"
    cp -r "$run/initramfs" "$dir/"
    patterns=("${modules[@]}")
    if [[ -n $option_guest && -n ${guest_modules[$option_guest]-} ]]; then
        patterns+=("${guest_modules[$option_guest]}")
    fi
    # busybox insmod takes no compressed module.
    for module in "${patterns[@]}"; do
        module=$(guest_file "$packages" "$module")
        case $module in
        *.ko.xz) xz --decompress --stdout "$module" >"$dir/initramfs/lib/modules/$(basename "$module" .xz)" ;;
        *) cp "$module" "$dir/initramfs/lib/modules/" ;;
        esac
    done
    cp "$packages/usr/bin/busybox" "$dir/initramfs/bin/busybox"
    boot_qemu=("${qemu[@]}")
    # the arguments of virt-fw-vars that enroll the keys of the scenario's variable store
    enroll=()
    case $option_firmware in
    default) ;;
    secboot-setup | secboot-user)
        boot_qemu=("${secboot_qemu[@]}")
        code=$secboot_dir/$secboot_firmware
        code_vars=$secboot_dir/$secboot_vars
        secboot_files "$dir/keys"
        mkdir "$dir/initramfs/auth"
        cp "$dir/keys/linux/"*.auth "$dir/initramfs/auth/"
        ;;
    esac
    case $option_firmware in
    default | secboot-setup) ;;
    secboot-user)
        enroll=(--set-pk "$secboot_owner" "$dir/keys/PK.crt"
            --add-kek "$secboot_owner" "$dir/keys/KEK.crt"
            --add-db "$secboot_owner" "$dir/keys/db.crt" --set-false SecureBootEnable)
        ;;
    esac
    (cd "$dir/initramfs" && find . | cpio --create --format=newc --quiet) >"$dir/initrd.img"
    # The firmware runs the Driver#### load options before it starts the kernel.
    seed=()
    if [[ $drivers != - ]]; then
        IFS=';' read -r -a files <<<"$drivers"
        virt-fw-vars --input "$code_vars" "${files[@]/#/--append-boot-filepath=}" \
            --output-json "$dir/boot.json" 2>"$dir/virt-fw-vars.log"
        jq '.variables[].name |= sub("^Boot"; "Driver")' "$dir/boot.json" >"$dir/drivers.json"
        seed+=("$dir/drivers.json")
    fi
    [[ $variables == - ]] || seed+=("$here/vars/$variables")
    jq --null-input '{version: 2, variables: [inputs.variables[]]}' "${seed[@]}" \
        </dev/null >"$dir/vars.json"
    virt-fw-vars --input "$code_vars" "${enroll[@]}" --set-json "$dir/vars.json" \
        --output "$dir/vars.fd" 2>>"$dir/virt-fw-vars.log"
    kernel_qemu_args=()
    # the kernel parameters of the scenario's Linux boots: the one that locks them down, if
    # any, and those of params=
    scenario_params=
    case $option_kernel in
    vamap) kernel_qemu_args=("${vamap_args[@]}") ;;
    lockdown) scenario_params=" lockdown=integrity" ;;
    lockdown-conf) scenario_params=" lockdown=confidentiality" ;;
    esac
    scenario_params+="${option_params[*]:+ ${option_params[*]}}"
    device_args=()
    for device in "${option_devices[@]}"; do
        case $device in
        # Its driver, VirtioRngDxe, gives the firmware EFI_RNG_PROTOCOL.
        virtio-rng) device_args+=(-device virtio-rng-pci) ;;
        esac
    done
    boot=0
    IFS=, read -r -a specs <<<"$boots"
    for spec in "${specs[@]}"; do
        boot=$((boot + 1))
        log=$dir/boot$boot
        echo "run.sh: $name boot $boot: $spec"
        case $spec in
        shell:*)
            # Without a kernel, the firmware boots its UEFI Shell, which runs startup.nsh:
            # the boot's script, on a copy of the ESP that also holds uefisettings.efi, and
            # the kernel and initrd, which the line @LINUX@ of the script starts from the
            # shell, into the guest test boot_smoke. The Secure Boot scenarios also get the
            # pinned Shell, as the removable media boot loader, and their payloads in \auth.
            script=$here/shell/${spec#shell:}
            esp=$log.esp
            cp -r "$run/esp" "$esp"
            if [[ $option_firmware != default ]]; then
                mkdir -p "$esp/EFI/BOOT" "$esp/auth"
                cp "$guest/$shell_efi" "$esp/EFI/BOOT/$removable_loader"
                cp "$dir/keys/shell/"*.auth "$esp/auth/"
            fi
            cp "$run/shell-esp/uefisettings.efi" "$esp/"
            cp "$vmlinuz" "$esp/vmlinuz.efi"
            cp "$dir/initrd.img" "$esp/initrd.img"
            linux="vmlinuz.efi initrd=\\initrd.img console=$console panic=-1"
            linux+="${kernel_params[*]:+ ${kernel_params[*]}} uefisettings.tty=$tty"
            linux+=" uefisettings.test=boot_smoke"
            # ENVIRON, as awk -v would take the backslash of \initrd.img as an escape
            LINUX=$linux awk '$0 == "@LINUX@" { $0 = ENVIRON["LINUX"] } { print $0 "\r" }' \
                "$script.nsh" >"$esp/startup.nsh"
            guest_args=(
                -drive "if=virtio,format=raw,readonly=on,file=fat:$esp"
                -chardev "file,id=tty,path=$log.test.log" "${tty_device[@]}"
            )
            ;;
        *)
            test=${spec%%/*}
            filter=${spec#"$test"}
            filter=${filter#/}
            guest_args=(
                -drive "if=virtio,format=raw,readonly=on,file=fat:$run/esp"
                -kernel "$vmlinuz" -initrd "$dir/initrd.img"
                -append "console=$console quiet panic=-1${kernel_params[*]:+ ${kernel_params[*]}} uefisettings.tty=$tty uefisettings.test=$test${filter:+ uefisettings.filter=$filter}$scenario_params"
                -chardev "file,id=tty,path=$log.test.log" "${tty_device[@]}"
            )
            ;;
        esac
        # Without --foreground, timeout would move QEMU into a process group of its own,
        # which a timeout around make does not reach.
        # The QEMU log, empty if QEMU does not start, tells how the guest ended (QEMU 10.2):
        # a poweroff makes a shutdown request (reason=6); a reset, after which -no-reboot
        # just ends QEMU, and a kill by the timeout make none. A CPU's last KVM exit is 8
        # (KVM_EXIT_SHUTDOWN) after its triple fault and 2 (I/O) after a reset through a port.
        # The console is the first serial port, before any of guest_args.
        : >"$log.qemu.log"
        timeout --foreground -k 10 120 "${boot_qemu[@]}" -nodefaults -no-user-config -no-reboot \
            -display none -sandbox on -m 1024 -smp 2 \
            -drive "if=pflash,format=raw,unit=0,readonly=on,file=$code" \
            -drive "if=pflash,format=raw,unit=1,file=$dir/vars.fd" \
            -serial "file:$log.console.log" "${guest_args[@]}" "${kernel_qemu_args[@]}" \
            "${device_args[@]}" \
            -d guest_errors,trace:qemu_system_shutdown_request,trace:kvm_run_exit \
            -D "$log.qemu.log" </dev/null || echo "run.sh: QEMU exited with $?"
        # A line per KVM exit, some MB a boot, of which only each CPU's last tells the end;
        # the other CPUs keep running after one of them triple-faults.
        awk '!/^kvm_run_exit / { print; next }
            { cpu = $3 + 0; last[cpu] = $0; if (cpu > max) max = cpu }
            END { for (cpu = 0; cpu <= max; cpu++) if (cpu in last) print last[cpu] }' \
            "$log.qemu.log" >"$log.qemu.log.new"
        mv "$log.qemu.log.new" "$log.qemu.log"
        passed=yes
        case $spec in
        shell:*)
            "$here/check-shell-log.sh" "$arch" "$script.tsv" "$log.console.log" || passed=no
            if grep --quiet --line-regexp @LINUX@ "$script.nsh"; then
                linux_passed "$log" || passed=no
            fi
            ;;
        *) linux_passed "$log" || passed=no ;;
        esac
        if [[ $passed == no ]]; then
            failed+=("$name boot $boot")
            sed "s/^/run.sh: $name boot $boot: QEMU: /" "$log.qemu.log"
        fi
    done
done 3<"$here/scenarios.tsv"

echo "run.sh: end $(date -u +%FT%TZ), logs in $run"
if ((ran == 0)); then
    echo "run.sh: FAILED: no selected scenario runs on $arch" >&2
    exit 1
fi
if ((${#failed[@]} > 0)); then
    printf 'run.sh: FAILED: %s; see its console.log, test.log and qemu.log\n' "${failed[@]}"
    exit 1
fi
