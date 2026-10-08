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
# ones, under OVMF and fails unless the guest tests and health checks of every boot pass.
# tests/qemu/README.md describes the requirements and the logs.
#
# Usage: tests/qemu/run.sh [SCENARIO...]
#
# Environment variables, which default to the paths of the Ubuntu 24.04 packages:
#   QEMU       the qemu-system-x86_64 to run (qemu-system-x86_64 from PATH)
#   OVMF_CODE  OVMF code image (/usr/share/OVMF/OVMF_CODE_4M.fd)
#   OVMF_VARS  OVMF variable store, which each scenario copies (/usr/share/OVMF/OVMF_VARS_4M.fd)
#   BUSYBOX    static busybox for the initramfs (/usr/bin/busybox)
#   DRIVER_SAMPLE_DIR  the directory of DriverSample.efi, which build-driver-sample.sh
#              fills if the file is missing (target/qemu-test/driver-sample)

set -euo pipefail

qemu=${QEMU:-qemu-system-x86_64}
ovmf_code=${OVMF_CODE:-/usr/share/OVMF/OVMF_CODE_4M.fd}
ovmf_vars=${OVMF_VARS:-/usr/share/OVMF/OVMF_VARS_4M.fd}
busybox=${BUSYBOX:-/usr/bin/busybox}

here=$(realpath "$(dirname "$0")")
repo=$(realpath "$here/../..")
out=$repo/target/qemu-test
driver_sample=${DRIVER_SAMPLE_DIR:-$out/driver-sample}
run=$out/$(date -u +%Y%m%dT%H%M%SZ)
target=x86_64-unknown-linux-musl

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
mkdir -p "$run/initramfs/bin" "$run/initramfs/tests" "$run/esp"
"$qemu" --version

# Prints "NAME PATH" for each executable that cargo reports building.
executables() {
    jq --raw-output 'select(.reason == "compiler-artifact" and .executable != null)
        | "\(.target.name) \(.executable)"'
}
cargo build --release --locked --target "$target" --bin uefisettings \
    --manifest-path "$repo/Cargo.toml" --message-format=json-render-diagnostics |
    executables >"$run/executables"
cargo build --release --locked --target x86_64-unknown-uefi \
    --manifest-path "$here/publish-hiidb/Cargo.toml" --message-format=json-render-diagnostics |
    executables >>"$run/executables"
cargo test --release --locked --target "$target" --features test-vm --test '*' --no-run \
    --manifest-path "$here/guest/Cargo.toml" --message-format=json-render-diagnostics |
    executables | sed 's|^|tests/|' >>"$run/executables"
# The initramfs gets uefisettings, the test binaries, busybox and init. The ESP gets the
# HII fixture: publish-hiidb and EDK2's DriverSample.
unnamed=()
while read -r name path; do
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
cp "$busybox" "$run/initramfs/bin/busybox"
cp "$here/init" "$run/initramfs/init"
if [[ ! -f $driver_sample/DriverSample.efi ]]; then
    "$here/build-driver-sample.sh" "$driver_sample"
fi
cp "$driver_sample/DriverSample.efi" "$run/esp/"

"$here/fetch-kernel.sh" "$out/kernel-rpms" "$run/kernel"
vmlinuz=$(echo "$run"/kernel/lib/modules/*/vmlinuz)
if [[ ! -f $vmlinuz ]]; then
    echo "expected the vmlinuz of exactly one kernel in $run/kernel" >&2
    exit 1
fi

failed=()
while IFS=$'\t' read -r -u 3 name drivers variables boots; do
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
        virt-fw-vars --input "$ovmf_vars" "${files[@]/#/--append-boot-filepath=}" \
            --output-json "$dir/boot.json" 2>"$dir/virt-fw-vars.log"
        jq '.variables[].name |= sub("^Boot"; "Driver")' "$dir/boot.json" >"$dir/drivers.json"
        seed+=("$dir/drivers.json")
    fi
    [[ $variables == - ]] || seed+=("$here/vars/$variables")
    jq --null-input '{version: 2, variables: [inputs.variables[]]}' "${seed[@]}" \
        </dev/null >"$dir/vars.json"
    virt-fw-vars --input "$ovmf_vars" --set-json "$dir/vars.json" --output "$dir/vars.fd" \
        2>>"$dir/virt-fw-vars.log"
    boot=0
    IFS=, read -r -a specs <<<"$boots"
    for spec in "${specs[@]}"; do
        boot=$((boot + 1))
        test=${spec%%/*}
        filter=${spec#"$test"}
        filter=${filter#/}
        log=$dir/boot$boot
        echo "run.sh: $name boot $boot: $spec"
        timeout 120 "$qemu" -nodefaults -no-user-config -no-reboot -display none \
            -sandbox on -machine q35 -accel kvm -cpu host -m 1024 -smp 2 \
            -drive "if=pflash,format=raw,unit=0,readonly=on,file=$ovmf_code" \
            -drive "if=pflash,format=raw,unit=1,file=$dir/vars.fd" \
            -drive "if=virtio,format=raw,readonly=on,file=fat:$run/esp" \
            -kernel "$vmlinuz" -initrd "$dir/initrd.img" \
            -append "console=ttyS0 quiet panic=-1 uefisettings.test=$test${filter:+ uefisettings.filter=$filter}" \
            -serial "file:$log.console.log" -serial "file:$log.test.log" \
            </dev/null || echo "run.sh: QEMU exited with $?"
        sed -n '/^uefisettings-qemu-test: start/,$p' "$log.test.log"
        # init prints the exit codes of the tests and the health checks last. A filter
        # that matches no test passes too, so the tests must also report a passed test.
        if ! tr -d '\r' <"$log.console.log" | grep --quiet --line-regexp 'uefisettings-qemu-test: exit 0 0' ||
            ! grep --quiet '^test result: ok\. [1-9]' "$log.test.log"; then
            failed+=("$name boot $boot")
        fi
    done
done 3<"$here/scenarios.tsv"

echo "run.sh: end $(date -u +%FT%TZ), logs in $run"
if ((${#failed[@]} > 0)); then
    printf 'run.sh: FAILED: %s; see its console.log and test.log\n' "${failed[@]}"
    exit 1
fi
