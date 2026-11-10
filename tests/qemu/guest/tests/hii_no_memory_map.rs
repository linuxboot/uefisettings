// Copyright 2023 Meta Platforms, Inc. and affiliates.
//
// Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
//
// 3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

//! The scenarios hii-no-memory-map-efivar and hii-no-memory-map-systab, on aarch64:
//! `publish-hiidb.efi rt-data` sets the `HiiDB` variable, or `publish-hiidb.efi
//! install-config-tables` installs the configuration table of the HII database. Where neither the
//! FDT, which locates both the EFI memory map and the EFI System Table, nor `/proc/kcore`, which
//! serves that memory map, is available, nothing bounds the reads of firmware memory: the `HiiDB`
//! variable method and the configuration-table method refuse before they open `/dev/mem`, naming
//! the missing FDT, and the automatic order, which moves on past either, names it too. Each test
//! runs `uefisettings` in a mount namespace of its own, where a tmpfs hides `/sys/firmware/fdt`
//! and another `/proc`.

use std::fs;
use std::process::Command;
use std::process::Stdio;

use uefisettings_qemu_guest::require_test_vm;
use uefisettings_qemu_guest::ErrorObject;
use uefisettings_qemu_guest::Output;
use uefisettings_qemu_guest::UEFISETTINGS;

/// What both methods fail with (`src/lib/hii/firmware_memory.rs` MemoryMapUnavailable::NoFdt).
const NO_FDT: &str =
    "/sys/firmware/fdt does not exist, so no EFI memory map bounds the reads of firmware memory";

/// The script that hides the FDT and `/proc` in a new mount namespace, keeps `/sys/firmware/efi`
/// and `/sys/firmware/acpi`, then runs its arguments.
const HIDE: &str = "set -e
mkdir -p /tmp/firmware
mount -o rbind /sys/firmware /tmp/firmware
mount -t tmpfs tmpfs /sys/firmware
for dir in efi acpi; do
    [ -e /tmp/firmware/$dir ] || continue
    mkdir /sys/firmware/$dir
    mount -o rbind /tmp/firmware/$dir /sys/firmware/$dir
done
mount -t tmpfs tmpfs /proc
[ ! -e /sys/firmware/fdt ] && [ ! -e /proc/kcore ] && [ -e /sys/firmware/efi/efivars ]
exec \"$@\"";

/// Runs `uefisettings` with `args` where neither the FDT nor `/proc/kcore` exists.
#[track_caller]
fn uefisettings_without_the_fdt(args: &[&str]) -> Output {
    require_test_vm();
    let output = Command::new("unshare")
        .args(["-m", "sh", "-c", HIDE, "sh", UEFISETTINGS])
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|error| panic!("cannot run {UEFISETTINGS} {args:?}: {error}"));
    Output {
        code: output.status.code(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// Panics unless extract-db with `flags` fails for the missing FDT, writing no file.
#[track_caller]
fn extract_db_refuses_without_the_fdt(flags: &[&str]) {
    let path = "/tmp/hiidb.bin";
    let output = uefisettings_without_the_fdt(&[flags, &["hii", "extract-db", path]].concat());
    let error: ErrorObject = output.json(1);
    assert!(
        error.error_message.contains(NO_FDT),
        "{flags:?}: {output:#?}"
    );
    assert!(
        fs::metadata(path).is_err(),
        "{flags:?}: the failed extract-db wrote {path}"
    );
}

/// The `HiiDB` variable method, named and as the starting tree's extract-db reaches it, after the
/// vendor ACPI tables that this firmware does not publish.
#[test]
fn efivar_refuses_without_the_fdt() {
    for flags in [&["--hii-source", "efivar"][..], &[]] {
        extract_db_refuses_without_the_fdt(flags);
    }
}

/// The configuration-table method, named and in the automatic order.
#[test]
fn systab_refuses_without_the_fdt() {
    for flags in [&["--hii-source", "systab"][..], &[]] {
        extract_db_refuses_without_the_fdt(flags);
    }
}
