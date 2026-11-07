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

//! The variables of the boot manager (src/lib/efi_variables/boot_manager.rs) in the scenario
//! boot-manager, whose variable store tests/qemu/vars/boot-manager.json seeds with Boot0099, of
//! a file that no ESP holds, with an undefined attribute bit and OptionalData, and Key0099,
//! CTRL-q to Boot0099, and whose Driver0000 loads DriverSample.efi: `before_shell` checks that
//! `variable get` shows them as their bytes tell; that `variable set-attributes` refuses
//! PlatformRecovery####, OsRecovery####, an absent load option and a flag both to set and to
//! clear, writing nothing; and that it clears and sets Boot0099's LOAD_OPTION_ACTIVE, changing
//! only its Attributes and the BootOptionCrc of Key0099, which follows it, and sets and clears
//! Driver0000's LOAD_OPTION_FORCE_RECONNECT. The UEFI Shell boot after it,
//! shell/boot-manager.nsh, does the same, and its checks compare what uefisettings.efi prints
//! with the lines "uefisettings-qemu-test: TAG JSON" of this test log.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::io::Write;

use serde_json::json;
use uefisettings_qemu_guest::changed_bytes;
use uefisettings_qemu_guest::global_variable;
use uefisettings_qemu_guest::json_error;
use uefisettings_qemu_guest::require_test_vm;
use uefisettings_qemu_guest::Output;
use uefisettings_qemu_guest::EFIVARS;
use uefisettings_qemu_guest::EFI_GLOBAL_VARIABLE;

/// The refusals of set-attributes, by its arguments.
const SET_ATTRIBUTES_REFUSALS: [(&[&str], &str); 4] = [
    (
        &["PlatformRecovery0000", "--set", "active"],
        "set-attributes does not write PlatformRecovery0000: \"These variables are only modified \
         by firmware and are read-only to the OS.\" (UEFI 2.11 section 3.3)",
    ),
    (
        &["OsRecovery0000", "--set", "active"],
        "set-attributes does not write OsRecovery0000, a Secure Boot Policy Variable: \"Secure \
         Boot Policy Variables must be created using the EFI_VARIABLE_AUTHENTICATION_2 \
         structure.\" (UEFI 2.11 section 3.3); variable write-signed writes a payload signed so",
    ),
    (&["Boot1234", "--set", "active"], "Boot1234 is absent"),
    (
        &["Boot0099", "--set", "active", "--clear", "active"],
        "set-attributes cannot both set and clear active",
    ),
];
/// What set-attributes prints on stderr when it updates Key0099.
const KEY0099_UPDATED: &str = "updated Key0099: its BootOptionCrc is the CRC-32 of the Boot#### \
                               that it starts again (UEFI 2.11 section 3.1.6)";

/// The output of `uefisettings variable` and `args`, whose standard output the test log records
/// as "uefisettings-qemu-test: TAG JSON", written to stderr itself, which libtest does not
/// capture, on a line of its own after libtest's "test ... ".
#[track_caller]
fn variable(tag: &str, args: &[&str]) -> Output {
    let output = uefisettings_qemu_guest::uefisettings(&[&["variable"][..], args].concat());
    writeln!(
        io::stderr(),
        "\nuefisettings-qemu-test: {tag} {}",
        output.stdout.trim_end()
    )
    .expect("cannot write to stderr");
    output
}

/// What `variable get` prints of `name`, recorded as `tag`.
#[track_caller]
fn get(tag: &str, name: &str) -> serde_json::Value {
    variable(tag, &["get", name]).json(0)
}

/// What `variable set-attributes` and `args`, which must succeed, print on stdout, recorded as
/// `tag`, and on stderr.
#[track_caller]
fn set_attributes(tag: &str, args: &[&str]) -> (serde_json::Value, String) {
    let output = variable(tag, &[&["set-attributes"][..], args].concat());
    (output.json(0), output.stderr)
}

/// The bytes of each efivar file, by name.
#[track_caller]
fn efivars() -> BTreeMap<String, Vec<u8>> {
    fs::read_dir(EFIVARS)
        .expect("cannot list the efivars")
        .map(|entry| {
            let path = entry.expect("cannot list the efivars").path();
            let bytes = fs::read(&path)
                .unwrap_or_else(|error| panic!("cannot read {}: {error}", path.display()));
            let name = path.file_name().expect("an efivar file").to_string_lossy();
            (name.into_owned(), bytes)
        })
        .collect()
}

/// The data of the global variable `name`, which must exist.
#[track_caller]
fn data(name: &str) -> Vec<u8> {
    global_variable(name).unwrap_or_else(|| panic!("{name} is absent"))
}

/// The global variable `name` of `value`, with NV+BS+RT, as get prints it.
fn global(name: &str, value: serde_json::Value) -> serde_json::Value {
    json!({
        "variable": format!("{name}-{EFI_GLOBAL_VARIABLE}"),
        "attributes": 7,
        "value": value,
    })
}

/// Boot0099 as tests/qemu/vars/boot-manager.json seeds it, with `attributes`.
fn seeded_boot0099(attributes: serde_json::Value) -> serde_json::Value {
    global(
        "Boot0099",
        json!({
            "attributes": attributes,
            "category": "boot",
            "description": "file missing-99.efi",
            "device_paths": ["\\missing-99.efi"],
            "optional_data": "7565666973657474696e6773",
        }),
    )
}

/// Key0099 as tests/qemu/vars/boot-manager.json seeds it, whose BootOptionCrc matches Boot0099.
fn seeded_key0099() -> serde_json::Value {
    global(
        "Key0099",
        json!({
            "revision": 0,
            "modifiers": ["control"],
            "keys": ["q"],
            "boot_option": "Boot0099",
            "crc_matches": true,
        }),
    )
}

#[test]
fn before_shell() {
    require_test_vm();

    assert_eq!(
        get("seeded-boot0099", "Boot0099"),
        seeded_boot0099(json!(["active", "0x40000000"])),
        "Boot0099"
    );
    assert_eq!(
        get("seeded-key0099", "Key0099"),
        seeded_key0099(),
        "Key0099"
    );

    let before = efivars();
    for (args, refusal) in SET_ATTRIBUTES_REFUSALS {
        let error = json_error(&[&["variable", "set-attributes"][..], args].concat());

        assert_eq!(error.error_message, refusal, "{args:?}");
        assert_eq!(efivars(), before, "{args:?}: the efivar files");
    }

    // Boot0099 inactive: only LOAD_OPTION_ACTIVE changes, and Key0099 follows it
    let (boot, key) = (data("Boot0099"), data("Key0099"));
    let (inactive, notes) = set_attributes("inactive-boot0099", &["Boot0099", "--clear", "active"]);

    let (inactive_boot, inactive_key) = (data("Boot0099"), data("Key0099"));
    assert_eq!(
        inactive,
        seeded_boot0099(json!(["0x40000000"])),
        "inactive Boot0099"
    );
    assert_eq!(
        notes.trim_end(),
        KEY0099_UPDATED,
        "inactive Boot0099: stderr"
    );
    assert_eq!(
        changed_bytes(&boot, &inactive_boot),
        [(0, 0)],
        "inactive Boot0099: bytes"
    );
    assert_eq!(
        inactive_key[4..8],
        crc32fast::hash(&inactive_boot).to_le_bytes(),
        "Key0099: BootOptionCrc"
    );
    assert!(
        changed_bytes(&key, &inactive_key)
            .iter()
            .all(|(offset, _)| (4..8).contains(offset)),
        "Key0099: bytes but BootOptionCrc changed: {key:02x?} {inactive_key:02x?}"
    );
    assert_eq!(
        get("inactive-key0099", "Key0099"),
        seeded_key0099(),
        "inactive Key0099"
    );
    let mut kept = efivars();
    for name in ["Boot0099", "Key0099"] {
        let file = format!("{name}-{EFI_GLOBAL_VARIABLE}");
        kept.insert(file.clone(), before[&file].clone());
    }
    assert_eq!(kept, before, "the other efivar files");

    let (active, notes) = set_attributes("active-boot0099", &["Boot0099", "--set", "active"]);

    assert_eq!(
        active,
        seeded_boot0099(json!(["active", "0x40000000"])),
        "active Boot0099"
    );
    assert_eq!(notes.trim_end(), KEY0099_UPDATED, "active Boot0099: stderr");
    assert_eq!(
        (data("Boot0099"), data("Key0099")),
        (boot, key),
        "Boot0099 and Key0099 again"
    );

    // Driver0000 with LOAD_OPTION_FORCE_RECONNECT, and without it again
    let driver = data("Driver0000");
    let (reconnect, notes) = set_attributes(
        "driver-force-reconnect",
        &["Driver0000", "--set", "force-reconnect"],
    );

    assert_eq!(
        reconnect["value"]["attributes"],
        json!(["active", "force-reconnect"]),
        "Driver0000 with LOAD_OPTION_FORCE_RECONNECT"
    );
    assert_eq!(notes, "", "Driver0000: stderr");
    assert_eq!(
        changed_bytes(&driver, &data("Driver0000")),
        [(0, 0x03)],
        "Driver0000 with LOAD_OPTION_FORCE_RECONNECT: bytes"
    );
    let (cleared, _) = set_attributes(
        "driver-reconnect-cleared",
        &["Driver0000", "--clear", "force-reconnect"],
    );
    assert_eq!(
        cleared["value"]["attributes"],
        json!(["active"]),
        "Driver0000 without LOAD_OPTION_FORCE_RECONNECT"
    );
    assert_eq!(data("Driver0000"), driver, "Driver0000 again");
}
