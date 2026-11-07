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
//! CTRL-q to Boot0099, and whose Driver0000 loads DriverSample.efi. `before_shell` checks that:
//! - `variable get` shows them as their bytes tell;
//! - `variable set-attributes` refuses PlatformRecovery####, OsRecovery####, an absent load
//!   option and a flag both to set and to clear, writing nothing, and clears and sets Boot0099's
//!   LOAD_OPTION_ACTIVE, changing only its Attributes and the BootOptionCrc of Key0099, which
//!   follows it, and sets and clears Driver0000's LOAD_OPTION_FORCE_RECONNECT;
//! - `variable create-load-option` refuses Boot0099, which exists, and creates Boot009A, to the
//!   UEFI Shell, by text, which BootNext then names, and Boot009C of the same device path's bytes
//!   and of OptionalData, both from files;
//! - `variable set-device-path` sets ConOut to its own text, which keeps its bytes, and refuses
//!   ConOutDev;
//! - `variable create-key` refuses Key0099, which exists, an absent Boot#### and Key0099's own
//!   shift states and keys, and creates Key009A, ALT-F11 to Boot0099.
//!
//! The UEFI Shell boots after it, shell/boot-manager.nsh through Boot009A and
//! shell/boot-manager-next.nsh through Boot009B, which the first creates, do the same; their
//! checks compare what uefisettings.efi prints with the lines "uefisettings-qemu-test: TAG JSON"
//! of this test log, and with the lines of the firmware's boot manager that loaded them.
//! `after_shell`, the last boot, reads what the Shell wrote.

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
/// What create-load-option prints for Boot0099, which exists.
const BOOT0099_EXISTS: &str = "Boot0099 exists: create-load-option creates load options; \
                               set-attributes changes the Attributes of one, and variable set \
                               BootOrder its place in BootOrder";
/// gUefiShellFileGuid, the FILE_GUID of the UEFI Shell (edk2-stable202608
/// ShellPkg/Application/Shell/Shell.inf), and its bytes.
const UEFI_SHELL_FILE_GUID: &str = "7C04A583-9E3E-4F1C-AD65-E05268D0B4D1";
const UEFI_SHELL_FILE_GUID_BYTES: [u8; 16] = [
    0x83, 0xA5, 0x04, 0x7C, 0x3E, 0x9E, 0x1C, 0x4F, 0xAD, 0x65, 0xE0, 0x52, 0x68, 0xD0, 0xB4, 0xD1,
];
/// The Description of Boot009A, which starts the UEFI Shell.
const SHELL_AGAIN: &str = "uefisettings Shell";
/// The OptionalData of Boot009C, bytes that no Description or text holds.
const OPTIONAL_DATA: &[u8] = &[0x00, 0xFF, 0x7F, 0x80, 0x0A];
/// What set-device-path prints for ConOutDev.
const CON_OUT_DEV_REFUSAL: &str = "set-device-path does not write ConOutDev: \"These variables \
                                   are volatile, and are set dynamically on every boot.\" (UEFI \
                                   2.11 section 3.3)";
/// The refusals of create-key, by its arguments.
const CREATE_KEY_REFUSALS: [(&[&str], &str); 3] = [
    (
        &["Key0099", "--boot", "Boot0099", "--key", "F2"],
        "Key0099 exists: create-key creates hot keys",
    ),
    (
        &["Key009A", "--boot", "Boot1234", "--key", "F2"],
        "Boot1234 is absent",
    ),
    (
        &[
            "Key009A",
            "--boot",
            "Boot0000",
            "--modifiers",
            "control",
            "--key",
            "q",
        ],
        "Key0099 holds these shift states and keys, and the boot manager takes it; it refuses \
         another of the same",
    ),
];
/// SCAN_F11 and SCAN_F12 (edk2-stable202608 MdePkg/Include/Protocol/SimpleTextIn.h)
const SCAN_F11: u16 = 0x0015;
const SCAN_F12: u16 = 0x0016;
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

/// What `variable create-load-option` and `args`, which must succeed, print on stdout, recorded
/// as `tag`, and on stderr.
#[track_caller]
fn create_load_option(tag: &str, args: &[&str]) -> (serde_json::Value, String) {
    let output = variable(tag, &[&["create-load-option"][..], args].concat());
    (output.json(0), output.stderr)
}

/// The FilePathList and OptionalData of `option`, an EFI_LOAD_OPTION (UEFI 2.11 §3.1.3).
#[track_caller]
fn load_option_parts(option: &[u8]) -> (&[u8], &[u8]) {
    let length = usize::from(u16::from_le_bytes([option[4], option[5]]));
    let description = option[6..]
        .chunks_exact(2)
        .position(|unit| unit == [0, 0])
        .expect("a Null-terminated Description");
    option[6 + 2 * (description + 1)..].split_at(length)
}

/// The EFI_LOAD_OPTION of `attributes`, `description`, `file_paths` and `optional_data`.
fn load_option(
    attributes: u32,
    description: &str,
    file_paths: &[u8],
    optional_data: &[u8],
) -> Vec<u8> {
    let description: Vec<u8> = description
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    let length = u16::try_from(file_paths.len()).expect("a short FilePathList");
    [
        &attributes.to_le_bytes()[..],
        &length.to_le_bytes(),
        &description,
        file_paths,
        optional_data,
    ]
    .concat()
}

/// The EFI_KEY_OPTION of KeyData `key_data`, whose BootOptionCrc is the CRC-32 of the global
/// variable `boot` as efivarfs holds it, to its number `boot_option`, of `keys`.
#[track_caller]
fn hot_key_bytes(key_data: u32, boot: &str, boot_option: u16, keys: &[(u16, u16)]) -> Vec<u8> {
    let mut bytes = [
        &key_data.to_le_bytes()[..],
        &crc32fast::hash(&data(boot)).to_le_bytes(),
        &boot_option.to_le_bytes(),
    ]
    .concat();
    for (scan_code, unicode_char) in keys {
        bytes.extend(scan_code.to_le_bytes());
        bytes.extend(unicode_char.to_le_bytes());
    }
    bytes
}

/// The instances of `path`, a device path, each without the End node that ends it.
#[track_caller]
fn instances(path: &[u8]) -> Vec<Vec<u8>> {
    let mut instances = vec![Vec::new()];
    let mut rest = path;
    while let [node_type, _, low, high, ..] = *rest {
        let length = usize::from(u16::from_le_bytes([low, high]));
        let (node, after) = rest.split_at(length);
        match node_type {
            0x7F => instances.push(Vec::new()),
            _ => instances.last_mut().expect("an instance").extend(node),
        }
        rest = after;
    }
    instances.pop();
    instances
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

    // create-load-option: refused over Boot0099, then Boot009A to the UEFI Shell, which BootNext
    // names, and Boot009C of its device path's bytes and OptionalData from files
    let before = efivars();
    let error = json_error(&[
        "variable",
        "create-load-option",
        "Boot0099",
        "--description",
        "again",
        "--device-path",
        "\\missing-99.efi",
    ]);
    assert_eq!(error.error_message, BOOT0099_EXISTS, "create Boot0099");
    assert_eq!(efivars(), before, "create Boot0099: the efivar files");

    // the firmware creates the Shell's Boot#### only on a boot without a kernel, after this one
    // (edk2-stable202608 OvmfPkg/Library/PlatformBootManagerLib/BdsPlatform.c:1666-1695), so the
    // Shell's device path is that of Boot0000, UiApp, of the same firmware volume, with the
    // Shell's FvFile
    let ui_app = get("boot0000", "Boot0000");
    let ui_app_path = ui_app["value"]["device_paths"][0]
        .as_str()
        .unwrap_or_else(|| panic!("Boot0000: {ui_app}"));
    let (volume, _) = ui_app_path
        .split_once("/FvFile(")
        .unwrap_or_else(|| panic!("Boot0000 is no FvFile: {ui_app_path}"));
    let shell_path = format!("{volume}/FvFile({UEFI_SHELL_FILE_GUID})");
    let (created, warnings) = create_load_option(
        "created-boot009a",
        &[
            "Boot009A",
            "--description",
            SHELL_AGAIN,
            "--device-path",
            &shell_path,
        ],
    );
    let ui_app_option = data("Boot0000");
    let (ui_app_file_paths, _) = load_option_parts(&ui_app_option);
    // Fv(), of the Length that its bytes 2-3 hold, then the Type, Sub-Type and Length of
    // FvFile(), then its GUID
    let guid_at = usize::from(u16::from_le_bytes([
        ui_app_file_paths[2],
        ui_app_file_paths[3],
    ])) + 4;
    let shell_file_paths = [
        &ui_app_file_paths[..guid_at],
        &UEFI_SHELL_FILE_GUID_BYTES,
        &ui_app_file_paths[guid_at + UEFI_SHELL_FILE_GUID_BYTES.len()..],
    ]
    .concat();
    let shell_file_paths = shell_file_paths.as_slice();
    assert_eq!(
        data("Boot009A"),
        load_option(1, SHELL_AGAIN, shell_file_paths, &[]),
        "Boot009A: bytes"
    );
    assert_eq!(
        created,
        global(
            "Boot009A",
            json!({
                "attributes": ["active"],
                "category": "boot",
                "description": SHELL_AGAIN,
                "device_paths": [shell_path],
                "optional_data": "",
            })
        ),
        "Boot009A"
    );
    assert_eq!(warnings, "", "Boot009A: stderr");

    let path_file = "/tmp/shell-path.bin";
    let optional_file = "/tmp/optional-data.bin";
    fs::write(path_file, shell_file_paths).expect("write the device path file");
    fs::write(optional_file, OPTIONAL_DATA).expect("write the OptionalData file");
    let (created, _) = create_load_option(
        "created-boot009c",
        &[
            "Boot009C",
            "--description",
            "from files",
            "--device-path-file",
            path_file,
            "--optional-data-file",
            optional_file,
            "--flags",
            "hidden",
            "--category",
            "app",
        ],
    );
    assert_eq!(
        data("Boot009C"),
        load_option(0x108, "from files", shell_file_paths, OPTIONAL_DATA),
        "Boot009C: bytes"
    );
    assert_eq!(
        created["value"]["device_paths"],
        json!([shell_path]),
        "Boot009C"
    );

    let written =
        variable("boot-next", &["set", "BootNext", "Boot009A"]).json::<serde_json::Value>(0);
    assert_eq!(written, global("BootNext", json!("Boot009A")), "BootNext");

    // set-device-path: ConOut set to its own text keeps its bytes; ConOutDev is refused
    let con_out = data("ConOut");
    let text = get("con-out", "ConOut")["value"]
        .as_str()
        .unwrap_or_else(|| panic!("ConOut has no text"))
        .to_owned();
    let output = variable(
        "con-out-set",
        &["set-device-path", "ConOut", "--device-path", &text],
    );
    let set: serde_json::Value = output.json(0);
    assert_eq!(
        set,
        global("ConOut", json!(text)),
        "ConOut set to its own text"
    );
    assert_eq!(data("ConOut"), con_out, "ConOut: bytes");
    let known = instances(&data("ConOutDev"));
    let lacking = instances(&con_out)
        .into_iter()
        .filter(|instance| !known.contains(instance))
        .count();
    assert_eq!(
        output
            .stderr
            .lines()
            .filter(|line| line.starts_with("warning: ConOutDev lacks the instance "))
            .count(),
        lacking,
        "ConOut: warnings: {}",
        output.stderr
    );
    let before = efivars();
    let error = json_error(&[
        "variable",
        "set-device-path",
        "ConOutDev",
        "--device-path",
        &text,
    ]);
    assert_eq!(error.error_message, CON_OUT_DEV_REFUSAL, "set ConOutDev");
    assert_eq!(efivars(), before, "set ConOutDev: the efivar files");

    // create-key: refused over Key0099, for an absent Boot####, and for Key0099's own keys, which
    // the boot manager takes; then Key009A, ALT-F11 to Boot0099
    for (args, refusal) in CREATE_KEY_REFUSALS {
        let error = json_error(&[&["variable", "create-key"][..], args].concat());

        assert_eq!(error.error_message, refusal, "{args:?}");
        assert_eq!(efivars(), before, "{args:?}: the efivar files");
    }
    let created = variable(
        "created-key009a",
        &[
            "create-key",
            "Key009A",
            "--boot",
            "Boot0099",
            "--modifiers",
            "alt",
            "--key",
            "F11",
        ],
    )
    .json::<serde_json::Value>(0);
    assert_eq!(
        data("Key009A"),
        hot_key_bytes(0x4000_0400, "Boot0099", 0x99, &[(SCAN_F11, 0)]),
        "Key009A: bytes"
    );
    assert_eq!(
        created,
        global(
            "Key009A",
            json!({
                "revision": 0,
                "modifiers": ["alt"],
                "keys": ["F11"],
                "boot_option": "Boot0099",
                "crc_matches": true,
            })
        ),
        "Key009A"
    );
    assert_eq!(get("key009a", "Key009A"), created, "get Key009A");
}

/// After the UEFI Shell boots, the first through Boot009A, which BootNext named, the second
/// through Boot009B, which the first created and BootNext named: the Shell's writes outlast the
/// resets, BootNext is gone, and Boot0099 and Key0099 are as seeded again.
#[test]
fn after_shell() {
    require_test_vm();

    let file_path: Vec<u8> = "\\uefisettings.efi"
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    let length = u16::try_from(4 + file_path.len()).expect("a short node");
    let path = [
        &[0x04, 0x04][..],
        &length.to_le_bytes(),
        &file_path,
        &[0x7F, 0xFF, 0x04, 0x00],
    ]
    .concat();
    assert_eq!(
        data("Boot009B"),
        load_option(1, "uefisettings again", &path, &[]),
        "Boot009B: bytes"
    );
    assert_eq!(global_variable("BootNext"), None, "BootNext is gone");
    assert_eq!(
        get("after-boot0099", "Boot0099"),
        seeded_boot0099(json!(["active", "0x40000000"])),
        "Boot0099"
    );
    assert_eq!(get("after-key0099", "Key0099"), seeded_key0099(), "Key0099");
    assert_eq!(
        data("Key009B"),
        hot_key_bytes(0x4000_0100, "Boot009B", 0x9B, &[(SCAN_F12, 0)]),
        "Key009B: bytes"
    );
    for name in ["Key009A", "Key009B"] {
        let key = get(&format!("after-{name}"), name);
        assert_eq!(key["value"]["crc_matches"], json!(true), "{name}: {key}");
    }
}
