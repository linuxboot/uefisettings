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

//! A guest whose firmware publishes, after its own package lists, those of publish-hiidb's
//! `global_variable_forms`: questions on EFI global variables of the firmware, under
//! VarStores that declare every variable non-volatile. `set` refuses those on a volatile
//! variable, naming it, and those whose variable it cannot read, with the read's error, before
//! it writes anything, and writes the one on Timeout; `get` reads those on ConOutDev, LangCodes
//! and Timeout. Each check of `set` compares every efivar file before and after. `variable list`
//! lists the variables of the efivar files, `variable info` tells their attributes and size, and
//! `variable storage` the storage that efivarfs tells. The firmware also exports the package list
//! that publish-hiidb's `padded_strings` registers, whose strings package header holds padding
//! after Language's null terminator: `hii list-strings` reads its strings at StringInfoOffset.
//! It exports that of publish-hiidb's `string_blocks` too: `hii list-strings` reads the strings
//! of a strings package of every string block type, and its last string ID is the one up to
//! which the firmware pads the package list's other strings package with an EFI_HII_SIBT_SKIP2
//! block, as `hii extract-db` shows.

use std::collections::BTreeMap;
use std::fs;

use uefisettings_qemu_guest::json;
use uefisettings_qemu_guest::json_error;
use uefisettings_qemu_guest::require_test_vm;
use uefisettings_qemu_guest::single_response;
use uefisettings_qemu_guest::uefisettings;
use uefisettings_qemu_guest::Responses;
use uefisettings_qemu_guest::StringPackage;
use uefisettings_qemu_guest::Variable;
use uefisettings_qemu_guest::BACKEND_HII;
use uefisettings_qemu_guest::EFIVARFS_HEADER_SIZE;
use uefisettings_qemu_guest::EFIVARS;
use uefisettings_qemu_guest::PREFIXES;

/// EFI_GLOBAL_VARIABLE, the vendor GUID of the variables, as efivarfs names their files.
const EFI_GLOBAL_VARIABLE: &str = "8be4df61-93ca-11d2-aa0d-00e098032b8c";

/// The attributes of a volatile variable: boot service and runtime access.
const BS_RT: u32 = 0x06;
/// The attributes of a non-volatile variable: non-volatile, boot service and runtime access.
const NV_BS_RT: u32 = 0x07;

/// A question on ConOutDev, which the firmware keeps volatile, under a VARSTORE_EFI of 1
/// byte.
const VOLATILE: &str = "Volatile EFI variable";
/// A question on LangCodes, which the firmware keeps volatile, under a buffer VARSTORE of 1
/// byte.
const VOLATILE_BUFFER: &str = "Buffer on a volatile EFI variable";
/// A question on PlatformLangCodes, which the firmware keeps volatile, under a VARSTORE_EFI
/// of [`LARGER_VAR_STORE`] bytes.
const VOLATILE_UNDER_A_LARGER_VAR_STORE: &str = "Volatile EFI variable under a larger VarStore";
/// The Size of the VarStore of [`VOLATILE_UNDER_A_LARGER_VAR_STORE`], more than the variable
/// holds.
const LARGER_VAR_STORE: usize = 255;
/// A question on Timeout, which the firmware keeps non-volatile, under a VARSTORE_EFI of 2
/// bytes.
const NON_VOLATILE: &str = "Non-volatile EFI variable";
/// A question in two package lists: on Timeout in the first, as [`NON_VOLATILE`], and on
/// ConOutDev in the second, as [`VOLATILE`].
const VOLATILE_COPY: &str = "Volatile copy among several";
/// A question in two package lists, on Timeout in both: under a VARSTORE_EFI of 2 bytes in
/// the first, and of 64, more than Timeout holds, in the second.
const UNREADABLE_COPY: &str = "Unreadable copy among several";
/// A question in two package lists, on Timeout under a VARSTORE_EFI of 2 bytes in both: up
/// to 200 in [`MAXIMUM_200`], then up to 100 in [`MAXIMUM_100`].
const DIFFERENT_MAXIMA: &str = "Copies with different maxima";
/// The package list of the copy of [`DIFFERENT_MAXIMA`] up to 200, as `set` names it.
const MAXIMUM_200: &str = "8C78A505-BAA0-4C4A-869F-000000000006";
/// The package list of the copy of [`DIFFERENT_MAXIMA`] up to 100, as `set` names it.
const MAXIMUM_100: &str = "8C78A505-BAA0-4C4A-869F-000000000007";

/// The strings of publish-hiidb's `padded_strings`, by string ID, after its padded header.
const PADDED_HEADER_STRINGS: [(&str, &str); 2] =
    [("1", "English"), ("2", "Strings after a padded header")];

/// The strings of the first strings package of publish-hiidb's `string_blocks`, by string ID,
/// which a block of every string block type assigns; string IDs 12 to 14 have none.
const EVERY_STRING_BLOCK_TYPE: [(&str, &str); 12] = [
    ("1", "Every string block type"),
    ("2", "SCSU in a font"),
    ("3", "SCSU strings"),
    ("4", "\u{3042}\u{3044}"),
    ("5", "SCSU strings in a font"),
    ("6", "UCS-2"),
    ("7", "UCS-2 in a font"),
    ("8", "UCS-2 strings"),
    ("9", "of one block"),
    ("10", "UCS-2 strings in a font"),
    ("11", "UCS-2"),
    ("15", "After every string block type"),
];
/// The one string of the second strings package of publish-hiidb's `string_blocks`, string ID 1.
const SECOND_STRINGS_PACKAGE: &str = "Second strings package";
/// The Language of that second strings package.
const SECOND_LANGUAGE: &str = "fr-FR";
/// The GUID of publish-hiidb's `string_blocks` package list, in EFI_GUID's byte order.
const STRING_BLOCKS_PACKAGE_LIST: [u8; 16] = [
    0x05, 0xA5, 0x78, 0x8C, 0xA0, 0xBA, 0x4A, 0x4C, 0x86, 0x9F, 0x00, 0x00, 0x00, 0x00, 0x16, 0x00,
];
/// The file that extract-db writes for the string blocks of publish-hiidb's `string_blocks`.
const STRING_BLOCKS_HIIDB: &str = "/tmp/hiidb-string-blocks.bin";
/// The offset of PackageLength in EFI_HII_PACKAGE_LIST_HEADER, after PackageListGuid (UEFI 2.11
/// §33.3.1.2).
const PACKAGE_LENGTH_OFFSET: usize = 16;
/// The size of EFI_HII_PACKAGE_LIST_HEADER.
const PACKAGE_LIST_HEADER_SIZE: usize = 20;
/// EFI_HII_PACKAGE_STRINGS, the Type of a strings package (UEFI 2.11 §33.3.1.1).
const EFI_HII_PACKAGE_STRINGS: u8 = 0x04;
/// The offset of StringInfoOffset in a strings package (UEFI 2.11 §33.3.6.1).
const STRING_INFO_OFFSET_OFFSET: usize = 8;
/// The offset of Language there, after LanguageWindow and LanguageName.
const LANGUAGE_OFFSET: usize = 46;

/// The bytes of every efivar file, or why it cannot be read.
type Efivars = BTreeMap<String, Result<Vec<u8>, String>>;

/// Every efivar file.
#[track_caller]
fn efivars() -> Efivars {
    require_test_vm();
    fs::read_dir(EFIVARS)
        .expect("cannot list the efivars")
        .map(|entry| {
            let entry = entry.expect("cannot list the efivars");
            let bytes = fs::read(entry.path()).map_err(|error| error.to_string());
            (entry.file_name().to_string_lossy().into_owned(), bytes)
        })
        .collect()
}

/// The names of the efivar files that differ between `before` and `after`.
fn changed(before: &Efivars, after: &Efivars) -> Vec<String> {
    let mut names: Vec<&String> = before.keys().chain(after.keys()).collect();
    names.sort();
    names.dedup();
    names
        .into_iter()
        .filter(|name| before.get(*name) != after.get(*name))
        .cloned()
        .collect()
}

/// The efivar file name of the EFI global variable `name`.
fn file_name(name: &str) -> String {
    format!("{name}-{EFI_GLOBAL_VARIABLE}")
}

/// The attribute word and the data of the EFI global variable `name`.
#[track_caller]
fn global_variable(name: &str) -> (u32, Vec<u8>) {
    require_test_vm();
    let path = format!("{EFIVARS}/{}", file_name(name));
    let bytes = fs::read(&path).unwrap_or_else(|error| panic!("cannot read {path}: {error}"));
    let (attributes, data) = bytes.split_at(EFIVARFS_HEADER_SIZE);
    let attributes = attributes
        .try_into()
        .expect("efivarfs gave no attribute word");
    (u32::from_ne_bytes(attributes), data.to_vec())
}

/// A value from 0 to 99, which every question takes, other than `current`.
fn other_than(current: u8) -> String {
    ((current % 100 + 1) % 100).to_string()
}

/// The error with which `set` refuses the volatile EFI global variable `name`.
fn volatile(name: &str) -> String {
    format!(
        "EFI variable {} is volatile (no EFI_VARIABLE_NON_VOLATILE) and cannot be written \
         through efivarfs",
        file_name(name)
    )
}

/// The error with which `set` refuses the EFI global variable `name` when it holds fewer bytes
/// than the VarStore of a question on it.
fn read_error(name: &str) -> String {
    format!(
        "failed to read efivar file '{EFIVARS}/{}': failed to fill whole buffer",
        file_name(name)
    )
}

/// Runs `set` of `question` to a value other than the first byte of the EFI global variable
/// `name`, after each of [`PREFIXES`], and checks that it fails with `error` and changes no
/// efivar file.
#[track_caller]
fn refuse(question: &str, name: &str, error: &str) {
    for prefix in PREFIXES {
        let value = other_than(global_variable(name).1[0]);
        let before = efivars();
        let refused = json_error(&[prefix, &["set", question, &value, "--json"]].concat());
        assert_eq!(
            (refused.error_message.as_str(), changed(&before, &efivars())),
            (error, vec![]),
            "{prefix:?} set {question:?} {value}"
        );
    }
}

/// The variables of the efivar files that hold one, which are not empty, from the files'
/// names: `<name>-<GUID>`.
#[track_caller]
fn efivarfs_variables() -> Vec<Variable> {
    let mut variables: Vec<Variable> = efivars()
        .into_iter()
        .filter(|(_, bytes)| !matches!(bytes, Ok(bytes) if bytes.is_empty()))
        .map(|(file, _)| {
            let (name, guid) = file
                .len()
                .checked_sub(EFI_GLOBAL_VARIABLE.len())
                .and_then(|at| file.split_at_checked(at))
                .and_then(|(name, guid)| Some((name.strip_suffix('-')?, guid)))
                .unwrap_or_else(|| panic!("efivar file {file} is no <name>-<GUID>"));
            Variable {
                name: name.to_string(),
                guid: guid.to_ascii_uppercase(),
            }
        })
        .collect();
    variables.sort();
    variables
}

#[test]
fn variable_list_lists_the_variables_of_the_efivar_files() {
    let variables = efivarfs_variables();
    let timeout = Variable {
        name: "Timeout".to_string(),
        guid: EFI_GLOBAL_VARIABLE.to_ascii_uppercase(),
    };
    assert!(variables.contains(&timeout), "no Timeout: {variables:#?}");

    let listed: Vec<Variable> = json(&["variable", "list"]);
    assert_eq!(listed, variables, "variable list");

    let global: Vec<Variable> = json(&["variable", "list", "--guid", EFI_GLOBAL_VARIABLE]);
    let want: Vec<&Variable> = variables
        .iter()
        .filter(|variable| variable.guid == timeout.guid)
        .collect();
    assert_eq!(global.iter().collect::<Vec<_>>(), want, "--guid");
    assert!(
        global.len() < listed.len(),
        "--guid kept every variable: {listed:#?}"
    );
}

#[test]
fn variable_info_tells_the_attributes_and_size_of_a_variable() {
    for name in ["Timeout", "ConOutDev"] {
        let (attributes, data) = global_variable(name);

        let info: serde_json::Value = json(&["variable", "info", name, EFI_GLOBAL_VARIABLE]);

        assert_eq!(
            info,
            serde_json::json!({
                "variable": file_name(name),
                "attributes": attributes,
                "size": data.len(),
            }),
            "{name}"
        );
    }

    let missing = json_error(&["variable", "info", "NoSuchVariable", EFI_GLOBAL_VARIABLE]);
    assert_eq!(
        missing.error_message,
        format!("no EFI variable {}", file_name("NoSuchVariable")),
        "a missing variable"
    );
}

/// `variable storage` tells the storage of non-volatile runtime variables that efivarfs tells,
/// which Linux does from v6.5 on, so not on the i686 guests, which run Linux 6.1
/// (`tests/qemu/guest-packages-i686`); it refuses other attributes.
#[test]
fn variable_storage_tells_the_storage_that_efivarfs_tells() {
    match cfg!(target_arch = "x86") {
        true => assert_eq!(
            json_error(&["variable", "storage"]).error_message,
            "efivarfs tells no storage of variables: Linux before v6.5 tells none, nor does a \
             later one where the firmware's QueryVariableInfo() fails or is not supported at \
             runtime; ask uefisettings.efi in the UEFI Shell",
            "Linux 6.1"
        ),
        false => {
            let storage: serde_json::Value = json(&["variable", "storage"]);
            let size = |field: &str| {
                storage[field]
                    .as_u64()
                    .unwrap_or_else(|| panic!("no {field}: {storage}"))
            };
            let maximum = size("maximum_variable_storage_size");
            assert!(
                maximum > 0 && size("remaining_variable_storage_size") <= maximum,
                "{storage}"
            );
            // f_bavail is f_bfree less what Linux keeps in reserve, 5 KiB on x86 without
            // efi_no_storage_paranoia (Linux v6.17 fs/efivarfs/super.c efivarfs_statfs(),
            // arch/x86/platform/efi/quirks.c)
            let stat = rustix::fs::statfs(EFIVARS).expect("statfs efivarfs");
            let bytes = |blocks: u64| blocks * u64::try_from(stat.f_bsize).expect("a block size");
            assert_eq!(
                (maximum, size("remaining_variable_storage_size")),
                (bytes(stat.f_blocks), bytes(stat.f_bfree)),
                "{storage}: f_blocks and f_bfree, not f_bavail"
            );
            assert_eq!(
                (&storage["attributes"], &storage["maximum_variable_size"]),
                (&serde_json::json!(NV_BS_RT), &serde_json::Value::Null),
                "{storage}"
            );
        }
    }

    let refused = json_error(&[
        "variable",
        "storage",
        "--attributes",
        "bootservice-access,runtime-access",
    ]);
    assert_eq!(
        refused.error_message,
        "efivarfs tells the storage of NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS \
         variables only, not of BOOTSERVICE_ACCESS | RUNTIME_ACCESS variables",
        "volatile runtime variables"
    );
}

#[test]
fn the_variables_have_the_attributes_and_sizes_that_the_forms_rely_on() {
    for (name, attributes) in [
        ("ConOutDev", BS_RT),
        ("LangCodes", BS_RT),
        ("PlatformLangCodes", BS_RT),
        ("Timeout", NV_BS_RT),
    ] {
        let (word, data) = global_variable(name);
        assert_eq!(word, attributes, "{name}: {data:02x?}");
        assert!(!data.is_empty(), "{name} holds no byte");
    }
    let (_, data) = global_variable("PlatformLangCodes");
    assert!(
        data.len() < LARGER_VAR_STORE,
        "PlatformLangCodes: {data:02x?}"
    );
    let (_, data) = global_variable("Timeout");
    assert_eq!(data.len(), 2, "Timeout: {data:02x?}");
}

#[test]
fn get_reads_volatile_variables() {
    for (question, name) in [(VOLATILE, "ConOutDev"), (VOLATILE_BUFFER, "LangCodes")] {
        let (got, _) = single_response(&["hii", "get", question, "--json"], BACKEND_HII);
        assert_eq!(
            got.answer,
            global_variable(name).1[0].to_string(),
            "{question}"
        );
    }
}

#[test]
fn set_of_a_volatile_variable_is_refused() {
    for (question, name) in [(VOLATILE, "ConOutDev"), (VOLATILE_BUFFER, "LangCodes")] {
        refuse(question, name, &volatile(name));
    }
}

#[test]
fn set_of_a_volatile_variable_under_a_larger_var_store_is_refused() {
    // its read before the first write fails, which refuses it
    refuse(
        VOLATILE_UNDER_A_LARGER_VAR_STORE,
        "PlatformLangCodes",
        &read_error("PlatformLangCodes"),
    );
}

#[test]
fn set_of_a_non_volatile_variable_is_written() {
    let (attributes, data) = global_variable("Timeout");
    let value = other_than(data[0]);
    let before = efivars();
    let (set, modified) =
        single_response(&["hii", "set", NON_VOLATILE, &value, "--json"], BACKEND_HII);
    assert_eq!(
        (set.answer.as_str(), modified),
        (value.as_str(), true),
        "set"
    );
    assert_eq!(
        changed(&before, &efivars()),
        [file_name("Timeout")],
        "efivar files changed"
    );
    let written = value.parse::<u8>().expect("a byte");
    assert_eq!(
        global_variable("Timeout"),
        (attributes, vec![written, data[1]]),
        "Timeout"
    );
    let (got, _) = single_response(&["hii", "get", NON_VOLATILE, "--json"], BACKEND_HII);
    assert_eq!(got.answer, value, "get after set");
}

#[test]
fn a_volatile_copy_among_several_is_refused_before_any_write() {
    refuse(VOLATILE_COPY, "Timeout", &volatile("ConOutDev"));
}

#[test]
fn an_unreadable_copy_among_several_is_refused_before_any_write() {
    refuse(UNREADABLE_COPY, "Timeout", &read_error("Timeout"));
}

#[test]
fn a_value_that_one_copy_refuses_writes_no_copy() {
    let before = efivars();
    let refused = json_error(&["hii", "set", DIFFERENT_MAXIMA, "150", "--json"]);
    assert_eq!(
        (refused.error_message.as_str(), changed(&before, &efivars())),
        ("provided value exceeded max possible value", vec![]),
        "set 150"
    );

    let (attributes, data) = global_variable("Timeout");
    let value = other_than(data[0]);
    let before = efivars();
    let Responses { responses } = json(&["hii", "set", DIFFERENT_MAXIMA, &value, "--json"]);
    assert_eq!(
        responses
            .iter()
            .map(|response| {
                let answer = response.question.answer.as_str();
                (response.selector.as_str(), answer, response.modified)
            })
            .collect::<Vec<_>>(),
        [
            (MAXIMUM_200, value.as_str(), true),
            (MAXIMUM_100, value.as_str(), true)
        ],
        "set {value}"
    );
    assert_eq!(
        changed(&before, &efivars()),
        [file_name("Timeout")],
        "efivar files changed by set {value}"
    );
    let written = value.parse::<u8>().expect("a byte");
    assert_eq!(
        global_variable("Timeout"),
        (attributes, vec![written, data[1]]),
        "Timeout after set {value}"
    );
}

/// list-strings reads the strings package whose header holds padding after Language's null
/// terminator, which the firmware's HII database exports as publish-hiidb registered it, from
/// its StringInfoOffset (UEFI 2.11 §33.3.6.1).
#[test]
fn list_strings_reads_a_strings_package_whose_header_holds_padding() {
    let packages: Vec<StringPackage> = json(&["hii", "list-strings", "--json"]);
    let padded: Vec<&StringPackage> = packages
        .iter()
        .filter(|package| {
            package
                .string_package
                .values()
                .any(|string| string == PADDED_HEADER_STRINGS[1].1)
        })
        .collect();

    let want = StringPackage {
        string_package: PADDED_HEADER_STRINGS
            .iter()
            .map(|&(id, string)| (id.to_string(), string.to_string()))
            .collect(),
        language: Some("en-US".to_string()),
    };
    assert_eq!(
        padded,
        [&want],
        "the packages holding {PADDED_HEADER_STRINGS:?}"
    );
}

/// list-strings reads the strings of publish-hiidb's `string_blocks`: those of a block of every
/// string block type in the first strings package (UEFI 2.11 §33.3.6.2), and the one string of
/// the second, to which the firmware's HII database appended an EFI_HII_SIBT_SKIP2 block.
#[test]
fn list_strings_reads_every_string_block_type() {
    let packages: Vec<StringPackage> = json(&["hii", "list-strings", "--json"]);
    let holding = |wanted: &str| -> Vec<&StringPackage> {
        packages
            .iter()
            .filter(|package| {
                package
                    .string_package
                    .values()
                    .any(|string| string == wanted)
            })
            .collect()
    };
    let package = |strings: &[(&str, &str)], language: &str| StringPackage {
        string_package: strings
            .iter()
            .map(|&(id, string)| (id.to_string(), string.to_string()))
            .collect(),
        language: Some(language.to_string()),
    };

    assert_eq!(
        holding(EVERY_STRING_BLOCK_TYPE[0].1),
        [&package(&EVERY_STRING_BLOCK_TYPE, "en-US")],
        "the packages holding {:?}",
        EVERY_STRING_BLOCK_TYPE[0].1
    );
    assert_eq!(
        holding(SECOND_STRINGS_PACKAGE),
        [&package(&[("1", SECOND_STRINGS_PACKAGE)], SECOND_LANGUAGE)],
        "the packages holding {SECOND_STRINGS_PACKAGE:?}"
    );
}

/// The firmware's HII database pads the second strings package of publish-hiidb's
/// `string_blocks` with an EFI_HII_SIBT_SKIP2 block up to the last string ID that it counts in
/// the first (edk2's AdjustStringPackage), which is the last string ID that list-strings reads
/// there. This checks only how uefisettings counts string IDs: edk2 widens SCSU bytes, and
/// decodes no SCSU string.
#[test]
fn list_strings_counts_string_ids_as_the_firmware_does() {
    let packages: Vec<StringPackage> = json(&["hii", "list-strings", "--json"]);
    let last_string_ids: Vec<u16> = packages
        .iter()
        .filter(|package| {
            package.string_package.get("1").map(String::as_str)
                == Some(EVERY_STRING_BLOCK_TYPE[0].1)
        })
        .map(|package| {
            package
                .string_package
                .keys()
                .map(|id| id.parse().expect("a string ID"))
                .max()
                .expect("a string")
        })
        .collect();
    let [last_string_id] = last_string_ids[..] else {
        panic!(
            "the last string IDs of the packages holding {:?}: {last_string_ids:?}",
            EVERY_STRING_BLOCK_TYPE[0].1
        );
    };

    let extracted = uefisettings(&["hii", "extract-db", STRING_BLOCKS_HIIDB]);
    assert_eq!(extracted.code, Some(0), "extract-db: {extracted:#?}");
    let hiidb = fs::read(STRING_BLOCKS_HIIDB)
        .unwrap_or_else(|error| panic!("cannot read {STRING_BLOCKS_HIIDB}: {error}"));
    let blocks = string_blocks(&hiidb, &STRING_BLOCKS_PACKAGE_LIST);

    // EFI_HII_SIBT_STRING_UCS2 of string ID 1, EFI_HII_SIBT_SKIP2 of the IDs after it, then
    // EFI_HII_SIBT_END
    let padded = [
        &[0x14][..],
        &ucs2(SECOND_STRINGS_PACKAGE),
        &[0x21],
        &(last_string_id - 1).to_le_bytes(),
        &[0x00],
    ]
    .concat();
    assert_eq!(
        blocks.get(SECOND_LANGUAGE),
        Some(&padded),
        "the string blocks of {SECOND_LANGUAGE}, with the strings package of {} read up to \
         string ID {last_string_id}",
        EVERY_STRING_BLOCK_TYPE[0].1
    );
}

/// The string blocks of each strings package in the package list `guid` of the HII database
/// `hiidb`, by Language.
#[track_caller]
fn string_blocks(hiidb: &[u8], guid: &[u8; 16]) -> BTreeMap<String, Vec<u8>> {
    let mut rest = hiidb;
    let mut blocks = BTreeMap::new();
    while !rest.is_empty() {
        let (list, next) = rest.split_at(uint32(rest, PACKAGE_LENGTH_OFFSET));
        rest = next;
        if !list.starts_with(guid) {
            continue;
        }

        let mut packages = &list[PACKAGE_LIST_HEADER_SIZE..];
        while !packages.is_empty() {
            // Length, the low 24 bits, then Type
            let header = uint32(packages, 0);
            let (package, next) = packages.split_at(header & 0x00FF_FFFF);
            packages = next;
            if header >> 24 != usize::from(EFI_HII_PACKAGE_STRINGS) {
                continue;
            }
            let language = &package[LANGUAGE_OFFSET..];
            let language = &language[..language
                .iter()
                .position(|&byte| byte == 0)
                .expect("a null-terminated Language")];
            blocks.insert(
                String::from_utf8(language.to_vec()).expect("an ASCII Language"),
                package[uint32(package, STRING_INFO_OFFSET_OFFSET)..].to_vec(),
            );
        }
    }
    blocks
}

/// The UINT32 at `offset` in `bytes`.
#[track_caller]
fn uint32(bytes: &[u8], offset: usize) -> usize {
    let field = bytes[offset..offset + 4].try_into().expect("a UINT32");
    usize::try_from(u32::from_le_bytes(field)).expect("a UINT32 fits usize")
}

/// `string` as a null-terminated CHAR16 string.
fn ucs2(string: &str) -> Vec<u8> {
    string
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}
