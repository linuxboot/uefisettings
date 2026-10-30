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
//! and Timeout. Each check of `set` compares every efivar file before and after.

use std::collections::BTreeMap;
use std::fs;

use uefisettings_qemu_guest::json;
use uefisettings_qemu_guest::json_error;
use uefisettings_qemu_guest::require_test_vm;
use uefisettings_qemu_guest::single_response;
use uefisettings_qemu_guest::Responses;
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
