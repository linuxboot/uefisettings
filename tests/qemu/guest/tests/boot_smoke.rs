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

//! A guest that boots without an HII fixture: OVMF publishes no HII database, so no backend
//! is detected and every HII command fails cleanly.

use std::fs;
use std::io;

use uefisettings_qemu_guest::json;
use uefisettings_qemu_guest::json_error;
use uefisettings_qemu_guest::require_test_vm;
use uefisettings_qemu_guest::MachineInfo;
use uefisettings_qemu_guest::BACKEND_UNKNOWN;
use uefisettings_qemu_guest::EFIVARS;
use uefisettings_qemu_guest::HIIDB_VARIABLE;

/// The vendor GUID of the variables that the UEFI specification defines, such as
/// `BootOrder`, as efivarfs spells it at the end of their file names.
const GLOBAL_VARIABLE_SUFFIX: &str = "-8be4df61-93ca-11d2-aa0d-00e098032b8c";

/// Any question; no backend has questions here.
const QUESTION: &str = "Serial port IO address";

#[test]
fn efivarfs_lists_the_global_variables() {
    require_test_vm();
    let names: Vec<String> = fs::read_dir(EFIVARS)
        .expect("cannot list efivarfs")
        .map(|entry| {
            entry
                .expect("cannot list efivarfs")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    assert!(
        names
            .iter()
            .any(|name| name.ends_with(GLOBAL_VARIABLE_SUFFIX)),
        "no global variable among {names:?}"
    );
}

#[test]
fn no_hii_database_is_published() {
    require_test_vm();
    let error = fs::metadata(HIIDB_VARIABLE).expect_err("the HiiDB variable exists");
    assert_eq!(error.kind(), io::ErrorKind::NotFound, "{error}");
}

#[test]
fn identify_detects_no_backend() {
    let machine: MachineInfo = json(&["identify", "--json"]);
    assert_eq!(machine.backend, [BACKEND_UNKNOWN]);
}

#[test]
fn generic_get_fails() {
    json_error(&["get", QUESTION, "--json"]);
}

#[test]
fn hii_get_fails() {
    json_error(&["hii", "get", QUESTION, "--json"]);
}

#[test]
fn hii_set_fails() {
    json_error(&["hii", "set", QUESTION, "2F8", "--json"]);
}

#[test]
fn hii_list_questions_fails() {
    json_error(&["hii", "list-questions", "--json"]);
}

#[test]
fn hii_list_strings_fails() {
    json_error(&["hii", "list-strings", "--json"]);
}

#[test]
fn hii_show_ifr_fails() {
    json_error(&["hii", "show-ifr"]);
}

#[test]
fn hii_extract_db_fails() {
    json_error(&["hii", "extract-db", "/tmp/hiidb.bin"]);
}
