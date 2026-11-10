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

//! The boot of the scenario short-var-store: publish-hiidb's `rt-data-short-var-store-forms`
//! registers the forms of `publish-hiidb/src/short_var_store_forms.rs` before it publishes the
//! HII database, and `vars/short-var-store.json` creates their variables: ShortVarA holds 5,
//! ShortVarB and ShortVarC 0, and ShortVarPw 20 bytes of 0xAA, standing for a password. On their
//! VARSTORE_EFI of the form before UEFI 2.3.1, each question keeps its value alone in the EFI
//! variable that its VarName names, of the store's Guid: get reads it and set writes it, the GET
//! of a SUPPRESS_IF and the SET of a WRITE expression reach the variables of their VarNames, the
//! PASSWORD's variable is neither read nor written, and dump-efivars copies the variables that
//! the questions read. set creates the missing ShortVarD of a UINT16 NUMERIC with the store's
//! Attributes. Each ORDERED_LIST and the REF read the whole variable of their VarName, which holds
//! their StorageWidth, and refuse one of another size; set writes the items of an ORDERED_LIST,
//! creating the missing ShortVarN, and neither the REF nor an ORDERED_LIST over the password.

use std::fs;
use std::path::Path;

use serde::Deserialize;
use uefisettings_qemu_guest::json_error;
use uefisettings_qemu_guest::single_response;
use uefisettings_qemu_guest::uefisettings;
use uefisettings_qemu_guest::variable_bytes;
use uefisettings_qemu_guest::variable_data;
use uefisettings_qemu_guest::ErrorObject;
use uefisettings_qemu_guest::BACKEND_HII;

/// The Guid of the VARSTORE_EFI, the vendor GUID of each variable of a VarName.
const VENDOR: &str = "8c78a505-baa0-4c4a-869f-000000000b01";
/// VENDOR as an EFI_GUID stores it.
const VENDOR_BYTES: [u8; 16] = [
    0x05, 0xA5, 0x78, 0x8C, 0xA0, 0xBA, 0x4A, 0x4C, 0x86, 0x9F, 0x00, 0x00, 0x00, 0x00, 0x0B, 0x01,
];
/// The UINT8 NUMERIC on ShortVarA.
const SHORT_NUMERIC: &str = "Short numeric";
/// The UINT8 ONE_OF on ShortVarB, of Disabled (0) and Enabled (1).
const SHORT_ONE_OF: &str = "Short one-of";
/// The CHECKBOX on ShortVarC that a SUPPRESS_IF hides while the GET of ShortVarA gives 5, whose
/// WRITE sets ShortVarB to its value.
const SHORT_CHECKBOX: &str = "Short checkbox";
/// The UINT16 NUMERIC on ShortVarD, which no variable holds until set creates it.
const SHORT_CREATED: &str = "Short created";
/// The ORDERED_LIST of 3 UINT8 containers on ShortVarL, of the options First (1), Second (2) and
/// Third (3), as are the other ORDERED_LISTs.
const SHORT_LIST: &str = "Short list";
/// The EFI_IFR_REF5 on ShortVarR.
const SHORT_REF: &str = "Short ref";
/// The ORDERED_LIST of 2 UINT16 containers on ShortVarW.
const SHORT_WIDE_LIST: &str = "Short wide list";
/// The ORDERED_LIST of 2 UINT8 containers on ShortVarM, which holds 3 bytes.
const SHORT_MISMATCH_LIST: &str = "Short mismatch list";
/// The ORDERED_LIST of 20 UINT8 containers on ShortVarPw, the PASSWORD's variable.
const SHORT_PASSWORD_LIST: &str = "Short password list";
/// The ORDERED_LIST of 3 UINT8 containers on ShortVarN, which no variable holds until set creates
/// it.
const SHORT_MISSING_LIST: &str = "Short missing list";
/// The Attributes of the VARSTORE_EFI: non-volatile, boot service and runtime access.
const NV_BS_RT: u32 = 0x07;
/// The variables of the questions, then that of the PASSWORD.
const VARIABLES: [&str; 4] = ["ShortVarA", "ShortVarB", "ShortVarC", "ShortVarPw"];
/// The variables of the ORDERED_LISTs and the REF that vars/short-var-store.json creates.
const LIST_VARIABLES: [&str; 4] = ["ShortVarL", "ShortVarR", "ShortVarW", "ShortVarM"];
/// What would show a byte of the password: 0xAA in hex or decimal.
const PASSWORD_TEXTS: [&str; 5] = ["aa aa", "AA AA", "aaaa", "AAAA", "170, 170"];

/// What `hii dump-efivars` prints.
#[derive(Debug, Deserialize)]
struct Dump {
    directory: String,
}

/// The efivarfs file of the variable `name` of VENDOR.
fn efivar(name: &str) -> String {
    format!("/sys/firmware/efi/efivars/{name}-{VENDOR}")
}

/// The data of the variables of VARIABLES, in their order.
fn variables() -> Vec<Vec<u8>> {
    VARIABLES
        .map(|name| variable_data(&efivar(name)).unwrap_or_else(|| panic!("no {name}")))
        .to_vec()
}

/// The data of the variables of VARIABLES and LIST_VARIABLES, in their order.
fn all_variables() -> Vec<Vec<u8>> {
    [&VARIABLES[..], &LIST_VARIABLES]
        .concat()
        .into_iter()
        .map(|name| variable_data(&efivar(name)).unwrap_or_else(|| panic!("no {name}")))
        .collect()
}

/// Sets the ORDERED_LIST `question` to `items`; panics unless set answers them, joined by `, `.
#[track_caller]
fn set_items(question: &str, items: &[&str]) {
    let args = [
        &["hii", "set", "--json", question][..],
        &items
            .iter()
            .flat_map(|&item| ["--item", item])
            .collect::<Vec<_>>(),
    ]
    .concat();
    let (set, _) = single_response(&args, BACKEND_HII);
    assert_eq!(set.answer, items.join(", "), "{args:?}");
}

/// Sets `question` to `value`; panics unless set answers `value` and says whether it changed.
#[track_caller]
fn set(question: &str, value: &str) {
    let (set, _) = single_response(&["hii", "set", "--json", question, value], BACKEND_HII);
    assert_eq!(set.answer, value, "set {question} {value}");
}

/// In the database as the firmware exports it, which dump-efivars saves, the 24 bytes of the
/// VARSTORE_EFI of the form before UEFI 2.3.1 are followed by the FORM of FormId 1:
/// edk2-stable202608 SetupBrowserDxe/IfrParse.c CreateStorage reads that FORM's OpCode and Length
/// as a Size and its FormId as the Name, which the FormId's high byte, 0x00, ends
/// (`publish-hiidb/src/short_var_store_forms.rs`).
#[test]
fn the_form_after_the_short_var_store_ends_the_name_that_edk2_reads() {
    let dir = "/tmp/short-var-store-hiidb";
    let dump: Dump = uefisettings(&["hii", "dump-efivars", dir]).json(0);
    assert_eq!(dump.directory, dir, "{dump:#?}");
    let hiidb = fs::read(format!("{dir}/hiidb.bin"))
        .unwrap_or_else(|error| panic!("cannot read hiidb.bin in {dir}: {error}"));
    // EFI_IFR_VARSTORE_EFI of Length 24, VarStoreId 1, the Guid, Attributes 7
    let short_op = [&[0x26, 24, 1, 0][..], &VENDOR_BYTES, &[7, 0, 0, 0]].concat();
    let at = hiidb
        .windows(short_op.len())
        .position(|bytes| bytes == short_op)
        .unwrap_or_else(|| panic!("no short VARSTORE_EFI {short_op:02x?} in hiidb.bin"));
    // EFI_IFR_FORM with the Scope bit, Length 6, then FormId 1
    assert_eq!(
        hiidb.get(at + short_op.len()..at + short_op.len() + 4),
        Some(&[0x01, 0x86, 0x01, 0x00][..]),
        "the bytes after the short VARSTORE_EFI at {at:#x} of hiidb.bin"
    );
}

/// get answers each question from the variable of its VarName.
#[test]
fn get_reads_the_variable_of_each_var_name() {
    for (question, name, data, answer) in [
        (SHORT_NUMERIC, "ShortVarA", [5], "5"),
        (SHORT_ONE_OF, "ShortVarB", [0], "Disabled"),
    ] {
        assert_eq!(variable_data(&efivar(name)), Some(data.to_vec()), "{name}");
        let (got, _) = single_response(&["hii", "get", "--json", question], BACKEND_HII);
        assert_eq!(got.answer, answer, "get {question}");
    }
}

/// set writes the variable of the question's VarName, and no other.
#[test]
fn set_writes_the_variable_of_its_var_name_only() {
    let before = variables();

    set(SHORT_NUMERIC, "7");
    let mut want = before.clone();
    want[0] = vec![7];
    assert_eq!(variables(), want, "after set {SHORT_NUMERIC} 7");

    set(SHORT_NUMERIC, "5");
    assert_eq!(variables(), before, "after set {SHORT_NUMERIC} back");
}

/// set refuses the CHECKBOX while the GET of its SUPPRESS_IF reads 5 from ShortVarA, and sets it
/// once ShortVarA holds 9: it writes ShortVarC, and the SET of its WRITE ShortVarB, which the
/// ONE_OF then answers.
#[test]
fn a_get_and_a_set_reach_the_variables_of_their_var_names() {
    let before = variables();
    let args = ["hii", "set", "--json", SHORT_CHECKBOX, "1"];
    let error: ErrorObject = uefisettings(&args).json(1);
    assert_eq!(
        error.error_message,
        format!(
            "question {SHORT_CHECKBOX:?} is suppressed; also include suppressed questions to \
             select it"
        ),
        "{args:?} while ShortVarA holds 5"
    );
    assert_eq!(variables(), before, "after the refused set");

    set(SHORT_NUMERIC, "9");
    set(SHORT_CHECKBOX, "1");
    assert_eq!(
        variables(),
        [vec![9], vec![1], vec![1], before[3].clone()],
        "after set {SHORT_CHECKBOX} 1"
    );
    let (got, _) = single_response(&["hii", "get", "--json", SHORT_ONE_OF], BACKEND_HII);
    assert_eq!(got.answer, "Enabled", "get {SHORT_ONE_OF}");

    set(SHORT_CHECKBOX, "0");
    set(SHORT_NUMERIC, "5");
    assert_eq!(variables(), before, "after setting them back");
}

/// set creates the missing variable of a question's VarName through efivarfs, with the Attributes
/// of its VARSTORE_EFI and the question's 2 bytes, writing no other variable; get then reads it.
#[test]
fn set_creates_the_missing_variable_of_its_var_name() {
    let created = efivar("ShortVarD");
    assert_eq!(variable_bytes(&created), None, "{created} before set");
    let before = variables();

    set(SHORT_CREATED, "513");

    assert_eq!(
        variable_bytes(&created),
        Some([&NV_BS_RT.to_le_bytes()[..], &513u16.to_le_bytes()].concat()),
        "{created} after set {SHORT_CREATED} 513"
    );
    assert_eq!(variables(), before, "the other variables");
    let (got, _) = single_response(&["hii", "get", "--json", SHORT_CREATED], BACKEND_HII);
    assert_eq!(got.answer, "513", "get {SHORT_CREATED}");
}

/// get answers each ORDERED_LIST and the REF from the whole variable of its VarName, and refuses
/// a variable of another size than the question's containers, and the ORDERED_LIST over the
/// PASSWORD's variable.
#[test]
fn ordered_lists_and_a_ref_read_the_variables_of_their_var_names() {
    let items = |items: &[&str]| Some(items.iter().map(|&item| item.to_owned()).collect());
    for (question, answer, listed) in [
        (
            SHORT_LIST,
            "Third, First, Second",
            items(&["Third", "First", "Second"]),
        ),
        (
            SHORT_REF,
            "QuestionId 0x0001, FormId 0x0001, FormSetGuid 8C78A505-BAA0-4C4A-869F-000000000B00, \
             DevicePath none",
            None,
        ),
        (SHORT_WIDE_LIST, "First, Second", items(&["First", "Second"])),
        (
            SHORT_MISMATCH_LIST,
            "<ValueUnavailable: EFI variable ShortVarM-8c78a505-baa0-4c4a-869f-000000000b01 holds 3 \
             bytes; the question takes 2>",
            None,
        ),
        (
            SHORT_PASSWORD_LIST,
            "<ValueUnavailable: its bytes hold a password>",
            None,
        ),
    ] {
        let (got, _) = single_response(&["hii", "get", "--json", question], BACKEND_HII);
        assert_eq!(
            (got.answer.as_str(), got.items),
            (answer, listed),
            "get {question}"
        );
    }
}

/// set writes the items of an ORDERED_LIST to the variable of its VarName whole, and no other
/// variable.
#[test]
fn set_writes_the_items_of_a_list_to_the_variable_of_its_var_name_only() {
    let before = all_variables();

    set_items(SHORT_LIST, &["First", "Third"]);
    let mut want = before.clone();
    want[VARIABLES.len()] = vec![1, 3, 0];
    assert_eq!(all_variables(), want, "after set {SHORT_LIST} First, Third");

    set_items(SHORT_LIST, &["Third", "First", "Second"]);
    assert_eq!(all_variables(), before, "after set {SHORT_LIST} back");
}

/// set refuses the REF, the target of its link, and the ORDERED_LIST over the password, and
/// writes no variable.
#[test]
fn set_writes_neither_a_ref_nor_a_list_over_the_password() {
    let before = all_variables();
    let set_ref = ["hii", "set", "--json", SHORT_REF, "0"];
    let set_list = [
        "hii",
        "set",
        "--json",
        SHORT_PASSWORD_LIST,
        "--item",
        "First",
    ];
    for (args, refusal) in [
        (
            &set_ref[..],
            format!(
                "cannot set question {SHORT_REF:?}: set does not write the EFI_HII_REF of a \
                 cross-reference question, the target of its link (UEFI 2.11 §33.2.5.4.10)"
            ),
        ),
        (
            &set_list[..],
            format!(
                "cannot set question {SHORT_PASSWORD_LIST:?}: its items cannot be read, so set \
                 cannot keep those of hidden options: its bytes hold a password"
            ),
        ),
    ] {
        assert_eq!(json_error(args).error_message, refusal, "{args:?}");
        assert_eq!(all_variables(), before, "after {args:?}");
    }
}

/// set creates the missing variable of an ORDERED_LIST's VarName through efivarfs, with the
/// Attributes of its VARSTORE_EFI, its item and the empty containers after it, writing no other
/// variable; get then reads it.
#[test]
fn set_creates_the_missing_variable_of_a_list() {
    let created = efivar("ShortVarN");
    assert_eq!(variable_bytes(&created), None, "{created} before set");
    let before = all_variables();

    set_items(SHORT_MISSING_LIST, &["Second"]);

    assert_eq!(
        variable_bytes(&created),
        Some([&NV_BS_RT.to_le_bytes()[..], &[2, 0, 0]].concat()),
        "{created} after set {SHORT_MISSING_LIST} Second"
    );
    assert_eq!(all_variables(), before, "the other variables");
    let (got, _) = single_response(&["hii", "get", "--json", SHORT_MISSING_LIST], BACKEND_HII);
    assert_eq!(got.answer, "Second", "get {SHORT_MISSING_LIST}");
}

/// get, list-questions and show-ifr show no byte of the password, which ShortVarPw keeps after
/// the other tests' sets.
#[test]
fn the_password_variable_is_neither_read_nor_written() {
    for args in [
        &["hii", "get", "--json", SHORT_NUMERIC][..],
        &["hii", "list-questions", "--json"],
        &["hii", "show-ifr"],
    ] {
        let output = uefisettings(args);
        assert_eq!(output.code, Some(0), "{args:?}: {output:#?}");
        for text in PASSWORD_TEXTS {
            assert!(
                !output.stdout.contains(text) && !output.stderr.contains(text),
                "{args:?} shows {text:?}: {output:#?}"
            );
        }
    }
    assert_eq!(
        variable_data(&efivar("ShortVarPw")),
        Some(vec![0xAA; 20]),
        "ShortVarPw"
    );
}

/// The redacted dump-efivars copies the variables that the questions and the GET read, whole, as
/// they are live, and not ShortVarPw.
#[test]
fn dump_efivars_copies_the_variables_of_the_var_names() {
    let dir = "/tmp/short-var-store-efivars";
    let dump: Dump = uefisettings(&["hii", "dump-efivars", dir]).json(0);
    assert_eq!(dump.directory, dir, "{dump:#?}");

    for name in &VARIABLES[..3] {
        let file = format!("{name}-{VENDOR}");
        let dumped = fs::read(format!("{dir}/{file}"))
            .unwrap_or_else(|error| panic!("cannot read {file} in {dir}: {error}"));
        assert_eq!(Some(dumped), variable_bytes(&efivar(name)), "{file}");
    }
    let password = format!("{dir}/ShortVarPw-{VENDOR}");
    assert!(!Path::new(&password).exists(), "{password} in the dump");
}
