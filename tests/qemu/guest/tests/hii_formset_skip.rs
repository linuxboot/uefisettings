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

//! The scenario `hii-formset-skip`: `publish-hiidb.efi formset-skip-forms` registers the forms
//! of `publish-hiidb/src/formset_skip_forms.rs`, two package lists, and `publish-hiidb.efi
//! rt-data` publishes the HII database. In the first, four form sets, all but the second on
//! UefisettingsFormSetSkip, the second on UefisettingsSkippedForm; in the second, two on
//! UefisettingsFirstFormSetSkip. uefisettings ignores the second form set of the first list and
//! the first of the second, each with a VARSTORE op shorter than its minimum (UEFI 2.11
//! §33.2.5.10.1), and disables the second form of the third form set of the first list, whose
//! CHECKBOX op is shorter than its minimum; it reads the questions of the others, but withholds
//! every byte of each variable that an ignored form set declares, so "Fourth setting" too, and
//! the bytes of the PASSWORD of that form, which "Over password" of the fourth form set overlaps,
//! and names the IFR that it ignores, that form too: get and set in the ignored_ifr of their
//! answer and in set's refusal of a question in it, list-questions on stderr.

use std::fs;

use serde::Deserialize;
use uefisettings_qemu_guest::changed_bytes;
use uefisettings_qemu_guest::json_error;
use uefisettings_qemu_guest::single_response;
use uefisettings_qemu_guest::uefisettings_with_env;
use uefisettings_qemu_guest::variable_data;
use uefisettings_qemu_guest::Output;
use uefisettings_qemu_guest::Question;
use uefisettings_qemu_guest::BACKEND_HII;
use uefisettings_qemu_guest::EFIVARFS_HEADER_SIZE;

/// The efivarfs file of UefisettingsFormSetSkip, the VARSTORE_EFI of the first list.
const FORMSET_SKIP: &str =
    "/sys/firmware/efi/efivars/UefisettingsFormSetSkip-8c78a505-baa0-4c4a-869f-000000001203";
/// The efivarfs file of UefisettingsFirstFormSetSkip, the VARSTORE_EFI of the second list.
const FIRST_FORMSET_SKIP: &str =
    "/sys/firmware/efi/efivars/UefisettingsFirstFormSetSkip-8c78a505-baa0-4c4a-869f-000000001213";
/// The bytes that tests/qemu/vars/formset-skip.json creates UefisettingsFormSetSkip with: 20
/// bytes that no question holds, "First setting" and "Third setting", then the password of the
/// disabled form and "Disabled setting".
const STORE_DATA: [u8; 43] = [
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0x01, 0x03, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
    0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0x05,
];
/// The bytes of UefisettingsFormSetSkip that the PASSWORD of the disabled form holds.
const DISABLED_PASSWORD_BYTES: std::ops::Range<usize> = 22..42;
/// The byte of UefisettingsFormSetSkip that "Disabled setting" holds.
const DISABLED_SETTING_OFFSET: usize = 42;
/// What shows a byte of the PASSWORD of the disabled form, 0xBB.
const DISABLED_PASSWORD_TEXTS: [&str; 5] = ["bb bb", "BB BB", "bbbb", "BBBB", "187, 187"];
/// The answer of a question whose bytes overlap a password's.
const PASSWORD_BYTES: &str = "<ValueUnavailable: its bytes hold a password>";
/// The environment of the runs that check for DISABLED_PASSWORD_TEXTS, which logs all that
/// uefisettings logs.
const TRACE: [(&str, &str); 1] = [("RUST_LOG", "trace")];
/// The bytes that tests/qemu/vars/formset-skip.json creates UefisettingsFirstFormSetSkip with: the
/// password of the ignored form set that declares it, then "Fourth setting".
const FIRST_STORE_DATA: [u8; 21] = [
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0x04,
];
/// The byte of UefisettingsFormSetSkip that "Third setting" holds.
const THIRD_SETTING_OFFSET: usize = 21;
/// The reason, up to its error, of each FormSet that uefisettings ignores.
const REASON: &str = "which holds, outside its forms, an op shorter than its minimum, which UEFI \
     2.11 §33.2.5.10.1 calls malformed, in no form for that section to disable: ";
/// The reason, up to its error, of the form that uefisettings disables.
const DISABLED_REASON: &str = "the form 2 of the FormSet 8C78A505-BAA0-4C4A-869F-000000001202, \
     whose EFI_IFR_CHECKBOX op is malformed; UEFI 2.11 §33.2.5.10.1 disables the form of a \
     malformed op: ";
/// The IFR that uefisettings ignores, each as its package list, its offset in the form package
/// and the FormSet, or None for the disabled form: the second form set of the first list, at the
/// end of the first, the second form of its third form set, and the first form set of the second
/// list.
const IGNORED: [(&str, u64, Option<&str>); 3] = [
    (
        "8C78A505-BAA0-4C4A-869F-000000001200",
        118,
        Some("8C78A505-BAA0-4C4A-869F-000000001201"),
    ),
    ("8C78A505-BAA0-4C4A-869F-000000001200", 356, None),
    (
        "8C78A505-BAA0-4C4A-869F-000000001210",
        0,
        Some("8C78A505-BAA0-4C4A-869F-000000001211"),
    ),
];

/// What `hii dump-efivars` prints.
#[derive(Debug, Deserialize)]
struct Dump {
    directory: String,
}

#[track_caller]
fn store_data(path: &str) -> Vec<u8> {
    variable_data(path).expect("tests/qemu/vars/formset-skip.json creates the variable")
}

/// The reason of IGNORED's record of the FormSet `form_set`, or of the disabled form for None, up
/// to its error.
fn reason(form_set: Option<&str>) -> String {
    match form_set {
        Some(form_set) => format!("the FormSet {form_set}, {REASON}"),
        None => DISABLED_REASON.to_string(),
    }
}

/// IGNORED as uefisettings names it, up to its error.
fn ignored_texts() -> Vec<String> {
    IGNORED
        .iter()
        .map(|(list, offset, form_set)| {
            format!(
                "the IFR that uefisettings ignores at offset {offset} of a form package of \
                 package list {list}: {}",
                reason(*form_set)
            )
        })
        .collect()
}

/// Runs `uefisettings` with `args` and TRACE; panics if its standard output or error holds any
/// of DISABLED_PASSWORD_TEXTS.
#[track_caller]
fn showing_no_password(args: &[&str]) -> Output {
    let output = uefisettings_with_env(args, &TRACE);
    for text in DISABLED_PASSWORD_TEXTS {
        assert!(
            !output.stdout.contains(text) && !output.stderr.contains(text),
            "{args:?} shows {text:?}: {output:#?}"
        );
    }
    output
}

/// Whether the ignored_ifr of the JSON answer `answer` lists IGNORED, in order.
#[track_caller]
fn lists_ignored(answer: &serde_json::Value) -> bool {
    let Some(records) = answer
        .get("ignored_ifr")
        .and_then(|records| records.as_array())
    else {
        return false;
    };
    records.len() == IGNORED.len()
        && records
            .iter()
            .zip(IGNORED)
            .all(|(record, (list, offset, form_set))| {
                record["package_list"].as_str() == Some(list)
                    && record["offset"].as_u64() == Some(offset)
                    && record["reason"]
                        .as_str()
                        .is_some_and(|got| got.starts_with(&reason(form_set)))
            })
}

/// list-questions prints the questions of the form sets that it reads, not the PASSWORDs of
/// those that it ignores nor the questions of the disabled form, in its JSON array, and names
/// each ignored form set and the disabled form on stderr.
#[test]
fn list_questions_names_the_ignored_form_sets_on_stderr() {
    let output = showing_no_password(&["hii", "list-questions", "--json"]);
    let questions: Vec<Question> = output.json(0);
    let names: Vec<&str> = questions
        .iter()
        .map(|question| question.name.as_str())
        .filter(|name| {
            [
                "First setting",
                "Password",
                "Third setting",
                "Over password",
                "Disabled setting",
                "Fourth setting",
            ]
            .contains(name)
        })
        .collect();
    assert_eq!(
        names,
        [
            "First setting",
            "Third setting",
            "Over password",
            "Fourth setting"
        ],
        "{output:#?}"
    );
    for ignored in ignored_texts() {
        let warning = format!("warning: questions may be in {ignored}");
        assert_eq!(
            output
                .stderr
                .lines()
                .filter(|line| line.starts_with(&warning))
                .count(),
            1,
            "{warning}: {output:#?}"
        );
    }
}

/// get reads the questions of the form sets that it reads, not those of the disabled form, and
/// lists the IFR that it ignores in ignored_ifr; "Over password" shows no byte of the PASSWORD of
/// the disabled form, nor "Fourth setting" any of UefisettingsFirstFormSetSkip, which an ignored
/// form set declares. set writes "Third setting" alone, and refuses "Fourth setting", the
/// PASSWORD and "Disabled setting", which no form that it reads holds, naming the IFR that it
/// ignores. In one test, as set changes what get sees.
#[test]
fn get_and_set_read_past_the_ignored_form_sets() {
    assert_eq!(store_data(FORMSET_SKIP), STORE_DATA, "before");
    assert_eq!(
        store_data(FIRST_FORMSET_SKIP),
        FIRST_STORE_DATA,
        "before: first"
    );
    for (question, answer) in [("First setting", "1"), ("Third setting", "3")] {
        let output = showing_no_password(&["hii", "get", question, "--json"]);
        let got: serde_json::Value = output.json(0);
        assert_eq!(
            got["responses"][0]["question"]["answer"].as_str(),
            Some(answer),
            "get {question}: {output:#?}"
        );
        assert!(lists_ignored(&got), "get {question}: {output:#?}");
    }
    for question in ["Over password", "Fourth setting"] {
        let output = showing_no_password(&["hii", "get", question, "--json"]);
        let got: serde_json::Value = output.json(0);
        assert!(
            got["responses"][0]["question"]["answer"]
                .as_str()
                .is_some_and(|answer| answer.starts_with(PASSWORD_BYTES)),
            "get {question}: {output:#?}"
        );
    }
    let output = showing_no_password(&["hii", "get", "Disabled setting", "--json"]);
    let got: serde_json::Value = output.json(0);
    assert!(
        got["responses"].as_array().is_some_and(Vec::is_empty) && lists_ignored(&got),
        "get Disabled setting: {output:#?}"
    );

    let (set, modified) =
        single_response(&["hii", "set", "Third setting", "4", "--json"], BACKEND_HII);
    assert_eq!((set.answer.as_str(), modified), ("4", true), "{set:#?}");
    assert_eq!(
        changed_bytes(&STORE_DATA, &store_data(FORMSET_SKIP)),
        [(THIRD_SETTING_OFFSET, 4)],
        "set Third setting writes its byte alone"
    );

    let before = (store_data(FORMSET_SKIP), store_data(FIRST_FORMSET_SKIP));
    let error = json_error(&["hii", "set", "Fourth setting", "5", "--json"]);
    assert!(
        error
            .error_message
            .contains("holds a password in every byte from 0 on, which set never writes"),
        "set Fourth setting: {error:#?}"
    );
    assert_eq!(
        (store_data(FORMSET_SKIP), store_data(FIRST_FORMSET_SKIP)),
        before,
        "set Fourth setting writes nothing"
    );
    let [first, second, third] = <[String; 3]>::try_from(ignored_texts()).expect("IGNORED holds 3");
    for (question, value) in [("Password", "x"), ("Disabled setting", "6")] {
        let error = json_error(&["hii", "set", question, value, "--json"]);
        assert!(
            error.error_message.starts_with(&format!(
                "no question \"{question}\" in the HiiDB, but it may be in {first}"
            )) && error.error_message.contains(&format!("; {second}"))
                && error.error_message.contains(&format!("; {third}")),
            "set {question}: {error:#?}"
        );
        assert_eq!(
            (store_data(FORMSET_SKIP), store_data(FIRST_FORMSET_SKIP)),
            before,
            "set {question} writes nothing"
        );
    }
}

/// The efivarfs file name of the efivarfs path `path`.
fn file_name(path: &str) -> &str {
    path.rsplit('/').next().expect("an efivarfs file name")
}

/// The redacted dump-efivars keeps no byte of the PASSWORD of the disabled form, which "Over
/// password" overlaps, nor "Disabled setting", which no question that uefisettings reads holds:
/// those bytes of UefisettingsFormSetSkip are 0 there, and "Third setting" is as it is live. It
/// keeps no UefisettingsFirstFormSetSkip, which an ignored form set declares.
#[test]
fn dump_efivars_keeps_no_byte_of_the_disabled_password() {
    let dir = "/tmp/formset-skip-efivars";
    let dump: Dump = showing_no_password(&["hii", "dump-efivars", dir]).json(0);
    assert_eq!(dump.directory, dir, "{dump:#?}");

    let first = format!("{dir}/{}", file_name(FIRST_FORMSET_SKIP));
    assert!(
        fs::symlink_metadata(&first).is_err(),
        "{first}: in the dump"
    );
    let file = file_name(FORMSET_SKIP);
    let dumped = fs::read(format!("{dir}/{file}"))
        .unwrap_or_else(|error| panic!("cannot read {file} in {dir}: {error}"));
    let data = dumped
        .get(EFIVARFS_HEADER_SIZE..)
        .unwrap_or_else(|| panic!("{file}: no attributes in {dumped:02x?}"));
    let live = store_data(FORMSET_SKIP);
    assert_eq!(
        data.get(DISABLED_PASSWORD_BYTES),
        Some(&[0; 20][..]),
        "{file}: the disabled password's bytes in the dump"
    );
    assert_eq!(
        data.get(DISABLED_SETTING_OFFSET),
        Some(&0),
        "{file}: Disabled setting in the dump"
    );
    assert_eq!(
        data.get(THIRD_SETTING_OFFSET),
        live.get(THIRD_SETTING_OFFSET),
        "{file}: Third setting in the dump"
    );
}
