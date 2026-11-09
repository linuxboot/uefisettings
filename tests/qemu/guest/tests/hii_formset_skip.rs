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
//! rt-data` publishes the HII database. In the first, three form sets on UefisettingsFormSetSkip;
//! in the second, two on UefisettingsFirstFormSetSkip. uefisettings ignores the second form set
//! of the first list and the first of the second, each with a VARSTORE op shorter than its
//! minimum (UEFI 2.11 §33.2.5.10.1), reads the questions of the others, and names the IFR that it
//! ignores: get and set in the ignored_ifr of their answer and in set's refusal of a question in
//! it, list-questions on stderr.

use uefisettings_qemu_guest::changed_bytes;
use uefisettings_qemu_guest::json_error;
use uefisettings_qemu_guest::single_response;
use uefisettings_qemu_guest::uefisettings;
use uefisettings_qemu_guest::variable_data;
use uefisettings_qemu_guest::Question;
use uefisettings_qemu_guest::BACKEND_HII;

/// The efivarfs file of UefisettingsFormSetSkip, the VARSTORE_EFI of the first list.
const FORMSET_SKIP: &str =
    "/sys/firmware/efi/efivars/UefisettingsFormSetSkip-8c78a505-baa0-4c4a-869f-000000001203";
/// The efivarfs file of UefisettingsFirstFormSetSkip, the VARSTORE_EFI of the second list.
const FIRST_FORMSET_SKIP: &str =
    "/sys/firmware/efi/efivars/UefisettingsFirstFormSetSkip-8c78a505-baa0-4c4a-869f-000000001213";
/// The bytes that tests/qemu/vars/formset-skip.json creates UefisettingsFormSetSkip with: a
/// password, then "First setting" and "Third setting".
const STORE_DATA: [u8; 22] = [
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0x01, 0x03,
];
/// The bytes that tests/qemu/vars/formset-skip.json creates UefisettingsFirstFormSetSkip with: a
/// password, then "Fourth setting".
const FIRST_STORE_DATA: [u8; 21] = [
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0x04,
];
/// The byte of UefisettingsFormSetSkip that "Third setting" holds.
const THIRD_SETTING_OFFSET: usize = 21;
/// The byte of UefisettingsFirstFormSetSkip that "Fourth setting" holds.
const FOURTH_SETTING_OFFSET: usize = 20;
/// The reason, up to the binrw error, of each FormSet that uefisettings ignores.
const REASON: &str = "which does not parse; uefisettings ignores it, where UEFI 2.11 §33.2.5.10.1 \
     disables only the form of a malformed op and ignores only a malformed forms set: ";
/// The IFR that uefisettings ignores, each as its package list, its offset in the form package
/// and the FormSet: the second form set of the first list, at the end of the first, and the first
/// of the second list.
const IGNORED: [(&str, u64, &str); 2] = [
    (
        "8C78A505-BAA0-4C4A-869F-000000001200",
        118,
        "8C78A505-BAA0-4C4A-869F-000000001201",
    ),
    (
        "8C78A505-BAA0-4C4A-869F-000000001210",
        0,
        "8C78A505-BAA0-4C4A-869F-000000001211",
    ),
];

#[track_caller]
fn store_data(path: &str) -> Vec<u8> {
    variable_data(path).expect("tests/qemu/vars/formset-skip.json creates the variable")
}

/// IGNORED as uefisettings names it, up to the binrw error.
fn ignored_texts() -> Vec<String> {
    IGNORED
        .iter()
        .map(|(list, offset, form_set)| {
            format!(
                "the IFR that uefisettings ignores at offset {offset} of a form package of \
                 package list {list}: the FormSet {form_set}, {REASON}"
            )
        })
        .collect()
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
                    && record["reason"].as_str().is_some_and(|reason| {
                        reason.starts_with(&format!("the FormSet {form_set}, {REASON}"))
                    })
            })
}

/// list-questions prints the questions of the form sets that it reads, not the PASSWORDs of
/// those that it ignores, in its JSON array, and names each ignored form set on stderr.
#[test]
fn list_questions_names_the_ignored_form_sets_on_stderr() {
    let output = uefisettings(&["hii", "list-questions", "--json"]);
    let questions: Vec<Question> = output.json(0);
    let names: Vec<&str> = questions
        .iter()
        .map(|question| question.name.as_str())
        .filter(|name| {
            [
                "First setting",
                "Password",
                "Third setting",
                "Fourth setting",
            ]
            .contains(name)
        })
        .collect();
    assert_eq!(
        names,
        ["First setting", "Third setting", "Fourth setting"],
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

/// get reads the questions of the form sets that it reads and lists those that it ignores in
/// ignored_ifr; set writes "Third setting" and "Fourth setting" alone, and refuses the PASSWORD,
/// which no form set that it reads holds, naming the ignored form sets. In one test, as set
/// changes what get sees.
#[test]
fn get_and_set_read_past_the_ignored_form_sets() {
    assert_eq!(store_data(FORMSET_SKIP), STORE_DATA, "before");
    assert_eq!(
        store_data(FIRST_FORMSET_SKIP),
        FIRST_STORE_DATA,
        "before: first"
    );
    for (question, answer) in [
        ("First setting", "1"),
        ("Third setting", "3"),
        ("Fourth setting", "4"),
    ] {
        let output = uefisettings(&["hii", "get", question, "--json"]);
        let got: serde_json::Value = output.json(0);
        assert_eq!(
            got["responses"][0]["question"]["answer"].as_str(),
            Some(answer),
            "get {question}: {output:#?}"
        );
        assert!(lists_ignored(&got), "get {question}: {output:#?}");
    }

    for (question, answer, path, before, offset) in [
        (
            "Third setting",
            "4",
            FORMSET_SKIP,
            &STORE_DATA[..],
            THIRD_SETTING_OFFSET,
        ),
        (
            "Fourth setting",
            "5",
            FIRST_FORMSET_SKIP,
            &FIRST_STORE_DATA[..],
            FOURTH_SETTING_OFFSET,
        ),
    ] {
        let (set, modified) =
            single_response(&["hii", "set", question, answer, "--json"], BACKEND_HII);
        assert_eq!((set.answer.as_str(), modified), (answer, true), "{set:#?}");
        let value = answer.parse().expect("a byte");
        assert_eq!(
            changed_bytes(before, &store_data(path)),
            [(offset, value)],
            "set {question} writes its byte alone"
        );
    }

    let before = (store_data(FORMSET_SKIP), store_data(FIRST_FORMSET_SKIP));
    let error = json_error(&["hii", "set", "Password", "x", "--json"]);
    let [first, second] = <[String; 2]>::try_from(ignored_texts()).expect("IGNORED holds 2");
    assert!(
        error.error_message.starts_with(&format!(
            "no question \"Password\" in the HiiDB, but it may be in {first}"
        )) && error.error_message.contains(&format!("; {second}")),
        "set Password: {error:#?}"
    );
    assert_eq!(
        (store_data(FORMSET_SKIP), store_data(FIRST_FORMSET_SKIP)),
        before,
        "set Password writes nothing"
    );
}
