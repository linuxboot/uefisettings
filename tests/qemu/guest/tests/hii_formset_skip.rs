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
//! of `publish-hiidb/src/formset_skip_forms.rs`, three form sets on UefisettingsFormSetSkip, and
//! `publish-hiidb.efi rt-data` publishes the HII database. uefisettings ignores the second form
//! set, which holds a VARSTORE op shorter than its minimum (UEFI 2.11 §33.2.5.10.1), reads the
//! questions of the others, and names the IFR that it ignores: get and set in the ignored_ifr of
//! their answer and in set's refusal of a question in it, list-questions on stderr.

use uefisettings_qemu_guest::changed_bytes;
use uefisettings_qemu_guest::json_error;
use uefisettings_qemu_guest::single_response;
use uefisettings_qemu_guest::uefisettings;
use uefisettings_qemu_guest::variable_data;
use uefisettings_qemu_guest::Question;
use uefisettings_qemu_guest::BACKEND_HII;

/// The efivarfs file of UefisettingsFormSetSkip, the VARSTORE_EFI of the forms.
const FORMSET_SKIP: &str =
    "/sys/firmware/efi/efivars/UefisettingsFormSetSkip-8c78a505-baa0-4c4a-869f-000000001203";
/// The bytes that tests/qemu/vars/formset-skip.json creates UefisettingsFormSetSkip with: a
/// password, then "First setting" and "Third setting".
const STORE_DATA: [u8; 22] = [
    0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    0xAA, 0xAA, 0xAA, 0xAA, 0x01, 0x03,
];
/// The byte of UefisettingsFormSetSkip that "Third setting" holds.
const THIRD_SETTING_OFFSET: usize = 21;
/// The reason, up to the binrw error, of each FormSet that uefisettings ignores.
const REASON: &str = "which does not parse; uefisettings ignores it, where UEFI 2.11 §33.2.5.10.1 \
     disables only the form of a malformed op and ignores only a malformed forms set: ";
/// The IFR that uefisettings ignores, each as its package list, its offset in the form package
/// and the FormSet: the second form set, at the end of the first.
const IGNORED: [(&str, u64, &str); 1] = [(
    "8C78A505-BAA0-4C4A-869F-000000001200",
    118,
    "8C78A505-BAA0-4C4A-869F-000000001201",
)];

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
        .filter(|name| ["First setting", "Password", "Third setting"].contains(name))
        .collect();
    assert_eq!(names, ["First setting", "Third setting"], "{output:#?}");
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
/// ignored_ifr; set writes "Third setting" alone, and refuses the PASSWORD,
/// which no form set that it reads holds, naming the ignored form sets. In one test, as set
/// changes what get sees.
#[test]
fn get_and_set_read_past_the_ignored_form_sets() {
    assert_eq!(store_data(FORMSET_SKIP), STORE_DATA, "before");
    for (question, answer) in [("First setting", "1"), ("Third setting", "3")] {
        let output = uefisettings(&["hii", "get", question, "--json"]);
        let got: serde_json::Value = output.json(0);
        assert_eq!(
            got["responses"][0]["question"]["answer"].as_str(),
            Some(answer),
            "get {question}: {output:#?}"
        );
        assert!(lists_ignored(&got), "get {question}: {output:#?}");
    }

    let (set, modified) =
        single_response(&["hii", "set", "Third setting", "4", "--json"], BACKEND_HII);
    assert_eq!((set.answer.as_str(), modified), ("4", true), "{set:#?}");
    assert_eq!(
        changed_bytes(&STORE_DATA, &store_data(FORMSET_SKIP)),
        [(THIRD_SETTING_OFFSET, 4)],
        "set Third setting writes its byte alone"
    );

    let before = store_data(FORMSET_SKIP);
    let error = json_error(&["hii", "set", "Password", "x", "--json"]);
    let [first] = <[String; 1]>::try_from(ignored_texts()).expect("IGNORED holds 1");
    assert!(
        error.error_message.starts_with(&format!(
            "no question \"Password\" in the HiiDB, but it may be in {first}"
        )),
        "set Password: {error:#?}"
    );
    assert_eq!(
        store_data(FORMSET_SKIP),
        before,
        "set Password writes nothing"
    );
}
