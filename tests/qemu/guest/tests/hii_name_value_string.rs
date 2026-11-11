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

//! The boots of the scenarios hii-name-value-string and hii-name-value-string-snapshot:
//! publish-hiidb's `rt-data-name-value-string-forms`, or `export-config-name-value-string` and
//! then `rt-data`, registers the package list of `publish-hiidb/src/name_value_string_forms.rs`
//! for a device path before it publishes the HII database: STRINGs of MaxSize 4 and a CHECKBOX
//! on the names of a VARSTORE_NAME_VALUE, whose values its driver exposes, as UEFI 2.11
//! §33.2.5.6 says, through EFI_HII_CONFIG_ACCESS_PROTOCOL, and no PASSWORD. Linux reads such a
//! value only from the ExportConfig snapshot: in hii-name-value-string-snapshot, get,
//! list-questions and show-ifr take each STRING's characters from it, 4 hex digits each, or say
//! why its setting holds none, and the CHECKBOX's number; without efivars, and in
//! hii-name-value-string, whose firmware lists no snapshot, each says why it has no value.

use uefisettings_qemu_guest::uefisettings_with_env;
use uefisettings_qemu_guest::Output;
use uefisettings_qemu_guest::Question;
use uefisettings_qemu_guest::Responses;
use uefisettings_qemu_guest::BACKEND_HII;
use uefisettings_qemu_guest::PREFIXES;

/// Why a question of the VARSTORE_NAME_VALUE has no value without the snapshot.
const NAME_VALUE: &str =
    "<ValueUnavailable: HII name/value varstore requires EFI_HII_CONFIG_ACCESS_PROTOCOL>";
/// The answers of the questions, each prompted by the name it is on, from the snapshot: its
/// STRINGs read up to a NULL or 4 characters, and refuse more or a CHAR16 of fewer than 4 digits.
const SNAPSHOT_ANSWERS: [(&str, &str); 8] = [
    ("Text", "AB <snapshot>"),
    ("Nul", "AB <snapshot>"),
    ("Full", "ABCD <snapshot>"),
    ("Padded", "ABCD <snapshot>"),
    (
        "Long",
        "<ValueUnavailable: its setting in the ExportConfig snapshot holds more than its MaxSize \
         of 4 characters>",
    ),
    (
        "Odd",
        "<ValueUnavailable: its setting in the ExportConfig snapshot is no <String>: 4 hex digits \
         per CHAR16>",
    ),
    ("Empty", " <snapshot>"),
    ("Flag", "1 <snapshot>"),
];
/// What the CHECKBOX shows after NAME_VALUE: its default, which no flag sets.
const FLAG_DEFAULT: &str = " <IFR default: 0>";
/// What tags a value from the ExportConfig snapshot.
const SNAPSHOT_TAG: &str = " <snapshot>";
/// What the debug log says where the configuration table lists no ExportConfig snapshot.
const NO_SNAPSHOT: &str = "no ExportConfig snapshot";
/// The environment of the runs, which logs all that uefisettings logs.
const TRACE: [(&str, &str); 1] = [("RUST_LOG", "trace")];

/// Whether uefisettings reads the ExportConfig snapshot: the firmware lists it and the run reads
/// System efivars.
#[derive(Clone, Copy, Debug)]
enum Snapshot {
    Absent,
    Listed,
}

/// The answer of the question prompted `name` with or without the snapshot.
fn answer(name: &str, snapshot: Snapshot) -> String {
    match snapshot {
        Snapshot::Listed => SNAPSHOT_ANSWERS
            .iter()
            .find(|(prompt, _)| *prompt == name)
            .map(|(_, answer)| (*answer).to_owned())
            .unwrap_or_else(|| panic!("no answer of {name}")),
        Snapshot::Absent if name == "Flag" => format!("{NAME_VALUE}{FLAG_DEFAULT}"),
        Snapshot::Absent => NAME_VALUE.to_owned(),
    }
}

/// Runs `uefisettings` with `args` and TRACE; panics unless it exits with 0 and its debug log
/// tells whether the firmware lists the snapshot, `listed`.
#[track_caller]
fn traced(args: &[&str], listed: Snapshot) -> Output {
    let output = uefisettings_with_env(args, &TRACE);
    assert_eq!(output.code, Some(0), "{args:?}: {output:#?}");
    let logged = output.stderr.contains(NO_SNAPSHOT);
    match listed {
        Snapshot::Absent => assert!(logged, "{args:?}: {output:#?}"),
        Snapshot::Listed => assert!(!logged, "{args:?}: {output:#?}"),
    }
    output
}

/// get gives each question its answer, with and without the hii prefix.
fn get_answers_each_question(snapshot: Snapshot) {
    for prefix in PREFIXES {
        for (name, _) in SNAPSHOT_ANSWERS {
            let output = traced(&[prefix, &["get", "--json", name]].concat(), snapshot);
            let Responses { responses } = output.json(0);
            let [response] = <[_; 1]>::try_from(responses)
                .unwrap_or_else(|responses| panic!("{name}: one response: {responses:#?}"));
            assert_eq!(response.backend, BACKEND_HII, "{name}: {response:#?}");
            assert_eq!(
                response.question.answer,
                answer(name, snapshot),
                "{prefix:?} get {name}"
            );
        }
    }
}

/// list-questions gives each question its answer.
fn list_questions_answers_each_question(snapshot: Snapshot) {
    let listed: Vec<Question> = traced(&["hii", "list-questions", "--json"], snapshot).json(0);
    for (name, _) in SNAPSHOT_ANSWERS {
        let question = listed
            .iter()
            .find(|question| question.name == name)
            .unwrap_or_else(|| panic!("list-questions lists no {name}: {listed:#?}"));
        assert_eq!(
            question.answer,
            answer(name, snapshot),
            "list-questions {name}"
        );
    }
}

/// show-ifr shows the snapshot's characters of the STRINGs and number of the CHECKBOX, or no
/// value of the snapshot.
fn show_ifr_shows_the_snapshot_answers(snapshot: Snapshot) {
    let output = traced(&["hii", "show-ifr"], snapshot);
    let shown = [
        "AB <snapshot>",
        "ABCD <snapshot>",
        " <snapshot>",
        "1 <snapshot>",
    ];
    for answer in shown {
        let line = format!("-Answer: {answer}\n");
        match snapshot {
            Snapshot::Listed => assert!(output.stdout.contains(&line), "show-ifr: {output:#?}"),
            Snapshot::Absent => assert!(!output.stdout.contains(&line), "show-ifr: {output:#?}"),
        }
    }
    if let Snapshot::Absent = snapshot {
        assert!(
            !output.stdout.contains(SNAPSHOT_TAG),
            "show-ifr: {output:#?}"
        );
    }
}

/// Without efivars uefisettings reads no snapshot, so each question says why it has no value.
fn without_efivars_no_question_has_a_value() {
    let listed: Vec<Question> =
        uefisettings_with_env(&["hii", "list-questions", "--json", "--no-efivars"], &TRACE).json(0);
    for (name, _) in SNAPSHOT_ANSWERS {
        let question = listed
            .iter()
            .find(|question| question.name == name)
            .unwrap_or_else(|| panic!("list-questions --no-efivars lists no {name}: {listed:#?}"));
        assert_eq!(
            question.answer,
            answer(name, Snapshot::Absent),
            "list-questions --no-efivars {name}"
        );
    }
    let output = uefisettings_with_env(&["hii", "get", "--json", "--no-efivars", "Text"], &TRACE);
    let Responses { responses } = output.json(0);
    let answers: Vec<&str> = responses
        .iter()
        .map(|response| response.question.answer.as_str())
        .collect();
    assert_eq!(answers, [NAME_VALUE], "get --no-efivars Text");
}

/// The tests of each scenario, in a module named after whether its firmware lists the snapshot.
macro_rules! name_value_string_tests {
    ($($module:ident: $snapshot:expr),* $(,)?) => {$(
        mod $module {
            #[test]
            fn get_answers_each_question() {
                super::get_answers_each_question($snapshot);
            }

            #[test]
            fn list_questions_answers_each_question() {
                super::list_questions_answers_each_question($snapshot);
            }

            #[test]
            fn show_ifr_shows_the_snapshot_answers() {
                super::show_ifr_shows_the_snapshot_answers($snapshot);
            }

            #[test]
            fn without_efivars_no_question_has_a_value() {
                super::without_efivars_no_question_has_a_value();
            }
        }
    )*};
}

name_value_string_tests!(
    without_snapshot: super::Snapshot::Absent,
    with_snapshot: super::Snapshot::Listed,
);
