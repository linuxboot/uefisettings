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

//! The boot of the scenario hii-form-set-disable-if: publish-hiidb's `form-set-disable-if-forms`
//! registers the forms of `publish-hiidb/src/form_set_disable_if_forms.rs`, and `rt-data`
//! publishes the HII database after it; vars/form-set-disable-if.json creates
//! UefisettingsFormSetDisableIf. UEFI 2.11 §33.3.8.3.14 has a Forms Processor not process a form
//! under a true DISABLE_IF outside forms, so Hidden and the PASSWORD there are no questions: no
//! --include lists, gets or sets them, and Shown, in a SUPPRESS_IF on Hidden, which holds 1, is
//! not suppressed, while the keyword HiddenKeyword selects Hidden as a disabled question. The
//! PASSWORD's bytes stay withheld: O, over them, shows none, set writes none, and dump-efivars
//! keeps none, while it keeps Hidden's byte, which the keyword reads. Whether a Forms Processor
//! processes After, under a DISABLE_IF on Gate, or Later, after a true SUPPRESS_IF in a DISABLE_IF
//! outside forms, is not known, so get shows both states and why, and set writes them only with
//! disabled questions included.

use std::fs;

use serde::Deserialize;
use uefisettings_qemu_guest::changed_bytes;
use uefisettings_qemu_guest::uefisettings_with_env;
use uefisettings_qemu_guest::variable_data;
use uefisettings_qemu_guest::Output;
use uefisettings_qemu_guest::EFIVARFS_HEADER_SIZE;
use uefisettings_qemu_guest::PREFIXES;
use uefisettings_qemu_guest::UNSAFE_OPERATIONS;

/// The efivarfs file of UefisettingsFormSetDisableIf.
const STORE: &str =
    "/sys/firmware/efi/efivars/UefisettingsFormSetDisableIf-8c78a505-baa0-4c4a-869f-000000002401";
/// The FormSet of the fixture, which list-questions names for each question.
const FORM_SET: &str = "8C78A505-BAA0-4C4A-869F-000000002400";
/// The bytes that tests/qemu/vars/form-set-disable-if.json creates UefisettingsFormSetDisableIf
/// with: Gate, Hidden, Shown, After and Later, 3 bytes that no question holds, then the password.
const STORE_DATA: [u8; 24] = [
    0, 1, 2, 3, 4, 0, 0, 0, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB, 0xBB,
    0xBB, 0xBB, 0xBB, 0xBB,
];
/// The byte of UefisettingsFormSetDisableIf that Hidden holds.
const HIDDEN_OFFSET: usize = 1;
/// The bytes of UefisettingsFormSetDisableIf that the PASSWORD holds.
const PASSWORD_BYTES: std::ops::Range<usize> = 8..24;
/// What shows a byte of the password, 0xBB.
const PASSWORD_TEXTS: [&str; 5] = ["bb bb", "BB BB", "bbbb", "BBBB", "187, 187"];
/// The questions that list-questions lists in the FormSet, in order, with every --include.
const LISTED: [&str; 5] = ["Gate", "Shown", "O", "After", "Later"];
/// The --include arguments: none, each state, and all of them.
const INCLUDES: [&[&str]; 5] = [
    &[],
    &["--include", "grayed-out"],
    &["--include", "suppressed"],
    &["--include", "disabled"],
    &["--include", "grayed-out,suppressed,disabled"],
];
/// The --include argument that selects a disabled question.
const INCLUDE_DISABLED: [&str; 2] = ["--include", "disabled"];
/// Why a Forms Processor may not process After: the condition of its DISABLE_IF.
const NOT_CONSTANT: &str = "it relies on EFI_IFR_EQ_ID_VAL, where a DISABLE_IF outside forms \
     must only rely on constants (UEFI 2.11 §33.3.8.3.14)";
/// Why a Forms Processor may not process Later: the true SUPPRESS_IF before its form.
const AFTER_SUPPRESS_IF: &str = "it is after an EFI_IFR_SUPPRESS_IF in the scope of a DISABLE_IF \
     of its FormSet, whose condition is TRUE: edk2-stable202608 SetupBrowserDxe/IfrParse.c takes \
     that condition for the DISABLE_IF's, which may skip the rest of its scope (:1690-1704, \
     :3045-3059), where UEFI 2.11 §33.3.8.3.75 has it only hide";
/// The answer of a question whose bytes overlap a password's.
const PASSWORD_ANSWER: &str = "<ValueUnavailable: its bytes hold a password>";
/// The end of set's refusal of O.
const PASSWORD_REFUSAL: &str = "holds a password at bytes 8..24, which set never writes";
/// The environment of the runs, which logs all that uefisettings logs.
const TRACE: [(&str, &str); 1] = [("RUST_LOG", "trace")];

/// What `hii dump-efivars` prints.
#[derive(Debug, Deserialize)]
struct Dump {
    directory: String,
}

#[track_caller]
fn store_data() -> Vec<u8> {
    variable_data(STORE).expect("tests/qemu/vars/form-set-disable-if.json creates the variable")
}

/// Runs `uefisettings` with `args` and TRACE; panics if its standard output or error holds any
/// of PASSWORD_TEXTS.
#[track_caller]
fn showing_no_password(args: &[&str]) -> Output {
    let output = uefisettings_with_env(args, &TRACE);
    for text in PASSWORD_TEXTS {
        assert!(
            !output.stdout.contains(text) && !output.stderr.contains(text),
            "{args:?} shows {text:?}: {output:#?}"
        );
    }
    output
}

/// The answers of get `args`, which must succeed.
#[track_caller]
fn answers(args: &[&str]) -> Vec<String> {
    let output = showing_no_password(args);
    let got: serde_json::Value = output.json(0);
    got["responses"]
        .as_array()
        .unwrap_or_else(|| panic!("{args:?}: no responses: {output:#?}"))
        .iter()
        .map(|response| {
            response["question"]["answer"]
                .as_str()
                .unwrap_or_else(|| panic!("{args:?}: no answer: {output:#?}"))
                .to_owned()
        })
        .collect()
}

/// The error message of `args`, which must fail.
#[track_caller]
fn refusal(args: &[&str]) -> String {
    let output = showing_no_password(args);
    let error: serde_json::Value = output.json(1);
    error["error_message"]
        .as_str()
        .unwrap_or_else(|| panic!("{args:?}: no error_message: {output:#?}"))
        .to_owned()
}

/// list-questions lists the questions of the FormSet but Hidden and the PASSWORD, with every
/// --include, and Shown unsuppressed, as Hidden is no question for its SUPPRESS_IF to read.
#[test]
fn a_true_form_set_disable_if_holds_no_question_to_list() {
    for include in INCLUDES {
        let args = [&["hii", "list-questions", "--json"][..], include].concat();
        let output = showing_no_password(&args);
        let questions: Vec<serde_json::Value> = output.json(0);
        let listed: Vec<(&str, &str)> = questions
            .iter()
            .filter(|question| question["form_set_guid"] == FORM_SET)
            .map(|question| {
                (
                    question["name"].as_str().unwrap_or_default(),
                    question["answer"].as_str().unwrap_or_default(),
                )
            })
            .collect();
        let names: Vec<&str> = listed.iter().map(|&(name, _)| name).collect();
        assert_eq!(names, LISTED, "{args:?}: {output:#?}");
        assert!(
            listed.contains(&("Shown", "2")),
            "{args:?}: Shown: {listed:?}"
        );
    }
}

/// get finds no Hidden with any --include, and set refuses it as a question that the HiiDB does
/// not have, also with --i-am-fine-to-brick-this-system, writing nothing.
#[test]
fn a_true_form_set_disable_if_holds_no_question_to_get_or_set() {
    let before = store_data();
    for prefix in PREFIXES {
        for include in INCLUDES {
            let args = [prefix, &["get", "--json", "Hidden"], include].concat();
            assert_eq!(answers(&args), Vec::<String>::new(), "{args:?}");
            for flag in [&[][..], &UNSAFE_OPERATIONS] {
                let args = [prefix, &["set", "--json"], flag, include, &["Hidden", "5"]].concat();
                let error = refusal(&args);
                assert!(
                    error.starts_with("no question \"Hidden\" in the HiiDB"),
                    "{args:?}: {error}"
                );
            }
        }
    }
    assert_eq!(store_data(), before, "set Hidden writes nothing");
}

/// get shows After and Later with both states they may be in and why; set refuses them, also
/// with --i-am-fine-to-brick-this-system, and writes each with disabled questions included, which
/// get then reads.
#[test]
fn questions_that_a_form_set_disable_if_may_skip_are_undetermined() {
    for (question, offset, reason, value) in [
        ("After", 3, NOT_CONSTANT, 9u8),
        ("Later", 4, AFTER_SUPPRESS_IF, 7),
    ] {
        let before = store_data();
        let state = |value: u8| format!("{value} <selectable or disabled: {reason}>");
        let current = before[offset];
        for prefix in PREFIXES {
            let args = [prefix, &["get", "--json", question]].concat();
            assert_eq!(answers(&args), [state(current)], "{args:?}");
            for flag in [&[][..], &UNSAFE_OPERATIONS] {
                let value = value.to_string();
                let args = [prefix, &["set", "--json"], flag, &[question, &value]].concat();
                assert_eq!(
                    refusal(&args),
                    format!(
                        "cannot tell whether question \"{question}\" is disabled: {reason}; also \
                         include disabled questions to select it regardless"
                    ),
                    "{args:?}"
                );
            }
        }
        assert_eq!(store_data(), before, "the refused sets of {question}");

        let value_text = value.to_string();
        let args = [
            &["hii", "set", "--json"][..],
            &INCLUDE_DISABLED,
            &[question, &value_text],
        ]
        .concat();
        assert_eq!(answers(&args), [state(value)], "{args:?}");
        assert_eq!(
            changed_bytes(&before, &store_data()),
            [(offset, value)],
            "{args:?} writes the byte of {question} alone"
        );
        let args = [&["hii", "get", "--json", question][..], &INCLUDE_DISABLED].concat();
        assert_eq!(answers(&args), [state(value)], "{args:?}");
    }
}

/// O, over the password's bytes, shows none of them, and set refuses it, also with
/// --i-am-fine-to-brick-this-system and disabled questions included, writing nothing.
#[test]
fn the_password_under_a_true_form_set_disable_if_stays_withheld() {
    let before = store_data();
    assert_eq!(
        before.get(PASSWORD_BYTES),
        STORE_DATA.get(PASSWORD_BYTES),
        "the password's bytes"
    );
    for prefix in PREFIXES {
        let args = [prefix, &["get", "--json", "O"]].concat();
        let got = answers(&args);
        assert!(
            got.len() == 1 && got[0].starts_with(PASSWORD_ANSWER),
            "{args:?}: {got:?}"
        );
        for flag in [&[][..], &UNSAFE_OPERATIONS] {
            for include in [&[][..], &INCLUDE_DISABLED] {
                let args = [prefix, &["set", "--json"], flag, include, &["O", "5"]].concat();
                let error = refusal(&args);
                assert!(error.ends_with(PASSWORD_REFUSAL), "{args:?}: {error}");
            }
        }
    }
    assert_eq!(store_data(), before, "the refused sets of O");
}

/// --keyword selects Hidden as a disabled question, as edk2's keyword handler evaluates no
/// condition: get refuses it unless disabled questions are included, and reads its byte then,
/// while ShownKeyword reads Shown without.
#[test]
fn a_keyword_selects_the_question_under_a_true_form_set_disable_if_as_disabled() {
    let hidden = store_data()[HIDDEN_OFFSET];
    let error = refusal(&["hii", "get", "--json", "--keyword", "HiddenKeyword"]);
    assert_eq!(
        error,
        "question \"keyword HiddenKeyword of a namespace starting with x-UEFI\" is disabled; also \
         include disabled questions to select it",
        "get --keyword HiddenKeyword"
    );
    let args = [
        &["hii", "get", "--json", "--keyword", "HiddenKeyword"][..],
        &INCLUDE_DISABLED,
    ]
    .concat();
    assert_eq!(answers(&args), [format!("{hidden} <disabled>")], "{args:?}");
    let args = ["hii", "get", "--json", "--keyword", "ShownKeyword"];
    assert_eq!(answers(&args), ["2"], "{args:?}");
}

/// The efivarfs file name of the efivarfs path `path`.
fn file_name(path: &str) -> &str {
    path.rsplit('/').next().expect("an efivarfs file name")
}

/// The redacted dump-efivars keeps Hidden's byte, which --keyword reads, so get --keyword
/// HiddenKeyword answers from the dump as from the live variables, and no byte of the password.
#[test]
fn dump_efivars_keeps_what_a_keyword_reads_and_no_password_byte() {
    let dir = "/tmp/form-set-disable-if-efivars";
    let dump: Dump = showing_no_password(&["hii", "dump-efivars", dir]).json(0);
    assert_eq!(dump.directory, dir, "{dump:#?}");

    let file = file_name(STORE);
    let dumped = fs::read(format!("{dir}/{file}"))
        .unwrap_or_else(|error| panic!("cannot read {file} in {dir}: {error}"));
    let data = dumped
        .get(EFIVARFS_HEADER_SIZE..)
        .unwrap_or_else(|| panic!("{file}: no attributes in {dumped:02x?}"));
    let live = store_data();
    assert_eq!(
        data.get(HIDDEN_OFFSET),
        live.get(HIDDEN_OFFSET),
        "{file}: Hidden in the dump"
    );
    assert_eq!(
        data.get(PASSWORD_BYTES),
        Some(&[0; 16][..]),
        "{file}: the password's bytes in the dump"
    );
    assert!(
        !data.contains(&0xBB),
        "{file}: a password byte in {data:02x?}"
    );

    let get = [
        &["hii", "get", "--json", "--keyword", "HiddenKeyword"][..],
        &INCLUDE_DISABLED,
    ]
    .concat();
    let live = showing_no_password(&get);
    let replayed = showing_no_password(&[&get[..], &["--efivars", dir]].concat());
    assert_eq!(live.code, Some(0), "{get:?}: {live:#?}");
    assert_eq!(
        (replayed.code, replayed.stdout),
        (live.code, live.stdout),
        "{get:?} --efivars {dir}"
    );
}
