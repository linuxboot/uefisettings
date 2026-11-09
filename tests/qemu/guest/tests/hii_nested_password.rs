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

//! The boot of the scenario hii-nested-password: publish-hiidb's `rt-data-nested-password-forms`
//! creates NestedPassword and NestedChoice and registers the forms of
//! `publish-hiidb/src/nested_password_forms.rs` before it publishes the HII database. Their
//! VarStores sit in the scopes of FormSet-level conditions (UEFI 2.11 §33.2.5.1): a question over
//! the password of the VarStore under a SUPPRESS_IF, in its form set or in one that declares the
//! VarStore directly, shows no byte of it and set refuses it, while the CHECKBOXes beside it and
//! on the VarStore under a DISABLE_IF whose condition is FALSE read and write their variables.

use uefisettings_qemu_guest::changed_bytes;
use uefisettings_qemu_guest::single_response;
use uefisettings_qemu_guest::uefisettings_with_env;
use uefisettings_qemu_guest::variable_data;
use uefisettings_qemu_guest::ErrorObject;
use uefisettings_qemu_guest::Output;
use uefisettings_qemu_guest::Question;
use uefisettings_qemu_guest::Responses;
use uefisettings_qemu_guest::BACKEND_HII;
use uefisettings_qemu_guest::PREFIXES;

/// The efivarfs file of NestedPassword, the VARSTORE_EFI under the SUPPRESS_IF.
const NESTED_PASSWORD: &str =
    "/sys/firmware/efi/efivars/NestedPassword-8c78a505-baa0-4c4a-869f-000000001c01";
/// The efivarfs file of NestedChoice, the VARSTORE_EFI under the DISABLE_IF whose condition is
/// FALSE.
const NESTED_CHOICE: &str =
    "/sys/firmware/efi/efivars/NestedChoice-8c78a505-baa0-4c4a-869f-000000001c01";
/// The UINT64 NUMERICs over bytes 0..8 of the password: in its form set, and in the form set
/// that declares NestedPassword directly.
const PASSWORD_PREFIXES: [&str; 2] = [
    "Nested password prefix as a number",
    "Nested password prefix from another form set",
];
/// The CHECKBOX at byte 16 of NestedPassword, which holds 1, beside its password.
const BESIDE_PASSWORD: &str = "Nested setting beside the password";
const BESIDE_PASSWORD_OFFSET: usize = 16;
/// The CHECKBOX at byte 0 of NestedChoice, which holds 0.
const CHOICE: &str = "Nested choice";
/// The answer of a question whose bytes overlap those of a password.
const PASSWORD_BYTES: &str = "<ValueUnavailable: its bytes hold a password>";
/// What would show the password "Kumquat" that publish-hiidb keeps in NestedPassword: its
/// text, its UCS-2 bytes in hex and as a Debug list, and its first 8 bytes as the UINT64 shows
/// them, in decimal and in hex.
const PASSWORD_TEXTS: [&str; 8] = [
    "Kumq",
    "4b007500",
    "4B007500",
    "4b 00 75 00",
    "4B 00 75 00",
    "75, 0, 117, 0",
    "31807140527407179",
    "71006d0075004b",
];
/// The environment of the runs that check for PASSWORD_TEXTS, which logs all that uefisettings
/// logs.
const TRACE: [(&str, &str); 1] = [("RUST_LOG", "trace")];

/// Runs `uefisettings` with `args` and TRACE; panics if its standard output or error holds any
/// of PASSWORD_TEXTS, in any case.
#[track_caller]
fn showing_no_password(args: &[&str]) -> Output {
    let output = uefisettings_with_env(args, &TRACE);
    let (stdout, stderr) = (output.stdout.to_lowercase(), output.stderr.to_lowercase());
    for text in PASSWORD_TEXTS.map(str::to_lowercase) {
        assert!(
            !stdout.contains(&text) && !stderr.contains(&text),
            "{args:?} shows {text:?}: {output:#?}"
        );
    }
    output
}

/// get, list-questions and show-ifr answer for the NUMERICs over the password that its bytes
/// hold a password, and show no byte of it.
#[test]
fn a_question_over_a_nested_password_shows_no_byte_of_it() {
    let listed: Vec<Question> = showing_no_password(&["hii", "list-questions", "--json"]).json(0);
    for question in PASSWORD_PREFIXES {
        for prefix in PREFIXES {
            let args = [prefix, &["get", "--json", question]].concat();
            let Responses { responses } = showing_no_password(&args).json(0);
            let answers: Vec<&str> = responses
                .iter()
                .map(|response| response.question.answer.as_str())
                .collect();
            assert!(
                matches!(answers.as_slice(), [answer] if answer.starts_with(PASSWORD_BYTES)),
                "{args:?}: {answers:?}"
            );
        }

        let answers: Vec<&str> = listed
            .iter()
            .filter(|listed| listed.name == question)
            .map(|listed| listed.answer.as_str())
            .collect();
        assert!(
            matches!(answers.as_slice(), [answer] if answer.starts_with(PASSWORD_BYTES)),
            "list-questions {question:?}: {answers:?}"
        );
    }

    let ifr = showing_no_password(&["hii", "show-ifr"]);
    assert_eq!(ifr.code, Some(0), "show-ifr: {ifr:#?}");
    assert!(
        ifr.stdout.contains(&format!("-Answer: {PASSWORD_BYTES}")),
        "show-ifr: {}",
        ifr.stdout
    );
}

/// The CHECKBOX beside the password and the one on NestedChoice read their values, and set
/// writes their bytes only.
#[test]
fn check_boxes_on_nested_var_stores_read_and_write() {
    for (path, question, offset, stored, other) in [
        (
            NESTED_PASSWORD,
            BESIDE_PASSWORD,
            BESIDE_PASSWORD_OFFSET,
            1,
            0,
        ),
        (NESTED_CHOICE, CHOICE, 0, 0, 1),
    ] {
        let before = variable_data(path).unwrap_or_else(|| panic!("no {path}"));
        assert_eq!(before.get(offset), Some(&stored), "{path}: byte {offset}");
        let (got, _) = single_response(&["hii", "get", "--json", question], BACKEND_HII);
        assert_eq!(got.answer, stored.to_string(), "get {question}");

        let other_text = other.to_string();
        let (set, modified) = single_response(
            &["hii", "set", "--json", question, &other_text],
            BACKEND_HII,
        );
        assert_eq!(
            (set.answer.as_str(), modified),
            (other_text.as_str(), true),
            "set {question}"
        );
        let after = variable_data(path).unwrap_or_else(|| panic!("no {path}"));
        assert_eq!(
            changed_bytes(&before, &after),
            [(offset, other)],
            "the bytes of {path} that set {question} changed"
        );

        single_response(
            &["hii", "set", "--json", question, &stored.to_string()],
            BACKEND_HII,
        );
        assert_eq!(
            variable_data(path).as_ref(),
            Some(&before),
            "{path} after set {question} back"
        );
    }
}

/// set refuses the NUMERICs over the password before any write, and its error shows no byte of
/// the password.
#[test]
fn set_refuses_a_question_over_a_nested_password() {
    let before = variable_data(NESTED_PASSWORD).expect("NestedPassword exists");
    for question in PASSWORD_PREFIXES {
        for prefix in PREFIXES {
            let args = [prefix, &["set", "--json", question, "1"]].concat();
            let error: ErrorObject = showing_no_password(&args).json(1);
            assert_eq!(
                error.error_message,
                format!(
                    "cannot set question {question:?}: EFI variable \
                     NestedPassword-8c78a505-baa0-4c4a-869f-000000001c01 holds a password at \
                     bytes 0..16, which set never writes"
                ),
                "{args:?}"
            );
        }
    }
    assert_eq!(
        variable_data(NESTED_PASSWORD).as_ref(),
        Some(&before),
        "NestedPassword after the refused sets"
    );
}
