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

//! The boot of the scenario hii-first-store-password: publish-hiidb's
//! `rt-data-first-store-password-forms` creates FirstStore and PasswordStore and registers the
//! forms of `publish-hiidb/src/first_store_password_forms.rs`, whose first form set declares
//! FirstStore for VarStoreId 1, the first VarStore of that id in the form package, and whose
//! second form set has a PASSWORD of that id, before it publishes the HII database. edk2's Config
//! Keyword Handler takes FirstStore for that PASSWORD, so FirstStore's bytes 0..16, which hold
//! the password "First", hold its password: through Linux, whose variables reach Runtime, the
//! question over those bytes shows none of them and set refuses it, while the question beside
//! them reads.

use uefisettings_qemu_guest::single_response;
use uefisettings_qemu_guest::uefisettings_with_env;
use uefisettings_qemu_guest::variable_data;
use uefisettings_qemu_guest::ErrorObject;
use uefisettings_qemu_guest::Output;
use uefisettings_qemu_guest::Question;
use uefisettings_qemu_guest::Responses;
use uefisettings_qemu_guest::BACKEND_HII;
use uefisettings_qemu_guest::PREFIXES;

/// The efivarfs file of FirstStore, the VARSTORE_EFI of the first form set.
const FIRST_STORE: &str =
    "/sys/firmware/efi/efivars/FirstStore-8c78a505-baa0-4c4a-869f-000000001d01";
/// The UINT64 NUMERIC over bytes 0..8 of the password.
const PASSWORD_PREFIX: &str = "First store password prefix as a number";
/// The UINT8 NUMERIC at byte 16 of FirstStore, which holds 5, beside the password.
const BESIDE_PASSWORD: &str = "Setting beside the first store password";
/// The answer of a question whose bytes overlap those of a password.
const PASSWORD_BYTES: &str = "<ValueUnavailable: its bytes hold a password>";
/// What would show the password "First" that publish-hiidb keeps in FirstStore: its UCS-2 bytes
/// in hex and as a Debug list, and its first 8 bytes as the UINT64 shows them, in decimal and in
/// hex. Its text is in the questions' prompts.
const PASSWORD_TEXTS: [&str; 5] = [
    "46006900",
    "46 00 69 00",
    "70, 0, 105, 0",
    "32370111954878534",
    "73007200690046",
];
/// The environment of the runs that check for PASSWORD_TEXTS, which logs all that uefisettings
/// logs.
const TRACE: [(&str, &str); 1] = [("RUST_LOG", "trace")];

/// Runs `uefisettings` with `args` and TRACE; panics if its standard output or error holds any
/// of PASSWORD_TEXTS, in any case.
#[track_caller]
fn showing_no_password(args: &[&str]) -> Output {
    let output = uefisettings_with_env(args, &TRACE);
    let (stdout, stderr) = (
        output.stdout.to_ascii_lowercase(),
        output.stderr.to_ascii_lowercase(),
    );
    for text in PASSWORD_TEXTS {
        assert!(
            !stdout.contains(text) && !stderr.contains(text),
            "{args:?} shows {text:?}: {output:#?}"
        );
    }
    output
}

/// get, list-questions and show-ifr answer for the NUMERIC over the password that its bytes hold
/// a password, and show no byte of it.
#[test]
fn a_question_over_the_first_store_of_a_password_shows_no_byte_of_it() {
    for prefix in PREFIXES {
        let args = [prefix, &["get", "--json", PASSWORD_PREFIX]].concat();
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

    let listed: Vec<Question> = showing_no_password(&["hii", "list-questions", "--json"]).json(0);
    let answers: Vec<&str> = listed
        .iter()
        .filter(|question| question.name == PASSWORD_PREFIX)
        .map(|question| question.answer.as_str())
        .collect();
    assert!(
        matches!(answers.as_slice(), [answer] if answer.starts_with(PASSWORD_BYTES)),
        "list-questions: {answers:?}"
    );

    let ifr = showing_no_password(&["hii", "show-ifr"]);
    assert_eq!(ifr.code, Some(0), "show-ifr: {ifr:#?}");
    assert!(
        ifr.stdout.contains(&format!("-Answer: {PASSWORD_BYTES}")),
        "show-ifr: {}",
        ifr.stdout
    );
}

/// The question beside the password reads its value.
#[test]
fn the_question_beside_the_first_store_password_reads() {
    let (got, _) = single_response(&["hii", "get", "--json", BESIDE_PASSWORD], BACKEND_HII);

    assert_eq!(got.answer, "5", "get {BESIDE_PASSWORD}");
}

/// set refuses the NUMERIC over the password before any write, and its error shows no byte of
/// the password.
#[test]
fn set_refuses_a_question_over_the_first_store_password() {
    let before = variable_data(FIRST_STORE).expect("FirstStore exists");
    for prefix in PREFIXES {
        let args = [prefix, &["set", "--json", PASSWORD_PREFIX, "1"]].concat();
        let error: ErrorObject = showing_no_password(&args).json(1);
        assert_eq!(
            error.error_message,
            format!(
                "cannot set question {PASSWORD_PREFIX:?}: EFI variable \
                 FirstStore-8c78a505-baa0-4c4a-869f-000000001d01 holds a password at bytes 0..16, \
                 which set never writes"
            ),
            "{args:?}"
        );
    }
    assert_eq!(
        variable_data(FIRST_STORE).as_ref(),
        Some(&before),
        "FirstStore after the refused sets"
    );
}
