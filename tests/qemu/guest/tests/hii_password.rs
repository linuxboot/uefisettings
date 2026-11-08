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

//! The boot of the scenario hii-password: publish-hiidb's `rt-data-password-forms` creates
//! PlaintextPassword and registers the forms of `publish-hiidb/src/password_forms.rs` and
//! `publish-hiidb/src/plaintext_password_forms.rs` before it publishes the HII database, and
//! `vars/amitse-setup.json` creates AMITSESetup with 80 bytes of 0xAA, standing for two
//! passwords, then 1. A question whose bytes overlap those of a PASSWORD question (UEFI 2.11
//! §33.3.8.3.54) shows no byte of the password, set refuses it, and dump-efivars keeps none; the
//! questions beside the passwords read and write.

use std::fs;

use serde::Deserialize;
use uefisettings_qemu_guest::changed_bytes;
use uefisettings_qemu_guest::single_response;
use uefisettings_qemu_guest::uefisettings_with_env;
use uefisettings_qemu_guest::variable_data;
use uefisettings_qemu_guest::ErrorObject;
use uefisettings_qemu_guest::Output;
use uefisettings_qemu_guest::Question;
use uefisettings_qemu_guest::Responses;
use uefisettings_qemu_guest::BACKEND_HII;
use uefisettings_qemu_guest::EFIVARFS_HEADER_SIZE;
use uefisettings_qemu_guest::PREFIXES;

/// The efivarfs file of PlaintextPassword, the VARSTORE_EFI of the plaintext password forms.
const PLAINTEXT_PASSWORD: &str =
    "/sys/firmware/efi/efivars/PlaintextPassword-8c78a505-baa0-4c4a-869f-000000001101";
/// The efivarfs file of AMITSESetup, the buffer VARSTORE of the password forms.
const AMITSE_SETUP: &str =
    "/sys/firmware/efi/efivars/AMITSESetup-8c78a505-baa0-4c4a-869f-000000000101";
/// The bytes of the PASSWORD of PlaintextPassword, MaxSize 8, and of the two of AMITSESetup,
/// MaxSize 20 each.
const PLAINTEXT_PASSWORD_BYTES: usize = 16;
const AMITSE_SETUP_PASSWORD_BYTES: usize = 80;
/// The UINT64 NUMERIC over bytes 0..8 of the plaintext password.
const PASSWORD_PREFIX: &str = "Password prefix as a number";
/// The UINT8 NUMERIC at byte 16 of PlaintextPassword, which holds 5, beside its password.
const BESIDE_PASSWORD: &str = "Setting beside the password";
const BESIDE_PASSWORD_OFFSET: usize = 16;
/// The ONE_OF at byte 80 of AMITSESetup, which holds 1, Enabled, beside its passwords.
const QUIET_BOOT: &str = "Quiet Boot";
const QUIET_BOOT_OFFSET: usize = 80;
/// The answer of a question whose bytes overlap those of a password.
const PASSWORD_BYTES: &str = "<ValueUnavailable: its bytes hold a password>";
/// What would show the password "Sesame" that publish-hiidb keeps in PlaintextPassword: its
/// text, its UCS-2 bytes in hex and as a Debug list, and its first 8 bytes as the UINT64 shows
/// them, in decimal and in hex.
const PASSWORD_TEXTS: [&str; 6] = [
    "Sesa",
    "53006500",
    "53 00 65 00",
    "83, 0, 101, 0",
    "27303566668791891",
    "61007300650053",
];
/// The environment of the runs that check for PASSWORD_TEXTS, which logs all that uefisettings
/// logs.
const TRACE: [(&str, &str); 1] = [("RUST_LOG", "trace")];

/// What `hii dump-efivars` prints.
#[derive(Debug, Deserialize)]
struct Dump {
    directory: String,
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

/// get, list-questions and show-ifr answer for the NUMERIC over the plaintext password that its
/// bytes hold a password, and show no byte of it.
#[test]
fn a_question_over_a_password_shows_no_byte_of_it() {
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

/// The questions beside the passwords read their values, and set writes their bytes only.
#[test]
fn questions_beside_passwords_read_and_write() {
    for (path, question, offset, (stored, stored_byte), (other, other_byte)) in [
        (
            AMITSE_SETUP,
            QUIET_BOOT,
            QUIET_BOOT_OFFSET,
            ("Enabled", 1),
            ("Disabled", 0),
        ),
        (
            PLAINTEXT_PASSWORD,
            BESIDE_PASSWORD,
            BESIDE_PASSWORD_OFFSET,
            ("5", 5),
            ("6", 6),
        ),
    ] {
        let before = variable_data(path).unwrap_or_else(|| panic!("no {path}"));
        assert_eq!(
            before.get(offset),
            Some(&stored_byte),
            "{path}: byte {offset}"
        );
        let (got, _) = single_response(&["hii", "get", "--json", question], BACKEND_HII);
        assert_eq!(got.answer, stored, "get {question}");

        let (set, modified) =
            single_response(&["hii", "set", "--json", question, other], BACKEND_HII);
        assert_eq!(
            (set.answer.as_str(), modified),
            (other, true),
            "set {question}"
        );
        let after = variable_data(path).unwrap_or_else(|| panic!("no {path}"));
        assert_eq!(
            changed_bytes(&before, &after),
            [(offset, other_byte)],
            "the bytes of {path} that set {question} changed"
        );

        single_response(&["hii", "set", "--json", question, stored], BACKEND_HII);
        assert_eq!(
            variable_data(path).as_ref(),
            Some(&before),
            "{path} after set {question} back"
        );
    }
}

/// set refuses the NUMERIC over the plaintext password before any write, and its error shows no
/// byte of the password.
#[test]
fn set_refuses_a_question_over_a_password() {
    let before = variable_data(PLAINTEXT_PASSWORD).expect("PlaintextPassword exists");
    for prefix in PREFIXES {
        let args = [prefix, &["set", "--json", PASSWORD_PREFIX, "1"]].concat();
        let error: ErrorObject = showing_no_password(&args).json(1);
        assert_eq!(
            error.error_message,
            format!(
                "cannot set question {PASSWORD_PREFIX:?}: EFI variable \
                 PlaintextPassword-8c78a505-baa0-4c4a-869f-000000001101 holds a password at bytes \
                 0..16, which set never writes"
            ),
            "{args:?}"
        );
    }
    assert_eq!(
        variable_data(PLAINTEXT_PASSWORD).as_ref(),
        Some(&before),
        "PlaintextPassword after the refused sets"
    );
}

/// The redacted dump-efivars keeps no byte of a password: the passwords' bytes of
/// PlaintextPassword and AMITSESetup are 0 there, and the byte beside them is as it is live.
#[test]
fn dump_efivars_keeps_no_password_byte() {
    let dir = "/tmp/password-efivars";
    let dump: Dump = showing_no_password(&["hii", "dump-efivars", dir]).json(0);
    assert_eq!(dump.directory, dir, "{dump:#?}");

    for (path, password, beside) in [
        (
            PLAINTEXT_PASSWORD,
            PLAINTEXT_PASSWORD_BYTES,
            BESIDE_PASSWORD_OFFSET,
        ),
        (AMITSE_SETUP, AMITSE_SETUP_PASSWORD_BYTES, QUIET_BOOT_OFFSET),
    ] {
        let file = path.rsplit('/').next().expect("an efivarfs file name");
        let dumped = fs::read(format!("{dir}/{file}"))
            .unwrap_or_else(|error| panic!("cannot read {file} in {dir}: {error}"));
        let data = dumped
            .get(EFIVARFS_HEADER_SIZE..)
            .unwrap_or_else(|| panic!("{file}: no attributes in {dumped:02x?}"));
        let live = variable_data(path).unwrap_or_else(|| panic!("no {path}"));
        assert_eq!(
            data.get(..password),
            Some(&vec![0; password][..]),
            "{file}: the passwords' bytes in the dump"
        );
        assert_eq!(
            data.get(beside),
            live.get(beside),
            "{file}: the byte beside them in the dump"
        );
    }
}
