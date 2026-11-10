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

//! The boots of the scenarios hii-name-value-password and hii-name-value-password-snapshot:
//! publish-hiidb's `rt-data-name-value-password-forms`, or `export-config-name-value-password` and
//! then `rt-data`, registers the package lists of `publish-hiidb/src/name_value_password_forms.rs`
//! for one device path before it publishes the HII database, and vars/name-value-password.json
//! creates NvBacking, whose bytes 0..4 hold 0x7A5BC3E1, and Other. The first list's PASSWORD is on
//! the name "Pin" of a VARSTORE_NAME_VALUE, whose values its driver exposes, as UEFI 2.11 §33.2.5.6
//! says, through EFI_HII_CONFIG_ACCESS_PROTOCOL, in storage of its own choosing, so in any
//! variable: through Linux, whose variables read, get, list-questions, set and dump-efivars refuse
//! the whole HiiDB, the question of the second list too, naming the PASSWORD, and write nothing,
//! while list-questions without efivars reads; nothing shows 0x7A5BC3E1. In
//! hii-name-value-password-snapshot, the ExportConfig snapshot holds 0x7A5BC3E1 for "Pin", and no
//! question shows a value from it either.

use std::path::Path;

use uefisettings_qemu_guest::uefisettings_with_env;
use uefisettings_qemu_guest::variable_data;
use uefisettings_qemu_guest::ErrorObject;
use uefisettings_qemu_guest::Output;
use uefisettings_qemu_guest::Question;
use uefisettings_qemu_guest::PREFIXES;

/// The efivarfs file of NvBacking, the buffer VARSTORE of the first package list.
const NV_BACKING: &str = "/sys/firmware/efi/efivars/NvBacking-8c78a505-baa0-4c4a-869f-000000001f02";
/// The UINT32 NUMERIC over bytes 0..4 of NvBacking.
const BACKING_SETTING: &str = "Backing setting";
/// The UINT32 NUMERIC on "Pin" of the VARSTORE_NAME_VALUE.
const PIN_NUMBER: &str = "Name value pin as a number";
/// The UINT16 NUMERIC over Other, of the second package list.
const OTHER_SETTING: &str = "Other setting";
/// The PASSWORD that edk2 may route to the VARSTORE_NAME_VALUE, which the refusals name.
const PASSWORD_RECORD: &str = "PASSWORD question 0x0003 in FormSet \
    8C78A505-BAA0-4C4A-869F-000000001F00: HII name/value varstore requires \
    EFI_HII_CONFIG_ACCESS_PROTOCOL";
/// The end of the refusal of a HiiDB whose PASSWORD may keep its password in any variable.
const ANY_VARIABLE: &str = "; as a PASSWORD there may keep its password in any variable, \
    uefisettings reads and writes no variable of this HiiDB";
/// What would show 0x7A5BC3E1, which NvBacking and the snapshot hold where the password may be:
/// the UINT32 in decimal, its digits, its little-endian bytes in hex, as a hex dump and as a
/// Debug list.
const PIN_TEXTS: [&str; 5] = [
    "2052834273",
    "7a5bc3e1",
    "e1c35b7a",
    "e1 c3 5b 7a",
    "225, 195, 91, 122",
];
/// What tags a value from the ExportConfig snapshot.
const SNAPSHOT_TAG: &str = " <snapshot>";
/// What the debug log says where the configuration table lists no ExportConfig snapshot.
const NO_SNAPSHOT: &str = "no ExportConfig snapshot";
/// The environment of the runs, which logs all that uefisettings logs.
const TRACE: [(&str, &str); 1] = [("RUST_LOG", "trace")];

/// Whether the firmware lists the ExportConfig snapshot.
#[derive(Clone, Copy, Debug)]
enum Snapshot {
    Absent,
    Listed,
}

/// Runs `uefisettings` with `args` and TRACE; panics if its standard output or error holds any
/// of PIN_TEXTS, in any case, or SNAPSHOT_TAG.
#[track_caller]
fn showing_no_pin(args: &[&str]) -> Output {
    let output = uefisettings_with_env(args, &TRACE);
    let (stdout, stderr) = (
        output.stdout.to_ascii_lowercase(),
        output.stderr.to_ascii_lowercase(),
    );
    for text in PIN_TEXTS {
        assert!(
            !stdout.contains(text) && !stderr.contains(text),
            "{args:?} shows {text:?}: {output:#?}"
        );
    }
    assert!(
        !output.stdout.contains(SNAPSHOT_TAG) && !output.stderr.contains(SNAPSHOT_TAG),
        "{args:?} shows a value of the snapshot: {output:#?}"
    );
    output
}

/// Runs `uefisettings` with `args` as showing_no_pin does; panics unless it fails with the
/// refusal of the HiiDB that names the PASSWORD.
#[track_caller]
fn refused(args: &[&str]) -> Output {
    let output = showing_no_pin(args);
    let error: ErrorObject = output.json(1);
    assert!(
        error.error_message.contains(PASSWORD_RECORD)
            && error.error_message.ends_with(ANY_VARIABLE),
        "{args:?}: {}",
        error.error_message
    );
    output
}

/// get refuses each question, of either package list.
fn get_refuses_every_question() {
    for prefix in PREFIXES {
        for question in [BACKING_SETTING, PIN_NUMBER, OTHER_SETTING] {
            refused(&[prefix, &["get", "--json", question]].concat());
        }
    }
}

/// list-questions and show-ifr refuse the HiiDB, and the debug log tells whether the firmware
/// lists the snapshot: list-questions reads it before the refusal.
fn list_questions_refuses_beside_the_snapshot(snapshot: Snapshot) {
    let listed = refused(&["hii", "list-questions", "--json"]);
    let logged = listed.stderr.contains(NO_SNAPSHOT);
    match snapshot {
        Snapshot::Absent => assert!(logged, "list-questions: {listed:#?}"),
        Snapshot::Listed => assert!(!logged, "list-questions: {listed:#?}"),
    }
    refused(&["hii", "show-ifr"]);
}

/// list-questions without efivars reads no variable, so it lists the questions of both package
/// lists.
fn list_questions_reads_without_efivars() {
    let output = showing_no_pin(&["hii", "list-questions", "--json", "--no-efivars"]);
    let listed: Vec<Question> = output.json(0);
    for name in [BACKING_SETTING, PIN_NUMBER, OTHER_SETTING] {
        assert!(
            listed.iter().any(|question| question.name == name),
            "list-questions --no-efivars: {name}: {listed:#?}"
        );
    }
}

/// set refuses the question over NvBacking and writes nothing.
fn set_refuses_and_writes_nothing() {
    let before = variable_data(NV_BACKING).expect("NvBacking exists");
    for prefix in PREFIXES {
        refused(&[prefix, &["set", "--json", BACKING_SETTING, "1"]].concat());
    }
    assert_eq!(
        variable_data(NV_BACKING).as_ref(),
        Some(&before),
        "NvBacking after the refused sets"
    );
}

/// The redacted dump-efivars refuses the HiiDB before it creates its directory.
fn dump_efivars_refuses_without_a_directory() {
    let dir = "/tmp/name-value-password-efivars";
    assert!(!Path::new(dir).exists(), "{dir} before dump-efivars");
    refused(&["hii", "dump-efivars", dir]);
    assert!(!Path::new(dir).exists(), "{dir} after dump-efivars");
}

/// The tests of each scenario, in a module named after whether its firmware lists the snapshot.
macro_rules! name_value_password_tests {
    ($($module:ident: $snapshot:expr),* $(,)?) => {$(
        mod $module {
            #[test]
            fn get_refuses_every_question() {
                super::get_refuses_every_question();
            }

            #[test]
            fn list_questions_refuses_beside_the_snapshot() {
                super::list_questions_refuses_beside_the_snapshot($snapshot);
            }

            #[test]
            fn list_questions_reads_without_efivars() {
                super::list_questions_reads_without_efivars();
            }

            #[test]
            fn set_refuses_and_writes_nothing() {
                super::set_refuses_and_writes_nothing();
            }

            #[test]
            fn dump_efivars_refuses_without_a_directory() {
                super::dump_efivars_refuses_without_a_directory();
            }
        }
    )*};
}

name_value_password_tests!(
    without_snapshot: super::Snapshot::Absent,
    with_snapshot: super::Snapshot::Listed,
);
