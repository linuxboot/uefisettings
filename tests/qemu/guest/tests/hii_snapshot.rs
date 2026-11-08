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

//! A guest whose firmware publishes ExportConfig()'s results for the OS (UEFI 2.11 §33.2.11.1),
//! as `publish-hiidb.efi export-config` installs them, with a `<ConfigResp>` of AMITSESetup
//! that holds 0xA5 bytes in the passwords of its password forms and Enabled in the ONE_OF Quiet
//! Boot after them, and whose DriverSample variable, which
//! tests/qemu/vars/my-ifr-nv-data-boot-services.json creates without runtime access and with
//! values that are not the defaults of DriverSample's Vfr.vfr, Linux does not see: get,
//! list-questions and show-ifr take the values of DriverSample's questions and of Quiet Boot
//! from the snapshot, tagged, but print and log no byte of the passwords; set refuses
//! DriverSample's questions as without the snapshot.

use std::ffi::OsStr;
use std::path::Path;

use uefisettings_qemu_guest::driver_sample::CHECK_BOX;
use uefisettings_qemu_guest::driver_sample::INCLUDE_GRAYED_OUT;
use uefisettings_qemu_guest::driver_sample::INCLUDE_SUPPRESSED;
use uefisettings_qemu_guest::driver_sample::LOCKED;
use uefisettings_qemu_guest::driver_sample::NUMERIC;
use uefisettings_qemu_guest::driver_sample::ONE_OF;
use uefisettings_qemu_guest::json;
use uefisettings_qemu_guest::json_error;
use uefisettings_qemu_guest::single_response;
use uefisettings_qemu_guest::uefisettings;
use uefisettings_qemu_guest::uefisettings_with_env;
use uefisettings_qemu_guest::variable_data;
use uefisettings_qemu_guest::Output;
use uefisettings_qemu_guest::Question;
use uefisettings_qemu_guest::BACKEND_HII;
use uefisettings_qemu_guest::DRIVER_SAMPLE_VARIABLE;

/// The ONE_OF of the password forms on byte 80 of AMITSESetup.
const QUIET_BOOT: &str = "Quiet Boot";
/// Eight of the 0xA5 bytes that the snapshot holds for the passwords of AMITSESetup, as hex
/// digits and as Debug shows a byte slice: what a leak of them would show.
const MARKER_RUNS: [&str; 2] = ["a5a5a5a5a5a5a5a5", "165, 165, 165, 165, 165, 165, 165, 165"];
/// Its answer from the snapshot, beside the passwords: Enabled, the option of value 1.
const QUIET_BOOT_ANSWER: &str = "Enabled <snapshot>";
/// The answers that DriverSample's questions take from the snapshot: the values of
/// my-ifr-nv-data-boot-services.json, where Vfr.vfr's defaults are 1, 18 and
/// "My one-of text #2". The conditions around CHECK_BOX and NUMERIC are false on values of the
/// snapshot, so the snapshot leaves them selectable.
const SNAPSHOT_ANSWERS: [(&str, &str); 3] = [
    (CHECK_BOX, "0 <snapshot> <selectable> <snapshot>"),
    (NUMERIC, "42 <snapshot> <selectable> <snapshot>"),
    (ONE_OF, "My one-of text #3 <snapshot>"),
];
/// What show-ifr shows for them: numbers, and CHECK_BOX's twice, as the forms list it twice.
const SHOWN_ANSWERS: [(&str, &[&str]); 3] = [
    (CHECK_BOX, &["0 <snapshot>", "0 <snapshot>"]),
    (NUMERIC, &["42 <snapshot>"]),
    (ONE_OF, &["3 <snapshot>"]),
];
/// The answer of DriverSample's name/value question: DriverSample's ExtractConfig() exports its
/// buffer storage only when ExportConfig() asks for everything (edk2-stable202608
/// DriverSample.c), so the snapshot holds no name/value setting.
const NAME_VALUE: &str = "<ValueUnavailable: HII name/value varstore requires \
    EFI_HII_CONFIG_ACCESS_PROTOCOL> <IFR default: 16> <grayed-out>";

/// Runs `uefisettings` with `args` and every log level on; panics unless it exits with 0.
#[track_caller]
fn traced(args: &[&str]) -> Output {
    let output = uefisettings_with_env(args, &[("RUST_LOG", "trace")]);
    assert_eq!(output.code, Some(0), "{args:?}: {output:#?}");
    output
}

/// The answers that show-ifr's `output` shows for the questions prompted `prompt`, in order.
fn shown_answers(output: &str, prompt: &str) -> Vec<String> {
    let mut question = "";
    let mut answers = Vec::new();
    for line in output.lines().map(str::trim_start) {
        // "Q: - <prompt> - Help: - <help>" for a CHECKBOX, "Q: <prompt> - Help: <help>" else
        if let Some((_, rest)) = line.split_once(" - Q: ") {
            let rest = rest.trim_start_matches("- ");
            question = rest.split_once(" - Help: ").map_or(rest, |(name, _)| name);
        }
        if let Some(answer) = line.strip_prefix("-Answer: ") {
            if question == prompt {
                answers.push(answer.to_owned());
            }
        }
    }
    answers
}

#[test]
fn driver_sample_variable_is_not_visible() {
    assert_eq!(variable_data(DRIVER_SAMPLE_VARIABLE), None);
}

#[test]
fn get_takes_values_from_the_snapshot() {
    for (name, want) in SNAPSHOT_ANSWERS {
        let (got, _) = single_response(&["hii", "get", name, "--json"], BACKEND_HII);
        assert_eq!(got.answer, want, "{name}: {got:#?}");
        let text = uefisettings(&["hii", "get", name]);
        assert_eq!(text.code, Some(0), "{name}: {text:#?}");
        assert!(
            text.stdout.contains(&format!("answer: \"{want}\"")),
            "{name}: {text:#?}"
        );
    }
}

#[test]
fn list_questions_takes_values_from_the_snapshot() {
    let questions: Vec<Question> = json(&["hii", "list-questions", "--json"]);
    for (name, want) in SNAPSHOT_ANSWERS {
        let listed: Vec<&str> = questions
            .iter()
            .filter(|question| question.name == name)
            .map(|question| question.answer.as_str())
            .collect();
        assert_eq!(listed, [want], "{name}");
    }

    // The form of CHECK_BOX's second listing is suppressed, as without the snapshot, here by its
    // value of BootOrderLarge.
    let questions: Vec<Question> = json(&[
        "hii",
        "list-questions",
        "--json",
        INCLUDE_SUPPRESSED[0],
        INCLUDE_SUPPRESSED[1],
    ]);
    let listed: Vec<&str> = questions
        .iter()
        .filter(|question| question.name == CHECK_BOX)
        .map(|question| question.answer.as_str())
        .collect();
    assert_eq!(
        listed,
        [
            "0 <snapshot> <selectable> <snapshot>",
            "0 <snapshot> <suppressed> <snapshot>"
        ]
    );
}

#[test]
fn show_ifr_takes_values_from_the_snapshot() {
    let output = uefisettings(&["hii", "show-ifr"]);
    assert_eq!(output.code, Some(0), "{output:#?}");
    for (name, want) in SHOWN_ANSWERS {
        assert_eq!(shown_answers(&output.stdout, name), want, "{name}");
    }
}

#[test]
fn name_value_questions_stay_unavailable() {
    let questions: Vec<Question> = json(&[
        "hii",
        "list-questions",
        "--json",
        INCLUDE_GRAYED_OUT[0],
        INCLUDE_GRAYED_OUT[1],
    ]);
    let listed: Vec<&str> = questions
        .iter()
        .filter(|question| question.name == LOCKED)
        .map(|question| question.answer.as_str())
        .collect();
    assert_eq!(listed, [NAME_VALUE], "{LOCKED}");
}

#[test]
fn quiet_boot_shows_its_snapshot_value_but_no_password_byte() {
    let (got, _) = single_response(&["hii", "get", QUIET_BOOT, "--json"], BACKEND_HII);
    assert_eq!(got.answer, QUIET_BOOT_ANSWER, "get --json: {got:#?}");
    let questions: Vec<Question> = json(&["hii", "list-questions", "--json"]);
    let listed: Vec<&str> = questions
        .iter()
        .filter(|question| question.name == QUIET_BOOT)
        .map(|question| question.answer.as_str())
        .collect();
    assert_eq!(listed, [QUIET_BOOT_ANSWER], "list-questions --json");
    let shown = uefisettings(&["hii", "show-ifr"]);
    assert_eq!(
        shown_answers(&shown.stdout, QUIET_BOOT),
        ["1 <snapshot>"],
        "show-ifr"
    );

    // as text and JSON, with every log message
    for args in [
        &["hii", "get", QUIET_BOOT][..],
        &["hii", "get", QUIET_BOOT, "--json"],
        &["hii", "list-questions"],
        &["hii", "list-questions", "--json"],
        &["hii", "show-ifr"],
    ] {
        let output = traced(args);
        for (stream, text) in [("stdout", &output.stdout), ("stderr", &output.stderr)] {
            let text = text.to_ascii_lowercase();
            for run in MARKER_RUNS {
                assert!(
                    !text.contains(run),
                    "{args:?}: {stream} shows bytes of the passwords"
                );
            }
        }
    }
}

#[test]
fn set_fails_naming_the_missing_variable() {
    let file_name = Path::new(DRIVER_SAMPLE_VARIABLE)
        .file_name()
        .and_then(OsStr::to_str)
        .expect("file name of the variable");
    for (name, value) in [(CHECK_BOX, "1"), (ONE_OF, "My one-of text #1")] {
        let error = json_error(&["hii", "set", name, value, "--json"]);
        assert_eq!(
            error.error_message,
            format!(
                "no EFI variable {file_name}: the firmware has not created it or does not expose \
                 it to the OS, so its questions cannot be set from Linux; change them in the \
                 firmware setup, or ask the board vendor for firmware that exposes it; see \
                 https://github.com/linuxboot/uefisettings/issues/2"
            ),
            "{name}"
        );
    }
    assert_eq!(variable_data(DRIVER_SAMPLE_VARIABLE), None);
}
