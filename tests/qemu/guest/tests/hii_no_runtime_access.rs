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

//! A guest whose firmware runs DriverSample from a `Driver####` load option without first
//! creating its variable, so DriverSample creates it without runtime access and Linux does
//! not see it: the questions on it are unavailable and cannot be set.
//! Their answers end with the default that their IFR declares.

use std::ffi::OsStr;
use std::path::Path;

use uefisettings_qemu_guest::driver_sample::CHECK_BOX;
use uefisettings_qemu_guest::driver_sample::NUMERIC;
use uefisettings_qemu_guest::driver_sample::ONE_OF;
use uefisettings_qemu_guest::json;
use uefisettings_qemu_guest::json_error;
use uefisettings_qemu_guest::single_response;
use uefisettings_qemu_guest::variable_data;
use uefisettings_qemu_guest::Question;
use uefisettings_qemu_guest::BACKEND_HII;
use uefisettings_qemu_guest::DRIVER_SAMPLE_VARIABLE;

/// Why the HII backend cannot read the questions on DriverSample's variable
/// (`src/lib/hii/forms.rs`).
/// Its name is spelled out, not derived from [`DRIVER_SAMPLE_VARIABLE`], to pin the
/// expected output.
const NO_CONFIG_ACCESS: &str = "<ValueUnavailable: no EFI variable \
    MyIfrNVData-a04a27f4-df00-4d42-b552-39511302113d; \
    HII buffer varstore requires EFI_HII_CONFIG_ACCESS_PROTOCOL>";

/// The answer of [`CHECK_BOX`], whose listings are both flagged `CHECKBOX_DEFAULT` in
/// DriverSample's Vfr.vfr.
fn check_box_answer() -> String {
    format!("{NO_CONFIG_ACCESS} <IFR default: 1>")
}

/// The answers that `hii list-questions` gives for the questions named `name`.
fn listed_answers(name: &str) -> Vec<String> {
    let questions: Vec<Question> = json(&["hii", "list-questions", "--json"]);
    questions
        .into_iter()
        .filter(|question| question.name == name)
        .map(|question| question.answer)
        .collect()
}

#[test]
fn driver_sample_variable_is_not_visible() {
    assert_eq!(variable_data(DRIVER_SAMPLE_VARIABLE), None);
}

#[test]
fn list_questions_reports_the_check_box_as_unavailable() {
    assert_eq!(
        listed_answers(CHECK_BOX),
        [check_box_answer(), check_box_answer()]
    );
}

#[test]
fn list_questions_reports_numeric_and_one_of_defaults() {
    // The standard defaults in DriverSample's Vfr.vfr: `default = 18` and the option
    // flagged DEFAULT.
    for (name, default) in [(NUMERIC, "18"), (ONE_OF, "My one-of text #2")] {
        assert_eq!(
            listed_answers(name),
            [format!("{NO_CONFIG_ACCESS} <IFR default: {default}>")],
            "{name}"
        );
    }
}

#[test]
fn get_reports_the_check_box_as_unavailable() {
    let (got, _) = single_response(&["hii", "get", CHECK_BOX, "--json"], BACKEND_HII);
    assert_eq!(got.answer, check_box_answer(), "{got:#?}");
}

#[test]
fn set_fails_naming_the_missing_variable() {
    let file_name = Path::new(DRIVER_SAMPLE_VARIABLE)
        .file_name()
        .and_then(OsStr::to_str)
        .expect("file name of the variable");
    for (name, value) in [(CHECK_BOX, "0"), (ONE_OF, "My one-of text #1")] {
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
