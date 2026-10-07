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

use uefisettings_qemu_guest::driver_sample::CHECK_BOX;
use uefisettings_qemu_guest::json;
use uefisettings_qemu_guest::json_error;
use uefisettings_qemu_guest::single_response;
use uefisettings_qemu_guest::variable_data;
use uefisettings_qemu_guest::Question;
use uefisettings_qemu_guest::BACKEND_HII;
use uefisettings_qemu_guest::DRIVER_SAMPLE_VARIABLE;
use uefisettings_qemu_guest::UNAVAILABLE;

#[test]
fn driver_sample_variable_is_not_visible() {
    assert_eq!(variable_data(DRIVER_SAMPLE_VARIABLE), None);
}

#[test]
fn list_questions_reports_the_check_box_as_unavailable() {
    let questions: Vec<Question> = json(&["hii", "list-questions", "--json"]);
    let listed: Vec<&Question> = questions
        .iter()
        .filter(|question| question.name == CHECK_BOX)
        .collect();
    assert!(
        listed.len() == 2
            && listed
                .iter()
                .all(|question| question.answer.starts_with(UNAVAILABLE)),
        "{listed:#?}"
    );
}

#[test]
fn get_reports_the_check_box_as_unavailable() {
    let (got, _) = single_response(&["hii", "get", CHECK_BOX, "--json"], BACKEND_HII);
    assert!(got.answer.starts_with(UNAVAILABLE), "{got:#?}");
}

#[test]
fn set_fails() {
    json_error(&["hii", "set", CHECK_BOX, "0", "--json"]);
    assert_eq!(variable_data(DRIVER_SAMPLE_VARIABLE), None);
}
