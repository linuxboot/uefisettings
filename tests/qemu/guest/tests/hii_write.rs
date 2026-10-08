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

//! The first boot of a guest set up like the one of `hii.rs`: each check changes the
//! answer of one DriverSample question, or tries a value that the form does not allow,
//! and compares DriverSample's variable before and after. `hii_persistence.rs` checks the
//! new answers in the next boot.

use uefisettings_qemu_guest::changed_bytes;
use uefisettings_qemu_guest::driver_sample::CHECK_BOX;
use uefisettings_qemu_guest::driver_sample::CHECK_BOX_OFFSET;
use uefisettings_qemu_guest::driver_sample::NUMERIC;
use uefisettings_qemu_guest::driver_sample::NUMERIC_OFFSET;
use uefisettings_qemu_guest::driver_sample::ONE_OF;
use uefisettings_qemu_guest::driver_sample::ONE_OF_OFFSET;
use uefisettings_qemu_guest::driver_sample::SERIAL_PORT;
use uefisettings_qemu_guest::driver_sample::SERIAL_PORT_OFFSET;
use uefisettings_qemu_guest::json_error;
use uefisettings_qemu_guest::single_response;
use uefisettings_qemu_guest::variable_data;
use uefisettings_qemu_guest::BACKEND_HII;
use uefisettings_qemu_guest::DRIVER_SAMPLE_VARIABLE;

#[track_caller]
fn driver_sample_data() -> Vec<u8> {
    variable_data(DRIVER_SAMPLE_VARIABLE).expect("the variable does not exist")
}

/// Sets `question` to `answer` with `set` and checks that `get` returns it, both after
/// `prefix`: `["hii"]` for the HII commands, `[]` for the generic ones. Returns the bytes of
/// the variable that changed.
#[track_caller]
fn set(prefix: &[&str], question: &str, answer: &str) -> Vec<(usize, u8)> {
    let before = driver_sample_data();
    let (set, modified) = single_response(
        &[prefix, &["set", question, answer, "--json"]].concat(),
        BACKEND_HII,
    );
    assert_eq!((set.answer.as_str(), modified), (answer, true), "{set:#?}");
    let (got, _) = single_response(
        &[prefix, &["get", question, "--json"]].concat(),
        BACKEND_HII,
    );
    assert_eq!(got.answer, answer, "{got:#?}");
    changed_bytes(&before, &driver_sample_data())
}

/// Checks that `hii set` refuses `answer` for `question` without changing the variable.
#[track_caller]
fn refuse(question: &str, answer: &str) {
    let before = driver_sample_data();
    json_error(&["hii", "set", question, answer, "--json"]);
    assert_eq!(changed_bytes(&before, &driver_sample_data()), []);
}

#[test]
fn set_one_of_is_stored() {
    let changed = set(&["hii"], ONE_OF, "My one-of text #3");
    assert_eq!(changed, [(ONE_OF_OFFSET, 3)]);
}

#[test]
fn set_one_of_to_an_unknown_option_is_refused() {
    refuse(ONE_OF, "Bogus");
}

#[test]
fn generic_set_check_box_is_stored() {
    let changed = set(&[], CHECK_BOX, "0");
    assert_eq!(changed, [(CHECK_BOX_OFFSET, 0)]);
}

#[test]
fn set_check_box_to_2_is_refused() {
    refuse(CHECK_BOX, "2");
}

#[test]
fn set_numeric_to_its_maximum_is_stored() {
    let changed = set(&["hii"], NUMERIC, "243");
    assert_eq!(changed, [(NUMERIC_OFFSET, 243)]);
}

#[test]
fn set_numeric_above_its_maximum_is_refused() {
    refuse(NUMERIC, "244");
}

#[test]
fn set_16_bit_one_of_is_stored() {
    // The only 16-bit question on a variable that Linux can write. The form grays it out
    // and hides it, but the library ignores that. 0x3F8 becomes 0x2F8: only the high byte
    // changes.
    let changed = set(&["hii"], SERIAL_PORT, "2F8");
    assert_eq!(changed, [(SERIAL_PORT_OFFSET + 1, 0x02)]);
}
