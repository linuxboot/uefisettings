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

//! The second boot after `hii_write.rs`, with the same variable store: DriverSample's
//! variable keeps the answers that the first boot set, and both the HII and the generic
//! commands read them.

use uefisettings_qemu_guest::driver_sample::CHECK_BOX;
use uefisettings_qemu_guest::driver_sample::CHECK_BOX_OFFSET;
use uefisettings_qemu_guest::driver_sample::NUMERIC;
use uefisettings_qemu_guest::driver_sample::NUMERIC_OFFSET;
use uefisettings_qemu_guest::driver_sample::ONE_OF;
use uefisettings_qemu_guest::driver_sample::ONE_OF_OFFSET;
use uefisettings_qemu_guest::driver_sample::SERIAL_PORT;
use uefisettings_qemu_guest::driver_sample::SERIAL_PORT_OFFSET;
use uefisettings_qemu_guest::single_response;
use uefisettings_qemu_guest::variable_data;
use uefisettings_qemu_guest::BACKEND_HII;
use uefisettings_qemu_guest::DRIVER_SAMPLE_VARIABLE;

/// The questions that `hii_write.rs` sets and their new answers.
const ANSWERS: [(&str, &str); 4] = [
    (ONE_OF, "My one-of text #3"),
    (CHECK_BOX, "0"),
    (NUMERIC, "243"),
    (SERIAL_PORT, "2F8"),
];

#[test]
fn driver_sample_variable_keeps_the_new_answers() {
    let data = variable_data(DRIVER_SAMPLE_VARIABLE).expect("the variable does not exist");
    assert_eq!(data[ONE_OF_OFFSET], 3);
    assert_eq!(data[CHECK_BOX_OFFSET], 0);
    assert_eq!(data[NUMERIC_OFFSET], 243);
    assert_eq!(
        data[SERIAL_PORT_OFFSET..SERIAL_PORT_OFFSET + 2],
        0x2f8u16.to_le_bytes()
    );
}

#[test]
fn get_returns_the_new_answers() {
    for (question, answer) in ANSWERS {
        let (got, _) = single_response(&["hii", "get", question, "--json"], BACKEND_HII);
        assert_eq!(got.answer, answer, "{got:#?}");
    }
}

#[test]
fn generic_get_returns_the_new_answers() {
    for (question, answer) in ANSWERS {
        let (got, _) = single_response(&["get", question, "--json"], BACKEND_HII);
        assert_eq!(got.answer, answer, "{got:#?}");
    }
}
