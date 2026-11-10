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
//! variables keep the answers that the first boot set, and both the HII and the generic
//! commands read them.

use uefisettings_qemu_guest::driver_sample::BOOT_ORDER;
use uefisettings_qemu_guest::driver_sample::BOOT_ORDER_OFFSET;
use uefisettings_qemu_guest::driver_sample::CHECK_BOX;
use uefisettings_qemu_guest::driver_sample::CHECK_BOX_OFFSET;
use uefisettings_qemu_guest::driver_sample::INCLUDE_GRAYED_OUT;
use uefisettings_qemu_guest::driver_sample::INCLUDE_SUPPRESSED;
use uefisettings_qemu_guest::driver_sample::MATCH2;
use uefisettings_qemu_guest::driver_sample::MATCH2_OFFSET;
use uefisettings_qemu_guest::driver_sample::MATCH2_REASON;
use uefisettings_qemu_guest::driver_sample::NUMERIC;
use uefisettings_qemu_guest::driver_sample::NUMERIC_OFFSET;
use uefisettings_qemu_guest::driver_sample::ONE_OF;
use uefisettings_qemu_guest::driver_sample::ONE_OF_OFFSET;
use uefisettings_qemu_guest::driver_sample::SERIAL_PORT;
use uefisettings_qemu_guest::driver_sample::SERIAL_PORT_OFFSET;
use uefisettings_qemu_guest::driver_sample::STRING;
use uefisettings_qemu_guest::driver_sample::STRING_OFFSET;
use uefisettings_qemu_guest::single_response;
use uefisettings_qemu_guest::variable_bytes;
use uefisettings_qemu_guest::variable_data;
use uefisettings_qemu_guest::BACKEND_HII;
use uefisettings_qemu_guest::DRIVER_SAMPLE_VARIABLE;
use uefisettings_qemu_guest::EFIVARFS_HEADER_SIZE;
use uefisettings_qemu_guest::MY_EFI_VAR;
use uefisettings_qemu_guest::MY_EFI_VAR_QUESTION;

/// The questions that `hii_write.rs` sets and their new answers.
/// Each comes with the flags that make `get` select it.
fn answers() -> [(&'static str, &'static [&'static str], String); 8] {
    [
        (ONE_OF, &[], "My one-of text #3".to_string()),
        (CHECK_BOX, &[], "0".to_string()),
        (NUMERIC, &[], "243".to_string()),
        (
            SERIAL_PORT,
            &INCLUDE_SUPPRESSED,
            "2F8 <suppressed>".to_string(),
        ),
        (
            MATCH2,
            &INCLUDE_GRAYED_OUT,
            format!("5 <selectable or grayed-out: {MATCH2_REASON}>"),
        ),
        (MY_EFI_VAR_QUESTION, &[], "32".to_string()),
        (BOOT_ORDER, &[], "USB <option suppressed>, PXE".to_string()),
        (STRING, &[], "STRING".to_string()),
    ]
}

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
    assert_eq!(data[MATCH2_OFFSET], 5, "{MATCH2}");
    assert_eq!(
        data[BOOT_ORDER_OFFSET..BOOT_ORDER_OFFSET + 6],
        [4, 0, 3, 0, 0, 0],
        "{BOOT_ORDER}"
    );
    let string: Vec<u8> = "STRING"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .chain([0; 68])
        .collect();
    assert_eq!(
        data[STRING_OFFSET..STRING_OFFSET + 80],
        string[..],
        "{STRING}"
    );
}

/// MyEfiVar keeps the answer that the first boot set and its attributes, with runtime access:
/// DriverSample's HiiValidateSettings took them at this boot.
#[test]
fn my_efi_var_keeps_the_new_answer_and_its_attributes() {
    let bytes = variable_bytes(MY_EFI_VAR).expect("MyEfiVar exists");
    assert_eq!(
        bytes.get(..EFIVARFS_HEADER_SIZE + 1),
        Some(&[7, 0, 0, 0, 32][..]),
        "{MY_EFI_VAR}: attributes and the first data byte"
    );
}

#[test]
fn get_returns_the_new_answers() {
    for (question, flags, answer) in answers() {
        let (got, _) = single_response(
            &[&["hii", "get", question, "--json"][..], flags].concat(),
            BACKEND_HII,
        );
        assert_eq!(got.answer, answer, "{question} {flags:?}: {got:#?}");
    }
}

#[test]
fn generic_get_returns_the_new_answers() {
    for (question, flags, answer) in answers() {
        let (got, _) = single_response(
            &[&["get", question, "--json"][..], flags].concat(),
            BACKEND_HII,
        );
        assert_eq!(got.answer, answer, "{question} {flags:?}: {got:#?}");
    }
}
