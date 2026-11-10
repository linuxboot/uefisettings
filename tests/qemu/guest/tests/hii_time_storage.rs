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

//! The boot of a guest whose firmware ran publish-hiidb's `wakeup-time-forms`: get and set of a
//! DATE and of a TIME that suppresses its second, on the variable DateTimeData, which keep their
//! EFI_HII_DATE and EFI_HII_TIME there (UEFI 2.11 §33.2.5.4.6, §33.2.5.4.11), and of a DATE and
//! a TIME of the wake-up time, EFI Date/Time Storage (§33.2.5.6) that Linux does not reach.

use uefisettings_qemu_guest::changed_bytes;
use uefisettings_qemu_guest::json_error;
use uefisettings_qemu_guest::single_response;
use uefisettings_qemu_guest::variable_data;
use uefisettings_qemu_guest::BACKEND_HII;

/// The variable of the forms, which publish-hiidb creates with 2024-02-29 at byte 0 and
/// 12:34:56 at byte 4.
const DATE_TIME_DATA: &str =
    "/sys/firmware/efi/efivars/DateTimeData-8c78a505-baa0-4c4a-869f-000000000501";
/// The DATE at byte 0 of [`DATE_TIME_DATA`].
const STORED_DATE: &str = "Stored date";
/// The TIME at byte 4 of [`DATE_TIME_DATA`], which suppresses its second.
const STORED_TIME: &str = "Stored time";
/// The DATE and TIME of the wake-up time, without a VarStore.
const WAKEUP_DATE: &str = "Wake-up date";
const WAKEUP_TIME: &str = "Wake-up time";

#[track_caller]
fn data() -> Vec<u8> {
    variable_data(DATE_TIME_DATA).expect("publish-hiidb creates DateTimeData")
}

/// The answer that get gives for `question`.
#[track_caller]
fn get(question: &str) -> String {
    single_response(&["hii", "get", question, "--json"], BACKEND_HII)
        .0
        .answer
}

/// Sets `question` to `answer`, checks that get gives it, and returns the bytes of
/// [`DATE_TIME_DATA`] that changed.
#[track_caller]
fn set(question: &str, answer: &str) -> Vec<(usize, u8)> {
    let before = data();
    let (set, modified) = single_response(&["hii", "set", question, answer, "--json"], BACKEND_HII);
    assert_eq!((set.answer.as_str(), modified), (answer, true), "{set:#?}");
    assert_eq!(get(question), answer, "get {question}");
    changed_bytes(&before, &data())
}

/// The error of set of `question` to `answer`, which changes no byte of [`DATE_TIME_DATA`].
#[track_caller]
fn refuse(question: &str, answer: &str) -> String {
    let before = data();
    let error = json_error(&["hii", "set", question, answer, "--json"]).error_message;
    assert_eq!(changed_bytes(&before, &data()), [], "{question} = {answer}");
    error
}

/// A DATE shows its EFI_HII_DATE as YYYY-MM-DD and set writes the date it takes there; a day
/// that the month lacks is refused.
#[test]
fn stored_date_is_set_as_its_efi_hii_date() {
    let shown = get(STORED_DATE);
    let [low, high, month, day] = data()[..4] else {
        panic!("DateTimeData holds an EFI_HII_DATE at byte 0")
    };
    assert_eq!(
        shown,
        format!("{:04}-{month:02}-{day:02}", u16::from_le_bytes([low, high])),
        "get {STORED_DATE}"
    );
    let changed = set(STORED_DATE, "2025-03-01");
    let want: Vec<(usize, u8)> = [0xE9, 0x07, 3, 1]
        .into_iter()
        .enumerate()
        .filter(|&(offset, byte)| [low, high, month, day][offset] != byte)
        .collect();
    assert_eq!(changed, want, "bytes of 2025-03-01");
    assert_eq!(
        refuse(STORED_DATE, "2025-02-29"),
        "day 29 is outside 1 to 28"
    );
}

/// A TIME that suppresses its second shows dashes there; set keeps the stored second for the
/// dashes it takes there, and refuses digits.
#[test]
fn stored_time_keeps_its_suppressed_second() {
    let [hour, minute, second] = data()[4..7] else {
        panic!("DateTimeData holds an EFI_HII_TIME at byte 4")
    };
    assert_eq!(get(STORED_TIME), format!("{hour:02}:{minute:02}:--"));
    let changed = set(STORED_TIME, "23:01:--");
    let want: Vec<(usize, u8)> = [(4, hour, 23), (5, minute, 1)]
        .into_iter()
        .filter(|&(_, old, new)| old != new)
        .map(|(offset, _, new)| (offset, new))
        .collect();
    assert_eq!(changed, want, "bytes of 23:01:--");
    assert_eq!(data()[6], second, "the suppressed second");
    assert_eq!(
        refuse(STORED_TIME, "23:01:02"),
        "the second of this TIME is suppressed (UEFI 2.11 §33.2.5.4.11): give dashes there, \
         which keep it"
    );
}

/// Linux reaches no Time Services: get shows the DATE and TIME of the wake-up time without a
/// value, naming GetWakeupTime(), and set refuses them, naming SetWakeupTime().
#[test]
fn wakeup_time_is_neither_read_nor_written() {
    for (question, answer) in [(WAKEUP_DATE, "2030-01-02"), (WAKEUP_TIME, "01:02:03")] {
        assert_eq!(
            get(question),
            "<ValueUnavailable: EFI Date/Time Storage (UEFI 2.11 §33.2.5.6) is read only \
             through GetWakeupTime(); run uefisettings.efi in the UEFI Shell>",
            "get {question}"
        );
        assert_eq!(
            refuse(question, answer),
            format!(
                "cannot set question {question:?}: EFI Date/Time Storage (UEFI 2.11 §33.2.5.6) \
                 is written only through SetWakeupTime(); run uefisettings.efi in the UEFI Shell"
            ),
            "set {question}"
        );
    }
}
