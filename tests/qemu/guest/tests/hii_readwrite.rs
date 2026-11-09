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

//! The boot of the scenario hii-readwrite: DriverSample, then publish-hiidb's
//! `rt-data-readwrite-forms`, which creates ReadWriteData and registers the forms of
//! `publish-hiidb/src/readwrite_forms.rs` before it publishes the HII database. get and set take
//! the values of questions through their READ and WRITE expressions (UEFI 2.11 §33.2.5.4.1),
//! and refuse each question without a VarStore that neither reaches, saying why, and a WRITE
//! expression that sets a VarStore without its variable, before any write. A question with an
//! EFI_IFR_VALUE shows the value of that expression, and set refuses it (UEFI 2.11 §33.3.8.3.88).
//! set writes an option of a narrower type than its question in all the question's bytes.

use uefisettings_qemu_guest::changed_bytes;
use uefisettings_qemu_guest::json;
use uefisettings_qemu_guest::json_error;
use uefisettings_qemu_guest::single_response;
use uefisettings_qemu_guest::variable_data;
use uefisettings_qemu_guest::Question;
use uefisettings_qemu_guest::BACKEND_HII;
use uefisettings_qemu_guest::DRIVER_SAMPLE_VARIABLE;
use uefisettings_qemu_guest::PREFIXES;

/// The efivarfs file of ReadWriteData, the VARSTORE_EFI of the forms.
const READ_WRITE_DATA: &str =
    "/sys/firmware/efi/efivars/ReadWriteData-8c78a505-baa0-4c4a-869f-000000000201";
/// The efivarfs file of AbsentBuffer, the buffer VARSTORE of the forms, which has no variable.
const ABSENT_BUFFER: &str =
    "/sys/firmware/efi/efivars/AbsentBuffer-8c78a505-baa0-4c4a-869f-000000000201";
/// The bytes that publish-hiidb creates ReadWriteData with (`readwrite_forms::STORE_DATA`).
const STORE_DATA: [u8; 11] = [
    0x00, 0x04, 0x04, 0x00, 0x04, 0x01, 0x00, 0xEE, 0x11, 0x07, 0xA5,
];
/// The NUMERIC at byte 7 of ReadWriteData whose READ gives the stored byte plus 1.
const READ_TRANSFORMED: &str = "Read transformed";
const READ_TRANSFORMED_OFFSET: usize = 7;
/// The byte of ReadWriteData that "Computed value" holds, which its EFI_IFR_VALUE, "Linked value"
/// plus 0x10, hides.
const COMPUTED_VALUE_OFFSET: usize = 8;

/// DriverSample's ONE_OF on SerialPortNo, at byte 0xC0, in a FORM_MAP with the standard method.
/// Its READ reaches the UNDEFINED among the operands of its inner EFI_IFR_CONDITIONAL, which ends
/// the evaluation whatever the CONDITIONAL would pick (edk2-stable202608
/// SetupBrowserDxe/Expression.c EvaluateExpression), so get shows the stored SerialPortNo; its
/// WRITE sets SerialPortStatus (0xC1), SerialPortIo (0xC2, 16 bits) and SerialPortIrq (0xC4) for
/// the port.
const SERIAL_PORT_NUMBER: &str = "Serial port number";
const SERIAL_PORT_NUMBER_OFFSET: usize = 0xC0;

/// The refusal of a question whose driver keeps its value, from Linux (UEFI 2.11 §7.4.6).
const DRIVER_HELD: &str = "question has no VarStore; its driver keeps the value, which only \
     EFI_HII_CONFIG_ACCESS_PROTOCOL.CallBack() reaches (UEFI 2.11 §33.2.5.6), and after \
     ExitBootServices() no EFI device-handle-based protocol may be used (UEFI 2.11 §7.4.6); use \
     uefisettings.efi in the UEFI Shell";
/// set stages a question that its driver holds for the next boot, on the ESP, which no boot here
/// mounts
const NO_MOUNTED_ESP: &str =
    "no mounted vfat volume is an EFI system partition; mount it. Mounted: none";
const NO_VALUE_SOURCE: &str = "question has no VarStore, READ or WRITE expression, or \
     EFI_IFR_FLAG_CALLBACK, one of which UEFI 2.11 §33.2.5.6 requires";
const NO_READ: &str = "question has no VarStore, READ expression or EFI_IFR_FLAG_CALLBACK, so it \
     has no value to retrieve (UEFI 2.11 §33.2.5.4.1)";
const NO_WRITE: &str = "question has no VarStore, WRITE expression or EFI_IFR_FLAG_CALLBACK, so \
     nothing keeps a changed value (UEFI 2.11 §33.2.5.4.1)";
const READ_UNDEFINED: &str = "its READ expression gives no value, and without a VarStore the \
     question has no other (UEFI 2.11 §33.2.5.4.1)";
const UNEVALUATED_READ: &str =
    "its READ expression uses EFI_IFR_TO_UINT, which uefisettings does not evaluate";
const VALUE_MAKES_READ_ONLY: &str =
    "its EFI_IFR_VALUE expression makes it read-only (UEFI 2.11 §33.3.8.3.88)";

#[track_caller]
fn read_write_data() -> Vec<u8> {
    variable_data(READ_WRITE_DATA).expect("publish-hiidb creates ReadWriteData")
}

/// The answer of `question` that `get` after `prefix` prints.
#[track_caller]
fn get(prefix: &[&str], question: &str) -> String {
    let args = [prefix, &["get", question, "--json"]].concat();
    single_response(&args, BACKEND_HII).0.answer
}

/// Sets `question` to `answer` with `hii set`, and returns the bytes of ReadWriteData that
/// changed.
#[track_caller]
fn set(question: &str, answer: &str) -> Vec<(usize, u8)> {
    let before = read_write_data();
    let (set, modified) = single_response(&["hii", "set", question, answer, "--json"], BACKEND_HII);
    assert_eq!(
        (set.answer.as_str(), modified),
        (answer, true),
        "{question} = {answer}: {set:#?}"
    );
    changed_bytes(&before, &read_write_data())
}

/// The error of `set` after `prefix` of `question` to `answer`, which changes neither
/// ReadWriteData nor DriverSample's variable.
#[track_caller]
fn refuse(prefix: &[&str], question: &str, answer: &str) -> String {
    let before = (read_write_data(), variable_data(DRIVER_SAMPLE_VARIABLE));
    let error = json_error(&[prefix, &["set", question, answer, "--json"]].concat());
    assert_eq!(
        (read_write_data(), variable_data(DRIVER_SAMPLE_VARIABLE)),
        before,
        "{prefix:?} {question} = {answer} wrote"
    );
    error.error_message
}

/// set of DriverSample's "Serial port number" to port 3 stores 3 and evaluates its WRITE, whose
/// SETs store SerialPortStatus TRUE, SerialPortIo 0x3E8 and SerialPortIrq 4 in the same write;
/// get shows the stored 3, as its READ ends at its UNDEFINED.
#[test]
fn set_of_a_question_with_a_write_expression_stores_its_sets() {
    let data = || variable_data(DRIVER_SAMPLE_VARIABLE).expect("MyIfrNVData exists");
    let before = data();
    let span = SERIAL_PORT_NUMBER_OFFSET..SERIAL_PORT_NUMBER_OFFSET + 5;
    assert_eq!(
        before[span.clone()],
        [0x00, 0x00, 0xF8, 0x03, 0x04],
        "{SERIAL_PORT_NUMBER}: the bytes of vars/my-ifr-nv-data.json"
    );
    // the READ ends at its UNDEFINED: get shows the stored 0
    assert_eq!(
        get(&["hii"], SERIAL_PORT_NUMBER),
        "Serial port disable",
        "before"
    );

    let (set, modified) = single_response(
        &["hii", "set", SERIAL_PORT_NUMBER, "Serial port 3", "--json"],
        BACKEND_HII,
    );
    assert_eq!(
        (set.answer.as_str(), modified),
        ("Serial port 3", true),
        "{set:#?}"
    );

    let after = data();
    assert_eq!(after[span], [0x03, 0x01, 0xE8, 0x03, 0x04], "after");
    assert_eq!(
        changed_bytes(&before, &after),
        [(0xC0, 0x03), (0xC1, 0x01), (0xC2, 0xE8)],
        "only the question and its SETs change"
    );
    assert_eq!(get(&["hii"], SERIAL_PORT_NUMBER), "Serial port 3", "after");
}

/// The questions over ReadWriteData, in one test, as each set changes what the next sees.
#[test]
fn get_and_set_take_values_through_read_and_write_expressions() {
    assert_eq!(read_write_data(), STORE_DATA, "before");

    // byte 0 holds no option of the MAP of "Mapped choice"
    assert_eq!(
        get(&["hii"], "Mapped choice"),
        format!("<ValueUnavailable: {READ_UNDEFINED}>"),
        "Mapped choice before"
    );
    assert_eq!(set("Mapped choice", "Second"), [(0, 2)], "Mapped choice");
    assert_eq!(
        get(&["hii"], "Mapped choice"),
        "Second",
        "Mapped choice after"
    );

    // the WRITE of "Linked value" copies it to byte 2 and, plus 0x100, to bytes 4 and 5
    assert_eq!(get(&["hii"], "Linked value"), "4", "Linked value before");
    assert_eq!(
        get(&["hii"], "Read only"),
        "4",
        "Read only takes byte 1 through its READ"
    );
    assert_eq!(
        get(&["hii"], "Computed value"),
        "20",
        "Computed value takes Linked value plus 0x10 through its VALUE"
    );
    assert_eq!(
        set("Linked value", "5"),
        [(1, 5), (2, 5), (4, 5)],
        "Linked value"
    );
    assert_eq!(get(&["hii"], "Linked value"), "5", "Linked value after");
    assert_eq!(get(&["hii"], "Read only"), "5", "Read only after");
    assert_eq!(
        get(&["hii"], "Computed value"),
        "21",
        "Computed value after"
    );

    // "Write only" keeps its value in byte 6 through its WRITE alone
    assert_eq!(set("Write only", "9"), [(6, 9)], "Write only");

    // the READ of "Read transformed" shows its stored byte 0xEE plus 1; set stores the value
    // given, which get then shows plus 1 (UEFI 2.11 §33.2.5.4.1)
    for prefix in PREFIXES {
        assert_eq!(
            get(prefix, READ_TRANSFORMED),
            "239",
            "{READ_TRANSFORMED} before {prefix:?}"
        );
    }
    let questions: Vec<Question> = json(&["hii", "list-questions", "--json"]);
    let listed: Vec<&str> = questions
        .iter()
        .filter(|question| question.name == READ_TRANSFORMED)
        .map(|question| question.answer.as_str())
        .collect();
    assert_eq!(listed, ["239"], "list-questions {READ_TRANSFORMED} before");
    assert_eq!(
        set(READ_TRANSFORMED, "100"),
        [(READ_TRANSFORMED_OFFSET, 100)],
        "{READ_TRANSFORMED}"
    );
    assert_eq!(
        get(&["hii"], READ_TRANSFORMED),
        "101",
        "{READ_TRANSFORMED} after"
    );

    // the UINT16 "Option width" holds 0xA507, which no option has; set writes its UINT8 option
    // "Narrow" zero-extended in both bytes, as edk2-stable202608 SetupBrowserDxe/Setup.c:2108
    // writes the StorageWidth bytes
    assert_eq!(
        get(&["hii"], "Option width"),
        "42247 (no matching option)",
        "Option width before"
    );
    assert_eq!(
        set("Option width", "Narrow"),
        [(9, 5), (10, 0)],
        "Option width"
    );
    assert_eq!(
        get(&["hii"], "Option width"),
        "Narrow",
        "Option width after"
    );

    assert_eq!(
        read_write_data(),
        [0x02, 0x05, 0x05, 0x00, 0x05, 0x01, 0x09, 0x64, 0x11, 0x05, 0x00],
        "after"
    );
}

/// get and list-questions show the value of the EFI_IFR_VALUE of "Computed value", "Linked
/// value" plus 0x10, never its stored byte; set refuses it as read-only and writes nothing.
#[test]
fn a_question_with_a_value_expression_shows_its_value_and_refuses_set() {
    let question = "Computed value";
    let stored = read_write_data()[COMPUTED_VALUE_OFFSET];
    assert_eq!(stored, STORE_DATA[COMPUTED_VALUE_OFFSET], "stored byte");
    // "Linked value" holds 4, or 5 once the test that sets it has run
    let linked: u16 = get(&["hii"], "Linked value")
        .parse()
        .expect("Linked value is a number");
    let computed = (linked + 0x10).to_string();
    assert_ne!(
        computed,
        stored.to_string(),
        "the VALUE hides the stored byte"
    );

    for prefix in PREFIXES {
        assert_eq!(get(prefix, question), computed, "get {prefix:?}");
        assert_eq!(
            refuse(prefix, question, "7"),
            format!("cannot set question {question:?}: {VALUE_MAKES_READ_ONLY}"),
            "set {prefix:?}"
        );
    }
    let questions: Vec<Question> = json(&["hii", "list-questions", "--json"]);
    let listed: Vec<&str> = questions
        .iter()
        .filter(|listed| listed.name == question)
        .map(|listed| listed.answer.as_str())
        .collect();
    assert_eq!(listed, [computed.as_str()], "list-questions");
}

/// A WRITE expression that sets AbsentBuffer, whose variable does not exist, refuses set before
/// any write: the question's own byte stays, and no variable is created.
#[test]
fn set_of_a_write_into_a_store_without_its_variable_is_refused() {
    for prefix in PREFIXES {
        assert_eq!(
            refuse(prefix, "Absent target", "5"),
            "cannot set question \"Absent target\": its WRITE expression sets VarStore 0x0002 \
             (EFI_IFR_VARSTORE \"AbsentBuffer\"), which set may not write: no EFI variable \
             AbsentBuffer-8c78a505-baa0-4c4a-869f-000000000201: the firmware has not created it \
             or does not expose it to the OS, so its questions cannot be set from Linux; change \
             them in the firmware setup, or ask the board vendor for firmware that exposes it; \
             see https://github.com/linuxboot/uefisettings/issues/2",
            "{prefix:?}"
        );
    }
    assert_eq!(variable_data(ABSENT_BUFFER), None, "AbsentBuffer created");
}

/// get and set say what each question without a VarStore lacks; get says that its driver keeps
/// its value, which nothing reaches from Linux, and set, which stages it for the next boot, that no
/// ESP is mounted.
#[test]
fn get_and_set_of_storageless_questions_say_why_they_are_refused() {
    // (question, answer for set, refusal of get, refusal of set): None where the other test
    // checks that it succeeds
    let cases = [
        (
            "Driver held",
            "First",
            Some(DRIVER_HELD),
            Some(NO_MOUNTED_ESP),
        ),
        (
            "No value source",
            "1",
            Some(NO_VALUE_SOURCE),
            Some(NO_VALUE_SOURCE),
        ),
        ("Write only", "1", Some(NO_READ), None),
        ("Read only", "1", None, Some(NO_WRITE)),
        (
            "Unevaluated read",
            "1",
            Some(UNEVALUATED_READ),
            Some(NO_WRITE),
        ),
    ];
    for (question, answer, get_refusal, set_refusal) in cases {
        for prefix in PREFIXES {
            if let Some(refusal) = get_refusal {
                assert_eq!(
                    get(prefix, question),
                    format!("<ValueUnavailable: {refusal}>"),
                    "get {prefix:?} {question}"
                );
            }
            if let Some(refusal) = set_refusal {
                assert_eq!(
                    refuse(prefix, question, answer),
                    format!("cannot set question {question:?}: {refusal}"),
                    "set {prefix:?} {question}"
                );
            }
        }
    }
}

/// list-questions never calls a driver: it lists the question that its driver holds with the
/// refusal of get, as the others without a VarStore.
#[test]
fn list_questions_shows_storageless_questions_with_their_refusals() {
    let questions: Vec<Question> = json(&["hii", "list-questions", "--json"]);
    let cases = [
        ("Driver held", DRIVER_HELD),
        ("No value source", NO_VALUE_SOURCE),
        ("Write only", NO_READ),
        ("Unevaluated read", UNEVALUATED_READ),
    ];
    for (name, refusal) in cases {
        let listed: Vec<&str> = questions
            .iter()
            .filter(|question| question.name == name)
            .map(|question| question.answer.as_str())
            .collect();
        assert_eq!(listed, [format!("<ValueUnavailable: {refusal}>")], "{name}");
    }
}
