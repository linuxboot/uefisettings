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

use std::ffi::OsStr;
use std::path::Path;

use uefisettings_qemu_guest::changed_bytes;
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
use uefisettings_qemu_guest::json_error;
use uefisettings_qemu_guest::single_response;
use uefisettings_qemu_guest::variable_bytes;
use uefisettings_qemu_guest::variable_data;
use uefisettings_qemu_guest::ErrorObject;
use uefisettings_qemu_guest::BACKEND_HII;
use uefisettings_qemu_guest::DRIVER_SAMPLE_VARIABLE;
use uefisettings_qemu_guest::MY_EFI_VAR;
use uefisettings_qemu_guest::MY_EFI_VAR_QUESTION;
use uefisettings_qemu_guest::PREFIXES;

#[track_caller]
fn driver_sample_data() -> Vec<u8> {
    variable_data(DRIVER_SAMPLE_VARIABLE).expect("the variable does not exist")
}

/// Sets `question` to `answer` with `set` and checks that `get` returns it, both after
/// `prefix`: `["hii"]` for the HII commands, `[]` for the generic ones. Returns the bytes of
/// the data of the efivarfs variable `variable` that changed.
/// `(flags, annotation)`: the flags of both commands, and the annotation that ends both answers.
#[track_caller]
fn set(
    variable: &str,
    prefix: &[&str],
    question: &str,
    answer: &str,
    (flags, annotation): (&[&str], &str),
) -> Vec<(usize, u8)> {
    let data = || variable_data(variable).unwrap_or_else(|| panic!("{variable} does not exist"));
    let before = data();
    let answered = format!("{answer}{annotation}");
    let (set, modified) = single_response(
        &[prefix, &["set", question, answer, "--json"], flags].concat(),
        BACKEND_HII,
    );
    assert_eq!(
        (set.answer.as_str(), modified),
        (answered.as_str(), true),
        "{set:#?}"
    );
    let (got, _) = single_response(
        &[prefix, &["get", question, "--json"], flags].concat(),
        BACKEND_HII,
    );
    assert_eq!(got.answer, answered, "{got:#?}");
    changed_bytes(&before, &data())
}

/// What `set` takes and answers for a question that no condition hides.
const SELECTABLE: (&[&str], &str) = (&[], "");

/// Checks that `set` after `prefix` refuses `answer` for `question` without changing the variable.
/// `flags` go to `set`.
/// Returns the error that `set` printed.
#[track_caller]
fn refuse(prefix: &[&str], question: &str, answer: &str, flags: &[&str]) -> ErrorObject {
    let before = driver_sample_data();
    let error = json_error(&[prefix, &["set", question, answer, "--json"], flags].concat());
    assert_eq!(
        changed_bytes(&before, &driver_sample_data()),
        [],
        "{prefix:?} {question} = {answer} {flags:?}"
    );
    error
}

#[test]
fn set_one_of_is_stored() {
    let changed = set(
        DRIVER_SAMPLE_VARIABLE,
        &["hii"],
        ONE_OF,
        "My one-of text #3",
        SELECTABLE,
    );
    assert_eq!(changed, [(ONE_OF_OFFSET, 3)]);
}

#[test]
fn set_bit_field_numeric_is_refused() {
    // The 12-bit BitNumeric field of DriverSample's variable; set picks it, as the
    // "BIT numeric" on MyEfiBitVar is grayed out unless EfiBitGrayoutTest, which Linux
    // cannot read, is nonzero.
    for prefix in PREFIXES {
        assert_eq!(
            refuse(prefix, "BIT numeric", "20", &[]).error_message,
            "setting EDKII bit-field values is not supported",
            "{prefix:?}"
        );
    }
}

#[test]
fn set_one_of_to_an_unknown_option_is_refused() {
    refuse(&["hii"], ONE_OF, "Bogus", &[]);
}

#[test]
fn generic_set_check_box_is_stored() {
    let changed = set(DRIVER_SAMPLE_VARIABLE, &[], CHECK_BOX, "0", SELECTABLE);
    assert_eq!(changed, [(CHECK_BOX_OFFSET, 0)]);
}

#[test]
fn set_check_box_to_2_is_refused() {
    refuse(&["hii"], CHECK_BOX, "2", &[]);
}

/// set writes a question on MyEfiVar, which Vfr.vfr declares boot-service-only, by the
/// variable's own attributes, which have runtime access here, and keeps them.
#[test]
fn set_question_on_a_runtime_variable_of_a_boot_service_only_form_is_stored() {
    let changed = set(MY_EFI_VAR, &["hii"], MY_EFI_VAR_QUESTION, "32", SELECTABLE);

    assert_eq!(changed, [(0, 0x20)], "{MY_EFI_VAR}: changed bytes");
    assert_eq!(
        variable_bytes(MY_EFI_VAR).expect("MyEfiVar exists"),
        [7, 0, 0, 0, 0x20, 1, 0, 0, 0, 0, 0x12, 0],
        "{MY_EFI_VAR}: attributes and data"
    );
}

/// set refuses a question on MyEfiUnionVar, which DriverSample creates without runtime
/// access, naming the boot-service-only declaration of its form, and writes nothing.
#[test]
fn set_question_on_a_missing_variable_of_a_boot_service_only_form_is_refused() {
    const QUESTION: &str = "UNION EfiVarStore byte numeric";
    const VARIABLE: &str =
        "/sys/firmware/efi/efivars/MyEfiUnionVar-a04a27f4-df00-4d42-b552-39511302113d";
    let file_name = Path::new(VARIABLE)
        .file_name()
        .and_then(OsStr::to_str)
        .expect("file name of the variable");

    let error = refuse(&["hii"], QUESTION, "1", &[]);

    assert_eq!(
        error.error_message,
        format!(
            "EFI variable {file_name} is not present at OS runtime: efivarfs does not list it, \
             and its form declares it boot-service-only (no EFI_VARIABLE_RUNTIME_ACCESS)"
        ),
        "{QUESTION}"
    );
    // and wrote nothing: the variable is still invisible to Linux
    assert_eq!(variable_data(VARIABLE), None, "{VARIABLE} is visible");
}

#[test]
fn set_numeric_to_its_maximum_is_stored() {
    let changed = set(DRIVER_SAMPLE_VARIABLE, &["hii"], NUMERIC, "243", SELECTABLE);
    assert_eq!(changed, [(NUMERIC_OFFSET, 243)]);
}

#[test]
fn set_numeric_above_its_maximum_is_refused() {
    refuse(&["hii"], NUMERIC, "244", &[]);
}

#[test]
fn set_16_bit_one_of_is_stored() {
    // The only 16-bit question on a variable that Linux can write. The form grays it out
    // and hides it, so set selects it only with INCLUDE_SUPPRESSED. 0x3F8 becomes 0x2F8:
    // only the high byte changes.
    let changed = set(
        DRIVER_SAMPLE_VARIABLE,
        &["hii"],
        SERIAL_PORT,
        "2F8",
        (&INCLUDE_SUPPRESSED, " <suppressed>"),
    );
    assert_eq!(changed, [(SERIAL_PORT_OFFSET + 1, 0x02)]);
}

#[test]
fn set_of_a_suppressed_question_is_refused_unless_suppressed_is_included() {
    // edk2-stable202608 SetupBrowserDxe/Expression.c EvaluateExpressionList ranks SuppressIf
    // above GrayOutIf, so including grayed-out questions is not enough for this one, which is
    // both.
    let excluded = format!(
        "question {SERIAL_PORT:?} is suppressed; also include suppressed questions to select it"
    );
    for flags in [&[][..], &INCLUDE_GRAYED_OUT] {
        assert_eq!(
            refuse(&["hii"], SERIAL_PORT, "2E8", flags).error_message,
            excluded,
            "{flags:?}"
        );
    }
}

#[test]
fn set_of_a_question_that_may_be_grayed_out_is_refused_unless_grayed_out_is_included() {
    let undetermined = format!(
        "cannot tell whether question {MATCH2:?} is grayed-out: {MATCH2_REASON}; also include \
         grayed-out questions to select it regardless"
    );
    assert_eq!(
        refuse(&["hii"], MATCH2, "5", &[]).error_message,
        undetermined,
        "{MATCH2} without flags"
    );

    let annotation = format!(" <selectable or grayed-out: {MATCH2_REASON}>");
    let changed = set(
        DRIVER_SAMPLE_VARIABLE,
        &["hii"],
        MATCH2,
        "5",
        (&INCLUDE_GRAYED_OUT, &annotation),
    );
    assert_eq!(
        changed,
        [(MATCH2_OFFSET, 5)],
        "{MATCH2} {INCLUDE_GRAYED_OUT:?}"
    );
}

#[test]
fn set_of_an_unknown_question_is_refused() {
    for prefix in PREFIXES {
        assert_eq!(
            refuse(prefix, "No Such Question", "1", &[]).error_message,
            "no question \"No Such Question\" in the HiiDB",
            "{prefix:?}"
        );
    }
}

#[test]
fn set_of_a_question_without_a_varstore_is_refused() {
    let cases = [
        (
            "NameValueVar0",
            "1",
            "HII name/value varstore requires EFI_HII_CONFIG_ACCESS_PROTOCOL",
        ),
        (
            "Disk Memory Type:",
            "Reserved",
            "question is callback-driven or temporary and has no varstore",
        ),
    ];
    for (question, answer, reason) in cases {
        for prefix in PREFIXES {
            assert_eq!(
                refuse(prefix, question, answer, &[]).error_message,
                format!("cannot set question {question:?}: {reason}"),
                "{prefix:?} {question}"
            );
        }
    }
}

/// set, through hii set and set, refuses --access-level on a HiiDB that declares no SystemAccess
/// VarStore, and writes nothing.
#[test]
fn set_with_an_access_level_is_refused_without_system_access() {
    for prefix in PREFIXES {
        for level in ["administrator", "user"] {
            assert_eq!(
                refuse(
                    prefix,
                    ONE_OF,
                    "My one-of text #3",
                    &["--access-level", level]
                )
                .error_message,
                "--access-level applies to AMI firmware whose HiiDB declares the SystemAccess \
                 VarStore; this HiiDB declares none",
                "{prefix:?} {level}"
            );
        }
    }
}
