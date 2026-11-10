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

//! The JSON that --json prints for each thrift type, simplejson_protocol's bytes, against
//! tests/fixtures/thrift-json; UEFISETTINGS_BLESS=1 rewrites the fixtures.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::hash::Hash;

use fbthrift::simplejson_protocol;
use fbthrift::simplejson_protocol::Serializable;
use uefisettings_backend_thrift::Backend;
use uefisettings_backend_thrift::Error;
use uefisettings_backend_thrift::ErrorCause;
use uefisettings_backend_thrift::FirmwareAttribute;
use uefisettings_backend_thrift::FirmwareAttributeAuthentication;
use uefisettings_backend_thrift::FirmwareAttributeAuthenticationList;
use uefisettings_backend_thrift::FirmwareAttributeIntegerBounds;
use uefisettings_backend_thrift::FirmwareAttributeKind;
use uefisettings_backend_thrift::FirmwareAttributeList;
use uefisettings_backend_thrift::FirmwareAttributeLoadError;
use uefisettings_backend_thrift::FirmwareAttributePendingReboot;
use uefisettings_backend_thrift::FirmwareAttributePendingRebootList;
use uefisettings_backend_thrift::FirmwareAttributeSetResult;
use uefisettings_backend_thrift::FirmwareAttributeStringBounds;
use uefisettings_backend_thrift::FirmwareAttributeValue;
use uefisettings_backend_thrift::GetResponse;
use uefisettings_backend_thrift::GetResponseList;
use uefisettings_backend_thrift::HiiDatabase;
use uefisettings_backend_thrift::HiiShowIfrResponse;
use uefisettings_backend_thrift::HiiStringsPackage;
use uefisettings_backend_thrift::IloAttributes;
use uefisettings_backend_thrift::MachineInfo;
use uefisettings_backend_thrift::Question;
use uefisettings_backend_thrift::QuestionDefault;
use uefisettings_backend_thrift::QuestionKeyword;
use uefisettings_backend_thrift::SetResponse;
use uefisettings_backend_thrift::SetResponseList;
use uefisettings_spellings_db_thrift::consts::translation_db;

mod golden;

/// The golden JSON files.
const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/thrift-json");
/// Quotes, a backslash, control characters, DEL, non-ASCII and HTML in one string.
const TRICKY: &str = "q\"b\\n\nt\tc\u{1}d\u{7f} é 日本 😀 </script>";

fn json(value: &impl Serializable) -> Vec<u8> {
    simplejson_protocol::serialize(value).to_vec()
}

fn question() -> Question {
    Question {
        name: TRICKY.to_owned(),
        answer: "Enabled <grayed-out>".to_owned(),
        options: vec!["Enabled".to_owned(), String::new(), TRICKY.to_owned()],
        help: String::new(),
        ..Default::default()
    }
}

/// The JSON of each type the CLI printed before the firmware-attributes types, from the values
/// that showed fbthrift-git 0.0.8 printing the bytes of fbthrift 0.0.3: each file was written
/// before those types joined the IDL.
fn existing_types() -> Vec<(&'static str, Vec<u8>)> {
    let machine = MachineInfo {
        backend: BTreeSet::from([Backend::Ilo, Backend::Hii, Backend::Unknown]),
        bios_vendor: "American Megatrends International, LLC.".to_owned(),
        bios_version: TRICKY.to_owned(),
        ..Default::default()
    };
    let get = GetResponseList {
        responses: vec![
            GetResponse {
                selector: "pkglist".to_owned(),
                backend: Backend::Hii,
                question: question(),
                is_translated: true,
                ..Default::default()
            },
            GetResponse {
                backend: Backend::Ilo,
                ..Default::default()
            },
        ],
        ..Default::default()
    };
    let set = SetResponseList {
        responses: vec![SetResponse {
            selector: "bios".to_owned(),
            backend: Backend::Ilo,
            question: question(),
            modified: true,
            is_translated: false,
            ..Default::default()
        }],
        ..Default::default()
    };
    let error = Error {
        error_message: TRICKY.to_owned(),
        ..Default::default()
    };
    let ilo = vec![IloAttributes {
        selector: "bios".to_owned(),
        attributes: BTreeMap::from([
            ("B".to_owned(), "x".to_owned()),
            ("A".to_owned(), TRICKY.to_owned()),
        ]),
        ..Default::default()
    }];
    let strings = vec![HiiStringsPackage {
        package_list: "guid".to_owned(),
        string_package: BTreeMap::from([
            (-1, "neg".to_owned()),
            (0, String::new()),
            (65535, TRICKY.to_owned()),
        ]),
        language: "x-UEFI-ns".to_owned(),
        ..Default::default()
    }];
    let ifr = HiiShowIfrResponse {
        readable_representation: TRICKY.to_owned(),
        ..Default::default()
    };
    let db = HiiDatabase {
        db: vec![0, 1, 0x7F, 0x80, 0xFF, b'"', b'\\'],
        ..Default::default()
    };

    vec![
        ("machine-info.json", json(&machine)),
        ("question.json", json(&question())),
        (
            "questions.json",
            json(&vec![question(), Question::default()]),
        ),
        ("get-response-list.json", json(&get)),
        ("set-response-list.json", json(&set)),
        (
            "set-response-list-default.json",
            json(&SetResponseList::default()),
        ),
        ("error.json", json(&error)),
        ("ilo-attributes.json", json(&ilo)),
        ("hii-strings-packages.json", json(&strings)),
        ("hii-show-ifr-response.json", json(&ifr)),
        ("hii-database.json", json(&db)),
        ("translation-db.json", json(&*translation_db)),
    ]
}

#[test]
fn existing_types_print_their_golden_json() {
    for (name, output) in existing_types() {
        golden::assert_golden(FIXTURES, name, &output);
    }
}

// Error stays Eq, Ord and Hash: its clear_error is an ErrorCause, which holds no Error and has
// rust.ord.
const _: () = {
    const fn eq_ord_hash<T: Eq + Ord + Hash>() {}
    eq_ord_hash::<Error>();
    eq_ord_hash::<ErrorCause>();
};

fn error_cause() -> ErrorCause {
    ErrorCause {
        error_message: "write current_password: Operation not permitted".to_owned(),
        kind: Some("PermissionDenied".to_owned()),
        os_errno: Some(1),
        ..Default::default()
    }
}

fn io_error(os_errno: i32) -> Error {
    Error {
        error_message: TRICKY.to_owned(),
        kind: Some("Io".to_owned()),
        os_errno: Some(os_errno),
        ..Default::default()
    }
}

fn full_error() -> Error {
    Error {
        error_message: "write current_value: Input/output error".to_owned(),
        kind: Some("WriteFailed".to_owned()),
        os_errno: Some(5),
        clear_error: Some(error_cause()),
        ..Default::default()
    }
}

fn full_integer_bounds() -> FirmwareAttributeIntegerBounds {
    FirmwareAttributeIntegerBounds {
        min_value: Some(-1),
        max_value: Some(23),
        scalar_increment: Some(1),
        ..Default::default()
    }
}

fn full_string_bounds() -> FirmwareAttributeStringBounds {
    FirmwareAttributeStringBounds {
        min_length: Some(1),
        max_length: Some(64),
        possible_values: Some(vec!["a".to_owned(), TRICKY.to_owned()]),
        ..Default::default()
    }
}

/// An attribute of each kind, with every optional field set in the first.
fn attributes() -> Vec<FirmwareAttribute> {
    let attribute = |device: &str, name: &str, kind, current_value| FirmwareAttribute {
        device: device.to_owned(),
        name: name.to_owned(),
        kind,
        current_value,
        ..Default::default()
    };
    let value = |text: &str| FirmwareAttributeValue::value(text.to_owned());
    vec![
        FirmwareAttribute {
            default_value: Some("0".to_owned()),
            display_name: Some("Auto On Hour".to_owned()),
            display_name_language_code: Some("en_US.UTF-8".to_owned()),
            not_writable_reason: Some("current_value is read-only".to_owned()),
            dell_modifier: Some("[SuppressIfNot:AutoOn=SelectDays]".to_owned()),
            dell_value_modifier: Some("0[ForceIf:AutoOn=Disabled]".to_owned()),
            ..attribute(
                "dell-wmi-sysman",
                "AutoOnHr",
                FirmwareAttributeKind::integer(full_integer_bounds()),
                value("7"),
            )
        },
        attribute(
            "dell-wmi-sysman",
            "Count",
            FirmwareAttributeKind::integer(FirmwareAttributeIntegerBounds::default()),
            FirmwareAttributeValue::read_error(io_error(21)),
        ),
        attribute(
            "thinklmi",
            "WakeOnLAN",
            FirmwareAttributeKind::enumeration(vec!["Disable".to_owned(), "Enable".to_owned()]),
            value("Enable"),
        ),
        attribute(
            "dell-wmi-sysman",
            "AssetTag",
            FirmwareAttributeKind::string_value(full_string_bounds()),
            value(TRICKY),
        ),
        attribute(
            "hp-bioscfg",
            "Boot Order",
            FirmwareAttributeKind::ordered_list(vec!["HDD".to_owned(), "USB".to_owned()]),
            value("HDD,USB"),
        ),
        attribute(
            "thinklmi",
            "Fancy",
            FirmwareAttributeKind::other("fancy".to_owned()),
            value("x"),
        ),
    ]
}

/// A device that failed to list, and an attribute of another that failed to load.
fn load_errors() -> Vec<FirmwareAttributeLoadError> {
    vec![
        FirmwareAttributeLoadError {
            device: "dell-wmi-sysman".to_owned(),
            name: Some("Broken".to_owned()),
            error: Error {
                kind: Some("Parse".to_owned()),
                ..Default::default()
            },
            ..Default::default()
        },
        FirmwareAttributeLoadError {
            device: "loop".to_owned(),
            error: io_error(40),
            ..Default::default()
        },
    ]
}

fn full_set_result() -> FirmwareAttributeSetResult {
    FirmwareAttributeSetResult {
        device: "thinklmi".to_owned(),
        name: "WakeOnLAN".to_owned(),
        status: "read_back_differs".to_owned(),
        read_back: Some("Disable".to_owned()),
        pending_reboot: Some(true),
        read_back_error: Some(io_error(5)),
        clear_error: Some(full_error()),
        ..Default::default()
    }
}

fn full_authentication() -> FirmwareAttributeAuthentication {
    FirmwareAttributeAuthentication {
        device: "thinklmi".to_owned(),
        name: "Admin".to_owned(),
        role: "bios-admin".to_owned(),
        is_enabled: true,
        mechanism: Some("password".to_owned()),
        min_password_length: Some(2),
        max_password_length: Some(64),
        ..Default::default()
    }
}

fn pending_reboots() -> Vec<FirmwareAttributePendingReboot> {
    let device = |name: &str| FirmwareAttributePendingReboot {
        device: name.to_owned(),
        ..Default::default()
    };
    vec![
        device("dell-wmi-sysman"),
        FirmwareAttributePendingReboot {
            pending_reboot: Some(true),
            ..device("hp-bioscfg")
        },
        FirmwareAttributePendingReboot {
            read_error: Some(io_error(40)),
            ..device("loop")
        },
        FirmwareAttributePendingReboot {
            pending_reboot: Some(false),
            ..device("thinklmi")
        },
    ]
}

/// The JSON of each type that the firmware-attributes commands print, and of the fields that
/// Error, SetResponse and Backend gained for them.
fn new_types() -> Vec<(&'static str, Vec<u8>)> {
    let machine = MachineInfo {
        backend: BTreeSet::from([Backend::Hii, Backend::FirmwareAttributes]),
        ..Default::default()
    };
    let set = SetResponseList {
        responses: vec![SetResponse {
            selector: "thinklmi".to_owned(),
            backend: Backend::FirmwareAttributes,
            question: Question {
                name: "WakeOnLAN".to_owned(),
                answer: "Disable".to_owned(),
                ..Default::default()
            },
            modified: true,
            firmware_attribute_set_result: Some(full_set_result()),
            ..Default::default()
        }],
        ..Default::default()
    };
    let list = FirmwareAttributeList {
        attributes: attributes(),
        errors: load_errors(),
        ..Default::default()
    };
    let authentications = FirmwareAttributeAuthenticationList {
        authentications: vec![
            full_authentication(),
            FirmwareAttributeAuthentication {
                device: "thinklmi".to_owned(),
                name: "Power-on".to_owned(),
                role: "power-on".to_owned(),
                ..Default::default()
            },
        ],
        errors: load_errors(),
        ..Default::default()
    };
    let pending = FirmwareAttributePendingRebootList {
        devices: pending_reboots(),
        ..Default::default()
    };

    vec![
        ("error-with-cause.json", json(&full_error())),
        ("machine-info-firmware-attributes.json", json(&machine)),
        ("set-response-list-firmware-attributes.json", json(&set)),
        ("firmware-attribute-list.json", json(&list)),
        (
            "firmware-attribute-authentication-list.json",
            json(&authentications),
        ),
        (
            "firmware-attribute-pending-reboot-list.json",
            json(&pending),
        ),
    ]
}

#[test]
fn new_types_print_their_golden_json() {
    for (name, output) in new_types() {
        golden::assert_golden(FIXTURES, name, &output);
    }
}

/// question() with the flags of a READ_ONLY question that needs a reset.
fn flagged_question() -> Question {
    Question {
        flags: Some(vec!["READ_ONLY".to_owned(), "RESET_REQUIRED".to_owned()]),
        ..question()
    }
}

/// A default of DefaultId 0x0001 whose FormSet declares no DEFAULTSTORE for it.
fn undeclared_default() -> QuestionDefault {
    QuestionDefault {
        default_id: Some(1),
        value: Some(TRICKY.to_owned()),
        ..Default::default()
    }
}

/// A default of the standard default store, which the FormSet declares.
fn standard_default() -> QuestionDefault {
    QuestionDefault {
        default_id: Some(0),
        default_store_name: Some("Standard Default".to_owned()),
        value: Some("Enabled".to_owned()),
        ..Default::default()
    }
}

/// question() with the defaults of the standard and the manufacturing default stores.
fn defaulted_question() -> Question {
    Question {
        defaults: Some(vec![standard_default(), undeclared_default()]),
        ..question()
    }
}

/// question() with a QuestionId above 0x7FFF, its FormSet's GUID and keywords in two namespaces.
fn identified_question() -> Question {
    Question {
        question_id: Some(0x8001),
        form_set_guid: Some("8C78A505-BAA0-4C4A-869F-000000000800".to_owned()),
        keywords: Some(vec![
            QuestionKeyword {
                namespace_id: "x-UEFI-ns".to_owned(),
                keyword: "Keyword:5".to_owned(),
                ..Default::default()
            },
            QuestionKeyword {
                namespace_id: "x-i-UEFI".to_owned(),
                keyword: TRICKY.to_owned(),
                ..Default::default()
            },
        ]),
        ..question()
    }
}

/// question() as an ORDERED_LIST of two items.
fn listed_question() -> Question {
    Question {
        items: Some(vec!["Enabled".to_owned(), TRICKY.to_owned()]),
        ..question()
    }
}

/// The JSON of the optional fields that Question gained for hii questions.
fn question_fields() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("question-flags.json", json(&flagged_question())),
        ("question-defaults.json", json(&defaulted_question())),
        ("question-identity.json", json(&identified_question())),
        ("question-items.json", json(&listed_question())),
    ]
}

#[test]
fn question_fields_print_their_golden_json() {
    for (name, output) in question_fields() {
        golden::assert_golden(FIXTURES, name, &output);
    }
}

/// The keys of the JSON object `json`.
fn keys(json: &[u8]) -> BTreeSet<String> {
    let value: serde_json::Value = serde_json::from_slice(json).expect("parse JSON");
    let serde_json::Value::Object(object) = value else {
        panic!("not a JSON object: {value}");
    };
    object.into_iter().map(|(key, _)| key).collect()
}

/// Asserts that `unset`, a `type_name` with its optional `fields` unset, prints none of them, and
/// that `set`, one with them set, prints every one of them besides the keys of `unset`.
fn assert_optionals(
    type_name: &str,
    unset: &impl Serializable,
    set: &impl Serializable,
    fields: &[&str],
) {
    let (unset, set) = (keys(&json(unset)), keys(&json(set)));
    let fields: BTreeSet<String> = fields.iter().map(|field| (*field).to_owned()).collect();

    assert_eq!(
        unset.intersection(&fields).collect::<Vec<_>>(),
        Vec::<&String>::new(),
        "{type_name}: unset optionals printed"
    );
    assert_eq!(
        set,
        unset.union(&fields).cloned().collect(),
        "{type_name}: the set value prints the unset one's keys and every optional"
    );
}

#[test]
fn unset_optionals_are_omitted_and_set_ones_present() {
    assert_optionals(
        "Error",
        &Error::default(),
        &full_error(),
        &["kind", "os_errno", "clear_error"],
    );
    assert_optionals(
        "ErrorCause",
        &ErrorCause::default(),
        &error_cause(),
        &["kind", "os_errno"],
    );
    assert_optionals("Question", &question(), &flagged_question(), &["flags"]);
    assert_optionals(
        "Question",
        &question(),
        &defaulted_question(),
        &["defaults"],
    );
    assert_optionals(
        "Question",
        &question(),
        &identified_question(),
        &["question_id", "form_set_guid", "keywords"],
    );
    assert_optionals("Question", &question(), &listed_question(), &["items"]);
    assert_optionals(
        "QuestionDefault",
        &QuestionDefault::default(),
        &standard_default(),
        &["default_id", "default_store_name", "value"],
    );
    assert_optionals(
        "SetResponse",
        &SetResponse::default(),
        &SetResponse {
            firmware_attribute_set_result: Some(full_set_result()),
            ..Default::default()
        },
        &["firmware_attribute_set_result"],
    );
    assert_optionals(
        "FirmwareAttributeIntegerBounds",
        &FirmwareAttributeIntegerBounds::default(),
        &full_integer_bounds(),
        &["min_value", "max_value", "scalar_increment"],
    );
    assert_optionals(
        "FirmwareAttributeStringBounds",
        &FirmwareAttributeStringBounds::default(),
        &full_string_bounds(),
        &["min_length", "max_length", "possible_values"],
    );
    assert_optionals(
        "FirmwareAttribute",
        &attributes()[2],
        &attributes()[0],
        &[
            "default_value",
            "display_name",
            "display_name_language_code",
            "not_writable_reason",
            "dell_modifier",
            "dell_value_modifier",
        ],
    );
    assert_optionals(
        "FirmwareAttributeLoadError",
        &load_errors()[1],
        &load_errors()[0],
        &["name"],
    );
    assert_optionals(
        "FirmwareAttributeSetResult",
        &FirmwareAttributeSetResult::default(),
        &full_set_result(),
        &[
            "read_back",
            "pending_reboot",
            "read_back_error",
            "clear_error",
        ],
    );
    assert_optionals(
        "FirmwareAttributeAuthentication",
        &FirmwareAttributeAuthentication::default(),
        &full_authentication(),
        &["mechanism", "min_password_length", "max_password_length"],
    );
    assert_optionals(
        "FirmwareAttributePendingReboot",
        &pending_reboots()[0],
        &FirmwareAttributePendingReboot {
            pending_reboot: Some(true),
            read_error: Some(io_error(40)),
            ..pending_reboots()[0].clone()
        },
        &["pending_reboot", "read_error"],
    );
}
