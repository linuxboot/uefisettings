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

//! A guest whose firmware runs EDK2's DriverSample, with its variable readable at runtime,
//! and publish-hiidb from `Driver####` load options before Linux starts. These checks only
//! read, so the answers are DriverSample's defaults.

use std::collections::BTreeMap;
use std::fs;

use serde::Deserialize;
use uefisettings_qemu_guest::driver_sample::CHECK_BOX;
use uefisettings_qemu_guest::driver_sample::CHECK_BOX_OFFSET;
use uefisettings_qemu_guest::driver_sample::NUMERIC;
use uefisettings_qemu_guest::driver_sample::NUMERIC_OFFSET;
use uefisettings_qemu_guest::driver_sample::ONE_OF;
use uefisettings_qemu_guest::driver_sample::ONE_OF_OFFSET;
use uefisettings_qemu_guest::driver_sample::SERIAL_PORT;
use uefisettings_qemu_guest::driver_sample::SERIAL_PORT_OFFSET;
use uefisettings_qemu_guest::json;
use uefisettings_qemu_guest::read_published_database;
use uefisettings_qemu_guest::single_response;
use uefisettings_qemu_guest::uefisettings;
use uefisettings_qemu_guest::variable_data;
use uefisettings_qemu_guest::MachineInfo;
use uefisettings_qemu_guest::Question;
use uefisettings_qemu_guest::Responses;
use uefisettings_qemu_guest::BACKEND_HII;
use uefisettings_qemu_guest::DRIVER_SAMPLE_VARIABLE;
use uefisettings_qemu_guest::UNAVAILABLE;

/// The questions of the tests with their default answers and options, and how many times
/// the HII database lists each.
const DEFAULTS: [(&str, &str, &[&str], usize); 4] = [
    (
        ONE_OF,
        "My one-of text #2",
        &[
            "My one-of text #1",
            "My one-of text #2",
            "My one-of text #3",
        ],
        1,
    ),
    (CHECK_BOX, "1", &[], 2),
    (NUMERIC, "18", &[], 1),
    (SERIAL_PORT, "3F8", &["3F8", "2F8", "3E8", "2E8"], 1),
];

/// Questions whose values the HII backend cannot read from Linux: on DriverSample's
/// variable without runtime access, on its name/value store, and on the RAM disk form of
/// OVMF, which has no store.
const UNAVAILABLE_QUESTIONS: [&str; 4] = [
    "How tall are you? (Hex)",
    "NameValueVar0",
    "Disk Memory Type:",
    "Size (Hex):",
];

/// One string package of `hii list-strings --json` (`HiiStringsPackage`).
#[derive(Debug, Deserialize)]
struct StringPackage {
    string_package: BTreeMap<String, String>,
}

fn question(name: &str, answer: &str, options: &[&str]) -> Question {
    Question {
        name: name.to_owned(),
        answer: answer.to_owned(),
        options: options.iter().map(|&option| option.to_owned()).collect(),
    }
}

#[test]
fn identify_detects_the_hii_backend() {
    let machine: MachineInfo = json(&["identify", "--json"]);
    assert_eq!(machine.backend, [BACKEND_HII]);
}

#[test]
fn driver_sample_variable_holds_the_defaults() {
    let data = variable_data(DRIVER_SAMPLE_VARIABLE).expect("the variable does not exist");
    assert_eq!(data[ONE_OF_OFFSET], 1);
    assert_eq!(data[CHECK_BOX_OFFSET], 1);
    assert_eq!(data[NUMERIC_OFFSET], 18);
    assert_eq!(
        data[SERIAL_PORT_OFFSET..SERIAL_PORT_OFFSET + 2],
        0x3f8u16.to_le_bytes()
    );
}

#[test]
fn extract_db_copies_the_published_database() {
    let published = read_published_database()
        .unwrap_or_else(|error| panic!("cannot read the published database: {error}"));
    let path = "/tmp/hiidb.bin";
    let output = uefisettings(&["hii", "extract-db", path]);
    assert_eq!(output.code, Some(0), "{output:#?}");
    let extracted = fs::read(path).unwrap_or_else(|error| panic!("cannot read {path}: {error}"));
    assert!(
        extracted == published,
        "{path} differs from the published database"
    );
}

#[test]
fn list_questions_lists_the_defaults() {
    let questions: Vec<Question> = json(&["hii", "list-questions", "--json"]);
    for (name, answer, options, times) in DEFAULTS {
        let expected = question(name, answer, options);
        let listed = questions
            .iter()
            .filter(|&question| question == &expected)
            .count();
        assert_eq!(listed, times, "{expected:?} in {questions:#?}");
    }
}

#[test]
fn list_questions_reports_unreadable_questions_as_unavailable() {
    let questions: Vec<Question> = json(&["hii", "list-questions", "--json"]);
    for name in UNAVAILABLE_QUESTIONS {
        let listed: Vec<&Question> = questions
            .iter()
            .filter(|question| question.name == name)
            .collect();
        assert!(
            matches!(listed[..], [question] if question.answer.starts_with(UNAVAILABLE)),
            "{name}: {listed:#?}"
        );
    }
}

#[test]
fn list_strings_lists_the_prompts() {
    let packages: Vec<StringPackage> = json(&["hii", "list-strings", "--json"]);
    let strings: Vec<&str> = packages
        .iter()
        .flat_map(|package| package.string_package.values())
        .map(String::as_str)
        .collect();
    for (name, ..) in DEFAULTS {
        assert!(strings.contains(&name), "{name:?} is not listed");
    }
}

#[test]
fn show_ifr_shows_the_formsets() {
    let output = uefisettings(&["hii", "show-ifr"]);
    assert_eq!(output.code, Some(0), "{output:#?}");
    let formsets: Vec<&str> = output
        .stdout
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("OpCode: FormSet - "))
        .filter_map(|line| line.split_once(" - GUID ").map(|(name, _)| name))
        .collect();
    // DriverSample's two formsets and one of OVMF.
    for name in [
        "Browser Testcase Engine",
        "ABC Information Sample",
        "RAM Disk Configuration",
    ] {
        assert!(formsets.contains(&name), "{name:?} is not in {formsets:?}");
    }
}

#[test]
fn show_translations_prints_the_spellings_database() {
    let translations: BTreeMap<String, serde_json::Value> = json(&["show-translations", "--json"]);
    assert!(translations.contains_key("TPM State"), "{translations:#?}");
}

#[test]
fn get_returns_the_defaults() {
    for (name, answer, options, _) in DEFAULTS {
        let (got, _) = single_response(&["hii", "get", name, "--json"], BACKEND_HII);
        assert_eq!(got, question(name, answer, options));
    }
}

#[test]
fn get_reports_unreadable_questions_as_unavailable() {
    for name in UNAVAILABLE_QUESTIONS {
        let (got, _) = single_response(&["hii", "get", name, "--json"], BACKEND_HII);
        assert!(got.answer.starts_with(UNAVAILABLE), "{got:#?}");
    }
}

#[test]
fn get_of_an_unknown_question_returns_no_answers() {
    let Responses { responses } = json(&["hii", "get", "No Such Question", "--json"]);
    assert!(responses.is_empty(), "{responses:#?}");
}
