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
use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;

use serde::Deserialize;
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
use uefisettings_qemu_guest::json;
use uefisettings_qemu_guest::json_error;
use uefisettings_qemu_guest::published_database;
use uefisettings_qemu_guest::read_dev_mem_byte;
use uefisettings_qemu_guest::single_response;
use uefisettings_qemu_guest::uefisettings;
use uefisettings_qemu_guest::variable_data;
use uefisettings_qemu_guest::MachineInfo;
use uefisettings_qemu_guest::Question;
use uefisettings_qemu_guest::Responses;
use uefisettings_qemu_guest::BACKEND_HII;
use uefisettings_qemu_guest::DRIVER_SAMPLE_VARIABLE;
use uefisettings_qemu_guest::EFAULT;
use uefisettings_qemu_guest::EFIVARFS_HEADER_SIZE;
use uefisettings_qemu_guest::UNAVAILABLE;

/// Linux's SIGBUS on arm64 (`include/uapi/asm-generic/signal.h`).
#[cfg(target_arch = "aarch64")]
const SIGBUS: i32 = 7;

/// A question of [`DEFAULTS`].
struct DefaultQuestion {
    name: &'static str,
    options: &'static [&'static str],
    /// Without INCLUDE_SUPPRESSED
    answers: &'static [&'static str],
    /// With INCLUDE_SUPPRESSED; `get` with the flag returns the first
    suppressed_answers: &'static [&'static str],
}

/// The questions of the tests with their default answers and options, and how many times
/// the HII database lists each.
const DEFAULTS: [DefaultQuestion; 4] = [
    DefaultQuestion {
        name: ONE_OF,
        options: &[
            "My one-of text #1",
            "My one-of text #2",
            "My one-of text #3",
        ],
        answers: &["My one-of text #2"],
        suppressed_answers: &["My one-of text #2"],
    },
    DefaultQuestion {
        name: CHECK_BOX,
        options: &[],
        answers: &["1"],
        suppressed_answers: &["1", "1 <suppressed>"],
    },
    DefaultQuestion {
        name: NUMERIC,
        options: &[],
        answers: &["18"],
        suppressed_answers: &["18"],
    },
    DefaultQuestion {
        name: SERIAL_PORT,
        options: &["3F8", "2F8", "3E8", "2E8"],
        answers: &[],
        suppressed_answers: &["3F8 <suppressed>"],
    },
];

/// Questions whose values the HII backend cannot read from Linux: on DriverSample's
/// variable without runtime access, on its name/value store, and on the RAM disk form of
/// the firmware, which has no store.
const UNAVAILABLE_QUESTIONS: [&str; 4] = [
    "How tall are you? (Hex)",
    "NameValueVar0",
    "Disk Memory Type:",
    "Size (Hex):",
];

/// The answers of the questions on bit fields of DriverSample's EFI variable, which lacks
/// runtime access, and then of its variable, which the HII backend reads but whose bit fields
/// it does not decode; each ends with the default of Vfr.vfr if it has one.
const BIT_FIELD_QUESTIONS: [(&str, [&str; 2]); 3] = [
    (
        "NEST_BIT check box",
        [
            "<ValueUnavailable: EFI variable MyEfiBitVar-a04a27f4-df00-4d42-b552-39511302113d is \
             boot-service-only (no EFI_VARIABLE_RUNTIME_ACCESS)> <IFR default: 1>",
            "<ValueUnavailable: EDKII bit-field value not decoded> <IFR default: 1>",
        ],
    ),
    (
        "NEST_BIT one-of",
        [
            "<ValueUnavailable: EFI variable MyEfiBitVar-a04a27f4-df00-4d42-b552-39511302113d is \
             boot-service-only (no EFI_VARIABLE_RUNTIME_ACCESS)> <IFR default: LargeBootList>",
            "<ValueUnavailable: EDKII bit-field value not decoded> <IFR default: LargeBootList>",
        ],
    ),
    (
        "NEST_BIT numeric",
        [
            "<ValueUnavailable: EFI variable MyEfiBitVar-a04a27f4-df00-4d42-b552-39511302113d is \
             boot-service-only (no EFI_VARIABLE_RUNTIME_ACCESS)>",
            "<ValueUnavailable: EDKII bit-field value not decoded> <IFR default: 6>",
        ],
    ),
];

/// The flag that makes `get` and `hii list-questions` select questions in every state.
const INCLUDE_ALL: [&str; 2] = ["--include", "grayed-out,suppressed,disabled"];

/// The answer of a question whose value `--no-efivars` leaves unread, before its IFR default.
const NOT_READ: &str = "<ValueUnavailable: EFI variables not read>";

/// What `hii dump-efivars` prints.
#[derive(Debug, Deserialize)]
struct Dump {
    directory: String,
    redaction: String,
    copied: Vec<String>,
}

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
    assert_eq!(data[MATCH2_OFFSET], 0, "{MATCH2}");
}

#[test]
fn extract_db_copies_the_published_database() {
    let published = published_database();
    let path = "/tmp/hiidb.bin";
    let report: serde_json::Value = json(&["hii", "extract-db", path]);
    assert_eq!(
        report,
        serde_json::json!({ "info": format!("HiiDB written to {path}") }),
        "extract-db report"
    );
    let extracted = fs::read(path).unwrap_or_else(|error| panic!("cannot read {path}: {error}"));
    assert_eq!(
        (extracted.len(), crc32fast::hash(&extracted)),
        (
            usize::try_from(published.length).expect("the length exceeds usize"),
            published.crc32
        ),
        "{path} differs from the published database, as (length, CRC-32)"
    );
}

/// read() of `/dev/mem` serves the database only on x86_64: arm64 Linux maps neither
/// runtime services data nor reserved memory, and 32-bit x86 Linux nothing above its low
/// memory, so there `extract_db_copies_the_published_database` passes only through the
/// fallback of `uefisettings` to mmap().
#[test]
fn dev_mem_read_serves_the_database_only_on_x86_64() {
    let address = published_database().address;
    let errno = read_dev_mem_byte(address)
        .err()
        .map(|error| error.raw_os_error());
    let expected = if cfg!(target_arch = "x86_64") {
        None
    } else {
        Some(Some(EFAULT))
    };
    assert_eq!(errno, expected, "read() of /dev/mem at {address:#x}: errno");
}

/// The emulator faults a 64-bit load from the mapped database, which publish-hiidb puts at an
/// unaligned address, as arm64 hardware faults unaligned wide loads from Device memory
/// (<https://github.com/linuxboot/uefisettings/pull/12>); so a load like that in `uefisettings`
/// fails `extract_db_copies_the_published_database`.
#[test]
#[cfg(target_arch = "aarch64")]
fn unaligned_wide_load_from_the_mapped_database_faults() {
    use std::os::unix::process::ExitStatusExt;
    use std::process::Command;
    use std::process::Stdio;

    let address = published_database().address;
    let status = Command::new("/bin/busybox")
        .args(["devmem", &format!("{address:#x}"), "64"])
        .stdout(Stdio::null())
        .status()
        .expect("cannot run busybox devmem");
    assert_eq!(
        status.signal(),
        Some(SIGBUS),
        "devmem at {address:#x}: {status}; QEMU before 9.0 does not fault unaligned loads from \
         Device memory"
    );
}

#[test]
fn list_questions_lists_the_defaults() {
    for flags in [&[][..], &INCLUDE_SUPPRESSED] {
        let questions: Vec<Question> =
            json(&[&["hii", "list-questions", "--json"][..], flags].concat());
        for DefaultQuestion {
            name,
            options,
            answers,
            suppressed_answers,
        } in DEFAULTS
        {
            let answers = if flags.is_empty() {
                answers
            } else {
                suppressed_answers
            };
            let expected: Vec<Question> = answers
                .iter()
                .map(|answer| question(name, answer, options))
                .collect();
            let listed: Vec<&Question> = questions
                .iter()
                .filter(|question| question.name == name)
                .collect();
            assert_eq!(
                listed,
                expected.iter().collect::<Vec<_>>(),
                "{name} {flags:?}"
            );
        }
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
fn list_questions_reports_bit_field_questions_with_their_defaults() {
    let questions: Vec<Question> = json(&["hii", "list-questions", "--json"]);
    for (name, answers) in BIT_FIELD_QUESTIONS {
        let listed: Vec<&str> = questions
            .iter()
            .filter(|question| question.name == name)
            .map(|question| question.answer.as_str())
            .collect();
        assert_eq!(listed, answers, "{name}");
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
    for DefaultQuestion { name, .. } in DEFAULTS {
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
    // DriverSample's two formsets and one of the firmware.
    for name in [
        "Browser Testcase Engine",
        "ABC Information Sample",
        "RAM Disk Configuration",
    ] {
        assert!(formsets.contains(&name), "{name:?} is not in {formsets:?}");
    }
    // The NEST_BIT check box, one-of and numeric on DriverSample's variable.
    let mut op_code = "";
    let mut not_decoded = BTreeSet::new();
    for line in output.stdout.lines().map(str::trim_start) {
        if let Some((name, _)) = line
            .strip_prefix("OpCode: ")
            .and_then(|op| op.split_once(" - "))
        {
            op_code = name;
        }
        if line == "-Answer: <ValueUnavailable: EDKII bit-field value not decoded>" {
            not_decoded.insert(op_code);
        }
    }
    assert_eq!(
        not_decoded,
        BTreeSet::from(["CheckBox", "Numeric", "OneOf"]),
        "{output:#?}"
    );
}

#[test]
fn show_translations_prints_the_spellings_database() {
    let translations: BTreeMap<String, serde_json::Value> = json(&["show-translations", "--json"]);
    assert!(translations.contains_key("TPM State"), "{translations:#?}");
}

#[test]
fn get_returns_the_defaults() {
    for DefaultQuestion {
        name,
        options,
        suppressed_answers,
        ..
    } in DEFAULTS
    {
        let (got, _) = single_response(
            &[&["hii", "get", name, "--json"][..], &INCLUDE_SUPPRESSED].concat(),
            BACKEND_HII,
        );
        assert_eq!(
            got,
            question(name, suppressed_answers[0], options),
            "{name}"
        );
    }
}

#[test]
fn get_refuses_a_suppressed_question_by_default() {
    let error = json_error(&["hii", "get", SERIAL_PORT, "--json"]);
    assert_eq!(
        error.error_message,
        format!(
            "question {SERIAL_PORT:?} is suppressed; also include suppressed questions to select \
             it"
        ),
        "{SERIAL_PORT}"
    );
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

/// get shows a question that a condition it cannot evaluate may gray out, with its possible
/// states and why; including grayed-out questions selects it for sure.
#[test]
fn get_shows_a_question_that_may_be_grayed_out_with_its_states() {
    let annotation = format!(" <selectable or grayed-out: {MATCH2_REASON}>");
    for flags in [&[][..], &INCLUDE_GRAYED_OUT] {
        let (got, _) = single_response(
            &[&["hii", "get", MATCH2, "--json"][..], flags].concat(),
            BACKEND_HII,
        );
        assert_eq!(got.answer, format!("0{annotation}"), "{flags:?}: {got:#?}");
    }
}

/// With --no-efivars, get, list-questions and show-ifr read no question value: each value that
/// they read from efivarfs without the flag shows as not read.
#[test]
fn no_efivars_reads_no_question_value() {
    for name in [ONE_OF, CHECK_BOX, NUMERIC] {
        let (got, _) =
            single_response(&["hii", "get", name, "--json", "--no-efivars"], BACKEND_HII);
        assert!(got.answer.starts_with(NOT_READ), "get {name}: {got:#?}");
    }

    let listed = |flags: &[&str]| -> Vec<Question> {
        json(
            &[
                &["hii", "list-questions", "--json"][..],
                &INCLUDE_ALL,
                flags,
            ]
            .concat(),
        )
    };
    let (live, unread) = (listed(&[]), listed(&["--no-efivars"]));
    assert_eq!(live.len(), unread.len(), "list-questions: questions");
    let read: Vec<(&Question, &Question)> = live
        .iter()
        .zip(&unread)
        .filter(|(live, _)| !live.answer.starts_with('<'))
        .collect();
    assert!(!read.is_empty(), "list-questions reads no value");
    for (live, unread) in read {
        assert!(
            unread.answer.starts_with(NOT_READ),
            "list-questions {:?}: {:?} with --no-efivars, {:?} without",
            live.name,
            unread.answer,
            live.answer
        );
    }

    let answers = |flags: &[&str]| -> Vec<String> {
        let output = uefisettings(&[&["hii", "show-ifr"][..], flags].concat());
        assert_eq!(output.code, Some(0), "show-ifr {flags:?}: {output:#?}");
        output
            .stdout
            .lines()
            .filter_map(|line| line.trim_start().strip_prefix("-Answer: "))
            .map(str::to_owned)
            .collect()
    };
    let (live, unread) = (answers(&[]), answers(&["--no-efivars"]));
    assert_eq!(live.len(), unread.len(), "show-ifr: answers");
    let read: Vec<(&String, &String)> = live
        .iter()
        .zip(&unread)
        .filter(|(live, _)| !live.starts_with('<'))
        .collect();
    assert!(!read.is_empty(), "show-ifr reads no value");
    for (live, unread) in read {
        assert_eq!(
            unread, NOT_READ,
            "show-ifr answer {live:?} with --no-efivars"
        );
    }
}

#[test]
fn dumped_efivars_answer_as_efivarfs() {
    let variable = DRIVER_SAMPLE_VARIABLE
        .rsplit_once('/')
        .map(|(_, name)| name)
        .expect("a variable path");
    let mode = |path: &str| {
        let metadata =
            fs::metadata(path).unwrap_or_else(|error| panic!("cannot stat {path}: {error}"));
        metadata.permissions().mode() & 0o777
    };
    for (dir, unredacted) in [("/tmp/efivars", false), ("/tmp/efivars-whole", true)] {
        let flags: &[&str] = if unredacted { &["--unredacted"] } else { &[] };
        let dump: Dump = json(&[&["hii", "dump-efivars"], flags, &[dir]].concat());
        let path = format!("{dir}/{variable}");
        let dumped = fs::read(&path).unwrap_or_else(|error| panic!("cannot read {path}: {error}"));
        let live = fs::read(DRIVER_SAMPLE_VARIABLE).expect("cannot read the DriverSample variable");
        let redaction = if unredacted {
            "unredacted"
        } else {
            "decoded-bytes"
        };

        assert_eq!(
            (dump.directory.as_str(), dump.redaction.as_str()),
            (dir, redaction),
            "{dump:#?}"
        );
        assert!(dump.copied.iter().any(|name| name == variable), "{dump:#?}");
        assert_eq!((mode(dir), mode(&path)), (0o700, 0o600), "{dir}: modes");
        if unredacted {
            assert_eq!(dumped, live, "{path}");
        } else {
            assert_eq!(dumped.len(), live.len(), "{path}: length");
            assert!(
                dumped
                    .iter()
                    .zip(&live)
                    .all(|(dumped, live)| dumped == live || *dumped == 0),
                "{path}: a byte neither copied nor zero"
            );
            for offset in [
                ONE_OF_OFFSET,
                CHECK_BOX_OFFSET,
                NUMERIC_OFFSET,
                SERIAL_PORT_OFFSET,
                SERIAL_PORT_OFFSET + 1,
            ] {
                let offset = EFIVARFS_HEADER_SIZE + offset;
                assert_eq!(dumped[offset], live[offset], "{path}: byte {offset}");
            }
        }
        for command in [
            vec!["hii", "list-questions", "--json"],
            [&["hii", "list-questions", "--json"][..], &INCLUDE_ALL].concat(),
            vec!["hii", "show-ifr"],
            vec!["hii", "get", ONE_OF, "--json"],
            [
                &["hii", "get", SERIAL_PORT, "--json"][..],
                &INCLUDE_SUPPRESSED,
            ]
            .concat(),
        ] {
            let live = uefisettings(&command);
            let replayed = uefisettings(&[&command[..], &["--efivars", dir]].concat());
            assert_eq!(
                (replayed.code, replayed.stdout),
                (live.code, live.stdout),
                "{command:?} --efivars {dir}"
            );
        }
    }
    let error = json_error(&["hii", "dump-efivars", "/tmp/efivars"]);
    assert_eq!(
        error.error_message,
        "failed to create efivars directory '/tmp/efivars': File exists (os error 17)",
        "second dump into /tmp/efivars"
    );
}
