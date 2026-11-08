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

//! A guest whose firmware runs EDK2's DriverSample, with its variables MyIfrNVData and MyEfiVar
//! readable at runtime, and publish-hiidb from `Driver####` load options before Linux starts.
//! These checks only read, so the answers are DriverSample's defaults.

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;

use serde::Deserialize;
use uefisettings_qemu_guest::driver_sample::CHECK_BOX;
use uefisettings_qemu_guest::driver_sample::CHECK_BOX_OFFSET;
use uefisettings_qemu_guest::driver_sample::INCLUDE_GRAYED_OUT;
use uefisettings_qemu_guest::driver_sample::INCLUDE_SUPPRESSED;
use uefisettings_qemu_guest::driver_sample::LOCKED;
use uefisettings_qemu_guest::driver_sample::MATCH2;
use uefisettings_qemu_guest::driver_sample::MATCH2_OFFSET;
use uefisettings_qemu_guest::driver_sample::MATCH2_REASON;
use uefisettings_qemu_guest::driver_sample::NUMERIC;
use uefisettings_qemu_guest::driver_sample::NUMERIC_OFFSET;
use uefisettings_qemu_guest::driver_sample::ONE_OF;
use uefisettings_qemu_guest::driver_sample::ONE_OF_OFFSET;
use uefisettings_qemu_guest::driver_sample::ONE_OF_PROMPT;
use uefisettings_qemu_guest::driver_sample::ONE_OF_PROMPT_FR_FR;
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
use uefisettings_qemu_guest::StringPackage;
use uefisettings_qemu_guest::BACKEND_HII;
use uefisettings_qemu_guest::DRIVER_SAMPLE_VARIABLE;
use uefisettings_qemu_guest::EFAULT;
use uefisettings_qemu_guest::EFIVARFS_HEADER_SIZE;
use uefisettings_qemu_guest::MY_EFI_VAR;
use uefisettings_qemu_guest::MY_EFI_VAR_QUESTION;
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
/// name/value store, which INCLUDE_GRAYED_OUT selects.
const UNAVAILABLE_QUESTIONS: [&str; 1] = [LOCKED];

/// The answers of the questions on bit fields of DriverSample's EFI variable MyEfiBitVar,
/// which lacks runtime access, each ending with the default of Vfr.vfr if it has one, and then
/// of its variable, which the HII backend reads.
const BIT_FIELD_QUESTIONS: [(&str, [&str; 2]); 3] = [
    (
        "NEST_BIT check box",
        [
            "<ValueUnavailable: EFI variable MyEfiBitVar-a04a27f4-df00-4d42-b552-39511302113d is \
             not present at OS runtime: efivarfs does not list it, and its form declares it \
             boot-service-only (no EFI_VARIABLE_RUNTIME_ACCESS)> <IFR default: 1>",
            "1",
        ],
    ),
    (
        "NEST_BIT one-of",
        [
            "<ValueUnavailable: EFI variable MyEfiBitVar-a04a27f4-df00-4d42-b552-39511302113d is \
             not present at OS runtime: efivarfs does not list it, and its form declares it \
             boot-service-only (no EFI_VARIABLE_RUNTIME_ACCESS)> <IFR default: LargeBootList>",
            "LargeBootList",
        ],
    ),
    (
        "NEST_BIT numeric",
        [
            "<ValueUnavailable: EFI variable MyEfiBitVar-a04a27f4-df00-4d42-b552-39511302113d is \
             not present at OS runtime: efivarfs does not list it, and its form declares it \
             boot-service-only (no EFI_VARIABLE_RUNTIME_ACCESS)>",
            "6",
        ],
    ),
];

/// The flag that makes `get` and `hii list-questions` select questions in every state.
const INCLUDE_ALL: [&str; 2] = ["--include", "grayed-out,suppressed,disabled"];

/// The answer of a question whose value `--no-efivars` leaves unread, before its IFR default.
const NOT_READ: &str = "<ValueUnavailable: EFI variables not read>";

/// NOT_READ for a question on MyEfiVar, whose form declares it boot-service-only.
const MY_EFI_VAR_NOT_READ: &str = "<ValueUnavailable: EFI variables not read; the form declares \
    EFI variable MyEfiVar-a04a27f4-df00-4d42-b552-39511302113d boot-service-only \
    (no EFI_VARIABLE_RUNTIME_ACCESS)>";

/// The questions on MyEfiVar in DriverSample's Vfr.vfr: on Field8, Field16 and
/// SubmittedCallback.
const MY_EFI_VAR_QUESTIONS: usize = 3;

/// What `hii dump-efivars` prints.
#[derive(Debug, Deserialize)]
struct Dump {
    directory: String,
    redaction: String,
    copied: Vec<String>,
}

/// A question of `hii list-questions --json`, with the fields that `Question` leaves out.
#[derive(Debug, Deserialize)]
struct ListedQuestion {
    name: String,
    // optional, so that a build without the field fails an assertion, not the parse
    flags: Option<Vec<String>>,
    defaults: Option<Vec<ListedDefault>>,
}

/// A default of a ListedQuestion.
#[derive(Debug, Deserialize, PartialEq)]
struct ListedDefault {
    default_id: i32,
    default_store_name: Option<String>,
    value: String,
}

/// A ListedDefault of the default store `default_id` of DriverSample's formset: 0, which
/// MyStandardDefault names "Standard Default", or 1, which MyManufactureDefault names
/// "Manufacture Default" (Vfr.vfr and VfrStrings.uni, edk2-stable202608).
fn driver_sample_default(default_id: i32, value: &str) -> ListedDefault {
    let name = match default_id {
        0 => "Standard Default",
        1 => "Manufacture Default",
        _ => panic!("DriverSample declares no default store {default_id}"),
    };
    ListedDefault {
        default_id,
        default_store_name: Some(name.to_owned()),
        value: value.to_owned(),
    }
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
    let output = uefisettings(&["hii", "extract-db", path]);
    // The HII source is logged at debug level, which RUST_LOG leaves off.
    assert_eq!(output.stderr, "", "extract-db stderr");
    let report: serde_json::Value = output.json(0);
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
    let questions: Vec<Question> = json(&[
        "hii",
        "list-questions",
        "--json",
        INCLUDE_GRAYED_OUT[0],
        INCLUDE_GRAYED_OUT[1],
    ]);
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
fn list_questions_reads_bit_field_questions() {
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

/// list-questions lists the question Flags that DriverSample's Vfr.vfr (edk2-stable202608)
/// gives its questions, and none for a question without: VfrCompile writes `flags = READ_ONLY`,
/// `RESET_REQUIRED` and `REST_STYLE` as EFI_IFR_FLAG_READ_ONLY, _RESET_REQUIRED and _REST_STYLE.
#[test]
fn list_questions_lists_the_question_flags() {
    let questions: Vec<ListedQuestion> = json(&[
        "hii",
        "list-questions",
        "--json",
        INCLUDE_ALL[0],
        INCLUDE_ALL[1],
    ]);
    for (name, flags) in [
        ("How old are you?(Readonly)", Some(&["READ_ONLY"][..])),
        (NUMERIC, None),
        (ONE_OF, Some(&["RESET_REQUIRED"][..])),
        (
            "x-UEFI HII Option",
            Some(&["RESET_REQUIRED", "REST_STYLE"][..]),
        ),
        (
            "Non x-UEFI HII Option",
            Some(&["RESET_REQUIRED", "REST_STYLE"][..]),
        ),
    ] {
        let listed: Vec<Option<Vec<&str>>> = questions
            .iter()
            .filter(|question| question.name == name)
            .map(|question| {
                question
                    .flags
                    .as_ref()
                    .map(|flags| flags.iter().map(String::as_str).collect())
            })
            .collect();
        assert_eq!(listed, [flags.map(<[&str]>::to_vec)], "flags of {name:?}");
    }
}

/// list-questions lists the defaults that DriverSample's Vfr.vfr (edk2-stable202608) declares
/// for a question, per default store: by `default`, with or without a `defaultstore`, and by the
/// CHECKBOX_DEFAULT and CHECKBOX_DEFAULT_MFG flags, clear ones too, and none for a question
/// without.
#[test]
fn list_questions_lists_the_declared_defaults() {
    let questions: Vec<ListedQuestion> = json(&[
        "hii",
        "list-questions",
        "--json",
        INCLUDE_ALL[0],
        INCLUDE_ALL[1],
    ]);
    let cases = [
        (
            NUMERIC,
            vec![Some(vec![
                driver_sample_default(0, "18"),
                driver_sample_default(1, "19"),
            ])],
        ),
        (
            CHECK_BOX,
            vec![
                Some(vec![
                    driver_sample_default(0, "1"),
                    driver_sample_default(1, "1"),
                ]),
                Some(vec![
                    driver_sample_default(0, "1"),
                    driver_sample_default(1, "0"),
                ]),
            ],
        ),
        (
            "How old are you?(Readonly)",
            vec![Some(vec![driver_sample_default(0, "21")])],
        ),
        (
            "Get Call Back default",
            vec![Some(vec![driver_sample_default(0, "18")])],
        ),
        (MATCH2, vec![None]),
    ];
    for (name, defaults) in cases {
        let listed: Vec<&Option<Vec<ListedDefault>>> = questions
            .iter()
            .filter(|question| question.name == name)
            .map(|question| &question.defaults)
            .collect();
        assert_eq!(
            listed,
            defaults.iter().collect::<Vec<_>>(),
            "defaults of {name:?}"
        );
    }
}

/// Each package of list-strings names its own language: DriverSample's VfrStrings.uni
/// (edk2-stable202608) defines en-US, fr-FR and x-UEFI-ns, edk2's build puts each language in a
/// strings package of its own, holding only the strings defined in it, and DriverSample adds
/// those packages to both of its package lists (DriverSample.c, HiiAddPackages).
#[test]
fn list_strings_names_each_package_language() {
    let packages: Vec<StringPackage> = json(&["hii", "list-strings", "--json"]);
    for (string, language) in [
        ("My one-of prompt #1", "en-US"),
        ("Mi uno- de gu\u{ed}a # 1", "fr-FR"),
        ("iSCSIBootEnable", "x-UEFI-ns"),
    ] {
        let languages: Vec<Option<&str>> = packages
            .iter()
            .filter(|package| package.string_package.values().any(|value| value == string))
            .map(|package| package.language.as_deref())
            .collect();
        assert_eq!(
            languages,
            [Some(language); 2],
            "languages of the packages holding {string:?}"
        );
    }
}

/// Each question that list-questions lists shows its QuestionId, 1 to 65535, and the GUID of its
/// FormSet as show-ifr prints it. ONE_OF lists its x-UEFI-ns prompt (VfrStrings.uni
/// STR_ONE_OF_PROMPT_KEYWORD, edk2-stable202608) as its keyword; ONE_OF_PROMPT, which no x-
/// package holds, lists none.
#[test]
fn questions_show_their_question_id_form_set_guid_and_keywords() {
    let shown = uefisettings(&["hii", "show-ifr"]);
    assert_eq!(shown.code, Some(0), "{shown:#?}");
    let form_sets: Vec<&str> = shown
        .stdout
        .lines()
        .filter_map(|line| line.trim_start().strip_prefix("OpCode: FormSet - "))
        .filter_map(|line| line.split_once(" - GUID "))
        .filter_map(|(_, rest)| rest.split_once(" - ClassGUID "))
        .map(|(guid, _)| guid)
        .collect();
    let questions: Vec<serde_json::Value> = json(&["hii", "list-questions", "--json"]);

    for question in &questions {
        assert!(
            matches!(question["question_id"].as_u64(), Some(1..=65535)),
            "QuestionId of {question}"
        );
        let form_set = question["form_set_guid"].as_str().unwrap_or_default();
        assert!(
            form_sets.contains(&form_set),
            "{question}: no FormSet of show-ifr, {form_sets:?}"
        );
    }
    let keywords_of = |name: &str| -> Vec<Option<&serde_json::Value>> {
        questions
            .iter()
            .filter(|question| question["name"] == name)
            .map(|question| question.get("keywords"))
            .collect()
    };
    let keyword = serde_json::json!([{"namespace_id": "x-UEFI-ns", "keyword": "iSCSIBootEnable"}]);
    assert_eq!(
        keywords_of(ONE_OF),
        [Some(&keyword)],
        "keywords of {ONE_OF:?}"
    );
    assert_eq!(
        keywords_of(ONE_OF_PROMPT),
        [None; 3],
        "keywords of {ONE_OF_PROMPT:?}"
    );
}

/// get selects the question of a keyword, and that of a FormSet GUID and QuestionId as
/// list-questions shows them, as by its prompt.
#[test]
fn get_selects_by_keyword_or_question_id_as_by_prompt() {
    let by_prompt = uefisettings(&["hii", "get", ONE_OF, "--json"]);
    assert_eq!(by_prompt.code, Some(0), "{by_prompt:#?}");
    let questions: Vec<serde_json::Value> = json(&["hii", "list-questions", "--json"]);
    let addresses: Vec<String> = questions
        .iter()
        .filter(|question| question["name"] == ONE_OF)
        .map(|question| {
            format!(
                "{}:{}",
                question["form_set_guid"].as_str().unwrap_or_default(),
                question["question_id"]
            )
        })
        .collect();
    let [address] = <[String; 1]>::try_from(addresses)
        .unwrap_or_else(|addresses| panic!("{ONE_OF:?} listed as {addresses:?}"));

    for args in [
        ["hii", "get", "--keyword", "iSCSIBootEnable", "--json"],
        ["hii", "get", "--question-id", &address, "--json"],
    ] {
        let output = uefisettings(&args);
        assert_eq!(
            (output.code, &output.stdout),
            (Some(0), &by_prompt.stdout),
            "{args:?}: {output:#?}"
        );
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
    // The stored numbers of the NEST_BIT check box, one-of and numeric on DriverSample's
    // variable; those on its EFI variable MyEfiBitVar, which lacks runtime access, have none.
    let mut question = "";
    let mut answers = Vec::new();
    for line in output.stdout.lines().map(str::trim_start) {
        // "Q: - <prompt> - Help: - <help>" for a CHECKBOX, "Q: <prompt> - Help: <help>" else
        if let Some((_, prompt)) = line.split_once(" - Q: ") {
            let prompt = prompt.trim_start_matches("- ");
            question = prompt
                .split_once(" - Help: ")
                .map_or(prompt, |(name, _)| name);
        }
        if let Some(answer) = line.strip_prefix("-Answer: ") {
            if question.starts_with("NEST_BIT") && !answer.starts_with(UNAVAILABLE) {
                answers.push((question, answer));
            }
        }
    }
    assert_eq!(
        answers,
        [
            ("NEST_BIT check box", "1"),
            ("NEST_BIT one-of", "1"),
            ("NEST_BIT numeric", "6"),
        ],
        "{output:#?}"
    );
    // ops of which show-ifr decodes nothing show by their OpCode, as DriverSample's SUPPRESS_IFs
    let suppress_ifs = output
        .stdout
        .lines()
        .filter(|line| line.trim_start() == "OpCode: SuppressIf")
        .count();
    assert!(suppress_ifs > 0, "no SuppressIf line: {output:#?}");
}

#[test]
fn show_translations_prints_the_spellings_database() {
    let translations: BTreeMap<String, serde_json::Value> = json(&["show-translations", "--json"]);
    assert!(translations.contains_key("TPM State"), "{translations:#?}");
}

/// --language fr-FR shows DriverSample's fr-FR texts instead of the platform language's en-US
/// ones, and get still selects by the en-US prompt.
#[test]
fn language_shows_the_texts_of_its_strings_package() {
    let questions: Vec<Question> =
        json(&["hii", "list-questions", "--language", "fr-FR", "--json"]);
    let names: Vec<&str> = questions
        .iter()
        .map(|question| question.name.as_str())
        .collect();
    assert!(
        names.contains(&ONE_OF_PROMPT_FR_FR),
        "{ONE_OF_PROMPT_FR_FR:?} is not listed: {names:?}"
    );
    assert!(
        !names.contains(&ONE_OF_PROMPT),
        "{ONE_OF_PROMPT:?} is listed: {names:?}"
    );

    let (got, _) = single_response(
        &["hii", "get", ONE_OF_PROMPT, "--language", "fr-FR", "--json"],
        BACKEND_HII,
    );
    assert_eq!(got.name, ONE_OF_PROMPT_FR_FR, "{got:#?}");
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

/// get reads the question on MyEfiVar, which its form declares boot-service-only, by the
/// variable's own attributes, which have runtime access here. It shows the value in decimal,
/// though Vfr.vfr has it displayed in hex.
#[test]
fn question_on_a_runtime_variable_of_a_boot_service_only_form_is_read() {
    let (got, _) = single_response(&["hii", "get", MY_EFI_VAR_QUESTION, "--json"], BACKEND_HII);
    assert_eq!(got.answer, "18", "{got:#?}");
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
        let (got, _) = single_response(
            &[&["hii", "get", name, "--json"][..], &INCLUDE_GRAYED_OUT].concat(),
            BACKEND_HII,
        );
        assert!(got.answer.starts_with(UNAVAILABLE), "{got:#?}");
    }
}

/// get and list-questions leave out DriverSample's question in a LOCKED scope, as edk2's setup
/// browser grays it out, unless --include selects grayed-out questions, and then show its state.
#[test]
fn get_and_list_questions_gray_out_a_question_in_a_locked_scope() {
    let error = json_error(&["hii", "get", LOCKED, "--json"]);
    assert_eq!(
        error.error_message,
        format!(
            "question {LOCKED:?} is grayed-out; also include grayed-out questions to select it"
        ),
        "get {LOCKED}"
    );
    let (got, _) = single_response(
        &[&["hii", "get", LOCKED, "--json"][..], &INCLUDE_GRAYED_OUT].concat(),
        BACKEND_HII,
    );
    assert!(
        got.answer.ends_with(" <grayed-out>"),
        "get {LOCKED} {got:#?}"
    );

    for (flags, want) in [(&[][..], 0), (&INCLUDE_GRAYED_OUT[..], 1)] {
        let questions: Vec<Question> =
            json(&[&["hii", "list-questions", "--json"][..], flags].concat());
        let listed: Vec<&Question> = questions
            .iter()
            .filter(|question| question.name == LOCKED)
            .collect();
        assert_eq!(listed.len(), want, "list-questions {flags:?}: {listed:#?}");
        assert!(
            listed
                .iter()
                .all(|question| question.answer.ends_with(" <grayed-out>")),
            "list-questions {flags:?}: {listed:#?}"
        );
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
/// they read from efivarfs without the flag shows as not read, naming the boot-service-only
/// declaration of MyEfiVar's form for the questions on it.
#[test]
fn no_efivars_reads_no_question_value() {
    for (name, unread) in [
        (ONE_OF, NOT_READ),
        (CHECK_BOX, NOT_READ),
        (NUMERIC, NOT_READ),
        (MY_EFI_VAR_QUESTION, MY_EFI_VAR_NOT_READ),
    ] {
        let (got, _) =
            single_response(&["hii", "get", name, "--json", "--no-efivars"], BACKEND_HII);
        assert!(got.answer.starts_with(unread), "get {name}: {got:#?}");
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
    let mut declared = 0;
    for (live, unread) in read {
        declared += usize::from(unread.answer.starts_with(MY_EFI_VAR_NOT_READ));
        assert!(
            unread.answer.starts_with(NOT_READ) || unread.answer.starts_with(MY_EFI_VAR_NOT_READ),
            "list-questions {:?}: {:?} with --no-efivars, {:?} without",
            live.name,
            unread.answer,
            live.answer
        );
    }
    assert_eq!(
        declared, MY_EFI_VAR_QUESTIONS,
        "list-questions: questions on MyEfiVar"
    );

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
    let mut declared = 0;
    for (live, unread) in read {
        declared += usize::from(unread == MY_EFI_VAR_NOT_READ);
        assert!(
            unread == NOT_READ || unread == MY_EFI_VAR_NOT_READ,
            "show-ifr answer {live:?}: {unread:?} with --no-efivars"
        );
    }
    assert_eq!(
        declared, MY_EFI_VAR_QUESTIONS,
        "show-ifr: questions on MyEfiVar"
    );
}

#[test]
fn dumped_efivars_answer_as_efivarfs() {
    let file_name = |path: &'static str| {
        path.rsplit_once('/')
            .map(|(_, name)| name)
            .expect("a variable path")
    };
    let variable = file_name(DRIVER_SAMPLE_VARIABLE);
    // whose form declares it boot-service-only
    let my_efi_var = file_name(MY_EFI_VAR);
    let mode = |path: &str| {
        let metadata =
            fs::metadata(path).unwrap_or_else(|error| panic!("cannot stat {path}: {error}"));
        metadata.permissions().mode() & 0o777
    };
    let extracted = uefisettings(&["hii", "extract-db", "/tmp/hiidb.bin"]);
    assert_eq!(extracted.code, Some(0), "extract-db: {extracted:#?}");
    let hiidb = fs::read("/tmp/hiidb.bin").expect("cannot read /tmp/hiidb.bin");
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
        let manifest: serde_json::Value = serde_json::from_slice(
            &fs::read(format!("{dir}/uefisettings-dump.json"))
                .unwrap_or_else(|error| panic!("cannot read the manifest in {dir}: {error}")),
        )
        .unwrap_or_else(|error| panic!("cannot parse the manifest in {dir}: {error}"));

        assert_eq!(
            (dump.directory.as_str(), dump.redaction.as_str()),
            (dir, redaction),
            "{dump:#?}"
        );
        assert_eq!(
            (&manifest["format"], &manifest["redaction"]),
            (&serde_json::json!(1), &serde_json::json!(redaction)),
            "{dir}: manifest {manifest}"
        );
        let saved = fs::read(format!("{dir}/hiidb.bin"))
            .unwrap_or_else(|error| panic!("cannot read the HiiDB in {dir}: {error}"));
        assert!(
            saved == hiidb,
            "{dir}: the saved HiiDB is not the extracted one"
        );
        for copied in [variable, my_efi_var] {
            assert!(
                dump.copied.iter().any(|name| name == copied),
                "{dir}: {copied} is not copied: {dump:#?}"
            );
        }
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
    let list = ["hii", "list-questions", "--json"];
    let live = uefisettings(&list);
    let matching = uefisettings(
        &[
            &list[..],
            &["-f", "/tmp/hiidb.bin", "--efivars", "/tmp/efivars"],
        ]
        .concat(),
    );
    assert_eq!(
        (matching.code, matching.stdout),
        (live.code, live.stdout.clone()),
        "-f /tmp/hiidb.bin --efivars /tmp/efivars"
    );
    let foreign = "/tmp/hiidb-foreign.bin";
    fs::write(foreign, [&hiidb[..], b"x"].concat()).expect("cannot write a foreign HiiDB");
    let error = json_error(&[&list[..], &["-f", foreign, "--efivars", "/tmp/efivars"]].concat());
    assert!(
        error.error_message.starts_with(&format!(
            "'{foreign}' is not the HiiDB that the efivars dump '/tmp/efivars' was dumped with"
        )),
        "-f {foreign} --efivars /tmp/efivars: {error:?}"
    );
    // without -f, --efivars reads the dump's hiidb.bin, and only while its manifest exists
    fs::write("/tmp/efivars-whole/hiidb.bin", b"not a HiiDB").expect("cannot overwrite hiidb.bin");
    let error = json_error(&[&list[..], &["--efivars", "/tmp/efivars-whole"]].concat());
    assert!(
        error
            .error_message
            .starts_with("failed to parse the package list"),
        "--efivars of a dump with a garbage hiidb.bin: {error:?}"
    );
    // binrw's frames are shown on one line, without the Rust source locations of its derive
    assert!(
        !error.error_message.contains('\n') && !error.error_message.contains("src/"),
        "--efivars of a dump with a garbage hiidb.bin, on one line: {error:?}"
    );
    fs::remove_file("/tmp/efivars-whole/uefisettings-dump.json")
        .expect("cannot remove the manifest");
    let plain = uefisettings(&[&list[..], &["--efivars", "/tmp/efivars-whole"]].concat());
    assert_eq!(
        (plain.code, plain.stdout),
        (live.code, live.stdout),
        "--efivars of a dump without its manifest"
    );
    let error = json_error(&["hii", "dump-efivars", "/tmp/efivars"]);
    assert_eq!(
        error.error_message,
        "failed to create efivars directory '/tmp/efivars': File exists (os error 17)",
        "second dump into /tmp/efivars"
    );
}
