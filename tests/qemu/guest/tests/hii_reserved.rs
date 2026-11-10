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

//! The scenario hii-reserved: DriverSample and `publish-hiidb.efi reserved`, which copies the HII
//! database into EfiReservedMemoryType pages, which firmware reserves without the RUNTIME
//! attribute, and points the `HiiDB` variable at the copy. With the default `--efivar-memory
//! runtime`, the `HiiDB` variable method refuses extract-db and set before it reads the copy; with
//! `--efivar-memory firmware-reserved`, it refuses to read there unless
//! `--i-am-fine-to-brick-this-system` is given, and then reads the database, warning of the read
//! on stderr.

use uefisettings_qemu_guest::driver_sample::NUMERIC;
use uefisettings_qemu_guest::extract_db_error;
use uefisettings_qemu_guest::extract_db_matches_with;
use uefisettings_qemu_guest::json_error;
use uefisettings_qemu_guest::published_database;
use uefisettings_qemu_guest::uefisettings;
use uefisettings_qemu_guest::variable_data;
use uefisettings_qemu_guest::Output;
use uefisettings_qemu_guest::Response;
use uefisettings_qemu_guest::Responses;
use uefisettings_qemu_guest::BACKEND_HII;
use uefisettings_qemu_guest::DRIVER_SAMPLE_VARIABLE;
use uefisettings_qemu_guest::UNSAFE_OPERATIONS;

/// The flags that name the `HiiDB` variable method with the memory that admits the copy.
const FIRMWARE_RESERVED: [&str; 4] = [
    "--hii-source",
    "efivar",
    "--efivar-memory",
    "firmware-reserved",
];

/// The refusal of a read of firmware-reserved memory without the flag
/// (`src/lib/unsafe_operations.rs` `UnsafeOperation::FirmwareReservedMemory`), and the warning of
/// it with the flag.
const FIRMWARE_RESERVED_READ: &str = "the efivar source would read the HiiDB from memory that the \
                                      firmware reserves, which may be device memory, whose reads \
                                      can have side effects: of I/O memory, \"Accidental access \
                                      to this is obviously disastrous\" (Linux 6.11 \
                                      lib/Kconfig.debug:1911-1913), and EfiReservedMemoryType is \
                                      \"Not usable.\" (UEFI 2.11 §7.2 Table 7.6)";

/// The warning lines of `output`'s stderr.
fn warnings(output: &Output) -> Vec<&str> {
    output
        .stderr
        .lines()
        .filter(|line| line.starts_with("warning: "))
        .collect()
}

/// The warning of a read of firmware-reserved memory that the flag lifted.
fn read_warning() -> String {
    format!(
        "warning: {FIRMWARE_RESERVED_READ}; --i-am-fine-to-brick-this-system lets uefisettings \
         read it"
    )
}

/// With the default memory, extract-db and set fail with the range check's refusal of the copy,
/// which lies in no EFI runtime region, and set writes nothing.
#[test]
fn default_memory_refuses_extract_db_and_set() {
    let refusal = published_database().refusal("EFI_MEMORY_RUNTIME");
    let flags = ["--hii-source", "efivar"];

    let extract_db = extract_db_error(&flags, "/tmp/hiidb-reserved-runtime.bin");
    assert_eq!(
        extract_db.error_message,
        format!("no HII database: efivar: {refusal}"),
        "extract-db"
    );

    let before = variable_data(DRIVER_SAMPLE_VARIABLE).expect("the variable does not exist");
    let set = json_error(&[&flags[..], &["hii", "set", NUMERIC, "19", "--json"]].concat());
    assert_eq!(
        set.error_message,
        format!("no HII database: efivar: {refusal}"),
        "set"
    );
    let after = variable_data(DRIVER_SAMPLE_VARIABLE).expect("the variable does not exist");
    assert_eq!(after, before, "set wrote the variable");
}

/// With `--efivar-memory firmware-reserved` but without the flag, extract-db, through the `HiiDB`
/// variable method and through the automatic order, which stops there, refuses the read before it
/// opens `/dev/mem`, naming the flag, and writes no file.
#[test]
fn extract_db_refuses_firmware_reserved_without_the_unsafe_flag() {
    let refusal =
        format!("{FIRMWARE_RESERVED_READ}; pass --i-am-fine-to-brick-this-system to read it");
    let efivar = extract_db_error(
        &FIRMWARE_RESERVED,
        "/tmp/hiidb-reserved-unflagged-efivar.bin",
    );
    let auto = extract_db_error(
        &FIRMWARE_RESERVED[2..],
        "/tmp/hiidb-reserved-unflagged-auto.bin",
    );

    assert_eq!(
        efivar.error_message,
        format!("no HII database: efivar: refused: {refusal}"),
        "efivar"
    );
    assert!(
        auto.error_message
            .ends_with(&format!("; efivar: refused: {refusal}")),
        "auto: {:?} lacks the efivar method's refusal {refusal:?} last",
        auto.error_message
    );
}

/// With firmware-reserved memory and the flag, extract-db writes exactly the published database,
/// and get answers from it, each warning of the read.
#[test]
fn firmware_reserved_memory_reads_the_database() {
    let length = usize::try_from(published_database().length).expect("a usize length");
    let output = extract_db_matches_with(
        &FIRMWARE_RESERVED,
        "/tmp/hiidb-reserved.bin",
        &UNSAFE_OPERATIONS,
        Some(length),
    );
    assert_eq!(
        warnings(&output),
        [read_warning()],
        "extract-db: stderr {:?}",
        output.stderr
    );

    let args = [
        &FIRMWARE_RESERVED[..],
        &["hii", "get", NUMERIC, "--json"],
        &UNSAFE_OPERATIONS,
    ]
    .concat();
    let output = uefisettings(&args);
    let Responses { responses } = output.json(0);
    let [Response {
        backend, question, ..
    }] = <[Response; 1]>::try_from(responses)
        .unwrap_or_else(|responses| panic!("{args:?}: expected one response: {responses:#?}"));
    assert_eq!(
        (backend, question.answer.as_str()),
        (BACKEND_HII, "18"),
        "{args:?}"
    );
    assert_eq!(
        warnings(&output),
        [read_warning()],
        "get: stderr {:?}",
        output.stderr
    );
}
