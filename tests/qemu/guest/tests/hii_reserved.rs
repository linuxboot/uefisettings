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
//! `--efivar-memory firmware-reserved`, it reads the database.

use uefisettings_qemu_guest::driver_sample::NUMERIC;
use uefisettings_qemu_guest::extract_db_error;
use uefisettings_qemu_guest::extract_db_matches;
use uefisettings_qemu_guest::json_error;
use uefisettings_qemu_guest::published_database;
use uefisettings_qemu_guest::single_response;
use uefisettings_qemu_guest::variable_data;
use uefisettings_qemu_guest::BACKEND_HII;
use uefisettings_qemu_guest::DRIVER_SAMPLE_VARIABLE;

/// The flags that name the `HiiDB` variable method with the memory that admits the copy.
const FIRMWARE_RESERVED: [&str; 4] = [
    "--hii-source",
    "efivar",
    "--efivar-memory",
    "firmware-reserved",
];

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

/// With firmware-reserved memory, extract-db writes exactly the published database, and get
/// answers from it.
#[test]
fn firmware_reserved_memory_reads_the_database() {
    let length = usize::try_from(published_database().length).expect("a usize length");
    extract_db_matches(&FIRMWARE_RESERVED, "/tmp/hiidb-reserved.bin", Some(length));

    let args = [&FIRMWARE_RESERVED[..], &["hii", "get", NUMERIC, "--json"]].concat();
    let (question, _) = single_response(&args, BACKEND_HII);
    assert_eq!(question.answer, "18", "{args:?}");
}
