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
//! and publish-hiidb, which installs the HII database as the body of a `HIID` ACPI table
//! and sets no `HiiDB` variable: the HII backend finds the database through the table alone.

use std::fs;

use uefisettings_qemu_guest::driver_sample::NUMERIC;
use uefisettings_qemu_guest::json;
use uefisettings_qemu_guest::published_crc32;
use uefisettings_qemu_guest::require_test_vm;
use uefisettings_qemu_guest::single_response;
use uefisettings_qemu_guest::variable_data;
use uefisettings_qemu_guest::MachineInfo;
use uefisettings_qemu_guest::BACKEND_HII;
use uefisettings_qemu_guest::HIIDB_VARIABLE;
use uefisettings_qemu_guest::PREFIXES;

/// The ACPI table that publish-hiidb installs (`src/lib/hii/extract.rs`).
const HIID_TABLE: &str = "/sys/firmware/acpi/tables/HIID";

/// Size of the ACPI table header, which the database follows.
const ACPI_HEADER_SIZE: usize = 36;

/// The file that extract-db writes.
const EXTRACTED: &str = "/tmp/hiidb.bin";

/// The bytes of [`HIID_TABLE`].
#[track_caller]
fn hiid_table() -> Vec<u8> {
    require_test_vm();
    fs::read(HIID_TABLE).unwrap_or_else(|error| panic!("cannot read {HIID_TABLE}: {error}"))
}

#[test]
fn no_hiidb_variable_exists() {
    assert_eq!(
        variable_data(HIIDB_VARIABLE),
        None,
        "the HiiDB variable exists"
    );
}

/// The table's bytes sum to 0, as an ACPI table's checksum makes them, and its body is the
/// database that publish-hiidb published.
#[test]
fn hiid_table_holds_the_published_database() {
    let table = hiid_table();
    let sum = table.iter().fold(0u8, |sum, &byte| sum.wrapping_add(byte));
    assert_eq!(sum, 0, "{HIID_TABLE}: checksum");
    let database = &table[ACPI_HEADER_SIZE..];
    assert_eq!(
        crc32fast::hash(database),
        published_crc32(),
        "{HIID_TABLE}: the body differs from the published database ({} bytes)",
        database.len()
    );
}

#[test]
fn identify_detects_the_hii_backend() {
    let machine: MachineInfo = json(&["identify", "--json"]);
    assert_eq!(machine.backend, [BACKEND_HII], "identify --json backends");
}

/// Both `get` and `hii get` answer from the database of the table: the generic one only once
/// identify detects the HII backend.
#[test]
fn get_returns_the_default() {
    for prefix in PREFIXES {
        let args = [prefix, &["get", NUMERIC, "--json"]].concat();
        let (question, _) = single_response(&args, BACKEND_HII);
        assert_eq!(question.answer, "18", "{args:?}");
    }
}

#[test]
fn extract_db_copies_the_database_of_the_table() {
    let table = hiid_table();
    let report: serde_json::Value = json(&["hii", "extract-db", EXTRACTED]);
    assert_eq!(
        report,
        serde_json::json!({ "info": format!("HiiDB written to {EXTRACTED}") }),
        "extract-db report"
    );
    let extracted =
        fs::read(EXTRACTED).unwrap_or_else(|error| panic!("cannot read {EXTRACTED}: {error}"));
    assert_eq!(
        (extracted.len(), crc32fast::hash(&extracted)),
        (table.len() - ACPI_HEADER_SIZE, published_crc32()),
        "{EXTRACTED} differs from the published database, as (length, CRC-32)"
    );
}
