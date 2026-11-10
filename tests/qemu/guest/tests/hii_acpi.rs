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
//! and publish-hiidb, which installs the HII database as the body of one vendor ACPI table,
//! QHII or HIID, and sets no `HiiDB` variable: the HII backend finds the database through that
//! table alone. The tests of each table are in the module named after it, which its scenario's
//! libtest filter selects: `qhii::` for hii-acpi and `hiid::` for hii-acpi-hiid. The tests of
//! hii-acpi-two-tables, in `two_tables::`, see a QHII table that holds no database and a valid
//! HIID table.

use std::fs;

use uefisettings_qemu_guest::acpi_table_path;
use uefisettings_qemu_guest::driver_sample::NUMERIC;
use uefisettings_qemu_guest::extract_db_matches;
use uefisettings_qemu_guest::json;
use uefisettings_qemu_guest::published_crc32;
use uefisettings_qemu_guest::require_test_vm;
use uefisettings_qemu_guest::single_response;
use uefisettings_qemu_guest::uefisettings_with_env;
use uefisettings_qemu_guest::variable_data;
use uefisettings_qemu_guest::MachineInfo;
use uefisettings_qemu_guest::BACKEND_HII;
use uefisettings_qemu_guest::HIIDB_VARIABLE;
use uefisettings_qemu_guest::PREFIXES;

/// Size of the ACPI table header, which the database follows.
const ACPI_HEADER_SIZE: usize = 36;

/// The bytes of the vendor ACPI table of `signature`.
#[track_caller]
fn table(signature: &str) -> Vec<u8> {
    require_test_vm();
    let path = acpi_table_path(signature);
    fs::read(&path).unwrap_or_else(|error| panic!("cannot read {path}: {error}"))
}

fn no_hiidb_variable_exists() {
    assert_eq!(
        variable_data(HIIDB_VARIABLE),
        None,
        "the HiiDB variable exists"
    );
}

/// The table's bytes sum to 0, as an ACPI table's checksum makes them, and its body is the
/// database that publish-hiidb published.
fn table_holds_the_published_database(signature: &str) {
    let path = acpi_table_path(signature);
    let table = table(signature);
    let sum = table.iter().fold(0u8, |sum, &byte| sum.wrapping_add(byte));
    assert_eq!(sum, 0, "{path}: checksum");
    let database = &table[ACPI_HEADER_SIZE..];
    assert_eq!(
        crc32fast::hash(database),
        published_crc32(),
        "{path}: the body differs from the published database ({} bytes)",
        database.len()
    );
}

fn identify_detects_the_hii_backend() {
    let machine: MachineInfo = json(&["identify", "--json"]);
    assert_eq!(machine.backend, [BACKEND_HII], "identify --json backends");
}

/// Both `get` and `hii get` answer from the database of the table: the generic one only once
/// identify detects the HII backend.
fn get_returns_the_default() {
    for prefix in PREFIXES {
        let args = [prefix, &["get", NUMERIC, "--json"]].concat();
        let (question, _) = single_response(&args, BACKEND_HII);
        assert_eq!(question.answer, "18", "{args:?}");
    }
}

/// extract-db through the vendor ACPI table method writes exactly the database of the table of
/// `signature`: its body, as long, with the published CRC-32.
fn extract_db_writes_the_table_s_database(signature: &str) {
    let body = table(signature).len() - ACPI_HEADER_SIZE;
    extract_db_matches(
        &["--hii-source", "acpi"],
        &format!("/tmp/hiidb-{signature}.bin"),
        Some(body),
    );
}

/// The tests of the scenario that publishes the vendor ACPI table of each signature, in a
/// module named after it.
macro_rules! table_tests {
    ($($module:ident: $signature:literal),* $(,)?) => {$(
        mod $module {
            #[test]
            fn no_hiidb_variable_exists() {
                super::no_hiidb_variable_exists();
            }

            #[test]
            fn table_holds_the_published_database() {
                super::table_holds_the_published_database($signature);
            }

            #[test]
            fn identify_detects_the_hii_backend() {
                super::identify_detects_the_hii_backend();
            }

            #[test]
            fn get_returns_the_default() {
                super::get_returns_the_default();
            }

            #[test]
            fn extract_db_writes_the_table_s_database() {
                super::extract_db_writes_the_table_s_database($signature);
            }
        }
    )*};
}

table_tests!(qhii: "QHII", hiid: "HIID");

/// publish-hiidb installs a QHII table whose body is 64 bytes of 0x5a, no HII package list,
/// and then an HIID table that holds the published database. The acpi source moves on past
/// the invalid QHII and reads HIID.
mod two_tables {
    use super::*;

    /// The body of the invalid QHII table (publish-hiidb acpi-table-junk-qhii).
    const JUNK_BODY: [u8; 64] = [0x5a; 64];

    #[test]
    fn no_hiidb_variable_exists() {
        super::no_hiidb_variable_exists();
    }

    /// QHII passes its checksum and holds JUNK_BODY; HIID holds the published database.
    #[test]
    fn tables_are_an_invalid_qhii_and_a_valid_hiid() {
        let qhii = table("QHII");
        let sum = qhii.iter().fold(0u8, |sum, &byte| sum.wrapping_add(byte));
        assert_eq!(sum, 0, "QHII checksum");
        assert_eq!(&qhii[..4], b"QHII", "QHII signature");
        assert_eq!(&qhii[ACPI_HEADER_SIZE..], &JUNK_BODY[..], "QHII body");
        super::table_holds_the_published_database("HIID");
    }

    #[test]
    fn identify_detects_the_hii_backend() {
        super::identify_detects_the_hii_backend();
    }

    #[test]
    fn get_returns_the_default() {
        super::get_returns_the_default();
    }

    /// The vendor ACPI table method moves past the invalid QHII and reads the database from
    /// HIID, as its debug log says.
    #[test]
    fn acpi_method_reads_hiid_past_the_invalid_qhii() {
        super::extract_db_writes_the_table_s_database("HIID");

        let args = [
            "--hii-source",
            "acpi",
            "hii",
            "extract-db",
            "/tmp/hiidb-two-tables-logged.bin",
        ];
        let output = uefisettings_with_env(&args, &[("RUST_LOG", "debug")]);
        assert_eq!(output.code, Some(0), "{output:#?}");
        for line in [
            "ACPI table QHII unavailable: ",
            "HII database ACPI table: /sys/firmware/acpi/tables/HIID",
        ] {
            assert!(output.stderr.contains(line), "{line:?}: {output:#?}");
        }
    }
}
