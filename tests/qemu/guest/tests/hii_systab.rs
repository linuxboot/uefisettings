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

//! The scenarios hii-systab and, on aarch64 with kernel=vamap, hii-systab-vamap: EDK2's
//! DriverSample and `publish-hiidb.efi install-config-tables`, which installs a copy of the HII
//! database as the EFI configuration table of EFI_HII_DATABASE_PROTOCOL_GUID (UEFI 2.11
//! §33.2.11.1), in a zeroed buffer a quarter larger, and sets no `HiiDB` variable and no vendor
//! ACPI table. The configuration-table method reads the database, named with `--hii-source systab`
//! and in the automatic order, where the vendor ACPI tables and the `HiiDB` variable report their
//! sources absent first.

use std::fs;

use uefisettings_qemu_guest::acpi_table_path;
use uefisettings_qemu_guest::assert_absent;
use uefisettings_qemu_guest::driver_sample::NUMERIC;
use uefisettings_qemu_guest::json_error;
use uefisettings_qemu_guest::published_crc32;
use uefisettings_qemu_guest::single_response;
use uefisettings_qemu_guest::uefisettings;
use uefisettings_qemu_guest::uefisettings_with_env;
use uefisettings_qemu_guest::variable_data;
use uefisettings_qemu_guest::MachineInfo;
use uefisettings_qemu_guest::BACKEND_HII;
use uefisettings_qemu_guest::HIIDB_VARIABLE;
use uefisettings_qemu_guest::PREFIXES;

/// The variable in which publish-hiidb puts the length and the address of the configuration
/// table's copy, in the layout of [`HIIDB_VARIABLE`].
const HIIDB_CONFIG_TABLE_VARIABLE: &str =
    "/sys/firmware/efi/efivars/HiiDBConfigTable-de145b29-c3cd-455f-91de-a76237b67c52";

/// The flags that name the configuration-table method, and none, for the automatic order.
const SOURCES: [&[&str]; 2] = [&["--hii-source", "systab"], &[]];

/// The length of the database that publish-hiidb copied, from [`HIIDB_CONFIG_TABLE_VARIABLE`].
#[track_caller]
fn published_length() -> usize {
    let data = variable_data(HIIDB_CONFIG_TABLE_VARIABLE)
        .expect("the HiiDBConfigTable variable does not exist");
    let length = data
        .first_chunk::<4>()
        .copied()
        .map(u32::from_le_bytes)
        .expect("HiiDBConfigTable holds no length");
    usize::try_from(length).expect("a usize length")
}

/// No other method's source exists: no `HiiDB` variable, no vendor ACPI table.
#[test]
fn no_other_source_exists() {
    assert_eq!(
        variable_data(HIIDB_VARIABLE),
        None,
        "the HiiDB variable exists"
    );
    for signature in ["QHII", "HIID"] {
        assert_absent(&acpi_table_path(signature));
    }
}

/// extract-db writes exactly the published database, without the zeros after it: the length of
/// HiiDBConfigTable and the CRC-32 of HiiDBCrc32.
#[test]
fn extract_db_writes_the_published_database() {
    for (index, flags) in SOURCES.iter().enumerate() {
        let path = format!("/tmp/hiidb-{index}.bin");
        let output = uefisettings(&[flags, &["hii", "extract-db", &path][..]].concat());
        assert_eq!(output.code, Some(0), "{flags:?}: {output:#?}");

        let database =
            fs::read(&path).unwrap_or_else(|error| panic!("cannot read {path}: {error}"));
        assert_eq!(database.len(), published_length(), "{flags:?}: length");
        assert_eq!(
            crc32fast::hash(&database),
            published_crc32(),
            "{flags:?}: CRC-32"
        );
    }
}

/// Both `get` and `hii get` answer from the configuration table's database.
#[test]
fn get_returns_the_default() {
    for flags in SOURCES {
        for prefix in PREFIXES {
            let args = [flags, prefix, &["get", NUMERIC, "--json"]].concat();
            let (question, _) = single_response(&args, BACKEND_HII);
            assert_eq!(question.answer, "18", "{args:?}");
        }
    }
}

/// The option is global: it also follows the command.
#[test]
fn hii_source_follows_the_command() {
    let args = ["hii", "get", NUMERIC, "--json", "--hii-source", "systab"];
    let (question, _) = single_response(&args, BACKEND_HII);
    assert_eq!(question.answer, "18", "{args:?}");
}

/// identify finds the HII backend in the configuration table, without assuming it as where it
/// cannot tell.
#[test]
fn identify_detects_the_hii_backend() {
    let output = uefisettings_with_env(&["identify", "--json"], &[("RUST_LOG", "warn")]);
    let machine: MachineInfo = output.json(0);
    assert_eq!(machine.backend, [BACKEND_HII], "identify --json backends");
    assert!(
        !output
            .stderr
            .contains("Cannot tell whether the firmware publishes its HII database"),
        "{output:#?}"
    );
}

/// At debug level, the automatic order logs the method that gave the database.
#[test]
fn the_automatic_order_logs_the_method_at_debug_level() {
    let output = uefisettings_with_env(
        &["hii", "extract-db", "/tmp/hiidb-logged.bin"],
        &[("RUST_LOG", "debug")],
    );
    assert_eq!(output.code, Some(0), "{output:#?}");
    assert!(
        output
            .stderr
            .contains("HII database: read by the systab method"),
        "{output:#?}"
    );
}

/// Named, the vendor ACPI table method and the `HiiDB` variable method report their sources
/// absent, as errors apart.
#[test]
fn the_other_methods_report_their_sources_absent() {
    for method in ["acpi", "efivar"] {
        let error = json_error(&["--hii-source", method, "hii", "extract-db", "/tmp/none.bin"]);
        assert!(
            error
                .error_message
                .starts_with(&format!("no HII database: {method}: absent: ")),
            "{method}: {error:?}"
        );
        assert!(
            !error.error_message.contains("systab"),
            "{method}: tried only the named method: {error:?}"
        );
    }
}
