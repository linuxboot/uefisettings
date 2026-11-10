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

//! The scenario hii-none: firmware that publishes its HII database in no way that the Linux build
//! reads: no vendor ACPI table, no `HiiDB` variable, and no configuration table of
//! EFI_HII_DATABASE_PROTOCOL_GUID, as OVMF and ArmVirt set PcdHiiOsRuntimeSupport to FALSE. Every
//! hii command that reads this machine's HII database fails, and its error names each method's
//! absent source, in the automatic order, or the named method's.

use uefisettings_qemu_guest::acpi_table_path;
use uefisettings_qemu_guest::assert_absent;
use uefisettings_qemu_guest::extract_db_error;
use uefisettings_qemu_guest::json;
use uefisettings_qemu_guest::json_error;
use uefisettings_qemu_guest::variable_data;
use uefisettings_qemu_guest::MachineInfo;
use uefisettings_qemu_guest::ACPI_ABSENT;
use uefisettings_qemu_guest::BACKEND_UNKNOWN;
use uefisettings_qemu_guest::EFIVAR_ABSENT;
use uefisettings_qemu_guest::HIIDB_VARIABLE;
use uefisettings_qemu_guest::SYSTAB_ABSENT;

/// No method's source exists: no vendor ACPI table, no `HiiDB` variable.
#[test]
fn no_source_exists() {
    assert_eq!(
        variable_data(HIIDB_VARIABLE),
        None,
        "the HiiDB variable exists"
    );
    for signature in ["QHII", "HIID"] {
        assert_absent(&acpi_table_path(signature));
    }
}

/// identify finds no HII backend, as every method finds its source absent.
#[test]
fn identify_finds_no_hii_backend() {
    let machine: MachineInfo = json(&["identify", "--json"]);
    assert_eq!(
        machine.backend,
        [BACKEND_UNKNOWN],
        "identify --json backends"
    );
}

/// get, set, list-questions, show-ifr, extract-db and dump-efivars fail, naming the absent source
/// of each method that the automatic order tried, all three; extract-db and dump-efivars write
/// nothing.
#[test]
fn every_hii_command_names_each_method_s_absent_source() {
    let dump = "/tmp/efivars-none";
    for args in [
        &["hii", "get", "Question", "--json"][..],
        &["hii", "set", "Question", "1", "--json"],
        &["hii", "list-questions", "--json"],
        &["hii", "show-ifr"],
        &["hii", "dump-efivars", dump],
    ] {
        let error = json_error(args);
        assert_names_each_absent_source(&error.error_message, args);
    }
    assert_absent(dump);

    let error = extract_db_error(&[], "/tmp/hiidb-none.bin");
    assert_names_each_absent_source(&error.error_message, &["hii", "extract-db"]);
}

/// Panics unless `message` names the absent source of each method, in the automatic order.
#[track_caller]
fn assert_names_each_absent_source(message: &str, args: &[&str]) {
    assert!(
        message.starts_with(&format!("no HII database: {ACPI_ABSENT}")),
        "{args:?}: {message}"
    );
    assert!(
        message.ends_with(&format!("; {EFIVAR_ABSENT}; {SYSTAB_ABSENT}")),
        "{args:?}: {message}"
    );
}

/// A named method is the only one tried, and names its absent source.
#[test]
fn a_named_method_names_its_absent_source() {
    for (method, want) in [
        ("acpi", ACPI_ABSENT),
        ("efivar", EFIVAR_ABSENT),
        ("systab", SYSTAB_ABSENT),
    ] {
        let path = format!("/tmp/hiidb-none-{method}.bin");
        let error = extract_db_error(&["--hii-source", method], &path);
        assert!(
            error
                .error_message
                .starts_with(&format!("no HII database: {want}")),
            "{method}: {error:?}"
        );
        assert_eq!(
            error.error_message.matches("absent: ").count(),
            1,
            "{method}: tried only the named method: {error:?}"
        );
    }
}
