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

//! The Linux boots of the Secure Boot scenarios, on the secboot firmware (tests/qemu/run.sh):
//! `setup_mode` in secboot-setup, whose variable store is a template copy, and `user_mode` and
//! `user_mode_db_append` in secboot-user, where run.sh enrolled per-run PK, KEK and db and
//! cleared SecureBootEnable. `user_mode_db_append` appends to db through efivarfs a KEK-signed
//! AUTH_2 payload of tests/qemu/auth-payload.sh, which the firmware accepts, then a copy with a
//! data byte flipped and the same append signed with db's key, which KEK lacks, and with a key
//! that no variable holds; it refuses all three with EFI_SECURITY_VIOLATION, whose errno depends
//! on the guest's kernel.

use std::fs;
use std::fs::File;
use std::io;
use std::io::Write;

use uefisettings_qemu_guest::auth2_data;
use uefisettings_qemu_guest::clear_immutable;
use uefisettings_qemu_guest::db_path;
use uefisettings_qemu_guest::global_variable;
use uefisettings_qemu_guest::require_test_vm;
use uefisettings_qemu_guest::security_violation_errno;
use uefisettings_qemu_guest::variable_data;
use uefisettings_qemu_guest::DB_APPEND;
use uefisettings_qemu_guest::DB_FOREIGN;
use uefisettings_qemu_guest::DB_TAMPERED;
use uefisettings_qemu_guest::DB_UNAUTHORIZED;
use uefisettings_qemu_guest::EFIVARS;
use uefisettings_qemu_guest::EFI_GLOBAL_VARIABLE;
use uefisettings_qemu_guest::EINVAL;

/// NV+BS+RT+AT and EFI_VARIABLE_APPEND_WRITE, the attributes that the payloads were signed
/// with.
const DB_APPEND_ATTRIBUTES: u32 = 0x67;
/// BS+RT, the attributes of AuditMode and DeployedMode in UEFI 2.11 §3.3.
const MODE_ATTRIBUTES: u32 = 0x06;

/// Writes a variable through efivarfs in one write(), as efivarfs requires, without
/// O_TRUNC: each write() is one SetVariable() of its own.
fn write_variable(path: &str, attributes: u32, data: &[u8]) -> io::Result<()> {
    let mut bytes = attributes.to_le_bytes().to_vec();
    bytes.extend_from_slice(data);
    let written = File::options()
        .write(true)
        .create(true)
        .truncate(false)
        .open(path)?
        .write(&bytes)?;
    assert_eq!(written, bytes.len(), "{path}: a short write");
    Ok(())
}

/// Checks that the firmware refuses `payload`, `what`, as a db append with
/// EFI_SECURITY_VIOLATION and leaves db's data `db_data`.
fn assert_refused(db: &str, payload: &[u8], db_data: &[u8], what: &str) {
    let error = match write_variable(db, DB_APPEND_ATTRIBUTES, payload) {
        Ok(()) => panic!("the firmware accepted {what}"),
        Err(error) => error,
    };
    assert_eq!(
        variable_data(db).as_deref(),
        Some(db_data),
        "db after {what}"
    );
    assert_eq!(
        error.raw_os_error(),
        Some(security_violation_errno()),
        "{what}: {error}"
    );
}

#[test]
fn setup_mode() {
    require_test_vm();
    assert_eq!(global_variable("SetupMode"), Some(vec![1]), "SetupMode");
    assert_eq!(global_variable("SecureBoot"), Some(vec![0]), "SecureBoot");
}

#[test]
fn user_mode() {
    require_test_vm();
    assert_eq!(global_variable("SetupMode"), Some(vec![0]), "SetupMode");
    assert_eq!(global_variable("SecureBoot"), Some(vec![0]), "SecureBoot");

    // edk2 refuses the names that §3.3 defines but it does not implement (MdeModulePkg
    // VarCheckUefiLibNullClass.c) with EFI_INVALID_PARAMETER. Every pinned guest fails the
    // write with EINVAL, which does not single that status out (SECURITY_VIOLATION_ERRNO), so
    // the result also goes to stderr itself, which libtest does not capture, and the boot's
    // test.log keeps it.
    for name in ["AuditMode", "DeployedMode"] {
        let path = format!("{EFIVARS}/{name}-{EFI_GLOBAL_VARIABLE}");
        let result = write_variable(&path, MODE_ATTRIBUTES, &[1]);
        writeln!(
            io::stderr(),
            "uefisettings-qemu-test: {name} write: {result:?}"
        )
        .expect("cannot write to stderr");
        assert_eq!(
            result.map_err(|error| error.raw_os_error()),
            Err(Some(EINVAL)),
            "{name} write"
        );
    }
}

#[test]
fn user_mode_db_append() {
    require_test_vm();
    let db = db_path();
    let before = variable_data(&db).expect("db is missing");
    clear_immutable(&db);
    let append = fs::read(DB_APPEND).expect("cannot read the db append payload");
    write_variable(&db, DB_APPEND_ATTRIBUTES, &append).expect("the KEK-signed db append");
    let appended = variable_data(&db).expect("db is missing after the append");
    let mut expected = before;
    expected.extend_from_slice(auth2_data(&append));
    assert_eq!(
        appended, expected,
        "db after the append: the old db, then the new list"
    );

    let tampered = fs::read(DB_TAMPERED).expect("cannot read the tampered payload");
    assert!(
        tampered != append,
        "the tampered payload equals the signed one"
    );
    assert_refused(&db, &tampered, &appended, "the tampered append");

    let unauthorized = fs::read(DB_UNAUTHORIZED).expect("cannot read the unauthorized payload");
    assert_refused(
        &db,
        &unauthorized,
        &appended,
        "the append signed with db's key",
    );

    let foreign = fs::read(DB_FOREIGN).expect("cannot read the foreign payload");
    assert_refused(
        &db,
        &foreign,
        &appended,
        "the append signed with a foreign key",
    );
}
