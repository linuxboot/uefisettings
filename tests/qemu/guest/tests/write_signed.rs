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

//! The Linux boots of the write-signed scenarios, on the secboot firmware (tests/qemu/run.sh),
//! which run `uefisettings variable write-signed` with the payloads of
//! tests/qemu/auth-payload.sh that run.sh puts in the initramfs: `user_mode` in
//! write-signed-user, where run.sh enrolled per-run PK, KEK and db, appends to db the KEK-signed
//! payload, which the firmware accepts, then a copy with a data byte flipped and the same append
//! signed with db's key, which KEK lacks, and with a key that no variable holds, which it refuses
//! with EFI_SECURITY_VIOLATION, then creates a variable of no policy with a KEK-signed write
//! without EFI_VARIABLE_APPEND_WRITE; `setup_mode` in write-signed-setup, whose variable store is a
//! template copy, where uefisettings refuses the db append before any write, but not the same
//! payload for another variable; `after_shell` in shell-write-signed-user, after its UEFI Shell
//! boot appended to db the KEK-signed payload of the Shell boots.

use std::fs;
use std::io;

use uefisettings_qemu_guest::assert_absent;
use uefisettings_qemu_guest::auth2_data;
use uefisettings_qemu_guest::db_path;
use uefisettings_qemu_guest::global_variable;
use uefisettings_qemu_guest::json_error;
use uefisettings_qemu_guest::require_test_vm;
use uefisettings_qemu_guest::security_violation_errno;
use uefisettings_qemu_guest::uefisettings;
use uefisettings_qemu_guest::variable_bytes;
use uefisettings_qemu_guest::variable_data;
use uefisettings_qemu_guest::DB_APPEND;
use uefisettings_qemu_guest::DB_FOREIGN;
use uefisettings_qemu_guest::DB_TAMPERED;
use uefisettings_qemu_guest::DB_UNAUTHORIZED;
use uefisettings_qemu_guest::EACCES;
use uefisettings_qemu_guest::EFIVARS;
use uefisettings_qemu_guest::EFI_IMAGE_SECURITY_DATABASE;
use uefisettings_qemu_guest::EINVAL;

/// The attributes that the payloads were signed with, but EFI_VARIABLE_APPEND_WRITE and
/// EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS: NV+BS+RT.
const ATTRIBUTES: &str = "non-volatile,bootservice-access,runtime-access";
/// The tests' vendor GUID, the owner of the certificates that run.sh enrolls and appends
/// (secboot_owner).
const OWNER: &str = "de145b29-c3cd-455f-91de-a76237b67c52";
/// A variable of OWNER that no Secure Boot policy names.
const PROBE: &str = "WriteSignedProbe";
/// A write of a text to PROBE without EFI_VARIABLE_APPEND_WRITE, signed with KEK, which creates
/// PROBE.
const PROBE_WRITE: &str = "/auth/probe-write.auth";
/// NV+BS+RT+AT, the attributes that the firmware keeps for PROBE after PROBE_WRITE.
const PROBE_ATTRIBUTES: u32 = 0x27;
/// EFI_CERT_X509_GUID, a5c059a1-94e4-4aa7-87b5-ab155c2bf072, as an EFI_GUID's bytes.
const EFI_CERT_X509_GUID: [u8; 16] = [
    0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a, 0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72,
];
/// OWNER as an EFI_GUID's bytes.
const OWNER_BYTES: [u8; 16] = [
    0x29, 0x5b, 0x14, 0xde, 0xcd, 0xc3, 0x5f, 0x45, 0x91, 0xde, 0xa7, 0x62, 0x37, 0xb6, 0x7c, 0x52,
];
/// The size of an EFI_SIGNATURE_LIST before its signatures: SignatureType, SignatureListSize,
/// SignatureHeaderSize and SignatureSize (UEFI 2.11 §32.4.1).
const SIGNATURE_LIST_HEADER_SIZE: usize = 28;

/// How a signed write changes its variable.
#[derive(Debug, Clone, Copy)]
enum Write {
    /// With EFI_VARIABLE_APPEND_WRITE: the payload's data goes after the variable's
    Append,
    /// Without it: the payload's data replaces the variable's, or creates the variable
    Replace,
}

/// The arguments of `uefisettings variable write-signed` that write the payload file `payload`
/// to the variable `name` of the vendor GUID `guid` as `write` says.
fn write_args<'a>(name: &'a str, guid: &'a str, write: Write, payload: &'a str) -> Vec<&'a str> {
    let mut args = vec![
        "variable",
        "write-signed",
        name,
        guid,
        "--attributes",
        ATTRIBUTES,
    ];
    match write {
        Write::Append => args.push("--append"),
        Write::Replace => {}
    }
    args.extend(["--payload-file", payload]);
    args
}

/// What uefisettings says of a write that the firmware refuses with EFI_SECURITY_VIOLATION, as
/// the guest's kernel reports it (src/lib/hii/efivarfs.rs SetVariableStatus).
fn security_violation() -> String {
    let errno = security_violation_errno();
    let status = match errno {
        EACCES => {
            "the firmware returned EFI_SECURITY_VIOLATION, or a security module refused the write"
        }
        EINVAL => {
            "the firmware returned EFI_INVALID_PARAMETER, EFI_UNSUPPORTED or another status that \
             Linux reports as EINVAL, or efivarfs refused the attributes or data; for \
             EFI_UNSUPPORTED, run uefisettings.efi in the UEFI Shell"
        }
        errno => panic!("no status text of errno {errno}"),
    };
    format!(
        "Failed to write to efivarfs file: {status}: {}",
        io::Error::from_raw_os_error(errno)
    )
}

/// The EFI_SIGNATURE_LISTs of `data`, the data of a signature database, each checked to hold one
/// X.509 certificate of OWNER, as run.sh enrolls and auth-payload.sh x509-esl appends them.
fn x509_signature_lists(data: &[u8]) -> Vec<&[u8]> {
    let mut lists = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let header = rest
            .get(..SIGNATURE_LIST_HEADER_SIZE)
            .unwrap_or_else(|| panic!("a signature list header cut short: {rest:02x?}"));
        let field = |offset: usize| {
            let bytes = header[offset..offset + 4].try_into().expect("4 bytes");
            usize::try_from(u32::from_le_bytes(bytes)).expect("a u32 fits usize")
        };
        let (list_size, header_size, signature_size) = (field(16), field(20), field(24));
        let (list, next) = rest.split_at_checked(list_size).unwrap_or_else(|| {
            panic!(
                "a SignatureListSize of {list_size} past the {} bytes left",
                rest.len()
            )
        });
        assert_eq!(&header[..16], EFI_CERT_X509_GUID, "SignatureType");
        assert_eq!(
            (header_size, signature_size),
            (0, list_size - SIGNATURE_LIST_HEADER_SIZE),
            "one signature without a header"
        );
        assert_eq!(
            &list[SIGNATURE_LIST_HEADER_SIZE..SIGNATURE_LIST_HEADER_SIZE + 16],
            OWNER_BYTES,
            "SignatureOwner"
        );
        lists.push(list);
        rest = next;
    }
    lists
}

/// Whether `bytes` hold `text`.
fn holds(bytes: &[u8], text: &[u8]) -> bool {
    bytes.windows(text.len()).any(|window| window == text)
}

#[test]
fn user_mode() {
    require_test_vm();
    assert_eq!(global_variable("SetupMode"), Some(vec![0]), "SetupMode");
    let db = db_path();
    let before = variable_data(&db).expect("db is missing");
    let append = fs::read(DB_APPEND).expect("cannot read the db append payload");

    let output = uefisettings(&write_args(
        "db",
        EFI_IMAGE_SECURITY_DATABASE,
        Write::Append,
        DB_APPEND,
    ));

    assert_eq!(
        (output.code, output.stdout.as_str()),
        (Some(0), ""),
        "the KEK-signed db append: {output:#?}"
    );
    let appended = variable_data(&db).expect("db is missing after the append");
    assert_eq!(
        appended,
        [&before[..], auth2_data(&append)].concat(),
        "db after the append: the old db, then the new list"
    );

    for (payload, what) in [
        (DB_TAMPERED, "the tampered append"),
        (DB_UNAUTHORIZED, "the append signed with db's key"),
        (DB_FOREIGN, "the append signed with a foreign key"),
    ] {
        let error = json_error(&write_args(
            "db",
            EFI_IMAGE_SECURITY_DATABASE,
            Write::Append,
            payload,
        ));

        assert_eq!(error.error_message, security_violation(), "{what}");
        assert_eq!(
            variable_data(&db).as_deref(),
            Some(&appended[..]),
            "db after {what}"
        );
    }

    let probe = format!("{EFIVARS}/{PROBE}-{OWNER}");
    assert_absent(&probe);
    let write = fs::read(PROBE_WRITE).expect("cannot read the payload of the probe write");

    let output = uefisettings(&write_args(PROBE, OWNER, Write::Replace, PROBE_WRITE));

    assert_eq!(
        (output.code, output.stdout.as_str()),
        (Some(0), ""),
        "the KEK-signed write of {PROBE}: {output:#?}"
    );
    assert_eq!(
        variable_bytes(&probe),
        Some([&PROBE_ATTRIBUTES.to_ne_bytes()[..], auth2_data(&write)].concat()),
        "{PROBE} after the write: its attributes, then the payload's data"
    );
}

#[test]
fn setup_mode() {
    require_test_vm();
    assert_eq!(global_variable("SetupMode"), Some(vec![1]), "SetupMode");
    let db = db_path();
    assert_absent(&db);

    let error = json_error(&write_args(
        "db",
        EFI_IMAGE_SECURITY_DATABASE,
        Write::Append,
        DB_APPEND,
    ));

    assert_eq!(
        error.error_message,
        format!(
            "EFI variable db-{EFI_IMAGE_SECURITY_DATABASE} is a Secure Boot policy variable and \
             SetupMode is 1, so the firmware would write it without checking the payload's \
             signature (UEFI 2.11 sections 3.3 and 8.2.6)"
        ),
        "the db append"
    );
    assert_absent(&db);

    // The same payload for a variable of no policy reaches the firmware, which verifies its
    // signature, made for db. The efivar file that the write creates stays, empty, where
    // efivarfs shows a variable that no write made as an empty file (Linux v6.11
    // fs/efivarfs/file.c efivarfs_file_read()), or goes, where efivarfs_file_release() removes
    // it as its last opener closes it (v6.17).
    let error = json_error(&write_args(PROBE, OWNER, Write::Append, DB_APPEND));

    assert_eq!(
        error.error_message,
        security_violation(),
        "the append to {PROBE}"
    );
    let probe = format!("{EFIVARS}/{PROBE}-{OWNER}");
    match fs::read(&probe) {
        Ok(bytes) => assert_eq!(bytes, [0_u8; 0], "{PROBE} after the append"),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => panic!("cannot read {probe}: {error}"),
    }
}

#[test]
fn after_shell() {
    require_test_vm();
    let db = variable_data(&db_path()).expect("db is missing");

    let lists = x509_signature_lists(&db);

    assert_eq!(lists.len(), 2, "the signature lists of db: {lists:02x?}");
    assert!(
        holds(lists[0], b"uefisettings test db") && !holds(lists[0], b"shell-db"),
        "the first list holds the enrolled certificate"
    );
    assert!(
        holds(lists[1], b"uefisettings test shell-db"),
        "the second list holds the certificate that the Shell boot appended"
    );
}
