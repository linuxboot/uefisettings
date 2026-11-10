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

//! A guest whose firmware runs publish-hiidb from a `Driver####` load option that puts the
//! HII database in loader data.

use std::fs;
use std::io;

use uefisettings_qemu_guest::extract_db_error;
use uefisettings_qemu_guest::is_system_ram;
use uefisettings_qemu_guest::json_error;
use uefisettings_qemu_guest::published_database;
use uefisettings_qemu_guest::require_test_vm;

#[test]
fn the_database_is_in_system_ram() {
    let address = published_database().address;
    assert!(is_system_ram(address), "{address:#x} is not System RAM");
}

#[test]
fn list_questions_fails() {
    json_error(&["hii", "list-questions", "--json"]);
}

#[test]
fn extract_db_fails() {
    require_test_vm();
    let path = "/tmp/hiidb.bin";
    let error = fs::metadata(path).expect_err("the file exists before extract-db");
    assert_eq!(error.kind(), io::ErrorKind::NotFound, "{error}");
    json_error(&["hii", "extract-db", path]);
}

/// The `HiiDB` variable method refuses extract-db and list-questions of the database, which lies
/// in no EFI runtime region, by the range check before any read: its error is that check's, not
/// the refusal of System RAM by the kernel's CONFIG_STRICT_DEVMEM, which a read would meet. So
/// it is named, and in the automatic order, which moves on past it.
#[test]
fn efivar_refuses_the_database_before_reading_it() {
    let refusal = published_database().refusal("EFI_MEMORY_RUNTIME");
    for (index, flags) in [&["--hii-source", "efivar"][..], &[]]
        .into_iter()
        .enumerate()
    {
        let path = format!("/tmp/hiidb-unread-{index}.bin");
        let extract_db = extract_db_error(flags, &path);
        let list_questions = json_error(&[flags, &["hii", "list-questions", "--json"]].concat());
        for (command, error) in [
            ("extract-db", extract_db),
            ("list-questions", list_questions),
        ] {
            assert!(
                error.error_message.contains(&format!("efivar: {refusal}")),
                "{flags:?} {command}: {error:?}"
            );
            assert!(
                !error.error_message.contains("the kernel refuses"),
                "{flags:?} {command}: read the database: {error:?}"
            );
        }
    }
}
