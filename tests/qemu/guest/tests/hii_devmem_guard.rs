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
//! HII database in loader data, which `/dev/mem` refuses to read: the HII commands fail
//! with an error object.

use std::fs;
use std::io;

use uefisettings_qemu_guest::json_error;
use uefisettings_qemu_guest::read_published_database;
use uefisettings_qemu_guest::require_test_vm;

#[test]
fn dev_mem_refuses_to_read_the_database() {
    let error = read_published_database().expect_err("/dev/mem served the database");
    assert_eq!(error.kind(), io::ErrorKind::PermissionDenied, "{error}");
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
