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

//! The HII package list that `padded-strings` registers in the HII database, for
//! `tests/qemu/guest/tests/hii_global_variables.rs`: one strings package whose header holds
//! padding after Language's null terminator, covered by HdrSize and StringInfoOffset (UEFI 2.11
//! §33.3.6.1), which edk2's HiiDatabase keeps as it is and exports so.

use alloc::vec::Vec;

use uefi::guid;
use uefi::Guid;

use crate::hii_package::package_list;
use crate::hii_package::strings_package_with_header_padding;

/// The package list's GUID, which no form set uses.
const PACKAGE_LIST: Guid = guid!("103cbcec-eb2d-4f7d-b8e0-796098695eb5");

/// The bytes after Language's null terminator: not a string block type (UEFI 2.11 §33.3.6.2), so
/// reading the strings from there fails.
const PADDING: [u8; 3] = [0xAA; 3];

/// The strings, from string ID 1: the language name, then the one that the test looks for.
const STRINGS: [&str; 2] = ["English", "Strings after a padded header"];

/// The package list, as NewPackageList() takes it.
pub(crate) fn package_list_bytes() -> Vec<u8> {
    package_list(
        PACKAGE_LIST,
        &[strings_package_with_header_padding(&PADDING, STRINGS)],
    )
}
