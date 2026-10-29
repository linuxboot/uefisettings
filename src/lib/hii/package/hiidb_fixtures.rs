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

use crate::hii::forms::ifr_fixtures::form_set;

use super::*;

/// END_PACKAGE is an EFI_HII_PACKAGE_HEADER with Length 4 and Type
/// End (0xDF), the package that terminates a package list.
///
/// Example: get_packages stops at END_PACKAGE without returning it, so
/// it yields no packages for the PackageList that get_package_lists
/// parses from `package_list(&END_PACKAGE)`.
pub(crate) const END_PACKAGE: [u8; 4] = [0x04, 0x00, 0x00, 0xDF];

/// A form package holding only the IFR End op.
pub(crate) const END_ONLY_FORM_PACKAGE: [u8; 6] = [0x06, 0x00, 0x00, 0x02, 0x29, 0x02];

/// encode_package_list encodes a package list header with the given
/// GUID and PackageLength, followed by `packages`, whatever their size.
///
/// Example: `encode_package_list([0x11; 16], 24, &END_PACKAGE)` is
/// `package_list(&END_PACKAGE)`.
pub(super) fn encode_package_list(guid: [u8; 16], length: u32, packages: &[u8]) -> Vec<u8> {
    [&guid[..], &length.to_le_bytes(), packages].concat()
}

/// package_list_with_guid encodes a package list with the given GUID
/// whose PackageLength covers its header and `packages`.
///
/// Example: `package_list_with_guid([0x22; 16], &END_PACKAGE)` is a
/// package list with GUID 22222222-2222-2222-2222-222222222222 that
/// holds only the End package.
pub(crate) fn package_list_with_guid(guid: [u8; 16], packages: &[u8]) -> Vec<u8> {
    let length = PACKAGE_LIST_HEADER_SIZE + u32::try_from(packages.len()).unwrap();
    encode_package_list(guid, length, packages)
}

/// A package list with GUID `guid` that holds `en_strings_package(letter)` and
/// the End package.
pub(crate) fn en_strings_list(guid: [u8; 16], letter: u8) -> Vec<u8> {
    package_list_with_guid(
        guid,
        &[en_strings_package(letter), END_PACKAGE.to_vec()].concat(),
    )
}

/// strings_package_header encodes a bare EFI_HII_PACKAGE_HEADER of Type
/// strings (0x04) with the given 24-bit Length.
///
/// Example: `package_list(&strings_package_header(0))` holds a package
/// that is shorter than its own header.
pub(super) fn strings_package_header(length: u32) -> Vec<u8> {
    package_header(0x04, length)
}

/// An EFI_HII_PACKAGE_HEADER of Type `package_type` with the 24-bit Length
/// `length`.
fn package_header(package_type: u8, length: u32) -> Vec<u8> {
    [&length.to_le_bytes()[..3], &[package_type]].concat()
}

/// en_strings_package encodes a strings package for language "en" that
/// holds string ID 1, the one-character string of the ASCII `letter`.
///
/// Example: read_db reads `[{1: "A"}]` as the strings of list
/// "11111111-1111-1111-1111-111111111111" for
/// `package_list(&[en_strings_package(b'A'), END_PACKAGE.to_vec()].concat())`.
pub(crate) fn en_strings_package(letter: u8) -> Vec<u8> {
    let language = [
        &[0x00; 32][..],     // LanguageWindow
        &1u16.to_le_bytes(), // LanguageName
        b"en\0",             // Language
    ]
    .concat();

    let strings = [
        &[0x14, letter, 0x00, 0x00, 0x00][..], // EFI_HII_SIBT_STRING_UCS2 `letter`
        &[0x00],                               // EFI_HII_SIBT_END
    ]
    .concat();

    // HdrSize covers the package header, HdrSize and StringInfoOffset
    // (a u32 each) and `language`; the strings follow the header.
    let hdr_size = PACKAGE_HEADER_SIZE
        + u32::try_from(2 * std::mem::size_of::<u32>() + language.len()).unwrap();
    let length = hdr_size + u32::try_from(strings.len()).unwrap();

    [
        &strings_package_header(length)[..],
        &hdr_size.to_le_bytes(), // HdrSize
        &hdr_size.to_le_bytes(), // StringInfoOffset
        &language,
        &strings,
    ]
    .concat()
}

/// A form package holding an EFI_IFR_FORM_SET titled by string ID 1 and no
/// forms.
pub(crate) fn form_set_package() -> Vec<u8> {
    let ifr = form_set(&[]);
    let length = PACKAGE_HEADER_SIZE + u32::try_from(ifr.len()).unwrap();
    [package_header(0x02, length), ifr].concat()
}
