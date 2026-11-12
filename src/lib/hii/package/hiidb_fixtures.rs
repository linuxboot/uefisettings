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

use crate::hii::forms::ifr_fixtures::checkbox_at;
use crate::hii::forms::ifr_fixtures::form;
use crate::hii::forms::ifr_fixtures::form_set;
use crate::hii::forms::ifr_fixtures::form_set_with_guid;
use crate::hii::forms::ifr_fixtures::password_on;
use crate::hii::forms::ifr_fixtures::var_store_efi_of;
use crate::hii::forms::ifr_fixtures::NV_BS_RT;
use crate::hii::variables::VariableKey;

use super::*;

/// The Guid of password_store, as stored.
const PASSWORD_STORE_GUID: [u8; 16] = [0xC5; 16];
/// The Guid of other_store, as stored.
const OTHER_STORE_GUID: [u8; 16] = [0xC8; 16];
/// The GUID of the package list of password_store_hiidb, as stored.
const PASSWORD_STORE_LIST_GUID: [u8; 16] = [0xC6; 16];
/// The GUID of the package list that password_past_the_walk_hiidb puts first, as stored.
pub(crate) const PAST_THE_WALK_LIST_GUID: [u8; 16] = [0xC7; 16];

/// END_PACKAGE is an EFI_HII_PACKAGE_HEADER with Length 4 and Type
/// End (0xDF), the package that terminates a package list.
///
/// Example: get_packages stops at END_PACKAGE without returning it, so
/// it yields no packages for the PackageList that get_package_lists
/// parses from `package_list(&END_PACKAGE)`.
pub(crate) const END_PACKAGE: [u8; 4] = [0x04, 0x00, 0x00, 0xDF];

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
pub(crate) fn strings_package_header(length: u32) -> Vec<u8> {
    package_header(0x04, length)
}

/// An EFI_HII_PACKAGE_HEADER of Type `package_type` with the 24-bit Length
/// `length`.
pub(super) fn package_header(package_type: u8, length: u32) -> Vec<u8> {
    [&length.to_le_bytes()[..3], &[package_type]].concat()
}

/// en_strings_package encodes a strings package for language "en" that
/// holds string ID 1, the one-character string of the ASCII `letter`.
///
/// Example: read_db reads `[{1: "A"}]` as the strings of list
/// "11111111-1111-1111-1111-111111111111" for
/// `package_list(&[en_strings_package(b'A'), END_PACKAGE.to_vec()].concat())`.
pub(crate) fn en_strings_package(letter: u8) -> Vec<u8> {
    let strings = [
        &[0x14, letter, 0x00, 0x00, 0x00][..], // EFI_HII_SIBT_STRING_UCS2 `letter`
        &[0x00],                               // EFI_HII_SIBT_END
    ]
    .concat();
    en_strings_package_with_blocks(&strings)
}

/// An "en" strings package holding `strings`, string ID 1 first.
pub(crate) fn en_strings_package_of(strings: &[&str]) -> Vec<u8> {
    strings_package_of(b"en", strings)
}

/// A strings package of Language `language` holding `strings`, string ID 1 first.
pub(crate) fn strings_package_of(language: &[u8], strings: &[&str]) -> Vec<u8> {
    let mut blocks = Vec::new();
    for string in strings {
        blocks.push(0x14); // EFI_HII_SIBT_STRING_UCS2
        blocks.extend(string.encode_utf16().flat_map(u16::to_le_bytes));
        blocks.extend([0x00, 0x00]);
    }
    blocks.push(0x00); // EFI_HII_SIBT_END
    strings_package_with_blocks(language, &blocks)
}

/// An "en" strings package whose string blocks are `blocks`, valid or not.
pub(crate) fn en_strings_package_with_blocks(blocks: &[u8]) -> Vec<u8> {
    strings_package_with_blocks(b"en", blocks)
}

/// A strings package of Language `language`, which this adds the null terminator to, whose
/// string blocks are `blocks`, valid or not.
fn strings_package_with_blocks(language: &[u8], blocks: &[u8]) -> Vec<u8> {
    strings_package_with_header(&[language, &[0x00]].concat(), &[], blocks)
}

/// STRINGS_LANGUAGE_OFFSET is the offset of Language in a strings package: the package header,
/// HdrSize and StringInfoOffset (a u32 each), LanguageWindow (16 CHAR16) and LanguageName
/// precede it (UEFI 2.11 §33.3.6.1).
pub(super) const STRINGS_LANGUAGE_OFFSET: u32 = PACKAGE_HEADER_SIZE + 4 + 4 + 32 + 2;

/// A strings package whose header ends with `language_field`, the bytes from Language on, and
/// whose string blocks `blocks` follow `gap`: HdrSize covers `language_field`, and
/// StringInfoOffset points past `gap`.
///
/// Example: `strings_package_with_header(b"en\0\xAA", &[], blocks)` pads the header with one
/// byte after Language's null terminator.
pub(super) fn strings_package_with_header(
    language_field: &[u8],
    gap: &[u8],
    blocks: &[u8],
) -> Vec<u8> {
    let hdr_size = STRINGS_LANGUAGE_OFFSET
        + u32::try_from(language_field.len()).expect("the fixture's lengths fit a u32");
    let string_info_offset =
        hdr_size + u32::try_from(gap.len()).expect("the fixture's lengths fit a u32");
    strings_package_with_offsets(
        hdr_size,
        string_info_offset,
        &[language_field, gap, blocks].concat(),
    )
}

/// A strings package of HdrSize `hdr_size` and StringInfoOffset `string_info_offset`, valid or
/// not, whose bytes from Language on are `rest`.
///
/// Example: `strings_package_with_offsets(0, 49, b"en\0\x00")` holds Language "en" and an
/// EFI_HII_SIBT_END block, under a HdrSize of 0.
pub(super) fn strings_package_with_offsets(
    hdr_size: u32,
    string_info_offset: u32,
    rest: &[u8],
) -> Vec<u8> {
    strings_package_with_fields(&[0; 16], hdr_size, string_info_offset, rest)
}

/// An "en" strings package of LanguageWindow `language_window` whose string blocks are
/// `blocks`, valid or not.
pub(super) fn en_strings_package_with_window(
    language_window: &[u16; 16],
    blocks: &[u8],
) -> Vec<u8> {
    const LANGUAGE: &[u8] = b"en\0";
    let hdr_size = STRINGS_LANGUAGE_OFFSET
        + u32::try_from(LANGUAGE.len()).expect("the fixture's lengths fit a u32");
    strings_package_with_fields(
        language_window,
        hdr_size,
        hdr_size,
        &[LANGUAGE, blocks].concat(),
    )
}

/// A strings package of LanguageWindow `language_window`, HdrSize `hdr_size` and
/// StringInfoOffset `string_info_offset`, valid or not, whose bytes from Language on are `rest`.
fn strings_package_with_fields(
    language_window: &[u16; 16],
    hdr_size: u32,
    string_info_offset: u32,
    rest: &[u8],
) -> Vec<u8> {
    let length = STRINGS_LANGUAGE_OFFSET
        + u32::try_from(rest.len()).expect("the fixture's lengths fit a u32");
    let language_window: Vec<u8> = language_window
        .iter()
        .flat_map(|window| window.to_le_bytes())
        .collect();
    [
        &strings_package_header(length)[..],
        &hdr_size.to_le_bytes(),
        &string_info_offset.to_le_bytes(),
        &language_window,
        &1u16.to_le_bytes(), // LanguageName
        rest,
    ]
    .concat()
}

/// A form package holding an EFI_IFR_FORM_SET titled by string ID 1 and no
/// forms.
pub(crate) fn form_set_package() -> Vec<u8> {
    form_package(&[])
}

/// A form package holding an EFI_IFR_FORM_SET titled by string ID 1 that holds
/// `children`.
pub(crate) fn form_package(children: &[Vec<u8>]) -> Vec<u8> {
    form_package_with_guid([0x11; 16], children)
}

/// form_package() whose FormSet has Guid `guid`.
pub(crate) fn form_package_with_guid(guid: [u8; 16], children: &[Vec<u8>]) -> Vec<u8> {
    form_package_of(&form_set_with_guid(guid, children))
}

/// A form package holding the IFR `ifr`.
pub(crate) fn form_package_of(ifr: &[u8]) -> Vec<u8> {
    let length = PACKAGE_HEADER_SIZE + u32::try_from(ifr.len()).unwrap();
    [&package_header(0x02, length)[..], ifr].concat()
}

/// A device path package holding `device_path`.
pub(crate) fn device_path_package(device_path: &[u8]) -> Vec<u8> {
    let length = PACKAGE_HEADER_SIZE
        + u32::try_from(device_path.len()).expect("device path length fits a u32");
    [&package_header(0x08, length)[..], device_path].concat()
}

/// The variable of VarStore 1 of password_store_hiidb, of 60 bytes.
pub(crate) fn password_store() -> VariableKey {
    VariableKey {
        name: "PasswordStore".to_string(),
        guid: Guid::from(PASSWORD_STORE_GUID),
    }
}

/// The variable of VarStore 2 of the second FormSet of password_store_hiidb, of 1 byte.
pub(crate) fn other_store() -> VariableKey {
    VariableKey {
        name: "OtherStore".to_string(),
        guid: Guid::from(OTHER_STORE_GUID),
    }
}

/// The VARSTORE_EFI of password_store, VarStore 1.
fn password_store_var_store() -> Vec<u8> {
    var_store_efi_of(1, PASSWORD_STORE_GUID, "PasswordStore", NV_BS_RT, 60)
}

/// A package list of GUID `guid` holding a form package of `ifr` and the strings Q1, Q2, Q3,
/// Password and O of string IDs 1 to 5.
fn password_store_list(guid: [u8; 16], ifr: &[u8]) -> Vec<u8> {
    let packages = [
        form_package_of(ifr),
        en_strings_package_of(&["Q1", "Q2", "Q3", "Password", "O"]),
        END_PACKAGE.to_vec(),
    ];
    package_list_with_guid(guid, &packages.concat())
}

/// A HiiDB of one package list of two FormSets that declare password_store as VarStore 1: the
/// first holds `level` outside its forms, the CHECKBOX Q1 at byte 50 in form 1 and `form2` in
/// form 2; the second holds, in form 1, the CHECKBOXes O at byte 10 and Q2 at byte 5, and Q3 at
/// byte 0 of other_store, its VarStore 2.
pub(crate) fn password_store_hiidb(level: Vec<u8>, form2: Vec<u8>) -> Vec<u8> {
    let ifr = [
        form_set(&[
            password_store_var_store(),
            level,
            form(1, &[checkbox_at(1, 1, 1, 50)]),
            form(2, &[form2]),
        ]),
        form_set(&[
            password_store_var_store(),
            var_store_efi_of(2, OTHER_STORE_GUID, "OtherStore", NV_BS_RT, 1),
            form(
                1,
                &[
                    checkbox_at(5, 5, 1, 10),
                    checkbox_at(2, 2, 1, 5),
                    checkbox_at(3, 3, 2, 0),
                ],
            ),
        ]),
    ]
    .concat();
    password_store_list(PASSWORD_STORE_LIST_GUID, &ifr)
}

/// A HiiDB of a package list of PAST_THE_WALK_LIST_GUID whose form package starts with an op of
/// Length 1, where the walk for FormSets ends, before a FormSet with a PASSWORD at bytes 10 to 49
/// of password_store; then password_store_hiidb without `level` and with an empty form 2.
pub(crate) fn password_past_the_walk_hiidb() -> Vec<u8> {
    let ifr = [
        vec![0x02, 0x01],
        form_set(&[
            password_store_var_store(),
            form(1, &[password_on(4, 4, 1, 10)]),
        ]),
    ]
    .concat();
    [
        password_store_list(PAST_THE_WALK_LIST_GUID, &ifr),
        password_store_hiidb(Vec::new(), Vec::new()),
    ]
    .concat()
}
