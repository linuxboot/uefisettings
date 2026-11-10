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

//! The encoding of the HII package lists that publish-hiidb adds to the database: package
//! lists, packages and IFR ops (UEFI 2.10 §33.3).

use alloc::vec::Vec;

use uefi::Guid;

/// The string ID of the name of a strings package's language, its first string.
const LANGUAGE_NAME: u16 = 1;

// The package types, string block types and IFR opcodes that the package lists use.
pub(crate) const EFI_HII_PACKAGE_FORMS: u8 = 0x02;
const EFI_HII_PACKAGE_STRINGS: u8 = 0x04;
const EFI_HII_PACKAGE_END: u8 = 0xDF;
pub(crate) const EFI_HII_SIBT_END: u8 = 0x00;
pub(crate) const EFI_HII_SIBT_STRING_SCSU: u8 = 0x10;
pub(crate) const EFI_HII_SIBT_STRING_SCSU_FONT: u8 = 0x11;
pub(crate) const EFI_HII_SIBT_STRINGS_SCSU: u8 = 0x12;
pub(crate) const EFI_HII_SIBT_STRINGS_SCSU_FONT: u8 = 0x13;
pub(crate) const EFI_HII_SIBT_STRING_UCS2: u8 = 0x14;
pub(crate) const EFI_HII_SIBT_STRING_UCS2_FONT: u8 = 0x15;
pub(crate) const EFI_HII_SIBT_STRINGS_UCS2: u8 = 0x16;
pub(crate) const EFI_HII_SIBT_STRINGS_UCS2_FONT: u8 = 0x17;
pub(crate) const EFI_HII_SIBT_DUPLICATE: u8 = 0x20;
pub(crate) const EFI_HII_SIBT_SKIP2: u8 = 0x21;
pub(crate) const EFI_HII_SIBT_SKIP1: u8 = 0x22;
pub(crate) const EFI_HII_SIBT_EXT1: u8 = 0x30;
pub(crate) const EFI_HII_SIBT_EXT2: u8 = 0x31;
pub(crate) const EFI_HII_SIBT_EXT4: u8 = 0x32;
pub(crate) const EFI_HII_SIBT_FONT: u8 = 0x40;
pub(crate) const EFI_IFR_FORM_OP: u8 = 0x01;
pub(crate) const EFI_IFR_ONE_OF_OP: u8 = 0x05;
pub(crate) const EFI_IFR_CHECKBOX_OP: u8 = 0x06;
pub(crate) const EFI_IFR_NUMERIC_OP: u8 = 0x07;
pub(crate) const EFI_IFR_PASSWORD_OP: u8 = 0x08;
pub(crate) const EFI_IFR_ONE_OF_OPTION_OP: u8 = 0x09;
pub(crate) const EFI_IFR_SUPPRESS_IF_OP: u8 = 0x0A;
pub(crate) const EFI_IFR_FORM_SET_OP: u8 = 0x0E;
pub(crate) const EFI_IFR_AND_OP: u8 = 0x15;
pub(crate) const EFI_IFR_DATE_OP: u8 = 0x1A;
pub(crate) const EFI_IFR_TIME_OP: u8 = 0x1B;
pub(crate) const EFI_IFR_MAP_OP: u8 = 0x22;
pub(crate) const EFI_IFR_VARSTORE_OP: u8 = 0x24;
pub(crate) const EFI_IFR_VARSTORE_EFI_OP: u8 = 0x26;
const EFI_IFR_END_OP: u8 = 0x29;
pub(crate) const EFI_IFR_GET_OP: u8 = 0x2B;
pub(crate) const EFI_IFR_SET_OP: u8 = 0x2C;
pub(crate) const EFI_IFR_READ_OP: u8 = 0x2D;
pub(crate) const EFI_IFR_WRITE_OP: u8 = 0x2E;
pub(crate) const EFI_IFR_EQUAL_OP: u8 = 0x2F;
pub(crate) const EFI_IFR_ADD_OP: u8 = 0x3A;
pub(crate) const EFI_IFR_QUESTION_REF1_OP: u8 = 0x40;
pub(crate) const EFI_IFR_UINT8_OP: u8 = 0x42;
pub(crate) const EFI_IFR_UINT16_OP: u8 = 0x43;
pub(crate) const EFI_IFR_TO_UINT_OP: u8 = 0x48;
pub(crate) const EFI_IFR_THIS_OP: u8 = 0x58;
pub(crate) const EFI_IFR_VALUE_OP: u8 = 0x5A;
/// EFI_IFR_NUMERIC_SIZE_1 | EFI_IFR_DISPLAY_UINT_DEC (UEFI 2.10 §33.3.8.3.47).
pub(crate) const UINT8_DECIMAL: u8 = 0x10;

/// A package list of `guid`: EFI_HII_PACKAGE_LIST_HEADER (UEFI 2.10 §33.3.1.2), then
/// `packages` and the End package.
pub(crate) fn package_list(guid: Guid, packages: &[Vec<u8>]) -> Vec<u8> {
    let packages = [packages.concat(), package(EFI_HII_PACKAGE_END, &[])].concat();
    let length = u32::try_from(16 + 4 + packages.len()).expect("a package list fits 4 GiB");
    [&guid.to_bytes()[..], &length.to_le_bytes(), &packages].concat()
}

/// An en-US strings package of `strings`, from string ID [`LANGUAGE_NAME`].
pub(crate) fn strings_package<'a>(strings: impl IntoIterator<Item = &'a str>) -> Vec<u8> {
    strings_package_with_header_padding(&[], strings)
}

/// [`strings_package`] whose header holds `padding` after Language's null terminator: HdrSize
/// and StringInfoOffset cover it (UEFI 2.11 §33.3.6.1).
pub(crate) fn strings_package_with_header_padding<'a>(
    padding: &[u8],
    strings: impl IntoIterator<Item = &'a str>,
) -> Vec<u8> {
    // EFI_HII_SIBT_STRING_UCS2 blocks, then EFI_HII_SIBT_END
    let blocks: Vec<u8> = strings
        .into_iter()
        .flat_map(|string| [&[EFI_HII_SIBT_STRING_UCS2][..], &ucs2(string)].concat())
        .chain([EFI_HII_SIBT_END])
        .collect();
    strings_package_with_blocks(b"en-US\0", &[0; 16], padding, &blocks)
}

/// A strings package of Language `language`, null terminator included, and LanguageWindow
/// `language_window`, whose header holds `padding` after Language and whose string blocks are
/// `blocks` (UEFI 2.11 §33.3.6).
pub(crate) fn strings_package_with_blocks(
    language: &[u8],
    language_window: &[u16; 16],
    padding: &[u8],
    blocks: &[u8],
) -> Vec<u8> {
    // EFI_HII_STRING_PACKAGE_HDR: the package header, HdrSize, StringInfoOffset,
    // LanguageWindow, LanguageName and Language, then `padding`
    let header_size = u32::try_from(4 + 4 + 4 + 32 + 2 + language.len() + padding.len())
        .expect("the header fits 4 GiB");
    let language_window: Vec<u8> = language_window
        .iter()
        .flat_map(|window| window.to_le_bytes())
        .collect();
    package(
        EFI_HII_PACKAGE_STRINGS,
        &[
            &header_size.to_le_bytes()[..],
            &header_size.to_le_bytes(),
            &language_window,
            &LANGUAGE_NAME.to_le_bytes(),
            language,
            padding,
            blocks,
        ]
        .concat(),
    )
}

/// `string` as a null-terminated CHAR16 string.
pub(crate) fn ucs2(string: &str) -> Vec<u8> {
    string
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

/// An IFR op: EFI_IFR_OP_HEADER (UEFI 2.10 §33.3.8.2.1), then `data`.
pub(crate) fn op(op_code: u8, scope: bool, data: &[u8]) -> Vec<u8> {
    let length = u8::try_from(2 + data.len())
        .ok()
        .filter(|length| length & 0x80 == 0)
        .expect("an IFR op fits its 7-bit Length");
    let scope = if scope { 0x80 } else { 0 };
    [&[op_code, scope | length][..], data].concat()
}

/// EFI_IFR_QUESTION_HEADER: Prompt, Help, QuestionId, VarStoreId, VarOffset and Flags 0.
pub(crate) fn question_header(
    prompt: u16,
    help: u16,
    id: u16,
    var_store: u16,
    offset: u16,
) -> Vec<u8> {
    [
        &prompt.to_le_bytes()[..],
        &help.to_le_bytes(),
        &id.to_le_bytes(),
        &var_store.to_le_bytes(),
        &offset.to_le_bytes(),
        &[0],
    ]
    .concat()
}

/// EFI_IFR_END, which closes a scope.
pub(crate) fn end() -> Vec<u8> {
    op(EFI_IFR_END_OP, false, &[])
}

/// An HII package of `kind`: EFI_HII_PACKAGE_HEADER (UEFI 2.10 §33.3.1.1), then `data`.
pub(crate) fn package(kind: u8, data: &[u8]) -> Vec<u8> {
    let length = u32::try_from(4 + data.len())
        .ok()
        .filter(|length| length >> 24 == 0)
        .expect("a package fits its 24-bit Length");
    [&length.to_le_bytes()[..3], &[kind], data].concat()
}
