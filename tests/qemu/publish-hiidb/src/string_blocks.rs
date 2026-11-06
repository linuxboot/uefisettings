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

//! The HII package list that `string-blocks` registers in the HII database, for
//! `tests/qemu/guest/tests/hii_global_variables.rs`: a strings package of every string block type
//! of UEFI 2.11 §33.3.6.2, then one of a single string in another language. As it adds the list,
//! edk2's HiiDatabase counts the first package's string IDs and pads the second with an
//! EFI_HII_SIBT_SKIP2 block up to the first's last string ID (edk2-stable202608
//! MdeModulePkg/Universal/HiiDatabaseDxe/Database.c AdjustStringPackage), which the test compares
//! with the IDs that uefisettings reads. So the first package holds only blocks that edk2 sizes
//! as the specification does: each SCSU string ends at its first 0x00 byte, which edk2's
//! AsciiStrSize takes as its end, and it holds neither an EXT block of Length 0 nor a block of an
//! unknown type, on which edk2 loops.

use alloc::vec::Vec;

use uefi::guid;
use uefi::Guid;

use crate::hii_package::package_list;
use crate::hii_package::strings_package_with_blocks;
use crate::hii_package::ucs2;
use crate::hii_package::EFI_HII_SIBT_DUPLICATE;
use crate::hii_package::EFI_HII_SIBT_END;
use crate::hii_package::EFI_HII_SIBT_EXT1;
use crate::hii_package::EFI_HII_SIBT_EXT2;
use crate::hii_package::EFI_HII_SIBT_EXT4;
use crate::hii_package::EFI_HII_SIBT_FONT;
use crate::hii_package::EFI_HII_SIBT_SKIP1;
use crate::hii_package::EFI_HII_SIBT_SKIP2;
use crate::hii_package::EFI_HII_SIBT_STRINGS_SCSU;
use crate::hii_package::EFI_HII_SIBT_STRINGS_SCSU_FONT;
use crate::hii_package::EFI_HII_SIBT_STRINGS_UCS2;
use crate::hii_package::EFI_HII_SIBT_STRINGS_UCS2_FONT;
use crate::hii_package::EFI_HII_SIBT_STRING_SCSU;
use crate::hii_package::EFI_HII_SIBT_STRING_SCSU_FONT;
use crate::hii_package::EFI_HII_SIBT_STRING_UCS2;
use crate::hii_package::EFI_HII_SIBT_STRING_UCS2_FONT;

/// The package list's GUID, which no form set uses.
const PACKAGE_LIST: Guid = guid!("8c78a505-baa0-4c4a-869f-000000001600");

/// edk2's mLanguageWindow (edk2-stable202608 MdeModulePkg/Universal/HiiDatabaseDxe/String.c):
/// UTS #6's static windows, then its dynamic windows, from which each SCSU string starts.
const LANGUAGE_WINDOW: [u16; 16] = [
    0x0000, 0x0080, 0x0100, 0x0300, 0x2000, 0x2080, 0x2100, 0x3000, //
    0x0080, 0x00C0, 0x0400, 0x0600, 0x0900, 0x3040, 0x30A0, 0xFF00,
];

/// The FontId of the package's EFI_HII_SIBT_FONT block.
const FONT_ID: u8 = 1;
/// The default font's FontIdentifier.
const DEFAULT_FONT: u8 = 0;
/// A BlockType2 of the EFI_HII_SIBT_EXT* blocks, which UEFI 2.11 §33.3.6.2 does not define.
const UNDEFINED_BLOCK_TYPE_2: u8 = 0x7E;

/// The string blocks of the first strings package, string ID 1 first.
fn every_string_block_type() -> Vec<u8> {
    let font_name = ucs2("Sans");
    let font_length = u16::try_from(4 + 1 + 2 + 4 + font_name.len()).expect("the font fits");
    [
        // EFI_HII_SIBT_EXT2 header, then FontId, FontSize 19, FontStyle 0 and FontName
        &[EFI_HII_SIBT_EXT2, EFI_HII_SIBT_FONT][..],
        &font_length.to_le_bytes(),
        &[FONT_ID, 19, 0x00, 0x00, 0x00, 0x00, 0x00],
        &font_name,
        // string ID 1
        &[EFI_HII_SIBT_STRING_SCSU],
        b"Every string block type\0",
        // 2
        &[EFI_HII_SIBT_STRING_SCSU_FONT, FONT_ID],
        b"SCSU in a font\0",
        // 3, then 4: U+3042 and U+3044 through dynamic window 5 (SC5)
        &[EFI_HII_SIBT_STRINGS_SCSU, 0x02, 0x00],
        b"SCSU strings\0",
        &[0x15, 0x82, 0x84, 0x00],
        // 5
        &[EFI_HII_SIBT_STRINGS_SCSU_FONT, DEFAULT_FONT, 0x01, 0x00],
        b"SCSU strings in a font\0",
        // 6
        &[EFI_HII_SIBT_STRING_UCS2],
        &ucs2("UCS-2"),
        // 7
        &[EFI_HII_SIBT_STRING_UCS2_FONT, FONT_ID],
        &ucs2("UCS-2 in a font"),
        // 8, 9
        &[EFI_HII_SIBT_STRINGS_UCS2, 0x02, 0x00],
        &ucs2("UCS-2 strings"),
        &ucs2("of one block"),
        // 10
        &[EFI_HII_SIBT_STRINGS_UCS2_FONT, FONT_ID, 0x01, 0x00],
        &ucs2("UCS-2 strings in a font"),
        // 11, a copy of 6
        &[EFI_HII_SIBT_DUPLICATE, 0x06, 0x00],
        // 12-14, no strings
        &[EFI_HII_SIBT_SKIP2, 0x02, 0x00, EFI_HII_SIBT_SKIP1, 0x01],
        // blocks of Length 4, 5 and 8, which assign no string ID
        &[EFI_HII_SIBT_EXT1, UNDEFINED_BLOCK_TYPE_2, 4, 0xAA],
        &[EFI_HII_SIBT_EXT2, UNDEFINED_BLOCK_TYPE_2],
        &5u16.to_le_bytes(),
        &[0xAA],
        &[EFI_HII_SIBT_EXT4, UNDEFINED_BLOCK_TYPE_2],
        &8u32.to_le_bytes(),
        &[0xAA, 0xAA],
        // 15, the last string ID
        &[EFI_HII_SIBT_STRING_UCS2],
        &ucs2("After every string block type"),
        &[EFI_HII_SIBT_END],
    ]
    .concat()
}

/// The package list, as NewPackageList() takes it.
pub(crate) fn package_list_bytes() -> Vec<u8> {
    let second = [
        &[EFI_HII_SIBT_STRING_UCS2][..],
        &ucs2("Second strings package"),
        &[EFI_HII_SIBT_END],
    ]
    .concat();
    package_list(
        PACKAGE_LIST,
        &[
            strings_package_with_blocks(
                b"en-US\0",
                &LANGUAGE_WINDOW,
                &[],
                &every_string_block_type(),
            ),
            strings_package_with_blocks(b"fr-FR\0", &LANGUAGE_WINDOW, &[], &second),
        ],
    )
}
