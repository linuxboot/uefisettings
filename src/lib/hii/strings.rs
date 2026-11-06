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

use std::collections::BTreeMap;
use std::ffi::CStr;
use std::ffi::FromBytesUntilNulError;
use std::num::TryFromIntError;

use anyhow::anyhow;
use anyhow::ensure;
use anyhow::Context;
use anyhow::Result;
use binrw::io::Cursor;
use binrw::BinRead;
use log::debug;
use log::warn;

use super::package::PACKAGE_HEADER_SIZE;
use crate::parse_error::ReadParsed;

/// LANGUAGE_OFFSET is the offset of Language in a strings package: the package header, HdrSize
/// and StringInfoOffset (a u32 each), LanguageWindow (16 CHAR16) and LanguageName precede it
/// (UEFI 2.11 §33.3.6.1).
const LANGUAGE_OFFSET: u32 = PACKAGE_HEADER_SIZE + 4 + 4 + 32 + 2;

/// MIN_HDR_SIZE is the smallest HdrSize of a strings package: the fields before Language, then
/// Language's null terminator.
const MIN_HDR_SIZE: u32 = LANGUAGE_OFFSET + 1;

// UEFI 2.10 §33.3.6.1
#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
struct StringPackageHeader {
    /// Size of the entire string package header
    hdr_size: u32,
    string_info_offset: u32,
}

// UEFI 2.10 §33.3.6.2
#[derive(BinRead, Debug, PartialEq)]
// no Vec of per-variant errors per block; see forms::IFROpCode
#[br(little, return_unexpected_error)]
enum StringBlockType {
    #[br(magic = 0x00u8)]
    End,
    #[br(magic = 0x10u8)]
    StringScsu,
    #[br(magic = 0x11u8)]
    StringScsuFont,
    #[br(magic = 0x12u8)]
    StringsScsu,
    #[br(magic = 0x13u8)]
    StringsScsuFont,
    #[br(magic = 0x14u8)]
    StringUcs2,
    #[br(magic = 0x15u8)]
    StringUcs2Font,
    #[br(magic = 0x16u8)]
    StringsUcs2,
    #[br(magic = 0x17u8)]
    StringsUcs2Font,
    #[br(magic = 0x20u8)]
    Duplicate,
    #[br(magic = 0x21u8)]
    Skip2,
    #[br(magic = 0x22u8)]
    Skip1,
    #[br(magic = 0x30u8)]
    Ext1,
    #[br(magic = 0x31u8)]
    Ext2,
    #[br(magic = 0x32u8)]
    Ext4,
    #[br(magic = 0x40u8)]
    Font,
    Unknown(u8),
}

/// A strings package's strings, by their string identifier: an EFI_STRING_ID, a UINT16 (UEFI 2.11
/// §33.3.8.2.1).
pub(crate) type StringMap = BTreeMap<u16, String>;

/// A strings package (UEFI 2.11 §33.3.6): the strings by id, in the language its header names.
pub struct StringPackage {
    pub language: Language,
    pub strings: StringMap,
}

/// StringIdCurrent (UEFI 2.11 §33.3.6.2): the string identifier that the next string block
/// assigns, from 1 up to 65536, one past the last string identifier, 65535.
#[derive(Clone, Copy, Debug)]
struct StringIdCurrent(u32);

impl StringIdCurrent {
    /// "set initially to one (1)"
    const FIRST: Self = Self(1);
    /// One past the last string identifier.
    const END: u32 = 1 << 16;

    /// The string identifier that a string block assigns, after which StringIdCurrent is the
    /// next one.
    fn assign(&mut self) -> Result<u16> {
        let id = u16::try_from(self.0).map_err(|_: TryFromIntError| {
            anyhow!(
                "string identifier {} is past the last string identifier 65535 \
                 (UEFI 2.11 §33.3.8.2.1)",
                self.0
            )
        })?;
        self.0 += 1;
        Ok(id)
    }

    /// Skips `count` string identifiers, as EFI_HII_SIBT_SKIP1 and EFI_HII_SIBT_SKIP2 do.
    fn skip(&mut self, count: u16) -> Result<()> {
        let next = self.0 + u32::from(count);
        ensure!(
            next <= Self::END,
            "StringIdCurrent {next} runs past 65536, one past the last string identifier 65535 \
             (UEFI 2.11 §33.3.6.2, §33.3.8.2.1)"
        );
        self.0 = next;
        Ok(())
    }
}

/// A strings package header's Language, as read: "en-US", for one, or a UEFI configuration
/// language such as "x-UEFI-ns" (§35.3.1). Only list-strings shows it, so only it needs ASCII.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Language(pub Vec<u8>);

impl Language {
    /// "The null-terminated ASCII string that specifies the language of the strings in the
    /// package" (UEFI 2.11 §33.3.6.1): fails if it is not ASCII.
    pub fn to_ascii_string(&self) -> Result<String> {
        ensure!(
            self.0.is_ascii(),
            "its Language \"{}\" is not ASCII",
            self.0.escape_ascii()
        );
        // each ASCII byte is its char
        Ok(self.0.iter().copied().map(char::from).collect())
    }
}

/// Parses the strings package `data`, the package after its EFI_HII_PACKAGE_HEADER. The offsets
/// in its header count from the start of the package, so `data` holds offset `o` at index
/// `o - PACKAGE_HEADER_SIZE` (see data_index). Fails if HdrSize, Language or StringInfoOffset
/// break UEFI 2.11 §33.3.6.1, naming the first that does, or if a string block fails to parse.
///
/// Example: for edk2's "en" packages, HdrSize and StringInfoOffset are both 49, Language is
/// bytes 46..49, and the string blocks are read from offset 49, index 45 of `data`.
pub fn handle_string_package(data: &[u8]) -> Result<StringPackage> {
    let StringPackageHeader {
        hdr_size,
        string_info_offset,
    } = Cursor::new(data)
        .parse_ne()
        .context("failed to parse string package header")?;
    let length = u64::try_from(data.len())
        .context("failed to convert the package size into u64")?
        .checked_add(u64::from(PACKAGE_HEADER_SIZE))
        .context("the package Length overflows u64")?;

    ensure!(
        hdr_size >= MIN_HDR_SIZE,
        "HdrSize {hdr_size} is below the {MIN_HDR_SIZE} bytes of the fixed header and \
         Language's null terminator (UEFI 2.11 §33.3.6.1)"
    );
    ensure!(
        u64::from(hdr_size) <= length,
        "HdrSize {hdr_size} runs past the package Length {length} (UEFI 2.11 §33.3.6.1)"
    );

    // HdrSize counts the 4-byte package header: Language is bytes 46..HdrSize; bytes after its
    // NUL are header bytes that no member defines.
    let language_field = data
        .get(data_index(LANGUAGE_OFFSET)?..data_index(hdr_size)?)
        .context("HdrSize runs past the package data")?;
    let language =
        CStr::from_bytes_until_nul(language_field).map_err(|_: FromBytesUntilNulError| {
            anyhow!(
                "Language has no null terminator within HdrSize {hdr_size} (UEFI 2.11 §33.3.6.1)"
            )
        })?;
    let language = Language(language.to_bytes().to_vec());

    ensure!(
        string_info_offset >= hdr_size,
        "StringInfoOffset {string_info_offset} is inside the {hdr_size}-byte header \
         (UEFI 2.11 §33.3.6.1)"
    );
    ensure!(
        u64::from(string_info_offset) < length,
        "StringInfoOffset {string_info_offset} is outside the package Length {length} \
         (UEFI 2.11 §33.3.6.1)"
    );
    // edk2-stable202608's HiiDatabase reads the string blocks from HdrSize
    // (MdeModulePkg/Universal/HiiDatabaseDxe/Database.c InsertStringPackage), so it may show
    // other strings
    if string_info_offset > hdr_size {
        warn!(
            "StringInfoOffset {string_info_offset} is past HdrSize {hdr_size}: the strings are \
             read from StringInfoOffset (UEFI 2.11 §33.3.6.1), while edk2's HiiDatabase reads \
             them from HdrSize, so the firmware may show other strings"
        );
    }
    let string_information = data
        .get(data_index(string_info_offset)?..)
        .context("StringInfoOffset runs past the package data")?;
    debug!(
        "String package language is {}, HdrSize {hdr_size}, StringInfoOffset {string_info_offset}",
        language.0.escape_ascii()
    );
    let mut blocks_cursor = Cursor::new(string_information);

    // Now parse the blocks

    let mut string_id_current = StringIdCurrent::FIRST;

    let mut string_map = StringMap::new();

    loop {
        // for every block the first 8 bits are the block type

        // We can also break because if there is an error here we loose track of string_id_current
        // and want to immediately stop parsing this string package anything beyond this wont be useful.
        let block_type: StringBlockType = blocks_cursor
            .parse_ne()
            .context("failed to read a string block type")?;
        debug!("Blocktype is {:?}", block_type);

        match block_type {
            StringBlockType::StringUcs2 => {
                // Or we can break;
                let null_str: binrw::NullWideString = blocks_cursor
                    .parse_ne()
                    .context("failed to read a null-terminated 16-bit string")?;
                debug!(
                    "Null-terminated 16-bit string is {:?} and its id is {}",
                    null_str, string_id_current.0
                );
                // save string here id changes later
                string_map.insert(string_id_current.assign()?, null_str.to_string());
            }
            StringBlockType::Skip2 => {
                // Or we can break;
                let skip_count: u16 = blocks_cursor
                    .parse_ne()
                    .context("failed to read a Skip2 count")?;
                string_id_current.skip(skip_count)?;
                debug!("Skip count is {}", skip_count);
            }
            StringBlockType::Skip1 => {
                // Or we can break;
                let skip_count: u8 = blocks_cursor
                    .parse_ne()
                    .context("failed to read a Skip1 count")?;
                string_id_current.skip(u16::from(skip_count))?;
                debug!("Skip count is {}", skip_count);
            }
            StringBlockType::End => {
                break;
            }
            StringBlockType::Unknown(code) => {
                return Err(anyhow!("unknown string block type {code:#04x}"));
            }
            StringBlockType::StringScsu
            | StringBlockType::StringScsuFont
            | StringBlockType::StringsScsu
            | StringBlockType::StringsScsuFont
            | StringBlockType::StringUcs2Font
            | StringBlockType::StringsUcs2
            | StringBlockType::StringsUcs2Font
            | StringBlockType::Duplicate
            | StringBlockType::Ext1
            | StringBlockType::Ext2
            | StringBlockType::Ext4
            | StringBlockType::Font => {
                // Or we can break;
                return Err(anyhow!("unhandled string block type {block_type:?}"));
                // If we encounter any unhandled String Info Block Types type,
                // we cannot parse the rest of the package. This is because string_id_current
                // is changed by each block and subsequent blocks need an updated value.

                // They're not used in any of the dumps we have encountered so far.
                // Hii lib doesn't handle the rest either.
            }
        }
    }

    Ok(StringPackage {
        language,
        strings: string_map,
    })
}

/// The index in a strings package's data, which starts after its package header, of the offset
/// `offset` from the start of the package.
///
/// Example: `data_index(49)` is 45.
fn data_index(offset: u32) -> Result<usize> {
    let index = offset
        .checked_sub(PACKAGE_HEADER_SIZE)
        .context("the offset is inside the package header")?;
    usize::try_from(index).context("failed to convert the offset into usize")
}
