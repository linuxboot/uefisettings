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

use anyhow::anyhow;
use anyhow::ensure;
use anyhow::Context;
use anyhow::Result;
use binrw::io::Cursor;
use binrw::BinRead;
use binrw::BinReaderExt;
use log::debug;

// UEFI 2.10 §33.3.6.1
#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
struct StringPackageHeader {
    /// Size of the entire string package header
    hdr_size: u32,
    string_info_offset: u32,
    language_window: [u16; 16], // no char16 in rust so will store like this, convert later
    language_name: u16,         // no char16 in rust so will store like this, convert later
    // I think there are some undocumented things after language which is why we can't calc sizeof
    // language via hdr_size - 42 (336 bits). Just stop reading language when the null terminated string ends.
    /// Null Terminated ASCII string like en-US
    language: binrw::NullString,
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

/// A strings package (UEFI 2.11 §33.3.6): the strings by id, in the language its header names.
pub struct StringPackage {
    pub language: Language,
    pub strings: BTreeMap<i32, String>,
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

pub fn handle_string_package(package_cursor: &mut Cursor<&Vec<u8>>) -> Result<StringPackage> {
    let string_header: StringPackageHeader = package_cursor
        .read_ne()
        .context("failed to parse string package header")?;
    let language = Language(string_header.language.0);
    debug!(
        "String package language is {} and language name is {:?}",
        language.0.escape_ascii(),
        string_header.language_name
    );

    // Now parse the blocks

    let mut string_id_current: i32 = 1;

    let mut string_map: BTreeMap<i32, String> = BTreeMap::new();

    loop {
        // for every block the first 8 bits are the block type

        // We can also break because if there is an error here we loose track of string_id_current
        // and want to immediately stop parsing this string package anything beyond this wont be useful.
        let block_type: StringBlockType = package_cursor
            .read_ne()
            .context("failed to read a string block type")?;
        debug!("Blocktype is {:?}", block_type);

        match block_type {
            StringBlockType::StringUcs2 => {
                // Or we can break;
                let null_str: binrw::NullWideString = package_cursor
                    .read_ne()
                    .context("failed to read a null-terminated 16-bit string")?;
                debug!(
                    "Null-terminated 16-bit string is {:?} and its id is {}",
                    null_str, string_id_current
                );
                // save string here id changes later
                string_map.insert(string_id_current, null_str.to_string());
                string_id_current += 1;
            }
            StringBlockType::Skip2 => {
                // Or we can break;
                let skip_count: u16 = package_cursor
                    .read_ne()
                    .context("failed to read a Skip2 count")?;
                string_id_current += skip_count as i32;
                debug!("Skip count is {}", skip_count);
            }
            StringBlockType::Skip1 => {
                // Or we can break;
                let skip_count: u8 = package_cursor
                    .read_ne()
                    .context("failed to read a Skip1 count")?;
                string_id_current += skip_count as i32;
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
