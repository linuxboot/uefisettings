// (c) Meta Platforms, Inc. and affiliates. Confidential and proprietary.

use std::collections::HashMap;

use anyhow::Context;
use log::debug;
use log::error;

use anyhow::anyhow;
use anyhow::Result;
use binrw::io::Cursor;
use binrw::BinRead;
use binrw::BinReaderExt;

// UEFI Spec v2.9 Page 1807
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

// UEFI Spec v2.9 Page 1809
#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
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

pub fn handle_string_package(
    package_cursor: &mut Cursor<&Vec<u8>>,
) -> Result<HashMap<i32, String>> {
    let string_header: StringPackageHeader = package_cursor
        .read_ne()
        .context("failed to parse string package header")?;
    debug!(
        "String package language is {} and language name is {:?}",
        string_header.language.into_string(),
        string_header.language_name
    );

    // Now parse the blocks

    let mut string_id_current: i32 = 1;

    let mut string_map: HashMap<i32, String> = HashMap::new();

    loop {
        // for every block the first 8 bits are the block type

        let block_type: StringBlockType = match package_cursor.read_ne() {
            Err(why) => {
                error!("Can't read block header {}", why);
                // We can also break because if there is an error here we loose track of string_id_current
                // and want to immidiately stop parsing this string package anything beyond this wont be useful.
                return Err(why.into());
            }
            Ok(p) => p,
        };
        debug!("Blocktype is {:?}", block_type);

        match block_type {
            StringBlockType::StringUcs2 => {
                let null_str: binrw::NullWideString = match package_cursor.read_ne() {
                    Err(why) => {
                        error!("Can't read null-terminated 16-bit string: {}", why);
                        // Or we can break;
                        return Err(why.into());
                    }
                    Ok(p) => p,
                };
                debug!(
                    "Null-terminated 16-bit string is {:?} and its id is {}",
                    null_str, string_id_current
                );
                // save string here id changes later
                string_map.insert(string_id_current, null_str.into_string());
                string_id_current += 1;
            }
            StringBlockType::Skip2 => {
                let skip_count: u16 = match package_cursor.read_ne() {
                    Err(why) => {
                        error!("Can't read skip count {}", why);
                        // Or we can break;
                        return Err(why.into());
                    }
                    Ok(p) => p,
                };
                string_id_current += skip_count as i32;
                debug!("Skip count is {}", skip_count);
            }
            StringBlockType::Skip1 => {
                let skip_count: u8 = match package_cursor.read_ne() {
                    Err(why) => {
                        // Or we can break;
                        return Err(why.into());
                    }
                    Ok(p) => p,
                };
                string_id_current += skip_count as i32;
                debug!("Skip count is {}", skip_count);
            }
            StringBlockType::End => {
                break;
            }
            _ => {
                error!("Unhandled block type");
                // Or we can break;
                return Err(anyhow!("Unhandled block type"));
                // If we encounter any unhandled String Info Block Types type,
                // we cannot parse the rest of the package. This is because string_id_current
                // is changed by each block and subsiquent blocks need an updated value.

                // They're not used in any of the dumps we have encountered so far.
                // Hiilib doesn't handle the rest either.
            }
        }
    }

    Ok(string_map)
}
