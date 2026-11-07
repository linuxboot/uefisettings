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
use std::collections::BTreeSet;
use std::ffi::CStr;
use std::ffi::FromBytesUntilNulError;
use std::num::TryFromIntError;
use std::rc::Rc;

use anyhow::anyhow;
use anyhow::bail;
use anyhow::ensure;
use anyhow::Context;
use anyhow::Result;
use binrw::io::Cursor;
use binrw::BinRead;
use log::debug;
use log::warn;

use super::package::PACKAGE_HEADER_SIZE;
use super::scsu;
use crate::parse_error::ReadParsed;

/// LANGUAGE_OFFSET is the offset of Language in a strings package: the package header, HdrSize
/// and StringInfoOffset (a u32 each), LanguageWindow (16 CHAR16) and LanguageName precede it
/// (UEFI 2.11 §33.3.6.1).
const LANGUAGE_OFFSET: u32 = PACKAGE_HEADER_SIZE + 4 + 4 + 32 + 2;

/// LANGUAGE_WINDOW_OFFSET is the offset of LanguageWindow in a strings package: the package
/// header, HdrSize and StringInfoOffset precede it (UEFI 2.11 §33.3.6.1).
const LANGUAGE_WINDOW_OFFSET: u32 = PACKAGE_HEADER_SIZE + 4 + 4;

/// MIN_HDR_SIZE is the smallest HdrSize of a strings package: the fields before Language, then
/// Language's null terminator.
const MIN_HDR_SIZE: u32 = LANGUAGE_OFFSET + 1;

/// MAX_CHARACTERS_PER_LENGTH_BYTE bounds a strings package's strings by its Length, so that no
/// caller materializes more: a string block decodes to at most one character per byte, an SCSU
/// byte in single-byte mode (UTS #6 §5 "one byte per character"), and only a DUPLICATE block,
/// 3 bytes (UEFI 2.11 §33.3.6.2.1), adds a whole earlier string. 16 per byte leaves each
/// DUPLICATE 48 characters, plus the 15 per byte that the other blocks leave unused.
const MAX_CHARACTERS_PER_LENGTH_BYTE: u64 = 16;

/// The prefix of a private-use language (Language::is_configuration).
const PRIVATE_USE_PREFIX: &[u8] = b"x-";

// UEFI 2.10 §33.3.6.1
#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
struct StringPackageHeader {
    /// Size of the entire string package header
    hdr_size: u32,
    string_info_offset: u32,
}

/// LanguageWindow (UEFI 2.11 §33.3.6.1): "the default values placed in the static and dynamic
/// windows before processing each SCSU-encoded string".
#[derive(BinRead, Debug, Clone, Copy, PartialEq, Eq)]
#[br(little)]
struct LanguageWindow([u16; 16]);

// UEFI 2.10 §33.3.6.2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum StringBlockType {
    End,
    StringScsu,
    StringScsuFont,
    StringsScsu,
    StringsScsuFont,
    StringUcs2,
    StringUcs2Font,
    StringsUcs2,
    StringsUcs2Font,
    Duplicate,
    Skip2,
    Skip1,
    Ext1,
    Ext2,
    Ext4,
    Unknown(u8),
}

impl From<u8> for StringBlockType {
    fn from(code: u8) -> Self {
        match code {
            0x00 => Self::End,
            0x10 => Self::StringScsu,
            0x11 => Self::StringScsuFont,
            0x12 => Self::StringsScsu,
            0x13 => Self::StringsScsuFont,
            0x14 => Self::StringUcs2,
            0x15 => Self::StringUcs2Font,
            0x16 => Self::StringsUcs2,
            0x17 => Self::StringsUcs2Font,
            0x20 => Self::Duplicate,
            0x21 => Self::Skip2,
            0x22 => Self::Skip1,
            0x30 => Self::Ext1,
            0x31 => Self::Ext2,
            0x32 => Self::Ext4,
            // EFI_HII_SIBT_FONT (0x40) is the BlockType2 of an EFI_HII_SIBT_EXT2 block
            code => Self::Unknown(code),
        }
    }
}

/// EFI_HII_SIBT_FONT, the BlockType2 of the EFI_HII_SIBT_EXT2 block that describes a font (UEFI
/// 2.11 §33.3.6.2.4).
const EFI_HII_SIBT_FONT: u8 = 0x40;

/// A strings package's strings, by their string identifier: an EFI_STRING_ID, a UINT16 (UEFI 2.11
/// §33.3.8.2.1). A DUPLICATE's string shares the text of the string it names.
pub(crate) type StringMap = BTreeMap<u16, Rc<str>>;

/// A strings package (UEFI 2.11 §33.3.6): the strings by id, in the language its header names.
#[derive(Debug, Clone, PartialEq, Eq)]
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

    /// Whether this is a private-use language, which UEFI 2.11 §33.2.6.1 has prefixed with "x"
    /// and makes a configuration language, such as x-UEFI-ns: its strings are keywords
    /// (§35.2.1.6), not texts to show.
    pub fn is_configuration(&self) -> bool {
        is_configuration_language(&self.0)
    }
}

/// Whether `language` starts with "x-", that of Language::is_configuration, in either case:
/// edk2-stable202211 HiiDatabaseDxe/String.c HiiCompareLanguage lowercases languages before it
/// compares them.
pub(crate) fn is_configuration_language(language: &[u8]) -> bool {
    language
        .get(..PRIVATE_USE_PREFIX.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(PRIVATE_USE_PREFIX))
}

/// The texts of the strings packages of one package list, as get, set, list-questions and
/// show-ifr show them; "the Forms Browser selects the actual text to display based on the
/// current platform language setting" (UEFI 2.11 §33.2.6). No expression reads them, so the
/// language they come in never changes a condition, READ or WRITE.
pub(crate) struct ListTexts<'a> {
    /// The package that texts come from first
    chosen: Option<&'a StringPackage>,
    /// The packages of no configuration language, in list order, which texts fall back on
    shown: Vec<&'a StringPackage>,
}

impl<'a> ListTexts<'a> {
    /// The texts of `packages`, those of one package list, from the first package of no
    /// configuration language.
    pub(crate) fn new(packages: &'a [StringPackage]) -> Self {
        let shown: Vec<&StringPackage> = packages
            .iter()
            .filter(|package| !package.language.is_configuration())
            .collect();
        Self {
            chosen: shown.first().copied(),
            shown,
        }
    }

    /// The text of the string `id`: the chosen package's, else that of the first package of no
    /// configuration language that holds it, else "" (edk2-stable202608 SetupBrowserDxe
    /// GetToken shows "!"), as a firmware may leave a string untranslated or out.
    pub(crate) fn display(&self, id: u16) -> &'a str {
        let text = self
            .chosen
            .into_iter()
            .chain(self.shown.iter().copied())
            .find_map(|package| package.strings.get(&id));
        match text {
            Some(text) => text,
            None => {
                debug!("string id: {id} not found");
                ""
            }
        }
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
    // read after HdrSize's checks, which refuse a header too short to hold it
    let language_window: LanguageWindow = Cursor::new(
        data.get(data_index(LANGUAGE_WINDOW_OFFSET)?..)
            .context("HdrSize runs past the package data")?,
    )
    .parse_le()
    .context("failed to read LanguageWindow")?;

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
    let strings = StringBlocks::new(string_information, language_window, length).read()?;

    Ok(StringPackage { language, strings })
}

/// UEFI 2.11 §33.3.6.2's string blocks of a strings package: "The blocks must be processed in
/// order, using the current string identifier (StringIdCurrent)".
struct StringBlocks<'a> {
    /// The string information from the next block on
    rest: &'a [u8],
    language_window: LanguageWindow,
    string_id_current: StringIdCurrent,
    strings: StringMap,
    /// The characters of the strings so far, each DUPLICATE's included
    characters: u64,
    /// The strings package's Length
    length: u64,
    /// The FontId of each EFI_HII_SIBT_FONT block so far
    font_ids: BTreeSet<u8>,
}

impl<'a> StringBlocks<'a> {
    fn new(string_information: &'a [u8], language_window: LanguageWindow, length: u64) -> Self {
        Self {
            rest: string_information,
            language_window,
            string_id_current: StringIdCurrent::FIRST,
            strings: StringMap::new(),
            characters: 0,
            length,
            font_ids: BTreeSet::new(),
        }
    }

    /// The strings of the blocks up to EFI_HII_SIBT_END. Fails at the first block that is
    /// unknown, cut short, that breaks a rule of its block type, or that takes the strings past
    /// MAX_CHARACTERS_PER_LENGTH_BYTE characters per byte of the package's Length.
    fn read(mut self) -> Result<StringMap> {
        loop {
            let (&code, rest) = self
                .rest
                .split_first()
                .context("failed to read a string block type")?;
            self.rest = rest;
            let block_type = StringBlockType::from(code);
            debug!("Blocktype is {:?}", block_type);

            match block_type {
                StringBlockType::End => return Ok(self.strings),
                StringBlockType::StringScsu => self.scsu_strings(1)?,
                StringBlockType::StringScsuFont => {
                    self.font_identifier("EFI_HII_SIBT_STRING_SCSU_FONT")?;
                    self.scsu_strings(1)?;
                }
                StringBlockType::StringsScsu => {
                    let count = self.string_count("EFI_HII_SIBT_STRINGS_SCSU")?;
                    self.scsu_strings(count)?;
                }
                StringBlockType::StringsScsuFont => {
                    const BLOCK: &str = "EFI_HII_SIBT_STRINGS_SCSU_FONT";
                    self.font_identifier(BLOCK)?;
                    let count = self.string_count(BLOCK)?;
                    self.scsu_strings(count)?;
                }
                StringBlockType::StringUcs2 => self.ucs2_strings("EFI_HII_SIBT_STRING_UCS2", 1)?,
                StringBlockType::StringUcs2Font => {
                    const BLOCK: &str = "EFI_HII_SIBT_STRING_UCS2_FONT";
                    self.font_identifier(BLOCK)?;
                    self.ucs2_strings(BLOCK, 1)?;
                }
                StringBlockType::StringsUcs2 => {
                    const BLOCK: &str = "EFI_HII_SIBT_STRINGS_UCS2";
                    let count = self.string_count(BLOCK)?;
                    self.ucs2_strings(BLOCK, count)?;
                }
                StringBlockType::StringsUcs2Font => {
                    const BLOCK: &str = "EFI_HII_SIBT_STRINGS_UCS2_FONT";
                    self.font_identifier(BLOCK)?;
                    let count = self.string_count(BLOCK)?;
                    self.ucs2_strings(BLOCK, count)?;
                }
                StringBlockType::Duplicate => self.duplicate()?,
                StringBlockType::Skip2 => {
                    let count = take(&mut self.rest, "EFI_HII_SIBT_SKIP2", "SkipCount")?;
                    self.string_id_current.skip(u16::from_le_bytes(count))?;
                }
                StringBlockType::Skip1 => {
                    let [count] = take(&mut self.rest, "EFI_HII_SIBT_SKIP1", "SkipCount")?;
                    self.string_id_current.skip(u16::from(count))?;
                }
                StringBlockType::Ext1 => {
                    const BLOCK: &str = "EFI_HII_SIBT_EXT1";
                    let [block_type2] = take(&mut self.rest, BLOCK, "BlockType2")?;
                    let [length] = take(&mut self.rest, BLOCK, "Length")?;
                    self.extension(BLOCK, 3, u32::from(length))?;
                    debug!("skipped an {BLOCK} block of BlockType2 {block_type2:#04x}");
                }
                StringBlockType::Ext2 => {
                    const BLOCK: &str = "EFI_HII_SIBT_EXT2";
                    let [block_type2] = take(&mut self.rest, BLOCK, "BlockType2")?;
                    let length = u16::from_le_bytes(take(&mut self.rest, BLOCK, "Length")?);
                    let fields = self.extension(BLOCK, 4, u32::from(length))?;
                    match block_type2 {
                        EFI_HII_SIBT_FONT => self.font(fields)?,
                        _ => debug!("skipped an {BLOCK} block of BlockType2 {block_type2:#04x}"),
                    }
                }
                StringBlockType::Ext4 => {
                    const BLOCK: &str = "EFI_HII_SIBT_EXT4";
                    let [block_type2] = take(&mut self.rest, BLOCK, "BlockType2")?;
                    let length = u32::from_le_bytes(take(&mut self.rest, BLOCK, "Length")?);
                    self.extension(BLOCK, 6, length)?;
                    debug!("skipped an {BLOCK} block of BlockType2 {block_type2:#04x}");
                }
                StringBlockType::Unknown(code) => bail!("unknown string block type {code:#04x}"),
            }
        }
    }

    /// Assigns `string` to `id`, unless the strings would then hold more characters than
    /// MAX_CHARACTERS_PER_LENGTH_BYTE per byte of the package's Length.
    fn insert(&mut self, id: u16, string: Rc<str>) -> Result<()> {
        // a count past u64 is past any bound
        let count = u64::try_from(string.chars().count()).unwrap_or(u64::MAX);
        self.characters = self.characters.saturating_add(count);
        ensure!(
            self.characters <= self.length.saturating_mul(MAX_CHARACTERS_PER_LENGTH_BYTE),
            "string {id} brings the strings to {} characters, past \
             {MAX_CHARACTERS_PER_LENGTH_BYTE} per byte of the strings package's Length {}",
            self.characters,
            self.length
        );
        self.strings.insert(id, string);
        Ok(())
    }

    /// The StringCount of the `block` block at the start of the rest.
    fn string_count(&mut self, block: &str) -> Result<u16> {
        Ok(u16::from_le_bytes(take(
            &mut self.rest,
            block,
            "StringCount",
        )?))
    }

    /// Reads the FontIdentifier of the `block` block at the start of the rest: "either 0 for the
    /// default font or an identifier previously specified by an EFI_HII_SIBT_FONT block" (UEFI
    /// 2.11 §33.3.6.2.8). The strings show without their fonts, which are hints (§33.2.6).
    fn font_identifier(&mut self, block: &str) -> Result<()> {
        let [font] = take(&mut self.rest, block, "FontIdentifier")?;
        ensure!(
            font == 0 || self.font_ids.contains(&font),
            "FontIdentifier {font} names no earlier EFI_HII_SIBT_FONT block"
        );
        Ok(())
    }

    /// Assigns the `count` SCSU strings at the start of the rest, each from the LanguageWindow
    /// (UEFI 2.11 §33.3.6.3.1).
    fn scsu_strings(&mut self, count: u16) -> Result<()> {
        for _ in 0..count {
            let id = self.string_id_current.assign()?;
            let (string, rest) = scsu::decode(self.rest, &self.language_window.0)
                .with_context(|| format!("failed to decode SCSU string {id}"))?;
            // the string's bytes come before the rest that decode returns
            let size = self.rest.len() - rest.len();
            // edk2-stable202608's HiiDatabase sizes an SCSU string by AsciiStrSize, up to its
            // first 0x00 byte (MdeModulePkg/Universal/HiiDatabaseDxe/String.c FindStringBlock);
            // looking within the string's own bytes reads each byte once, where looking on into
            // the blocks after it would read them again for each string
            let first_nul = self
                .rest
                .get(..size)
                .and_then(|text| text.iter().position(|&byte| byte == 0x00));
            if first_nul != size.checked_sub(1) {
                warn!(
                    "string {id}'s SCSU text does not end at its first 0x00 byte, where edk2's \
                     HiiDatabase ends it (AsciiStrSize), so the firmware may show other strings"
                );
            }
            self.insert(id, string.into())?;
            self.rest = rest;
        }
        Ok(())
    }

    /// Assigns the `count` null-terminated CHAR16 strings of the `block` block at the start of
    /// the rest.
    fn ucs2_strings(&mut self, block: &str, count: u16) -> Result<()> {
        for _ in 0..count {
            let id = self.string_id_current.assign()?;
            let (string, rest) = ucs2_string(self.rest).with_context(|| {
                format!("the StringText of an {block} block has no null terminator")
            })?;
            self.insert(id, string.into())?;
            self.rest = rest;
        }
        Ok(())
    }

    /// EFI_HII_SIBT_DUPLICATE: assigns the string of its StringId, "a previously defined string"
    /// (UEFI 2.11 §33.3.6.2.1), sharing its text.
    fn duplicate(&mut self) -> Result<()> {
        const BLOCK: &str = "EFI_HII_SIBT_DUPLICATE";
        let string_id = u16::from_le_bytes(take(&mut self.rest, BLOCK, "StringId")?);
        let id = self.string_id_current.assign()?;
        let string = Rc::clone(self.strings.get(&string_id).with_context(|| {
            format!("{BLOCK} StringId {string_id} names no previously defined string")
        })?);
        self.insert(id, string)
    }

    /// The rest of the `block` block whose Length, the size of the whole block (UEFI 2.11
    /// §33.3.6.2.3), counts `header` bytes before the rest, which this moves past.
    fn extension(&mut self, block: &str, header: u32, length: u32) -> Result<&'a [u8]> {
        let size = length.checked_sub(header).with_context(|| {
            format!("{block} Length {length} is below its {header}-byte header")
        })?;
        let (fields, rest) = usize::try_from(size)
            .ok()
            .and_then(|size| self.rest.split_at_checked(size))
            .with_context(|| format!("{block} Length {length} runs past the string information"))?;
        self.rest = rest;
        Ok(fields)
    }

    /// Reads the EFI_HII_SIBT_FONT block whose `fields` follow its EFI_HII_SIBT_EXT2 header
    /// (UEFI 2.11 §33.3.6.2.4) and keeps its FontId, which "must be unique within the string
    /// package". Bytes after its FontName, within its Length, are skipped, as edk2-stable202608's
    /// HiiDatabase moves past the block by its Length
    /// (MdeModulePkg/Universal/HiiDatabaseDxe/String.c FindStringBlock).
    fn font(&mut self, mut fields: &[u8]) -> Result<()> {
        const BLOCK: &str = "EFI_HII_SIBT_FONT";
        let [font_id] = take(&mut fields, BLOCK, "FontId")?;
        let font_size = u16::from_le_bytes(take(&mut fields, BLOCK, "FontSize")?);
        let font_style = u32::from_le_bytes(take(&mut fields, BLOCK, "FontStyle")?);
        let (font_name, after) = ucs2_string(fields)
            .with_context(|| format!("the FontName of an {BLOCK} block has no null terminator"))?;
        ensure!(
            self.font_ids.insert(font_id),
            "{BLOCK} FontId {font_id} is not unique"
        );
        debug!(
            "{BLOCK} FontId {font_id}: {font_name:?}, {font_size} pixels, style {font_style:#x}, \
             {} bytes after its FontName",
            after.len()
        );
        Ok(())
    }
}

/// The `N` bytes of the field `field` of an `block` block at the start of `bytes`, which this
/// moves past them.
fn take<const N: usize>(bytes: &mut &[u8], block: &str, field: &str) -> Result<[u8; N]> {
    let (field_bytes, rest) = bytes
        .split_first_chunk()
        .with_context(|| format!("failed to read the {field} of an {block} block"))?;
    *bytes = rest;
    Ok(*field_bytes)
}

/// The null-terminated CHAR16 string at the start of `bytes` and the bytes after its terminator;
/// None if `bytes` end first, which binrw's NullWideString reported in words that name no block.
/// It decodes as UTF-16 with U+FFFD for an unpaired surrogate, as NullWideString's Display does.
fn ucs2_string(bytes: &[u8]) -> Option<(String, &[u8])> {
    let (units, _) = bytes.as_chunks::<2>();
    let length = units.iter().position(|&unit| unit == [0, 0])?;
    let units: Vec<u16> = units
        .iter()
        .take(length)
        .map(|&unit| u16::from_le_bytes(unit))
        .collect();
    let (_, rest) = bytes.split_at_checked(2 * (length + 1))?;
    Some((String::from_utf16_lossy(&units), rest))
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A language is a configuration language if it starts with "x-" in either case, and only
    /// then.
    #[test]
    fn configuration_languages_start_with_x_in_either_case() {
        let cases = [
            ("x-UEFI-ns", true),
            ("X-UEFI-ns", true),
            ("x-", true),
            ("X-", true),
            ("en-US", false),
            ("x", false),
            ("xx-UEFI", false),
            ("-x-UEFI", false),
            ("", false),
        ];
        for (language, want) in cases {
            assert_eq!(
                package(language).language.is_configuration(),
                want,
                "language {language:?}"
            );
        }
    }

    /// A strings package of `language` without strings.
    fn package(language: &str) -> StringPackage {
        StringPackage {
            language: Language(language.as_bytes().to_vec()),
            strings: BTreeMap::new(),
        }
    }
}
