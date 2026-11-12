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

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ffi::CStr;
use std::ffi::FromBytesUntilNulError;
use std::fmt;
use std::num::TryFromIntError;
use std::ops::RangeInclusive;
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
use super::scsu::ScsuUnit;
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

/// Unicode's private use area of the BMP, which UEFI 2.11 §33.2.6.2.1 counts as "6500
/// characters": "UEFI prohibits use of this area in a UEFI environment." The common control codes
/// lie in it (is_control_code).
pub(crate) const PRIVATE_USE_AREA: RangeInclusive<u32> = 0xE000..=0xF8FF;

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

/// The strings of a strings package that held a character that UEFI rules out, which reads as
/// U+FFFD, by id: with the CHAR16s that a UCS-2 string held, which a firmware copies as they are
/// (edk2-stable202608 SetupBrowserDxe/Setup.c GetQuestionDefault), None for an SCSU string, whose
/// block holds no CHAR16s.
pub(crate) type Replaced = BTreeMap<u16, Option<Rc<[u16]>>>;

/// A strings package (UEFI 2.11 §33.3.6): the strings by id, in the language its header names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StringPackage {
    pub language: Language,
    pub strings: StringMap,
    pub replaced: Replaced,
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
/// language such as "x-UEFI-ns" (§35.3.1). Only list-strings shows it as is, so only it needs ASCII.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
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

/// The bytes as read, escaped where they are not printable ASCII.
impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0.escape_ascii())
    }
}

/// The package of `packages` whose language edk2-stable202608 MdePkg/Library/UefiLib/UefiLib.c
/// GetBestLanguage picks for the language code `requested` in RFC 4646 mode: the first that
/// starts with the code before any ';', or with that code cut back to each '-' in turn. Unlike
/// GetBestLanguage's AsciiStrnCmp (UefiLib.c:1584), the comparison ignores ASCII case, as
/// edk2-stable202608 HiiDatabaseDxe/String.c HiiCompareLanguage does when the HII database takes
/// a language.
pub(crate) fn best_language<'a>(
    packages: &'a [StringPackage],
    requested: &str,
) -> Option<&'a StringPackage> {
    let code = requested.split(';').next().unwrap_or_default().as_bytes();
    let mut len = code.len();
    while len > 0 {
        let prefix = code.get(..len)?;
        let picked = packages.iter().find(|package| {
            package
                .language
                .0
                .get(..len)
                .is_some_and(|start| start.eq_ignore_ascii_case(prefix))
        });
        if picked.is_some() {
            return picked;
        }
        // GetBestLanguage's `for (LanguageLength--; LanguageLength > 0 &&
        // Language[LanguageLength] != '-'; LanguageLength--)`
        len = code
            .get(1..len)?
            .iter()
            .rposition(|&byte| byte == b'-')
            .map_or(0, |at| at + 1);
    }
    None
}

/// The texts of the strings packages of one package list, as get, set, list-questions and
/// show-ifr show and match them; "the Forms Browser selects the actual text to display based on
/// the current platform language setting" (UEFI 2.11 §33.2.6). No expression reads them, so the
/// language they show in never changes a condition, READ or WRITE.
pub(crate) struct ListTexts<'a> {
    /// The packages, in list order
    packages: &'a [StringPackage],
    /// The package that texts come from first
    chosen: Option<&'a StringPackage>,
    /// The packages of no configuration language, in list order, which texts fall back on
    shown: Vec<&'a StringPackage>,
}

/// Which texts a QUESTION or VALUE matches: those as stored, then, where they name nothing, those
/// that display shows. So an input that names a text as stored never selects another whose text
/// reads alike only once the reader has replaced a character of it, or display has taken out its
/// common control codes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MatchTier {
    /// The texts as stored (ListTexts::matching)
    Stored,
    /// The texts that display shows (ListTexts::matching_displayed)
    Displayed,
}

impl MatchTier {
    /// The tiers, in the order that a match tries them.
    pub(crate) const ALL: [Self; 2] = [Self::Stored, Self::Displayed];
}

/// A string of an SCSU block that held a character that UEFI rules out, which reads as U+FFFD:
/// it holds no CHAR16s that a firmware copies (ListTexts::shown_units).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ScsuRuledOut;

impl<'a> ListTexts<'a> {
    /// The texts of `packages`, those of one package list, from the package that best_language
    /// picks for the first of `requested` that it picks one for, else from the first package of
    /// no configuration language.
    pub(crate) fn new(packages: &'a [StringPackage], requested: &[&str]) -> Self {
        let shown: Vec<&StringPackage> = packages
            .iter()
            .filter(|package| !package.language.is_configuration())
            .collect();
        let chosen = requested
            .iter()
            .find_map(|requested| best_language(packages, requested))
            .or_else(|| shown.first().copied());
        Self {
            packages,
            chosen,
            shown,
        }
    }

    /// The text of the string `id`: the chosen package's, else that of the first package of no
    /// configuration language that holds it, else "" (edk2-stable202608 SetupBrowserDxe
    /// GetToken shows "!"), as a firmware may leave a string untranslated or out. Unlike
    /// shown_text, it takes the chosen package also where it is of a configuration language,
    /// as for --language x-UEFI-ns, whose prompts are the keywords. It shows a text without its
    /// common control codes (displayed), and a keyword as stored.
    pub(crate) fn display(&self, id: u16) -> Cow<'a, str> {
        match self.find(id) {
            Some((language, text)) if language.is_configuration() => Cow::Borrowed(text),
            Some((_, text)) => displayed(text),
            None => Cow::Borrowed(""),
        }
    }

    /// The text of the string `id` that display shows, as stored, else "": for a name, such as
    /// that of a name/value storage, which must match the firmware's own.
    pub(crate) fn stored(&self, id: u16) -> &'a str {
        self.find(id).map_or("", |(_, text)| text)
    }

    /// The text of the string `id` that display shows, as stored, and the language of its
    /// package: the chosen package's, else that of the first package of no configuration language
    /// that holds it.
    fn find(&self, id: u16) -> Option<(&'a Language, &'a str)> {
        let found = self
            .chosen
            .into_iter()
            .chain(self.shown.iter().copied())
            .find_map(|package| {
                package
                    .strings
                    .get(&id)
                    .map(|text| (&package.language, text.as_ref()))
            });
        if found.is_none() {
            debug!("string id: {id} not found");
        }
        found
    }

    /// The stored text of the string `id` that display shows, None unless a package of no
    /// configuration language holds it: a text that a Forms Browser can show, never a keyword.
    pub(crate) fn shown_text(&self, id: u16) -> Option<&'a str> {
        self.shown_package(id)
            .and_then(|package| package.strings.get(&id))
            .map(AsRef::as_ref)
    }

    /// The CHAR16s of the string `id` that shown_text gives, as the firmware holds them: those
    /// that it held where a character of it reads as U+FFFD (StringPackage::replaced), else those
    /// of its text; Err(ScsuRuledOut) for such an SCSU string, which held none; None as
    /// shown_text.
    pub(crate) fn shown_units(&self, id: u16) -> Option<Result<Vec<u16>, ScsuRuledOut>> {
        let package = self.shown_package(id)?;
        match package.replaced.get(&id) {
            Some(Some(units)) => Some(Ok(units.to_vec())),
            Some(None) => Some(Err(ScsuRuledOut)),
            None => package
                .strings
                .get(&id)
                .map(|text| Ok(text.encode_utf16().collect())),
        }
    }

    /// The package of the string `id` that shown_text gives.
    fn shown_package(&self, id: u16) -> Option<&'a StringPackage> {
        self.chosen
            .filter(|package| !package.language.is_configuration())
            .into_iter()
            .chain(self.shown.iter().copied())
            .find(|package| package.strings.contains_key(&id))
    }

    /// The text of the string `id` in each package of no configuration language that holds it as
    /// stored, with that package's language: the texts that QUESTION and VALUE match first
    /// (MatchTier::Stored). A text with a character that reads as U+FFFD
    /// (StringPackage::replaced) is left out, as the firmware holds another.
    pub(crate) fn matching(&self, id: u16) -> impl Iterator<Item = (&'a Language, &'a str)> + '_ {
        self.shown
            .iter()
            .filter(move |package| !package.replaced.contains_key(&id))
            .filter_map(move |package| {
                package
                    .strings
                    .get(&id)
                    .map(|text| (&package.language, text.as_ref()))
            })
    }

    /// The text of the string `id` that display shows, in each package of no configuration
    /// language that holds it, replaced characters included, without its common control codes
    /// (displayed), with that package's language: the texts that QUESTION and VALUE match where
    /// none as stored does (MatchTier::Displayed).
    pub(crate) fn matching_displayed(
        &self,
        id: u16,
    ) -> impl Iterator<Item = (&'a Language, Cow<'a, str>)> + '_ {
        self.shown.iter().filter_map(move |package| {
            package
                .strings
                .get(&id)
                .map(|text| (&package.language, displayed(text)))
        })
    }

    /// The texts of the string `id` that QUESTION and VALUE match in `tier`, with their languages.
    pub(crate) fn matching_in(
        &self,
        id: u16,
        tier: MatchTier,
    ) -> Vec<(&'a Language, Cow<'a, str>)> {
        match tier {
            MatchTier::Stored => self
                .matching(id)
                .map(|(language, text)| (language, Cow::Borrowed(text)))
                .collect(),
            MatchTier::Displayed => self.matching_displayed(id).collect(),
        }
    }

    /// The text of the string `id` in each package of a configuration language that holds it,
    /// with that package's language, in list order: a question's keywords, if `id` is its prompt
    /// (UEFI 2.11 §35.2.1.6).
    pub(crate) fn keywords(&self, id: u16) -> impl Iterator<Item = (&'a Language, &'a str)> {
        self.texts_in(id, Language::is_configuration)
    }

    /// The text of the string `id` in each package whose language `keep` takes that holds it,
    /// with that package's language, in list order.
    fn texts_in(
        &self,
        id: u16,
        keep: impl Fn(&Language) -> bool,
    ) -> impl Iterator<Item = (&'a Language, &'a str)> {
        self.packages
            .iter()
            .filter(move |package| keep(&package.language))
            .filter_map(move |package| {
                package
                    .strings
                    .get(&id)
                    .map(|text| (&package.language, text.as_ref()))
            })
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
    let (strings, replaced) =
        StringBlocks::new(string_information, &language, language_window, length).read()?;

    Ok(StringPackage {
        language,
        strings,
        replaced,
    })
}

/// UEFI 2.11 §33.3.6.2's string blocks of a strings package: "The blocks must be processed in
/// order, using the current string identifier (StringIdCurrent)".
struct StringBlocks<'a> {
    /// The string information from the next block on
    rest: &'a [u8],
    /// The strings package's Language
    language: &'a Language,
    language_window: LanguageWindow,
    string_id_current: StringIdCurrent,
    strings: StringMap,
    /// The strings so far that held a character that UEFI rules out, each DUPLICATE's included
    replaced: Replaced,
    /// The characters of the strings so far, each DUPLICATE's included
    characters: u64,
    /// The strings package's Length
    length: u64,
    /// The FontId of each EFI_HII_SIBT_FONT block so far
    font_ids: BTreeSet<u8>,
}

impl<'a> StringBlocks<'a> {
    fn new(
        string_information: &'a [u8],
        language: &'a Language,
        language_window: LanguageWindow,
        length: u64,
    ) -> Self {
        Self {
            rest: string_information,
            language,
            language_window,
            string_id_current: StringIdCurrent::FIRST,
            strings: StringMap::new(),
            replaced: Replaced::new(),
            characters: 0,
            length,
            font_ids: BTreeSet::new(),
        }
    }

    /// The strings of the blocks up to EFI_HII_SIBT_END, and those of them that held a character
    /// that UEFI rules out. Fails at the first block that is unknown, cut short, that breaks a
    /// rule of its block type, or that takes the strings past MAX_CHARACTERS_PER_LENGTH_BYTE
    /// characters per byte of the package's Length.
    fn read(mut self) -> Result<(StringMap, Replaced)> {
        loop {
            let (&code, rest) = self
                .rest
                .split_first()
                .context("failed to read a string block type")?;
            self.rest = rest;
            let block_type = StringBlockType::from(code);
            debug!("Blocktype is {:?}", block_type);

            match block_type {
                StringBlockType::End => return Ok((self.strings, self.replaced)),
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

    /// Assigns to `id` the text of `string` (string_text), warning of the first character of it
    /// that UEFI rules out of strings, and keeping such a string in `replaced`.
    fn insert_text(&mut self, id: u16, string: EncodedString<'_>) -> Result<()> {
        let (text, ruled_out) = match string {
            EncodedString::Ucs2(units) => string_text(units.iter().copied()),
            EncodedString::Scsu(units) => string_text(units.iter().copied()),
        };
        if let Some((code_point, rule)) = ruled_out {
            warn!(
                "string {id} of the \"{}\" strings package holds U+{code_point:04X}, which is \
                 {rule}: it reads as U+FFFD",
                self.language
            );
            let units = match string {
                EncodedString::Ucs2(units) => Some(Rc::from(units)),
                EncodedString::Scsu(_) => None,
            };
            self.replaced.insert(id, units);
        }
        self.insert(id, text.into())
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
            let (units, rest) = scsu::decode(self.rest, &self.language_window.0)
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
            self.insert_text(id, EncodedString::Scsu(&units))?;
            self.rest = rest;
        }
        Ok(())
    }

    /// Assigns the `count` null-terminated CHAR16 strings of the `block` block at the start of
    /// the rest.
    fn ucs2_strings(&mut self, block: &str, count: u16) -> Result<()> {
        for _ in 0..count {
            let id = self.string_id_current.assign()?;
            let (units, rest) = ucs2_string(self.rest).with_context(|| {
                format!("the StringText of an {block} block has no null terminator")
            })?;
            self.insert_text(id, EncodedString::Ucs2(&units))?;
            self.rest = rest;
        }
        Ok(())
    }

    /// EFI_HII_SIBT_DUPLICATE: assigns the string of its StringId, "a previously defined string"
    /// (UEFI 2.11 §33.3.6.2.1), sharing its text and what it held where that was replaced.
    fn duplicate(&mut self) -> Result<()> {
        const BLOCK: &str = "EFI_HII_SIBT_DUPLICATE";
        let string_id = u16::from_le_bytes(take(&mut self.rest, BLOCK, "StringId")?);
        let id = self.string_id_current.assign()?;
        let string = Rc::clone(self.strings.get(&string_id).with_context(|| {
            format!("{BLOCK} StringId {string_id} names no previously defined string")
        })?);
        if let Some(units) = self.replaced.get(&string_id) {
            let units = units.as_ref().map(Rc::clone);
            self.replaced.insert(id, units);
        }
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
        // read as the strings are, though only the debug log below shows it
        let (font_name, _) = string_text(font_name);
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

/// The CHAR16s of the null-terminated string at the start of `bytes` and the bytes after its
/// terminator; None if `bytes` end first, which binrw's NullWideString reported in words that
/// name no block.
fn ucs2_string(bytes: &[u8]) -> Option<(Vec<u16>, &[u8])> {
    let (units, _) = bytes.as_chunks::<2>();
    let length = units.iter().position(|&unit| unit == [0, 0])?;
    let units: Vec<u16> = units
        .iter()
        .take(length)
        .map(|&unit| u16::from_le_bytes(unit))
        .collect();
    let (_, rest) = bytes.split_at_checked(2 * (length + 1))?;
    Some((units, rest))
}

/// A string's characters, as its string block encodes them.
#[derive(Clone, Copy, Debug)]
enum EncodedString<'s> {
    /// The CHAR16s of a UCS-2 string
    Ucs2(&'s [u16]),
    /// The units that the SCSU decoder yields
    Scsu(&'s [ScsuUnit]),
}

/// A unit of a string's text, as its string block encodes it.
trait EncodedUnit: Copy {
    /// The code point that a warning names
    fn code_point(self) -> u32;

    /// Its character, or why UEFI rules it out of strings
    fn character(self) -> Result<char, RuledOut>;
}

/// A CHAR16 of a UCS-2 string. The common control codes lie in the private use area and between
/// 0xF000 and 0xFCFF, yet UCS-2 strings may hold them (UEFI 2.11 §33.2.6.2.4), so they are taken
/// first.
impl EncodedUnit for u16 {
    fn code_point(self) -> u32 {
        u32::from(self)
    }

    fn character(self) -> Result<char, RuledOut> {
        match is_control_code(self.code_point()) {
            // char::from_u32 refuses exactly the surrogates of the BMP, which hold no control code
            true => char::from_u32(self.code_point()).ok_or(RuledOut::Surrogate),
            false => character(self.code_point()),
        }
    }
}

/// A unit of an SCSU string. SCSU encodes control codes through 0x7F alone (UEFI 2.11
/// §33.2.6.2.4), so a character between 0xF000 and 0xFCFF, a control code's 0xFxyy form among
/// them, is ruled out (§33.3.6.3.1).
impl EncodedUnit for ScsuUnit {
    fn code_point(self) -> u32 {
        match self {
            Self::Character(code_point) => code_point,
            Self::ControlCode(code) => code.code_point(),
        }
    }

    fn character(self) -> Result<char, RuledOut> {
        match self {
            Self::Character(code_point) => character(code_point),
            Self::ControlCode(code) => code.character(),
        }
    }
}

/// Why UEFI rules a character out of strings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuledOut {
    /// 0xD800-0xDFFF: "UEFI does not support surrogate characters" (UEFI 2.11 §33.2.6.2.2)
    Surrogate,
    /// PRIVATE_USE_AREA, 0xE000-0xF8FF
    PrivateUse,
    /// 0xF900-0xFCFF, the rest of "Characters between 0xF000 and 0xFCFF should be rejected" (UEFI
    /// 2.11 §33.3.6.3.1, §33.3.6.3.2) past the private use area
    F000ToFcff,
    /// Past 0xFFFF, as an SCSU string may encode: "The UEFI specification uses UCS-2" (UEFI 2.11
    /// §33.2.6.2.2)
    OutsideUcs2,
}

impl fmt::Display for RuledOut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Surrogate => "a surrogate (UEFI 2.11 §33.2.6.2.2)",
            Self::PrivateUse => "in the private use area (UEFI 2.11 §33.2.6.2.1)",
            Self::F000ToFcff => "between 0xF000 and 0xFCFF (UEFI 2.11 §33.3.6.3.1, §33.3.6.3.2)",
            Self::OutsideUcs2 => "outside UCS-2 (UEFI 2.11 §33.2.6.2.2)",
        })
    }
}

/// Whether `code_point` is a common control code of UEFI 2.11 Table 33.3: 0xF620-0xF62B, 0xF7zz
/// or 0xF8zz (§33.2.6.2.4).
pub(crate) fn is_control_code(code_point: u32) -> bool {
    matches!(code_point, 0xF620..=0xF62B | 0xF700..=0xF8FF)
}

/// Whether `character` is a common control code (is_control_code).
pub(crate) fn is_control_character(character: char) -> bool {
    is_control_code(u32::from(character))
}

/// `text` without its common control codes, display hints that "different platforms may ignore"
/// (UEFI 2.11 §33.2.6.2.4): the text that get, set, list-questions and show-ifr show, and that
/// QUESTION and VALUE match where no text as stored names a question or option (MatchTier).
/// Texts equal only after this stripping are then equal prompts, which select resolves to the
/// first selectable match in IFR order.
fn displayed(text: &str) -> Cow<'_, str> {
    match text.contains(is_control_character) {
        true => Cow::Owned(text.replace(is_control_character, "")),
        false => Cow::Borrowed(text),
    }
}

/// The character of the code point `code_point` of a string, or why UEFI rules it out, a common
/// control code's code point included: only EncodedUnit takes control codes.
fn character(code_point: u32) -> Result<char, RuledOut> {
    match code_point {
        code_point if PRIVATE_USE_AREA.contains(&code_point) => return Err(RuledOut::PrivateUse),
        0xF900..=0xFCFF => return Err(RuledOut::F000ToFcff),
        0x1_0000.. => return Err(RuledOut::OutsideUcs2),
        _ => {}
    }
    // char::from_u32 refuses exactly the surrogates of the BMP
    char::from_u32(code_point).ok_or(RuledOut::Surrogate)
}

/// The text of the string of `units`, each its own character, and the first of them that UEFI
/// rules out, with its code point and why (EncodedUnit). One that UEFI rules out reads as
/// U+FFFD, as String::from_utf16_lossy reads an unpaired surrogate. A QUESTION or VALUE matches
/// such a text only where no text as stored names a question or option (MatchTier), and texts
/// equal after this replacement are then equal prompts, which select resolves to the first
/// selectable match in IFR order.
fn string_text<U: EncodedUnit>(
    units: impl IntoIterator<Item = U>,
) -> (String, Option<(u32, RuledOut)>) {
    let mut first_ruled_out = None;
    let text = units
        .into_iter()
        .map(|unit| {
            unit.character().unwrap_or_else(|rule| {
                first_ruled_out.get_or_insert((unit.code_point(), rule));
                char::REPLACEMENT_CHARACTER
            })
        })
        .collect();
    (text, first_ruled_out)
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

    /// best_language picks as edk2-stable202608 GetBestLanguage does in RFC 4646 mode, but
    /// ignoring ASCII case: the first language that starts with the requested code, before any
    /// ';', or with that code cut back to each '-' in turn.
    #[test]
    fn best_language_picks_as_get_best_language() {
        let packages = ["x-UEFI-ns", "en-US", "fr-FR", "zh-Hant-TW", "fr"].map(package);
        let cases = [
            ("en-US", Some("en-US")),
            ("fr-FR", Some("fr-FR")),
            ("FR-fr", Some("fr-FR")),
            ("fr", Some("fr-FR")),
            ("fr-CA", Some("fr-FR")),
            ("fr-", Some("fr-FR")),
            ("zh-Hant-HK", Some("zh-Hant-TW")),
            ("zh-Hans", Some("zh-Hant-TW")),
            ("x-UEFI", Some("x-UEFI-ns")),
            ("de-DE", None),
            ("de;fr", None),
            ("fr;de", Some("fr-FR")),
            ("", None),
            ("-", None),
        ];
        for (requested, want) in cases {
            assert_eq!(
                best_language(&packages, requested).map(|picked| picked.language.to_string()),
                want.map(str::to_string),
                "requested {requested:?}"
            );
        }
    }

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

    /// shown_text gives what display shows from a package of a display language, the chosen
    /// one first, and None where only a configuration language holds the string, even one that
    /// `requested` picks, or none does; display shows the keyword or "" there.
    #[test]
    fn shown_text_is_display_from_a_display_language_alone() {
        let with = |language: &str, strings: &[(u16, &str)]| StringPackage {
            strings: strings
                .iter()
                .map(|&(id, text)| (id, Rc::from(text)))
                .collect(),
            ..package(language)
        };
        let packages = [
            with("x-UEFI-ns", &[(1, "Keyword"), (2, "OnlyKeyword")]),
            with("en-US", &[(1, "Prompt"), (3, "English")]),
            with("fr-FR", &[(1, "Invite")]),
        ];
        let cases = [
            ("fr-FR", 1, Some("Invite"), "Invite"),
            ("fr-FR", 3, Some("English"), "English"),
            ("en-US", 1, Some("Prompt"), "Prompt"),
            ("x-UEFI", 1, Some("Prompt"), "Keyword"),
            ("x-UEFI", 2, None, "OnlyKeyword"),
            ("en-US", 2, None, ""),
            ("en-US", 4, None, ""),
        ];
        for (requested, id, shown, displayed) in cases {
            let texts = ListTexts::new(&packages, &[requested]);
            assert_eq!(
                (texts.shown_text(id), texts.display(id).as_ref()),
                (shown, displayed),
                "string {id}, requested {requested:?}"
            );
        }
    }

    /// display and matching_displayed take the common control codes out of a text, wherever they
    /// lie, but not out of a keyword, which display shows as stored, as keywords gives it, while a
    /// text that display falls back on for --language x-UEFI loses them; stored, shown_text and
    /// matching give the text as stored.
    #[test]
    fn texts_show_and_match_without_control_codes_and_keywords_with_them() {
        let packages = [
            StringPackage {
                strings: StringMap::from([(1, Rc::from("\u{F620}Keyword"))]),
                ..package("x-UEFI-ns")
            },
            StringPackage {
                strings: StringMap::from([
                    (1, Rc::from("\u{F620}Pr\u{F7AB}ompt\u{F621}")),
                    (2, Rc::from("Q\u{F7AB}")),
                ]),
                ..package("en-US")
            },
        ];
        let stored = "\u{F620}Pr\u{F7AB}ompt\u{F621}";

        let texts = ListTexts::new(&packages, &["en-US"]);
        assert_eq!(texts.display(1), "Prompt", "display");
        assert_eq!(texts.display(2), "Q", "display of a trailing control code");
        assert_eq!(texts.stored(1), stored, "stored");
        assert_eq!(texts.shown_text(1), Some(stored), "shown_text");
        let matching: Vec<(String, String)> = MatchTier::ALL
            .into_iter()
            .flat_map(|tier| texts.matching_in(1, tier))
            .map(|(language, text)| (language.to_string(), text.into_owned()))
            .collect();
        assert_eq!(
            matching,
            [
                ("en-US".to_string(), stored.to_string()),
                ("en-US".to_string(), "Prompt".to_string())
            ],
            "matching, then matching_displayed"
        );
        let keywords: Vec<(String, &str)> = texts
            .keywords(1)
            .map(|(language, text)| (language.to_string(), text))
            .collect();
        assert_eq!(
            keywords,
            [("x-UEFI-ns".to_string(), "\u{F620}Keyword")],
            "keywords"
        );

        let texts = ListTexts::new(&packages, &["x-UEFI"]);
        assert_eq!(
            texts.display(1),
            "\u{F620}Keyword",
            "display of --language x-UEFI"
        );
        assert_eq!(
            texts.display(2),
            "Q",
            "display of --language x-UEFI, falling back on en-US"
        );
    }

    /// character takes each rule up to its bounds, for a CHAR16 of a UCS-2 string the common
    /// control codes first, which lie in the private use area. An SCSU character is ruled out
    /// there, and past UCS-2: only an SCSU control code, which 0x7F introduces, is one.
    #[test]
    fn character_rules_out_each_range_up_to_its_bounds() {
        let private_use = Err(RuledOut::PrivateUse);
        // the CHAR16 or code point, then its character in a UCS-2 string and in an SCSU one
        let cases: &[(u16, _, _)] = &[
            (0xD7FF, Ok('\u{D7FF}'), Ok('\u{D7FF}')),
            (0xD800, Err(RuledOut::Surrogate), Err(RuledOut::Surrogate)),
            (0xDFFF, Err(RuledOut::Surrogate), Err(RuledOut::Surrogate)),
            (0xE000, private_use, private_use),
            (0xF61F, private_use, private_use),
            (0xF620, Ok('\u{F620}'), private_use),
            (0xF62B, Ok('\u{F62B}'), private_use),
            (0xF62C, private_use, private_use),
            (0xF6FF, private_use, private_use),
            (0xF700, Ok('\u{F700}'), private_use),
            (0xF8FF, Ok('\u{F8FF}'), private_use),
            (0xF900, Err(RuledOut::F000ToFcff), Err(RuledOut::F000ToFcff)),
            (0xFCFF, Err(RuledOut::F000ToFcff), Err(RuledOut::F000ToFcff)),
            (0xFD00, Ok('\u{FD00}'), Ok('\u{FD00}')),
            (0xFFFF, Ok('\u{FFFF}'), Ok('\u{FFFF}')),
        ];
        for &(unit, ucs2, scsu) in cases {
            assert_eq!(unit.character(), ucs2, "CHAR16 {unit:#06x}");
            let character = ScsuUnit::Character(u32::from(unit));
            assert_eq!(character.character(), scsu, "SCSU U+{unit:04X}");
        }

        for code_point in [0x1_0000, 0x10_FFFF, 0x11_0000] {
            let character = ScsuUnit::Character(code_point).character();
            assert_eq!(
                character,
                Err(RuledOut::OutsideUcs2),
                "SCSU U+{code_point:04X}"
            );
        }

        let control_codes = [
            (0xF620, '\u{F620}'),
            (0xF62B, '\u{F62B}'),
            (0xF700, '\u{F700}'),
            (0xF8FF, '\u{F8FF}'),
        ];
        for (code, want) in control_codes {
            let character = ScsuUnit::ControlCode(code).character();
            assert_eq!(character, Ok(want), "SCSU control code {code:#06x}");
        }
    }

    /// A strings package of `language` without strings.
    fn package(language: &str) -> StringPackage {
        StringPackage {
            language: Language(language.as_bytes().to_vec()),
            strings: BTreeMap::new(),
            replaced: Replaced::new(),
        }
    }
}
