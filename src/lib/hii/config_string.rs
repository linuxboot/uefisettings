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

//! UEFI 2.10 §35.2.1 configuration strings, which the HII Configuration Routing Protocol and
//! the drivers' Config Access Protocols exchange: a `<ConfigRequest>` names the settings of one
//! storage to read, and a `<ConfigResp>` carries their values. The Keyword Handler Protocol
//! names settings by keyword instead (§35.2.1.6): `<KeywordRequest>` and `<KeywordResp>`.

use std::fmt;
use std::iter::Peekable;
use std::num::NonZeroUsize;
use std::ops::Range;
use std::str::FromStr;
use std::str::Split;

use bitflags::bitflags;
use thiserror::Error;

use crate::hex_digits::hex_byte;
use crate::hex_digits::hex_bytes;
use crate::hex_digits::hex_digit;
use crate::hii::forms::DefaultId;
use crate::hii::package::DevicePath;
use crate::hii::package::Guid;

/// The names that UEFI 2.10 §35.2.1.5 reserves: "cannot be used as names in a `<ConfigElement>`".
const RESERVED_NAMES: [&str; 7] = ["GUID", "NAME", "PATH", "ALTCFG", "OFFSET", "WIDTH", "VALUE"];

/// The furthest end of a `<BlockConfig>`. Blocks lie in IFR varstores, whose Size is a UINT16
/// (UEFI 2.10 §33.3.8.3.89, §33.3.8.3.91), so no storage holds a byte at or past it, and no
/// WIDTH makes a value allocate more than 64 KiB.
const MAX_BLOCK_END: usize = 0xFFFF;

/// The length of an End node alone, the shortest device path: sizeof(EFI_DEVICE_PATH_PROTOCOL).
const MIN_DEVICE_PATH_LEN: usize = 4;

// What a value or an element should have been, for ConfigStringError
const GUID: &str = "<Guid>: 32 hex digits";
const STRING: &str = "<String>: 4 hex digits per CHAR16";
const DEVICE_PATH: &str = "a device path: 2 hex digits per byte";
const NUMBER: &str = "<Number>: hex digits";
const SIZE_NUMBER: &str = "<Number>: hex digits of a value that fits usize";
const NONZERO_NUMBER: &str = "a nonzero <Number>";
const ALT_CFG_ID: &str = "<AltCfgId>: 4 hex digits";
const CONFIG_RESP_END: &str = "the end of a <ConfigResp>";
const CONFIG_ELEMENT: &str = "<ConfigElement>: OFFSET= or <Label>=";
const DATA_FILTER: &str =
    "<DataFilter>: Buffer, Numeric[:1|:2|:4|:8], String, Boolean, Date or Time";
const NUMERIC_TYPE: &str = "Numeric[:1|:2|:4|:8]";
const KEYWORD_INFO_FILTER: &str =
    "<KeywordInfoFilter>: All, or DataType, ValueAttribute, Default and DisplayName in this order";
const KEYWORD_RESP_END: &str = "the next <KeywordResp> or the end";
const KEYWORD_REQUEST_END: &str =
    "the end of a <KeywordRequest> of PATH=, KEYWORD= and KEYWORDINFO= alone";

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum ConfigStringError {
    #[error("expected {expected}, found {found:?}")]
    Unexpected {
        expected: &'static str,
        found: String,
    },
    #[error("expected {expected}, found the end of the string")]
    Truncated { expected: &'static str },
    #[error("{name}={value:?} is not {expected}")]
    InvalidValue {
        name: String,
        value: String,
        expected: &'static str,
    },
    /// Leaves the value out, as a setting may be a password.
    #[error("{name}= holds {len} characters, not {}", NUMBER)]
    InvalidNumber { name: String, len: usize },
    #[error("{0:?} is not a <Label>: a letter or _, then letters, digits and _")]
    InvalidLabel(String),
    #[error("{0} is a reserved name, so no <Label>")]
    ReservedName(String),
    #[error(
        "{0:?} is not a <Keyword>: text without &, = or :, then optionally : and 1 to 4 digits"
    )]
    InvalidKeyword(String),
    #[error(
        "{0:?} is not a <NameSpaceId>: ASCII letters, digits and punctuation other than & and ="
    )]
    InvalidNamespace(String),
    #[error("VALUE's {digits} hex digits hold a nonzero byte past WIDTH={width}")]
    ValueWiderThanWidth { digits: usize, width: usize },
    #[error("the block at OFFSET={offset:#x} of WIDTH={width:#x} ends past every IFR varstore")]
    BlockBeyondStorage { offset: usize, width: usize },
    #[error("an <AltResp> comes before any <ConfigResp>")]
    AltRespFirst,
    #[error("an <AltResp> names another storage than its <ConfigResp>")]
    AltRespHeader,
    #[error("a <ConfigRequest> without <RequestElement>s requests every setting of its storage")]
    EmptyRequest,
    #[error("a <MultiKeywordResp> has at least one <KeywordResp>")]
    EmptyMultiKeywordResp,
    #[error(
        "a keyword string's PATH holds {0} bytes, fewer than the {} of an End node",
        MIN_DEVICE_PATH_LEN
    )]
    ShortKeywordPath(usize),
    #[error("a <Number> has at least one byte")]
    EmptyValue,
    #[error(
        "the block at OFFSET={offset:#x} of WIDTH={width:#x} is outside the {len}-byte buffer"
    )]
    OutsideBuffer {
        offset: usize,
        width: usize,
        len: usize,
    },
}

/// `<ConfigHdr>`: the storage that a request or a response routes to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfigHdr {
    pub(crate) guid: Guid,
    /// The storage's name, in CHAR16s. Empty for a NULL Name, as EDK2's HiiConstructConfigHdr
    /// writes it although `<String>` has at least one `<Char>`.
    pub(crate) name: Vec<u16>,
    /// The device path of the driver's handle. Empty for a NULL DriverHandle, as EDK2's
    /// HiiConstructConfigHdr writes it.
    pub(crate) device_path: DevicePath,
}

impl ConfigHdr {
    fn parse(elements: &mut Elements<'_>) -> Result<Self, ConfigStringError> {
        let guid_digits = elements.required_value("GUID=")?;
        let guid = hex_bytes::<Vec<u8>>(guid_digits)
            .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok())
            .ok_or_else(|| invalid_value("GUID", guid_digits, GUID))?;

        Ok(Self {
            guid: guid.into(),
            name: parse_string("NAME", elements.required_value("NAME=")?)?,
            device_path: parse_device_path(elements.required_value("PATH=")?)?,
        })
    }
}

impl fmt::Display for ConfigHdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GUID=")?;
        write_hex(f, &<[u8; 16]>::from(self.guid))?;
        f.write_str("&NAME=")?;
        write_string(f, &self.name)?;
        f.write_str("&PATH=")?;
        write_hex(f, self.device_path.as_ref())
    }
}

/// `<Label>`: the C label that names a setting of name/value storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Label(String);

impl TryFrom<&str> for Label {
    type Error = ConfigStringError;

    fn try_from(text: &str) -> Result<Self, Self::Error> {
        let mut chars = text.chars();
        let starts_label = chars
            .next()
            .is_some_and(|first| first.is_ascii_alphabetic() || first == '_');
        let continues_label =
            chars.all(|character| character.is_ascii_alphanumeric() || character == '_');
        if !starts_label || !continues_label {
            return Err(ConfigStringError::InvalidLabel(text.to_owned()));
        }
        if RESERVED_NAMES.contains(&text) {
            return Err(ConfigStringError::ReservedName(text.to_owned()));
        }
        Ok(Self(text.to_owned()))
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// `<BlockName>`: `width` bytes at `offset` of buffer storage, at most up to MAX_BLOCK_END.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct BlockName {
    offset: usize,
    width: NonZeroUsize,
}

impl BlockName {
    pub(crate) fn new(offset: usize, width: NonZeroUsize) -> Result<Self, ConfigStringError> {
        check_block_end(offset, width)?;
        Ok(Self { offset, width })
    }

    pub(crate) fn offset(&self) -> usize {
        self.offset
    }

    pub(crate) fn width(&self) -> NonZeroUsize {
        self.width
    }
}

impl fmt::Display for BlockName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "OFFSET={:04x}&WIDTH={:04x}", self.offset, self.width)
    }
}

/// `<RequestElement>`: a block of buffer storage or a setting of name/value storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RequestElement {
    Block(BlockName),
    Label(Label),
}

impl fmt::Display for RequestElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Block(block) => block.fmt(f),
            Self::Label(label) => label.fmt(f),
        }
    }
}

/// `<ConfigRequest>` with at least one `<RequestElement>`. A bare `<ConfigHdr>` would ask for every
/// setting: "if a ConfigHdr is passed in with no request elements, all of the settings being
/// abstracted for that particular ConfigHdr reference will be returned" (UEFI 2.10 §35.5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfigRequest {
    header: ConfigHdr,
    elements: Vec<RequestElement>,
}

impl ConfigRequest {
    pub(crate) fn new(
        header: ConfigHdr,
        elements: Vec<RequestElement>,
    ) -> Result<Self, ConfigStringError> {
        if elements.is_empty() {
            return Err(ConfigStringError::EmptyRequest);
        }
        Ok(Self { header, elements })
    }
}

impl fmt::Display for ConfigRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.header.fmt(f)?;
        self.elements
            .iter()
            .try_for_each(|element| write!(f, "&{element}"))
    }
}

/// `<BlockConfig>`: the bytes of a block of buffer storage, at most up to MAX_BLOCK_END.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BlockConfig {
    offset: usize,
    value: Vec<u8>,
}

impl BlockConfig {
    pub(crate) fn new(offset: usize, value: Vec<u8>) -> Result<Self, ConfigStringError> {
        let width = NonZeroUsize::new(value.len()).ok_or(ConfigStringError::EmptyValue)?;
        check_block_end(offset, width)?;
        Ok(Self { offset, value })
    }

    pub(crate) fn offset(&self) -> usize {
        self.offset
    }

    /// The block's bytes, as they lie in the buffer.
    pub(crate) fn value(&self) -> &[u8] {
        &self.value
    }

    /// The bytes of the buffer that the block covers, which end at most at MAX_BLOCK_END.
    pub(crate) fn range(&self) -> Range<usize> {
        self.offset..self.offset + self.value.len()
    }

    /// Copies the block into `buffer`, as ConfigToBlock does (UEFI 2.10 §35.4.6).
    pub(crate) fn write_to(&self, buffer: &mut [u8]) -> Result<(), ConfigStringError> {
        let outside = ConfigStringError::OutsideBuffer {
            offset: self.offset,
            width: self.value.len(),
            len: buffer.len(),
        };
        let target = self
            .offset
            .checked_add(self.value.len())
            .and_then(|end| buffer.get_mut(self.offset..end))
            .ok_or(outside)?;
        target.copy_from_slice(&self.value);
        Ok(())
    }

    /// Parses OFFSET=`offset_digits`, then WIDTH= and VALUE= from `elements`.
    ///
    /// VALUE's digits come most significant first and the buffer holds its least significant
    /// byte first: UEFI 2.10 §35.4.6's example writes VALUE=AA55 as 55 AA, against the
    /// §35.2.1.5 note that a `<Number>` lists bytes "in the same order as the buffer bytes reside
    /// in memory". EDK2's GetValueOfNumber reads them that way, and BlockToConfig's "%x" (UEFI
    /// 2.10 §35.4.5) drops leading zeros, so a short VALUE fills its WIDTH with zeros.
    fn parse(offset_digits: &str, elements: &mut Elements<'_>) -> Result<Self, ConfigStringError> {
        let offset = parse_size("OFFSET", offset_digits)?;
        let width_digits = elements.required_value("WIDTH=")?;
        let width = NonZeroUsize::new(parse_size("WIDTH", width_digits)?)
            .ok_or_else(|| invalid_value("WIDTH", width_digits, NONZERO_NUMBER))?;
        check_block_end(offset, width)?;

        let value_digits = elements.required_value("VALUE=")?;
        let mut value =
            hex_number(value_digits).ok_or_else(|| invalid_number("VALUE", value_digits))?;
        let beyond_width = value.get(width.get()..);
        if beyond_width.is_some_and(|bytes| bytes.iter().any(|byte| *byte != 0)) {
            return Err(ConfigStringError::ValueWiderThanWidth {
                digits: value_digits.len(),
                width: width.get(),
            });
        }
        value.resize(width.get(), 0);
        Ok(Self { offset, value })
    }
}

impl fmt::Display for BlockConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "OFFSET={:04x}&WIDTH={:04x}&VALUE=",
            self.offset,
            self.value.len()
        )?;
        // most significant first, as parse reads VALUE
        write_hex(f, self.value.iter().rev())
    }
}

/// `<NvConfig>`: a setting of name/value storage. Its value is a `<String>` for a string question
/// and a `<Number>` else, as EDK2's SetupBrowserDxe BufferToValue reads it; both are hex digits.
/// It is empty for an empty string, as EDK2's DriverSample ExtractConfig and SetupBrowserDxe
/// SetQuestionValue write it, although `<String>` has at least one `<Char>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NvConfig {
    label: Label,
    value: String,
}

impl NvConfig {
    pub(crate) fn new(label: Label, value: &str) -> Result<Self, ConfigStringError> {
        if !value.bytes().all(|digit| digit.is_ascii_hexdigit()) {
            return Err(invalid_number(&label.0, value));
        }
        Ok(Self {
            label,
            value: value.to_ascii_lowercase(),
        })
    }

    pub(crate) fn label(&self) -> &Label {
        &self.label
    }

    /// The value's hex digits, in lowercase.
    pub(crate) fn value(&self) -> &str {
        &self.value
    }

    /// The value as a `<Number>`, least significant byte first, as EDK2's SetupBrowserDxe
    /// BufferToValue reads that of a question that holds no string: None if it is empty.
    pub(crate) fn number(&self) -> Option<Number> {
        hex_number(&self.value).map(Number)
    }
}

impl fmt::Display for NvConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}={}", self.label, self.value)
    }
}

/// `<ConfigElement>`
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConfigElement {
    Block(BlockConfig),
    Nv(NvConfig),
}

impl ConfigElement {
    fn parse(element: &str, elements: &mut Elements<'_>) -> Result<Self, ConfigStringError> {
        let Some((name, value)) = element.split_once('=') else {
            return Err(ConfigStringError::Unexpected {
                expected: CONFIG_ELEMENT,
                found: element.to_owned(),
            });
        };
        match name {
            "OFFSET" => BlockConfig::parse(value, elements).map(Self::Block),
            label => NvConfig::new(Label::try_from(label)?, value).map(Self::Nv),
        }
    }
}

impl fmt::Display for ConfigElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Block(config) => config.fmt(f),
            Self::Nv(config) => config.fmt(f),
        }
    }
}

/// `<ConfigResp>`: the current values of settings of one storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfigResp {
    pub(crate) header: ConfigHdr,
    pub(crate) body: Vec<ConfigElement>,
}

impl FromStr for ConfigResp {
    type Err = ConfigStringError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let mut elements = Elements::new(text);
        let resp = Self {
            header: ConfigHdr::parse(&mut elements)?,
            body: parse_body(&mut elements)?,
        };
        match elements.next() {
            None => Ok(resp),
            Some(element) => Err(ConfigStringError::Unexpected {
                expected: CONFIG_RESP_END,
                found: element.to_owned(),
            }),
        }
    }
}

impl fmt::Display for ConfigResp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.header.fmt(f)?;
        write_body(f, &self.body)
    }
}

/// `<AltResp>`: the values of settings in one of the storage's alternative configurations, such
/// as a default store, which ALTCFG names by its default ID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AltResp {
    pub(crate) alt_cfg_id: DefaultId,
    pub(crate) body: Vec<ConfigElement>,
}

/// `<ConfigAltResp>`: a `<ConfigResp>` and the `<AltResp>`s that follow it, each with the
/// `<ConfigResp>`'s `<ConfigHdr>`, as EDK2's GenerateAltConfigResp writes them and
/// MergeDefaultString finds them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfigAltResp {
    pub(crate) resp: ConfigResp,
    pub(crate) alternates: Vec<AltResp>,
}

impl fmt::Display for ConfigAltResp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.resp.fmt(f)?;
        self.alternates.iter().try_for_each(|alternate| {
            write!(
                f,
                "&{}&ALTCFG={:04x}",
                self.resp.header, alternate.alt_cfg_id.0
            )?;
            write_body(f, &alternate.body)
        })
    }
}

/// `<MultiConfigAltResp>`: at least one `<ConfigAltResp>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MultiConfigAltResp(Vec<ConfigAltResp>);

impl MultiConfigAltResp {
    pub(crate) fn as_slice(&self) -> &[ConfigAltResp] {
        &self.0
    }

    /// Each `<ConfigAltResp>` of `text`, or why it does not parse, in order: one that does not
    /// parse ends at the next `<ConfigHdr>`, and the `<AltResp>`s that follow it are its own, so
    /// it hides none of the others.
    pub(crate) fn parse_each(text: &str) -> Vec<Result<ConfigAltResp, ConfigStringError>> {
        let mut elements = Elements::new(text);
        let mut resps = Vec::new();
        while elements.peek().is_some() {
            if let Err(error) = parse_next_resp(&mut elements, &mut resps) {
                while elements.next_unless_header().is_some() {}
                resps.push(Err(error));
            }
        }
        resps
    }
}

impl FromStr for MultiConfigAltResp {
    type Err = ConfigStringError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let mut elements = Elements::new(text);
        let mut resps: Vec<ConfigAltResp> = Vec::new();
        loop {
            let (header, alt_cfg_id) = parse_resp_start(&mut elements)?;
            match alt_cfg_id {
                Some(alt_cfg_id) => {
                    let resp = resps.last_mut().ok_or(ConfigStringError::AltRespFirst)?;
                    if header != resp.resp.header {
                        return Err(ConfigStringError::AltRespHeader);
                    }
                    resp.alternates.push(AltResp {
                        alt_cfg_id,
                        body: parse_body(&mut elements)?,
                    });
                }
                None => resps.push(ConfigAltResp {
                    resp: ConfigResp {
                        header,
                        body: parse_body(&mut elements)?,
                    },
                    alternates: Vec::new(),
                }),
            }
            if elements.peek().is_none() {
                return Ok(Self(resps));
            }
        }
    }
}

/// The `<ConfigHdr>` that starts the next `<ConfigResp>` or `<AltResp>` of `elements`, and the
/// ALTCFG of an `<AltResp>`.
fn parse_resp_start(
    elements: &mut Elements<'_>,
) -> Result<(ConfigHdr, Option<DefaultId>), ConfigStringError> {
    let header = ConfigHdr::parse(elements)?;
    let alt_cfg_id = elements
        .optional_value("ALTCFG=")
        .map(|digits| parse_alt_cfg_id(digits).map(DefaultId))
        .transpose()?;
    Ok((header, alt_cfg_id))
}

/// Parses the next `<ConfigResp>` of `elements` into `resps`, or the next `<AltResp>` into the
/// last of them; one of a `<ConfigAltResp>` that does not parse is taken and dropped.
fn parse_next_resp(
    elements: &mut Elements<'_>,
    resps: &mut Vec<Result<ConfigAltResp, ConfigStringError>>,
) -> Result<(), ConfigStringError> {
    let (header, alt_cfg_id) = parse_resp_start(elements)?;
    match (alt_cfg_id, resps.last_mut()) {
        (None, _) => {
            let body = parse_body(elements)?;
            resps.push(Ok(ConfigAltResp {
                resp: ConfigResp { header, body },
                alternates: Vec::new(),
            }));
        }
        (Some(_), None) => return Err(ConfigStringError::AltRespFirst),
        (Some(_), Some(Err(_))) => {
            parse_body(elements)?;
        }
        (Some(alt_cfg_id), Some(Ok(resp))) => {
            if header != resp.resp.header {
                return Err(ConfigStringError::AltRespHeader);
            }
            let body = parse_body(elements)?;
            resp.alternates.push(AltResp { alt_cfg_id, body });
        }
    }
    Ok(())
}

impl fmt::Display for MultiConfigAltResp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_joined(f, &self.0)
    }
}

/// `<Number>` outside a `<BlockConfig>`: a buffer's bytes, at least one, which no WIDTH fills.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Number(Vec<u8>);

impl Number {
    /// The buffer's bytes, as they lie in memory.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Parses `digits` as BlockConfig::parse reads VALUE, without a WIDTH. EDK2's Keyword
    /// Handler copies a `<KeywordResp>`'s VALUE from the `<ConfigResp>` of ExtractConfig.
    fn parse(name: &str, digits: &str) -> Result<Self, ConfigStringError> {
        hex_number(digits)
            .map(Self)
            .ok_or_else(|| invalid_number(name, digits))
    }
}

impl TryFrom<Vec<u8>> for Number {
    type Error = ConfigStringError;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        if bytes.is_empty() {
            return Err(ConfigStringError::EmptyValue);
        }
        Ok(Self(bytes))
    }
}

impl fmt::Display for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, self.0.iter().rev())
    }
}

/// `<NameSpaceId>`'s platform configuration language, such as "x-UEFI-ns".
///
/// Plain text, although the BNF has a `<String>`: EDK2's Keyword Handler reads and writes it so
/// (ExtractNameSpace, GenerateKeywordResp), as the §35.2.1.6 examples do, and converts it to
/// ASCII (UnicodeStrToAsciiStrS).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Namespace(String);

impl TryFrom<&str> for Namespace {
    type Error = ConfigStringError;

    fn try_from(text: &str) -> Result<Self, Self::Error> {
        let printable = text
            .chars()
            .all(|character| character.is_ascii_graphic() && !matches!(character, '&' | '='));
        if text.is_empty() || !printable {
            return Err(ConfigStringError::InvalidNamespace(text.to_owned()));
        }
        Ok(Self(text.to_owned()))
    }
}

impl fmt::Display for Namespace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// `<Keyword>`'s keyword of the UEFI Configuration Namespace Registry, with the ':' and 1 to 4
/// digits that tell instances of a keyword apart, as in "ChipsetSATAPortEnable:5".
///
/// Plain text, as for Namespace: EDK2's ExtractKeyword and GenerateKeywordResp, and the
/// §35.2.1.6 examples.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct Keyword(String);

impl TryFrom<&str> for Keyword {
    type Error = ConfigStringError;

    fn try_from(text: &str) -> Result<Self, Self::Error> {
        let (name, instance) = match text.split_once(':') {
            Some((name, instance)) => (name, Some(instance)),
            None => (text, None),
        };
        let name_ok = !name.is_empty()
            && name
                .chars()
                .all(|character| !character.is_control() && !matches!(character, '&' | '='));
        let instance_ok = instance.is_none_or(|digits| {
            (1..=4).contains(&digits.len()) && digits.bytes().all(|digit| digit.is_ascii_digit())
        });
        if !name_ok || !instance_ok {
            return Err(ConfigStringError::InvalidKeyword(text.to_owned()));
        }
        Ok(Self(text.to_owned()))
    }
}

impl fmt::Display for Keyword {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// `<UsageFilter>`, and whether a `<KeywordResp>` has "&READONLY".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Usage {
    ReadOnly,
    ReadWrite,
}

impl fmt::Display for Usage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ReadOnly => "ReadOnly",
            Self::ReadWrite => "ReadWrite",
        })
    }
}

/// The byte width of 'Numeric':1, :2, :4 or :8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NumericWidth {
    One,
    Two,
    Four,
    Eight,
}

/// 'Numeric'[':1'|':2'|':4'|':8']: a numeric value of the width, else of a width that "may vary".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Numeric {
    pub(crate) width: Option<NumericWidth>,
}

impl Numeric {
    fn parse(text: &str) -> Option<Self> {
        let width = match text {
            "Numeric" => None,
            "Numeric:1" => Some(NumericWidth::One),
            "Numeric:2" => Some(NumericWidth::Two),
            "Numeric:4" => Some(NumericWidth::Four),
            "Numeric:8" => Some(NumericWidth::Eight),
            _ => return None,
        };
        Some(Self { width })
    }
}

impl fmt::Display for Numeric {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self.width {
            None => "Numeric",
            Some(NumericWidth::One) => "Numeric:1",
            Some(NumericWidth::Two) => "Numeric:2",
            Some(NumericWidth::Four) => "Numeric:4",
            Some(NumericWidth::Eight) => "Numeric:8",
        })
    }
}

/// `<DataFilter>`: a keyword's data type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DataFilter {
    Buffer,
    Numeric(Numeric),
    String,
    Boolean,
    Date,
    Time,
}

impl DataFilter {
    fn parse(name: &str, text: &str) -> Result<Self, ConfigStringError> {
        match text {
            "Buffer" => Ok(Self::Buffer),
            "String" => Ok(Self::String),
            "Boolean" => Ok(Self::Boolean),
            "Date" => Ok(Self::Date),
            "Time" => Ok(Self::Time),
            _ => Numeric::parse(text)
                .map(Self::Numeric)
                .ok_or_else(|| invalid_value(name, text, DATA_FILTER)),
        }
    }
}

impl fmt::Display for DataFilter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Buffer => f.write_str("Buffer"),
            Self::Numeric(numeric) => numeric.fmt(f),
            Self::String => f.write_str("String"),
            Self::Boolean => f.write_str("Boolean"),
            Self::Date => f.write_str("Date"),
            Self::Time => f.write_str("Time"),
        }
    }
}

bitflags! {
    /// `<KeywordInfoFilter>`: the `<KeywordInfoResp>` items that a `<KeywordRequest>` asks for.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct KeywordInfoFilter: u64 {
        const DATA_TYPE = 1;
        const VALUE_ATTRIBUTE = 1 << 1;
        const DEFAULT = 1 << 2;
        const DISPLAY_NAME = 1 << 3;
    }
}

impl KeywordInfoFilter {
    /// The items and their names, in BNF order.
    const NAMES: [(Self, &'static str); 4] = [
        (Self::DATA_TYPE, "DataType"),
        (Self::VALUE_ATTRIBUTE, "ValueAttribute"),
        (Self::DEFAULT, "Default"),
        (Self::DISPLAY_NAME, "DisplayName"),
    ];

    /// Parses what Display writes: 'All', else the items' names in BNF order, each at most once,
    /// as UEFI 2.11 §35.2.1.6's `<KeywordInfoFilter>` concatenates them; none is an empty filter.
    fn parse(text: &str) -> Result<Self, ConfigStringError> {
        if text == "All" {
            return Ok(Self::all());
        }
        let mut filter = Self::empty();
        let mut rest = text;
        for (item, name) in Self::NAMES {
            if let Some(after) = rest.strip_prefix(name) {
                filter |= item;
                rest = after;
            }
        }
        match rest.is_empty() {
            true => Ok(filter),
            false => Err(invalid_value("KEYWORDINFO", text, KEYWORD_INFO_FILTER)),
        }
    }
}

impl fmt::Display for KeywordInfoFilter {
    /// 'All' for every item, which means "all the supported information", else the items'
    /// names in BNF order.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_all() {
            return f.write_str("All");
        }
        Self::NAMES
            .into_iter()
            .filter(|(item, _)| self.contains(*item))
            .try_for_each(|(_, name)| f.write_str(name))
    }
}

/// A keyword string's `<PathHdr>`, which unlike a `<ConfigHdr>`'s holds at least an End node:
/// EDK2's Keyword Handler refuses a shorter one (ExtractDevicePath) and writes the handle's whole
/// device path (GenerateKeywordResp).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeywordPath(DevicePath);

impl TryFrom<DevicePath> for KeywordPath {
    type Error = ConfigStringError;

    fn try_from(path: DevicePath) -> Result<Self, Self::Error> {
        match path.as_ref().len() {
            len if len < MIN_DEVICE_PATH_LEN => Err(ConfigStringError::ShortKeywordPath(len)),
            _ => Ok(Self(path)),
        }
    }
}

/// PATH='s hex digits, as a `<KeywordPath>`.
impl FromStr for KeywordPath {
    type Err = ConfigStringError;

    fn from_str(digits: &str) -> Result<Self, Self::Err> {
        Self::try_from(parse_device_path(digits)?)
    }
}

impl AsRef<DevicePath> for KeywordPath {
    fn as_ref(&self) -> &DevicePath {
        &self.0
    }
}

impl fmt::Display for KeywordPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, self.0.as_ref())
    }
}

/// `<KeywordRequest>`: a keyword to read through GetData.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeywordRequest {
    /// The device path of the instance to read; None reads "all instances".
    pub(crate) device_path: Option<KeywordPath>,
    pub(crate) keyword: Keyword,
    pub(crate) info: Option<KeywordInfoFilter>,
    pub(crate) usage: Option<Usage>,
    pub(crate) data: Option<DataFilter>,
}

impl fmt::Display for KeywordRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(device_path) = &self.device_path {
            write!(f, "PATH={device_path}&")?;
        }
        write!(f, "KEYWORD={}", self.keyword)?;
        if let Some(info) = self.info {
            write!(f, "&KEYWORDINFO={info}")?;
        }
        if let Some(usage) = self.usage {
            write!(f, "&{usage}")?;
        }
        if let Some(data) = self.data {
            write!(f, "&{data}")?;
        }
        Ok(())
    }
}

/// A `<KeywordRequest>` of an optional PATH, a KEYWORD and an optional KEYWORDINFO; the filters
/// are refused.
impl FromStr for KeywordRequest {
    type Err = ConfigStringError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let mut elements = Elements::new(text);
        let device_path = elements
            .optional_value("PATH=")
            .map(str::parse::<KeywordPath>)
            .transpose()?;
        let keyword = Keyword::try_from(elements.required_value("KEYWORD=")?)?;
        let info = elements
            .optional_value("KEYWORDINFO=")
            .map(KeywordInfoFilter::parse)
            .transpose()?;
        if let Some(found) = elements.next() {
            return Err(ConfigStringError::Unexpected {
                expected: KEYWORD_REQUEST_END,
                found: found.to_owned(),
            });
        }
        Ok(Self {
            device_path,
            keyword,
            info,
            usage: None,
            data: None,
        })
    }
}

/// `<ValueRange>`: a numeric question's bounds and step, or a string question's lengths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValueRange {
    pub(crate) max: Number,
    pub(crate) min: Number,
    pub(crate) step: Option<Number>,
}

/// `<ValueOption>`: a one-of or ordered-list option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValueOption {
    pub(crate) value: Number,
    pub(crate) string: Vec<u16>,
    /// The numeric type of an ordered list's buffer elements
    pub(crate) value_type: Option<Numeric>,
}

/// `<KeywordInfoResp>`: what a `<KeywordInfoFilter>` asked about a keyword.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct KeywordInfo {
    pub(crate) data_type: Option<DataFilter>,
    pub(crate) range: Option<ValueRange>,
    pub(crate) options: Vec<ValueOption>,
    pub(crate) standard_default: Option<Number>,
    pub(crate) manufacturing_default: Option<Number>,
    pub(crate) safe_default: Option<Number>,
    pub(crate) display_name: Option<Vec<u16>>,
}

impl KeywordInfo {
    fn parse(elements: &mut Elements<'_>) -> Result<Self, ConfigStringError> {
        let data_type = elements
            .optional_value("DATATYPE=")
            .map(|text| DataFilter::parse("DATATYPE", text))
            .transpose()?;
        let range = match elements.optional_value("MAX=") {
            Some(max) => Some(ValueRange {
                max: Number::parse("MAX", max)?,
                min: Number::parse("MIN", elements.required_value("MIN=")?)?,
                step: parse_optional_number(elements, "STEP")?,
            }),
            None => None,
        };
        let mut options = Vec::new();
        while let Some(value) = elements.optional_value("OPTIONVALUE=") {
            options.push(ValueOption {
                value: Number::parse("OPTIONVALUE", value)?,
                string: parse_string("OPTIONSTRING", elements.required_value("OPTIONSTRING=")?)?,
                value_type: elements
                    .optional_value("VALUETYPE=")
                    .map(|text| {
                        Numeric::parse(text)
                            .ok_or_else(|| invalid_value("VALUETYPE", text, NUMERIC_TYPE))
                    })
                    .transpose()?,
            });
        }
        Ok(Self {
            data_type,
            range,
            options,
            standard_default: parse_optional_number(elements, "STANDARDDEFAULT")?,
            manufacturing_default: parse_optional_number(elements, "MFGDEFAULT")?,
            safe_default: parse_optional_number(elements, "SAFEDEFAULT")?,
            display_name: elements
                .optional_value("DISPLAYNAME=")
                .map(|digits| parse_string("DISPLAYNAME", digits))
                .transpose()?,
        })
    }
}

impl fmt::Display for KeywordInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(data_type) = self.data_type {
            write!(f, "&DATATYPE={data_type}")?;
        }
        if let Some(range) = &self.range {
            write!(f, "&MAX={}&MIN={}", range.max, range.min)?;
            if let Some(step) = &range.step {
                write!(f, "&STEP={step}")?;
            }
        }
        for option in &self.options {
            write!(f, "&OPTIONVALUE={}&OPTIONSTRING=", option.value)?;
            write_string(f, &option.string)?;
            if let Some(value_type) = option.value_type {
                write!(f, "&VALUETYPE={value_type}")?;
            }
        }
        let defaults = [
            ("STANDARDDEFAULT", &self.standard_default),
            ("MFGDEFAULT", &self.manufacturing_default),
            ("SAFEDEFAULT", &self.safe_default),
        ];
        for (name, default) in defaults {
            if let Some(default) = default {
                write!(f, "&{name}={default}")?;
            }
        }
        if let Some(display_name) = &self.display_name {
            f.write_str("&DISPLAYNAME=")?;
            write_string(f, display_name)?;
        }
        Ok(())
    }
}

/// `<KeywordResp>`: a keyword's value from GetData, or one to write through SetData.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeywordResp {
    pub(crate) namespace: Namespace,
    pub(crate) device_path: KeywordPath,
    pub(crate) keyword: Keyword,
    pub(crate) value: Number,
    /// ReadOnly writes "&READONLY". EDK2's SetData refuses a `<KeywordResp>` whose READONLY
    /// differs from the question's flag, and refuses any read-only keyword.
    pub(crate) usage: Usage,
    pub(crate) info: KeywordInfo,
}

impl KeywordResp {
    fn parse(elements: &mut Elements<'_>) -> Result<Self, ConfigStringError> {
        let namespace = Namespace::try_from(elements.required_value("NAMESPACE=")?)?;
        let device_path =
            KeywordPath::try_from(parse_device_path(elements.required_value("PATH=")?)?)?;
        let keyword = Keyword::try_from(elements.required_value("KEYWORD=")?)?;
        let value = Number::parse("VALUE", elements.required_value("VALUE=")?)?;
        let usage = if elements.take_if_eq("READONLY") {
            Usage::ReadOnly
        } else {
            Usage::ReadWrite
        };
        Ok(Self {
            namespace,
            device_path,
            keyword,
            value,
            usage,
            info: KeywordInfo::parse(elements)?,
        })
    }
}

impl fmt::Display for KeywordResp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NAMESPACE={}&PATH={}&KEYWORD={}&VALUE={}",
            self.namespace, self.device_path, self.keyword, self.value
        )?;
        match self.usage {
            Usage::ReadOnly => f.write_str("&READONLY")?,
            Usage::ReadWrite => {}
        }
        self.info.fmt(f)
    }
}

/// `<MultiKeywordResp>`: at least one `<KeywordResp>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MultiKeywordResp(Vec<KeywordResp>);

impl MultiKeywordResp {
    pub(crate) fn as_slice(&self) -> &[KeywordResp] {
        &self.0
    }
}

impl TryFrom<Vec<KeywordResp>> for MultiKeywordResp {
    type Error = ConfigStringError;

    fn try_from(resps: Vec<KeywordResp>) -> Result<Self, Self::Error> {
        if resps.is_empty() {
            return Err(ConfigStringError::EmptyMultiKeywordResp);
        }
        Ok(Self(resps))
    }
}

impl FromStr for MultiKeywordResp {
    type Err = ConfigStringError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let mut elements = Elements::new(text);
        let mut resps = vec![KeywordResp::parse(&mut elements)?];
        while let Some(element) = elements.peek() {
            if !element.starts_with("NAMESPACE=") {
                return Err(ConfigStringError::Unexpected {
                    expected: KEYWORD_RESP_END,
                    found: element.to_owned(),
                });
            }
            resps.push(KeywordResp::parse(&mut elements)?);
        }
        Ok(Self(resps))
    }
}

impl fmt::Display for MultiKeywordResp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_joined(f, &self.0)
    }
}

/// The '&'-separated elements of a configuration string.
struct Elements<'a>(Peekable<Split<'a, char>>);

impl<'a> Elements<'a> {
    fn new(text: &'a str) -> Self {
        Self(text.split('&').peekable())
    }

    fn peek(&mut self) -> Option<&'a str> {
        self.0.peek().copied()
    }

    /// The next element unless it starts a `<ConfigHdr>`.
    fn next_unless_header(&mut self) -> Option<&'a str> {
        self.0.next_if(|element| !element.starts_with("GUID="))
    }

    /// Takes the next element if it is `element`.
    fn take_if_eq(&mut self, element: &str) -> bool {
        self.0.next_if_eq(&element).is_some()
    }

    /// The value of the next element, which starts with `prefix`, such as "GUID=".
    fn required_value(&mut self, prefix: &'static str) -> Result<&'a str, ConfigStringError> {
        let element = self
            .0
            .next()
            .ok_or(ConfigStringError::Truncated { expected: prefix })?;
        element
            .strip_prefix(prefix)
            .ok_or_else(|| ConfigStringError::Unexpected {
                expected: prefix,
                found: element.to_owned(),
            })
    }

    /// The value of the next element if it starts with `prefix`, which it then takes.
    fn optional_value(&mut self, prefix: &str) -> Option<&'a str> {
        let value = self.0.peek()?.strip_prefix(prefix)?;
        self.0.next();
        Some(value)
    }
}

impl<'a> Iterator for Elements<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

/// The `<ConfigElement>`s up to the next `<ConfigHdr>` or the end.
fn parse_body(elements: &mut Elements<'_>) -> Result<Vec<ConfigElement>, ConfigStringError> {
    let mut body = Vec::new();
    while let Some(element) = elements.next_unless_header() {
        body.push(ConfigElement::parse(element, elements)?);
    }
    Ok(body)
}

fn write_body(f: &mut fmt::Formatter<'_>, body: &[ConfigElement]) -> fmt::Result {
    body.iter().try_for_each(|element| write!(f, "&{element}"))
}

/// Writes `items` separated by '&', as the Multi strings join theirs.
fn write_joined(f: &mut fmt::Formatter<'_>, items: &[impl fmt::Display]) -> fmt::Result {
    items
        .iter()
        .enumerate()
        .try_for_each(|(index, item)| match index {
            0 => item.fmt(f),
            _ => write!(f, "&{item}"),
        })
}

fn parse_alt_cfg_id(digits: &str) -> Result<u16, ConfigStringError> {
    hex_unit(digits.as_bytes()).ok_or_else(|| invalid_value("ALTCFG", digits, ALT_CFG_ID))
}

fn parse_optional_number(
    elements: &mut Elements<'_>,
    name: &str,
) -> Result<Option<Number>, ConfigStringError> {
    elements
        .optional_value(&format!("{name}="))
        .map(|digits| Number::parse(name, digits))
        .transpose()
}

/// The CHAR16s of a `<String>`, 4 hex digits each.
fn parse_string(name: &str, digits: &str) -> Result<Vec<u16>, ConfigStringError> {
    digits
        .as_bytes()
        .chunks(4)
        .map(hex_unit)
        .collect::<Option<_>>()
        .ok_or_else(|| invalid_value(name, digits, STRING))
}

fn write_string(f: &mut fmt::Formatter<'_>, units: &[u16]) -> fmt::Result {
    units.iter().try_for_each(|unit| write!(f, "{unit:04x}"))
}

fn parse_device_path(digits: &str) -> Result<DevicePath, ConfigStringError> {
    hex_bytes(digits).ok_or_else(|| invalid_value("PATH", digits, DEVICE_PATH))
}

/// OFFSET's or WIDTH's value.
fn parse_size(name: &str, digits: &str) -> Result<usize, ConfigStringError> {
    let value = match digits {
        "" => None,
        _ => digits.bytes().try_fold(0_usize, |value, digit| {
            value
                .checked_mul(16)?
                .checked_add(usize::from(hex_digit(digit)?))
        }),
    };
    value.ok_or_else(|| invalid_value(name, digits, SIZE_NUMBER))
}

fn check_block_end(offset: usize, width: NonZeroUsize) -> Result<(), ConfigStringError> {
    match offset.checked_add(width.get()) {
        Some(end) if end <= MAX_BLOCK_END => Ok(()),
        _ => Err(ConfigStringError::BlockBeyondStorage {
            offset,
            width: width.get(),
        }),
    }
}

/// The bytes of a `<Number>`'s `digits`, least significant first.
fn hex_number(digits: &str) -> Option<Vec<u8>> {
    if digits.is_empty() {
        return None;
    }
    digits
        .as_bytes()
        .rchunks(2)
        .map(|chunk| match chunk {
            [high, low] => hex_byte(*high, *low),
            [low] => hex_digit(*low),
            _ => None,
        })
        .collect()
}

/// The CHAR16 of 4 hex digits, most significant first.
fn hex_unit(digits: &[u8]) -> Option<u16> {
    match digits {
        [a, b, c, d] => Some(u16::from_be_bytes([hex_byte(*a, *b)?, hex_byte(*c, *d)?])),
        _ => None,
    }
}

fn write_hex<'a>(
    f: &mut fmt::Formatter<'_>,
    bytes: impl IntoIterator<Item = &'a u8>,
) -> fmt::Result {
    bytes
        .into_iter()
        .try_for_each(|byte| write!(f, "{byte:02x}"))
}

fn invalid_value(name: &str, value: &str, expected: &'static str) -> ConfigStringError {
    ConfigStringError::InvalidValue {
        name: name.to_owned(),
        value: value.to_owned(),
        expected,
    }
}

fn invalid_number(name: &str, value: &str) -> ConfigStringError {
    ConfigStringError::InvalidNumber {
        name: name.to_owned(),
        len: value.chars().count(),
    }
}

#[cfg(test)]
mod tests {
    use std::num::NonZeroUsize;

    use crate::hii::variables::tests::EFI_GLOBAL_VARIABLE;

    use super::*;

    /// EFI_GLOBAL_VARIABLE's bytes in memory order.
    const GLOBAL_VARIABLE_HEX: &str = "61dfe48bca93d211aa0d00e098032b8c";
    /// "Setup", each CHAR16 in 4 hex digits.
    const SETUP_HEX: &str = "00530065007400750070";
    /// An End of Hardware Device Path node: type 0x7F, sub-type 0xFF, length 4.
    const END_DEVICE_PATH: [u8; 4] = [0x7F, 0xFF, 0x04, 0x00];

    fn setup_header() -> ConfigHdr {
        ConfigHdr {
            guid: EFI_GLOBAL_VARIABLE,
            name: "Setup".encode_utf16().collect(),
            device_path: END_DEVICE_PATH.to_vec().into(),
        }
    }

    fn setup_header_text() -> String {
        format!("GUID={GLOBAL_VARIABLE_HEX}&NAME={SETUP_HEX}&PATH=7fff0400")
    }

    fn width(width: usize) -> NonZeroUsize {
        NonZeroUsize::new(width).expect("nonzero width")
    }

    fn label(text: &str) -> Label {
        Label::try_from(text).expect("valid label")
    }

    fn parse_resp(body: &str) -> Result<ConfigResp, ConfigStringError> {
        format!("{}{body}", setup_header_text()).parse()
    }

    fn invalid_value(name: &str, value: &str, expected: &'static str) -> ConfigStringError {
        ConfigStringError::InvalidValue {
            name: name.to_owned(),
            value: value.to_owned(),
            expected,
        }
    }

    fn invalid_number(name: &str, len: usize) -> ConfigStringError {
        ConfigStringError::InvalidNumber {
            name: name.to_owned(),
            len,
        }
    }

    #[test]
    fn header_prints_guid_name_and_path_bytes_in_memory_order() {
        assert_eq!(
            setup_header().to_string(),
            setup_header_text(),
            "EFI_GLOBAL_VARIABLE's Setup at an End node"
        );
    }

    #[test]
    fn one_element_request_builds() {
        let block = BlockName::new(0x10, width(2)).expect("block in a varstore");
        let request = ConfigRequest::new(setup_header(), vec![RequestElement::Block(block)])
            .expect("one element");

        assert_eq!(
            request.to_string(),
            format!("{}&OFFSET=0010&WIDTH=0002", setup_header_text()),
            "2 bytes at 0x10"
        );
    }

    #[test]
    fn block_name_ends_where_the_largest_varstore_ends() {
        let block = BlockName::new(0xFFFE, width(1)).expect("last byte of a varstore");

        assert_eq!(
            (block.offset(), block.width(), block.to_string()),
            (0xFFFE, width(1), "OFFSET=fffe&WIDTH=0001".to_owned()),
            "last byte of a varstore"
        );
        assert_eq!(
            BlockName::new(0xFFFF, width(1)),
            Err(ConfigStringError::BlockBeyondStorage {
                offset: 0xFFFF,
                width: 1,
            }),
            "byte past every varstore"
        );
    }

    #[test]
    fn request_keeps_the_order_of_labels_and_blocks() {
        let elements = vec![
            RequestElement::Label(label("fred")),
            RequestElement::Block(BlockName::new(0x1234, width(1)).expect("block in a varstore")),
            RequestElement::Label(label("_goyle9")),
        ];
        let request = ConfigRequest::new(setup_header(), elements).expect("three elements");

        assert_eq!(
            request.to_string(),
            format!(
                "{}&fred&OFFSET=1234&WIDTH=0001&_goyle9",
                setup_header_text()
            ),
            "label, block, label"
        );
    }

    #[test]
    fn request_without_elements_is_refused() {
        assert_eq!(
            ConfigRequest::new(setup_header(), Vec::new()).map(|request| request.to_string()),
            Err(ConfigStringError::EmptyRequest),
            "no element"
        );
    }

    #[test]
    fn labels_follow_c_label_syntax_and_skip_reserved_names() {
        for valid in ["fred", "_", "_x9", "Goyle_11", "GUIDE", "guid"] {
            assert_eq!(
                Label::try_from(valid).map(|label| label.to_string()),
                Ok(valid.to_owned()),
                "label {valid:?}"
            );
        }
        for invalid in ["", "9lives", "a-b", "a b", "\u{e9}t\u{e9}"] {
            assert_eq!(
                Label::try_from(invalid),
                Err(ConfigStringError::InvalidLabel(invalid.to_owned())),
                "label {invalid:?}"
            );
        }
        for reserved in ["GUID", "NAME", "PATH", "ALTCFG", "OFFSET", "WIDTH", "VALUE"] {
            assert_eq!(
                Label::try_from(reserved),
                Err(ConfigStringError::ReservedName(reserved.to_owned())),
                "label {reserved:?}"
            );
        }
        assert_eq!(
            parse_resp("&GUIDE=00").map(|resp| resp.body),
            Ok(vec![ConfigElement::Nv(
                NvConfig::new(label("GUIDE"), "00").expect("value")
            )]),
            "a label that starts with GUID"
        );
    }

    /// UEFI 2.10 §35.4.6's ConfigToBlock example, with the '&' that its "OFFSET=3WIDTH=1" lacks.
    #[test]
    fn config_to_block_example_writes_55_aa_02_07_04_05() {
        let resp = parse_resp("&OFFSET=3&WIDTH=1&VALUE=7&OFFSET=0&WIDTH=2&VALUE=AA55")
            .expect("example parses");
        let mut block = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
        for element in &resp.body {
            let ConfigElement::Block(config) = element else {
                panic!("example has only <BlockConfig>s, got {element:?}");
            };
            config.write_to(&mut block).expect("block in range");
        }

        assert_eq!(
            block,
            [0x55, 0xAA, 0x02, 0x07, 0x04, 0x05],
            "§35.4.6 ConfigToBlock example"
        );
    }

    #[test]
    fn config_to_block_example_as_printed_is_refused() {
        assert_eq!(
            parse_resp("&OFFSET=3WIDTH=1&VALUE=7&OFFSET=0&WIDTH=2&VALUE=AA55"),
            Err(invalid_value("OFFSET", "3WIDTH=1", SIZE_NUMBER)),
            "§35.4.6 example as printed"
        );
    }

    #[test]
    fn value_fills_its_width_least_significant_byte_first() {
        let resp = parse_resp("&OFFSET=0&WIDTH=2&VALUE=7&OFFSET=2&WIDTH=1&VALUE=0007")
            .expect("short and zero-padded values");
        let values: Vec<_> = resp
            .body
            .iter()
            .map(|element| match element {
                ConfigElement::Block(config) => (config.offset(), config.value().to_vec()),
                ConfigElement::Nv(config) => panic!("no <NvConfig> here, got {config:?}"),
            })
            .collect();

        assert_eq!(
            values,
            [(0, vec![0x07, 0x00]), (2, vec![0x07])],
            "VALUE=7 in WIDTH=2, VALUE=0007 in WIDTH=1"
        );
    }

    #[test]
    fn value_wider_than_its_width_is_refused() {
        assert_eq!(
            parse_resp("&OFFSET=0&WIDTH=1&VALUE=0102"),
            Err(ConfigStringError::ValueWiderThanWidth {
                digits: 4,
                width: 1,
            }),
            "nonzero byte past WIDTH"
        );
        assert_eq!(
            parse_resp("&OFFSET=0&WIDTH=1&VALUE=010002"),
            Err(ConfigStringError::ValueWiderThanWidth {
                digits: 6,
                width: 1,
            }),
            "zero and nonzero bytes past WIDTH"
        );
    }

    #[test]
    fn block_config_prints_value_most_significant_byte_first() {
        let config = BlockConfig::new(0x2A, vec![0x55, 0xAA, 0x01]).expect("nonempty value");

        assert_eq!(
            config.to_string(),
            "OFFSET=002a&WIDTH=0003&VALUE=01aa55",
            "3 bytes at 0x2a"
        );
    }

    #[test]
    fn block_config_without_bytes_is_refused() {
        assert_eq!(
            BlockConfig::new(0, Vec::new()).map(|config| config.to_string()),
            Err(ConfigStringError::EmptyValue),
            "no byte"
        );
    }

    #[test]
    fn block_may_end_where_the_largest_varstore_ends() {
        let resp = parse_resp("&OFFSET=fffe&WIDTH=1&VALUE=ab").expect("last byte of a varstore");

        assert_eq!(
            resp.body,
            [ConfigElement::Block(
                BlockConfig::new(0xFFFE, vec![0xAB]).expect("last byte of a varstore")
            )],
            "last byte of a varstore"
        );
        assert_eq!(
            BlockConfig::new(0xFFFE, vec![0xAB, 0xCD]),
            Err(ConfigStringError::BlockBeyondStorage {
                offset: 0xFFFE,
                width: 2,
            }),
            "block ending at 0x10000"
        );
    }

    #[test]
    fn nv_config_keeps_its_label_and_lowercase_digits() {
        let config = NvConfig::new(label("fred"), "00AB").expect("hex digits");

        assert_eq!(
            (config.label().to_string(), config.value()),
            ("fred".to_owned(), "00ab"),
            "uppercase digits"
        );
        for invalid in ["xyz", "+1"] {
            assert_eq!(
                NvConfig::new(label("fred"), invalid),
                Err(invalid_number("fred", invalid.len())),
                "value {invalid:?}"
            );
        }
        assert_eq!(
            NvConfig::new(label("fred"), "").map(|config| config.value().to_owned()),
            Ok(String::new()),
            "empty string value"
        );
    }

    /// DriverSample answers an empty NameValueVar2 with no digits, as EDK2 writes an empty string.
    #[test]
    fn empty_nv_config_value_round_trips() {
        let text = format!("{}&NameValueVar0=00&NameValueVar2=", setup_header_text());

        assert_eq!(
            text.parse::<ConfigResp>().map(|resp| resp.to_string()),
            Ok(text.clone()),
            "{text:?}"
        );
    }

    #[test]
    fn block_beyond_the_buffer_is_refused() {
        let config = BlockConfig::new(5, vec![0xAA, 0x55]).expect("nonempty value");
        let mut block = [0; 6];

        assert_eq!(
            config.write_to(&mut block),
            Err(ConfigStringError::OutsideBuffer {
                offset: 5,
                width: 2,
                len: 6,
            }),
            "2 bytes at 5 of 6"
        );
        assert_eq!(block, [0; 6], "nothing written");
    }

    #[test]
    fn config_resp_parses_and_prints_lowercase() {
        let text = format!(
            "GUID={}&NAME=0053&PATH=7FFF0400&OFFSET=10&WIDTH=2&VALUE=BEEF&fred=0012",
            GLOBAL_VARIABLE_HEX.to_uppercase()
        );
        let resp: ConfigResp = text.parse().expect("parses");

        assert_eq!(
            resp,
            ConfigResp {
                header: ConfigHdr {
                    guid: EFI_GLOBAL_VARIABLE,
                    name: vec![0x53],
                    device_path: END_DEVICE_PATH.to_vec().into(),
                },
                body: vec![
                    ConfigElement::Block(BlockConfig::new(0x10, vec![0xEF, 0xBE]).expect("value")),
                    ConfigElement::Nv(NvConfig::new(label("fred"), "0012").expect("value")),
                ],
            },
            "parsed from uppercase"
        );
        assert_eq!(
            resp.to_string(),
            format!(
                "GUID={GLOBAL_VARIABLE_HEX}&NAME=0053&PATH=7fff0400\
                 &OFFSET=0010&WIDTH=0002&VALUE=beef&fred=0012"
            ),
            "printed in lowercase"
        );
    }

    #[test]
    fn config_resp_may_have_no_body_and_empty_name_and_path() {
        let text = format!("GUID={GLOBAL_VARIABLE_HEX}&NAME=&PATH=");
        let resp: ConfigResp = text.parse().expect("parses");

        assert_eq!(
            resp,
            ConfigResp {
                header: ConfigHdr {
                    guid: EFI_GLOBAL_VARIABLE,
                    name: Vec::new(),
                    device_path: Vec::new().into(),
                },
                body: Vec::new(),
            },
            "parsed"
        );
        assert_eq!(resp.to_string(), text, "printed");
    }

    #[test]
    fn malformed_config_resp_is_refused() {
        let header = setup_header_text();
        let usize_overflow = format!("1{}", "0".repeat(2 * size_of::<usize>()));
        let cases = [
            ("".to_owned(), unexpected("GUID=", "")),
            (
                format!("GUID={GLOBAL_VARIABLE_HEX}&PATH=7fff0400"),
                unexpected("NAME=", "PATH=7fff0400"),
            ),
            (
                format!("GUID={GLOBAL_VARIABLE_HEX}&NAME={SETUP_HEX}"),
                ConfigStringError::Truncated { expected: "PATH=" },
            ),
            (
                format!("GUID={}&NAME=&PATH=", &GLOBAL_VARIABLE_HEX[1..]),
                invalid_value("GUID", &GLOBAL_VARIABLE_HEX[1..], GUID),
            ),
            (
                format!("GUID={}g&NAME=&PATH=", &GLOBAL_VARIABLE_HEX[1..]),
                invalid_value("GUID", &format!("{}g", &GLOBAL_VARIABLE_HEX[1..]), GUID),
            ),
            (
                format!("GUID={}&NAME=&PATH=", &GLOBAL_VARIABLE_HEX[2..]),
                invalid_value("GUID", &GLOBAL_VARIABLE_HEX[2..], GUID),
            ),
            (
                format!("GUID={GLOBAL_VARIABLE_HEX}00&NAME=&PATH="),
                invalid_value("GUID", &format!("{GLOBAL_VARIABLE_HEX}00"), GUID),
            ),
            (
                format!("GUID={GLOBAL_VARIABLE_HEX}&NAME=005&PATH="),
                invalid_value("NAME", "005", STRING),
            ),
            (
                format!("GUID={GLOBAL_VARIABLE_HEX}&NAME=&PATH=7ff"),
                invalid_value("PATH", "7ff", DEVICE_PATH),
            ),
            (
                format!("{header}&OFFSET=0&VALUE=00"),
                unexpected("WIDTH=", "VALUE=00"),
            ),
            (
                format!("{header}&OFFSET=0&WIDTH=1"),
                ConfigStringError::Truncated { expected: "VALUE=" },
            ),
            (
                format!("{header}&OFFSET=0&WIDTH=0&VALUE=00"),
                invalid_value("WIDTH", "0", NONZERO_NUMBER),
            ),
            (
                format!("{header}&OFFSET=+1&WIDTH=1&VALUE=00"),
                invalid_value("OFFSET", "+1", SIZE_NUMBER),
            ),
            (
                format!("{header}&OFFSET=&WIDTH=1&VALUE=00"),
                invalid_value("OFFSET", "", SIZE_NUMBER),
            ),
            (
                format!("{header}&OFFSET=0&WIDTH=&VALUE=00"),
                invalid_value("WIDTH", "", SIZE_NUMBER),
            ),
            (
                format!("{header}&OFFSET=0&WIDTH=1&VALUE="),
                invalid_number("VALUE", 0),
            ),
            (
                format!("{header}&OFFSET={usize_overflow}&WIDTH=1&VALUE=00"),
                invalid_value("OFFSET", &usize_overflow, SIZE_NUMBER),
            ),
            (
                format!("{header}&OFFSET={:x}&WIDTH=2&VALUE=00", usize::MAX),
                ConfigStringError::BlockBeyondStorage {
                    offset: usize::MAX,
                    width: 2,
                },
            ),
            (
                format!("{header}&OFFSET=ffff&WIDTH=1&VALUE=00"),
                ConfigStringError::BlockBeyondStorage {
                    offset: 0xFFFF,
                    width: 1,
                },
            ),
            (format!("{header}&"), unexpected(CONFIG_ELEMENT, "")),
            (
                format!("{header}&fred=00&&goyle=11"),
                unexpected(CONFIG_ELEMENT, ""),
            ),
            (format!("{header}&fred"), unexpected(CONFIG_ELEMENT, "fred")),
            (format!("{header}&fred=xyz"), invalid_number("fred", 3)),
            (
                format!("{header}&9lives=00"),
                ConfigStringError::InvalidLabel("9lives".to_owned()),
            ),
            (
                format!("{header}&NAME=0053"),
                ConfigStringError::ReservedName("NAME".to_owned()),
            ),
            (
                format!("{header}&ALTCFG=0001"),
                ConfigStringError::ReservedName("ALTCFG".to_owned()),
            ),
            (
                format!("{header}&fred=00&{header}"),
                unexpected(CONFIG_RESP_END, &format!("GUID={GLOBAL_VARIABLE_HEX}")),
            ),
        ];
        for (text, error) in cases {
            assert_eq!(text.parse::<ConfigResp>(), Err(error), "{text:?}");
        }
    }

    fn unexpected(expected: &'static str, found: &str) -> ConfigStringError {
        ConfigStringError::Unexpected {
            expected,
            found: found.to_owned(),
        }
    }

    #[test]
    fn multi_config_alt_resp_groups_alternates_under_their_resp() {
        let header = setup_header_text();
        let other_header = format!("GUID={GLOBAL_VARIABLE_HEX}&NAME=0058&PATH=7fff0400");
        let text = format!(
            "{header}&OFFSET=0000&WIDTH=0001&VALUE=01\
             &{header}&ALTCFG=0000&OFFSET=0000&WIDTH=0001&VALUE=00\
             &{header}&ALTCFG=0001&OFFSET=0000&WIDTH=0001&VALUE=02\
             &{other_header}&fred=0012\
             &{other_header}&ALTCFG=0000&fred=0034"
        );
        let multi = text.parse::<MultiConfigAltResp>();
        let block = |value: u8| {
            vec![ConfigElement::Block(
                BlockConfig::new(0, vec![value]).expect("value"),
            )]
        };

        assert_eq!(
            multi.as_ref().map(|multi| multi.as_slice().to_vec()),
            Ok(vec![
                ConfigAltResp {
                    resp: ConfigResp {
                        header: setup_header(),
                        body: block(0x01),
                    },
                    alternates: vec![
                        AltResp {
                            alt_cfg_id: DefaultId(0x0000),
                            body: block(0x00),
                        },
                        AltResp {
                            alt_cfg_id: DefaultId(0x0001),
                            body: block(0x02),
                        },
                    ],
                },
                ConfigAltResp {
                    resp: ConfigResp {
                        header: ConfigHdr {
                            name: vec![0x58],
                            ..setup_header()
                        },
                        body: vec![ConfigElement::Nv(
                            NvConfig::new(label("fred"), "0012").expect("value"),
                        )],
                    },
                    alternates: vec![AltResp {
                        alt_cfg_id: DefaultId(0x0000),
                        body: vec![ConfigElement::Nv(
                            NvConfig::new(label("fred"), "0034").expect("value"),
                        )],
                    }],
                },
            ]),
            "alternates under the first and the second ConfigResp"
        );
        assert_eq!(multi.map(|multi| multi.to_string()), Ok(text), "printed");
    }

    #[test]
    fn malformed_multi_config_alt_resp_is_refused() {
        let header = setup_header_text();
        let other_header = format!("GUID={GLOBAL_VARIABLE_HEX}&NAME=0058&PATH=7fff0400");
        let cases = [
            (
                format!("{header}&ALTCFG=0001&OFFSET=0&WIDTH=1&VALUE=00"),
                ConfigStringError::AltRespFirst,
            ),
            (
                format!("{header}&{header}&ALTCFG=001"),
                invalid_value("ALTCFG", "001", ALT_CFG_ID),
            ),
            (format!("{header}&fred=00&"), unexpected(CONFIG_ELEMENT, "")),
            (
                format!("{header}&fred=00&{other_header}&ALTCFG=0000&fred=01"),
                ConfigStringError::AltRespHeader,
            ),
        ];
        for (text, error) in cases {
            assert_eq!(text.parse::<MultiConfigAltResp>(), Err(error), "{text:?}");
        }
    }

    /// parse_each gives each <ConfigAltResp> as the strict parse gives it alone, and for one that
    /// does not parse its error, in order: it ends at the next <ConfigHdr>, and an <AltResp> after
    /// it is its own, while one before any <ConfigResp> or of another storage fails alone.
    #[test]
    fn parse_each_parses_each_config_alt_resp_on_its_own() {
        let header = setup_header_text();
        let other_header = format!("GUID={GLOBAL_VARIABLE_HEX}&NAME=0058&PATH=7fff0400");
        let first = format!("{header}&OFFSET=0&WIDTH=1&VALUE=01&{header}&ALTCFG=0000&fred=01");
        let unparsed = format!("{other_header}&OFFSET=0&WIDTH=1g&VALUE=02");
        let its_alternate = format!("{other_header}&ALTCFG=0001&OFFSET=0&WIDTH=1&VALUE=03");
        let last = format!("{header}&OFFSET=1&WIDTH=1&VALUE=04");
        let alone = |text: &str| {
            text.parse::<MultiConfigAltResp>()
                .map(|multi| multi.as_slice().to_vec())
                .expect("parse alone")
        };
        let cases = [
            (
                [first.as_str(), &unparsed, &its_alternate, &last].join("&"),
                vec![
                    Ok(alone(&first).remove(0)),
                    Err(invalid_value("WIDTH", "1g", SIZE_NUMBER)),
                    Ok(alone(&last).remove(0)),
                ],
            ),
            (
                format!("{its_alternate}&{last}"),
                vec![
                    Err(ConfigStringError::AltRespFirst),
                    Ok(alone(&last).remove(0)),
                ],
            ),
            (
                format!("{last}&{its_alternate}"),
                vec![
                    Ok(alone(&last).remove(0)),
                    Err(ConfigStringError::AltRespHeader),
                ],
            ),
        ];
        for (text, want) in cases {
            assert_eq!(MultiConfigAltResp::parse_each(&text), want, "{text:?}");
        }
    }

    /// "Acme" as a string keyword's VALUE: its CHAR16s little-endian, printed most significant
    /// byte first.
    const ACME_VALUE: &str = "0065006d00630041";

    fn keyword(text: &str) -> Keyword {
        Keyword::try_from(text).expect("valid keyword")
    }

    fn namespace(text: &str) -> Namespace {
        Namespace::try_from(text).expect("valid namespace")
    }

    fn number(bytes: &[u8]) -> Number {
        Number::try_from(bytes.to_vec()).expect("nonempty number")
    }

    fn ucs2(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    fn end_keyword_path() -> KeywordPath {
        KeywordPath::try_from(DevicePath::from(END_DEVICE_PATH.to_vec())).expect("an End node")
    }

    fn bios_vendor_resp(info: KeywordInfo) -> KeywordResp {
        KeywordResp {
            namespace: namespace("x-UEFI-ns"),
            device_path: end_keyword_path(),
            keyword: keyword("BIOSVendor"),
            value: number(
                &ucs2("Acme")
                    .iter()
                    .flat_map(|unit| unit.to_le_bytes())
                    .collect::<Vec<_>>(),
            ),
            usage: Usage::ReadWrite,
            info,
        }
    }

    fn keyword_request(keyword_text: &str) -> KeywordRequest {
        KeywordRequest {
            device_path: None,
            keyword: keyword(keyword_text),
            info: None,
            usage: None,
            data: None,
        }
    }

    /// UEFI 2.10 §35.2.1.6.1's `<KeywordRequest>`.
    #[test]
    fn keyword_request_example_builds() {
        assert_eq!(
            keyword_request("BIOSVendor").to_string(),
            "KEYWORD=BIOSVendor",
            "§35.2.1.6.1 example"
        );
    }

    /// UEFI 2.10 §35.2.1.6.4's `<KeywordRequest>`.
    #[test]
    fn keyword_info_request_example_builds() {
        let request = KeywordRequest {
            info: Some(KeywordInfoFilter::all()),
            ..keyword_request("BIOSVendor")
        };

        assert_eq!(
            request.to_string(),
            "KEYWORD=BIOSVendor&KEYWORDINFO=All",
            "§35.2.1.6.4 example"
        );
    }

    #[test]
    fn keyword_request_lists_path_info_and_filters_in_order() {
        let request = KeywordRequest {
            device_path: Some(end_keyword_path()),
            info: Some(KeywordInfoFilter::DATA_TYPE | KeywordInfoFilter::DEFAULT),
            usage: Some(Usage::ReadOnly),
            data: Some(DataFilter::Numeric(Numeric {
                width: Some(NumericWidth::One),
            })),
            ..keyword_request("ChipsetSATAPortEnable:5")
        };

        assert_eq!(
            request.to_string(),
            "PATH=7fff0400&KEYWORD=ChipsetSATAPortEnable:5\
             &KEYWORDINFO=DataTypeDefault&ReadOnly&Numeric:1",
            "every optional part"
        );
    }

    #[test]
    fn keyword_request_of_path_and_keyword_parses() {
        let with_path = KeywordRequest {
            device_path: Some(end_keyword_path()),
            ..keyword_request("ChipsetSATAPortEnable:5")
        };
        let cases = [
            ("KEYWORD=BIOSVendor", Ok(keyword_request("BIOSVendor"))),
            (
                "PATH=7fff0400&KEYWORD=ChipsetSATAPortEnable:5",
                Ok(with_path),
            ),
            (
                "KEYWORD=BIOSVendor&KEYWORDINFO=All",
                Ok(KeywordRequest {
                    info: Some(KeywordInfoFilter::all()),
                    ..keyword_request("BIOSVendor")
                }),
            ),
            (
                "KEYWORD=BIOSVendor&KEYWORDINFO=All&KEYWORDINFO=Default",
                Err(unexpected(KEYWORD_REQUEST_END, "KEYWORDINFO=Default")),
            ),
            (
                "KEYWORD=BIOSVendor&KEYWORDINFO=All&ReadOnly",
                Err(unexpected(KEYWORD_REQUEST_END, "ReadOnly")),
            ),
            (
                "KEYWORD=BIOSVendor&ReadOnly",
                Err(unexpected(KEYWORD_REQUEST_END, "ReadOnly")),
            ),
            (
                "PATH=7fff04&KEYWORD=BIOSVendor",
                Err(ConfigStringError::ShortKeywordPath(3)),
            ),
            ("BIOSVendor", Err(unexpected("KEYWORD=", "BIOSVendor"))),
            (
                "PATH=7fff0400",
                Err(ConfigStringError::Truncated {
                    expected: "KEYWORD=",
                }),
            ),
        ];
        for (text, expected) in cases {
            assert_eq!(text.parse::<KeywordRequest>(), expected, "{text:?}");
        }
    }

    /// KEYWORDINFO= takes what a KeywordInfoFilter prints: All, or the items in BNF order, each
    /// at most once, none for an empty filter; other text, the items out of order or twice, is
    /// refused.
    #[test]
    fn keyword_info_filter_parses_what_it_prints() {
        for filter in [
            KeywordInfoFilter::empty(),
            KeywordInfoFilter::DATA_TYPE | KeywordInfoFilter::DEFAULT,
            KeywordInfoFilter::VALUE_ATTRIBUTE | KeywordInfoFilter::DISPLAY_NAME,
            KeywordInfoFilter::all(),
        ] {
            let text = format!("KEYWORD=BIOSVendor&KEYWORDINFO={filter}");
            assert_eq!(
                text.parse::<KeywordRequest>(),
                Ok(KeywordRequest {
                    info: Some(filter),
                    ..keyword_request("BIOSVendor")
                }),
                "{text:?}"
            );
        }
        for filter in [
            "DefaultDataType",
            "DataTypeDataType",
            "AllDefault",
            "all",
            "Bogus",
        ] {
            assert_eq!(
                format!("KEYWORD=BIOSVendor&KEYWORDINFO={filter}").parse::<KeywordRequest>(),
                Err(invalid_value("KEYWORDINFO", filter, KEYWORD_INFO_FILTER)),
                "{filter:?}"
            );
        }
    }

    /// What a `<KeywordRequest>` of PATH and KEYWORD writes, it parses back.
    #[test]
    fn keyword_request_of_path_and_keyword_reads_back() {
        let request = KeywordRequest {
            device_path: Some(end_keyword_path()),
            ..keyword_request("iSCSIBootEnable")
        };

        assert_eq!(
            request.to_string().parse::<KeywordRequest>(),
            Ok(request),
            "PATH and KEYWORD"
        );
    }

    #[test]
    fn keyword_path_parses_from_hex_digits() {
        let cases = [
            ("7fff0400", Ok(end_keyword_path())),
            ("7fff04", Err(ConfigStringError::ShortKeywordPath(3))),
            (
                "7fff04zz",
                Err(invalid_value("PATH", "7fff04zz", DEVICE_PATH)),
            ),
        ];
        for (digits, expected) in cases {
            assert_eq!(digits.parse::<KeywordPath>(), expected, "{digits:?}");
        }
    }

    #[test]
    fn keyword_path_holds_at_least_an_end_node() {
        let end_node = DevicePath::from(END_DEVICE_PATH.to_vec());

        assert_eq!(
            KeywordPath::try_from(end_node.clone())
                .map(|path| (path.as_ref().clone(), path.to_string())),
            Ok((end_node, "7fff0400".to_owned())),
            "an End node"
        );
        assert_eq!(
            KeywordPath::try_from(DevicePath::from(vec![0x7F, 0xFF, 0x04])),
            Err(ConfigStringError::ShortKeywordPath(3)),
            "3 bytes"
        );
    }

    #[test]
    fn keyword_info_filter_lists_items_in_bnf_order() {
        let cases = [
            (KeywordInfoFilter::empty(), ""),
            (KeywordInfoFilter::DISPLAY_NAME, "DisplayName"),
            (
                KeywordInfoFilter::DISPLAY_NAME | KeywordInfoFilter::VALUE_ATTRIBUTE,
                "ValueAttributeDisplayName",
            ),
            (KeywordInfoFilter::all(), "All"),
        ];
        for (filter, text) in cases {
            assert_eq!(filter.to_string(), text, "{filter:?}");
        }
    }

    #[test]
    fn data_filters_print_as_the_bnf_spells_them() {
        let cases = [
            (DataFilter::Buffer, "Buffer"),
            (DataFilter::Numeric(Numeric { width: None }), "Numeric"),
            (
                DataFilter::Numeric(Numeric {
                    width: Some(NumericWidth::One),
                }),
                "Numeric:1",
            ),
            (
                DataFilter::Numeric(Numeric {
                    width: Some(NumericWidth::Two),
                }),
                "Numeric:2",
            ),
            (
                DataFilter::Numeric(Numeric {
                    width: Some(NumericWidth::Four),
                }),
                "Numeric:4",
            ),
            (
                DataFilter::Numeric(Numeric {
                    width: Some(NumericWidth::Eight),
                }),
                "Numeric:8",
            ),
            (DataFilter::String, "String"),
            (DataFilter::Boolean, "Boolean"),
            (DataFilter::Date, "Date"),
            (DataFilter::Time, "Time"),
        ];
        for (filter, text) in cases {
            assert_eq!(
                (filter.to_string(), DataFilter::parse("DATATYPE", text)),
                (text.to_owned(), Ok(filter)),
                "{text}"
            );
        }
    }

    #[test]
    fn usage_filters_print_as_the_bnf_spells_them() {
        for (usage, text) in [
            (Usage::ReadOnly, "ReadOnly"),
            (Usage::ReadWrite, "ReadWrite"),
        ] {
            assert_eq!(usage.to_string(), text, "{usage:?}");
        }
    }

    #[test]
    fn keywords_and_namespaces_refuse_separators() {
        for valid in [
            "BIOSVendor",
            "ChipsetSATAPortEnable:5",
            "Port:1234",
            "x-UEFI-AMI",
        ] {
            assert_eq!(
                Keyword::try_from(valid).map(|keyword| keyword.to_string()),
                Ok(valid.to_owned()),
                "keyword {valid:?}"
            );
        }
        for invalid in [
            "",
            ":5",
            "Port:",
            "Port:12345",
            "Port:a",
            "Port:5:6",
            "a&b",
            "a=b",
            "a\0b",
        ] {
            assert_eq!(
                Keyword::try_from(invalid),
                Err(ConfigStringError::InvalidKeyword(invalid.to_owned())),
                "keyword {invalid:?}"
            );
        }
        for valid in ["x-UEFI-ns", "x-UEFI-extension-ACME"] {
            assert_eq!(
                Namespace::try_from(valid).map(|namespace| namespace.to_string()),
                Ok(valid.to_owned()),
                "namespace {valid:?}"
            );
        }
        for invalid in ["", "x UEFI", "a&b", "a=b", "x-UEFI-\u{e9}"] {
            assert_eq!(
                Namespace::try_from(invalid),
                Err(ConfigStringError::InvalidNamespace(invalid.to_owned())),
                "namespace {invalid:?}"
            );
        }
    }

    /// UEFI 2.10 §35.2.1.6.2's and §35.2.1.6.3's responses, with the NAMESPACE= and PATH= that
    /// `<KeywordResp>` has and hex VALUEs.
    #[test]
    fn keyword_resp_examples_parse_in_bnf_form() {
        let text = format!(
            "NAMESPACE=x-UEFI-ns&PATH=7fff0400&KEYWORD=BIOSVendor&VALUE={ACME_VALUE}\
             &NAMESPACE=x-UEFI-extension-ACME&PATH=7fff0400&KEYWORD=SpecialSettingX&VALUE=3"
        );
        let multi: MultiKeywordResp = text.parse().expect("parses");

        assert_eq!(
            multi.as_slice(),
            [
                bios_vendor_resp(KeywordInfo::default()),
                KeywordResp {
                    namespace: namespace("x-UEFI-extension-ACME"),
                    keyword: keyword("SpecialSettingX"),
                    value: number(&[0x03]),
                    ..bios_vendor_resp(KeywordInfo::default())
                },
            ],
            "§35.2.1.6.2 and §35.2.1.6.3 examples"
        );
        assert_eq!(
            multi.to_string(),
            text.replace("VALUE=3", "VALUE=03"),
            "a <Number> prints whole bytes"
        );
    }

    #[test]
    fn keyword_resp_examples_as_printed_are_refused() {
        let cases = [
            (
                "x-UEFI-ns&KEYWORD=BIOSVendor&VALUE=AcmeBIOSCompany".to_owned(),
                unexpected("NAMESPACE=", "x-UEFI-ns"),
            ),
            (
                "NAMESPACE=x-UEFI-ns&PATH=7fff0400&KEYWORD=BIOSVendor&VALUE=AcmeBIOSCompany"
                    .to_owned(),
                invalid_number("VALUE", 15),
            ),
            (
                format!(
                    "NAMESPACE=x-UEFI-ns&PATH=7fff0400&KEYWORD=BIOSVendor&VALUE={ACME_VALUE}\
                     &DataType=String&MAX=1e&MIN=06"
                ),
                unexpected(KEYWORD_RESP_END, "DataType=String"),
            ),
        ];
        for (text, error) in cases {
            assert_eq!(text.parse::<MultiKeywordResp>(), Err(error), "{text:?}");
        }
    }

    /// UEFI 2.10 §35.2.1.6.4's response, in BNF form: NAMESPACE=, PATH=, hex values, DATATYPE=.
    #[test]
    fn keyword_info_resp_example_parses_in_bnf_form() {
        let text = format!(
            "NAMESPACE=x-UEFI-ns&PATH=7fff0400&KEYWORD=BIOSVendor&VALUE={ACME_VALUE}\
             &DATATYPE=String&MAX=1e&MIN=06\
             &STANDARDDEFAULT={ACME_VALUE}&MFGDEFAULT={ACME_VALUE}"
        );
        let resp: MultiKeywordResp = text.parse().expect("parses");
        let acme = bios_vendor_resp(KeywordInfo::default()).value;

        assert_eq!(
            resp.as_slice(),
            [bios_vendor_resp(KeywordInfo {
                data_type: Some(DataFilter::String),
                range: Some(ValueRange {
                    max: number(&[0x1E]),
                    min: number(&[0x06]),
                    step: None,
                }),
                standard_default: Some(acme.clone()),
                manufacturing_default: Some(acme),
                ..KeywordInfo::default()
            })],
            "parsed"
        );
        assert_eq!(resp.to_string(), text, "printed");
    }

    #[test]
    fn keyword_resp_keeps_readonly_options_and_display_name() {
        let text = "NAMESPACE=x-UEFI-ns&PATH=7fff0400&KEYWORD=ChipsetSATAPortEnable:2&VALUE=01\
                    &READONLY&DATATYPE=Buffer&MAX=02&MIN=01&STEP=01\
                    &OPTIONVALUE=00&OPTIONSTRING=004f00660066&VALUETYPE=Numeric:1\
                    &OPTIONVALUE=01&OPTIONSTRING=004f006e\
                    &SAFEDEFAULT=00&DISPLAYNAME=0050006f00720074";
        let resp: MultiKeywordResp = text.parse().expect("parses");

        assert_eq!(
            resp.as_slice(),
            [KeywordResp {
                keyword: keyword("ChipsetSATAPortEnable:2"),
                value: number(&[0x01]),
                usage: Usage::ReadOnly,
                info: KeywordInfo {
                    data_type: Some(DataFilter::Buffer),
                    range: Some(ValueRange {
                        max: number(&[0x02]),
                        min: number(&[0x01]),
                        step: Some(number(&[0x01])),
                    }),
                    options: vec![
                        ValueOption {
                            value: number(&[0x00]),
                            string: ucs2("Off"),
                            value_type: Some(Numeric {
                                width: Some(NumericWidth::One),
                            }),
                        },
                        ValueOption {
                            value: number(&[0x01]),
                            string: ucs2("On"),
                            value_type: None,
                        },
                    ],
                    safe_default: Some(number(&[0x00])),
                    display_name: Some(ucs2("Port")),
                    ..KeywordInfo::default()
                },
                ..bios_vendor_resp(KeywordInfo::default())
            }],
            "parsed"
        );
        assert_eq!(resp.to_string(), text, "printed");
    }

    #[test]
    fn multi_keyword_resp_joins_its_keyword_resps() {
        let resps = vec![
            bios_vendor_resp(KeywordInfo::default()),
            KeywordResp {
                keyword: keyword("BIOSVersion"),
                usage: Usage::ReadOnly,
                ..bios_vendor_resp(KeywordInfo::default())
            },
        ];
        let multi = MultiKeywordResp::try_from(resps.clone()).expect("two KeywordResps");
        let text = format!(
            "NAMESPACE=x-UEFI-ns&PATH=7fff0400&KEYWORD=BIOSVendor&VALUE={ACME_VALUE}\
             &NAMESPACE=x-UEFI-ns&PATH=7fff0400&KEYWORD=BIOSVersion&VALUE={ACME_VALUE}&READONLY"
        );

        assert_eq!(multi.to_string(), text, "printed");
        assert_eq!(
            text.parse::<MultiKeywordResp>()
                .map(|parsed| parsed.as_slice().to_vec()),
            Ok(resps),
            "parsed back"
        );
        assert_eq!(
            MultiKeywordResp::try_from(Vec::new()),
            Err(ConfigStringError::EmptyMultiKeywordResp),
            "no KeywordResp"
        );
    }

    /// A setting may be a password, so an error names it but leaves out its digits.
    #[test]
    fn errors_leave_setting_values_out() {
        const SECRET: &str = "5ec2e7";
        let cases = [
            (
                "VALUE wider than WIDTH",
                parse_resp(&format!("&OFFSET=0&WIDTH=1&VALUE={SECRET}")).map(|_| ()),
                "VALUE",
            ),
            (
                "VALUE not hex",
                parse_resp(&format!("&OFFSET=0&WIDTH=4&VALUE={SECRET}x")).map(|_| ()),
                "VALUE",
            ),
            (
                "<NvConfig> value not hex",
                parse_resp(&format!("&fred={SECRET}x")).map(|_| ()),
                "fred",
            ),
            (
                "<KeywordResp> VALUE not hex",
                format!("NAMESPACE=x-UEFI-ns&PATH=7fff0400&KEYWORD=a&VALUE={SECRET}x")
                    .parse::<MultiKeywordResp>()
                    .map(|_| ()),
                "VALUE",
            ),
        ];
        for (case, result, name) in cases {
            let message = result.map_err(|error| error.to_string());
            assert!(
                message
                    .as_ref()
                    .is_err_and(|message| message.contains(name) && !message.contains(SECRET)),
                "{case}: {message:?}"
            );
        }
    }

    #[test]
    fn number_holds_at_least_one_byte_least_significant_first() {
        assert_eq!(
            Number::try_from(vec![0x55, 0xAA])
                .map(|number| (number.to_string(), number.as_bytes().to_vec())),
            Ok(("aa55".to_owned(), vec![0x55, 0xAA])),
            "2 bytes"
        );
        assert_eq!(
            Number::try_from(Vec::new()),
            Err(ConfigStringError::EmptyValue),
            "no byte"
        );
    }

    #[test]
    fn malformed_keyword_resp_is_refused() {
        let start = "NAMESPACE=x-UEFI-ns&PATH=7fff0400&KEYWORD=BIOSVendor&VALUE=01";
        let cases = [
            ("".to_owned(), unexpected("NAMESPACE=", "")),
            (
                "NAMESPACE=&PATH=&KEYWORD=a&VALUE=01".to_owned(),
                ConfigStringError::InvalidNamespace(String::new()),
            ),
            (
                "NAMESPACE=x-UEFI-ns&KEYWORD=a&VALUE=01".to_owned(),
                unexpected("PATH=", "KEYWORD=a"),
            ),
            (
                "NAMESPACE=x-UEFI-ns&PATH=7ff&KEYWORD=a&VALUE=01".to_owned(),
                invalid_value("PATH", "7ff", DEVICE_PATH),
            ),
            (
                "NAMESPACE=x-UEFI-ns&PATH=&KEYWORD=a&VALUE=01".to_owned(),
                ConfigStringError::ShortKeywordPath(0),
            ),
            (
                "NAMESPACE=x-UEFI-ns&PATH=7fff&KEYWORD=a&VALUE=01".to_owned(),
                ConfigStringError::ShortKeywordPath(2),
            ),
            (
                "NAMESPACE=x-UEFI-ns&PATH=7fff0400&KEYWORD=Port:12345&VALUE=01".to_owned(),
                ConfigStringError::InvalidKeyword("Port:12345".to_owned()),
            ),
            (
                "NAMESPACE=x-UEFI-ns&PATH=7fff0400&KEYWORD=a".to_owned(),
                ConfigStringError::Truncated { expected: "VALUE=" },
            ),
            (format!("{start}&"), unexpected(KEYWORD_RESP_END, "")),
            (
                format!("{start}&READONLY&READONLY"),
                unexpected(KEYWORD_RESP_END, "READONLY"),
            ),
            (
                format!("{start}&READONLYX"),
                unexpected(KEYWORD_RESP_END, "READONLYX"),
            ),
            (
                format!("{start}&DATATYPE=Numeric:3"),
                invalid_value("DATATYPE", "Numeric:3", DATA_FILTER),
            ),
            (
                format!("{start}&MAX=02"),
                ConfigStringError::Truncated { expected: "MIN=" },
            ),
            (
                format!("{start}&MAX=02&STEP=01"),
                unexpected("MIN=", "STEP=01"),
            ),
            (
                format!("{start}&OPTIONVALUE=00&VALUETYPE=Numeric"),
                unexpected("OPTIONSTRING=", "VALUETYPE=Numeric"),
            ),
            (
                format!("{start}&OPTIONVALUE=00&OPTIONSTRING=004&VALUETYPE=Numeric"),
                invalid_value("OPTIONSTRING", "004", STRING),
            ),
            (
                format!("{start}&OPTIONVALUE=00&OPTIONSTRING=004f&VALUETYPE=Buffer"),
                invalid_value("VALUETYPE", "Buffer", NUMERIC_TYPE),
            ),
            (
                format!("{start}&MFGDEFAULT=00&STANDARDDEFAULT=00"),
                unexpected(KEYWORD_RESP_END, "STANDARDDEFAULT=00"),
            ),
            (
                format!("{start}&DISPLAYNAME=0050&DATATYPE=String"),
                unexpected(KEYWORD_RESP_END, "DATATYPE=String"),
            ),
        ];
        for (text, error) in cases {
            assert_eq!(text.parse::<MultiKeywordResp>(), Err(error), "{text:?}");
        }
    }
}
