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
//! storage to read, and a `<ConfigResp>` carries their values.

use std::fmt;
use std::iter::Peekable;
use std::num::NonZeroUsize;
use std::str::FromStr;
use std::str::Split;

use thiserror::Error;

use crate::hii::forms::DefaultId;
use crate::hii::package::DevicePath;
use crate::hii::package::Guid;

/// The names that UEFI 2.10 §35.2.1.5 reserves: "cannot be used as names in a `<ConfigElement>`".
const RESERVED_NAMES: [&str; 7] = ["GUID", "NAME", "PATH", "ALTCFG", "OFFSET", "WIDTH", "VALUE"];

/// The furthest end of a `<BlockConfig>`. Blocks lie in IFR varstores, whose Size is a UINT16
/// (UEFI 2.10 §33.3.8.3.89, §33.3.8.3.91), so no storage holds a byte at or past it, and no
/// WIDTH makes a value allocate more than 64 KiB.
const MAX_BLOCK_END: usize = 0xFFFF;

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
    #[error("{0:?} is not a <Label>: a letter or _, then letters, digits and _")]
    InvalidLabel(String),
    #[error("{0} is a reserved name, so no <Label>")]
    ReservedName(String),
    #[error("VALUE={value} is wider than WIDTH={width}")]
    ValueWiderThanWidth { value: String, width: usize },
    #[error("the block at OFFSET={offset:#x} of WIDTH={width:#x} ends past every IFR varstore")]
    BlockBeyondStorage { offset: usize, width: usize },
    #[error("an <AltResp> comes before any <ConfigResp>")]
    AltRespFirst,
    #[error("an <AltResp> names another storage than its <ConfigResp>")]
    AltRespHeader,
    #[error("a <ConfigRequest> without <RequestElement>s requests every setting of its storage")]
    EmptyRequest,
    #[error("a <BlockConfig> has at least one byte")]
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

        let name_digits = elements.required_value("NAME=")?;
        let name = name_digits
            .as_bytes()
            .chunks(4)
            .map(|unit| match unit {
                [a, b, c, d] => Some(u16::from_be_bytes([hex_byte(*a, *b)?, hex_byte(*c, *d)?])),
                _ => None,
            })
            .collect::<Option<_>>()
            .ok_or_else(|| invalid_value("NAME", name_digits, STRING))?;

        let path_digits = elements.required_value("PATH=")?;
        let device_path = hex_bytes(path_digits)
            .ok_or_else(|| invalid_value("PATH", path_digits, DEVICE_PATH))?;

        Ok(Self {
            guid: guid.into(),
            name,
            device_path,
        })
    }
}

impl fmt::Display for ConfigHdr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GUID=")?;
        write_hex(f, &<[u8; 16]>::from(self.guid))?;
        f.write_str("&NAME=")?;
        self.name
            .iter()
            .try_for_each(|unit| write!(f, "{unit:04x}"))?;
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
            hex_number(value_digits).ok_or_else(|| invalid_value("VALUE", value_digits, NUMBER))?;
        let beyond_width = value.get(width.get()..);
        if beyond_width.is_some_and(|bytes| bytes.iter().any(|byte| *byte != 0)) {
            return Err(ConfigStringError::ValueWiderThanWidth {
                value: value_digits.to_owned(),
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
            return Err(invalid_value(&label.0, value, NUMBER));
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
}

impl FromStr for MultiConfigAltResp {
    type Err = ConfigStringError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let mut elements = Elements::new(text);
        let mut resps: Vec<ConfigAltResp> = Vec::new();
        loop {
            let header = ConfigHdr::parse(&mut elements)?;
            match elements.optional_value("ALTCFG=") {
                Some(digits) => {
                    let alt_cfg_id = DefaultId(parse_alt_cfg_id(digits)?);
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

impl fmt::Display for MultiConfigAltResp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut resps = self.0.iter();
        let Some(first) = resps.next() else {
            return Ok(());
        };
        first.fmt(f)?;
        resps.try_for_each(|resp| write!(f, "&{resp}"))
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

fn parse_alt_cfg_id(digits: &str) -> Result<u16, ConfigStringError> {
    match digits.as_bytes() {
        [a, b, c, d] => hex_byte(*a, *b)
            .zip(hex_byte(*c, *d))
            .map(|(high, low)| u16::from_be_bytes([high, low])),
        _ => None,
    }
    .ok_or_else(|| invalid_value("ALTCFG", digits, ALT_CFG_ID))
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

/// The bytes of `digits`, two hex digits per byte in order, as `<Guid>` and `<PathHdr>` list them.
fn hex_bytes<B: FromIterator<u8>>(digits: &str) -> Option<B> {
    digits
        .as_bytes()
        .chunks(2)
        .map(|pair| match pair {
            [high, low] => hex_byte(*high, *low),
            _ => None,
        })
        .collect()
}

fn hex_byte(high: u8, low: u8) -> Option<u8> {
    Some((hex_digit(high)? << 4) | hex_digit(low)?)
}

/// The value of a hex digit of either case: `<HexCh>` is lowercase, but EDK2's StrHexToUint64
/// reads both and §35.4.6's example has "AA55".
fn hex_digit(digit: u8) -> Option<u8> {
    match digit {
        b'0'..=b'9' => Some(digit - b'0'),
        b'a'..=b'f' => Some(digit - b'a' + 10),
        b'A'..=b'F' => Some(digit - b'A' + 10),
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
                value: "0102".to_owned(),
                width: 1,
            }),
            "nonzero byte past WIDTH"
        );
        assert_eq!(
            parse_resp("&OFFSET=0&WIDTH=1&VALUE=010002"),
            Err(ConfigStringError::ValueWiderThanWidth {
                value: "010002".to_owned(),
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
                Err(invalid_value("fred", invalid, NUMBER)),
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
                invalid_value("VALUE", "", NUMBER),
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
            (
                format!("{header}&fred=xyz"),
                invalid_value("fred", "xyz", NUMBER),
            ),
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
}
