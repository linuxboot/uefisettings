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

//! The option parameters of a named form (UEFI 2.11 §10.6.1.5): read from its text as Table 10.66
//! types them, and written into it as edk2-stable202608's DevicePathToText.c writes them.

use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::str::FromStr;

use super::DevicePathTextError;
use crate::hii::package::Guid;

/// An IP address parameter as Table 10.66 writes one: the address, then the port after ":", 0
/// if none.
pub(super) struct IpParameter<const N: usize> {
    pub(super) address: [u8; N],
    pub(super) port: u16,
}

impl<const N: usize> IpParameter<N> {
    /// All zeros, an omitted address
    const ZERO: Self = Self {
        address: [0; N],
        port: 0,
    };
}

/// The parameters of a named form, comma-separated as edk2's GetNextParamStr() splits them; a
/// missing one reads as "".
pub(super) struct Parameters<'a>(std::vec::IntoIter<&'a str>);

impl<'a> Parameters<'a> {
    /// The parameters between a form's parentheses: "Name()" has none, not one empty one.
    pub(super) fn new(text: &'a str) -> Self {
        let parameters = match text {
            "" => Vec::new(),
            text => text.split(',').collect(),
        };
        Self(parameters.into_iter())
    }

    pub(super) fn next(&mut self) -> &'a str {
        self.0.next().unwrap_or("")
    }

    /// The next parameter, None if omitted.
    pub(super) fn optional(&mut self) -> Option<&'a str> {
        Some(self.next()).filter(|text| !text.is_empty())
    }

    /// The parameters not read yet.
    pub(super) fn rest(&mut self) -> impl Iterator<Item = &'a str> + '_ {
        self.0.by_ref()
    }

    pub(super) fn integer<T: TryFrom<u64>>(&mut self) -> Result<T, DevicePathTextError> {
        integer(self.next())
    }

    /// An Integer, `default` if omitted.
    pub(super) fn integer_or<T: TryFrom<u64>>(
        &mut self,
        default: T,
    ) -> Result<T, DevicePathTextError> {
        match self.next() {
            "" => Ok(default),
            text => integer(text),
        }
    }

    /// The value of one of `keywords`, `default` if omitted.
    pub(super) fn keyword_or<T: Copy>(
        &mut self,
        keywords: &[(&str, T)],
        default: T,
    ) -> Result<T, DevicePathTextError> {
        self.optional()
            .map_or(Ok(default), |text| keyword(text, keywords))
    }

    /// The value of one of `keywords`, else an Integer.
    pub(super) fn keyword_or_integer<T: Copy + TryFrom<u64>>(
        &mut self,
        keywords: &[(&str, T)],
    ) -> Result<T, DevicePathTextError> {
        keyword_or_integer(self.next(), keywords)
    }

    /// A Hex Dump, none if omitted.
    pub(super) fn hex(&mut self) -> Result<Vec<u8>, DevicePathTextError> {
        hex_dump(self.next())
    }

    /// A Hex Dump of exactly N bytes.
    pub(super) fn hex_array<const N: usize>(&mut self) -> Result<[u8; N], DevicePathTextError> {
        let text = self.next();
        hex_dump(text)?
            .try_into()
            .map_err(|_| DevicePathTextError::HexDump(text.to_owned()))
    }

    /// An 8-byte array that edk2 writes as "0x" and its bytes in order, byte 0 first, and reads as
    /// an Integer whose bytes it swaps.
    pub(super) fn byte_array(&mut self) -> Result<[u8; 8], DevicePathTextError> {
        self.integer::<u64>().map(u64::to_be_bytes)
    }

    pub(super) fn guid(&mut self) -> Result<[u8; 16], DevicePathTextError> {
        guid(self.next()).map(<[u8; 16]>::from)
    }

    /// An EISAID, `default` if omitted.
    pub(super) fn eisa_id_or(&mut self, default: u32) -> Result<u32, DevicePathTextError> {
        match self.next() {
            "" => Ok(default),
            text => eisa_id(text),
        }
    }

    /// A String of ASCII characters but Null, as edk2 copies each character into a CHAR8.
    pub(super) fn ascii(&mut self) -> Result<&'a str, DevicePathTextError> {
        let text = self.next();
        match text.chars().all(|c| c.is_ascii() && c != '\0') {
            true => Ok(text),
            false => Err(DevicePathTextError::NotAscii(text.to_owned())),
        }
    }

    /// A String of ASCII characters but Null that fits a field of `max` bytes.
    pub(super) fn ascii_up_to(&mut self, max: usize) -> Result<&'a str, DevicePathTextError> {
        let text = self.ascii()?;
        match text.len() <= max {
            true => Ok(text),
            false => Err(DevicePathTextError::TooLongString(text.to_owned(), max)),
        }
    }

    /// An IPv4 Address, its port too if `with_port`, all zeros if omitted.
    pub(super) fn ipv4_or_zero(
        &mut self,
        with_port: bool,
    ) -> Result<IpParameter<4>, DevicePathTextError> {
        self.optional()
            .map_or(Ok(IpParameter::ZERO), |text| ipv4(text, with_port))
    }

    /// An IPv6 Address, its port too if `with_port`, all zeros if omitted.
    pub(super) fn ipv6_or_zero(
        &mut self,
        with_port: bool,
    ) -> Result<IpParameter<16>, DevicePathTextError> {
        self.optional()
            .map_or(Ok(IpParameter::ZERO), |text| ipv6(text, with_port))
    }

    /// Fails if parameters are left.
    pub(super) fn finish(mut self, text: &str) -> Result<(), DevicePathTextError> {
        match self.0.next() {
            None => Ok(()),
            Some(_) => Err(DevicePathTextError::Parameters(text.to_owned())),
        }
    }
}

/// An Integer of UEFI 2.11 Table 10.66: hexadecimal after "0x" or "0X", else decimal.
pub(super) fn integer<T: TryFrom<u64>>(text: &str) -> Result<T, DevicePathTextError> {
    let (digits, radix) = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(digits) => (digits, 16),
        None => (text, 10),
    };
    digits
        .chars()
        .all(|c| c.is_digit(radix))
        .then(|| u64::from_str_radix(digits, radix).ok())
        .flatten()
        .and_then(|value| T::try_from(value).ok())
        .ok_or_else(|| DevicePathTextError::Value(text.to_owned()))
}

/// The value of one of `keywords`, as edk2 compares them: case-sensitive.
pub(super) fn keyword<T: Copy>(
    text: &str,
    keywords: &[(&str, T)],
) -> Result<T, DevicePathTextError> {
    keywords
        .iter()
        .find(|(keyword, _)| *keyword == text)
        .map(|(_, value)| *value)
        .ok_or_else(|| DevicePathTextError::Value(text.to_owned()))
}

/// The value of one of `keywords`, else an Integer.
pub(super) fn keyword_or_integer<T: Copy + TryFrom<u64>>(
    text: &str,
    keywords: &[(&str, T)],
) -> Result<T, DevicePathTextError> {
    keyword(text, keywords).or_else(|_| integer(text))
}

/// An IPv4 Address of UEFI 2.11 Table 10.66, and its port after ":", 0 if none, which only
/// `with_port` takes.
pub(super) fn ipv4(text: &str, with_port: bool) -> Result<IpParameter<4>, DevicePathTextError> {
    let invalid = || DevicePathTextError::IpAddress(text.to_owned());
    let (address, port) = match text.split_once(':') {
        Some((address, port)) if with_port => (address, integer(port)?),
        Some(_) => return Err(invalid()),
        None => (text, 0),
    };
    Ipv4Addr::from_str(address)
        .map(|address| IpParameter {
            address: address.octets(),
            port,
        })
        .map_err(|_| invalid())
}

/// An IPv6 Address of UEFI 2.11 Table 10.66, `[address]:port` or `[address]`, or the bare
/// address as edk2 writes it; the port, 0 if none, only `with_port` takes. The address is
/// hexadecimal pieces as edk2's StrToIpv6Address() reads them, "::" too, but no dotted IPv4
/// tail, which it does not read.
pub(super) fn ipv6(text: &str, with_port: bool) -> Result<IpParameter<16>, DevicePathTextError> {
    let invalid = || DevicePathTextError::IpAddress(text.to_owned());
    let (address, port) = match text.strip_prefix('[') {
        Some(bracketed) => match bracketed.split_once(']').ok_or_else(invalid)? {
            (address, "") => (address, 0),
            (address, port) => match port.strip_prefix(':') {
                Some(port) if with_port => (address, integer(port)?),
                Some(_) | None => return Err(invalid()),
            },
        },
        None => (text, 0),
    };
    match address.contains('.') {
        true => Err(invalid()),
        false => Ipv6Addr::from_str(address)
            .map(|address| IpParameter {
                address: address.octets(),
                port,
            })
            .map_err(|_| invalid()),
    }
}

/// A Hex Dump of UEFI 2.11 Table 10.66: two hexadecimal digits a byte.
fn hex_dump(text: &str) -> Result<Vec<u8>, DevicePathTextError> {
    let digits = text.as_bytes();
    match digits.len().is_multiple_of(2) && digits.iter().all(u8::is_ascii_hexdigit) {
        true => Ok(digits
            .chunks_exact(2)
            .filter_map(|pair| std::str::from_utf8(pair).ok())
            .filter_map(|pair| u8::from_str_radix(pair, 16).ok())
            .collect()),
        false => Err(DevicePathTextError::HexDump(text.to_owned())),
    }
}

pub(super) fn guid(text: &str) -> Result<Guid, DevicePathTextError> {
    Guid::from_str(text).map_err(|_| DevicePathTextError::Guid(text.to_owned()))
}

/// An EISAID of UEFI 2.11 Table 10.66: three letters and four hexadecimal digits, or 0. The
/// letters may also be "@" and "[" to "_", the 5-bit values 0 and 27 to 31 that edk2 writes as
/// "@" + value and its EisaIdFromText() reads back.
pub(super) fn eisa_id(text: &str) -> Result<u32, DevicePathTextError> {
    if text == "0" {
        return Ok(0);
    }
    let invalid = || DevicePathTextError::EisaId(text.to_owned());
    let (letters, number) = text.split_at_checked(3).ok_or_else(invalid)?;
    let letters: Option<Vec<u32>> = letters
        .bytes()
        .map(|letter| match letter.to_ascii_uppercase() {
            letter @ b'@'..=b'_' => Some(u32::from(letter - b'@')),
            _ => None,
        })
        .collect();
    let compressed = letters
        .ok_or_else(invalid)?
        .into_iter()
        .fold(0, |id, letter| id << 5 | letter);
    if number.len() != 4 || !number.bytes().all(|digit| digit.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    let number = u32::from_str_radix(number, 16).map_err(|_| invalid())?;
    Ok(compressed | number << 16)
}

/// An EISA ID as edk2 writes one: each 5-bit letter as "@" + its value, then the high 16 bits in
/// hexadecimal; None if bit 15, outside the letters, is set, as no text holds it.
pub(super) fn eisa_id_text(id: u32) -> Option<String> {
    let letters: String = [10, 5, 0]
        .map(|shift| (id >> shift) & 0x1F)
        .iter()
        .filter_map(|letter| char::from_u32(u32::from(b'@') + letter))
        .collect();
    (id & 0x8000 == 0).then(|| format!("{letters}{:04X}", id >> 16))
}

/// `bytes` in uppercase hex, two digits a byte, as edk2's PrintLib writes "%02x".
pub(super) fn upper_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02X}")).collect()
}

/// `bytes` as a String if each is an ASCII character but Null, as edk2's "%a" writes them and its
/// StrToAscii() reads them back.
pub(super) fn ascii_text(bytes: &[u8]) -> Option<&str> {
    bytes
        .iter()
        .all(|byte| byte.is_ascii() && *byte != 0)
        .then(|| std::str::from_utf8(bytes).ok())
        .flatten()
}

/// An IPv4 address as edk2's CatIPv4Address() writes it.
pub(super) fn ipv4_text(address: [u8; 4]) -> String {
    Ipv4Addr::from(address).to_string()
}

/// An IPv6 address as edk2's CatIPv6Address() writes it: 8 pieces of 4 hexadecimal digits.
pub(super) fn ipv6_text(address: [u8; 16]) -> String {
    let pieces: Vec<String> = address.chunks_exact(2).map(upper_hex).collect();
    pieces.join(":")
}
