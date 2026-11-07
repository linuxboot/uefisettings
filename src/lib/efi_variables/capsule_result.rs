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

//! The results of capsule processing that the firmware reports (UEFI 2.11 §8.5.6): a Capsule####
//! variable of EFI_CAPSULE_REPORT_GUID for each capsule payload that it processed, CapsuleMax and
//! CapsuleLast, which name such variables, and the JSON capsule result table that it installs
//! for a JSON capsule (§23.5.3). A result is an EFI_CAPSULE_RESULT_VARIABLE_HEADER, whose
//! CapsuleStatus is an EFI_STATUS, a UINTN of the firmware's width, then for an FMP capsule an
//! EFI_CAPSULE_RESULT_VARIABLE_FMP, and for a JSON capsule an EFI_CAPSULE_RESULT_VARIABLE_JSON.

use std::fmt;

#[cfg(configuration_tables)]
use anyhow::Context;
use anyhow::Result;
use serde::ser::SerializeMap;
use serde::Serialize;
use serde::Serializer;
use thiserror::Error;

use super::json_bytes::Hex;
use super::json_bytes::TextOrHex;
#[cfg(variable_names)]
use super::list_variables;
use super::VariableData;
#[cfg(variable_names)]
use super::VariableNames;
#[cfg(configuration_tables)]
use super::VendorTable;
use super::EFI_JSON_CAPSULE_ID_GUID;
use super::EFI_TIME_SIZE;
use crate::firmware_width::FirmwareWidth;
use crate::hii::package::Guid;
use crate::hii::VariableKey;

/// EFI_CAPSULE_REPORT_GUID, the vendor GUID of the result variables (UEFI 2.11 §8.5.6.1).
pub(crate) const EFI_CAPSULE_REPORT_GUID: Guid = Guid {
    data1: 0x39b6_8c46,
    data2: 0xf7fb,
    data3: 0x441b,
    data4: [0xb6, 0xec, 0x16, 0xb0, 0xf6, 0x98, 0x21, 0xf3],
};
/// EFI_JSON_CAPSULE_RESULT_TABLE_GUID, the configuration table of the result of a JSON capsule
/// (UEFI 2.11 §4.6.1.2, §23.5.3).
#[cfg(configuration_tables)]
pub(crate) const EFI_JSON_CAPSULE_RESULT_TABLE_GUID: Guid = Guid {
    data1: 0xdbc4_61c3,
    data2: 0xb3de,
    data3: 0x422a,
    data4: [0xb9, 0xb4, 0x98, 0x86, 0xfd, 0x49, 0xa1, 0xe5],
};
/// The offset of CapsuleGuid, after the UINT32s VariableTotalSize, the first field, and Reserved
/// (UEFI 2.11 §8.5.6.1.1).
const CAPSULE_GUID_OFFSET: usize = 4 + 4;
/// The offset of CapsuleProcessed, after the CapsuleGuid.
const CAPSULE_PROCESSED_OFFSET: usize = CAPSULE_GUID_OFFSET + 16;
/// The offset of CapsuleStatus, after CapsuleProcessed, which aligns it for either width.
const CAPSULE_STATUS_OFFSET: usize = CAPSULE_PROCESSED_OFFSET + EFI_TIME_SIZE;
/// sizeof (EFI_CAPSULE_RESULT_VARIABLE_JSON) before its Resp: the UINT32s Version, CapsuleId
/// and RespLength (UEFI 2.11 §8.5.6.1.3).
const JSON_RESULT_HEADER_SIZE: usize = 3 * 4;
/// EFI_CAPSULE_RESULT_VARIABLE_JSON's Version, "currently 0x00000001" (UEFI 2.11 §8.5.6.1.3).
const JSON_RESULT_VERSION: u32 = 1;
/// EFI_FIRMWARE_MANAGEMENT_CAPSULE_ID_GUID, the CapsuleGuid of an FMP capsule (UEFI 2.11
/// §23.3.1), whose result adds an EFI_CAPSULE_RESULT_VARIABLE_FMP (§8.5.6.1.2).
const EFI_FIRMWARE_MANAGEMENT_CAPSULE_ID_GUID: Guid = Guid {
    data1: 0x6dcb_d5ed,
    data2: 0xe82d,
    data3: 0x4c44,
    data4: [0xbd, 0xa1, 0x71, 0x94, 0x19, 0x9a, 0xd9, 0x2a],
};
/// sizeof (EFI_CAPSULE_RESULT_VARIABLE_FMP) before its strings: the UINT16 Version, the UINT8s
/// PayloadIndex and UpdateImageIndex, and the UpdateImageTypeId (UEFI 2.11 §8.5.6.1.2).
const FMP_RESULT_HEADER_SIZE: usize = 2 + 1 + 1 + 16;
/// EFI_CAPSULE_RESULT_VARIABLE_FMP's Version, "currently 0x00000001" (UEFI 2.11 §8.5.6.1.2).
const FMP_RESULT_VERSION: u16 = 1;
/// The name of a result variable before its 4 hexadecimal digits (UEFI 2.11 §8.5.6).
const RESULT_NAME_PREFIX: &str = "Capsule";
/// The hexadecimal digits of the name of a result variable.
const RESULT_NAME_DIGITS: usize = 4;
/// The CHAR16s of the name of a result variable, as CapsuleMax and CapsuleLast hold it without a
/// terminator (UEFI 2.11 §8.5.6, Table 8.9).
const RESULT_NAME_UNITS: usize = RESULT_NAME_PREFIX.len() + RESULT_NAME_DIGITS;
/// The bytes of RESULT_NAME_UNITS.
const RESULT_NAME_SIZE: usize = 2 * RESULT_NAME_UNITS;
/// The variable that names the last result variable before the firmware rolls over to
/// Capsule0000 (UEFI 2.11 §8.5.6).
const CAPSULE_MAX: &str = "CapsuleMax";
/// The variable that names the result variable that the firmware created last (UEFI 2.11
/// §8.5.6).
const CAPSULE_LAST: &str = "CapsuleLast";

/// The size of the EFI_CAPSULE_RESULT_VARIABLE_HEADER of firmware of `width`: 44 bytes on
/// 32-bit firmware, 48 on 64-bit firmware.
const fn header_size(width: FirmwareWidth) -> usize {
    CAPSULE_STATUS_OFFSET + width.uintn_size()
}

/// The name of a result variable: "Capsule", then 4 hexadecimal digits, "chosen by the firmware"
/// (UEFI 2.11 §8.5.6). It serializes as the name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResultName {
    name: String,
    #[cfg_attr(
        not(any(target_os = "windows", test)),
        allow(dead_code, reason = "only the Windows build reads results by index")
    )]
    index: ResultIndex,
}

/// The value of the hexadecimal digits of the name of a result variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct ResultIndex(u16);

/// The case of the letter digits of a result name, which the firmware chooses.
#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HexCase {
    Upper,
    Lower,
}

impl ResultName {
    /// `name`, if it is the name of a result variable.
    pub fn parse(name: &str) -> Option<Self> {
        let digits = name.strip_prefix(RESULT_NAME_PREFIX)?;
        if digits.len() != RESULT_NAME_DIGITS
            || !digits.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return None;
        }
        Some(Self {
            name: name.to_owned(),
            index: ResultIndex(u16::from_str_radix(digits, 16).ok()?),
        })
    }

    /// The result variable of `index`, in digits of `case`.
    #[cfg(any(target_os = "windows", test))]
    fn of_index(index: ResultIndex, case: HexCase) -> Self {
        let ResultIndex(value) = index;
        let name = match case {
            HexCase::Upper => format!("{RESULT_NAME_PREFIX}{value:0RESULT_NAME_DIGITS$X}"),
            HexCase::Lower => format!("{RESULT_NAME_PREFIX}{value:0RESULT_NAME_DIGITS$x}"),
        };
        Self { name, index }
    }

    /// The case of the name's letter digits, if it has some, all in one case.
    #[cfg(any(target_os = "windows", test))]
    fn letter_case(&self) -> Option<HexCase> {
        let digits = self.name.strip_prefix(RESULT_NAME_PREFIX)?;
        let upper = digits.bytes().any(|digit| digit.is_ascii_uppercase());
        let lower = digits.bytes().any(|digit| digit.is_ascii_lowercase());
        match (upper, lower) {
            (true, false) => Some(HexCase::Upper),
            (false, true) => Some(HexCase::Lower),
            (false, false) | (true, true) => None,
        }
    }

    /// The value of the name's digits.
    #[cfg(any(target_os = "windows", test))]
    fn index(&self) -> ResultIndex {
        self.index
    }

    /// The name that `data`, the data of CapsuleMax or CapsuleLast, holds: "CHAR16\[11\] (no zero
    /// terminator)" (UEFI 2.11 §8.5.6, Table 8.9).
    fn from_data(variable: &'static str, data: &[u8]) -> Result<Self, CapsuleResultError> {
        let size_error = CapsuleResultError::NameSize {
            variable,
            size: data.len(),
        };
        let (units, []) = data.as_chunks::<2>() else {
            return Err(size_error);
        };
        if units.len() != RESULT_NAME_UNITS {
            return Err(size_error);
        }
        let units: Vec<u16> = units.iter().map(|&unit| u16::from_le_bytes(unit)).collect();
        let text = String::from_utf16_lossy(&units);
        Self::parse(&text).ok_or(CapsuleResultError::NameText { variable, text })
    }

    pub fn as_str(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for ResultName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.name)
    }
}

impl Serialize for ResultName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.name)
    }
}

/// EFI_TIME (UEFI 2.11 §8.3.1), as the firmware wrote it, without its padding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct EfiTime {
    pub year: u16,
    pub month: u8,
    pub day: u8,
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
    pub nanosecond: u32,
    /// Minutes from UTC, or 2047, EFI_UNSPECIFIED_TIMEZONE
    pub time_zone: i16,
    pub daylight: u8,
}

impl From<[u8; EFI_TIME_SIZE]> for EfiTime {
    fn from(bytes: [u8; EFI_TIME_SIZE]) -> Self {
        let [y0, y1, month, day, hour, minute, second, _pad1, n0, n1, n2, n3, z0, z1, daylight, _pad2] =
            bytes;
        Self {
            year: u16::from_le_bytes([y0, y1]),
            month,
            day,
            hour,
            minute,
            second,
            nanosecond: u32::from_le_bytes([n0, n1, n2, n3]),
            time_zone: i16::from_le_bytes([z0, z1]),
            daylight,
        }
    }
}

/// A result of capsule processing: an EFI_CAPSULE_RESULT_VARIABLE_HEADER, and what follows it
/// (UEFI 2.11 §8.5.6.1). It serializes as the header's fields, then what follows under the key
/// of its kind.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct CapsuleResult {
    /// VariableTotalSize: the size of the result, header included
    pub variable_total_size: u32,
    /// CapsuleGuid, that of the processed capsule's EFI_CAPSULE_HEADER
    pub capsule_guid: Guid,
    /// CapsuleProcessed: "Timestamp using system time when processing completed"
    pub capsule_processed: EfiTime,
    /// CapsuleStatus, an EFI_STATUS of the firmware's width
    #[serde(serialize_with = "serialize_status")]
    pub capsule_status: u64,
    /// What follows the header
    #[serde(flatten)]
    pub details: CapsuleResultDetails,
}

/// `status`, an EFI_STATUS, in lowercase hex: an error status sets the high bit of the UINTN
/// (edk2-stable202508 MdePkg/Include/Base.h ENCODE_ERROR), and a JSON number of 64-bit firmware's
/// errors loses its low bits where JSON numbers are doubles, as JavaScript reads them.
fn serialize_status<S: Serializer>(status: &u64, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.collect_str(&format_args!("{status:#x}"))
}

/// What follows the header of a result, which its CapsuleGuid determines (UEFI 2.11 §8.5.6.1).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub enum CapsuleResultDetails {
    /// The EFI_CAPSULE_RESULT_VARIABLE_FMP of an FMP capsule (§8.5.6.1.2)
    #[serde(rename = "fmp")]
    Fmp(FmpCapsuleResult),
    /// The EFI_CAPSULE_RESULT_VARIABLE_JSON of a JSON capsule (§8.5.6.1.3)
    #[serde(rename = "json")]
    Json(JsonCapsuleResult),
    /// The bytes after the header, of any other CapsuleGuid, or of a part of a Version that
    /// uefisettings does not read, which serialize as hex, UTF-8 or not
    #[serde(rename = "data", serialize_with = "serialize_hex")]
    Other(Vec<u8>),
}

/// `bytes` as Hex serializes them.
fn serialize_hex<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    Hex(bytes).serialize(serializer)
}

/// An EFI_CAPSULE_RESULT_VARIABLE_FMP of Version 1 (UEFI 2.11 §8.5.6.1.2).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct FmpCapsuleResult {
    /// PayloadIndex: the index of the processed payload within the FMP capsule, from zero
    pub payload_index: u8,
    /// UpdateImageIndex: that of the payload's EFI_FIRMWARE_MANAGEMENT_CAPSULE_IMAGE_HEADER
    pub update_image_index: u8,
    /// UpdateImageTypeId: that of the payload's EFI_FIRMWARE_MANAGEMENT_CAPSULE_IMAGE_HEADER
    pub update_image_type_id: Guid,
    /// CapsuleFileName: the file that the capsule was loaded from, empty for a capsule passed to
    /// UpdateCapsule()
    pub capsule_file_name: String,
    /// CapsuleTarget: the text of the device path of the device publishing the Firmware
    /// Management Protocol, empty where the firmware knows none, or blocked or skipped the
    /// payload
    pub capsule_target: String,
}

/// An EFI_CAPSULE_RESULT_VARIABLE_JSON of Version 1 (UEFI 2.11 §8.5.6.1.3).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct JsonCapsuleResult {
    /// CapsuleId: that of the processed capsule's EFI_JSON_CAPSULE_HEADER
    pub capsule_id: u32,
    /// Resp: "the replied JSON payload", which uefisettings does not parse, and which serializes
    /// as TextOrHex does
    #[serde(serialize_with = "serialize_text_or_hex")]
    pub resp: Vec<u8>,
}

/// `bytes` as TextOrHex serializes them.
fn serialize_text_or_hex<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    TextOrHex(bytes).serialize(serializer)
}

impl CapsuleResult {
    /// The result that `bytes`, all of a result variable's data, hold, of firmware of `width`.
    pub(crate) fn decode(bytes: &[u8], width: FirmwareWidth) -> Result<Self, CapsuleResultError> {
        let header = header_size(width);
        let Some((fields, rest)) = bytes
            .split_at_checked(header)
            .and_then(|(fields, rest)| Some((HeaderFields::of(fields, width)?, rest)))
        else {
            return Err(CapsuleResultError::HeaderShort {
                size: bytes.len(),
                header,
                bits: width.bits(),
            });
        };
        let total_size = fields.variable_total_size;
        match usize::try_from(total_size) {
            Ok(total) if total < header => {
                return Err(CapsuleResultError::TotalSizeShort { total_size, header });
            }
            Ok(total) if total == bytes.len() => {}
            _ => {
                return Err(CapsuleResultError::TotalSizeNotSize {
                    total_size,
                    size: bytes.len(),
                });
            }
        }

        let details = match fields.capsule_guid {
            EFI_FIRMWARE_MANAGEMENT_CAPSULE_ID_GUID => {
                FmpCapsuleResult::decode(rest)?.map(CapsuleResultDetails::Fmp)
            }
            EFI_JSON_CAPSULE_ID_GUID => {
                JsonCapsuleResult::decode(rest)?.map(CapsuleResultDetails::Json)
            }
            _ => None,
        }
        .unwrap_or_else(|| CapsuleResultDetails::Other(rest.to_vec()));
        Ok(Self {
            variable_total_size: total_size,
            capsule_guid: fields.capsule_guid,
            capsule_processed: fields.capsule_processed,
            capsule_status: fields.capsule_status,
            details,
        })
    }

    /// The result of `table`, the JSON capsule result table: it reads the header of the width of
    /// the firmware that lists the table, then the table's VariableTotalSize bytes.
    #[cfg(configuration_tables)]
    pub(crate) fn read(table: &impl VendorTable) -> Result<Self> {
        let width = table.firmware_width();
        let header = header_size(width);
        let fields = table.read(header).context(
            "read the EFI_CAPSULE_RESULT_VARIABLE_HEADER of the JSON capsule result table",
        )?;
        let total_size = HeaderFields::of(&fields, width)
            .context("the JSON capsule result table's header read short")?
            .variable_total_size;
        if usize::try_from(total_size)? < header {
            return Err(CapsuleResultError::TotalSizeShort { total_size, header }.into());
        }

        let bytes = table.read(usize::try_from(total_size)?).with_context(|| {
            format!(
                "read the VariableTotalSize {total_size} bytes of the JSON capsule result table"
            )
        })?;
        Ok(Self::decode(&bytes, width)?)
    }
}

/// The fields of an EFI_CAPSULE_RESULT_VARIABLE_HEADER (UEFI 2.11 §8.5.6.1.1).
struct HeaderFields {
    variable_total_size: u32,
    capsule_guid: Guid,
    capsule_processed: EfiTime,
    capsule_status: u64,
}

impl HeaderFields {
    /// The fields of `header`, a header of firmware of `width`, if it holds header_size(`width`)
    /// bytes at least.
    fn of(header: &[u8], width: FirmwareWidth) -> Option<Self> {
        let field = |start: usize, end: usize| header.get(start..end);
        Some(Self {
            variable_total_size: u32::from_le_bytes(*header.first_chunk()?),
            capsule_guid: Guid::from(
                <[u8; 16]>::try_from(field(CAPSULE_GUID_OFFSET, CAPSULE_PROCESSED_OFFSET)?).ok()?,
            ),
            capsule_processed: EfiTime::from(
                <[u8; EFI_TIME_SIZE]>::try_from(field(
                    CAPSULE_PROCESSED_OFFSET,
                    CAPSULE_STATUS_OFFSET,
                )?)
                .ok()?,
            ),
            capsule_status: width.uintn(field(CAPSULE_STATUS_OFFSET, header_size(width))?)?,
        })
    }
}

impl FmpCapsuleResult {
    /// The EFI_CAPSULE_RESULT_VARIABLE_FMP `bytes`, all the bytes after a result's header: the
    /// fixed fields, then CapsuleFileName and CapsuleTarget, each zero-terminated CHAR16s, and
    /// nothing after them; or None if its Version is not the 1 that uefisettings reads, as
    /// JsonCapsuleResult::decode.
    fn decode(bytes: &[u8]) -> Result<Option<Self>, CapsuleResultError> {
        let short = CapsuleResultError::FmpShort { count: bytes.len() };
        let Some(version) = bytes.first_chunk().copied().map(u16::from_le_bytes) else {
            return Err(short);
        };
        if version != FMP_RESULT_VERSION {
            return Ok(None);
        }
        let Some((fields, strings)) = bytes.split_first_chunk::<FMP_RESULT_HEADER_SIZE>() else {
            return Err(short);
        };
        let [_, _, payload_index, update_image_index, update_image_type_id @ ..] = *fields;
        let (units, []) = strings.as_chunks::<2>() else {
            return Err(CapsuleResultError::FmpStringsOdd {
                count: strings.len(),
            });
        };
        let units: Vec<u16> = units.iter().map(|&unit| u16::from_le_bytes(unit)).collect();
        let (capsule_file_name, rest) = zero_terminated(&units, "CapsuleFileName")?;
        let (capsule_target, rest) = zero_terminated(rest, "CapsuleTarget")?;
        if !rest.is_empty() {
            return Err(CapsuleResultError::FmpTrailing {
                count: 2 * rest.len(),
            });
        }
        Ok(Some(Self {
            payload_index,
            update_image_index,
            update_image_type_id: Guid::from(update_image_type_id),
            capsule_file_name,
            capsule_target,
        }))
    }
}

/// The zero-terminated CHAR16 string `field` at the start of `units`, and the units after its
/// terminator.
fn zero_terminated<'a>(
    units: &'a [u16],
    field: &'static str,
) -> Result<(String, &'a [u16]), CapsuleResultError> {
    let mut parts = units.splitn(2, |&unit| unit == 0);
    let (Some(text), Some(rest)) = (parts.next(), parts.next()) else {
        return Err(CapsuleResultError::FmpUnterminated { field });
    };
    let text = String::from_utf16(text).map_err(|_| CapsuleResultError::FmpText {
        field,
        text: String::from_utf16_lossy(text),
    })?;
    Ok((text, rest))
}

impl JsonCapsuleResult {
    /// The EFI_CAPSULE_RESULT_VARIABLE_JSON `bytes`, all the bytes after a result's header, or
    /// None if its Version is not the 1 that uefisettings reads: a later Version may lay out more.
    fn decode(bytes: &[u8]) -> Result<Option<Self>, CapsuleResultError> {
        let short = CapsuleResultError::JsonShort { count: bytes.len() };
        let Some(version) = bytes.first_chunk().copied().map(u32::from_le_bytes) else {
            return Err(short);
        };
        if version != JSON_RESULT_VERSION {
            return Ok(None);
        }
        let Some((fields, resp)) = bytes.split_first_chunk::<JSON_RESULT_HEADER_SIZE>() else {
            return Err(short);
        };
        let [_, _, _, _, c0, c1, c2, c3, r0, r1, r2, r3] = *fields;
        let resp_length = u32::from_le_bytes([r0, r1, r2, r3]);
        if usize::try_from(resp_length).ok() != Some(resp.len()) {
            return Err(CapsuleResultError::RespLengthNotRest {
                resp_length,
                count: resp.len(),
            });
        }
        Ok(Some(Self {
            capsule_id: u32::from_le_bytes([c0, c1, c2, c3]),
            resp: resp.to_vec(),
        }))
    }
}

/// A result that CapsuleResult::decode refuses, or a name that ResultName::from_data refuses.
/// The messages spell "section", as PayloadError's do.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Error)]
pub enum CapsuleResultError {
    #[error(
        "the capsule result holds {size} bytes, fewer than the {header} of the \
         EFI_CAPSULE_RESULT_VARIABLE_HEADER of {bits}-bit firmware (UEFI 2.11 section 8.5.6.1.1)"
    )]
    HeaderShort {
        size: usize,
        header: usize,
        bits: u32,
    },
    #[error(
        "the capsule result's VariableTotalSize {total_size} is less than the {header} bytes of \
         its EFI_CAPSULE_RESULT_VARIABLE_HEADER (UEFI 2.11 section 8.5.6.1.1)"
    )]
    TotalSizeShort { total_size: u32, header: usize },
    #[error(
        "the capsule result's VariableTotalSize {total_size} is not its size, {size} bytes: \
         \"Size in bytes of the variable including any data beyond header\" (UEFI 2.11 section \
         8.5.6.1.1)"
    )]
    TotalSizeNotSize { total_size: u32, size: usize },
    #[error(
        "the {count} bytes after the capsule result's header are fewer than the \
         {FMP_RESULT_HEADER_SIZE} of the Version, PayloadIndex, UpdateImageIndex and \
         UpdateImageTypeId of an EFI_CAPSULE_RESULT_VARIABLE_FMP (UEFI 2.11 section 8.5.6.1.2)"
    )]
    FmpShort { count: usize },
    #[error(
        "the capsule result's CapsuleFileName and CapsuleTarget hold {count} bytes, an odd \
         count of bytes for CHAR16s (UEFI 2.11 section 8.5.6.1.2)"
    )]
    FmpStringsOdd { count: usize },
    #[error(
        "the capsule result's {field} has no zero terminator, which VariableTotalSize includes \
         (UEFI 2.11 section 8.5.6.1.2)"
    )]
    FmpUnterminated { field: &'static str },
    #[error("the capsule result's {field} holds {text:?}, which is not UTF-16")]
    FmpText { field: &'static str, text: String },
    #[error(
        "the capsule result holds {count} bytes after the zero terminator of its CapsuleTarget \
         (UEFI 2.11 section 8.5.6.1.2)"
    )]
    FmpTrailing { count: usize },
    #[error(
        "the {count} bytes after the capsule result's header are fewer than the \
         {JSON_RESULT_HEADER_SIZE} of the Version, CapsuleId and RespLength of an \
         EFI_CAPSULE_RESULT_VARIABLE_JSON (UEFI 2.11 section 8.5.6.1.3)"
    )]
    JsonShort { count: usize },
    #[error(
        "the capsule result's RespLength {resp_length} is not the {count} bytes after its \
         Version, CapsuleId and RespLength (UEFI 2.11 section 8.5.6.1.3)"
    )]
    RespLengthNotRest { resp_length: u32, count: usize },
    #[error(
        "{variable} holds {size} bytes, not the {RESULT_NAME_SIZE} of its \
         CHAR16[{RESULT_NAME_UNITS}] without a terminator (UEFI 2.11 section 8.5.6, Table 8.9)"
    )]
    NameSize { variable: &'static str, size: usize },
    #[error(
        "{variable} holds {text:?}, not {RESULT_NAME_PREFIX:?} and {RESULT_NAME_DIGITS} \
         hexadecimal digits (UEFI 2.11 section 8.5.6)"
    )]
    NameText {
        variable: &'static str,
        text: String,
    },
}

/// A variable of EFI_CAPSULE_REPORT_GUID whose data does not decode: why, and the data. It
/// serializes as "error", the message, and "data", as Hex serializes it.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Undecoded {
    pub error: CapsuleResultError,
    pub data: Vec<u8>,
}

impl Undecoded {
    fn new(error: CapsuleResultError, data: &[u8]) -> Self {
        Self {
            error,
            data: data.to_vec(),
        }
    }

    /// Serializes "error" and "data" into `map`.
    fn serialize_entries<M: SerializeMap>(&self, map: &mut M) -> Result<(), M::Error> {
        map.serialize_entry("error", &self.error.to_string())?;
        map.serialize_entry("data", &Hex(&self.data))
    }
}

impl Serialize for Undecoded {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        self.serialize_entries(&mut map)?;
        map.end()
    }
}

/// A result variable and the result that it holds, or why it does not decode. It serializes as
/// "name", then "result", or Undecoded's entries.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NamedCapsuleResult {
    pub name: ResultName,
    pub result: Result<CapsuleResult, Undecoded>,
}

impl Serialize for NamedCapsuleResult {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("name", &self.name)?;
        match &self.result {
            Ok(result) => map.serialize_entry("result", result)?,
            Err(undecoded) => undecoded.serialize_entries(&mut map)?,
        }
        map.end()
    }
}

/// The results of capsule processing that the firmware reports in variables (UEFI 2.11 §8.5.6).
/// CapsuleMax and CapsuleLast serialize as their names, or as Undecoded, or null where absent.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct CapsuleResults {
    /// CapsuleMax, the last result variable before the firmware rolls over, if it publishes it
    #[serde(serialize_with = "serialize_name_variable")]
    pub capsule_max: Option<Result<ResultName, Undecoded>>,
    /// CapsuleLast, the result variable that the firmware created last, if any
    #[serde(serialize_with = "serialize_name_variable")]
    pub capsule_last: Option<Result<ResultName, Undecoded>>,
    /// The result variables, in name order
    pub results: Vec<NamedCapsuleResult>,
}

/// `variable`, CapsuleMax or CapsuleLast, as its name, as Undecoded, or as null where absent.
fn serialize_name_variable<S: Serializer>(
    variable: &Option<Result<ResultName, Undecoded>>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match variable {
        None => serializer.serialize_none(),
        Some(Ok(name)) => name.serialize(serializer),
        Some(Err(undecoded)) => undecoded.serialize(serializer),
    }
}

/// The variable `name` of EFI_CAPSULE_REPORT_GUID.
fn report_key(name: &str) -> VariableKey {
    VariableKey {
        name: name.to_owned(),
        guid: EFI_CAPSULE_REPORT_GUID,
    }
}

/// The results that `variables` hold under the names that `names` list: each result variable
/// of EFI_CAPSULE_REPORT_GUID, of firmware of `width`, and CapsuleMax and CapsuleLast, each
/// decoded on its own, as each is a record of its own that the firmware may overwrite or delete
/// (UEFI 2.11 §8.5.6). A variable that is gone by the time it is read is left out.
#[cfg(variable_names)]
pub(crate) fn list_capsule_results(
    names: &impl VariableNames,
    variables: &impl VariableData,
    width: FirmwareWidth,
) -> Result<CapsuleResults> {
    let keys = list_variables(names, Some(EFI_CAPSULE_REPORT_GUID))?;
    let capsule_max = read_result_name(variables, CAPSULE_MAX)?;
    let capsule_last = read_result_name(variables, CAPSULE_LAST)?;
    let mut results = Vec::new();
    for name in keys.iter().filter_map(|key| ResultName::parse(&key.name)) {
        results.extend(read_result(variables, name, width)?);
    }
    Ok(CapsuleResults {
        capsule_max,
        capsule_last,
        results,
    })
}

/// The results that `variables`, which no backend lists (GetFirmwareEnvironmentVariableExW),
/// hold by name: CapsuleMax, CapsuleLast, then each result variable of firmware of `width` from
/// Capsule0000 up to the greater of the names that they hold, as list_capsule_results decodes
/// them. An absent name is left out, and without either name there are none.
#[cfg(any(target_os = "windows", test))]
pub(crate) fn probe_capsule_results(
    variables: &impl VariableData,
    width: FirmwareWidth,
) -> Result<CapsuleResults> {
    let capsule_max = read_result_name(variables, CAPSULE_MAX)?;
    let capsule_last = read_result_name(variables, CAPSULE_LAST)?;
    let named: Vec<&ResultName> = [&capsule_max, &capsule_last]
        .into_iter()
        .flatten()
        .flatten()
        .collect();
    let case = named.iter().find_map(|name| name.letter_case());
    let mut results = Vec::new();
    if let Some(ResultIndex(last)) = named.iter().map(|name| name.index()).max() {
        for index in (0..=last).map(ResultIndex) {
            results.extend(probe_result(variables, index, case, width)?);
        }
    }
    Ok(CapsuleResults {
        capsule_max,
        capsule_last,
        results,
    })
}

/// The result variable of `index` of firmware of `width`, if the firmware has it, by its name in
/// `case`, the case of the firmware's names. Without it, the name in uppercase, as edk2 spells
/// it (edk2-stable202608 MdeModulePkg/Library/DxeCapsuleLibFmp/DxeCapsuleReportLib.c
/// "Capsule%04x", which MdePkg/Library/BasePrintLib/PrintLibInternal.c prints from mHexStr), then
/// in lowercase if that differs, as GetVariable() compares names byte by byte
/// (MdeModulePkg/Universal/Variable/RuntimeDxe/VariableParsing.c FindVariableEx()).
#[cfg(any(target_os = "windows", test))]
fn probe_result(
    variables: &impl VariableData,
    index: ResultIndex,
    case: Option<HexCase>,
    width: FirmwareWidth,
) -> Result<Option<NamedCapsuleResult>> {
    let names = match case {
        Some(case) => vec![ResultName::of_index(index, case)],
        None => {
            let upper = ResultName::of_index(index, HexCase::Upper);
            let lower = ResultName::of_index(index, HexCase::Lower);
            match upper == lower {
                true => vec![upper],
                false => vec![upper, lower],
            }
        }
    };
    for name in names {
        if let Some(result) = read_result(variables, name, width)? {
            return Ok(Some(result));
        }
    }
    Ok(None)
}

/// The result name that the variable `variable` of EFI_CAPSULE_REPORT_GUID holds, or why it
/// holds none, if the firmware has the variable.
fn read_result_name(
    variables: &impl VariableData,
    variable: &'static str,
) -> Result<Option<Result<ResultName, Undecoded>>> {
    let Some(contents) = variables.variable_data(&report_key(variable))? else {
        return Ok(None);
    };
    let data = contents.data();
    Ok(Some(
        ResultName::from_data(variable, data).map_err(|error| Undecoded::new(error, data)),
    ))
}

/// The result that the result variable `name` of firmware of `width` holds, or why it does not
/// decode, if the firmware has the variable.
fn read_result(
    variables: &impl VariableData,
    name: ResultName,
    width: FirmwareWidth,
) -> Result<Option<NamedCapsuleResult>> {
    let Some(contents) = variables.variable_data(&report_key(name.as_str()))? else {
        return Ok(None);
    };
    let data = contents.data();
    Ok(Some(NamedCapsuleResult {
        name,
        result: CapsuleResult::decode(data, width).map_err(|error| Undecoded::new(error, data)),
    }))
}

/// The result in the JSON capsule result table `table`, which the firmware must list.
#[cfg(configuration_tables)]
pub(crate) fn read_json_capsule_result(table: Option<impl VendorTable>) -> Result<CapsuleResult> {
    let table = table.ok_or(NoJsonCapsuleResultTable)?;
    CapsuleResult::read(&table)
}

/// A firmware that lists no JSON capsule result table: it installs one only after it processes
/// a JSON capsule (UEFI 2.11 §23.5.3). The message spells "section", as PayloadError's do.
#[cfg(configuration_tables)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error(
    "the firmware lists no configuration table of EFI_JSON_CAPSULE_RESULT_TABLE_GUID, \
     {EFI_JSON_CAPSULE_RESULT_TABLE_GUID} (UEFI 2.11 section 23.5.3)"
)]
struct NoJsonCapsuleResultTable;

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(configuration_tables)]
    use crate::efi_variables::capsule::fixture::TableInRegion;
    #[cfg(variable_names)]
    use crate::efi_variables::globals::tests::HeldVariables;

    /// Each width, the size of its EFI_CAPSULE_RESULT_VARIABLE_HEADER, and its
    /// EFI_INVALID_PARAMETER, whose high bit is the UINTN's (edk2-stable202508
    /// MdePkg/Include/Base.h ENCODE_ERROR).
    const WIDTHS: [(FirmwareWidth, usize, u64); 2] = [
        (FirmwareWidth::Bits32, 44, 0x8000_0002),
        (FirmwareWidth::Bits64, 48, 0x8000_0000_0000_0002),
    ];
    /// A CapsuleGuid that no specification defines, 8C78A505-BAA0-4C4A-869F-000000001300.
    const OTHER_GUID: Guid = Guid {
        data1: 0x8c78_a505,
        data2: 0xbaa0,
        data3: 0x4c4a,
        data4: [0x86, 0x9f, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00],
    };
    /// A vendor GUID of no result variable, 8C78A505-BAA0-4C4A-869F-000000001302.
    #[cfg(variable_names)]
    const OTHER_VENDOR: Guid = Guid {
        data1: 0x8c78_a505,
        data2: 0xbaa0,
        data3: 0x4c4a,
        data4: [0x86, 0x9f, 0x00, 0x00, 0x00, 0x00, 0x13, 0x02],
    };
    /// CapsuleProcessed: 2026-11-07 12:34:56.000000789, TimeZone -60, Daylight 1, with padding
    /// bytes that the decoder ignores.
    const PROCESSED: [u8; 16] = [
        0xea, 0x07, 11, 7, 12, 34, 56, 0xa5, 0x15, 0x03, 0, 0, 0xc4, 0xff, 1, 0xa5,
    ];

    /// The EfiTime of PROCESSED.
    fn processed() -> EfiTime {
        EfiTime {
            year: 2026,
            month: 11,
            day: 7,
            hour: 12,
            minute: 34,
            second: 56,
            nanosecond: 789,
            time_zone: -60,
            daylight: 1,
        }
    }

    /// A result of firmware of `width` with VariableTotalSize `total_size`, CapsuleGuid `guid`
    /// and CapsuleStatus `status`, a Reserved of 0xa5 bytes, then `rest`.
    fn result(
        width: FirmwareWidth,
        total_size: u32,
        guid: Guid,
        status: u64,
        rest: &[u8],
    ) -> Vec<u8> {
        let status = match width {
            FirmwareWidth::Bits32 => u32::try_from(status)
                .expect("a 32-bit EFI_STATUS")
                .to_le_bytes()
                .to_vec(),
            FirmwareWidth::Bits64 => status.to_le_bytes().to_vec(),
        };
        [
            &total_size.to_le_bytes()[..],
            &[0xa5; 4],
            &<[u8; 16]>::from(guid),
            &PROCESSED,
            &status,
            rest,
        ]
        .concat()
    }

    /// The result of `result` whose VariableTotalSize is its size, after a header of `header`
    /// bytes.
    fn whole(width: FirmwareWidth, header: usize, guid: Guid, status: u64, rest: &[u8]) -> Vec<u8> {
        let size = u32::try_from(header + rest.len()).expect("a UINT32 VariableTotalSize");
        result(width, size, guid, status, rest)
    }

    /// An EFI_CAPSULE_RESULT_VARIABLE_JSON of `version`, `capsule_id` and `resp_length`, then
    /// `resp`.
    fn json(version: u32, capsule_id: u32, resp_length: u32, resp: &[u8]) -> Vec<u8> {
        [
            &version.to_le_bytes()[..],
            &capsule_id.to_le_bytes(),
            &resp_length.to_le_bytes(),
            resp,
        ]
        .concat()
    }

    /// The CHAR16 bytes of `text`, without a terminator.
    fn char16(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// An EFI_CAPSULE_RESULT_VARIABLE_FMP of `version`, PayloadIndex 2, UpdateImageIndex 3 and
    /// UpdateImageTypeId OTHER_GUID, then `strings`.
    fn fmp(version: u16, strings: &[u8]) -> Vec<u8> {
        [
            &version.to_le_bytes()[..],
            &[2, 3],
            &<[u8; 16]>::from(OTHER_GUID),
            strings,
        ]
        .concat()
    }

    /// The result name `name`.
    fn name(name: &str) -> ResultName {
        ResultName::parse(name).unwrap_or_else(|| panic!("{name} is a result name"))
    }

    /// decode reads the header and the EFI_CAPSULE_RESULT_VARIABLE_JSON of a JSON capsule's
    /// result of each width, whose CapsuleStatus is a UINTN of that width; a 64-bit result read
    /// as a 32-bit one has the low half of its CapsuleStatus, and its high half starts a Version
    /// that is not 1.
    #[test]
    fn decode_reads_the_json_result_of_each_width() {
        let resp = br#"{"status":"done"}"#;
        for (width, header, status) in WIDTHS {
            let bytes = whole(
                width,
                header,
                EFI_JSON_CAPSULE_ID_GUID,
                status,
                &json(1, 0x0102_0304, 17, resp),
            );

            let decoded = CapsuleResult::decode(&bytes, width);

            assert_eq!(
                decoded,
                Ok(CapsuleResult {
                    variable_total_size: u32::try_from(header + 12 + 17).expect("a UINT32"),
                    capsule_guid: EFI_JSON_CAPSULE_ID_GUID,
                    capsule_processed: processed(),
                    capsule_status: status,
                    details: CapsuleResultDetails::Json(JsonCapsuleResult {
                        capsule_id: 0x0102_0304,
                        resp: resp.to_vec(),
                    }),
                }),
                "{width:?}"
            );
        }

        let bytes = whole(
            FirmwareWidth::Bits64,
            48,
            EFI_JSON_CAPSULE_ID_GUID,
            0x8000_0000_0000_0002,
            &json(1, 7, 2, b"{}"),
        );
        assert_eq!(
            CapsuleResult::decode(&bytes, FirmwareWidth::Bits32),
            Ok(CapsuleResult {
                variable_total_size: 62,
                capsule_guid: EFI_JSON_CAPSULE_ID_GUID,
                capsule_processed: processed(),
                capsule_status: 2,
                details: CapsuleResultDetails::Other(bytes[44..].to_vec()),
            }),
            "a 64-bit result as a 32-bit one"
        );
    }

    /// decode keeps the bytes after the header of a JSON capsule's result raw where its
    /// EFI_CAPSULE_RESULT_VARIABLE_JSON has a Version but 1, which may lay out more: "The version
    /// of this structure, currently 0x00000001" (UEFI 2.11 §8.5.6.1.3).
    #[test]
    fn decode_keeps_a_json_part_of_another_version_raw() {
        for (width, header, _) in WIDTHS {
            for rest in [
                json(2, 7, 2, b"{}"),
                json(0, 7, 2, b"{}"),
                json(2, 7, 9, b""),
                2_u32.to_le_bytes().to_vec(),
            ] {
                let bytes = whole(width, header, EFI_JSON_CAPSULE_ID_GUID, 0, &rest);

                assert_eq!(
                    CapsuleResult::decode(&bytes, width),
                    Ok(CapsuleResult {
                        variable_total_size: u32::try_from(header + rest.len()).expect("a UINT32"),
                        capsule_guid: EFI_JSON_CAPSULE_ID_GUID,
                        capsule_processed: processed(),
                        capsule_status: 0,
                        details: CapsuleResultDetails::Other(rest.clone()),
                    }),
                    "{width:?} {rest:?}"
                );
            }
        }
    }

    /// decode keeps the bytes after the header of any CapsuleGuid but the FMP and JSON capsules',
    /// none or some.
    #[test]
    fn decode_keeps_the_rest_of_other_guids_raw() {
        for (width, header, _) in WIDTHS {
            for rest in [&[][..], &[1, 2, 3]] {
                let bytes = whole(width, header, OTHER_GUID, 0, rest);

                let decoded = CapsuleResult::decode(&bytes, width);

                assert_eq!(
                    decoded,
                    Ok(CapsuleResult {
                        variable_total_size: u32::try_from(header + rest.len()).expect("a UINT32"),
                        capsule_guid: OTHER_GUID,
                        capsule_processed: processed(),
                        capsule_status: 0,
                        details: CapsuleResultDetails::Other(rest.to_vec()),
                    }),
                    "{width:?} {rest:?}"
                );
            }
        }
    }

    /// decode refuses fewer bytes than the header of the firmware's width.
    #[test]
    fn decode_refuses_a_result_short_of_its_header() {
        for (width, header, bits) in [
            (FirmwareWidth::Bits32, 44, 32),
            (FirmwareWidth::Bits64, 48, 64),
        ] {
            let bytes = whole(width, header, OTHER_GUID, 0, &[]);

            let decoded = CapsuleResult::decode(&bytes[..header - 1], width);

            assert_eq!(
                decoded,
                Err(CapsuleResultError::HeaderShort {
                    size: header - 1,
                    header,
                    bits,
                }),
                "{width:?}"
            );
        }
        let error = CapsuleResult::decode(&[0; 47], FirmwareWidth::Bits64)
            .expect_err("decode 47 bytes of a 64-bit result");
        assert_eq!(
            error.to_string(),
            "the capsule result holds 47 bytes, fewer than the 48 of the \
             EFI_CAPSULE_RESULT_VARIABLE_HEADER of 64-bit firmware (UEFI 2.11 section 8.5.6.1.1)",
            "message"
        );
    }

    /// decode refuses a VariableTotalSize under the header's size, past the result's bytes, or
    /// short of them.
    #[test]
    fn decode_refuses_a_variable_total_size_that_is_not_the_size() {
        for (width, header, _) in WIDTHS {
            let size = header + 3;
            let total = |total: usize| u32::try_from(total).expect("a UINT32");
            for (total_size, refusal) in [
                (
                    header - 1,
                    CapsuleResultError::TotalSizeShort {
                        total_size: total(header - 1),
                        header,
                    },
                ),
                (
                    size + 1,
                    CapsuleResultError::TotalSizeNotSize {
                        total_size: total(size + 1),
                        size,
                    },
                ),
                (
                    size - 1,
                    CapsuleResultError::TotalSizeNotSize {
                        total_size: total(size - 1),
                        size,
                    },
                ),
            ] {
                let bytes = result(width, total(total_size), OTHER_GUID, 0, &[1, 2, 3]);

                assert_eq!(
                    CapsuleResult::decode(&bytes, width),
                    Err(refusal),
                    "{width:?} {total_size}"
                );
            }
        }
        assert_eq!(
            CapsuleResultError::TotalSizeNotSize {
                total_size: 52,
                size: 51
            }
            .to_string(),
            "the capsule result's VariableTotalSize 52 is not its size, 51 bytes: \"Size in bytes \
             of the variable including any data beyond header\" (UEFI 2.11 section 8.5.6.1.1)",
            "message"
        );
    }

    /// decode refuses a JSON capsule's result whose EFI_CAPSULE_RESULT_VARIABLE_JSON is short of
    /// its Version, or of Version 1 and short of its CapsuleId and RespLength, or with a
    /// RespLength past the end or short of it.
    #[test]
    fn decode_refuses_a_json_part_that_it_cannot_read() {
        for (width, header, _) in WIDTHS {
            for (rest, refusal) in [
                (vec![1, 0, 0], CapsuleResultError::JsonShort { count: 3 }),
                (
                    json(1, 7, 0, b"")[..11].to_vec(),
                    CapsuleResultError::JsonShort { count: 11 },
                ),
                (
                    json(1, 7, 3, b"{}"),
                    CapsuleResultError::RespLengthNotRest {
                        resp_length: 3,
                        count: 2,
                    },
                ),
                (
                    json(1, 7, 1, b"{}"),
                    CapsuleResultError::RespLengthNotRest {
                        resp_length: 1,
                        count: 2,
                    },
                ),
                (
                    json(1, 7, u32::MAX, b"{}"),
                    CapsuleResultError::RespLengthNotRest {
                        resp_length: u32::MAX,
                        count: 2,
                    },
                ),
            ] {
                let bytes = whole(width, header, EFI_JSON_CAPSULE_ID_GUID, 0, &rest);

                assert_eq!(
                    CapsuleResult::decode(&bytes, width),
                    Err(refusal),
                    "{width:?} {rest:?}"
                );
            }
        }
        assert_eq!(
            CapsuleResultError::RespLengthNotRest {
                resp_length: 3,
                count: 2
            }
            .to_string(),
            "the capsule result's RespLength 3 is not the 2 bytes after its Version, CapsuleId and \
             RespLength (UEFI 2.11 section 8.5.6.1.3)",
            "message"
        );
    }

    /// decode reads the EFI_CAPSULE_RESULT_VARIABLE_FMP of an FMP capsule's result of each width:
    /// its fixed fields, then its CapsuleFileName and CapsuleTarget as text, or as empty text
    /// where each is a single zero character.
    #[test]
    fn decode_reads_the_fmp_result_of_each_width() {
        for (width, header, status) in WIDTHS {
            for (file_name, target) in [("update.cap", "PciRoot(0x0)/Pci(0x1,0x0)"), ("", "")] {
                let strings = [char16(file_name), vec![0, 0], char16(target), vec![0, 0]].concat();
                let rest = fmp(1, &strings);
                let bytes = whole(
                    width,
                    header,
                    EFI_FIRMWARE_MANAGEMENT_CAPSULE_ID_GUID,
                    status,
                    &rest,
                );

                let decoded = CapsuleResult::decode(&bytes, width);

                assert_eq!(
                    decoded,
                    Ok(CapsuleResult {
                        variable_total_size: u32::try_from(header + rest.len()).expect("a UINT32"),
                        capsule_guid: EFI_FIRMWARE_MANAGEMENT_CAPSULE_ID_GUID,
                        capsule_processed: processed(),
                        capsule_status: status,
                        details: CapsuleResultDetails::Fmp(FmpCapsuleResult {
                            payload_index: 2,
                            update_image_index: 3,
                            update_image_type_id: OTHER_GUID,
                            capsule_file_name: file_name.to_owned(),
                            capsule_target: target.to_owned(),
                        }),
                    }),
                    "{width:?} {file_name:?} {target:?}"
                );
            }
        }
    }

    /// decode keeps the bytes after the header of an FMP capsule's result raw where its
    /// EFI_CAPSULE_RESULT_VARIABLE_FMP has a Version but 1, which may lay out more: "The version
    /// of this structure, currently 0x00000001" (UEFI 2.11 §8.5.6.1.2).
    #[test]
    fn decode_keeps_an_fmp_part_of_another_version_raw() {
        for (width, header, _) in WIDTHS {
            for rest in [
                fmp(2, &[0; 4]),
                fmp(0x0100, &[0; 4]),
                fmp(2, &[0; 5]),
                fmp(2, &[])[..2].to_vec(),
            ] {
                let bytes = whole(
                    width,
                    header,
                    EFI_FIRMWARE_MANAGEMENT_CAPSULE_ID_GUID,
                    0,
                    &rest,
                );

                assert_eq!(
                    CapsuleResult::decode(&bytes, width),
                    Ok(CapsuleResult {
                        variable_total_size: u32::try_from(header + rest.len()).expect("a UINT32"),
                        capsule_guid: EFI_FIRMWARE_MANAGEMENT_CAPSULE_ID_GUID,
                        capsule_processed: processed(),
                        capsule_status: 0,
                        details: CapsuleResultDetails::Other(rest.clone()),
                    }),
                    "{width:?} {rest:?}"
                );
            }
        }
    }

    /// decode refuses an FMP capsule's result whose EFI_CAPSULE_RESULT_VARIABLE_FMP is short of
    /// its Version, or of Version 1 and short of its other fixed fields, with an odd count of
    /// string bytes, without the zero terminator of either string, with a string that is not
    /// UTF-16, or with bytes after the terminator of CapsuleTarget.
    #[test]
    fn decode_refuses_an_fmp_part_that_it_cannot_read() {
        let name = char16("a.cap");
        let nul = [0, 0];
        let unpaired = |field| CapsuleResultError::FmpText {
            field,
            text: "\u{fffd}".to_owned(),
        };
        for (width, header, _) in WIDTHS {
            for (rest, refusal) in [
                (vec![1], CapsuleResultError::FmpShort { count: 1 }),
                (
                    fmp(1, &[])[..19].to_vec(),
                    CapsuleResultError::FmpShort { count: 19 },
                ),
                (
                    fmp(1, &[0; 5]),
                    CapsuleResultError::FmpStringsOdd { count: 5 },
                ),
                (
                    fmp(1, &[]),
                    CapsuleResultError::FmpUnterminated {
                        field: "CapsuleFileName",
                    },
                ),
                (
                    fmp(1, &name),
                    CapsuleResultError::FmpUnterminated {
                        field: "CapsuleFileName",
                    },
                ),
                (
                    fmp(1, &[&name[..], &nul].concat()),
                    CapsuleResultError::FmpUnterminated {
                        field: "CapsuleTarget",
                    },
                ),
                (
                    fmp(1, &[&name[..], &nul, &name].concat()),
                    CapsuleResultError::FmpUnterminated {
                        field: "CapsuleTarget",
                    },
                ),
                (
                    fmp(1, &[0x00, 0xd8, 0, 0, 0, 0]),
                    unpaired("CapsuleFileName"),
                ),
                (fmp(1, &[0, 0, 0x00, 0xdc, 0, 0]), unpaired("CapsuleTarget")),
                (
                    fmp(1, &[0, 0, 0, 0, 0x41, 0]),
                    CapsuleResultError::FmpTrailing { count: 2 },
                ),
                (
                    fmp(1, &[0; 6]),
                    CapsuleResultError::FmpTrailing { count: 2 },
                ),
            ] {
                let bytes = whole(
                    width,
                    header,
                    EFI_FIRMWARE_MANAGEMENT_CAPSULE_ID_GUID,
                    0,
                    &rest,
                );

                assert_eq!(
                    CapsuleResult::decode(&bytes, width),
                    Err(refusal),
                    "{width:?} {rest:?}"
                );
            }
        }
        assert_eq!(
            CapsuleResultError::FmpUnterminated {
                field: "CapsuleTarget"
            }
            .to_string(),
            "the capsule result's CapsuleTarget has no zero terminator, which VariableTotalSize \
             includes (UEFI 2.11 section 8.5.6.1.2)",
            "message"
        );
    }

    /// A result name is "Capsule" and 4 hexadecimal digits, either case, whose index they are;
    /// probing names each index in digits of either case, and the case of a name is that of its
    /// letter digits, if all are of one.
    #[test]
    fn result_names_are_capsule_and_4_hexadecimal_digits() {
        for (text, index) in [
            ("Capsule0000", 0),
            ("Capsule00aF", 0xaf),
            ("CapsuleFFFF", 0xffff),
        ] {
            let parsed =
                ResultName::parse(text).map(|name| (name.as_str().to_owned(), name.index().0));

            assert_eq!(parsed, Some((text.to_owned(), index)), "{text}");
        }
        for text in [
            "Capsule000",
            "Capsule00000",
            "capsule0000",
            "CapsuleMax",
            "Capsule+123",
            "Capsule 123",
            "Capsule00G0",
            "Capsule\u{e9}00",
            "Capsule",
            "",
        ] {
            assert_eq!(ResultName::parse(text), None, "{text:?}");
        }
        for (index, upper, lower) in [
            (0, "Capsule0000", "Capsule0000"),
            (0x2b, "Capsule002B", "Capsule002b"),
            (0xffff, "CapsuleFFFF", "Capsuleffff"),
        ] {
            for (case, text) in [(HexCase::Upper, upper), (HexCase::Lower, lower)] {
                let name = ResultName::of_index(ResultIndex(index), case);

                assert_eq!(
                    (name.as_str(), name.index()),
                    (text, ResultIndex(index)),
                    "{index} {case:?}"
                );
            }
        }
        for (text, case) in [
            ("Capsule0000", None),
            ("Capsule002B", Some(HexCase::Upper)),
            ("Capsule002b", Some(HexCase::Lower)),
            ("Capsule00aF", None),
        ] {
            assert_eq!(name(text).letter_case(), case, "{text}");
        }
    }

    /// CapsuleMax and CapsuleLast hold a result name as CHAR16\[11\] without a terminator; other
    /// sizes and other text are refused, naming the variable.
    #[test]
    fn from_data_reads_the_char16_of_a_result_name() {
        assert_eq!(
            ResultName::from_data(CAPSULE_MAX, &char16("Capsule0003")),
            Ok(name("Capsule0003")),
            "Capsule0003"
        );
        for (data, refusal) in [
            (
                char16("Capsule0003\0"),
                CapsuleResultError::NameSize {
                    variable: CAPSULE_MAX,
                    size: 24,
                },
            ),
            (
                char16("Capsule000"),
                CapsuleResultError::NameSize {
                    variable: CAPSULE_MAX,
                    size: 20,
                },
            ),
            (
                char16("Capsule0003")[..21].to_vec(),
                CapsuleResultError::NameSize {
                    variable: CAPSULE_MAX,
                    size: 21,
                },
            ),
            (
                [&char16("Capsule0003")[..], &[0]].concat(),
                CapsuleResultError::NameSize {
                    variable: CAPSULE_MAX,
                    size: 23,
                },
            ),
            (
                char16("CapsuleLast"),
                CapsuleResultError::NameText {
                    variable: CAPSULE_MAX,
                    text: "CapsuleLast".to_owned(),
                },
            ),
            (
                [&char16("Capsule000")[..], &0xd800_u16.to_le_bytes()].concat(),
                CapsuleResultError::NameText {
                    variable: CAPSULE_MAX,
                    text: "Capsule000\u{fffd}".to_owned(),
                },
            ),
        ] {
            assert_eq!(
                ResultName::from_data(CAPSULE_MAX, &data),
                Err(refusal),
                "{data:?}"
            );
        }
        assert_eq!(
            CapsuleResultError::NameSize {
                variable: CAPSULE_LAST,
                size: 24
            }
            .to_string(),
            "CapsuleLast holds 24 bytes, not the 22 of its CHAR16[11] without a terminator (UEFI \
             2.11 section 8.5.6, Table 8.9)",
            "message"
        );
    }

    /// VariableNames that list the keys they hold.
    #[cfg(variable_names)]
    struct Names(Vec<VariableKey>);

    #[cfg(variable_names)]
    impl VariableNames for Names {
        fn variable_names(&self) -> Result<Vec<VariableKey>> {
            Ok(self.0.clone())
        }
    }

    /// The result variable of 64-bit firmware that the listing tests hold as Capsule0000: a
    /// JSON capsule's.
    #[cfg(variable_names)]
    fn json_result_bytes() -> Vec<u8> {
        whole(
            FirmwareWidth::Bits64,
            48,
            EFI_JSON_CAPSULE_ID_GUID,
            0,
            &json(1, 9, 2, b"{}"),
        )
    }

    /// The result of json_result_bytes.
    #[cfg(variable_names)]
    fn json_result() -> CapsuleResult {
        CapsuleResult {
            variable_total_size: 62,
            capsule_guid: EFI_JSON_CAPSULE_ID_GUID,
            capsule_processed: processed(),
            capsule_status: 0,
            details: CapsuleResultDetails::Json(JsonCapsuleResult {
                capsule_id: 9,
                resp: b"{}".to_vec(),
            }),
        }
    }

    /// list_capsule_results reads CapsuleMax, CapsuleLast, then each listed result variable of
    /// EFI_CAPSULE_REPORT_GUID in name order, and leaves out other names, other vendors and a
    /// listed variable that is gone, reading those after it.
    #[cfg(variable_names)]
    #[test]
    fn list_capsule_results_reads_each_result_variable() {
        let other_result = whole(
            FirmwareWidth::Bits64,
            48,
            OTHER_GUID,
            0x8000_0000_0000_0003,
            &[7],
        );
        let variables = HeldVariables::default()
            .with("Capsule0002", EFI_CAPSULE_REPORT_GUID, &other_result)
            .with("Capsule0000", EFI_CAPSULE_REPORT_GUID, &json_result_bytes())
            .with(CAPSULE_MAX, EFI_CAPSULE_REPORT_GUID, &char16("Capsule0003"))
            .with(
                CAPSULE_LAST,
                EFI_CAPSULE_REPORT_GUID,
                &char16("Capsule0002"),
            )
            .with("CapsuleOther", EFI_CAPSULE_REPORT_GUID, b"x")
            .with("Capsule0003", OTHER_VENDOR, b"x");
        let gone = report_key("Capsule0001");
        let mut listed: Vec<VariableKey> = variables.variables.borrow().keys().cloned().collect();
        listed.push(gone.clone());
        listed.reverse();

        let results = list_capsule_results(&Names(listed), &variables, FirmwareWidth::Bits64);

        assert_eq!(
            results.expect("list the results"),
            CapsuleResults {
                capsule_max: Some(Ok(name("Capsule0003"))),
                capsule_last: Some(Ok(name("Capsule0002"))),
                results: vec![
                    NamedCapsuleResult {
                        name: name("Capsule0000"),
                        result: Ok(json_result()),
                    },
                    NamedCapsuleResult {
                        name: name("Capsule0002"),
                        result: Ok(CapsuleResult {
                            variable_total_size: 49,
                            capsule_guid: OTHER_GUID,
                            capsule_processed: processed(),
                            capsule_status: 0x8000_0000_0000_0003,
                            details: CapsuleResultDetails::Other(vec![7]),
                        }),
                    },
                ],
            },
            "results"
        );
        assert_eq!(
            variables.read.borrow().clone(),
            [
                report_key(CAPSULE_MAX),
                report_key(CAPSULE_LAST),
                report_key("Capsule0000"),
                gone,
                report_key("Capsule0002"),
            ],
            "variables read"
        );
    }

    /// list_capsule_results without any variable of EFI_CAPSULE_REPORT_GUID reports none.
    #[cfg(variable_names)]
    #[test]
    fn list_capsule_results_without_results_reports_none() {
        let variables = HeldVariables::default().with("Capsule0000", OTHER_VENDOR, b"x");
        let listed = variables.variables.borrow().keys().cloned().collect();

        let results = list_capsule_results(&Names(listed), &variables, FirmwareWidth::Bits32);

        let results = results.expect("list no results");

        assert_eq!(
            results,
            CapsuleResults {
                capsule_max: None,
                capsule_last: None,
                results: Vec::new(),
            },
            "results"
        );
        assert_eq!(
            serde_json::to_value(&results).expect("serialize the results"),
            serde_json::json!({ "capsule_max": null, "capsule_last": null, "results": [] }),
            "JSON"
        );
    }

    /// list_capsule_results reports a result that it cannot decode, and a CapsuleMax or CapsuleLast
    /// that holds no result name, each with why and its data, and reads the others.
    #[cfg(variable_names)]
    #[test]
    fn list_capsule_results_reports_what_it_cannot_decode() {
        let max = char16("Capsule0003\0");
        let last = char16("CapsuleNone");
        let variables = HeldVariables::default()
            .with(CAPSULE_MAX, EFI_CAPSULE_REPORT_GUID, &max)
            .with(CAPSULE_LAST, EFI_CAPSULE_REPORT_GUID, &last)
            .with("Capsule0000", EFI_CAPSULE_REPORT_GUID, &[1, 2, 3])
            .with("Capsule0001", EFI_CAPSULE_REPORT_GUID, &json_result_bytes());
        let listed = variables.variables.borrow().keys().cloned().collect();

        let results = list_capsule_results(&Names(listed), &variables, FirmwareWidth::Bits64);

        assert_eq!(
            results.expect("list the results"),
            CapsuleResults {
                capsule_max: Some(Err(Undecoded {
                    error: CapsuleResultError::NameSize {
                        variable: CAPSULE_MAX,
                        size: 24,
                    },
                    data: max,
                })),
                capsule_last: Some(Err(Undecoded {
                    error: CapsuleResultError::NameText {
                        variable: CAPSULE_LAST,
                        text: "CapsuleNone".to_owned(),
                    },
                    data: last,
                })),
                results: vec![
                    NamedCapsuleResult {
                        name: name("Capsule0000"),
                        result: Err(Undecoded {
                            error: CapsuleResultError::HeaderShort {
                                size: 3,
                                header: 48,
                                bits: 64,
                            },
                            data: vec![1, 2, 3],
                        }),
                    },
                    NamedCapsuleResult {
                        name: name("Capsule0001"),
                        result: Ok(json_result()),
                    },
                ],
            },
            "results"
        );
        assert_eq!(
            CapsuleResultError::NameText {
                variable: CAPSULE_LAST,
                text: "CapsuleNone".to_owned(),
            }
            .to_string(),
            "CapsuleLast holds \"CapsuleNone\", not \"Capsule\" and 4 hexadecimal digits (UEFI \
             2.11 section 8.5.6)",
            "message"
        );
    }

    /// The results serialize as `capsule results` prints them: CapsuleMax and CapsuleLast by name,
    /// and each result by name with its header's fields, CapsuleStatus in hex, and an FMP
    /// capsule's EFI_CAPSULE_RESULT_VARIABLE_FMP, a JSON capsule's CapsuleId and Resp as text if
    /// it is UTF-8, else as hex, or the bytes after another's header as hex, UTF-8 or not; what
    /// does not decode, as why and its data in hex.
    #[cfg(variable_names)]
    #[test]
    fn results_serialize_as_capsule_results_prints_them() {
        let resp_not_utf8 = whole(
            FirmwareWidth::Bits64,
            48,
            EFI_JSON_CAPSULE_ID_GUID,
            0x8000_0000_0000_0002,
            &json(1, 10, 2, &[0xff, 0x00]),
        );
        let other_utf8 = whole(
            FirmwareWidth::Bits64,
            48,
            OTHER_GUID,
            0x8000_0000_0000_0003,
            b"ab",
        );
        let fmp_result = whole(
            FirmwareWidth::Bits64,
            48,
            EFI_FIRMWARE_MANAGEMENT_CAPSULE_ID_GUID,
            0,
            &fmp(1, &[char16("update.cap"), vec![0, 0, 0, 0]].concat()),
        );
        let variables = HeldVariables::default()
            .with(CAPSULE_MAX, EFI_CAPSULE_REPORT_GUID, &char16("Capsule0003"))
            .with(CAPSULE_LAST, EFI_CAPSULE_REPORT_GUID, &[0x41, 0x00])
            .with("Capsule0000", EFI_CAPSULE_REPORT_GUID, &json_result_bytes())
            .with("Capsule0001", EFI_CAPSULE_REPORT_GUID, &resp_not_utf8)
            .with("Capsule0002", EFI_CAPSULE_REPORT_GUID, &other_utf8)
            .with("Capsule0003", EFI_CAPSULE_REPORT_GUID, &[1, 2, 3])
            .with("Capsule0004", EFI_CAPSULE_REPORT_GUID, &fmp_result);
        let listed = variables.variables.borrow().keys().cloned().collect();
        let processed = serde_json::json!({
            "year": 2026,
            "month": 11,
            "day": 7,
            "hour": 12,
            "minute": 34,
            "second": 56,
            "nanosecond": 789,
            "time_zone": -60,
            "daylight": 1,
        });

        let results = list_capsule_results(&Names(listed), &variables, FirmwareWidth::Bits64)
            .expect("list the results");

        assert_eq!(
            serde_json::to_value(&results).expect("serialize the results"),
            serde_json::json!({
                "capsule_max": "Capsule0003",
                "capsule_last": {
                    "error": "CapsuleLast holds 2 bytes, not the 22 of its CHAR16[11] without a \
                              terminator (UEFI 2.11 section 8.5.6, Table 8.9)",
                    "data": { "hex": "4100" },
                },
                "results": [
                    {
                        "name": "Capsule0000",
                        "result": {
                            "variable_total_size": 62,
                            "capsule_guid": "67D6F4CD-D6B8-4573-BF4A-DE5E252D61AE",
                            "capsule_processed": processed,
                            "capsule_status": "0x0",
                            "json": { "capsule_id": 9, "resp": { "text": "{}" } },
                        },
                    },
                    {
                        "name": "Capsule0001",
                        "result": {
                            "variable_total_size": 62,
                            "capsule_guid": "67D6F4CD-D6B8-4573-BF4A-DE5E252D61AE",
                            "capsule_processed": processed,
                            "capsule_status": "0x8000000000000002",
                            "json": { "capsule_id": 10, "resp": { "hex": "ff00" } },
                        },
                    },
                    {
                        "name": "Capsule0002",
                        "result": {
                            "variable_total_size": 50,
                            "capsule_guid": "8C78A505-BAA0-4C4A-869F-000000001300",
                            "capsule_processed": processed,
                            "capsule_status": "0x8000000000000003",
                            "data": { "hex": "6162" },
                        },
                    },
                    {
                        "name": "Capsule0003",
                        "error": "the capsule result holds 3 bytes, fewer than the 48 of the \
                                  EFI_CAPSULE_RESULT_VARIABLE_HEADER of 64-bit firmware (UEFI \
                                  2.11 section 8.5.6.1.1)",
                        "data": { "hex": "010203" },
                    },
                    {
                        "name": "Capsule0004",
                        "result": {
                            "variable_total_size": 92,
                            "capsule_guid": "6DCBD5ED-E82D-4C44-BDA1-7194199AD92A",
                            "capsule_processed": processed,
                            "capsule_status": "0x0",
                            "fmp": {
                                "payload_index": 2,
                                "update_image_index": 3,
                                "update_image_type_id": "8C78A505-BAA0-4C4A-869F-000000001300",
                                "capsule_file_name": "update.cap",
                                "capsule_target": "",
                            },
                        },
                    },
                ],
            }),
            "JSON"
        );
    }

    /// CapsuleResult::read reads the header of the firmware's width, then the table's
    /// VariableTotalSize bytes, and nothing after them.
    #[cfg(configuration_tables)]
    #[test]
    fn read_reads_the_header_then_the_total_size() {
        for (width, header, status) in WIDTHS {
            let bytes = whole(
                width,
                header,
                EFI_JSON_CAPSULE_ID_GUID,
                status,
                &json(1, 5, 1, b"x"),
            );
            let table = TableInRegion::of_width([&bytes[..], &[0xee; 32]].concat(), width);

            let result = CapsuleResult::read(&table);

            assert_eq!(
                result.expect("read the table"),
                CapsuleResult::decode(&bytes, width).expect("decode the table"),
                "{width:?}"
            );
            assert_eq!(
                table.reads.borrow().clone(),
                [header, header + 13],
                "{width:?}"
            );
        }
    }

    /// CapsuleResult::read refuses a VariableTotalSize under the header's size before reading
    /// more, and reads that run past the table's memory, naming what it read.
    #[cfg(configuration_tables)]
    #[test]
    fn read_refuses_what_it_cannot_read() {
        let short = result(FirmwareWidth::Bits64, 47, OTHER_GUID, 0, &[]);
        let past = result(FirmwareWidth::Bits64, 4096, OTHER_GUID, 0, &[]);
        for (region, reads, refusal) in [
            (
                short,
                vec![48],
                "the capsule result's VariableTotalSize 47 is less than the 48 bytes of its \
                 EFI_CAPSULE_RESULT_VARIABLE_HEADER (UEFI 2.11 section 8.5.6.1.1)",
            ),
            (
                past,
                vec![48, 4096],
                "read the VariableTotalSize 4096 bytes of the JSON capsule result table: 4096 \
                 bytes run past the region of 48 bytes",
            ),
            (
                vec![0; 40],
                vec![48],
                "read the EFI_CAPSULE_RESULT_VARIABLE_HEADER of the JSON capsule result table: 48 \
                 bytes run past the region of 40 bytes",
            ),
        ] {
            let table = TableInRegion::new(region);

            let error = CapsuleResult::read(&table).expect_err("refuse the table");

            assert_eq!(format!("{error:#}"), refusal, "{refusal}");
            assert_eq!(table.reads.borrow().clone(), reads, "{refusal}");
        }
    }

    /// read_json_capsule_result names the GUID of a table that the firmware does not list.
    #[cfg(configuration_tables)]
    #[test]
    fn read_json_capsule_result_names_a_missing_table() {
        let error =
            read_json_capsule_result(None::<TableInRegion>).expect_err("read a missing table");

        assert_eq!(
            error.to_string(),
            "the firmware lists no configuration table of EFI_JSON_CAPSULE_RESULT_TABLE_GUID, \
             DBC461C3-B3DE-422A-B9B4-9886FD49A1E5 (UEFI 2.11 section 23.5.3)",
            "message"
        );
    }
}
