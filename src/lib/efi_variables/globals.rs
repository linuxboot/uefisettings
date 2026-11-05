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

//! The global variables of UEFI 2.11 §3.3 but its load options, hot keys and device paths, and
//! the signature databases of §32.7.1, decoded as variable get prints them.

use std::fmt;

use anyhow::Context;
use anyhow::Result;
use serde::ser::SerializeMap;
use serde::ser::SerializeSeq;
use serde::Serialize;
use serde::Serializer;
use sha2::Digest;
use sha2::Sha256;
use thiserror::Error;

use crate::efi_variables::VariableData;
use crate::hii::package::Guid;
use crate::hii::VariableKey;

/// EFI_GLOBAL_VARIABLE, the vendor GUID of the global variables (UEFI 2.11 §3.3).
const EFI_GLOBAL_VARIABLE: Guid = Guid {
    data1: 0x8BE4_DF61,
    data2: 0x93CA,
    data3: 0x11D2,
    data4: [0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C],
};
/// EFI_IMAGE_SECURITY_DATABASE_GUID, the vendor GUID of db, dbx, dbt and dbr (UEFI 2.11 §32.7.1).
const EFI_IMAGE_SECURITY_DATABASE: Guid = Guid {
    data1: 0xD719_B2CB,
    data2: 0x3D3A,
    data3: 0x4596,
    data4: [0xA3, 0xBC, 0xDA, 0xD0, 0x0E, 0x67, 0x65, 0x6F],
};
/// The size of an EFI_GUID, such as SignatureOwner, which starts each EFI_SIGNATURE_DATA.
const GUID_SIZE: usize = 16;
/// The fields of an EFI_SIGNATURE_LIST before its SignatureHeader: SignatureType,
/// SignatureListSize, SignatureHeaderSize and SignatureSize (UEFI 2.11 §32.4.1).
const SIGNATURE_LIST_HEADER_SIZE: usize = GUID_SIZE + 3 * 4;
/// The Timeout that waits for user input (UEFI 2.11 §3.3).
const WAIT_FOR_USER_INPUT: u16 = 0xFFFF;
/// What variable get prints for the Timeout that waits for user input.
const WAIT_FOR_USER_INPUT_TEXT: &str = "wait for user input";
/// EFI_BOOT_OPTION_SUPPORT_COUNT, the bits of BootOptionSupport that hold a count (UEFI 2.11
/// §3.1.4).
const BOOT_OPTION_SUPPORT_COUNT: u32 = 0x0000_0300;

/// The variables that variable get decodes: those of UEFI 2.11 Table 3.1 but the load options,
/// hot keys and device paths, and the signature databases.
const GLOBALS: [Global; 33] = [
    Global::efi_global("AuditMode", Codec::Byte),
    Global::efi_global("BootCurrent", Codec::BootOption),
    Global::efi_global("BootNext", Codec::BootOption),
    Global::efi_global("BootOptionSupport", Codec::BootOptionSupport),
    Global::efi_global("BootOrder", Codec::Order(LoadOptionKind::Boot)),
    Global::efi_global("dbDefault", Codec::SignatureLists),
    Global::efi_global("dbrDefault", Codec::SignatureLists),
    Global::efi_global("dbtDefault", Codec::SignatureLists),
    Global::efi_global("dbxDefault", Codec::SignatureLists),
    Global::efi_global("DeployedMode", Codec::Byte),
    Global::efi_global("devAuthBoot", Codec::Byte),
    Global::efi_global("devdbDefault", Codec::SignatureLists),
    Global::efi_global("DriverOrder", Codec::Order(LoadOptionKind::Driver)),
    Global::efi_global("HwErrRecSupport", Codec::Word),
    Global::efi_global("KEK", Codec::SignatureLists),
    Global::efi_global("KEKDefault", Codec::SignatureLists),
    Global::efi_global("OsIndications", Codec::OsIndications),
    Global::efi_global("OsIndicationsSupported", Codec::OsIndications),
    Global::efi_global("OsRecoveryOrder", Codec::Guids),
    Global::efi_global("PK", Codec::SignatureLists),
    Global::efi_global("PKDefault", Codec::SignatureLists),
    Global::efi_global("PlatformLangCodes", Codec::Ascii),
    Global::efi_global("PlatformLang", Codec::Ascii),
    Global::efi_global("SignatureSupport", Codec::Guids),
    Global::efi_global("SecureBoot", Codec::Byte),
    Global::efi_global("SetupMode", Codec::Byte),
    Global::efi_global("SysPrepOrder", Codec::Order(LoadOptionKind::SysPrep)),
    Global::efi_global("Timeout", Codec::Timeout),
    Global::efi_global("VendorKeys", Codec::Byte),
    Global::image_security("db"),
    Global::image_security("dbx"),
    Global::image_security("dbt"),
    Global::image_security("dbr"),
];

/// What variable get tells of a variable that it decodes: its name as an efivar file, and its
/// attributes and value unless the firmware has not created it.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalVariable {
    /// The variable, named as its efivar file
    pub variable: String,
    /// Its attributes and value; None if it is absent
    pub contents: Option<GlobalContents>,
}

/// The JSON object that variable get prints: the variable, then its attributes and value, or
/// "absent": true.
impl Serialize for GlobalVariable {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("variable", &self.variable)?;
        match &self.contents {
            Some(contents) => {
                map.serialize_entry("attributes", &contents.attributes)?;
                map.serialize_entry("value", &contents.value)?;
            }
            None => map.serialize_entry("absent", &true)?,
        }
        map.end()
    }
}

/// The attributes and decoded data of a variable that variable get decodes.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GlobalContents {
    /// Its attributes bitmask (UEFI 2.10 §8.2.1)
    pub attributes: u32,
    /// Its data, decoded
    pub value: GlobalValue,
}

/// The data of a variable that variable get decodes, which serializes as the JSON that it
/// prints.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
#[serde(untagged)]
pub enum GlobalValue {
    /// Timeout
    Timeout(Timeout),
    /// BootOrder, DriverOrder and SysPrepOrder: the load options, in order
    LoadOptions(Vec<LoadOptionName>),
    /// BootCurrent and BootNext
    LoadOption(LoadOptionName),
    /// PlatformLang and PlatformLangCodes, without the NUL
    Ascii(String),
    /// OsIndications and OsIndicationsSupported
    OsIndications(OsIndications),
    /// SecureBoot, SetupMode, AuditMode, DeployedMode, VendorKeys and devAuthBoot
    Byte(u8),
    /// HwErrRecSupport
    Word(u16),
    /// BootOptionSupport
    BootOptionSupport(BootOptionSupport),
    /// SignatureSupport and OsRecoveryOrder
    Guids(Vec<Guid>),
    /// PK, KEK, db, dbx, dbt, dbr and the defaults of the signature databases
    SignatureLists(Vec<SignatureList>),
}

/// What Timeout tells: "the number of seconds that the firmware will wait before initiating the
/// original default boot selection", or that "firmware will wait for user input before booting"
/// at 0xFFFF (UEFI 2.11 §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Timeout {
    Seconds(u16),
    WaitForUserInput,
}

impl From<u16> for Timeout {
    fn from(value: u16) -> Self {
        match value {
            WAIT_FOR_USER_INPUT => Self::WaitForUserInput,
            seconds => Self::Seconds(seconds),
        }
    }
}

/// The seconds as a number, else WAIT_FOR_USER_INPUT_TEXT.
impl Serialize for Timeout {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Seconds(seconds) => serializer.serialize_u16(*seconds),
            Self::WaitForUserInput => serializer.serialize_str(WAIT_FOR_USER_INPUT_TEXT),
        }
    }
}

/// The kinds of load options that the order variables list (UEFI 2.11 §3.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LoadOptionKind {
    Boot,
    Driver,
    SysPrep,
}

impl LoadOptionKind {
    /// The name of the variables of this kind before their option number.
    fn prefix(self) -> &'static str {
        match self {
            Self::Boot => "Boot",
            Self::Driver => "Driver",
            Self::SysPrep => "SysPrep",
        }
    }
}

/// A load option variable, such as Boot0001, whose number is "in printable hexadecimal
/// representation using the digits 0-9, and the upper case versions of the characters A-F"
/// (UEFI 2.11 §3.1.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct LoadOptionName {
    pub kind: LoadOptionKind,
    pub number: u16,
}

impl fmt::Display for LoadOptionName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{:04X}", self.kind.prefix(), self.number)
    }
}

/// As Display writes it.
impl Serialize for LoadOptionName {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

bitflags::bitflags! {
    /// The bits of OsIndications and OsIndicationsSupported, EFI_OS_INDICATIONS_ and these
    /// names (UEFI 2.11 §8.5.4), and any reserved ones.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct OsIndications: u64 {
        const BOOT_TO_FW_UI = 0x0000_0000_0000_0001;
        const TIMESTAMP_REVOCATION = 0x0000_0000_0000_0002;
        const FILE_CAPSULE_DELIVERY_SUPPORTED = 0x0000_0000_0000_0004;
        const FMP_CAPSULE_SUPPORTED = 0x0000_0000_0000_0008;
        const CAPSULE_RESULT_VAR_SUPPORTED = 0x0000_0000_0000_0010;
        const START_OS_RECOVERY = 0x0000_0000_0000_0020;
        const START_PLATFORM_RECOVERY = 0x0000_0000_0000_0040;
        const JSON_CONFIG_DATA_REFRESH = 0x0000_0000_0000_0080;
    }
}

/// As serialize_bits writes them.
impl Serialize for OsIndications {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serialize_bits(
            serializer,
            self.iter_names().map(|(name, _)| name),
            self.bits() & !Self::all().bits(),
        )
    }
}

bitflags::bitflags! {
    /// The flags of BootOptionSupport, EFI_BOOT_OPTION_SUPPORT_ and these names (UEFI 2.11
    /// §3.1.4), and any reserved ones, but EFI_BOOT_OPTION_SUPPORT_COUNT.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct BootOptionFlags: u32 {
        const KEY = 0x0000_0001;
        const APP = 0x0000_0002;
        const SYSPREP = 0x0000_0010;
    }
}

/// As serialize_bits writes them.
impl Serialize for BootOptionFlags {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        serialize_bits(
            serializer,
            self.iter_names().map(|(name, _)| name),
            u64::from(self.bits() & !Self::all().bits()),
        )
    }
}

/// What BootOptionSupport tells: its flags, and in EFI_BOOT_OPTION_SUPPORT_COUNT "the maximum
/// number of key presses which the boot manager supports in the EFI_KEY_OPTION.KeyData.InputKeyCount"
/// (UEFI 2.11 §3.1.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct BootOptionSupport {
    pub flags: BootOptionFlags,
    pub count: u32,
}

impl From<u32> for BootOptionSupport {
    fn from(value: u32) -> Self {
        Self {
            flags: BootOptionFlags::from_bits_retain(value & !BOOT_OPTION_SUPPORT_COUNT),
            count: (value & BOOT_OPTION_SUPPORT_COUNT)
                >> BOOT_OPTION_SUPPORT_COUNT.trailing_zeros(),
        }
    }
}

/// An EFI_SIGNATURE_LIST (UEFI 2.11 §32.4.1), summarized: its SignatureType and its signatures.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct SignatureList {
    #[serde(rename = "type")]
    pub signature_type: Guid,
    pub signatures: Vec<Signature>,
}

/// An EFI_SIGNATURE_DATA, summarized: its SignatureOwner and the SHA-256 of its SignatureData.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct Signature {
    pub owner: Guid,
    #[serde(serialize_with = "serialize_hex")]
    pub sha256: [u8; 32],
}

/// The variable `name` that `variables` hold, of the vendor GUID `vendor` if given, which must be
/// its own, decoded.
pub(crate) fn read_global(
    variables: &impl VariableData,
    name: &str,
    vendor: Option<Guid>,
) -> Result<GlobalVariable> {
    let global = Global::named(name, vendor)?;
    let key = global.key();
    let contents = variables
        .variable_data(&key)?
        .map(|contents| {
            let value = global
                .codec
                .decode(contents.data())
                .with_context(|| format!("EFI variable {key} is malformed"))?;
            anyhow::Ok(GlobalContents {
                attributes: contents.attributes().bits(),
                value,
            })
        })
        .transpose()?;
    Ok(GlobalVariable {
        variable: key.to_string(),
        contents,
    })
}

/// A variable that variable get decodes: its name, vendor GUID and codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Global {
    name: &'static str,
    vendor: Guid,
    codec: Codec,
}

impl Global {
    /// The global variable `name` (UEFI 2.11 §3.3).
    const fn efi_global(name: &'static str, codec: Codec) -> Self {
        Self {
            name,
            vendor: EFI_GLOBAL_VARIABLE,
            codec,
        }
    }

    /// The signature database `name` (UEFI 2.11 §32.7.1).
    const fn image_security(name: &'static str) -> Self {
        Self {
            name,
            vendor: EFI_IMAGE_SECURITY_DATABASE,
            codec: Codec::SignatureLists,
        }
    }

    /// The variable `name` of GLOBALS, of the vendor GUID `vendor` if given.
    fn named(name: &str, vendor: Option<Guid>) -> std::result::Result<Self, NoGlobal> {
        let global = GLOBALS
            .iter()
            .find(|global| global.name == name)
            .copied()
            .ok_or_else(|| NoGlobal::Unknown(name.to_owned()))?;
        match vendor {
            Some(vendor) if vendor != global.vendor => Err(NoGlobal::ForeignVendor {
                name: name.to_owned(),
                vendor,
                own: global.vendor,
            }),
            Some(_) | None => Ok(global),
        }
    }

    fn key(self) -> VariableKey {
        VariableKey {
            name: self.name.to_owned(),
            guid: self.vendor,
        }
    }
}

/// A variable that variable get does not decode.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
enum NoGlobal {
    #[error(
        "variable get decodes {}, not {0}; `uefisettings variable info {0} GUID` shows the \
         attributes and size of any EFI variable",
        global_names()
    )]
    Unknown(String),
    #[error(
        "{name} of vendor {vendor} is not the {name} that variable get decodes, of vendor {own}; \
         `uefisettings variable info {name} {vendor}` shows its attributes and size"
    )]
    ForeignVendor {
        name: String,
        vendor: Guid,
        own: Guid,
    },
}

/// The names of GLOBALS, comma-separated.
fn global_names() -> String {
    GLOBALS.map(|global| global.name).join(", ")
}

/// How the data of a variable that variable get decodes is laid out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Codec {
    /// "a binary UINT16" of seconds (UEFI 2.11 §3.3)
    Timeout,
    /// "an array of UINT16's" of option numbers of this kind
    Order(LoadOptionKind),
    /// "a single UINT16" Boot#### number
    BootOption,
    /// "a null-terminated ASCII string"
    Ascii,
    /// "a UINT64 bitmask" (UEFI 2.11 §8.5.4)
    OsIndications,
    /// "an 8-bit unsigned integer"
    Byte,
    /// "a binary UINT16"
    Word,
    /// "a UINT32"
    BootOptionSupport,
    /// "an array of GUIDs"
    Guids,
    /// EFI_SIGNATURE_LISTs (UEFI 2.11 §32.4.1)
    SignatureLists,
}

impl Codec {
    /// The value of `data`, or why it is malformed.
    fn decode(self, data: &[u8]) -> std::result::Result<GlobalValue, MalformedData> {
        Ok(match self {
            Self::Timeout => {
                GlobalValue::Timeout(u16::from_le_bytes(exact(data, "a UINT16")?).into())
            }
            Self::Order(kind) => GlobalValue::LoadOptions(
                items::<2>(data, "UINT16")?
                    .map(|number| LoadOptionName {
                        kind,
                        number: u16::from_le_bytes(number),
                    })
                    .collect(),
            ),
            Self::BootOption => GlobalValue::LoadOption(LoadOptionName {
                kind: LoadOptionKind::Boot,
                number: u16::from_le_bytes(exact(data, "a UINT16")?),
            }),
            Self::Ascii => GlobalValue::Ascii(ascii(data)?),
            Self::OsIndications => GlobalValue::OsIndications(OsIndications::from_bits_retain(
                u64::from_le_bytes(exact(data, "a UINT64")?),
            )),
            Self::Byte => GlobalValue::Byte(u8::from_le_bytes(exact(data, "a UINT8")?)),
            Self::Word => GlobalValue::Word(u16::from_le_bytes(exact(data, "a UINT16")?)),
            Self::BootOptionSupport => {
                GlobalValue::BootOptionSupport(u32::from_le_bytes(exact(data, "a UINT32")?).into())
            }
            Self::Guids => GlobalValue::Guids(
                items::<GUID_SIZE>(data, "EFI_GUID")?
                    .map(Guid::from)
                    .collect(),
            ),
            Self::SignatureLists => GlobalValue::SignatureLists(signature_lists(data)?),
        })
    }
}

/// Data that a Codec refuses.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
enum MalformedData {
    #[error("{held} bytes, not the {size} of {what}")]
    Size {
        held: usize,
        size: usize,
        what: &'static str,
    },
    #[error("{held} bytes, not a whole number of {what}s of {size} bytes")]
    Items {
        held: usize,
        size: usize,
        what: &'static str,
    },
    #[error("no NUL at its end")]
    Unterminated,
    #[error("a NUL at byte {0}, before its end")]
    InteriorNul(usize),
    #[error("byte {at} is 0x{byte:02X}, which is not ASCII")]
    NotAscii { at: usize, byte: u8 },
    #[error("the EFI_SIGNATURE_LIST at byte {offset} has {error}")]
    SignatureList {
        offset: usize,
        error: SignatureListError,
    },
}

/// An EFI_SIGNATURE_LIST that signature_lists refuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
enum SignatureListError {
    #[error(
        "{0} bytes, fewer than the {} of its header",
        SIGNATURE_LIST_HEADER_SIZE
    )]
    Header(usize),
    #[error("a SignatureListSize of {size} bytes, but {held} are left")]
    ListSize { size: u32, held: usize },
    #[error(
        "a SignatureListSize of {size} bytes, fewer than its header and its SignatureHeaderSize of \
         {header_size}"
    )]
    ShorterThanHeader { size: u32, header_size: u32 },
    #[error(
        "a SignatureSize of {0} bytes, fewer than the {} of its SignatureOwner",
        GUID_SIZE
    )]
    SignatureSize(u32),
    #[error("{held} bytes of signatures, not a whole number of its SignatureSize of {size}")]
    Signatures { held: usize, size: u32 },
}

/// The `N` bytes of `data`, which errors call `what`, if it holds exactly those.
fn exact<const N: usize>(
    data: &[u8],
    what: &'static str,
) -> std::result::Result<[u8; N], MalformedData> {
    data.try_into().map_err(|_| MalformedData::Size {
        held: data.len(),
        size: N,
        what,
    })
}

/// The `N`-byte items of `data`, which errors call `what`s, if it holds a whole number of them.
fn items<'a, const N: usize>(
    data: &'a [u8],
    what: &'static str,
) -> std::result::Result<impl Iterator<Item = [u8; N]> + 'a, MalformedData> {
    match data.as_chunks::<N>() {
        (items, []) => Ok(items.iter().copied()),
        (_, _) => Err(MalformedData::Items {
            held: data.len(),
            size: N,
            what,
        }),
    }
}

/// The null-terminated ASCII string of `data`, without its NUL.
fn ascii(data: &[u8]) -> std::result::Result<String, MalformedData> {
    let Some((&0, text)) = data.split_last() else {
        return Err(MalformedData::Unterminated);
    };
    if let Some(at) = text.iter().position(|&byte| byte == 0) {
        return Err(MalformedData::InteriorNul(at));
    }
    if let Some((at, &byte)) = text.iter().enumerate().find(|(_, byte)| !byte.is_ascii()) {
        return Err(MalformedData::NotAscii { at, byte });
    }
    Ok(text.iter().copied().map(char::from).collect())
}

/// The EFI_SIGNATURE_LISTs of a signature database, which "consists of zero or more signature
/// lists" (UEFI 2.11 §32.4.1).
fn signature_lists(data: &[u8]) -> std::result::Result<Vec<SignatureList>, MalformedData> {
    let mut lists = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let offset = data.len().saturating_sub(rest.len());
        let (list, after) =
            signature_list(rest).map_err(|error| MalformedData::SignatureList { offset, error })?;
        lists.push(list);
        rest = after;
    }
    Ok(lists)
}

/// The EFI_SIGNATURE_LIST that starts `data`, and the bytes after it.
fn signature_list(data: &[u8]) -> std::result::Result<(SignatureList, &[u8]), SignatureListError> {
    let mut fields = data;
    let (Some(signature_type), Some(size), Some(header_size), Some(signature_size)) = (
        take::<GUID_SIZE>(&mut fields),
        take::<4>(&mut fields).map(u32::from_le_bytes),
        take::<4>(&mut fields).map(u32::from_le_bytes),
        take::<4>(&mut fields).map(u32::from_le_bytes),
    ) else {
        return Err(SignatureListError::Header(data.len()));
    };
    // SignatureListSize is the "Total size of the signature list, including this header".
    let (list, after) = usize::try_from(size)
        .ok()
        .and_then(|size| data.split_at_checked(size))
        .ok_or(SignatureListError::ListSize {
            size,
            held: data.len(),
        })?;
    let signatures = usize::try_from(header_size)
        .ok()
        .and_then(|header_size| list.get(SIGNATURE_LIST_HEADER_SIZE..)?.get(header_size..))
        .ok_or(SignatureListError::ShorterThanHeader { size, header_size })?;
    let signature_bytes = usize::try_from(signature_size)
        .ok()
        .filter(|&signature_bytes| signature_bytes >= GUID_SIZE)
        .ok_or(SignatureListError::SignatureSize(signature_size))?;
    let chunks = signatures.chunks_exact(signature_bytes);
    if !chunks.remainder().is_empty() {
        return Err(SignatureListError::Signatures {
            held: signatures.len(),
            size: signature_size,
        });
    }
    let signatures = chunks
        .map(|signature| {
            let (owner, data) = signature
                .split_first_chunk::<GUID_SIZE>()
                .ok_or(SignatureListError::SignatureSize(signature_size))?;
            Ok(Signature {
                owner: (*owner).into(),
                sha256: Sha256::digest(data).into(),
            })
        })
        .collect::<std::result::Result<_, _>>()?;
    Ok((
        SignatureList {
            signature_type: signature_type.into(),
            signatures,
        },
        after,
    ))
}

/// The first `N` bytes of `*data`, which it then skips.
fn take<const N: usize>(data: &mut &[u8]) -> Option<[u8; N]> {
    let (chunk, rest) = data.split_first_chunk::<N>()?;
    *data = rest;
    Some(*chunk)
}

/// `names`, then each bit of `reserved` in hex, such as 0x100.
fn serialize_bits<S: Serializer>(
    serializer: S,
    names: impl Iterator<Item = &'static str>,
    reserved: u64,
) -> std::result::Result<S::Ok, S::Error> {
    let mut seq = serializer.serialize_seq(None)?;
    for name in names {
        seq.serialize_element(name)?;
    }
    for bit in (0..u64::BITS)
        .map(|shift| 1_u64 << shift)
        .filter(|bit| reserved & bit != 0)
    {
        seq.serialize_element(&format!("{bit:#X}"))?;
    }
    seq.end()
}

/// `bytes` in lowercase hex, as sha256sum prints a hash.
fn serialize_hex<S: Serializer>(
    bytes: &[u8; 32],
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    let hex: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
    serializer.serialize_str(&hex)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;

    use serde_json::json;

    use super::*;
    use crate::efi_variables::VariableContents;
    use crate::hii::VariableAttributes;

    /// EFI_CERT_SHA256_GUID (UEFI 2.11 §32.4.1) as its bytes.
    const EFI_CERT_SHA256: [u8; 16] = [
        0x26, 0x16, 0xC4, 0xC1, 0x4C, 0x50, 0x92, 0x40, 0xAC, 0xA9, 0x41, 0xF9, 0x36, 0x93, 0x43,
        0x28,
    ];
    /// EFI_CERT_X509_GUID (UEFI 2.11 §32.4.1) as its bytes.
    const EFI_CERT_X509: [u8; 16] = [
        0xA1, 0x59, 0xC0, 0xA5, 0xE4, 0x94, 0xA7, 0x4A, 0x87, 0xB5, 0xAB, 0x15, 0x5C, 0x2B, 0xF0,
        0x72,
    ];
    /// The owner of the signatures here: the formset GUID of EDK2's DriverSample.
    const OWNER: [u8; 16] = [
        0xF4, 0x27, 0x4A, 0xA0, 0x00, 0xDF, 0x42, 0x4D, 0xB5, 0x52, 0x39, 0x51, 0x13, 0x02, 0x11,
        0x3D,
    ];
    /// The SHA-256 of "abc" and of no bytes (FIPS 180-2 Appendix B.1; NIST's example values).
    const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    const SHA256_EMPTY: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    /// NV+BS+RT.
    const NV_BS_RT: VariableAttributes = VariableAttributes::NON_VOLATILE
        .union(VariableAttributes::BOOTSERVICE_ACCESS)
        .union(VariableAttributes::RUNTIME_ACCESS);

    /// VariableData that hold `variables` and record each key read.
    #[derive(Default)]
    struct HeldVariables {
        variables: BTreeMap<VariableKey, VariableContents>,
        read: RefCell<Vec<VariableKey>>,
    }

    impl HeldVariables {
        /// Holds `data` with NV+BS+RT as the variable `name` of `vendor`.
        fn with(mut self, name: &str, vendor: Guid, data: &[u8]) -> Self {
            let contents = VariableContents::new(NV_BS_RT, data.to_vec()).expect("hold data");
            self.variables.insert(key(name, vendor), contents);
            self
        }
    }

    impl VariableData for HeldVariables {
        fn variable_data(&self, key: &VariableKey) -> Result<Option<VariableContents>> {
            self.read.borrow_mut().push(key.clone());
            Ok(self.variables.get(key).cloned())
        }
    }

    fn key(name: &str, vendor: Guid) -> VariableKey {
        VariableKey {
            name: name.to_string(),
            guid: vendor,
        }
    }

    /// The vendor GUID of a variable that `name` names in GLOBALS.
    fn vendor_of(name: &str) -> Guid {
        GLOBALS
            .iter()
            .find(|global| global.name == name)
            .unwrap_or_else(|| panic!("{name} is not in GLOBALS"))
            .vendor
    }

    /// An EFI_SIGNATURE_LIST (UEFI 2.11 §32.4.1) of `signature_type` with `header` and
    /// `signatures`, each of SignatureOwner OWNER and the SignatureData given, padded with zeros
    /// to `data_size` bytes.
    fn signature_list(
        signature_type: [u8; 16],
        header: &[u8],
        data_size: usize,
        signatures: &[&[u8]],
    ) -> Vec<u8> {
        let signature_size = 16 + data_size;
        let size = 28 + header.len() + signature_size * signatures.len();
        let mut list = signature_type.to_vec();
        for field in [size, header.len(), signature_size] {
            list.extend(u32::try_from(field).expect("a UINT32").to_le_bytes());
        }
        list.extend(header);
        for data in signatures {
            list.extend(OWNER);
            list.extend(*data);
            list.resize(list.len() + data_size - data.len(), 0);
        }
        list
    }

    /// The JSON of the value of `data` as the variable `name`.
    fn decoded(name: &str, data: &[u8]) -> serde_json::Value {
        let variables = HeldVariables::default().with(name, vendor_of(name), data);
        let global = read_global(&variables, name, None)
            .unwrap_or_else(|error| panic!("read {name} {data:02X?}: {error:#}"));
        let contents = global
            .contents
            .unwrap_or_else(|| panic!("{name} {data:02X?} is absent"));
        assert_eq!(contents.attributes, NV_BS_RT.bits(), "{name} attributes");
        serde_json::to_value(&contents.value).expect("serialize the value")
    }

    /// Each codec turns the data of its variables into the value that variable get prints,
    /// SecureBoot=1 among them, and reserved values and bits stay in it.
    #[test]
    fn codecs_decode_the_data_of_each_variable() {
        let owner = "A04A27F4-DF00-4D42-B552-39511302113D";
        let databases = [
            signature_list(EFI_CERT_X509, &[], 3, &[b"abc"]),
            // a SignatureType that §32.4.1 gives no sizes, for a SignatureHeader
            signature_list(OWNER, &[0xAA, 0xBB], 0, &[b"", b""]),
        ]
        .concat();
        let databases_json = json!([
            {
                "type": "A5C059A1-94E4-4AA7-87B5-AB155C2BF072",
                "signatures": [{ "owner": owner, "sha256": SHA256_ABC }],
            },
            {
                "type": owner,
                "signatures": [
                    { "owner": owner, "sha256": SHA256_EMPTY },
                    { "owner": owner, "sha256": SHA256_EMPTY },
                ],
            },
        ]);
        let cases: Vec<(&str, Vec<u8>, serde_json::Value)> = vec![
            ("Timeout", vec![5, 0], json!(5)),
            ("Timeout", vec![0, 0], json!(0)),
            ("Timeout", vec![0xFE, 0xFF], json!(65534)),
            ("Timeout", vec![0xFF, 0xFF], json!("wait for user input")),
            (
                "BootOrder",
                vec![1, 0, 0x0A, 0x0B],
                json!(["Boot0001", "Boot0B0A"]),
            ),
            ("DriverOrder", vec![0, 0], json!(["Driver0000"])),
            ("SysPrepOrder", vec![0xFF, 0xFF], json!(["SysPrepFFFF"])),
            ("BootNext", vec![3, 0], json!("Boot0003")),
            ("BootCurrent", vec![0xCD, 0xAB], json!("BootABCD")),
            ("PlatformLang", b"en-US\0".to_vec(), json!("en-US")),
            (
                "PlatformLangCodes",
                b"en;fr;en-US;fr-FR\0".to_vec(),
                json!("en;fr;en-US;fr-FR"),
            ),
            ("OsIndications", vec![0; 8], json!([])),
            (
                "OsIndicationsSupported",
                vec![0x45, 0x01, 0, 0, 0, 0, 0, 0x80],
                json!([
                    "BOOT_TO_FW_UI",
                    "FILE_CAPSULE_DELIVERY_SUPPORTED",
                    "START_PLATFORM_RECOVERY",
                    "0x100",
                    "0x8000000000000000",
                ]),
            ),
            (
                "OsIndications",
                vec![0xBA, 0, 0, 0, 0, 0, 0, 0],
                json!([
                    "TIMESTAMP_REVOCATION",
                    "FMP_CAPSULE_SUPPORTED",
                    "CAPSULE_RESULT_VAR_SUPPORTED",
                    "START_OS_RECOVERY",
                    "JSON_CONFIG_DATA_REFRESH",
                ]),
            ),
            ("SecureBoot", vec![1], json!(1)),
            ("SecureBoot", vec![0], json!(0)),
            ("SetupMode", vec![1], json!(1)),
            ("AuditMode", vec![0], json!(0)),
            ("DeployedMode", vec![1], json!(1)),
            ("VendorKeys", vec![2], json!(2)),
            ("devAuthBoot", vec![0], json!(0)),
            ("HwErrRecSupport", vec![1, 0], json!(1)),
            ("HwErrRecSupport", vec![0xFF, 0xFF], json!(65535)),
            (
                "BootOptionSupport",
                vec![0x13, 0x03, 0, 0],
                json!({ "flags": ["KEY", "APP", "SYSPREP"], "count": 3 }),
            ),
            (
                "BootOptionSupport",
                vec![0x00, 0x05, 0, 0x80],
                json!({ "flags": ["0x400", "0x80000000"], "count": 1 }),
            ),
            (
                "SignatureSupport",
                [EFI_CERT_SHA256, EFI_CERT_X509].concat(),
                json!([
                    "C1C41626-504C-4092-ACA9-41F936934328",
                    "A5C059A1-94E4-4AA7-87B5-AB155C2BF072",
                ]),
            ),
            ("OsRecoveryOrder", OWNER.to_vec(), json!([owner])),
            ("PK", databases.clone(), databases_json.clone()),
            ("KEK", databases.clone(), databases_json.clone()),
            ("db", databases.clone(), databases_json.clone()),
            ("dbx", databases.clone(), databases_json.clone()),
            ("dbt", databases.clone(), databases_json.clone()),
            ("dbr", databases.clone(), databases_json.clone()),
            ("dbDefault", databases.clone(), databases_json.clone()),
            ("devdbDefault", databases, databases_json),
            (
                "dbxDefault",
                signature_list(EFI_CERT_SHA256, &[], 32, &[]),
                json!([{ "type": "C1C41626-504C-4092-ACA9-41F936934328", "signatures": [] }]),
            ),
        ];
        for (name, data, want) in cases {
            assert_eq!(decoded(name, &data), want, "{name} {data:02X?}");
        }
    }

    /// Each codec refuses data of another size or layout than its variables have, naming the
    /// variable.
    #[test]
    fn codecs_refuse_malformed_data() {
        let list = signature_list(EFI_CERT_X509, &[], 3, &[b"abc"]);
        let mut short_list = list.clone();
        short_list.truncate(10);
        let mut long_list = list.clone();
        long_list[16..20].copy_from_slice(&100_u32.to_le_bytes());
        let mut header_past_list = list.clone();
        header_past_list[20..24].copy_from_slice(&20_u32.to_le_bytes());
        let mut small_signature = list.clone();
        small_signature[24..28].copy_from_slice(&8_u32.to_le_bytes());
        let mut ragged = list.clone();
        ragged[24..28].copy_from_slice(&18_u32.to_le_bytes());
        let cases: Vec<(&str, Vec<u8>, &str)> = vec![
            ("Timeout", vec![5, 0, 0], "3 bytes, not the 2 of a UINT16"),
            (
                "BootOrder",
                vec![1, 0, 2],
                "3 bytes, not a whole number of UINT16s of 2 bytes",
            ),
            (
                "DriverOrder",
                vec![1],
                "1 bytes, not a whole number of UINT16s of 2 bytes",
            ),
            ("BootNext", vec![1, 0, 2, 0], "4 bytes, not the 2 of a UINT16"),
            ("BootCurrent", vec![1], "1 bytes, not the 2 of a UINT16"),
            ("PlatformLang", b"en-US".to_vec(), "no NUL at its end"),
            (
                "PlatformLang",
                b"en\0US\0".to_vec(),
                "a NUL at byte 2, before its end",
            ),
            (
                "PlatformLangCodes",
                b"en;fr\xE9\0".to_vec(),
                "byte 5 is 0xE9, which is not ASCII",
            ),
            ("OsIndications", vec![0; 7], "7 bytes, not the 8 of a UINT64"),
            (
                "OsIndicationsSupported",
                vec![0; 9],
                "9 bytes, not the 8 of a UINT64",
            ),
            ("SecureBoot", vec![1, 0], "2 bytes, not the 1 of a UINT8"),
            ("SetupMode", vec![0, 0, 0, 0], "4 bytes, not the 1 of a UINT8"),
            ("HwErrRecSupport", vec![1, 0, 0], "3 bytes, not the 2 of a UINT16"),
            (
                "BootOptionSupport",
                vec![1, 0],
                "2 bytes, not the 4 of a UINT32",
            ),
            (
                "SignatureSupport",
                vec![0; 17],
                "17 bytes, not a whole number of EFI_GUIDs of 16 bytes",
            ),
            (
                "db",
                short_list,
                "the EFI_SIGNATURE_LIST at byte 0 has 10 bytes, fewer than the 28 of its header",
            ),
            (
                "PK",
                [list.clone(), long_list].concat(),
                "the EFI_SIGNATURE_LIST at byte 47 has a SignatureListSize of 100 bytes, but 47 \
                 are left",
            ),
            (
                "KEK",
                header_past_list,
                "the EFI_SIGNATURE_LIST at byte 0 has a SignatureListSize of 47 bytes, fewer than \
                 its header and its SignatureHeaderSize of 20",
            ),
            (
                "dbx",
                small_signature,
                "the EFI_SIGNATURE_LIST at byte 0 has a SignatureSize of 8 bytes, fewer than the 16 \
                 of its SignatureOwner",
            ),
            (
                "dbDefault",
                ragged,
                "the EFI_SIGNATURE_LIST at byte 0 has 19 bytes of signatures, not a whole number \
                 of its SignatureSize of 18",
            ),
        ];
        for (name, data, want) in cases {
            let vendor = vendor_of(name);
            let variables = HeldVariables::default().with(name, vendor, &data);
            let error = read_global(&variables, name, None).expect_err("decode malformed data");

            assert_eq!(
                format!("{error:#}"),
                format!("EFI variable {} is malformed: {want}", key(name, vendor)),
                "{name} {data:02X?}"
            );
        }
    }

    /// A variable serializes as its name and its attributes and value, or that it is absent.
    #[test]
    fn global_variable_serializes_its_contents_or_that_it_is_absent() {
        let present = GlobalVariable {
            variable: "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c".to_string(),
            contents: Some(GlobalContents {
                attributes: 0x06,
                value: GlobalValue::Byte(1),
            }),
        };
        let absent = GlobalVariable {
            variable: "SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c".to_string(),
            contents: None,
        };

        assert_eq!(
            serde_json::to_string(&present).expect("serialize SecureBoot"),
            r#"{"variable":"SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c","attributes":6,"value":1}"#,
            "present"
        );
        assert_eq!(
            serde_json::to_string(&absent).expect("serialize SetupMode"),
            r#"{"variable":"SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c","absent":true}"#,
            "absent"
        );
    }

    /// A variable that the firmware has not created is absent, not an error.
    #[test]
    fn read_global_tells_an_absent_variable() {
        let variables = HeldVariables::default().with("SetupMode", EFI_GLOBAL_VARIABLE, &[1]);

        let global = read_global(&variables, "SecureBoot", None).expect("read SecureBoot");

        assert_eq!(
            global,
            GlobalVariable {
                variable: "SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c".to_string(),
                contents: None,
            },
            "SecureBoot"
        );
    }

    /// db, dbx, dbt and dbr are variables of EFI_IMAGE_SECURITY_DATABASE_GUID, and the others
    /// of EFI_GLOBAL_VARIABLE, unless a vendor GUID names their own.
    #[test]
    fn read_global_reads_each_variable_of_its_own_vendor() {
        let list = signature_list(EFI_CERT_X509, &[], 3, &[b"abc"]);
        let variables = HeldVariables::default()
            .with("db", EFI_IMAGE_SECURITY_DATABASE, &list)
            .with("db", EFI_GLOBAL_VARIABLE, &[0])
            .with("Timeout", EFI_GLOBAL_VARIABLE, &[3, 0]);
        let cases = [
            ("db", None, "db-d719b2cb-3d3a-4596-a3bc-dad00e67656f"),
            (
                "db",
                Some(EFI_IMAGE_SECURITY_DATABASE),
                "db-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
            ),
            (
                "Timeout",
                None,
                "Timeout-8be4df61-93ca-11d2-aa0d-00e098032b8c",
            ),
            (
                "Timeout",
                Some(EFI_GLOBAL_VARIABLE),
                "Timeout-8be4df61-93ca-11d2-aa0d-00e098032b8c",
            ),
        ];
        for (name, vendor, variable) in cases {
            let global = read_global(&variables, name, vendor)
                .unwrap_or_else(|error| panic!("read {name} {vendor:?}: {error:#}"));

            assert_eq!(global.variable, variable, "{name} {vendor:?}");
            assert!(global.contents.is_some(), "{name} {vendor:?} is absent");
        }
        assert_eq!(
            variables.read.into_inner(),
            [
                key("db", EFI_IMAGE_SECURITY_DATABASE),
                key("db", EFI_IMAGE_SECURITY_DATABASE),
                key("Timeout", EFI_GLOBAL_VARIABLE),
                key("Timeout", EFI_GLOBAL_VARIABLE),
            ],
            "keys read"
        );
    }

    /// A name that variable get does not decode, or a vendor GUID other than the variable's
    /// own, is refused before any read, pointing at variable info.
    #[test]
    fn read_global_refuses_other_variables_unread() {
        let variables = HeldVariables::default()
            .with("Boot0001", EFI_GLOBAL_VARIABLE, &[1])
            .with(
                "Timeout",
                vendor("A04A27F4-DF00-4D42-B552-39511302113D"),
                &[1, 0],
            );

        let foreign = read_global(
            &variables,
            "Timeout",
            Some(vendor("a04a27f4-df00-4d42-b552-39511302113d")),
        )
        .expect_err("read the Timeout of another vendor");
        let unknown = read_global(&variables, "Boot0001", None).expect_err("read Boot0001");

        assert_eq!(
            foreign.to_string(),
            "Timeout of vendor A04A27F4-DF00-4D42-B552-39511302113D is not the Timeout that \
             variable get decodes, of vendor 8BE4DF61-93CA-11D2-AA0D-00E098032B8C; `uefisettings \
             variable info Timeout A04A27F4-DF00-4D42-B552-39511302113D` shows its attributes \
             and size",
            "foreign vendor"
        );
        let unknown = unknown.to_string();
        assert!(
            unknown.starts_with("variable get decodes AuditMode, BootCurrent, BootNext, ")
                && unknown.ends_with(
                    ", dbr, not Boot0001; `uefisettings variable info Boot0001 GUID` shows the \
                     attributes and size of any EFI variable"
                ),
            "unknown name: {unknown}"
        );
        assert_eq!(variables.read.into_inner(), [], "keys read");
    }

    /// GLOBALS holds each name once, those of UEFI 2.11 Table 3.1 but its load options, hot keys
    /// and device paths among them.
    #[test]
    fn globals_are_table_3_1_but_load_options_hot_keys_and_device_paths() {
        let table_3_1 = [
            "AuditMode",
            "Boot####",
            "BootCurrent",
            "BootNext",
            "BootOrder",
            "BootOptionSupport",
            "ConIn",
            "ConInDev",
            "ConOut",
            "ConOutDev",
            "dbDefault",
            "dbrDefault",
            "dbtDefault",
            "dbxDefault",
            "DeployedMode",
            "devAuthBoot",
            "devdbDefault",
            "Driver####",
            "DriverOrder",
            "ErrOut",
            "ErrOutDev",
            "HwErrRecSupport",
            "KEK",
            "KEKDefault",
            "Key####",
            "OsIndications",
            "OsIndicationsSupported",
            "OsRecoveryOrder",
            "PK",
            "PKDefault",
            "PlatformLangCodes",
            "PlatformLang",
            "PlatformRecovery####",
            "SignatureSupport",
            "SecureBoot",
            "SetupMode",
            "SysPrep####",
            "SysPrepOrder",
            "Timeout",
            "VendorKeys",
        ];
        let globals: BTreeSet<&str> = GLOBALS
            .iter()
            .filter(|global| global.vendor == EFI_GLOBAL_VARIABLE)
            .map(|global| global.name)
            .collect();
        let databases: Vec<&str> = GLOBALS
            .iter()
            .filter(|global| global.vendor == EFI_IMAGE_SECURITY_DATABASE)
            .map(|global| global.name)
            .collect();

        assert_eq!(
            GLOBALS
                .iter()
                .map(|global| global.name)
                .collect::<BTreeSet<_>>()
                .len(),
            GLOBALS.len(),
            "unique names"
        );
        assert_eq!(
            table_3_1
                .into_iter()
                .filter(|name| !globals.contains(name))
                .collect::<Vec<_>>(),
            [
                "Boot####",
                "ConIn",
                "ConInDev",
                "ConOut",
                "ConOutDev",
                "Driver####",
                "ErrOut",
                "ErrOutDev",
                "Key####",
                "PlatformRecovery####",
                "SysPrep####",
            ],
            "Table 3.1 names that variable get leaves to variable info"
        );
        assert!(
            globals.iter().all(|name| table_3_1.contains(name)),
            "names of EFI_GLOBAL_VARIABLE outside Table 3.1: {globals:?}"
        );
        assert_eq!(
            databases,
            ["db", "dbx", "dbt", "dbr"],
            "signature databases"
        );
    }

    fn vendor(text: &str) -> Guid {
        text.parse()
            .unwrap_or_else(|error| panic!("parse GUID {text}: {error}"))
    }
}
