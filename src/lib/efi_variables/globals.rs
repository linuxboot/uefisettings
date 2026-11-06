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
//! the signature databases of §32.7.1 and §32.7.2, decoded as variable get prints them, and those
//! that the OS may write, as variable set writes them.

use std::fmt;

use anyhow::Context;
use anyhow::Result;
use log::warn;
use serde::ser::SerializeMap;
use serde::ser::SerializeSeq;
use serde::Serialize;
use serde::Serializer;
use sha2::Digest;
use sha2::Sha256;
use thiserror::Error;

use crate::efi_variables::enhanced_authenticated::metadata_end;
use crate::efi_variables::enhanced_authenticated::MetadataRefusal;
use crate::efi_variables::secure_boot_mode::ModeTransition;
use crate::efi_variables::VariableContents;
use crate::efi_variables::VariableData;
use crate::hii::package::Guid;
use crate::hii::VariableAttributes;
use crate::hii::VariableKey;

/// EFI_GLOBAL_VARIABLE, the vendor GUID of the global variables (UEFI 2.11 §3.3).
pub(super) const EFI_GLOBAL_VARIABLE: Guid = Guid {
    data1: 0x8BE4_DF61,
    data2: 0x93CA,
    data3: 0x11D2,
    data4: [0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C],
};
/// EFI_IMAGE_SECURITY_DATABASE_GUID, the vendor GUID of db, dbx, dbt and dbr (UEFI 2.11 §32.7.1).
pub(super) const EFI_IMAGE_SECURITY_DATABASE: Guid = Guid {
    data1: 0xD719_B2CB,
    data2: 0x3D3A,
    data3: 0x4596,
    data4: [0xA3, 0xBC, 0xDA, 0xD0, 0x0E, 0x67, 0x65, 0x6F],
};
/// EFI_DEVICE_SECURITY_DATABASE_GUID, the vendor GUID of devdb (UEFI 2.11 §32.7.2).
pub(super) const EFI_DEVICE_SECURITY_DATABASE: Guid = Guid {
    data1: 0xB9C2_B4F4,
    data2: 0xBF5F,
    data3: 0x462D,
    data4: [0x8A, 0xDF, 0xC5, 0xC7, 0x0A, 0xC3, 0x5D, 0xAD],
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
/// What variable set takes for an OsIndications of none of its defined bits, as an empty
/// argument does not reach uefisettings.efi from the UEFI Shell.
const NO_OS_INDICATIONS: &str = "none";
/// EFI_BOOT_OPTION_SUPPORT_COUNT, the bits of BootOptionSupport that hold a count (UEFI 2.11
/// §3.1.4).
const BOOT_OPTION_SUPPORT_COUNT: u32 = 0x0000_0300;
/// NV, BS, RT: the attributes of each variable of UEFI 2.11 Table 3.1 that the OS may write, which
/// variable set creates a missing one with.
const WRITABLE_ATTRIBUTES: VariableAttributes = VariableAttributes::NON_VOLATILE
    .union(VariableAttributes::BOOTSERVICE_ACCESS)
    .union(VariableAttributes::RUNTIME_ACCESS);
/// Why the OS does not write a variable, in the words of UEFI 2.11 §3.3: those of Table 3.1 for
/// most of them, of the text after it for the others.
const TREATED_AS_READ_ONLY: &str = "Should be treated as read-only.";
const BOOT_CURRENT_READ_ONLY: &str =
    "The platform sets this variable before signaling EFI_EVENT_GROUP_READY_TO_BOOT.";
const HW_ERR_REC_SUPPORT_READ_ONLY: &str =
    "This variable is only modified by firmware and is read-only to the OS.";
const OS_INDICATIONS_SUPPORTED_READ_ONLY: &str =
    "This variable is recreated by firmware every boot, and cannot be modified by the OS";
const PLATFORM_LANG_CODES_READ_ONLY: &str = "This value is considered read-only.";
const SECURE_BOOT_POLICY_VARIABLE: &str = "Secure Boot Policy Variables must be created using the \
                                           EFI_VARIABLE_AUTHENTICATION_2 structure.";
/// The section of UEFI 2.11 that tells which global variables the OS writes.
const GLOBAL_VARIABLES_SECTION: &str = "3.3";
/// Why the OS does not write devdb, which §3.3 does not name, in the words of UEFI 2.11 §32.6.3.
const DEVICE_SIGNATURE_DATABASE: Quote = Quote {
    words: "The Authorized device signature databases are stored as UEFI authenticated variables \
            (see Variable Services) for the GUID EFI_DEVICE_SECURITY_DATABASE_GUID.",
    section: "32.6.3",
};

/// The variables that variable get decodes: those of UEFI 2.11 Table 3.1 but the load options,
/// hot keys and device paths, and the signature databases; and whether variable set writes them.
const GLOBALS: [Global; 34] = [
    Global::mode_transition(ModeTransition::EnterAuditModeClearingPk),
    Global::read_only("BootCurrent", Codec::BootOption, BOOT_CURRENT_READ_ONLY),
    Global::writable("BootNext", Setter::BootNext),
    Global::read_only(
        "BootOptionSupport",
        Codec::BootOptionSupport,
        TREATED_AS_READ_ONLY,
    ),
    Global::writable("BootOrder", Setter::Order(LoadOptionKind::Boot)),
    Global::read_only("dbDefault", Codec::SignatureLists, TREATED_AS_READ_ONLY),
    Global::read_only("dbrDefault", Codec::SignatureLists, TREATED_AS_READ_ONLY),
    Global::read_only("dbtDefault", Codec::SignatureLists, TREATED_AS_READ_ONLY),
    Global::read_only("dbxDefault", Codec::SignatureLists, TREATED_AS_READ_ONLY),
    Global::mode_transition(ModeTransition::EnterDeployedModeIrreversibly),
    Global::read_only("devAuthBoot", Codec::Byte, TREATED_AS_READ_ONLY),
    Global::read_only("devdbDefault", Codec::SignatureLists, TREATED_AS_READ_ONLY),
    Global::writable("DriverOrder", Setter::Order(LoadOptionKind::Driver)),
    Global::read_only("HwErrRecSupport", Codec::Word, HW_ERR_REC_SUPPORT_READ_ONLY),
    Global::read_only("KEK", Codec::SignatureLists, SECURE_BOOT_POLICY_VARIABLE),
    Global::read_only("KEKDefault", Codec::SignatureLists, TREATED_AS_READ_ONLY),
    Global::writable("OsIndications", Setter::OsIndications),
    Global::read_only(
        "OsIndicationsSupported",
        Codec::OsIndications,
        OS_INDICATIONS_SUPPORTED_READ_ONLY,
    ),
    Global::read_only("OsRecoveryOrder", Codec::Guids, SECURE_BOOT_POLICY_VARIABLE),
    Global::read_only("PK", Codec::SignatureLists, SECURE_BOOT_POLICY_VARIABLE),
    Global::read_only("PKDefault", Codec::SignatureLists, TREATED_AS_READ_ONLY),
    Global::read_only(
        "PlatformLangCodes",
        Codec::Ascii,
        PLATFORM_LANG_CODES_READ_ONLY,
    ),
    Global::writable("PlatformLang", Setter::PlatformLang),
    Global::read_only("SignatureSupport", Codec::Guids, TREATED_AS_READ_ONLY),
    Global::read_only("SecureBoot", Codec::Byte, TREATED_AS_READ_ONLY),
    Global::read_only("SetupMode", Codec::Byte, TREATED_AS_READ_ONLY),
    Global::writable("SysPrepOrder", Setter::Order(LoadOptionKind::SysPrep)),
    Global::writable("Timeout", Setter::Timeout),
    Global::read_only("VendorKeys", Codec::Byte, TREATED_AS_READ_ONLY),
    Global::image_security("db"),
    Global::image_security("dbx"),
    Global::image_security("dbt"),
    Global::image_security("dbr"),
    Global::device_security("devdb"),
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

impl From<Timeout> for u16 {
    fn from(timeout: Timeout) -> Self {
        match timeout {
            Timeout::Seconds(seconds) => seconds,
            Timeout::WaitForUserInput => WAIT_FOR_USER_INPUT,
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

impl LoadOptionName {
    /// The load option of `kind` that `text` names as Display writes it, such as Boot0001.
    fn parse(kind: LoadOptionKind, text: &str) -> std::result::Result<Self, SetRefusal> {
        text.strip_prefix(kind.prefix())
            .filter(|digits| {
                digits.len() == 4
                    && digits
                        .bytes()
                        .all(|byte| matches!(byte, b'0'..=b'9' | b'A'..=b'F'))
            })
            .and_then(|digits| u16::from_str_radix(digits, 16).ok())
            .map(|number| Self { kind, number })
            .ok_or_else(|| SetRefusal::OptionName {
                kind,
                text: text.to_owned(),
            })
    }

    /// The variable of this load option.
    fn key(self) -> VariableKey {
        VariableKey {
            name: self.to_string(),
            guid: EFI_GLOBAL_VARIABLE,
        }
    }
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
/// its own, decoded: the bytes after the metadata that metadata_end finds by its attributes (UEFI
/// 2.11 §8.2.1).
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
            let data = contents.data();
            let value = metadata_end(contents.attributes().bits(), data)
                .and_then(|end| data.get(end..).ok_or(MetadataRefusal::truncated(data)))
                .map_err(anyhow::Error::from)
                .and_then(|value| global.codec.decode(value).map_err(anyhow::Error::from))
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

/// Sets the variable `name` that `variables` hold to `text`, which names its value as variable
/// get prints it, unless variable set refuses the variable or the value; a missing variable is
/// created with WRITABLE_ATTRIBUTES, an existing one keeps its attributes.
pub(crate) fn write_global(
    variables: &impl VariableData,
    name: &str,
    text: &str,
) -> Result<GlobalVariable> {
    let (global, setter) = Global::writable_named(name)?;
    let key = global.key();
    let current = variables.variable_data(&key)?;
    let setting = setter.setting(global, variables, text, current.as_ref())?;
    let attributes = current.map_or(WRITABLE_ATTRIBUTES, |current| current.attributes());
    let contents = VariableContents::new(attributes, setting.data)
        .with_context(|| format!("EFI variable {key}"))?;
    variables.set_variable(&key, &contents)?;
    Ok(GlobalVariable {
        variable: key.to_string(),
        contents: Some(GlobalContents {
            attributes: attributes.bits(),
            value: setting.value,
        }),
    })
}

/// A variable that variable get decodes: its name, vendor GUID and codec, and whether variable
/// set writes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Global {
    name: &'static str,
    vendor: Guid,
    codec: Codec,
    access: Access,
}

impl Global {
    /// The global variable `name` (UEFI 2.11 §3.3), which the OS may write as `setter` checks.
    const fn writable(name: &'static str, setter: Setter) -> Self {
        Self {
            name,
            vendor: EFI_GLOBAL_VARIABLE,
            codec: setter.codec(),
            access: Access::Writable(setter),
        }
    }

    /// The global variable `name` (UEFI 2.11 §3.3), which the OS does not write, for `reason`,
    /// words of §3.3.
    const fn read_only(name: &'static str, codec: Codec, reason: &'static str) -> Self {
        Self {
            name,
            vendor: EFI_GLOBAL_VARIABLE,
            codec,
            access: Access::ReadOnly(Quote {
                words: reason,
                section: GLOBAL_VARIABLES_SECTION,
            }),
        }
    }

    /// The global variable that `transition` sets, a byte of UEFI 2.11 §3.3, which set_mode
    /// writes, not set.
    const fn mode_transition(transition: ModeTransition) -> Self {
        Self {
            name: transition.variable(),
            vendor: EFI_GLOBAL_VARIABLE,
            codec: Codec::Byte,
            access: Access::ModeTransition(transition),
        }
    }

    /// The signature database `name` (UEFI 2.11 §32.7.1), a Secure Boot Policy Variable (§3.3).
    const fn image_security(name: &'static str) -> Self {
        Self {
            name,
            vendor: EFI_IMAGE_SECURITY_DATABASE,
            codec: Codec::SignatureLists,
            access: Access::ReadOnly(Quote {
                words: SECURE_BOOT_POLICY_VARIABLE,
                section: GLOBAL_VARIABLES_SECTION,
            }),
        }
    }

    /// The device signature database `name` (UEFI 2.11 §32.7.2), an authenticated variable
    /// (§32.6.3).
    const fn device_security(name: &'static str) -> Self {
        Self {
            name,
            vendor: EFI_DEVICE_SECURITY_DATABASE,
            codec: Codec::SignatureLists,
            access: Access::ReadOnly(DEVICE_SIGNATURE_DATABASE),
        }
    }

    /// The variable `name` of GLOBALS that variable set writes, and how.
    fn writable_named(name: &str) -> std::result::Result<(Self, Setter), SetRefusal> {
        let Some(global) = GLOBALS.iter().find(|global| global.name == name) else {
            return Err(SetRefusal::NotWritable(name.to_owned()));
        };
        match global.access {
            Access::Writable(setter) => Ok((*global, setter)),
            Access::ReadOnly(reason) => Err(SetRefusal::ReadOnly {
                name: global.name,
                reason,
            }),
            Access::ModeTransition(transition) => Err(SetRefusal::ModeTransition(transition)),
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

/// The names of GLOBALS that variable set writes, comma-separated.
fn writable_names() -> String {
    GLOBALS
        .iter()
        .filter(|global| matches!(global.access, Access::Writable(_)))
        .map(|global| global.name)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Whether variable set writes a variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Access {
    /// The OS may write it: "By using the SetVariable() function the data that contain these
    /// environment variables can be modified" (UEFI 2.11 §3.1.1)
    Writable(Setter),
    /// The OS does not write it, for these words of UEFI 2.11
    ReadOnly(Quote),
    /// Setting it makes this Secure Boot mode transition (UEFI 2.11 §32.3), which set_mode
    /// makes, not set
    ModeTransition(ModeTransition),
}

/// Words of UEFI 2.11 and the section that holds them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Quote {
    words: &'static str,
    section: &'static str,
}

impl fmt::Display for Quote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "\"{}\" (UEFI 2.11 section {})", self.words, self.section)
    }
}

/// How variable set takes and checks the value of a variable that the OS may write.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Setter {
    /// Timeout: seconds, or WAIT_FOR_USER_INPUT_TEXT
    Timeout,
    /// BootOrder, DriverOrder and SysPrepOrder: load options of this kind, each of which exists,
    /// none twice
    Order(LoadOptionKind),
    /// BootNext: a Boot#### that exists
    BootNext,
    /// PlatformLang, which "may be changed to any value supported by PlatformLangCodes" (UEFI
    /// 2.11 §3.3)
    PlatformLang,
    /// OsIndications, which "The OS will supply ... with a SetVariable() call" (UEFI 2.11
    /// §8.5.4): bits of OsIndicationsSupported, the reserved bits kept
    OsIndications,
}

/// A value that variable set writes, and the data that holds it.
struct Setting {
    value: GlobalValue,
    data: Vec<u8>,
}

impl Setter {
    const fn codec(self) -> Codec {
        match self {
            Self::Timeout => Codec::Timeout,
            Self::Order(kind) => Codec::Order(kind),
            Self::BootNext => Codec::BootOption,
            Self::PlatformLang => Codec::Ascii,
            Self::OsIndications => Codec::OsIndications,
        }
    }

    /// The value that `text` names of `global`, checked against `variables`, of which `current`
    /// is the contents of `global`, if it exists.
    fn setting(
        self,
        global: Global,
        variables: &impl VariableData,
        text: &str,
        current: Option<&VariableContents>,
    ) -> Result<Setting> {
        let name = global.name;
        Ok(match self {
            Self::Timeout => {
                let timeout = match text {
                    WAIT_FOR_USER_INPUT_TEXT => Timeout::WaitForUserInput,
                    seconds => seconds
                        .parse::<u16>()
                        .map(Timeout::from)
                        .map_err(|_| SetRefusal::Timeout(text.to_owned()))?,
                };
                Setting {
                    value: GlobalValue::Timeout(timeout),
                    data: u16::from(timeout).to_le_bytes().to_vec(),
                }
            }
            Self::Order(kind) => {
                if text.is_empty() {
                    return Err(SetRefusal::EmptyOrder(name).into());
                }
                let mut options = Vec::new();
                for option in text.split(',') {
                    let option = LoadOptionName::parse(kind, option)?;
                    if options.contains(&option) {
                        return Err(SetRefusal::Twice { name, option }.into());
                    }
                    options.push(option);
                }
                for &option in &options {
                    check_present(variables, name, option)?;
                }
                Setting {
                    data: options
                        .iter()
                        .flat_map(|option| option.number.to_le_bytes())
                        .collect(),
                    value: GlobalValue::LoadOptions(options),
                }
            }
            Self::BootNext => {
                let option = LoadOptionName::parse(LoadOptionKind::Boot, text)?;
                check_present(variables, name, option)?;
                Setting {
                    value: GlobalValue::LoadOption(option),
                    data: option.number.to_le_bytes().to_vec(),
                }
            }
            Self::PlatformLang => {
                if text.is_empty()
                    || !text
                        .bytes()
                        .all(|byte| byte.is_ascii() && byte != 0 && byte != b';')
                {
                    return Err(SetRefusal::LanguageCode(text.to_owned()).into());
                }
                let codes = read_decoded(variables, "PlatformLangCodes", ascii)?
                    .ok_or(SetRefusal::NoLanguageCodes)?;
                if !codes.split(';').any(|code| code == text) {
                    return Err(SetRefusal::UnsupportedLanguage {
                        code: text.to_owned(),
                        codes,
                    }
                    .into());
                }
                Setting {
                    value: GlobalValue::Ascii(text.to_owned()),
                    data: [text.as_bytes(), &[0]].concat(),
                }
            }
            Self::OsIndications => {
                let named = match text {
                    NO_OS_INDICATIONS => OsIndications::empty(),
                    bits => bits
                        .split(',')
                        .map(|bit| {
                            OsIndications::from_name(bit)
                                .ok_or_else(|| SetRefusal::OsIndication(bit.to_owned()))
                        })
                        .collect::<std::result::Result<_, _>>()?,
                };
                let supported = read_decoded(variables, "OsIndicationsSupported", os_indications)?
                    .unwrap_or_else(OsIndications::empty);
                let unsupported = named.difference(supported);
                if !unsupported.is_empty() {
                    return Err(SetRefusal::UnsupportedOsIndications(unsupported).into());
                }
                let current = current
                    .map(|current| os_indications(current.data()))
                    .transpose()
                    .with_context(|| format!("EFI variable {} is malformed", global.key()))?
                    .unwrap_or_else(OsIndications::empty);
                let bits = named | current.difference(OsIndications::all());
                Setting {
                    value: GlobalValue::OsIndications(bits),
                    data: bits.bits().to_le_bytes().to_vec(),
                }
            }
        })
    }
}

/// The global variable `name` that `variables` hold, decoded with `decode`, if present.
fn read_decoded<T>(
    variables: &impl VariableData,
    name: &str,
    decode: impl Fn(&[u8]) -> std::result::Result<T, MalformedData>,
) -> Result<Option<T>> {
    let key = VariableKey {
        name: name.to_owned(),
        guid: EFI_GLOBAL_VARIABLE,
    };
    variables
        .variable_data(&key)?
        .map(|contents| decode(contents.data()))
        .transpose()
        .with_context(|| format!("EFI variable {key} is malformed"))
}

/// The platform language, PlatformLang, that `variables` hold, unless it is absent or malformed.
pub(crate) fn platform_lang(variables: &impl VariableData) -> Result<Option<String>> {
    Ok(
        match read_decoded(variables, "PlatformLang", |data| Ok(ascii(data)))? {
            Some(Ok(code)) => Some(code),
            Some(Err(error)) => {
                warn!("EFI variable PlatformLang is malformed, so it picks no texts: {error}");
                None
            }
            None => {
                warn!("EFI variable PlatformLang is absent, so it picks no texts");
                None
            }
        },
    )
}

/// Fails unless `variables` hold the load option `option` that the variable `name` names.
fn check_present(
    variables: &impl VariableData,
    name: &'static str,
    option: LoadOptionName,
) -> Result<()> {
    match variables.variable_data(&option.key())? {
        Some(_) => Ok(()),
        None => Err(SetRefusal::Absent { name, option }.into()),
    }
}

/// A variable or value that variable set refuses, before it writes anything.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
enum SetRefusal {
    #[error("variable set writes {}, not {0}", writable_names())]
    NotWritable(String),
    #[error("variable set does not write {name}: {reason}")]
    ReadOnly { name: &'static str, reason: Quote },
    #[error(
        "set writes no {}, whose write makes a Secure Boot mode transition, which set_mode makes",
        .0.variable()
    )]
    ModeTransition(ModeTransition),
    #[error(
        "Timeout takes seconds from 0 to 65535, or \"{}\", not \"{0}\"",
        WAIT_FOR_USER_INPUT_TEXT
    )]
    Timeout(String),
    #[error(
        "\"{text}\" is no {}####: \"#### is replaced by a unique option number in printable \
         hexadecimal representation using the digits 0-9, and the upper case versions of the \
         characters A-F\" (UEFI 2.11 section 3.1.1)",
        kind.prefix()
    )]
    OptionName { kind: LoadOptionKind, text: String },
    #[error(
        "an empty {0} would delete it: \"using SetVariable() with a DataSize of zero will cause \
         the entire variable to be deleted\" (UEFI 2.11 section 8.2.3)"
    )]
    EmptyOrder(&'static str),
    #[error("{name} names {option} twice")]
    Twice {
        name: &'static str,
        option: LoadOptionName,
    },
    #[error("{name} names {option}, which is absent")]
    Absent {
        name: &'static str,
        option: LoadOptionName,
    },
    #[error("PlatformLang takes one language code of ASCII, such as en-US, not \"{0}\"")]
    LanguageCode(String),
    #[error("PlatformLangCodes is absent, so PlatformLang has no value that it supports")]
    NoLanguageCodes,
    #[error(
        "PlatformLang \"may be changed to any value supported by PlatformLangCodes\" (UEFI 2.11 \
         section 3.3), {codes}, not {code}"
    )]
    UnsupportedLanguage { code: String, codes: String },
    #[error(
        "OsIndications takes the bits {}, comma-separated, or {}, not \"{0}\"",
        os_indication_names(),
        NO_OS_INDICATIONS
    )]
    OsIndication(String),
    #[error("OsIndicationsSupported lacks {}", bit_names(*.0))]
    UnsupportedOsIndications(OsIndications),
}

/// The names of the bits of OsIndications, comma-separated.
fn os_indication_names() -> String {
    bit_names(OsIndications::all())
}

/// The names of `bits`, comma-separated.
fn bit_names(bits: OsIndications) -> String {
    bits.iter_names()
        .map(|(name, _)| name)
        .collect::<Vec<_>>()
        .join(", ")
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
            Self::OsIndications => GlobalValue::OsIndications(os_indications(data)?),
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

/// The bits of OsIndications or OsIndicationsSupported in `data`, "a UINT64 bitmask" (UEFI 2.11
/// §8.5.4).
fn os_indications(data: &[u8]) -> std::result::Result<OsIndications, MalformedData> {
    Ok(OsIndications::from_bits_retain(u64::from_le_bytes(exact(
        data, "a UINT64",
    )?)))
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
pub(crate) mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    use std::collections::BTreeSet;

    use serde_json::json;

    use super::*;
    use crate::efi_variables::enhanced_authenticated::fixture::timestamp_metadata;
    use crate::efi_variables::VariableContents;
    use crate::hii::VariableAttributes;
    use crate::hii::VariableInterface;
    use crate::hii::VariableNotFound;

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
    pub(crate) const NV_BS_RT: VariableAttributes = VariableAttributes::NON_VOLATILE
        .union(VariableAttributes::BOOTSERVICE_ACCESS)
        .union(VariableAttributes::RUNTIME_ACCESS);
    /// EFI_DEVICE_SECURITY_DATABASE_GUID as UEFI 2.11 §32.7.2 spells it, the vendor of devdb.
    pub(crate) const DEVDB_VENDOR: Guid = Guid {
        data1: 0xB9C2_B4F4,
        data2: 0xBF5F,
        data3: 0x462D,
        data4: [0x8A, 0xDF, 0xC5, 0xC7, 0x0A, 0xC3, 0x5D, 0xAD],
    };

    /// VariableData that hold `variables` and record each key read and set, as `interface`
    /// reaches them: through GetVariable() and SetVariable() unless `through` says otherwise.
    pub(crate) struct HeldVariables {
        pub(crate) variables: RefCell<BTreeMap<VariableKey, VariableContents>>,
        pub(crate) read: RefCell<Vec<VariableKey>>,
        pub(crate) set: RefCell<Vec<VariableKey>>,
        pub(crate) deleted: RefCell<Vec<VariableKey>>,
        interface: VariableInterface,
    }

    impl Default for HeldVariables {
        fn default() -> Self {
            Self {
                variables: RefCell::default(),
                read: RefCell::default(),
                set: RefCell::default(),
                deleted: RefCell::default(),
                interface: VariableInterface::VariableServices,
            }
        }
    }

    impl HeldVariables {
        /// These variables, as `interface` reaches them.
        pub(crate) fn through(self, interface: VariableInterface) -> Self {
            Self { interface, ..self }
        }

        /// Holds `data` with NV+BS+RT as the variable `name` of `vendor`.
        pub(crate) fn with(self, name: &str, vendor: Guid, data: &[u8]) -> Self {
            self.with_attributes(name, vendor, NV_BS_RT, data)
        }

        /// Holds `data` with `attributes` as the variable `name` of `vendor`.
        fn with_attributes(
            self,
            name: &str,
            vendor: Guid,
            attributes: VariableAttributes,
            data: &[u8],
        ) -> Self {
            let contents = VariableContents::new(attributes, data.to_vec()).expect("hold data");
            self.variables
                .borrow_mut()
                .insert(key(name, vendor), contents);
            self
        }

        /// The attributes and data of the global variable `name`, if held.
        fn global(&self, name: &str) -> Option<(VariableAttributes, Vec<u8>)> {
            self.variables
                .borrow()
                .get(&key(name, EFI_GLOBAL_VARIABLE))
                .map(|contents| (contents.attributes(), contents.data().to_vec()))
        }
    }

    impl VariableData for HeldVariables {
        fn interface(&self) -> VariableInterface {
            self.interface
        }

        fn variable_data(&self, key: &VariableKey) -> Result<Option<VariableContents>> {
            self.read.borrow_mut().push(key.clone());
            Ok(self.variables.borrow().get(key).cloned())
        }

        fn set_variable(&self, key: &VariableKey, contents: &VariableContents) -> Result<()> {
            self.set.borrow_mut().push(key.clone());
            self.variables
                .borrow_mut()
                .insert(key.clone(), contents.clone());
            Ok(())
        }

        fn delete_variable(&self, key: &VariableKey) -> Result<()> {
            self.deleted.borrow_mut().push(key.clone());
            match self.variables.borrow_mut().remove(key) {
                Some(_) => Ok(()),
                None => Err(VariableNotFound(key.clone()).into()),
            }
        }
    }

    pub(crate) fn key(name: &str, vendor: Guid) -> VariableKey {
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
            ("devdb", databases.clone(), databases_json.clone()),
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

    /// db, dbx, dbt and dbr are variables of EFI_IMAGE_SECURITY_DATABASE_GUID, devdb of
    /// EFI_DEVICE_SECURITY_DATABASE_GUID, and the others of EFI_GLOBAL_VARIABLE, unless a vendor
    /// GUID names their own.
    #[test]
    fn read_global_reads_each_variable_of_its_own_vendor() {
        let list = signature_list(EFI_CERT_X509, &[], 3, &[b"abc"]);
        let variables = HeldVariables::default()
            .with("db", EFI_IMAGE_SECURITY_DATABASE, &list)
            .with("db", EFI_GLOBAL_VARIABLE, &[0])
            .with("devdb", DEVDB_VENDOR, &list)
            .with("devdb", EFI_IMAGE_SECURITY_DATABASE, &[0])
            .with("Timeout", EFI_GLOBAL_VARIABLE, &[3, 0]);
        let cases = [
            ("db", None, "db-d719b2cb-3d3a-4596-a3bc-dad00e67656f"),
            (
                "db",
                Some(EFI_IMAGE_SECURITY_DATABASE),
                "db-d719b2cb-3d3a-4596-a3bc-dad00e67656f",
            ),
            ("devdb", None, "devdb-b9c2b4f4-bf5f-462d-8adf-c5c70ac35dad"),
            (
                "devdb",
                Some(DEVDB_VENDOR),
                "devdb-b9c2b4f4-bf5f-462d-8adf-c5c70ac35dad",
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
                key("devdb", DEVDB_VENDOR),
                key("devdb", DEVDB_VENDOR),
                key("Timeout", EFI_GLOBAL_VARIABLE),
                key("Timeout", EFI_GLOBAL_VARIABLE),
            ],
            "keys read"
        );
    }

    /// read_global decodes the value after the EFI_VARIABLE_AUTHENTICATION_3 metadata that
    /// GetVariable() returns first for a variable with EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS
    /// (UEFI 2.11 §8.2.1), as it decodes that value alone, and refuses data that ends inside the
    /// metadata.
    #[test]
    fn read_global_decodes_the_value_after_enhanced_authenticated_metadata() {
        let list = signature_list(EFI_CERT_X509, &[], 3, &[b"abc"]);
        let enhanced = NV_BS_RT | VariableAttributes::ENHANCED_AUTHENTICATED_ACCESS;
        let read = |attributes, data: &[u8]| {
            let variables =
                HeldVariables::default().with_attributes("devdb", DEVDB_VENDOR, attributes, data);
            read_global(&variables, "devdb", None).map_err(|error| format!("{error:#}"))
        };
        let alone = read(NV_BS_RT, &list)
            .expect("read devdb")
            .contents
            .expect("devdb held");

        let after_metadata = read(enhanced, &[timestamp_metadata(), list.clone()].concat())
            .expect("read devdb after its metadata")
            .contents
            .expect("devdb held");

        assert_eq!(after_metadata.value, alone.value, "value");
        assert_eq!(after_metadata.attributes, enhanced.bits(), "attributes");
        assert_eq!(
            read(enhanced, &timestamp_metadata()[..10]),
            Err(
                "EFI variable devdb-b9c2b4f4-bf5f-462d-8adf-c5c70ac35dad is malformed: its 10 \
                 bytes of data end inside its metadata"
                    .to_string()
            ),
            "data ending inside the metadata"
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
        let foreign_devdb = read_global(&variables, "devdb", Some(EFI_IMAGE_SECURITY_DATABASE))
            .expect_err("read the devdb of EFI_IMAGE_SECURITY_DATABASE_GUID");
        let unknown = read_global(&variables, "Boot0001", None).expect_err("read Boot0001");

        assert_eq!(
            foreign.to_string(),
            "Timeout of vendor A04A27F4-DF00-4D42-B552-39511302113D is not the Timeout that \
             variable get decodes, of vendor 8BE4DF61-93CA-11D2-AA0D-00E098032B8C; `uefisettings \
             variable info Timeout A04A27F4-DF00-4D42-B552-39511302113D` shows its attributes \
             and size",
            "foreign vendor"
        );
        assert_eq!(
            foreign_devdb.to_string(),
            "devdb of vendor D719B2CB-3D3A-4596-A3BC-DAD00E67656F is not the devdb that variable \
             get decodes, of vendor B9C2B4F4-BF5F-462D-8ADF-C5C70AC35DAD; `uefisettings variable \
             info devdb D719B2CB-3D3A-4596-A3BC-DAD00E67656F` shows its attributes and size",
            "devdb of a foreign vendor"
        );
        let unknown = unknown.to_string();
        assert!(
            unknown.starts_with("variable get decodes AuditMode, BootCurrent, BootNext, ")
                && unknown.ends_with(
                    ", dbr, devdb, not Boot0001; `uefisettings variable info Boot0001 GUID` shows \
                     the attributes and size of any EFI variable"
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
        let databases: Vec<(&str, Guid)> = GLOBALS
            .iter()
            .filter(|global| global.vendor != EFI_GLOBAL_VARIABLE)
            .map(|global| (global.name, global.vendor))
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
            [
                ("db", EFI_IMAGE_SECURITY_DATABASE),
                ("dbx", EFI_IMAGE_SECURITY_DATABASE),
                ("dbt", EFI_IMAGE_SECURITY_DATABASE),
                ("dbr", EFI_IMAGE_SECURITY_DATABASE),
                ("devdb", DEVDB_VENDOR),
            ],
            "signature databases"
        );
    }

    /// Variables that the checks of variable set read: Boot0001, Boot0002, Driver0001,
    /// SysPrep000A, PlatformLangCodes as EDK2 defaults it, OsIndicationsSupported of
    /// BOOT_TO_FW_UI and START_PLATFORM_RECOVERY, and an OsIndications of BOOT_TO_FW_UI and a
    /// reserved bit.
    fn settable_variables() -> HeldVariables {
        HeldVariables::default()
            .with("Boot0001", EFI_GLOBAL_VARIABLE, &[1])
            .with("Boot0002", EFI_GLOBAL_VARIABLE, &[1])
            .with("Driver0001", EFI_GLOBAL_VARIABLE, &[1])
            .with("SysPrep000A", EFI_GLOBAL_VARIABLE, &[1])
            .with(
                "PlatformLangCodes",
                EFI_GLOBAL_VARIABLE,
                b"en;fr;en-US;fr-FR\0",
            )
            .with(
                "OsIndicationsSupported",
                EFI_GLOBAL_VARIABLE,
                &0x41_u64.to_le_bytes(),
            )
            .with(
                "OsIndications",
                EFI_GLOBAL_VARIABLE,
                &0x101_u64.to_le_bytes(),
            )
    }

    /// Each setter writes the data of the value that its text names, which get reads back as
    /// that value, and an OsIndications keeps its reserved bits but not its defined ones; both
    /// ways of each codec of the variables that the OS may write.
    #[test]
    fn set_writes_what_get_reads_back() {
        let cases: Vec<(&str, &str, Vec<u8>, serde_json::Value)> = vec![
            ("Timeout", "5", vec![5, 0], json!(5)),
            ("Timeout", "0", vec![0, 0], json!(0)),
            ("Timeout", "65534", vec![0xFE, 0xFF], json!(65534)),
            (
                "Timeout",
                "65535",
                vec![0xFF, 0xFF],
                json!("wait for user input"),
            ),
            (
                "Timeout",
                "wait for user input",
                vec![0xFF, 0xFF],
                json!("wait for user input"),
            ),
            (
                "BootOrder",
                "Boot0002,Boot0001",
                vec![2, 0, 1, 0],
                json!(["Boot0002", "Boot0001"]),
            ),
            ("BootOrder", "Boot0001", vec![1, 0], json!(["Boot0001"])),
            (
                "DriverOrder",
                "Driver0001",
                vec![1, 0],
                json!(["Driver0001"]),
            ),
            (
                "SysPrepOrder",
                "SysPrep000A",
                vec![0x0A, 0],
                json!(["SysPrep000A"]),
            ),
            ("BootNext", "Boot0002", vec![2, 0], json!("Boot0002")),
            ("PlatformLang", "fr-FR", b"fr-FR\0".to_vec(), json!("fr-FR")),
            ("PlatformLang", "en", b"en\0".to_vec(), json!("en")),
            (
                "OsIndications",
                "START_PLATFORM_RECOVERY,BOOT_TO_FW_UI",
                0x141_u64.to_le_bytes().to_vec(),
                json!(["BOOT_TO_FW_UI", "START_PLATFORM_RECOVERY", "0x100"]),
            ),
            (
                "OsIndications",
                "START_PLATFORM_RECOVERY",
                0x140_u64.to_le_bytes().to_vec(),
                json!(["START_PLATFORM_RECOVERY", "0x100"]),
            ),
            (
                "OsIndications",
                "none",
                0x100_u64.to_le_bytes().to_vec(),
                json!(["0x100"]),
            ),
        ];
        for (name, text, data, want) in cases {
            let variables = settable_variables();

            let written = write_global(&variables, name, text)
                .unwrap_or_else(|error| panic!("set {name} {text:?}: {error:#}"));

            let read = read_global(&variables, name, None).expect("read back");
            assert_eq!(
                variables.global(name).map(|(_, data)| data),
                Some(data),
                "{name} {text:?}: data"
            );
            assert_eq!(written, read, "{name} {text:?}: written and read back");
            let value = read.contents.map(|contents| contents.value);
            assert_eq!(
                value.map(|value| serde_json::to_value(value).expect("serialize the value")),
                Some(want),
                "{name} {text:?}: value"
            );
            assert_eq!(
                variables.set.into_inner(),
                [key(name, EFI_GLOBAL_VARIABLE)],
                "{name} {text:?}: sets"
            );
        }
    }

    /// set creates a missing variable with NV+BS+RT, as UEFI 2.11 Table 3.1 gives each that the
    /// OS may write, and keeps the attributes of an existing one.
    #[test]
    fn set_creates_a_missing_variable_with_its_table_3_1_attributes() {
        let nv_bs = VariableAttributes::NON_VOLATILE | VariableAttributes::BOOTSERVICE_ACCESS;
        let variables =
            settable_variables().with_attributes("BootNext", EFI_GLOBAL_VARIABLE, nv_bs, &[1, 0]);

        for (name, text) in [("Timeout", "3"), ("BootNext", "Boot0002")] {
            write_global(&variables, name, text)
                .unwrap_or_else(|error| panic!("set {name}: {error:#}"));
        }

        assert_eq!(
            variables.global("Timeout"),
            Some((NV_BS_RT, vec![3, 0])),
            "a missing Timeout"
        );
        assert_eq!(
            variables.global("BootNext"),
            Some((nv_bs, vec![2, 0])),
            "an existing BootNext"
        );
        assert!(
            WRITABLE_ATTRIBUTES.contains(VariableAttributes::BOOTSERVICE_ACCESS),
            "\"Runtime access to a data variable implies boot service access\" (UEFI 2.11 \
             section 8.2.3)"
        );
    }

    /// set refuses, before it writes anything: a value that its variable does not take, a load
    /// option twice or one that is absent, a PlatformLang outside PlatformLangCodes, a bit of
    /// OsIndications outside OsIndicationsSupported, and a variable that the OS does not write.
    #[test]
    fn set_refusals_leave_the_variables_unchanged() {
        let read_only = |name: &str, reason: &str| {
            format!("variable set does not write {name}: \"{reason}\" (UEFI 2.11 section 3.3)")
        };
        let option_name = |text: &str, kind: &str| {
            format!(
                "\"{text}\" is no {kind}####: \"#### is replaced by a unique option number in \
                 printable hexadecimal representation using the digits 0-9, and the upper case \
                 versions of the characters A-F\" (UEFI 2.11 section 3.1.1)"
            )
        };
        let os_indication = |text: &str| {
            format!(
                "OsIndications takes the bits BOOT_TO_FW_UI, TIMESTAMP_REVOCATION, \
                 FILE_CAPSULE_DELIVERY_SUPPORTED, FMP_CAPSULE_SUPPORTED, \
                 CAPSULE_RESULT_VAR_SUPPORTED, START_OS_RECOVERY, START_PLATFORM_RECOVERY, \
                 JSON_CONFIG_DATA_REFRESH, comma-separated, or none, not \"{text}\""
            )
        };
        let cases: Vec<(&str, &str, String)> =
            vec![
            (
                "BootOrder",
                "Boot0001,Boot0002,Boot0001",
                "BootOrder names Boot0001 twice".to_string(),
            ),
            (
                "BootOrder",
                "Boot0001,Boot0003",
                "BootOrder names Boot0003, which is absent".to_string(),
            ),
            (
                "DriverOrder",
                "Driver0002",
                "DriverOrder names Driver0002, which is absent".to_string(),
            ),
            (
                "BootOrder",
                "",
                "an empty BootOrder would delete it: \"using SetVariable() with a DataSize of \
                 zero will cause the entire variable to be deleted\" (UEFI 2.11 section 8.2.3)"
                    .to_string(),
            ),
            ("BootOrder", "Boot1", option_name("Boot1", "Boot")),
            ("BootOrder", "boot0001", option_name("boot0001", "Boot")),
            ("BootOrder", "Boot000a", option_name("Boot000a", "Boot")),
            ("BootOrder", "Driver0001", option_name("Driver0001", "Boot")),
            ("SysPrepOrder", "Boot0001", option_name("Boot0001", "SysPrep")),
            (
                "BootNext",
                "Boot1234",
                "BootNext names Boot1234, which is absent".to_string(),
            ),
            ("BootNext", "Boot0001,Boot0002", option_name("Boot0001,Boot0002", "Boot")),
            (
                "PlatformLang",
                "xx-XX",
                "PlatformLang \"may be changed to any value supported by PlatformLangCodes\" \
                 (UEFI 2.11 section 3.3), en;fr;en-US;fr-FR, not xx-XX"
                    .to_string(),
            ),
            (
                "PlatformLang",
                "fr-",
                "PlatformLang \"may be changed to any value supported by PlatformLangCodes\" \
                 (UEFI 2.11 section 3.3), en;fr;en-US;fr-FR, not fr-"
                    .to_string(),
            ),
            (
                "PlatformLang",
                "en;fr",
                "PlatformLang takes one language code of ASCII, such as en-US, not \"en;fr\""
                    .to_string(),
            ),
            (
                "PlatformLang",
                "",
                "PlatformLang takes one language code of ASCII, such as en-US, not \"\""
                    .to_string(),
            ),
            (
                "OsIndications",
                "BOOT_TO_FW_UI,TIMESTAMP_REVOCATION",
                "OsIndicationsSupported lacks TIMESTAMP_REVOCATION".to_string(),
            ),
            ("OsIndications", "BOOT_TO_FW_UI,0x100", os_indication("0x100")),
            ("OsIndications", "", os_indication("")),
            ("OsIndications", "BOOT_TO_FW_UI,", os_indication("")),
            ("OsIndications", "none,BOOT_TO_FW_UI", os_indication("none")),
            (
                "Timeout",
                "-1",
                "Timeout takes seconds from 0 to 65535, or \"wait for user input\", not \"-1\""
                    .to_string(),
            ),
            (
                "Timeout",
                "65536",
                "Timeout takes seconds from 0 to 65535, or \"wait for user input\", not \
                 \"65536\""
                    .to_string(),
            ),
            (
                "SecureBoot",
                "1",
                read_only("SecureBoot", "Should be treated as read-only."),
            ),
            (
                "SetupMode",
                "0",
                read_only("SetupMode", "Should be treated as read-only."),
            ),
            (
                "PlatformLangCodes",
                "en",
                read_only("PlatformLangCodes", "This value is considered read-only."),
            ),
            (
                "OsIndicationsSupported",
                "BOOT_TO_FW_UI",
                read_only(
                    "OsIndicationsSupported",
                    "This variable is recreated by firmware every boot, and cannot be modified \
                     by the OS",
                ),
            ),
            (
                "PK",
                "",
                read_only(
                    "PK",
                    "Secure Boot Policy Variables must be created using the \
                     EFI_VARIABLE_AUTHENTICATION_2 structure.",
                ),
            ),
            (
                "db",
                "",
                read_only(
                    "db",
                    "Secure Boot Policy Variables must be created using the \
                     EFI_VARIABLE_AUTHENTICATION_2 structure.",
                ),
            ),
            (
                "devdb",
                "",
                "variable set does not write devdb: \"The Authorized device signature databases \
                 are stored as UEFI authenticated variables (see Variable Services) for the GUID \
                 EFI_DEVICE_SECURITY_DATABASE_GUID.\" (UEFI 2.11 section 32.6.3)"
                    .to_string(),
            ),
            (
                "KEK",
                "",
                read_only(
                    "KEK",
                    "Secure Boot Policy Variables must be created using the \
                     EFI_VARIABLE_AUTHENTICATION_2 structure.",
                ),
            ),
            (
                "OsRecoveryOrder",
                "",
                read_only(
                    "OsRecoveryOrder",
                    "Secure Boot Policy Variables must be created using the \
                     EFI_VARIABLE_AUTHENTICATION_2 structure.",
                ),
            ),
            (
                "AuditMode",
                "1",
                "set writes no AuditMode, whose write makes a Secure Boot mode transition, which \
                 set_mode makes"
                    .to_string(),
            ),
            (
                "DeployedMode",
                "1",
                "set writes no DeployedMode, whose write makes a Secure Boot mode transition, \
                 which set_mode makes"
                    .to_string(),
            ),
            (
                "BootCurrent",
                "Boot0001",
                read_only(
                    "BootCurrent",
                    "The platform sets this variable before signaling \
                     EFI_EVENT_GROUP_READY_TO_BOOT.",
                ),
            ),
            (
                "HwErrRecSupport",
                "1",
                read_only(
                    "HwErrRecSupport",
                    "This variable is only modified by firmware and is read-only to the OS.",
                ),
            ),
            (
                "Boot0001",
                "",
                "variable set writes BootNext, BootOrder, DriverOrder, OsIndications, \
                 PlatformLang, SysPrepOrder, Timeout, not Boot0001"
                    .to_string(),
            ),
        ];
        for (name, text, refusal) in cases {
            let variables = settable_variables();
            let before = variables.variables.borrow().clone();

            let error = write_global(&variables, name, text).expect_err("a refused set");

            assert_eq!(format!("{error:#}"), refusal, "{name} {text:?}");
            assert_eq!(variables.set.into_inner(), [], "{name} {text:?}: sets");
            assert_eq!(
                variables.variables.into_inner(),
                before,
                "{name} {text:?}: variables"
            );
        }
    }

    /// A PlatformLang needs PlatformLangCodes, and an OsIndications bit needs
    /// OsIndicationsSupported, which the firmware may not have created.
    #[test]
    fn set_refuses_what_the_firmware_does_not_tell_it_supports() {
        let variables = HeldVariables::default();

        let language =
            write_global(&variables, "PlatformLang", "en").expect_err("set PlatformLang");
        let bits = write_global(&variables, "OsIndications", "BOOT_TO_FW_UI")
            .expect_err("set OsIndications");
        let none = write_global(&variables, "OsIndications", "none").expect("set no OsIndications");

        assert_eq!(
            language.to_string(),
            "PlatformLangCodes is absent, so PlatformLang has no value that it supports",
            "PlatformLang"
        );
        assert_eq!(
            bits.to_string(),
            "OsIndicationsSupported lacks BOOT_TO_FW_UI",
            "OsIndications"
        );
        assert_eq!(
            none.contents.map(|contents| contents.value),
            Some(GlobalValue::OsIndications(OsIndications::empty())),
            "no OsIndications"
        );
        assert_eq!(
            variables.global("OsIndications"),
            Some((NV_BS_RT, vec![0; 8])),
            "OsIndications created"
        );
    }

    /// set refuses, before it writes anything, when a variable that it reads to check or keep
    /// bits of is malformed: OsIndications itself, PlatformLangCodes and OsIndicationsSupported.
    #[test]
    fn set_refuses_over_malformed_variables_that_it_reads() {
        let cases: [(&str, &[u8], &str, &str, &str); 3] = [
            (
                "OsIndications",
                &[0; 4],
                "OsIndications",
                "BOOT_TO_FW_UI",
                "4 bytes, not the 8 of a UINT64",
            ),
            (
                "PlatformLangCodes",
                b"en;fr",
                "PlatformLang",
                "en",
                "no NUL at its end",
            ),
            (
                "OsIndicationsSupported",
                &[0; 9],
                "OsIndications",
                "none",
                "9 bytes, not the 8 of a UINT64",
            ),
        ];
        for (malformed, data, name, text, want) in cases {
            let variables = settable_variables().with(malformed, EFI_GLOBAL_VARIABLE, data);
            let before = variables.variables.borrow().clone();

            let error = write_global(&variables, name, text).expect_err("set over malformed data");

            assert_eq!(
                format!("{error:#}"),
                format!(
                    "EFI variable {} is malformed: {want}",
                    key(malformed, EFI_GLOBAL_VARIABLE)
                ),
                "{malformed}"
            );
            assert_eq!(variables.set.into_inner(), [], "{malformed}: sets");
            assert_eq!(
                variables.variables.into_inner(),
                before,
                "{malformed}: variables"
            );
        }
    }

    fn vendor(text: &str) -> Guid {
        text.parse()
            .unwrap_or_else(|error| panic!("parse GUID {text}: {error}"))
    }

    /// platform_lang decodes PlatformLang, a "null-terminated ASCII string language code"
    /// (UEFI 2.11 §3.3), and gives None for one that is absent or that is no such string.
    #[test]
    fn platform_lang_decodes_or_skips_a_malformed_one() {
        let cases: [(Option<&[u8]>, Option<&str>); 5] = [
            (Some(b"fr-FR\0"), Some("fr-FR")),
            (None, None),
            (Some(b"fr-FR"), None),
            (Some(b"fr\0FR\0"), None),
            (Some(b"fr-\xc9\0"), None),
        ];
        for (data, want) in cases {
            let variables = match data {
                Some(data) => {
                    HeldVariables::default().with("PlatformLang", EFI_GLOBAL_VARIABLE, data)
                }
                None => HeldVariables::default(),
            };

            let got = platform_lang(&variables).expect("read PlatformLang");

            assert_eq!(got.as_deref(), want, "PlatformLang {data:?}");
        }
    }

    /// VariableData whose every read fails.
    struct FailingReads;

    impl VariableData for FailingReads {
        fn interface(&self) -> VariableInterface {
            panic!("ask for the variable interface")
        }

        fn variable_data(&self, key: &VariableKey) -> Result<Option<VariableContents>> {
            Err(anyhow::anyhow!("cannot read EFI variable {key}"))
        }

        fn set_variable(&self, key: &VariableKey, _contents: &VariableContents) -> Result<()> {
            panic!("set EFI variable {key}")
        }

        fn delete_variable(&self, key: &VariableKey) -> Result<()> {
            panic!("delete EFI variable {key}")
        }
    }

    /// platform_lang fails with a read's error, which is no malformed PlatformLang.
    #[test]
    fn platform_lang_fails_on_a_read_error() {
        let error = platform_lang(&FailingReads).expect_err("read PlatformLang");

        assert_eq!(
            error.to_string(),
            "cannot read EFI variable PlatformLang-8be4df61-93ca-11d2-aa0d-00e098032b8c",
            "error"
        );
    }
}
