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

//! The variables of the boot manager (UEFI 2.11 §3.1) that globals.rs leaves out, decoded as
//! variable get prints them: the load options Boot####, Driver####, SysPrep####,
//! PlatformRecovery#### and OsRecovery#### (§3.1.3, §3.4.1), the hot keys Key#### (§3.1.6) and
//! the console device paths ConIn, ConOut, ErrOut, ConInDev, ConOutDev and ErrOutDev (§3.3).

use std::fmt;

use anyhow::Context;
use anyhow::Result;
use serde::ser::SerializeMap;
use serde::Serialize;
use serde::Serializer;
use thiserror::Error;

use super::device_path;
use super::enhanced_authenticated::metadata_end;
use super::enhanced_authenticated::MetadataRefusal;
use super::globals::lower_hex;
use super::globals::serialize_bits;
use super::globals::GlobalContents;
use super::globals::GlobalValue;
use super::globals::GlobalVariable;
use super::globals::LoadOptionKind;
use super::globals::LoadOptionName;
use super::globals::EFI_GLOBAL_VARIABLE;
use super::key_option::InputKey;
use super::key_option::KeyModifier;
use super::key_option::KeyModifiers;
use super::key_option::KeyOption;
use super::load_option::LoadOption;
use super::load_option::LoadOptionAttributes;
use super::VariableContents;
use super::VariableData;
use crate::hii::package::Guid;
use crate::hii::VariableKey;

/// The name of the hot key variables before their option number (UEFI 2.11 §3.1.6)
const HOT_KEY_PREFIX: &str = "Key";
/// The Attributes bits of a load option that UEFI 2.11 §3.1.3 defines: LOAD_OPTION_ACTIVE,
/// LOAD_OPTION_FORCE_RECONNECT, LOAD_OPTION_HIDDEN and the LOAD_OPTION_CATEGORY field
const DEFINED_ATTRIBUTES: LoadOptionAttributes =
    LoadOptionAttributes::from_bits_retain(0x0000_1F0B);
/// LOAD_OPTION_CATEGORY, a field whose values but LOAD_OPTION_CATEGORY_BOOT (0) and
/// LOAD_OPTION_CATEGORY_APP (0x100) are reserved
const CATEGORY: LoadOptionAttributes = LoadOptionAttributes::from_bits_retain(0x0000_1F00);

/// The kinds of load option variables (UEFI 2.11 §3.1.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OptionKind {
    /// Boot####, Driver#### and SysPrep####, which the order variables list
    Ordered(LoadOptionKind),
    /// PlatformRecovery####, which "are only modified by firmware and are read-only to the OS"
    /// (UEFI 2.11 §3.3)
    PlatformRecovery,
    /// OsRecovery####, of the vendor GUIDs that OsRecoveryOrder lists (UEFI 2.11 §3.4.1)
    OsRecovery,
}

impl OptionKind {
    const ALL: [Self; 5] = [
        Self::Ordered(LoadOptionKind::Boot),
        Self::Ordered(LoadOptionKind::Driver),
        Self::Ordered(LoadOptionKind::SysPrep),
        Self::PlatformRecovery,
        Self::OsRecovery,
    ];

    /// The name of the variables of this kind before their option number.
    fn prefix(self) -> &'static str {
        match self {
            Self::Ordered(kind) => kind.prefix(),
            Self::PlatformRecovery => "PlatformRecovery",
            Self::OsRecovery => "OsRecovery",
        }
    }
}

/// A load option variable, such as Boot0001.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct OptionName {
    pub(crate) kind: OptionKind,
    pub(crate) number: u16,
}

impl fmt::Display for OptionName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{:04X}", self.kind.prefix(), self.number)
    }
}

/// A variable that holds a console device path (UEFI 2.11 §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Console {
    ConIn,
    ConOut,
    ErrOut,
    /// ConInDev, ConOutDev and ErrOutDev, which "are volatile, and are set dynamically on every
    /// boot" (UEFI 2.11 §3.3)
    ConInDev,
    ConOutDev,
    ErrOutDev,
}

impl Console {
    const ALL: [Self; 6] = [
        Self::ConIn,
        Self::ConOut,
        Self::ErrOut,
        Self::ConInDev,
        Self::ConOutDev,
        Self::ErrOutDev,
    ];

    fn name(self) -> &'static str {
        match self {
            Self::ConIn => "ConIn",
            Self::ConOut => "ConOut",
            Self::ErrOut => "ErrOut",
            Self::ConInDev => "ConInDev",
            Self::ConOutDev => "ConOutDev",
            Self::ErrOutDev => "ErrOutDev",
        }
    }
}

/// A variable that this module decodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BootManagerVariable {
    LoadOption(OptionName),
    /// Key####, by its option number
    HotKey(u16),
    Console(Console),
}

impl BootManagerVariable {
    /// The variable that `name` names, if this module decodes it.
    pub(crate) fn parse(name: &str) -> Option<Self> {
        if let Some(console) = Console::ALL
            .into_iter()
            .find(|console| console.name() == name)
        {
            return Some(Self::Console(console));
        }
        if let Some(number) = option_number(name, HOT_KEY_PREFIX) {
            return Some(Self::HotKey(number));
        }
        OptionKind::ALL.into_iter().find_map(|kind| {
            option_number(name, kind.prefix())
                .map(|number| Self::LoadOption(OptionName { kind, number }))
        })
    }

    /// The variable's key: of the vendor GUID `vendor`, which an OsRecovery#### needs and any
    /// other may give if it is EFI_GLOBAL_VARIABLE.
    fn key(self, vendor: Option<Guid>) -> Result<VariableKey, VendorError> {
        let name = self.to_string();
        let guid = match (self, vendor) {
            (
                Self::LoadOption(OptionName {
                    kind: OptionKind::OsRecovery,
                    ..
                }),
                vendor,
            ) => vendor.ok_or(VendorError::Missing(name.clone()))?,
            (_, Some(vendor)) if vendor != EFI_GLOBAL_VARIABLE => {
                return Err(VendorError::Foreign { name, vendor });
            }
            (_, Some(_) | None) => EFI_GLOBAL_VARIABLE,
        };
        Ok(VariableKey { name, guid })
    }
}

impl fmt::Display for BootManagerVariable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LoadOption(option) => option.fmt(f),
            Self::HotKey(number) => write!(f, "{HOT_KEY_PREFIX}{number:04X}"),
            Self::Console(console) => f.write_str(console.name()),
        }
    }
}

/// The option number of `text`, `prefix` and then four digits "in printable hexadecimal
/// representation using the digits 0-9, and the upper case versions of the characters A-F"
/// (UEFI 2.11 §3.1.1), as Boot0001 has.
pub(super) fn option_number(text: &str, prefix: &str) -> Option<u16> {
    text.strip_prefix(prefix)
        .filter(|digits| {
            digits.len() == 4
                && digits
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'A'..=b'F'))
        })
        .and_then(|digits| u16::from_str_radix(digits, 16).ok())
}

/// The names of the variables of this module, comma-separated, such as Boot####.
pub(super) fn variable_names() -> String {
    OptionKind::ALL
        .map(OptionKind::prefix)
        .into_iter()
        .chain([HOT_KEY_PREFIX])
        .map(|prefix| format!("{prefix}####"))
        .chain(Console::ALL.map(|console| console.name().to_owned()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The variable `variable` that `variables` hold, of the vendor GUID `vendor` if given, decoded:
/// the bytes after the metadata that metadata_end finds by its attributes, as read_global
/// decodes the others (UEFI 2.11 §8.2.1).
pub(crate) fn read(
    variables: &impl VariableData,
    variable: BootManagerVariable,
    vendor: Option<Guid>,
) -> Result<GlobalVariable> {
    let key = variable.key(vendor)?;
    let contents = variables
        .variable_data(&key)?
        .map(|contents| {
            let value = value_after_metadata(&contents)
                .map_err(anyhow::Error::from)
                .and_then(|data| match variable {
                    BootManagerVariable::LoadOption(_) => {
                        load_option_data(data).map(GlobalValue::LoadOptionData)
                    }
                    BootManagerVariable::HotKey(_) => {
                        hot_key(variables, data).map(GlobalValue::HotKey)
                    }
                    BootManagerVariable::Console(_) => {
                        console_path(data).map(GlobalValue::DevicePath)
                    }
                })
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

/// The value of `contents`, a variable of the boot manager: its data after the
/// EFI_VARIABLE_AUTHENTICATION_3 metadata that metadata_end finds by its attributes (UEFI 2.11
/// §8.2.1).
fn value_after_metadata(contents: &VariableContents) -> Result<&[u8], MetadataRefusal> {
    let data = contents.data();
    metadata_end(contents.attributes().bits(), data)
        .and_then(|end| data.get(end..).ok_or(MetadataRefusal::truncated(data)))
}

/// The EFI_LOAD_OPTION of `data`, as variable get shows it.
fn load_option_data(data: &[u8]) -> Result<LoadOptionData> {
    let option = LoadOption::decode(data)?;
    let device_paths = device_path::device_paths(option.file_paths.as_ref())?
        .into_iter()
        .map(DevicePathText::of)
        .collect();
    Ok(LoadOptionData {
        attributes: option.attributes.bits(),
        description: option.description.as_ref().to_owned(),
        device_paths,
        optional_data: option.optional_data,
    })
}

/// The EFI_KEY_OPTION of `data`, as variable get shows it, its BootOptionCrc checked against the
/// Boot#### that `variables` hold.
fn hot_key(variables: &impl VariableData, data: &[u8]) -> Result<HotKey> {
    let option = KeyOption::decode(data)?;
    let boot_option = LoadOptionName {
        kind: LoadOptionKind::Boot,
        number: option.boot_option,
    };
    let crc_matches = variables
        .variable_data(&boot_option.key())?
        .is_some_and(|boot| value_after_metadata(&boot).is_ok_and(|value| option.matches(value)));
    Ok(HotKey {
        revision: option.revision(),
        modifiers: option.modifiers().bits(),
        keys: option.keys,
        boot_option,
        crc_matches,
    })
}

/// The one device path of a console variable's `data`.
fn console_path(data: &[u8]) -> Result<DevicePathText> {
    match device_path::device_paths(data)?.as_slice() {
        [path] => Ok(DevicePathText::of(path)),
        paths => Err(MalformedConsole(paths.len()).into()),
    }
}

/// A load option as variable get shows it (UEFI 2.11 §3.1.3).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LoadOptionData {
    /// Attributes, its reserved bits kept
    pub attributes: u32,
    /// Description, each CHAR16 that is a surrogate as U+FFFD
    pub description: String,
    /// The device paths of FilePathList
    pub device_paths: Vec<DevicePathText>,
    /// OptionalData, the bytes that the boot manager passes to the image
    pub optional_data: Vec<u8>,
}

/// Attributes as the names of LoadOptionFlag, then each undefined bit in hex, and the
/// LOAD_OPTION_CATEGORY field as the name of its LoadOptionCategory, else in hex; OptionalData
/// in hex.
impl Serialize for LoadOptionData {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("attributes", &LoadOptionFlags(self.attributes))?;
        map.serialize_entry("category", &category_text(self.attributes))?;
        map.serialize_entry("description", &self.description)?;
        map.serialize_entry("device_paths", &self.device_paths)?;
        map.serialize_entry("optional_data", &lower_hex(&self.optional_data))?;
        map.end()
    }
}

/// The flags of a load option's Attributes (UEFI 2.11 §3.1.3), LOAD_OPTION_ and these names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum LoadOptionFlag {
    Active,
    ForceReconnect,
    Hidden,
}

impl LoadOptionFlag {
    const ALL: [Self; 3] = [Self::Active, Self::ForceReconnect, Self::Hidden];

    /// The name that variable get prints.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::ForceReconnect => "force-reconnect",
            Self::Hidden => "hidden",
        }
    }

    pub(crate) fn attribute(self) -> LoadOptionAttributes {
        match self {
            Self::Active => LoadOptionAttributes::ACTIVE,
            Self::ForceReconnect => LoadOptionAttributes::FORCE_RECONNECT,
            Self::Hidden => LoadOptionAttributes::HIDDEN,
        }
    }
}

/// The values of the LOAD_OPTION_CATEGORY field that UEFI 2.11 §3.1.3 defines, LOAD_OPTION_CATEGORY_
/// and these names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum LoadOptionCategory {
    Boot,
    App,
}

impl LoadOptionCategory {
    const ALL: [Self; 2] = [Self::Boot, Self::App];

    /// The name that variable get prints.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::Boot => "boot",
            Self::App => "app",
        }
    }

    /// The value of the field.
    pub(crate) fn attributes(self) -> LoadOptionAttributes {
        match self {
            Self::Boot => LoadOptionAttributes::empty(),
            Self::App => LoadOptionAttributes::CATEGORY_APP,
        }
    }
}

/// A load option's Attributes, which serializes as the names of its LoadOptionFlags, then each
/// undefined bit in hex.
struct LoadOptionFlags(u32);

impl Serialize for LoadOptionFlags {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let attributes = LoadOptionAttributes::from_bits_retain(self.0);
        serialize_bits(
            serializer,
            LoadOptionFlag::ALL
                .into_iter()
                .filter(|flag| attributes.contains(flag.attribute()))
                .map(LoadOptionFlag::name),
            u64::from((attributes - DEFINED_ATTRIBUTES).bits()),
        )
    }
}

/// The name of the LoadOptionCategory of `attributes`, else its reserved value in hex.
fn category_text(attributes: u32) -> String {
    let field = LoadOptionAttributes::from_bits_retain(attributes) & CATEGORY;
    match LoadOptionCategory::ALL
        .into_iter()
        .find(|category| category.attributes() == field)
    {
        Some(category) => category.name().to_owned(),
        None => format!("{:#X}", field.bits()),
    }
}

/// A hot key as variable get shows it (UEFI 2.11 §3.1.6).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct HotKey {
    /// KeyData's Revision, which "should be 0"
    pub revision: u8,
    /// KeyData's shift states and Reserved bits, where KeyData holds them
    pub modifiers: u32,
    /// Keys
    pub keys: Vec<InputKey>,
    /// The Boot#### that the key starts
    pub boot_option: LoadOptionName,
    /// Whether that Boot#### exists and BootOptionCrc is its CRC-32: else the boot manager
    /// ignores the key
    pub crc_matches: bool,
}

/// The shift states as the names of KeyModifier, then each Reserved bit in hex.
impl Serialize for HotKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("revision", &self.revision)?;
        map.serialize_entry("modifiers", &ModifierNames(self.modifiers))?;
        map.serialize_entry("keys", &self.keys)?;
        map.serialize_entry("boot_option", &self.boot_option)?;
        map.serialize_entry("crc_matches", &self.crc_matches)?;
        map.end()
    }
}

/// KeyData's shift states and Reserved bits, which serialize as the names of the KeyModifiers,
/// then each Reserved bit in hex.
struct ModifierNames(u32);

impl Serialize for ModifierNames {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let modifiers = KeyModifiers::from_bits_retain(self.0);
        serialize_bits(
            serializer,
            KeyModifier::ALL
                .into_iter()
                .filter(|modifier| modifiers.contains(modifier.modifiers()))
                .map(KeyModifier::name),
            u64::from((modifiers - KeyModifiers::all()).bits()),
        )
    }
}

/// A device path as variable get shows it (UEFI 2.11 §10.6).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum DevicePathText {
    /// Its text, which reads back to its bytes
    Text(String),
    /// A device path that no text reads back to: its bytes, with the End Entire Device Path
    /// node, and why
    NoText { bytes: Vec<u8>, reason: String },
}

impl DevicePathText {
    /// The text of `path`, one device path with its End Entire Device Path node, if it has one.
    fn of(path: &[u8]) -> Self {
        match device_path::to_text(path) {
            Ok(text) => Self::Text(text),
            Err(error) => Self::NoText {
                bytes: path.to_vec(),
                reason: error.to_string(),
            },
        }
    }
}

/// Text as a string; else an object of the bytes in hex and the reason.
impl Serialize for DevicePathText {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        match self {
            Self::Text(text) => serializer.serialize_str(text),
            Self::NoText { bytes, reason } => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("bytes", &lower_hex(bytes))?;
                map.serialize_entry("no_text", reason)?;
                map.end()
            }
        }
    }
}

/// A vendor GUID that variable get refuses for a variable of this module.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
enum VendorError {
    #[error(
        "{0} needs its vendor GUID, one that OsRecoveryOrder lists (UEFI 2.11 section 3.4.1): \
         `uefisettings variable get {0} GUID`"
    )]
    Missing(String),
    #[error(
        "{name} of vendor {vendor} is not the {name} that variable get decodes, of vendor \
         {EFI_GLOBAL_VARIABLE}; `uefisettings variable info {name} {vendor}` shows its \
         attributes and size"
    )]
    Foreign { name: String, vendor: Guid },
}

/// The data of a console variable, which holds one device path (UEFI 2.11 §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("{0} device paths, not the one of a console variable")]
struct MalformedConsole(usize);

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::efi_variables::device_path::tests::bytes;
    use crate::efi_variables::device_path::tests::path;
    use crate::efi_variables::device_path::tests::X64_BOOT0000;
    use crate::efi_variables::device_path::tests::X64_BOOT0001;
    use crate::efi_variables::device_path::tests::X64_CONOUT;
    use crate::efi_variables::enhanced_authenticated::fixture::timestamp_metadata;
    use crate::efi_variables::globals::tests::key;
    use crate::efi_variables::globals::tests::HeldVariables;
    use crate::efi_variables::globals::tests::NV_BS_RT;
    use crate::efi_variables::key_option::boot_option_crc;
    use crate::efi_variables::key_option::tests::X64_KEY0000;
    use crate::hii::VariableAttributes;

    /// A vendor GUID of OsRecovery####: the formset GUID of EDK2's DriverSample
    const RECOVERY_VENDOR: &str = "A04A27F4-DF00-4D42-B552-39511302113D";
    /// The text of the device path of OVMF's x86_64 Boot0000, UiApp
    const UI_APP: &str =
        "Fv(7CB8BDC9-F8EB-4F34-AAEA-3EE4AF6516A1)/FvFile(462CAA21-7614-4503-836E-8AB6F4662331)";
    /// The End Device Path node that ends an instance
    const END_INSTANCE: [u8; 4] = [0x7F, 0x01, 0x04, 0x00];
    /// Pci(0x1,0x0): Function 0 of Device 1 (UEFI 2.11 Table 10.6)
    const PCI_1_0: [u8; 6] = [0x01, 0x01, 0x06, 0x00, 0x00, 0x01];

    fn vendor(text: &str) -> Guid {
        text.parse()
            .unwrap_or_else(|error| panic!("parse GUID {text}: {error}"))
    }

    /// The JSON that variable get prints of the variable `name` of `vendor` that `variables`
    /// hold.
    fn printed(variables: &HeldVariables, name: &str, vendor: Option<Guid>) -> serde_json::Value {
        let variable = BootManagerVariable::parse(name).unwrap_or_else(|| panic!("parse {name}"));
        let read = read(variables, variable, vendor)
            .unwrap_or_else(|error| panic!("read {name}: {error:#}"));
        serde_json::to_value(&read).expect("serialize the variable")
    }

    /// `option` with its Attributes replaced by `attributes`.
    fn with_attributes(option: &str, attributes: u32) -> Vec<u8> {
        let mut option = bytes(option);
        option[..4].copy_from_slice(&attributes.to_le_bytes());
        option
    }

    /// An EFI_LOAD_OPTION of Attributes 1, Description "A" and `file_paths`.
    fn load_option(file_paths: &[u8]) -> Vec<u8> {
        let length = u16::try_from(file_paths.len()).expect("a short FilePathList");
        [
            &1_u32.to_le_bytes()[..],
            &length.to_le_bytes(),
            &[0x41, 0, 0, 0],
            file_paths,
        ]
        .concat()
    }

    #[test]
    fn names_parse_as_boot_manager_variables_or_fall_to_globals() {
        let boot = |kind, number| {
            Some(BootManagerVariable::LoadOption(OptionName {
                kind: OptionKind::Ordered(kind),
                number,
            }))
        };
        let cases = [
            ("Boot0001", boot(LoadOptionKind::Boot, 1)),
            ("DriverFFFF", boot(LoadOptionKind::Driver, 0xFFFF)),
            ("SysPrep00A1", boot(LoadOptionKind::SysPrep, 0xA1)),
            (
                "PlatformRecovery0000",
                Some(BootManagerVariable::LoadOption(OptionName {
                    kind: OptionKind::PlatformRecovery,
                    number: 0,
                })),
            ),
            (
                "OsRecovery0002",
                Some(BootManagerVariable::LoadOption(OptionName {
                    kind: OptionKind::OsRecovery,
                    number: 2,
                })),
            ),
            ("Key000B", Some(BootManagerVariable::HotKey(0xB))),
            ("ConIn", Some(BootManagerVariable::Console(Console::ConIn))),
            (
                "ErrOutDev",
                Some(BootManagerVariable::Console(Console::ErrOutDev)),
            ),
            ("Boot001", None),
            ("Boot00001", None),
            ("Boot00a1", None),
            ("boot0001", None),
            ("Boot+001", None),
            ("BootNext", None),
            ("BootOrder", None),
            ("BootCurrent", None),
            ("KEK", None),
            ("ConInDevX", None),
            ("Key", None),
        ];
        for (name, want) in cases {
            let variable = BootManagerVariable::parse(name);

            assert_eq!(variable, want, "{name}");
            if let Some(variable) = variable {
                assert_eq!(variable.to_string(), name, "{name} written back");
            }
        }
    }

    /// Attributes as names, each undefined bit in hex, the category by name or in hex, each
    /// device path as text and OptionalData in hex, for every kind of load option.
    #[test]
    fn load_options_read_as_variable_get_prints_them() {
        let recovery = vendor(RECOVERY_VENDOR);
        let variables = HeldVariables::default()
            .with("Boot0000", EFI_GLOBAL_VARIABLE, &bytes(X64_BOOT0000))
            .with(
                "Driver0001",
                EFI_GLOBAL_VARIABLE,
                &with_attributes(X64_BOOT0001, 0x8000_0003),
            )
            .with(
                "SysPrep0002",
                EFI_GLOBAL_VARIABLE,
                &with_attributes(X64_BOOT0001, 0x0000_0308),
            )
            .with(
                "PlatformRecovery0000",
                EFI_GLOBAL_VARIABLE,
                &bytes(X64_BOOT0001),
            )
            .with("OsRecovery0000", recovery, &bytes(X64_BOOT0001));
        let misc_device = |attributes: serde_json::Value, category: &str| {
            json!({
                "attributes": attributes,
                "category": category,
                "description": "UEFI Misc Device",
                "device_paths": ["PciRoot(0x0)/Pci(0x1,0x0)"],
                "optional_data": "4eac0881119f594d850ee21a522c59b2",
            })
        };
        let cases = [
            (
                "Boot0000",
                None,
                "Boot0000-8be4df61-93ca-11d2-aa0d-00e098032b8c",
                json!({
                    "attributes": ["active", "hidden"],
                    "category": "app",
                    "description": "UiApp",
                    "device_paths": [UI_APP],
                    "optional_data": "",
                }),
            ),
            (
                "Driver0001",
                Some(EFI_GLOBAL_VARIABLE),
                "Driver0001-8be4df61-93ca-11d2-aa0d-00e098032b8c",
                misc_device(json!(["active", "force-reconnect", "0x80000000"]), "boot"),
            ),
            (
                "SysPrep0002",
                None,
                "SysPrep0002-8be4df61-93ca-11d2-aa0d-00e098032b8c",
                misc_device(json!(["hidden"]), "0x300"),
            ),
            (
                "PlatformRecovery0000",
                None,
                "PlatformRecovery0000-8be4df61-93ca-11d2-aa0d-00e098032b8c",
                misc_device(json!(["active"]), "boot"),
            ),
            (
                "OsRecovery0000",
                Some(recovery),
                "OsRecovery0000-a04a27f4-df00-4d42-b552-39511302113d",
                misc_device(json!(["active"]), "boot"),
            ),
        ];
        for (name, vendor, variable, value) in cases {
            assert_eq!(
                printed(&variables, name, vendor),
                json!({"variable": variable, "attributes": 7, "value": value}),
                "{name}"
            );
        }
        assert_eq!(
            variables.read.into_inner(),
            [
                key("Boot0000", EFI_GLOBAL_VARIABLE),
                key("Driver0001", EFI_GLOBAL_VARIABLE),
                key("SysPrep0002", EFI_GLOBAL_VARIABLE),
                key("PlatformRecovery0000", EFI_GLOBAL_VARIABLE),
                key("OsRecovery0000", recovery),
            ],
            "keys read"
        );
    }

    /// read decodes the value after the EFI_VARIABLE_AUTHENTICATION_3 metadata that GetVariable()
    /// returns first for a variable with EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS (UEFI 2.11
    /// §8.2.1), as it decodes that value alone, and refuses data that ends inside the metadata.
    #[test]
    fn variables_decode_after_enhanced_authenticated_metadata() {
        let enhanced = NV_BS_RT | VariableAttributes::ENHANCED_AUTHENTICATED_ACCESS;
        let decode = |attributes, data: &[u8]| {
            let variables = HeldVariables::default().with_attributes(
                "Boot0000",
                EFI_GLOBAL_VARIABLE,
                attributes,
                data,
            );
            let variable = BootManagerVariable::parse("Boot0000").expect("parse Boot0000");
            read(&variables, variable, None).map_err(|error| format!("{error:#}"))
        };
        let alone = decode(NV_BS_RT, &bytes(X64_BOOT0000))
            .expect("read Boot0000")
            .contents
            .expect("Boot0000 held");

        let after_metadata = decode(
            enhanced,
            &[timestamp_metadata(), bytes(X64_BOOT0000)].concat(),
        )
        .expect("read Boot0000 after its metadata")
        .contents
        .expect("Boot0000 held");

        assert_eq!(after_metadata.value, alone.value, "value");
        assert_eq!(after_metadata.attributes, enhanced.bits(), "attributes");
        assert_eq!(
            decode(enhanced, &timestamp_metadata()[..10]),
            Err(
                "EFI variable Boot0000-8be4df61-93ca-11d2-aa0d-00e098032b8c is malformed: its 10 \
                 bytes of data end inside its metadata"
                    .to_string()
            ),
            "data ending inside the metadata"
        );
    }

    /// A device path that no text reads back to shows its bytes and why, and the others of the
    /// variable still show as text.
    #[test]
    fn device_paths_of_no_text_show_their_bytes() {
        let empty_instance = [&END_INSTANCE[..], &path(&[PCI_1_0.to_vec()])].concat();
        let pci = path(&[PCI_1_0.to_vec()]);
        let variables = HeldVariables::default()
            .with(
                "Boot0003",
                EFI_GLOBAL_VARIABLE,
                &load_option(&[&pci[..], &empty_instance].concat()),
            )
            .with("ConIn", EFI_GLOBAL_VARIABLE, &empty_instance);
        let no_text = json!({
            "bytes": "7f0104000101060000017fff0400",
            "no_text": device_path::to_text(&empty_instance)
                .expect_err("an empty instance")
                .to_string(),
        });

        assert_eq!(
            printed(&variables, "Boot0003", None)["value"]["device_paths"],
            json!(["Pci(0x1,0x0)", no_text]),
            "Boot0003"
        );
        assert_eq!(
            printed(&variables, "ConIn", None)["value"],
            no_text,
            "ConIn"
        );
    }

    /// Key#### shows its shift states by name, Reserved bits in hex, each key by its scan code
    /// name or character, and whether BootOptionCrc is the CRC-32 of its Boot#### as held.
    #[test]
    fn hot_keys_read_with_whether_their_crc_matches() {
        let mut ctrl_alt_p_r = bytes(X64_KEY0000);
        ctrl_alt_p_r[..4].copy_from_slice(&0x8000_4601_u32.to_le_bytes());
        ctrl_alt_p_r.splice(10..14, [0, 0, 0x70, 0, 0, 0, 0x72, 0]);
        let mut of_boot0005 = bytes(X64_KEY0000);
        of_boot0005[8] = 5;
        let f2 = |boot_option: &str, crc_matches: bool| {
            json!({
                "revision": 0,
                "modifiers": [],
                "keys": ["F2"],
                "boot_option": boot_option,
                "crc_matches": crc_matches,
            })
        };
        // Boot0000 with LOAD_OPTION_ACTIVE cleared, whose CRC-32 differs
        let inactive = with_attributes(X64_BOOT0000, 0x0000_0108);
        let cases = [
            (
                "Key0000",
                bytes(X64_KEY0000),
                bytes(X64_BOOT0000),
                f2("Boot0000", true),
            ),
            (
                "Key0000",
                bytes(X64_KEY0000),
                inactive,
                f2("Boot0000", false),
            ),
            (
                "Key0001",
                ctrl_alt_p_r,
                bytes(X64_BOOT0000),
                json!({
                    "revision": 1,
                    "modifiers": ["control", "alt", "0x4000"],
                    "keys": ["p", "r"],
                    "boot_option": "Boot0000",
                    "crc_matches": true,
                }),
            ),
            (
                "Key0002",
                of_boot0005,
                bytes(X64_BOOT0000),
                f2("Boot0005", false),
            ),
        ];
        for (name, key_option, boot0000, value) in cases {
            let variables = HeldVariables::default()
                .with("Boot0000", EFI_GLOBAL_VARIABLE, &boot0000)
                .with(name, EFI_GLOBAL_VARIABLE, &key_option);

            assert_eq!(
                printed(&variables, name, None)["value"],
                value,
                "{name} of Boot0000 {boot0000:02x?}"
            );
        }
    }

    /// Of a Boot#### with EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS, a Key#### matches the CRC-32
    /// of the EFI_LOAD_OPTION after the metadata (UEFI 2.11 §3.1.6, §8.2.1), not of the data.
    #[test]
    fn hot_keys_match_the_crc_of_the_load_option_after_its_metadata() {
        let data = [timestamp_metadata(), bytes(X64_BOOT0000)].concat();
        let mut of_the_data = bytes(X64_KEY0000);
        of_the_data[4..8].copy_from_slice(&boot_option_crc(&data).to_le_bytes());
        let cases = [
            ("load option", bytes(X64_KEY0000), true),
            ("data", of_the_data, false),
        ];
        for (crc_of, key_option, crc_matches) in cases {
            let variables = HeldVariables::default()
                .with_attributes(
                    "Boot0000",
                    EFI_GLOBAL_VARIABLE,
                    NV_BS_RT | VariableAttributes::ENHANCED_AUTHENTICATED_ACCESS,
                    &data,
                )
                .with("Key0000", EFI_GLOBAL_VARIABLE, &key_option);

            assert_eq!(
                printed(&variables, "Key0000", None)["value"]["crc_matches"],
                json!(crc_matches),
                "Key0000 of the CRC-32 of the {crc_of}"
            );
        }
    }

    #[test]
    fn consoles_read_as_one_device_path() {
        let conout = bytes(X64_CONOUT);
        let serial = |n: u8| {
            format!("PciRoot(0x0)/Pci(0x1F,0x0)/Serial(0x{n})/Uart(115200,8,N,1)/VenUtf8()")
        };
        let variables = HeldVariables::default()
            .with("ConOut", EFI_GLOBAL_VARIABLE, &conout)
            .with(
                "ConOutDev",
                EFI_GLOBAL_VARIABLE,
                &[&conout[..], &conout].concat(),
            );

        assert_eq!(
            printed(&variables, "ConOut", None),
            json!({
                "variable": "ConOut-8be4df61-93ca-11d2-aa0d-00e098032b8c",
                "attributes": 7,
                "value": format!("{},/{}", serial(0), serial(1)),
            }),
            "ConOut"
        );
        let error = read(
            &variables,
            BootManagerVariable::Console(Console::ConOutDev),
            None,
        )
        .expect_err("read two device paths");
        assert_eq!(
            format!("{error:#}"),
            "EFI variable ConOutDev-8be4df61-93ca-11d2-aa0d-00e098032b8c is malformed: 2 device \
             paths, not the one of a console variable",
            "ConOutDev"
        );
        assert_eq!(
            read(
                &variables,
                BootManagerVariable::Console(Console::ErrOut),
                None
            )
            .expect("read ErrOut")
            .contents,
            None,
            "ErrOut is absent"
        );
    }

    /// An OsRecovery#### without its vendor GUID, or another variable of a vendor GUID other than
    /// EFI_GLOBAL_VARIABLE, is refused before any read.
    #[test]
    fn vendors_other_than_their_own_are_refused_unread() {
        let foreign = vendor(RECOVERY_VENDOR);
        let variables = HeldVariables::default()
            .with("OsRecovery0000", foreign, &bytes(X64_BOOT0001))
            .with("Boot0001", foreign, &bytes(X64_BOOT0001));
        let cases = [
            (
                "OsRecovery0000",
                None,
                "OsRecovery0000 needs its vendor GUID, one that OsRecoveryOrder lists (UEFI 2.11 \
                 section 3.4.1): `uefisettings variable get OsRecovery0000 GUID`",
            ),
            (
                "Boot0001",
                Some(foreign),
                "Boot0001 of vendor A04A27F4-DF00-4D42-B552-39511302113D is not the Boot0001 that \
                 variable get decodes, of vendor 8BE4DF61-93CA-11D2-AA0D-00E098032B8C; \
                 `uefisettings variable info Boot0001 A04A27F4-DF00-4D42-B552-39511302113D` shows \
                 its attributes and size",
            ),
            (
                "Key0001",
                Some(foreign),
                "Key0001 of vendor A04A27F4-DF00-4D42-B552-39511302113D is not the Key0001 that \
                 variable get decodes, of vendor 8BE4DF61-93CA-11D2-AA0D-00E098032B8C; \
                 `uefisettings variable info Key0001 A04A27F4-DF00-4D42-B552-39511302113D` shows \
                 its attributes and size",
            ),
        ];
        for (name, vendor, want) in cases {
            let variable = BootManagerVariable::parse(name).expect("a boot manager variable");
            let error = read(&variables, variable, vendor).expect_err("read with a wrong vendor");

            assert_eq!(error.to_string(), want, "{name} {vendor:?}");
        }
        assert_eq!(variables.read.into_inner(), [], "keys read");
    }

    #[test]
    fn malformed_variables_are_refused() {
        let mut short_key = bytes(X64_KEY0000);
        short_key.pop();
        let variables = HeldVariables::default()
            .with("Boot0000", EFI_GLOBAL_VARIABLE, &[1, 0, 0, 0])
            .with("Key0000", EFI_GLOBAL_VARIABLE, &short_key)
            .with("ConIn", EFI_GLOBAL_VARIABLE, &PCI_1_0);
        for name in ["Boot0000", "Key0000", "ConIn"] {
            let variable = BootManagerVariable::parse(name).expect("a boot manager variable");
            let error = read(&variables, variable, None).expect_err("read malformed data");

            assert!(
                format!("{error:#}").starts_with(&format!(
                    "EFI variable {} is malformed: ",
                    key(name, EFI_GLOBAL_VARIABLE)
                )),
                "{name}: {error:#}"
            );
        }
    }

    /// The names that variable get prints for the flags, categories and shift states are those
    /// of their constants in UEFI 2.11 §3.1.3 and §3.1.6, lowercase, "-" for "_".
    #[test]
    fn names_are_those_of_the_spec_constants() {
        let names = |names: &[&str]| -> Vec<String> {
            names
                .iter()
                .map(|name| name.to_ascii_lowercase().replace('_', "-"))
                .collect()
        };
        assert_eq!(
            LoadOptionFlag::ALL.map(LoadOptionFlag::name),
            names(&["ACTIVE", "FORCE_RECONNECT", "HIDDEN"]).as_slice(),
            "LOAD_OPTION_"
        );
        assert_eq!(
            LoadOptionCategory::ALL.map(LoadOptionCategory::name),
            names(&["BOOT", "APP"]).as_slice(),
            "LOAD_OPTION_CATEGORY_"
        );
        assert_eq!(
            KeyModifier::ALL.map(KeyModifier::name),
            names(&["SHIFT", "CONTROL", "ALT", "LOGO", "MENU", "SYS_REQ"]).as_slice(),
            "the Pressed fields of EFI_BOOT_KEY_DATA"
        );
        assert_eq!(
            LoadOptionFlag::ALL
                .map(|flag| flag.attribute().bits())
                .into_iter()
                .chain(LoadOptionCategory::ALL.map(|category| category.attributes().bits()))
                .collect::<Vec<_>>(),
            [0x1, 0x2, 0x8, 0x0, 0x100],
            "values"
        );
    }
}
