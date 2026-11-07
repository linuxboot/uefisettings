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

//! The EFI variables of a machine (UEFI 2.10 §8.2): what the variable commands
//! make of what each backend tells. The backends do the I/O: efivarfs on Linux (hii/efivarfs.rs),
//! the runtime services in the UEFI Shell (hii/variable_services.rs), and the firmware environment
//! calls on Windows (hii/firmware_environment.rs). Capsules for the machine's firmware (UEFI 2.11
//! §8.5.3) too: their bytes come from capsule.rs, and Linux's capsule loader
//! (capsule_loader.rs) or the runtime services in the UEFI Shell (capsule_services.rs) take
//! them. And the configuration data of the firmware's JSON configuration table (§23.5.2), which
//! capsule.rs decodes from a VendorTable. Every build reads the values of questions behind the
//! metadata of enhanced authenticated variables (enhanced_authenticated.rs).

#[cfg(variable_data)]
pub(crate) mod authenticated;
#[cfg(any(capsule_delivery, configuration_tables))]
mod capsule;
#[cfg(capsule_delivery)]
mod capsule_delivery;
#[cfg(variable_data)]
mod capsule_result;
pub(crate) mod enhanced_authenticated;
#[cfg(variable_data)]
mod json_bytes;

#[cfg(all(variable_names, any(target_os = "uefi", test)))]
use anyhow::anyhow;
#[cfg(any(variable_names, variable_info))]
use anyhow::Context;
#[cfg(any(variable_names, variable_info, variable_storage_info, variable_data))]
use anyhow::Result;
#[cfg(any(variable_info, variable_storage_info))]
use serde::Serialize;
#[cfg(any(variable_storage_info, variable_data, configuration_tables))]
use thiserror::Error;

#[cfg(capsule_delivery)]
pub use capsule::CapsuleCapabilities;
#[cfg(capsule_delivery)]
pub(crate) use capsule::JsonCapsule;
#[cfg(configuration_tables)]
pub use capsule::JsonConfigData;
#[cfg(capsule_delivery)]
pub(crate) use capsule::Processing;
#[cfg(capsule_delivery)]
pub use capsule::ResetType;
#[cfg(configuration_tables)]
pub(crate) use capsule::EFI_JSON_CONFIG_DATA_TABLE_GUID;
#[cfg(capsule_delivery)]
pub(crate) use capsule_delivery::deliver_json_capsule;
#[cfg(capsule_delivery)]
pub use capsule_delivery::CapsuleDelivered;
#[cfg(capsule_delivery)]
pub(crate) use capsule_delivery::CapsuleDelivery;
#[cfg(all(capsule_delivery, target_os = "uefi"))]
pub(crate) use capsule_delivery::CapsuleServices;
#[cfg(all(capsule_delivery, target_os = "uefi"))]
pub(crate) use capsule_delivery::UpdateCapsuleDelivery;
#[cfg(variable_names)]
pub(crate) use capsule_result::list_capsule_results;
#[cfg(all(variable_data, any(target_os = "windows", test)))]
pub(crate) use capsule_result::probe_capsule_results;
#[cfg(configuration_tables)]
pub(crate) use capsule_result::read_json_capsule_result;
#[cfg(variable_data)]
pub use capsule_result::CapsuleResult;
#[cfg(variable_data)]
pub use capsule_result::CapsuleResultDetails;
#[cfg(variable_data)]
pub use capsule_result::CapsuleResultError;
#[cfg(variable_data)]
pub use capsule_result::CapsuleResults;
#[cfg(variable_data)]
pub use capsule_result::EfiTime;
#[cfg(variable_data)]
pub use capsule_result::FmpCapsuleResult;
#[cfg(variable_data)]
pub use capsule_result::JsonCapsuleResult;
#[cfg(variable_data)]
pub use capsule_result::NamedCapsuleResult;
#[cfg(variable_data)]
pub use capsule_result::ResultName;
#[cfg(variable_data)]
pub use capsule_result::Undecoded;
#[cfg(configuration_tables)]
pub(crate) use capsule_result::EFI_JSON_CAPSULE_RESULT_TABLE_GUID;
#[cfg(variable_data)]
pub use json_bytes::TextOrHex;

#[cfg(configuration_tables)]
use crate::firmware_width::FirmwareWidth;
#[cfg(any(
    variable_names,
    variable_info,
    capsule_delivery,
    configuration_tables,
    variable_data
))]
use crate::hii::package::Guid;
#[cfg(any(variable_storage_info, variable_data))]
use crate::hii::VariableAttributes;
#[cfg(variable_data)]
use crate::hii::VariableInterface;
#[cfg(any(variable_names, variable_info, variable_data))]
use crate::hii::VariableKey;

#[cfg(variable_data)]
pub(crate) mod globals;
#[cfg(variable_data)]
#[cfg_attr(
    not(any(target_os = "linux", target_os = "windows", test)),
    allow(
        dead_code,
        reason = "only the Linux and Windows builds stage a set in a load option"
    )
)]
pub(crate) mod load_option;
#[cfg(variable_data)]
pub(crate) mod secure_boot_mode;

/// The size of EFI_TIME (UEFI 2.11 §8.3.1).
const EFI_TIME_SIZE: usize = 16;

/// Whether `time_stamp`, an EFI_TIME, is the TimeStamp of an authentication descriptor, which
/// is in GMT: Pad1, Nanosecond, TimeZone, Daylight and Pad2 are 0 (UEFI 2.11 §8.2.3, §8.2.5).
fn is_gmt_time_stamp(time_stamp: &[u8; EFI_TIME_SIZE]) -> bool {
    // Year, Month, Day, Hour, Minute and Second, then Pad1, Nanosecond, TimeZone, Daylight and
    // Pad2 (UEFI 2.11 §8.3.1)
    let [_, _, _, _, _, _, _, gmt_fields @ ..] = *time_stamp;
    gmt_fields.iter().all(|&byte| byte == 0)
}

/// EFI_JSON_CAPSULE_ID_GUID, the CapsuleGuid of a JSON capsule (UEFI 2.11 §23.5.1), which the
/// result of its processing names too (§8.5.6.1.3).
#[cfg(any(capsule_delivery, configuration_tables, variable_data))]
const EFI_JSON_CAPSULE_ID_GUID: Guid = Guid {
    data1: 0x67d6_f4cd,
    data2: 0xd6b8,
    data3: 0x4573,
    data4: [0xbf, 0x4a, 0xde, 0x5e, 0x25, 0x2d, 0x61, 0xae],
};

/// The vendor GUID of uefisettings' own EFI variables.
#[cfg(variable_data)]
pub(crate) const UEFISETTINGS_VENDOR_GUID: Guid = Guid {
    data1: 0xdd16_f539,
    data2: 0x09ed,
    data3: 0x41b9,
    data4: [0x8b, 0x64, 0xd8, 0x5d, 0x6c, 0xd9, 0x3a, 0x8e],
};

/// GetNextVariableName() (UEFI 2.10 §8.2.2): the variables that a backend reaches, by name and
/// vendor GUID.
#[cfg(variable_names)]
pub(crate) trait VariableNames {
    /// Every variable these reach, in no particular order.
    fn variable_names(&self) -> Result<Vec<VariableKey>>;
}

#[cfg(variable_names)]
impl<T: VariableNames + ?Sized> VariableNames for &T {
    fn variable_names(&self) -> Result<Vec<VariableKey>> {
        (**self).variable_names()
    }
}

/// What one GetNextVariableName() call (UEFI 2.10 §8.2.2) did.
#[cfg(all(variable_names, any(target_os = "uefi", test)))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NextVariableName {
    /// EFI_SUCCESS: it wrote the next variable's name and vendor GUID over the previous ones
    Found,
    /// EFI_NOT_FOUND: "The next variable was not found", so the listing ends
    End,
    /// EFI_BUFFER_TOO_SMALL: the next name needs a buffer of this many CHAR16
    BufferTooSmall(usize),
}

/// GetNextVariableName(), one call at a time.
#[cfg(all(variable_names, any(target_os = "uefi", test)))]
pub(crate) trait GetNextVariableName {
    /// Calls GetNextVariableName() with the NUL-terminated `name` and the `vendor` of the
    /// previous variable, or a NUL first on the first call; any other status than those of
    /// NextVariableName is an error.
    fn get_next_variable_name(
        &mut self,
        name: &mut [u16],
        vendor: &mut Guid,
    ) -> Result<NextVariableName>;
}

/// Every variable that `calls` give, from a first call with an empty name to EFI_NOT_FOUND
/// (UEFI 2.10 §8.2.2), each name as VariableKey::from_ucs2 reads it. A variable given twice
/// fails the walk: some firmware gives one variable again and again (Linux v6.17
/// fs/efivarfs/vars.c efivar_init()).
#[cfg(all(variable_names, any(target_os = "uefi", test)))]
pub(crate) fn walk_variable_names(
    calls: &mut impl GetNextVariableName,
) -> Result<Vec<VariableKey>> {
    // 512 CHAR16 first, as a Toshiba Satellite Pro R50-B-12P does not update VariableNameSize
    // (uefi 0.41 runtime::VariableKeys::new())
    let mut name = vec![0; 512];
    let mut vendor = Guid::from([0; 16]);
    let mut keys = Vec::new();
    let mut given = std::collections::BTreeSet::new();
    loop {
        match calls.get_next_variable_name(&mut name, &mut vendor)? {
            NextVariableName::Found => {}
            NextVariableName::End => return Ok(keys),
            NextVariableName::BufferTooSmall(size) if size > name.len() => {
                name.resize(size, 0);
                continue;
            }
            NextVariableName::BufferTooSmall(size) => {
                return Err(anyhow!(
                    "GetNextVariableName() asked for {size} CHAR16, which its buffer of {} holds",
                    name.len()
                ));
            }
        }
        let units = name
            .iter()
            .position(|&unit| unit == 0)
            .and_then(|end| name.get(..end))
            .context("GetNextVariableName() gave a name without its NUL")?;
        let key = VariableKey::from_ucs2(units, vendor);
        // the units, as from_ucs2 reads distinct surrogates alike
        if !given.insert((units.to_vec(), vendor)) {
            return Err(anyhow!(
                "GetNextVariableName() returned EFI variable {key} twice"
            ));
        }
        keys.push(key);
    }
}

/// The variables that `names` reach, of the vendor `vendor` only if given, sorted by name, then
/// vendor: GetNextVariableName() "cannot be used as a filter" (UEFI 2.10 §8.2.2), so those of
/// other vendors drop out after the listing.
#[cfg(variable_names)]
pub(crate) fn list_variables(
    names: &impl VariableNames,
    vendor: Option<Guid>,
) -> Result<Vec<VariableKey>> {
    let mut keys = names.variable_names()?;
    keys.retain(|key| vendor.is_none_or(|vendor| key.guid == vendor));
    keys.sort();
    Ok(keys)
}

/// GetVariable() (UEFI 2.10 §8.2.1) without the data: what a backend tells of a variable that
/// it reaches.
#[cfg(variable_info)]
pub(crate) trait VariableInfoSource {
    /// The VariableInfo of `key`, or VariableNotFound.
    fn variable_info(&self, key: &VariableKey) -> Result<VariableInfo>;
}

/// What variable_info tells of an EFI variable: never its data. `variable info` prints it as
/// it serializes.
#[cfg(variable_info)]
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize)]
pub struct VariableInfo {
    /// The variable, named as its efivar file
    pub variable: String,
    /// Its attributes bitmask (UEFI 2.10 §8.2.1)
    pub attributes: u32,
    /// The size of its data, in bytes
    pub size: usize,
}

/// GetVariable() (UEFI 2.10 §8.2.1) with the data, and SetVariable() (§8.2.3): a variable that a
/// backend reaches, whole.
#[cfg(variable_data)]
pub(crate) trait VariableData {
    /// The interface through which the backend reads and writes variables, which decides what
    /// it can write.
    fn interface(&self) -> VariableInterface;
    /// The attributes and data of `key`, or None if the backend reaches no such variable.
    fn variable_data(&self, key: &VariableKey) -> Result<Option<VariableContents>>;
    /// Sets `key` to `contents`, creating it if missing.
    fn set_variable(&self, key: &VariableKey, contents: &VariableContents) -> Result<()>;
    /// Deletes `key`, as SetVariable() without data does (UEFI 2.11 §8.2.3); fails with
    /// VariableNotFound if the backend reaches no such variable.
    #[cfg_attr(
        not(any(target_os = "uefi", test)),
        allow(
            dead_code,
            reason = "only the UEFI Shell build restores a FormSet's stores"
        )
    )]
    fn delete_variable(&self, key: &VariableKey) -> Result<()>;
}

#[cfg(variable_data)]
impl<T: VariableData + ?Sized> VariableData for &T {
    fn interface(&self) -> VariableInterface {
        (**self).interface()
    }

    fn variable_data(&self, key: &VariableKey) -> Result<Option<VariableContents>> {
        (**self).variable_data(key)
    }

    fn set_variable(&self, key: &VariableKey, contents: &VariableContents) -> Result<()> {
        (**self).set_variable(key, contents)
    }

    fn delete_variable(&self, key: &VariableKey) -> Result<()> {
        (**self).delete_variable(key)
    }
}

/// What SetVariable() returned, but EFI_SUCCESS, for a Secure Boot Mode transition that the
/// firmware queues instead of making (UEFI 2.11 §32.3), which set_variable fails with so that
/// secure_boot_mode reports it as returned.
#[cfg(variable_data)]
#[cfg_attr(
    not(any(target_os = "uefi", test)),
    allow(
        dead_code,
        reason = "only SetVariable() of the UEFI Shell build returns these"
    )
)]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum SetVariableStatus {
    /// The transition is queued, and a reset processes it
    #[error("SetVariable() of EFI variable {0}: WARN_RESET_REQUIRED")]
    WarnResetRequired(VariableKey),
    /// A transition was queued already
    #[error("SetVariable() of EFI variable {0}: ALREADY_STARTED")]
    AlreadyStarted(VariableKey),
}

/// The attributes and data of an EFI variable: "A variable must contain one or more bytes of
/// Data" (UEFI 2.11 §8.2.3).
#[cfg(variable_data)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VariableContents {
    attributes: VariableAttributes,
    data: Vec<u8>,
}

#[cfg(variable_data)]
impl VariableContents {
    /// A variable of `attributes` holding `data`, unless `data` is empty.
    pub(crate) fn new(
        attributes: VariableAttributes,
        data: Vec<u8>,
    ) -> std::result::Result<Self, EmptyVariable> {
        match data.is_empty() {
            true => Err(EmptyVariable),
            false => Ok(Self { attributes, data }),
        }
    }

    pub(crate) fn attributes(&self) -> VariableAttributes {
        self.attributes
    }

    pub(crate) fn data(&self) -> &[u8] {
        &self.data
    }
}

/// Data that VariableContents refuses.
#[cfg(variable_data)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("an EFI variable holds one byte of data at least (UEFI 2.11 section 8.2.3)")]
pub(crate) struct EmptyVariable;

/// QueryVariableInfo() (UEFI 2.10 §8.2.4): the storage of the variables of some attributes.
#[cfg(variable_storage_info)]
pub(crate) trait VariableStorageInfo {
    /// The storage of the variables of `attributes`, which query_storage takes.
    fn variable_storage(&self, attributes: VariableAttributes) -> Result<VariableStorage>;
}

/// What QueryVariableInfo() tells of the storage of the variables of some attributes (UEFI 2.10
/// §8.2.4), in bytes. `variable storage` prints it as it serializes, with the attributes.
#[cfg(variable_storage_info)]
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct VariableStorage {
    /// MaximumVariableStorageSize: the storage for those variables
    pub maximum_variable_storage_size: u64,
    /// RemainingVariableStorageSize: what is left of it
    pub remaining_variable_storage_size: u64,
    /// MaximumVariableSize: the largest of those variables, if the backend tells it
    pub maximum_variable_size: Option<u64>,
}

/// The storage that `storage` tells of the variables of `attributes`, unless no variable has
/// them: "Attributes that have EFI_VARIABLE_RUNTIME_ACCESS set must also have
/// EFI_VARIABLE_BOOTSERVICE_ACCESS set. The caller is responsible for following this rule."
/// (UEFI 2.10 §8.2.3).
#[cfg(variable_storage_info)]
pub(crate) fn query_storage(
    storage: &impl VariableStorageInfo,
    attributes: VariableAttributes,
) -> Result<VariableStorage> {
    if attributes.contains(VariableAttributes::RUNTIME_ACCESS)
        && !attributes.contains(VariableAttributes::BOOTSERVICE_ACCESS)
    {
        return Err(RuntimeAccessWithoutBootServiceAccess(attributes).into());
    }
    storage.variable_storage(attributes)
}

/// Attributes that query_storage and write_signed refuse. The message spells "section", as
/// edk2's terminals but VT-UTF8 show '?' for '§' (edk2-stable202508 TerminalDxe/TerminalConOut.c
/// TerminalConOutOutputString()).
#[cfg(any(variable_storage_info, variable_data))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("{0}: runtime access implies boot service access (UEFI 2.10 section 8.2.3)")]
struct RuntimeAccessWithoutBootServiceAccess(VariableAttributes);

/// A configuration table of the EFI System Table (UEFI 2.11 §4.6), read from its VendorTable: one
/// of gST in the UEFI Shell (uefi_config_table.rs).
#[cfg(configuration_tables)]
pub(crate) trait VendorTable {
    /// The table's first `len` bytes, all of them, unless they run past the memory region that
    /// holds the table.
    fn read(&self, len: usize) -> Result<Vec<u8>>;
    /// The width of the firmware that lists the table.
    fn firmware_width(&self) -> FirmwareWidth;
}

/// The configuration data of `table`, the firmware's JSON configuration table, which the
/// firmware must list.
#[cfg(configuration_tables)]
pub(crate) fn read_json_config_data(table: Option<impl VendorTable>) -> Result<JsonConfigData> {
    let table = table.ok_or(NoJsonConfigDataTable)?;
    JsonConfigData::read(&table)
}

/// A firmware that lists no JSON configuration table, which UEFI 2.11 §4.6.1.2 does not require.
/// The message spells "section", as PayloadError's do.
#[cfg(configuration_tables)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error(
    "the firmware lists no configuration table of EFI_JSON_CONFIG_DATA_TABLE_GUID, \
     {EFI_JSON_CONFIG_DATA_TABLE_GUID} (UEFI 2.11 section 4.6.1.2)"
)]
struct NoJsonConfigDataTable;

/// The vendor GUID `vendor` that a command names, such as 8BE4DF61-93CA-11D2-AA0D-00E098032B8C.
#[cfg(any(variable_names, variable_info))]
pub(crate) fn parse_vendor(vendor: &str) -> Result<Guid> {
    vendor
        .parse()
        .with_context(|| format!("vendor {vendor} is not a GUID"))
}

#[cfg(all(
    test,
    any(variable_names, variable_info, variable_storage_info, variable_data)
))]
mod tests {
    #[cfg(configuration_tables)]
    use super::capsule::fixture::config_data;
    #[cfg(configuration_tables)]
    use super::capsule::fixture::item;
    #[cfg(configuration_tables)]
    use super::capsule::fixture::TableInRegion;
    use super::*;

    /// EFI_GLOBAL_VARIABLE, the vendor GUID of the global variables (UEFI 2.10 §3.3).
    #[cfg(any(variable_names, variable_info))]
    const EFI_GLOBAL_VARIABLE: &str = "8BE4DF61-93CA-11D2-AA0D-00E098032B8C";
    /// The formset GUID of EDK2's DriverSample, the vendor GUID of its variables.
    #[cfg(variable_names)]
    const DRIVER_SAMPLE: &str = "A04A27F4-DF00-4D42-B552-39511302113D";
    /// A vendor GUID of no variable here.
    #[cfg(variable_names)]
    const UNLISTED: &str = "00000000-0000-0000-0000-000000000001";

    /// VariableNames that reach the variables it holds.
    #[cfg(variable_names)]
    struct ListedNames(Vec<VariableKey>);

    #[cfg(variable_names)]
    impl VariableNames for ListedNames {
        fn variable_names(&self) -> Result<Vec<VariableKey>> {
            Ok(self.0.clone())
        }
    }

    /// The GUID `text`.
    #[cfg(variable_names)]
    fn guid(text: &str) -> Guid {
        text.parse()
            .unwrap_or_else(|error| panic!("parse GUID {text}: {error}"))
    }

    /// The variable `name` of the vendor GUID `vendor`.
    #[cfg(variable_names)]
    fn key(name: &str, vendor: &str) -> VariableKey {
        VariableKey {
            name: name.to_string(),
            guid: guid(vendor),
        }
    }

    /// What ScriptedNames answers to a call of GetNextVariableName().
    #[cfg(variable_names)]
    enum Answer {
        /// Writes this name, of these CHAR16, then a NUL, and this vendor
        Name(Vec<u16>, &'static str),
        /// Writes this name, of these CHAR16, filling the buffer without a NUL
        Unterminated(Vec<u16>),
        TooSmall(usize),
        End,
        Fails,
    }

    /// GetNextVariableName() that answers each call with the next of `answers`, and records the
    /// name that each call passes.
    #[cfg(variable_names)]
    struct ScriptedNames {
        answers: std::collections::VecDeque<Answer>,
        passed: Vec<Vec<u16>>,
    }

    #[cfg(variable_names)]
    impl ScriptedNames {
        fn new(answers: impl IntoIterator<Item = Answer>) -> Self {
            Self {
                answers: answers.into_iter().collect(),
                passed: Vec::new(),
            }
        }
    }

    #[cfg(variable_names)]
    impl GetNextVariableName for ScriptedNames {
        fn get_next_variable_name(
            &mut self,
            name: &mut [u16],
            vendor: &mut Guid,
        ) -> Result<NextVariableName> {
            let end = name
                .iter()
                .position(|&unit| unit == 0)
                .expect("a NUL passed");
            self.passed.push(name[..end].to_vec());
            Ok(match self.answers.pop_front().expect("an answer") {
                Answer::Name(units, guid_text) => {
                    name[..units.len()].copy_from_slice(&units);
                    name[units.len()] = 0;
                    *vendor = guid(guid_text);
                    NextVariableName::Found
                }
                Answer::Unterminated(units) => {
                    name.copy_from_slice(&units);
                    NextVariableName::Found
                }
                Answer::TooSmall(size) => NextVariableName::BufferTooSmall(size),
                Answer::End => NextVariableName::End,
                Answer::Fails => return Err(anyhow!("GetNextVariableName(): DEVICE_ERROR")),
            })
        }
    }

    /// The CHAR16 of `text`.
    #[cfg(variable_names)]
    fn char16(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    /// walk_variable_names passes each name back to get the next until EFI_NOT_FOUND, grows its
    /// buffer to the size that EFI_BUFFER_TOO_SMALL asks for and passes the same name again, and
    /// reads each surrogate code unit as U+FFFD, where two names can read alike.
    #[cfg(variable_names)]
    #[test]
    fn walk_variable_names_lists_every_variable() {
        let long = "L".repeat(600);
        let mut calls = ScriptedNames::new([
            Answer::Name(char16("Timeout"), EFI_GLOBAL_VARIABLE),
            Answer::TooSmall(601),
            Answer::Name(char16(&long), DRIVER_SAMPLE),
            Answer::Name(vec![0x41, 0xD800, 0x42, 0xDE00], EFI_GLOBAL_VARIABLE),
            // a variable of another name, which reads alike
            Answer::Name(vec![0x41, 0xD801, 0x42, 0xDE00], EFI_GLOBAL_VARIABLE),
            Answer::End,
        ]);

        let keys = walk_variable_names(&mut calls).expect("walk the variables");

        assert_eq!(
            keys,
            [
                key("Timeout", EFI_GLOBAL_VARIABLE),
                key(&long, DRIVER_SAMPLE),
                key("A\u{fffd}B\u{fffd}", EFI_GLOBAL_VARIABLE),
                key("A\u{fffd}B\u{fffd}", EFI_GLOBAL_VARIABLE),
            ],
            "keys"
        );
        assert_eq!(
            calls.passed,
            [
                vec![],
                char16("Timeout"),
                char16("Timeout"),
                char16(&long),
                vec![0x41, 0xD800, 0x42, 0xDE00],
                vec![0x41, 0xD801, 0x42, 0xDE00],
            ],
            "names passed"
        );
    }

    /// walk_variable_names fails where a call fails, asks for no larger buffer, gives a name
    /// without its NUL, or gives a variable again.
    #[cfg(variable_names)]
    #[test]
    fn walk_variable_names_refuses_what_it_cannot_list() {
        for (answer, refusal) in [
            (
                Answer::Fails,
                "GetNextVariableName(): DEVICE_ERROR".to_string(),
            ),
            (
                Answer::TooSmall(512),
                "GetNextVariableName() asked for 512 CHAR16, which its buffer of 512 holds"
                    .to_string(),
            ),
            (
                Answer::Unterminated(vec![0x41; 512]),
                "GetNextVariableName() gave a name without its NUL".to_string(),
            ),
            (
                Answer::Name(char16("Timeout"), EFI_GLOBAL_VARIABLE),
                "GetNextVariableName() returned EFI variable \
                 Timeout-8be4df61-93ca-11d2-aa0d-00e098032b8c twice"
                    .to_string(),
            ),
        ] {
            let mut calls = ScriptedNames::new([
                Answer::Name(char16("Timeout"), EFI_GLOBAL_VARIABLE),
                answer,
                Answer::End,
            ]);

            let error = walk_variable_names(&mut calls).expect_err("walk to a refusal");

            assert_eq!(error.to_string(), refusal, "{refusal}");
        }
    }

    #[cfg(variable_names)]
    #[test]
    fn list_variables_sorts_and_keeps_only_the_vendor_asked() {
        let names = ListedNames(vec![
            key("Timeout", EFI_GLOBAL_VARIABLE),
            key("MyIfrNVData", DRIVER_SAMPLE),
            key("BootOrder", EFI_GLOBAL_VARIABLE),
            key("Timeout", DRIVER_SAMPLE),
        ]);
        let cases = [
            (
                "every vendor",
                None,
                vec![
                    key("BootOrder", EFI_GLOBAL_VARIABLE),
                    key("MyIfrNVData", DRIVER_SAMPLE),
                    key("Timeout", EFI_GLOBAL_VARIABLE),
                    key("Timeout", DRIVER_SAMPLE),
                ],
            ),
            (
                "EFI_GLOBAL_VARIABLE",
                Some(EFI_GLOBAL_VARIABLE),
                vec![
                    key("BootOrder", EFI_GLOBAL_VARIABLE),
                    key("Timeout", EFI_GLOBAL_VARIABLE),
                ],
            ),
            ("a vendor of no variable", Some(UNLISTED), vec![]),
        ];

        for (case, vendor, want) in cases {
            let keys = list_variables(&names, vendor.map(guid)).expect("list the variables");

            assert_eq!(keys, want, "{case}");
        }
    }

    /// VariableStorageInfo that tells `storage` and records the attributes asked.
    #[cfg(variable_storage_info)]
    struct RecordedStorage {
        storage: VariableStorage,
        asked: std::cell::RefCell<Vec<VariableAttributes>>,
    }

    #[cfg(variable_storage_info)]
    impl VariableStorageInfo for RecordedStorage {
        fn variable_storage(&self, attributes: VariableAttributes) -> Result<VariableStorage> {
            self.asked.borrow_mut().push(attributes);
            Ok(self.storage)
        }
    }

    /// query_storage asks the backend of attributes that variables can have, runtime access
    /// with boot service access among them, and refuses runtime access without it unasked.
    #[cfg(variable_storage_info)]
    #[test]
    fn query_storage_refuses_runtime_access_without_boot_service_access() {
        let backend = RecordedStorage {
            storage: VariableStorage {
                maximum_variable_storage_size: 100,
                remaining_variable_storage_size: 40,
                maximum_variable_size: Some(30),
            },
            asked: std::cell::RefCell::default(),
        };
        let nv = VariableAttributes::NON_VOLATILE;
        let bs = VariableAttributes::BOOTSERVICE_ACCESS;
        let rt = VariableAttributes::RUNTIME_ACCESS;
        for attributes in [nv | bs | rt, bs | rt, nv | bs, bs] {
            assert_eq!(
                query_storage(&backend, attributes).expect("query the storage"),
                backend.storage,
                "{attributes}"
            );
        }
        for (attributes, refusal) in [
            (
                rt,
                "RUNTIME_ACCESS: runtime access implies boot service access (UEFI 2.10 section \
                 8.2.3)",
            ),
            (
                nv | rt,
                "NON_VOLATILE | RUNTIME_ACCESS: runtime access implies boot service access \
                 (UEFI 2.10 section 8.2.3)",
            ),
        ] {
            let error = query_storage(&backend, attributes).expect_err("query a refused storage");

            assert_eq!(error.to_string(), refusal, "{attributes}");
        }
        assert_eq!(
            backend.asked.into_inner(),
            [nv | bs | rt, bs | rt, nv | bs, bs],
            "attributes asked"
        );
    }

    #[cfg(variable_data)]
    #[test]
    fn variable_contents_hold_one_byte_at_least() {
        let attributes = VariableAttributes::NON_VOLATILE | VariableAttributes::BOOTSERVICE_ACCESS;

        let contents = VariableContents::new(attributes, vec![0]).expect("hold one byte");

        assert_eq!(
            (contents.attributes(), contents.data()),
            (attributes, &[0][..]),
            "one byte"
        );
        assert_eq!(
            VariableContents::new(attributes, Vec::new()),
            Err(EmptyVariable),
            "no byte"
        );
    }

    #[cfg(any(variable_names, variable_info))]
    #[test]
    fn parse_vendor_takes_either_case_and_names_a_vendor_that_is_no_guid() {
        for vendor in [
            EFI_GLOBAL_VARIABLE.to_string(),
            EFI_GLOBAL_VARIABLE.to_ascii_lowercase(),
        ] {
            assert_eq!(
                parse_vendor(&vendor).expect("parse the vendor").to_string(),
                EFI_GLOBAL_VARIABLE,
                "{vendor}"
            );
        }

        let error = parse_vendor("8BE4DF61-93CA-11D2-AA0D").expect_err("parse a short vendor");

        assert_eq!(
            format!("{error:#}"),
            "vendor 8BE4DF61-93CA-11D2-AA0D is not a GUID: GUID string has wrong length \
             (expected 36 bytes)",
            "short vendor"
        );
    }

    /// VariableInfo serializes as `variable info` prints it: the variable, its attributes and the
    /// size of its data.
    #[cfg(variable_info)]
    #[test]
    fn variable_info_serializes_as_info_prints_it() {
        let info = VariableInfo {
            variable: "MyIfrNVData-a04a27f4-df00-4d42-b552-39511302113d".to_string(),
            attributes: 7,
            size: 220,
        };

        assert_eq!(
            serde_json::to_value(&info).expect("serialize the info"),
            serde_json::json!({
                "variable": "MyIfrNVData-a04a27f4-df00-4d42-b552-39511302113d",
                "attributes": 7,
                "size": 220,
            }),
            "{info:?}"
        );
    }

    /// VariableStorage serializes as `variable storage` prints it, the maximum variable size as
    /// null where the backend does not tell it.
    #[cfg(variable_storage_info)]
    #[test]
    fn variable_storage_serializes_as_storage_prints_it() {
        for (maximum_variable_size, want) in [
            (Some(30), serde_json::json!(30)),
            (None, serde_json::Value::Null),
        ] {
            let storage = VariableStorage {
                maximum_variable_storage_size: 100,
                remaining_variable_storage_size: 40,
                maximum_variable_size,
            };

            assert_eq!(
                serde_json::to_value(storage).expect("serialize the storage"),
                serde_json::json!({
                    "maximum_variable_storage_size": 100,
                    "remaining_variable_storage_size": 40,
                    "maximum_variable_size": want,
                }),
                "{storage:?}"
            );
        }
    }

    /// read_json_config_data decodes the table that the firmware lists, and names the GUID of
    /// the one that it does not list.
    #[cfg(configuration_tables)]
    #[test]
    fn read_json_config_data_names_a_missing_table() {
        let listed = TableInRegion::new(config_data(1, 13, &item(b"{")));

        let data = read_json_config_data(Some(listed)).expect("read a listed table");

        assert_eq!(data.items, [b"{".to_vec()], "listed");

        let error = read_json_config_data(None::<TableInRegion>).expect_err("read no table");

        assert_eq!(
            error.to_string(),
            "the firmware lists no configuration table of EFI_JSON_CONFIG_DATA_TABLE_GUID, \
             87367F87-1119-41CE-AAEC-8BE0111F558A (UEFI 2.11 section 4.6.1.2)",
            "no table"
        );
    }
}
