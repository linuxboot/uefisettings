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

//! The firmware variables that questions read and set, whatever holds them: efivarfs on Linux
//! (efivarfs.rs), GetVariable() and SetVariable() in the UEFI Shell (variable_services.rs),
//! and GetFirmwareEnvironmentVariableExW and SetFirmwareEnvironmentVariableExW on Windows
//! (firmware_environment.rs).

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;
use std::ops::Range;
use std::path::Path;
use std::rc::Rc;

#[cfg(any(system_variables, test))]
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use thiserror::Error;

use crate::efi_variables::enhanced_authenticated::has_metadata;
use crate::efi_variables::enhanced_authenticated::metadata_end;
use crate::efi_variables::enhanced_authenticated::MetadataRefusal;
use crate::hii::config_snapshot::SnapshotLookup;
#[cfg(all(efivar_dumps, not(system_variables)))]
use crate::hii::efivarfs_format::EfivarCopy;
use crate::hii::package::Guid;
use crate::hii::time_services::TimeServices;

/// The size of the attributes word that FirmwareVariables::read gives before the data, as
/// efivarfs does.
pub(super) const EFIVARFS_HEADER_SIZE: usize = std::mem::size_of::<u32>();
const EFI_VARIABLE_NON_VOLATILE: u32 = VariableAttributes::NON_VOLATILE.bits();
pub(super) const EFI_VARIABLE_RUNTIME_ACCESS: u32 = VariableAttributes::RUNTIME_ACCESS.bits();
/// EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS (UEFI 2.10 §8.2.1)
const EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS: u32 =
    VariableAttributes::ENHANCED_AUTHENTICATED_ACCESS.bits();
/// EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS, EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS
/// and EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS (UEFI 2.10 §8.2.1)
const EFI_VARIABLE_AUTHENTICATED_ACCESS: u32 = VariableAttributes::AUTHENTICATED_WRITE_ACCESS
    .union(VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS)
    .bits()
    | EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS;
/// Every value byte of a variable.
const WHOLE_VALUE: &Range<usize> = &(0..usize::MAX);

bitflags::bitflags! {
    /// The attributes of an EFI variable (UEFI 2.10 §8.2.1).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct VariableAttributes: u32 {
        const NON_VOLATILE = 0x0000_0001;
        const BOOTSERVICE_ACCESS = 0x0000_0002;
        const RUNTIME_ACCESS = 0x0000_0004;
        const HARDWARE_ERROR_RECORD = 0x0000_0008;
        const AUTHENTICATED_WRITE_ACCESS = 0x0000_0010;
        const TIME_BASED_AUTHENTICATED_WRITE_ACCESS = 0x0000_0020;
        const APPEND_WRITE = 0x0000_0040;
        const ENHANCED_AUTHENTICATED_ACCESS = 0x0000_0080;
    }
}

/// The names of the attributes, such as NON_VOLATILE | BOOTSERVICE_ACCESS, and any bits besides
/// them in hex, or "no attributes".
impl fmt::Display for VariableAttributes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.is_empty() {
            true => f.write_str("no attributes"),
            false => bitflags::parser::to_writer(self, f),
        }
    }
}

/// A firmware variable: its name and vendor GUID (UEFI 2.10 §8.2.1).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VariableKey {
    pub name: String,
    pub guid: Guid,
}

#[cfg(variable_names)]
impl VariableKey {
    /// The variable of the CHAR16 `name` and the vendor `guid`: "all characters and strings are
    /// stored in the UCS-2 encoding format" (UEFI 2.11 §2.3.1), which holds no surrogate code
    /// unit, so each surrogate here becomes U+FFFD.
    pub(crate) fn from_ucs2(name: &[u16], guid: Guid) -> Self {
        Self {
            name: name
                .iter()
                .map(|&unit| char::from_u32(u32::from(unit)).unwrap_or(char::REPLACEMENT_CHARACTER))
                .collect(),
            guid,
        }
    }
}

/// `<name>-<lowercase GUID>` with '!' for each '/', as Linux v7.2 fs/efivarfs/vars.c
/// efivar_get_utf8name() names a variable's file.
impl fmt::Display for VariableKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}-{}",
            self.name.replace('/', "!"),
            self.guid.to_string().to_ascii_lowercase()
        )
    }
}

/// The name of the efivar file of a variable, as VariableKey displays it: always exactly one path
/// component.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) struct EfivarFileName(String);

impl From<&VariableKey> for EfivarFileName {
    fn from(key: &VariableKey) -> Self {
        Self(key.to_string())
    }
}

impl AsRef<Path> for EfivarFileName {
    fn as_ref(&self) -> &Path {
        Path::new(&self.0)
    }
}

impl fmt::Display for EfivarFileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which variables FirmwareVariables reach: after ExitBootServices, as through efivarfs,
/// GetVariable, GetNextVariableName and SetVariable reach only those with
/// EFI_VARIABLE_RUNTIME_ACCESS; before it, as in the UEFI Shell, all (UEFI 2.10 §8.2.1-§8.2.3).
/// Decisions on runtime access take this, never the VariableInterface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VariableReach {
    #[cfg_attr(
        target_os = "uefi",
        allow(dead_code, reason = "no UEFI Shell variables reach Runtime")
    )]
    Runtime,
    #[cfg_attr(
        not(target_os = "uefi"),
        allow(dead_code, reason = "only UEFI Shell variables reach BootServices")
    )]
    BootServices,
}

/// Whether set writes a variable without EFI_VARIABLE_NON_VOLATILE, whose value does not outlast
/// a power cycle and which SetVariable() sets only before ExitBootServices (UEFI 2.11 §8.2.3), so
/// only through variables that reach BootServices.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum VolatileWrites {
    /// Refuse it
    #[default]
    Refuse,
    /// Write it through variables that reach BootServices; through others, refuse it
    Allow,
}

/// The suffix of set's answer for a question that wrote a volatile variable (UEFI 2.11 §8.2.3).
pub(crate) const VOLATILE_ANNOTATION: &str =
    " <volatile: lasts until the next reset or power cycle>";

/// The interface through which FirmwareVariables read and write variables, which their error
/// texts name; it decides no runtime access, which VariableReach does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum VariableInterface {
    /// Linux's efivarfs, and copies of it (efivarfs.rs, efivarfs_format.rs)
    #[cfg_attr(
        any(target_os = "uefi", target_os = "windows"),
        allow(
            dead_code,
            reason = "the UEFI Shell and Windows builds read no efivarfs"
        )
    )]
    Efivarfs,
    /// GetVariable() and SetVariable() in the UEFI Shell (variable_services.rs)
    #[cfg_attr(
        not(target_os = "uefi"),
        allow(dead_code, reason = "only the UEFI Shell build calls GetVariable()")
    )]
    VariableServices,
    /// GetFirmwareEnvironmentVariableExW and SetFirmwareEnvironmentVariableExW on Windows
    /// (firmware_environment.rs)
    #[cfg_attr(
        not(target_os = "windows"),
        allow(
            dead_code,
            reason = "only the Windows build calls the firmware environment calls"
        )
    )]
    FirmwareEnvironment,
}

/// The texts of errors about variables of each interface.
impl VariableInterface {
    /// What errors call the data bytes of a variable, which follow its attributes word.
    #[cfg(any(system_variables, test))]
    fn data(self) -> &'static str {
        match self {
            Self::Efivarfs => "efivarfs payload",
            Self::VariableServices => "GetVariable() data",
            Self::FirmwareEnvironment => "GetFirmwareEnvironmentVariableExW payload",
        }
    }

    /// The error for variable bytes without their whole attributes word.
    fn missing_attributes(self) -> &'static str {
        match self {
            Self::Efivarfs => "efivarfs file is missing its attributes header",
            Self::VariableServices => "variable bytes are missing their attributes word",
            Self::FirmwareEnvironment => {
                "GetFirmwareEnvironmentVariableExW data is missing its attributes word"
            }
        }
    }

    /// What errors call a write of a question's value.
    pub(super) fn write(self) -> &'static str {
        match self {
            Self::Efivarfs => "efivarfs write",
            Self::VariableServices => "SetVariable() write",
            Self::FirmwareEnvironment => "SetFirmwareEnvironmentVariableExW write",
        }
    }

    /// Why set refuses a volatile variable, after its name.
    fn volatile_refusal(self) -> &'static str {
        match self {
            Self::Efivarfs => " and cannot be written through efivarfs",
            Self::VariableServices => {
                ", so a write would not outlast a power cycle; pass --allow-volatile to write it \
                 anyway"
            }
            Self::FirmwareEnvironment => ", so a write would not outlast a power cycle",
        }
    }

    /// Why set cannot write a variable that does not exist, after its VariableNotFound.
    pub(super) fn not_found_refusal(self) -> &'static str {
        match self {
            Self::Efivarfs => {
                "the firmware has not created it or does not expose it to the OS, so its \
                 questions cannot be set from Linux; change them in the firmware setup, or ask \
                 the board vendor for firmware that exposes it; see \
                 https://github.com/linuxboot/uefisettings/issues/2"
            }
            Self::VariableServices => {
                "the firmware has not created it, and set creates only the per-question variables \
                 of an EFI_IFR_VARSTORE_EFI before UEFI 2.3.1"
            }
            Self::FirmwareEnvironment => {
                "the firmware has not created it or does not expose it to the OS, so its \
                 questions cannot be set from Windows; change them in the firmware setup, or ask \
                 the board vendor for firmware that exposes it; see \
                 https://github.com/linuxboot/uefisettings/issues/2"
            }
        }
    }

    /// Why set creates no missing per-question variable through this interface, after the
    /// variable, if it does not: it creates one through efivarfs, where writing a new file creates
    /// the variable (Linux v6.11 fs/efivarfs/inode.c efivarfs_create()), and through
    /// SetVariable() (UEFI 2.11 §8.2.3), but not through SetFirmwareEnvironmentVariableExW.
    pub(super) fn creation_refusal(self) -> Option<&'static str> {
        match self {
            Self::Efivarfs | Self::VariableServices => None,
            Self::FirmwareEnvironment => {
                Some("which set does not create through SetFirmwareEnvironmentVariableExW")
            }
        }
    }

    /// How this interface lacks a variable that is not present at OS runtime.
    pub(super) fn absence(self) -> &'static str {
        match self {
            Self::Efivarfs => "efivarfs does not list it",
            Self::VariableServices => "GetVariable() does not find it",
            Self::FirmwareEnvironment => "GetFirmwareEnvironmentVariableExW does not find it",
        }
    }
}

/// The firmware variables that questions read and set: efivarfs on Linux, GetVariable/SetVariable
/// in the UEFI Shell, and GetFirmwareEnvironmentVariableExW/SetFirmwareEnvironmentVariableExW
/// on Windows, the third implementation, in firmware_environment.rs.
/// A variable that does not exist is VariableNotFound, which get shows as missing and set
/// explains.
pub(crate) trait FirmwareVariables {
    /// Which variables these reach.
    fn reach(&self) -> VariableReach;
    /// The interface that these read and write through, which their errors name.
    fn interface(&self) -> VariableInterface;
    /// Whether these read and write no variable at all, as those of EfivarSource::Disabled.
    fn reads_nothing(&self) -> bool {
        false
    }
    /// The attributes word and the first `size` data bytes of `key`, as an efivarfs file starts.
    fn read(&self, key: &VariableKey, size: u16) -> Result<Vec<u8>>;
    /// The attributes word and all the data of `key`, as its efivarfs file holds them.
    fn read_whole(&self, key: &VariableKey) -> Result<Vec<u8>>;
    /// Writes `patches`, in order, at their data offsets of `key`, whose VarStore has `size`
    /// bytes, in one write of the variable, keeping its attributes and the bytes that no patch
    /// changes as the variable holds them, a SetVariable() of a non-volatile variable saving all of
    /// its data or none (UEFI 2.11 §8.2.3); a volatile `key` only as `volatile` allows
    /// (check_volatile_write); a missing `key` as `missing` says.
    fn write_patches(
        &self,
        key: &VariableKey,
        size: u16,
        patches: &[DataPatch<'_>],
        volatile: VolatileWrites,
        missing: MissingVariable,
    ) -> Result<()>;
}

/// What FirmwareVariables::write_patches does where its variable is missing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MissingVariable {
    /// Fails with VariableNotFound
    Refuse,
    /// Creates it with these attributes, of the data bytes that the patches write
    /// (created_variable_bytes)
    Create(u32),
}

/// `bytes` that a write puts at data offset `offset` of a variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DataPatch<'a> {
    pub(crate) offset: u16,
    pub(crate) bytes: &'a [u8],
}

impl DataPatch<'_> {
    /// The data bytes that the patch changes.
    pub(crate) fn range(&self) -> Range<usize> {
        usize::from(self.offset)..usize::from(self.offset) + self.bytes.len()
    }
}

impl<T: FirmwareVariables + ?Sized> FirmwareVariables for &T {
    fn reach(&self) -> VariableReach {
        (**self).reach()
    }

    fn interface(&self) -> VariableInterface {
        (**self).interface()
    }

    fn reads_nothing(&self) -> bool {
        (**self).reads_nothing()
    }

    fn read(&self, key: &VariableKey, size: u16) -> Result<Vec<u8>> {
        (**self).read(key, size)
    }

    fn read_whole(&self, key: &VariableKey) -> Result<Vec<u8>> {
        (**self).read_whole(key)
    }

    fn write_patches(
        &self,
        key: &VariableKey,
        size: u16,
        patches: &[DataPatch<'_>],
        volatile: VolatileWrites,
        missing: MissingVariable,
    ) -> Result<()> {
        (**self).write_patches(key, size, patches, volatile, missing)
    }
}

impl<T: FirmwareVariables + ?Sized> FirmwareVariables for Box<T> {
    fn reach(&self) -> VariableReach {
        (**self).reach()
    }

    fn interface(&self) -> VariableInterface {
        (**self).interface()
    }

    fn reads_nothing(&self) -> bool {
        (**self).reads_nothing()
    }

    fn read(&self, key: &VariableKey, size: u16) -> Result<Vec<u8>> {
        (**self).read(key, size)
    }

    fn read_whole(&self, key: &VariableKey) -> Result<Vec<u8>> {
        (**self).read_whole(key)
    }

    fn write_patches(
        &self,
        key: &VariableKey,
        size: u16,
        patches: &[DataPatch<'_>],
        volatile: VolatileWrites,
        missing: MissingVariable,
    ) -> Result<()> {
        (**self).write_patches(key, size, patches, volatile, missing)
    }
}

/// The attribute word of efivar file bytes, which Linux v7.2 fs/efivarfs/file.c
/// efivarfs_file_read() copies as a native u32 before the payload; None for fewer bytes.
pub(super) fn efivar_attributes(bytes: &[u8]) -> Option<u32> {
    efivar_parts(bytes).map(|(attributes, _)| attributes)
}

/// The attribute word of efivar file bytes and the payload after it; None for fewer bytes than
/// the word.
pub(super) fn efivar_parts(bytes: &[u8]) -> Option<(u32, &[u8])> {
    bytes
        .split_first_chunk::<EFIVARFS_HEADER_SIZE>()
        .map(|(attributes, data)| (u32::from_ne_bytes(*attributes), data))
}

/// What FirmwareVariables::read gives for the variable `key` whose GetVariable() returned
/// `attributes` and `data`: the attributes word and the first `size` data bytes, as an efivarfs
/// file starts.
pub(super) fn attributes_and_data(
    key: &VariableKey,
    attributes: u32,
    data: &[u8],
    size: u16,
) -> Result<Vec<u8>> {
    let data = data.get(..usize::from(size)).with_context(|| {
        format!(
            "EFI variable {key} holds {} data bytes, fewer than the {size} of its VarStore",
            data.len()
        )
    })?;
    Ok([&attributes.to_ne_bytes()[..], data].concat())
}

/// The read-modify-write of FirmwareVariables::write_patches on `bytes`, the attributes word and
/// all the data of variable `key`, which `variables` hold: refuses an authenticated variable, and
/// a volatile one unless `volatile` allows it (check_volatile_write), then writes each of
/// `patches`, in order, as update_efivarfs_bytes does.
// set writes this machine's variables; the tests' MemoryVariables write on any build
#[cfg(any(system_variables, test))]
pub(super) fn modify_variable_bytes(
    variables: &dyn FirmwareVariables,
    key: &VariableKey,
    volatile: VolatileWrites,
    bytes: &mut [u8],
    size: u16,
    patches: &[DataPatch<'_>],
) -> Result<()> {
    let interface = variables.interface();
    let attributes = efivar_attributes(bytes).context(interface.missing_attributes())?;
    check_volatile_write(key, interface, variables.reach(), volatile, attributes)?;
    check_unauthenticated(key, attributes)?;
    patches.iter().try_for_each(|patch| {
        update_efivarfs_bytes(interface, bytes, size, patch.offset, patch.bytes)
    })
}

/// The bytes of the efivar file that FirmwareVariables::write_patches creates for the missing
/// variable `key` of `variables` with `attributes`: its `size` data bytes, each of which one of
/// `patches` writes, so that the variable holds no byte that nobody set. It refuses `attributes`
/// as modify_variable_bytes refuses those of an existing variable.
// efivarfs and Variable Services create variables; the tests' MemoryVariables do on any build
#[cfg(any(target_os = "linux", target_os = "uefi", test))]
pub(super) fn created_variable_bytes(
    variables: &dyn FirmwareVariables,
    key: &VariableKey,
    volatile: VolatileWrites,
    attributes: u32,
    size: u16,
    patches: &[DataPatch<'_>],
) -> Result<Vec<u8>> {
    let mut bytes = [&attributes.to_ne_bytes()[..], &vec![0; usize::from(size)]].concat();
    modify_variable_bytes(variables, key, volatile, &mut bytes, size, patches)?;
    let unwritten = (0..usize::from(size))
        .find(|byte| !patches.iter().any(|patch| patch.range().contains(byte)));
    match unwritten {
        Some(byte) => Err(UnwrittenCreation {
            key: key.clone(),
            byte,
            size,
        }
        .into()),
        None => Ok(bytes),
    }
}

/// A variable that FirmwareVariables::write_patches does not create: no patch writes its data
/// byte `byte`.
#[cfg(any(target_os = "linux", target_os = "uefi", test))]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "EFI variable {key} is missing, and no patch writes its data byte {byte} of {size}, so set \
     does not create it"
)]
struct UnwrittenCreation {
    key: VariableKey,
    byte: usize,
    size: u16,
}

/// Writes `encoded` at VarOffset `offset` of the efivar file `bytes`, unless its payload is
/// shorter than the `payload_size` bytes of its VarStore, which VarStoreWrite::new fits the
/// write in. Errors word it as variables of `interface` hold it.
#[cfg(any(system_variables, test))]
fn update_efivarfs_bytes(
    interface: VariableInterface,
    bytes: &mut [u8],
    payload_size: u16,
    offset: u16,
    encoded: &[u8],
) -> Result<()> {
    let payload = bytes
        .get_mut(EFIVARFS_HEADER_SIZE..)
        .context(interface.missing_attributes())?;
    if payload.len() < usize::from(payload_size) {
        return Err(anyhow!(
            "{} is shorter than the declared varstore: {} < {} bytes",
            interface.data(),
            payload.len(),
            payload_size
        ));
    }

    let start = usize::from(offset);
    payload
        .get_mut(start..start + encoded.len())
        .with_context(|| format!("write past the {}", interface.data()))?
        .copy_from_slice(encoded);
    Ok(())
}

/// Refuses an EFI variable without EFI_VARIABLE_NON_VOLATILE, which efivarfs cannot write
/// (UEFI 2.10 §8.2.3) and a power cycle would erase; errors word it as variables of `interface`
/// hold it.
/// Takes the variable's own attribute word, which its write passes to SetVariable(), not
/// VARSTORE_EFI's Attributes, as check_runtime_writable does.
pub(super) fn check_non_volatile(
    key: &VariableKey,
    interface: VariableInterface,
    attributes: u32,
) -> std::result::Result<(), VolatileVariable> {
    if is_volatile(attributes) {
        return Err(VolatileVariable {
            key: key.clone(),
            interface,
        });
    }
    Ok(())
}

/// Whether a variable of the attribute word `attributes` is volatile: without
/// EFI_VARIABLE_NON_VOLATILE, its value does not outlast a power cycle (UEFI 2.11 §8.2.3).
pub(super) fn is_volatile(attributes: u32) -> bool {
    attributes & EFI_VARIABLE_NON_VOLATILE == 0
}

/// check_non_volatile, unless `volatile` allows writing a volatile variable and `reach` is
/// BootServices: SetVariable() sets a volatile variable only before ExitBootServices (UEFI 2.11
/// §8.2.3).
pub(super) fn check_volatile_write(
    key: &VariableKey,
    interface: VariableInterface,
    reach: VariableReach,
    volatile: VolatileWrites,
    attributes: u32,
) -> std::result::Result<(), VolatileVariable> {
    match (reach, volatile) {
        (VariableReach::BootServices, VolatileWrites::Allow) => Ok(()),
        (VariableReach::BootServices, VolatileWrites::Refuse)
        | (VariableReach::Runtime, VolatileWrites::Refuse | VolatileWrites::Allow) => {
            check_non_volatile(key, interface, attributes)
        }
    }
}

/// An EFI variable without EFI_VARIABLE_NON_VOLATILE, which set refuses.
#[derive(Error, Debug)]
#[error(
    "EFI variable {key} is volatile (no EFI_VARIABLE_NON_VOLATILE){}",
    .interface.volatile_refusal()
)]
pub(super) struct VolatileVariable {
    key: VariableKey,
    interface: VariableInterface,
}

/// Refuses, for variables of `reach` Runtime, an EFI variable whose own `attributes`
/// word lacks EFI_VARIABLE_RUNTIME_ACCESS: after ExitBootServices, edk2-stable202608 refuses to
/// write an existing variable without it, VariableServiceSetVariable with EFI_WRITE_PROTECTED
/// and UpdateVariable with EFI_INVALID_PARAMETER.
pub(super) fn check_runtime_writable(
    key: &VariableKey,
    reach: VariableReach,
    attributes: u32,
) -> std::result::Result<(), BootServiceOnlyVariable> {
    match reach {
        VariableReach::Runtime if attributes & EFI_VARIABLE_RUNTIME_ACCESS == 0 => {
            Err(BootServiceOnlyVariable {
                key: key.clone(),
                attributes,
            })
        }
        VariableReach::Runtime | VariableReach::BootServices => Ok(()),
    }
}

/// An EFI variable without EFI_VARIABLE_RUNTIME_ACCESS, which set refuses through variables that
/// reach Runtime.
#[derive(Error, Debug)]
#[error(
    "EFI variable {key} has no EFI_VARIABLE_RUNTIME_ACCESS (attributes {attributes:#x}), so the \
     firmware refuses to write it at OS runtime"
)]
pub(super) struct BootServiceOnlyVariable {
    key: VariableKey,
    attributes: u32,
}

/// Refuses an EFI variable with authenticated access, which its `attributes` word names: every
/// write of it needs a signed descriptor (UEFI 2.10 §8.2.3).
pub(super) fn check_unauthenticated(
    key: &VariableKey,
    attributes: u32,
) -> std::result::Result<(), AuthenticatedVariable> {
    if attributes & EFI_VARIABLE_AUTHENTICATED_ACCESS != 0 {
        return Err(AuthenticatedVariable {
            key: key.clone(),
            attributes,
        });
    }
    Ok(())
}

/// An EFI variable with authenticated access, which set refuses.
#[derive(Error, Debug)]
#[error(
    "EFI variable {key} has authenticated access (attributes {attributes:#x}), which \
     uefisettings does not write"
)]
pub(super) struct AuthenticatedVariable {
    key: VariableKey,
    attributes: u32,
}

/// The value of the variable `key` in `data`, its GetVariable() data: the bytes after the
/// metadata that metadata_end finds by its `attributes`.
fn value_of<'a>(
    key: &VariableKey,
    attributes: u32,
    data: &'a [u8],
) -> std::result::Result<&'a [u8], EnhancedAuthenticatedVariable> {
    metadata_end(attributes, data)
        .and_then(|end| data.get(end..).ok_or(MetadataRefusal::truncated(data)))
        .map_err(|reason| EnhancedAuthenticatedVariable {
            key: key.clone(),
            attributes,
            reason,
        })
}

/// An EFI variable with EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS whose metadata metadata_end
/// refuses, so questions decode no value from it.
#[derive(Error, Debug, Clone)]
#[error(
    "EFI variable {key} has enhanced authenticated access (attributes {attributes:#x}), whose \
     metadata uefisettings refuses: {reason}"
)]
pub(super) struct EnhancedAuthenticatedVariable {
    key: VariableKey,
    pub(super) attributes: u32,
    reason: MetadataRefusal,
}

/// FirmwareVariables::read of the attributes word and the first `size` bytes of the value of
/// `key`, or under VariableLayout::OneValue its whole value, which must be `size` bytes: for a
/// variable whose data has_metadata, those after its metadata (value_of), which it reads whole to
/// find.
fn read_value_bytes(
    variables: &dyn FirmwareVariables,
    key: &VariableKey,
    size: u16,
    layout: VariableLayout,
) -> Result<Vec<u8>> {
    match layout {
        VariableLayout::Offsets => {}
        VariableLayout::OneValue => {
            let whole = variables.read_whole(key)?;
            let (attributes, data) =
                efivar_parts(&whole).context(variables.interface().missing_attributes())?;
            let value = value_of(key, attributes, data)?;
            if value.len() != usize::from(size) {
                return Err(VariableSizeMismatch {
                    key: key.clone(),
                    held: value.len(),
                    width: size,
                }
                .into());
            }
            return Ok([&attributes.to_ne_bytes()[..], value].concat());
        }
    }
    let bytes = variables.read(key, size)?;
    match efivar_attributes(&bytes).map(has_metadata) {
        Some(Ok(false)) | None => return Ok(bytes),
        // value_of finds the metadata, or refuses it, in the whole variable
        Some(Ok(true) | Err(_)) => {}
    }
    // attributes, metadata and value from one read
    let whole = variables.read_whole(key)?;
    let (attributes, data) =
        efivar_parts(&whole).context(variables.interface().missing_attributes())?;
    attributes_and_data(key, attributes, value_of(key, attributes, data)?, size)
}

/// A variable that FirmwareVariables does not hold.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("no EFI variable {0}")]
pub(crate) struct VariableNotFound(pub(crate) VariableKey);

/// A variable of VariableLayout::OneValue whose value is not as wide as its question's, which get
/// and set refuse. UEFI 2.11 §33.2.5.4.10 requires that size of a cross-reference question's
/// EFI_HII_REF; for other questions edk2-stable202608 SetupBrowserDxe/Setup.c GetQuestionValue
/// instead reads the bytes of a smaller one and ignores the EFI_BUFFER_TOO_SMALL (UEFI 2.11
/// §8.2.1) of a larger one (:1772-1782).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("EFI variable {key} holds {held} bytes; the question takes {width}")]
pub(super) struct VariableSizeMismatch {
    pub(super) key: VariableKey,
    pub(super) held: usize,
    pub(super) width: u16,
}

/// Where question values are read: the variables of this machine, a directory of efivar files,
/// or none.
// Each backend makes the variables of a source in EfivarSource::into_variables: efivarfs.rs,
// variable_services.rs, firmware_environment.rs; a build without variables of its own makes them
// below.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub enum EfivarSource {
    /// This machine's variables: its efivarfs on Linux, GetVariable() in the UEFI Shell,
    /// GetFirmwareEnvironmentVariableExW on Windows, where opening them enables the
    /// SeSystemEnvironmentPrivilege, so that a process that is not elevated fails there before
    /// any read, even for a HiiDB whose questions read no variable. On Linux on x86 and arm64,
    /// get, list-questions and show-ifr also take the values of the variables that it lacks
    /// from the ExportConfig snapshot that the configuration table lists (UEFI 2.11 §33.2.11.1),
    /// read from physical memory.
    #[cfg(system_variables)]
    #[default]
    System,
    /// A directory of efivar files in efivarfs format, such as a copy of another machine's.
    #[cfg(efivar_dumps)]
    Directory(std::path::PathBuf),
    /// No variables: each value shows as unavailable (get and list-questions add its IFR
    /// default) and conditions on values stay undetermined.
    #[cfg_attr(not(system_variables), default)]
    Disabled,
}

impl EfivarSource {
    /// Fails if this is a Directory that is not a directory: every efivar file in it would read
    /// as missing, or fail to open.
    pub fn validate(&self) -> Result<()> {
        match self {
            #[cfg(system_variables)]
            Self::System => Ok(()),
            Self::Disabled => Ok(()),
            #[cfg(efivar_dumps)]
            Self::Directory(dir) => match std::fs::metadata(dir) {
                Ok(metadata) if metadata.is_dir() => Ok(()),
                Ok(_) => Err(EfivarsNotADirectory(dir.clone()).into()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    Err(EfivarsNotADirectory(dir.clone()).into())
                }
                Err(error) => Err(anyhow::Error::new(error).context(format!(
                    "failed to stat efivars directory {}",
                    dir.display()
                ))),
            },
        }
    }
}

/// The variables of a build without variables of its own.
#[cfg(not(system_variables))]
impl EfivarSource {
    /// The firmware variables that questions read from this source, which validate accepts. Those
    /// of Disabled reach Runtime, as Linux's efivarfs does, so that questions show as under
    /// --no-efivars on Linux.
    pub(crate) fn into_variables(self) -> Result<Box<dyn FirmwareVariables>> {
        self.validate()?;
        Ok(match self {
            #[cfg(efivar_dumps)]
            Self::Directory(dir) => Box::new(EfivarCopy::new(dir)),
            Self::Disabled => Box::new(UnreadVariables {
                reach: VariableReach::Runtime,
                interface: VariableInterface::Efivarfs,
            }),
        })
    }

    /// No platform language: a build without VariableData reads none, from a Directory either.
    pub(crate) fn platform_lang(&self) -> Result<Option<String>> {
        Ok(None)
    }
}

/// Why EfivarSource::validate refuses a Directory.
#[cfg(efivar_dumps)]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("efivars directory {} is not a directory", .0.display())]
pub(super) struct EfivarsNotADirectory(std::path::PathBuf);

/// The outcome of every efivar range under EfivarSource::Disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("EFI variables not read")]
pub(super) struct EfivarsNotRead;

/// The variables of EfivarSource::Disabled: every read and write fails with EfivarsNotRead. They
/// reach what the build's own variables reach, or Runtime, as Linux's efivarfs, on a build
/// without any, so that each refusal of a VarStore stays, and through their interface, or
/// efivarfs, so that it keeps its words.
pub(super) struct UnreadVariables {
    pub(super) reach: VariableReach,
    pub(super) interface: VariableInterface,
}

impl FirmwareVariables for UnreadVariables {
    fn reach(&self) -> VariableReach {
        self.reach
    }

    fn interface(&self) -> VariableInterface {
        self.interface
    }

    fn reads_nothing(&self) -> bool {
        true
    }

    fn read(&self, _key: &VariableKey, _size: u16) -> Result<Vec<u8>> {
        Err(EfivarsNotRead.into())
    }

    fn read_whole(&self, _key: &VariableKey) -> Result<Vec<u8>> {
        Err(EfivarsNotRead.into())
    }

    fn write_patches(
        &self,
        _key: &VariableKey,
        _size: u16,
        _patches: &[DataPatch<'_>],
        _volatile: VolatileWrites,
        _missing: MissingVariable,
    ) -> Result<()> {
        Err(EfivarsNotRead.into())
    }
}

/// The arguments of read_value_bytes, which an EfivarReader reads once.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct EfivarRange {
    pub(super) key: VariableKey,
    pub(super) size: u16,
    pub(super) layout: VariableLayout,
}

/// How the variable of a VarStore holds the values of its questions, which decides what of it
/// read_value_bytes reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum VariableLayout {
    /// Each at its VarOffset, in a value at least as large as the VarStore
    Offsets,
    /// The value of one question, alone and whole: the variable of a VarName on a VARSTORE_EFI
    /// before UEFI 2.3.1
    OneValue,
}

impl VariableLayout {
    /// Where a value of VarStoreInfo `var_store_info` starts in the variable: at that VarOffset,
    /// or at byte 0 of the variable of a VarName.
    pub(super) fn offset(self, var_store_info: u16) -> u16 {
        match self {
            Self::Offsets => var_store_info,
            Self::OneValue => 0,
        }
    }
}

/// The payload bytes `value` that a question decodes from a variable of `layout`, of which
/// FirmwareVariables::read reads `size` payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DecodedValue {
    pub(super) size: u16,
    pub(super) layout: VariableLayout,
    pub(super) value: Range<usize>,
}

/// Reads each EfivarRange of one command once, keeping the outcomes:
/// Linux v7.2 efivarfs sleeps once a non-root user has read 100 times within a second
/// (fs/efivarfs/file.c, kernel/user.c). VarStore names that differ only in '/' and '!' are two
/// keys of one efivarfs file, which it reads once for each.
pub(crate) struct EfivarReader {
    variables: Box<dyn FirmwareVariables>,
    /// The Time Services through which DATE and TIME questions of EFI Date/Time Storage read
    /// and set writes their values, if the build reaches any
    time_services: Option<Rc<dyn TimeServices>>,
    pub(super) outcomes: BTreeMap<EfivarRange, Result<Vec<u8>>>,
    /// The payload bytes that the callers of read decode, by variable
    pub(super) decoded: BTreeMap<VariableKey, Vec<DecodedValue>>,
    /// The bytes that `variables` withhold, which no value decodes
    withheld: WithheldBytes,
    /// Where get, list-questions and show-ifr take the values of missing variables from, if
    /// anywhere
    pub(super) snapshot: Option<SnapshotLookup>,
}

impl EfivarReader {
    /// Reads the variables of `source`, which EfivarSource::validate accepts, withholding none:
    /// outside the tests, PasswordQuestions::reader reads a source.
    #[cfg(test)]
    pub(crate) fn new(source: EfivarSource) -> Result<Self> {
        Ok(Self::with_variables(source.into_variables()?))
    }

    /// Reads `variables`, withholding none: outside the tests, PasswordQuestions::reader reads
    /// variables.
    #[cfg(test)]
    pub(crate) fn with_variables(variables: Box<dyn FirmwareVariables>) -> Self {
        Self::withholding(variables, WithheldBytes::default())
    }

    /// Reads `variables` but their `withheld` bytes, which read as zero and which no value
    /// decodes.
    pub(crate) fn withholding(
        variables: Box<dyn FirmwareVariables>,
        withheld: WithheldBytes,
    ) -> Self {
        Self {
            variables: Box::new(WithholdingVariables::new(variables, withheld.clone())),
            time_services: None,
            outcomes: BTreeMap::new(),
            decoded: BTreeMap::new(),
            withheld,
            snapshot: None,
        }
    }

    /// The withheld bytes of `key` that the payload bytes `value` overlap, if any.
    pub(super) fn withheld_overlap(
        &self,
        key: &VariableKey,
        value: &Range<usize>,
    ) -> Option<Range<usize>> {
        self.withheld.overlap(key, value)
    }

    /// Refuses a write of `patches` of `key`, at value offsets, one of which overlaps its
    /// withheld bytes.
    pub(super) fn check_patches<'p>(
        &self,
        key: &VariableKey,
        patches: impl IntoIterator<Item = DataPatch<'p>>,
    ) -> std::result::Result<(), WithheldPassword> {
        self.withheld.check_patches(key, patches)
    }

    /// This reader, with `time_services`.
    pub(crate) fn with_time_services(self, time_services: Option<Rc<dyn TimeServices>>) -> Self {
        Self {
            time_services,
            ..self
        }
    }

    /// The Time Services of DATE and TIME questions of EFI Date/Time Storage, if any.
    pub(crate) fn time_services(&self) -> Option<&Rc<dyn TimeServices>> {
        self.time_services.as_ref()
    }

    /// Which variables this reader reaches.
    pub(crate) fn reach(&self) -> VariableReach {
        self.variables.reach()
    }

    /// The interface that this reader reads through.
    pub(crate) fn interface(&self) -> VariableInterface {
        self.variables.interface()
    }

    /// read_value_bytes of `range`, read once.
    /// The caller decodes the payload bytes `value`, which this records in `decoded` with
    /// `range.size` unless they end past the `range.size` bytes that read_value_bytes reads,
    /// where they never decode. The variable is recorded either way, so that a dump answers
    /// as its source.
    pub(super) fn read(
        &mut self,
        range: EfivarRange,
        value: Range<usize>,
    ) -> std::result::Result<&[u8], &anyhow::Error> {
        let decoded = self.decoded.entry(range.key.clone()).or_default();
        if value.end <= usize::from(range.size) {
            decoded.push(DecodedValue {
                size: range.size,
                layout: range.layout,
                value,
            });
        }
        let variables = &self.variables;
        self.outcomes
            .entry(range)
            .or_insert_with_key(|range| {
                read_value_bytes(variables.as_ref(), &range.key, range.size, range.layout)
            })
            .as_deref()
    }
}

/// The vendor GUIDs of variables whose names are unknown: these, or every GUID where one is unknown
/// too.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub(crate) struct VariableGuids {
    guids: BTreeSet<Guid>,
    every: bool,
}

impl VariableGuids {
    /// Adds `guid`, or every GUID for None, an unknown one.
    pub(crate) fn insert(&mut self, guid: Option<Guid>) {
        match guid {
            Some(guid) => {
                self.guids.insert(guid);
            }
            None => self.every = true,
        }
    }

    /// Adds those of `other`.
    pub(crate) fn extend(&mut self, other: &Self) {
        self.guids.extend(other.guids.iter().copied());
        self.every |= other.every;
    }

    /// Whether it holds `guid`.
    fn contains(&self, guid: &Guid) -> bool {
        self.every || self.guids.contains(guid)
    }
}

/// The bytes of variables in which PASSWORD questions keep their passwords (UEFI 2.11
/// §33.3.8.3.54), by efivar file, counted from the start of its value: after its metadata, if any
/// (value_of). Variable names that differ only in '/' and '!' name one efivar file, so they share
/// withheld bytes; where they name two variables, as they do outside efivarfs, both are withheld,
/// which fails safe. Bytes that many files withhold are recorded once, in a shared set. Every
/// variable of `guids` is withheld whole.
#[derive(Clone, Default)]
pub(crate) struct WithheldBytes {
    files: BTreeMap<EfivarFileName, FileBytes>,
    shared: Vec<Vec<Range<usize>>>,
    guids: VariableGuids,
}

/// The bytes that an efivar file withholds: its own, and the sets of WithheldBytes::shared at
/// these indexes.
#[derive(Clone, Default)]
struct FileBytes {
    own: Vec<Range<usize>>,
    shared: Vec<Range<usize>>,
}

impl WithheldBytes {
    /// Withholds the value bytes `bytes` of `key` too; an empty range withholds none.
    pub(super) fn insert(&mut self, key: VariableKey, bytes: Range<usize>) {
        if !bytes.is_empty() {
            self.files
                .entry(EfivarFileName::from(&key))
                .or_default()
                .own
                .push(bytes);
        }
    }

    /// Withholds every variable of `guids` whole too.
    pub(super) fn insert_guids(&mut self, guids: &VariableGuids) {
        self.guids.extend(guids);
    }

    /// Records `sets` of value bytes, which withhold_shared shares, and returns their indexes;
    /// their empty ranges withhold none.
    pub(super) fn share(
        &mut self,
        sets: impl IntoIterator<Item = Vec<Range<usize>>>,
    ) -> Range<usize> {
        let start = self.shared.len();
        self.shared.extend(sets.into_iter().map(|mut set| {
            set.retain(|bytes| !bytes.is_empty());
            set
        }));
        start..self.shared.len()
    }

    /// Withholds the shared sets at the indexes `sets`, from share, in `key` too.
    pub(super) fn withhold_shared(&mut self, key: &VariableKey, sets: Range<usize>) {
        self.files
            .entry(EfivarFileName::from(key))
            .or_default()
            .shared
            .push(sets);
    }

    /// The withheld bytes of `key`.
    pub(super) fn of<'a>(&'a self, key: &VariableKey) -> impl Iterator<Item = &'a Range<usize>> {
        let whole = self.guids.contains(&key.guid).then_some(WHOLE_VALUE);
        whole
            .into_iter()
            .chain(self.of_file(&EfivarFileName::from(key)))
    }

    /// The withheld bytes of the efivar file `file`.
    fn of_file<'a>(&'a self, file: &EfivarFileName) -> impl Iterator<Item = &'a Range<usize>> {
        self.files.get(file).into_iter().flat_map(|bytes| {
            bytes.own.iter().chain(
                bytes
                    .shared
                    .iter()
                    .flat_map(|sets| self.shared[sets.clone()].iter().flatten()),
            )
        })
    }

    /// Whether `key` withholds any byte.
    fn withholds(&self, key: &VariableKey) -> bool {
        self.of(key).next().is_some()
    }

    /// The withheld bytes of each efivar file that withholds any, sorted, whichever records hold
    /// them.
    fn by_file(&self) -> BTreeMap<&EfivarFileName, Vec<Range<usize>>> {
        self.files
            .keys()
            .filter_map(|file| {
                let mut bytes: Vec<Range<usize>> = self.of_file(file).cloned().collect();
                bytes.sort_by_key(|bytes| (bytes.start, bytes.end));
                (!bytes.is_empty()).then_some((file, bytes))
            })
            .collect()
    }

    /// The ranges and the links to shared sets that this records, which tests of the bound on
    /// PasswordQuestions' records count.
    #[cfg(test)]
    pub(crate) fn entries(&self) -> usize {
        let files: usize = self
            .files
            .values()
            .map(|bytes| bytes.own.len() + bytes.shared.len())
            .sum();
        files + self.shared.iter().map(Vec::len).sum::<usize>()
    }

    /// The first withheld bytes of `key` that `bytes` overlap, if any.
    fn overlap(&self, key: &VariableKey, bytes: &Range<usize>) -> Option<Range<usize>> {
        self.of(key)
            .find(|withheld| withheld.start < bytes.end && bytes.start < withheld.end)
            .cloned()
    }

    /// Refuses a write of the value bytes `bytes` of `key` that overlaps withheld bytes.
    fn check_write(
        &self,
        key: &VariableKey,
        bytes: &Range<usize>,
    ) -> std::result::Result<(), WithheldPassword> {
        match self.overlap(key, bytes) {
            Some(withheld) => Err(WithheldPassword {
                key: key.clone(),
                bytes: withheld,
            }),
            None => Ok(()),
        }
    }

    /// Refuses a write of `patches` of `key`, at value offsets, one of which overlaps withheld
    /// bytes.
    fn check_patches<'p>(
        &self,
        key: &VariableKey,
        patches: impl IntoIterator<Item = DataPatch<'p>>,
    ) -> std::result::Result<(), WithheldPassword> {
        patches
            .into_iter()
            .try_for_each(|patch| self.check_write(key, &patch.range()))
    }

    /// Zeroes the withheld bytes of `key` in `value`, the start of its value.
    fn zero(&self, key: &VariableKey, value: &mut [u8]) {
        let len = value.len();
        for withheld in self.of(key) {
            if let Some(password) = value.get_mut(withheld.start.min(len)..withheld.end.min(len)) {
                password.fill(0);
            }
        }
    }
}

impl PartialEq for WithheldBytes {
    fn eq(&self, other: &Self) -> bool {
        self.by_file() == other.by_file() && self.guids == other.guids
    }
}

impl Eq for WithheldBytes {}

impl fmt::Debug for WithheldBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WithheldBytes")
            .field("files", &self.by_file())
            .field("guids", &self.guids)
            .finish()
    }
}

/// `variables` without their `withheld` bytes, those of PASSWORD questions: they read as zero,
/// where the value of their variable holds them, and a write that overlaps them fails with
/// WithheldPassword before `variables` see it, so that no password byte is shown or written back.
pub(crate) struct WithholdingVariables<V> {
    variables: V,
    withheld: WithheldBytes,
}

impl<V> WithholdingVariables<V> {
    pub(super) fn new(variables: V, withheld: WithheldBytes) -> Self {
        Self {
            variables,
            withheld,
        }
    }

    /// Zeroes the withheld bytes of `key` in `bytes`, its attributes word and data as read and
    /// read_whole give them, where its value holds them: after its metadata (value_of), whose
    /// refusal this returns.
    fn zero_withheld(
        &self,
        key: &VariableKey,
        bytes: &mut [u8],
    ) -> std::result::Result<(), EnhancedAuthenticatedVariable> {
        if !self.withheld.withholds(key) {
            return Ok(());
        }
        let Some((attributes, data)) = efivar_parts(bytes) else {
            return Ok(());
        };
        let start = EFIVARFS_HEADER_SIZE + data.len() - value_of(key, attributes, data)?.len();
        if let Some(value) = bytes.get_mut(start..) {
            self.withheld.zero(key, value);
        }
        Ok(())
    }
}

impl<V: FirmwareVariables> FirmwareVariables for WithholdingVariables<V> {
    fn reach(&self) -> VariableReach {
        self.variables.reach()
    }

    fn interface(&self) -> VariableInterface {
        self.variables.interface()
    }

    fn reads_nothing(&self) -> bool {
        self.variables.reads_nothing()
    }

    fn read(&self, key: &VariableKey, size: u16) -> Result<Vec<u8>> {
        let mut bytes = self.variables.read(key, size)?;
        // the first `size` data bytes may end inside metadata, which then hides where the value
        // starts: they read as zero, as read_value_bytes takes only the attributes word from them
        // and the value from read_whole
        if self.zero_withheld(key, &mut bytes).is_err() {
            if let Some(data) = bytes.get_mut(EFIVARFS_HEADER_SIZE..) {
                data.fill(0);
            }
        }
        Ok(bytes)
    }

    fn read_whole(&self, key: &VariableKey) -> Result<Vec<u8>> {
        let mut bytes = self.variables.read_whole(key)?;
        self.zero_withheld(key, &mut bytes)?;
        Ok(bytes)
    }

    fn write_patches(
        &self,
        key: &VariableKey,
        size: u16,
        patches: &[DataPatch<'_>],
        volatile: VolatileWrites,
        missing: MissingVariable,
    ) -> Result<()> {
        // a data offset is a value offset: set writes no variable with metadata
        // (check_unauthenticated)
        self.withheld.check_patches(key, patches.iter().copied())?;
        self.variables
            .write_patches(key, size, patches, volatile, missing)
    }
}

/// `variables` whose write_patches writes a volatile variable as `volatile` says, whatever a
/// caller passes, the policy of one set: the policy reaches the check of each backend's
/// read-modify-write (modify_variable_bytes).
pub(crate) struct VolatileWritingVariables<V> {
    variables: V,
    volatile: VolatileWrites,
}

impl<V> VolatileWritingVariables<V> {
    pub(crate) fn new(variables: V, volatile: VolatileWrites) -> Self {
        Self {
            variables,
            volatile,
        }
    }
}

impl<V: FirmwareVariables> FirmwareVariables for VolatileWritingVariables<V> {
    fn reach(&self) -> VariableReach {
        self.variables.reach()
    }

    fn interface(&self) -> VariableInterface {
        self.variables.interface()
    }

    fn reads_nothing(&self) -> bool {
        self.variables.reads_nothing()
    }

    fn read(&self, key: &VariableKey, size: u16) -> Result<Vec<u8>> {
        self.variables.read(key, size)
    }

    fn read_whole(&self, key: &VariableKey) -> Result<Vec<u8>> {
        self.variables.read_whole(key)
    }

    fn write_patches(
        &self,
        key: &VariableKey,
        size: u16,
        patches: &[DataPatch<'_>],
        _: VolatileWrites,
        missing: MissingVariable,
    ) -> Result<()> {
        self.variables
            .write_patches(key, size, patches, self.volatile, missing)
    }
}

/// A write that WithholdingVariables refuse: it overlaps the bytes of a password.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "EFI variable {key} holds a password {}, which set never writes",
    PasswordBytes(.bytes)
)]
pub(super) struct WithheldPassword {
    key: VariableKey,
    bytes: Range<usize>,
}

/// The withheld bytes of a WithheldPassword, as its error names them: a range, or all from its
/// start on.
struct PasswordBytes<'a>(&'a Range<usize>);

impl std::fmt::Display for PasswordBytes<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0.end {
            usize::MAX => write!(f, "in every byte from {} on", self.0.start),
            end => write!(f, "at bytes {}..{end}", self.0.start),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::cell::RefCell;
    #[cfg(efivar_dumps)]
    use std::fs;
    use std::rc::Rc;

    use super::*;
    use crate::efi_variables::enhanced_authenticated::fixture::timestamp_metadata;

    /// EFI variable Attributes: non-volatile, boot service and runtime access.
    pub(crate) const NV_BS_RT: u32 = 0x07;
    /// EFI variable Attributes: non-volatile and boot service access only.
    pub(crate) const NV_BS: u32 = 0x03;
    /// EFI variable Attributes: boot service and runtime access, volatile.
    pub(crate) const BS_RT: u32 = 0x06;

    pub(crate) const NIL_GUID: Guid = Guid {
        data1: 0,
        data2: 0,
        data3: 0,
        data4: [0; 8],
    };
    pub(crate) const EFI_GLOBAL_VARIABLE: Guid = Guid {
        data1: 0x8BE4_DF61,
        data2: 0x93CA,
        data3: 0x11D2,
        data4: [0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C],
    };

    /// Why MemoryVariables fails the writes of a variable: `cause`, in `context` if any, as
    /// anyhow::Context adds it.
    #[derive(Clone, Copy)]
    pub(crate) struct WriteError {
        pub(crate) cause: &'static str,
        pub(crate) context: Option<&'static str>,
    }

    /// Firmware variables in memory, each its attributes word and data, as read gives them, that
    /// reach `reach` through `interface`. Records every read and the writes that succeed, and
    /// fails those of the variables in `failures`.
    pub(crate) struct MemoryVariables {
        reach: VariableReach,
        interface: VariableInterface,
        variables: RefCell<BTreeMap<VariableKey, Vec<u8>>>,
        failures: BTreeMap<VariableKey, WriteError>,
        reads: RefCell<Vec<(VariableKey, u16)>>,
        writes: RefCell<Vec<(VariableKey, u16, Vec<u8>)>>,
    }

    /// No variables, reaching what efivarfs reaches, through efivarfs.
    impl Default for MemoryVariables {
        fn default() -> Self {
            Self::new(VariableReach::Runtime, VariableInterface::Efivarfs)
        }
    }

    impl MemoryVariables {
        /// No variables, reaching `reach` through `interface`.
        pub(crate) fn new(reach: VariableReach, interface: VariableInterface) -> Self {
            Self {
                reach,
                interface,
                variables: RefCell::default(),
                failures: BTreeMap::new(),
                reads: RefCell::default(),
                writes: RefCell::default(),
            }
        }

        /// Makes the attribute word `attributes` and then `data` the variable `key`.
        pub(crate) fn insert(&self, key: VariableKey, attributes: u32, data: &[u8]) {
            let bytes = [&attributes.to_ne_bytes()[..], data].concat();
            self.variables.borrow_mut().insert(key, bytes);
        }

        /// Fails the writes of the variable `key` with `error`.
        #[cfg(efivar_dumps)]
        pub(crate) fn fail_writes(&mut self, key: VariableKey, error: WriteError) {
            self.failures.insert(key, error);
        }

        /// The attributes word and data of the variable `key`.
        pub(crate) fn bytes(&self, key: &VariableKey) -> Option<Vec<u8>> {
            self.variables.borrow().get(key).cloned()
        }

        /// The sizes of the reads of `key`, in order.
        pub(crate) fn reads_of(&self, key: &VariableKey) -> Vec<u16> {
            self.reads
                .borrow()
                .iter()
                .filter(|(read, _)| read == key)
                .map(|(_, size)| *size)
                .collect()
        }

        /// The variables and sizes of every read, in order.
        pub(crate) fn reads(&self) -> Vec<(VariableKey, u16)> {
            self.reads.borrow().clone()
        }

        /// The writes to `key` that succeeded, in order: each the lowest data offset of its
        /// patches, and the bytes from there to the end of the patch that ends last, as written.
        pub(crate) fn writes_to(&self, key: &VariableKey) -> Vec<(u16, Vec<u8>)> {
            self.writes
                .borrow()
                .iter()
                .filter(|(written, _, _)| written == key)
                .map(|(_, offset, encoded)| (*offset, encoded.clone()))
                .collect()
        }
    }

    impl FirmwareVariables for MemoryVariables {
        fn reach(&self) -> VariableReach {
            self.reach
        }

        fn interface(&self) -> VariableInterface {
            self.interface
        }

        fn read(&self, key: &VariableKey, size: u16) -> Result<Vec<u8>> {
            self.reads.borrow_mut().push((key.clone(), size));
            let variables = self.variables.borrow();
            let bytes = variables
                .get(key)
                .ok_or_else(|| VariableNotFound(key.clone()))?;
            let attributes = efivar_attributes(bytes).context("attributes word")?;
            let data = bytes.get(EFIVARFS_HEADER_SIZE..).unwrap_or_default();
            attributes_and_data(key, attributes, data, size)
        }

        fn read_whole(&self, key: &VariableKey) -> Result<Vec<u8>> {
            self.variables
                .borrow()
                .get(key)
                .cloned()
                .ok_or_else(|| VariableNotFound(key.clone()).into())
        }

        fn write_patches(
            &self,
            key: &VariableKey,
            size: u16,
            patches: &[DataPatch<'_>],
            volatile: VolatileWrites,
            missing: MissingVariable,
        ) -> Result<()> {
            match self.failures.get(key) {
                None => {}
                Some(WriteError {
                    cause,
                    context: None,
                }) => return Err(anyhow!(*cause)),
                Some(WriteError {
                    cause,
                    context: Some(context),
                }) => return Err(anyhow!(*cause).context(*context)),
            }
            let mut variables = self.variables.borrow_mut();
            let modified = match (variables.get(key), missing) {
                (Some(bytes), _) => {
                    let mut modified = bytes.clone();
                    modify_variable_bytes(self, key, volatile, &mut modified, size, patches)?;
                    modified
                }
                (None, MissingVariable::Create(attributes)) => {
                    created_variable_bytes(self, key, volatile, attributes, size, patches)?
                }
                (None, MissingVariable::Refuse) => return Err(VariableNotFound(key.clone()).into()),
            };
            let start = patches.iter().map(|patch| patch.offset).min().unwrap_or(0);
            let end = patches
                .iter()
                .map(|patch| usize::from(patch.offset) + patch.bytes.len())
                .max()
                .unwrap_or(0);
            let written = modified
                .get(EFIVARFS_HEADER_SIZE + usize::from(start)..EFIVARFS_HEADER_SIZE + end)
                .context("the written bytes")?
                .to_vec();
            variables.insert(key.clone(), modified);
            self.writes.borrow_mut().push((key.clone(), start, written));
            Ok(())
        }
    }

    /// Shares MemoryVariables with an EfivarReader, which owns its variables.
    impl FirmwareVariables for Rc<MemoryVariables> {
        fn reach(&self) -> VariableReach {
            self.as_ref().reach()
        }

        fn interface(&self) -> VariableInterface {
            self.as_ref().interface()
        }

        fn read(&self, key: &VariableKey, size: u16) -> Result<Vec<u8>> {
            self.as_ref().read(key, size)
        }

        fn read_whole(&self, key: &VariableKey) -> Result<Vec<u8>> {
            self.as_ref().read_whole(key)
        }

        fn write_patches(
            &self,
            key: &VariableKey,
            size: u16,
            patches: &[DataPatch<'_>],
            volatile: VolatileWrites,
            missing: MissingVariable,
        ) -> Result<()> {
            self.as_ref()
                .write_patches(key, size, patches, volatile, missing)
        }
    }

    /// The write of one patch, under VolatileWrites::Refuse, that most tests make.
    pub(crate) trait WriteAt: FirmwareVariables {
        /// write_patches of `encoded` at data offset `offset` of `key`, whose VarStore has
        /// `size` bytes, under VolatileWrites::Refuse.
        fn write_at(
            &self,
            key: &VariableKey,
            size: u16,
            offset: u16,
            encoded: &[u8],
        ) -> Result<()> {
            self.write_patches(
                key,
                size,
                &[patch(offset, encoded)],
                VolatileWrites::Refuse,
                MissingVariable::Refuse,
            )
        }
    }

    impl<T: FirmwareVariables + ?Sized> WriteAt for T {}

    /// `bytes` at data offset `offset`.
    pub(crate) fn patch(offset: u16, bytes: &[u8]) -> DataPatch<'_> {
        DataPatch { offset, bytes }
    }

    /// No variables, reaching what variables of `interface` reach, through it.
    fn variables_of(interface: VariableInterface) -> MemoryVariables {
        let reach = match interface {
            VariableInterface::VariableServices => VariableReach::BootServices,
            VariableInterface::Efivarfs | VariableInterface::FirmwareEnvironment => {
                VariableReach::Runtime
            }
        };
        MemoryVariables::new(reach, interface)
    }

    /// The variable `name` of NIL_GUID.
    pub(crate) fn variable_key(name: &str) -> VariableKey {
        VariableKey {
            name: name.to_string(),
            guid: NIL_GUID,
        }
    }

    /// The errors of a write word it as variables of their interface hold it: Efivarfs as
    /// efivarfs, VariableServices as GetVariable() and SetVariable(), FirmwareEnvironment as the
    /// firmware environment calls, never efivarfs.
    #[test]
    fn write_errors_follow_their_interface() {
        let volatile = |interface| {
            check_non_volatile(&variable_key("Volatile"), interface, BS_RT)
                .map_err(|error| error.to_string())
        };
        let short = |interface| {
            update_efivarfs_bytes(interface, &mut variable_bytes(2), 4, 0, &[1])
                .map_err(|error| error.to_string())
        };
        let past = |interface| {
            update_efivarfs_bytes(interface, &mut variable_bytes(4), 4, 4, &[1])
                .map_err(|error| format!("{error:#}"))
        };
        let headless = |interface| {
            update_efivarfs_bytes(interface, &mut [7, 0], 0, 0, &[])
                .map_err(|error| format!("{error:#}"))
        };
        let cases = [
            (
                VariableInterface::Efivarfs,
                "EFI variable Volatile-00000000-0000-0000-0000-000000000000 is volatile (no \
                 EFI_VARIABLE_NON_VOLATILE) and cannot be written through efivarfs",
                "efivarfs payload is shorter than the declared varstore: 2 < 4 bytes",
                "write past the efivarfs payload",
                "efivarfs file is missing its attributes header",
                "efivarfs write",
            ),
            (
                VariableInterface::VariableServices,
                "EFI variable Volatile-00000000-0000-0000-0000-000000000000 is volatile (no \
                 EFI_VARIABLE_NON_VOLATILE), so a write would not outlast a power cycle; pass \
                 --allow-volatile to write it anyway",
                "GetVariable() data is shorter than the declared varstore: 2 < 4 bytes",
                "write past the GetVariable() data",
                "variable bytes are missing their attributes word",
                "SetVariable() write",
            ),
            (
                VariableInterface::FirmwareEnvironment,
                "EFI variable Volatile-00000000-0000-0000-0000-000000000000 is volatile (no \
                 EFI_VARIABLE_NON_VOLATILE), so a write would not outlast a power cycle",
                "GetFirmwareEnvironmentVariableExW payload is shorter than the declared \
                 varstore: 2 < 4 bytes",
                "write past the GetFirmwareEnvironmentVariableExW payload",
                "GetFirmwareEnvironmentVariableExW data is missing its attributes word",
                "SetFirmwareEnvironmentVariableExW write",
            ),
        ];
        for (interface, want_volatile, want_short, want_past, want_headless, want_write) in cases {
            assert_eq!(
                volatile(interface),
                Err(want_volatile.to_string()),
                "{interface:?}: volatile"
            );
            assert_eq!(
                short(interface),
                Err(want_short.to_string()),
                "{interface:?}: short"
            );
            assert_eq!(
                past(interface),
                Err(want_past.to_string()),
                "{interface:?}: past"
            );
            assert_eq!(
                headless(interface),
                Err(want_headless.to_string()),
                "{interface:?}: headless"
            );
            assert_eq!(interface.write(), want_write, "{interface:?}: write");
        }
    }

    /// write_patches of a missing variable fails with VariableNotFound under
    /// MissingVariable::Refuse, and under MissingVariable::Create makes it of those attributes,
    /// its data the bytes that the patches write, every one of them: it refuses patches that leave
    /// a data byte unwritten, and attributes that modify_variable_bytes refuses, creating nothing.
    /// An existing variable keeps its own attributes.
    #[test]
    fn write_patches_creates_a_missing_variable_as_missing_says() {
        // EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS
        const TIME_BASED_AUTHENTICATED: u32 = 0x20;
        let key = variable_key("Created");
        let variable = "Created-00000000-0000-0000-0000-000000000000";
        let created = |attributes: u32| Ok(Some([&attributes.to_ne_bytes()[..], &[1, 2]].concat()));
        let cases = [
            (
                "refused",
                None,
                MissingVariable::Refuse,
                vec![patch(0, &[1, 2])],
                Err(format!("no EFI variable {variable}")),
            ),
            (
                "created",
                None,
                MissingVariable::Create(NV_BS_RT),
                vec![patch(0, &[1, 2])],
                created(NV_BS_RT),
            ),
            (
                "created of two patches",
                None,
                MissingVariable::Create(NV_BS_RT),
                vec![patch(1, &[2]), patch(0, &[1])],
                created(NV_BS_RT),
            ),
            (
                "a byte unwritten",
                None,
                MissingVariable::Create(NV_BS_RT),
                vec![patch(0, &[1])],
                Err(format!(
                    "EFI variable {variable} is missing, and no patch writes its data byte 1 of 2, \
                     so set does not create it"
                )),
            ),
            (
                "volatile",
                None,
                MissingVariable::Create(BS_RT),
                vec![patch(0, &[1, 2])],
                Err(format!(
                    "EFI variable {variable} is volatile (no EFI_VARIABLE_NON_VOLATILE) and cannot \
                     be written through efivarfs"
                )),
            ),
            (
                "authenticated",
                None,
                MissingVariable::Create(NV_BS_RT | TIME_BASED_AUTHENTICATED),
                vec![patch(0, &[1, 2])],
                Err(format!(
                    "EFI variable {variable} has authenticated access (attributes 0x27), which \
                     uefisettings does not write"
                )),
            ),
            (
                "existing",
                Some(&[5, 5][..]),
                MissingVariable::Create(NV_BS_RT),
                vec![patch(0, &[1, 2])],
                created(NV_BS),
            ),
        ];
        for (case, existing, missing, patches, want) in cases {
            let variables =
                MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);
            if let Some(data) = existing {
                variables.insert(key.clone(), NV_BS, data);
            }

            let written = variables
                .write_patches(&key, 2, &patches, VolatileWrites::Refuse, missing)
                .map_err(|error| format!("{error:#}"));

            assert_eq!(written.map(|()| variables.bytes(&key)), want, "{case}");
            if want.is_err() {
                assert_eq!(variables.bytes(&key), None, "{case}: nothing created");
            }
        }
    }

    /// set's refusal of a variable that does not exist follows its interface: efivarfs as on
    /// Linux, the firmware environment calls as on Windows, GetVariable() as in the UEFI Shell,
    /// whose variables reach every variable that the firmware has created.
    #[test]
    fn not_found_refusal_follows_its_interface() {
        assert_eq!(
            VariableInterface::Efivarfs.not_found_refusal(),
            "the firmware has not created it or does not expose it to the OS, so its questions \
             cannot be set from Linux; change them in the firmware setup, or ask the board vendor \
             for firmware that exposes it; see https://github.com/linuxboot/uefisettings/issues/2",
            "Efivarfs"
        );
        assert_eq!(
            VariableInterface::VariableServices.not_found_refusal(),
            "the firmware has not created it, and set creates only the per-question variables of \
             an EFI_IFR_VARSTORE_EFI before UEFI 2.3.1",
            "VariableServices"
        );
        assert_eq!(
            VariableInterface::FirmwareEnvironment.not_found_refusal(),
            "the firmware has not created it or does not expose it to the OS, so its \
             questions cannot be set from Windows; change them in the firmware setup, or ask \
             the board vendor for firmware that exposes it; see \
             https://github.com/linuxboot/uefisettings/issues/2",
            "FirmwareEnvironment"
        );
    }

    #[test]
    fn efivar_attributes_are_the_first_native_u32() {
        let bytes = [&0x6u32.to_ne_bytes()[..], &[0x2A]].concat();
        assert_eq!(
            efivar_attributes(&bytes),
            Some(0x6),
            "attributes and payload"
        );
        for length in 0..EFIVARFS_HEADER_SIZE {
            assert_eq!(efivar_attributes(&bytes[..length]), None, "{length} bytes");
        }
    }

    /// VariableAttributes display the names of their attributes, any other bits in hex, and
    /// "no attributes" for none.
    #[test]
    fn variable_attributes_display_their_names() {
        for (attributes, names) in [
            (
                VariableAttributes::from_bits_retain(NV_BS_RT),
                "NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS",
            ),
            (
                VariableAttributes::RUNTIME_ACCESS | VariableAttributes::from_bits_retain(0x100),
                "RUNTIME_ACCESS | 0x100",
            ),
            (VariableAttributes::empty(), "no attributes"),
        ] {
            assert_eq!(attributes.to_string(), names, "{attributes:?}");
        }
    }

    /// A VariableKey displays as its efivar file: '!' for each '/', the GUID in lowercase.
    #[test]
    fn variable_key_displays_as_its_efivar_file_name() {
        let key = VariableKey {
            name: "a/b".to_string(),
            guid: EFI_GLOBAL_VARIABLE,
        };

        assert_eq!(
            key.to_string(),
            "a!b-8be4df61-93ca-11d2-aa0d-00e098032b8c",
            "VariableKey a/b"
        );
    }

    /// The reader reads each range once through FirmwareVariables, keeping the outcome, also an
    /// error.
    #[test]
    fn reader_reads_each_range_once() {
        let variables = Rc::new(MemoryVariables::default());
        variables.insert(variable_key("Setup"), NV_BS_RT, &[1, 2]);
        let range = |name: &str, size| EfivarRange {
            key: variable_key(name),
            size,
            layout: VariableLayout::Offsets,
        };
        let mut reader = EfivarReader::with_variables(Box::new(Rc::clone(&variables)));

        for _ in 0..2 {
            assert_eq!(
                reader
                    .read(range("Setup", 2), 0..1)
                    .map(<[u8]>::to_vec)
                    .ok(),
                Some([&NV_BS_RT.to_ne_bytes()[..], &[1, 2]].concat()),
                "Setup, 2 bytes"
            );
            assert!(
                reader.read(range("Missing", 1), 0..1).is_err(),
                "Missing, 1 byte"
            );
        }
        reader
            .read(range("Setup", 1), 0..1)
            .expect("read Setup, 1 byte");

        assert_eq!(
            variables.reads(),
            [
                (variable_key("Setup"), 2),
                (variable_key("Missing"), 1),
                (variable_key("Setup"), 1)
            ],
            "reads: each range once, in order"
        );
    }

    /// WithholdingVariables read each withheld range of a variable as zero and its other bytes as
    /// they are; they refuse a write that overlaps a range before their variables see it, and
    /// pass the other writes through, which keep the withheld bytes as they are.
    #[test]
    fn withheld_bytes_are_neither_read_nor_written() {
        let variables = MemoryVariables::new(
            VariableReach::BootServices,
            VariableInterface::VariableServices,
        );
        variables.insert(variable_key("Setup"), NV_BS_RT, &[1]);
        // two passwords, at bytes 1..3 and 3..5, as AMI firmware keeps two, then a setting
        variables.insert(
            variable_key("AMITSESetup"),
            NV_BS_RT,
            &[0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 1],
        );
        let mut withheld = WithheldBytes::default();
        withheld.insert(variable_key("AMITSESetup"), 1..3);
        withheld.insert(variable_key("AMITSESetup"), 3..5);
        let withholding = WithholdingVariables::new(&variables, withheld);
        let attributes = NV_BS_RT.to_ne_bytes();

        assert_eq!(
            withholding.read(&variable_key("AMITSESetup"), 6).ok(),
            Some([&attributes[..], &[0xAA, 0, 0, 0, 0, 1]].concat()),
            "read AMITSESetup"
        );
        assert_eq!(
            withholding.read(&variable_key("AMITSESetup"), 2).ok(),
            Some([&attributes[..], &[0xAA, 0]].concat()),
            "read 2 bytes of AMITSESetup, which end inside the first password"
        );
        assert_eq!(
            withholding.read_whole(&variable_key("AMITSESetup")).ok(),
            Some([&attributes[..], &[0xAA, 0, 0, 0, 0, 1]].concat()),
            "read AMITSESetup whole"
        );
        for (offset, encoded, password) in [
            (2, &[0][..], "1..3"),
            (0, &[0, 0][..], "1..3"),
            (4, &[0, 0][..], "3..5"),
            (0, &[0; 6][..], "1..3"),
        ] {
            assert_eq!(
                withholding
                    .write_at(&variable_key("AMITSESetup"), 6, offset, encoded)
                    .map_err(|error| error.to_string()),
                Err(format!(
                    "EFI variable AMITSESetup-00000000-0000-0000-0000-000000000000 holds a \
                     password at bytes {password}, which set never writes"
                )),
                "write {encoded:?} at {offset}"
            );
        }
        withholding
            .write_at(&variable_key("AMITSESetup"), 6, 5, &[0])
            .expect("write after the passwords");
        withholding
            .write_at(&variable_key("AMITSESetup"), 6, 0, &[0])
            .expect("write before the passwords");
        withholding
            .write_at(&variable_key("Setup"), 1, 0, &[2])
            .expect("write Setup");
        assert_eq!(
            variables.writes_to(&variable_key("AMITSESetup")),
            [(5, vec![0]), (0, vec![0])],
            "writes to AMITSESetup"
        );
        assert_eq!(
            variables.bytes(&variable_key("AMITSESetup")),
            Some([&attributes[..], &[0, 0xAA, 0xAA, 0xAA, 0xAA, 0]].concat()),
            "AMITSESetup keeps the passwords' bytes"
        );
        assert_eq!(
            withholding.read(&variable_key("Setup"), 1).ok(),
            Some([&attributes[..], &[2]].concat()),
            "read Setup"
        );
        assert_eq!(
            variables.writes_to(&variable_key("Setup")),
            [(0, vec![2])],
            "writes to Setup"
        );
    }

    /// WithholdingVariables refuse a write of several patches if any of them overlaps withheld
    /// bytes, the last one too, before their variables see it, through variables of every
    /// interface; patches on both sides of withheld bytes write in one write that keeps those bytes
    /// as they are, byte for byte.
    #[test]
    fn withheld_bytes_are_not_written_by_any_patch() {
        // a password at bytes 1..3, between two settings
        const HELD: [u8; 5] = [0x11, 0xA7, 0x3C, 0x22, 1];
        let password = |variables: &MemoryVariables| {
            variables
                .bytes(&variable_key("AMITSESetup"))
                .and_then(|bytes| {
                    bytes
                        .get(EFIVARFS_HEADER_SIZE + 1..EFIVARFS_HEADER_SIZE + 3)
                        .map(<[u8]>::to_vec)
                })
        };
        for (reach, interface) in [
            (VariableReach::Runtime, VariableInterface::Efivarfs),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            ),
            (
                VariableReach::Runtime,
                VariableInterface::FirmwareEnvironment,
            ),
        ] {
            let variables = MemoryVariables::new(reach, interface);
            variables.insert(variable_key("AMITSESetup"), NV_BS_RT, &HELD);
            let mut withheld = WithheldBytes::default();
            withheld.insert(variable_key("AMITSESetup"), 1..3);
            let withholding = WithholdingVariables::new(&variables, withheld);

            for patches in [
                [patch(4, &[0]), patch(2, &[0])],
                [patch(0, &[0, 0]), patch(4, &[0])],
            ] {
                assert_eq!(
                    withholding
                        .write_patches(
                            &variable_key("AMITSESetup"),
                            5,
                            &patches,
                            VolatileWrites::Refuse,
                            MissingVariable::Refuse,
                        )
                        .map_err(|error| error.to_string()),
                    Err(
                        "EFI variable AMITSESetup-00000000-0000-0000-0000-000000000000 holds a \
                         password at bytes 1..3, which set never writes"
                            .to_string()
                    ),
                    "{interface:?}: write {patches:?}"
                );
            }
            assert_eq!(
                variables.writes_to(&variable_key("AMITSESetup")),
                [],
                "{interface:?}: writes of a patch over the password"
            );

            withholding
                .write_patches(
                    &variable_key("AMITSESetup"),
                    5,
                    &[patch(0, &[0]), patch(3, &[0, 0])],
                    VolatileWrites::Refuse,
                    MissingVariable::Refuse,
                )
                .unwrap_or_else(|error| {
                    panic!("{interface:?}: write on both sides of the password: {error:#}")
                });
            assert_eq!(
                variables.writes_to(&variable_key("AMITSESetup")),
                [(0, vec![0, 0xA7, 0x3C, 0, 0])],
                "{interface:?}: writes on both sides of the password"
            );
            assert_eq!(
                password(&variables),
                HELD.get(1..3).map(<[u8]>::to_vec),
                "{interface:?}: the password's bytes"
            );
        }
    }

    /// WithholdingVariables zero the withheld bytes of a variable with
    /// EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS where its value holds them, after its metadata
    /// (UEFI 2.11 §8.2.1), which they keep; read gives no data byte where those end inside the
    /// metadata, and read_whole refuses metadata that hides where the value starts, as get does.
    #[test]
    fn withheld_bytes_after_metadata_read_as_zero() {
        let enhanced = NV_BS_RT | EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS;
        let metadata = timestamp_metadata();
        let variables = MemoryVariables::default();
        variables.insert(
            variable_key("Enhanced"),
            enhanced,
            &[&metadata[..], &[0xAA, 0xAA, 0xAA, 1]].concat(),
        );
        variables.insert(variable_key("BadMetadata"), enhanced, &[2, 0xAA, 0xAA]);
        let mut withheld = WithheldBytes::default();
        withheld.insert(variable_key("Enhanced"), 1..3);
        withheld.insert(variable_key("BadMetadata"), 1..3);
        let withholding = WithholdingVariables::new(&variables, withheld);
        let attributes = enhanced.to_ne_bytes();
        let size = u16::try_from(metadata.len() + 4).expect("the size of Enhanced");

        assert_eq!(
            withholding.read_whole(&variable_key("Enhanced")).ok(),
            Some([&attributes[..], &metadata, &[0xAA, 0, 0, 1]].concat()),
            "read Enhanced whole"
        );
        assert_eq!(
            withholding.read(&variable_key("Enhanced"), size).ok(),
            Some([&attributes[..], &metadata, &[0xAA, 0, 0, 1]].concat()),
            "read Enhanced, its metadata and its value"
        );
        assert_eq!(
            withholding.read(&variable_key("Enhanced"), 4).ok(),
            Some([&attributes[..], &[0; 4]].concat()),
            "read 4 bytes of Enhanced, inside its metadata"
        );
        assert_eq!(
            withholding
                .read_whole(&variable_key("BadMetadata"))
                .map_err(|error| error.to_string()),
            Err(
                "EFI variable BadMetadata-00000000-0000-0000-0000-000000000000 has enhanced \
                 authenticated access (attributes 0x87), whose metadata uefisettings refuses: \
                 EFI_VARIABLE_AUTHENTICATION_3 Version 2, not 1"
                    .to_string()
            ),
            "read BadMetadata whole"
        );
    }

    #[test]
    fn disabled_source_reads_no_efivar() {
        let mut reader =
            EfivarReader::new(EfivarSource::Disabled).expect("create a reader without efivars");
        let range = EfivarRange {
            key: variable_key("Setup"),
            size: 1,
            layout: VariableLayout::Offsets,
        };

        let error = reader.read(range, 0..1).expect_err("read without efivars");

        assert_eq!(
            error.downcast_ref::<EfivarsNotRead>(),
            Some(&EfivarsNotRead),
            "Disabled: {error:#}"
        );
    }

    #[cfg(efivar_dumps)]
    #[test]
    fn directory_source_must_be_a_directory() {
        let dir = tempfile::tempdir().expect("create directory");
        let file = dir.path().join("file");
        fs::write(&file, b"").expect("write a file");
        let missing = dir.path().join("missing");

        #[cfg(system_variables)]
        EfivarSource::System
            .validate()
            .expect("validate this machine's variables");
        for (case, source) in [
            ("Disabled", EfivarSource::Disabled),
            (
                "directory",
                EfivarSource::Directory(dir.path().to_path_buf()),
            ),
        ] {
            source
                .validate()
                .unwrap_or_else(|error| panic!("validate {case}: {error:#}"));
        }
        for (case, path) in [("file", &file), ("missing", &missing)] {
            let error = EfivarSource::Directory(path.clone())
                .validate()
                .expect_err("validate a directory that is not one");

            assert_eq!(
                error.to_string(),
                format!("efivars directory {} is not a directory", path.display()),
                "{case}"
            );
        }
    }

    #[test]
    fn reader_keeps_the_decoded_bytes_of_every_read() {
        let mut reader =
            EfivarReader::new(EfivarSource::Disabled).expect("create a reader without efivars");
        let setup = variable_key("Setup");
        let other = variable_key("Other");
        let past = variable_key("Past");
        let reads = [
            (&setup, 1, 0..1),
            (&setup, 4, 2..4),
            (&other, 2, 0..2),
            (&other, 2, 1..2),
            (&other, 2, 1..3), // ends one byte past Size
            (&past, 2, 3..5),
        ];
        let decoded = |size, value| DecodedValue {
            size,
            layout: VariableLayout::Offsets,
            value,
        };

        for (key, size, value) in reads {
            let range = EfivarRange {
                key: key.clone(),
                size,
                layout: VariableLayout::Offsets,
            };
            reader.read(range, value).expect_err("read without efivars");
        }

        assert_eq!(
            reader.decoded,
            BTreeMap::from([
                (other, vec![decoded(2, 0..2), decoded(2, 1..2)]),
                (past, vec![]),
                (setup, vec![decoded(1, 0..1), decoded(4, 2..4)])
            ]),
            "decoded bytes of six reads of three variables, without values past their sizes"
        );
    }

    fn variable_bytes(payload_size: usize) -> Vec<u8> {
        let mut bytes = 7u32.to_le_bytes().to_vec();
        bytes.extend(vec![0xa5; payload_size]);
        bytes
    }

    #[test]
    fn trailing_thermal_fields_do_not_overlap() {
        let mut bytes = variable_bytes(42);
        update_efivarfs_bytes(
            VariableInterface::Efivarfs,
            &mut bytes,
            42,
            38,
            &95u16.to_le_bytes(),
        )
        .expect("update 38");
        update_efivarfs_bytes(
            VariableInterface::Efivarfs,
            &mut bytes,
            42,
            40,
            &90u16.to_le_bytes(),
        )
        .expect("update 40");
        assert_eq!(
            &bytes[EFIVARFS_HEADER_SIZE + 38..][..2],
            &95u16.to_le_bytes()
        );
        assert_eq!(
            &bytes[EFIVARFS_HEADER_SIZE + 40..][..2],
            &90u16.to_le_bytes()
        );
        assert_eq!(&bytes[..4], &7u32.to_le_bytes());
    }

    #[test]
    fn rejects_writes_past_the_payload_without_changing_bytes() {
        for (offset, encoded) in [(42, &[1][..]), (41, &[1, 2]), (u16::MAX, &[1])] {
            let mut bytes = variable_bytes(42);
            let original = bytes.clone();
            assert_eq!(
                update_efivarfs_bytes(VariableInterface::Efivarfs, &mut bytes, 42, offset, encoded)
                    .map_err(|error| error.to_string()),
                Err("write past the efivarfs payload".to_string()),
                "{} bytes at offset {offset}",
                encoded.len()
            );
            assert_eq!(
                bytes,
                original,
                "{} bytes at offset {offset}",
                encoded.len()
            );
        }
    }

    #[test]
    fn rejects_short_payload_even_when_requested_field_fits() {
        for offset in [0, 40] {
            let mut bytes = variable_bytes(39);
            let original = bytes.clone();
            assert!(update_efivarfs_bytes(
                VariableInterface::Efivarfs,
                &mut bytes,
                42,
                offset,
                &1u16.to_le_bytes()
            )
            .is_err());
            assert_eq!(bytes, original);
        }
    }

    #[test]
    fn rejects_incomplete_attributes_header() {
        for length in 0..EFIVARFS_HEADER_SIZE {
            let mut bytes = vec![0xa5; length];
            let original = bytes.clone();
            assert!(
                update_efivarfs_bytes(VariableInterface::Efivarfs, &mut bytes, 1, 0, &[1]).is_err()
            );
            assert_eq!(bytes, original);
        }
    }

    #[test]
    fn preserves_bytes_beyond_declared_varstore() {
        let mut bytes = variable_bytes(50);
        let original = bytes.clone();
        update_efivarfs_bytes(
            VariableInterface::Efivarfs,
            &mut bytes,
            42,
            40,
            &95u16.to_le_bytes(),
        )
        .expect("update 40");
        assert_eq!(&bytes[46..], &original[46..]);
        assert_eq!(&bytes[..44], &original[..44]);
        assert_eq!(bytes.len(), original.len());
    }

    #[test]
    fn writes_small_and_maximum_sized_varstores() {
        for size in [1, 2, u16::MAX] {
            let mut bytes = variable_bytes(usize::from(size));
            update_efivarfs_bytes(
                VariableInterface::Efivarfs,
                &mut bytes,
                size,
                size - 1,
                &[95],
            )
            .unwrap_or_else(|error| panic!("update the last of {size} bytes: {error}"));
            assert_eq!(bytes.len(), EFIVARFS_HEADER_SIZE + usize::from(size));
            assert_eq!(bytes.last(), Some(&95));
        }
    }

    #[test]
    fn volatile_efivar_is_refused() {
        let key = variable_key("TestVarStore");
        let cases = [
            (
                BS_RT,
                Err(
                    "EFI variable TestVarStore-00000000-0000-0000-0000-000000000000 is volatile \
                     (no EFI_VARIABLE_NON_VOLATILE) and cannot be written through efivarfs"
                        .to_string(),
                ),
            ),
            (NV_BS_RT, Ok(())),
        ];
        for (attributes, want) in cases {
            assert_eq!(
                check_non_volatile(&key, VariableInterface::Efivarfs, attributes)
                    .map_err(|error| error.to_string()),
                want,
                "attributes {attributes:#x}"
            );
        }
    }

    /// check_runtime_writable refuses a variable without EFI_VARIABLE_RUNTIME_ACCESS for variables
    /// that reach Runtime, and nothing else.
    #[test]
    fn variable_without_runtime_access_is_refused_at_runtime() {
        let key = variable_key("TestVarStore");
        let refusal = "EFI variable TestVarStore-00000000-0000-0000-0000-000000000000 has no \
                       EFI_VARIABLE_RUNTIME_ACCESS (attributes 0x3), so the firmware refuses to \
                       write it at OS runtime";
        let cases = [
            (NV_BS, VariableReach::Runtime, Err(refusal.to_string())),
            (NV_BS, VariableReach::BootServices, Ok(())),
            (NV_BS_RT, VariableReach::Runtime, Ok(())),
            (NV_BS_RT, VariableReach::BootServices, Ok(())),
        ];
        for (attributes, reach, want) in cases {
            assert_eq!(
                check_runtime_writable(&key, reach, attributes).map_err(|error| error.to_string()),
                want,
                "attributes {attributes:#x}, {reach:?}"
            );
        }
    }

    /// A variable read gives the attributes word and the first `size` data bytes, and fails for
    /// fewer data bytes.
    #[test]
    fn attributes_and_data_start_as_an_efivarfs_file() {
        let key = variable_key("Setup");
        let cases = [
            (2, Ok([&NV_BS_RT.to_ne_bytes()[..], &[1, 2]].concat())),
            (3, Ok([&NV_BS_RT.to_ne_bytes()[..], &[1, 2, 3]].concat())),
            (0, Ok(NV_BS_RT.to_ne_bytes().to_vec())),
            (
                4,
                Err(
                    "EFI variable Setup-00000000-0000-0000-0000-000000000000 holds 3 data bytes, \
                     fewer than the 4 of its VarStore"
                        .to_string(),
                ),
            ),
        ];
        for (size, want) in cases {
            assert_eq!(
                attributes_and_data(&key, NV_BS_RT, &[1, 2, 3], size)
                    .map_err(|error| error.to_string()),
                want,
                "{size} bytes"
            );
        }
    }

    /// write_at writes the value at its offset and keeps the attributes word and the other bytes,
    /// also those past the VarStore.
    #[test]
    fn write_at_writes_the_value_and_keeps_the_other_bytes() {
        let variables = MemoryVariables::default();
        variables.insert(variable_key("Setup"), NV_BS_RT, &[1, 2, 3, 4, 5]);

        variables
            .write_at(&variable_key("Setup"), 4, 1, &[0x2A, 0x2B])
            .expect("write 2 bytes at offset 1");

        assert_eq!(
            variables.bytes(&variable_key("Setup")),
            Some([&NV_BS_RT.to_ne_bytes()[..], &[1, 0x2A, 0x2B, 4, 5]].concat()),
            "attributes, then the data with bytes 1 and 2 written"
        );
    }

    /// modify_variable_bytes refuses a volatile variable, in the words of its interface, and keeps
    /// its bytes.
    #[test]
    fn modify_variable_bytes_refuses_a_volatile_variable() {
        let key = variable_key("Volatile");
        let cases = [
            (
                VariableInterface::Efivarfs,
                "EFI variable Volatile-00000000-0000-0000-0000-000000000000 is volatile (no \
                 EFI_VARIABLE_NON_VOLATILE) and cannot be written through efivarfs",
            ),
            (
                VariableInterface::VariableServices,
                "EFI variable Volatile-00000000-0000-0000-0000-000000000000 is volatile (no \
                 EFI_VARIABLE_NON_VOLATILE), so a write would not outlast a power cycle; pass \
                 --allow-volatile to write it anyway",
            ),
        ];
        for (interface, want) in cases {
            let mut bytes = [&BS_RT.to_ne_bytes()[..], &[1]].concat();
            let before = bytes.clone();

            let error = modify_variable_bytes(
                &variables_of(interface),
                &key,
                VolatileWrites::Refuse,
                &mut bytes,
                1,
                &[patch(0, &[0x2A])],
            )
            .expect_err("modify a volatile variable");

            assert_eq!(error.to_string(), want, "{interface:?}: refusal");
            assert_eq!(bytes, before, "{interface:?}: bytes");
        }
    }

    /// Before ExitBootServices (UEFI 2.11 §8.2.3), modify_variable_bytes writes a volatile variable
    /// of the UEFI Shell's GetVariable() and SetVariable() under VolatileWrites::Allow.
    #[test]
    fn modify_variable_bytes_writes_a_volatile_shell_variable_if_allowed() {
        let key = variable_key("Volatile");
        let mut bytes = [&BS_RT.to_ne_bytes()[..], &[1]].concat();

        let got = modify_variable_bytes(
            &variables_of(VariableInterface::VariableServices),
            &key,
            VolatileWrites::Allow,
            &mut bytes,
            1,
            &[patch(0, &[0x2A])],
        );

        assert_eq!(got.map_err(|error| error.to_string()), Ok(()), "write");
        assert_eq!(bytes, [&BS_RT.to_ne_bytes()[..], &[0x2A]].concat(), "bytes");
    }

    /// modify_variable_bytes keeps refusing a volatile variable, and its bytes, without
    /// VolatileWrites::Allow, and through variables that reach Runtime whatever the policy:
    /// SetVariable() sets no volatile variable after ExitBootServices (UEFI 2.11 §8.2.3).
    #[test]
    fn modify_variable_bytes_refuses_a_volatile_variable_unless_allowed_before_exit_boot_services()
    {
        let key = variable_key("Volatile");
        let cases = [
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
                VolatileWrites::Refuse,
                ", so a write would not outlast a power cycle; pass --allow-volatile to write it \
                 anyway",
            ),
            (
                VariableReach::Runtime,
                VariableInterface::Efivarfs,
                VolatileWrites::Allow,
                " and cannot be written through efivarfs",
            ),
            (
                VariableReach::Runtime,
                VariableInterface::FirmwareEnvironment,
                VolatileWrites::Allow,
                ", so a write would not outlast a power cycle",
            ),
        ];
        for (reach, interface, volatile, refusal) in cases {
            let mut bytes = [&BS_RT.to_ne_bytes()[..], &[1]].concat();
            let before = bytes.clone();

            let got = modify_variable_bytes(
                &MemoryVariables::new(reach, interface),
                &key,
                volatile,
                &mut bytes,
                1,
                &[patch(0, &[0x2A])],
            );

            let case = format!("{reach:?}, {interface:?}, {volatile:?}");
            assert_eq!(
                got.map_err(|error| error.to_string()),
                Err(format!(
                    "EFI variable Volatile-00000000-0000-0000-0000-000000000000 is volatile (no \
                     EFI_VARIABLE_NON_VOLATILE){refusal}"
                )),
                "{case}: refusal"
            );
            assert_eq!(bytes, before, "{case}: bytes");
        }
    }

    /// set's stacks write a volatile variable as the bound policy says, by write_patches whatever
    /// policy it passes: WithholdingVariables over VolatileWritingVariables, and set_questions's
    /// VolatileWritingVariables over WithholdingVariables, here over a boxed backend.
    #[test]
    fn set_stack_writes_a_volatile_variable_by_its_bound_policy_alone() {
        #[derive(Debug, Clone, Copy)]
        enum Stack {
            WithholdingOverDecorator,
            DecoratorOverWithholdingOverBox,
        }
        let key = variable_key("Volatile");
        let refusal = "EFI variable Volatile-00000000-0000-0000-0000-000000000000 is volatile (no \
                       EFI_VARIABLE_NON_VOLATILE), so a write would not outlast a power cycle; \
                       pass --allow-volatile to write it anyway";
        for stack in [
            Stack::WithholdingOverDecorator,
            Stack::DecoratorOverWithholdingOverBox,
        ] {
            for bound in [VolatileWrites::Refuse, VolatileWrites::Allow] {
                for passed in [VolatileWrites::Refuse, VolatileWrites::Allow] {
                    let variables = MemoryVariables::new(
                        VariableReach::BootServices,
                        VariableInterface::VariableServices,
                    );
                    variables.insert(key.clone(), BS_RT, &[1]);
                    let write = |stack: &dyn FirmwareVariables| {
                        stack.write_patches(
                            &key,
                            1,
                            &[patch(0, &[0x2A])],
                            passed,
                            MissingVariable::Refuse,
                        )
                    };

                    let got = match stack {
                        Stack::WithholdingOverDecorator => write(&WithholdingVariables::new(
                            VolatileWritingVariables::new(&variables, bound),
                            WithheldBytes::default(),
                        )),
                        Stack::DecoratorOverWithholdingOverBox => {
                            let boxed: Box<dyn FirmwareVariables + '_> = Box::new(&variables);
                            write(&VolatileWritingVariables::new(
                                &WithholdingVariables::new(boxed, WithheldBytes::default()),
                                bound,
                            ))
                        }
                    };

                    let case = format!("{stack:?}, {bound:?}, {passed:?}");
                    let (want, want_data): (Result<(), String>, &[u8]) = match bound {
                        VolatileWrites::Refuse => (Err(refusal.to_string()), &[1]),
                        VolatileWrites::Allow => (Ok(()), &[0x2A]),
                    };
                    assert_eq!(got.map_err(|error| error.to_string()), want, "{case}");
                    assert_eq!(
                        variables.bytes(&key),
                        Some([&BS_RT.to_ne_bytes()[..], want_data].concat()),
                        "{case}: bytes"
                    );
                }
            }
        }
    }

    /// VolatileWritingVariables reach what their variables reach, through the same interface, and
    /// read what they hold, whatever their policy.
    #[test]
    fn volatile_writing_variables_reach_and_read_as_their_variables() {
        let key = variable_key("Volatile");
        for interface in [
            VariableInterface::Efivarfs,
            VariableInterface::VariableServices,
            VariableInterface::FirmwareEnvironment,
        ] {
            let variables = variables_of(interface);
            variables.insert(key.clone(), BS_RT, &[1]);
            for volatile in [VolatileWrites::Refuse, VolatileWrites::Allow] {
                let decorated = VolatileWritingVariables::new(&variables, volatile);

                let case = format!("{interface:?}, {volatile:?}");
                assert_eq!(
                    (decorated.reach(), decorated.interface()),
                    (variables.reach(), interface),
                    "{case}"
                );
                assert_eq!(
                    decorated.read(&key, 1).map_err(|error| error.to_string()),
                    Ok([&BS_RT.to_ne_bytes()[..], &[1]].concat()),
                    "{case}: read"
                );
                assert_eq!(
                    decorated
                        .read_whole(&key)
                        .map_err(|error| error.to_string()),
                    Ok([&BS_RT.to_ne_bytes()[..], &[1]].concat()),
                    "{case}: read_whole"
                );
            }
        }
    }

    /// modify_variable_bytes refuses a variable with authenticated access, whose writes need a
    /// signed descriptor (UEFI 2.10 §8.2.3), whatever its interface, and keeps its bytes.
    #[test]
    fn modify_variable_bytes_refuses_an_authenticated_variable() {
        let key = variable_key("Signed");
        for interface in [
            VariableInterface::Efivarfs,
            VariableInterface::VariableServices,
        ] {
            for attributes in [NV_BS_RT | 0x10, NV_BS_RT | 0x20, NV_BS_RT | 0x80] {
                let mut bytes = [&attributes.to_ne_bytes()[..], &[1]].concat();
                let before = bytes.clone();

                let error = modify_variable_bytes(
                    &variables_of(interface),
                    &key,
                    VolatileWrites::Allow,
                    &mut bytes,
                    1,
                    &[patch(0, &[0x2A])],
                )
                .expect_err("modify an authenticated variable");

                assert_eq!(
                    error.to_string(),
                    format!(
                        "EFI variable Signed-00000000-0000-0000-0000-000000000000 has \
                         authenticated access (attributes {attributes:#x}), which uefisettings \
                         does not write"
                    ),
                    "{interface:?}, attributes {attributes:#x}: refusal"
                );
                assert_eq!(
                    bytes, before,
                    "{interface:?}, attributes {attributes:#x}: bytes"
                );
            }
        }
    }

    /// modify_variable_bytes refuses a variable whose data is shorter than its VarStore, also
    /// where the value fits, and keeps its bytes.
    #[test]
    fn modify_variable_bytes_refuses_data_shorter_than_the_var_store() {
        let key = variable_key("Short");
        let mut bytes = [&NV_BS_RT.to_ne_bytes()[..], &[1, 2]].concat();
        let before = bytes.clone();

        let error = modify_variable_bytes(
            &variables_of(VariableInterface::Efivarfs),
            &key,
            VolatileWrites::Refuse,
            &mut bytes,
            4,
            &[patch(0, &[0x2A])],
        )
        .expect_err("modify a variable shorter than its VarStore");

        assert_eq!(
            error.to_string(),
            "efivarfs payload is shorter than the declared varstore: 2 < 4 bytes",
            "refusal"
        );
        assert_eq!(bytes, before, "bytes");
    }

    /// modify_variable_bytes refuses a variable without its whole attributes word and keeps its
    /// bytes.
    #[test]
    fn modify_variable_bytes_refuses_a_variable_without_attributes() {
        let key = variable_key("Headless");
        let mut bytes = vec![7, 0];
        let before = bytes.clone();

        let error = modify_variable_bytes(
            &variables_of(VariableInterface::Efivarfs),
            &key,
            VolatileWrites::Refuse,
            &mut bytes,
            0,
            &[patch(0, &[])],
        )
        .expect_err("modify a variable without its attributes word");

        assert_eq!(
            error.to_string(),
            "efivarfs file is missing its attributes header",
            "refusal"
        );
        assert_eq!(bytes, before, "bytes");
    }
}
