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
//! (efivarfs.rs), GetVariable() and SetVariable() in the UEFI Shell (variable_services.rs).

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;
use std::ops::Range;

#[cfg(system_variables)]
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use thiserror::Error;

use crate::hii::package::Guid;

/// The size of the attributes word that FirmwareVariables::read gives before the data, as
/// efivarfs does.
pub(super) const EFIVARFS_HEADER_SIZE: usize = std::mem::size_of::<u32>();
const EFI_VARIABLE_NON_VOLATILE: u32 = 0x00000001;
/// EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS (UEFI 2.10 §8.2.1)
const EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS: u32 = 0x00000080;
/// EFI_VARIABLE_AUTHENTICATED_WRITE_ACCESS, EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS
/// and EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS (UEFI 2.10 §8.2.1)
const EFI_VARIABLE_AUTHENTICATED_ACCESS: u32 =
    0x00000010 | 0x00000020 | EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS;

/// A firmware variable: its name and vendor GUID (UEFI 2.10 §8.2.1).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct VariableKey {
    pub(crate) name: String,
    pub(crate) guid: Guid,
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

/// Which variables FirmwareVariables reach: after ExitBootServices, as through efivarfs,
/// GetVariable, GetNextVariableName and SetVariable reach only those with
/// EFI_VARIABLE_RUNTIME_ACCESS; before it, as in the UEFI Shell, all (UEFI 2.10 §8.2.1-§8.2.3).
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

/// The texts of errors about variables of each reach: Runtime as through Linux's efivarfs,
/// BootServices as through GetVariable() and SetVariable() in the UEFI Shell.
impl VariableReach {
    /// What errors call the data bytes of a variable, which follow its attributes word.
    #[cfg(system_variables)]
    fn data(self) -> &'static str {
        match self {
            Self::Runtime => "efivarfs payload",
            Self::BootServices => "GetVariable() data",
        }
    }

    /// The error for variable bytes without their whole attributes word.
    #[cfg(system_variables)]
    fn missing_attributes(self) -> &'static str {
        match self {
            Self::Runtime => "efivarfs file is missing its attributes header",
            Self::BootServices => "variable bytes are missing their attributes word",
        }
    }

    /// What errors call a write of a question's value.
    pub(super) fn write(self) -> &'static str {
        match self {
            Self::Runtime => "efivarfs write",
            Self::BootServices => "SetVariable() write",
        }
    }

    /// Why set refuses a volatile variable, after its name.
    fn volatile_refusal(self) -> &'static str {
        match self {
            Self::Runtime => " and cannot be written through efivarfs",
            Self::BootServices => ", so a write would not outlast a power cycle",
        }
    }

    /// Why set cannot write a variable that does not exist, after its VariableNotFound.
    pub(super) fn not_found_refusal(self) -> &'static str {
        match self {
            Self::Runtime => {
                "the firmware has not created it or does not expose it to the OS, so its \
                 questions cannot be set from Linux; change them in the firmware setup, or ask \
                 the board vendor for firmware that exposes it; see \
                 https://github.com/linuxboot/uefisettings/issues/2"
            }
            Self::BootServices => {
                "the firmware has not created it, and set never creates variables"
            }
        }
    }
}

/// The firmware variables that questions read and set: efivarfs on Linux, GetVariable/SetVariable
/// in the UEFI Shell.
/// A variable that does not exist is VariableNotFound, which get shows as missing and set
/// explains.
pub(crate) trait FirmwareVariables {
    /// Which variables these reach.
    fn reach(&self) -> VariableReach;
    /// The attributes word and the first `size` data bytes of `key`, as an efivarfs file starts.
    fn read(&self, key: &VariableKey, size: u16) -> Result<Vec<u8>>;
    /// Writes `encoded` at data offset `offset` of `key`, whose VarStore has `size` bytes,
    /// keeping its attributes and other bytes.
    fn write_at(&self, key: &VariableKey, size: u16, offset: u16, encoded: &[u8]) -> Result<()>;
}

impl<T: FirmwareVariables + ?Sized> FirmwareVariables for &T {
    fn reach(&self) -> VariableReach {
        (**self).reach()
    }

    fn read(&self, key: &VariableKey, size: u16) -> Result<Vec<u8>> {
        (**self).read(key, size)
    }

    fn write_at(&self, key: &VariableKey, size: u16, offset: u16, encoded: &[u8]) -> Result<()> {
        (**self).write_at(key, size, offset, encoded)
    }
}

impl<T: FirmwareVariables + ?Sized> FirmwareVariables for Box<T> {
    fn reach(&self) -> VariableReach {
        (**self).reach()
    }

    fn read(&self, key: &VariableKey, size: u16) -> Result<Vec<u8>> {
        (**self).read(key, size)
    }

    fn write_at(&self, key: &VariableKey, size: u16, offset: u16, encoded: &[u8]) -> Result<()> {
        (**self).write_at(key, size, offset, encoded)
    }
}

/// The attribute word of efivar file bytes, which Linux v7.2 fs/efivarfs/file.c
/// efivarfs_file_read() copies as a native u32 before the payload; None for fewer bytes.
pub(super) fn efivar_attributes(bytes: &[u8]) -> Option<u32> {
    bytes
        .first_chunk::<EFIVARFS_HEADER_SIZE>()
        .copied()
        .map(u32::from_ne_bytes)
}

/// What FirmwareVariables::read gives for the variable `key` whose GetVariable() returned
/// `attributes` and `data`: the attributes word and the first `size` data bytes, as an efivarfs
/// file starts.
#[cfg_attr(
    not(target_os = "uefi"),
    allow(
        dead_code,
        reason = "efivarfs reads its files; the UEFI build and the tests' MemoryVariables call it"
    )
)]
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

/// The read-modify-write of FirmwareVariables::write_at on `bytes`, the attributes word and all
/// the data of variable `key`, which variables of `reach` hold: refuses a volatile or
/// authenticated variable, then writes `encoded` at data offset `offset` as update_efivarfs_bytes
/// does.
#[cfg(system_variables)]
pub(super) fn modify_variable_bytes(
    key: &VariableKey,
    reach: VariableReach,
    bytes: &mut [u8],
    size: u16,
    offset: u16,
    encoded: &[u8],
) -> Result<()> {
    let attributes = efivar_attributes(bytes).context(reach.missing_attributes())?;
    check_non_volatile(key, reach, attributes)?;
    check_unauthenticated(key, attributes)?;
    update_efivarfs_bytes(reach, bytes, size, offset, encoded)
}

/// Writes `encoded` at VarOffset `offset` of the efivar file `bytes`, unless its payload is
/// shorter than the `payload_size` bytes of its VarStore, which VarStoreWrite::new fits the
/// write in. Errors word it as variables of `reach` hold it.
#[cfg(system_variables)]
fn update_efivarfs_bytes(
    reach: VariableReach,
    bytes: &mut [u8],
    payload_size: u16,
    offset: u16,
    encoded: &[u8],
) -> Result<()> {
    let payload = bytes
        .get_mut(EFIVARFS_HEADER_SIZE..)
        .context(reach.missing_attributes())?;
    if payload.len() < usize::from(payload_size) {
        return Err(anyhow!(
            "{} is shorter than the declared varstore: {} < {} bytes",
            reach.data(),
            payload.len(),
            payload_size
        ));
    }

    let start = usize::from(offset);
    payload
        .get_mut(start..start + encoded.len())
        .with_context(|| format!("write past the {}", reach.data()))?
        .copy_from_slice(encoded);
    Ok(())
}

/// Refuses an EFI variable without EFI_VARIABLE_NON_VOLATILE, which efivarfs cannot write
/// (UEFI 2.10 §8.2.3) and a power cycle would erase; errors word it as variables of `reach` hold
/// it.
/// Takes the variable's own attribute word, which its write passes to SetVariable(), not
/// VARSTORE_EFI's Attributes; check_runtime_access cannot, as a boot-service-only variable has
/// no file.
pub(super) fn check_non_volatile(
    key: &VariableKey,
    reach: VariableReach,
    attributes: u32,
) -> std::result::Result<(), VolatileVariable> {
    if attributes & EFI_VARIABLE_NON_VOLATILE == 0 {
        return Err(VolatileVariable {
            key: key.clone(),
            reach,
        });
    }
    Ok(())
}

/// An EFI variable without EFI_VARIABLE_NON_VOLATILE, which set refuses.
#[derive(Error, Debug)]
#[error(
    "EFI variable {key} is volatile (no EFI_VARIABLE_NON_VOLATILE){}",
    .reach.volatile_refusal()
)]
pub(super) struct VolatileVariable {
    key: VariableKey,
    reach: VariableReach,
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

/// Refuses to decode an EFI variable with EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS, which its
/// `attributes` word names: its data starts with metadata (UEFI 2.10 §8.2.1), where questions
/// would decode their values.
pub(super) fn check_decodable(
    key: &VariableKey,
    attributes: u32,
) -> std::result::Result<(), EnhancedAuthenticatedVariable> {
    if attributes & EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS != 0 {
        return Err(EnhancedAuthenticatedVariable {
            key: key.clone(),
            attributes,
        });
    }
    Ok(())
}

/// An EFI variable with EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS, which questions do not
/// decode.
#[derive(Error, Debug)]
#[error(
    "EFI variable {key} has enhanced authenticated access (attributes {attributes:#x}): its data \
     starts with metadata, which uefisettings does not decode"
)]
pub(super) struct EnhancedAuthenticatedVariable {
    key: VariableKey,
    attributes: u32,
}

/// A variable that FirmwareVariables does not hold.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("no EFI variable {0}")]
pub(super) struct VariableNotFound(pub(super) VariableKey);

/// Where question values are read: the variables of this machine, a directory of efivar files,
/// or none.
// Each backend makes the variables of a source in EfivarSource::into_variables: efivarfs.rs,
// variable_services.rs; a build without variables of its own makes them below.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub enum EfivarSource {
    /// This machine's variables: its efivarfs on Linux, GetVariable() in the UEFI Shell.
    #[cfg(system_variables)]
    #[default]
    System,
    /// A directory of efivar files in efivarfs format, such as a copy of another machine's.
    #[cfg(target_os = "linux")]
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
            #[cfg(target_os = "linux")]
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
            Self::Disabled => Box::new(UnreadVariables(VariableReach::Runtime)),
        })
    }
}

/// Why EfivarSource::validate refuses a Directory.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("efivars directory {} is not a directory", .0.display())]
pub(super) struct EfivarsNotADirectory(std::path::PathBuf);

/// The outcome of every efivar range under EfivarSource::Disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("EFI variables not read")]
pub(super) struct EfivarsNotRead;

/// The variables of EfivarSource::Disabled: every read and write fails with EfivarsNotRead. They
/// reach what the build's own variables reach, or Runtime, as Linux's efivarfs, on a build
/// without any, so that each refusal of a VarStore stays.
pub(super) struct UnreadVariables(pub(super) VariableReach);

impl FirmwareVariables for UnreadVariables {
    fn reach(&self) -> VariableReach {
        self.0
    }

    fn read(&self, _key: &VariableKey, _size: u16) -> Result<Vec<u8>> {
        Err(EfivarsNotRead.into())
    }

    fn write_at(
        &self,
        _key: &VariableKey,
        _size: u16,
        _offset: u16,
        _encoded: &[u8],
    ) -> Result<()> {
        Err(EfivarsNotRead.into())
    }
}

/// The arguments of FirmwareVariables::read, which an EfivarReader reads once.
#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct EfivarRange {
    pub(super) key: VariableKey,
    pub(super) size: u16,
}

/// The payload bytes `value` that a question decodes from a variable, of which
/// FirmwareVariables::read reads `size` payload bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DecodedValue {
    pub(super) size: u16,
    pub(super) value: Range<usize>,
}

/// Reads each EfivarRange of one command once, keeping the outcomes:
/// Linux v7.2 efivarfs sleeps once a non-root user has read 100 times within a second
/// (fs/efivarfs/file.c, kernel/user.c). VarStore names that differ only in '/' and '!' are two
/// keys of one efivarfs file, which it reads once for each.
pub(crate) struct EfivarReader {
    variables: Box<dyn FirmwareVariables>,
    pub(super) outcomes: BTreeMap<EfivarRange, Result<Vec<u8>>>,
    /// The payload bytes that the callers of read decode, by variable
    pub(super) decoded: BTreeMap<VariableKey, Vec<DecodedValue>>,
}

impl EfivarReader {
    /// Reads the variables of `source`, which EfivarSource::validate accepts.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(
            dead_code,
            reason = "the exports withhold password VarStores from a source's variables; only \
                      the Linux build's dump-efivars and the tests read a source as it is"
        )
    )]
    pub(crate) fn new(source: EfivarSource) -> Result<Self> {
        Ok(Self::with_variables(source.into_variables()?))
    }

    /// Reads `variables`.
    pub(crate) fn with_variables(variables: Box<dyn FirmwareVariables>) -> Self {
        Self {
            variables,
            outcomes: BTreeMap::new(),
            decoded: BTreeMap::new(),
        }
    }

    /// Which variables this reader reaches.
    pub(crate) fn reach(&self) -> VariableReach {
        self.variables.reach()
    }

    /// FirmwareVariables::read of `range`, read once.
    /// The caller decodes the payload bytes `value`, which this records in `decoded` with
    /// `range.size` unless they end past the `range.size` bytes that FirmwareVariables::read
    /// reads, where they never decode. The variable is recorded either way, so that a dump answers
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
                value,
            });
        }
        let variables = &self.variables;
        self.outcomes
            .entry(range)
            .or_insert_with_key(|range| variables.read(&range.key, range.size))
            .as_deref()
    }
}

/// `variables` without the `withheld` ones, the VarStores that PASSWORD questions name: each read
/// or write of one fails with WithheldVariable, before `variables` see it.
pub(crate) struct WithholdingVariables<V> {
    variables: V,
    withheld: BTreeSet<VariableKey>,
}

impl<V> WithholdingVariables<V> {
    pub(super) fn new(variables: V, withheld: BTreeSet<VariableKey>) -> Self {
        Self {
            variables,
            withheld,
        }
    }

    /// Refuses the variable `key` if it is withheld.
    fn check(&self, key: &VariableKey) -> std::result::Result<(), WithheldVariable> {
        match self.withheld.contains(key) {
            true => Err(WithheldVariable(key.clone())),
            false => Ok(()),
        }
    }
}

impl<V: FirmwareVariables> FirmwareVariables for WithholdingVariables<V> {
    fn reach(&self) -> VariableReach {
        self.variables.reach()
    }

    fn read(&self, key: &VariableKey, size: u16) -> Result<Vec<u8>> {
        self.check(key)?;
        self.variables.read(key, size)
    }

    fn write_at(&self, key: &VariableKey, size: u16, offset: u16, encoded: &[u8]) -> Result<()> {
        self.check(key)?;
        self.variables.write_at(key, size, offset, encoded)
    }
}

/// The outcome of every read and write of a variable that WithholdingVariables withhold: a
/// password VarStore.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("EFI variable {0} holds a password, which the UEFI Shell build never reads or writes")]
pub(super) struct WithheldVariable(pub(super) VariableKey);

#[cfg(test)]
pub(crate) mod tests {
    use std::cell::RefCell;
    use std::fs;
    use std::rc::Rc;

    use super::*;

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
    /// reach `reach`. Records every read and the writes that succeed, and fails those of the
    /// variables in `failures`.
    pub(crate) struct MemoryVariables {
        reach: VariableReach,
        variables: RefCell<BTreeMap<VariableKey, Vec<u8>>>,
        failures: BTreeMap<VariableKey, WriteError>,
        reads: RefCell<Vec<(VariableKey, u16)>>,
        writes: RefCell<Vec<(VariableKey, u16, Vec<u8>)>>,
    }

    /// No variables, reaching what efivarfs reaches.
    impl Default for MemoryVariables {
        fn default() -> Self {
            Self::with_reach(VariableReach::Runtime)
        }
    }

    impl MemoryVariables {
        /// No variables, reaching `reach`.
        pub(crate) fn with_reach(reach: VariableReach) -> Self {
            Self {
                reach,
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

        /// The data offsets and values of the writes to `key` that succeeded, in order.
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

        fn write_at(
            &self,
            key: &VariableKey,
            size: u16,
            offset: u16,
            encoded: &[u8],
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
            let bytes = variables
                .get_mut(key)
                .ok_or_else(|| VariableNotFound(key.clone()))?;
            let mut modified = bytes.clone();
            modify_variable_bytes(key, self.reach, &mut modified, size, offset, encoded)?;
            *bytes = modified;
            self.writes
                .borrow_mut()
                .push((key.clone(), offset, encoded.to_vec()));
            Ok(())
        }
    }

    /// Shares MemoryVariables with an EfivarReader, which owns its variables.
    impl FirmwareVariables for Rc<MemoryVariables> {
        fn reach(&self) -> VariableReach {
            self.as_ref().reach()
        }

        fn read(&self, key: &VariableKey, size: u16) -> Result<Vec<u8>> {
            self.as_ref().read(key, size)
        }

        fn write_at(
            &self,
            key: &VariableKey,
            size: u16,
            offset: u16,
            encoded: &[u8],
        ) -> Result<()> {
            self.as_ref().write_at(key, size, offset, encoded)
        }
    }

    /// The variable `name` of NIL_GUID.
    pub(crate) fn variable_key(name: &str) -> VariableKey {
        VariableKey {
            name: name.to_string(),
            guid: NIL_GUID,
        }
    }

    /// The errors of a write word it as variables of their reach hold it: Runtime as efivarfs,
    /// BootServices as GetVariable() and SetVariable(), never efivarfs.
    #[test]
    fn write_errors_follow_their_reach() {
        let volatile = |reach| {
            check_non_volatile(&variable_key("Volatile"), reach, BS_RT)
                .map_err(|error| error.to_string())
        };
        let short = |reach| {
            update_efivarfs_bytes(reach, &mut variable_bytes(2), 4, 0, &[1])
                .map_err(|error| error.to_string())
        };
        let past = |reach| {
            update_efivarfs_bytes(reach, &mut variable_bytes(4), 4, 4, &[1])
                .map_err(|error| format!("{error:#}"))
        };
        let headless = |reach| {
            update_efivarfs_bytes(reach, &mut [7, 0], 0, 0, &[])
                .map_err(|error| format!("{error:#}"))
        };
        let cases = [
            (
                VariableReach::Runtime,
                "EFI variable Volatile-00000000-0000-0000-0000-000000000000 is volatile (no \
                 EFI_VARIABLE_NON_VOLATILE) and cannot be written through efivarfs",
                "efivarfs payload is shorter than the declared varstore: 2 < 4 bytes",
                "write past the efivarfs payload",
                "efivarfs file is missing its attributes header",
                "efivarfs write",
            ),
            (
                VariableReach::BootServices,
                "EFI variable Volatile-00000000-0000-0000-0000-000000000000 is volatile (no \
                 EFI_VARIABLE_NON_VOLATILE), so a write would not outlast a power cycle",
                "GetVariable() data is shorter than the declared varstore: 2 < 4 bytes",
                "write past the GetVariable() data",
                "variable bytes are missing their attributes word",
                "SetVariable() write",
            ),
        ];
        for (reach, want_volatile, want_short, want_past, want_headless, want_write) in cases {
            assert_eq!(
                volatile(reach),
                Err(want_volatile.to_string()),
                "{reach:?}: volatile"
            );
            assert_eq!(
                short(reach),
                Err(want_short.to_string()),
                "{reach:?}: short"
            );
            assert_eq!(past(reach), Err(want_past.to_string()), "{reach:?}: past");
            assert_eq!(
                headless(reach),
                Err(want_headless.to_string()),
                "{reach:?}: headless"
            );
            assert_eq!(reach.write(), want_write, "{reach:?}: write");
        }
    }

    /// set's refusal of a variable that does not exist follows its reach: Runtime as on Linux,
    /// BootServices, which reach every variable that the firmware has created.
    #[test]
    fn not_found_refusal_follows_its_reach() {
        assert_eq!(
            VariableReach::Runtime.not_found_refusal(),
            "the firmware has not created it or does not expose it to the OS, so its questions \
             cannot be set from Linux; change them in the firmware setup, or ask the board vendor \
             for firmware that exposes it; see https://github.com/linuxboot/uefisettings/issues/2",
            "Runtime"
        );
        assert_eq!(
            VariableReach::BootServices.not_found_refusal(),
            "the firmware has not created it, and set never creates variables",
            "BootServices"
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

    /// WithholdingVariables refuse to read or write a withheld variable before their variables
    /// see it, and pass the others through.
    #[test]
    fn withheld_variable_is_neither_read_nor_written() {
        let variables = MemoryVariables::with_reach(VariableReach::BootServices);
        variables.insert(variable_key("Setup"), NV_BS_RT, &[1]);
        variables.insert(variable_key("AMITSESetup"), NV_BS_RT, &[0xAA]);
        let withholding =
            WithholdingVariables::new(&variables, BTreeSet::from([variable_key("AMITSESetup")]));
        let withheld = |error: anyhow::Error| error.downcast_ref::<WithheldVariable>().cloned();

        assert_eq!(
            withholding
                .read(&variable_key("AMITSESetup"), 1)
                .map_err(withheld),
            Err(Some(WithheldVariable(variable_key("AMITSESetup")))),
            "read AMITSESetup"
        );
        assert_eq!(
            withholding
                .write_at(&variable_key("AMITSESetup"), 1, 0, &[0])
                .map_err(withheld),
            Err(Some(WithheldVariable(variable_key("AMITSESetup")))),
            "write AMITSESetup"
        );
        assert_eq!(
            withholding.read(&variable_key("Setup"), 1).ok(),
            Some([&NV_BS_RT.to_ne_bytes()[..], &[1]].concat()),
            "read Setup"
        );
        withholding
            .write_at(&variable_key("Setup"), 1, 0, &[2])
            .expect("write Setup");
        assert_eq!(
            variables.reads(),
            [(variable_key("Setup"), 1)],
            "reads: Setup only"
        );
        assert_eq!(
            variables.writes_to(&variable_key("AMITSESetup")),
            [],
            "writes to AMITSESetup"
        );
        assert_eq!(
            variables.writes_to(&variable_key("Setup")),
            [(0, vec![2])],
            "writes to Setup"
        );
    }

    #[test]
    fn disabled_source_reads_no_efivar() {
        let mut reader =
            EfivarReader::new(EfivarSource::Disabled).expect("create a reader without efivars");
        let range = EfivarRange {
            key: variable_key("Setup"),
            size: 1,
        };

        let error = reader.read(range, 0..1).expect_err("read without efivars");

        assert_eq!(
            error.downcast_ref::<EfivarsNotRead>(),
            Some(&EfivarsNotRead),
            "Disabled: {error:#}"
        );
    }

    #[test]
    fn directory_source_must_be_a_directory() {
        let dir = tempfile::tempdir().expect("create directory");
        let file = dir.path().join("file");
        fs::write(&file, b"").expect("write a file");
        let missing = dir.path().join("missing");

        for (case, source) in [
            ("System", EfivarSource::System),
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
        let decoded = |size, value| DecodedValue { size, value };

        for (key, size, value) in reads {
            let range = EfivarRange {
                key: key.clone(),
                size,
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
            VariableReach::Runtime,
            &mut bytes,
            42,
            38,
            &95u16.to_le_bytes(),
        )
        .expect("update 38");
        update_efivarfs_bytes(
            VariableReach::Runtime,
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
                update_efivarfs_bytes(VariableReach::Runtime, &mut bytes, 42, offset, encoded)
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
                VariableReach::Runtime,
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
            assert!(update_efivarfs_bytes(VariableReach::Runtime, &mut bytes, 1, 0, &[1]).is_err());
            assert_eq!(bytes, original);
        }
    }

    #[test]
    fn preserves_bytes_beyond_declared_varstore() {
        let mut bytes = variable_bytes(50);
        let original = bytes.clone();
        update_efivarfs_bytes(
            VariableReach::Runtime,
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
            update_efivarfs_bytes(VariableReach::Runtime, &mut bytes, size, size - 1, &[95])
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
                check_non_volatile(&key, VariableReach::Runtime, attributes)
                    .map_err(|error| error.to_string()),
                want,
                "attributes {attributes:#x}"
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

    /// modify_variable_bytes refuses a volatile variable, in the words of its reach, and keeps its
    /// bytes.
    #[test]
    fn modify_variable_bytes_refuses_a_volatile_variable() {
        let key = variable_key("Volatile");
        let cases = [
            (
                VariableReach::Runtime,
                "EFI variable Volatile-00000000-0000-0000-0000-000000000000 is volatile (no \
                 EFI_VARIABLE_NON_VOLATILE) and cannot be written through efivarfs",
            ),
            (
                VariableReach::BootServices,
                "EFI variable Volatile-00000000-0000-0000-0000-000000000000 is volatile (no \
                 EFI_VARIABLE_NON_VOLATILE), so a write would not outlast a power cycle",
            ),
        ];
        for (reach, want) in cases {
            let mut bytes = [&BS_RT.to_ne_bytes()[..], &[1]].concat();
            let before = bytes.clone();

            let error = modify_variable_bytes(&key, reach, &mut bytes, 1, 0, &[0x2A])
                .expect_err("modify a volatile variable");

            assert_eq!(error.to_string(), want, "{reach:?}: refusal");
            assert_eq!(bytes, before, "{reach:?}: bytes");
        }
    }

    /// modify_variable_bytes refuses a variable with authenticated access, whose writes need a
    /// signed descriptor (UEFI 2.10 §8.2.3), whatever its reach, and keeps its bytes.
    #[test]
    fn modify_variable_bytes_refuses_an_authenticated_variable() {
        let key = variable_key("Signed");
        for reach in [VariableReach::Runtime, VariableReach::BootServices] {
            for attributes in [NV_BS_RT | 0x10, NV_BS_RT | 0x20, NV_BS_RT | 0x80] {
                let mut bytes = [&attributes.to_ne_bytes()[..], &[1]].concat();
                let before = bytes.clone();

                let error = modify_variable_bytes(&key, reach, &mut bytes, 1, 0, &[0x2A])
                    .expect_err("modify an authenticated variable");

                assert_eq!(
                    error.to_string(),
                    format!(
                        "EFI variable Signed-00000000-0000-0000-0000-000000000000 has \
                         authenticated access (attributes {attributes:#x}), which uefisettings \
                         does not write"
                    ),
                    "{reach:?}, attributes {attributes:#x}: refusal"
                );
                assert_eq!(
                    bytes, before,
                    "{reach:?}, attributes {attributes:#x}: bytes"
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

        let error = modify_variable_bytes(&key, VariableReach::Runtime, &mut bytes, 4, 0, &[0x2A])
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

        let error = modify_variable_bytes(&key, VariableReach::Runtime, &mut bytes, 0, 0, &[])
            .expect_err("modify a variable without its attributes word");

        assert_eq!(
            error.to_string(),
            "efivarfs file is missing its attributes header",
            "refusal"
        );
        assert_eq!(bytes, before, "bytes");
    }
}
