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

//! The firmware variables of the UEFI Shell build: GetVariable() and SetVariable() through the
//! uefi crate, which the image's entry point initializes, while boot services run.

use core::ptr;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use uefi::runtime;
use uefi::runtime::VariableAttributes;
use uefi::runtime::VariableVendor;
use uefi::CString16;
use uefi::Status;

use crate::hii::package::Guid;
use crate::hii::variables::attributes_and_data;
use crate::hii::variables::modify_variable_bytes;
use crate::hii::variables::EfivarSource;
use crate::hii::variables::FirmwareVariables;
use crate::hii::variables::UnreadVariables;
use crate::hii::variables::VariableKey;
use crate::hii::variables::VariableNotFound;
use crate::hii::variables::VariableReach;
use crate::hii::variables::EFIVARFS_HEADER_SIZE;

/// Attributes that no variable has, as GetVariable() never returns EFI_VARIABLE_APPEND_WRITE
/// (UEFI 2.10 §8.2.1): variable_info's sign that the firmware left them unset.
const UNSET_ATTRIBUTES: u32 = u32::MAX;

impl EfivarSource {
    /// The firmware variables that questions read from this source, which validate accepts.
    pub(crate) fn into_variables(self) -> Result<Box<dyn FirmwareVariables>> {
        self.validate()?;
        Ok(match self {
            Self::System => Box::new(VariableServices),
            Self::Disabled => Box::new(UnreadVariables(VariableServices::REACH)),
        })
    }
}

/// The variables of the firmware that the UEFI Shell runs on, every one of them, as boot
/// services still run.
pub(crate) struct VariableServices;

impl VariableServices {
    /// What GetVariable() and SetVariable() reach while boot services run.
    const REACH: VariableReach = VariableReach::BootServices;
}

impl FirmwareVariables for VariableServices {
    fn reach(&self) -> VariableReach {
        Self::REACH
    }

    fn read(&self, key: &VariableKey, size: u16) -> Result<Vec<u8>> {
        let (data, attributes) = get_variable(key)?;
        attributes_and_data(key, attributes.bits(), &data, size)
    }

    fn write_at(&self, key: &VariableKey, size: u16, offset: u16, encoded: &[u8]) -> Result<()> {
        let (data, attributes) = get_variable(key)?;
        let mut bytes = [&attributes.bits().to_ne_bytes()[..], &data].concat();
        modify_variable_bytes(key, Self::REACH, &mut bytes, size, offset, encoded)?;
        let data = bytes
            .get(EFIVARFS_HEADER_SIZE..)
            .context("data after the attributes word")?;
        let (variable_name, vendor) = uefi_key(key)?;
        // GetVariable() never returns EFI_VARIABLE_APPEND_WRITE (UEFI 2.10 §8.2.1), and
        // modify_variable_bytes refuses authenticated access, so these attributes rewrite the
        // whole variable.
        runtime::set_variable(&variable_name, &vendor, attributes, data)
            .map_err(|error| anyhow!("SetVariable() of EFI variable {key}: {:?}", error.status()))
    }
}

/// What variable_info tells of an EFI variable: never its data.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VariableInfo {
    /// The variable, named as its efivar file
    pub variable: String,
    /// Its attributes bitmask (UEFI 2.10 §8.2.1)
    pub attributes: u32,
    /// The size of its data, in bytes
    pub size: usize,
}

/// The VariableInfo of the EFI variable `name` of the vendor GUID `vendor`, from GetVariable()
/// with a DataSize of 0, which reads no byte of its data: as every variable holds one at least
/// (UEFI 2.10 §8.2.3), the firmware returns EFI_BUFFER_TOO_SMALL with the attributes and the
/// size (§8.2.1), and uefi::runtime::get_variable drops the attributes then.
pub(crate) fn variable_info(name: &str, vendor: &str) -> Result<VariableInfo> {
    let guid: uefi::Guid = vendor
        .parse()
        .with_context(|| format!("vendor {vendor} is not a GUID"))?;
    let key = VariableKey {
        name: name.to_owned(),
        guid: guid.into(),
    };
    let (variable_name, variable_vendor) = uefi_key(&key)?;
    let system_table = uefi::table::system_table_raw().context("no system table")?;
    // SAFETY: the system table of the firmware, which the entry point set and boot services
    // keep
    let runtime_services = unsafe { system_table.as_ref() }.runtime_services;
    // SAFETY: the firmware's runtime services, which the system table points at
    let runtime_services = unsafe { runtime_services.as_ref() }.context("no runtime services")?;
    let mut attributes = VariableAttributes::from_bits_retain(UNSET_ATTRIBUTES);
    let mut size = 0;
    // SAFETY: GetVariable() with a NUL-terminated name, a GUID and places for the attributes
    // and the size; Data may be NULL as DataSize is 0 (§8.2.1)
    let status = unsafe {
        (runtime_services.get_variable)(
            variable_name.as_ptr().cast(),
            &variable_vendor.0,
            &mut attributes,
            &mut size,
            ptr::null_mut(),
        )
    };
    match status {
        Status::BUFFER_TOO_SMALL | Status::SUCCESS if attributes.bits() == UNSET_ATTRIBUTES => {
            Err(anyhow!(
                "GetVariable() of EFI variable {key} returned {status:?} without its attributes"
            ))
        }
        Status::BUFFER_TOO_SMALL | Status::SUCCESS => Ok(VariableInfo {
            variable: key.to_string(),
            attributes: attributes.bits(),
            size,
        }),
        Status::NOT_FOUND => Err(VariableNotFound(key).into()),
        status => Err(anyhow!("GetVariable() of EFI variable {key}: {status:?}")),
    }
}

/// GetVariable() of `key`: its data and attributes, or VariableNotFound.
fn get_variable(key: &VariableKey) -> Result<(Box<[u8]>, VariableAttributes)> {
    let (name, vendor) = uefi_key(key)?;
    runtime::get_variable_boxed(&name, &vendor).map_err(|error| match error.status() {
        Status::NOT_FOUND => VariableNotFound(key.clone()).into(),
        status => anyhow!("GetVariable() of EFI variable {key}: {status:?}"),
    })
}

/// The VariableName and VendorGuid of GetVariable() and SetVariable() for `key`.
fn uefi_key(key: &VariableKey) -> Result<(CString16, VariableVendor)> {
    let name = CString16::try_from(key.name.as_str())
        .with_context(|| format!("EFI variable {key} has a name that UCS-2 cannot hold"))?;
    Ok((name, VariableVendor(key.guid.into())))
}

impl From<Guid> for uefi::Guid {
    fn from(guid: Guid) -> Self {
        Self::from_bytes(guid.into())
    }
}

impl From<uefi::Guid> for Guid {
    fn from(guid: uefi::Guid) -> Self {
        guid.to_bytes().into()
    }
}
