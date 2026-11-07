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

//! The Hardware Device Path nodes (UEFI 2.11 §10.3.2) of named forms in Table 10.67, but Vendor's,
//! which vendor.rs writes for each Type.

use super::parameters::Parameters;
use super::DevicePathTextError;
use super::Fields;

/// The Sub-Types of UEFI 2.11 §10.3.2
pub(super) const PCI: u8 = 0x01;
pub(super) const PCCARD: u8 = 0x02;
pub(super) const MEMORY_MAPPED: u8 = 0x03;
pub(super) const VENDOR: u8 = 0x04;
pub(super) const CONTROLLER: u8 = 0x05;
pub(super) const BMC: u8 = 0x06;

pub(super) fn pci_text(data: &[u8]) -> Option<String> {
    let mut fields = Fields(data);
    let (function, device) = (fields.u8()?, fields.u8()?);
    Some(format!("Pci(0x{device:X},0x{function:X})"))
}

/// Pci(Device,Function), into Function then Device.
pub(super) fn pci(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    let device: u8 = p.integer()?;
    Ok(vec![p.integer()?, device])
}

pub(super) fn pc_card_text(data: &[u8]) -> Option<String> {
    Some(format!("PcCard(0x{:X})", Fields(data).u8()?))
}

pub(super) fn pc_card(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    Ok(vec![p.integer()?])
}

pub(super) fn memory_mapped_text(data: &[u8]) -> Option<String> {
    let mut fields = Fields(data);
    let (memory_type, start, end) = (fields.u32()?, fields.u64()?, fields.u64()?);
    Some(format!(
        "MemoryMapped(0x{memory_type:X},0x{start:X},0x{end:X})"
    ))
}

pub(super) fn memory_mapped(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    let memory_type: u32 = p.integer()?;
    let (start, end): (u64, u64) = (p.integer()?, p.integer()?);
    Ok([
        &memory_type.to_le_bytes()[..],
        &start.to_le_bytes(),
        &end.to_le_bytes(),
    ]
    .concat())
}

pub(super) fn controller_text(data: &[u8]) -> Option<String> {
    Some(format!("Ctrl(0x{:X})", Fields(data).u32()?))
}

pub(super) fn controller(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    Ok(p.integer::<u32>()?.to_le_bytes().to_vec())
}

pub(super) fn bmc_text(data: &[u8]) -> Option<String> {
    let mut fields = Fields(data);
    let (interface_type, address) = (fields.u8()?, fields.u64()?);
    Some(format!("BMC(0x{interface_type:X},0x{address:X})"))
}

/// BMC(Type,Address); an Address without "0x" is decimal, as Table 10.66 makes an Integer, where
/// edk2's DevPathFromTextBmc() reads it as hexadecimal.
pub(super) fn bmc(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    let interface_type: u8 = p.integer()?;
    let address: u64 = p.integer()?;
    Ok([&[interface_type][..], &address.to_le_bytes()].concat())
}
