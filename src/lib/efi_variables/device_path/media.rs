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

//! The Media Device Path nodes (UEFI 2.11 §10.3.5) of named forms in Table 10.67, but Vendor's,
//! which vendor.rs writes for each Type, and File Path's, the text of its path.

use super::guid;
use super::parameters::integer;
use super::parameters::Parameters;
use super::DevicePathTextError;
use super::Fields;
use crate::hii::package::Guid;

/// The Sub-Types of UEFI 2.11 §10.3.5
pub(super) const HARD_DRIVE: u8 = 0x01;
pub(super) const CDROM: u8 = 0x02;
pub(super) const VENDOR: u8 = 0x03;
pub(super) const FILE_PATH: u8 = 0x04;
pub(super) const PROTOCOL: u8 = 0x05;
pub(super) const FIRMWARE_FILE: u8 = 0x06;
pub(super) const FIRMWARE_VOLUME: u8 = 0x07;
pub(super) const OFFSET: u8 = 0x08;
pub(super) const RAM_DISK: u8 = 0x09;

/// The Hard Drive Partition Format and Signature Type of an MBR and a GPT partition (UEFI 2.11
/// §10.3.5.1), the values of the keywords MBR and GPT
const MBR: u8 = 0x01;
const GPT: u8 = 0x02;
/// The RAM Disk types that UEFI 2.11 Table 10.67 names, by their Disk Type GUID
pub(super) const RAM_DISK_NAMES: [(Guid, &str); 4] = [
    (
        guid(
            0x77AB535A,
            0x45FC,
            0x624B,
            [0x55, 0x60, 0xF7, 0xB2, 0x81, 0xD1, 0xF9, 0x6E],
        ),
        "VirtualDisk",
    ),
    (
        guid(
            0x3D5ABD30,
            0x4175,
            0x87CE,
            [0x6D, 0x64, 0xD2, 0xAD, 0xE5, 0x23, 0xC4, 0xBB],
        ),
        "VirtualCD",
    ),
    (
        guid(
            0x5CEA02C9,
            0x4D07,
            0x69D3,
            [0x26, 0x9F, 0x44, 0x96, 0xFB, 0xE0, 0x96, 0xF9],
        ),
        "PersistentVirtualDisk",
    ),
    (
        guid(
            0x08018188,
            0x42CD,
            0xBB48,
            [0x10, 0x0F, 0x53, 0x87, 0xD5, 0x3D, 0xED, 0x3D],
        ),
        "PersistentVirtualCD",
    ),
];

/// HD(Partition,Type,Signature,Start,Size): MBR and its signature, GPT and its GUID, else the
/// Signature Type and 0. edk2 writes the partition number with "%d", negative from 2^31; this
/// writes it unsigned, as its StrDecimalToUintn() reads it.
pub(super) fn hard_drive_text(data: &[u8]) -> Option<String> {
    let mut fields = Fields(data);
    let number = fields.u32()?;
    let (start, size) = (fields.u64()?, fields.u64()?);
    let signature = fields.take::<16>()?;
    let (_format, signature_type) = (fields.u8()?, fields.u8()?);
    let signature = match signature_type {
        MBR => format!(
            "MBR,0x{:08X}",
            u32::from_le_bytes(*signature.first_chunk()?)
        ),
        GPT => format!("GPT,{}", Guid::from(signature)),
        other => format!("{other},0"),
    };
    Some(format!("HD({number},{signature},0x{start:X},0x{size:X})"))
}

/// HD(…): Partition 0 and Type GPT if omitted, as Table 10.67 gives them, where edk2 reads an
/// omitted Type as 0; the Type 1 and 2 as MBR and GPT, whose values they are, where edk2 drops
/// their Signature; another Type of Signature 0, as no Signature fits it. Start and Size are
/// required, but 0 if omitted for Partition 0, which "prohibits" them.
pub(super) fn hard_drive(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    let number: u32 = p.integer_or(0)?;
    let kind = p.next();
    let signature_text = p.next();
    let signature_type = match kind {
        "MBR" => MBR,
        "GPT" | "" => GPT,
        other => integer(other)?,
    };
    let (format, signature) = match signature_type {
        MBR => {
            let [a, b, c, d] = integer::<u32>(signature_text)?.to_le_bytes();
            (MBR, [a, b, c, d, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        }
        GPT => (
            GPT,
            <[u8; 16]>::from(super::parameters::guid(signature_text)?),
        ),
        _ => match integer::<u64>(signature_text)? {
            0 => (0, [0; 16]),
            _ => return Err(DevicePathTextError::Value(signature_text.to_owned())),
        },
    };
    let (start, size): (u64, u64) = match number {
        0 => (p.integer_or(0)?, p.integer_or(0)?),
        _ => (p.integer()?, p.integer()?),
    };
    let data = [
        &number.to_le_bytes()[..],
        &start.to_le_bytes(),
        &size.to_le_bytes(),
        &signature,
        &[format, signature_type],
    ];
    Ok(data.concat())
}

pub(super) fn cdrom_text(data: &[u8]) -> Option<String> {
    let mut fields = Fields(data);
    let entry = fields.u32()?;
    let (start, size) = (fields.u64()?, fields.u64()?);
    Some(format!("CDROM(0x{entry:X},0x{start:X},0x{size:X})"))
}

/// CDROM(Entry,Start,Size), Entry 0 if omitted.
pub(super) fn cdrom(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    let entry: u32 = p.integer_or(0)?;
    let (start, size): (u64, u64) = (p.integer()?, p.integer()?);
    Ok([
        &entry.to_le_bytes()[..],
        &start.to_le_bytes(),
        &size.to_le_bytes(),
    ]
    .concat())
}

/// A File Path node's path: UCS-2, then Null.
pub(super) fn file_path_text(data: &[u8]) -> Option<String> {
    let (units, []) = data.as_chunks::<2>() else {
        return None;
    };
    let units: Vec<u16> = units.iter().map(|unit| u16::from_le_bytes(*unit)).collect();
    let (&0, name) = units.split_last()? else {
        return None;
    };
    String::from_utf16(name).ok()
}

/// Media(Guid), Fv(Guid) or FvFile(Guid).
pub(super) fn guid_text(name: &str, data: &[u8]) -> Option<String> {
    Some(format!("{name}({})", Fields(data).guid()?))
}

pub(super) fn guid_node(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    Ok(p.guid()?.to_vec())
}

/// Offset(StartingOffset,EndingOffset), after a Reserved field that the text leaves 0.
pub(super) fn offset_text(data: &[u8]) -> Option<String> {
    let mut fields = Fields(data);
    let _reserved = fields.u32()?;
    let (start, end) = (fields.u64()?, fields.u64()?);
    Some(format!("Offset(0x{start:X},0x{end:X})"))
}

pub(super) fn offset(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    let (start, end): (u64, u64) = (p.integer()?, p.integer()?);
    Ok([
        &0_u32.to_le_bytes()[..],
        &start.to_le_bytes(),
        &end.to_le_bytes(),
    ]
    .concat())
}

/// The name of the node's Disk Type of RAM_DISK_NAMES, or RamDisk: (StartingAddress,
/// EndingAddress,DiskInstance), the Disk Type GUID last for RamDisk.
pub(super) fn ram_disk_text(data: &[u8]) -> Option<String> {
    let mut fields = Fields(data);
    let (start, end) = (fields.u64()?, fields.u64()?);
    let (disk_type, instance) = (fields.guid()?, fields.u16()?);
    let addresses = format!("0x{start:X},0x{end:X},{instance}");
    Some(
        match RAM_DISK_NAMES.iter().find(|(named, _)| *named == disk_type) {
            Some((_, name)) => format!("{name}({addresses})"),
            None => format!("RamDisk({addresses},{disk_type})"),
        },
    )
}

/// RamDisk(StartingAddress,EndingAddress,DiskInstance,DiskTypeGuid), DiskInstance 0 if omitted.
pub(super) fn ram_disk(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    let (start, end, instance) = ram_disk_range(p)?;
    Ok(ram_disk_data(start, end, p.guid()?, instance))
}

/// A name of RAM_DISK_NAMES: (StartingAddress,EndingAddress,DiskInstance), DiskInstance 0 if
/// omitted.
pub(super) fn named_ram_disk(
    p: &mut Parameters<'_>,
    disk_type: Guid,
) -> Result<Vec<u8>, DevicePathTextError> {
    let (start, end, instance) = ram_disk_range(p)?;
    Ok(ram_disk_data(start, end, disk_type.into(), instance))
}

fn ram_disk_range(p: &mut Parameters<'_>) -> Result<(u64, u64, u16), DevicePathTextError> {
    Ok((p.integer()?, p.integer()?, p.integer_or(0)?))
}

fn ram_disk_data(start: u64, end: u64, disk_type: [u8; 16], instance: u16) -> Vec<u8> {
    [
        &start.to_le_bytes()[..],
        &end.to_le_bytes(),
        &disk_type,
        &instance.to_le_bytes(),
    ]
    .concat()
}
