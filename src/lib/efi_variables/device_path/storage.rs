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

//! The Messaging Device Path nodes of storage buses and devices (UEFI 2.11 §10.3.4) of named
//! forms in Table 10.67: ATAPI, SCSI, Fibre Channel, 1394, I2O, Device Logical Unit, SATA, SAS,
//! iSCSI, NVM Express, UFS, SD, eMMC, NVDIMM Namespace and NVMe-oF Namespace.

use super::parameters::ascii_text;
use super::parameters::integer;
use super::parameters::keyword;
use super::parameters::upper_hex;
use super::parameters::Parameters;
use super::DevicePathTextError;
use super::Fields;
use crate::hii::package::Guid;

/// The Sub-Types of UEFI 2.11 §10.3.4
pub(super) const ATAPI: u8 = 0x01;
pub(super) const SCSI: u8 = 0x02;
pub(super) const FIBRE_CHANNEL: u8 = 0x03;
pub(super) const F1394: u8 = 0x04;
pub(super) const I2O: u8 = 0x06;
pub(super) const LOGICAL_UNIT: u8 = 0x11;
pub(super) const SATA: u8 = 0x12;
pub(super) const ISCSI: u8 = 0x13;
pub(super) const FIBRE_CHANNEL_EX: u8 = 0x15;
pub(super) const SAS_EX: u8 = 0x16;
pub(super) const NVME: u8 = 0x17;
pub(super) const UFS: u8 = 0x19;
pub(super) const SD: u8 = 0x1A;
pub(super) const EMMC: u8 = 0x1D;
pub(super) const NVDIMM: u8 = 0x20;
pub(super) const NVME_OF: u8 = 0x22;

/// The ATAPI PrimarySecondary and SlaveMaster keywords (UEFI 2.11 Table 10.67)
const CONTROLLERS: [(&str, u8); 2] = [("Primary", 0), ("Secondary", 1)];
const DRIVES: [(&str, u8); 2] = [("Master", 0), ("Slave", 1)];
/// The SAS Location and Connect keywords, and the bits of SAS Device and Topology Info that
/// they, SATA and the drive bay take (UEFI 2.11 §10.3.4.18.1, edk2-stable202608
/// DevPathFromTextSasEx())
const LOCATIONS: [(&str, u16); 2] = [("Internal", 0), ("External", 1)];
const CONNECTIONS: [(&str, u16); 2] = [("Direct", 0), ("Expanded", 1)];
const TOPOLOGY_KIND: u16 = 0x000F;
const TOPOLOGY_SATA: u16 = 0x0010;
const TOPOLOGY_EXTERNAL: u16 = 0x0020;
const TOPOLOGY_EXPANDED: u16 = 0x0040;
const TOPOLOGY_INTEGER: u16 = 0x0080;
/// The largest Connect, 2 bits
const MAX_CONNECT: u16 = 3;
/// The largest DriveBay, 1 more than its byte
const MAX_DRIVE_BAY: u16 = 256;
/// The iSCSI Login Options bits (UEFI 2.11 §10.3.4.20.1) and their keywords in Table 10.67
const HEADER_DIGESTS: [(&str, u16); 2] = [("None", 0), ("CRC32C", 0x0002)];
const DATA_DIGESTS: [(&str, u16); 2] = [("None", 0), ("CRC32C", 0x0008)];
const AUTH_NONE: u16 = 0x0800;
const AUTH_CHAP_UNI: u16 = 0x1000;
const AUTHENTICATIONS: [(&str, u16); 3] = [
    ("None", AUTH_NONE),
    ("CHAP_UNI", AUTH_CHAP_UNI),
    ("CHAP_BI", 0),
];
/// The iSCSI Network Protocol as edk2 writes it: TCP for 0, "reserved" for any other, which it
/// reads back as 1
const NETWORK_PROTOCOLS: [(&str, u16); 2] = [("TCP", 0), ("reserved", 1)];
/// The longest iSCSI Target Name (UEFI 2.11 §10.3.4.20.1) and NVMe-oF SubsystemNQN without its
/// Null (§10.3.4.32)
const MAX_TARGET_NAME: usize = 223;
const MAX_SUBSYSTEM_NQN: usize = 223;
/// The NVMe-oF NIDT of a namespace UUID, the NID that Table 10.67 writes as an RFC 4122 URN
const NIDT_UUID: u8 = 0x03;
const UUID_URN_PREFIX: &str = "urn:uuid:";

pub(super) fn atapi_text(data: &[u8]) -> Option<String> {
    let mut fields = Fields(data);
    let (controller, drive, lun) = (fields.u8()?, fields.u8()?, fields.u16()?);
    // edk2's DevPathToTextAtapi(): 1 is Secondary or Slave, any other value Primary or Master
    let controller = if controller == 1 {
        "Secondary"
    } else {
        "Primary"
    };
    let drive = if drive == 1 { "Slave" } else { "Master" };
    Some(format!("Ata({controller},{drive},0x{lun:X})"))
}

pub(super) fn atapi(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    let controller = p.keyword_or_integer(&CONTROLLERS)?;
    let drive = p.keyword_or_integer(&DRIVES)?;
    let lun: u16 = p.integer()?;
    Ok([&[controller, drive][..], &lun.to_le_bytes()].concat())
}

pub(super) fn scsi_text(data: &[u8]) -> Option<String> {
    let mut fields = Fields(data);
    let (pun, lun) = (fields.u16()?, fields.u16()?);
    Some(format!("Scsi(0x{pun:X},0x{lun:X})"))
}

pub(super) fn scsi(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    let (pun, lun): (u16, u16) = (p.integer()?, p.integer()?);
    Ok([pun, lun].map(u16::to_le_bytes).concat())
}

/// Fibre(WWN,LUN), after a Reserved field that the text leaves 0.
pub(super) fn fibre_channel_text(data: &[u8]) -> Option<String> {
    let mut fields = Fields(data);
    let _reserved = fields.u32()?;
    let (wwn, lun) = (fields.u64()?, fields.u64()?);
    Some(format!("Fibre(0x{wwn:X},0x{lun:X})"))
}

pub(super) fn fibre_channel(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    let (wwn, lun): (u64, u64) = (p.integer()?, p.integer()?);
    Ok([
        &0_u32.to_le_bytes()[..],
        &wwn.to_le_bytes(),
        &lun.to_le_bytes(),
    ]
    .concat())
}

/// FibreEx(WWN,LUN): 8-byte arrays, byte 0 first.
pub(super) fn fibre_channel_ex_text(data: &[u8]) -> Option<String> {
    let mut fields = Fields(data);
    let _reserved = fields.u32()?;
    let (wwn, lun) = (fields.take::<8>()?, fields.take::<8>()?);
    Some(format!(
        "FibreEx(0x{},0x{})",
        upper_hex(&wwn),
        upper_hex(&lun)
    ))
}

pub(super) fn fibre_channel_ex(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    let (wwn, lun) = (p.byte_array()?, p.byte_array()?);
    Ok([&0_u32.to_le_bytes()[..], &wwn, &lun].concat())
}

/// I1394(GUID): the 1394 GUID is a UINT64, which edk2 writes as 16 hexadecimal digits, as a GUID
/// of Table 10.66 could not hold it.
pub(super) fn f1394_text(data: &[u8]) -> Option<String> {
    let mut fields = Fields(data);
    let _reserved = fields.u32()?;
    Some(format!("I1394({:016X})", fields.u64()?))
}

/// The 1394 GUID in hexadecimal, after "0x" or not, as edk2's DevPathFromText1394() reads it.
pub(super) fn f1394(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    let text = p.next();
    let digits = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    let guid = match !digits.is_empty() && digits.bytes().all(|digit| digit.is_ascii_hexdigit()) {
        true => u64::from_str_radix(digits, 16).ok(),
        false => None,
    }
    .ok_or_else(|| DevicePathTextError::Value(text.to_owned()))?;
    Ok([&0_u32.to_le_bytes()[..], &guid.to_le_bytes()].concat())
}

pub(super) fn i2o_text(data: &[u8]) -> Option<String> {
    Some(format!("I2O(0x{:X})", Fields(data).u32()?))
}

pub(super) fn i2o(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    Ok(p.integer::<u32>()?.to_le_bytes().to_vec())
}

pub(super) fn logical_unit_text(data: &[u8]) -> Option<String> {
    Some(format!("Unit(0x{:X})", Fields(data).u8()?))
}

pub(super) fn logical_unit(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    Ok(vec![p.integer()?])
}

pub(super) fn sata_text(data: &[u8]) -> Option<String> {
    let mut fields = Fields(data);
    let (hba, multiplier, lun) = (fields.u16()?, fields.u16()?, fields.u16()?);
    Some(format!("Sata(0x{hba:X},0x{multiplier:X},0x{lun:X})"))
}

/// Sata(HPN,PMPN,LUN), PMPN 0xFFFF, no port multiplier, if omitted.
pub(super) fn sata(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    let hba: u16 = p.integer()?;
    let multiplier: u16 = p.integer_or(0xFFFF)?;
    let lun: u16 = p.integer()?;
    Ok([hba, multiplier, lun].map(u16::to_le_bytes).concat())
}

/// SasEx(Address,LUN,RTP,SASSATA,Location,Connect,DriveBay): 8-byte arrays, byte 0 first, then
/// the relative target port and the topology.
pub(super) fn sas_ex_text(data: &[u8]) -> Option<String> {
    let mut fields = Fields(data);
    let (address, lun) = (fields.take::<8>()?, fields.take::<8>()?);
    let (topology, port) = (fields.u16()?, fields.u16()?);
    Some(format!(
        "SasEx(0x{},0x{},0x{port:X},{})",
        upper_hex(&address),
        upper_hex(&lun),
        topology_text(topology)
    ))
}

/// SasEx(…), LUN, RTP and the topology 0 if omitted.
pub(super) fn sas_ex(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    let address = p.byte_array()?;
    let lun = p.integer_or(0_u64)?.to_be_bytes();
    let port: u16 = p.integer_or(0)?;
    let topology = topology(p)?;
    Ok([
        &address[..],
        &lun,
        &topology.to_le_bytes(),
        &port.to_le_bytes(),
    ]
    .concat())
}

/// SAS(Address,LUN,RTP,SASSATA,Location,Connect,DriveBay,Reserved), of the data that follows the
/// GUID of a SAS node: Reserved, the address, the LUN, the topology, the relative target port.
pub(super) fn sas_text(data: &[u8]) -> Option<String> {
    let mut fields = Fields(data);
    let reserved = fields.u32()?;
    let (address, lun) = (fields.u64()?, fields.u64()?);
    let (topology, port) = (fields.u16()?, fields.u16()?);
    Some(format!(
        "SAS(0x{address:X},0x{lun:X},0x{port:X},{},0x{reserved:X})",
        topology_text(topology)
    ))
}

/// The data after the GUID of SAS(…): LUN, RTP, the topology and Reserved 0 if omitted.
pub(super) fn sas(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    let address: u64 = p.integer()?;
    let lun: u64 = p.integer_or(0)?;
    let port: u16 = p.integer_or(0)?;
    let topology = topology(p)?;
    let reserved: u32 = p.integer_or(0)?;
    let data = [
        &reserved.to_le_bytes()[..],
        &address.to_le_bytes(),
        &lun.to_le_bytes(),
        &topology.to_le_bytes(),
        &port.to_le_bytes(),
    ];
    Ok(data.concat())
}

/// SASSATA,Location,Connect,DriveBay as edk2's DevPathToTextSasEx() writes them.
fn topology_text(topology: u16) -> String {
    let kind = topology & TOPOLOGY_KIND;
    match (kind, topology & TOPOLOGY_INTEGER) {
        (0, 0) => "NoTopology,0,0,0".to_owned(),
        (1 | 2, 0) => {
            let pick = |bit, set, clear| if topology & bit != 0 { set } else { clear };
            let drive_bay = match kind {
                1 => "0".to_owned(),
                _ => format!("0x{:X}", (topology >> 8) + 1),
            };
            format!(
                "{},{},{},{drive_bay}",
                pick(TOPOLOGY_SATA, "SATA", "SAS"),
                pick(TOPOLOGY_EXTERNAL, "External", "Internal"),
                pick(TOPOLOGY_EXPANDED, "Expanded", "Direct")
            )
        }
        _ => format!("0x{topology:X},0,0,0"),
    }
}

/// SAS Device and Topology Info from SASSATA,Location,Connect,DriveBay: NoTopology if omitted.
/// NoTopology and an integer take no Location, Connect or DriveBay, "0" too as edk2 writes them;
/// SAS and SATA take a DriveBay of 0, none, as edk2 writes it, or 1 to 256.
fn topology(p: &mut Parameters<'_>) -> Result<u16, DevicePathTextError> {
    let kind = p.next();
    let (location, connect, drive_bay) = (p.next(), p.next(), p.next());
    let sata = match kind {
        "NoTopology" | "" => return none_set([location, connect, drive_bay]).map(|()| 0),
        "SAS" => 0,
        "SATA" => TOPOLOGY_SATA,
        integer_text => {
            let topology = integer(integer_text)?;
            return none_set([location, connect, drive_bay]).map(|()| topology);
        }
    };
    let location = bounded(location, &LOCATIONS, 1)?;
    let connect = bounded(connect, &CONNECTIONS, MAX_CONNECT)?;
    let bay = match drive_bay {
        "" => 0,
        text => integer::<u16>(text)?,
    };
    let kind = match bay {
        0 => 1,
        1..=MAX_DRIVE_BAY => 2 | (bay - 1) << 8,
        _ => return Err(DevicePathTextError::Value(drive_bay.to_owned())),
    };
    Ok(kind | sata | location << 5 | connect << 6)
}

/// A keyword of `keywords` or an Integer up to `max`, 0 if omitted.
fn bounded(text: &str, keywords: &[(&str, u16)], max: u16) -> Result<u16, DevicePathTextError> {
    let value = match text {
        "" => 0,
        text => keyword(text, keywords).or_else(|_| integer(text))?,
    };
    match value <= max {
        true => Ok(value),
        false => Err(DevicePathTextError::Value(text.to_owned())),
    }
}

/// Fails unless each of `texts` is omitted or 0.
fn none_set(texts: [&str; 3]) -> Result<(), DevicePathTextError> {
    match texts
        .iter()
        .find(|text| !text.is_empty() && integer::<u64>(text) != Ok(0))
    {
        Some(text) => Err(DevicePathTextError::SasTopology((*text).to_owned())),
        None => Ok(()),
    }
}

/// iSCSI(TargetName,PortalGroup,LUN,HeaderDigest,DataDigest,Authentication,Protocol), of a
/// Target Name ended by Null, as edk2 writes it.
pub(super) fn iscsi_text(data: &[u8]) -> Option<String> {
    let mut fields = Fields(data);
    let (protocol, options) = (fields.u16()?, fields.u16()?);
    let (lun, tag) = (fields.take::<8>()?, fields.u16()?);
    let name = ascii_text(fields.0.strip_suffix(&[0])?)?;
    let pick = |bit, set, clear| if options & bit != 0 { set } else { clear };
    let authentication = match (options & AUTH_NONE, options & AUTH_CHAP_UNI) {
        (AUTH_NONE, _) => "None",
        (_, AUTH_CHAP_UNI) => "CHAP_UNI",
        _ => "CHAP_BI",
    };
    let protocol = if protocol == 0 { "TCP" } else { "reserved" };
    Some(format!(
        "iSCSI({name},0x{tag:X},0x{},{},{},{authentication},{protocol})",
        upper_hex(&lun),
        pick(0x0002, "CRC32C", "None"),
        pick(0x0008, "CRC32C", "None")
    ))
}

/// iSCSI(…): the digests None, the Authentication None and the Protocol TCP if omitted, as Table
/// 10.67 gives them, where edk2 reads an omitted Authentication as CHAP_BI.
pub(super) fn iscsi(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    let name = p.ascii_up_to(MAX_TARGET_NAME)?;
    let tag: u16 = p.integer()?;
    let lun = p.byte_array()?;
    let header_digest = p.keyword_or(&HEADER_DIGESTS, 0)?;
    let data_digest = p.keyword_or(&DATA_DIGESTS, 0)?;
    let authentication = p.keyword_or(&AUTHENTICATIONS, AUTH_NONE)?;
    let protocol = p.keyword_or(&NETWORK_PROTOCOLS, 0)?;
    let options = header_digest | data_digest | authentication;
    let data = [
        &protocol.to_le_bytes()[..],
        &options.to_le_bytes(),
        &lun,
        &tag.to_le_bytes(),
        name.as_bytes(),
        &[0],
    ];
    Ok(data.concat())
}

/// NVMe(NSID,EUI): the EUI-64 as edk2 writes it, its octets from the last, separated by "-".
pub(super) fn nvme_text(data: &[u8]) -> Option<String> {
    let mut fields = Fields(data);
    let namespace = fields.u32()?;
    let eui: Vec<String> = fields
        .take::<8>()?
        .iter()
        .rev()
        .map(|byte| format!("{byte:02X}"))
        .collect();
    Some(format!("NVMe(0x{namespace:X},{})", eui.join("-")))
}

pub(super) fn nvme(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    let namespace: u32 = p.integer()?;
    let text = p.next();
    let octet = |octet: &str| match (1..=2).contains(&octet.len())
        && octet.bytes().all(|digit| digit.is_ascii_hexdigit())
    {
        true => u8::from_str_radix(octet, 16).ok(),
        false => None,
    };
    let mut eui = text
        .split('-')
        .map(octet)
        .collect::<Option<Vec<u8>>>()
        .filter(|eui| eui.len() == 8)
        .ok_or_else(|| DevicePathTextError::Value(text.to_owned()))?;
    eui.reverse();
    Ok([&namespace.to_le_bytes()[..], &eui].concat())
}

pub(super) fn ufs_text(data: &[u8]) -> Option<String> {
    let mut fields = Fields(data);
    let (pun, lun) = (fields.u8()?, fields.u8()?);
    Some(format!("UFS(0x{pun:X},0x{lun:X})"))
}

pub(super) fn ufs(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    Ok(vec![p.integer()?, p.integer()?])
}

/// SD(SlotNumber) or eMMC(SlotNumber).
pub(super) fn slot_text(name: &str, data: &[u8]) -> Option<String> {
    Some(format!("{name}(0x{:X})", Fields(data).u8()?))
}

/// SD(SlotNumber) or eMMC(SlotNumber), slot 0 if omitted.
pub(super) fn slot(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    Ok(vec![p.integer_or(0)?])
}

/// NVDIMM(UUID), as Table 10.67 gives it: edk2 has no form for it. The UUID is an EFI_GUID, as
/// edk2-stable202608 NvdimmLabel.h types the label's Uuid.
pub(super) fn nvdimm_text(data: &[u8]) -> Option<String> {
    Some(format!("NVDIMM({})", Fields(data).guid()?))
}

pub(super) fn nvdimm(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    Ok(p.guid()?.to_vec())
}

/// NVMEoF(SubsystemNQN,NID), as Table 10.67 gives it: edk2 has no form for it. Table 10.67 gives
/// the NID no text but the RFC 4122 URN of a namespace UUID, NIDT 3h, in its example (UEFI 2.11
/// §10.3.4.33); a node of another NIDT has no named form.
pub(super) fn nvme_of_text(data: &[u8]) -> Option<String> {
    let mut fields = Fields(data);
    let (nidt, nid) = (fields.u8()?, fields.take::<16>()?);
    let nqn = std::str::from_utf8(fields.0.strip_suffix(&[0])?).ok()?;
    (nidt == NIDT_UUID).then(|| format!("NVMEoF({nqn},{UUID_URN_PREFIX}{})", uuid_text(nid)))
}

/// NVMEoF(SubsystemNQN,NID): the NQN, of UTF-8, ended by Null, and the NID, the URN of a
/// namespace UUID, whose octets the NID holds in order, big-endian.
pub(super) fn nvme_of(p: &mut Parameters<'_>) -> Result<Vec<u8>, DevicePathTextError> {
    let nqn = p.next();
    if nqn.contains('\0') || nqn.is_empty() {
        return Err(DevicePathTextError::Value(nqn.to_owned()));
    }
    if nqn.len() > MAX_SUBSYSTEM_NQN {
        return Err(DevicePathTextError::TooLongString(
            nqn.to_owned(),
            MAX_SUBSYSTEM_NQN,
        ));
    }
    let text = p.next();
    let uuid = text
        .get(..UUID_URN_PREFIX.len())
        .filter(|prefix| prefix.eq_ignore_ascii_case(UUID_URN_PREFIX))
        .and_then(|_| text.get(UUID_URN_PREFIX.len()..))
        .and_then(|uuid| uuid.parse::<Guid>().ok())
        .ok_or_else(|| DevicePathTextError::Value(text.to_owned()))?;
    let nid = [
        &uuid.data1.to_be_bytes()[..],
        &uuid.data2.to_be_bytes(),
        &uuid.data3.to_be_bytes(),
        &uuid.data4,
    ];
    Ok([&[NIDT_UUID][..], &nid.concat(), nqn.as_bytes(), &[0]].concat())
}

/// A UUID's octets in order as RFC 4122 writes them: lowercase, 8-4-4-4-12.
fn uuid_text(octets: [u8; 16]) -> String {
    let hex: String = octets.iter().map(|octet| format!("{octet:02x}")).collect();
    let pieces =
        [0..8, 8..12, 12..16, 16..20, 20..32].map(|range| hex.get(range).unwrap_or_default());
    pieces.join("-")
}
