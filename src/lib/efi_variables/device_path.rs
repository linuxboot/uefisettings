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

//! Device paths as text (UEFI 2.11 §10.6): each node in the form that edk2-stable202608's
//! ConvertDevicePathToText() writes with DisplayOnly FALSE and AllowShortcuts TRUE, for each
//! Type/Sub-Type row and named form of UEFI 2.11 Table 10.67, read back as its
//! ConvertTextToDevicePath() reads it. NvdimmAcpiAdr, NVDIMM, RestService and NVMEoF, which edk2
//! lacks, take the forms that Table 10.67 gives them. A node whose form would not read back to its
//! bytes is written in the form that edk2 writes without the shortcut, if that does, else in the
//! generic form of Table 10.67, Path() or that of its Type, which always does: the text that
//! to_text writes reads back by from_text to the same bytes, as §10.6.1.3 requires. A device path
//! holding an instance of no node has no text, as no text reads back to it.
//!
//! Where the form of edk2 would not read back, to_text differs from it by design:
//! - a UART of BaudRate or DataBits 0 is written Uart(0,0,…), where edk2 writes DEFAULT
//!   (DevicePathToText.c DevPathToTextUart()) and reads DEFAULT back as 115200 and 8
//!   (DevicePathFromText.c DevPathFromTextUart()), so from_text refuses DEFAULT;
//! - an ACPI node whose _HID is not a PNP one is written Acpi(HWP0002,…), its EISA ID as edk2
//!   writes those of AcpiEx, where edk2 writes Acpi(0x%08x,…), which its EisaIdFromText() does
//!   not read;
//! - an ACPI Expanded node of UIDSTR alone and a UID other than 0 is written AcpiEx(…), where
//!   edk2 writes AcpiExp(…), which has no UID;
//! - a Messaging Vendor node of a GUID that edk2 names, VenPcAnsi() and DebugPort() among them,
//!   with data that the name does not show is written VenMsg(GUID,data), where edk2 writes the
//!   name and drops the data;
//! - a Hard Drive node of a partition number from 2^31 is written unsigned, where edk2's "%d"
//!   writes it negative;
//! - every other node whose form would not read back is written in its generic form. Among them,
//!   each with a row in node_cases: a value that its keywords map back to another, such as an
//!   ATAPI controller of 2; a field that the form does not show, such as a Reserved one, the
//!   ports of IPv4 and IPv6 or the bytes of a MAC address past 6 for IfType 0 and 1; data past
//!   the fields, or short of them; a string holding "/", ",", "(" or ")", a byte outside ASCII or,
//!   where edk2 writes one, no Null at its end, such as a URI holding ","; a File Path holding
//!   "/" or reading as a node, which edk2 writes as it is; a partition of mixed formats; an
//!   NVMe-oF NID other than a UUID, which Table 10.67 gives no text.
//!
//! from_text reads each text that to_text writes as edk2 does. Where edk2 reads another text
//! than Tables 10.66 and 10.67 say, from_text follows the tables: an omitted BaudRate, DataBits,
//! IPv4 or IPv6 Protocol, iSCSI Authentication or HD Type reads as 115200, 8, UDP, None and GPT,
//! an omitted HID or CID of AcpiEx and an EISAID of 0 as 0, HD's Type 1 and 2 as MBR and GPT, a
//! BMC Address without "0x" as decimal, UartFlowCtrl's integers as their values, an IPv4
//! GatewayIPAddress or SubnetMask, or an IPv6 PrefixLength or GatewayIPAddress, given alone as
//! given, and an IPv4 or IPv6 Address may hold a port, or brackets. It refuses what edk2 drops or
//! reads to another node: a name of no form, text after a form's ")", a value that does not fit
//! its field, Uart DEFAULT, a Parity keyword next to a StopBits integer or the reverse, which
//! "Mixing formats is prohibited" forbids and edk2 accepts.
//!
//! Firmware logs show the edk2 form there.

mod acpi;
mod bbs;
mod hardware;
mod media;
mod network;
mod parameters;
mod serial;
mod storage;
mod usb;
mod vendor;

use thiserror::Error;

use super::load_option::LoadOptionError;
use super::load_option::RawNode;
use super::load_option::RawNodes;
use crate::hii::package::Guid;
use parameters::upper_hex;
use parameters::Parameters;

/// Type, Sub-Type and Length, which every device path node starts with
const NODE_HEADER_SIZE: usize = 4;
/// The device path Types of UEFI 2.11 Table 10.1
const HARDWARE: u8 = 0x01;
const ACPI: u8 = 0x02;
const MESSAGING: u8 = 0x03;
const MEDIA: u8 = 0x04;
const BBS: u8 = 0x05;
const END: u8 = 0x7F;
/// The Sub-Types of an End node: End This Instance and End Entire Device Path (UEFI 2.11
/// Table 10.2)
const END_INSTANCE: u8 = 0x01;
const END_ENTIRE: u8 = 0xFF;
/// The separators of a text device path: "/" between nodes, "," between instances, and the
/// parentheses of a node's parameters, which edk2's GetNextDeviceNodeStr() skips before a node
const SEPARATORS: [char; 4] = ['/', ',', '(', ')'];

/// The generic form of a node of each Type of UEFI 2.11 Table 10.67, which to_text writes for a
/// Sub-Type that the table names no form of (Hardware 0 and 7 to 255, ACPI 0 and 5 to 255,
/// Messaging 0, 7, 8 and 35 to 255, Media 0 and 10 to 255, BBS 0 and 2 to 255) and for a node
/// whose form would not read back; Path() for every other Type
const GENERIC_NAMES: [(u8, &str); 5] = [
    (HARDWARE, "HardwarePath"),
    (ACPI, "AcpiPath"),
    (MESSAGING, "Msg"),
    (MEDIA, "MediaPath"),
    (BBS, "BbsPath"),
];

const fn guid(data1: u32, data2: u16, data3: u16, data4: [u8; 8]) -> Guid {
    Guid {
        data1,
        data2,
        data3,
        data4,
    }
}

/// The device paths that `bytes` pack, as a FilePathList does, each with its End Entire Device
/// Path node; ConIn, ConOut and ErrOut hold one.
pub(crate) fn device_paths(bytes: &[u8]) -> Result<Vec<&[u8]>, DevicePathTextError> {
    let mut paths = Vec::new();
    let mut start = 0;
    let mut end = 0;
    for node in RawNodes::new(bytes) {
        let node = node?;
        end += NODE_HEADER_SIZE + node.data.len();
        if (node.node_type, node.sub_type) == (END, END_ENTIRE) {
            paths.push(bytes.get(start..end).ok_or(DevicePathTextError::NoEnd)?);
            start = end;
        }
    }
    match (start == bytes.len(), paths.is_empty()) {
        (true, false) => Ok(paths),
        (false, _) | (_, true) => Err(DevicePathTextError::NoEnd),
    }
}

/// The text of `path`, one device path that its End Entire Device Path node ends: nodes
/// separated by "/", instances by ",/" as edk2 writes them.
pub(crate) fn to_text(path: &[u8]) -> Result<String, DevicePathTextError> {
    let mut text = String::new();
    let mut nodes_of_instance = 0_usize;
    let mut ended = false;
    let mut nodes = RawNodes::new(path);
    for node in nodes.by_ref() {
        let node = node?;
        match (node.node_type, node.sub_type, nodes_of_instance) {
            (END, END_ENTIRE | END_INSTANCE, 0) => return Err(DevicePathTextError::EmptyInstance),
            (END, END_ENTIRE, _) => {
                ended = true;
                break;
            }
            (END, END_INSTANCE, _) => {
                text.push(',');
                nodes_of_instance = 0;
            }
            (END, sub_type, _) => return Err(DevicePathTextError::EndSubType(sub_type)),
            (_, _, _) => {
                // as edk2 writes it: "/" before each node but the first, after "," too
                if !text.is_empty() {
                    text.push('/');
                }
                text.push_str(&node_text(&node));
                nodes_of_instance += 1;
            }
        }
    }
    match (ended, nodes.next()) {
        (true, None) => Ok(text),
        (true, Some(_)) => Err(DevicePathTextError::AfterEnd),
        (false, _) => Err(DevicePathTextError::NoEnd),
    }
}

/// The bytes of the device path that `text` writes, ended by an End Entire Device Path node:
/// nodes separated by "/", instances by ",", as edk2's ConvertTextToDevicePath() reads them, but
/// for the texts that it reads to a node of another form or to an instance of no node, which
/// from_text refuses.
#[cfg_attr(
    not(test),
    allow(dead_code, reason = "nothing writes a device path from its text yet")
)]
pub(crate) fn from_text(text: &str) -> Result<Vec<u8>, DevicePathTextError> {
    let nodes = node_texts(text)?;
    if nodes.is_empty() {
        return Err(DevicePathTextError::NoNodeText(text.to_owned()));
    }
    let mut bytes = Vec::new();
    let mut nodes = nodes.into_iter().peekable();
    while let Some((node, instance_ends)) = nodes.next() {
        bytes.extend(node_from_text(node)?);
        match (instance_ends, nodes.peek()) {
            (true, None) => return Err(DevicePathTextError::NoNodeText(text.to_owned())),
            (true, Some(_)) => bytes.extend(end_node(END_INSTANCE)),
            (false, _) => {}
        }
    }
    bytes.extend(end_node(END_ENTIRE));
    Ok(bytes)
}

fn end_node(sub_type: u8) -> [u8; NODE_HEADER_SIZE] {
    [END, sub_type, 4, 0]
}

/// The text of a node: its named form if that reads back to its bytes, else the form without the
/// shortcut if that does, else its generic form.
fn node_text(node: &RawNode<'_>) -> String {
    let bytes = node_bytes(node.node_type, node.sub_type, node.data);
    [named_text(node), longer_text(node)]
        .into_iter()
        .flatten()
        .find(|text| {
            matches!(node_texts(text).as_deref(), Ok([(single, false)]) if single == text)
                && bytes
                    .as_ref()
                    .is_ok_and(|bytes| node_from_text(text).as_ref() == Ok(bytes))
        })
        .unwrap_or_else(|| generic_text(node))
}

/// The form that edk2's ConvertDeviceNodeToText() writes for the node's Type and Sub-Type, as its
/// mUefiDevicePathLibToTextTable picks it, or Table 10.67's for the four forms that edk2 lacks.
fn named_text(node: &RawNode<'_>) -> Option<String> {
    let data = node.data;
    match (node.node_type, node.sub_type) {
        (HARDWARE, hardware::PCI) => hardware::pci_text(data),
        (HARDWARE, hardware::PCCARD) => hardware::pc_card_text(data),
        (HARDWARE, hardware::MEMORY_MAPPED) => hardware::memory_mapped_text(data),
        (HARDWARE, hardware::VENDOR) => vendor::text("Hw", data),
        (HARDWARE, hardware::CONTROLLER) => hardware::controller_text(data),
        (HARDWARE, hardware::BMC) => hardware::bmc_text(data),
        (ACPI, acpi::HID) => acpi::hid_text(data),
        (ACPI, acpi::EXTENDED) => acpi::extended_text(data),
        (ACPI, acpi::ADR) => acpi::adr_text(data),
        (ACPI, acpi::NVDIMM) => acpi::nvdimm_text(data),
        (MESSAGING, storage::ATAPI) => storage::atapi_text(data),
        (MESSAGING, storage::SCSI) => storage::scsi_text(data),
        (MESSAGING, storage::FIBRE_CHANNEL) => storage::fibre_channel_text(data),
        (MESSAGING, storage::FIBRE_CHANNEL_EX) => storage::fibre_channel_ex_text(data),
        (MESSAGING, storage::SAS_EX) => storage::sas_ex_text(data),
        (MESSAGING, storage::NVME) => storage::nvme_text(data),
        (MESSAGING, storage::UFS) => storage::ufs_text(data),
        (MESSAGING, storage::SD) => storage::slot_text("SD", data),
        (MESSAGING, storage::EMMC) => storage::slot_text("eMMC", data),
        (MESSAGING, storage::F1394) => storage::f1394_text(data),
        (MESSAGING, usb::USB) => usb::usb_text(data),
        (MESSAGING, usb::USB_WWID) => usb::wwid_text(data),
        (MESSAGING, storage::LOGICAL_UNIT) => storage::logical_unit_text(data),
        (MESSAGING, usb::USB_CLASS) => usb::class_text(data),
        (MESSAGING, storage::SATA) => storage::sata_text(data),
        (MESSAGING, storage::I2O) => storage::i2o_text(data),
        (MESSAGING, network::MAC_ADDRESS) => network::mac_text(data),
        (MESSAGING, network::IPV4) => network::ipv4_text_of(data),
        (MESSAGING, network::IPV6) => network::ipv6_text_of(data),
        (MESSAGING, network::INFINIBAND) => network::infiniband_text(data),
        (MESSAGING, serial::UART) => serial::uart_text(data),
        (MESSAGING, vendor::MESSAGING_VENDOR) => vendor::messaging_text(data),
        (MESSAGING, storage::ISCSI) => storage::iscsi_text(data),
        (MESSAGING, network::VLAN) => network::vlan_text(data),
        (MESSAGING, network::DNS) => network::dns_text(data),
        (MESSAGING, network::URI) => network::uri_text(data),
        (MESSAGING, network::BLUETOOTH) => network::bluetooth_text(data),
        (MESSAGING, network::WIFI) => network::wifi_text(data),
        (MESSAGING, network::BLUETOOTH_LE) => network::bluetooth_le_text(data),
        (MESSAGING, storage::NVDIMM) => storage::nvdimm_text(data),
        (MESSAGING, network::REST_SERVICE) => network::rest_service_text(data),
        (MESSAGING, storage::NVME_OF) => storage::nvme_of_text(data),
        (MEDIA, media::HARD_DRIVE) => media::hard_drive_text(data),
        (MEDIA, media::CDROM) => media::cdrom_text(data),
        (MEDIA, media::VENDOR) => vendor::text("Media", data),
        (MEDIA, media::PROTOCOL) => media::guid_text("Media", data),
        (MEDIA, media::FILE_PATH) => media::file_path_text(data),
        (MEDIA, media::FIRMWARE_VOLUME) => media::guid_text("Fv", data),
        (MEDIA, media::FIRMWARE_FILE) => media::guid_text("FvFile", data),
        (MEDIA, media::OFFSET) => media::offset_text(data),
        (MEDIA, media::RAM_DISK) => media::ram_disk_text(data),
        (BBS, bbs::BBS_101) => bbs::bbs_text(data),
        (_, _) => None,
    }
}

/// The form that edk2 writes without the shortcut that named_text may write, which can drop a
/// field: VenMsg for a Messaging Vendor node, AcpiEx for an ACPI Expanded one.
fn longer_text(node: &RawNode<'_>) -> Option<String> {
    match (node.node_type, node.sub_type) {
        (MESSAGING, vendor::MESSAGING_VENDOR) => vendor::text("Msg", node.data),
        (ACPI, acpi::EXTENDED) => acpi::extended_full_text(node.data),
        (_, _) => None,
    }
}

/// Path(Type,Sub-Type,data), or the generic form of the node's Type: decimal Type and Sub-Type,
/// then the data as a hex dump.
fn generic_text(node: &RawNode<'_>) -> String {
    let mut text = match GENERIC_NAMES
        .iter()
        .find(|(kind, _)| *kind == node.node_type)
    {
        Some((_, name)) => format!("{name}({}", node.sub_type),
        None => format!("Path({},{}", node.node_type, node.sub_type),
    };
    if !node.data.is_empty() {
        text.push(',');
        text.push_str(&upper_hex(node.data));
    }
    text.push(')');
    text
}

/// The fields of a node's data, read in order; None once the data runs out.
struct Fields<'a>(&'a [u8]);

impl Fields<'_> {
    fn take<const N: usize>(&mut self) -> Option<[u8; N]> {
        let (head, rest) = self.0.split_first_chunk::<N>()?;
        self.0 = rest;
        Some(*head)
    }

    fn u8(&mut self) -> Option<u8> {
        self.take::<1>().map(|[byte]| byte)
    }

    fn u16(&mut self) -> Option<u16> {
        self.take().map(u16::from_le_bytes)
    }

    fn u32(&mut self) -> Option<u32> {
        self.take().map(u32::from_le_bytes)
    }

    fn u64(&mut self) -> Option<u64> {
        self.take().map(u64::from_le_bytes)
    }

    fn guid(&mut self) -> Option<Guid> {
        self.take::<16>().map(Guid::from)
    }
}

/// The text of each node, and whether a "," ends its instance, as edk2's GetNextDeviceNodeStr()
/// (DevicePathFromText.c) splits a text device path: it skips SEPARATORS before a node, then
/// takes the node up to a "/" or "," outside parentheses.
fn node_texts(text: &str) -> Result<Vec<(&str, bool)>, DevicePathTextError> {
    let mut nodes = Vec::new();
    let mut rest = text;
    loop {
        rest = rest.trim_start_matches(SEPARATORS);
        if rest.is_empty() {
            return Ok(nodes);
        }
        let unpaired = || DevicePathTextError::Parentheses(rest.to_owned());
        let mut depth = 0_usize;
        let mut end = None;
        for (at, c) in rest.char_indices() {
            match c {
                '(' => depth += 1,
                ')' => depth = depth.checked_sub(1).ok_or_else(unpaired)?,
                '/' | ',' if depth == 0 => {
                    end = Some((at, c));
                    break;
                }
                _ => {}
            }
        }
        if depth != 0 {
            return Err(unpaired());
        }
        match end {
            Some((at, separator)) => {
                let (node, after) = rest.split_at(at);
                nodes.push((node, separator == ','));
                rest = after.get(separator.len_utf8()..).unwrap_or_default();
            }
            None => {
                nodes.push((rest, false));
                return Ok(nodes);
            }
        }
    }
}

/// The bytes of the node that `text` writes: a form of a Name that from_text knows, its
/// parameters up to the first ")" as edk2's GetParamByNodeName() takes them, else a File Path
/// whose Path Name is the text. Unlike edk2, it refuses text after that ")", which edk2 drops; a
/// Name(...) of no form it knows, which edk2 reads as a File Path, as a typo there would become
/// one; and an End node, as only "," and the end of the text write those.
fn node_from_text(text: &str) -> Result<Vec<u8>, DevicePathTextError> {
    let form = text
        .split_once('(')
        .filter(|(name, _)| {
            !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
        .and_then(|(name, rest)| {
            rest.split_once(')')
                .map(|(parameters, after)| (name, parameters, after))
        });
    let Some((name, parameters, after)) = form else {
        return file_path(text);
    };
    let mut parameters = Parameters::new(parameters);
    match (form_node(name, &mut parameters, text)?, after) {
        (Some((node_type, sub_type, data)), "") => {
            parameters.finish(text)?;
            node_bytes(node_type, sub_type, &data)
        }
        (Some(_), _) => Err(DevicePathTextError::AfterParentheses(text.to_owned())),
        (None, "") => Err(DevicePathTextError::UnknownName(text.to_owned())),
        (None, _) => file_path(text),
    }
}

/// The Type, Sub-Type and data of the node that the form `name` writes from `p`, as edk2's
/// mUefiDevicePathLibDevPathFromTextTable reads each, and Table 10.67 the four forms that edk2
/// lacks; None for a name of no form.
fn form_node(
    name: &str,
    p: &mut Parameters<'_>,
    text: &str,
) -> Result<Option<(u8, u8, Vec<u8>)>, DevicePathTextError> {
    let node = match name {
        "Path" => match p.integer()? {
            END => return Err(DevicePathTextError::EndNodeText(text.to_owned())),
            node_type => (node_type, p.integer()?, p.hex()?),
        },
        "HardwarePath" => (HARDWARE, p.integer()?, p.hex()?),
        "Pci" => (HARDWARE, hardware::PCI, hardware::pci(p)?),
        "PcCard" => (HARDWARE, hardware::PCCARD, hardware::pc_card(p)?),
        "MemoryMapped" => (
            HARDWARE,
            hardware::MEMORY_MAPPED,
            hardware::memory_mapped(p)?,
        ),
        "VenHw" => (HARDWARE, hardware::VENDOR, vendor::vendor(p)?),
        "Ctrl" => (HARDWARE, hardware::CONTROLLER, hardware::controller(p)?),
        "BMC" => (HARDWARE, hardware::BMC, hardware::bmc(p)?),
        "AcpiPath" => (ACPI, p.integer()?, p.hex()?),
        "Acpi" => (ACPI, acpi::HID, acpi::hid(p)?),
        "AcpiEx" => (ACPI, acpi::EXTENDED, acpi::extended(p)?),
        "AcpiExp" => (ACPI, acpi::EXTENDED, acpi::expanded(p)?),
        "AcpiAdr" => (ACPI, acpi::ADR, acpi::adr(p, text)?),
        "NvdimmAcpiAdr" => (ACPI, acpi::NVDIMM, acpi::nvdimm(p)?),
        "Msg" => (MESSAGING, p.integer()?, p.hex()?),
        "Ata" => (MESSAGING, storage::ATAPI, storage::atapi(p)?),
        "Scsi" => (MESSAGING, storage::SCSI, storage::scsi(p)?),
        "Fibre" => (
            MESSAGING,
            storage::FIBRE_CHANNEL,
            storage::fibre_channel(p)?,
        ),
        "FibreEx" => (
            MESSAGING,
            storage::FIBRE_CHANNEL_EX,
            storage::fibre_channel_ex(p)?,
        ),
        "I1394" => (MESSAGING, storage::F1394, storage::f1394(p)?),
        "USB" => (MESSAGING, usb::USB, usb::usb(p)?),
        "I2O" => (MESSAGING, storage::I2O, storage::i2o(p)?),
        "Infiniband" => (MESSAGING, network::INFINIBAND, network::infiniband(p)?),
        "VenMsg" => (MESSAGING, vendor::MESSAGING_VENDOR, vendor::vendor(p)?),
        "UartFlowCtrl" => (
            MESSAGING,
            vendor::MESSAGING_VENDOR,
            vendor::flow_control(p)?,
        ),
        "SAS" => (MESSAGING, vendor::MESSAGING_VENDOR, vendor::sas(p)?),
        "SasEx" => (MESSAGING, storage::SAS_EX, storage::sas_ex(p)?),
        "NVMe" => (MESSAGING, storage::NVME, storage::nvme(p)?),
        "UFS" => (MESSAGING, storage::UFS, storage::ufs(p)?),
        "SD" => (MESSAGING, storage::SD, storage::slot(p)?),
        "eMMC" => (MESSAGING, storage::EMMC, storage::slot(p)?),
        "MAC" => (MESSAGING, network::MAC_ADDRESS, network::mac(p, text)?),
        "IPv4" => (MESSAGING, network::IPV4, network::ipv4_node(p)?),
        "IPv6" => (MESSAGING, network::IPV6, network::ipv6_node(p)?),
        "Uart" => (MESSAGING, serial::UART, serial::uart(p, text)?),
        "UsbClass" => (MESSAGING, usb::USB_CLASS, usb::class(p)?),
        "UsbWwid" => (MESSAGING, usb::USB_WWID, usb::wwid(p)?),
        "Unit" => (MESSAGING, storage::LOGICAL_UNIT, storage::logical_unit(p)?),
        "iSCSI" => (MESSAGING, storage::ISCSI, storage::iscsi(p)?),
        "Vlan" => (MESSAGING, network::VLAN, network::vlan(p)?),
        "Dns" => (MESSAGING, network::DNS, network::dns(p, text)?),
        "Uri" => (MESSAGING, network::URI, network::uri(p)?),
        "Bluetooth" => (MESSAGING, network::BLUETOOTH, network::bluetooth(p)?),
        "Wi-Fi" => (MESSAGING, network::WIFI, network::wifi(p)?),
        "BluetoothLE" => (MESSAGING, network::BLUETOOTH_LE, network::bluetooth_le(p)?),
        "NVDIMM" => (MESSAGING, storage::NVDIMM, storage::nvdimm(p)?),
        "RestService" => (MESSAGING, network::REST_SERVICE, network::rest_service(p)?),
        "NVMEoF" => (MESSAGING, storage::NVME_OF, storage::nvme_of(p)?),
        "Sata" => (MESSAGING, storage::SATA, storage::sata(p)?),
        "MediaPath" => (MEDIA, p.integer()?, p.hex()?),
        "HD" => (MEDIA, media::HARD_DRIVE, media::hard_drive(p)?),
        "CDROM" => (MEDIA, media::CDROM, media::cdrom(p)?),
        "VenMedia" => (MEDIA, media::VENDOR, vendor::vendor(p)?),
        "Media" => (MEDIA, media::PROTOCOL, media::guid_node(p)?),
        "Fv" => (MEDIA, media::FIRMWARE_VOLUME, media::guid_node(p)?),
        "FvFile" => (MEDIA, media::FIRMWARE_FILE, media::guid_node(p)?),
        "Offset" => (MEDIA, media::OFFSET, media::offset(p)?),
        "RamDisk" => (MEDIA, media::RAM_DISK, media::ram_disk(p)?),
        "BbsPath" => (BBS, p.integer()?, p.hex()?),
        "BBS" => (BBS, bbs::BBS_101, bbs::bbs(p)?),
        name => {
            let pnp = acpi::PNP_NAMES.iter().find(|(_, named)| *named == name);
            let vendor = vendor::NAMES.iter().find(|(_, named)| *named == name);
            let class = usb::CLASS_NAMES.iter().find(|(_, named)| *named == name);
            let subclass = usb::SUBCLASS_NAMES.iter().find(|(_, named)| *named == name);
            let ram_disk = media::RAM_DISK_NAMES
                .iter()
                .find(|(_, named)| *named == name);
            match (pnp, vendor, class, subclass, ram_disk) {
                (Some((number, _)), _, _, _, _) => (ACPI, acpi::HID, acpi::pnp(p, *number)?),
                (None, Some((guid, _)), _, _, _) => (
                    MESSAGING,
                    vendor::MESSAGING_VENDOR,
                    <[u8; 16]>::from(*guid).to_vec(),
                ),
                (None, None, Some((class, _)), _, _) => {
                    (MESSAGING, usb::USB_CLASS, usb::named_class(p, *class)?)
                }
                (None, None, None, Some((subclass, _)), _) => (
                    MESSAGING,
                    usb::USB_CLASS,
                    usb::named_subclass(p, *subclass)?,
                ),
                (None, None, None, None, Some((disk_type, _))) => (
                    MEDIA,
                    media::RAM_DISK,
                    media::named_ram_disk(p, *disk_type)?,
                ),
                (None, None, None, None, None) => return Ok(None),
            }
        }
    };
    Ok(Some(node))
}

/// A node's bytes: Type, Sub-Type, Length, then `data`.
fn node_bytes(node_type: u8, sub_type: u8, data: &[u8]) -> Result<Vec<u8>, DevicePathTextError> {
    let length = NODE_HEADER_SIZE + data.len();
    let length = u16::try_from(length).map_err(|_| DevicePathTextError::TooLong(length))?;
    Ok([&[node_type, sub_type][..], &length.to_le_bytes(), data].concat())
}

/// A File Path node of `name`, UCS-2 and then Null.
fn file_path(name: &str) -> Result<Vec<u8>, DevicePathTextError> {
    if name.chars().any(|c| c == '\0' || c.len_utf16() != 1) {
        return Err(DevicePathTextError::NotUcs2(name.to_owned()));
    }
    let data: Vec<u8> = name
        .encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect();
    node_bytes(MEDIA, media::FILE_PATH, &data)
}

/// Why bytes are no device path or have no text, or text writes none.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum DevicePathTextError {
    #[error(transparent)]
    Node(#[from] LoadOptionError),
    #[error("the device path does not end with an End Entire Device Path node")]
    NoEnd,
    #[error("nodes follow the End Entire Device Path node of the device path")]
    AfterEnd,
    #[error(
        "the device path holds an instance of no node, which no text reads back to (UEFI 2.11 \
         section 10.6.1.3)"
    )]
    EmptyInstance,
    #[error("the device path holds an End node of Sub-Type 0x{0:02X}, which no text writes")]
    EndSubType(u8),
    #[error("{0:?} writes an instance of no node")]
    NoNodeText(String),
    #[error("{0:?} has unpaired parentheses")]
    Parentheses(String),
    #[error("{0:?} is no Integer or keyword that fits the field (UEFI 2.11 Table 10.66)")]
    Value(String),
    #[error(
        "a UART's BaudRate and DataBits take a number: edk2 writes {} for 0 and reads it back \
         as 115200 and 8",
        serial::UART_DEFAULT
    )]
    UartDefault,
    #[error(
        "{0:?} writes Parity and StopBits as a keyword and an integer: \"Mixing formats is \
         prohibited.\" (UEFI 2.11 Table 10.67)"
    )]
    UartMixedFormats(String),
    #[error("{0:?} is no Hex Dump of whole bytes (UEFI 2.11 Table 10.66)")]
    HexDump(String),
    #[error("{0:?} is no GUID (UEFI 2.11 Table 10.66)")]
    Guid(String),
    #[error("{0:?} is no EISAID (UEFI 2.11 Table 10.66)")]
    EisaId(String),
    #[error("{0:?} has more parameters than its form")]
    Parameters(String),
    #[error("{0:?} has text after the \")\" of its parameters, which edk2 drops")]
    AfterParentheses(String),
    #[error("{0:?} lists no value, where its form takes one or more")]
    EmptyList(String),
    #[error("{0:?} is no IP address of UEFI 2.11 Table 10.66 that fits the field")]
    IpAddress(String),
    #[error("{0:?} holds Null or a character outside ASCII, which the field holds none of")]
    NotAscii(String),
    #[error("{0:?} is longer than the {1} bytes of its field")]
    TooLongString(String, usize),
    #[error(
        "{0:?} gives a Location, Connect or DriveBay, which UEFI 2.11 Table 10.67 prohibits \
         for NoTopology and an integer topology"
    )]
    SasTopology(String),
    #[error(
        "{0:?} names no device node form that uefisettings reads; write the node in the generic \
         form of UEFI 2.11 Table 10.67, such as Path(Type,SubType,HexDump)"
    )]
    UnknownName(String),
    #[error("{0:?} writes an End node: \",\" ends an instance, and the end of the text the path")]
    EndNodeText(String),
    #[error("{0:?} holds Null or a character outside UCS-2")]
    NotUcs2(String),
    #[error("a device path node of {0} bytes does not fit its Length")]
    TooLong(usize),
}

#[cfg(test)]
pub(crate) mod tests {
    use std::net::Ipv6Addr;
    use std::str::FromStr;

    use super::*;
    use crate::efi_variables::load_option::LoadOption;

    pub(crate) fn bytes(hex: &str) -> Vec<u8> {
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                u8::from_str_radix(std::str::from_utf8(pair).expect("ASCII"), 16).expect("hex")
            })
            .collect()
    }

    // Variables that OVMF's boot manager wrote, read from the vars.fd of QEMU runs of Ubuntu's
    // edk2 2024.02 builds (i686 equals x86_64)
    pub(crate) const X64_BOOT0000: &str = "090100002c0055006900410070007000000004071400c9bdb87cebf8344faaea3ee4af6516a10406140021aa2c4614760345836e8ab6f46623317fff0400";
    pub(crate) const X64_BOOT0001: &str = "010000001600550045004600490020004d006900730063002000440065007600690063006500000002010c00d041030a000000000101060000017fff04004eac0881119f594d850ee21a522c59b2";
    pub(crate) const X64_BOOT0002: &str = "010000002c00450046004900200049006e007400650072006e0061006c0020005300680065006c006c00000004071400c9bdb87cebf8344faaea3ee4af6516a10406140083a5047c3e9e1c4fad65e05268d0b4d17fff0400";
    pub(crate) const X64_CONOUT: &str = "02010c00d041030a0000000001010600001f02010c00d041010500000000030e13000000000000c2010000000000080101030a1400d6a015adec8bcf4aa073d01de77e2d887f01040002010c00d041030a0000000001010600001f02010c00d041010501000000030e13000000000000c2010000000000080101030a1400d6a015adec8bcf4aa073d01de77e2d887fff0400";
    const X64_CONIN: &str = "02010c00d041030a0000000001010600001f02010c00d0410303000000007f01040002010c00d041030a0000000001010600001f02010c00d041010500000000030e13000000000000c2010000000000080101030a1400d6a015adec8bcf4aa073d01de77e2d887f01040002010c00d041030a0000000001010600001f02010c00d041010501000000030e13000000000000c2010000000000080101030a1400d6a015adec8bcf4aa073d01de77e2d887f010400030f0b00ffffffff0301017fff0400";
    pub(crate) const AA64_BOOT0000: &str = "090100002c0055006900410070007000000004071400fe4a07640a34e64b94ba91b5b4d0f71e0406140021aa2c4614760345836e8ab6f46623317fff0400";
    const AA64_BOOT0001: &str = "010000001600550045004600490020004d006900730063002000440065007600690063006500000002010c00d041030a000000000101060000027fff04004eac0881119f594d850ee21a522c59b2";
    const AA64_BOOT0002: &str = "010000002c00450046004900200049006e007400650072006e0061006c0020005300680065006c006c00000004071400fe4a07640a34e64b94ba91b5b4d0f71e0406140083a5047c3e9e1c4fad65e05268d0b4d17fff0400";
    const AA64_CONOUT: &str = "010414004b7d98d31a975f438caf4967eb627241030e1300000000000096000000000000080101030a14006560a6df19b4d3119a2d0090273fc14d7f01040002010c00d041030a0000000001010600000102010c00d041010500000000030e13000000000000c2010000000000080101030a14006560a6df19b4d3119a2d0090273fc14d7fff0400";

    const ESP: &str = "C12A7328-F81F-11D2-BA4B-00A0C93EC93B";
    /// The Messaging Vendor GUIDs of a debug port, UART flow control and SAS (UEFI 2.11 Table
    /// 10.67; edk2-stable202608 MdePkg.dec)
    const DEBUG_PORT_GUID: &str = "EBA4E8D2-3858-41EC-A281-2647BA9660D0";
    const FLOW_CONTROL_GUID: &str = "37499A9D-542F-4C89-A026-35DA142094E4";
    const SAS_GUID: &str = "D487DDB4-008B-11D9-AFDC-001083FFCA4D";
    /// The forms of UEFI 2.11 Table 10.67 that edk2 lacks, whose texts its DevicePath tool reads
    /// as File Paths
    const TABLE_ONLY_FORMS: [&str; 4] = ["NvdimmAcpiAdr(", "NVDIMM(", "RestService(", "NVMEoF("];
    /// Texts that edk2's GetNextDeviceNodeStr() reads past their leading separators, and what
    /// from_text reads each to
    const SEPARATOR_TEXTS: [&str; 3] = [
        ",/Pci(0x1,0x0)",
        "),/(Pci(0x1,0x0)",
        "Pci(0x1,0x0),,Pci(0x1,0x0)",
    ];

    /// A node of `node_type` and `sub_type` whose data is `fields` concatenated, as the tables
    /// of UEFI 2.11 §10.3 lay it out.
    pub(crate) fn node(node_type: u8, sub_type: u8, fields: &[&[u8]]) -> Vec<u8> {
        let data = fields.concat();
        let length = u16::try_from(4 + data.len()).expect("a short node");
        [&[node_type, sub_type][..], &length.to_le_bytes(), &data].concat()
    }

    fn guid_bytes(text: &str) -> [u8; 16] {
        Guid::from_str(text).expect("a GUID").into()
    }

    /// One device path of `nodes`, ended by an End Entire Device Path node.
    pub(crate) fn path(nodes: &[Vec<u8>]) -> Vec<u8> {
        [nodes.concat(), end_node(END_ENTIRE).to_vec()].concat()
    }

    /// A File Path node of `name`, as UEFI 2.11 Table 10.57 lays it out.
    fn file(name: &str) -> Vec<u8> {
        let name: Vec<u8> = name
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect();
        node(MEDIA, 0x04, &[&name])
    }

    /// The text of each device path of `bytes`.
    fn texts(bytes: &[u8]) -> Result<Vec<String>, DevicePathTextError> {
        device_paths(bytes)?.into_iter().map(to_text).collect()
    }

    /// Each node of the named and generic forms, field by field as the tables of UEFI 2.11 §10.3
    /// lay them out, and its text: a row of each named form of Table 10.67, of each departure
    /// from edk2 that the module documentation names, and of each class of node whose named form
    /// would not read back to its bytes, which takes the generic form.
    fn node_cases() -> Vec<(&'static str, Vec<u8>, &'static str)> {
        let mac = |address: &[u8], if_type: u8| {
            let mut field = [0; 32];
            field[..address.len()].copy_from_slice(address);
            node(MESSAGING, 0x0B, &[&field, &[if_type]])
        };
        let uart = |baud: u64, data_bits: u8, parity: u8, stop: u8| {
            node(
                MESSAGING,
                0x0E,
                &[&[0; 4], &baud.to_le_bytes(), &[data_bits, parity, stop]],
            )
        };
        let hd = |number: u32, signature: [u8; 16], format: u8, kind: u8| {
            node(
                MEDIA,
                0x01,
                &[
                    &number.to_le_bytes(),
                    &0x800_u64.to_le_bytes(),
                    &0x10_0000_u64.to_le_bytes(),
                    &signature,
                    &[format, kind],
                ],
            )
        };
        let acpi = |hid: u32, uid: u32| node(ACPI, 0x01, &[&hid.to_le_bytes(), &uid.to_le_bytes()]);
        let acpi_ex = |[hid, uid, cid]: [u32; 3], strings: [&str; 3]| {
            let strings: Vec<u8> = strings
                .iter()
                .flat_map(|text| [text.as_bytes(), &[0]].concat())
                .collect();
            node(
                ACPI,
                0x02,
                &[
                    &hid.to_le_bytes(),
                    &uid.to_le_bytes(),
                    &cid.to_le_bytes(),
                    &strings,
                ],
            )
        };
        let vendor = |guid: &str, data: &[u8]| node(MESSAGING, 0x0A, &[&guid_bytes(guid), data]);
        let usb_class = |class: u8, subclass: u8, protocol: u8| {
            node(MESSAGING, 0x0F, &[&[0xFF; 4], &[class, subclass, protocol]])
        };
        let sas_address = 0x5000_C500_1234_5678_u64;
        let sas = |topology: u16, port: u16, lun: u64| {
            vendor(
                SAS_GUID,
                &[
                    &0_u32.to_le_bytes()[..],
                    &sas_address.to_le_bytes(),
                    &lun.to_le_bytes(),
                    &topology.to_le_bytes(),
                    &port.to_le_bytes(),
                ]
                .concat(),
            )
        };
        let sas_ex = |topology: u16| {
            node(
                MESSAGING,
                0x16,
                &[
                    &sas_address.to_be_bytes(),
                    &[0; 8],
                    &topology.to_le_bytes(),
                    &1_u16.to_le_bytes(),
                ],
            )
        };
        let iscsi = |protocol: u16, options: u16, lun: [u8; 8], name: &[u8]| {
            node(
                MESSAGING,
                0x13,
                &[
                    &protocol.to_le_bytes(),
                    &options.to_le_bytes(),
                    &lun,
                    &1_u16.to_le_bytes(),
                    name,
                ],
            )
        };
        let ipv4 = |[local, remote]: [[u8; 4]; 2],
                    [local_port, remote_port, protocol]: [u16; 3],
                    kind: u8,
                    rest: &[u8]| {
            node(
                MESSAGING,
                0x0C,
                &[
                    &local,
                    &remote,
                    &local_port.to_le_bytes(),
                    &remote_port.to_le_bytes(),
                    &protocol.to_le_bytes(),
                    &[kind],
                    rest,
                ],
            )
        };
        let ram_disk = |disk_type: &str, instance: u16| {
            node(
                MEDIA,
                0x09,
                &[
                    &0x1000_u64.to_le_bytes(),
                    &0x1FFF_u64.to_le_bytes(),
                    &guid_bytes(disk_type),
                    &instance.to_le_bytes(),
                ],
            )
        };
        let mut mbr = [0; 16];
        mbr[..4].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
        let mut padded = [0; 32];
        padded[31] = 0xAA;
        let mut ssid = [0; 32];
        ssid[..4].copy_from_slice(b"home");
        let bluetooth = [0x00, 0x1A, 0x7D, 0xDA, 0x71, 0x13];
        let mut dns_ipv4 = vec![0];
        for address in [[8, 8, 8, 8], [1, 1, 1, 1]] {
            dns_ipv4.extend(address);
            dns_ipv4.extend([0; 12]);
        }
        let dns_ipv6 = [
            &[1][..],
            &[
                0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88,
            ],
        ]
        .concat();
        // the example of UEFI 2.11 Table 10.53, its NIDT, NID and SubsystemNQN
        let nvme_of_nid = [
            0x4E, 0xFF, 0x7F, 0x8E, 0xD3, 0x53, 0x4E, 0x9B, 0xA4, 0xEC, 0xDE, 0xEA, 0x8E, 0xAB,
            0x84, 0xD7,
        ];
        let nqn = b"nqn.1991-05.org.uefi:nvmeoftarget-nvmeofdisk-target\0";
        let serial: Vec<u8> = "4C530001"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let ipv6_remote = [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let ipv6_gateway = [0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        vec![
            // Hardware
            ("PCI", node(HARDWARE, 0x01, &[&[0x02, 0x1F]]), "Pci(0x1F,0x2)"),
            ("PC Card", node(HARDWARE, 0x02, &[&[0x05]]), "PcCard(0x5)"),
            (
                "memory mapped",
                node(HARDWARE, 0x03, &[&11_u32.to_le_bytes(), &0xFED0_0000_u64.to_le_bytes(), &0xFED0_0FFF_u64.to_le_bytes()]),
                "MemoryMapped(0xB,0xFED00000,0xFED00FFF)",
            ),
            (
                "Vendor hardware with data",
                node(HARDWARE, 0x04, &[&guid_bytes(ESP), &[0x01, 0xAB]]),
                "VenHw(C12A7328-F81F-11D2-BA4B-00A0C93EC93B,01AB)",
            ),
            ("controller", node(HARDWARE, 0x05, &[&2_u32.to_le_bytes()]), "Ctrl(0x2)"),
            ("BMC", node(HARDWARE, 0x06, &[&[0x01], &0xCA2_u64.to_le_bytes()]), "BMC(0x1,0xCA2)"),
            ("hardware node of no named Sub-Type", node(HARDWARE, 0x77, &[&[0xAB]]), "HardwarePath(119,AB)"),
            // ACPI
            ("PCI root", acpi(0x0A03_41D0, 0), "PciRoot(0x0)"),
            ("PCIe root", acpi(0x0A08_41D0, 1), "PcieRoot(0x1)"),
            ("floppy", acpi(0x0604_41D0, 0), "Floppy(0x0)"),
            ("keyboard", acpi(0x0301_41D0, 1), "Keyboard(0x1)"),
            ("serial port", acpi(0x0501_41D0, 2), "Serial(0x2)"),
            ("parallel port", acpi(0x0401_41D0, 0), "ParallelPort(0x0)"),
            ("ACPI PNP device without a name", acpi(0x0C0A_41D0, 0), "Acpi(PNP0C0A,0x0)"),
            ("ACPI non-PNP EISA ID", acpi(0x0002_22F0, 3), "Acpi(HWP0002,0x3)"),
            ("ACPI _HID 0, an EISA ID of no letters", acpi(0, 0), "Acpi(@@@0000,0x0)"),
            ("ACPI _HID of no EISA ID", acpi(0x0000_8000, 0), "AcpiPath(1,0080000000000000)"),
            (
                "ACPI expanded",
                acpi_ex([0x0A08_41D0, 0, 0x0A03_41D0], ["", "", ""]),
                "AcpiEx(PNP0A08,PNP0A03,0x0,,,)",
            ),
            (
                "ACPI expanded of a _HID string",
                acpi_ex([0, 0, 0], ["ACPI0004", "", ""]),
                "AcpiEx(@@@0000,@@@0000,0x0,ACPI0004,,)",
            ),
            ("ACPI expanded of UIDSTR", acpi_ex([0x0A03_41D0, 0, 0], ["", "PCI0", ""]), "AcpiExp(PNP0A03,0,PCI0)"),
            (
                "ACPI expanded of a _CID and UIDSTR",
                acpi_ex([0x0002_22F0, 0, 0x0A03_41D0], ["", "PCI1", ""]),
                "AcpiExp(HWP0002,PNP0A03,PCI1)",
            ),
            (
                "ACPI expanded of UIDSTR and a UID, which AcpiExp drops",
                acpi_ex([0x0A03_41D0, 5, 0], ["", "PCI0", ""]),
                "AcpiEx(PNP0A03,@@@0000,0x5,,,PCI0)",
            ),
            (
                "ACPI expanded without its strings",
                node(ACPI, 0x02, &[&0x0A03_41D0_u32.to_le_bytes(), &[0; 4], &0x0A08_41D0_u32.to_le_bytes()]),
                "AcpiPath(2,D041030A00000000D041080A)",
            ),
            (
                "ACPI _ADR",
                node(ACPI, 0x03, &[&0x8000_0100_u32.to_le_bytes(), &0x8000_0200_u32.to_le_bytes()]),
                "AcpiAdr(0x80000100,0x80000200)",
            ),
            ("ACPI _ADR of a part of one", node(ACPI, 0x03, &[&[0x00, 0x01, 0x00, 0x80, 0x01, 0x02]]), "AcpiPath(3,000100800102)"),
            ("NVDIMM device", node(ACPI, 0x04, &[&0x0001_0203_u32.to_le_bytes()]), "NvdimmAcpiAdr(0x10203)"),
            ("ACPI node of no named Sub-Type", node(ACPI, 0x05, &[&[0x01]]), "AcpiPath(5,01)"),
            // Messaging
            ("ATAPI", node(MESSAGING, 0x01, &[&[1, 0], &3_u16.to_le_bytes()]), "Ata(Secondary,Master,0x3)"),
            ("ATAPI of controller 2, which reads as Primary", node(MESSAGING, 0x01, &[&[2, 1, 0, 0]]), "Msg(1,02010000)"),
            ("SCSI", node(MESSAGING, 0x02, &[&1_u16.to_le_bytes(), &0_u16.to_le_bytes()]), "Scsi(0x1,0x0)"),
            (
                "Fibre Channel",
                node(MESSAGING, 0x03, &[&[0; 4], &0x2000_0025_B500_A01F_u64.to_le_bytes(), &1_u64.to_le_bytes()]),
                "Fibre(0x20000025B500A01F,0x1)",
            ),
            (
                "Fibre Channel of a Reserved field set",
                node(MESSAGING, 0x03, &[&1_u32.to_le_bytes(), &0x2000_0025_B500_A01F_u64.to_le_bytes(), &1_u64.to_le_bytes()]),
                "Msg(3,010000001FA000B5250000200100000000000000)",
            ),
            (
                "Fibre Channel Ex",
                node(MESSAGING, 0x15, &[&[0; 4], &[0x20, 0, 0, 0x25, 0xB5, 0, 0xA0, 0x1F], &[0, 1, 0, 0, 0, 0, 0, 0]]),
                "FibreEx(0x20000025B500A01F,0x0001000000000000)",
            ),
            ("1394", node(MESSAGING, 0x04, &[&[0; 4], &0x0001_0203_0405_0607_u64.to_le_bytes()]), "I1394(0001020304050607)"),
            ("USB", node(MESSAGING, 0x05, &[&[0x02, 0x00]]), "USB(0x2,0x0)"),
            ("I2O", node(MESSAGING, 0x06, &[&0x10_u32.to_le_bytes()]), "I2O(0x10)"),
            ("Messaging node of no named Sub-Type", node(MESSAGING, 0x07, &[&[0x01]]), "Msg(7,01)"),
            (
                "InfiniBand",
                node(MESSAGING, 0x09, &[&1_u32.to_le_bytes(), &guid_bytes(ESP), &2_u64.to_le_bytes(), &3_u64.to_le_bytes(), &4_u64.to_le_bytes()]),
                "Infiniband(0x1,C12A7328-F81F-11D2-BA4B-00A0C93EC93B,0x2,0x3,0x4)",
            ),
            ("PC-ANSI terminal", vendor("E0C14753-F9BE-11D2-9A0C-0090273FC14D", &[]), "VenPcAnsi()"),
            ("VT-100 terminal", vendor("DFA66065-B419-11D3-9A2D-0090273FC14D", &[]), "VenVt100()"),
            ("VT-100+ terminal", vendor("7BAEC70B-57E0-4C76-8E87-2F9E28088343", &[]), "VenVt100Plus()"),
            ("VT-UTF8 terminal", vendor("AD15A0D6-8BEC-4ACF-A073-D01DE77E2D88", &[]), "VenUtf8()"),
            ("debug port", vendor(DEBUG_PORT_GUID, &[]), "DebugPort()"),
            (
                "PC-ANSI terminal with data",
                vendor("E0C14753-F9BE-11D2-9A0C-0090273FC14D", &[0x01]),
                "VenMsg(E0C14753-F9BE-11D2-9A0C-0090273FC14D,01)",
            ),
            ("debug port with data", vendor(DEBUG_PORT_GUID, &[0xAA]), "VenMsg(EBA4E8D2-3858-41EC-A281-2647BA9660D0,AA)"),
            ("UART flow control XON/XOFF", vendor(FLOW_CONTROL_GUID, &2_u32.to_le_bytes()), "UartFlowCtrl(XonXoff)"),
            ("UART flow control by hardware", vendor(FLOW_CONTROL_GUID, &1_u32.to_le_bytes()), "UartFlowCtrl(Hardware)"),
            ("UART without flow control", vendor(FLOW_CONTROL_GUID, &0_u32.to_le_bytes()), "UartFlowCtrl(None)"),
            (
                "UART flow control of both bits, which edk2 writes no text for",
                vendor(FLOW_CONTROL_GUID, &3_u32.to_le_bytes()),
                "VenMsg(37499A9D-542F-4C89-A026-35DA142094E4,03000000)",
            ),
            (
                "SAS of an internal SATA device in drive bay 1",
                sas(0x0012, 0, 0),
                "SAS(0x5000C50012345678,0x0,0x0,SATA,Internal,Direct,0x1,0x0)",
            ),
            ("SAS of no topology", sas(0x0000, 2, 1), "SAS(0x5000C50012345678,0x1,0x2,NoTopology,0,0,0,0x0)"),
            ("Ethernet MAC", mac(&[0x52, 0x54, 0x00, 0x12, 0x34, 0x56], 1), "MAC(525400123456,0x1)"),
            (
                "Ethernet MAC with padding",
                mac(&padded, 1),
                "Msg(11,00000000000000000000000000000000000000000000000000000000000000AA01)",
            ),
            (
                "IPv4 static TCP",
                ipv4([[192, 168, 0, 2], [192, 168, 0, 1]], [0, 0, 6], 1, &[192, 168, 0, 254, 255, 255, 255, 0]),
                "IPv4(192.168.0.1,TCP,Static,192.168.0.2,192.168.0.254,255.255.255.0)",
            ),
            ("IPv4 by DHCP", ipv4([[0; 4], [0; 4]], [0, 0, 17], 0, &[0; 8]), "IPv4(0.0.0.0,UDP,DHCP,0.0.0.0,0.0.0.0,0.0.0.0)"),
            (
                "IPv4 of a port, which the form does not show",
                ipv4([[0; 4], [192, 168, 0, 1]], [0, 69, 17], 0, &[0; 8]),
                "Msg(12,00000000C0A80001000045001100000000000000000000)",
            ),
            (
                "IPv4 without a gateway, of UEFI 2.0",
                ipv4([[0; 4], [192, 168, 0, 1]], [0, 0, 6], 1, &[]),
                "Msg(12,00000000C0A8000100000000060001)",
            ),
            (
                "IPv6",
                node(
                    MESSAGING,
                    0x0D,
                    &[&[0; 16], &ipv6_remote, &[0; 4], &17_u16.to_le_bytes(), &[1, 64], &ipv6_gateway],
                ),
                "IPv6(2001:0DB8:0000:0000:0000:0000:0000:0001,UDP,StatelessAutoConfigure,\
                 0000:0000:0000:0000:0000:0000:0000:0000,0x40,FE80:0000:0000:0000:0000:0000:0000:0001)",
            ),
            ("UART", uart(115_200, 8, 1, 1), "Uart(115200,8,N,1)"),
            ("UART of even parity and 1.5 stop bits", uart(115_200, 8, 2, 2), "Uart(115200,8,E,1.5)"),
            ("UART of odd parity and 2 stop bits", uart(9600, 7, 3, 3), "Uart(9600,7,O,2)"),
            ("UART of mark parity", uart(57_600, 8, 4, 1), "Uart(57600,8,M,1)"),
            ("UART of space parity and default stop bits", uart(38_400, 8, 5, 0), "Uart(38400,8,S,D)"),
            ("UART of baud rate 0", uart(0, 0, 0, 0), "Uart(0,0,D,D)"),
            ("UART parity as an integer", uart(9600, 7, 6, 4), "Uart(9600,7,6,4)"),
            (
                "UART of integers that read as keywords",
                uart(9600, 7, 6, 2),
                "Msg(14,000000008025000000000000070602)",
            ),
            (
                "USB class",
                node(MESSAGING, 0x0F, &[&0x1234_u16.to_le_bytes(), &0x5678_u16.to_le_bytes(), &[0x12, 0x34, 0x56]]),
                "UsbClass(0x1234,0x5678,0x12,0x34,0x56)",
            ),
            ("USB audio", usb_class(1, 1, 2), "UsbAudio(0xFFFF,0xFFFF,0x1,0x2)"),
            ("USB CDC control", usb_class(2, 1, 2), "UsbCDCControl(0xFFFF,0xFFFF,0x1,0x2)"),
            ("USB HID", usb_class(3, 1, 1), "UsbHID(0xFFFF,0xFFFF,0x1,0x1)"),
            ("USB image", usb_class(6, 1, 2), "UsbImage(0xFFFF,0xFFFF,0x1,0x2)"),
            ("USB printer", usb_class(7, 1, 2), "UsbPrinter(0xFFFF,0xFFFF,0x1,0x2)"),
            ("USB mass storage", usb_class(8, 6, 0x50), "UsbMassStorage(0xFFFF,0xFFFF,0x6,0x50)"),
            ("USB hub", usb_class(9, 0, 0), "UsbHub(0xFFFF,0xFFFF,0x0,0x0)"),
            ("USB CDC data", usb_class(10, 1, 2), "UsbCDCData(0xFFFF,0xFFFF,0x1,0x2)"),
            ("USB smart card", usb_class(11, 1, 2), "UsbSmartCard(0xFFFF,0xFFFF,0x1,0x2)"),
            ("USB video", usb_class(14, 1, 2), "UsbVideo(0xFFFF,0xFFFF,0x1,0x2)"),
            ("USB diagnostic", usb_class(220, 1, 2), "UsbDiagnostic(0xFFFF,0xFFFF,0x1,0x2)"),
            ("USB wireless", usb_class(224, 1, 2), "UsbWireless(0xFFFF,0xFFFF,0x1,0x2)"),
            ("USB device firmware update", usb_class(254, 1, 2), "UsbDeviceFirmwareUpdate(0xFFFF,0xFFFF,0x2)"),
            ("USB IrDA bridge", usb_class(254, 2, 2), "UsbIrdaBridge(0xFFFF,0xFFFF,0x2)"),
            ("USB test and measurement", usb_class(254, 3, 2), "UsbTestAndMeasurement(0xFFFF,0xFFFF,0x2)"),
            ("USB application-specific subclass of no name", usb_class(254, 4, 0), "UsbClass(0xFFFF,0xFFFF,0xFE,0x4,0x0)"),
            (
                "USB WWID",
                node(MESSAGING, 0x10, &[&0_u16.to_le_bytes(), &0x0781_u16.to_le_bytes(), &0x5581_u16.to_le_bytes(), &serial]),
                "UsbWwid(0x781,0x5581,0x0,\"4C530001\")",
            ),
            ("logical unit", node(MESSAGING, 0x11, &[&[0x03]]), "Unit(0x3)"),
            (
                "SATA",
                node(MESSAGING, 0x12, &[&0_u16.to_le_bytes(), &0xFFFF_u16.to_le_bytes(), &[0, 0]]),
                "Sata(0x0,0xFFFF,0x0)",
            ),
            (
                "iSCSI of a header digest",
                iscsi(0, 0x0802, [0, 1, 0, 0, 0, 0, 0, 0], b"iqn.2001-04.com.example:storage\0"),
                "iSCSI(iqn.2001-04.com.example:storage,0x1,0x0001000000000000,CRC32C,None,None,TCP)",
            ),
            (
                "iSCSI of a data digest, CHAP_UNI and a reserved protocol",
                iscsi(1, 0x1008, [0; 8], b"t\0"),
                "iSCSI(t,0x1,0x0000000000000000,None,CRC32C,CHAP_UNI,reserved)",
            ),
            ("iSCSI of CHAP_BI", iscsi(0, 0, [0; 8], b"t\0"), "iSCSI(t,0x1,0x0000000000000000,None,None,CHAP_BI,TCP)"),
            ("iSCSI of a name without Null", iscsi(0, 0x0800, [0; 8], b"t"), "Msg(19,000000080000000000000000010074)"),
            ("VLAN", node(MESSAGING, 0x14, &[&100_u16.to_le_bytes()]), "Vlan(100)"),
            (
                "SAS Ex of an external SAS device through an expander",
                sas_ex(0x0061),
                "SasEx(0x5000C50012345678,0x0000000000000000,0x1,SAS,External,Expanded,0)",
            ),
            ("SAS Ex of a topology integer", sas_ex(0x0083), "SasEx(0x5000C50012345678,0x0000000000000000,0x1,0x83,0,0,0)"),
            (
                "NVMe",
                node(MESSAGING, 0x17, &[&1_u32.to_le_bytes(), &[1, 2, 3, 4, 5, 6, 7, 8]]),
                "NVMe(0x1,08-07-06-05-04-03-02-01)",
            ),
            ("URI", node(MESSAGING, 0x18, &[b"http://host/boot.efi"]), "Uri(http://host/boot.efi)"),
            ("URI with a comma", node(MESSAGING, 0x18, &[b"a,b"]), "Msg(24,612C62)"),
            ("URI outside ASCII", node(MESSAGING, 0x18, &["\u{E9}".as_bytes()]), "Msg(24,C3A9)"),
            ("UFS", node(MESSAGING, 0x19, &[&[0, 0x81]]), "UFS(0x0,0x81)"),
            ("SD", node(MESSAGING, 0x1A, &[&[1]]), "SD(0x1)"),
            ("Bluetooth", node(MESSAGING, 0x1B, &[&bluetooth]), "Bluetooth(001A7DDA7113)"),
            ("Wi-Fi", node(MESSAGING, 0x1C, &[&ssid]), "Wi-Fi(home)"),
            (
                "Wi-Fi of bytes after a Null",
                node(MESSAGING, 0x1C, &[b"ab\0c", &[0; 28]]),
                "Msg(28,6162006300000000000000000000000000000000000000000000000000000000)",
            ),
            ("eMMC", node(MESSAGING, 0x1D, &[&[0]]), "eMMC(0x0)"),
            ("BluetoothLE", node(MESSAGING, 0x1E, &[&bluetooth, &[1]]), "BluetoothLE(001A7DDA7113,0x01)"),
            ("DNS over IPv4", node(MESSAGING, 0x1F, &[&dns_ipv4]), "Dns(8.8.8.8,1.1.1.1)"),
            ("DNS over IPv6", node(MESSAGING, 0x1F, &[&dns_ipv6]), "Dns(2001:4860:4860:0000:0000:0000:0000:8888)"),
            ("NVDIMM namespace", node(MESSAGING, 0x20, &[&guid_bytes(ESP)]), "NVDIMM(C12A7328-F81F-11D2-BA4B-00A0C93EC93B)"),
            ("Redfish out-of-band REST service", node(MESSAGING, 0x21, &[&[1, 2]]), "RestService(1,2)"),
            (
                "vendor-specific REST service",
                node(MESSAGING, 0x21, &[&[0xFF, 1], &guid_bytes(ESP), &[0xAB]]),
                "RestService(255,1,C12A7328-F81F-11D2-BA4B-00A0C93EC93B,AB)",
            ),
            (
                "NVMe-oF namespace, the example of UEFI 2.11 Table 10.53",
                node(MESSAGING, 0x22, &[&[0x03], &nvme_of_nid, nqn]),
                "NVMEoF(nqn.1991-05.org.uefi:nvmeoftarget-nvmeofdisk-target,\
                 urn:uuid:4eff7f8e-d353-4e9b-a4ec-deea8eab84d7)",
            ),
            (
                "NVMe-oF namespace of an NGUID",
                node(MESSAGING, 0x22, &[&[0x02], &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16], b"a\0"]),
                "Msg(34,020102030405060708090A0B0C0D0E0F106100)",
            ),
            // Media
            (
                "GPT partition",
                hd(1, guid_bytes(ESP), 0x02, 0x02),
                "HD(1,GPT,C12A7328-F81F-11D2-BA4B-00A0C93EC93B,0x800,0x100000)",
            ),
            ("MBR partition", hd(2, mbr, 0x01, 0x01), "HD(2,MBR,0x12345678,0x800,0x100000)"),
            ("partition without a signature", hd(3, [0; 16], 0x00, 0x00), "HD(3,0,0,0x800,0x100000)"),
            (
                "partition of mixed formats",
                hd(4, mbr, 0x02, 0x01),
                "MediaPath(1,0400000000080000000000000000100000000000785634120000000000000000000000000201)",
            ),
            (
                "partition numbered from 2^31",
                hd(0x8000_0000, guid_bytes(ESP), 0x02, 0x02),
                "HD(2147483648,GPT,C12A7328-F81F-11D2-BA4B-00A0C93EC93B,0x800,0x100000)",
            ),
            (
                "CD-ROM",
                node(MEDIA, 0x02, &[&0_u32.to_le_bytes(), &0x10_u64.to_le_bytes(), &0x20_u64.to_le_bytes()]),
                "CDROM(0x0,0x10,0x20)",
            ),
            (
                "Vendor media",
                node(MEDIA, 0x03, &[&guid_bytes(ESP)]),
                "VenMedia(C12A7328-F81F-11D2-BA4B-00A0C93EC93B)",
            ),
            ("file path", file("\\EFI\\BOOT\\BOOTX64.EFI"), "\\EFI\\BOOT\\BOOTX64.EFI"),
            ("file path with a slash", file("a/b"), "MediaPath(4,61002F0062000000)"),
            ("file path that reads as a node", file("Pci(0x1,0x0)"), "MediaPath(4,50006300690028003000780031002C0030007800300029000000)"),
            (
                "file path that edk2 reads as a node and the text after it",
                file("Pci(0x1,0x0)abc"),
                "MediaPath(4,50006300690028003000780031002C0030007800300029006100620063000000)",
            ),
            (
                "file path named as a node of no known form",
                file("PciRot(0x0)"),
                "MediaPath(4,50006300690052006F007400280030007800300029000000)",
            ),
            ("file path that starts with a separator", file("(a"), "MediaPath(4,280061000000)"),
            (
                "media protocol",
                node(MEDIA, 0x05, &[&guid_bytes("7C04A583-9E3E-4F1C-AD65-E05268D0B4D1")]),
                "Media(7C04A583-9E3E-4F1C-AD65-E05268D0B4D1)",
            ),
            (
                "firmware volume",
                node(MEDIA, 0x07, &[&guid_bytes("7CB8BDC9-F8EB-4F34-AAEA-3EE4AF6516A1")]),
                "Fv(7CB8BDC9-F8EB-4F34-AAEA-3EE4AF6516A1)",
            ),
            (
                "firmware file",
                node(MEDIA, 0x06, &[&guid_bytes("7C04A583-9E3E-4F1C-AD65-E05268D0B4D1")]),
                "FvFile(7C04A583-9E3E-4F1C-AD65-E05268D0B4D1)",
            ),
            (
                "relative offset range",
                node(MEDIA, 0x08, &[&[0; 4], &0_u64.to_le_bytes(), &0xFFF_u64.to_le_bytes()]),
                "Offset(0x0,0xFFF)",
            ),
            ("RAM disk", ram_disk(ESP, 1), "RamDisk(0x1000,0x1FFF,1,C12A7328-F81F-11D2-BA4B-00A0C93EC93B)"),
            ("virtual disk", ram_disk("77AB535A-45FC-624B-5560-F7B281D1F96E", 0), "VirtualDisk(0x1000,0x1FFF,0)"),
            ("virtual CD", ram_disk("3D5ABD30-4175-87CE-6D64-D2ADE523C4BB", 0), "VirtualCD(0x1000,0x1FFF,0)"),
            (
                "persistent virtual disk",
                ram_disk("5CEA02C9-4D07-69D3-269F-4496FBE096F9", 2),
                "PersistentVirtualDisk(0x1000,0x1FFF,2)",
            ),
            (
                "persistent virtual CD",
                ram_disk("08018188-42CD-BB48-100F-5387D53DED3D", 0),
                "PersistentVirtualCD(0x1000,0x1FFF,0)",
            ),
            ("Media node of no named Sub-Type", node(MEDIA, 0x0A, &[&[0x01]]), "MediaPath(10,01)"),
            // BIOS Boot Specification
            ("BBS hard drive", node(BBS, 0x01, &[&2_u16.to_le_bytes(), &0_u16.to_le_bytes(), b"SATA0\0"]), "BBS(HD,SATA0,0x0)"),
            ("BBS of a type of no keyword", node(BBS, 0x01, &[&0x80_u16.to_le_bytes(), &1_u16.to_le_bytes(), b"PXE\0"]), "BBS(0x80,PXE,0x1)"),
            ("BBS node of no named Sub-Type", node(BBS, 0x02, &[&[0x01]]), "BbsPath(2,01)"),
            ("node of no named Type", node(0x09, 0x09, &[&[0x01, 0x02]]), "Path(9,9,0102)"),
        ]
    }

    #[test]
    fn ovmf_load_options_read_as_its_boot_manager_writes_them() {
        // the text of BdsDxe's "loading Boot####" and "failed to load Boot####" lines in the
        // console logs of the same runs
        let cases = [
            ("x86_64 Boot0001", X64_BOOT0001, "PciRoot(0x0)/Pci(0x1,0x0)"),
            (
                "x86_64 Boot0002",
                X64_BOOT0002,
                "Fv(7CB8BDC9-F8EB-4F34-AAEA-3EE4AF6516A1)/FvFile(7C04A583-9E3E-4F1C-AD65-E05268D0B4D1)",
            ),
            ("aarch64 Boot0001", AA64_BOOT0001, "PciRoot(0x0)/Pci(0x2,0x0)"),
            (
                "aarch64 Boot0002",
                AA64_BOOT0002,
                "Fv(64074AFE-340A-4BE6-94BA-91B5B4D0F71E)/FvFile(7C04A583-9E3E-4F1C-AD65-E05268D0B4D1)",
            ),
        ];
        for (name, option, want) in cases {
            let option = LoadOption::decode(&bytes(option)).expect("an OVMF load option");
            assert_eq!(
                texts(option.file_paths.as_ref()),
                Ok(vec![want.to_owned()]),
                "{name}: the text that OVMF's BdsDxe logged"
            );
            assert_eq!(
                from_text(want).as_deref(),
                Ok(option.file_paths.as_ref()),
                "{name}: read back to its bytes"
            );
        }
    }

    #[test]
    fn ovmf_console_paths_read_back_to_their_bytes() {
        let serial = |n: u8| {
            format!("PciRoot(0x0)/Pci(0x1F,0x0)/Serial(0x{n})/Uart(115200,8,N,1)/VenUtf8()")
        };
        let cases = [
            (
                "x86_64 ConOut",
                X64_CONOUT,
                format!("{},/{}", serial(0), serial(1)),
            ),
            (
                "x86_64 ConIn",
                X64_CONIN,
                format!(
                    "PciRoot(0x0)/Pci(0x1F,0x0)/Acpi(PNP0303,0x0),/{},/{},/UsbHID(0xFFFF,0xFFFF,0x1,0x1)",
                    serial(0),
                    serial(1)
                ),
            ),
            (
                "aarch64 ConOut",
                AA64_CONOUT,
                "VenHw(D3987D4B-971A-435F-8CAF-4967EB627241)/Uart(38400,8,N,1)/VenVt100(),/\
                 PciRoot(0x0)/Pci(0x1,0x0)/Serial(0x0)/Uart(115200,8,N,1)/VenVt100()"
                    .to_owned(),
            ),
        ];
        for (name, variable, want) in cases {
            let variable = bytes(variable);
            assert_eq!(texts(&variable), Ok(vec![want.clone()]), "{name}: as text");
            assert_eq!(
                from_text(&want),
                Ok(variable),
                "{name}: read back to its bytes"
            );
        }
    }

    #[test]
    fn each_node_reads_as_its_form_and_back_to_its_bytes() {
        for (name, node, want) in node_cases() {
            let path = path(std::slice::from_ref(&node));
            assert_eq!(to_text(&path), Ok(want.to_owned()), "{name}: as text");
            assert_eq!(from_text(want), Ok(path), "{name}: read back to its bytes");
        }
    }

    /// Texts that to_text does not write, each read as UEFI 2.11 Tables 10.66 and 10.67 give it:
    /// omitted parameters as their defaults, keywords and integers, an IP address with its port,
    /// and a text that names no form but holds text after its ")", which edk2 reads as a File
    /// Path too.
    #[test]
    fn texts_read_as_tables_10_66_and_10_67_give_them() {
        let esp = guid_bytes(ESP);
        let ipv4 = |[local, remote]: [[u8; 4]; 2],
                    [local_port, remote_port, protocol]: [u16; 3],
                    kind: u8,
                    gateway: [u8; 4]| {
            node(
                MESSAGING,
                0x0C,
                &[
                    &local,
                    &remote,
                    &local_port.to_le_bytes(),
                    &remote_port.to_le_bytes(),
                    &protocol.to_le_bytes(),
                    &[kind],
                    &gateway,
                    &[0; 4],
                ],
            )
        };
        let ipv6 =
            |remote: [u8; 16], remote_port: u16, protocol: u16, [origin, prefix]: [u8; 2]| {
                node(
                    MESSAGING,
                    0x0D,
                    &[
                        &[0; 16],
                        &remote,
                        &0_u16.to_le_bytes(),
                        &remote_port.to_le_bytes(),
                        &protocol.to_le_bytes(),
                        &[origin, prefix],
                        &[0; 16],
                    ],
                )
            };
        let hd =
            |number: u32, signature: [u8; 16], [format, kind]: [u8; 2], [start, size]: [u64; 2]| {
                node(
                    MEDIA,
                    0x01,
                    &[
                        &number.to_le_bytes(),
                        &start.to_le_bytes(),
                        &size.to_le_bytes(),
                        &signature,
                        &[format, kind],
                    ],
                )
            };
        let acpi_ex = |[hid, uid, cid]: [u32; 3], strings: &[u8]| {
            node(
                ACPI,
                0x02,
                &[
                    &hid.to_le_bytes(),
                    &uid.to_le_bytes(),
                    &cid.to_le_bytes(),
                    strings,
                ],
            )
        };
        let uart = |parity: u8, stop: u8| {
            node(
                MESSAGING,
                0x0E,
                &[&[0; 4], &9600_u64.to_le_bytes(), &[8, parity, stop]],
            )
        };
        let usb_class = |vendor: u16, product: u16, codes: [u8; 3]| {
            node(
                MESSAGING,
                0x0F,
                &[&vendor.to_le_bytes(), &product.to_le_bytes(), &codes],
            )
        };
        let ram_disk = |disk_type: [u8; 16]| {
            node(
                MEDIA,
                0x09,
                &[
                    &0x1000_u64.to_le_bytes(),
                    &0x1FFF_u64.to_le_bytes(),
                    &disk_type,
                    &0_u16.to_le_bytes(),
                ],
            )
        };
        let mut mbr = [0; 16];
        mbr[..4].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
        let ipv6_remote = [0x20, 0x01, 0x0D, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let nvme_of_nid = [
            0x4E, 0xFF, 0x7F, 0x8E, 0xD3, 0x53, 0x4E, 0x9B, 0xA4, 0xEC, 0xDE, 0xEA, 0x8E, 0xAB,
            0x84, 0xD7,
        ];
        let serial: Vec<u8> = "4C530001"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        let sas_address = 0x5000_C500_1234_5678_u64;
        let cases: Vec<(&str, Vec<u8>)> = vec![
            (
                "Floppy()",
                node(ACPI, 0x01, &[&0x0604_41D0_u32.to_le_bytes(), &[0; 4]]),
            ),
            (
                "Keyboard(5)",
                node(
                    ACPI,
                    0x01,
                    &[&0x0301_41D0_u32.to_le_bytes(), &5_u32.to_le_bytes()],
                ),
            ),
            ("Acpi(0)", node(ACPI, 0x01, &[&[0; 8]])),
            (
                "AcpiEx(,,,ACPI0004,,)",
                acpi_ex([0, 0, 0], b"ACPI0004\0\0\0"),
            ),
            (
                "AcpiEx(PNP0A03,PNP0A08,0x1,,,PCI0)",
                acpi_ex([0x0A03_41D0, 1, 0x0A08_41D0], b"\0PCI0\0\0"),
            ),
            (
                "AcpiExp(PNP0A03,,PCI0)",
                acpi_ex([0x0A03_41D0, 0, 0], b"\0PCI0\0\0"),
            ),
            (
                "AcpiAdr(1,2,3)",
                node(
                    ACPI,
                    0x03,
                    &[
                        &1_u32.to_le_bytes(),
                        &2_u32.to_le_bytes(),
                        &3_u32.to_le_bytes(),
                    ],
                ),
            ),
            (
                "BMC(1,16)",
                node(HARDWARE, 0x06, &[&[1], &16_u64.to_le_bytes()]),
            ),
            ("Ata(0,1,0x0)", node(MESSAGING, 0x01, &[&[0, 1, 0, 0]])),
            (
                "Uart()",
                node(
                    MESSAGING,
                    0x0E,
                    &[&[0; 4], &115_200_u64.to_le_bytes(), &[8, 0, 0]],
                ),
            ),
            ("Uart(9600,8,N,)", uart(1, 0)),
            ("Uart(9600,8,2,1)", uart(2, 1)),
            ("Uart(9600,8,,2)", uart(0, 3)),
            (
                "UartFlowCtrl(1)",
                node(
                    MESSAGING,
                    0x0A,
                    &[&guid_bytes(FLOW_CONTROL_GUID), &1_u32.to_le_bytes()],
                ),
            ),
            (
                "SAS(0x5000C50012345678)",
                node(
                    MESSAGING,
                    0x0A,
                    &[
                        &guid_bytes(SAS_GUID),
                        &[0; 4],
                        &sas_address.to_le_bytes(),
                        &[0; 8],
                        &[0; 4],
                    ],
                ),
            ),
            (
                "SasEx(0x5000C50012345678,,,SATA,External,Direct,0x2)",
                node(
                    MESSAGING,
                    0x16,
                    &[
                        &sas_address.to_be_bytes(),
                        &[0; 8],
                        &0x0132_u16.to_le_bytes(),
                        &[0; 2],
                    ],
                ),
            ),
            (
                "IPv4(192.168.0.1)",
                ipv4([[0; 4], [192, 168, 0, 1]], [0, 0, 17], 0, [0; 4]),
            ),
            (
                "IPv4(192.168.0.1:69,TCP,Static,10.0.0.2:1024)",
                ipv4([[10, 0, 0, 2], [192, 168, 0, 1]], [1024, 69, 6], 1, [0; 4]),
            ),
            (
                "IPv4(192.168.0.1,UDP,DHCP,0.0.0.0,192.168.0.254)",
                ipv4(
                    [[0; 4], [192, 168, 0, 1]],
                    [0, 0, 17],
                    0,
                    [192, 168, 0, 254],
                ),
            ),
            ("IPv6([2001:db8::1]:69)", ipv6(ipv6_remote, 69, 17, [2, 0])),
            (
                "IPv6(2001:db8::1,TCP,Static,,64)",
                ipv6(ipv6_remote, 0, 6, [0, 64]),
            ),
            ("UsbHID()", usb_class(0xFFFF, 0xFFFF, [3, 0xFF, 0xFF])),
            ("UsbClass(,,3)", usb_class(0xFFFF, 0xFFFF, [3, 0xFF, 0xFF])),
            (
                "UsbTestAndMeasurement(0x1,0x2)",
                usb_class(1, 2, [0xFE, 3, 0xFF]),
            ),
            (
                "UsbWwid(0x781,0x5581,0x0,4C530001)",
                node(
                    MESSAGING,
                    0x10,
                    &[
                        &[0; 2],
                        &0x0781_u16.to_le_bytes(),
                        &0x5581_u16.to_le_bytes(),
                        &serial,
                    ],
                ),
            ),
            (
                "Sata(0x1,,0x0)",
                node(
                    MESSAGING,
                    0x12,
                    &[&1_u16.to_le_bytes(), &0xFFFF_u16.to_le_bytes(), &[0; 2]],
                ),
            ),
            (
                "iSCSI(t,0x1,0x0)",
                node(
                    MESSAGING,
                    0x13,
                    &[
                        &[0; 2],
                        &0x0800_u16.to_le_bytes(),
                        &[0; 8],
                        &1_u16.to_le_bytes(),
                        b"t\0",
                    ],
                ),
            ),
            ("SD()", node(MESSAGING, 0x1A, &[&[0]])),
            (
                "Dns(::1)",
                node(MESSAGING, 0x1F, &[&[1], &Ipv6Addr::LOCALHOST.octets()]),
            ),
            (
                "RestService(0xFF,2,C12A7328-F81F-11D2-BA4B-00A0C93EC93B)",
                node(MESSAGING, 0x21, &[&[0xFF, 2], &esp]),
            ),
            (
                "NVMEoF(nqn.x,URN:UUID:4EFF7F8E-D353-4E9B-A4EC-DEEA8EAB84D7)",
                node(MESSAGING, 0x22, &[&[3], &nvme_of_nid, b"nqn.x\0"]),
            ),
            (
                "HD(1,,C12A7328-F81F-11D2-BA4B-00A0C93EC93B,0x800,0x100000)",
                hd(1, esp, [0x02, 0x02], [0x800, 0x10_0000]),
            ),
            (
                "HD(1,1,0x12345678,0x800,0x100000)",
                hd(1, mbr, [0x01, 0x01], [0x800, 0x10_0000]),
            ),
            (
                "HD(0,GPT,C12A7328-F81F-11D2-BA4B-00A0C93EC93B)",
                hd(0, esp, [0x02, 0x02], [0, 0]),
            ),
            (
                "CDROM(,0x10,0x20)",
                node(
                    MEDIA,
                    0x02,
                    &[&[0; 4], &0x10_u64.to_le_bytes(), &0x20_u64.to_le_bytes()],
                ),
            ),
            (
                "RamDisk(0x1000,0x1FFF,,C12A7328-F81F-11D2-BA4B-00A0C93EC93B)",
                ram_disk(esp),
            ),
            (
                "VirtualCD(0x1000,0x1FFF)",
                ram_disk(guid_bytes("3D5ABD30-4175-87CE-6D64-D2ADE523C4BB")),
            ),
            (
                "BBS(2,X)",
                node(BBS, 0x01, &[&2_u16.to_le_bytes(), &[0; 2], b"X\0"]),
            ),
            ("a(b)c", file("a(b)c")),
        ];
        for (text, node) in cases {
            assert_eq!(from_text(text), Ok(path(&[node])), "{text}");
        }
    }

    #[test]
    fn instances_and_device_paths_split_as_edk2_writes_them() {
        let pci = node(HARDWARE, 0x01, &[&[0x00, 0x01]]);
        let two_instances = [pci.clone(), end_node(END_INSTANCE).to_vec(), pci.clone()].concat();
        let two_paths = [
            path(std::slice::from_ref(&pci)),
            path(std::slice::from_ref(&pci)),
        ]
        .concat();
        assert_eq!(
            texts(&path(std::slice::from_ref(&two_instances))),
            Ok(vec!["Pci(0x1,0x0),/Pci(0x1,0x0)".to_owned()]),
            "two instances, \",/\" between them as edk2 writes it"
        );
        assert_eq!(
            from_text("Pci(0x1,0x0),Pci(0x1,0x0)"),
            Ok(path(&[two_instances])),
            "two instances without the \"/\" after \",\""
        );
        assert_eq!(
            texts(&two_paths),
            Ok(vec!["Pci(0x1,0x0)".to_owned(), "Pci(0x1,0x0)".to_owned()]),
            "two device paths, as a FilePathList packs them"
        );
        assert_eq!(
            from_text("/PciRoot(0x0)/Pci(0x1,0x0)"),
            from_text("PciRoot(0x0)/Pci(0x1,0x0)"),
            "a leading \"/\""
        );
    }

    /// An instance of no node has no text, as no text reads back to it, and from_text writes
    /// none; before each node it skips "/", ",", "(" and ")" as edk2's GetNextDeviceNodeStr()
    /// does, so "," before a node ends no instance.
    #[test]
    fn empty_instances_have_no_text_and_leading_separators_are_skipped() {
        let pci = node(HARDWARE, 0x01, &[&[0x00, 0x01]]);
        let end_instance = end_node(END_INSTANCE).to_vec();
        for (name, bytes) in [
            (
                "an empty first instance",
                path(&[end_instance.clone(), pci.clone()]),
            ),
            (
                "an empty last instance",
                path(&[pci.clone(), end_instance.clone()]),
            ),
            (
                "an empty middle instance",
                path(&[
                    pci.clone(),
                    end_instance.clone(),
                    end_instance.clone(),
                    pci.clone(),
                ]),
            ),
            ("no node", path(&[])),
        ] {
            assert_eq!(
                to_text(&bytes),
                Err(DevicePathTextError::EmptyInstance),
                "{name}"
            );
        }
        let one = path(std::slice::from_ref(&pci));
        let two = path(&[pci.clone(), end_instance.clone(), pci.clone()]);
        for (text, want) in SEPARATOR_TEXTS.into_iter().zip([&one, &one, &two]) {
            assert_eq!(from_text(text).as_ref(), Ok(want), "{text}");
        }
        for text in ["Pci(0x1,0x0),", "", "/,()"] {
            assert_eq!(
                from_text(text),
                Err(DevicePathTextError::NoNodeText(text.to_owned())),
                "{text:?}"
            );
        }
    }

    /// from_text refuses a Name(...) of no form it knows, where edk2 would write a File Path of
    /// that name, and a Path() of an End node, where only "," and the end of the text write End
    /// nodes; to_text writes such a File Path in its generic form.
    #[test]
    fn unknown_names_and_end_nodes_are_refused() {
        for (text, want) in [
            (
                "PciRot(0x0)/Pci(0x1,0x0)",
                DevicePathTextError::UnknownName("PciRot(0x0)".into()),
            ),
            (
                "WiFi(home)",
                DevicePathTextError::UnknownName("WiFi(home)".into()),
            ),
            (
                "Pci(0x1,0x0)/Path(127,255)/Pci(0x2,0x0)",
                DevicePathTextError::EndNodeText("Path(127,255)".into()),
            ),
            (
                "Path(127,1)",
                DevicePathTextError::EndNodeText("Path(127,1)".into()),
            ),
            (
                "Path(0x7F,0xFF)",
                DevicePathTextError::EndNodeText("Path(0x7F,0xFF)".into()),
            ),
        ] {
            assert_eq!(from_text(text), Err(want), "{text}");
        }
        let unknown = path(&[file("PciRot(0x0)")]);
        let text = to_text(&unknown).expect("a text");
        assert_eq!(
            text, "MediaPath(4,50006300690052006F007400280030007800300029000000)",
            "a File Path named as a node of no known form"
        );
        assert_eq!(from_text(&text), Ok(unknown), "read back to its bytes");
    }

    #[test]
    fn malformed_device_paths_and_texts_are_refused() {
        let pci = node(HARDWARE, 0x01, &[&[0x00, 0x01]]);
        assert_eq!(
            device_paths(&pci),
            Err(DevicePathTextError::NoEnd),
            "no End node"
        );
        assert_eq!(
            device_paths(&[]),
            Err(DevicePathTextError::NoEnd),
            "no node"
        );
        assert!(
            matches!(
                device_paths(&[0x01, 0x01, 0x02, 0x00]),
                Err(DevicePathTextError::Node(_))
            ),
            "a node Length below 4"
        );
        assert_eq!(
            to_text(&pci),
            Err(DevicePathTextError::NoEnd),
            "a path without End"
        );
        assert_eq!(
            to_text(&[path(std::slice::from_ref(&pci)), pci.clone()].concat()),
            Err(DevicePathTextError::AfterEnd),
            "a node after the End"
        );
        assert_eq!(
            to_text(&path(&[pci.clone(), end_node(0x02).to_vec(), pci.clone()])),
            Err(DevicePathTextError::EndSubType(0x02)),
            "an End node of a reserved Sub-Type"
        );
        let cases = [
            (
                "Pci(0x1,0x0",
                DevicePathTextError::Parentheses("Pci(0x1,0x0".into()),
            ),
            (
                "Pci(0x1,0x0))/Pci(0x2,0x0)",
                DevicePathTextError::Parentheses("Pci(0x1,0x0))/Pci(0x2,0x0)".into()),
            ),
            (
                "Pci(0x1F,0x2,0x3)",
                DevicePathTextError::Parameters("Pci(0x1F,0x2,0x3)".into()),
            ),
            ("Pci(0x100,0x0)", DevicePathTextError::Value("0x100".into())),
            ("Pci(+1,0x0)", DevicePathTextError::Value("+1".into())),
            ("Pci(1F,0x0)", DevicePathTextError::Value("1F".into())),
            (
                "MAC(5254,0x1)",
                DevicePathTextError::Value("MAC(5254,0x1)".into()),
            ),
            ("Uart(DEFAULT,8,N,1)", DevicePathTextError::UartDefault),
            ("Uart(115200,DEFAULT,N,1)", DevicePathTextError::UartDefault),
            (
                "VenHw(C12A7328-F81F-11D2-BA4B-00A0C93EC93B,ABC)",
                DevicePathTextError::HexDump("ABC".into()),
            ),
            (
                "Fv(not-a-guid)",
                DevicePathTextError::Guid("not-a-guid".into()),
            ),
            (
                "Acpi(PN0A03,0)",
                DevicePathTextError::EisaId("PN0A03".into()),
            ),
            (
                "\\EFI\u{1F600}",
                DevicePathTextError::NotUcs2("\\EFI\u{1F600}".into()),
            ),
            (
                "Acpi(PNP+123,0)",
                DevicePathTextError::EisaId("PNP+123".into()),
            ),
            (
                "VenHw(C12A7328-F81F-11D2-BA4B-00A0C93EC93B,+1)",
                DevicePathTextError::HexDump("+1".into()),
            ),
            (
                "NVMe(0x1,+1-02-03-04-05-06-07-08)",
                DevicePathTextError::Value("+1-02-03-04-05-06-07-08".into()),
            ),
            (
                "Uart(115200,8,N,0)",
                DevicePathTextError::UartMixedFormats("Uart(115200,8,N,0)".into()),
            ),
            (
                "Uart(115200,8,2,1.5)",
                DevicePathTextError::UartMixedFormats("Uart(115200,8,2,1.5)".into()),
            ),
            (
                "Uart(115200,8,3,2)",
                DevicePathTextError::UartMixedFormats("Uart(115200,8,3,2)".into()),
            ),
            (
                "Pci(0x1,0x0)abc",
                DevicePathTextError::AfterParentheses("Pci(0x1,0x0)abc".into()),
            ),
            (
                "Uri(a(b))",
                DevicePathTextError::AfterParentheses("Uri(a(b))".into()),
            ),
            (
                "AcpiAdr()",
                DevicePathTextError::EmptyList("AcpiAdr()".into()),
            ),
            ("Dns()", DevicePathTextError::EmptyList("Dns()".into())),
            (
                "IPv4(1.2.3.4,UDP,DHCP,0.0.0.0,1.2.3.4:5)",
                DevicePathTextError::IpAddress("1.2.3.4:5".into()),
            ),
            (
                "IPv4(256.0.0.1)",
                DevicePathTextError::IpAddress("256.0.0.1".into()),
            ),
            ("IPv4()", DevicePathTextError::IpAddress("".into())),
            (
                "IPv6(::ffff:1.2.3.4)",
                DevicePathTextError::IpAddress("::ffff:1.2.3.4".into()),
            ),
            (
                "IPv6([::1]:80,UDP,Static,::,0x40,[::2]:80)",
                DevicePathTextError::IpAddress("[::2]:80".into()),
            ),
            (
                "Dns(1.2.3.4,::1)",
                DevicePathTextError::IpAddress("::1".into()),
            ),
            (
                "Wi-Fi(abcdefghijklmnopqrstuvwxyz0123456)",
                DevicePathTextError::TooLongString("abcdefghijklmnopqrstuvwxyz0123456".into(), 32),
            ),
            (
                "Uri(\u{E9})",
                DevicePathTextError::NotAscii("\u{E9}".into()),
            ),
            (
                "SAS(0x1,0,0,NoTopology,1)",
                DevicePathTextError::SasTopology("1".into()),
            ),
            (
                "SasEx(0x1,0,0,0x83,0,0,1)",
                DevicePathTextError::SasTopology("1".into()),
            ),
            (
                "SasEx(0x1,0,0,SAS,2)",
                DevicePathTextError::Value("2".into()),
            ),
            (
                "SasEx(0x1,0,0,SAS,0,4)",
                DevicePathTextError::Value("4".into()),
            ),
            (
                "SasEx(0x1,0,0,SAS,0,0,257)",
                DevicePathTextError::Value("257".into()),
            ),
            ("UartFlowCtrl(3)", DevicePathTextError::Value("3".into())),
            ("UartFlowCtrl()", DevicePathTextError::Value("".into())),
            (
                "HD(1,3,0x1,0x800,0x1000)",
                DevicePathTextError::Value("0x1".into()),
            ),
            ("HD(1,MBR,0x1)", DevicePathTextError::Value("".into())),
            ("I1394(xyz)", DevicePathTextError::Value("xyz".into())),
            (
                "NVMEoF(nqn.x,urn:uuid:zz)",
                DevicePathTextError::Value("urn:uuid:zz".into()),
            ),
            (
                "NVMEoF(nqn.x,4EFF7F8E-D353-4E9B-A4EC-DEEA8EAB84D7)",
                DevicePathTextError::Value("4EFF7F8E-D353-4E9B-A4EC-DEEA8EAB84D7".into()),
            ),
            (
                "UsbWwid(0x1,0x2,0x3,)",
                DevicePathTextError::Value("".into()),
            ),
            (
                "Ata(Tertiary,Master,0x0)",
                DevicePathTextError::Value("Tertiary".into()),
            ),
            (
                "iSCSI(t,0x1,0x0,MD5)",
                DevicePathTextError::Value("MD5".into()),
            ),
            (
                "IPv6(::1,UDP,Dynamic)",
                DevicePathTextError::Value("Dynamic".into()),
            ),
            (
                "RestService(1,2,C12A7328-F81F-11D2-BA4B-00A0C93EC93B)",
                DevicePathTextError::Parameters(
                    "RestService(1,2,C12A7328-F81F-11D2-BA4B-00A0C93EC93B)".into(),
                ),
            ),
            (
                "VenPcAnsi(01)",
                DevicePathTextError::Parameters("VenPcAnsi(01)".into()),
            ),
        ];
        for (text, want) in cases {
            assert_eq!(from_text(text), Err(want), "{text}");
        }
    }

    /// Writes `<hex>\t<text>` lines to $VECTORS_DIR/vectors.tsv, the bytes of each node case and
    /// OVMF device path and the text that to_text writes, but those of the forms that edk2 lacks,
    /// which go to $VECTORS_DIR/table-only.tsv, and to $VECTORS_DIR/separators.tsv, the bytes that
    /// from_text reads SEPARATOR_TEXTS to. The oracle that checks them is BaseTools' port of
    /// edk2's DevicePathFromText.c, its DevicePath tool, which reads each text: it checks text to
    /// bytes only, and reads the forms that it lacks as File Paths.
    #[test]
    #[ignore = "writes the vectors that edk2's DevicePath tool checks"]
    fn writes_device_path_vectors() {
        let out = std::env::var("VECTORS_DIR").expect("VECTORS_DIR names the output directory");
        let mut lines = String::new();
        let mut table_only = String::new();
        let mut add = |bytes: &[u8]| {
            for path in device_paths(bytes).expect("device paths") {
                let text = to_text(path).expect("a text");
                let line = format!("{}\t{text}\n", upper_hex(path));
                match TABLE_ONLY_FORMS.iter().any(|form| text.starts_with(form)) {
                    true => table_only.push_str(&line),
                    false => lines.push_str(&line),
                }
            }
        };
        for (_, node, _) in node_cases() {
            add(&path(&[node]));
        }
        for variable in [X64_CONOUT, X64_CONIN, AA64_CONOUT] {
            add(&bytes(variable));
        }
        for option in [
            X64_BOOT0000,
            X64_BOOT0001,
            X64_BOOT0002,
            AA64_BOOT0000,
            AA64_BOOT0001,
            AA64_BOOT0002,
        ] {
            add(LoadOption::decode(&bytes(option))
                .expect("an option")
                .file_paths
                .as_ref());
        }
        std::fs::write(format!("{out}/vectors.tsv"), lines).expect("write vectors.tsv");
        std::fs::write(format!("{out}/table-only.tsv"), table_only).expect("write table-only.tsv");
        let separators: String = SEPARATOR_TEXTS
            .iter()
            .map(|text| format!("{}\t{text}\n", upper_hex(&from_text(text).expect("bytes"))))
            .collect();
        std::fs::write(format!("{out}/separators.tsv"), separators).expect("write separators.tsv");
    }
}
