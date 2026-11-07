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

//! EFI_LOAD_OPTION (UEFI 2.11 §3.1.3), what a Boot#### variable holds, and the device path nodes
//! of its FilePathList that uefisettings writes or looks for: the Hard Drive and File Path media
//! nodes (UEFI 2.11 §10.3.5.1, §10.3.5.4), each device path ended by an End Entire Device Path
//! node (UEFI 2.11 §10.3.1).

use thiserror::Error;

use crate::hii::package::Guid;

/// Attributes and FilePathListLength, the fixed fields of an EFI_LOAD_OPTION
const LOAD_OPTION_HEADER_SIZE: usize = 6;
/// Type, Sub-Type and Length, which every device path node starts with
const NODE_HEADER_SIZE: usize = 4;
/// Type 4 (Media Device Path) and its Sub-Types 1 (Hard Drive) and 4 (File Path)
const MEDIA_DEVICE_PATH: u8 = 0x04;
const MEDIA_HARD_DRIVE: u8 = 0x01;
const MEDIA_FILE_PATH: u8 = 0x04;
/// Type 0x7F (End of Hardware Device Path) and its Sub-Type 0xFF (End Entire Device Path)
const END_DEVICE_PATH: u8 = 0x7F;
const END_ENTIRE: u8 = 0xFF;
/// Partition Format 0x01 (legacy MBR) and 0x02 (GPT), and Signature Type 0x01 (32-bit MBR
/// signature) and 0x02 (GUID) of a Hard Drive node
const FORMAT_MBR: u8 = 0x01;
const FORMAT_GPT: u8 = 0x02;
const SIGNATURE_MBR: u8 = 0x01;
const SIGNATURE_GUID: u8 = 0x02;
/// What lossy decoding puts for a CHAR16 that is no character, a surrogate
const REPLACEMENT: char = '\u{FFFD}';

bitflags::bitflags! {
    /// The Attributes of an EFI_LOAD_OPTION, LOAD_OPTION_ and these names (UEFI 2.11 §3.1.3),
    /// and any reserved bits, kept as read.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(crate) struct LoadOptionAttributes: u32 {
        const ACTIVE = 0x0000_0001;
        const FORCE_RECONNECT = 0x0000_0002;
        const HIDDEN = 0x0000_0008;
        /// LOAD_OPTION_CATEGORY_APP in the LOAD_OPTION_CATEGORY field (0x1F00), where
        /// LOAD_OPTION_CATEGORY_BOOT is 0
        const CATEGORY_APP = 0x0000_0100;
        const _ = !0;
    }
}

/// An EFI_LOAD_OPTION.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LoadOption {
    pub(crate) attributes: LoadOptionAttributes,
    /// Description, without its Null character
    pub(crate) description: Ucs2String,
    pub(crate) file_paths: FilePathList,
    /// The bytes that the boot manager passes to the image as its LoadOptions
    pub(crate) optional_data: Vec<u8>,
}

impl LoadOption {
    /// The EFI_LOAD_OPTION that `bytes` hold; a Description that is not UCS-2 is decoded with
    /// U+FFFD for each surrogate.
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, LoadOptionError> {
        let (header, rest) = bytes
            .split_first_chunk::<LOAD_OPTION_HEADER_SIZE>()
            .ok_or(LoadOptionError::Short(bytes.len()))?;
        let [a, b, c, d, e, f] = *header;
        let attributes = LoadOptionAttributes::from_bits_retain(u32::from_le_bytes([a, b, c, d]));
        let file_path_list_length = usize::from(u16::from_le_bytes([e, f]));

        let units = char16_units(rest);
        let (description, rest) = units
            .iter()
            .position(|unit| *unit == 0)
            .and_then(|null| Some((units.get(..null)?, rest.get(2 * (null + 1)..)?)))
            .ok_or(LoadOptionError::UnterminatedDescription)?;
        let description = Ucs2String::from_units_lossy(description);

        let (file_paths, optional_data) = rest.split_at_checked(file_path_list_length).ok_or(
            LoadOptionError::FilePathListBeyondEnd {
                length: file_path_list_length,
                left: rest.len(),
            },
        )?;
        Ok(Self {
            attributes,
            description,
            file_paths: FilePathList::parse(file_paths)?,
            optional_data: optional_data.to_vec(),
        })
    }

    /// The bytes of the EFI_LOAD_OPTION.
    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut bytes = self.attributes.bits().to_le_bytes().to_vec();
        bytes.extend(self.file_paths.length().to_le_bytes());
        bytes.extend(self.description.to_char16_bytes());
        bytes.extend(&self.file_paths.0);
        bytes.extend(&self.optional_data);
        bytes
    }
}

/// The little-endian CHAR16s of `bytes`, without an odd last byte.
fn char16_units(bytes: &[u8]) -> Vec<u16> {
    bytes
        .chunks_exact(2)
        .filter_map(|unit| unit.try_into().ok())
        .map(u16::from_le_bytes)
        .collect()
}

/// A string of UCS-2 characters other than Null, as a Description or a Path Name holds them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Ucs2String(String);

impl Ucs2String {
    /// The string of these CHAR16s, U+FFFD for each surrogate.
    fn from_units_lossy(units: &[u16]) -> Self {
        Self(
            units
                .iter()
                .map(|unit| char::from_u32(u32::from(*unit)).unwrap_or(REPLACEMENT))
                .collect(),
        )
    }

    /// The CHAR16s of the string, then a Null character.
    pub(crate) fn to_char16_bytes(&self) -> Vec<u8> {
        self.0
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    }
}

impl TryFrom<&str> for Ucs2String {
    type Error = LoadOptionError;

    fn try_from(text: &str) -> Result<Self, Self::Error> {
        match text.chars().all(|c| c != '\0' && c.len_utf16() == 1) {
            true => Ok(Self(text.to_string())),
            false => Err(LoadOptionError::NotUcs2(text.to_string())),
        }
    }
}

impl AsRef<str> for Ucs2String {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// FilePathList: device paths, packed, each ended by an End Entire Device Path node; the first
/// describes the device and location of the image.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct FilePathList(Vec<u8>);

impl FilePathList {
    /// The FilePathList of one device path of `nodes`, ended by an End Entire Device Path node.
    pub(crate) fn of(nodes: &[DevicePathNode]) -> Result<Self, LoadOptionError> {
        let mut bytes = Vec::new();
        for node in nodes {
            bytes.extend(node.encode()?);
        }
        bytes.extend(end_node(END_ENTIRE));
        if u16::try_from(bytes.len()).is_err() {
            return Err(LoadOptionError::FilePathListTooLong(bytes.len()));
        }
        Ok(Self(bytes))
    }

    /// `bytes` as a FilePathList: at least one node, each within the bytes, the last an End
    /// Entire Device Path node.
    fn parse(bytes: &[u8]) -> Result<Self, LoadOptionError> {
        let mut last = None;
        for node in RawNodes::new(bytes) {
            last = Some(node?);
        }
        match last {
            Some(RawNode {
                node_type: END_DEVICE_PATH,
                sub_type: END_ENTIRE,
                ..
            }) => Ok(Self(bytes.to_vec())),
            Some(_) => Err(LoadOptionError::NoEnd),
            None => Err(LoadOptionError::EmptyFilePathList),
        }
    }

    /// FilePathListLength, which `of` and `parse` keep within a UINT16.
    fn length(&self) -> u16 {
        u16::try_from(self.0.len()).unwrap_or(u16::MAX)
    }

    /// The nodes of the first instance of the first device path, which locates the image: up to
    /// its End This Instance (Sub-Type 0x01) or End Entire Device Path node.
    pub(crate) fn image_path(&self) -> Result<Vec<DevicePathNode>, LoadOptionError> {
        let mut nodes = Vec::new();
        for node in RawNodes::new(&self.0) {
            let node = node?;
            if node.node_type == END_DEVICE_PATH {
                break;
            }
            nodes.push(DevicePathNode::decode(&node)?);
        }
        Ok(nodes)
    }

    /// The first Hard Drive node of image_path, if any.
    pub(crate) fn hard_drive(&self) -> Result<Option<HardDrive>, LoadOptionError> {
        Ok(self.image_path()?.into_iter().find_map(|node| match node {
            DevicePathNode::HardDrive(hard_drive) => Some(hard_drive),
            DevicePathNode::FilePath(_) | DevicePathNode::Other { .. } => None,
        }))
    }
}

/// `bytes` as a FilePathList, as parse checks them, and short enough for FilePathListLength.
impl TryFrom<&[u8]> for FilePathList {
    type Error = LoadOptionError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let list = Self::parse(bytes)?;
        match u16::try_from(bytes.len()) {
            Ok(_) => Ok(list),
            Err(_) => Err(LoadOptionError::FilePathListTooLong(bytes.len())),
        }
    }
}

impl AsRef<[u8]> for FilePathList {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

/// An End of Hardware Device Path node of `sub_type`.
fn end_node(sub_type: u8) -> [u8; NODE_HEADER_SIZE] {
    [END_DEVICE_PATH, sub_type, 0x04, 0x00]
}

/// A device path node as found: its Type, Sub-Type and data.
pub(super) struct RawNode<'a> {
    pub(super) node_type: u8,
    pub(super) sub_type: u8,
    pub(super) data: &'a [u8],
}

/// The nodes of packed device paths, each checked to lie within them.
pub(super) struct RawNodes<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> RawNodes<'a> {
    pub(super) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
}

impl<'a> Iterator for RawNodes<'a> {
    type Item = Result<RawNode<'a>, LoadOptionError>;

    fn next(&mut self) -> Option<Self::Item> {
        let left = self
            .bytes
            .get(self.offset..)
            .filter(|left| !left.is_empty())?;
        let node = match left.split_first_chunk::<NODE_HEADER_SIZE>() {
            Some((&[node_type, sub_type, low, high], _)) => {
                let length = usize::from(u16::from_le_bytes([low, high]));
                // None for a Length below 4, or beyond the bytes left
                match left.get(NODE_HEADER_SIZE..length) {
                    Some(data) => Ok((
                        RawNode {
                            node_type,
                            sub_type,
                            data,
                        },
                        length,
                    )),
                    None => Err(LoadOptionError::NodeLength {
                        offset: self.offset,
                        length,
                        left: left.len(),
                    }),
                }
            }
            None => Err(LoadOptionError::NodeLength {
                offset: self.offset,
                length: left.len(),
                left: left.len(),
            }),
        };
        match node {
            Ok((node, length)) => {
                self.offset += length;
                Some(Ok(node))
            }
            Err(error) => {
                // nothing after a malformed node is a node
                self.offset = self.bytes.len();
                Some(Err(error))
            }
        }
    }
}

/// A device path node of the image's device path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DevicePathNode {
    HardDrive(HardDrive),
    /// A File Path node's Path Name, without its Null character
    FilePath(Ucs2String),
    /// Any other node but an End node: its Type, Sub-Type and data
    Other {
        node_type: u8,
        sub_type: u8,
        data: Vec<u8>,
    },
}

impl DevicePathNode {
    fn decode(node: &RawNode<'_>) -> Result<Self, LoadOptionError> {
        Ok(match (node.node_type, node.sub_type) {
            (MEDIA_DEVICE_PATH, MEDIA_HARD_DRIVE) => Self::HardDrive(HardDrive::decode(node.data)?),
            (MEDIA_DEVICE_PATH, MEDIA_FILE_PATH) => {
                let units = char16_units(node.data);
                match (node.data.len() % 2, units.split_last()) {
                    (0, Some((&0, name))) => Self::FilePath(Ucs2String::from_units_lossy(name)),
                    _ => return Err(LoadOptionError::FilePathName),
                }
            }
            (node_type, sub_type) => Self::Other {
                node_type,
                sub_type,
                data: node.data.to_vec(),
            },
        })
    }

    /// The node's bytes, Type, Sub-Type and Length first.
    fn encode(&self) -> Result<Vec<u8>, LoadOptionError> {
        let (node_type, sub_type, data) = match self {
            Self::HardDrive(hard_drive) => {
                (MEDIA_DEVICE_PATH, MEDIA_HARD_DRIVE, hard_drive.encode())
            }
            Self::FilePath(name) => (MEDIA_DEVICE_PATH, MEDIA_FILE_PATH, name.to_char16_bytes()),
            Self::Other {
                node_type,
                sub_type,
                data,
            } => (*node_type, *sub_type, data.clone()),
        };
        let length = NODE_HEADER_SIZE + data.len();
        let length_field =
            u16::try_from(length).map_err(|_| LoadOptionError::NodeTooLong(length))?;
        let mut bytes = vec![node_type, sub_type];
        bytes.extend(length_field.to_le_bytes());
        bytes.extend(data);
        Ok(bytes)
    }
}

/// A Hard Drive media node: a partition of a disk, by its entry in the partition table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HardDrive {
    /// The partition table entry, starting with 1
    pub(crate) partition_number: u32,
    /// Partition Start, in logical blocks
    pub(crate) start: u64,
    /// Partition Size, in logical blocks
    pub(crate) size: u64,
    pub(crate) signature: PartitionSignature,
}

/// A Hard Drive node's Partition Format, Signature Type and Partition Signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PartitionSignature {
    /// A legacy MBR partition of the disk whose 32-bit signature at address 0x1B8 of its MBR is
    /// this
    Mbr(u32),
    /// A GPT partition whose UniquePartitionGUID is this
    Gpt(Guid),
    /// Any other Partition Format and Signature Type, with the Partition Signature
    Other {
        format: u8,
        signature_type: u8,
        signature: [u8; 16],
    },
}

impl HardDrive {
    /// The Hard Drive node of these data, the node's bytes after its Length.
    fn decode(data: &[u8]) -> Result<Self, LoadOptionError> {
        let fields = HardDriveFields::read(data).ok_or(LoadOptionError::HardDriveLength(
            NODE_HEADER_SIZE + data.len(),
        ))?;
        let signature = match (fields.format, fields.signature_type) {
            (FORMAT_GPT, SIGNATURE_GUID) => PartitionSignature::Gpt(Guid::from(fields.signature)),
            (FORMAT_MBR, SIGNATURE_MBR) => match fields.signature.split_first_chunk::<4>() {
                Some((mbr, rest)) if rest.iter().all(|byte| *byte == 0) => {
                    PartitionSignature::Mbr(u32::from_le_bytes(*mbr))
                }
                Some(_) | None => fields.other_signature(),
            },
            _ => fields.other_signature(),
        };
        Ok(Self {
            partition_number: fields.partition_number,
            start: fields.start,
            size: fields.size,
            signature,
        })
    }

    /// The node's data, after its Length.
    fn encode(&self) -> Vec<u8> {
        let (signature, format, signature_type) = match self.signature {
            PartitionSignature::Mbr(mbr) => {
                let mut signature = [0; 16];
                signature
                    .iter_mut()
                    .zip(mbr.to_le_bytes())
                    .for_each(|(byte, mbr)| *byte = mbr);
                (signature, FORMAT_MBR, SIGNATURE_MBR)
            }
            PartitionSignature::Gpt(guid) => (<[u8; 16]>::from(guid), FORMAT_GPT, SIGNATURE_GUID),
            PartitionSignature::Other {
                format,
                signature_type,
                signature,
            } => (signature, format, signature_type),
        };
        [
            &self.partition_number.to_le_bytes()[..],
            &self.start.to_le_bytes(),
            &self.size.to_le_bytes(),
            &signature,
            &[format, signature_type],
        ]
        .concat()
    }
}

/// The fields of a Hard Drive node after its Length, at their byte offsets 4 to 41.
struct HardDriveFields {
    partition_number: u32,
    start: u64,
    size: u64,
    signature: [u8; 16],
    format: u8,
    signature_type: u8,
}

impl HardDriveFields {
    /// The fields that `data` holds, None unless it has exactly their 38 bytes.
    fn read(data: &[u8]) -> Option<Self> {
        let (partition_number, rest) = data.split_first_chunk::<4>()?;
        let (start, rest) = rest.split_first_chunk::<8>()?;
        let (size, rest) = rest.split_first_chunk::<8>()?;
        let (signature, rest) = rest.split_first_chunk::<16>()?;
        let &[format, signature_type] = rest else {
            return None;
        };
        Some(Self {
            partition_number: u32::from_le_bytes(*partition_number),
            start: u64::from_le_bytes(*start),
            size: u64::from_le_bytes(*size),
            signature: *signature,
            format,
            signature_type,
        })
    }

    /// The signature of a Partition Format and Signature Type that PartitionSignature does not
    /// name.
    fn other_signature(&self) -> PartitionSignature {
        PartitionSignature::Other {
            format: self.format,
            signature_type: self.signature_type,
            signature: self.signature,
        }
    }
}

/// Why bytes are no EFI_LOAD_OPTION, or a value cannot be one.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum LoadOptionError {
    #[error("{0} bytes are fewer than an EFI_LOAD_OPTION's Attributes and FilePathListLength")]
    Short(usize),
    #[error("the Description has no Null character")]
    UnterminatedDescription,
    #[error("FilePathListLength {length} exceeds the {left} bytes after the Description")]
    FilePathListBeyondEnd { length: usize, left: usize },
    #[error("the FilePathList holds no device path")]
    EmptyFilePathList,
    #[error(
        "the device path node at byte {offset} of the FilePathList has Length {length}, outside \
         4 to the {left} bytes left"
    )]
    NodeLength {
        offset: usize,
        length: usize,
        left: usize,
    },
    #[error("the FilePathList does not end with an End Entire Device Path node")]
    NoEnd,
    #[error("a Hard Drive node has Length {0}, not 42")]
    HardDriveLength(usize),
    #[error("a File Path node's Path Name is no Null-terminated CHAR16 string")]
    FilePathName,
    #[error("{0:?} holds Null or a character outside UCS-2")]
    NotUcs2(String),
    #[error("a FilePathList of {0} bytes does not fit FilePathListLength")]
    FilePathListTooLong(usize),
    #[error("a device path node of {0} bytes does not fit its Length")]
    NodeTooLong(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    const ESP_GUID: [u8; 16] = [
        0x28, 0x73, 0x2A, 0xC1, 0x1F, 0xF8, 0xD2, 0x11, 0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9,
        0x3B,
    ];

    /// `text` as CHAR16s with a Null character, as the spec lays out a Description or Path Name.
    fn char16(text: &str) -> Vec<u8> {
        text.encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect()
    }

    /// A Hard Drive node, field by field as UEFI 2.11 Table 10.54 lays it out.
    fn hard_drive_bytes(
        number: u32,
        start: u64,
        size: u64,
        signature: [u8; 16],
        format: u8,
        kind: u8,
    ) -> Vec<u8> {
        [
            &[0x04, 0x01, 42, 0][..],
            &number.to_le_bytes(),
            &start.to_le_bytes(),
            &size.to_le_bytes(),
            &signature,
            &[format, kind],
        ]
        .concat()
    }

    /// A File Path node of `name`, as UEFI 2.11 Table 10.57 lays it out.
    fn file_path_bytes(name: &str) -> Vec<u8> {
        let name = char16(name);
        let length = u16::try_from(4 + name.len()).expect("a short name");
        [&[0x04, 0x04][..], &length.to_le_bytes(), &name].concat()
    }

    /// An EFI_LOAD_OPTION, field by field as UEFI 2.11 §3.1.3 lays it out.
    fn load_option_bytes(
        attributes: u32,
        description: &str,
        file_paths: &[u8],
        optional: &[u8],
    ) -> Vec<u8> {
        let length = u16::try_from(file_paths.len()).expect("a short FilePathList");
        [
            &attributes.to_le_bytes()[..],
            &length.to_le_bytes(),
            &char16(description),
            file_paths,
            optional,
        ]
        .concat()
    }

    const END: [u8; 4] = [0x7F, 0xFF, 0x04, 0x00];

    fn ucs2(text: &str) -> Ucs2String {
        Ucs2String::try_from(text).expect("UCS-2")
    }

    fn gpt_partition() -> HardDrive {
        HardDrive {
            partition_number: 2,
            start: 0x800,
            size: 0x10_0000,
            signature: PartitionSignature::Gpt(Guid::from(ESP_GUID)),
        }
    }

    #[test]
    fn a_load_option_encodes_as_the_spec_lays_it_out_and_decodes_back() {
        let option = LoadOption {
            attributes: LoadOptionAttributes::ACTIVE
                | LoadOptionAttributes::HIDDEN
                | LoadOptionAttributes::CATEGORY_APP,
            description: ucs2("uefisettings"),
            file_paths: FilePathList::of(&[
                DevicePathNode::HardDrive(gpt_partition()),
                DevicePathNode::FilePath(ucs2(r"\EFI\uefisettings\uefisettings.efi")),
            ])
            .expect("a FilePathList"),
            optional_data: vec![1, 2, 3],
        };
        let file_paths = [
            hard_drive_bytes(2, 0x800, 0x10_0000, ESP_GUID, 0x02, 0x02),
            file_path_bytes(r"\EFI\uefisettings\uefisettings.efi"),
            END.to_vec(),
        ]
        .concat();
        let want = load_option_bytes(0x109, "uefisettings", &file_paths, &[1, 2, 3]);

        assert_eq!(option.encode(), want, "the bytes");
        assert_eq!(LoadOption::decode(&want), Ok(option), "decoded back");
    }

    #[test]
    fn the_image_path_is_the_first_instance_and_its_hard_drive_node_is_found() {
        // PciRoot(0x0)/Pci(0x1F,0x2)/Sata(0x0,0xFFFF,0x0)/HD(...)/File(...), then a second
        // instance and a second device path
        let acpi = [0x02, 0x01, 0x0C, 0x00, 0xD0, 0x41, 0x03, 0x0A, 0, 0, 0, 0];
        let pci = [0x01, 0x01, 0x06, 0x00, 0x02, 0x1F];
        let sata = [0x03, 0x12, 0x0A, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00];
        let file_paths = [
            &acpi[..],
            &pci,
            &sata,
            &hard_drive_bytes(1, 0x800, 0x8_0000, ESP_GUID, 0x02, 0x02),
            &file_path_bytes(r"\EFI\os\loader.efi"),
            &[0x7F, 0x01, 0x04, 0x00],
            &hard_drive_bytes(3, 0x9000, 0x100, [0x33; 16], 0x02, 0x02),
            &END,
            &file_path_bytes(r"\second.efi"),
            &END,
        ]
        .concat();
        let option = LoadOption::decode(&load_option_bytes(1, "OS", &file_paths, &[]))
            .expect("a load option");

        let nodes = option.file_paths.image_path().expect("the image path");
        assert_eq!(
            nodes,
            [
                DevicePathNode::Other {
                    node_type: 0x02,
                    sub_type: 0x01,
                    data: acpi[4..].to_vec()
                },
                DevicePathNode::Other {
                    node_type: 0x01,
                    sub_type: 0x01,
                    data: pci[4..].to_vec()
                },
                DevicePathNode::Other {
                    node_type: 0x03,
                    sub_type: 0x12,
                    data: sata[4..].to_vec()
                },
                DevicePathNode::HardDrive(HardDrive {
                    partition_number: 1,
                    start: 0x800,
                    size: 0x8_0000,
                    signature: PartitionSignature::Gpt(Guid::from(ESP_GUID)),
                }),
                DevicePathNode::FilePath(ucs2(r"\EFI\os\loader.efi")),
            ],
            "the nodes of the first instance only"
        );
        assert_eq!(
            option
                .file_paths
                .hard_drive()
                .expect("decoded")
                .map(|hd| hd.partition_number),
            Some(1),
            "the image's partition"
        );
        assert!(option.optional_data.is_empty(), "no OptionalData");
    }

    #[test]
    fn mbr_and_other_signatures_keep_their_bytes() {
        let mbr = HardDrive {
            signature: PartitionSignature::Mbr(0x1234_5678),
            ..gpt_partition()
        };
        let mbr_bytes = hard_drive_bytes(
            2,
            0x800,
            0x10_0000,
            [0x78, 0x56, 0x34, 0x12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            0x01,
            0x01,
        );
        let path = FilePathList::of(&[DevicePathNode::HardDrive(mbr)]).expect("a path");
        assert_eq!(
            path.as_ref(),
            [mbr_bytes.clone(), END.to_vec()].concat(),
            "MBR signature bytes"
        );

        let cases = [
            // a signature MBR with bytes beyond its 4, no signature, and a reserved format
            (
                [0x78, 0x56, 0x34, 0x12, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                0x01,
                0x01,
            ),
            ([0; 16], 0x01, 0x00),
            ([0x44; 16], 0x03, 0x02),
        ];
        for (signature, format, kind) in cases {
            let bytes = [
                hard_drive_bytes(2, 0x800, 0x10_0000, signature, format, kind),
                END.to_vec(),
            ]
            .concat();
            let path = FilePathList::parse(&bytes).expect("a FilePathList");
            let hard_drive = path
                .hard_drive()
                .expect("decoded")
                .expect("a Hard Drive node");
            assert_eq!(
                hard_drive.signature,
                PartitionSignature::Other {
                    format,
                    signature_type: kind,
                    signature
                },
                "format {format:#x}, type {kind:#x}"
            );
            assert_eq!(
                FilePathList::of(&[DevicePathNode::HardDrive(hard_drive)])
                    .expect("a path")
                    .as_ref(),
                bytes,
                "format {format:#x}, type {kind:#x} encodes back"
            );
        }
    }

    #[test]
    fn reserved_attribute_bits_are_kept() {
        let bytes = load_option_bytes(0x8000_0201, "", &END, &[]);
        let option = LoadOption::decode(&bytes).expect("a load option");
        assert_eq!(option.attributes.bits(), 0x8000_0201, "the attributes");
        assert_eq!(option.encode(), bytes, "encoded back");
    }

    #[test]
    fn malformed_load_options_are_refused() {
        let hard_drive = hard_drive_bytes(1, 0, 1, ESP_GUID, 0x02, 0x02);
        let cases = [
            (vec![1, 0, 0, 0, 4], LoadOptionError::Short(5)),
            (
                [&[1, 0, 0, 0, 4, 0][..], &[0x41, 0x00, 0x42]].concat(),
                LoadOptionError::UnterminatedDescription,
            ),
            (
                load_option_bytes(1, "x", &END, &[])[..11].to_vec(),
                LoadOptionError::FilePathListBeyondEnd { length: 4, left: 1 },
            ),
            (
                load_option_bytes(1, "x", &[], &[]),
                LoadOptionError::EmptyFilePathList,
            ),
            (
                load_option_bytes(
                    1,
                    "x",
                    &[0x01, 0x01, 0x03, 0x00, 0x7F, 0xFF, 0x04, 0x00],
                    &[],
                ),
                LoadOptionError::NodeLength {
                    offset: 0,
                    length: 3,
                    left: 8,
                },
            ),
            (
                load_option_bytes(
                    1,
                    "x",
                    &[0x01, 0x01, 0x10, 0x00, 0x7F, 0xFF, 0x04, 0x00],
                    &[],
                ),
                LoadOptionError::NodeLength {
                    offset: 0,
                    length: 16,
                    left: 8,
                },
            ),
            (
                load_option_bytes(1, "x", &[0x7F, 0xFF, 0x04], &[]),
                LoadOptionError::NodeLength {
                    offset: 0,
                    length: 3,
                    left: 3,
                },
            ),
            (
                load_option_bytes(1, "x", &hard_drive, &[]),
                LoadOptionError::NoEnd,
            ),
            (
                load_option_bytes(
                    1,
                    "x",
                    &[&[0x7F, 0x01, 0x04, 0x00][..], &END[..2]].concat(),
                    &[],
                ),
                LoadOptionError::NodeLength {
                    offset: 4,
                    length: 2,
                    left: 2,
                },
            ),
        ];
        for (bytes, want) in cases {
            assert_eq!(LoadOption::decode(&bytes), Err(want.clone()), "{want}");
        }
    }

    #[test]
    fn malformed_image_path_nodes_are_refused() {
        let short_hard_drive = [&[0x04, 0x01, 41, 0][..], &[0; 37], &END].concat();
        let odd_name = [&[0x04, 0x04, 0x07, 0x00][..], &[0x41, 0x00, 0x00], &END].concat();
        let unterminated = [&[0x04, 0x04, 0x06, 0x00][..], &[0x41, 0x00], &END].concat();
        let cases = [
            (short_hard_drive, LoadOptionError::HardDriveLength(41)),
            (odd_name, LoadOptionError::FilePathName),
            (unterminated, LoadOptionError::FilePathName),
        ];
        for (bytes, want) in cases {
            let path = FilePathList::parse(&bytes).expect("well-formed nodes");
            assert_eq!(path.image_path(), Err(want.clone()), "{want}");
        }
    }

    #[test]
    fn ucs2_strings_hold_no_null_or_surrogate_pair_and_decode_lossily() {
        assert_eq!(
            Ucs2String::try_from("A\u{0}B"),
            Err(LoadOptionError::NotUcs2("A\u{0}B".to_string())),
            "Null"
        );
        assert_eq!(
            Ucs2String::try_from("\u{1F600}"),
            Err(LoadOptionError::NotUcs2("\u{1F600}".to_string())),
            "outside the BMP"
        );
        assert_eq!(
            Ucs2String::from_units_lossy(&[0x41, 0xD800, 0x42]).as_ref(),
            "A\u{FFFD}B",
            "a surrogate"
        );
        let bytes = load_option_bytes(1, "", &END, &[]);
        let mut description = bytes.clone();
        description.splice(6..6, [0x00, 0xD8]);
        assert_eq!(
            LoadOption::decode(&description).map(|option| option.description),
            Ok(Ucs2String("\u{FFFD}".to_string())),
            "a Description with a surrogate"
        );
    }

    #[test]
    fn nodes_and_lists_that_do_not_fit_their_length_are_refused() {
        let long = DevicePathNode::Other {
            node_type: 0x01,
            sub_type: 0x01,
            data: vec![0; 65532],
        };
        assert_eq!(
            FilePathList::of(std::slice::from_ref(&long)),
            Err(LoadOptionError::NodeTooLong(65536)),
            "a node"
        );
        let half = DevicePathNode::Other {
            node_type: 0x01,
            sub_type: 0x01,
            data: vec![0; 32766],
        };
        assert_eq!(
            FilePathList::of(&[half.clone(), half]),
            Err(LoadOptionError::FilePathListTooLong(65544)),
            "a list"
        );
    }
}
