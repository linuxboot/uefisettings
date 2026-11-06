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

//! The EFI System Partition (ESP) of a disk, from the disk's partition table, and the Hard Drive
//! node (UEFI 2.11 §10.3.5.1) that names it to firmware. The table is the primary GPT (UEFI 2.11
//! §5.3) behind a protective MBR (UEFI 2.11 §5.2.3), or a legacy MBR (UEFI 2.11 §5.2.1).

use std::io;

use thiserror::Error;

use crate::efi_variables::load_option::HardDrive;
use crate::efi_variables::load_option::PartitionSignature;
use crate::hii::package::Guid;

#[cfg(test)]
mod sfdisk_images;

/// UniqueMBRDiskSignature, the four partition records and Signature of an MBR (UEFI 2.11
/// Table 5.1)
const MBR_DISK_SIGNATURE: usize = 440;
const MBR_PARTITION_RECORDS: usize = 446;
const MBR_PARTITION_RECORD_SIZE: usize = 16;
const MBR_SIGNATURE_OFFSET: usize = 510;
const MBR_SIGNATURE: u16 = 0xAA55;
/// OSType 0xEF, a UEFI system partition, and 0xEE, GPT Protective (UEFI 2.11 §5.2.2)
const OS_TYPE_ESP: u8 = 0xEF;
const OS_TYPE_GPT_PROTECTIVE: u8 = 0xEE;
/// The LBA of the primary GPT header
const PRIMARY_GPT_HEADER: u64 = 1;
/// "EFI PART", a GPT header's Signature
const GPT_SIGNATURE: u64 = 0x5452_4150_2049_4645;
/// Revision 1.0, the GPT header that UEFI 2.11 Table 5.5 lays out
const GPT_REVISION: u32 = 0x0001_0000;
/// The bytes of the fields that UEFI 2.11 Table 5.5 defines, the least HeaderSize
const GPT_HEADER_SIZE: usize = 92;
/// The byte offset of HeaderCRC32, which is zero while the header's CRC32 is computed
const GPT_HEADER_CRC32: usize = 16;
/// The bytes of a GPT entry's fields (UEFI 2.11 Table 5.6), the least SizeOfPartitionEntry
const GPT_ENTRY_SIZE: u32 = 128;
/// The largest entry array that uefisettings reads, 8192 entries of 128 bytes
const MAX_ENTRY_ARRAY: usize = 1 << 20;
/// Attributes bit 1 of a GPT entry, No Block IO Protocol (UEFI 2.11 Table 5.8)
const NO_BLOCK_IO_PROTOCOL: u64 = 1 << 1;
/// The PartitionTypeGUID of an unused GPT entry (UEFI 2.11 Table 5.7)
const UNUSED_ENTRY: Guid = Guid {
    data1: 0,
    data2: 0,
    data3: 0,
    data4: [0; 8],
};
/// The PartitionTypeGUID of an ESP (UEFI 2.11 Table 5.7)
const ESP_TYPE: Guid = Guid {
    data1: 0xC12A_7328,
    data2: 0xF81F,
    data3: 0x11D2,
    data4: [0xBA, 0x4B, 0x00, 0xA0, 0xC9, 0x3E, 0xC9, 0x3B],
};

/// A disk, read in logical blocks.
pub(crate) trait BlockDevice {
    /// The logical block size, in bytes
    fn block_size(&self) -> u32;

    /// Fills `blocks`, whole logical blocks, from LBA `lba` on.
    fn read_blocks(&self, lba: u64, blocks: &mut [u8]) -> io::Result<()>;
}

/// Where a volume's partition lies on its disk, in bytes, as the OS reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PartitionExtent {
    pub(crate) offset: u64,
    pub(crate) length: u64,
}

/// A disk's partition table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PartitionTable {
    /// The logical block size, in bytes, at least 512
    block_size: u64,
    layout: Layout,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Layout {
    Gpt(Gpt),
    Mbr(Mbr),
}

impl PartitionTable {
    /// The partition table of `disk`: its primary GPT if LBA 0 holds a GPT Protective record
    /// that starts at LBA 1, else LBA 0's legacy MBR, as edk2-stable202608
    /// PartitionDxe/Gpt.c PartitionInstallGptChildHandles tells them apart.
    pub(crate) fn read(disk: &impl BlockDevice) -> Result<Self, PartitionTableError> {
        let block_size = disk.block_size();
        let block_len =
            usize::try_from(block_size).map_err(|_| PartitionTableError::BlockSize(block_size))?;

        let lba0 = read_blocks(disk, 0, block_len)?;
        let signature = bytes_at(&lba0, MBR_SIGNATURE_OFFSET)
            .map(u16::from_le_bytes)
            .ok_or(PartitionTableError::BlockSize(block_size))?;
        if signature != MBR_SIGNATURE {
            return Err(PartitionTableError::MbrSignature(signature));
        }
        let mbr = Mbr::parse(&lba0).ok_or(PartitionTableError::BlockSize(block_size))?;

        let layout = if mbr.protects_gpt() {
            Layout::Gpt(Gpt::read(disk, block_len)?)
        } else {
            Layout::Mbr(mbr)
        };
        Ok(Self {
            block_size: u64::from(block_size),
            layout,
        })
    }

    /// The Hard Drive node of the ESP at `extent`: the partition table entry that starts there,
    /// refused unless it is an ESP that spans exactly `extent`.
    pub(crate) fn esp_hard_drive(
        &self,
        extent: PartitionExtent,
    ) -> Result<HardDrive, PartitionTableError> {
        let (Some(start), Some(size)) = (self.blocks(extent.offset), self.blocks(extent.length))
        else {
            return Err(PartitionTableError::NotInBlocks {
                offset: extent.offset,
                length: extent.length,
                block_size: self.block_size,
            });
        };
        match &self.layout {
            Layout::Gpt(gpt) => gpt.esp_hard_drive(start, size),
            Layout::Mbr(mbr) => mbr.esp_hard_drive(start, size),
        }
    }

    /// The logical blocks that `bytes` make, None unless whole.
    fn blocks(&self, bytes: u64) -> Option<u64> {
        bytes
            .is_multiple_of(self.block_size)
            .then(|| bytes / self.block_size)
    }
}

/// `len` bytes, whole logical blocks, of `disk` from LBA `lba` on.
fn read_blocks(
    disk: &impl BlockDevice,
    lba: u64,
    len: usize,
) -> Result<Vec<u8>, PartitionTableError> {
    let mut blocks = vec![0; len];
    disk.read_blocks(lba, &mut blocks)
        .map_err(|error| PartitionTableError::Read { lba, len, error })?;
    Ok(blocks)
}

/// The `N` bytes at byte `offset` of `bytes`.
fn bytes_at<const N: usize>(bytes: &[u8], offset: usize) -> Option<[u8; N]> {
    bytes.get(offset..)?.first_chunk().copied()
}

/// A partition table entry: a GPT entry or an MBR partition record.
trait TableEntry {
    /// The Partition Number of the entry's Hard Drive node, starting with 1
    fn number(&self) -> u32;

    /// The first and last LBA of the entry's partition, None if the entry is not in use.
    fn lbas(&self) -> Option<(u64, u64)>;
}

/// The entry in use that starts at LBA `start` and its last LBA, refused unless it is the only
/// one.
fn entry_starting_at<E: TableEntry>(
    entries: &[E],
    start: u64,
) -> Result<(&E, u64), PartitionTableError> {
    let starting: Vec<(&E, u64)> = entries
        .iter()
        .filter_map(|entry| match entry.lbas()? {
            (first, last) if first == start => Some((entry, last)),
            _ => None,
        })
        .collect();
    match starting.as_slice() {
        [entry] => Ok(*entry),
        [] => Err(PartitionTableError::NoPartitionAt(start)),
        several => Err(PartitionTableError::SeveralPartitionsAt {
            lba: start,
            numbers: several.iter().map(|(entry, _)| entry.number()).collect(),
        }),
    }
}

/// Refuses the partition of `entry`, LBAs `first` to `last`, unless it spans the volume's `size`
/// logical blocks and overlaps no other entry in use: GPT partitions must not overlap (UEFI 2.11
/// §5.3.1), and edk2-stable202608 PartitionDxe makes no partition of overlapping GPT entries,
/// nor of any record of an MBR with overlapping records.
fn check_extent<E: TableEntry>(
    entries: &[E],
    entry: &E,
    (first, last): (u64, u64),
    size: u64,
) -> Result<(), PartitionTableError> {
    let overlapping: Vec<u32> = entries
        .iter()
        .filter(|other| other.number() != entry.number())
        .filter_map(|other| match other.lbas()? {
            (other_first, other_last) if other_first <= last && first <= other_last => {
                Some(other.number())
            }
            _ => None,
        })
        .collect();
    if !overlapping.is_empty() {
        return Err(PartitionTableError::Overlap {
            number: entry.number(),
            overlapping,
        });
    }

    match last.checked_sub(first).and_then(|span| span.checked_add(1)) {
        Some(blocks) if blocks == size => Ok(()),
        Some(_) | None => Err(PartitionTableError::SizeMismatch {
            number: entry.number(),
            first,
            last,
            volume_blocks: size,
        }),
    }
}

/// LBA 0's MBR: its UniqueMBRDiskSignature and its four partition records.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Mbr {
    disk_signature: u32,
    records: Vec<MbrRecord>,
}

/// A partition record of an MBR (UEFI 2.11 Table 5.2) and its slot, 1 to 4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MbrRecord {
    slot: u32,
    os_type: u8,
    starting_lba: u32,
    size_in_lba: u32,
}

impl Mbr {
    /// The MBR in `lba0`, None if it is shorter than the 510 bytes before Signature.
    fn parse(lba0: &[u8]) -> Option<Self> {
        let records = lba0
            .get(MBR_PARTITION_RECORDS..MBR_SIGNATURE_OFFSET)?
            .chunks_exact(MBR_PARTITION_RECORD_SIZE)
            .zip(1..)
            .map(|(record, slot)| {
                let [_, _, _, _, os_type, _, _, _, a, b, c, d, e, f, g, h] =
                    <[u8; MBR_PARTITION_RECORD_SIZE]>::try_from(record).ok()?;
                Some(MbrRecord {
                    slot,
                    os_type,
                    starting_lba: u32::from_le_bytes([a, b, c, d]),
                    size_in_lba: u32::from_le_bytes([e, f, g, h]),
                })
            })
            .collect::<Option<_>>()?;
        Some(Self {
            disk_signature: bytes_at(lba0, MBR_DISK_SIGNATURE).map(u32::from_le_bytes)?,
            records,
        })
    }

    /// Whether the MBR is a protective MBR, with a GPT Protective record that starts at the
    /// primary GPT header.
    fn protects_gpt(&self) -> bool {
        self.records.iter().any(|record| {
            record.os_type == OS_TYPE_GPT_PROTECTIVE
                && u64::from(record.starting_lba) == PRIMARY_GPT_HEADER
        })
    }

    /// The Hard Drive node of the ESP of `size` logical blocks from LBA `start` on: its
    /// partition record's slot, with Signature Type 0x01 (UEFI 2.11 §10.3.5.1).
    fn esp_hard_drive(&self, start: u64, size: u64) -> Result<HardDrive, PartitionTableError> {
        let (record, last) = entry_starting_at(&self.records, start)?;
        if record.os_type != OS_TYPE_ESP {
            return Err(PartitionTableError::MbrNotEsp {
                slot: record.slot,
                os_type: record.os_type,
            });
        }
        check_extent(&self.records, record, (start, last), size)?;
        Ok(HardDrive {
            partition_number: record.slot,
            start,
            size,
            signature: PartitionSignature::Mbr(self.disk_signature),
        })
    }
}

impl TableEntry for MbrRecord {
    fn number(&self) -> u32 {
        self.slot
    }

    /// edk2-stable202608 PartitionDxe/Mbr.c skips a record whose OSType or SizeInLBA is 0, and a
    /// GPT Protective one.
    fn lbas(&self) -> Option<(u64, u64)> {
        let span = self.size_in_lba.checked_sub(1)?;
        let first = u64::from(self.starting_lba);
        match self.os_type {
            0 | OS_TYPE_GPT_PROTECTIVE => None,
            _ => Some((first, first + u64::from(span))),
        }
    }
}

/// The primary GPT: the usable LBAs that its header declares and its entries.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Gpt {
    first_usable_lba: u64,
    last_usable_lba: u64,
    entries: Vec<GptEntry>,
}

impl Gpt {
    /// The primary GPT of `disk`, refused unless its header and entry array pass the tests of
    /// UEFI 2.11 §5.3.2; the backup GPT is not read.
    fn read(disk: &impl BlockDevice, block_len: usize) -> Result<Self, PartitionTableError> {
        let block = read_blocks(disk, PRIMARY_GPT_HEADER, block_len)?;
        let header = GptHeader::read(&block)
            .ok_or_else(|| PartitionTableError::BlockSize(disk.block_size()))?;
        header.check(&block)?;
        Ok(Self {
            first_usable_lba: header.first_usable_lba,
            last_usable_lba: header.last_usable_lba,
            entries: header.read_entries(disk, block_len)?,
        })
    }

    /// The Hard Drive node of the ESP of `size` logical blocks from LBA `start` on: its GPT
    /// entry's index plus 1, as edk2-stable202608 PartitionDxe/Gpt.c numbers it, with its
    /// UniquePartitionGUID (UEFI 2.11 §10.3.5.1).
    fn esp_hard_drive(&self, start: u64, size: u64) -> Result<HardDrive, PartitionTableError> {
        let (entry, last) = entry_starting_at(&self.entries, start)?;
        if entry.partition_type != ESP_TYPE {
            return Err(PartitionTableError::GptNotEsp {
                number: entry.number,
                partition_type: entry.partition_type,
            });
        }
        // firmware must not produce an EFI_BLOCK_IO_PROTOCOL device for such a partition, so
        // UEFI makes no file system mapping for it (UEFI 2.11 Table 5.8)
        if entry.attributes & NO_BLOCK_IO_PROTOCOL != 0 {
            return Err(PartitionTableError::GptNoBlockIo(entry.number));
        }
        let usable = self.first_usable_lba..=self.last_usable_lba;
        if start > last || !usable.contains(&start) || !usable.contains(&last) {
            return Err(PartitionTableError::GptOutsideUsable {
                number: entry.number,
                first: start,
                last,
                first_usable: self.first_usable_lba,
                last_usable: self.last_usable_lba,
            });
        }
        check_extent(&self.entries, entry, (start, last), size)?;
        Ok(HardDrive {
            partition_number: entry.number,
            start,
            size,
            signature: PartitionSignature::Gpt(entry.unique_partition),
        })
    }
}

/// The fields of a GPT header (UEFI 2.11 Table 5.5) that it is checked by, that locate its
/// entry array and that bound the partitions.
struct GptHeader {
    signature: u64,
    revision: u32,
    header_size: u32,
    header_crc32: u32,
    my_lba: u64,
    first_usable_lba: u64,
    last_usable_lba: u64,
    partition_entry_lba: u64,
    number_of_partition_entries: u32,
    size_of_partition_entry: u32,
    partition_entry_array_crc32: u32,
}

impl GptHeader {
    /// The fields at their byte offsets in `block`, None if it is shorter than 92 bytes.
    fn read(block: &[u8]) -> Option<Self> {
        let u32_at = |offset| bytes_at(block, offset).map(u32::from_le_bytes);
        let u64_at = |offset| bytes_at(block, offset).map(u64::from_le_bytes);
        Some(Self {
            signature: u64_at(0)?,
            revision: u32_at(8)?,
            header_size: u32_at(12)?,
            header_crc32: u32_at(GPT_HEADER_CRC32)?,
            my_lba: u64_at(24)?,
            first_usable_lba: u64_at(40)?,
            last_usable_lba: u64_at(48)?,
            partition_entry_lba: u64_at(72)?,
            number_of_partition_entries: u32_at(80)?,
            size_of_partition_entry: u32_at(84)?,
            partition_entry_array_crc32: u32_at(88)?,
        })
    }

    /// Refuses the header in `block` unless it is a revision 1.0 header that covers its fields
    /// and fits the block, and passes the header tests of UEFI 2.11 §5.3.2: its Signature,
    /// HeaderCRC32 and MyLBA. SizeOfPartitionEntry must be 128 × 2^n.
    fn check(&self, block: &[u8]) -> Result<(), PartitionTableError> {
        if self.signature != GPT_SIGNATURE {
            return Err(PartitionTableError::GptSignature(self.signature));
        }
        if self.revision != GPT_REVISION {
            return Err(PartitionTableError::GptRevision(self.revision));
        }
        let header = usize::try_from(self.header_size)
            .ok()
            .filter(|size| *size >= GPT_HEADER_SIZE)
            .and_then(|size| block.get(..size))
            .ok_or(PartitionTableError::GptHeaderSize {
                size: self.header_size,
                block_size: block.len(),
            })?;

        let mut zeroed = header.to_vec();
        zeroed
            .iter_mut()
            .skip(GPT_HEADER_CRC32)
            .take(size_of::<u32>())
            .for_each(|byte| *byte = 0);
        let computed = crc32fast::hash(&zeroed);
        if computed != self.header_crc32 {
            return Err(PartitionTableError::GptHeaderCrc {
                stored: self.header_crc32,
                computed,
            });
        }

        if self.my_lba != PRIMARY_GPT_HEADER {
            return Err(PartitionTableError::GptMyLba(self.my_lba));
        }
        if self.size_of_partition_entry < GPT_ENTRY_SIZE
            || !self.size_of_partition_entry.is_power_of_two()
        {
            return Err(PartitionTableError::GptEntrySize(
                self.size_of_partition_entry,
            ));
        }
        Ok(())
    }

    /// The entries of the entry array, refused unless the array's CRC32 is
    /// PartitionEntryArrayCRC32 (UEFI 2.11 §5.3.2).
    fn read_entries(
        &self,
        disk: &impl BlockDevice,
        block_len: usize,
    ) -> Result<Vec<GptEntry>, PartitionTableError> {
        let entry_size = usize::try_from(self.size_of_partition_entry)
            .map_err(|_| self.entry_array_too_large())?;
        let array_len = usize::try_from(self.number_of_partition_entries)
            .ok()
            .and_then(|entries| entries.checked_mul(entry_size))
            .filter(|len| *len <= MAX_ENTRY_ARRAY)
            .ok_or_else(|| self.entry_array_too_large())?;
        let blocks_len = array_len
            .div_ceil(block_len)
            .checked_mul(block_len)
            .ok_or_else(|| self.entry_array_too_large())?;

        let mut array = read_blocks(disk, self.partition_entry_lba, blocks_len)?;
        array.truncate(array_len);
        let computed = crc32fast::hash(&array);
        if computed != self.partition_entry_array_crc32 {
            return Err(PartitionTableError::GptEntryArrayCrc {
                stored: self.partition_entry_array_crc32,
                computed,
            });
        }

        array
            .chunks_exact(entry_size)
            .zip(1..)
            .map(|(entry, number)| {
                GptEntry::read(entry, number).ok_or(PartitionTableError::GptEntrySize(
                    self.size_of_partition_entry,
                ))
            })
            .collect()
    }

    /// The refusal of an entry array larger than uefisettings reads.
    fn entry_array_too_large(&self) -> PartitionTableError {
        PartitionTableError::GptEntryArrayTooLarge {
            entries: self.number_of_partition_entries,
            entry_size: self.size_of_partition_entry,
        }
    }
}

/// A GPT entry (UEFI 2.11 Table 5.6) and its Partition Number, its index in the array plus 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GptEntry {
    number: u32,
    partition_type: Guid,
    unique_partition: Guid,
    starting_lba: u64,
    ending_lba: u64,
    attributes: u64,
}

impl GptEntry {
    /// The entry whose fields start `bytes`, None if it is shorter than the 56 bytes before
    /// PartitionName.
    fn read(bytes: &[u8], number: u32) -> Option<Self> {
        let u64_at = |offset| bytes_at(bytes, offset).map(u64::from_le_bytes);
        Some(Self {
            number,
            partition_type: bytes_at(bytes, 0).map(Guid::from)?,
            unique_partition: bytes_at(bytes, 16).map(Guid::from)?,
            starting_lba: u64_at(32)?,
            ending_lba: u64_at(40)?,
            attributes: u64_at(48)?,
        })
    }
}

impl TableEntry for GptEntry {
    fn number(&self) -> u32 {
        self.number
    }

    /// An entry whose PartitionTypeGUID is zero is not in use (UEFI 2.11 Table 5.6).
    fn lbas(&self) -> Option<(u64, u64)> {
        (self.partition_type != UNUSED_ENTRY).then_some((self.starting_lba, self.ending_lba))
    }
}

/// Why a disk's partition table cannot be read, or names no ESP at a volume's extent.
#[derive(Debug, Error)]
pub(crate) enum PartitionTableError {
    #[error("a logical block of {0} bytes is shorter than the 512 bytes of an MBR")]
    BlockSize(u32),
    #[error("cannot read {len} bytes of the disk from LBA {lba}: {error}")]
    Read {
        lba: u64,
        len: usize,
        error: io::Error,
    },
    #[error("LBA 0 holds no MBR: its Signature is {0:#06X}, not 0xAA55")]
    MbrSignature(u16),
    #[error("the primary GPT header's Signature is {0:#018X}, not \"EFI PART\"")]
    GptSignature(u64),
    #[error("the primary GPT header's Revision is {0:#010X}, not 1.0 (0x00010000)")]
    GptRevision(u32),
    #[error(
        "the primary GPT header's HeaderSize {size} is outside 92 to the {block_size} bytes of a \
         logical block"
    )]
    GptHeaderSize { size: u32, block_size: usize },
    #[error(
        "the primary GPT header's HeaderCRC32 is {stored:#010X}, but the header's CRC32 is \
         {computed:#010X}"
    )]
    GptHeaderCrc { stored: u32, computed: u32 },
    #[error("the primary GPT header's MyLBA is {0}, not 1")]
    GptMyLba(u64),
    #[error("the primary GPT header's SizeOfPartitionEntry {0} is not 128 × 2^n")]
    GptEntrySize(u32),
    #[error(
        "the GPT entry array of {entries} entries of {entry_size} bytes exceeds the {limit} \
         bytes that uefisettings reads",
        limit = MAX_ENTRY_ARRAY
    )]
    GptEntryArrayTooLarge { entries: u32, entry_size: u32 },
    #[error(
        "the primary GPT header's PartitionEntryArrayCRC32 is {stored:#010X}, but the entry \
         array's CRC32 is {computed:#010X}"
    )]
    GptEntryArrayCrc { stored: u32, computed: u32 },
    #[error(
        "the partition at byte {offset} of its disk, {length} bytes long, is no whole number of \
         the disk's {block_size}-byte logical blocks"
    )]
    NotInBlocks {
        offset: u64,
        length: u64,
        block_size: u64,
    },
    #[error("no partition table entry in use starts at LBA {0}")]
    NoPartitionAt(u64),
    #[error("partition table entries {numbers:?} all start at LBA {lba}")]
    SeveralPartitionsAt { lba: u64, numbers: Vec<u32> },
    #[error(
        "GPT entry {number} has PartitionTypeGUID {partition_type}, not the EFI System \
         Partition's {ESP_TYPE}"
    )]
    GptNotEsp { number: u32, partition_type: Guid },
    #[error(
        "MBR partition record {slot} has OSType {os_type:#04X}, not 0xEF (UEFI system partition)"
    )]
    MbrNotEsp { slot: u32, os_type: u8 },
    #[error(
        "GPT entry {0} has Attributes bit 1 (No Block IO Protocol) set, so firmware makes no \
         EFI_BLOCK_IO_PROTOCOL for its partition"
    )]
    GptNoBlockIo(u32),
    #[error(
        "GPT entry {number} spans LBA {first} to {last}, which is no range inside the usable \
         LBAs {first_usable} to {last_usable}"
    )]
    GptOutsideUsable {
        number: u32,
        first: u64,
        last: u64,
        first_usable: u64,
        last_usable: u64,
    },
    #[error("partition table entry {number} overlaps entries {overlapping:?}")]
    Overlap { number: u32, overlapping: Vec<u32> },
    #[error(
        "partition table entry {number} spans LBA {first} to {last}, but the volume spans \
         {volume_blocks} logical blocks from LBA {first}"
    )]
    SizeMismatch {
        number: u32,
        first: u64,
        last: u64,
        volume_blocks: u64,
    },
}

#[cfg(test)]
mod tests {
    use super::sfdisk_images::SfdiskImage;
    use super::sfdisk_images::GPT_4096;
    use super::sfdisk_images::GPT_512;
    use super::sfdisk_images::MBR_512;
    use super::*;

    const LINUX_TYPE: &str = "0FC63DAF-8483-4772-8E79-3D69D8477DE4";
    const ESP_UNIQUE: &str = "8C78A505-BAA0-4C4A-869F-000000001A0D";
    const OTHER_UNIQUE: &str = "8C78A505-BAA0-4C4A-869F-000000001A07";
    /// The LastUsableLBA of gpt_disk's header
    const LAST_USABLE: u64 = 999_998;

    /// An ESP's Hard Drive node, or why there is none
    type EspLookup = Result<HardDrive, String>;
    /// The OSType, StartingLBA and SizeInLBA of each partition record of an MBR
    type MbrRecords = [(u8, u32, u32); 4];

    /// A disk image in memory.
    struct DiskImage {
        block_size: u32,
        bytes: Vec<u8>,
    }

    impl BlockDevice for DiskImage {
        fn block_size(&self) -> u32 {
            self.block_size
        }

        fn read_blocks(&self, lba: u64, blocks: &mut [u8]) -> io::Result<()> {
            let len = blocks.len();
            let bytes = usize::try_from(lba)
                .ok()
                .and_then(|lba| lba.checked_mul(usize::try_from(self.block_size).ok()?))
                .and_then(|start| self.bytes.get(start..start.checked_add(len)?))
                .ok_or(io::ErrorKind::UnexpectedEof)?;
            blocks.copy_from_slice(bytes);
            Ok(())
        }
    }

    impl From<&SfdiskImage> for DiskImage {
        fn from(image: &SfdiskImage) -> Self {
            let mut bytes = vec![0; image.length];
            for (offset, run) in image.runs {
                bytes[*offset..offset + run.len()].copy_from_slice(run);
            }
            Self {
                block_size: image.block_size,
                bytes,
            }
        }
    }

    /// A GPT entry that gpt_disk writes at its index in the array.
    struct Entry {
        index: usize,
        partition_type: &'static str,
        unique: &'static str,
        first: u64,
        last: u64,
        attributes: u64,
    }

    fn esp_entry(index: usize, first: u64, last: u64) -> Entry {
        Entry {
            index,
            partition_type: "C12A7328-F81F-11D2-BA4B-00A0C93EC93B",
            unique: ESP_UNIQUE,
            first,
            last,
            attributes: 0,
        }
    }

    fn linux_entry(index: usize, first: u64, last: u64) -> Entry {
        Entry {
            index,
            partition_type: LINUX_TYPE,
            unique: OTHER_UNIQUE,
            first,
            last,
            attributes: 0,
        }
    }

    fn guid(text: &str) -> Guid {
        text.parse().expect("a GUID in registry format")
    }

    /// A disk of `block_size`-byte blocks: a protective MBR, the primary GPT header in LBA 1
    /// and from LBA 2 on an array of `count` entries of `entry_size` bytes that holds
    /// `entries`, with both CRC32s computed.
    fn gpt_disk(
        block_size: usize,
        entry_size: usize,
        count: usize,
        entries: &[Entry],
    ) -> DiskImage {
        let array_len = count * entry_size;
        let array_blocks = array_len.div_ceil(block_size);
        let mut bytes = vec![0; (2 + array_blocks) * block_size];

        // the GPT Protective record, from LBA 1 over the whole disk, and the Signature 0xAA55
        bytes[450] = 0xEE;
        bytes[454..458].copy_from_slice(&1u32.to_le_bytes());
        bytes[458..462].copy_from_slice(&u32::MAX.to_le_bytes());
        bytes[510..512].copy_from_slice(&[0x55, 0xAA]);

        let mut array = vec![0; array_len];
        for entry in entries {
            let fields = [
                &<[u8; 16]>::from(guid(entry.partition_type))[..],
                &<[u8; 16]>::from(guid(entry.unique)),
                &entry.first.to_le_bytes(),
                &entry.last.to_le_bytes(),
                &entry.attributes.to_le_bytes(),
            ]
            .concat();
            let at = entry.index * entry_size;
            array[at..at + fields.len()].copy_from_slice(&fields);
        }
        bytes[2 * block_size..2 * block_size + array_len].copy_from_slice(&array);

        let first_usable = u64::try_from(2 + array_blocks).expect("the first usable LBA");
        let header = [
            &b"EFI PART"[..],
            &0x0001_0000u32.to_le_bytes(),
            &92u32.to_le_bytes(),
            &[0; 8],
            &1u64.to_le_bytes(),
            &(LAST_USABLE + 1).to_le_bytes(),
            &first_usable.to_le_bytes(),
            &LAST_USABLE.to_le_bytes(),
            &<[u8; 16]>::from(guid("8C78A505-BAA0-4C4A-869F-000000001A00")),
            &2u64.to_le_bytes(),
            &u32::try_from(count).expect("the entry count").to_le_bytes(),
            &u32::try_from(entry_size)
                .expect("the entry size")
                .to_le_bytes(),
            &crc32fast::hash(&array).to_le_bytes(),
        ]
        .concat();
        bytes[block_size..block_size + header.len()].copy_from_slice(&header);
        set_header_crc32(&mut bytes[block_size..2 * block_size]);
        DiskImage {
            block_size: u32::try_from(block_size).expect("the block size"),
            bytes,
        }
    }

    /// An MBR disk whose four partition records are these OSTypes, StartingLBAs and SizeInLBAs.
    fn mbr_disk(records: MbrRecords) -> DiskImage {
        let mut bytes = vec![0; 512];
        bytes[440..444].copy_from_slice(&0x1234_5678u32.to_le_bytes());
        for (record, (os_type, starting_lba, size_in_lba)) in
            bytes[446..510].chunks_exact_mut(16).zip(records)
        {
            record[4] = os_type;
            record[8..12].copy_from_slice(&starting_lba.to_le_bytes());
            record[12..16].copy_from_slice(&size_in_lba.to_le_bytes());
        }
        bytes[510..512].copy_from_slice(&[0x55, 0xAA]);
        DiskImage {
            block_size: 512,
            bytes,
        }
    }

    /// Sets the HeaderCRC32 of the GPT header that starts `block` to the CRC32 of its HeaderSize
    /// bytes with HeaderCRC32 zero, if they fit the block.
    fn set_header_crc32(block: &mut [u8]) {
        let size = u32::from_le_bytes(block[12..16].try_into().expect("HeaderSize's 4 bytes"));
        let Some(header) = block.get(..usize::try_from(size).expect("HeaderSize")) else {
            return;
        };
        let mut zeroed = header.to_vec();
        zeroed[16..20].fill(0);
        let crc32 = crc32fast::hash(&zeroed);
        block[16..20].copy_from_slice(&crc32.to_le_bytes());
    }

    /// GPT_512 with `edit` applied to its primary GPT header block, LBA 1, whose HeaderCRC32 is
    /// then computed again.
    fn gpt_512_with_header(edit: impl FnOnce(&mut [u8])) -> DiskImage {
        let mut disk = DiskImage::from(&GPT_512);
        let block = &mut disk.bytes[512..1024];
        edit(block);
        set_header_crc32(block);
        disk
    }

    /// The `size` blocks of `block_size` bytes from LBA `start` on, in bytes.
    fn extent(block_size: u64, start: u64, size: u64) -> PartitionExtent {
        PartitionExtent {
            offset: start * block_size,
            length: size * block_size,
        }
    }

    /// The Hard Drive node of the ESP of `disk` at `extent`, or why there is none.
    fn esp_of(disk: &DiskImage, extent: PartitionExtent) -> EspLookup {
        let table = PartitionTable::read(disk).map_err(|err| err.to_string())?;
        table.esp_hard_drive(extent).map_err(|err| err.to_string())
    }

    /// The Hard Drive node of a GPT disk's ESP, with ESP_UNIQUE.
    fn gpt_esp(partition_number: u32, start: u64, size: u64) -> EspLookup {
        Ok(HardDrive {
            partition_number,
            start,
            size,
            signature: PartitionSignature::Gpt(guid(ESP_UNIQUE)),
        })
    }

    #[test]
    fn the_esp_type_guid_is_what_sfdisk_writes_as_an_esp_entry_s_type() {
        let type_bytes = |offset: usize| -> [u8; 16] {
            let (_, run) = GPT_512
                .runs
                .iter()
                .find(|(at, _)| *at == offset)
                .expect("the entry's run");
            run[..16].try_into().expect("PartitionTypeGUID's 16 bytes")
        };
        // GPT_512's entry 3, at byte 0x500, is the ESP; entry 1, at byte 0x400, is not
        let esp = type_bytes(0x500);
        let linux = type_bytes(0x400);

        assert_eq!(Guid::from(esp), ESP_TYPE, "entry 3's PartitionTypeGUID");
        assert_eq!(<[u8; 16]>::from(ESP_TYPE), esp, "ESP_TYPE's bytes");
        assert_eq!(
            ESP_TYPE.to_string(),
            "C12A7328-F81F-11D2-BA4B-00A0C93EC93B",
            "ESP_TYPE in registry format"
        );
        assert_eq!(
            Guid::from(linux),
            guid(LINUX_TYPE),
            "entry 1's PartitionTypeGUID"
        );
        assert_ne!(Guid::from(linux), ESP_TYPE, "entry 1 is no ESP");
    }

    #[test]
    fn sfdisk_gpt_disks_name_their_esp_by_its_entry_s_index() {
        let disk = DiskImage::from(&GPT_512);
        // entry 3, after the unused entry 2, is the first partition by offset
        assert_eq!(
            esp_of(&disk, extent(512, 2048, 2048)),
            Ok(HardDrive {
                partition_number: 3,
                start: 2048,
                size: 2048,
                signature: PartitionSignature::Gpt(guid("8C78A505-BAA0-4C4A-869F-000000001A0E")),
            }),
            "GPT_512's ESP"
        );
        assert_eq!(
            esp_of(&disk, extent(512, 4096, 2048)),
            Err(format!(
                "GPT entry 1 has PartitionTypeGUID {LINUX_TYPE}, not the EFI System Partition's \
                 C12A7328-F81F-11D2-BA4B-00A0C93EC93B"
            )),
            "GPT_512's Linux partition"
        );

        let disk = DiskImage::from(&GPT_4096);
        assert_eq!(
            esp_of(&disk, extent(4096, 512, 256)),
            Ok(HardDrive {
                partition_number: 1,
                start: 512,
                size: 256,
                signature: PartitionSignature::Gpt(guid("8C78A505-BAA0-4C4A-869F-000000001A0A")),
            }),
            "GPT_4096's ESP"
        );
    }

    #[test]
    fn an_sfdisk_mbr_disk_names_its_esp_by_its_record_s_slot() {
        let disk = DiskImage::from(&MBR_512);

        assert_eq!(
            esp_of(&disk, extent(512, 4096, 2048)),
            Ok(HardDrive {
                partition_number: 2,
                start: 4096,
                size: 2048,
                signature: PartitionSignature::Mbr(0x5EC7_A1B2),
            }),
            "MBR_512's ESP"
        );
        assert_eq!(
            esp_of(&disk, extent(512, 2048, 2048)),
            Err("MBR partition record 1 has OSType 0x83, not 0xEF (UEFI system partition)".into()),
            "MBR_512's Linux partition"
        );
    }

    #[test]
    fn a_gpt_header_that_fails_a_test_refuses_the_disk() {
        type Edit = fn(&mut [u8]);
        let cases: [(&str, Edit, &str); 9] = [
            (
                "Signature",
                |block| block[0] = b'F',
                "the primary GPT header's Signature is 0x5452415020494646, not \"EFI PART\"",
            ),
            (
                "Revision",
                |block| block[8] = 0x01,
                "the primary GPT header's Revision is 0x00010001, not 1.0 (0x00010000)",
            ),
            (
                "HeaderSize below 92",
                |block| block[12] = 91,
                "the primary GPT header's HeaderSize 91 is outside 92 to the 512 bytes of a \
                 logical block",
            ),
            (
                "HeaderSize past the block",
                |block| block[12..14].copy_from_slice(&513u16.to_le_bytes()),
                "the primary GPT header's HeaderSize 513 is outside 92 to the 512 bytes of a \
                 logical block",
            ),
            (
                "MyLBA",
                |block| block[24] = 2,
                "the primary GPT header's MyLBA is 2, not 1",
            ),
            (
                "SizeOfPartitionEntry a multiple of 8",
                |block| block[84] = 136,
                "the primary GPT header's SizeOfPartitionEntry 136 is not 128 × 2^n",
            ),
            (
                "SizeOfPartitionEntry below 128",
                |block| block[84] = 64,
                "the primary GPT header's SizeOfPartitionEntry 64 is not 128 × 2^n",
            ),
            (
                "NumberOfPartitionEntries past the limit",
                |block| block[80..84].copy_from_slice(&8193u32.to_le_bytes()),
                "the GPT entry array of 8193 entries of 128 bytes exceeds the 1048576 bytes \
                 that uefisettings reads",
            ),
            (
                "NumberOfPartitionEntries at the limit, past the disk",
                |block| block[80..84].copy_from_slice(&8192u32.to_le_bytes()),
                "cannot read 1048576 bytes of the disk from LBA 2: unexpected end of file",
            ),
        ];
        for (field, edit, want) in cases {
            let disk = gpt_512_with_header(edit);

            let got = PartitionTable::read(&disk).map(|_| ());

            assert_eq!(
                got.map_err(|err| err.to_string()),
                Err(want.into()),
                "{field}"
            );
        }

        // HeaderSize may be the whole block
        let disk =
            gpt_512_with_header(|block| block[12..14].copy_from_slice(&512u16.to_le_bytes()));
        assert!(
            matches!(
                esp_of(&disk, extent(512, 2048, 2048)),
                Ok(HardDrive {
                    partition_number: 3,
                    ..
                })
            ),
            "HeaderSize 512"
        );
    }

    #[test]
    fn a_gpt_whose_stored_crc32s_differ_from_its_bytes_is_refused() {
        // GPT_512's HeaderCRC32 and PartitionEntryArrayCRC32, as sfdisk computed them
        const HEADER_CRC32: u32 = 0x9757_2999;
        const ENTRY_ARRAY_CRC32: u32 = 0xEE74_E86A;
        let crc32_at = |disk: &DiskImage, offset: usize| {
            u32::from_le_bytes(disk.bytes[offset..offset + 4].try_into().expect("4 bytes"))
        };
        let sfdisk = DiskImage::from(&GPT_512);
        assert_eq!(
            crc32_at(&sfdisk, 512 + 16),
            HEADER_CRC32,
            "GPT_512's HeaderCRC32"
        );
        assert_eq!(
            crc32_at(&sfdisk, 512 + 88),
            ENTRY_ARRAY_CRC32,
            "GPT_512's array CRC32"
        );

        // a DiskGUID byte, inside HeaderSize
        let mut disk = DiskImage::from(&GPT_512);
        disk.bytes[512 + 56] ^= 1;
        let got = PartitionTable::read(&disk);
        assert!(
            matches!(
                got,
                Err(PartitionTableError::GptHeaderCrc { stored: HEADER_CRC32, computed })
                    if computed != HEADER_CRC32
            ),
            "a changed DiskGUID: {got:?}"
        );

        // a reserved byte past HeaderSize is outside the header's CRC32
        let mut disk = DiskImage::from(&GPT_512);
        disk.bytes[512 + 100] = 1;
        assert!(
            matches!(
                esp_of(&disk, extent(512, 2048, 2048)),
                Ok(HardDrive {
                    partition_number: 3,
                    ..
                })
            ),
            "a changed byte past HeaderSize"
        );

        // the unused entry 2's PartitionName
        let mut disk = DiskImage::from(&GPT_512);
        disk.bytes[1024 + 128 + 56] = b'x';
        let got = PartitionTable::read(&disk);
        assert!(
            matches!(
                got,
                Err(PartitionTableError::GptEntryArrayCrc { stored: ENTRY_ARRAY_CRC32, computed })
                    if computed != ENTRY_ARRAY_CRC32
            ),
            "a changed unused entry: {got:?}"
        );
    }

    #[test]
    fn entries_of_256_bytes_are_read_and_the_rest_of_the_array_s_last_block_is_not() {
        // 5 entries of 256 bytes end 256 bytes into the array's third block
        let mut disk = gpt_disk(
            512,
            256,
            5,
            &[linux_entry(0, 10, 99), esp_entry(4, 100, 199)],
        );
        disk.bytes[2 * 512 + 5 * 256..5 * 512].fill(0xA5);

        assert_eq!(
            esp_of(&disk, extent(512, 100, 100)),
            gpt_esp(5, 100, 100),
            "entry 5"
        );
    }

    #[test]
    fn a_gpt_esp_must_be_a_partition_that_firmware_makes() {
        let esp_with = |attributes| Entry {
            attributes,
            ..esp_entry(0, 100, 199)
        };
        let unused = Entry {
            partition_type: "00000000-0000-0000-0000-000000000000",
            ..linux_entry(2, 150, 160)
        };
        let cases: [(&str, Vec<Entry>, PartitionExtent, EspLookup); 13] = [
            (
                "Required Partition, Legacy BIOS Bootable and a type-specific bit",
                vec![esp_with(1 | (1 << 2) | (1 << 60))],
                extent(512, 100, 100),
                gpt_esp(1, 100, 100),
            ),
            (
                "No Block IO Protocol",
                vec![esp_with(1 << 1)],
                extent(512, 100, 100),
                Err(
                    "GPT entry 1 has Attributes bit 1 (No Block IO Protocol) set, so firmware \
                     makes no EFI_BLOCK_IO_PROTOCOL for its partition"
                        .into(),
                ),
            ),
            (
                "below FirstUsableLBA",
                vec![esp_entry(0, 5, 99)],
                extent(512, 5, 95),
                Err(
                    "GPT entry 1 spans LBA 5 to 99, which is no range inside the usable LBAs 6 \
                     to 999998"
                        .into(),
                ),
            ),
            (
                "past LastUsableLBA",
                vec![esp_entry(0, 999_990, 999_999)],
                extent(512, 999_990, 10),
                Err(
                    "GPT entry 1 spans LBA 999990 to 999999, which is no range inside the \
                     usable LBAs 6 to 999998"
                        .into(),
                ),
            ),
            (
                "EndingLBA before StartingLBA",
                vec![esp_entry(0, 100, 99)],
                extent(512, 100, 1),
                Err(
                    "GPT entry 1 spans LBA 100 to 99, which is no range inside the usable LBAs \
                     6 to 999998"
                        .into(),
                ),
            ),
            (
                "overlapping a later partition",
                vec![esp_entry(0, 100, 199), linux_entry(1, 199, 299)],
                extent(512, 100, 100),
                Err("partition table entry 1 overlaps entries [2]".into()),
            ),
            (
                "overlapping an earlier partition",
                vec![linux_entry(0, 10, 100), esp_entry(1, 100, 199)],
                extent(512, 100, 100),
                Err("partition table entry 2 overlaps entries [1]".into()),
            ),
            (
                "between adjacent partitions and over an unused entry's LBAs",
                vec![
                    linux_entry(0, 10, 99),
                    esp_entry(1, 100, 199),
                    unused,
                    linux_entry(3, 200, 299),
                ],
                extent(512, 100, 100),
                gpt_esp(2, 100, 100),
            ),
            (
                "starting where another partition starts",
                vec![esp_entry(0, 100, 199), esp_entry(3, 100, 149)],
                extent(512, 100, 100),
                Err("partition table entries [1, 4] all start at LBA 100".into()),
            ),
            (
                "where only an unused entry starts",
                vec![esp_entry(0, 100, 199), unused_at(150)],
                extent(512, 150, 11),
                Err("no partition table entry in use starts at LBA 150".into()),
            ),
            (
                "smaller than the volume",
                vec![esp_entry(0, 100, 199)],
                extent(512, 100, 101),
                Err(
                    "partition table entry 1 spans LBA 100 to 199, but the volume spans 101 \
                     logical blocks from LBA 100"
                        .into(),
                ),
            ),
            (
                "a volume offset in no whole block",
                vec![esp_entry(0, 100, 199)],
                PartitionExtent {
                    offset: 100 * 512 + 1,
                    length: 100 * 512,
                },
                Err(
                    "the partition at byte 51201 of its disk, 51200 bytes long, is no whole \
                     number of the disk's 512-byte logical blocks"
                        .into(),
                ),
            ),
            (
                "a volume length in no whole block",
                vec![esp_entry(0, 100, 199)],
                PartitionExtent {
                    offset: 100 * 512,
                    length: 100 * 512 - 256,
                },
                Err(
                    "the partition at byte 51200 of its disk, 50944 bytes long, is no whole \
                     number of the disk's 512-byte logical blocks"
                        .into(),
                ),
            ),
        ];
        for (case, entries, extent, want) in cases {
            let disk = gpt_disk(512, 128, 16, &entries);

            assert_eq!(esp_of(&disk, extent), want, "{case}");
        }
    }

    /// An unused entry, PartitionTypeGUID zero, whose other fields name a partition from LBA
    /// `first` on.
    fn unused_at(first: u64) -> Entry {
        Entry {
            partition_type: "00000000-0000-0000-0000-000000000000",
            ..linux_entry(2, first, first + 10)
        }
    }

    #[test]
    fn an_mbr_esp_must_be_a_record_in_use_alone_that_spans_the_volume() {
        let esp_at_100 = Ok(HardDrive {
            partition_number: 2,
            start: 100,
            size: 100,
            signature: PartitionSignature::Mbr(0x1234_5678),
        });
        let empty = (0, 0, 0);
        let cases: [(&str, MbrRecords, EspLookup); 7] = [
            (
                "beside others, after an empty slot",
                [empty, (0xEF, 100, 100), (0x83, 200, 50), (0x07, 1, 99)],
                esp_at_100.clone(),
            ),
            (
                "beside a GPT Protective record that does not start at LBA 1",
                [(0xEE, 2, 1000), (0xEF, 100, 100), empty, empty],
                esp_at_100.clone(),
            ),
            (
                "overlapping another partition",
                [empty, (0xEF, 100, 100), (0x83, 199, 50), empty],
                Err("partition table entry 2 overlaps entries [3]".into()),
            ),
            (
                "smaller than the volume",
                [empty, (0xEF, 100, 99), empty, empty],
                Err(
                    "partition table entry 2 spans LBA 100 to 198, but the volume spans 100 \
                     logical blocks from LBA 100"
                        .into(),
                ),
            ),
            (
                "of SizeInLBA 0",
                [empty, (0xEF, 100, 0), empty, empty],
                Err("no partition table entry in use starts at LBA 100".into()),
            ),
            (
                "of OSType 0",
                [empty, (0x00, 100, 100), empty, empty],
                Err("no partition table entry in use starts at LBA 100".into()),
            ),
            (
                "behind a GPT Protective record that starts at LBA 1",
                [(0xEE, 1, 1000), (0xEF, 100, 100), empty, empty],
                Err(
                    "the primary GPT header's Signature is 0x0000000000000000, not \"EFI PART\""
                        .into(),
                ),
            ),
        ];
        for (case, records, want) in cases {
            let mut disk = mbr_disk(records);
            // LBA 1, read as a GPT header behind a protective MBR
            disk.bytes.resize(1024, 0);

            assert_eq!(esp_of(&disk, extent(512, 100, 100)), want, "{case}");
        }
    }

    #[test]
    fn a_disk_whose_blocks_cannot_hold_its_table_or_be_read_is_refused() {
        for block_size in [0, 256, 511] {
            let disk = DiskImage {
                block_size,
                ..DiskImage::from(&GPT_512)
            };

            let got = PartitionTable::read(&disk).map(|_| ());

            assert_eq!(
                got.map_err(|err| err.to_string()),
                Err(format!(
                    "a logical block of {block_size} bytes is shorter than the 512 bytes of an MBR"
                )),
                "block size {block_size}"
            );
        }

        let mut disk = mbr_disk([
            (0x83, 1, 99),
            (0x07, 100, 100),
            (0x0C, 200, 100),
            (0xEF, 300, 100),
        ]);
        disk.bytes[510] = 0;
        assert_eq!(
            esp_of(&disk, extent(512, 300, 100)),
            Err("LBA 0 holds no MBR: its Signature is 0xAA00, not 0xAA55".into()),
            "LBA 0 without 0xAA55"
        );

        for (blocks, lba, len) in [(1, 1, 512), (2, 2, 16384)] {
            let mut disk = DiskImage::from(&GPT_512);
            disk.bytes.truncate(blocks * 512);

            let got = PartitionTable::read(&disk);

            assert!(
                matches!(
                    &got,
                    Err(PartitionTableError::Read { lba: got_lba, len: got_len, error })
                        if (*got_lba, *got_len) == (lba, len)
                            && error.kind() == io::ErrorKind::UnexpectedEof
                ),
                "a disk of {blocks} blocks: {got:?}"
            );
        }
    }
}
