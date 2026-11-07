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

//! The EFI system partition on Windows, which mounts it without a drive letter: the volume of
//! FindFirstVolumeW and FindNextVolumeW whose partition is an ESP in its disk's partition table,
//! the one that BootCurrent's Hard Drive node names. Its volume GUID path names its root
//! directory (Microsoft Learn, Naming a Volume). Opening volumes and disks needs Administrator.

use std::fmt;
use std::io;
use std::path::PathBuf;

use anyhow::anyhow;
use anyhow::Result;
use thiserror::Error;

use super::boot_current_hard_drive;
use super::described;
use super::is_wanted;
use super::wanted;
use super::BlockDevice;
use super::EspLocator;
use super::MountedEsp;
use super::PartitionExtent;
use super::PartitionTable;
use super::PartitionTableError;
use crate::efi_variables::load_option::HardDrive;
use crate::efi_variables::VariableData;
use crate::hii::win32::Win32Error;

/// A Win32 call that failed, and the code that it left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CallFailed {
    pub(crate) call: &'static str,
    pub(crate) code: Win32Error,
}

impl fmt::Display for CallFailed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} failed: {}", self.call, self.code)?;
        if self.code == Win32Error::ACCESS_DENIED {
            write!(
                f,
                " (ERROR_ACCESS_DENIED): uefisettings needs Administrator"
            )?;
        }
        Ok(())
    }
}

impl std::error::Error for CallFailed {}

/// A run of a volume on a disk, in bytes, as DISK_EXTENT holds it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct DiskExtent {
    pub(crate) disk_number: u32,
    pub(crate) starting_offset: i64,
    pub(crate) extent_length: i64,
}

impl fmt::Display for DiskExtent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} bytes at byte {} of disk {}",
            self.extent_length, self.starting_offset, self.disk_number
        )
    }
}

/// The Win32 calls that locate reads volumes and disks through, behind which tests fake them.
pub(crate) trait EspCalls {
    /// The volume search of FindFirstVolumeW, which FindVolumeClose ends
    type Search;
    /// An open \\.\PhysicalDriveN
    type Disk;

    /// FindFirstVolumeW: the search and the first volume GUID path, which ends in a backslash.
    fn find_first_volume(&self) -> Result<(Self::Search, String), CallFailed>;

    /// FindNextVolumeW: the next volume GUID path; ERROR_NO_MORE_FILES after the last.
    fn find_next_volume(&self, search: &mut Self::Search) -> Result<String, CallFailed>;

    /// The extents of the volume that `device`, a volume GUID path without its trailing
    /// backslash, opens: CreateFileW, then IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS.
    fn volume_disk_extents(&self, device: &str) -> Result<Vec<DiskExtent>, CallFailed>;

    /// Opens \\.\PhysicalDrive`number` to read: CreateFileW.
    fn open_disk(&self, number: u32) -> Result<Self::Disk, CallFailed>;

    /// The logical block size of `disk`: IOCTL_DISK_GET_DRIVE_GEOMETRY.
    fn disk_block_size(&self, disk: &Self::Disk) -> Result<u32, CallFailed>;

    /// Reads `buffer` from byte `offset` of `disk`: ReadFile. Returns the bytes read.
    fn read_disk(
        &self,
        disk: &Self::Disk,
        offset: u64,
        buffer: &mut [u8],
    ) -> Result<usize, CallFailed>;
}

impl<C: EspCalls> EspLocator for C {
    /// The ESP that staging writes to: the volume whose partition the Hard Drive node of
    /// BootCurrent's Boot#### names, else, if it names none, the only ESP; refused unless exactly
    /// one volume is that, and if Windows denies a volume or disk to this process. A GPT partition
    /// matches by its UniquePartitionGUID; an MBR one by its disk signature and partition number.
    fn locate(&self, variables: &impl VariableData) -> Result<MountedEsp> {
        let named = boot_current_hard_drive(variables)?;
        let volumes: Vec<(String, Result<HardDrive, VolumeError>)> = volume_paths(self)
            .map_err(|failed| anyhow!("cannot list the volumes: {failed}"))?
            .into_iter()
            .map(|path| {
                let hard_drive = volume_hard_drive(self, &path);
                (path, hard_drive)
            })
            .collect();
        if let Some((path, failed)) = volumes.iter().find_map(|(path, hard_drive)| {
            let failed = hard_drive.as_ref().err()?.denied()?;
            Some((path, failed))
        }) {
            return Err(anyhow!("cannot read volume {path}: {failed}"));
        }

        let matching: Vec<MountedEsp> = volumes
            .iter()
            .filter_map(|(path, hard_drive)| {
                let hard_drive = *hard_drive.as_ref().ok()?;
                is_wanted(named.as_ref(), &hard_drive).then(|| MountedEsp {
                    mount_point: PathBuf::from(path),
                    hard_drive,
                })
            })
            .collect();
        let wanted = wanted(named.as_ref());
        match matching.as_slice() {
            [esp] => Ok(esp.clone()),
            [] => Err(anyhow!(
                "no volume is {wanted}. Volumes: {}",
                listed(&volumes)
            )),
            several => Err(anyhow!(
                "several volumes are {wanted}: {}",
                several
                    .iter()
                    .map(|esp| esp.mount_point.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        }
    }
}

/// The volume GUID paths that FindFirstVolumeW and FindNextVolumeW list. Only
/// ERROR_NO_MORE_FILES ends the list; any other failure refuses it.
fn volume_paths(calls: &impl EspCalls) -> Result<Vec<String>, CallFailed> {
    let (mut search, first) = match calls.find_first_volume() {
        Ok(found) => found,
        Err(failed) if failed.code == Win32Error::NO_MORE_FILES => return Ok(Vec::new()),
        Err(failed) => return Err(failed),
    };
    let mut paths = vec![first];
    loop {
        match calls.find_next_volume(&mut search) {
            Ok(path) => paths.push(path),
            Err(failed) if failed.code == Win32Error::NO_MORE_FILES => return Ok(paths),
            Err(failed) => return Err(failed),
        }
    }
}

/// Why a volume is no ESP that staging can write to.
#[derive(Debug, Error)]
enum VolumeError {
    #[error(transparent)]
    Call(#[from] CallFailed),
    #[error("its volume GUID path ends in no backslash")]
    NoRootBackslash,
    #[error("it spans no disk extent")]
    NoExtent,
    #[error("it spans {} disk extents, not one: {}", .0.len(), extents(.0))]
    Extents(Vec<DiskExtent>),
    #[error("its disk extent, {0}, has a negative offset or length")]
    NegativeExtent(DiskExtent),
    #[error(transparent)]
    Table(#[from] PartitionTableError),
}

impl VolumeError {
    /// The call that Windows denied to this process, if that is why.
    fn denied(&self) -> Option<&CallFailed> {
        match self {
            Self::Call(failed) => (failed.code == Win32Error::ACCESS_DENIED).then_some(failed),
            Self::NoRootBackslash
            | Self::NoExtent
            | Self::Extents(_)
            | Self::NegativeExtent(_)
            | Self::Table(_) => None,
        }
    }
}

/// `extents`, in words.
fn extents(extents: &[DiskExtent]) -> String {
    extents
        .iter()
        .map(DiskExtent::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// The Hard Drive node of the ESP that the volume GUID path `path` names: its one disk extent must
/// be an ESP of its disk's partition table, as PartitionTable::esp_hard_drive checks it.
fn volume_hard_drive(calls: &impl EspCalls, path: &str) -> Result<HardDrive, VolumeError> {
    let device = path
        .strip_suffix('\\')
        .ok_or(VolumeError::NoRootBackslash)?;
    let disk_extents = calls.volume_disk_extents(device)?;
    let extent = match disk_extents.as_slice() {
        [extent] => extent,
        [] => return Err(VolumeError::NoExtent),
        [_, _, ..] => return Err(VolumeError::Extents(disk_extents)),
    };
    let (Ok(offset), Ok(length)) = (
        u64::try_from(extent.starting_offset),
        u64::try_from(extent.extent_length),
    ) else {
        return Err(VolumeError::NegativeExtent(*extent));
    };
    let disk = calls.open_disk(extent.disk_number)?;
    let block_size = calls.disk_block_size(&disk)?;
    let table = PartitionTable::read(&PhysicalDisk {
        calls,
        disk: &disk,
        block_size,
    })?;
    Ok(table.esp_hard_drive(PartitionExtent { offset, length })?)
}

/// A disk that `calls` opened, read in logical blocks.
struct PhysicalDisk<'a, C: EspCalls> {
    calls: &'a C,
    disk: &'a C::Disk,
    block_size: u32,
}

impl<C: EspCalls> BlockDevice for PhysicalDisk<'_, C> {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn read_blocks(&self, lba: u64, blocks: &mut [u8]) -> io::Result<()> {
        let offset = lba
            .checked_mul(u64::from(self.block_size))
            .ok_or_else(|| io::Error::other(format!("LBA {lba} lies past 2^64 bytes")))?;
        let read = self
            .calls
            .read_disk(self.disk, offset, blocks)
            .map_err(io::Error::other)?;
        match read == blocks.len() {
            true => Ok(()),
            false => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "ReadFile read {read} of {} bytes at byte {offset}",
                    blocks.len()
                ),
            )),
        }
    }
}

/// The volumes, each with its partition or why it is no ESP, in words.
fn listed(volumes: &[(String, Result<HardDrive, VolumeError>)]) -> String {
    match volumes {
        [] => "none".to_owned(),
        _ => volumes
            .iter()
            .map(|(path, hard_drive)| match hard_drive {
                Ok(hard_drive) => format!("{path} ({})", described(hard_drive)),
                Err(error) => format!("{path} ({error})"),
            })
            .collect::<Vec<_>>()
            .join("; "),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::collections::BTreeMap;

    use super::super::sfdisk_images::SfdiskImage;
    use super::super::sfdisk_images::GPT_4096;
    use super::super::sfdisk_images::GPT_512;
    use super::super::sfdisk_images::MBR_512;
    use super::super::sfdisk_images::QEMU_ESP_DISK;
    use super::super::tests::booted_from;
    use super::super::tests::gpt_512_esp;
    use super::*;
    use crate::efi_variables::globals::tests::HeldVariables;
    use crate::efi_variables::load_option::PartitionSignature;

    /// Volume GUID paths, of an ESP, of a partition that is none, and of another ESP
    const ESP: &str = r"\\?\Volume{8c78a505-baa0-4c4a-869f-000000001a03}\";
    const DATA: &str = r"\\?\Volume{8c78a505-baa0-4c4a-869f-000000001a02}\";
    const OTHER_ESP: &str = r"\\?\Volume{8c78a505-baa0-4c4a-869f-000000001a04}\";
    /// The disk numbers of the fixtures
    const GPT_512_DISK: u32 = 0;
    const QEMU_DISK: u32 = 2;
    /// A failure of a call that no other code names
    const DEVICE_FAILED: Win32Error = Win32Error::INVALID_FUNCTION;

    /// A disk: its logical block size, its bytes, and what reading it fails with, if it does.
    struct FakeDisk {
        block_size: u32,
        bytes: Vec<u8>,
        read_failure: Option<CallFailed>,
    }

    /// A Windows machine's volumes and disks, as the Win32 calls see them.
    #[derive(Default)]
    pub(crate) struct FakeWindows {
        /// Each volume GUID path with the extents of its volume, or how getting them fails
        volumes: Vec<(String, Result<Vec<DiskExtent>, CallFailed>)>,
        /// How FindFirstVolumeW fails, if it does
        first_failure: Option<CallFailed>,
        /// How FindNextVolumeW fails after the last volume, if not with ERROR_NO_MORE_FILES
        last_failure: Option<CallFailed>,
        /// The disks by number, or how opening one fails
        disks: BTreeMap<u32, Result<FakeDisk, CallFailed>>,
        /// How IOCTL_DISK_GET_DRIVE_GEOMETRY fails, if it does
        block_size_failure: Option<CallFailed>,
    }

    impl FakeWindows {
        /// Adds disk `number` holding `image`.
        fn disk(mut self, number: u32, image: &SfdiskImage) -> Self {
            let disk = FakeDisk {
                block_size: image.block_size,
                bytes: image.bytes(),
                read_failure: None,
            };
            self.disks.insert(number, Ok(disk));
            self
        }

        /// Adds the volume `path` of the partition of disk `disk` from LBA `start` on, `size`
        /// logical blocks long.
        fn volume(mut self, path: &str, disk: u32, (start, size): (u64, u64)) -> Self {
            let block_size = match self.disks.get(&disk) {
                Some(Ok(disk)) => u64::from(disk.block_size),
                Some(Err(_)) | None => 512,
            };
            let bytes = |blocks: u64| i64::try_from(blocks * block_size).expect("an offset");
            let extent = DiskExtent {
                disk_number: disk,
                starting_offset: bytes(start),
                extent_length: bytes(size),
            };
            self.volumes.push((path.to_owned(), Ok(vec![extent])));
            self
        }

        /// GPT_512 as disk 0, with volumes of its ESP and its Linux partition.
        pub(crate) fn with_esp() -> Self {
            Self::default()
                .disk(GPT_512_DISK, &GPT_512)
                .volume(ESP, GPT_512_DISK, (2048, 2048))
                .volume(DATA, GPT_512_DISK, (4096, 2048))
        }
    }

    impl EspCalls for FakeWindows {
        type Search = usize;
        type Disk = u32;

        fn find_first_volume(&self) -> Result<(usize, String), CallFailed> {
            if let Some(failed) = self.first_failure {
                return Err(failed);
            }
            match self.volumes.first() {
                Some((path, _)) => Ok((1, path.clone())),
                None => Err(CallFailed {
                    call: "FindFirstVolumeW",
                    code: Win32Error::NO_MORE_FILES,
                }),
            }
        }

        fn find_next_volume(&self, search: &mut usize) -> Result<String, CallFailed> {
            let Some((path, _)) = self.volumes.get(*search) else {
                return Err(self.last_failure.unwrap_or(CallFailed {
                    call: "FindNextVolumeW",
                    code: Win32Error::NO_MORE_FILES,
                }));
            };
            *search += 1;
            Ok(path.clone())
        }

        fn volume_disk_extents(&self, device: &str) -> Result<Vec<DiskExtent>, CallFailed> {
            let (_, extents) = self
                .volumes
                .iter()
                .find(|(path, _)| path.strip_suffix('\\') == Some(device))
                .unwrap_or_else(|| panic!("no volume {device}"));
            extents.clone()
        }

        fn open_disk(&self, number: u32) -> Result<u32, CallFailed> {
            match self.disks.get(&number) {
                Some(Ok(_)) => Ok(number),
                Some(Err(failed)) => Err(*failed),
                None => Err(CallFailed {
                    call: "CreateFileW",
                    code: Win32Error::FILE_NOT_FOUND,
                }),
            }
        }

        fn disk_block_size(&self, disk: &u32) -> Result<u32, CallFailed> {
            if let Some(failed) = self.block_size_failure {
                return Err(failed);
            }
            Ok(self.fake_disk(*disk).block_size)
        }

        fn read_disk(
            &self,
            disk: &u32,
            offset: u64,
            buffer: &mut [u8],
        ) -> Result<usize, CallFailed> {
            let disk = self.fake_disk(*disk);
            if let Some(failed) = disk.read_failure {
                return Err(failed);
            }
            let start = usize::try_from(offset).expect("an offset in memory");
            let available = disk.bytes.get(start..).unwrap_or_default();
            let read = available.len().min(buffer.len());
            buffer[..read].copy_from_slice(&available[..read]);
            Ok(read)
        }
    }

    impl FakeWindows {
        fn fake_disk(&self, number: u32) -> &FakeDisk {
            match self.disks.get(&number) {
                Some(Ok(disk)) => disk,
                Some(Err(_)) | None => panic!("disk {number} is not open"),
            }
        }
    }

    /// QEMU_ESP_DISK's ESP, entry 2, the first partition on its disk.
    fn qemu_esp() -> HardDrive {
        HardDrive {
            partition_number: 2,
            start: 2048,
            size: 81920,
            signature: PartitionSignature::Gpt(
                "8C78A505-BAA0-4C4A-869F-000000001A10"
                    .parse()
                    .expect("a GUID"),
            ),
        }
    }

    fn located(windows: &FakeWindows, variables: &HeldVariables) -> Result<MountedEsp, String> {
        windows.locate(variables).map_err(|err| format!("{err:#}"))
    }

    fn mounted(path: &str, hard_drive: HardDrive) -> Result<MountedEsp, String> {
        Ok(MountedEsp {
            mount_point: PathBuf::from(path),
            hard_drive,
        })
    }

    /// The reason why GPT_512's Linux partition, entry 1, is no ESP.
    const DATA_IS_NO_ESP: &str = "GPT entry 1 has PartitionTypeGUID \
         0FC63DAF-8483-4772-8E79-3D69D8477DE4, not the EFI System Partition's \
         C12A7328-F81F-11D2-BA4B-00A0C93EC93B";

    #[test]
    fn the_esp_is_the_volume_that_boot_current_names() {
        // a mirrored boot configuration: an ESP on each of two disks
        let windows = FakeWindows::with_esp()
            .disk(QEMU_DISK, &QEMU_ESP_DISK)
            .volume(OTHER_ESP, QEMU_DISK, (2048, 81920));

        assert_eq!(
            located(&windows, &booted_from(Some(qemu_esp()))),
            mounted(OTHER_ESP, qemu_esp()),
            "BootCurrent names QEMU_ESP_DISK's ESP"
        );
        assert_eq!(
            located(&windows, &booted_from(Some(gpt_512_esp()))),
            mounted(ESP, gpt_512_esp()),
            "BootCurrent names GPT_512's ESP"
        );
        assert_eq!(
            located(&windows, &booted_from(None)),
            Err(format!(
                "several volumes are an EFI system partition: {ESP}, {OTHER_ESP}"
            )),
            "BootCurrent names no partition"
        );
        assert_eq!(
            located(&windows, &HeldVariables::default()),
            Err(format!(
                "several volumes are an EFI system partition: {ESP}, {OTHER_ESP}"
            )),
            "no BootCurrent"
        );

        let elsewhere = HardDrive {
            signature: PartitionSignature::Gpt(
                "8C78A505-BAA0-4C4A-869F-000000001A06"
                    .parse()
                    .expect("a GUID"),
            ),
            ..gpt_512_esp()
        };
        assert_eq!(
            located(&windows, &booted_from(Some(elsewhere))),
            Err(format!(
                "no volume is the EFI system partition that BootCurrent names, GPT partition \
                 8C78A505-BAA0-4C4A-869F-000000001A06. Volumes: {ESP} (GPT partition \
                 8C78A505-BAA0-4C4A-869F-000000001A0E); {DATA} ({DATA_IS_NO_ESP}); {OTHER_ESP} \
                 (GPT partition 8C78A505-BAA0-4C4A-869F-000000001A10)"
            )),
            "BootCurrent names an ESP that no volume is"
        );
    }

    #[test]
    fn exactly_one_volume_must_be_an_esp_when_boot_current_names_none() {
        let windows = FakeWindows::with_esp();
        assert_eq!(
            located(&windows, &booted_from(None)),
            mounted(ESP, gpt_512_esp()),
            "one ESP"
        );

        let windows = FakeWindows::default().disk(GPT_512_DISK, &GPT_512).volume(
            DATA,
            GPT_512_DISK,
            (4096, 2048),
        );
        assert_eq!(
            located(&windows, &booted_from(None)),
            Err(format!(
                "no volume is an EFI system partition. Volumes: {DATA} ({DATA_IS_NO_ESP})"
            )),
            "no ESP"
        );

        assert_eq!(
            located(&FakeWindows::default(), &booted_from(None)),
            Err("no volume is an EFI system partition. Volumes: none".to_owned()),
            "no volume"
        );
    }

    #[test]
    fn esps_are_named_as_firmware_names_them() {
        let windows = FakeWindows::default()
            .disk(4, &GPT_4096)
            .volume(ESP, 4, (512, 256));
        assert_eq!(
            located(&windows, &booted_from(None)),
            mounted(
                ESP,
                HardDrive {
                    partition_number: 1,
                    start: 512,
                    size: 256,
                    signature: PartitionSignature::Gpt(
                        "8C78A505-BAA0-4C4A-869F-000000001A0A"
                            .parse()
                            .expect("a GUID"),
                    ),
                }
            ),
            "GPT_4096's ESP, in 4096-byte blocks"
        );

        let windows = FakeWindows::default()
            .disk(1, &MBR_512)
            .volume(ESP, 1, (4096, 2048));
        assert_eq!(
            located(&windows, &booted_from(None)),
            mounted(
                ESP,
                HardDrive {
                    partition_number: 2,
                    start: 4096,
                    size: 2048,
                    signature: PartitionSignature::Mbr(0x5EC7_A1B2),
                }
            ),
            "MBR_512's ESP, by its record's slot"
        );

        // the GPT entry's index, not its place on the disk
        let windows = FakeWindows::default()
            .disk(QEMU_DISK, &QEMU_ESP_DISK)
            .volume(ESP, QEMU_DISK, (2048, 81920));
        assert_eq!(
            located(&windows, &booted_from(None)),
            mounted(ESP, qemu_esp()),
            "QEMU_ESP_DISK's ESP"
        );
    }

    #[test]
    fn a_volume_is_an_esp_only_if_one_disk_extent_is_an_esp_partition() {
        let extent = |start: i64, length: i64| DiskExtent {
            disk_number: GPT_512_DISK,
            starting_offset: start,
            extent_length: length,
        };
        let cases = [
            (
                "two extents",
                Ok(vec![extent(1_048_576, 1_048_576), extent(2_097_152, 512)]),
                "it spans 2 disk extents, not one: 1048576 bytes at byte 1048576 of disk 0, 512 \
                 bytes at byte 2097152 of disk 0",
            ),
            ("no extent", Ok(Vec::new()), "it spans no disk extent"),
            (
                "a negative offset",
                Ok(vec![extent(-512, 1_048_576)]),
                "its disk extent, 1048576 bytes at byte -512 of disk 0, has a negative offset or \
                 length",
            ),
            (
                "a part of the ESP",
                Ok(vec![extent(1_048_576, 512)]),
                "partition table entry 3 spans LBA 2048 to 4095, but the volume spans 1 logical \
                 blocks from LBA 2048",
            ),
            (
                "no whole blocks",
                Ok(vec![extent(1_048_577, 1_048_576)]),
                "the partition at byte 1048577 of its disk, 1048576 bytes long, is no whole number \
                 of the disk's 512-byte logical blocks",
            ),
            (
                "a failed IOCTL",
                Err(CallFailed {
                    call: "DeviceIoControl(IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS)",
                    code: DEVICE_FAILED,
                }),
                "DeviceIoControl(IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS) failed: Win32 error 1",
            ),
        ];
        for (case, extents, reason) in cases {
            let mut windows = FakeWindows::default().disk(GPT_512_DISK, &GPT_512);
            windows.volumes.push((ESP.to_owned(), extents));
            assert_eq!(
                located(&windows, &booted_from(None)),
                Err(format!(
                    "no volume is an EFI system partition. Volumes: {ESP} ({reason})"
                )),
                "{case}"
            );
        }
    }

    #[test]
    fn each_failed_win32_call_is_named() {
        let failed = |call| CallFailed {
            call,
            code: DEVICE_FAILED,
        };

        let mut windows = FakeWindows::with_esp();
        windows.first_failure = Some(failed("FindFirstVolumeW"));
        assert_eq!(
            located(&windows, &booted_from(None)),
            Err("cannot list the volumes: FindFirstVolumeW failed: Win32 error 1".to_owned()),
            "FindFirstVolumeW"
        );

        // only ERROR_NO_MORE_FILES ends the list
        let mut windows = FakeWindows::with_esp();
        windows.last_failure = Some(failed("FindNextVolumeW"));
        assert_eq!(
            located(&windows, &booted_from(None)),
            Err("cannot list the volumes: FindNextVolumeW failed: Win32 error 1".to_owned()),
            "FindNextVolumeW"
        );

        /// The disk's step that fails
        #[derive(Clone, Copy, Debug)]
        enum Step {
            Open,
            BlockSize,
            Read,
        }
        for step in [Step::Open, Step::BlockSize, Step::Read] {
            let mut windows = FakeWindows::with_esp();
            let reason = match step {
                Step::Open => {
                    windows
                        .disks
                        .insert(GPT_512_DISK, Err(failed("CreateFileW")));
                    "CreateFileW failed: Win32 error 1"
                }
                Step::BlockSize => {
                    windows.block_size_failure =
                        Some(failed("DeviceIoControl(IOCTL_DISK_GET_DRIVE_GEOMETRY)"));
                    "DeviceIoControl(IOCTL_DISK_GET_DRIVE_GEOMETRY) failed: Win32 error 1"
                }
                Step::Read => {
                    if let Some(Ok(disk)) = windows.disks.get_mut(&GPT_512_DISK) {
                        disk.read_failure = Some(failed("ReadFile"));
                    }
                    "cannot read 512 bytes of the disk from LBA 0: ReadFile failed: Win32 error 1"
                }
            };
            assert_eq!(
                located(&windows, &booted_from(None)),
                Err(format!(
                    "no volume is an EFI system partition. Volumes: {ESP} ({reason}); {DATA} \
                     ({reason})"
                )),
                "{step:?}"
            );
        }
    }

    #[test]
    fn a_short_read_is_no_partition_table() {
        let mut windows = FakeWindows::default().disk(GPT_512_DISK, &GPT_512).volume(
            ESP,
            GPT_512_DISK,
            (2048, 2048),
        );
        if let Some(Ok(disk)) = windows.disks.get_mut(&GPT_512_DISK) {
            disk.bytes.truncate(1000);
        }
        assert_eq!(
            located(&windows, &booted_from(None)),
            Err(format!(
                "no volume is an EFI system partition. Volumes: {ESP} (cannot read 512 bytes of \
                 the disk from LBA 1: ReadFile read 488 of 512 bytes at byte 512)"
            )),
            "a disk of 1000 bytes"
        );
    }

    #[test]
    fn a_denied_volume_or_disk_asks_for_administrator() {
        let denied = CallFailed {
            call: "CreateFileW",
            code: Win32Error::ACCESS_DENIED,
        };
        let refused = |path: &str| {
            Err(format!(
                "cannot read volume {path}: CreateFileW failed: Win32 error 5 \
                 (ERROR_ACCESS_DENIED): uefisettings needs Administrator"
            ))
        };

        let mut windows = FakeWindows::with_esp();
        windows.disks.insert(GPT_512_DISK, Err(denied));
        assert_eq!(
            located(&windows, &booted_from(None)),
            refused(ESP),
            "CreateFileW of the disk"
        );

        // though another volume is the one ESP
        let mut windows = FakeWindows::with_esp();
        if let Some((_, extents)) = windows.volumes.iter_mut().find(|(path, _)| path == DATA) {
            *extents = Err(denied);
        }
        assert_eq!(
            located(&windows, &booted_from(None)),
            refused(DATA),
            "CreateFileW of a volume"
        );
    }

    /// One fixture through the Linux and the Windows locators gives one Hard Drive node.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_and_windows_name_one_esp_alike() {
        let (linux, _mount_point) = crate::esp::linux::tests::FakeLinux::with_esp();
        let variables = booted_from(None);
        let on_linux = linux.paths.locate(&variables).expect("the ESP on Linux");
        let on_windows = FakeWindows::with_esp()
            .locate(&variables)
            .expect("the ESP on Windows");
        assert_eq!(on_windows.hard_drive, on_linux.hard_drive, "GPT_512's ESP");
    }
}
