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

//! The EFI system partition that staging writes to on Linux: a mounted vfat volume whose partition
//! is an ESP in its disk's partition table, the one that BootCurrent's Hard Drive node names.

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::fs::File;
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::FileExt;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::path::PathBuf;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;

use super::boot_current_hard_drive;
use super::described;
use super::is_wanted;
use super::wanted;
use super::BlockDevice;
use super::EspLocator;
use super::MountedEsp;
use super::PartitionExtent;
use super::PartitionTable;
use crate::efi_variables::load_option::HardDrive;
use crate::efi_variables::VariableData;

/// The sector of Linux's block layer, which sysfs counts a partition's start and size in
const SECTOR_SIZE: u64 = 512;
/// The type that Linux mounts a FAT file system as, the ESP's (UEFI 2.11 §13.3)
const VFAT: &[u8] = b"vfat";

/// Where Linux tells of mounts and block devices, and what tells the device that a path reaches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinuxPaths<D = Stat> {
    /// proc_pid_mountinfo(5)
    pub(crate) mountinfo: PathBuf,
    /// A directory of each block device's sysfs directory, by major:minor
    pub(crate) sys_dev_block: PathBuf,
    /// The device files
    pub(crate) dev: PathBuf,
    pub(crate) devices: D,
}

impl Default for LinuxPaths {
    fn default() -> Self {
        Self {
            mountinfo: PathBuf::from("/proc/self/mountinfo"),
            sys_dev_block: PathBuf::from("/sys/dev/block"),
            dev: PathBuf::from("/dev"),
            devices: Stat,
        }
    }
}

/// What tells the device whose file system a path reaches.
pub(crate) trait PathDevices {
    /// The major:minor of the device whose file system holds `path`, as mountinfo writes it.
    fn device_of(&self, path: &Path) -> Result<String>;
}

/// stat(2): st_dev is the major:minor that mountinfo writes for a file system
/// (proc_pid_mountinfo(5)).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct Stat;

impl PathDevices for Stat {
    fn device_of(&self, path: &Path) -> Result<String> {
        let device = fs::metadata(path)
            .with_context(|| format!("stat {}", path.display()))?
            .dev();
        Ok(format!("{}:{}", libc::major(device), libc::minor(device)))
    }
}

impl<D: PathDevices> EspLocator for LinuxPaths<D> {
    /// The mounted ESP that staging writes to: the mounted vfat volume whose partition the Hard
    /// Drive node of BootCurrent's Boot#### names, else, if it names none, the only mounted ESP;
    /// refused unless exactly one volume is that. A GPT partition matches by its
    /// UniquePartitionGUID; an MBR one by its disk signature and partition number. A volume
    /// counts only if its mount point reaches it.
    fn locate(&self, variables: &impl VariableData) -> Result<MountedEsp> {
        let named = boot_current_hard_drive(variables)?;
        let volumes: Vec<(PathBuf, Result<HardDrive>)> = vfat_mounts(&self.mountinfo)?
            .into_iter()
            .map(|(device, mount_point)| {
                let hard_drive = mounted_partition(self, &device, &mount_point);
                (mount_point, hard_drive)
            })
            .collect();
        let matching: Vec<MountedEsp> = volumes
            .iter()
            .filter_map(|(mount_point, hard_drive)| {
                let hard_drive = *hard_drive.as_ref().ok()?;
                is_wanted(named.as_ref(), &hard_drive).then(|| MountedEsp {
                    mount_point: mount_point.clone(),
                    hard_drive,
                })
            })
            .collect();

        let wanted = wanted(named.as_ref());
        match matching.as_slice() {
            [esp] => Ok(esp.clone()),
            [] => Err(anyhow!(
                "no mounted vfat volume is {wanted}; mount it. Mounted: {}",
                listed(&volumes)
            )),
            several => Err(anyhow!(
                "several mounted vfat volumes are {wanted}: {}",
                several
                    .iter()
                    .map(|esp| esp.mount_point.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )),
        }
    }

    /// Refused: Linux writes through the mount point where it finds the ESP mounted.
    fn mounted_at(&self, esp: MountedEsp, mount_point: &Path) -> Result<MountedEsp> {
        Err(anyhow!(
            "an ESP mount point, {}, applies to Windows; Linux writes through {}, where it finds \
             the ESP mounted",
            mount_point.display(),
            esp.mount_point.display()
        ))
    }
}

/// The mounted vfat volumes, each with its partition or why it is no ESP, in words.
fn listed(volumes: &[(PathBuf, Result<HardDrive>)]) -> String {
    match volumes {
        [] => "none".to_owned(),
        _ => volumes
            .iter()
            .map(|(mount_point, hard_drive)| match hard_drive {
                Ok(hard_drive) => format!("{} ({})", mount_point.display(), described(hard_drive)),
                Err(error) => format!("{} ({error:#})", mount_point.display()),
            })
            .collect::<Vec<_>>()
            .join("; "),
    }
}

/// The vfat volumes mounted whole, each by its device's major:minor and the first mount point,
/// from `mountinfo` (proc_pid_mountinfo(5)).
fn vfat_mounts(mountinfo: &Path) -> Result<Vec<(String, PathBuf)>> {
    let text = fs::read(mountinfo).with_context(|| format!("read {}", mountinfo.display()))?;
    let mut mounts: BTreeMap<String, PathBuf> = BTreeMap::new();
    for line in text
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        if let Some((device, mount_point)) = vfat_mount(line).with_context(|| {
            format!(
                "{} holds a malformed line: {}",
                mountinfo.display(),
                String::from_utf8_lossy(line)
            )
        })? {
            mounts.entry(device).or_insert(mount_point);
        }
    }
    Ok(mounts.into_iter().collect())
}

/// The device's major:minor and mount point of the mountinfo line `line` if it mounts a vfat
/// volume whole, from its root; None for another type, or for a directory of a volume.
fn vfat_mount(line: &[u8]) -> Result<Option<(String, PathBuf)>> {
    let mut fields = line.split(|byte| *byte == b' ');
    let (Some(_id), Some(_parent), Some(device), Some(root), Some(mount_point)) = (
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
        fields.next(),
    ) else {
        return Err(anyhow!("fewer than 5 fields"));
    };
    // optional fields end with a "-" field, then the type
    let mut after_separator = fields.skip_while(|field| *field != b"-").skip(1);
    let fs_type = after_separator
        .next()
        .ok_or_else(|| anyhow!("no file system type after a \"-\" field"))?;
    if fs_type != VFAT || root != b"/" {
        return Ok(None);
    }
    let device = std::str::from_utf8(device)
        .context("a major:minor in no UTF-8")?
        .to_owned();
    Ok(Some((
        device,
        PathBuf::from(OsString::from_vec(unescaped(mount_point)?)),
    )))
}

/// `field` with each octal escape \ooo, which mountinfo writes for a space, tab, newline or
/// backslash, replaced by its byte.
fn unescaped(field: &[u8]) -> Result<Vec<u8>> {
    let mut bytes = Vec::with_capacity(field.len());
    let mut rest = field;
    while let Some((&byte, after)) = rest.split_first() {
        match (byte, after.split_first_chunk::<3>()) {
            (b'\\', Some((digits, after)))
                if digits.iter().all(|digit| matches!(digit, b'0'..=b'7')) =>
            {
                let value = digits
                    .iter()
                    .fold(0u16, |value, digit| value * 8 + u16::from(digit - b'0'));
                bytes.push(u8::try_from(value).context("an octal escape past 0o377")?);
                rest = after;
            }
            (b'\\', _) => return Err(anyhow!("a backslash without 3 octal digits")),
            (byte, _) => {
                bytes.push(byte);
                rest = after;
            }
        }
    }
    Ok(bytes)
}

/// The Hard Drive node of the partition of the block device `device`, a major:minor, that
/// mountinfo mounts at `mount_point`, refused unless partition_hard_drive allows it and
/// `mount_point` reaches its file system, which a later mount on it or on a directory above it
/// shadows.
fn mounted_partition(
    paths: &LinuxPaths<impl PathDevices>,
    device: &str,
    mount_point: &Path,
) -> Result<HardDrive> {
    let hard_drive = partition_hard_drive(paths, device)?;
    let reached = paths.devices.device_of(mount_point)?;
    match reached == device {
        true => Ok(hard_drive),
        false => Err(anyhow!(
            "it reaches device {reached}, not {device}: a later mount shadows it"
        )),
    }
}

/// The Hard Drive node of the partition of the block device `device`, a major:minor, from its
/// disk's partition table, refused unless that is an ESP's.
fn partition_hard_drive<D>(paths: &LinuxPaths<D>, device: &str) -> Result<HardDrive> {
    let partition = paths.sys_dev_block.join(device);
    match fs::metadata(partition.join("partition")) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(anyhow!("block device {device} is no partition of a disk"))
        }
        Err(error) => return Err(error).with_context(|| format!("read {}", partition.display())),
    }
    let disk = partition.join("..");
    let extent = PartitionExtent {
        offset: sectors(&partition.join("start"))?,
        length: sectors(&partition.join("size"))?,
    };
    let block_size = number(&disk.join("queue").join("logical_block_size"))?;
    let device_file = paths.dev.join(device_name(&disk.join("uevent"))?);
    let file =
        File::open(&device_file).with_context(|| format!("open {}", device_file.display()))?;
    let table = PartitionTable::read(&DiskFile {
        file,
        block_size: u32::try_from(block_size).context("a logical block size past 4 GiB")?,
    })
    .with_context(|| format!("read the partition table of {}", device_file.display()))?;
    table
        .esp_hard_drive(extent)
        .with_context(|| format!("in the partition table of {}", device_file.display()))
}

/// The bytes of the sectors that the sysfs file `path` counts.
fn sectors(path: &Path) -> Result<u64> {
    number(path)?.checked_mul(SECTOR_SIZE).ok_or_else(|| {
        anyhow!(
            "{} counts more sectors than 64 bits of bytes",
            path.display()
        )
    })
}

/// The decimal number that the sysfs file `path` holds.
fn number(path: &Path) -> Result<u64> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    text.trim_end()
        .parse()
        .with_context(|| format!("{} holds no number: {text:?}", path.display()))
}

/// The DEVNAME that the sysfs uevent file `path` tells, the device file's name.
fn device_name(path: &Path) -> Result<String> {
    let text = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    text.lines()
        .find_map(|line| line.strip_prefix("DEVNAME="))
        .filter(|name| !name.split('/').any(|part| matches!(part, "" | "." | "..")))
        .map(str::to_owned)
        .ok_or_else(|| anyhow!("{} tells no DEVNAME", path.display()))
}

/// A disk's device file, read in logical blocks.
struct DiskFile {
    file: File,
    block_size: u32,
}

impl BlockDevice for DiskFile {
    fn block_size(&self) -> u32 {
        self.block_size
    }

    fn read_blocks(&self, lba: u64, blocks: &mut [u8]) -> io::Result<()> {
        let offset = lba.checked_mul(u64::from(self.block_size)).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "LBA past 64 bits of bytes")
        })?;
        self.file.read_exact_at(blocks, offset)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::cell::RefCell;
    use std::os::unix::fs::symlink;

    use tempfile::TempDir;

    use super::super::sfdisk_images::SfdiskImage;
    use super::super::sfdisk_images::GPT_4096;
    use super::super::sfdisk_images::GPT_512;
    use super::super::sfdisk_images::MBR_512;
    use super::super::tests::booted_from;
    use super::super::tests::gpt_512_esp;
    use super::*;
    use crate::efi_variables::globals::tests::HeldVariables;
    use crate::efi_variables::load_option::PartitionSignature;

    /// GPT_512's ESP, entry 3, and its Linux partition, entry 1, as sysfs counts them
    const GPT_512_ESP: (u64, u64) = (2048, 2048);
    const GPT_512_LINUX: (u64, u64) = (4096, 2048);

    /// A Linux system in a directory: its mountinfo, sysfs block devices and device files.
    pub(crate) struct FakeLinux {
        root: TempDir,
        pub(crate) paths: LinuxPaths<FakeDevices>,
    }

    /// The mounts of a FakeLinux, in order, each by mount point and device: a path reaches the
    /// device of the last mount on it or on a directory above it.
    #[derive(Debug, Default)]
    pub(crate) struct FakeDevices(RefCell<Vec<(PathBuf, String)>>);

    impl PathDevices for FakeDevices {
        fn device_of(&self, path: &Path) -> Result<String> {
            self.0
                .borrow()
                .iter()
                .rev()
                .find(|(mount_point, _)| path.starts_with(mount_point))
                .map(|(_, device)| device.clone())
                .ok_or_else(|| anyhow!("no mount holds {}", path.display()))
        }
    }

    impl FakeLinux {
        pub(crate) fn new() -> Self {
            let root = TempDir::new().expect("a temporary directory");
            let paths = LinuxPaths {
                mountinfo: root.path().join("mountinfo"),
                sys_dev_block: root.path().join("sys").join("dev").join("block"),
                dev: root.path().join("dev"),
                devices: FakeDevices::default(),
            };
            fs::create_dir_all(&paths.sys_dev_block).expect("sys/dev/block");
            fs::create_dir_all(&paths.dev).expect("dev");
            fs::write(&paths.mountinfo, "").expect("mountinfo");
            Self { root, paths }
        }

        /// A disk named `name` of major `major`, minor 0, whose device file holds `image`, and
        /// its partitions, each of a minor and the start and size that sysfs counts in sectors.
        fn disk(
            &self,
            name: &str,
            major: u32,
            image: &SfdiskImage,
            partitions: &[(u32, (u64, u64))],
        ) {
            let disk = self.root.path().join("sys").join("devices").join(name);
            fs::create_dir_all(disk.join("queue")).expect("the disk's queue");
            fs::write(
                disk.join("queue").join("logical_block_size"),
                format!("{}\n", image.block_size),
            )
            .expect("logical_block_size");
            fs::write(
                disk.join("uevent"),
                format!("MAJOR={major}\nMINOR=0\nDEVNAME={name}\nDEVTYPE=disk\n"),
            )
            .expect("uevent");
            symlink(
                format!("../../devices/{name}"),
                self.paths.sys_dev_block.join(format!("{major}:0")),
            )
            .expect("the disk's link");
            for (minor, (start, size)) in partitions {
                let partition = disk.join(format!("{name}{minor}"));
                fs::create_dir_all(&partition).expect("the partition");
                for (file, value) in [
                    ("partition", minor.to_string()),
                    ("start", start.to_string()),
                    ("size", size.to_string()),
                ] {
                    fs::write(partition.join(file), format!("{value}\n")).expect(file);
                }
                symlink(
                    format!("../../devices/{name}/{name}{minor}"),
                    self.paths.sys_dev_block.join(format!("{major}:{minor}")),
                )
                .expect("the partition's link");
            }
            fs::write(self.paths.dev.join(name), image.bytes()).expect("the device file");
        }

        /// Mounts `device`, a major:minor, from `root` as `fs_type` at the directory `name`, which
        /// mountinfo writes as `escaped`; returns the mount point.
        fn mount_as(
            &self,
            device: &str,
            root: &str,
            fs_type: &str,
            name: &str,
            escaped: &str,
        ) -> PathBuf {
            let mount_point = self.root.path().join(name);
            fs::create_dir_all(&mount_point).expect("the mount point");
            let line = format!(
                "29 1 {device} {root} {}/{escaped} rw,relatime shared:1 - {fs_type} /dev/x rw\n",
                self.root.path().display()
            );
            let mut mountinfo = fs::read(&self.paths.mountinfo).expect("mountinfo");
            mountinfo.extend(line.as_bytes());
            fs::write(&self.paths.mountinfo, mountinfo).expect("mountinfo");
            self.paths
                .devices
                .0
                .borrow_mut()
                .push((mount_point.clone(), device.to_owned()));
            mount_point
        }

        fn mount(&self, device: &str, name: &str) -> PathBuf {
            self.mount_as(device, "/", "vfat", name, name)
        }

        /// GPT_512 as disk sda, its ESP 8:3 mounted at esp, and its Linux partition 8:1.
        pub(crate) fn with_esp() -> (Self, PathBuf) {
            let linux = Self::new();
            linux.disk("sda", 8, &GPT_512, &[(1, GPT_512_LINUX), (3, GPT_512_ESP)]);
            let esp = linux.mount("8:3", "esp");
            (linux, esp)
        }
    }

    fn located(linux: &FakeLinux, variables: &HeldVariables) -> Result<MountedEsp, String> {
        linux
            .paths
            .locate(variables)
            .map_err(|err| format!("{err:#}"))
    }

    #[test]
    fn the_esp_is_the_mounted_partition_that_boot_current_names() {
        let (linux, esp) = FakeLinux::with_esp();
        linux.mount("8:1", "linux");
        linux.mount_as("8:3", "/EFI", "vfat", "esp-efi", "esp-efi");
        linux.mount_as("8:1", "/", "ext4", "ext4", "ext4");
        let want = Ok(MountedEsp {
            mount_point: esp.clone(),
            hard_drive: gpt_512_esp(),
        });

        assert_eq!(
            located(&linux, &booted_from(Some(gpt_512_esp()))),
            want,
            "named"
        );
        assert_eq!(
            located(&linux, &booted_from(None)),
            want,
            "no Hard Drive node"
        );
        assert_eq!(
            located(&linux, &HeldVariables::default()),
            want,
            "no BootCurrent"
        );

        // mounted twice, at its first mount point
        linux.mount("8:3", "again");
        assert_eq!(
            located(&linux, &booted_from(Some(gpt_512_esp()))),
            want,
            "mounted twice"
        );

        // a directory of the ESP mounted before the ESP itself
        let linux = FakeLinux::new();
        linux.disk("sda", 8, &GPT_512, &[(3, GPT_512_ESP)]);
        linux.mount_as("8:3", "/EFI", "vfat", "esp-efi", "esp-efi");
        let esp = linux.mount("8:3", "esp");
        assert_eq!(
            located(&linux, &booted_from(Some(gpt_512_esp()))).map(|esp| esp.mount_point),
            Ok(esp),
            "a directory mounted first"
        );

        // a mount point that mountinfo escapes
        let linux = FakeLinux::new();
        linux.disk("sda", 8, &GPT_512, &[(3, GPT_512_ESP)]);
        let spaced = linux.mount_as("8:3", "/", "vfat", "an esp", "an\\040esp");
        assert_eq!(
            located(&linux, &booted_from(Some(gpt_512_esp()))).map(|esp| esp.mount_point),
            Ok(spaced),
            "escaped"
        );
    }

    #[test]
    fn exactly_one_mounted_volume_must_be_the_esp() {
        let other_esp = HardDrive {
            signature: PartitionSignature::Gpt(
                "8C78A505-BAA0-4C4A-869F-000000001A05"
                    .parse()
                    .expect("a GUID"),
            ),
            ..gpt_512_esp()
        };
        let (linux, esp) = FakeLinux::with_esp();
        let linux_partition = linux.mount("8:1", "linux");
        assert_eq!(
            located(&linux, &booted_from(Some(other_esp))),
            Err(format!(
                "no mounted vfat volume is the EFI system partition that BootCurrent names, GPT \
                 partition 8C78A505-BAA0-4C4A-869F-000000001A05; mount it. Mounted: {} (in the \
                 partition table of {}: GPT entry 1 has PartitionTypeGUID \
                 0FC63DAF-8483-4772-8E79-3D69D8477DE4, not the EFI System Partition's \
                 C12A7328-F81F-11D2-BA4B-00A0C93EC93B); {} (GPT partition \
                 8C78A505-BAA0-4C4A-869F-000000001A0E)",
                linux_partition.display(),
                linux.paths.dev.join("sda").display(),
                esp.display()
            )),
            "another partition named"
        );

        // a second ESP, of another disk
        linux.disk("sdb", 16, &GPT_4096, &[(1, (512 * 8, 256 * 8))]);
        let second = linux.mount("16:1", "second");
        assert_eq!(
            located(&linux, &booted_from(None)),
            Err(format!(
                "several mounted vfat volumes are an EFI system partition: {}, {}",
                second.display(),
                esp.display()
            )),
            "two ESPs, none named"
        );
        assert!(
            located(&linux, &booted_from(Some(gpt_512_esp()))).is_ok(),
            "two ESPs, one named"
        );

        let linux = FakeLinux::new();
        assert_eq!(
            located(&linux, &booted_from(None)),
            Err(
                "no mounted vfat volume is an EFI system partition; mount it. Mounted: none".into()
            ),
            "nothing mounted"
        );
        linux.disk("sda", 8, &GPT_512, &[(3, GPT_512_ESP)]);
        linux.mount_as("8:3", "/", "ext4", "ext4", "ext4");
        assert_eq!(
            located(&linux, &booted_from(Some(gpt_512_esp()))),
            Err(
                "no mounted vfat volume is the EFI system partition that BootCurrent names, GPT \
                 partition 8C78A505-BAA0-4C4A-869F-000000001A0E; mount it. Mounted: none"
                    .into()
            ),
            "the ESP mounted as another type"
        );
        let whole = linux.mount("8:0", "whole");
        assert_eq!(
            located(&linux, &booted_from(None)),
            Err(format!(
                "no mounted vfat volume is an EFI system partition; mount it. Mounted: {} (block \
                 device 8:0 is no partition of a disk)",
                whole.display()
            )),
            "a whole disk mounted"
        );
    }

    /// A mount on a directory above the ESP's mount point shadows it: writes there would reach
    /// the later mount's file system.
    #[test]
    fn a_mount_point_that_a_later_mount_shadows_is_refused() {
        let linux = FakeLinux::new();
        linux.disk("sda", 8, &GPT_512, &[(3, GPT_512_ESP)]);
        let esp = linux.mount_as("8:3", "/", "vfat", "boot/efi", "boot/efi");
        linux.mount_as("0:42", "/", "tmpfs", "boot", "boot");
        assert_eq!(
            located(&linux, &booted_from(Some(gpt_512_esp()))),
            Err(format!(
                "no mounted vfat volume is the EFI system partition that BootCurrent names, GPT \
                 partition 8C78A505-BAA0-4C4A-869F-000000001A0E; mount it. Mounted: {} (it \
                 reaches device 0:42, not 8:3: a later mount shadows it)",
                esp.display()
            )),
            "shadowed"
        );

        let linux = FakeLinux::new();
        linux.disk("sda", 8, &GPT_512, &[(3, GPT_512_ESP)]);
        linux.mount_as("0:42", "/", "tmpfs", "boot", "boot");
        let esp = linux.mount_as("8:3", "/", "vfat", "boot/efi", "boot/efi");
        assert_eq!(
            located(&linux, &booted_from(Some(gpt_512_esp()))).map(|esp| esp.mount_point),
            Ok(esp),
            "mounted over another mount"
        );
    }

    #[test]
    fn a_devname_names_a_file_below_the_device_directory() {
        let directory = TempDir::new().expect("a temporary directory");
        let uevent = directory.path().join("uevent");
        let refused = format!("{} tells no DEVNAME", uevent.display());
        for (devname, want) in [
            ("sda", Ok("sda")),
            ("mapper/x", Ok("mapper/x")),
            ("", Err(&refused)),
            ("../sda", Err(&refused)),
            ("a/./b", Err(&refused)),
            ("a//b", Err(&refused)),
        ] {
            fs::write(
                &uevent,
                format!("MAJOR=8\nMINOR=0\nDEVNAME={devname}\nDEVTYPE=disk\n"),
            )
            .expect("uevent");
            assert_eq!(
                device_name(&uevent).map_err(|err| format!("{err:#}")),
                want.map(str::to_owned).map_err(String::clone),
                "DEVNAME={devname:?}"
            );
        }
    }

    #[test]
    fn an_mbr_esp_is_named_by_its_disk_signature_and_partition_number() {
        let linux = FakeLinux::new();
        linux.disk("sda", 8, &MBR_512, &[(2, (4096, 2048))]);
        let esp = linux.mount("8:2", "esp");
        let mbr_esp = HardDrive {
            partition_number: 2,
            start: 4096,
            size: 2048,
            signature: PartitionSignature::Mbr(0x5EC7_A1B2),
        };

        assert_eq!(
            located(&linux, &booted_from(Some(mbr_esp))),
            Ok(MountedEsp {
                mount_point: esp,
                hard_drive: mbr_esp,
            }),
            "named"
        );
        for (case, named) in [
            (
                "another partition number",
                HardDrive {
                    partition_number: 1,
                    ..mbr_esp
                },
            ),
            (
                "another disk signature",
                HardDrive {
                    signature: PartitionSignature::Mbr(0x5EC7_A1B3),
                    ..mbr_esp
                },
            ),
            ("a GPT partition", gpt_512_esp()),
        ] {
            assert!(
                located(&linux, &booted_from(Some(named))).is_err(),
                "{case}"
            );
        }
    }

    #[test]
    fn mountinfo_lines_that_are_not_mounts_are_refused() {
        for line in [
            "29 1 8:3 / /esp",
            "29 1 8:3 / /esp rw shared:1",
            "29 1 8:3 / /e\\04sp rw - vfat /dev/sda3 rw",
            "29 1 8:3 / /e\\777sp rw - vfat /dev/sda3 rw",
        ] {
            assert!(vfat_mount(line.as_bytes()).is_err(), "{line}");
        }
        assert_eq!(
            vfat_mount(b"29 1 8:3 / /e\\134sp\\011 rw - vfat /dev/sda3 rw").ok(),
            Some(Some(("8:3".to_owned(), PathBuf::from("/e\\sp\t")))),
            "escaped backslash and tab"
        );
    }
}
