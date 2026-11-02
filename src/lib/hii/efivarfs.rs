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

use std::fs::File;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use log::debug;
use log::error;
use log::warn;
use nix::mount::mount;
use nix::mount::MsFlags;
use proc_mounts::MountIter;
use thiserror::Error;

use crate::chattr::EfivarsImmutabilityGuard;
use crate::file_lock::FileLock;
use crate::hii::efivarfs_format::as_variable_not_found;
use crate::hii::efivarfs_format::open_efivar;
use crate::hii::efivarfs_format::read_efivar;
use crate::hii::efivarfs_format::read_efivar_file;
use crate::hii::efivarfs_format::EfivarFileName;
use crate::hii::variables::modify_variable_bytes;
use crate::hii::variables::EfivarSource;
use crate::hii::variables::FirmwareVariables;
use crate::hii::variables::UnreadVariables;
use crate::hii::variables::VariableKey;
use crate::hii::variables::VariableReach;

pub(super) const EFIVARS_MOUNT_POINT: &str = "/sys/firmware/efi/efivars";
/// The file that EfivarFiles::system() locks while it remounts EFIVARS_MOUNT_POINT.
const REMOUNT_LOCK_FILE: &str = "/run/lock/efibootmgr-remount";

impl EfivarSource {
    /// The firmware variables that questions read from this source, which validate accepts.
    pub(crate) fn into_variables(self) -> Result<Box<dyn FirmwareVariables>> {
        self.validate()?;
        Ok(match self {
            Self::System => Box::new(EfivarFiles::system()),
            Self::Directory(dir) => Box::new(EfivarFiles::from_copy(dir)),
            Self::Disabled => Box::new(UnreadVariables(EfivarFiles::REACH)),
        })
    }
}

/// The efivar files in `dir` as FirmwareVariables: this machine's efivarfs, or a copy of one,
/// which takes no writes.
pub(crate) struct EfivarFiles {
    dir: PathBuf,
    /// The file that write_at locks while it remounts `dir` read-write; None for a copy.
    remount_lock: Option<PathBuf>,
}

impl EfivarFiles {
    /// What efivarfs reaches.
    const REACH: VariableReach = VariableReach::Runtime;

    /// This machine's efivarfs.
    pub(crate) fn system() -> Self {
        Self {
            dir: PathBuf::from(EFIVARS_MOUNT_POINT),
            remount_lock: Some(PathBuf::from(REMOUNT_LOCK_FILE)),
        }
    }

    /// The copy of efivarfs in `dir`.
    fn from_copy(dir: PathBuf) -> Self {
        Self {
            dir,
            remount_lock: None,
        }
    }
}

impl FirmwareVariables for EfivarFiles {
    fn reach(&self) -> VariableReach {
        Self::REACH
    }

    fn read(&self, key: &VariableKey, size: u16) -> Result<Vec<u8>> {
        read_efivar(&self.dir, &EfivarFileName::from(key), size)
            .map_err(|error| as_variable_not_found(key, error))
    }

    fn write_at(&self, key: &VariableKey, size: u16, offset: u16, encoded: &[u8]) -> Result<()> {
        let Some(remount_lock) = &self.remount_lock else {
            return Err(CopyOfEfivars.into());
        };

        // Steps:
        // * Read bytes
        // * Seek to 4 + offset
        // * If checks pass, write your answer

        // We have three layers of checks so as to not accidentally corrupt EFI vars.

        // The /run/lock/efibootmgr-remount lock will release automatically on drop.
        // If something errors out, doesn't matter since we are using the flock syscall to lock it.
        // Linux will then release it automatically after the program ends.

        let mut lock = FileLock::new(remount_lock);
        lock.lock()?;

        let file_name = EfivarFileName::from(key);
        let path = self.dir.join(&file_name);

        let file_ro = open_efivar(&self.dir, &file_name)
            .map_err(|error| as_variable_not_found(key, error))?;

        let mut file_contents = file_ro
            .metadata()
            .and_then(|metadata| read_efivar_file(&file_ro, metadata.len()))
            .context(format!("Failed to read efivarfs file '{}'", path.display()))?;

        modify_variable_bytes(key, Self::REACH, &mut file_contents, size, offset, encoded)?;

        let _efifs =
            EfivarsMountGuard::new(&self.dir).context("Failed to create efivars fs mount guard")?;

        // Needed on kernel 4.6+ to make EFI vars the kernel doesn't know how to
        // validate temporarily writable.
        let _immutability_attribute_guard = EfivarsImmutabilityGuard::new(&path)
            .context("failed to create immutability attribute guard")?;

        // All checks passed, now we can try to write.
        debug!("Writing value to {}", path.display());
        File::create(&path)
            .context("Failed to open efivarfs file for writing")?
            .write_all(&file_contents)
            .context("Failed to write to efivarfs file")?;

        Ok(())
    }
}

/// Why EfivarFiles of a copy of efivarfs refuse a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("a copy of efivars takes no writes")]
pub(super) struct CopyOfEfivars;

/// Keeps the efivarfs at `mount_point` read-write while it lives, remounting it read-only again
/// if it was.
pub struct EfivarsMountGuard {
    mount_point: PathBuf,
    original_flags: MsFlags,
}

impl EfivarsMountGuard {
    pub fn new(mount_point: &Path) -> Result<Self> {
        let original_flags = get_current_mount_flags(mount_point)?;
        if original_flags.contains(MsFlags::MS_RDONLY) {
            debug!(
                "{} mounted read only, remounting read/write",
                mount_point.display()
            );
            mount(
                None as Option<&str>,
                mount_point,
                None as Option<&str>,
                original_flags & !MsFlags::MS_RDONLY | MsFlags::MS_REMOUNT,
                None as Option<&str>,
            )
            .context(format!("Failed to remount {} RW", mount_point.display()))?
        } else {
            debug!(
                "{} is mounted read/write, skipping remount",
                mount_point.display()
            );
        }

        Ok(EfivarsMountGuard {
            mount_point: mount_point.to_path_buf(),
            original_flags,
        })
    }
}

impl Drop for EfivarsMountGuard {
    fn drop(&mut self) {
        // efivarfs being rw is scary. We should unmount it ASAP.
        // If efivarfs is set as ro in fstab (the ideal), "remount" along will change it back.
        if self.original_flags.contains(MsFlags::MS_RDONLY) {
            debug!("remounting {} as read only", self.mount_point.display());
            let res = mount(
                None as Option<&str>,
                &self.mount_point,
                None as Option<&str>,
                self.original_flags | MsFlags::MS_REMOUNT,
                None as Option<&str>,
            );
            if let Err(why) = res {
                error!(
                    "failed to remount {} because {:#}",
                    self.mount_point.display(),
                    why
                );
            }
        }
    }
}

pub fn get_current_mount_flags(dest: impl AsRef<Path>) -> Result<MsFlags> {
    let dest = dest.as_ref();
    match MountIter::new()
        .context("cannot read /proc/mounts")?
        .filter_map(Result::ok)
        .find(|m| m.dest == dest)
    {
        Some(mount_info) => {
            debug!("MountInfo for {}: {}", dest.to_string_lossy(), mount_info);
            Ok(to_ms_flags(&mount_info.options))
        }
        None => Err(anyhow!(
            "mount {} is not in /proc/mounts",
            dest.to_string_lossy()
        )),
    }
}

fn to_ms_flags(options: &[String]) -> MsFlags {
    options
        .iter()
        .fold(MsFlags::empty(), |acc, option| match option.as_str() {
            "ro" => acc | MsFlags::MS_RDONLY,
            "rw" => acc, // rw means MS_RDONLY is not set
            "noexec" => acc | MsFlags::MS_NOEXEC,
            "nosuid" => acc | MsFlags::MS_NOSUID,
            "nodev" => acc | MsFlags::MS_NODEV,
            "sync" => acc | MsFlags::MS_SYNCHRONOUS,
            "dirsync" => acc | MsFlags::MS_DIRSYNC,
            "remount" => acc | MsFlags::MS_REMOUNT,
            "bind" => acc | MsFlags::MS_BIND,
            "rbind" => acc | MsFlags::MS_BIND | MsFlags::MS_REC,
            "silent" => acc | MsFlags::MS_SILENT,
            "mand" => acc | MsFlags::MS_MANDLOCK,
            "noatime" => acc | MsFlags::MS_NOATIME,
            "iversion" => acc | MsFlags::MS_I_VERSION,
            "nodiratime" => acc | MsFlags::MS_NODIRATIME,
            "relatime" => acc | MsFlags::MS_RELATIME,
            "strictatime" => acc | MsFlags::MS_STRICTATIME,
            "lazytime" => acc | MsFlags::MS_LAZYTIME,
            "unbindable" => acc | MsFlags::MS_UNBINDABLE,
            "runbindable" => acc | MsFlags::MS_UNBINDABLE | MsFlags::MS_REC,
            "private" => acc | MsFlags::MS_PRIVATE,
            "rprivate" => acc | MsFlags::MS_PRIVATE | MsFlags::MS_REC,
            "slave" => acc | MsFlags::MS_SLAVE,
            "rslave" => acc | MsFlags::MS_SLAVE | MsFlags::MS_REC,
            "shared" => acc | MsFlags::MS_SHARED,
            "rshared" => acc | MsFlags::MS_SHARED | MsFlags::MS_REC,
            unknown => {
                warn!("unknown mount option: {}", &unknown);
                acc
            }
        })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use anyhow::Context;
    use anyhow::Result;
    use tempfile::TempDir;

    use super::*;
    use crate::hii::variables::tests::variable_key;
    use crate::hii::variables::tests::BS_RT;
    use crate::hii::variables::tests::NV_BS_RT;

    /// EfivarFiles of a temporary directory, which no mount lists, and their remount lock, in a
    /// directory of its own.
    fn unmounted_efivar_files() -> (TempDir, TempDir, EfivarFiles) {
        let dir = tempfile::tempdir().expect("create efivars directory");
        let lock = tempfile::tempdir().expect("create lock directory");
        let files = EfivarFiles {
            dir: dir.path().to_path_buf(),
            remount_lock: Some(lock.path().join("remount")),
        };
        (dir, lock, files)
    }

    /// write_at refuses a volatile, short or missing variable before it remounts efivarfs, which
    /// fails for a directory that no mount lists, and writes nothing.
    #[test]
    fn efivar_files_refuse_a_variable_before_the_remount() {
        let (dir, _lock, files) = unmounted_efivar_files();
        let volatile = [&BS_RT.to_ne_bytes()[..], &[0; 4]].concat();
        let short = [&NV_BS_RT.to_ne_bytes()[..], &[0; 2]].concat();
        for (name, bytes) in [("Volatile", &volatile), ("Short", &short)] {
            fs::write(
                dir.path().join(EfivarFileName::from(&variable_key(name))),
                bytes,
            )
            .expect("write the efivar file");
        }
        let cases = [
            (
                "Volatile",
                "EFI variable Volatile-00000000-0000-0000-0000-000000000000 is volatile (no \
                 EFI_VARIABLE_NON_VOLATILE) and cannot be written through efivarfs",
                Some(&volatile),
            ),
            (
                "Short",
                "efivarfs payload is shorter than the declared varstore: 2 < 4 bytes",
                Some(&short),
            ),
            (
                "Missing",
                "no EFI variable Missing-00000000-0000-0000-0000-000000000000",
                None,
            ),
        ];

        for (name, refusal, bytes) in cases {
            let key = variable_key(name);
            let error = files
                .write_at(&key, 4, 0, &[1])
                .expect_err("write a variable that write_at refuses");

            assert_eq!(error.to_string(), refusal, "{name}");
            assert_eq!(
                fs::read(dir.path().join(EfivarFileName::from(&key))).ok(),
                bytes.cloned(),
                "{name}: the efivar file"
            );
        }
    }

    /// write_at writes nothing when it cannot remount efivarfs.
    #[test]
    fn efivar_files_write_nothing_without_the_remount() {
        let (dir, _lock, files) = unmounted_efivar_files();
        let key = variable_key("Setup");
        let path = dir.path().join(EfivarFileName::from(&key));
        let bytes = [&NV_BS_RT.to_ne_bytes()[..], &[0; 4]].concat();
        fs::write(&path, &bytes).expect("write the efivar file");

        let error = files
            .write_at(&key, 4, 0, &[1])
            .expect_err("write without the remount");

        assert_eq!(
            format!("{error:#}"),
            format!(
                "Failed to create efivars fs mount guard: mount {} is not in /proc/mounts",
                dir.path().display()
            ),
            "refusal"
        );
        assert_eq!(
            fs::read(&path).expect("read the efivar file"),
            bytes,
            "bytes"
        );
    }

    /// The variables of an EfivarSource::Directory read its efivar files and take no writes.
    #[test]
    fn copy_of_efivars_takes_no_writes() {
        let dir = tempfile::tempdir().expect("create efivars directory");
        let key = variable_key("Setup");
        let path = dir.path().join(EfivarFileName::from(&key));
        let bytes = [&NV_BS_RT.to_ne_bytes()[..], &[0; 4]].concat();
        fs::write(&path, &bytes).expect("write the efivar file");
        let variables = EfivarSource::Directory(dir.path().to_path_buf())
            .into_variables()
            .expect("make the variables of the directory");

        let error = variables
            .write_at(&key, 4, 0, &[1])
            .expect_err("write a copy of efivars");

        assert_eq!(
            error.to_string(),
            "a copy of efivars takes no writes",
            "refusal"
        );
        assert_eq!(
            fs::read(&path).expect("read the efivar file"),
            bytes,
            "bytes"
        );
        assert_eq!(
            variables.read(&key, 4).expect("read the copy"),
            bytes,
            "read"
        );
    }

    #[test]
    fn test_get_current_mount_flags_not_mounted() -> Result<()> {
        assert!(
            get_current_mount_flags("some random stuff").is_err(),
            "error expected"
        );
        Ok(())
    }
    #[test]
    fn test_get_current_mount_flags_for_root() -> Result<()> {
        let _options =
            get_current_mount_flags("/").context("failed to get current mount options for /")?;
        Ok(())
    }
    #[test]
    fn test_get_current_mount_flags_for_proc() -> Result<()> {
        let options = get_current_mount_flags("/proc")
            .context("failed to get current mount options for /")?;
        assert!(
            options.contains(MsFlags::MS_NODEV | MsFlags::MS_NOEXEC | MsFlags::MS_NOSUID),
            "expected /proc to be mounted with nodev, noexec, nosuid"
        );
        assert!(
            !options.contains(MsFlags::MS_REMOUNT),
            "remount is not expected for /proc"
        );
        Ok(())
    }
}
