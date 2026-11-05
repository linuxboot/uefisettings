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
use std::io;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use log::debug;
use log::error;
use log::warn;
use nix::errno::Errno;
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
use crate::hii::efivarfs_format::EfivarCopy;
use crate::hii::efivarfs_format::EfivarFileName;
use crate::hii::efivarfs_format::EFIVARFS_INTERFACE;
use crate::hii::efivarfs_format::EFIVARFS_REACH;
use crate::hii::variables::modify_variable_bytes;
use crate::hii::variables::EfivarSource;
use crate::hii::variables::FirmwareVariables;
use crate::hii::variables::UnreadVariables;
use crate::hii::variables::VariableInterface;
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
            Self::Directory(dir) => Box::new(EfivarCopy::new(dir)),
            Self::Disabled => Box::new(UnreadVariables {
                reach: EFIVARFS_REACH,
                interface: EFIVARFS_INTERFACE,
            }),
        })
    }
}

/// The efivar files in `dir` as FirmwareVariables: this machine's efivarfs.
pub(crate) struct EfivarFiles {
    dir: PathBuf,
    /// The file that write_at locks while it remounts `dir` read-write.
    remount_lock: PathBuf,
}

impl EfivarFiles {
    /// This machine's efivarfs.
    pub(crate) fn system() -> Self {
        Self {
            dir: PathBuf::from(EFIVARS_MOUNT_POINT),
            remount_lock: PathBuf::from(REMOUNT_LOCK_FILE),
        }
    }
}

impl FirmwareVariables for EfivarFiles {
    fn reach(&self) -> VariableReach {
        EFIVARFS_REACH
    }

    fn interface(&self) -> VariableInterface {
        EFIVARFS_INTERFACE
    }

    fn read(&self, key: &VariableKey, size: u16) -> Result<Vec<u8>> {
        read_efivar(&self.dir, &EfivarFileName::from(key), size)
            .map_err(|error| as_variable_not_found(key, error))
    }

    fn write_at(&self, key: &VariableKey, size: u16, offset: u16, encoded: &[u8]) -> Result<()> {
        // Steps:
        // * Read bytes
        // * Seek to 4 + offset
        // * If checks pass, write your answer

        // We have three layers of checks so as to not accidentally corrupt EFI vars.

        // The /run/lock/efibootmgr-remount lock will release automatically on drop.
        // If something errors out, doesn't matter since we are using the flock syscall to lock it.
        // Linux will then release it automatically after the program ends.

        let mut lock = FileLock::new(&self.remount_lock);
        lock.lock()?;

        let file_name = EfivarFileName::from(key);
        let path = self.dir.join(&file_name);

        let file_ro = open_efivar(&self.dir, &file_name)
            .map_err(|error| as_variable_not_found(key, error))?;

        let mut file_contents = file_ro
            .metadata()
            .and_then(|metadata| read_efivar_file(&file_ro, metadata.len()))
            .context(format!("Failed to read efivarfs file '{}'", path.display()))?;

        modify_variable_bytes(
            key,
            EFIVARFS_INTERFACE,
            &mut file_contents,
            size,
            offset,
            encoded,
        )?;

        let _efifs =
            EfivarsMountGuard::new(&self.dir).context("Failed to create efivars fs mount guard")?;

        // Needed on kernel 4.6+ to make EFI vars the kernel doesn't know how to
        // validate temporarily writable.
        let _immutability_attribute_guard = EfivarsImmutabilityGuard::new(&path)
            .context("failed to create immutability attribute guard")?;

        // All checks passed, now we can try to write.
        debug!("Writing value to {}", path.display());
        write_efivar_file(&path, &file_contents)
    }
}

/// The statuses behind the errno of a failed efivarfs write, after Linux v6.11
/// drivers/firmware/efi/efi.c efi_status_to_err(): SetVariable()'s, or on x86 those of the
/// QueryVariableInfo() that Linux calls first for a non-volatile variable
/// (drivers/firmware/efi/vars.c check_var_size(), arch/x86/platform/efi/quirks.c
/// efi_query_variable_store()). efivarfs_file_write() (fs/efivarfs/file.c) turns ENOENT
/// (EFI_NOT_FOUND) into EIO, and write_all retries EINTR (EFI_ABORTED), so neither errno has a
/// variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
enum SetVariableStatus {
    /// EINVAL: efi_status_to_err()'s default, and efivarfs's own refusals. Its EFI_UNSUPPORTED is
    /// SetVariable()'s, as check_var_size() turns QueryVariableInfo()'s into a size check, and
    /// means a call the platform does not support at that time (UEFI 2.11 §8.2.3), as after
    /// ExitBootServices(); the UEFI Shell runs before it.
    #[error(
        "the firmware returned EFI_INVALID_PARAMETER, EFI_UNSUPPORTED or another status that \
         Linux reports as EINVAL, or efivarfs refused the attributes or data; for \
         EFI_UNSUPPORTED, run uefisettings.efi in the UEFI Shell"
    )]
    InvalidParameter,
    /// ENOSPC, also from Linux's check_var_size() (drivers/firmware/efi/vars.c) before the call.
    #[error(
        "the firmware returned EFI_OUT_OF_RESOURCES, or Linux found too little variable storage"
    )]
    OutOfResources,
    /// EIO, also when Linux disabled runtime services (drivers/firmware/efi/runtime-wrappers.c
    /// __efi_queue_work()).
    #[error(
        "the firmware returned EFI_DEVICE_ERROR, or the variable is gone (EFI_NOT_FOUND), or \
         Linux has disabled EFI runtime services"
    )]
    DeviceErrorOrNotFound,
    /// EROFS.
    #[error("the firmware returned EFI_WRITE_PROTECTED (the variable is read-only)")]
    WriteProtected,
    /// EACCES, also a security module's refusal through vfs_write() rw_verify_area()
    /// security_file_permission() (fs/read_write.c).
    #[error(
        "the firmware returned EFI_SECURITY_VIOLATION, or a security module refused the write"
    )]
    SecurityViolation,
}

impl SetVariableStatus {
    /// The statuses behind `error`, of a write to an efivarfs file, if its errno carries any.
    fn of(error: &io::Error) -> Option<Self> {
        match error.raw_os_error()? {
            libc::EINVAL => Some(Self::InvalidParameter),
            libc::ENOSPC => Some(Self::OutOfResources),
            libc::EIO => Some(Self::DeviceErrorOrNotFound),
            libc::EROFS => Some(Self::WriteProtected),
            libc::EACCES => Some(Self::SecurityViolation),
            _ => None,
        }
    }
}

/// `error`, of a write to an efivarfs file, naming the statuses behind it.
fn efivarfs_write_error(error: io::Error) -> anyhow::Error {
    let status = SetVariableStatus::of(&error);
    let error = anyhow::Error::new(error);
    match status {
        Some(status) => error.context(status),
        None => error,
    }
    .context("Failed to write to efivarfs file")
}

/// Writes `contents` to the efivarfs file at `path`, naming the statuses behind a refused write.
fn write_efivar_file(path: &Path, contents: &[u8]) -> Result<()> {
    File::create(path)
        .context("Failed to open efivarfs file for writing")?
        .write_all(contents)
        .map_err(efivarfs_write_error)
}

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
            .map_err(|errno| remount_error(mount_point, errno))?
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

/// Why Linux refuses a read-write efivarfs with EINVAL: efivarfs_reconfigure() (Linux v6.11
/// fs/efivarfs/super.c) refuses it without a runtime SetVariable(), which generic_ops_register()
/// (drivers/firmware/efi/efi.c) leaves out when the firmware's EFI_RT_PROPERTIES_TABLE does not
/// list it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error(
    "Linux refuses a read-write efivarfs without a runtime SetVariable(), as on firmware whose \
     EFI_RT_PROPERTIES_TABLE (UEFI 2.11 §4.6.2) leaves it out; run uefisettings.efi in the UEFI \
     Shell"
)]
struct NoRuntimeSetVariable;

/// `errno`, of remounting the efivarfs at `mount_point` read-write, explained when it is EINVAL.
fn remount_error(mount_point: &Path, errno: Errno) -> anyhow::Error {
    let error = anyhow::Error::new(errno);
    match errno {
        Errno::EINVAL => error.context(NoRuntimeSetVariable),
        _ => error,
    }
    .context(format!("Failed to remount {} RW", mount_point.display()))
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
    use std::io::Read;

    use anyhow::Context;
    use anyhow::Result;
    use tempfile::TempDir;

    use super::*;
    use crate::hii::efivarfs_format::MAX_EFIVAR_FILE_SIZE;
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
            remount_lock: lock.path().join("remount"),
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

    /// write_at refuses an efivar file of more than MAX_EFIVAR_FILE_SIZE bytes, a sparse one
    /// here, with read_efivar_file's error, and writes nothing.
    #[test]
    fn efivar_files_refuse_a_file_longer_than_the_maximum() {
        let (dir, _lock, files) = unmounted_efivar_files();
        let key = variable_key("Setup");
        let path = dir.path().join(EfivarFileName::from(&key));
        let attributes = NV_BS_RT.to_ne_bytes();
        File::create(&path)
            .and_then(|mut file| {
                file.write_all(&attributes)?;
                file.set_len(MAX_EFIVAR_FILE_SIZE + 1)
            })
            .expect("create an efivar file one byte longer than the maximum");
        let too_long = format!(
            "'{}': longer than its maximum of {MAX_EFIVAR_FILE_SIZE} bytes",
            path.display()
        );

        let written = files
            .write_at(&key, 4, 0, &[1])
            .map_err(|error| format!("{error:#}"));

        assert_eq!(
            written,
            Err(format!("Failed to read efivarfs file {too_long}")),
            "write_at"
        );
        let mut head = [0xFF; 5];
        File::open(&path)
            .and_then(|mut file| file.read_exact(&mut head))
            .expect("read the head of the efivar file");
        assert_eq!(
            (
                fs::metadata(&path)
                    .expect("read the efivar file's metadata")
                    .len(),
                head.to_vec()
            ),
            (MAX_EFIVAR_FILE_SIZE + 1, [&attributes[..], &[0]].concat()),
            "the efivar file"
        );
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

    /// write_efivar_file names the statuses behind the errno of a refused write, ENOSPC from
    /// /dev/full (full(4)), and none behind a refused open.
    #[test]
    fn write_efivar_file_names_the_status_behind_a_refused_write() {
        let dir = tempfile::tempdir().expect("create a directory");
        let cases = [
            (
                PathBuf::from("/dev/full"),
                format!(
                    "Failed to write to efivarfs file: {}: {}",
                    SetVariableStatus::OutOfResources,
                    io::Error::from_raw_os_error(libc::ENOSPC)
                ),
            ),
            (
                dir.path().join("missing").join("Setup"),
                format!(
                    "Failed to open efivarfs file for writing: {}",
                    io::Error::from_raw_os_error(libc::ENOENT)
                ),
            ),
        ];

        for (path, want) in cases {
            let error = write_efivar_file(&path, &[0; 8]).expect_err("write a refused file");

            assert_eq!(format!("{error:#}"), want, "{}", path.display());
        }
    }

    /// A failed efivarfs write names the statuses that Linux reports as its errno, and names none
    /// for an errno that carries no status.
    #[test]
    fn efivarfs_write_error_names_the_set_variable_status() {
        let cases = [
            (
                libc::EINVAL,
                Some(
                    "the firmware returned EFI_INVALID_PARAMETER, EFI_UNSUPPORTED or another \
                     status that Linux reports as EINVAL, or efivarfs refused the attributes or \
                     data; for EFI_UNSUPPORTED, run uefisettings.efi in the UEFI Shell",
                ),
            ),
            (
                libc::ENOSPC,
                Some(
                    "the firmware returned EFI_OUT_OF_RESOURCES, or Linux found too little \
                     variable storage",
                ),
            ),
            (
                libc::EIO,
                Some(
                    "the firmware returned EFI_DEVICE_ERROR, or the variable is gone \
                     (EFI_NOT_FOUND), or Linux has disabled EFI runtime services",
                ),
            ),
            (
                libc::EROFS,
                Some("the firmware returned EFI_WRITE_PROTECTED (the variable is read-only)"),
            ),
            (
                libc::EACCES,
                Some(
                    "the firmware returned EFI_SECURITY_VIOLATION, or a security module refused \
                     the write",
                ),
            ),
            (libc::ENOENT, None),
            (libc::EINTR, None),
            (libc::EPERM, None),
            (libc::EFAULT, None),
            (libc::ENOMEM, None),
        ];

        for (errno, status) in cases {
            let os_error = io::Error::from_raw_os_error(errno);
            let want = match status {
                Some(status) => format!("Failed to write to efivarfs file: {status}: {os_error}"),
                None => format!("Failed to write to efivarfs file: {os_error}"),
            };

            assert_eq!(
                format!("{:#}", efivarfs_write_error(os_error)),
                want,
                "errno {errno}"
            );
        }
    }

    /// A read-write remount refused with EINVAL explains that Linux has no runtime SetVariable()
    /// and points at uefisettings.efi; a remount refused with another errno explains nothing.
    #[test]
    fn remount_error_explains_einval() {
        let cases = [
            (
                Errno::EINVAL,
                Some(
                    "Linux refuses a read-write efivarfs without a runtime SetVariable(), as on \
                     firmware whose EFI_RT_PROPERTIES_TABLE (UEFI 2.11 §4.6.2) leaves it out; run \
                     uefisettings.efi in the UEFI Shell",
                ),
            ),
            (Errno::EPERM, None),
            (Errno::EACCES, None),
            (Errno::EBUSY, None),
        ];

        for (errno, explanation) in cases {
            let want = match explanation {
                Some(explanation) => {
                    format!("Failed to remount {EFIVARS_MOUNT_POINT} RW: {explanation}: {errno}")
                }
                None => format!("Failed to remount {EFIVARS_MOUNT_POINT} RW: {errno}"),
            };

            assert_eq!(
                format!("{:#}", remount_error(Path::new(EFIVARS_MOUNT_POINT), errno)),
                want,
                "{errno}"
            );
        }
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
