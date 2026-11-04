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

use std::fs;
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
use nix::sys::statfs::statfs;
use nix::sys::statfs::FsType;
use nix::sys::statfs::Statfs;
use proc_mounts::MountIter;
use thiserror::Error;

use crate::chattr::EfivarsImmutabilityGuard;
use crate::efi_variables::VariableNames;
use crate::file_lock::FileLock;
use crate::hii::efivarfs_format::as_variable_not_found;
use crate::hii::efivarfs_format::check_regular_file;
use crate::hii::efivarfs_format::listed_names;
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
/// The f_type of an efivarfs's statfs (Linux v6.11 include/uapi/linux/magic.h).
const EFIVARFS_MAGIC: u32 = 0xde5e_81e4;

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

impl VariableNames for EfivarFiles {
    fn variable_names(&self) -> Result<Vec<VariableKey>> {
        efivarfs_statfs(&self.dir)?;
        efivar_names(&self.dir)
    }
}

/// The statfs of `dir`, which fails unless an efivarfs is mounted on it: else `dir` lists no
/// variable, as EFIVARS_MOUNT_POINT is then the empty directory of sysfs that efisubsys_init()
/// (Linux v6.11 drivers/firmware/efi/efi.c) creates for the mount.
fn efivarfs_statfs(dir: &Path) -> Result<Statfs> {
    let stat = statfs(dir).map_err(|errno| statfs_error(dir, errno))?;
    match is_efivarfs(stat.filesystem_type()) {
        true => Ok(stat),
        false => Err(NotEfivarfs(dir.to_path_buf()).into()),
    }
}

/// The error of the statfs of `dir` that failed with `errno`. Linux 6.5 to 6.5.4 fail the statfs
/// of efivarfs where the firmware's QueryVariableInfo() fails, with EINVAL where it is not
/// supported at runtime (Linux v6.5 fs/efivarfs/super.c efivarfs_statfs(),
/// drivers/firmware/efi/efi.c efi_status_to_err()); 79b83606abc7 fixed it in 6.5.5 and 6.6.
fn statfs_error(dir: &Path, errno: Errno) -> anyhow::Error {
    let failed = format!("failed to statfs {}", dir.display());
    let context = match errno {
        Errno::EINVAL => format!(
            "{failed}, as Linux 6.5 to 6.5.4 do where the firmware's QueryVariableInfo() fails or \
             is not supported at runtime"
        ),
        _ => failed,
    };
    anyhow::Error::new(errno).context(context)
}

/// Whether `fs_type`, the f_type of a statfs, is EFIVARFS_MAGIC.
fn is_efivarfs(fs_type: FsType) -> bool {
    let fs_type = i128::from(fs_type.0);
    // the same 32 bits where f_type is a signed 32-bit integer, as with 32-bit glibc
    let signed = i32::from_ne_bytes(EFIVARFS_MAGIC.to_ne_bytes());
    fs_type == i128::from(EFIVARFS_MAGIC) || fs_type == i128::from(signed)
}

/// Why EfivarFiles lists no variables of a directory.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("no efivarfs is mounted on {}", .0.display())]
struct NotEfivarfs(PathBuf);

/// The variables of the efivar files in `dir`, from its listing and their metadata, never their
/// data. A file of no bytes holds no variable: efivarfs creates the file of a new name at once,
/// and the variable once something writes it (Linux v6.11 fs/efivarfs/inode.c
/// efivarfs_create()). A file removed since the listing is left out.
fn efivar_names(dir: &Path) -> Result<Vec<VariableKey>> {
    let names = listed_names(dir)
        .and_then(Iterator::collect::<io::Result<Vec<_>>>)
        .with_context(|| format!("failed to list efivars directory '{}'", dir.display()))?;
    let mut keys = Vec::new();
    for name in names {
        let path = dir.join(&name);
        let metadata = match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            result => result
                .with_context(|| format!("failed to stat efivar file '{}'", path.display()))?,
        };
        check_regular_file(&path, &metadata, "efivar file")?;
        if metadata.len() > 0 {
            keys.push(VariableKey::from_efivar_file_name(&name)?);
        }
    }
    Ok(keys)
}

#[cfg(test)]
mod tests {
    use std::ffi::OsStr;
    use std::ffi::OsString;
    use std::io::Read;
    use std::os::unix::ffi::OsStrExt;

    use anyhow::Context;
    use anyhow::Result;
    use nix::sys::inotify::AddWatchFlags;
    use nix::sys::inotify::InitFlags;
    use nix::sys::inotify::Inotify;
    use tempfile::TempDir;

    use super::*;
    use crate::hii::efivarfs_format::MAX_EFIVAR_FILE_SIZE;
    use crate::hii::variables::tests::variable_key;
    use crate::hii::variables::tests::BS_RT;
    use crate::hii::variables::tests::EFI_GLOBAL_VARIABLE;
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

    /// The names of the files in the directory that `watch` watches that were opened or read
    /// since the last call.
    fn touched(watch: &Inotify) -> Vec<OsString> {
        match watch.read_events() {
            Ok(events) => events.into_iter().filter_map(|event| event.name).collect(),
            Err(Errno::EAGAIN) => Vec::new(),
            Err(error) => panic!("read the inotify events: {error}"),
        }
    }

    /// efivar_names lists the variable of every efivar file that holds one, by the file's name,
    /// where a '!' stays one; it skips a file of no bytes, and opens no file.
    #[test]
    fn efivar_names_list_the_variables_of_the_files_without_opening_them() {
        let dir = tempfile::tempdir().expect("create efivars directory");
        let timeout = VariableKey {
            name: "Timeout".to_string(),
            guid: EFI_GLOBAL_VARIABLE,
        };
        let timeout_file = dir.path().join(EfivarFileName::from(&timeout));
        let files = [
            (
                timeout_file.clone(),
                [&NV_BS_RT.to_ne_bytes()[..], &[5, 0]].concat(),
            ),
            (
                dir.path().join(EfivarFileName::from(&variable_key("a/b"))),
                [&NV_BS_RT.to_ne_bytes()[..], &[1]].concat(),
            ),
            (
                dir.path()
                    .join(EfivarFileName::from(&variable_key("Uncommitted"))),
                vec![],
            ),
        ];
        for (path, bytes) in files {
            fs::write(path, bytes).expect("write the efivar file");
        }
        let watch = Inotify::init(InitFlags::IN_NONBLOCK).expect("create an inotify instance");
        watch
            .add_watch(
                dir.path(),
                AddWatchFlags::IN_OPEN | AddWatchFlags::IN_ACCESS,
            )
            .expect("watch the directory");

        let mut keys = efivar_names(dir.path()).expect("list the efivar files");

        keys.sort();
        assert_eq!(keys, [timeout, variable_key("a!b")], "variables");
        assert_eq!(
            touched(&watch),
            Vec::<OsString>::new(),
            "files opened or read"
        );
        fs::read(&timeout_file).expect("read an efivar file");
        let read = touched(&watch);
        assert!(
            !read.is_empty()
                && read
                    .iter()
                    .all(|name| Some(name.as_os_str()) == timeout_file.file_name()),
            "the watch misses a read of {}: {read:?}",
            timeout_file.display()
        );
    }

    /// efivar_names lists a variable whose name holds a surrogate code unit, with U+FFFD for it,
    /// and the other variables too.
    #[test]
    fn efivar_names_list_a_name_with_a_surrogate() {
        let dir = tempfile::tempdir().expect("create efivars directory");
        // the surrogate 0xD800 as ucs2_as_utf8() writes it
        for name in [&b"A\xed\xa0\x80B"[..], b"Timeout"] {
            let file = [name, b"-8be4df61-93ca-11d2-aa0d-00e098032b8c"].concat();
            fs::write(dir.path().join(OsStr::from_bytes(&file)), [7, 0, 0, 0, 1])
                .expect("write an efivar file");
        }

        let mut keys = efivar_names(dir.path()).expect("list a name with a surrogate");

        keys.sort();
        assert_eq!(
            keys,
            ["A\u{fffd}B", "Timeout"].map(|name| VariableKey {
                name: name.to_string(),
                guid: EFI_GLOBAL_VARIABLE,
            }),
            "listed"
        );
    }

    /// efivar_names refuses an entry that is no efivar file, by its name or its type.
    #[test]
    fn efivar_names_refuse_an_entry_that_is_no_efivar_file() {
        /// The refusal of the entry at a path.
        type Refusal = fn(&Path) -> String;
        let cases: [(&str, bool, Refusal); 2] = [
            ("README", false, |_| {
                "'README' is not the name of an efivar file".to_string()
            }),
            (
                "Directory-8be4df61-93ca-11d2-aa0d-00e098032b8c",
                true,
                |path| format!("efivar file '{}' is not a regular file", path.display()),
            ),
        ];
        for (name, directory, refusal) in cases {
            let dir = tempfile::tempdir().expect("create efivars directory");
            let path = dir.path().join(name);
            match directory {
                true => fs::create_dir(&path).expect("create a directory"),
                false => fs::write(&path, [7, 0, 0, 0]).expect("write a file"),
            }

            let error = efivar_names(dir.path()).expect_err("list a directory with the entry");

            assert_eq!(error.to_string(), refusal(&path), "{name}");
        }
    }

    /// EfivarFiles lists no variables of a directory on which no efivarfs is mounted, though
    /// it holds efivar files.
    #[test]
    fn efivar_files_list_no_variables_without_efivarfs() {
        let (dir, _lock, files) = unmounted_efivar_files();
        let setup = variable_key("Setup");
        fs::write(
            dir.path().join(EfivarFileName::from(&setup)),
            [&NV_BS_RT.to_ne_bytes()[..], &[1]].concat(),
        )
        .expect("write the efivar file");

        let error = files
            .variable_names()
            .expect_err("list a directory without efivarfs");

        assert_eq!(
            error.downcast_ref::<NotEfivarfs>(),
            Some(&NotEfivarfs(dir.path().to_path_buf())),
            "{error:#}"
        );
        assert_eq!(
            efivar_names(dir.path()).expect("list the efivar files"),
            [setup],
            "the efivar files"
        );
    }

    /// is_efivarfs takes EFIVARFS_MAGIC as statfs gives it, also as a negative signed 32-bit
    /// f_type, and no other file system type.
    #[test]
    fn is_efivarfs_takes_only_efivarfs_magic() {
        let cases: [(&str, i128, bool); 4] = [
            ("EFIVARFS_MAGIC", 0xde5e_81e4, true),
            (
                "EFIVARFS_MAGIC as a signed 32-bit f_type",
                -0x21a1_7e1c,
                true,
            ),
            ("TMPFS_MAGIC", 0x0102_1994, false),
            ("EFIVARFS_MAGIC with a higher bit", 0x1_de5e_81e4, false),
        ];
        let mut checked = Vec::new();
        for (case, fs_type, want) in cases {
            // a value that the f_type of this target cannot hold, such as EFIVARFS_MAGIC for
            // 32-bit glibc, is no f_type to check
            let Ok(fs_type) = fs_type.try_into() else {
                continue;
            };

            assert_eq!(is_efivarfs(FsType(fs_type)), want, "{case}");
            checked.push(want);
        }
        assert!(
            checked.contains(&true) && checked.contains(&false),
            "checked: {checked:?}"
        );
    }

    /// statfs_error tells of EINVAL why Linux 6.5 to 6.5.4 fail the statfs of efivarfs, and of
    /// other errors only that the statfs failed.
    #[test]
    fn statfs_error_tells_why_linux_6_5_fails_with_einval() {
        let dir = Path::new(EFIVARS_MOUNT_POINT);
        for (errno, want) in [
            (
                Errno::EINVAL,
                "failed to statfs /sys/firmware/efi/efivars, as Linux 6.5 to 6.5.4 do where the \
                 firmware's QueryVariableInfo() fails or is not supported at runtime: EINVAL: \
                 Invalid argument",
            ),
            (
                Errno::ENOENT,
                "failed to statfs /sys/firmware/efi/efivars: ENOENT: No such file or directory",
            ),
        ] {
            assert_eq!(format!("{:#}", statfs_error(dir, errno)), want, "{errno}");
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
