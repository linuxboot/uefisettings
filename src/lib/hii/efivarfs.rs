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

use std::collections::HashMap;
use std::fmt;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::os::unix::io::FromRawFd;
use std::path::Path;
use std::path::PathBuf;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use log::debug;
use log::error;
use log::warn;
use nix::fcntl::OFlag;
use nix::mount::mount;
use nix::mount::MsFlags;
use nix::sys::stat::Mode;
use proc_mounts::MountIter;
use thiserror::Error;

use crate::hii::package::Guid;

pub(super) const EFIVARS_MOUNT_POINT: &str = "/sys/firmware/efi/efivars";
pub(super) const EFIVARFS_HEADER_SIZE: usize = std::mem::size_of::<u32>();
/// The directory of this process's file descriptors, through which reopen opens a located file.
const PROC_SELF_FD: &str = "/proc/self/fd";

/// `<name>-<lowercase GUID>` with '!' for each '/', as Linux v7.2 fs/efivarfs/vars.c
/// efivar_get_utf8name() names a variable's file: always exactly one path component.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct EfivarFileName(String);

impl EfivarFileName {
    pub(super) fn new(name: &str, guid: Guid) -> Self {
        Self(format!(
            "{}-{}",
            name.replace('/', "!"),
            guid.to_string().to_ascii_lowercase()
        ))
    }
}

impl AsRef<Path> for EfivarFileName {
    fn as_ref(&self) -> &Path {
        Path::new(&self.0)
    }
}

impl fmt::Display for EfivarFileName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("no EFI variable {name}")]
pub(super) struct EfivarNotFound {
    pub(super) name: EfivarFileName,
}

/// Opens the efivar file `name` in `dir` for reading. A missing file is EfivarNotFound without
/// context, so the error names the variable.
/// A symlink or other non-regular file is an error, so a directory of efivar files cannot send
/// a read elsewhere or block it. The check is on the file that is then read: an O_PATH
/// descriptor opens no file (open(2)), so a device node runs no driver open, and reopening it
/// through /proc/self/fd opens the very file checked, whatever the path names by then.
pub(super) fn open_efivar(dir: &Path, name: &EfivarFileName) -> Result<File> {
    let path = dir.join(name);
    let location = locate(&path).map_err(|error| open_error(&path, name, error))?;
    let metadata = location
        .metadata()
        .with_context(|| format!("failed to stat efivar file '{}'", path.display()))?;
    check_regular_file(&path, &metadata)?;
    reopen(&location).map_err(|error| reopen_error(&path, error))
}

/// An O_PATH descriptor of `path`, of the link itself if it is a symlink.
fn locate(path: &Path) -> io::Result<File> {
    // not OpenOptions::custom_flags, which clears O_ACCMODE: musl defines it to include O_PATH
    let fd = nix::fcntl::open(
        path,
        OFlag::O_PATH | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?;
    // SAFETY: open() returned `fd` as a new descriptor that nothing else owns.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// Opens the file of the O_PATH descriptor `location` for reading, whatever its path names now.
fn reopen(location: &File) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        // a file under a write lease fails at once instead of waiting lease-break-time
        // (Linux v7.2 fs/locks.c); efivarfs_file_read() ignores O_NONBLOCK
        .custom_flags(libc::O_NONBLOCK)
        .open(Path::new(PROC_SELF_FD).join(location.as_raw_fd().to_string()))
}

/// Fails unless `metadata`, of the efivar file at `path`, is a regular file's.
fn check_regular_file(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    if !metadata.is_file() {
        return Err(anyhow!(
            "efivar file '{}' is not a regular file",
            path.display()
        ));
    }
    Ok(())
}

/// open_efivar's error for `error` from opening the efivar file `name` at `path`.
fn open_error(path: &Path, name: &EfivarFileName, error: io::Error) -> anyhow::Error {
    match error.kind() {
        io::ErrorKind::NotFound => EfivarNotFound { name: name.clone() }.into(),
        _ => anyhow::Error::new(error)
            .context(format!("failed to open efivar file '{}'", path.display())),
    }
}

/// open_efivar's error for `error` from reopening the efivar file at `path`.
fn reopen_error(path: &Path, error: io::Error) -> anyhow::Error {
    let hint = match error.kind() {
        // the descriptor is open, so NotFound means /proc/self/fd is missing
        io::ErrorKind::NotFound => ", which is missing: is /proc mounted?",
        _ => "",
    };
    anyhow::Error::new(error).context(format!(
        "failed to open efivar file '{}' through {PROC_SELF_FD}{hint}",
        path.display()
    ))
}

pub(super) fn read_efivarfs_bytes<R: Read>(reader: &mut R, payload_size: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; EFIVARFS_HEADER_SIZE + payload_size];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// Reads the efivar file `name` in `dir`: its attributes field and `size` payload bytes.
fn read_efivar(dir: &Path, name: &EfivarFileName, size: u16) -> Result<Vec<u8>> {
    let mut file = open_efivar(dir, name)?;
    debug!("buffer size: {}", size);
    // efivarfs prepends a 4-byte attributes field to the variable payload.
    read_efivarfs_bytes(&mut file, size.into())
        .with_context(|| format!("failed to read efivar file '{}'", dir.join(name).display()))
}

/// Where question values are read: the efivar files of this machine or of a directory, or none.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub enum EfivarSource {
    /// This machine's efivarfs.
    #[default]
    System,
    /// A directory of efivar files in efivarfs format, such as a copy of another machine's.
    Directory(PathBuf),
    /// No efivar files: each value shows as unavailable (get and list-questions add its IFR
    /// default) and conditions on values stay undetermined.
    Disabled,
}

impl EfivarSource {
    /// Fails if this is a Directory that is not a directory: every efivar file in it would read
    /// as missing, or fail to open.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::System | Self::Disabled => Ok(()),
            Self::Directory(dir) => match fs::metadata(dir) {
                Ok(metadata) if metadata.is_dir() => Ok(()),
                Ok(_) => Err(EfivarsNotADirectory(dir.clone()).into()),
                Err(error) if error.kind() == io::ErrorKind::NotFound => {
                    Err(EfivarsNotADirectory(dir.clone()).into())
                }
                Err(error) => Err(anyhow::Error::new(error).context(format!(
                    "failed to stat efivars directory {}",
                    dir.display()
                ))),
            },
        }
    }

    /// read_efivar of `range` in this source.
    fn read(&self, range: &EfivarRange) -> Result<Vec<u8>> {
        match self {
            Self::System => read_efivar(Path::new(EFIVARS_MOUNT_POINT), &range.name, range.size),
            Self::Directory(dir) => read_efivar(dir, &range.name, range.size),
            Self::Disabled => Err(EfivarsNotRead.into()),
        }
    }
}

/// Why EfivarSource::validate refuses a Directory.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("efivars directory {} is not a directory", .0.display())]
pub(super) struct EfivarsNotADirectory(PathBuf);

/// The outcome of every efivar range under EfivarSource::Disabled.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("EFI variables not read")]
pub(super) struct EfivarsNotRead;

/// The arguments of read_efivar after its directory, which an EfivarReader fixes.
#[derive(PartialEq, Eq, Hash)]
pub(super) struct EfivarRange {
    pub(super) name: EfivarFileName,
    pub(super) size: u16,
}

/// Reads the efivar ranges of one command, each once, keeping the outcomes:
/// Linux v7.2 efivarfs sleeps once a non-root user has read 100 times within a second
/// (fs/efivarfs/file.c, kernel/user.c).
pub(crate) struct EfivarReader {
    source: EfivarSource,
    pub(super) outcomes: HashMap<EfivarRange, Result<Vec<u8>>>,
}

impl EfivarReader {
    /// Reads the efivar files of `source`, which EfivarSource::validate accepts.
    pub(crate) fn new(source: EfivarSource) -> Result<Self> {
        source.validate()?;
        Ok(Self {
            source,
            outcomes: HashMap::new(),
        })
    }

    /// read_efivar of `range` in this source, read once.
    pub(super) fn read(
        &mut self,
        range: EfivarRange,
    ) -> std::result::Result<&[u8], &anyhow::Error> {
        let source = &self.source;
        self.outcomes
            .entry(range)
            .or_insert_with_key(|range| source.read(range))
            .as_deref()
    }
}

pub struct EfivarsMountGuard {
    original_flags: MsFlags,
}

impl EfivarsMountGuard {
    pub fn new() -> Result<Self> {
        let original_flags = get_current_mount_flags(EFIVARS_MOUNT_POINT)?;
        if original_flags.contains(MsFlags::MS_RDONLY) {
            debug!(
                "{} mounted read only, remounting read/write",
                EFIVARS_MOUNT_POINT
            );
            mount(
                None as Option<&str>,
                EFIVARS_MOUNT_POINT,
                None as Option<&str>,
                original_flags & !MsFlags::MS_RDONLY | MsFlags::MS_REMOUNT,
                None as Option<&str>,
            )
            .context(format!("Failed to remount {} RW", EFIVARS_MOUNT_POINT))?
        } else {
            debug!(
                "{} is mounted read/write, skipping remount",
                EFIVARS_MOUNT_POINT
            );
        }

        Ok(EfivarsMountGuard { original_flags })
    }
}

impl Drop for EfivarsMountGuard {
    fn drop(&mut self) {
        // efivarfs being rw is scary. We should unmount it ASAP.
        // If efivarfs is set as ro in fstab (the ideal), "remount" along will change it back.
        if self.original_flags.contains(MsFlags::MS_RDONLY) {
            debug!("remounting {} as read only", EFIVARS_MOUNT_POINT);
            let res = mount(
                None as Option<&str>,
                EFIVARS_MOUNT_POINT,
                None as Option<&str>,
                self.original_flags | MsFlags::MS_REMOUNT,
                None as Option<&str>,
            );
            if let Err(why) = res {
                error!(
                    "failed to remount {} because {:#}",
                    EFIVARS_MOUNT_POINT, why
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
pub mod tests {
    use std::ffi::OsStr;
    use std::ffi::OsString;
    use std::fs;
    use std::io::Read;
    use std::path::Component;

    use anyhow::Context;
    use anyhow::Result;
    use nix::errno::Errno;
    use nix::sys::inotify::AddWatchFlags;
    use nix::sys::inotify::InitFlags;
    use nix::sys::inotify::Inotify;

    use super::*;

    pub(crate) const EFI_GLOBAL_VARIABLE: Guid = Guid {
        data1: 0x8BE4_DF61,
        data2: 0x93CA,
        data3: 0x11D2,
        data4: [0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C],
    };

    #[test]
    fn efivar_file_name_is_one_path_component() {
        for (name, expected) in [
            ("Setup", "Setup-8be4df61-93ca-11d2-aa0d-00e098032b8c"),
            ("a/b", "a!b-8be4df61-93ca-11d2-aa0d-00e098032b8c"),
            ("../x", "..!x-8be4df61-93ca-11d2-aa0d-00e098032b8c"),
            ("/etc/x", "!etc!x-8be4df61-93ca-11d2-aa0d-00e098032b8c"),
            ("..", "..-8be4df61-93ca-11d2-aa0d-00e098032b8c"),
            ("", "-8be4df61-93ca-11d2-aa0d-00e098032b8c"),
        ] {
            let file_name = EfivarFileName::new(name, EFI_GLOBAL_VARIABLE);
            let path: &Path = file_name.as_ref();

            assert_eq!(file_name.to_string(), expected, "VarStore name {name:?}");
            assert_eq!(
                path.components().collect::<Vec<_>>(),
                [Component::Normal(OsStr::new(expected))],
                "VarStore name {name:?}"
            );
        }
    }

    #[test]
    fn open_efivar_opens_the_named_file() {
        let dir = tempfile::tempdir().expect("create directory");
        let name = EfivarFileName::new("Setup", EFI_GLOBAL_VARIABLE);
        fs::write(dir.path().join(&name), b"data").expect("write efivar file");
        let mut contents = String::new();

        open_efivar(dir.path(), &name)
            .expect("open efivar file")
            .read_to_string(&mut contents)
            .expect("read efivar file");

        assert_eq!(contents, "data");
    }

    #[test]
    fn open_efivar_returns_a_missing_file_as_efivar_not_found() {
        let dir = tempfile::tempdir().expect("create directory");
        let name = EfivarFileName::new("Setup", EFI_GLOBAL_VARIABLE);

        let error = open_efivar(dir.path(), &name).expect_err("open missing efivar file");

        assert_eq!(
            format!("{error:#}"),
            "no EFI variable Setup-8be4df61-93ca-11d2-aa0d-00e098032b8c",
            "Display of the missing-file error"
        );
        assert_eq!(
            error
                .downcast::<EfivarNotFound>()
                .expect("downcast to EfivarNotFound"),
            EfivarNotFound { name },
            "EfivarNotFound of the missing file"
        );
    }

    #[test]
    fn open_efivar_keeps_other_errors_with_the_path() {
        let not_a_dir = tempfile::NamedTempFile::new().expect("create file");
        let name = EfivarFileName::new("Setup", EFI_GLOBAL_VARIABLE);

        let error = open_efivar(not_a_dir.path(), &name).expect_err("open efivar file in a file");

        assert!(
            error.downcast_ref::<EfivarNotFound>().is_none(),
            "{error:#} is EfivarNotFound"
        );
        assert_eq!(
            error
                .root_cause()
                .downcast_ref::<io::Error>()
                .map(io::Error::kind),
            Some(io::ErrorKind::NotADirectory),
            "root cause of opening in a file"
        );
        assert_eq!(
            error.to_string(),
            format!(
                "failed to open efivar file '{}'",
                not_a_dir.path().join(&name).display()
            ),
            "message of opening in a file"
        );
    }

    #[test]
    fn open_error_keeps_permission_errors_with_the_path() {
        let name = EfivarFileName::new("Setup", EFI_GLOBAL_VARIABLE);
        let path = Path::new(EFIVARS_MOUNT_POINT).join(&name);
        let denied = io::Error::from(io::ErrorKind::PermissionDenied);

        let error = open_error(&path, &name, denied);

        assert!(
            error.downcast_ref::<EfivarNotFound>().is_none(),
            "{error:#} is EfivarNotFound"
        );
        assert_eq!(
            error
                .root_cause()
                .downcast_ref::<io::Error>()
                .map(io::Error::kind),
            Some(io::ErrorKind::PermissionDenied),
            "root cause of the permission error"
        );
        assert_eq!(
            error.to_string(),
            format!("failed to open efivar file '{}'", path.display()),
            "message of the permission error"
        );
    }

    #[test]
    fn open_efivar_refuses_a_symlink() {
        let dir = tempfile::tempdir().expect("create directory");
        let name = EfivarFileName::new("Setup", EFI_GLOBAL_VARIABLE);
        let path = dir.path().join(&name);
        fs::write(dir.path().join("target"), b"data").expect("write the link's target");
        std::os::unix::fs::symlink("target", &path).expect("link the efivar file");

        let error = open_efivar(dir.path(), &name).expect_err("open a symlink");

        assert_eq!(
            error.to_string(),
            format!("efivar file '{}' is not a regular file", path.display()),
            "symlink"
        );
    }

    #[test]
    fn open_efivar_refuses_a_non_regular_file() {
        let dir = tempfile::tempdir().expect("create directory");
        let directory = EfivarFileName::new("Directory", EFI_GLOBAL_VARIABLE);
        let fifo = EfivarFileName::new("Fifo", EFI_GLOBAL_VARIABLE);
        fs::create_dir(dir.path().join(&directory)).expect("create a directory");
        nix::unistd::mkfifo(&dir.path().join(&fifo), nix::sys::stat::Mode::S_IRWXU)
            .expect("create a FIFO");
        // a writer, so that an open of the FIFO that is not O_PATH returns instead of blocking
        let _writer = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.path().join(&fifo))
            .expect("hold the FIFO open");

        for (case, name) in [("directory", directory), ("FIFO", fifo)] {
            let error = open_efivar(dir.path(), &name).expect_err("open a non-regular file");

            assert_eq!(
                error.to_string(),
                format!(
                    "efivar file '{}' is not a regular file",
                    dir.path().join(&name).display()
                ),
                "{case}"
            );
        }
    }

    /// open_efivar opens no non-regular file: the check is Metadata::is_file of an O_PATH
    /// descriptor, false for a device node as for the directory, FIFO and symlink here, which a
    /// test can create without root.
    #[test]
    fn open_efivar_opens_no_non_regular_file() {
        let dir = tempfile::tempdir().expect("create directory");
        let regular = EfivarFileName::new("Setup", EFI_GLOBAL_VARIABLE);
        let directory = EfivarFileName::new("Directory", EFI_GLOBAL_VARIABLE);
        let fifo = EfivarFileName::new("Fifo", EFI_GLOBAL_VARIABLE);
        let symlink = EfivarFileName::new("Symlink", EFI_GLOBAL_VARIABLE);
        fs::write(dir.path().join(&regular), [7, 0, 0, 0]).expect("write the efivar file");
        fs::create_dir(dir.path().join(&directory)).expect("create a directory");
        nix::unistd::mkfifo(&dir.path().join(&fifo), nix::sys::stat::Mode::S_IRWXU)
            .expect("create a FIFO");
        std::os::unix::fs::symlink(&regular, dir.path().join(&symlink)).expect("create a symlink");
        // a writer, so that an open of the FIFO that is not O_PATH returns instead of blocking
        let _writer = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(dir.path().join(&fifo))
            .expect("hold the FIFO open");
        let opens = Inotify::init(InitFlags::IN_NONBLOCK).expect("create an inotify instance");
        opens
            .add_watch(dir.path(), AddWatchFlags::IN_OPEN)
            .expect("watch the opens in the directory");

        open_efivar(dir.path(), &regular).expect("open the regular file");
        for (case, name) in [
            ("directory", &directory),
            ("FIFO", &fifo),
            ("symlink", &symlink),
        ] {
            let opened = open_efivar(dir.path(), name);

            assert!(opened.is_err(), "{case}: {opened:?}");
        }

        let opened: Vec<OsString> = match opens.read_events() {
            Ok(events) => events.into_iter().filter_map(|event| event.name).collect(),
            Err(Errno::EAGAIN) => Vec::new(),
            Err(error) => panic!("read the inotify events: {error}"),
        };
        assert_eq!(
            opened,
            [OsString::from(regular.to_string())],
            "opened files"
        );
    }

    /// reopen opens the file that open_efivar checked, though another now has its path.
    #[test]
    fn reopen_reads_the_located_file_not_its_path() {
        let dir = tempfile::tempdir().expect("create directory");
        let name = EfivarFileName::new("Setup", EFI_GLOBAL_VARIABLE);
        let path = dir.path().join(&name);
        fs::write(&path, b"checked").expect("write the efivar file");
        let location = locate(&path).expect("locate the efivar file");
        fs::write(dir.path().join("swapped"), b"swapped").expect("write another file");
        fs::rename(dir.path().join("swapped"), &path).expect("swap the efivar file");
        let mut contents = String::new();

        reopen(&location)
            .expect("reopen the located file")
            .read_to_string(&mut contents)
            .expect("read the located file");

        assert_eq!(contents, "checked", "contents");
    }

    #[test]
    fn reopen_error_asks_for_proc_only_when_it_is_missing() {
        let path =
            Path::new(EFIVARS_MOUNT_POINT).join(EfivarFileName::new("Setup", EFI_GLOBAL_VARIABLE));

        for (case, kind, through) in [
            (
                "missing",
                io::ErrorKind::NotFound,
                "/proc/self/fd, which is missing: is /proc mounted?",
            ),
            (
                "would block on a lease",
                io::ErrorKind::WouldBlock,
                "/proc/self/fd",
            ),
        ] {
            let error = reopen_error(&path, io::Error::from(kind));

            assert_eq!(
                error.to_string(),
                format!(
                    "failed to open efivar file '{}' through {through}",
                    path.display()
                ),
                "{case}"
            );
            assert_eq!(
                error
                    .root_cause()
                    .downcast_ref::<io::Error>()
                    .map(io::Error::kind),
                Some(kind),
                "{case}: cause"
            );
        }
    }

    #[test]
    fn directory_source_must_be_a_directory() {
        let dir = tempfile::tempdir().expect("create directory");
        let file = dir.path().join("file");
        fs::write(&file, b"").expect("write a file");
        let missing = dir.path().join("missing");

        for (case, source) in [
            ("System", EfivarSource::System),
            ("Disabled", EfivarSource::Disabled),
            (
                "directory",
                EfivarSource::Directory(dir.path().to_path_buf()),
            ),
        ] {
            source
                .validate()
                .unwrap_or_else(|error| panic!("validate {case}: {error:#}"));
        }
        for (case, path) in [("file", &file), ("missing", &missing)] {
            let error = EfivarSource::Directory(path.clone())
                .validate()
                .expect_err("validate a directory that is not one");

            assert_eq!(
                error.to_string(),
                format!("efivars directory {} is not a directory", path.display()),
                "{case}"
            );
        }
    }

    #[test]
    fn disabled_source_reads_no_efivar() {
        let mut reader =
            EfivarReader::new(EfivarSource::Disabled).expect("create a reader without efivars");
        let range = EfivarRange {
            name: EfivarFileName::new("Setup", EFI_GLOBAL_VARIABLE),
            size: 1,
        };

        let error = reader.read(range).expect_err("read without efivars");

        assert_eq!(
            error.downcast_ref::<EfivarsNotRead>(),
            Some(&EfivarsNotRead),
            "Disabled: {error:#}"
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
