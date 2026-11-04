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

//! Files in efivarfs format, as efivarfs and copies of it hold: their names, and how to open
//! and read them.

use std::ffi::OsStr;
use std::fmt;
use std::fs;
use std::fs::File;
use std::fs::OpenOptions;
use std::io;
use std::io::Read;
#[cfg(any(target_os = "macos", test))]
use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::OpenOptionsExt;
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::io::FromRawFd;
use std::path::Path;
use std::path::PathBuf;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use log::debug;
#[cfg(target_os = "linux")]
use nix::fcntl::OFlag;
#[cfg(target_os = "linux")]
use nix::sys::stat::Mode;
use thiserror::Error;

use crate::hii::variables::FirmwareVariables;
use crate::hii::variables::VariableInterface;
use crate::hii::variables::VariableKey;
use crate::hii::variables::VariableNotFound;
use crate::hii::variables::VariableReach;
use crate::hii::variables::EFIVARFS_HEADER_SIZE;

/// The directory of this process's file descriptors, through which reopen opens a located file.
#[cfg(target_os = "linux")]
const PROC_SELF_FD: &str = "/proc/self/fd";
/// The largest efivar file that read_efivar_file reads, far above EDK2's largest EFI variables:
/// PcdMaxVariableSize is 0x400 by default (MdeModulePkg.dec) and 0x8400 in a 4 MiB OVMF
/// (OvmfPkgX64.dsc), as of edk2-stable202508.
#[cfg(any(target_os = "linux", test))]
const MAX_EFIVAR_FILE_SIZE: u64 = 16 * 1024 * 1024;
/// What efivarfs, and so a copy of it, reaches.
pub(super) const EFIVARFS_REACH: VariableReach = VariableReach::Runtime;
/// The interface of efivarfs, and so of a copy of it.
pub(super) const EFIVARFS_INTERFACE: VariableInterface = VariableInterface::Efivarfs;

/// The name of the efivar file of a variable, as VariableKey displays it: always exactly one path
/// component.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(super) struct EfivarFileName(String);

impl From<&VariableKey> for EfivarFileName {
    fn from(key: &VariableKey) -> Self {
        Self(key.to_string())
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

/// An efivar file missing from its directory.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("no EFI variable {name}")]
pub(super) struct EfivarNotFound {
    pub(super) name: EfivarFileName,
}

/// Opens the efivar file `name` in `dir` for reading, as open_regular_file does. A missing file
/// is EfivarNotFound without context, so the error names the variable.
pub(super) fn open_efivar(dir: &Path, name: &EfivarFileName) -> Result<File> {
    open_regular_file(&dir.join(name), "efivar file")?
        .ok_or_else(|| EfivarNotFound { name: name.clone() }.into())
}

/// Opens the regular file at `path`, which errors call `noun`, for reading; None if it does not
/// exist. A symlink or other non-regular file is an error, so a directory of efivar files cannot
/// send a read elsewhere or block it. The check is on the file that is then read: an O_PATH
/// descriptor opens no file (open(2)), so a device node runs no driver open, and reopening it
/// through /proc/self/fd opens the very file checked, whatever the path names by then.
#[cfg(target_os = "linux")]
pub(super) fn open_regular_file(path: &Path, noun: &str) -> Result<Option<File>> {
    let location = match locate(path) {
        Ok(location) => location,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(open_error(path, noun, error)),
    };
    let metadata = location
        .metadata()
        .with_context(|| format!("failed to stat {noun} '{}'", path.display()))?;
    check_regular_file(path, &metadata, noun)?;
    reopen(&location)
        .map(Some)
        .map_err(|error| reopen_error(path, noun, error))
}

/// An O_PATH descriptor of `path`, of the link itself if it is a symlink.
#[cfg(target_os = "linux")]
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
#[cfg(target_os = "linux")]
fn reopen(location: &File) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        // a file under a write lease fails at once instead of waiting lease-break-time
        // (Linux v7.2 fs/locks.c); efivarfs_file_read() ignores O_NONBLOCK
        .custom_flags(libc::O_NONBLOCK)
        .open(Path::new(PROC_SELF_FD).join(location.as_raw_fd().to_string()))
}

/// Opens the regular file at `path`, which errors call `noun`, for reading; None if it does not
/// exist. A symlink or other non-regular file is an error, so a directory of efivar files cannot
/// send a read elsewhere or block it. xnu has no O_PATH (xnu-12377.121.6 bsd/sys/fcntl.h), so
/// the check is on lstat, before the open: a node there that is not a regular file runs no
/// driver open. One swapped in after the lstat does run its driver open, before the check that
/// the opened file is the one checked, by device and inode, refuses it; O_NOFOLLOW refuses a
/// symlink swapped in, and O_NONBLOCK keeps a FIFO swapped in from blocking the open.
#[cfg(target_os = "macos")]
pub(super) fn open_regular_file(path: &Path, noun: &str) -> Result<Option<File>> {
    let checked = match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        result => result.with_context(|| format!("failed to stat {noun} '{}'", path.display()))?,
    };
    check_regular_file(path, &checked, noun)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| open_error(path, noun, error))?;
    let opened = file
        .metadata()
        .with_context(|| format!("failed to stat {noun} '{}'", path.display()))?;
    check_same_file(path, noun, &checked, &opened)?;
    Ok(Some(file))
}

/// Fails unless `opened`, of the `noun` opened at `path`, is a regular file with the device and
/// inode of `checked`: another file swapped in after the check is refused, and so is a
/// non-regular file that reuses the inode of one removed since.
#[cfg(any(target_os = "macos", test))]
fn check_same_file(
    path: &Path,
    noun: &str,
    checked: &fs::Metadata,
    opened: &fs::Metadata,
) -> Result<()> {
    check_regular_file(path, opened, noun)?;
    if (opened.dev(), opened.ino()) != (checked.dev(), checked.ino()) {
        return Err(anyhow!(
            "{noun} '{}' changed while it was opened",
            path.display()
        ));
    }
    Ok(())
}

/// Fails unless `metadata`, of the `noun` at `path`, is a regular file's.
fn check_regular_file(path: &Path, metadata: &fs::Metadata, noun: &str) -> Result<()> {
    if !metadata.is_file() {
        return Err(anyhow!("{noun} '{}' is not a regular file", path.display()));
    }
    Ok(())
}

/// open_regular_file's error for `error` from opening the `noun` at `path`.
fn open_error(path: &Path, noun: &str, error: io::Error) -> anyhow::Error {
    anyhow::Error::new(error).context(format!("failed to open {noun} '{}'", path.display()))
}

/// open_regular_file's error for `error` from reopening the `noun` at `path`.
#[cfg(target_os = "linux")]
fn reopen_error(path: &Path, noun: &str, error: io::Error) -> anyhow::Error {
    let hint = match error.kind() {
        // the descriptor is open, so NotFound means /proc/self/fd is missing
        io::ErrorKind::NotFound => ", which is missing: is /proc mounted?",
        _ => "",
    };
    anyhow::Error::new(error).context(format!(
        "failed to open {noun} '{}' through {PROC_SELF_FD}{hint}",
        path.display()
    ))
}

pub(super) fn read_efivarfs_bytes<R: Read>(reader: &mut R, payload_size: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; EFIVARFS_HEADER_SIZE + payload_size];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

/// Reads the efivar file `name` in `dir`: its attributes field and `size` payload bytes.
pub(super) fn read_efivar(dir: &Path, name: &EfivarFileName, size: u16) -> Result<Vec<u8>> {
    let mut file = open_efivar(dir, name)?;
    debug!("buffer size: {}", size);
    // efivarfs prepends a 4-byte attributes field to the variable payload.
    read_efivarfs_bytes(&mut file, size.into())
        .with_context(|| format!("failed to read efivar file '{}'", dir.join(name).display()))
}

/// The bytes of the efivar `file`, of `size` bytes by its metadata, in one read() unless it grew
/// since: each efivarfs read() reads the whole variable from the firmware (Linux v7.2
/// fs/efivarfs/file.c efivarfs_file_read()). A file of more than MAX_EFIVAR_FILE_SIZE bytes, by
/// its metadata or as read, is an error.
// efivarfs writes and dump-efivars read whole files; the tests write dumps on any build
#[cfg(any(target_os = "linux", test))]
pub(super) fn read_efivar_file<R: Read>(file: R, size: u64) -> io::Result<Vec<u8>> {
    if size > MAX_EFIVAR_FILE_SIZE {
        return Err(efivar_file_too_large());
    }
    // one byte past the maximum, so that a file that grew past it shows
    let mut file = file.take(MAX_EFIVAR_FILE_SIZE + 1);
    let size = usize::try_from(size).map_err(io::Error::other)?;
    // one byte more than its size, so that a read() that fills it shows the file grew
    let capacity = size.saturating_add(1);
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity)?;
    bytes.resize(capacity, 0);
    let read = loop {
        match file.read(&mut bytes) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => break result?,
        }
    };
    bytes.truncate(read);
    if read > size {
        file.read_to_end(&mut bytes)?;
    }
    if file.limit() == 0 {
        return Err(efivar_file_too_large());
    }
    Ok(bytes)
}

/// read_efivar_file's error for a file of more than MAX_EFIVAR_FILE_SIZE bytes.
#[cfg(any(target_os = "linux", test))]
fn efivar_file_too_large() -> io::Error {
    io::Error::new(
        io::ErrorKind::FileTooLarge,
        format!("longer than its maximum of {MAX_EFIVAR_FILE_SIZE} bytes"),
    )
}

/// `error`, with an EfivarNotFound of the efivar file of `key` as VariableNotFound; other errors
/// unchanged.
pub(super) fn as_variable_not_found(key: &VariableKey, error: anyhow::Error) -> anyhow::Error {
    match error.downcast::<EfivarNotFound>() {
        Ok(_) => VariableNotFound(key.clone()).into(),
        Err(error) => error,
    }
}

/// A copy of efivarfs in `dir`, such as dump-efivars writes, as FirmwareVariables: it reads the
/// efivar file of each variable by its exact name and takes no writes.
pub(super) struct EfivarCopy {
    dir: PathBuf,
}

impl EfivarCopy {
    pub(super) fn new(dir: PathBuf) -> Self {
        Self { dir }
    }
}

impl FirmwareVariables for EfivarCopy {
    fn reach(&self) -> VariableReach {
        EFIVARFS_REACH
    }

    fn interface(&self) -> VariableInterface {
        EFIVARFS_INTERFACE
    }

    fn read(&self, key: &VariableKey, size: u16) -> Result<Vec<u8>> {
        let name = EfivarFileName::from(key);
        check_exact_name(&self.dir, &name)
            .and_then(|()| read_efivar(&self.dir, &name, size))
            .map_err(|error| as_variable_not_found(key, error))
    }

    fn write_at(
        &self,
        _key: &VariableKey,
        _size: u16,
        _offset: u16,
        _encoded: &[u8],
    ) -> Result<()> {
        Err(CopyOfEfivars.into())
    }
}

/// Fails with EfivarNotFound unless `dir` lists an entry named exactly `name`: a case-insensitive
/// file system, such as APFS unless formatted case-sensitive, opens a name that differs only in
/// case, which is another variable's file. Copied onto such a file system, two files whose names
/// differ only in case become one, which no check can detect.
fn check_exact_name(dir: &Path, name: &EfivarFileName) -> Result<()> {
    let listed = lists_entry(dir, AsRef::<Path>::as_ref(name).as_os_str())
        .with_context(|| format!("failed to list efivars directory '{}'", dir.display()))?;
    if !listed {
        return Err(EfivarNotFound { name: name.clone() }.into());
    }
    Ok(())
}

/// Whether `dir` lists an entry of exactly the name `name`.
fn lists_entry(dir: &Path, name: &OsStr) -> io::Result<bool> {
    for entry in fs::read_dir(dir)? {
        if entry?.file_name() == name {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Why an EfivarCopy refuses a write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("a copy of efivars takes no writes")]
struct CopyOfEfivars;

#[cfg(test)]
pub mod tests {
    use std::collections::VecDeque;
    use std::ffi::OsStr;
    #[cfg(target_os = "linux")]
    use std::ffi::OsString;
    use std::path::Component;

    #[cfg(target_os = "linux")]
    use nix::errno::Errno;
    #[cfg(target_os = "linux")]
    use nix::sys::inotify::AddWatchFlags;
    #[cfg(target_os = "linux")]
    use nix::sys::inotify::InitFlags;
    #[cfg(target_os = "linux")]
    use nix::sys::inotify::Inotify;

    use super::*;
    #[cfg(target_os = "linux")]
    use crate::hii::efivarfs::EFIVARS_MOUNT_POINT;
    use crate::hii::package::Guid;
    use crate::hii::variables::tests::variable_key;
    use crate::hii::variables::tests::EFI_GLOBAL_VARIABLE;
    use crate::hii::variables::tests::NV_BS_RT;
    use crate::hii::variables::EfivarSource;
    use crate::hii::variables::FirmwareVariables;

    impl EfivarFileName {
        /// The efivar file of the variable `name` of `guid`.
        pub(crate) fn new(name: &str, guid: Guid) -> Self {
            Self::from(&VariableKey {
                name: name.to_string(),
                guid,
            })
        }
    }

    /// Attributes 7, then payload bytes 1 to 10.
    pub(crate) const SETUP: [u8; 14] = [7, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    /// SETUP's size, as its metadata gives it.
    const SETUP_SIZE: u64 = SETUP.len() as u64;
    /// What open_regular_file does first to a path, which its error there names: Linux's opener
    /// opens an O_PATH descriptor, macOS's stats the path.
    #[cfg(target_os = "linux")]
    pub(crate) const FIRST_STEP: &str = "open";
    #[cfg(target_os = "macos")]
    pub(crate) const FIRST_STEP: &str = "stat";

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
    fn efivar_files_read_whole() {
        let dir = tempfile::tempdir().expect("create efivars directory");
        for (case, contents) in [("Setup", &SETUP[..]), ("empty file", &[][..])] {
            let path = dir.path().join(case);
            fs::write(&path, contents).expect("write the efivar file");
            let file = File::open(&path).expect("open the efivar file");
            let size = file.metadata().expect("stat the efivar file").len();

            let bytes = read_efivar_file(&file, size).expect("read the efivar file");

            assert_eq!(bytes, contents, "{case}");
        }
    }

    /// A file longer than its metadata says, as an efivar written after open_efivar's fstat,
    /// still reads whole: procfs gives /proc/version the size 0.
    #[test]
    // procfs, which macOS lacks
    #[cfg(target_os = "linux")]
    fn efivar_files_longer_than_their_size_read_whole() {
        let path = Path::new("/proc/version");
        let file = File::open(path).expect("open /proc/version");
        let size = file.metadata().expect("stat /proc/version").len();
        assert_eq!(size, 0, "size");

        let bytes = read_efivar_file(&file, size).expect("read /proc/version");

        assert!(bytes.len() > 1, "/proc/version: {bytes:?}");
        assert_eq!(
            bytes,
            fs::read(path).expect("read /proc/version"),
            "contents"
        );
    }

    /// A reader that gives one of `results` per read(), then end of file, counting its read()s.
    struct ScriptedReader {
        results: VecDeque<io::Result<Vec<u8>>>,
        reads: usize,
    }

    impl ScriptedReader {
        fn new(results: Vec<io::Result<Vec<u8>>>) -> Self {
            Self {
                results: results.into(),
                reads: 0,
            }
        }
    }

    impl Read for ScriptedReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            let chunk = match self.results.pop_front() {
                None => return Ok(0),
                Some(result) => result?,
            };
            buf.get_mut(..chunk.len())
                .expect("the scripted chunk fits the read() buffer")
                .copy_from_slice(&chunk);
            Ok(chunk.len())
        }
    }

    #[test]
    fn efivar_file_reads_in_one_read() {
        let whole: &[u8] = &SETUP;
        for (case, results, expected) in [
            ("whole", vec![Ok(SETUP.to_vec())], whole),
            (
                "short read, as end of file",
                vec![Ok(SETUP[..6].to_vec()), Ok(SETUP[6..].to_vec())],
                &SETUP[..6],
            ),
        ] {
            let mut reader = ScriptedReader::new(results);

            let bytes = read_efivar_file(&mut reader, SETUP_SIZE).expect("read the efivar file");

            assert_eq!(bytes, expected, "{case}: bytes");
            assert_eq!(reader.reads, 1, "{case}: read() calls");
        }
    }

    #[test]
    fn efivar_file_read_retries_eintr() {
        let mut reader = ScriptedReader::new(vec![
            Err(io::ErrorKind::Interrupted.into()),
            Ok(SETUP.to_vec()),
        ]);

        let bytes = read_efivar_file(&mut reader, SETUP_SIZE).expect("read the efivar file");

        assert_eq!(bytes, SETUP, "bytes");
        assert_eq!(
            reader.reads, 2,
            "read() calls: the interrupted one and the read"
        );
    }

    #[test]
    fn efivar_file_grown_since_its_metadata_reads_to_the_end() {
        let mut reader =
            ScriptedReader::new(vec![Ok(SETUP[..5].to_vec()), Ok(SETUP[5..].to_vec())]);

        let bytes = read_efivar_file(&mut reader, 4).expect("read the efivar file");

        assert_eq!(bytes, SETUP, "bytes");
        assert_eq!(
            reader.reads, 3,
            "read() calls: size + 1 bytes, the rest, end of file"
        );
    }

    /// A file of more than MAX_EFIVAR_FILE_SIZE bytes by its metadata is refused unread.
    #[test]
    fn efivar_file_larger_than_its_maximum_is_refused_unread() {
        let mut reader = ScriptedReader::new(vec![Ok(SETUP.to_vec())]);

        let error = read_efivar_file(&mut reader, MAX_EFIVAR_FILE_SIZE + 1)
            .expect_err("read a file larger than the maximum");

        assert_eq!(
            error.kind(),
            io::ErrorKind::FileTooLarge,
            "a file larger than the maximum by its metadata: {error}"
        );
        assert_eq!(reader.reads, 0, "read() calls");
    }

    /// A file that grew since its metadata reads to the end up to MAX_EFIVAR_FILE_SIZE bytes, and
    /// is refused once it holds more.
    #[test]
    fn efivar_file_grown_past_its_maximum_is_refused() {
        let max = usize::try_from(MAX_EFIVAR_FILE_SIZE).expect("a usize maximum");
        for (case, length, want) in [
            ("grown to the maximum", MAX_EFIVAR_FILE_SIZE, Some(max)),
            (
                "grown one byte past the maximum",
                MAX_EFIVAR_FILE_SIZE + 1,
                None,
            ),
        ] {
            let read = read_efivar_file(io::repeat(7).take(length), SETUP_SIZE);

            match (read, want) {
                (Ok(bytes), Some(want)) => assert_eq!(bytes.len(), want, "{case}: length"),
                (Err(error), None) => {
                    assert_eq!(error.kind(), io::ErrorKind::FileTooLarge, "{case}: {error}")
                }
                (read, want) => panic!(
                    "{case}: read {:?} bytes, want {want:?}",
                    read.map(|bytes| bytes.len())
                ),
            }
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
                "failed to {FIRST_STEP} efivar file '{}'",
                not_a_dir.path().join(&name).display()
            ),
            "message of opening in a file"
        );
    }

    #[test]
    fn open_error_keeps_permission_errors_with_the_path() {
        let name = EfivarFileName::new("Setup", EFI_GLOBAL_VARIABLE);
        let path = Path::new("efivars").join(&name);
        let denied = io::Error::from(io::ErrorKind::PermissionDenied);

        let error = open_error(&path, "efivar file", denied);

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
    // inotify, which macOS lacks; its opener checks before it opens
    #[cfg(target_os = "linux")]
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
    // reopen, of Linux's opener: macOS lacks /proc/self/fd
    #[cfg(target_os = "linux")]
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
    // reopen_error, of Linux's opener: macOS lacks /proc/self/fd
    #[cfg(target_os = "linux")]
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
            let error = reopen_error(&path, "efivar file", io::Error::from(kind));

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

    /// check_same_file takes the metadata of the file checked, and refuses that of another file
    /// and that of a non-regular file.
    #[test]
    fn check_same_file_refuses_another_file() {
        let dir = tempfile::tempdir().expect("create directory");
        let path = dir
            .path()
            .join(EfivarFileName::new("Setup", EFI_GLOBAL_VARIABLE));
        let other = dir.path().join("other");
        fs::write(&path, b"checked").expect("write the efivar file");
        fs::write(&other, b"other").expect("write another file");
        let metadata = |path: &Path| fs::symlink_metadata(path).expect("stat a file");
        let checked = metadata(&path);

        check_same_file(&path, "efivar file", &checked, &metadata(&path))
            .expect("check the same file");
        for (case, opened, refusal) in [
            (
                "another file",
                metadata(&other),
                "changed while it was opened",
            ),
            ("a directory", metadata(dir.path()), "is not a regular file"),
        ] {
            let error = check_same_file(&path, "efivar file", &checked, &opened).expect_err(case);

            assert_eq!(
                error.to_string(),
                format!("efivar file '{}' {refusal}", path.display()),
                "{case}"
            );
        }
    }

    /// A copy of efivars reads the efivar file of each variable by its exact name: a
    /// case-insensitive file system, such as APFS unless formatted case-sensitive, opens a name
    /// that differs only in case, which is another variable's file.
    #[test]
    fn exact_name_refuses_a_case_variant() {
        let dir = tempfile::tempdir().expect("create efivars directory");
        let setup = variable_key("Setup");
        let bytes = [&NV_BS_RT.to_ne_bytes()[..], &[1]].concat();
        fs::write(dir.path().join(EfivarFileName::from(&setup)), &bytes)
            .expect("write the efivar file");
        let variables = EfivarSource::Directory(dir.path().to_path_buf())
            .into_variables()
            .expect("make the variables of the directory");

        assert_eq!(
            variables.read(&setup, 1).expect("read Setup"),
            bytes,
            "Setup"
        );
        let variant = variable_key("SETUP");
        let error = variables.read(&variant, 1).expect_err("read SETUP");
        assert_eq!(
            error.downcast_ref::<VariableNotFound>(),
            Some(&VariableNotFound(variant)),
            "SETUP: {error:#}"
        );
    }

    /// check_exact_name compares the bytes of each name it lists, on any file system.
    #[test]
    fn exact_name_check_is_case_sensitive() {
        let dir = tempfile::tempdir().expect("create efivars directory");
        let name = EfivarFileName::new("Setup", EFI_GLOBAL_VARIABLE);
        fs::write(dir.path().join(&name), b"").expect("write the efivar file");

        check_exact_name(dir.path(), &name).expect("check the exact name");
        let variant = EfivarFileName::new("SETUP", EFI_GLOBAL_VARIABLE);
        let error = check_exact_name(dir.path(), &variant).expect_err("check a case variant");
        assert_eq!(
            error.downcast_ref::<EfivarNotFound>(),
            Some(&EfivarNotFound { name: variant }),
            "case variant: {error:#}"
        );
    }

    /// A copy of efivars reads an efivar file only through a listing of its directory: one that
    /// it cannot list fails the read, though the file would open.
    #[test]
    fn copy_reads_only_listed_entries() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().expect("create efivars directory");
        let setup = variable_key("Setup");
        let bytes = [&NV_BS_RT.to_ne_bytes()[..], &[1]].concat();
        fs::write(dir.path().join(EfivarFileName::from(&setup)), &bytes)
            .expect("write the efivar file");
        let copy = EfivarCopy::new(dir.path().to_path_buf());
        // search and write but no read, which root has anyway: the tests run as a user
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o300))
            .expect("make the directory unlistable");

        let unlisted = copy.read(&setup, 1);

        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))
            .expect("make the directory listable");
        let error = unlisted.expect_err("read through an unlistable directory");
        assert_eq!(
            error.to_string(),
            format!(
                "failed to list efivars directory '{}'",
                dir.path().display()
            ),
            "unlistable: {error:#}"
        );
        assert_eq!(
            error
                .root_cause()
                .downcast_ref::<io::Error>()
                .map(io::Error::kind),
            Some(io::ErrorKind::PermissionDenied),
            "unlistable: cause"
        );
        assert_eq!(copy.read(&setup, 1).expect("read Setup"), bytes, "listable");
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
}
