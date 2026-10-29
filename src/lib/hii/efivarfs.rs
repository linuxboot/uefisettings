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
use std::fs::File;
use std::io;
use std::io::Read;
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

use crate::hii::package::Guid;

pub(super) const EFIVARS_MOUNT_POINT: &str = "/sys/firmware/efi/efivars";
pub(super) const EFIVARFS_HEADER_SIZE: usize = std::mem::size_of::<u32>();

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
pub(super) fn open_efivar(dir: &Path, name: &EfivarFileName) -> Result<File> {
    let path = dir.join(name);
    File::open(&path).map_err(|error| open_error(&path, name, error))
}

/// open_efivar's error for `error` from opening the efivar file `name` at `path`.
fn open_error(path: &Path, name: &EfivarFileName, error: io::Error) -> anyhow::Error {
    match error.kind() {
        io::ErrorKind::NotFound => EfivarNotFound { name: name.clone() }.into(),
        _ => anyhow::Error::new(error)
            .context(format!("failed to open efivar file '{}'", path.display())),
    }
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
    read_efivarfs_bytes(&mut file, size.into()).with_context(|| {
        format!(
            "failed to read bytes from sysfs efivars '{}' of size specified by varstore in hiidb",
            dir.join(name).display()
        )
    })
}

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
    efivars: PathBuf,
    pub(super) outcomes: HashMap<EfivarRange, Result<Vec<u8>>>,
}

impl Default for EfivarReader {
    /// Reads this machine's efivarfs.
    fn default() -> Self {
        Self::new(PathBuf::from(EFIVARS_MOUNT_POINT))
    }
}

impl EfivarReader {
    /// Reads the efivar files in `efivars`.
    pub(super) fn new(efivars: PathBuf) -> Self {
        Self {
            efivars,
            outcomes: HashMap::new(),
        }
    }

    /// read_efivar of `range` in these efivars, read once.
    pub(super) fn read(
        &mut self,
        range: EfivarRange,
    ) -> std::result::Result<&[u8], &anyhow::Error> {
        let efivars = &self.efivars;
        self.outcomes
            .entry(range)
            .or_insert_with_key(|range| read_efivar(efivars, &range.name, range.size))
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
    use std::fs;
    use std::io::Read;
    use std::path::Component;

    use anyhow::Context;
    use anyhow::Result;

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
