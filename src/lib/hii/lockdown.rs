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

//! The kernel lockdown mode, which refuses opening /dev/mem or /proc/kcore.

use std::fmt;
use std::fs;
use std::io;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Result;
use nix::errno::Errno;
use nix::sys::statfs::statfs;
use nix::sys::statfs::FsType;
use nix::sys::statfs::SECURITYFS_MAGIC;
use thiserror::Error;

use crate::hii::memory_access_denied::DenialCause;
use crate::hii::memory_access_denied::MemoryAccessDenied;
use crate::hii::memory_access_denied::MemoryDevice;
use crate::hii::memory_access_denied::MemoryOperation;

/// The kernel's lockdown mode, where securityfs is mounted (Linux v6.11
/// security/lockdown/lockdown.c lockdown_read()).
pub(super) const LOCKDOWN_PATH: &str = "/sys/kernel/security/lockdown";

/// A kernel lockdown mode (Linux v6.11 security/lockdown/lockdown.c lockdown_levels).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LockdownMode {
    /// No lockdown.
    None,
    /// Disables what lets userspace modify the running kernel, /dev/mem among it
    /// (Documentation/admin-guide/kernel-parameters.txt lockdown=).
    Integrity,
    /// Also disables what lets userspace extract confidential information from the kernel,
    /// /proc/kcore among it.
    Confidentiality,
}

impl LockdownMode {
    /// Whether this mode refuses opening `device`: integrity refuses the reasons up to
    /// LOCKDOWN_INTEGRITY_MAX, such as LOCKDOWN_DEV_MEM, and confidentiality also those up to
    /// LOCKDOWN_CONFIDENTIALITY_MAX, such as LOCKDOWN_KCORE (Linux v6.11
    /// include/linux/security.h; drivers/char/mem.c open_port(), fs/proc/kcore.c open_kcore()).
    pub(super) fn refuses(self, device: MemoryDevice) -> bool {
        match (self, device) {
            (Self::None, _) => false,
            (Self::Integrity, MemoryDevice::DevMem) => true,
            (Self::Integrity, MemoryDevice::Kcore) => false,
            (Self::Confidentiality, _) => true,
        }
    }
}

impl fmt::Display for LockdownMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::None => "none",
            Self::Integrity => "integrity",
            Self::Confidentiality => "confidentiality",
        })
    }
}

/// Why the kernel lockdown mode is unknown.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LockdownUnknown {
    /// The lockdown file marks no mode as active.
    #[error("no active lockdown mode in {0:?}")]
    NoActiveMode(String),
    /// The lockdown file marks a mode that this build does not know as active.
    #[error("unknown lockdown mode {mode:?} in {contents:?}")]
    UnknownMode { mode: String, contents: String },
    /// The lockdown file is missing from this directory, which is not securityfs: the lockdown
    /// LSM may have created it in a securityfs that is not mounted there.
    #[error(
        "{} is not securityfs, so the kernel lockdown mode is unknown; mount securityfs at {}",
        .0.display(),
        .0.display()
    )]
    SecurityfsNotMounted(PathBuf),
    /// The lockdown file's directory is missing too, which securityfs creates
    /// (security/inode.c securityfs_init()): the kernel has no securityfs (CONFIG_SECURITYFS).
    #[error(
        "{} does not exist, so the kernel has no securityfs and its lockdown mode is unknown; use \
         another HII source",
        .0.display()
    )]
    NoSecurityfs(PathBuf),
    /// The lockdown file, or its directory, cannot be read. Display renders the error rather
    /// than source(), as mark_refused_open shows this under MemoryAccessDenied as an anyhow
    /// context, whose source() anyhow does not follow.
    #[error("cannot read the kernel lockdown mode at {}: {1}", .0.display())]
    Unreadable(PathBuf, io::Error),
}

/// The kernel lockdown mode in the lockdown file `path` (LOCKDOWN_PATH). A missing file means
/// none only where securityfs is mounted at its directory, which shows that the kernel has no
/// lockdown LSM: that LSM creates the file there (security/lockdown/lockdown.c).
pub(super) fn read_lockdown_mode(path: &Path) -> Result<LockdownMode, LockdownUnknown> {
    match fs::read_to_string(path) {
        Ok(contents) => parse_lockdown_mode(&contents),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let dir = path.parent().unwrap_or(path);
            mode_unless_securityfs(dir, statfs(dir).map(|stat| stat.filesystem_type()))
        }
        Err(error) => Err(LockdownUnknown::Unreadable(path.to_owned(), error)),
    }
}

/// The active mode in `contents` of LOCKDOWN_PATH, such as `none [integrity] confidentiality`.
fn parse_lockdown_mode(contents: &str) -> Result<LockdownMode, LockdownUnknown> {
    let mode = contents
        .split_whitespace()
        .find_map(|mode| mode.strip_prefix('[')?.strip_suffix(']'))
        .ok_or_else(|| LockdownUnknown::NoActiveMode(contents.to_owned()))?;
    match mode {
        "none" => Ok(LockdownMode::None),
        "integrity" => Ok(LockdownMode::Integrity),
        "confidentiality" => Ok(LockdownMode::Confidentiality),
        mode => Err(LockdownUnknown::UnknownMode {
            mode: mode.to_owned(),
            contents: contents.to_owned(),
        }),
    }
}

/// The lockdown mode none for a missing lockdown file in `dir` if `dir_type`, the statfs()
/// result of `dir`, is securityfs.
fn mode_unless_securityfs(
    dir: &Path,
    dir_type: nix::Result<FsType>,
) -> Result<LockdownMode, LockdownUnknown> {
    match dir_type {
        Ok(fs_type) if fs_type == SECURITYFS_MAGIC => Ok(LockdownMode::None),
        Ok(_) => Err(LockdownUnknown::SecurityfsNotMounted(dir.to_owned())),
        Err(Errno::ENOENT) => Err(LockdownUnknown::NoSecurityfs(dir.to_owned())),
        Err(errno) => Err(LockdownUnknown::Unreadable(dir.to_owned(), errno.into())),
    }
}

/// Fails, before anything opens `device`, if the lockdown mode in `lockdown` (LOCKDOWN_PATH)
/// refuses opening it, or is unknown (LockdownUnknown); no other way to the same memory then
/// retries.
pub(super) fn refuse_locked_down(device: MemoryDevice, lockdown: &Path) -> Result<()> {
    let mode = read_lockdown_mode(lockdown)?;
    match mode.refuses(device) {
        true => Err(MemoryAccessDenied {
            device,
            operation: MemoryOperation::Open,
            cause: DenialCause::Lockdown(mode),
        }
        .into()),
        false => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The lockdown mode none.
    const NO_LOCKDOWN: &str = "[none] integrity confidentiality\n";

    /// parse_lockdown_mode reads the active mode, and fails on contents that mark none or one
    /// that it does not know.
    #[test]
    fn parse_lockdown_mode_reads_the_active_mode() {
        for (contents, want) in [
            (NO_LOCKDOWN, LockdownMode::None),
            (
                "none [integrity] confidentiality\n",
                LockdownMode::Integrity,
            ),
            (
                "none integrity [confidentiality]\n",
                LockdownMode::Confidentiality,
            ),
        ] {
            let got = parse_lockdown_mode(contents)
                .unwrap_or_else(|error| panic!("{contents:?}: {error}"));

            assert_eq!(got, want, "{contents:?}");
        }

        for (contents, want) in [
            (
                "none integrity confidentiality\n",
                "no active lockdown mode in \"none integrity confidentiality\\n\"",
            ),
            (
                "none [secrecy]\n",
                "unknown lockdown mode \"secrecy\" in \"none [secrecy]\\n\"",
            ),
        ] {
            let error = parse_lockdown_mode(contents).expect_err(contents);

            assert_eq!(error.to_string(), want, "{contents:?}");
        }
    }

    /// A missing lockdown file means none only where securityfs shows it, in its directory;
    /// otherwise the mode is unknown and the error says what to do. A lockdown file or directory
    /// that cannot be read leaves it unknown too.
    #[test]
    fn read_lockdown_mode_is_none_only_where_securityfs_shows_it() {
        let dir = tempfile::tempdir().expect("create a directory");
        let path = dir.path().join("lockdown");
        fs::write(&path, NO_LOCKDOWN).expect("write lockdown");
        let got = read_lockdown_mode(&path).expect("read no lockdown");
        assert_eq!(got, LockdownMode::None, "none");

        // The temporary directory is not securityfs.
        let error = read_lockdown_mode(&dir.path().join("missing"))
            .expect_err("read a missing lockdown file outside securityfs");
        assert!(
            matches!(&error, LockdownUnknown::SecurityfsNotMounted(got) if got == dir.path()),
            "outside securityfs: {error}"
        );
        assert!(
            error
                .to_string()
                .ends_with(&format!("; mount securityfs at {}", dir.path().display())),
            "outside securityfs: {error}"
        );

        let no_dir = dir.path().join("security");
        let error = read_lockdown_mode(&no_dir.join("lockdown"))
            .expect_err("read a lockdown file without its directory");
        assert!(
            matches!(&error, LockdownUnknown::NoSecurityfs(got) if *got == no_dir),
            "no directory: {error}"
        );
        assert!(
            error.to_string().ends_with(
                "so the kernel has no securityfs and its lockdown mode is unknown; use another \
                 HII source"
            ),
            "no directory: {error}"
        );

        let error = read_lockdown_mode(dir.path()).expect_err("read a lockdown directory");
        assert!(
            matches!(
                &error,
                LockdownUnknown::Unreadable(path, source)
                    if path == dir.path() && source.raw_os_error() == Some(libc::EISDIR)
            ),
            "a directory: {error}"
        );
    }

    #[test]
    fn mode_unless_securityfs_passes_securityfs_only() {
        let dir = Path::new("/sys/kernel/security");
        let refusal = |dir_type| {
            mode_unless_securityfs(dir, dir_type)
                .err()
                .map(|error| format!("{:#}", anyhow::Error::new(error)))
        };
        assert_eq!(
            mode_unless_securityfs(dir, Ok(SECURITYFS_MAGIC)).ok(),
            Some(LockdownMode::None),
            "securityfs"
        );
        assert_eq!(
            refusal(Ok(nix::sys::statfs::SYSFS_MAGIC)),
            Some(
                "/sys/kernel/security is not securityfs, so the kernel lockdown mode is unknown; \
                 mount securityfs at /sys/kernel/security"
                    .to_owned()
            ),
            "sysfs"
        );
        assert_eq!(
            refusal(Err(Errno::ENOENT)),
            Some(
                "/sys/kernel/security does not exist, so the kernel has no securityfs and its \
                 lockdown mode is unknown; use another HII source"
                    .to_owned()
            ),
            "no directory"
        );
        assert_eq!(
            refusal(Err(Errno::EACCES)),
            Some(
                "cannot read the kernel lockdown mode at /sys/kernel/security: Permission denied \
                 (os error 13)"
                    .to_owned()
            ),
            "a statfs() error"
        );
    }

    /// refuse_locked_down refuses /dev/mem at integrity and confidentiality, /proc/kcore at
    /// confidentiality only, nothing at none, and anything while the mode is unknown.
    #[test]
    fn refuse_locked_down_refuses_by_mode_and_device() {
        let dir = tempfile::tempdir().expect("create a directory");
        let file = dir.path().join("lockdown");
        for (contents, device, refused) in [
            (NO_LOCKDOWN, MemoryDevice::DevMem, None),
            (NO_LOCKDOWN, MemoryDevice::Kcore, None),
            (
                "none [integrity] confidentiality\n",
                MemoryDevice::DevMem,
                Some(LockdownMode::Integrity),
            ),
            (
                "none [integrity] confidentiality\n",
                MemoryDevice::Kcore,
                None,
            ),
            (
                "none integrity [confidentiality]\n",
                MemoryDevice::DevMem,
                Some(LockdownMode::Confidentiality),
            ),
            (
                "none integrity [confidentiality]\n",
                MemoryDevice::Kcore,
                Some(LockdownMode::Confidentiality),
            ),
        ] {
            let case = format!("{device} under {contents:?}");
            fs::write(&file, contents).expect("write the lockdown file");

            let got = refuse_locked_down(device, &file);

            let want = refused.map(|mode| MemoryAccessDenied {
                device,
                operation: MemoryOperation::Open,
                cause: DenialCause::Lockdown(mode),
            });
            match (got, want) {
                (Ok(()), None) => {}
                (Err(error), Some(want)) => assert_eq!(
                    error.downcast_ref::<MemoryAccessDenied>(),
                    Some(&want),
                    "{case}: {error:#}"
                ),
                (got, want) => panic!("{case}: got {got:?}, want {want:?}"),
            }
        }

        // The temporary directory is not securityfs.
        let error = refuse_locked_down(MemoryDevice::DevMem, &dir.path().join("missing"))
            .expect_err("check an unknown lockdown mode");
        assert!(
            matches!(
                error.downcast_ref::<LockdownUnknown>(),
                Some(LockdownUnknown::SecurityfsNotMounted(got)) if got == dir.path()
            ),
            "unknown: {error:#}"
        );
    }
}
