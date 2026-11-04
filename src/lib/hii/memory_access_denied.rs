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

//! Refused physical memory access: MemoryAccessDenied and what the kernel refused it for.

use std::fmt;
#[cfg(any(firmware_memory_maps, test))]
use std::io;
#[cfg(any(firmware_memory_maps, test))]
use std::path::Path;

use thiserror::Error;

#[cfg(any(firmware_memory_maps, test))]
use crate::hii::lockdown::read_lockdown_mode;
use crate::hii::lockdown::LockdownMode;

/// A file of physical memory that the kernel guards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MemoryDevice {
    /// /dev/mem.
    DevMem,
    /// /proc/kcore.
    Kcore,
}

impl fmt::Display for MemoryDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::DevMem => "/dev/mem",
            Self::Kcore => "/proc/kcore",
        })
    }
}

/// What was done with physical memory when the kernel refused it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum MemoryOperation {
    /// open(), which kernel lockdown refuses too.
    Open,
    /// pread().
    Read,
    /// mmap().
    Map,
}

impl fmt::Display for MemoryOperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Open => "open",
            Self::Read => "read",
            Self::Map => "map",
        })
    }
}

/// A use of physical memory after its open, which kernel lockdown never refuses: it refuses
/// only the opens (Linux v6.11 drivers/char/mem.c open_port(), fs/proc/kcore.c open_kcore()).
#[cfg(any(firmware_memory_maps, test))]
#[derive(Debug, Clone, Copy)]
pub(super) enum MemoryAccess {
    DevMemRead,
    DevMemMap,
    /// /proc/kcore has no mmap() (fs/proc/kcore.c kcore_proc_ops).
    #[cfg(any(target_arch = "aarch64", test))]
    KcoreRead,
}

#[cfg(any(firmware_memory_maps, test))]
impl MemoryAccess {
    fn device(self) -> MemoryDevice {
        match self {
            Self::DevMemRead | Self::DevMemMap => MemoryDevice::DevMem,
            #[cfg(any(target_arch = "aarch64", test))]
            Self::KcoreRead => MemoryDevice::Kcore,
        }
    }

    fn operation(self) -> MemoryOperation {
        match self {
            Self::DevMemRead => MemoryOperation::Read,
            Self::DevMemMap => MemoryOperation::Map,
            #[cfg(any(target_arch = "aarch64", test))]
            Self::KcoreRead => MemoryOperation::Read,
        }
    }
}

/// Why the kernel refused physical memory access, after Linux v6.11 drivers/char/mem.c,
/// fs/proc/kcore.c, fs/namei.c, fs/open.c, fs/read_write.c and mm/util.c. A security module is
/// an LSM or, for /dev/mem, a fanotify permission listener (FAN_DENY gives EPERM); procfs takes
/// no fanotify permission events (FS_DISALLOW_NOTIFY_PERM).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DenialCause {
    /// Kernel lockdown in this mode, which refuses opening the device: /dev/mem from integrity
    /// on (LOCKDOWN_DEV_MEM), /proc/kcore at confidentiality (LOCKDOWN_KCORE).
    Lockdown(LockdownMode),
    /// EPERM from opening, with no lockdown that refuses the device: the process lacks
    /// CAP_SYS_RAWIO (open_port(), open_kcore()), or a security module refuses it before the
    /// device's open (do_dentry_open() security_file_open()), or, for /dev/mem, a device cgroup
    /// does (inode_permission() devcgroup_inode_permission()).
    Capability,
    /// EPERM from opening, while the lockdown mode is unknown: Capability, or kernel lockdown.
    /// The LockdownUnknown is the context under MemoryAccessDenied.
    CapabilityOrLockdown,
    /// EPERM from a read or a mapping of /dev/mem: CONFIG_STRICT_DEVMEM refuses the range
    /// (read_mem() page_is_allowed(), mmap_mem() range_is_allowed()), or a security module
    /// does first (vfs_read() rw_verify_area(), vm_mmap_pgoff() security_mmap_file()).
    StrictDevmem,
    /// EACCES from opening: file permissions or a security module. EACCES from a read or a
    /// mapping: a security module, as no permission bits are checked after the open. EPERM
    /// from reading /proc/kcore, which only a security module refuses (fs/read_write.c
    /// vfs_read() rw_verify_area()).
    Permission,
}

/// The kernel refused, or refuses, `operation` of `device` for `cause`.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct MemoryAccessDenied {
    /// The refused file.
    pub device: MemoryDevice,
    /// What was refused.
    pub operation: MemoryOperation,
    /// Why.
    pub cause: DenialCause,
}

impl fmt::Display for MemoryAccessDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the kernel refuses to {} {} (",
            self.operation, self.device
        )?;
        match (self.cause, self.device, self.operation) {
            (DenialCause::Lockdown(mode), _, _) => write!(f, "kernel lockdown is {mode}")?,
            (DenialCause::Capability, MemoryDevice::DevMem, _) => f.write_str(
                "it needs CAP_SYS_RAWIO, or a device cgroup or a security module refuses it",
            )?,
            (DenialCause::Capability, MemoryDevice::Kcore, _) => {
                f.write_str("it needs CAP_SYS_RAWIO, or a security module refuses it")?
            }
            (DenialCause::CapabilityOrLockdown, MemoryDevice::DevMem, _) => f.write_str(
                "it needs CAP_SYS_RAWIO, unless kernel lockdown, a device cgroup or a security \
                 module refuses it",
            )?,
            (DenialCause::CapabilityOrLockdown, MemoryDevice::Kcore, _) => f.write_str(
                "it needs CAP_SYS_RAWIO, unless kernel lockdown or a security module refuses it",
            )?,
            (DenialCause::StrictDevmem, _, _) => {
                f.write_str("CONFIG_STRICT_DEVMEM or a security module refuses the range")?
            }
            (DenialCause::Permission, _, MemoryOperation::Open) => {
                f.write_str("file permissions or a security module refuse it")?
            }
            (DenialCause::Permission, _, MemoryOperation::Read | MemoryOperation::Map) => {
                f.write_str("a security module refuses it")?
            }
        }
        f.write_str(")")
    }
}

/// The errnos with which the kernel refuses physical memory access.
#[cfg(any(firmware_memory_maps, test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RefusalErrno {
    Eperm,
    Eacces,
}

#[cfg(any(firmware_memory_maps, test))]
impl RefusalErrno {
    /// The refusal errno that is the root cause of `error`, if any.
    fn of(error: &anyhow::Error) -> Option<Self> {
        match error
            .root_cause()
            .downcast_ref::<io::Error>()
            .and_then(io::Error::raw_os_error)
        {
            Some(libc::EPERM) => Some(Self::Eperm),
            Some(libc::EACCES) => Some(Self::Eacces),
            _ => None,
        }
    }
}

/// `error`, of opening `device`, under a MemoryAccessDenied context if the kernel refused it,
/// i.e. its root cause is EPERM or EACCES. EPERM reads the lockdown mode in `lockdown`
/// (LOCKDOWN_PATH); an unknown one is a LockdownUnknown context under the mark.
#[cfg(any(firmware_memory_maps, test))]
pub(super) fn mark_refused_open(
    error: anyhow::Error,
    device: MemoryDevice,
    lockdown: &Path,
) -> anyhow::Error {
    let Some(errno) = RefusalErrno::of(&error) else {
        return error;
    };
    let (error, cause) = match errno {
        RefusalErrno::Eacces => (error, DenialCause::Permission),
        RefusalErrno::Eperm => match read_lockdown_mode(lockdown) {
            Ok(mode) if mode.refuses(device) => (error, DenialCause::Lockdown(mode)),
            Ok(_) => (error, DenialCause::Capability),
            Err(unknown) => (error.context(unknown), DenialCause::CapabilityOrLockdown),
        },
    };
    error.context(MemoryAccessDenied {
        device,
        operation: MemoryOperation::Open,
        cause,
    })
}

/// `error`, of `access` to opened physical memory, under a MemoryAccessDenied context if the
/// kernel refused it, i.e. its root cause is EPERM or EACCES.
#[cfg(any(firmware_memory_maps, test))]
pub(super) fn mark_refused_access(error: anyhow::Error, access: MemoryAccess) -> anyhow::Error {
    let Some(errno) = RefusalErrno::of(&error) else {
        return error;
    };
    let device = access.device();
    let cause = match (device, errno) {
        (MemoryDevice::DevMem, RefusalErrno::Eperm) => DenialCause::StrictDevmem,
        (MemoryDevice::Kcore, RefusalErrno::Eperm)
        | (MemoryDevice::DevMem | MemoryDevice::Kcore, RefusalErrno::Eacces) => {
            DenialCause::Permission
        }
    };
    error.context(MemoryAccessDenied {
        device,
        operation: access.operation(),
        cause,
    })
}

/// Files for the tests of refused opens.
#[cfg(test)]
pub(super) mod fixture {
    use std::fs;
    use std::fs::File;
    use std::io;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;
    use std::path::PathBuf;

    /// An open that the kernel refuses with EPERM, as lockdown, a missing CAP_SYS_RAWIO or a
    /// security module does.
    pub(in crate::hii) fn refused_open(_: &Path) -> io::Result<File> {
        Err(io::Error::from_raw_os_error(libc::EPERM))
    }

    /// A lockdown file in `dir` that shows `mode` as active.
    pub(in crate::hii) fn lockdown_file(dir: &Path, mode: &str) -> PathBuf {
        let path = dir.join(format!("lockdown-{mode}"));
        let contents = ["none", "integrity", "confidentiality"]
            .map(|known| match known == mode {
                true => format!("[{known}]"),
                false => known.to_owned(),
            })
            .join(" ");
        fs::write(&path, contents + "\n").expect("write the lockdown file");
        path
    }

    /// Takes the read permission of the file at `path`, created empty unless it exists; false if
    /// this process opens it anyway, as one with CAP_DAC_OVERRIDE does.
    pub(in crate::hii) fn unreadable_file(path: &Path) -> bool {
        File::options()
            .create(true)
            .append(true)
            .open(path)
            .expect("create the file");
        fs::set_permissions(path, fs::Permissions::from_mode(0o000))
            .expect("take the read permission");
        File::open(path).is_err()
    }
}

#[cfg(test)]
mod tests {
    use anyhow::Context;

    use super::*;
    use crate::hii::lockdown::LockdownUnknown;

    /// The error of a call that failed with `errno`.
    fn failed_call(errno: i32) -> anyhow::Error {
        Err::<(), _>(io::Error::from_raw_os_error(errno))
            .context("the failed call")
            .expect_err("an error")
    }

    /// mark_refused_open marks EPERM and EACCES only: EPERM as the lockdown mode refusing the
    /// device, or else as Capability, or as CapabilityOrLockdown under the LockdownUnknown if
    /// the mode is unknown; EACCES as Permission. It keeps the error under the mark.
    #[test]
    fn mark_refused_open_marks_only_eperm_and_eacces() {
        let dir = tempfile::tempdir().expect("create a directory");
        let integrity = dir.path().join("integrity");
        std::fs::write(&integrity, "none [integrity] confidentiality\n").expect("write lockdown");
        let confidentiality = dir.path().join("confidentiality");
        std::fs::write(&confidentiality, "none integrity [confidentiality]\n")
            .expect("write lockdown");
        // read() of a directory fails with EISDIR
        let unreadable = dir.path().to_path_buf();
        // The temporary directory is not securityfs.
        let missing = dir.path().join("missing");
        for (device, errno, lockdown, want, want_unknown) in [
            (
                MemoryDevice::DevMem,
                libc::EPERM,
                &integrity,
                Some(DenialCause::Lockdown(LockdownMode::Integrity)),
                None,
            ),
            (
                MemoryDevice::Kcore,
                libc::EPERM,
                &integrity,
                Some(DenialCause::Capability),
                None,
            ),
            (
                MemoryDevice::Kcore,
                libc::EPERM,
                &confidentiality,
                Some(DenialCause::Lockdown(LockdownMode::Confidentiality)),
                None,
            ),
            (
                MemoryDevice::DevMem,
                libc::EPERM,
                &unreadable,
                Some(DenialCause::CapabilityOrLockdown),
                Some(format!(
                    "cannot read the kernel lockdown mode at {}: Is a directory (os error 21)",
                    unreadable.display()
                )),
            ),
            (
                MemoryDevice::Kcore,
                libc::EPERM,
                &missing,
                Some(DenialCause::CapabilityOrLockdown),
                Some(format!(
                    "{} is not securityfs, so the kernel lockdown mode is unknown; mount \
                     securityfs at {}",
                    dir.path().display(),
                    dir.path().display()
                )),
            ),
            (
                MemoryDevice::DevMem,
                libc::EACCES,
                &integrity,
                Some(DenialCause::Permission),
                None,
            ),
            (
                MemoryDevice::Kcore,
                libc::EACCES,
                &missing,
                Some(DenialCause::Permission),
                None,
            ),
            (MemoryDevice::DevMem, libc::ENOENT, &integrity, None, None),
            (MemoryDevice::Kcore, libc::EIO, &missing, None, None),
        ] {
            let case = format!("open {device} errno {errno} under {}", lockdown.display());

            let marked = mark_refused_open(failed_call(errno), device, lockdown);

            let want = want.map(|cause| MemoryAccessDenied {
                device,
                operation: MemoryOperation::Open,
                cause,
            });
            assert_eq!(
                marked.downcast_ref::<MemoryAccessDenied>(),
                want.as_ref(),
                "{case}"
            );
            assert_eq!(
                marked
                    .downcast_ref::<LockdownUnknown>()
                    .map(ToString::to_string),
                want_unknown,
                "{case}: {marked:#}"
            );
            assert!(
                format!("{marked:#}").contains("the failed call"),
                "{case}: {marked:#}"
            );
        }

        let error = mark_refused_open(
            anyhow::anyhow!("no errno"),
            MemoryDevice::DevMem,
            &integrity,
        );
        assert!(!error.is::<MemoryAccessDenied>(), "no errno: {error:#}");
    }

    /// mark_refused_access marks EPERM and EACCES only: EPERM of /dev/mem as
    /// CONFIG_STRICT_DEVMEM, of /proc/kcore as Permission, which a security module makes, and
    /// EACCES as Permission. It keeps the error under the mark.
    #[test]
    fn mark_refused_access_marks_only_eperm_and_eacces() {
        for (access, errno, want) in [
            (
                MemoryAccess::DevMemRead,
                libc::EPERM,
                Some((
                    MemoryDevice::DevMem,
                    MemoryOperation::Read,
                    DenialCause::StrictDevmem,
                )),
            ),
            (
                MemoryAccess::DevMemMap,
                libc::EPERM,
                Some((
                    MemoryDevice::DevMem,
                    MemoryOperation::Map,
                    DenialCause::StrictDevmem,
                )),
            ),
            (
                MemoryAccess::KcoreRead,
                libc::EPERM,
                Some((
                    MemoryDevice::Kcore,
                    MemoryOperation::Read,
                    DenialCause::Permission,
                )),
            ),
            (
                MemoryAccess::DevMemRead,
                libc::EACCES,
                Some((
                    MemoryDevice::DevMem,
                    MemoryOperation::Read,
                    DenialCause::Permission,
                )),
            ),
            (
                MemoryAccess::DevMemMap,
                libc::EACCES,
                Some((
                    MemoryDevice::DevMem,
                    MemoryOperation::Map,
                    DenialCause::Permission,
                )),
            ),
            (
                MemoryAccess::KcoreRead,
                libc::EACCES,
                Some((
                    MemoryDevice::Kcore,
                    MemoryOperation::Read,
                    DenialCause::Permission,
                )),
            ),
            (MemoryAccess::DevMemRead, libc::EIO, None),
            (MemoryAccess::DevMemMap, libc::EINVAL, None),
            (MemoryAccess::KcoreRead, libc::EFAULT, None),
        ] {
            let case = format!("{access:?} errno {errno}");

            let marked = mark_refused_access(failed_call(errno), access);

            let want = want.map(|(device, operation, cause)| MemoryAccessDenied {
                device,
                operation,
                cause,
            });
            assert_eq!(
                marked.downcast_ref::<MemoryAccessDenied>(),
                want.as_ref(),
                "{case}"
            );
            assert!(
                format!("{marked:#}").contains("the failed call"),
                "{case}: {marked:#}"
            );
        }

        let error = mark_refused_access(anyhow::anyhow!("no errno"), MemoryAccess::DevMemRead);
        assert!(!error.is::<MemoryAccessDenied>(), "no errno: {error:#}");
    }

    /// MemoryAccessDenied names the operation, the device and the cause, each in its own words.
    #[test]
    fn memory_access_denied_names_the_operation_and_the_cause() {
        for (device, operation, cause, want) in [
            (
                MemoryDevice::DevMem,
                MemoryOperation::Open,
                DenialCause::Lockdown(LockdownMode::Integrity),
                "the kernel refuses to open /dev/mem (kernel lockdown is integrity)",
            ),
            (
                MemoryDevice::Kcore,
                MemoryOperation::Open,
                DenialCause::Lockdown(LockdownMode::Confidentiality),
                "the kernel refuses to open /proc/kcore (kernel lockdown is confidentiality)",
            ),
            (
                MemoryDevice::DevMem,
                MemoryOperation::Open,
                DenialCause::Capability,
                "the kernel refuses to open /dev/mem (it needs CAP_SYS_RAWIO, or a device cgroup \
                 or a security module refuses it)",
            ),
            (
                MemoryDevice::Kcore,
                MemoryOperation::Open,
                DenialCause::Capability,
                "the kernel refuses to open /proc/kcore (it needs CAP_SYS_RAWIO, or a security \
                 module refuses it)",
            ),
            (
                MemoryDevice::DevMem,
                MemoryOperation::Open,
                DenialCause::CapabilityOrLockdown,
                "the kernel refuses to open /dev/mem (it needs CAP_SYS_RAWIO, unless kernel \
                 lockdown, a device cgroup or a security module refuses it)",
            ),
            (
                MemoryDevice::Kcore,
                MemoryOperation::Open,
                DenialCause::CapabilityOrLockdown,
                "the kernel refuses to open /proc/kcore (it needs CAP_SYS_RAWIO, unless kernel \
                 lockdown or a security module refuses it)",
            ),
            (
                MemoryDevice::DevMem,
                MemoryOperation::Read,
                DenialCause::StrictDevmem,
                "the kernel refuses to read /dev/mem (CONFIG_STRICT_DEVMEM or a security module \
                 refuses the range)",
            ),
            (
                MemoryDevice::DevMem,
                MemoryOperation::Map,
                DenialCause::StrictDevmem,
                "the kernel refuses to map /dev/mem (CONFIG_STRICT_DEVMEM or a security module \
                 refuses the range)",
            ),
            (
                MemoryDevice::DevMem,
                MemoryOperation::Open,
                DenialCause::Permission,
                "the kernel refuses to open /dev/mem (file permissions or a security module \
                 refuse it)",
            ),
            (
                MemoryDevice::Kcore,
                MemoryOperation::Read,
                DenialCause::Permission,
                "the kernel refuses to read /proc/kcore (a security module refuses it)",
            ),
            (
                MemoryDevice::DevMem,
                MemoryOperation::Map,
                DenialCause::Permission,
                "the kernel refuses to map /dev/mem (a security module refuses it)",
            ),
        ] {
            let denied = MemoryAccessDenied {
                device,
                operation,
                cause,
            };

            assert_eq!(denied.to_string(), want, "{denied:?}");
        }
    }
}
