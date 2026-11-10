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

use std::fmt;
use std::fs;
use std::fs::File;
use std::io;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use std::str::FromStr;
use std::sync::OnceLock;

use anyhow::anyhow;
use anyhow::bail;
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
use crate::efi_variables::VariableContents;
use crate::efi_variables::VariableData;
use crate::efi_variables::VariableInfo;
use crate::efi_variables::VariableInfoSource;
use crate::efi_variables::VariableNames;
use crate::efi_variables::VariableStorage;
use crate::efi_variables::VariableStorageInfo;
use crate::file_lock::FileLock;
use crate::hii::boot_log::open_kmsg;
use crate::hii::boot_log::require_char_device;
use crate::hii::boot_log::rt_properties_in_boot_log;
use crate::hii::boot_log::KernelLog;
use crate::hii::boot_log::RtPropertiesInBootLog;
use crate::hii::boot_log::Syslog;
use crate::hii::boot_log::KMSG_DEVICE;
use crate::hii::boot_log::KMSG_PATH;
use crate::hii::efivarfs_format::as_variable_not_found;
use crate::hii::efivarfs_format::check_regular_file;
use crate::hii::efivarfs_format::listed_names;
use crate::hii::efivarfs_format::open_efivar;
use crate::hii::efivarfs_format::read_efivar;
use crate::hii::efivarfs_format::read_efivar_file_of;
use crate::hii::efivarfs_format::read_whole_efivar;
use crate::hii::efivarfs_format::EfivarCopy;
use crate::hii::efivarfs_format::EfivarFileName;
use crate::hii::efivarfs_format::EfivarNotFound;
use crate::hii::efivarfs_format::EFIVARFS_INTERFACE;
use crate::hii::efivarfs_format::EFIVARFS_REACH;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use crate::hii::firmware_memory::kcore::read_kcore_file;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use crate::hii::firmware_memory::kcore::KcoreAddress;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use crate::hii::firmware_memory::kcore::KCORE_PATH;
#[cfg(firmware_memory_maps)]
use crate::hii::firmware_memory::runtime_memory::DevMem;
#[cfg(firmware_memory_maps)]
use crate::hii::firmware_memory::runtime_memory::PhysicalMemory;
#[cfg(not(firmware_memory_maps))]
use crate::hii::firmware_memory::MemoryMapUnavailable;
use crate::hii::kallsyms::GenericSetVariable;
use crate::hii::kallsyms::KernelSymbols;
use crate::hii::kallsyms::KALLSYMS_PATH;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use crate::hii::lockdown::refuse_locked_down;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use crate::hii::lockdown::LOCKDOWN_PATH;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use crate::hii::memory_access_denied::mark_refused_open;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use crate::hii::memory_access_denied::MemoryDevice;
#[cfg(firmware_memory_maps)]
use crate::hii::package::Guid;
#[cfg(firmware_memory_maps)]
use crate::hii::system_table::ConfigurationTables;
#[cfg(firmware_memory_maps)]
use crate::hii::system_table::PointerSpace;
#[cfg(firmware_memory_maps)]
use crate::hii::system_table::SystemTableFiles;
use crate::hii::variables::modify_variable_bytes;
use crate::hii::variables::EfivarSource;
use crate::hii::variables::FirmwareVariables;
use crate::hii::variables::UnreadVariables;
use crate::hii::variables::VariableAttributes;
use crate::hii::variables::VariableInterface;
use crate::hii::variables::VariableKey;
use crate::hii::variables::VariableNotFound;
use crate::hii::variables::VariableReach;
use crate::hii::variables::VolatileWrites;
use crate::hii::variables::EFIVARFS_HEADER_SIZE;

pub(super) const EFIVARS_MOUNT_POINT: &str = "/sys/firmware/efi/efivars";
/// The file that EfivarFiles::system() locks while it remounts EFIVARS_MOUNT_POINT.
const REMOUNT_LOCK_FILE: &str = "/run/lock/efibootmgr-remount";
/// The f_type of an efivarfs's statfs (Linux v6.11 include/uapi/linux/magic.h).
const EFIVARFS_MAGIC: u32 = 0xde5e_81e4;
/// The attributes of the variables whose storage the statfs of efivarfs tells (Linux v6.11
/// fs/efivarfs/super.c efivarfs_statfs()).
const EFIVARFS_STATFS_ATTRIBUTES: VariableAttributes = VariableAttributes::NON_VOLATILE
    .union(VariableAttributes::BOOTSERVICE_ACCESS)
    .union(VariableAttributes::RUNTIME_ACCESS);
/// EFI_RT_SUPPORTED_SET_VARIABLE, RuntimeServicesSupported's bit of SetVariable() (UEFI 2.11
/// §4.6.2).
const EFI_RT_SUPPORTED_SET_VARIABLE: u32 = 0x0040;
/// EFI_RT_PROPERTIES_TABLE_GUID (UEFI 2.11 §4.6.2).
#[cfg(firmware_memory_maps)]
const EFI_RT_PROPERTIES_TABLE_GUID: Guid = Guid {
    data1: 0xeb66_918a,
    data2: 0x7eef,
    data3: 0x402a,
    data4: [0x84, 0x2e, 0x93, 0x1d, 0x21, 0xc3, 0x8a, 0xe9],
};
/// The size of EFI_RT_PROPERTIES_TABLE: Version, Length and RuntimeServicesSupported (UEFI 2.11
/// §4.6.2).
#[cfg(firmware_memory_maps)]
const RT_PROPERTIES_TABLE_SIZE: usize = 8;

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
    /// What tells whether an efivarfs write crashes this Linux.
    evidence: Box<dyn WriteSafetyEvidence>,
    /// Set by the first write_at that finds that writes cannot crash this Linux.
    survives: OnceLock<KernelSurvivesWrites>,
}

impl EfivarFiles {
    /// This machine's efivarfs.
    pub(crate) fn system() -> Self {
        Self {
            dir: PathBuf::from(EFIVARS_MOUNT_POINT),
            remount_lock: PathBuf::from(REMOUNT_LOCK_FILE),
            evidence: Box::new(LinuxEvidence::system()),
            survives: OnceLock::new(),
        }
    }

    /// The proof that an efivarfs write cannot crash this Linux, which the first call looks for
    /// (kernel_survives_writes).
    fn survives(&self) -> Result<&KernelSurvivesWrites> {
        if let Some(survives) = self.survives.get() {
            return Ok(survives);
        }
        let survives = kernel_survives_writes(self.evidence.as_ref())?;
        Ok(self.survives.get_or_init(|| survives))
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

    fn read_whole(&self, key: &VariableKey) -> Result<Vec<u8>> {
        read_whole_efivar(&self.dir, &EfivarFileName::from(key))
            .map_err(|error| as_variable_not_found(key, error))
    }

    fn write_at_with(
        &self,
        key: &VariableKey,
        size: u16,
        offset: u16,
        encoded: &[u8],
        volatile: VolatileWrites,
    ) -> Result<()> {
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

        let mut file_contents = read_efivar_file_of(&file_ro)
            .context(format!("Failed to read efivarfs file '{}'", path.display()))?;

        modify_variable_bytes(
            self,
            key,
            volatile,
            &mut file_contents,
            size,
            offset,
            encoded,
        )?;

        let survives = self.survives()?;
        let _efifs = EfivarsMountGuard::new(&self.dir, survives)
            .context("Failed to create efivars fs mount guard")?;

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

/// Proof that an efivarfs write cannot crash this Linux, which only kernel_survives_writes makes:
/// EfivarsMountGuard::new takes it, so that no write goes unchecked.
#[derive(Debug)]
pub(super) struct KernelSurvivesWrites(());

/// What tells kernel_survives_writes whether an efivarfs write crashes this Linux. Linux v5.8
/// (f88814cc2578; stable 5.7.11) to v6.7 mount efivarfs read-only without a runtime SetVariable()
/// but remount it read-write, and the next write calls a NULL set_variable (upstream 0e8d2444168d,
/// which Linux v6.8 and stable 5.10.209, 5.15.148, 6.1.75, 6.6.14 and 6.7.2 have). Each method's
/// error means that its source tells nothing.
pub(super) trait WriteSafetyEvidence {
    /// Whether the kernel's symbols name efivarfs_reconfigure(), which upstream 0e8d2444168d added
    /// with the check that keeps such an efivarfs read-only.
    fn names_efivarfs_reconfigure(&self) -> Result<bool>;
    /// Whether the efivar_operations through which efivarfs writes holds a SetVariable(): the NULL
    /// one is what such a write calls, unless another efivars_register() caller replaced it (gsmi
    /// before v6.3, qcom uefisecapp in v6.7), where a NULL set_variable refuses a write that would
    /// not crash.
    fn generic_set_variable(&self) -> Result<GenericSetVariable>;
    /// Whether the boot log names an EFI_RT_PROPERTIES_TABLE that Linux applied.
    fn rt_properties_in_boot_log(&self) -> Result<RtPropertiesInBootLog>;
    /// The RuntimeServicesSupported of the firmware's EFI_RT_PROPERTIES_TABLE, which Linux ANDs
    /// into its mask of runtime services (Linux v6.7 drivers/firmware/efi/efi.c
    /// efi_config_parse_tables()), or None without one.
    fn rt_properties_supported(&self) -> Result<Option<u32>>;
}

/// Why an efivarfs write would crash this Linux, or may.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
enum CrashingWrite {
    #[error(
        "Linux has no runtime SetVariable() and, without efivarfs_reconfigure() (upstream \
         0e8d2444168d, Linux v6.8), crashes on an efivarfs write; run uefisettings.efi in the \
         UEFI Shell"
    )]
    NoSetVariable,
    #[error(
        "Linux without efivarfs_reconfigure() (upstream 0e8d2444168d, Linux v6.8) crashes on an \
         efivarfs write without a runtime SetVariable(), as on firmware whose \
         EFI_RT_PROPERTIES_TABLE (UEFI 2.11 §4.6.2) leaves it out, as this one does \
         (RuntimeServicesSupported {0:#06x}); run uefisettings.efi in the UEFI Shell"
    )]
    TableOmitsSetVariable(u32),
    #[error(
        "Linux without efivarfs_reconfigure() (upstream 0e8d2444168d, Linux v6.8) crashes on an \
         efivarfs write without a runtime SetVariable(), as on firmware whose \
         EFI_RT_PROPERTIES_TABLE (UEFI 2.11 §4.6.2) leaves it out, and uefisettings cannot tell \
         whether this one does; run uefisettings.efi in the UEFI Shell"
    )]
    Unknown,
}

/// What the steps of kernel_survives_writes that decided nothing found.
#[derive(Debug, Error)]
struct UndecidedSteps(Vec<anyhow::Error>);

impl fmt::Display for UndecidedSteps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, step) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str("; ")?;
            }
            write!(f, "{step:#}")?;
        }
        Ok(())
    }
}

/// Whether an efivarfs write cannot crash this Linux, from `evidence`. The first step that
/// decides wins:
/// 1. the kernel names efivarfs_reconfigure(): it keeps efivarfs read-only without SetVariable();
/// 2. generic_ops holds a SetVariable(), or refuses the write without one;
/// 3. the boot log names no usable RT properties table: Linux kept SetVariable();
/// 4. the firmware's RT properties table, which Linux applied, lists SetVariable(), or there is
///    none; one that leaves it out refuses the write, and so does an unreadable one, with what
///    each step found.
fn kernel_survives_writes(evidence: &dyn WriteSafetyEvidence) -> Result<KernelSurvivesWrites> {
    let mut undecided = Vec::new();
    match evidence.names_efivarfs_reconfigure() {
        Ok(true) => return Ok(KernelSurvivesWrites(())),
        Ok(false) => undecided.push(anyhow!("the kernel names no efivarfs_reconfigure()")),
        Err(error) => undecided.push(error),
    }
    match evidence.generic_set_variable() {
        Ok(GenericSetVariable::Absent) => return Err(CrashingWrite::NoSetVariable.into()),
        Ok(GenericSetVariable::Present) => return Ok(KernelSurvivesWrites(())),
        Err(error) => undecided.push(error),
    }
    match evidence.rt_properties_in_boot_log() {
        Ok(RtPropertiesInBootLog::Absent) => return Ok(KernelSurvivesWrites(())),
        Ok(RtPropertiesInBootLog::Present) => undecided.push(anyhow!(
            "the kernel log names an EFI_RT_PROPERTIES_TABLE that Linux applied"
        )),
        Err(error) => undecided.push(error),
    }
    match evidence.rt_properties_supported() {
        Ok(None) => Ok(KernelSurvivesWrites(())),
        Ok(Some(supported)) if supported & EFI_RT_SUPPORTED_SET_VARIABLE != 0 => {
            Ok(KernelSurvivesWrites(()))
        }
        Ok(Some(supported)) => Err(CrashingWrite::TableOmitsSetVariable(supported).into()),
        Err(error) => {
            undecided.push(error);
            Err(anyhow::Error::new(UndecidedSteps(undecided)).context(CrashingWrite::Unknown))
        }
    }
}

/// The RuntimeServicesSupported of the EFI_RT_PROPERTIES_TABLE that the System Table of `files`
/// lists, in the physical memory that `open_memory` opens, or None without one: Linux takes it
/// whatever the table's Version and Length (Linux v6.11 drivers/firmware/efi/efi.c:779-784), and
/// so does this. Its address is physical and never converted (UEFI 2.11 §4.6.2), so a virtual
/// range that holds it does not lead to it.
#[cfg(firmware_memory_maps)]
fn read_rt_properties_supported<M: PhysicalMemory>(
    files: &SystemTableFiles,
    open_memory: impl FnOnce(&Path, &Path) -> Result<M>,
) -> Result<Option<u32>> {
    let Some(table) = ConfigurationTables::read(files, open_memory)?
        .into_table(&EFI_RT_PROPERTIES_TABLE_GUID, PointerSpace::PhysicalOnly)?
    else {
        return Ok(None);
    };
    let bytes = table
        .read_at(0, RT_PROPERTIES_TABLE_SIZE)
        .context("Failed to read the EFI_RT_PROPERTIES_TABLE")?;
    let [_, _, _, _, s0, s1, s2, s3] = <[u8; RT_PROPERTIES_TABLE_SIZE]>::try_from(bytes)
        .map_err(|bytes| anyhow!("read {} bytes of the EFI_RT_PROPERTIES_TABLE", bytes.len()))?;
    Ok(Some(u32::from_le_bytes([s0, s1, s2, s3])))
}

/// The evidence of this Linux: its symbol table, its memory and its log.
struct LinuxEvidence {
    kallsyms: PathBuf,
    /// The symbols of `kallsyms`, from the first pass that read it.
    symbols: OnceLock<KernelSymbols>,
    /// The lockdown mode, which may refuse `kcore`.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    lockdown: PathBuf,
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    kcore: PathBuf,
    /// The kernel release, as uname(2) gives it (Linux v6.7 kernel/utsname_sysctl.c osrelease).
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    osrelease: PathBuf,
    /// The first release whose /proc/kcore reads generic_ops safely, if not every release's does:
    /// KCORE_SAFE_SINCE.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    kcore_safe_since: Option<KernelRelease>,
    kmsg: PathBuf,
    /// The character device that `kmsg` must be, or None for any file, as the tests give.
    kmsg_device: Option<libc::dev_t>,
    /// syslog(2), where the kernel refuses `kmsg`.
    kernel_log: Box<dyn KernelLog>,
    /// The files that locate the firmware's configuration tables, among them the RT properties
    /// table.
    #[cfg(firmware_memory_maps)]
    system_table: SystemTableFiles,
}

impl LinuxEvidence {
    /// This machine's.
    fn system() -> Self {
        Self {
            kallsyms: PathBuf::from(KALLSYMS_PATH),
            symbols: OnceLock::new(),
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            lockdown: PathBuf::from(LOCKDOWN_PATH),
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            kcore: PathBuf::from(KCORE_PATH),
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            osrelease: PathBuf::from(OSRELEASE_PATH),
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            kcore_safe_since: KCORE_SAFE_SINCE,
            kmsg: PathBuf::from(KMSG_PATH),
            kmsg_device: Some(KMSG_DEVICE),
            kernel_log: Box::new(Syslog),
            #[cfg(firmware_memory_maps)]
            system_table: SystemTableFiles::default(),
        }
    }

    /// The symbols of the symbol table, which the first call reads.
    fn symbols(&self) -> Result<&KernelSymbols> {
        if let Some(symbols) = self.symbols.get() {
            return Ok(symbols);
        }
        let symbols = KernelSymbols::read(&self.kallsyms)?;
        Ok(self.symbols.get_or_init(|| symbols))
    }
}

/// The kernel release, as uname(2) gives it.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
const OSRELEASE_PATH: &str = "/proc/sys/kernel/osrelease";

/// Before Linux v5.14 (2711032c64a9), read_kcore() calls __pa() on every /proc/kcore address
/// (v5.13 fs/proc/kcore.c), which arm64's CONFIG_DEBUG_VIRTUAL warns on for an address outside
/// the linear map (arch/arm64/mm/physaddr.c __virt_to_phys()), as generic_ops' kernel-image
/// address is. On x86_64, __pa() of a kernel-image address only bounds-checks it.
#[cfg(target_arch = "aarch64")]
const KCORE_SAFE_SINCE: Option<KernelRelease> = Some(KernelRelease {
    major: 5,
    minor: 14,
});
#[cfg(target_arch = "x86_64")]
const KCORE_SAFE_SINCE: Option<KernelRelease> = None;

/// The major and minor numbers that start a Linux release, such as 5.13 in
/// 5.13.19-100.fc33.aarch64.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct KernelRelease {
    major: u32,
    minor: u32,
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
impl FromStr for KernelRelease {
    type Err = anyhow::Error;

    fn from_str(release: &str) -> Result<Self> {
        let (major, rest) = release
            .split_once('.')
            .with_context(|| format!("kernel release {release:?} has no minor number"))?;
        let minor = rest
            .split(|c: char| !c.is_ascii_digit())
            .next()
            .unwrap_or_default();
        Ok(Self {
            major: major
                .parse()
                .with_context(|| format!("kernel release {release:?}: major number"))?,
            minor: minor
                .parse()
                .with_context(|| format!("kernel release {release:?}: minor number"))?,
        })
    }
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
impl fmt::Display for KernelRelease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// Refuses a kernel before `since`, by its release at `osrelease`: its /proc/kcore read of
/// generic_ops may warn (KCORE_SAFE_SINCE).
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn refuse_kcore_before(osrelease: &Path, since: KernelRelease) -> Result<()> {
    let text = fs::read_to_string(osrelease)
        .with_context(|| format!("Failed to read {}", osrelease.display()))?;
    let release: KernelRelease = text.trim_end().parse()?;
    if release < since {
        bail!(
            "Linux before v{since} calls __pa() on every /proc/kcore address (2711032c64a9), \
             which arm64's CONFIG_DEBUG_VIRTUAL warns on for generic_ops' kernel-image address"
        );
    }
    Ok(())
}

impl WriteSafetyEvidence for LinuxEvidence {
    fn names_efivarfs_reconfigure(&self) -> Result<bool> {
        Ok(self.symbols()?.efivarfs_reconfigure)
    }

    /// generic_ops' words, from /proc/kcore, which root reads under kernel lockdown integrity but
    /// not confidentiality (LOCKDOWN_KCORE; Linux v6.7 fs/proc/kcore.c open_kcore()), so the
    /// lockdown check comes first. A security module may audit the open.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn generic_set_variable(&self) -> Result<GenericSetVariable> {
        let symbols = self.symbols()?;
        symbols.require_generic_ops()?;
        if let Some(since) = self.kcore_safe_since {
            refuse_kcore_before(&self.osrelease, since)?;
        }
        refuse_locked_down(MemoryDevice::Kcore, &self.lockdown)?;
        let kcore = File::open(&self.kcore)
            .with_context(|| format!("Failed to open {}", self.kcore.display()))
            .map_err(|error| mark_refused_open(error, MemoryDevice::Kcore, &self.lockdown))?;
        symbols.generic_set_variable(|address, length| {
            read_kcore_file(&kcore, &self.kcore, KcoreAddress::Virtual(address), length)
        })
    }

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    fn generic_set_variable(&self) -> Result<GenericSetVariable> {
        bail!(
            "uefisettings reads Linux's generic_ops through /proc/kcore only on x86_64 and aarch64"
        )
    }

    fn rt_properties_in_boot_log(&self) -> Result<RtPropertiesInBootLog> {
        rt_properties_in_boot_log(
            &self.kmsg,
            |path| {
                let file = open_kmsg(path)?;
                match self.kmsg_device {
                    Some(device) => require_char_device(path, file, device),
                    None => Ok(file),
                }
            },
            self.kernel_log.as_ref(),
        )
    }

    /// The RT properties table that the System Table lists, from /dev/mem (system_table).
    #[cfg(firmware_memory_maps)]
    fn rt_properties_supported(&self) -> Result<Option<u32>> {
        read_rt_properties_supported(&self.system_table, DevMem::open)
    }

    /// Refuses: no firmware memory map bounds the read of the table on this architecture.
    #[cfg(not(firmware_memory_maps))]
    fn rt_properties_supported(&self) -> Result<Option<u32>> {
        Err(MemoryMapUnavailable::NoMapReader.into())
    }
}

/// Keeps the efivarfs at `mount_point` read-write while it lives, remounting it read-only again
/// if it was.
pub struct EfivarsMountGuard {
    mount_point: PathBuf,
    original_flags: MsFlags,
}

impl EfivarsMountGuard {
    /// Remounts `mount_point` read-write if it is read-only, once `_survives` proves that a
    /// write cannot crash this Linux.
    pub fn new(mount_point: &Path, _survives: &KernelSurvivesWrites) -> Result<Self> {
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

impl VariableInfoSource for EfivarFiles {
    fn variable_info(&self, key: &VariableKey) -> Result<VariableInfo> {
        let name = EfivarFileName::from(key);
        let file = open_efivar(&self.dir, &name).map_err(|error| as_variable_not_found(key, error));
        let file = match file {
            Err(error) if error.is::<VariableNotFound>() => {
                // as variable_names says, where no efivarfs is mounted
                efivarfs_statfs(&self.dir)?;
                return Err(error);
            }
            result => result?,
        };
        let bytes = read_efivar_file_of(&file).with_context(|| {
            format!(
                "failed to read efivar file '{}'",
                self.dir.join(&name).display()
            )
        })?;
        efivar_info(key, &bytes)
    }
}

/// The VariableInfo of `key` from the `bytes` of its efivar file: the size comes from what a
/// read gives, as efivarfs reads the whole variable from the firmware on each read() (Linux
/// v6.17 fs/efivarfs/file.c efivarfs_file_read()) but sets the file's size only when it lists
/// or writes the variable (super.c efivarfs_create_dentry(), file.c efivarfs_file_write()). No
/// bytes hold no variable (efivar_names), as a read gives none of one that the firmware dropped
/// since efivarfs listed it (efivarfs_file_read()).
fn efivar_info(key: &VariableKey, bytes: &[u8]) -> Result<VariableInfo> {
    if bytes.is_empty() {
        return Err(VariableNotFound(key.clone()).into());
    }
    let (attributes, data) = bytes
        .split_first_chunk::<EFIVARFS_HEADER_SIZE>()
        .with_context(|| {
            format!(
                "efivar file of EFI variable {key} holds {} bytes, fewer than its attributes",
                bytes.len()
            )
        })?;
    Ok(VariableInfo {
        variable: key.to_string(),
        attributes: u32::from_ne_bytes(*attributes),
        size: data.len(),
    })
}

impl VariableData for EfivarFiles {
    /// The contents of `key` from its efivar file, which read_efivar_file_of reads whole.
    fn variable_data(&self, key: &VariableKey) -> Result<Option<VariableContents>> {
        let name = EfivarFileName::from(key);
        let file = match open_efivar(&self.dir, &name) {
            Err(error) if error.is::<EfivarNotFound>() => return Ok(None),
            result => result?,
        };
        let bytes = read_efivar_file_of(&file).with_context(|| {
            format!(
                "failed to read efivar file '{}'",
                self.dir.join(&name).display()
            )
        })?;
        efivar_contents(key, &bytes)
    }

    /// Writes the attributes and data of `contents` to the efivar file of `key` as write_at
    /// writes, which creates the variable if the file is missing.
    fn set_variable(&self, key: &VariableKey, contents: &VariableContents) -> Result<()> {
        let mut lock = FileLock::new(&self.remount_lock);
        lock.lock()?;

        let path = self.dir.join(EfivarFileName::from(key));
        let exists = match fs::symlink_metadata(&path) {
            Ok(metadata) => {
                check_regular_file(&path, &metadata, "efivar file")?;
                true
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("failed to stat efivar file '{}'", path.display()))
            }
        };

        let survives = self.survives()?;
        let _efifs = EfivarsMountGuard::new(&self.dir, survives)
            .context("Failed to create efivars fs mount guard")?;

        // efivarfs makes the file of a variable that Linux does not know immutable, as for
        // write_at.
        let _immutability_attribute_guard = exists
            .then(|| EfivarsImmutabilityGuard::new(&path))
            .transpose()
            .context("failed to create immutability attribute guard")?;

        debug!("Writing value to {}", path.display());
        write_efivar_file(&path, &efivar_file_bytes(contents))
    }
}

/// The bytes of the efivar file of `contents`, as efivar_contents reads them.
fn efivar_file_bytes(contents: &VariableContents) -> Vec<u8> {
    [
        &contents.attributes().bits().to_ne_bytes()[..],
        contents.data(),
    ]
    .concat()
}

/// The contents of `key` from the `bytes` of its efivar file: its attributes word, then its data.
/// A file of no bytes holds no variable (efivar_names).
fn efivar_contents(key: &VariableKey, bytes: &[u8]) -> Result<Option<VariableContents>> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let (attributes, data) = bytes
        .split_first_chunk::<EFIVARFS_HEADER_SIZE>()
        .with_context(|| {
            format!(
                "efivar file of EFI variable {key} holds {} bytes, fewer than its attributes",
                bytes.len()
            )
        })?;
    let attributes = VariableAttributes::from_bits_retain(u32::from_ne_bytes(*attributes));
    VariableContents::new(attributes, data.to_vec())
        .map(Some)
        .with_context(|| format!("efivar file of EFI variable {key}"))
}

impl VariableStorageInfo for EfivarFiles {
    /// What the statfs of efivarfs tells: QueryVariableInfo() of EFIVARFS_STATFS_ATTRIBUTES only,
    /// and of those not MaximumVariableSize.
    fn variable_storage(&self, attributes: VariableAttributes) -> Result<VariableStorage> {
        // QueryVariableInfo() ignores EFI_VARIABLE_APPEND_WRITE (UEFI 2.10 §8.2.4)
        if attributes.difference(VariableAttributes::APPEND_WRITE) != EFIVARFS_STATFS_ATTRIBUTES {
            return Err(UnsupportedStorageAttributes(attributes).into());
        }
        StatfsSizes::try_from(&efivarfs_statfs(&self.dir)?)?.storage()
    }
}

/// Attributes of variables whose storage the statfs of efivarfs does not tell.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error(
    "efivarfs tells the storage of {} variables only, not of {0} variables",
    EFIVARFS_STATFS_ATTRIBUTES
)]
struct UnsupportedStorageAttributes(VariableAttributes);

/// The sizes in a statfs: blocks of `block_size` bytes, `free_blocks` of them free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StatfsSizes {
    block_size: u64,
    blocks: u64,
    free_blocks: u64,
}

impl TryFrom<&Statfs> for StatfsSizes {
    type Error = anyhow::Error;

    fn try_from(stat: &Statfs) -> Result<Self> {
        Ok(Self {
            block_size: u64::try_from(stat.block_size())?,
            blocks: stat.blocks(),
            free_blocks: stat.blocks_free(),
        })
    }
}

impl StatfsSizes {
    /// The VariableStorage that these, of efivarfs, tell: since Linux v6.5 (d86ff3333cb1)
    /// efivarfs_statfs() puts MaximumVariableStorageSize in f_blocks and
    /// RemainingVariableStorageSize in f_bfree, of blocks of 1 byte, and no blocks where
    /// QueryVariableInfo() fails or is not supported at runtime.
    fn storage(self) -> Result<VariableStorage> {
        if self.blocks == 0 {
            return Err(NoVariableStorage.into());
        }
        Ok(VariableStorage {
            maximum_variable_storage_size: self.bytes(self.blocks)?,
            remaining_variable_storage_size: self.bytes(self.free_blocks)?,
            maximum_variable_size: None,
        })
    }

    /// The bytes of `blocks` blocks.
    fn bytes(self, blocks: u64) -> Result<u64> {
        blocks
            .checked_mul(self.block_size)
            .with_context(|| format!("{blocks} blocks of {} bytes overflow u64", self.block_size))
    }
}

/// Why efivarfs tells no storage of variables.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error(
    "efivarfs tells no storage of variables: Linux before v6.5 tells none, nor does a later one \
     where the firmware's QueryVariableInfo() fails or is not supported at runtime; ask \
     uefisettings.efi in the UEFI Shell"
)]
struct NoVariableStorage;

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
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
    use crate::hii::boot_log::fixture::FakeSyslog;
    use crate::hii::efivarfs_format::read_efivar_file;
    use crate::hii::efivarfs_format::tests::SETUP;
    use crate::hii::efivarfs_format::MAX_EFIVAR_FILE_SIZE;
    use crate::hii::kallsyms::fixture::write_kallsyms;
    use crate::hii::kallsyms::fixture::FIXED_KALLSYMS;
    use crate::hii::kallsyms::fixture::UNFIXED_KALLSYMS;
    use crate::hii::variables::tests::variable_key;
    use crate::hii::variables::tests::BS_RT;
    use crate::hii::variables::tests::EFI_GLOBAL_VARIABLE;
    use crate::hii::variables::tests::NV_BS_RT;

    /// LinuxEvidence of the files in `dir`, kallsyms with the symbol table `kallsyms`, and a
    /// syslog(2) that fails; the others are missing unless a test writes them.
    fn linux_evidence(dir: &Path, kallsyms: &str) -> LinuxEvidence {
        let evidence = LinuxEvidence {
            kallsyms: dir.join("kallsyms"),
            symbols: OnceLock::new(),
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            lockdown: dir.join("lockdown"),
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            kcore: dir.join("kcore"),
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            osrelease: dir.join("osrelease"),
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            kcore_safe_since: None,
            kmsg: dir.join("kmsg"),
            kmsg_device: None,
            kernel_log: Box::new(FakeSyslog(Err(libc::ENOSYS))),
            #[cfg(firmware_memory_maps)]
            system_table: SystemTableFiles {
                locator: crate::hii::system_table::SystemTableLocator::BootParams {
                    boot_params: dir.join("boot_params"),
                    config_table: dir.join("config_table"),
                },
                maps: crate::hii::firmware_memory::MemoryMapFiles::Sysfs {
                    runtime_map: dir.join("runtime-map"),
                    firmware_memmap: dir.join("memmap"),
                },
                dev_mem: dir.join("mem"),
                lockdown: dir.join("lockdown"),
            },
        };
        write_kallsyms(&evidence.kallsyms, kallsyms);
        evidence
    }

    /// EfivarFiles of a temporary directory, which no mount lists, and their remount lock, in a
    /// directory of its own, with the evidence of a temporary directory with the symbol table
    /// `kallsyms`; the directories.
    fn unmounted_efivar_files_of(kallsyms: &str) -> ([TempDir; 3], EfivarFiles) {
        let dir = tempfile::tempdir().expect("create efivars directory");
        let lock = tempfile::tempdir().expect("create lock directory");
        let evidence = tempfile::tempdir().expect("create evidence directory");
        let files = EfivarFiles {
            dir: dir.path().to_path_buf(),
            remount_lock: lock.path().join("remount"),
            evidence: Box::new(linux_evidence(evidence.path(), kallsyms)),
            survives: OnceLock::new(),
        };
        ([dir, lock, evidence], files)
    }

    /// unmounted_efivar_files_of a kernel that names efivarfs_reconfigure().
    fn unmounted_efivar_files() -> ([TempDir; 3], EfivarFiles) {
        unmounted_efivar_files_of(FIXED_KALLSYMS)
    }

    /// write_at refuses a volatile, short or missing variable before it remounts efivarfs, which
    /// fails for a directory that no mount lists, and writes nothing.
    #[test]
    fn efivar_files_refuse_a_variable_before_the_remount() {
        let ([dir, _lock, _evidence], files) = unmounted_efivar_files();
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
        let ([dir, _lock, _evidence], files) = unmounted_efivar_files();
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
        let ([dir, _lock, _evidence], files) = unmounted_efivar_files();
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

    /// efivar_info tells the attributes and data size of a variable from the bytes of its
    /// efivar file, and refuses no bytes as a missing variable and fewer than the attributes.
    #[test]
    fn efivar_info_tells_the_attributes_and_size_of_the_bytes_read() {
        let key = variable_key("Setup");

        assert_eq!(
            efivar_info(&key, &SETUP).expect("tell the variable"),
            VariableInfo {
                variable: "Setup-00000000-0000-0000-0000-000000000000".to_string(),
                attributes: NV_BS_RT,
                size: SETUP.len() - EFIVARFS_HEADER_SIZE,
            },
            "info"
        );
        for (bytes, refusal) in [
            (
                &[][..],
                "no EFI variable Setup-00000000-0000-0000-0000-000000000000",
            ),
            (
                &SETUP[..3],
                "efivar file of EFI variable Setup-00000000-0000-0000-0000-000000000000 holds 3 \
                 bytes, fewer than its attributes",
            ),
        ] {
            let error = efivar_info(&key, bytes).expect_err("tell an empty or short file");

            assert_eq!(error.to_string(), refusal, "{} bytes", bytes.len());
        }
    }

    /// efivar_info tells a variable that the firmware dropped since efivarfs listed it as
    /// missing: its file keeps its size, but a read gives no bytes (Linux v6.17
    /// fs/efivarfs/file.c efivarfs_file_read()).
    #[test]
    fn efivar_info_tells_a_variable_deleted_since_the_listing_missing() {
        let key = variable_key("Setup");
        let size = u64::try_from(SETUP.len()).expect("a u64 size");
        let bytes = read_efivar_file(io::empty(), size).expect("read a deleted variable");

        let error = efivar_info(&key, &bytes).expect_err("tell a deleted variable");

        assert_eq!(
            error.downcast_ref::<VariableNotFound>(),
            Some(&VariableNotFound(key)),
            "{error:#}"
        );
    }

    /// EfivarFiles tell a variable from its efivar file, and that an empty one holds none; of a
    /// missing one, that no efivarfs is mounted, as the listing says.
    #[test]
    fn efivar_files_tell_a_variable_or_that_it_is_missing() {
        let ([dir, _lock, _evidence], files) = unmounted_efivar_files();
        for (name, bytes) in [("Setup", &SETUP[..]), ("Empty", &[][..])] {
            fs::write(
                dir.path().join(EfivarFileName::from(&variable_key(name))),
                bytes,
            )
            .expect("write the efivar file");
        }

        assert_eq!(
            files
                .variable_info(&variable_key("Setup"))
                .expect("tell Setup"),
            VariableInfo {
                variable: "Setup-00000000-0000-0000-0000-000000000000".to_string(),
                attributes: NV_BS_RT,
                size: SETUP.len() - EFIVARFS_HEADER_SIZE,
            },
            "Setup"
        );
        let empty = files
            .variable_info(&variable_key("Empty"))
            .expect_err("tell an empty efivar file");
        let missing = files
            .variable_info(&variable_key("Missing"))
            .expect_err("tell a missing efivar file");

        assert_eq!(
            empty.downcast_ref::<VariableNotFound>(),
            Some(&VariableNotFound(variable_key("Empty"))),
            "Empty: {empty:#}"
        );
        assert_eq!(
            missing.downcast_ref::<NotEfivarfs>(),
            Some(&NotEfivarfs(dir.path().to_path_buf())),
            "Missing: {missing:#}"
        );
    }

    /// FirmwareVariables::read_whole of EfivarFiles gives the whole efivar file of a variable,
    /// and VariableNotFound for a missing one.
    #[test]
    fn efivar_files_give_whole_efivar_files() {
        let ([dir, _lock, _evidence], files) = unmounted_efivar_files();
        fs::write(
            dir.path()
                .join(EfivarFileName::from(&variable_key("Setup"))),
            SETUP,
        )
        .expect("write the efivar file");

        assert_eq!(
            files
                .read_whole(&variable_key("Setup"))
                .expect("read Setup whole"),
            SETUP,
            "Setup"
        );
        let error = files
            .read_whole(&variable_key("Missing"))
            .expect_err("read Missing whole");
        assert_eq!(
            error.downcast_ref::<VariableNotFound>(),
            Some(&VariableNotFound(variable_key("Missing"))),
            "Missing: {error:#}"
        );
    }

    /// EfivarFiles read the attributes and data of a variable from its efivar file, tell that a
    /// missing or empty one holds none, and refuse one without data.
    #[test]
    fn efivar_files_read_a_variable_whole_or_tell_it_absent() {
        let ([dir, _lock, _evidence], files) = unmounted_efivar_files();
        let attributes_only = NV_BS_RT.to_ne_bytes();
        for (name, bytes) in [
            ("Setup", &SETUP[..]),
            ("Empty", &[][..]),
            ("AttributesOnly", &attributes_only[..]),
            ("Short", &[7, 0, 0][..]),
        ] {
            fs::write(
                dir.path().join(EfivarFileName::from(&variable_key(name))),
                bytes,
            )
            .expect("write the efivar file");
        }

        let contents = files
            .variable_data(&variable_key("Setup"))
            .expect("read Setup")
            .expect("Setup is present");

        assert_eq!(
            (contents.attributes().bits(), contents.data()),
            (NV_BS_RT, &SETUP[EFIVARFS_HEADER_SIZE..]),
            "Setup"
        );
        for name in ["Missing", "Empty"] {
            assert_eq!(
                files
                    .variable_data(&variable_key(name))
                    .unwrap_or_else(|error| panic!("read {name}: {error:#}")),
                None,
                "{name}"
            );
        }
        for (name, refusal) in [
            (
                "AttributesOnly",
                "efivar file of EFI variable AttributesOnly-00000000-0000-0000-0000-000000000000: \
                 an EFI variable holds one byte of data at least (UEFI 2.11 section 8.2.3)",
            ),
            (
                "Short",
                "efivar file of EFI variable Short-00000000-0000-0000-0000-000000000000 holds 3 \
                 bytes, fewer than its attributes",
            ),
        ] {
            let error = files
                .variable_data(&variable_key(name))
                .expect_err("read a variable without data");

            assert_eq!(format!("{error:#}"), refusal, "{name}");
        }
    }

    /// The bytes that set_variable writes to an efivar file read back as the contents written.
    #[test]
    fn efivar_file_bytes_read_back_as_their_contents() {
        let contents = VariableContents::new(
            VariableAttributes::from_bits_retain(NV_BS_RT),
            vec![1, 2, 3],
        )
        .expect("hold three bytes");

        let bytes = efivar_file_bytes(&contents);

        assert_eq!(
            efivar_contents(&variable_key("Setup"), &bytes).expect("read the bytes back"),
            Some(contents),
            "the contents read back"
        );
    }

    /// EfivarFiles tell the storage of NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS
    /// variables only, with APPEND_WRITE or without, from the statfs of efivarfs, and refuse other
    /// attributes before the statfs, naming them.
    #[test]
    fn efivar_files_tell_the_storage_of_non_volatile_runtime_variables_only() {
        let ([dir, _lock, _evidence], files) = unmounted_efivar_files();
        for attributes in [
            EFIVARFS_STATFS_ATTRIBUTES,
            EFIVARFS_STATFS_ATTRIBUTES | VariableAttributes::APPEND_WRITE,
        ] {
            let error = files
                .variable_storage(attributes)
                .expect_err("statfs a directory without efivarfs");

            assert_eq!(
                error.downcast_ref::<NotEfivarfs>(),
                Some(&NotEfivarfs(dir.path().to_path_buf())),
                "{attributes}: {error:#}"
            );
        }
        for attributes in [
            VariableAttributes::BOOTSERVICE_ACCESS | VariableAttributes::RUNTIME_ACCESS,
            VariableAttributes::NON_VOLATILE | VariableAttributes::BOOTSERVICE_ACCESS,
            EFIVARFS_STATFS_ATTRIBUTES | VariableAttributes::HARDWARE_ERROR_RECORD,
        ] {
            let error = files
                .variable_storage(attributes)
                .expect_err("tell the storage of other attributes");

            assert_eq!(
                error.to_string(),
                format!(
                    "efivarfs tells the storage of NON_VOLATILE | BOOTSERVICE_ACCESS | \
                     RUNTIME_ACCESS variables only, not of {attributes} variables"
                ),
                "{attributes}"
            );
        }
    }

    /// The sizes in the statfs of efivarfs tell its storage in bytes, but no maximum variable
    /// size, and no storage where they hold no blocks.
    #[test]
    fn statfs_sizes_tell_the_storage_in_bytes() {
        let storage = |maximum, remaining| VariableStorage {
            maximum_variable_storage_size: maximum,
            remaining_variable_storage_size: remaining,
            maximum_variable_size: None,
        };
        let cases = [
            ((1, 65536, 40000), Ok(storage(65536, 40000))),
            ((4096, 2, 1), Ok(storage(8192, 4096))),
            (
                (1, 0, 0),
                Err(
                    "efivarfs tells no storage of variables: Linux before v6.5 tells none, nor \
                     does a later one where the firmware's QueryVariableInfo() fails or is not \
                     supported at runtime; ask uefisettings.efi in the UEFI Shell"
                        .to_string(),
                ),
            ),
            (
                (2, u64::MAX, 0),
                Err(format!("{} blocks of 2 bytes overflow u64", u64::MAX)),
            ),
        ];

        for ((block_size, blocks, free_blocks), want) in cases {
            let sizes = StatfsSizes {
                block_size,
                blocks,
                free_blocks,
            };

            assert_eq!(
                sizes.storage().map_err(|error| error.to_string()),
                want,
                "{sizes:?}"
            );
        }
    }

    /// write_at writes nothing when it cannot remount efivarfs.
    #[test]
    fn efivar_files_write_nothing_without_the_remount() {
        let ([dir, _lock, _evidence], files) = unmounted_efivar_files();
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

    /// On a kernel without efivarfs_reconfigure() whose log names an RT properties table that it
    /// applied, write_at refuses before it remounts efivarfs when it cannot read the table, says
    /// what each step found, and writes nothing.
    #[test]
    fn efivar_files_refuse_a_write_that_may_crash_before_the_remount() {
        let ([dir, _lock, evidence], files) = unmounted_efivar_files_of(UNFIXED_KALLSYMS);
        fs::write(
            evidence.path().join("kmsg"),
            "6,12,1000,-;efi: ACPI=0x3fb7e000 RTPROP=0x3f989998 \n",
        )
        .expect("write the kernel log");
        let key = variable_key("Setup");
        let path = dir.path().join(EfivarFileName::from(&key));
        let bytes = [&NV_BS_RT.to_ne_bytes()[..], &[0; 4]].concat();
        fs::write(&path, &bytes).expect("write the efivar file");

        let error = files
            .write_at(&key, 4, 0, &[1])
            .expect_err("write on a kernel that may crash");

        assert_eq!(
            error.downcast_ref::<CrashingWrite>(),
            Some(&CrashingWrite::Unknown),
            "{error:#}"
        );
        let message = format!("{error:#}");
        for step in [
            "the kernel names no efivarfs_reconfigure()",
            "the kernel log names an EFI_RT_PROPERTIES_TABLE that Linux applied",
        ] {
            assert!(message.contains(step), "{message:?} lacks {step:?}");
        }
        assert!(
            !message.contains("mount guard"),
            "{message:?}: refused after the remount"
        );
        assert_eq!(
            fs::read(&path).expect("read the efivar file"),
            bytes,
            "bytes"
        );
    }

    /// Writes, in `dir`, the lockdown file of `mode` and a /proc/kcore whose kernel text holds,
    /// at the generic_ops of GENERIC_OPS_KALLSYMS, the words `words`.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn write_generic_ops(dir: &Path, mode: &str, words: [u64; 3]) {
        use crate::hii::firmware_memory::kcore::fixture::kcore_fixture_of;
        use crate::hii::kallsyms::fixture::GENERIC_OPS_AT;

        fs::write(dir.join("lockdown"), mode).expect("write the lockdown file");
        let text = [
            &[0xcc; 0x20][..],
            &words
                .iter()
                .flat_map(|word| word.to_le_bytes())
                .collect::<Vec<u8>>(),
            &[0xcc; 0x20],
        ]
        .concat();
        kcore_fixture_of(
            &dir.join("kcore"),
            &[(0x3c1_a2c0, GENERIC_OPS_AT - 0x20, &text)],
        );
    }

    /// On a kernel before the release that kcore_safe_since gives, LinuxEvidence refuses to read
    /// generic_ops before it reads the lockdown mode or opens /proc/kcore; from that release on,
    /// it reads them.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn linux_evidence_reads_kcore_only_since_the_release_given() {
        use crate::hii::kallsyms::fixture::GENERIC_OPS_KALLSYMS;
        use crate::hii::kallsyms::fixture::GET_NEXT_VARIABLE_AT;
        use crate::hii::kallsyms::fixture::GET_VARIABLE_AT;
        use crate::hii::kallsyms::fixture::SET_VARIABLE_AT;

        for (release, want) in [
            ("5.13.19-100.fc33.aarch64\n", None),
            ("5.14.0\n", Some(GenericSetVariable::Present)),
        ] {
            let dir = tempfile::tempdir().expect("create a directory");
            let mut evidence = linux_evidence(dir.path(), GENERIC_OPS_KALLSYMS);
            evidence.kcore_safe_since = Some(KernelRelease {
                major: 5,
                minor: 14,
            });
            write_generic_ops(
                dir.path(),
                "[none] integrity confidentiality\n",
                [GET_VARIABLE_AT, GET_NEXT_VARIABLE_AT, SET_VARIABLE_AT],
            );
            fs::write(&evidence.osrelease, release).expect("write the kernel release");
            let watch = Inotify::init(InitFlags::IN_NONBLOCK).expect("create an inotify instance");
            watch
                .add_watch(dir.path(), AddWatchFlags::IN_OPEN)
                .expect("watch the directory");

            let got = evidence.generic_set_variable();

            let opened = touched(&watch);
            match want {
                Some(want) => {
                    let got = got.unwrap_or_else(|error| panic!("{release:?}: {error:#}"));
                    assert_eq!(got, want, "{release:?}");
                    assert!(
                        opened.iter().any(|name| name == "kcore"),
                        "{release:?}: kcore unopened: {opened:?}"
                    );
                }
                None => {
                    let error = got.expect_err("read generic_ops before the release");
                    assert_eq!(
                        format!("{error:#}"),
                        "Linux before v5.14 calls __pa() on every /proc/kcore address \
                         (2711032c64a9), which arm64's CONFIG_DEBUG_VIRTUAL warns on for \
                         generic_ops' kernel-image address",
                        "{release:?}"
                    );
                    assert!(
                        !opened
                            .iter()
                            .any(|name| name == "kcore" || name == "lockdown"),
                        "{release:?}: opened {opened:?}"
                    );
                }
            }
        }
    }

    /// LinuxEvidence reads generic_ops through the kernel text of /proc/kcore, under kernel
    /// lockdown integrity too, but refuses to open it under confidentiality.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn linux_evidence_reads_generic_ops_through_kcore() {
        use crate::hii::kallsyms::fixture::GENERIC_OPS_KALLSYMS;
        use crate::hii::kallsyms::fixture::GET_NEXT_VARIABLE_AT;
        use crate::hii::kallsyms::fixture::GET_VARIABLE_AT;
        use crate::hii::kallsyms::fixture::SET_VARIABLE_AT;
        use crate::hii::lockdown::LockdownMode;
        use crate::hii::memory_access_denied::DenialCause;
        use crate::hii::memory_access_denied::MemoryAccessDenied;
        use crate::hii::memory_access_denied::MemoryOperation;

        const NONE: &str = "[none] integrity confidentiality\n";
        const INTEGRITY: &str = "none [integrity] confidentiality\n";
        for (case, mode, set, want) in [
            (
                "SetVariable() left out",
                NONE,
                0,
                GenericSetVariable::Absent,
            ),
            (
                "SetVariable()",
                NONE,
                SET_VARIABLE_AT,
                GenericSetVariable::Present,
            ),
            (
                "lockdown integrity",
                INTEGRITY,
                0,
                GenericSetVariable::Absent,
            ),
        ] {
            let dir = tempfile::tempdir().expect("create a directory");
            let evidence = linux_evidence(dir.path(), GENERIC_OPS_KALLSYMS);
            write_generic_ops(
                dir.path(),
                mode,
                [GET_VARIABLE_AT, GET_NEXT_VARIABLE_AT, set],
            );

            let got = evidence
                .generic_set_variable()
                .unwrap_or_else(|error| panic!("{case}: {error:#}"));

            assert_eq!(got, want, "{case}");
        }

        let dir = tempfile::tempdir().expect("create a directory");
        let evidence = linux_evidence(dir.path(), GENERIC_OPS_KALLSYMS);
        write_generic_ops(
            dir.path(),
            "none integrity [confidentiality]\n",
            [GET_VARIABLE_AT, GET_NEXT_VARIABLE_AT, 0],
        );
        let error = evidence
            .generic_set_variable()
            .expect_err("read /proc/kcore under confidentiality");
        assert_eq!(
            error.downcast_ref::<MemoryAccessDenied>(),
            Some(&MemoryAccessDenied {
                device: MemoryDevice::Kcore,
                operation: MemoryOperation::Open,
                cause: DenialCause::Lockdown(LockdownMode::Confidentiality),
            }),
            "confidentiality: {error:#}"
        );

        let dir = tempfile::tempdir().expect("create a directory");
        let evidence = linux_evidence(dir.path(), GENERIC_OPS_KALLSYMS);
        fs::write(dir.path().join("lockdown"), NONE).expect("write the lockdown file");
        crate::hii::firmware_memory::kcore::fixture::kcore_fixture(
            &dir.path().join("kcore"),
            &[(0x100_0000, &[0; 0x40])],
        );
        let error = evidence
            .generic_set_variable()
            .expect_err("read generic_ops outside every segment");
        assert!(
            format!("{error:#}").contains("no segment holds virtual 0xffffffff83c1a2e0+0x18"),
            "no segment: {error:#}"
        );

        let dir = tempfile::tempdir().expect("create a directory");
        let evidence = linux_evidence(dir.path(), GENERIC_OPS_KALLSYMS);
        fs::write(dir.path().join("lockdown"), NONE).expect("write the lockdown file");
        let error = evidence
            .generic_set_variable()
            .expect_err("read generic_ops without /proc/kcore");
        let message = format!("{error:#}");
        assert!(
            message.contains(&format!(
                "Failed to open {}",
                dir.path().join("kcore").display()
            )) && !message.contains("memory map"),
            "no kcore: {message}"
        );

        let dir = tempfile::tempdir().expect("create a directory");
        let evidence = linux_evidence(dir.path(), FIXED_KALLSYMS);
        fs::write(dir.path().join("lockdown"), NONE).expect("write the lockdown file");
        let error = evidence
            .generic_set_variable()
            .expect_err("read generic_ops without its address");
        let message = format!("{error:#}");
        assert!(
            message.contains("no address of generic_ops") && !message.contains("Failed to open"),
            "no address: {message}"
        );
    }

    /// On a kernel without efivarfs_reconfigure() whose generic_ops lacks SetVariable(),
    /// write_at refuses before it remounts efivarfs, whatever the boot log and the RT properties
    /// table say, and writes nothing.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn efivar_files_refuse_a_kernel_without_set_variable_before_the_remount() {
        use crate::hii::kallsyms::fixture::GENERIC_OPS_KALLSYMS;
        use crate::hii::kallsyms::fixture::GET_NEXT_VARIABLE_AT;
        use crate::hii::kallsyms::fixture::GET_VARIABLE_AT;

        let ([dir, _lock, evidence], files) = unmounted_efivar_files_of(GENERIC_OPS_KALLSYMS);
        write_generic_ops(
            evidence.path(),
            "[none] integrity confidentiality\n",
            [GET_VARIABLE_AT, GET_NEXT_VARIABLE_AT, 0],
        );
        let key = variable_key("Setup");
        let path = dir.path().join(EfivarFileName::from(&key));
        let bytes = [&NV_BS_RT.to_ne_bytes()[..], &[0; 4]].concat();
        fs::write(&path, &bytes).expect("write the efivar file");

        let error = files
            .write_at(&key, 4, 0, &[1])
            .expect_err("write on a kernel without SetVariable()");

        assert_eq!(
            error.downcast_ref::<CrashingWrite>(),
            Some(&CrashingWrite::NoSetVariable),
            "{error:#}"
        );
        assert!(
            !format!("{error:#}").contains("mount guard"),
            "{error:#}: refused after the remount"
        );
        assert_eq!(
            fs::read(&path).expect("read the efivar file"),
            bytes,
            "bytes"
        );
    }

    /// The refusals say why, word for word, and point at uefisettings.efi in the UEFI Shell, as
    /// NoRuntimeSetVariable does.
    #[test]
    fn crashing_write_texts() {
        for (refusal, want) in [
            (
                CrashingWrite::NoSetVariable,
                "Linux has no runtime SetVariable() and, without efivarfs_reconfigure() (upstream \
                 0e8d2444168d, Linux v6.8), crashes on an efivarfs write; run uefisettings.efi in \
                 the UEFI Shell",
            ),
            (
                CrashingWrite::TableOmitsSetVariable(0x3fbf),
                "Linux without efivarfs_reconfigure() (upstream 0e8d2444168d, Linux v6.8) crashes \
                 on an efivarfs write without a runtime SetVariable(), as on firmware whose \
                 EFI_RT_PROPERTIES_TABLE (UEFI 2.11 §4.6.2) leaves it out, as this one does \
                 (RuntimeServicesSupported 0x3fbf); run uefisettings.efi in the UEFI Shell",
            ),
            (
                CrashingWrite::Unknown,
                "Linux without efivarfs_reconfigure() (upstream 0e8d2444168d, Linux v6.8) crashes \
                 on an efivarfs write without a runtime SetVariable(), as on firmware whose \
                 EFI_RT_PROPERTIES_TABLE (UEFI 2.11 §4.6.2) leaves it out, and uefisettings \
                 cannot tell whether this one does; run uefisettings.efi in the UEFI Shell",
            ),
        ] {
            assert_eq!(refusal.to_string(), want, "{refusal:?}");
        }
    }

    /// LinuxEvidence reads the boot log only from the kernel log's character device: a file in
    /// its place, such as a container may bind-mount, tells nothing, though it names an applied
    /// RT properties table, which the tests' evidence, taking any file, finds in it.
    #[test]
    fn linux_evidence_reads_the_boot_log_only_from_the_kmsg_device() {
        let dir = tempfile::tempdir().expect("create a directory");
        let mut evidence = linux_evidence(dir.path(), UNFIXED_KALLSYMS);
        fs::write(
            &evidence.kmsg,
            "6,12,1000,-;efi: ACPI=0x3fb7e000 RTPROP=0x3f989998 \n",
        )
        .expect("write the kernel log");
        assert_eq!(
            evidence.rt_properties_in_boot_log().ok(),
            Some(RtPropertiesInBootLog::Present),
            "any file"
        );

        evidence.kmsg_device = Some(KMSG_DEVICE);
        let error = evidence
            .rt_properties_in_boot_log()
            .expect_err("read a file as the kernel log's device");
        let kmsg = evidence.kmsg.display();
        assert_eq!(
            format!("{error:#}"),
            format!("Failed to open {kmsg}: {kmsg} is not the character device 1:11"),
            "the kernel log's device"
        );
    }

    /// The RT properties table, as Linux finds it through the System Table.
    #[cfg(firmware_memory_maps)]
    mod rt_properties {
        use std::os::unix::fs::FileExt;

        use super::*;
        use crate::firmware_width::FirmwareWidth;
        use crate::hii::system_table::fixture::configuration_table;
        use crate::hii::system_table::fixture::valid_system_table;
        use crate::hii::system_table::fixture::x86_files;
        use crate::hii::system_table::fixture::SegmentMemory;
        use crate::memory_map::efi_memory_map::MemoryType;

        /// Two runtime data regions: A, whose virtual addresses after SetVirtualAddressMap() are
        /// B's physical ones, and B.
        const REGION_A_AT: u64 = 0x7e00_0000;
        const REGION_B_AT: u64 = 0x7f00_0000;
        const REGION_PAGES: u64 = 16;
        const REGIONS: [(MemoryType, u64, u64, u64); 2] = [
            (
                MemoryType::RUNTIME_SERVICES_DATA,
                REGION_A_AT,
                REGION_B_AT,
                REGION_PAGES,
            ),
            (
                MemoryType::RUNTIME_SERVICES_DATA,
                REGION_B_AT,
                0xffff_fffe_ff00_0000,
                REGION_PAGES,
            ),
        ];
        /// The System Table and its entries, in A.
        const SYSTEM_TABLE_AT: u64 = REGION_A_AT + 0x18;
        const ENTRIES_AT: u64 = REGION_A_AT + 0x200;
        /// The RT properties table, in B, where its pointer taken as virtual leads to A.
        const TABLE_AT: u64 = REGION_B_AT + 0x100;
        const DECOY_AT: u64 = REGION_A_AT + 0x100;
        /// Another table that the System Table lists.
        const OTHER: Guid = Guid {
            data1: 0x8c78_a505,
            data2: 0xbaa0,
            data3: 0x4c4a,
            data4: [0x86, 0x9f, 0, 0, 0, 0, 0x17, 0x02],
        };

        /// An EFI_RT_PROPERTIES_TABLE of `version`, `length` and `supported`, and `length` bytes
        /// in all, at least 8.
        fn rt_table(version: u16, length: u16, supported: u32) -> Vec<u8> {
            let mut bytes = [
                &version.to_le_bytes()[..],
                &length.to_le_bytes(),
                &supported.to_le_bytes(),
            ]
            .concat();
            bytes.resize(usize::from(length).max(RT_PROPERTIES_TABLE_SIZE), 0xa5);
            bytes
        }

        /// The (address, bytes) of physical memory where a System Table of `width` lists
        /// `entries`, with `table` at TABLE_AT, and a decoy table that lists every runtime
        /// service at DECOY_AT.
        fn segments(
            width: FirmwareWidth,
            entries: &[(Guid, u64)],
            table: Vec<u8>,
        ) -> Vec<(u64, Vec<u8>)> {
            let count = u64::try_from(entries.len()).expect("a u64 count");
            vec![
                (
                    SYSTEM_TABLE_AT,
                    valid_system_table(width, count, ENTRIES_AT),
                ),
                (ENTRIES_AT, configuration_table(width, entries)),
                (TABLE_AT, table),
                (DECOY_AT, rt_table(1, 8, u32::MAX)),
            ]
        }

        /// What read_rt_properties_supported finds through x86's files in `dir` in `segments`.
        fn read(
            dir: &Path,
            width: FirmwareWidth,
            segments: Vec<(u64, Vec<u8>)>,
        ) -> Result<Option<u32>> {
            let files = x86_files(dir, width, SYSTEM_TABLE_AT, ENTRIES_AT, &REGIONS);
            read_rt_properties_supported(&files, |_, _| Ok(SegmentMemory(segments)))
        }

        /// The listed table's RuntimeServicesSupported is read whatever its Version and Length, as
        /// Linux reads it, at its physical address, never the virtual one that SetVirtualAddressMap()
        /// would give it.
        #[test]
        fn reads_the_table_at_its_physical_address_whatever_its_version() {
            for width in [FirmwareWidth::Bits32, FirmwareWidth::Bits64] {
                for (version, length, supported) in [(1, 8, 0x3fbf), (2, 12, 0x3fff), (0, 0, 0)] {
                    let case = format!("{width:?}: version {version}, length {length}");
                    let dir = tempfile::tempdir().expect("create a directory");
                    let entries = [(OTHER, DECOY_AT), (EFI_RT_PROPERTIES_TABLE_GUID, TABLE_AT)];

                    let got = read(
                        dir.path(),
                        width,
                        segments(width, &entries, rt_table(version, length, supported)),
                    )
                    .unwrap_or_else(|error| panic!("{case}: {error:#}"));

                    assert_eq!(got, Some(supported), "{case}");
                }
            }
        }

        /// A System Table that lists no RT properties table gives none.
        #[test]
        fn finds_no_table_that_the_system_table_does_not_list() {
            let dir = tempfile::tempdir().expect("create a directory");
            let width = FirmwareWidth::Bits64;

            let got = read(
                dir.path(),
                width,
                segments(width, &[(OTHER, TABLE_AT)], rt_table(1, 8, 0x3fbf)),
            )
            .expect("read the configuration tables");

            assert_eq!(got, None);
        }

        /// A table whose 8 bytes run past its runtime region is refused.
        #[test]
        fn refuses_a_table_past_its_region() {
            let dir = tempfile::tempdir().expect("create a directory");
            let width = FirmwareWidth::Bits64;
            let at = REGION_B_AT + REGION_PAGES * 0x1000 - 4;
            let mut segments = segments(width, &[(EFI_RT_PROPERTIES_TABLE_GUID, at)], Vec::new());
            segments.push((at, rt_table(1, 8, 0x3fbf)));

            let error = read(dir.path(), width, segments).expect_err("read past the region");

            let message = format!("{error:#}");
            assert!(
                message.contains(&format!("{at:#x}+0x8 lies in no EFI_MEMORY_RUNTIME region")),
                "{message}"
            );
        }

        /// A table that no runtime region holds is refused, though a runtime region's virtual
        /// range holds its address, as arm64's runtime virtual addresses from 512 MiB may hold
        /// the physical address of other memory: the table "will be referenced as physical and
        /// will not be fixed up" (UEFI 2.11 §4.6.2), so that address never leads to the bytes of
        /// that region, here a decoy that lists every runtime service.
        #[test]
        fn refuses_a_table_outside_the_runtime_regions() {
            const VIRTUAL_AT: u64 = 0x2000_0000;
            let dir = tempfile::tempdir().expect("create a directory");
            let width = FirmwareWidth::Bits64;
            let at = VIRTUAL_AT + (DECOY_AT - REGION_A_AT);
            let files = x86_files(
                dir.path(),
                width,
                SYSTEM_TABLE_AT,
                ENTRIES_AT,
                &[(
                    MemoryType::RUNTIME_SERVICES_DATA,
                    REGION_A_AT,
                    VIRTUAL_AT,
                    REGION_PAGES,
                )],
            );
            let memory = segments(width, &[(EFI_RT_PROPERTIES_TABLE_GUID, at)], Vec::new());

            let error = read_rt_properties_supported(&files, |_, _| Ok(SegmentMemory(memory)))
                .expect_err("read a table outside the runtime regions");

            let message = format!("{error:#}");
            assert!(
                message.contains(&format!("{at:#x}+0x8 lies in no EFI_MEMORY_RUNTIME region")),
                "{message}"
            );
        }

        /// LinuxEvidence reads the table from its /dev/mem, so that a kernel without the fix,
        /// whose log names the table and whose generic_ops it cannot read, refuses a write by the
        /// table, which leaves SetVariable() out.
        #[test]
        fn linux_evidence_refuses_by_the_table_that_it_reads_from_dev_mem() {
            let dir = tempfile::tempdir().expect("create a directory");
            let width = FirmwareWidth::Bits64;
            let mut evidence = linux_evidence(dir.path(), UNFIXED_KALLSYMS);
            evidence.system_table =
                x86_files(dir.path(), width, SYSTEM_TABLE_AT, ENTRIES_AT, &REGIONS);
            fs::write(
                &evidence.kmsg,
                "6,12,1000,-;efi: ACPI=0x3fb7e000 RTPROP=0x7f000100 \n",
            )
            .expect("write the kernel log");
            let mem =
                fs::File::create(&evidence.system_table.dev_mem).expect("create the memory file");
            let entries = [(EFI_RT_PROPERTIES_TABLE_GUID, TABLE_AT)];
            for (address, bytes) in segments(width, &entries, rt_table(1, 8, 0x3fbf)) {
                mem.write_all_at(&bytes, address)
                    .expect("write physical memory");
            }

            let error = kernel_survives_writes(&evidence).expect_err("survive the write");

            assert_eq!(
                error.downcast_ref::<CrashingWrite>(),
                Some(&CrashingWrite::TableOmitsSetVariable(0x3fbf)),
                "{error:#}"
            );
        }

        #[test]
        fn rt_properties_table_guid_is_the_specification_s() {
            assert_eq!(
                EFI_RT_PROPERTIES_TABLE_GUID.to_string(),
                "EB66918A-7EEF-402A-842E-931D21C38AE9"
            );
        }
    }

    /// An outcome of a WriteSafetyEvidence step for FakeEvidence: a value, or an error.
    type Outcome<T> = Result<T, &'static str>;

    /// Evidence of these outcomes, which records the steps asked.
    struct FakeEvidence {
        reconfigure: Outcome<bool>,
        generic: Outcome<GenericSetVariable>,
        boot_log: Outcome<RtPropertiesInBootLog>,
        table: Outcome<Option<u32>>,
        asked: RefCell<Vec<&'static str>>,
    }

    impl FakeEvidence {
        fn new(
            reconfigure: Outcome<bool>,
            generic: Outcome<GenericSetVariable>,
            boot_log: Outcome<RtPropertiesInBootLog>,
            table: Outcome<Option<u32>>,
        ) -> Self {
            Self {
                reconfigure,
                generic,
                boot_log,
                table,
                asked: RefCell::new(Vec::new()),
            }
        }

        /// `outcome` of the step `step`, recorded.
        fn ask<T: Copy>(&self, step: &'static str, outcome: Outcome<T>) -> Result<T> {
            self.asked.borrow_mut().push(step);
            outcome.map_err(|error| anyhow!(error))
        }
    }

    impl WriteSafetyEvidence for FakeEvidence {
        fn names_efivarfs_reconfigure(&self) -> Result<bool> {
            self.ask("kallsyms", self.reconfigure)
        }

        fn generic_set_variable(&self) -> Result<GenericSetVariable> {
            self.ask("kcore", self.generic)
        }

        fn rt_properties_in_boot_log(&self) -> Result<RtPropertiesInBootLog> {
            self.ask("boot log", self.boot_log)
        }

        fn rt_properties_supported(&self) -> Result<Option<u32>> {
            self.ask("table", self.table)
        }
    }

    /// What kernel_survives_writes decides.
    #[derive(Debug, PartialEq, Eq)]
    enum Decision {
        /// Proceed, after asking these steps.
        Proceed(Vec<&'static str>),
        Refuse(CrashingWrite),
    }

    /// Every combination of outcomes decides as the first step that decides says, and every
    /// combination that a kernel which crashes on the write can give is a refusal: no fix, and
    /// generic_ops without SetVariable(), or unknown with a boot log that names a table or tells
    /// nothing and a table that leaves SetVariable() out or is unreadable.
    #[test]
    fn kernel_survives_writes_decides_by_the_first_step_that_decides() {
        use GenericSetVariable as Generic;
        use RtPropertiesInBootLog::Absent;
        use RtPropertiesInBootLog::Present;
        const SET: u32 = 0x3fff;
        const CLEAR: u32 = 0x3fbf;
        for reconfigure in [Ok(true), Ok(false), Err("no kallsyms")] {
            for generic in [Ok(Generic::Absent), Ok(Generic::Present), Err("no kcore")] {
                for boot_log in [Ok(Absent), Ok(Present), Err("no kernel log")] {
                    for table in [Ok(None), Ok(Some(SET)), Ok(Some(CLEAR)), Err("no table")] {
                        let case = format!("{reconfigure:?}, {generic:?}, {boot_log:?}, {table:?}");
                        let evidence = FakeEvidence::new(reconfigure, generic, boot_log, table);

                        let got = kernel_survives_writes(&evidence);

                        let all = vec!["kallsyms", "kcore", "boot log", "table"];
                        let want = match (reconfigure, generic, boot_log, table) {
                            (Ok(true), ..) => Decision::Proceed(vec!["kallsyms"]),
                            (_, Ok(Generic::Absent), ..) => {
                                Decision::Refuse(CrashingWrite::NoSetVariable)
                            }
                            (_, Ok(Generic::Present), ..) => {
                                Decision::Proceed(vec!["kallsyms", "kcore"])
                            }
                            (_, _, Ok(Absent), _) => {
                                Decision::Proceed(vec!["kallsyms", "kcore", "boot log"])
                            }
                            (.., Ok(None) | Ok(Some(SET))) => Decision::Proceed(all),
                            (.., Ok(Some(supported))) => {
                                Decision::Refuse(CrashingWrite::TableOmitsSetVariable(supported))
                            }
                            (.., Err(_)) => Decision::Refuse(CrashingWrite::Unknown),
                        };
                        let decision = match &got {
                            Ok(_) => Decision::Proceed(evidence.asked.borrow().clone()),
                            Err(error) => Decision::Refuse(
                                *error
                                    .downcast_ref::<CrashingWrite>()
                                    .unwrap_or_else(|| panic!("{case}: {error:#}")),
                            ),
                        };
                        assert_eq!(decision, want, "{case}");

                        let crashing = reconfigure != Ok(true)
                            && (generic == Ok(Generic::Absent)
                                || generic.is_err()
                                    && boot_log != Ok(Absent)
                                    && matches!(table, Ok(Some(CLEAR)) | Err(_)));
                        assert_eq!(got.is_err(), crashing, "{case}: refused");
                        if let (Err(error), Decision::Refuse(CrashingWrite::Unknown)) = (got, want)
                        {
                            let message = format!("{error:#}");
                            for found in [
                                reconfigure.err(),
                                generic.err(),
                                boot_log.err(),
                                table.err(),
                            ]
                            .into_iter()
                            .flatten()
                            {
                                assert!(
                                    message.contains(found),
                                    "{case}: {message:?} lacks {found:?}"
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    /// EfivarFiles asks the evidence once and keeps the proof, but asks again after a refusal.
    #[test]
    fn efivar_files_keep_only_a_proof() {
        let (_dirs, mut files) = unmounted_efivar_files();
        files.evidence = Box::new(FakeEvidence::new(
            Ok(true),
            Err("unasked"),
            Err("unasked"),
            Err("unasked"),
        ));
        files.survives().expect("check");
        files.evidence = Box::new(FakeEvidence::new(
            Ok(false),
            Err("no kcore"),
            Err("no log"),
            Err("no table"),
        ));
        files.survives().expect("keep the proof of the first check");

        let (_dirs, mut files) = unmounted_efivar_files();
        files.evidence = Box::new(FakeEvidence::new(
            Ok(false),
            Err("no kcore"),
            Err("no log"),
            Err("no table"),
        ));
        files.survives().expect_err("refuse");
        files.evidence = Box::new(FakeEvidence::new(
            Ok(true),
            Err("unasked"),
            Err("unasked"),
            Err("unasked"),
        ));
        files.survives().expect("ask again after the refusal");
    }

    /// set_variable writes neither a variable nor a new one when it cannot remount efivarfs, and
    /// refuses an efivar file that is no regular file before it tries.
    #[test]
    fn efivar_files_set_nothing_without_the_remount() {
        let ([dir, _lock, _evidence], files) = unmounted_efivar_files();
        let path = |name: &str| dir.path().join(EfivarFileName::from(&variable_key(name)));
        fs::write(path("Setup"), SETUP).expect("write the efivar file");
        fs::create_dir(path("Directory")).expect("create a directory");
        let contents =
            VariableContents::new(VariableAttributes::from_bits_retain(NV_BS_RT), vec![1])
                .expect("hold one byte");

        for name in ["Setup", "New"] {
            let error = files
                .set_variable(&variable_key(name), &contents)
                .expect_err("set without the remount");

            assert_eq!(
                format!("{error:#}"),
                format!(
                    "Failed to create efivars fs mount guard: mount {} is not in /proc/mounts",
                    dir.path().display()
                ),
                "{name}"
            );
        }
        let error = files
            .set_variable(&variable_key("Directory"), &contents)
            .expect_err("set a directory");

        assert_eq!(
            format!("{error:#}"),
            format!(
                "efivar file '{}' is not a regular file",
                path("Directory").display()
            ),
            "Directory"
        );
        assert_eq!(fs::read(path("Setup")).expect("read Setup"), SETUP, "Setup");
        assert!(!path("New").exists(), "New was created");
    }

    /// On a kernel without efivarfs_reconfigure() whose log names an RT properties table that it
    /// applied, set_variable refuses before it remounts efivarfs when it cannot read the table,
    /// as write_at does, and neither changes a variable nor creates one.
    #[test]
    fn efivar_files_set_nothing_on_a_kernel_that_may_crash() {
        let ([dir, _lock, evidence], files) = unmounted_efivar_files_of(UNFIXED_KALLSYMS);
        fs::write(
            evidence.path().join("kmsg"),
            "6,12,1000,-;efi: ACPI=0x3fb7e000 RTPROP=0x3f989998 \n",
        )
        .expect("write the kernel log");
        let path = |name: &str| dir.path().join(EfivarFileName::from(&variable_key(name)));
        fs::write(path("Setup"), SETUP).expect("write the efivar file");
        let contents =
            VariableContents::new(VariableAttributes::from_bits_retain(NV_BS_RT), vec![1])
                .expect("hold one byte");

        for name in ["Setup", "New"] {
            let error = files
                .set_variable(&variable_key(name), &contents)
                .expect_err("set on a kernel that may crash");

            assert_eq!(
                error.downcast_ref::<CrashingWrite>(),
                Some(&CrashingWrite::Unknown),
                "{name}: {error:#}"
            );
            let message = format!("{error:#}");
            assert!(
                !message.contains("mount guard"),
                "{name}: {message:?}: refused after the remount"
            );
        }
        assert_eq!(fs::read(path("Setup")).expect("read Setup"), SETUP, "Setup");
        assert!(!path("New").exists(), "New was created");
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
