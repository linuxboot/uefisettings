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

//! /proc/kcore, which serves arm64 Linux's EFI memory map: System RAM that /dev/mem refuses.

use std::fs::File;
use std::io;
use std::os::unix::fs::FileExt;
use std::path::Path;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;

use super::array_at;
use super::MemoryMapUnavailable;
use crate::hii::memory_access_denied::mark_refused_access;
use crate::hii::memory_access_denied::mark_refused_open;
use crate::hii::memory_access_denied::MemoryAccess;
use crate::hii::memory_access_denied::MemoryDevice;

/// The kernel's memory as an ELF core file (fs/proc/kcore.c).
#[cfg(target_arch = "aarch64")]
pub(in crate::hii) const KCORE_PATH: &str = "/proc/kcore";

/// The start of e_ident of the Elf64_Ehdr that /proc/kcore starts with: ELFMAG, ELFCLASS64,
/// ELFDATA2LSB (include/uapi/linux/elf.h).
const ELF64_LE_IDENT: &[u8] = b"\x7fELF\x02\x01";
/// The p_type of a loadable segment (include/uapi/linux/elf.h).
const PT_LOAD: u32 = 1;

/// Returns `length` bytes of System RAM at physical `address` from /proc/kcore at `path`, which
/// serves System RAM that /dev/mem refuses under CONFIG_STRICT_DEVMEM. Both need CAP_SYS_RAWIO,
/// but kernel lockdown refuses /proc/kcore from confidentiality on (LOCKDOWN_KCORE), while it
/// refuses /dev/mem from integrity on (LOCKDOWN_DEV_MEM; include/linux/security.h,
/// fs/proc/kcore.c open_kcore(), drivers/char/mem.c open_port()), so refuse_locked_down runs
/// first. It reads a page that it cannot read as zeros (read_kcore_iter()), so callers check
/// what it returns. `open_file` opens it; a refused open, where the kernel refuses /proc/kcore
/// (open_kcore()), is under MemoryAccessDenied (mark_refused_open, after the lockdown file
/// `lockdown`), and so is a refused read (read_kcore_file). A missing one, without
/// CONFIG_PROC_KCORE, is MemoryMapUnavailable::NoKcore: it serves only the EFI memory map.
pub(super) fn read_kcore(
    path: &Path,
    lockdown: &Path,
    open_file: impl FnOnce(&Path) -> io::Result<File>,
    address: u64,
    length: usize,
) -> Result<Vec<u8>> {
    let kcore = match open_file(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Err(MemoryMapUnavailable::NoKcore(path.to_owned()).into())
        }
        opened => opened
            .with_context(|| format!("Failed to open {}", path.display()))
            .map_err(|error| mark_refused_open(error, MemoryDevice::Kcore, lockdown))?,
    };
    read_kcore_file(&kcore, path, address, length)
}

/// The read of read_kcore from `kcore`, the open `path`. A refused read is under
/// MemoryAccessDenied (mark_refused_access): a security module can refuse it (Linux v6.11
/// fs/read_write.c vfs_read() rw_verify_area()).
fn read_kcore_file(
    kcore: &impl FileExt,
    path: &Path,
    address: u64,
    length: usize,
) -> Result<Vec<u8>> {
    read_kcore_at(kcore, address, length)
        .with_context(|| {
            format!(
                "Failed to read 0x{length:x} bytes of {} at physical 0x{address:x}",
                path.display()
            )
        })
        .map_err(|error| mark_refused_access(error, MemoryAccess::KcoreRead))
}

/// Implements read_kcore on the ELF core file `kcore`: the PT_LOAD segment whose p_paddr range
/// holds the whole range serves it; the kernel sets p_paddr to -1 for segments that are neither
/// RAM nor kernel text (Linux v6.11 fs/proc/kcore.c read_kcore_iter()).
fn read_kcore_at(kcore: &impl FileExt, address: u64, length: usize) -> Result<Vec<u8>> {
    // Elf64_Ehdr and Elf64_Phdr (include/uapi/linux/elf.h)
    let mut header = [0; 64];
    kcore.read_exact_at(&mut header, 0)?;
    if !header.starts_with(ELF64_LE_IDENT) {
        bail!("not a little-endian ELF64 file");
    }
    let (Some(phoff), Some(phentsize), Some(phnum)) = (
        array_at(&header, 32).map(u64::from_le_bytes),
        array_at(&header, 54).map(u16::from_le_bytes),
        array_at(&header, 56).map(u16::from_le_bytes),
    ) else {
        bail!("the ELF header is truncated");
    };
    let end = address
        .checked_add(u64::try_from(length)?)
        .context("the range overflows")?;
    for index in 0..u64::from(phnum) {
        let mut phdr = [0; 56];
        let at = index
            .checked_mul(u64::from(phentsize))
            .and_then(|offset| offset.checked_add(phoff))
            .context("a program header offset overflows")?;
        kcore.read_exact_at(&mut phdr, at)?;
        let (Some(p_type), Some(p_offset), Some(p_paddr), Some(p_filesz)) = (
            array_at(&phdr, 0).map(u32::from_le_bytes),
            array_at(&phdr, 8).map(u64::from_le_bytes),
            array_at(&phdr, 24).map(u64::from_le_bytes),
            array_at(&phdr, 32).map(u64::from_le_bytes),
        ) else {
            bail!("a program header is truncated");
        };
        if p_type != PT_LOAD || p_paddr.saturating_add(p_filesz) < end {
            continue;
        }
        let Some(segment_offset) = address.checked_sub(p_paddr) else {
            continue;
        };
        let at = p_offset
            .checked_add(segment_offset)
            .context("a segment offset overflows")?;
        let mut bytes = vec![0; length];
        kcore.read_exact_at(&mut bytes, at)?;
        return Ok(bytes);
    }
    bail!("no segment holds physical 0x{address:x}+0x{length:x}")
}

/// /proc/kcore files for the tests.
#[cfg(test)]
pub(in crate::hii) mod fixture {
    use std::fs::File;
    use std::os::unix::fs::FileExt;
    use std::path::Path;

    /// An ELF64 core file at `path` whose PT_LOAD segments are `segments` of (p_paddr, bytes),
    /// after a PT_NOTE of 16 bytes at physical 0, like /proc/kcore's, whose program headers the
    /// kernel zero-allocates (fs/proc/kcore.c read_kcore_iter()).
    pub(in crate::hii) fn kcore_fixture(path: &Path, segments: &[(u64, &[u8])]) -> File {
        const PHENTSIZE: u64 = 56;
        const NOTE_SIZE: u64 = 16;
        let phoff = 64;
        let phnum = u64::try_from(segments.len()).expect("a u64 count") + 1;
        let note_offset = phoff + phnum * PHENTSIZE;
        let mut data_offset = note_offset + NOTE_SIZE;
        let mut header = [0; 64];
        header[..6].copy_from_slice(b"\x7fELF\x02\x01");
        header[32..40].copy_from_slice(&phoff.to_le_bytes());
        header[54..56].copy_from_slice(&u16::try_from(PHENTSIZE).expect("a u16").to_le_bytes());
        header[56..58].copy_from_slice(&u16::try_from(phnum).expect("a u16").to_le_bytes());
        let file = File::options()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .expect("create the kcore file");
        file.write_all_at(&header, 0).expect("write the ELF header");
        let mut note = [0; 56];
        note[..4].copy_from_slice(&4u32.to_le_bytes()); // PT_NOTE
        note[8..16].copy_from_slice(&note_offset.to_le_bytes());
        note[32..40].copy_from_slice(&NOTE_SIZE.to_le_bytes());
        file.write_all_at(&note, phoff)
            .expect("write the PT_NOTE header");
        file.write_all_at(&[0xcc; 16], note_offset)
            .expect("write the notes");
        for (index, (paddr, bytes)) in (1..).zip(segments) {
            let size = u64::try_from(bytes.len()).expect("a u64 size");
            let mut phdr = [0; 56];
            phdr[..4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
            phdr[8..16].copy_from_slice(&data_offset.to_le_bytes());
            phdr[24..32].copy_from_slice(&paddr.to_le_bytes());
            phdr[32..40].copy_from_slice(&size.to_le_bytes());
            phdr[40..48].copy_from_slice(&size.to_le_bytes());
            file.write_all_at(&phdr, phoff + index * PHENTSIZE)
                .expect("write a PT_LOAD header");
            file.write_all_at(bytes, data_offset)
                .expect("write a segment");
            data_offset += size;
        }
        file
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::kcore_fixture;
    use super::*;
    use crate::hii::lockdown::LockdownMode;
    use crate::hii::memory_access_denied::fixture::lockdown_file;
    use crate::hii::memory_access_denied::fixture::refused_open;
    use crate::hii::memory_access_denied::DenialCause;
    use crate::hii::memory_access_denied::MemoryAccessDenied;
    use crate::hii::memory_access_denied::MemoryOperation;

    #[test]
    fn read_kcore_at_reads_the_segment_that_holds_the_range() {
        let low: Vec<u8> = (0..=255).collect();
        let high: Vec<u8> = (0..=255).rev().collect();
        // A segment that is not RAM: kcore sets its p_paddr to -1.
        let not_ram = [0xee; 16];
        let dir = tempfile::tempdir().expect("create a directory");
        let kcore = kcore_fixture(
            &dir.path().join("kcore"),
            &[
                (u64::MAX, &not_ram),
                (0x4000_0000, &low),
                (0x7c75_0000, &high),
            ],
        );
        for (address, length, want) in [
            (0x4000_0000, 16, &low[..16]),
            (0x4000_00f0, 16, &low[0xf0..]),
            (0x7c75_0010, 32, &high[0x10..0x30]),
        ] {
            let got = read_kcore_at(&kcore, address, length)
                .unwrap_or_else(|error| panic!("{address:#x}: {error:#}"));
            assert_eq!(got, want, "{address:#x}");
        }
        for (address, length) in [
            // past a segment's end, before its start, in no segment, and in the PT_NOTE's
            // physical range only
            (0x4000_00f1, 16),
            (0x3fff_fff0, 32),
            (0x5000_0000, 1),
            (0, 1),
        ] {
            let error = read_kcore_at(&kcore, address, length)
                .expect_err("read a range that no segment holds");
            assert_eq!(
                error.to_string(),
                format!("no segment holds physical {address:#x}+{length:#x}"),
                "{address:#x}"
            );
        }
    }

    /// A refused open of /proc/kcore takes its cause from the lockdown file it was given:
    /// confidentiality refuses /proc/kcore, integrity does not.
    #[test]
    fn read_kcore_marks_a_refusal_after_its_lockdown_file() {
        let dir = tempfile::tempdir().expect("create a directory");
        for (mode, cause) in [
            (
                "confidentiality",
                DenialCause::Lockdown(LockdownMode::Confidentiality),
            ),
            ("integrity", DenialCause::Capability),
        ] {
            let lockdown = lockdown_file(dir.path(), mode);

            let error = read_kcore(&dir.path().join("kcore"), &lockdown, refused_open, 0, 1)
                .expect_err("open a refusing /proc/kcore");

            assert_eq!(
                error.downcast_ref::<MemoryAccessDenied>(),
                Some(&MemoryAccessDenied {
                    device: MemoryDevice::Kcore,
                    operation: MemoryOperation::Open,
                    cause,
                }),
                "{mode}: {error:#}"
            );
        }
    }

    /// Only a missing /proc/kcore, as without CONFIG_PROC_KCORE, is MemoryMapUnavailable: a
    /// refused open stays MemoryAccessDenied, and another error is neither.
    #[test]
    fn read_kcore_refuses_only_a_missing_kcore_as_no_map() {
        let dir = tempfile::tempdir().expect("create a directory");
        let path = dir.path().join("kcore");
        let lockdown = lockdown_file(dir.path(), "none");
        for (errno, missing, refused) in [
            (libc::ENOENT, true, false),
            (libc::EACCES, false, true),
            (libc::EPERM, false, true),
            (libc::ENOTDIR, false, false),
        ] {
            let error = read_kcore(
                &path,
                &lockdown,
                |_| Err(io::Error::from_raw_os_error(errno)),
                0,
                1,
            )
            .expect_err("open a failing /proc/kcore");

            assert_eq!(
                error.downcast_ref::<MemoryMapUnavailable>(),
                missing
                    .then(|| MemoryMapUnavailable::NoKcore(path.clone()))
                    .as_ref(),
                "errno {errno}: {error:#}"
            );
            assert_eq!(
                error.downcast_ref::<MemoryAccessDenied>().is_some(),
                refused,
                "errno {errno}: {error:#}"
            );
        }
    }

    /// /proc/kcore, open, whose reads fail with this errno, as a security module's refusal does.
    struct RefusedRead(i32);

    impl FileExt for RefusedRead {
        fn read_at(&self, _: &mut [u8], _: u64) -> std::io::Result<usize> {
            Err(std::io::Error::from_raw_os_error(self.0))
        }

        fn write_at(&self, _: &[u8], _: u64) -> std::io::Result<usize> {
            panic!("wrote /proc/kcore")
        }
    }

    /// A read of /proc/kcore that fails with EPERM or EACCES is a refusal, which a security
    /// module made, never CONFIG_STRICT_DEVMEM; other errors are not.
    #[test]
    fn a_refused_kcore_read_is_a_refusal() {
        for (errno, refused) in [
            (libc::EPERM, true),
            (libc::EACCES, true),
            (libc::EIO, false),
        ] {
            let error = read_kcore_file(&RefusedRead(errno), Path::new("kcore"), 0x1000, 16)
                .expect_err("read a refusing /proc/kcore");

            let want = refused.then_some(MemoryAccessDenied {
                device: MemoryDevice::Kcore,
                operation: MemoryOperation::Read,
                cause: DenialCause::Permission,
            });
            assert_eq!(
                error.downcast_ref::<MemoryAccessDenied>(),
                want.as_ref(),
                "errno {errno}: {error:#}"
            );
            assert!(
                format!("{error:#}")
                    .contains("Failed to read 0x10 bytes of kcore at physical 0x1000"),
                "errno {errno}: {error:#}"
            );
        }
    }

    #[test]
    fn read_kcore_at_refuses_a_file_that_is_not_elf64() {
        let file = tempfile::tempfile().expect("create the file");
        file.write_all_at(&[0; 64], 0).expect("write zeros");
        let error = read_kcore_at(&file, 0, 1).expect_err("read zeros as kcore");
        assert_eq!(error.to_string(), "not a little-endian ELF64 file");
    }
}
