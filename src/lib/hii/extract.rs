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
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::path::Path;
use std::path::PathBuf;
use std::ptr;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use binrw::io::Cursor;
use binrw::BinRead;
use binrw::BinReaderExt;
use log::debug;

use crate::hii::package::db_file::read_db_bytes;

// TODO: build this path from EFIVARS_MOUNT_POINT and EfivarFileName and open it with
// open_efivar, so efivarfs paths and missing-variable errors have one source.
// A missing HiiDB variable fails every command that reads the live HII database with only
// extract_db's open error; say instead that the firmware does not export its HII database, as
// VariableNotExported says for a missing varstore variable.
pub const OCP_HIIDB_PATH: &str =
    "/sys/firmware/efi/efivars/HiiDB-1b838190-4625-4ead-abc9-cd5e6af18fe0";

// Vendor ACPI table ("HIID"), with no public spec. Per the patch author, its
// body (after the 36-byte ACPI header) is a copy of the HII database itself, so
// it is read straight from sysfs with no /dev/mem, which lockdown refuses (Linux
// v6.11 drivers/char/mem.c:612, open_port()) and STRICT_DEVMEM refuses for System
// RAM.
pub const HIIDB_ACPI_PATH: &str = "/sys/firmware/acpi/tables/HIID";

// Size of the standard ACPI table header (EFI_ACPI_DESCRIPTION_HEADER) that
// prefixes the HII database bytes in the HIID table.
const ACPI_HEADER_LEN: usize = 36;

// Linux prints the physical address of the EFI System Table's ConfigurationTable
// array here (an EFI_CONFIGURATION_TABLE[]). Not every kernel creates it (e.g.
// NVIDIA aarch64 does not).
pub const EFI_CONFIG_TABLE_PATH: &str = "/sys/firmware/efi/config_table";

// gEfiHiiDatabaseProtocolGuid, EF9FC172-A1B2-4693-B327-6D32FC416042, in memory
// byte order (the first three fields little-endian). HiiDatabaseDxe installs
// the exported database under it when PcdHiiOsRuntimeSupport is TRUE.
const HII_DATABASE_GUID: [u8; 16] = [
    0x72, 0xc1, 0x9f, 0xef, 0xb2, 0xa1, 0x93, 0x46, 0xb3, 0x27, 0x6d, 0x32, 0xfc, 0x41, 0x60, 0x42,
];

// A 64-bit EFI_CONFIGURATION_TABLE entry: VendorGuid (16 bytes) + VendorTable
// pointer (8 bytes).
const CONFIG_TABLE_ENTRY_LEN: usize = 24;

// The entry count lives in the EFI System Table, which Linux does not expose, so
// stop after this many entries (firmware has a few dozen).
const MAX_CONFIG_TABLE_ENTRIES: u64 = 256;

// EFI_HII_PACKAGE_LIST_HEADER: PackageListGuid (16 bytes) + PackageLength (u32,
// which includes this header).
const PACKAGE_LIST_HEADER_LEN: usize = 20;

// Upper bound for the database size found by walking its package lists.
const MAX_HII_DB_LEN: usize = 64 * 1024 * 1024;

const DEV_MEM_PATH: &str = "/dev/mem";

/// Below this address (1 MiB), x86 read() of /dev/mem may return zeros.
const X86_ZERO_FILL_END: u64 = 0x10_0000;

/// Where extract_db reads the EFI configuration table, the HIID ACPI table, the OCP HiiDB
/// efivar and physical memory; Default is this machine's.
#[derive(Debug, Clone, PartialEq, Eq)]
struct HiiSourcePaths {
    /// The address of the EFI configuration table, as Linux prints it.
    efi_config_table: PathBuf,
    /// The OCP HiiDB efivar.
    ocp_hiidb: PathBuf,
    /// The HIID ACPI table.
    acpi_hiid: PathBuf,
    /// Physical memory, which the OCP HiiDB efivar points into.
    dev_mem: PathBuf,
}

impl Default for HiiSourcePaths {
    fn default() -> Self {
        Self {
            efi_config_table: PathBuf::from(EFI_CONFIG_TABLE_PATH),
            ocp_hiidb: PathBuf::from(OCP_HIIDB_PATH),
            acpi_hiid: PathBuf::from(HIIDB_ACPI_PATH),
            dev_mem: PathBuf::from(DEV_MEM_PATH),
        }
    }
}

/// Whether a source file of extract_db exists: the HIID ACPI table or the OCP
/// variable.
pub fn hii_db_published() -> std::io::Result<bool> {
    hii_db_published_at(&HiiSourcePaths::default())
}

/// hii_db_published, probing the acpi and efivar sources at `paths`, in extract_db's order.
fn hii_db_published_at(paths: &HiiSourcePaths) -> std::io::Result<bool> {
    for path in [&paths.acpi_hiid, &paths.ocp_hiidb] {
        if path.try_exists()? {
            return Ok(true);
        }
    }
    Ok(false)
}

pub fn extract_db() -> Result<Vec<u8>> {
    extract_db_at(&HiiSourcePaths::default())
}

/// extract_db, reading the EFI configuration table, the HIID ACPI table, the OCP HiiDB efivar
/// and physical memory at `paths`.
fn extract_db_at(paths: &HiiSourcePaths) -> Result<Vec<u8>> {
    // Prefer the spec-standard route (the HII database configuration table
    // found through the EFI System Table), then the vendor ACPI table that
    // carries the database content directly (read from sysfs, no /dev/mem), and
    // fall back to the OCP variable + /dev/mem. Each fallback reason is logged
    // at debug level so a failure here is not masked by the OCP error below.
    match extract_db_efi_config_table(&paths.efi_config_table, &paths.dev_mem) {
        Ok(bytes) => {
            debug!(
                "HII database source: EFI configuration table ({})",
                paths.efi_config_table.display()
            );
            return Ok(bytes);
        }
        Err(e) => debug!(
            "could not use the EFI configuration table ({}): {e:#}; \
             falling back to the HII ACPI table",
            paths.efi_config_table.display()
        ),
    }

    match extract_db_acpi(paths.acpi_hiid.as_path()) {
        Ok(bytes) => return Ok(bytes),
        Err(e) => debug!(
            "could not use the HII ACPI table ({}): {e:#}; \
             falling back to the OCP HiiDB variable + /dev/mem",
            paths.acpi_hiid.display()
        ),
    }

    extract_db_efivar(&paths.ocp_hiidb, &paths.dev_mem)
}

#[derive(Debug, PartialEq)]
struct HiiDBEFIVar {
    // hiitool calls this varlen but I think these are flags/attributes
    // first 4 bytes of the (efivarfs) output represent the UEFI variable attributes - from kernel.org
    flags: u32,

    length: u32,
    address: u64,
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
struct HiiDBEFIVar32 {
    flags: u32,
    length: u32,
    address: u32,
}

impl HiiDBEFIVar32 {
    /// The size of this layout of the HiiDB efivar.
    const SIZE: usize = 12;
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
struct HiiDBEFIVar64 {
    flags: u32,
    length: u32,
    address: u64,
}

impl HiiDBEFIVar64 {
    /// The size of this layout of the HiiDB efivar, the longer one.
    const SIZE: usize = 16;
}

impl HiiDBEFIVar {
    fn parse(contents: &[u8]) -> Result<Self> {
        match contents.len() {
            HiiDBEFIVar32::SIZE => {
                let mut cursor = Cursor::new(contents);
                let var: HiiDBEFIVar32 = cursor.read_ne()?;

                Ok(Self {
                    flags: var.flags,
                    length: var.length,
                    address: var.address.into(),
                })
            }
            HiiDBEFIVar64::SIZE => {
                let mut cursor = Cursor::new(contents);
                let var: HiiDBEFIVar64 = cursor.read_ne()?;

                Ok(Self {
                    flags: var.flags,
                    length: var.length,
                    address: var.address,
                })
            }
            size => bail!("Unexpected HiiDB efivar size: {size} bytes"),
        }
    }
}

/// The HiiDB that the OCP HiiDB efivar `ocp_hiidb` points to in `dev_mem`.
fn extract_db_efivar(ocp_hiidb: &Path, dev_mem: &Path) -> Result<Vec<u8>> {
    // I haven't seen any documentation on extracting HiiDB anywhere on the internet
    // So this is directly based on what hiitool does.

    // try to read data from varstore
    let efivar_file =
        File::open(ocp_hiidb).with_context(|| format!("Failed to open {}", ocp_hiidb.display()))?;

    let efivar_contents = read_hiidb_efivar(efivar_file)
        .with_context(|| format!("Failed to read efivar file, {}", ocp_hiidb.display()))?;

    let db_info = HiiDBEFIVar::parse(&efivar_contents)?;

    // Now that we have offset and size from the HiiDB efivar, use it to read DB from memory.
    read_physical_memory(dev_mem, db_info.address, db_info.length.try_into()?)
}

/// Reads the HII database through the EFI configuration table: the
/// ConfigurationTable address from `config_table` (EFI_CONFIG_TABLE_PATH), the entry for
/// gEfiHiiDatabaseProtocolGuid in it, then the database that entry points to.
/// Every step reads physical memory, `dev_mem`.
fn extract_db_efi_config_table(config_table: &Path, dev_mem: &Path) -> Result<Vec<u8>> {
    let text = std::fs::read_to_string(config_table)
        .with_context(|| format!("Failed to read {}", config_table.display()))?;
    let table_address = parse_hex_address(&text)?;

    let mem_file =
        File::open(dev_mem).with_context(|| format!("Failed to open {}", dev_mem.display()))?;
    let read = |address: u64, length: usize| {
        read_physical_memory_at(&mem_file, address, length, FileExt::read_exact_at)
    };

    let mut db_address = None;
    for index in 0..MAX_CONFIG_TABLE_ENTRIES {
        let entry_address = table_address + index * CONFIG_TABLE_ENTRY_LEN as u64;
        let entry = read(entry_address, CONFIG_TABLE_ENTRY_LEN)?;
        if let Some(address) = parse_hii_config_table_entry(&entry) {
            db_address = Some(address);
            break;
        }
    }
    let db_address = db_address.with_context(|| {
        format!(
            "No gEfiHiiDatabaseProtocolGuid entry in the first {MAX_CONFIG_TABLE_ENTRIES} \
             configuration table entries (is PcdHiiOsRuntimeSupport FALSE?)"
        )
    })?;

    let length = hii_db_length(|offset, len| read(db_address + offset as u64, len))?;
    read(db_address, length)
}

/// Parses the address in `text`, as Linux prints it ("0x7fc2d198").
fn parse_hex_address(text: &str) -> Result<u64> {
    let text = text.trim();
    let digits = text.strip_prefix("0x").unwrap_or(text);
    u64::from_str_radix(digits, 16).with_context(|| format!("Not a hexadecimal address: {text:?}"))
}

/// Returns the VendorTable pointer of `entry` (an EFI_CONFIGURATION_TABLE) when
/// it is the gEfiHiiDatabaseProtocolGuid entry with a non-NULL pointer.
fn parse_hii_config_table_entry(entry: &[u8]) -> Option<u64> {
    let (guid, pointer) = entry.split_at(16);
    if guid != HII_DATABASE_GUID {
        return None;
    }
    let address = u64::from_le_bytes(pointer.try_into().ok()?);
    (address != 0).then_some(address)
}

/// Returns the size of the exported database, which the configuration table does
/// not record: HiiDatabaseDxe over-allocates the buffer by 25% and zero-fills it
/// (HiiGetDatabaseInfo), so the database is the run of package lists, walked by
/// their PackageLength, that ends at the first zero PackageLength. `read(offset,
/// length)` returns database bytes.
fn hii_db_length(read: impl Fn(usize, usize) -> Result<Vec<u8>>) -> Result<usize> {
    let mut total = 0;
    loop {
        let header = read(total, PACKAGE_LIST_HEADER_LEN)?;
        let length = u32::from_le_bytes(header[16..20].try_into()?) as usize;
        if length == 0 {
            break;
        }
        if length < PACKAGE_LIST_HEADER_LEN {
            bail!("HII package list at offset 0x{total:x} has a bad PackageLength: {length}");
        }
        total += length;
        if total > MAX_HII_DB_LEN {
            bail!("HII database is larger than {MAX_HII_DB_LEN} bytes");
        }
    }
    if total == 0 {
        bail!("HII database holds no package list");
    }
    Ok(total)
}

/// The bytes of the HiiDB efivar `file`; one longer than HiiDBEFIVar64::SIZE, which
/// HiiDBEFIVar::parse would refuse, is refused without being read whole.
fn read_hiidb_efivar(file: impl Read) -> Result<Vec<u8>> {
    // one byte past the maximum, so that a longer file shows
    let mut file = file.take(u64::try_from(HiiDBEFIVar64::SIZE)? + 1);
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)?;
    if file.limit() == 0 {
        bail!(
            "HiiDB efivar is longer than its maximum of {} bytes",
            HiiDBEFIVar64::SIZE
        );
    }
    Ok(contents)
}

/// Returns `length` bytes of physical memory, `dev_mem`, at `address`.
///
/// It reads /dev/mem with one pread(), so the kernel copies the whole range and
/// the copy costs the same in unoptimized builds, unlike read_mapped()'s
/// userspace loop. Linux v7.2 fails that read with EFAULT when
/// valid_phys_addr_range() rejects the range (drivers/char/mem.c read_mem()).
/// mmap() of /dev/mem still maps those ranges, so only
/// EFAULT falls back to read_mapped(); every other error is returned, e.g.
/// EPERM from CONFIG_STRICT_DEVMEM, which mmap() enforces too.
///
/// Ranges for which pread_may_zero_fill() holds go straight to read_mapped().
fn read_physical_memory(dev_mem: &Path, address: u64, length: usize) -> Result<Vec<u8>> {
    let mem_file =
        File::open(dev_mem).with_context(|| format!("Failed to open {}", dev_mem.display()))?;
    read_physical_memory_at(&mem_file, address, length, FileExt::read_exact_at)
}

/// Implements read_physical_memory; tests pass a fake `pread`.
fn read_physical_memory_at(
    mem_file: &File,
    address: u64,
    length: usize,
    pread: impl Fn(&File, &mut [u8], u64) -> std::io::Result<()>,
) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; length];

    if pread_may_zero_fill(address) {
        debug!("{DEV_MEM_PATH} at 0x{address:x} may read as zeros; using mmap()");
        read_mapped(mem_file, address, &mut buf).with_context(|| {
            format!("Failed to map 0x{length:x} bytes of {DEV_MEM_PATH} at 0x{address:x}")
        })?;
        return Ok(buf);
    }

    match pread(mem_file, &mut buf, address) {
        Ok(()) => Ok(buf),
        Err(e) if e.raw_os_error() == Some(libc::EFAULT) => {
            debug!("pread() of {DEV_MEM_PATH} at 0x{address:x} returned EFAULT; using mmap()");
            read_mapped(mem_file, address, &mut buf).with_context(|| {
                format!(
                    "pread() of 0x{length:x} bytes of {DEV_MEM_PATH} at 0x{address:x} returned \
                     EFAULT and the mmap() fallback failed"
                )
            })?;
            Ok(buf)
        }
        Err(e) => Err(e).with_context(|| {
            format!("Failed to read 0x{length:x} bytes of {DEV_MEM_PATH} at 0x{address:x}")
        }),
    }
}

/// Reports whether read() of /dev/mem may return zeros for a range starting at
/// `address` while mmap() maps the real bytes.
///
/// With CONFIG_STRICT_DEVMEM, Linux v7.2 x86 does so for System RAM below
/// 1 MiB (devmem_is_allowed(), arch/x86/mm/init.c); other architectures never
/// do. A range touching the first 1 MiB starts in it, so `address` suffices.
fn pread_may_zero_fill(address: u64) -> bool {
    cfg!(any(target_arch = "x86", target_arch = "x86_64")) && address < X86_ZERO_FILL_END
}

/// Fills `dst` from byte `offset` of `file`, mapping one page at a
/// time: Linux v7.2 picks one memory type per /dev/mem mapping
/// (mmap_mem_prepare(), drivers/char/mem.c). `file` must back the
/// whole range: a load from a page past the end of a regular file raises
/// SIGBUS (mmap(2)).
fn read_mapped(file: &File, offset: u64, dst: &mut [u8]) -> Result<()> {
    let length = dst.len();
    // Reject a range whose end overflows u64 before deriving the mapping from
    // it, so the error names the requested range instead of a derived value.
    offset
        .checked_add(u64::try_from(length)?)
        .with_context(|| format!("Range 0x{offset:x}+0x{length:x} overflows u64"))?;

    let mut done = 0;
    while done < length {
        // Cannot overflow: offset + length was checked above.
        done += copy_mapped_page(file, offset + done as u64, &mut dst[done..])?;
    }

    Ok(())
}

/// Copies bytes from `offset` to the end of its page, at most `dst.len()`,
/// through a one-page mapping; returns the count. `file` must back the copied
/// range. Loads go through copy_from_mapping: the page may be Device memory.
fn copy_mapped_page(file: &File, offset: u64, dst: &mut [u8]) -> Result<usize> {
    let page_size = page_size()?;
    let offset_in_page = usize::try_from(offset % page_size as u64)?;
    let len = (page_size - offset_in_page).min(dst.len());
    let page_base = offset - offset_in_page as u64;
    // mmap64(), as off_t is signed and has 32 bits on most 32-bit glibc targets.
    let map_base = libc::off64_t::try_from(page_base)
        .with_context(|| format!("Mapping offset 0x{page_base:x} does not fit off64_t"))?;

    // SAFETY: addr = NULL lets the kernel pick an unused address range, so the
    // new PROT_READ mapping cannot alias any Rust allocation (including dst).
    let mapped = unsafe {
        libc::mmap64(
            ptr::null_mut(),
            page_size,
            libc::PROT_READ,
            libc::MAP_SHARED,
            file.as_raw_fd(),
            map_base,
        )
    };
    if mapped == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!("Failed to mmap 0x{page_size:x} bytes at offset 0x{map_base:x}")
        });
    }

    // SAFETY: mmap succeeded, so [mapped, mapped + page_size) is mapped
    // PROT_READ, file backs the whole range, as the doc comment requires, and
    // offset_in_page + len <= page_size keeps the source in bounds. The mapping is
    // new, so it does not overlap dst.
    unsafe { copy_from_mapping(mapped.cast::<u8>().add(offset_in_page), &mut dst[..len]) };

    // SAFETY: mapped/page_size are exactly the region returned by mmap above and
    // no pointer into it is used after this call.
    if unsafe { libc::munmap(mapped, page_size) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("Failed to munmap 0x{page_size:x} bytes"));
    }

    Ok(len)
}

/// Returns the kernel page size, the granularity of mmap offsets.
fn page_size() -> Result<usize> {
    // SAFETY: sysconf has no memory-safety preconditions.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let size = usize::try_from(size).context("Failed to query system page size")?;
    if !size.is_power_of_two() {
        bail!("System page size {size} is not a power of two");
    }
    Ok(size)
}

/// The widest load copy_from_mapping issues.
type MappedWord = u64;

/// Fills `dst` from `src` using only volatile loads from
/// addresses that are multiples of the load size: single bytes up to the first
/// MappedWord boundary, MappedWord loads, then the trailing bytes.
///
/// Wider unaligned loads fault on memory with strict access requirements
/// (<https://github.com/linuxboot/uefisettings/pull/12>); MappedWord loads cut
/// the load count ~8x. Linux v7.2 memcpy_fromio() (lib/iomem_copy.c) does the same.
///
/// # Safety
///
/// `src` must be valid for volatile reads of `dst.len()` bytes and must not
/// overlap `dst`.
unsafe fn copy_from_mapping(src: *const u8, dst: &mut [u8]) {
    const WORD: usize = std::mem::size_of::<MappedWord>();
    let len = dst.len();
    let dst = dst.as_mut_ptr();
    // SAFETY (every pointer access below): byte accesses use i < len and word
    // accesses use i + WORD <= len, so all stay inside src (caller contract) and
    // dst (length len). Word reads start only once src + i is a multiple of
    // WORD (a power of two, so the mask test is exact), which is a multiple of
    // align_of::<MappedWord>(), and i then advances by WORD, which keeps it so.
    let mut i = 0;
    while i < len && (src.add(i) as usize) & (WORD - 1) != 0 {
        *dst.add(i) = ptr::read_volatile(src.add(i));
        i += 1;
    }
    while len - i >= WORD {
        let word = ptr::read_volatile(src.add(i).cast::<MappedWord>());
        dst.add(i).cast::<MappedWord>().write_unaligned(word);
        i += WORD;
    }
    while i < len {
        *dst.add(i) = ptr::read_volatile(src.add(i));
        i += 1;
    }
}

/// Reads the HII database from the vendor ACPI table at `path` (HIIDB_ACPI_PATH) whose
/// body IS the database content. The sysfs file is a 36-byte ACPI header
/// (EFI_ACPI_DESCRIPTION_HEADER) followed by the database bytes, so we drop the
/// header and return the rest. No /dev/mem — works even where /dev/mem is
/// unavailable/blocked, and (unlike a UEFI variable) has no efivarfs
/// single-read size limit; read_db_bytes caps it at MAX_ALLOWED_FILESIZE.
fn extract_db_acpi(path: &Path) -> Result<Vec<u8>> {
    let mut acpi_file =
        File::open(path).with_context(|| format!("Failed to open {}", path.display()))?;

    let mut contents = read_db_bytes(&mut acpi_file)
        .with_context(|| format!("Failed to read ACPI table file, {}", path.display()))?;

    if contents.len() <= ACPI_HEADER_LEN {
        return Err(anyhow::anyhow!(
            "{} is too short ({} bytes) to contain a HII database",
            path.display(),
            contents.len()
        ));
    }
    Ok(contents.split_off(ACPI_HEADER_LEN))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hii::package::db_file::MAX_ALLOWED_FILESIZE;

    /// hii_db_published fails, rather than answers false, when it cannot check a file.
    #[test]
    fn hii_db_published_fails_when_a_file_cannot_be_checked() {
        let dir = tempfile::tempdir().expect("create a directory");
        let file = dir.path().join("file");
        std::fs::write(&file, b"").expect("create the file");
        // stat() of a path through a regular file fails with ENOTDIR, not ENOENT
        let paths = HiiSourcePaths {
            efi_config_table: file.join("config_table"),
            ocp_hiidb: file.join("HiiDB"),
            acpi_hiid: file.join("HIID"),
            dev_mem: file.join("mem"),
        };

        let error = hii_db_published_at(&paths).expect_err("checked a path through a file");

        assert_eq!(error.kind(), std::io::ErrorKind::NotADirectory, "{error}");
    }

    /// hii_db_published holds once either file exists, the OCP HiiDB efivar or the HIID table.
    #[test]
    fn hii_db_published_once_either_file_exists() {
        for (case, ocp_file, acpi_file, want) in [
            ("neither file", false, false, false),
            ("the HiiDB efivar only", true, false, true),
            ("the HIID table only", false, true, true),
            ("both files", true, true, true),
        ] {
            let dir = tempfile::tempdir().expect("create a directory");
            let paths = HiiSourcePaths {
                efi_config_table: dir.path().join("config_table"),
                ocp_hiidb: dir.path().join("HiiDB"),
                acpi_hiid: dir.path().join("HIID"),
                dev_mem: dir.path().join("mem"),
            };
            for (exists, path) in [(ocp_file, &paths.ocp_hiidb), (acpi_file, &paths.acpi_hiid)] {
                if exists {
                    std::fs::write(path, b"").expect("create the file");
                }
            }

            let got = hii_db_published_at(&paths).unwrap_or_else(|error| panic!("{case}: {error}"));

            assert_eq!(got, want, "{case}");
        }
    }

    /// The HIID table is the HiiDB after its ACPI header, and no longer than MAX_ALLOWED_FILESIZE.
    #[test]
    fn extract_db_acpi_strips_the_header_and_caps_the_size() {
        let dir = tempfile::tempdir().expect("create a directory");
        let path = dir.path().join("HIID");
        let over_cap = usize::try_from(MAX_ALLOWED_FILESIZE + 1).expect("a usize size");
        for (case, size, want) in [
            (
                "a header and a HiiDB",
                ACPI_HEADER_LEN + 3,
                Ok(&[1, 1, 1][..]),
            ),
            (
                "a header only",
                ACPI_HEADER_LEN,
                Err("is too short (36 bytes)"),
            ),
            ("shorter than a header", 4, Err("is too short (4 bytes)")),
            (
                "longer than MAX_ALLOWED_FILESIZE",
                over_cap,
                Err("File size is too big for the file to be a HII database."),
            ),
        ] {
            let file = File::create(&path).expect("create the table");
            file.set_len(u64::try_from(size).expect("a u64 size"))
                .expect("size the table");
            if size == ACPI_HEADER_LEN + 3 {
                file.write_all_at(&[1, 1, 1], u64::try_from(ACPI_HEADER_LEN).expect("a u64"))
                    .expect("write the HiiDB");
            }

            match (extract_db_acpi(&path), want) {
                (Ok(db), Ok(want)) => assert_eq!(db, want, "{case}"),
                (Err(error), Err(message)) => {
                    assert!(format!("{error:#}").contains(message), "{case}: {error:#}")
                }
                (got, _) => panic!("{case}: got {got:?}"),
            }
        }
    }

    /// A HiiDB efivar of HiiDBEFIVar64::SIZE bytes reads whole; one byte longer, it is
    /// refused.
    #[test]
    fn hiidb_efivar_longer_than_its_maximum_is_refused() {
        let size = u64::try_from(HiiDBEFIVar64::SIZE).expect("a u64 size");
        for (case, length, fits) in [
            ("the 64-bit layout's size", size, true),
            ("one byte longer", size + 1, false),
        ] {
            let read = read_hiidb_efivar(std::io::repeat(0).take(length));

            match (read, fits) {
                (Ok(contents), true) => {
                    assert_eq!(contents, [0; HiiDBEFIVar64::SIZE], "{case}: contents")
                }
                (Err(error), false) => assert_eq!(
                    error.to_string(),
                    "HiiDB efivar is longer than its maximum of 16 bytes",
                    "{case}"
                ),
                (read, _) => panic!("{case}: read {read:?}"),
            }
        }
    }

    #[test]
    fn parses_32_bit_hiidb_address() {
        let contents = [
            0x06, 0x00, 0x00, 0x00, // flags
            0x34, 0x12, 0x00, 0x00, // length
            0x78, 0x56, 0x34, 0x12, // address
        ];

        let var = HiiDBEFIVar::parse(&contents).unwrap();

        assert_eq!(var.flags, 0x6);
        assert_eq!(var.length, 0x1234);
        assert_eq!(var.address, 0x12345678);
    }

    #[test]
    fn parses_64_bit_hiidb_address() {
        let contents = [
            0x06, 0x00, 0x00, 0x00, // flags
            0x34, 0x12, 0x00, 0x00, // length
            0x00, 0xf0, 0xcc, 0xa4, 0x00, 0x02, 0x00, 0x00, // address
        ];

        let var = HiiDBEFIVar::parse(&contents).unwrap();

        assert_eq!(var.flags, 0x6);
        assert_eq!(var.length, 0x1234);
        assert_eq!(var.address, 0x200a4ccf000);
    }

    /// Returns a temp file of `len` bytes and those bytes. The pattern's period,
    /// 251, is prime, so reads shifted by a word or a page mismatch.
    fn mapped_fixture(len: usize) -> (File, Vec<u8>) {
        use std::io::Write;
        let data: Vec<u8> = (0..len).map(|i| ((i * 131 + 7) % 251) as u8).collect();
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&data).unwrap();
        (file, data)
    }

    #[test]
    fn read_mapped_matches_file_bytes_at_every_alignment() {
        let page = page_size().unwrap();
        let (file, data) = mapped_fixture(3 * page + 64);
        for offset in (0..=8).chain([page - 1, page, page + 3]) {
            for length in [1, 7, 8, 9, 15, 16, 17, page, page + 13, 2 * page + 5] {
                // 0xff is not in the fixture, so unwritten bytes fail.
                let mut got = vec![0xff; length];
                read_mapped(&file, offset as u64, &mut got).unwrap();
                assert_eq!(
                    got,
                    data[offset..offset + length],
                    "offset {offset} length {length}"
                );
            }
        }
    }

    #[test]
    fn read_mapped_zero_length_is_empty() {
        let (file, _) = mapped_fixture(16);
        for offset in [0, 3] {
            read_mapped(&file, offset, &mut [])
                .unwrap_or_else(|err| panic!("offset {offset}: {err:#}"));
        }
    }

    /// The offset also fails the off64_t check; the overflow error must win.
    #[test]
    fn read_mapped_rejects_overflowing_range() {
        let (file, _) = mapped_fixture(16);
        let err = read_mapped(&file, u64::MAX - 2, &mut [0; 8]).unwrap_err();
        assert!(
            format!("{err:#}").contains("overflows u64"),
            "unexpected error: {err:#}"
        );
    }

    /// Catches off_t truncation to 32 bits.
    #[test]
    fn read_mapped_reads_above_4gib() {
        let offset: u64 = 0x1_0000_0123;
        let file = tempfile::tempfile().unwrap();
        let data: Vec<u8> = (0..100u8).collect();
        file.write_all_at(&data, offset).unwrap();
        let mut got = vec![0xff; data.len()];
        read_mapped(&file, offset, &mut got).unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn copy_mapped_page_stops_at_page_end() {
        let page = page_size().unwrap();
        let (file, data) = mapped_fixture(2 * page);
        for (offset, dst_len, want) in [(page - 3, 8, 3), (page, page + 5, page), (page + 1, 4, 4)]
        {
            // 0xff is not in the fixture, so bytes written past `want` fail.
            let mut got = vec![0xff; dst_len];
            let copied = copy_mapped_page(&file, offset as u64, &mut got).unwrap();
            assert_eq!(copied, want, "offset {offset}");
            assert_eq!(got[..want], data[offset..offset + want], "offset {offset}");
            assert!(got[want..].iter().all(|&b| b == 0xff), "offset {offset}");
        }
    }

    #[test]
    fn parse_rejects_unexpected_hiidb_efivar_size() {
        for size in [0, 4, 8, 11, 13, 15, 17, 20, 24] {
            let err = HiiDBEFIVar::parse(&vec![0x5a; size]).unwrap_err();
            assert_eq!(
                err.to_string(),
                format!("Unexpected HiiDB efivar size: {size} bytes")
            );
        }
    }

    #[test]
    fn pread_may_zero_fill_only_below_1_mib_on_x86() {
        let x86 = cfg!(any(target_arch = "x86", target_arch = "x86_64"));
        for (address, want) in [
            (0, x86),
            (0x9f000, x86),
            (0xf_ffff, x86),
            (0x10_0000, false),
            (0x6bb3_9000, false),
            (u64::MAX, false),
        ] {
            assert_eq!(pread_may_zero_fill(address), want, "address 0x{address:x}");
        }
    }

    fn failing_pread(errno: i32) -> impl Fn(&File, &mut [u8], u64) -> std::io::Result<()> {
        move |_, _, _| Err(std::io::Error::from_raw_os_error(errno))
    }

    fn offset_stamp(offset: u64) -> u8 {
        offset as u8 ^ 0xa5
    }

    /// Fakes a successful pread whose bytes encode their offset.
    fn offset_stamping_pread(_: &File, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
        for (i, byte) in buf.iter_mut().enumerate() {
            *byte = offset_stamp(offset + i as u64);
        }
        Ok(())
    }

    fn root_errno(err: &anyhow::Error) -> Option<i32> {
        err.root_cause()
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::raw_os_error)
    }

    #[test]
    fn read_physical_memory_at_routes_by_pread_may_zero_fill() {
        let x86 = cfg!(any(target_arch = "x86", target_arch = "x86_64"));
        let (file, data) = mapped_fixture(X86_ZERO_FILL_END as usize + 16);
        for (address, mapped) in [
            (0, x86),
            (0x9f000, x86),
            (0xf_fff8, x86),
            (0x10_0000, false),
            (0x6bb3_9000, false),
        ] {
            let start = address as usize;
            let stamps: Vec<u8> = (address..address + 16).map(offset_stamp).collect();
            // File bytes differ from stamps, so each result's source is clear.
            assert_ne!(
                data.get(start..start + 16),
                Some(&stamps[..]),
                "address 0x{address:x}"
            );

            let failed = read_physical_memory_at(&file, address, 16, failing_pread(libc::EIO));
            // Below 1 MiB, x86 read() succeeds even when it returns zeros, so a
            // successful `pread` must be skipped too.
            let stamped = read_physical_memory_at(&file, address, 16, offset_stamping_pread)
                .unwrap_or_else(|err| panic!("stamping pread, address 0x{address:x}: {err:#}"));
            if mapped {
                let want = &data[start..start + 16];
                let failed = failed
                    .unwrap_or_else(|err| panic!("EIO pread, address 0x{address:x}: {err:#}"));
                assert_eq!(failed, want, "EIO pread, address 0x{address:x}");
                assert_eq!(stamped, want, "stamping pread, address 0x{address:x}");
            } else {
                let err = failed.unwrap_err();
                assert_eq!(
                    root_errno(&err),
                    Some(libc::EIO),
                    "EIO pread, address 0x{address:x}: {err:#}"
                );
                assert_eq!(stamped, stamps, "stamping pread, address 0x{address:x}");
            }
        }
    }

    #[test]
    fn read_physical_memory_at_returns_pread_bytes() {
        let address = X86_ZERO_FILL_END + 5;
        let file = tempfile::tempfile().unwrap();
        file.write_all_at(&[1; 100], address).unwrap();
        let want: Vec<u8> = (address..address + 100).map(offset_stamp).collect();
        // Neither zeros nor the file's bytes (1) can match `want`.
        assert!(want.iter().all(|&b| b != 0 && b != 1), "{want:?}");

        let got = read_physical_memory_at(&file, address, want.len(), offset_stamping_pread);

        assert_eq!(got.unwrap(), want);
    }

    #[test]
    fn read_physical_memory_at_maps_on_efault() {
        let address = X86_ZERO_FILL_END + 5;
        let file = tempfile::tempfile().unwrap();
        let data: Vec<u8> = (1..=100u8).collect();
        file.write_all_at(&data, address).unwrap();
        let got = read_physical_memory_at(&file, address, data.len(), failing_pread(libc::EFAULT))
            .unwrap();
        assert_eq!(got, data);
    }

    #[test]
    fn read_physical_memory_at_returns_other_pread_errors() {
        let address = X86_ZERO_FILL_END + 5;
        let file = tempfile::tempfile().unwrap();
        // mmap() would succeed here, so a fallback would hide the error.
        file.write_all_at(&[1; 100], address).unwrap();
        for errno in [libc::EPERM, libc::EIO, libc::EINVAL] {
            let err =
                read_physical_memory_at(&file, address, 100, failing_pread(errno)).unwrap_err();
            assert_eq!(root_errno(&err), Some(errno), "{err:#}");
        }
    }

    #[test]
    fn parses_config_table_address() {
        assert_eq!(parse_hex_address("0x7fc2d198\n").unwrap(), 0x7fc2d198);
        assert_eq!(parse_hex_address("7fc2d198").unwrap(), 0x7fc2d198);
        assert!(parse_hex_address("none").is_err());
    }

    #[test]
    fn finds_only_the_hii_database_config_table_entry() {
        let mut entry = [0u8; CONFIG_TABLE_ENTRY_LEN];
        entry[..16].copy_from_slice(&HII_DATABASE_GUID);
        entry[16..].copy_from_slice(&0x7fc0_6018u64.to_le_bytes());
        assert_eq!(parse_hii_config_table_entry(&entry), Some(0x7fc0_6018));

        entry[16..].fill(0);
        assert_eq!(parse_hii_config_table_entry(&entry), None, "NULL pointer");

        entry[16..].copy_from_slice(&0x7fc0_6018u64.to_le_bytes());
        entry[0] ^= 1;
        assert_eq!(parse_hii_config_table_entry(&entry), None, "other GUID");
    }

    /// A package list of `length` bytes: a header whose PackageLength is `length`.
    fn package_list(length: u32) -> Vec<u8> {
        let mut list = vec![0xaa; length as usize];
        list[16..20].copy_from_slice(&length.to_le_bytes());
        list
    }

    #[test]
    fn hii_db_length_stops_at_zero_padding() {
        let mut db = package_list(40);
        db.extend(package_list(24));
        db.extend([0u8; 30]); // the 25% over-allocation, zero-filled
        let read = |offset: usize, len: usize| Ok(db[offset..offset + len].to_vec());
        assert_eq!(hii_db_length(read).unwrap(), 64);
    }

    #[test]
    fn hii_db_length_rejects_bad_databases() {
        let empty = [0u8; 32];
        let read = |offset: usize, len: usize| Ok(empty[offset..offset + len].to_vec());
        assert!(hii_db_length(read).is_err(), "no package list");

        let mut short = package_list(20);
        short[16..20].copy_from_slice(&19u32.to_le_bytes());
        let read = |offset: usize, len: usize| Ok(short[offset..offset + len].to_vec());
        assert!(
            hii_db_length(read).is_err(),
            "PackageLength below the header"
        );

        // Every list claims 16 MiB and the data never ends.
        let endless = package_list(20);
        let mut header = endless[..PACKAGE_LIST_HEADER_LEN].to_vec();
        header[16..20].copy_from_slice(&(16u32 << 20).to_le_bytes());
        let read = |_: usize, _: usize| Ok(header.clone());
        assert!(hii_db_length(read).is_err(), "over the size cap");
    }
}
