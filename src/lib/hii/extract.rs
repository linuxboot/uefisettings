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
use std::ptr;

use anyhow::bail;
use anyhow::Context;
use anyhow::Result;
use binrw::io::Cursor;
use binrw::BinRead;
use binrw::BinReaderExt;
use log::debug;

pub const OCP_HIIDB_PATH: &str =
    "/sys/firmware/efi/efivars/HiiDB-1b838190-4625-4ead-abc9-cd5e6af18fe0";

/// DEV_MEM_PATH is the physical-memory character device that the HiiDB
/// export buffer is read from.
///
/// Example: `read_physical_memory(0x1000, 16)` returns the 16 bytes at offset
/// 0x1000 of DEV_MEM_PATH.
const DEV_MEM_PATH: &str = "/dev/mem";

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

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
struct HiiDBEFIVar64 {
    flags: u32,
    length: u32,
    address: u64,
}

impl HiiDBEFIVar {
    fn parse(contents: &[u8]) -> Result<Self> {
        match contents.len() {
            12 => {
                let mut cursor = Cursor::new(contents);
                let var: HiiDBEFIVar32 = cursor.read_ne()?;

                Ok(Self {
                    flags: var.flags,
                    length: var.length,
                    address: var.address.into(),
                })
            }
            16 => {
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

pub fn extract_db() -> Result<Vec<u8>> {
    // I haven't seen any documentation on extracting HiiDB anywhere on the internet
    // So this is directly based on what hiitool does.

    // try to read data from varstore
    let mut efivar_file =
        File::open(OCP_HIIDB_PATH).context(format!("Failed to open {OCP_HIIDB_PATH}"))?;

    let mut efivar_contents = Vec::new();
    efivar_file
        .read_to_end(&mut efivar_contents)
        .context(format!("Failed to read efivar file, {}", OCP_HIIDB_PATH))?;

    let db_info = HiiDBEFIVar::parse(&efivar_contents)?;

    // Now that we have offset and size from the HiiDB efivar, use it to read DB from memory.
    read_physical_memory(db_info.address, db_info.length.try_into()?)
}

/// read_physical_memory returns `length` bytes of physical memory at `address`.
///
/// It reads /dev/mem with one pread(), so the kernel copies the whole range and
/// the copy costs the same in unoptimized builds, unlike read_mapped()'s
/// userspace loop. Linux v7.2 fails that read with EFAULT when
/// valid_phys_addr_range() rejects the range (drivers/char/mem.c read_mem()):
/// on arm64, e.g. MEMBLOCK_NOMAP memory, which includes EFI regions not usable
/// as System RAM (arch/arm64/mm/mmap.c, drivers/firmware/efi/efi-init.c
/// reserve_regions()); on x86, addresses above high_memory
/// (arch/x86/mm/mmap.c). mmap() of /dev/mem still maps those ranges, so only
/// EFAULT falls back to read_mapped(); every other error is returned, e.g.
/// EPERM from CONFIG_STRICT_DEVMEM, which mmap_mem_prepare() in
/// drivers/char/mem.c enforces as well through range_is_allowed()
/// (include/linux/io.h).
///
/// Example: extract_db reads the HiiDB with
/// `read_physical_memory(db_info.address, db_info.length.try_into()?)`.
fn read_physical_memory(address: u64, length: usize) -> Result<Vec<u8>> {
    let mem_file =
        File::open(DEV_MEM_PATH).with_context(|| format!("Failed to open {DEV_MEM_PATH}"))?;
    let mut buf = vec![0u8; length];
    match mem_file.read_exact_at(&mut buf, address) {
        Ok(()) => Ok(buf),
        Err(e) if e.raw_os_error() == Some(libc::EFAULT) => {
            debug!("pread() of {DEV_MEM_PATH} at 0x{address:x} returned EFAULT; using mmap()");
            read_mapped(&mem_file, address, length).with_context(|| {
                format!(
                    "pread() of 0x{length:x} bytes of {DEV_MEM_PATH} at 0x{address:x} returned \
                     EFAULT and the mmap() fallback failed"
                )
            })
        }
        Err(e) => Err(e).with_context(|| {
            format!("Failed to read 0x{length:x} bytes of {DEV_MEM_PATH} at 0x{address:x}")
        }),
    }
}

/// read_mapped copies `length` bytes at byte `offset` of `file` through one
/// read-only shared mapping of the page-aligned range that contains them, so
/// it costs one mmap()/munmap() pair whatever the length. `file` must back the
/// whole range: a load from a page past the end of a regular file raises
/// SIGBUS (Linux man-pages 6.13, mmap(2), ERRORS, SIGBUS).
///
/// It loads from the mapping only through copy_from_mapping, because on arm64
/// these ranges may be mapped as Device memory: Linux v7.2
/// phys_mem_access_prot() (arch/arm64/mm/mmu.c) maps the whole range with
/// pgprot_noncached(), which selects MT_DEVICE_nGnRnE
/// (arch/arm64/include/asm/pgtable.h), when its first pfn fails
/// pfn_is_map_memory().
///
/// Example: `read_mapped(&mem_file, 0x17fc00010, 16)` maps the page at
/// 0x17fc00000 and returns its bytes 0x10..0x20.
fn read_mapped(file: &File, offset: u64, length: usize) -> Result<Vec<u8>> {
    // A page-aligned empty range would need a zero-length mapping, which mmap()
    // rejects with EINVAL (Linux man-pages 6.13, mmap(2), ERRORS, EINVAL).
    if length == 0 {
        return Ok(Vec::new());
    }

    // Reject a range whose end overflows u64 before deriving the mapping from
    // it, so the error names the requested range instead of a derived value.
    offset
        .checked_add(u64::try_from(length)?)
        .with_context(|| format!("Range 0x{offset:x}+0x{length:x} overflows u64"))?;

    let page_size = page_size()?;
    let map_offset = usize::try_from(offset % page_size as u64)?;
    let map_base = offset - map_offset as u64;
    let map_len = map_offset
        .checked_add(length)
        .context("Mapping length overflows usize")?;
    let map_base = libc::off_t::try_from(map_base)
        .with_context(|| format!("Mapping offset 0x{map_base:x} does not fit off_t"))?;
    let mut buf = vec![0u8; length];

    // SAFETY: addr = NULL lets the kernel pick an unused address range, so the
    // new PROT_READ mapping cannot alias any Rust allocation (including buf).
    let mapped = unsafe {
        libc::mmap(
            ptr::null_mut(),
            map_len,
            libc::PROT_READ,
            libc::MAP_SHARED,
            file.as_raw_fd(),
            map_base,
        )
    };
    if mapped == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!("Failed to mmap 0x{map_len:x} bytes at offset 0x{map_base:x}")
        });
    }

    // SAFETY: mmap succeeded, so [mapped, mapped + map_len) is mapped
    // PROT_READ, file backs the whole range, as the doc comment requires, and
    // map_offset + length == map_len keeps the source in bounds. The mapping is
    // new, so it does not overlap buf.
    unsafe { copy_from_mapping(mapped.cast::<u8>().add(map_offset), &mut buf) };

    // SAFETY: mapped/map_len are exactly the region returned by mmap above and
    // no pointer into it is used after this call.
    if unsafe { libc::munmap(mapped, map_len) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("Failed to munmap 0x{map_len:x} bytes"));
    }

    Ok(buf)
}

/// page_size returns the kernel page size, the granularity of mmap offsets.
///
/// Example: read_mapped rounds its offset down to a multiple of page_size()
/// before it calls mmap().
fn page_size() -> Result<usize> {
    // SAFETY: sysconf has no memory-safety preconditions.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let size = usize::try_from(size).context("Failed to query system page size")?;
    if !size.is_power_of_two() {
        bail!("System page size {size} is not a power of two");
    }
    Ok(size)
}

/// MappedWord is the widest load copy_from_mapping issues; it is only ever
/// loaded from an address that is a multiple of its size.
///
/// Example: an aligned 16-byte copy_from_mapping issues two MappedWord loads.
type MappedWord = u64;

/// copy_from_mapping fills `dst` from `src` using only volatile loads from
/// addresses that are multiples of the load size: single bytes up to the first
/// MappedWord boundary, MappedWord loads, then the trailing bytes.
///
/// No load wider than a byte is unaligned, as
/// <https://github.com/linuxboot/uefisettings/pull/12> requires ("avoid faults
/// from wider unaligned loads on memory with strict access requirements").
/// Copying whole MappedWords takes about 8x fewer loads than a byte-by-byte
/// copy. Linux v7.2 arch/arm64/include/asm/pgtable.h (comment above
/// pgprot_dmacoherent) states that `Device-nGnR[nE]` memory "requires strict
/// alignment". Linux v7.2 memcpy_fromio() (lib/iomem_copy.c) copies from I/O
/// memory with the same access pattern when long is 64 bits (CONFIG_64BIT).
///
/// Example: a 20-byte copy from 3 bytes past a MappedWord boundary issues 5
/// byte loads, one MappedWord load, then 7 byte loads.
///
/// # Safety
///
/// `src` must be valid for volatile reads of `dst.len()` bytes and must not
/// overlap `dst`.
unsafe fn copy_from_mapping(src: *const u8, dst: &mut [u8]) {
    /// WORD is the size of one MappedWord load in bytes.
    ///
    /// Example: each iteration of the word loop copies WORD bytes.
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

#[cfg(test)]
mod tests {
    use super::*;

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

    /// mapped_fixture returns a temp file of `len` bytes and a copy of those
    /// bytes. The byte pattern repeats every 251 bytes, so the bytes of one
    /// MappedWord differ, and, since 251 is prime and page sizes are powers of
    /// two, bytes read one page off differ from the expected ones.
    ///
    /// Example: `let (file, data) = mapped_fixture(16);` gives a 16-byte file
    /// whose read_mapped result is compared with `data`.
    fn mapped_fixture(len: usize) -> (File, Vec<u8>) {
        use std::io::Write;
        let data: Vec<u8> = (0..len).map(|i| ((i * 131 + 7) % 251) as u8).collect();
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(&data).unwrap();
        (file, data)
    }

    /// read_mapped_matches_file_bytes_at_every_alignment checks that
    /// read_mapped returns the file's bytes for every offset modulo
    /// MappedWord, for offsets in the first and second page, and for lengths
    /// that end on and off MappedWord and page boundaries, including
    /// multi-page ranges.
    ///
    /// Example: offset page + 3 with length 2 * page + 5 spans three pages.
    #[test]
    fn read_mapped_matches_file_bytes_at_every_alignment() {
        let page = page_size().unwrap();
        let (file, data) = mapped_fixture(3 * page + 64);
        for offset in (0..=8).chain([page - 1, page, page + 3]) {
            for length in [1, 7, 8, 9, 15, 16, 17, page, page + 13, 2 * page + 5] {
                let got = read_mapped(&file, offset as u64, length).unwrap();
                assert_eq!(
                    got,
                    data[offset..offset + length],
                    "offset {offset} length {length}"
                );
            }
        }
    }

    /// read_mapped_zero_length_is_empty checks that a zero-length read_mapped
    /// returns an empty buffer at a page-aligned offset, where the mapping
    /// would be zero bytes long, and at an unaligned one.
    ///
    /// Example: `read_mapped(&file, 0, 0)` returns an empty Vec.
    #[test]
    fn read_mapped_zero_length_is_empty() {
        let (file, _) = mapped_fixture(16);
        for offset in [0, 3] {
            let got = read_mapped(&file, offset, 0)
                .unwrap_or_else(|err| panic!("offset {offset}: {err:#}"));
            assert!(got.is_empty(), "offset {offset}");
        }
    }

    /// read_mapped_rejects_overflowing_range checks that read_mapped rejects a
    /// range whose end overflows u64 with the overflow error, not with the
    /// off_t error that the same offset also triggers.
    ///
    /// Example: offset u64::MAX - 2 with length 8.
    #[test]
    fn read_mapped_rejects_overflowing_range() {
        let (file, _) = mapped_fixture(16);
        let err = read_mapped(&file, u64::MAX - 2, 8).unwrap_err();
        assert!(
            format!("{err:#}").contains("overflows u64"),
            "unexpected error: {err:#}"
        );
    }

    /// read_mapped_reads_above_4gib checks that read_mapped reads at a file
    /// offset above 4 GiB, which needs a 64-bit off_t.
    ///
    /// Example: 100 bytes at offset 0x1_0000_0123 of a sparse temp file.
    #[test]
    fn read_mapped_reads_above_4gib() {
        let offset: u64 = 0x1_0000_0123;
        let file = tempfile::tempfile().unwrap();
        let data: Vec<u8> = (0..100u8).collect();
        file.write_all_at(&data, offset).unwrap();
        assert_eq!(read_mapped(&file, offset, data.len()).unwrap(), data);
    }
}
