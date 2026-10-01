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

const DEV_MEM_PATH: &str = "/dev/mem";

/// Below this address (1 MiB), x86 read() of /dev/mem may return zeros.
const X86_ZERO_FILL_END: u64 = 0x10_0000;

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

/// Returns `length` bytes of physical memory at `address`.
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
fn read_physical_memory(address: u64, length: usize) -> Result<Vec<u8>> {
    let mem_file =
        File::open(DEV_MEM_PATH).with_context(|| format!("Failed to open {DEV_MEM_PATH}"))?;
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
    let map_base = libc::off_t::try_from(page_base)
        .with_context(|| format!("Mapping offset 0x{page_base:x} does not fit off_t"))?;

    // SAFETY: addr = NULL lets the kernel pick an unused address range, so the
    // new PROT_READ mapping cannot alias any Rust allocation (including dst).
    let mapped = unsafe {
        libc::mmap(
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

    /// The offset also fails the off_t check; the overflow error must win.
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
}
