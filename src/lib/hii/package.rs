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

use std::cell::RefCell;
use std::collections::HashMap;
use std::fmt;
use std::io::Seek;
use std::rc::Rc;

use anyhow::ensure;
use anyhow::Context;
use anyhow::Result;
use binrw::io::Cursor;
use binrw::io::SeekFrom;
use binrw::BinRead;
use binrw::BinReaderExt;
use log::debug;
use log::error;

use crate::hii::forms;
use crate::hii::forms::IFROperation;
use crate::hii::strings;

/// PACKAGE_LIST_HEADER_SIZE is the size of EFI_HII_PACKAGE_LIST_HEADER:
/// PackageListGuid (16 bytes) + PackageLength (4 bytes).
///
/// Example: PackageLength includes the header, so a package list carries
/// `length - PACKAGE_LIST_HEADER_SIZE` bytes of packages.
const PACKAGE_LIST_HEADER_SIZE: u32 = 20;

/// PACKAGE_HEADER_SIZE is the size of EFI_HII_PACKAGE_HEADER:
/// Length (24 bits) + Type (8 bits).
///
/// Example: Length includes the header, so a package carries
/// `length - PACKAGE_HEADER_SIZE` bytes of data.
const PACKAGE_HEADER_SIZE: u32 = 4;

/// PADDING_BYTES are the byte values of the padding that may follow the
/// last package list of a HiiDB, one value throughout. edk2 exports the
/// package lists into a buffer that it over-allocates by 25% and zero-fills
/// (HiiGetDatabaseInfo() in MdeModulePkg/Universal/HiiDatabaseDxe/Database.c),
/// and firmware may report the size of that buffer rather than the size of
/// the package lists, as in <https://github.com/linuxboot/uefisettings/issues/8>.
/// 0xFF is accepted only for compatibility with
/// <https://github.com/linuxboot/uefisettings/pull/9>, which accepted it.
///
/// Example: a 15925-byte HiiDB whose package lists end at byte 12740 ends
/// with 3185 zero bytes of padding.
const PADDING_BYTES: [u8; 2] = [0x00, 0xFF];

/// AvailableBytes is the number of bytes from the start of a PackageList
/// or Package to the end of what holds it, which its length must not
/// exceed. It has no Default, so reading either type without it does not
/// compile, rather than reading with 0 bytes available.
///
/// Example: a package that starts 6 bytes before the end of its package
/// list is read with `AvailableBytes(6)`, so its Length may be at most 6.
struct AvailableBytes(u64);

/// PackageList is an EFI_HII_PACKAGE_LIST_HEADER followed by its packages.
/// Its import `available` counts the bytes from its start to the end of the
/// HiiDB; reading fails if its length is below the header size or above
/// `available`.
///
/// Example: get_package_lists reads each package list with
/// `db_cursor.read_ne_args::<PackageList>(AvailableBytes(db_size - used_bytes))`.
#[derive(BinRead, Debug, PartialEq)]
#[br(little, import_raw(available: AvailableBytes))]
struct PackageList {
    guid: Guid,
    // binrw computes `count` below without a bounds check (debug builds
    // panic on underflow, release builds wrap) and reserves that many bytes
    // before reading them, so the length is validated first: a length below
    // the header size would underflow, and one beyond the available bytes
    // would reserve up to 4 GiB.
    #[br(assert(
        length >= PACKAGE_LIST_HEADER_SIZE && u64::from(length) <= available.0,
        "invalid package list length {} ({} bytes available)",
        length,
        available.0
    ))]
    length: u32,
    #[br(count = length - PACKAGE_LIST_HEADER_SIZE)]
    data: Vec<u8>,
}

/// Package is an EFI_HII_PACKAGE_HEADER followed by its data. Its import
/// `available` counts the bytes from its start to the end of its package
/// list; reading fails if its length is below the header size or above
/// `available`.
///
/// Example: get_packages reads each package with
/// `pl_cursor.read_ne_args::<Package>(AvailableBytes(pl_size - pl_cursor.position()))`.
#[derive(BinRead, Debug, PartialEq)]
#[br(little, import_raw(available: AvailableBytes))]
struct Package {
    // we need only 24 bits for length but are reading as u32 so discard the rest
    #[br(map = |x: u32| x  & 0x00FFFFFF)]
    // validated for the same reason as PackageList::length
    #[br(assert(
        length >= PACKAGE_HEADER_SIZE && u64::from(length) <= available.0,
        "invalid package length {} ({} bytes available)",
        length,
        available.0
    ))]
    length: u32,
    // now move cursor back by 32 - 24 = 8 bits = 1 byte
    #[br(seek_before = SeekFrom::Current(-1))]
    package_type: PackageType, // 8 bits
    #[br(count = length - PACKAGE_HEADER_SIZE)]
    data: Vec<u8>,
}

// UEFI Spec v2.9 Page 1790
#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
enum PackageType {
    #[br(magic = 0x01u8)]
    Guid,
    #[br(magic = 0x02u8)]
    Form,
    #[br(magic = 0x03u8)]
    KeyboardLayout,
    #[br(magic = 0x04u8)]
    Strings,
    #[br(magic = 0x05u8)]
    Fonts,
    #[br(magic = 0x06u8)]
    Images,
    #[br(magic = 0x07u8)]
    SimpleFonts,
    #[br(magic = 0x08u8)]
    DevicePath,
    #[br(magic = 0xDFu8)]
    End,
    Unknown(u8),
}

/// get_package_lists splits a HiiDB into its package lists. Of each list it
/// validates only the PackageLength, which must cover the header and end
/// within the HiiDB; the packages inside, including the End package that
/// every list needs, are validated by get_packages, so a header-only
/// package list without an End package is accepted here. It ignores
/// trailing padding (see is_padding), and fails if the HiiDB is empty or
/// padding only, if a PackageLength is invalid, or if a tail that is not
/// padding is too short for a package list header.
///
/// Example: a HiiDB of two package lists followed by 64 zero bytes yields
/// the two lists, while one with 32 zero bytes between the lists fails.
fn get_package_lists(source: &[u8]) -> Result<Vec<PackageList>> {
    let mut db_cursor = Cursor::new(&source);

    let mut package_lists: Vec<PackageList> = Vec::new();

    let db_size: u64 = source
        .len()
        .try_into()
        .context("failed to convert buffer size into u64")?;
    debug!("Size of db is {} bytes", db_size);

    let mut used_bytes = db_cursor
        .stream_position()
        .context("failed to find current position of db_cursor")?;

    while used_bytes < db_size {
        // The whole rest is checked rather than the next header: padding
        // followed by anything else, even by the other padding value, is
        // not trailing padding, so it goes to the parser instead of ending
        // the parse with a partial result.
        let offset =
            usize::try_from(used_bytes).context("failed to convert db offset into usize")?;
        let rest = &source[offset..];
        if is_padding(rest) {
            debug!(
                "Ignoring {} bytes of trailing padding at offset {}",
                rest.len(),
                used_bytes
            );
            break;
        }

        let available = db_size - used_bytes;
        let package_list: PackageList = match db_cursor.read_ne_args(AvailableBytes(available)) {
            Err(why) => {
                error!("Can't parse more package lists: {}", why);
                // Fail: returning the lists parsed so far would give the caller
                // `Ok` without the unparsable list or any list after it.
                return Err(why.into());
            }
            Ok(p) => p,
        };
        debug!("Package List GUID is {}", package_list.guid);
        package_lists.push(package_list);

        used_bytes = db_cursor
            .stream_position()
            .context("failed to find current position of db_cursor")?;
        debug!("Current db_cursor stream position is {}", used_bytes);
    }

    ensure!(
        !package_lists.is_empty(),
        "no package lists in {}-byte HiiDB",
        db_size
    );
    Ok(package_lists)
}

/// is_padding reports whether all of `bytes` equal the same one of
/// PADDING_BYTES; bytes that mix padding values are not padding. An empty
/// slice counts as padding; get_package_lists never passes one, as its loop
/// runs only while `used_bytes < db_size`.
///
/// Example: `is_padding(&[0x00; 7])` is true, `is_padding(&[0x00, 0xFF])`
/// is false.
fn is_padding(bytes: &[u8]) -> bool {
    PADDING_BYTES
        .iter()
        .any(|&padding| bytes.iter().all(|&b| b == padding))
}

/// get_packages splits a package list into its packages, excluding the
/// End package that terminates it; bytes after the End package are
/// ignored. It fails on a package whose Length is invalid and on a list
/// that ends without an End package.
///
/// Example: a package list of a strings package, a form package and the
/// End package yields the strings package and the form package.
fn get_packages(package_list: &PackageList) -> Result<Vec<Package>> {
    let mut packages: Vec<Package> = Vec::new(); // packages of one package_list

    let mut pl_cursor = Cursor::new(&package_list.data);
    let pl_size: u64 = package_list
        .data
        .len()
        .try_into()
        .context("failed to convert package list size into u64")?;

    loop {
        // Cannot underflow: every package read so far had
        // `length <= available`, so the position stays <= pl_size.
        let available = pl_size - pl_cursor.position();
        let package: Package = match pl_cursor.read_ne_args(AvailableBytes(available)) {
            Err(why) => {
                error!("Can't parse more packages in this package list {}", why);
                // Fail: returning the packages parsed so far would give the
                // caller `Ok` without the unparsable package or any package
                // after it, and accept a list that ends without an End package.
                return Err(why.into());
            }
            Ok(p) => p,
        };

        debug!(
            "Package List {}. This package type is {:?}",
            package_list.guid, package.package_type
        );
        if package.package_type == PackageType::End {
            break;
        }
        packages.push(package);
    }

    Ok(packages)
}

#[derive(PartialEq, Eq, Copy, Clone, BinRead)]
#[br(little)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

// lifted from https://github.com/LongSoft/IFRExtractor-RS/blob/ae9b550a6fe530f3a4911373ce22646043322bbc/src/parser.rs#L34
impl fmt::Display for Guid {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            self.data1,
            self.data2,
            self.data3,
            self.data4[0],
            self.data4[1],
            self.data4[2],
            self.data4[3],
            self.data4[4],
            self.data4[5],
            self.data4[6],
            self.data4[7]
        )
    }
}

impl fmt::Debug for Guid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self)
    }
}

type StringMap = HashMap<i32, String>;
type IFRNodeLink = Rc<RefCell<IFROperation>>;

/// ParsedHiiDB is the 'result' superstruct which will
/// hold the results of our parsed strings and forms packages.
pub struct ParsedHiiDB {
    /// `HashMap<packagelist_guid_string, Vec<StringMap>>`
    /// for each packagelist the key = packagelist guid string and val = vector of string package hashmaps
    /// each string package hashmap here has its key = string id and val = the string
    pub strings: HashMap<String, Vec<StringMap>>,
    pub forms: HashMap<String, Vec<IFRNodeLink>>,
}

/// read_db input (source) is a vector of u8 bytes
/// In hiidb, we have package lists (with unique guids) which have multiple packages of different types including string, form and end type packages.
/// For every package list, we will parse different packages. If package type is
/// * string -> parse and save data
/// * form -> parse and save data
/// * something else (like fonts or animations) -> we don't care about them, so continue to the next package in the package list.
///
/// In the end return a ParsedHiiDB struct which will have the parsed and saved data.
pub fn read_db(source: &[u8]) -> Result<ParsedHiiDB> {
    let mut res = ParsedHiiDB {
        strings: HashMap::new(),
        forms: HashMap::new(),
    };

    for package_list in get_package_lists(source)? {
        let package_list_guid = package_list.guid.to_string();

        // once filled this will have string maps from each string package in the package list.
        let mut package_list_string_maps: Vec<StringMap> = Vec::new();
        let mut roots: Vec<IFRNodeLink> = Vec::new();

        for package in get_packages(&package_list)? {
            let mut package_cursor = Cursor::new(&package.data);

            match package.package_type {
                PackageType::Strings => match strings::handle_string_package(&mut package_cursor) {
                    Ok(string_map) => package_list_string_maps.push(string_map),
                    Err(why) => {
                        error!("Can't parse as string header {}", why);
                        // We can also continue to ignore the error because we already know the bounds of each package so we can skip to the next one.
                        return Err(why);
                    }
                },
                PackageType::Form => match forms::handle_form_package(&mut package_cursor) {
                    Ok(root_node) => roots.push(root_node),
                    Err(why) => {
                        error!("Can't parse form package {}", why);
                        // We can also continue to ignore the error because we already know the bounds of each package so we can skip to the next one.
                        return Err(why);
                    }
                },
                _ => continue,
            }
        }

        if !package_list_string_maps.is_empty() {
            res.strings
                .insert(package_list_guid.clone(), package_list_string_maps);
        }
        if !roots.is_empty() {
            res.forms.insert(package_list_guid, roots);
        }
    }
    Ok(res)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::fs::File;
    use std::io::Read;

    use super::*;

    /// END_PACKAGE is an EFI_HII_PACKAGE_HEADER with Length 4 and Type
    /// End (0xDF), the package that terminates every package list.
    ///
    /// Example: get_packages stops at END_PACKAGE without returning it, so
    /// it yields no packages for the PackageList that get_package_lists
    /// parses from `package_list(&END_PACKAGE)`.
    const END_PACKAGE: [u8; 4] = [0x04, 0x00, 0x00, 0xDF];

    /// OPAQUE_PACKAGE is a package with Length 6, that is, 2 bytes of data:
    /// 0xAA 0xBB. Its Type 0xE0 is in the range that UEFI Spec v2.10 §33.3.1.1
    /// (Table 33.9) reserves for system firmware implementers, so its data
    /// has no spec-defined layout, and read_db skips it.
    ///
    /// Example: get_packages reads OPAQUE_PACKAGE as a package of type
    /// `Unknown(0xE0)` with data `[0xAA, 0xBB]`.
    const OPAQUE_PACKAGE: [u8; 6] = [0x06, 0x00, 0x00, 0xE0, 0xAA, 0xBB];

    /// encode_package_list encodes a package list header with the given
    /// GUID and PackageLength, followed by `packages`, whatever their size.
    ///
    /// Example: `encode_package_list([0x11; 16], 24, &END_PACKAGE)` is
    /// `package_list(&END_PACKAGE)`.
    fn encode_package_list(guid: [u8; 16], length: u32, packages: &[u8]) -> Vec<u8> {
        [&guid[..], &length.to_le_bytes(), packages].concat()
    }

    /// package_list encodes a package list with GUID 11..11 whose
    /// PackageLength covers its header and `packages`.
    ///
    /// Example: `package_list(&END_PACKAGE)` is 24 bytes long, with
    /// PackageLength 24.
    fn package_list(packages: &[u8]) -> Vec<u8> {
        package_list_with_guid([0x11; 16], packages)
    }

    /// package_list_with_guid encodes a package list with the given GUID
    /// whose PackageLength covers its header and `packages`.
    ///
    /// Example: `package_list_with_guid([0x22; 16], &END_PACKAGE)` is a
    /// package list with GUID 22222222-2222-2222-2222-222222222222 that
    /// holds only the End package.
    fn package_list_with_guid(guid: [u8; 16], packages: &[u8]) -> Vec<u8> {
        let length = PACKAGE_LIST_HEADER_SIZE + u32::try_from(packages.len()).unwrap();
        encode_package_list(guid, length, packages)
    }

    /// package_list_header encodes a bare package list header with the
    /// given PackageLength; its GUID is 01 00..00, so it is not padding.
    ///
    /// Example: `[package_list(&END_PACKAGE), package_list_header(0)].concat()`
    /// ends with a list that is shorter than its own header.
    fn package_list_header(length: u32) -> Vec<u8> {
        let mut guid = [0x00; 16];
        guid[0] = 0x01;
        encode_package_list(guid, length, &[])
    }

    /// nil_guid_list encodes a valid package list whose header consists of
    /// 0x00 and 0xFF bytes only: the nil GUID and PackageLength 0xFF. It
    /// holds the End package, followed by zero bytes up to that length.
    ///
    /// Example: `[nil_guid_list(), package_list(&END_PACKAGE)].concat()`
    /// holds two package lists.
    fn nil_guid_list() -> Vec<u8> {
        let length: u32 = 0xFF;
        let packages_size = usize::try_from(length - PACKAGE_LIST_HEADER_SIZE).unwrap();
        let mut packages = END_PACKAGE.to_vec();
        packages.resize(packages_size, 0x00);
        encode_package_list([0x00; 16], length, &packages)
    }

    /// strings_package_header encodes a bare EFI_HII_PACKAGE_HEADER of Type
    /// strings (0x04) with the given 24-bit Length.
    ///
    /// Example: `package_list(&strings_package_header(0))` holds a package
    /// that is shorter than its own header.
    fn strings_package_header(length: u32) -> Vec<u8> {
        [&length.to_le_bytes()[..3], &[0x04]].concat()
    }

    /// en_strings_package encodes a strings package for language "en" that
    /// holds string ID 1, the one-character string of the ASCII `letter`.
    ///
    /// Example: read_db's `strings` maps "11111111-1111-1111-1111-111111111111"
    /// to `[{1: "A"}]` for
    /// `package_list(&[en_strings_package(b'A'), END_PACKAGE.to_vec()].concat())`.
    fn en_strings_package(letter: u8) -> Vec<u8> {
        let language = [
            &[0x00; 32][..],     // LanguageWindow
            &1u16.to_le_bytes(), // LanguageName
            b"en\0",             // Language
        ]
        .concat();

        let strings = [
            &[0x14, letter, 0x00, 0x00, 0x00][..], // EFI_HII_SIBT_STRING_UCS2 `letter`
            &[0x00],                               // EFI_HII_SIBT_END
        ]
        .concat();

        // HdrSize covers the package header, HdrSize and StringInfoOffset
        // (a u32 each) and `language`; the strings follow the header.
        let hdr_size = PACKAGE_HEADER_SIZE
            + u32::try_from(2 * std::mem::size_of::<u32>() + language.len()).unwrap();
        let length = hdr_size + u32::try_from(strings.len()).unwrap();

        [
            &strings_package_header(length)[..],
            &hdr_size.to_le_bytes(), // HdrSize
            &hdr_size.to_le_bytes(), // StringInfoOffset
            &language,
            &strings,
        ]
        .concat()
    }

    /// A PackageLength below the header size is rejected as an invalid
    /// length before binrw computes the size of the list's data from it.
    #[test]
    fn test_list_length_below_header_size_is_an_error() {
        for length in [0, PACKAGE_LIST_HEADER_SIZE - 1] {
            let hiidb = [package_list(&END_PACKAGE), package_list_header(length)].concat();

            let err = format!("{:#}", get_package_lists(&hiidb).unwrap_err());

            // only the bare header is left to read from
            let want = format!(
                "invalid package list length {} ({} bytes available) at 0x",
                length, PACKAGE_LIST_HEADER_SIZE
            );
            assert!(err.contains(&want), "length {}: {}", length, err);
        }
    }

    /// A PackageLength beyond the end of the HiiDB, by one byte or by
    /// almost 4 GiB, is rejected as an invalid length before binrw reserves
    /// memory for it.
    #[test]
    fn test_list_length_beyond_hiidb_is_an_error() {
        for length in [PACKAGE_LIST_HEADER_SIZE + 1, 0xFFFF_FF00] {
            let hiidb = [package_list(&END_PACKAGE), package_list_header(length)].concat();

            let err = format!("{:#}", get_package_lists(&hiidb).unwrap_err());

            // only the bare header is left to read from
            let want = format!(
                "invalid package list length {} ({} bytes available) at 0x",
                length, PACKAGE_LIST_HEADER_SIZE
            );
            assert!(err.contains(&want), "length {}: {}", length, err);
        }
    }

    /// A package list of the header size alone, without packages, is
    /// parsed, and the next package list is read from the byte after it.
    #[test]
    fn test_list_of_header_size_is_parsed() {
        let hiidb = [package_list(&[]), package_list(&END_PACKAGE)].concat();

        let lists = get_package_lists(&hiidb).unwrap();

        assert_eq!(lists.len(), 2);
        assert!(lists[0].data.is_empty());
        assert_eq!(lists[1].data, END_PACKAGE);
    }

    /// A package list that ends exactly at the end of the HiiDB fits in the
    /// available bytes.
    #[test]
    fn test_list_ending_at_hiidb_end_is_parsed() {
        let packages = [OPAQUE_PACKAGE.as_slice(), &END_PACKAGE].concat();
        let hiidb = [package_list(&END_PACKAGE), package_list(&packages)].concat();

        let lists = get_package_lists(&hiidb).unwrap();

        assert_eq!(lists.len(), 2);
        assert_eq!(lists[1].data, packages);
    }

    /// A package Length below the header size is rejected as an invalid
    /// length before binrw computes the size of the package's data from it.
    #[test]
    fn test_package_length_below_header_size_is_an_error() {
        for length in [0, PACKAGE_HEADER_SIZE - 1] {
            let hiidb = package_list(&strings_package_header(length));
            let lists = get_package_lists(&hiidb).unwrap();

            let err = format!("{:#}", get_packages(&lists[0]).unwrap_err());

            // only the bare header is left to read from
            let want = format!(
                "invalid package length {} ({} bytes available) at 0x",
                length, PACKAGE_HEADER_SIZE
            );
            assert!(err.contains(&want), "length {}: {}", length, err);
        }
    }

    /// A package Length beyond the end of its package list, by one byte or
    /// by almost 16 MiB, is rejected as an invalid length before binrw
    /// reserves memory for it. The bytes available are counted from the
    /// start of the package, whether it is the first one in the list or
    /// follows another package.
    #[test]
    fn test_package_length_beyond_list_is_an_error() {
        let data = [0xAA, 0xBB];
        // the Length of a package with `data` that ends at the end of the list
        let available = PACKAGE_HEADER_SIZE + u32::try_from(data.len()).unwrap();
        for preceding in [&[][..], &OPAQUE_PACKAGE] {
            for length in [available + 1, 0xFF_FFFF] {
                let header = strings_package_header(length);
                let packages = [preceding, &header, &data].concat();
                let lists = get_package_lists(&package_list(&packages)).unwrap();

                let err = format!("{:#}", get_packages(&lists[0]).unwrap_err());

                let want = format!(
                    "invalid package length {} ({} bytes available) at 0x",
                    length, available
                );
                let case = format!("length {} after {} bytes", length, preceding.len());
                assert!(err.contains(&want), "{}: {}", case, err);
            }
        }
    }

    /// Packages that end exactly at the end of their package list fit in the
    /// available bytes.
    #[test]
    fn test_packages_filling_the_list_are_parsed() {
        let hiidb = package_list(&[OPAQUE_PACKAGE.as_slice(), &END_PACKAGE].concat());
        let lists = get_package_lists(&hiidb).unwrap();

        let packages = get_packages(&lists[0]).unwrap();

        assert_eq!(packages.len(), 1);
        assert_eq!(packages[0].package_type, PackageType::Unknown(0xE0));
        assert_eq!(packages[0].data, [0xAA, 0xBB]);
    }

    /// A package list that ends without an End package, whether it is
    /// empty or holds other packages, is an error rather than yielding the
    /// packages before its end: the read of the missing End package runs
    /// out of bytes.
    #[test]
    fn test_list_without_end_package_is_an_error() {
        for packages in [&[][..], &OPAQUE_PACKAGE] {
            let lists = get_package_lists(&package_list(packages)).unwrap();

            let err = get_packages(&lists[0]).unwrap_err();

            assert!(
                err.downcast_ref::<binrw::Error>().unwrap().is_eof(),
                "packages {:02x?}: {}",
                packages,
                err
            );
        }
    }

    /// Zero padding after the last package list, as edk2 leaves it (see
    /// PADDING_BYTES), is ignored.
    #[test]
    fn test_trailing_zero_padding_is_ignored() {
        let hiidb = [package_list(&END_PACKAGE), vec![0x00; 64]].concat();

        let lists = get_package_lists(&hiidb).unwrap();

        assert_eq!(lists.len(), 1);
        assert_eq!(lists[0].data, END_PACKAGE);
    }

    /// 0xFF padding after the last package list is ignored.
    #[test]
    fn test_trailing_ff_padding_is_ignored() {
        let hiidb = [package_list(&END_PACKAGE), vec![0xFF; 64]].concat();

        let lists = get_package_lists(&hiidb).unwrap();

        assert_eq!(lists.len(), 1);
        assert_eq!(lists[0].data, END_PACKAGE);
    }

    /// Zero padding shorter than a package list header is ignored.
    #[test]
    fn test_short_zero_tail_is_ignored() {
        let hiidb = [package_list(&END_PACKAGE), vec![0x00; 7]].concat();

        let lists = get_package_lists(&hiidb).unwrap();

        assert_eq!(lists.len(), 1);
        assert_eq!(lists[0].data, END_PACKAGE);
    }

    /// 0xFF padding shorter than a package list header is ignored.
    #[test]
    fn test_short_ff_tail_is_ignored() {
        let hiidb = [package_list(&END_PACKAGE), vec![0xFF; 7]].concat();

        let lists = get_package_lists(&hiidb).unwrap();

        assert_eq!(lists.len(), 1);
        assert_eq!(lists[0].data, END_PACKAGE);
    }

    /// A tail shorter than a package list header that is not padding,
    /// whether garbage or a mix of padding values, is read as a header, and
    /// the read runs out of bytes.
    #[test]
    fn test_short_non_padding_tail_is_an_error() {
        let garbage = vec![0xAB; 7];
        let mixed_padding = vec![0x00, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00];
        for tail in [garbage, mixed_padding] {
            let hiidb = [&package_list(&END_PACKAGE)[..], &tail].concat();

            let err = get_package_lists(&hiidb).unwrap_err();

            assert!(
                err.downcast_ref::<binrw::Error>().unwrap().is_eof(),
                "tail {:02x?}: {}",
                tail,
                err
            );
        }
    }

    /// A tail of mixed padding values is not padding: its zero header is
    /// read and has an invalid length.
    #[test]
    fn test_mixed_00_ff_tail_is_an_error() {
        let tail = [vec![0x00; 32], vec![0xFF; 32]].concat();
        let hiidb = [&package_list(&END_PACKAGE)[..], &tail].concat();

        let err = format!("{:#}", get_package_lists(&hiidb).unwrap_err());

        let want = format!(
            "invalid package list length 0 ({} bytes available) at 0x",
            tail.len()
        );
        assert!(err.contains(&want), "{}", err);
    }

    /// Padding between package lists is an error, so that the lists after
    /// it are not silently dropped.
    #[test]
    fn test_zero_gap_between_lists_is_an_error() {
        let list = package_list(&END_PACKAGE);
        let gap = vec![0x00; 32];
        let hiidb = [&list[..], &gap, &list].concat();

        let err = format!("{:#}", get_package_lists(&hiidb).unwrap_err());

        let want = format!(
            "invalid package list length 0 ({} bytes available) at 0x",
            gap.len() + list.len()
        );
        assert!(err.contains(&want), "{}", err);
    }

    /// A package list whose header consists of 0x00 and 0xFF bytes only is
    /// parsed, not taken for padding, when another list follows it.
    #[test]
    fn test_nil_guid_first_list_is_not_padding() {
        let hiidb = [nil_guid_list(), package_list(&END_PACKAGE)].concat();

        let lists = get_package_lists(&hiidb).unwrap();

        assert_eq!(lists.len(), 2);
        assert_eq!(
            lists[0].guid.to_string(),
            "00000000-0000-0000-0000-000000000000"
        );
        assert_eq!(
            lists[1].guid.to_string(),
            "11111111-1111-1111-1111-111111111111"
        );
    }

    /// A package list whose header consists of 0x00 and 0xFF bytes only is
    /// parsed, not taken for padding, also as the last list.
    #[test]
    fn test_nil_guid_last_list_is_not_padding() {
        let hiidb = [package_list(&END_PACKAGE), nil_guid_list()].concat();

        let lists = get_package_lists(&hiidb).unwrap();

        assert_eq!(lists.len(), 2);
        assert_eq!(
            lists[0].guid.to_string(),
            "11111111-1111-1111-1111-111111111111"
        );
        assert_eq!(
            lists[1].guid.to_string(),
            "00000000-0000-0000-0000-000000000000"
        );
    }

    /// Input that holds padding only has no package lists, which is an
    /// error rather than an empty result.
    #[test]
    fn test_all_padding_hiidb_is_an_error() {
        for padding in [0x00, 0xFF] {
            let hiidb = vec![padding; 64];

            let err = format!("{:#}", get_package_lists(&hiidb).unwrap_err());

            let want = "no package lists in 64-byte HiiDB";
            assert!(err.contains(want), "padding {:#04x}: {}", padding, err);
        }
    }

    /// Empty input has no package lists, which is an error rather than an
    /// empty result.
    #[test]
    fn test_empty_hiidb_is_an_error() {
        let err = format!("{:#}", get_package_lists(&[]).unwrap_err());

        assert!(err.contains("no package lists in 0-byte HiiDB"), "{}", err);
    }

    /// read_db returns the strings of every package list of a zero-padded
    /// HiiDB, each under the GUID of its list, and no entry for a list
    /// without strings.
    #[test]
    fn test_read_db_keys_strings_by_list_guid_in_padded_hiidb() {
        let a_packages = [en_strings_package(b'A'), END_PACKAGE.to_vec()].concat();
        let b_packages = [en_strings_package(b'B'), END_PACKAGE.to_vec()].concat();
        // the list without strings sits between the lists with strings, so a
        // read_db that stops before the last list loses the string "B"
        let hiidb = [
            package_list_with_guid([0x11; 16], &a_packages),
            package_list_with_guid([0x22; 16], &END_PACKAGE),
            package_list_with_guid([0x33; 16], &b_packages),
            vec![0x00; 16],
        ]
        .concat();

        let db = read_db(&hiidb).unwrap();

        let want = HashMap::from([
            (
                "11111111-1111-1111-1111-111111111111".to_string(),
                vec![HashMap::from([(1, "A".to_string())])],
            ),
            (
                "33333333-3333-3333-3333-333333333333".to_string(),
                vec![HashMap::from([(1, "B".to_string())])],
            ),
        ]);
        assert_eq!(db.strings, want);
        assert!(db.forms.is_empty());
    }

    #[test]
    fn test_read_db_strings() {
        let file_path = "testdata/hiidb.bin";
        if fs::metadata(file_path).is_err() {
            // The BIOS firmware we tested on was proprietary, thus I'm not sure we're allowed to share even the HiiDB. Keeping the test here for anybody how has the HiiDB this is tested on; or feel free to modify the test to use GALAGOPRO or any other free UEFI firmware.
            return;
        }
        let mut file = File::open(file_path).unwrap();
        let mut file_contents = Vec::new();
        file.read_to_end(&mut file_contents).unwrap();
        let res = read_db(&file_contents).unwrap();

        // compare number of package lists which have string type packages
        assert_eq!(res.strings.len(), 12);

        // compare a certain string
        assert_eq!(
            res.strings
                .get("ABBCE13D-E25A-4D9F-A1F9-2F7710786892")
                .unwrap()
                .first()
                .unwrap()
                .get(&8)
                .unwrap(),
            "MMIO Low Base"
        );

        // compare number of strings in the 0 indexed (1st) package of given package list
        assert_eq!(
            res.strings
                .get("ABBCE13D-E25A-4D9F-A1F9-2F7710786892")
                .unwrap()
                .first()
                .unwrap()
                .len(),
            5714
        );

        // compare number of string packages in this package list
        assert_eq!(
            res.strings
                .get("ABBCE13D-E25A-4D9F-A1F9-2F7710786892")
                .unwrap()
                .len(),
            2
        );
    }

    #[test]
    fn test_read_db_forms() {
        let file_path = "testdata/hiidb.bin";
        if fs::metadata(file_path).is_err() {
            // The BIOS firmware we tested on was proprietary, thus I'm not sure we're allowed to share even the HiiDB. Keeping the test here for anybody how has the HiiDB this is tested on; or feel free to modify the test to use GALAGOPRO or any other free UEFI firmware.
            return;
        }
        let mut file = File::open(file_path).unwrap();
        let mut file_contents = Vec::new();
        file.read_to_end(&mut file_contents).unwrap();
        let res = read_db(&file_contents).unwrap();

        let root_node = res
            .forms
            .get("ABBCE13D-E25A-4D9F-A1F9-2F7710786892")
            .unwrap()
            .first()
            .unwrap()
            .borrow();

        // root element should only have one child
        assert_eq!(root_node.children.len(), 1);

        // root elements's child should be FormSet
        assert_eq!(
            root_node.children.first().unwrap().borrow().op_code,
            forms::IFROpCode::FormSet
        );

        // root elements's child FormSet should have open scope
        assert!(root_node.children.first().unwrap().borrow().open_scope);

        // root_node's child should be able to refer to it's parent which is root_node
        // root_node has a dummy opcode used only in root nodes so if they match
        // we can be sure it's referring to the correct node
        assert_eq!(
            root_node
                .children
                .first()
                .unwrap()
                .borrow()
                .parent
                .as_ref()
                .unwrap()
                .upgrade()
                .unwrap()
                .borrow()
                .op_code,
            root_node.op_code
        );
    }
}
