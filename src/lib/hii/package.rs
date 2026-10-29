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
// no Vec of per-variant errors per package; see forms::IFROpCode
#[br(little, return_unexpected_error)]
enum PackageType {
    #[br(magic = 0x01u8)]
    Guid,
    #[br(magic = 0x02u8)]
    Form,
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
    #[br(magic = 0x09u8)]
    KeyboardLayout,
    #[br(magic = 0xDFu8)]
    End,
    Unknown(u8),
}

/// get_package_lists splits a HiiDB into its package lists. Of each list it
/// validates only the PackageLength, which must cover the header and end
/// within the HiiDB; the packages inside are validated by get_packages. It
/// ignores trailing padding (see is_padding), and fails if the HiiDB is
/// empty or padding only, if a PackageLength is invalid, or if a tail that
/// is not padding is too short for a package list header.
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
        // Fail: returning the lists parsed so far would give the caller
        // `Ok` without the unparsable list or any list after it.
        let package_list: PackageList = db_cursor
            .read_ne_args(AvailableBytes(available))
            .with_context(|| {
                format!("failed to parse the package list at offset {used_bytes:#x}")
            })?;
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
/// ignored, and a list without one ends at its PackageLength. It fails on a
/// package whose Length is invalid and on a list that ends inside a package
/// header.
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
        // UEFI Spec v2.10 §33.3.1.1 requires an End package, but the HiiDB of
        // <https://github.com/linuxboot/uefisettings/issues/16> omits it, and
        // PackageLength bounds the list.
        if pl_cursor.position() == pl_size {
            debug!(
                "Package List {} ends without an End package",
                package_list.guid
            );
            break;
        }

        // Cannot underflow: every package read so far had
        // `length <= available`, so the position stays <= pl_size.
        let available = pl_size - pl_cursor.position();
        // Fail: returning the packages parsed so far would give the
        // caller `Ok` without the unparsable package or any package
        // after it.
        let package: Package = pl_cursor.read_ne_args(AvailableBytes(available))?;

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

/// String map (string id -> string) per strings package and IFR root per form
/// package of one package list.
pub struct ParsedPackageList {
    pub guid: Guid,
    pub strings: Vec<StringMap>,
    pub forms: Vec<IFRNodeLink>,
}

impl ParsedPackageList {
    /// Fails if the list has forms but no strings packages.
    pub fn check_form_strings(&self) -> Result<()> {
        ensure!(
            self.forms.is_empty() || !self.strings.is_empty(),
            "Failed to get string packages using GUID {}",
            self.guid
        );
        Ok(())
    }
}

/// read_db input (source) is a vector of u8 bytes
/// In hiidb, we have package lists which have multiple packages of different types including string, form and end type packages.
/// For every package list, we will parse different packages. If package type is
/// * string -> parse and save data
/// * form -> parse and save data
/// * something else (like fonts or animations) -> we don't care about them, so continue to the next package in the package list.
///
/// In the end return the parsed package lists in HiiDB order; GUIDs may repeat.
pub fn read_db(source: &[u8]) -> Result<Vec<ParsedPackageList>> {
    // into_iter frees each raw list once parsed, lowering peak memory
    get_package_lists(source)?
        .into_iter()
        .map(|package_list| {
            read_package_list(&package_list)
                .with_context(|| format!("failed to parse package list {}", package_list.guid))
        })
        .collect()
}

/// Parses the strings and form packages of a package list and skips the others.
fn read_package_list(package_list: &PackageList) -> Result<ParsedPackageList> {
    // once filled this will have string maps from each string package in the package list.
    let mut package_list_string_maps: Vec<StringMap> = Vec::new();
    let mut roots: Vec<IFRNodeLink> = Vec::new();

    for package in get_packages(package_list)? {
        let mut package_cursor = Cursor::new(&package.data);

        match package.package_type {
            PackageType::Strings => {
                // We can also continue to ignore the error because we already know the bounds of each package so we can skip to the next one.
                let string_map = strings::handle_string_package(&mut package_cursor)
                    .context("failed to parse a strings package")?;
                package_list_string_maps.push(string_map);
            }
            PackageType::Form => {
                // We can also continue to ignore the error because we already know the bounds of each package so we can skip to the next one.
                let root_node = forms::handle_form_package(&mut package_cursor)
                    .context("failed to parse a form package")?;
                roots.push(root_node);
            }
            _ => continue,
        }
    }

    Ok(ParsedPackageList {
        guid: package_list.guid,
        strings: package_list_string_maps,
        forms: roots,
    })
}

#[cfg(test)]
pub(crate) mod hiidb_fixtures;

#[cfg(test)]
mod tests {
    use std::fs;
    use std::fs::File;
    use std::io::Read;

    use super::hiidb_fixtures::*;
    use super::*;

    /// OPAQUE_PACKAGE is a package with Length 6, that is, 2 bytes of data:
    /// 0xAA 0xBB. Its Type 0xE0 is in the range that UEFI Spec v2.10 §33.3.1.1
    /// (Table 33.9) reserves for system firmware implementers, so its data
    /// has no spec-defined layout, and read_db skips it.
    ///
    /// Example: get_packages reads OPAQUE_PACKAGE as a package of type
    /// `Unknown(0xE0)` with data `[0xAA, 0xBB]`.
    const OPAQUE_PACKAGE: [u8; 6] = [0x06, 0x00, 0x00, 0xE0, 0xAA, 0xBB];

    /// package_list encodes a package list with GUID 11..11 whose
    /// PackageLength covers its header and `packages`.
    ///
    /// Example: `package_list(&END_PACKAGE)` is 24 bytes long, with
    /// PackageLength 24.
    fn package_list(packages: &[u8]) -> Vec<u8> {
        package_list_with_guid([0x11; 16], packages)
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

    /// Pairs each list's GUID with its string maps, in order.
    fn strings_of_lists(lists: Vec<ParsedPackageList>) -> Vec<(String, Vec<StringMap>)> {
        lists
            .into_iter()
            .map(|list| (list.guid.to_string(), list.strings))
            .collect()
    }

    /// Returns the first list with GUID `guid`.
    fn list_with_guid<'a>(lists: &'a [ParsedPackageList], guid: &str) -> &'a ParsedPackageList {
        lists
            .iter()
            .find(|list| list.guid.to_string() == guid)
            .unwrap_or_else(|| panic!("find package list {guid}"))
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

    /// A package of Type 0x09 is a keyboard layout package, while 0x03, which
    /// UEFI Spec v2.10 §33.3.1.1 leaves undefined, is an unknown one.
    #[test]
    fn test_package_types_follow_the_spec() {
        for (package_type, want) in [
            (0x09, PackageType::KeyboardLayout),
            (0x03, PackageType::Unknown(0x03)),
        ] {
            let case = format!("Type {:#04x}", package_type);
            let lists = get_package_lists(&package_list(&[0x04, 0x00, 0x00, package_type]))
                .unwrap_or_else(|e| panic!("split list of {}: {:#}", case, e));

            let got = get_packages(&lists[0]).unwrap_or_else(|e| panic!("{}: {:#}", case, e));

            assert_eq!(got.len(), 1, "{}", case);
            assert_eq!(got[0].package_type, want, "{}", case);
        }
    }

    /// A package list whose packages fill its PackageLength without an End
    /// package, whether it is empty or holds packages, yields those packages.
    #[test]
    fn test_list_without_end_package_is_parsed() {
        let two_packages = [OPAQUE_PACKAGE; 2].concat();
        for (packages, want) in [
            (&[][..], 0),
            (&OPAQUE_PACKAGE[..], 1),
            (&two_packages[..], 2),
        ] {
            let case = format!("packages {:02x?}", packages);
            let lists = get_package_lists(&package_list(packages))
                .unwrap_or_else(|e| panic!("split list of {}: {:#}", case, e));

            let got = get_packages(&lists[0]).unwrap_or_else(|e| panic!("{}: {:#}", case, e));

            assert_eq!(got.len(), want, "{}", case);
            for package in got {
                assert_eq!(package.package_type, PackageType::Unknown(0xE0), "{}", case);
                assert_eq!(package.data, [0xAA, 0xBB], "{}", case);
            }
        }
    }

    /// A package list that ends inside a package header is an error rather
    /// than the end of the list: the read of that header runs out of bytes.
    #[test]
    fn test_list_ending_in_package_header_is_an_error() {
        for partial in 1..PACKAGE_HEADER_SIZE {
            let partial = usize::try_from(partial).expect("convert header size into usize");
            let packages = [&OPAQUE_PACKAGE[..], &OPAQUE_PACKAGE[..partial]].concat();
            let lists = get_package_lists(&package_list(&packages))
                .unwrap_or_else(|e| panic!("split list with {} header bytes: {:#}", partial, e));

            let Err(err) = get_packages(&lists[0]) else {
                panic!("{} header bytes: list parsed", partial);
            };

            assert!(
                err.downcast_ref::<binrw::Error>()
                    .is_some_and(binrw::Error::is_eof),
                "{} header bytes: {:#}",
                partial,
                err
            );
        }
    }

    /// A parse error renders as main puts it into the JSON error_message:
    /// with its context but without the ANSI escapes or banner of binrw's
    /// verbose-backtrace feature (off in Cargo.toml).
    #[test]
    fn test_parse_error_renders_without_ansi_or_banner() {
        let lists =
            get_package_lists(&package_list(&OPAQUE_PACKAGE[..2])).expect("split the HiiDB");
        let Err(err) = get_packages(&lists[0]) else {
            panic!("list ending in a package header parsed");
        };

        let rendered = format!("{:#}", err);

        let context = "While parsing field 'length' in Package";
        assert!(rendered.contains(context), "context in {:?}", rendered);
        assert!(!rendered.contains('\x1b'), "escape in {:?}", rendered);
        assert!(!rendered.contains('━'), "banner in {:?}", rendered);
    }

    /// The End package ends its package list before PackageLength does: the
    /// bytes after it are not read as packages.
    #[test]
    fn test_end_package_ends_list_before_its_length() {
        // Length 0xABABAB exceeds the bytes, so they fail as a package
        let unparsable = [0xAB; 5];
        let packages = [&OPAQUE_PACKAGE[..], &END_PACKAGE, &unparsable].concat();
        let lists = get_package_lists(&package_list(&packages)).expect("split the HiiDB");

        let got = get_packages(&lists[0]).expect("read the packages before the End package");

        assert_eq!(got.len(), 1, "count of packages before the End package");
        let case = "package before the End package";
        assert_eq!(got[0].package_type, PackageType::Unknown(0xE0), "{}", case);
        assert_eq!(got[0].data, [0xAA, 0xBB], "{}", case);
    }

    /// read_db reads package lists that end without End packages, as in
    /// <https://github.com/linuxboot/uefisettings/issues/16>, next to a list
    /// with one.
    #[test]
    fn test_read_db_reads_lists_without_end_package() {
        let hiidb = [
            package_list_with_guid([0x11; 16], &en_strings_package(b'A')),
            package_list_with_guid([0x22; 16], &OPAQUE_PACKAGE),
            en_strings_list([0x33; 16], b'B'),
        ]
        .concat();

        let lists = read_db(&hiidb).expect("read the HiiDB");

        assert!(
            lists.iter().all(|list| list.forms.is_empty()),
            "forms of the lists"
        );
        let want = vec![
            (
                "11111111-1111-1111-1111-111111111111".to_string(),
                vec![HashMap::from([(1, "A".to_string())])],
            ),
            ("22222222-2222-2222-2222-222222222222".to_string(), vec![]),
            (
                "33333333-3333-3333-3333-333333333333".to_string(),
                vec![HashMap::from([(1, "B".to_string())])],
            ),
        ];
        assert_eq!(strings_of_lists(lists), want, "strings of the lists");
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
    /// HiiDB, each with the GUID of its list.
    #[test]
    fn test_read_db_reads_strings_of_every_list_in_padded_hiidb() {
        // the list without strings sits between the lists with strings, so a
        // read_db that stops before the last list loses the string "B"
        let hiidb = [
            en_strings_list([0x11; 16], b'A'),
            package_list_with_guid([0x22; 16], &END_PACKAGE),
            en_strings_list([0x33; 16], b'B'),
            vec![0x00; 16],
        ]
        .concat();

        let lists = read_db(&hiidb).expect("read the HiiDB");

        assert!(
            lists.iter().all(|list| list.forms.is_empty()),
            "forms of the lists"
        );
        let want = vec![
            (
                "11111111-1111-1111-1111-111111111111".to_string(),
                vec![HashMap::from([(1, "A".to_string())])],
            ),
            ("22222222-2222-2222-2222-222222222222".to_string(), vec![]),
            (
                "33333333-3333-3333-3333-333333333333".to_string(),
                vec![HashMap::from([(1, "B".to_string())])],
            ),
        ];
        assert_eq!(strings_of_lists(lists), want, "strings of the lists");
    }

    /// read_db keeps package lists in HiiDB order, duplicate GUIDs included.
    #[test]
    fn test_read_db_keeps_hiidb_order_and_duplicate_guids() {
        let hiidb = [
            en_strings_list([0x33; 16], b'A'),
            en_strings_list([0x11; 16], b'C'),
            en_strings_list([0x33; 16], b'B'),
        ]
        .concat();

        let lists = read_db(&hiidb).expect("read the HiiDB");

        let want = vec![
            (
                "33333333-3333-3333-3333-333333333333".to_string(),
                vec![HashMap::from([(1, "A".to_string())])],
            ),
            (
                "11111111-1111-1111-1111-111111111111".to_string(),
                vec![HashMap::from([(1, "C".to_string())])],
            ),
            (
                "33333333-3333-3333-3333-333333333333".to_string(),
                vec![HashMap::from([(1, "B".to_string())])],
            ),
        ];
        assert_eq!(
            strings_of_lists(lists),
            want,
            "lists in HiiDB order, duplicates kept"
        );
    }

    /// read_db keeps the forms of a package list with its own strings, not
    /// with those of a later list of the same GUID.
    #[test]
    fn test_read_db_keeps_forms_with_strings_of_their_list() {
        let hiidb = [
            package_list_with_guid(
                [0x33; 16],
                &[
                    &END_ONLY_FORM_PACKAGE[..],
                    &en_strings_package(b'A'),
                    &END_PACKAGE,
                ]
                .concat(),
            ),
            en_strings_list([0x33; 16], b'B'),
        ]
        .concat();

        let lists = read_db(&hiidb).expect("read the HiiDB");

        let got: Vec<(usize, Vec<StringMap>)> = lists
            .into_iter()
            .map(|list| (list.forms.len(), list.strings))
            .collect();
        let want = vec![
            (1, vec![HashMap::from([(1, "A".to_string())])]),
            (0, vec![HashMap::from([(1, "B".to_string())])]),
        ];
        assert_eq!(got, want, "forms stay with the strings of their list");
    }

    /// check_form_strings fails only for a list with forms but no strings
    /// packages.
    #[test]
    fn test_check_form_strings_fails_for_forms_without_strings() {
        let forms_only = [&END_ONLY_FORM_PACKAGE[..], &END_PACKAGE].concat();
        let both = [
            &END_ONLY_FORM_PACKAGE[..],
            &en_strings_package(b'A'),
            &END_PACKAGE,
        ]
        .concat();
        let hiidb = [
            package_list_with_guid([0x11; 16], &forms_only),
            package_list_with_guid([0x22; 16], &END_PACKAGE),
            en_strings_list([0x33; 16], b'A'),
            package_list_with_guid([0x44; 16], &both),
        ]
        .concat();

        let lists = read_db(&hiidb).expect("read the HiiDB");

        let got: Vec<Option<String>> = lists
            .iter()
            .map(|list| {
                list.check_form_strings()
                    .err()
                    .map(|err| format!("{err:#}"))
            })
            .collect();
        let want = vec![
            Some(
                "Failed to get string packages using GUID 11111111-1111-1111-1111-111111111111"
                    .to_string(),
            ),
            None,
            None,
            None,
        ];
        assert_eq!(got, want, "forms only, neither, strings only, both");
    }

    /// read_db errors name the package list whose packages it cannot parse.
    #[test]
    fn test_read_db_error_names_the_package_list() {
        // Length 256 exceeds the 6 bytes left in the list
        let hiidb = package_list_with_guid([0x22; 16], &[0x00, 0x01, 0x00, 0xE0, 0xAA, 0xBB]);
        let Err(err) = read_db(&hiidb) else {
            panic!("read_db parsed a package beyond its list");
        };
        let msg = format!("{err:#}");
        assert!(
            msg.starts_with("failed to parse package list 22222222-2222-2222-2222-222222222222: "),
            "error names the list: {msg}"
        );
        assert!(
            msg.contains("invalid package length 256 (6 bytes available)"),
            "error keeps its cause: {msg}"
        );
        assert_eq!(
            msg.matches("22222222-2222-2222-2222-222222222222").count(),
            1,
            "error names the list once: {msg}"
        );
    }

    /// read_db errors in a string block name the package list, the strings
    /// package and the read that failed.
    #[test]
    fn test_read_db_error_names_the_strings_package_and_block() {
        let cases: [(&[u8], &str); 4] = [
            (&[], "failed to read a string block type"),
            // EFI_HII_SIBT_STRING_UCS2 "A" without its null terminator
            (
                &[0x14, b'A', 0x00],
                "failed to read a null-terminated 16-bit string",
            ),
            // EFI_HII_SIBT_SKIP2 with 1 of the 2 bytes of its count
            (&[0x21, 0x05], "failed to read a Skip2 count"),
            // EFI_HII_SIBT_SKIP1 without its count
            (&[0x22], "failed to read a Skip1 count"),
        ];
        for (blocks, read) in cases {
            let package = en_strings_package_with_blocks(blocks);
            let hiidb =
                package_list_with_guid([0x22; 16], &[package, END_PACKAGE.to_vec()].concat());

            let Err(err) = read_db(&hiidb) else {
                panic!("read_db parsed the string blocks {blocks:02x?}");
            };

            let msg = format!("{err:#}");
            let want = format!(
                "failed to parse package list 22222222-2222-2222-2222-222222222222: \
                 failed to parse a strings package: {read}: "
            );
            assert!(msg.starts_with(&want), "blocks {blocks:02x?}: {msg}");
            assert!(
                err.chain().any(|cause| cause.is::<binrw::Error>()),
                "blocks {blocks:02x?} keep the cause: {msg}"
            );
        }
    }

    /// read_db errors in a form package name the package list and the form
    /// package.
    #[test]
    fn test_read_db_error_names_the_form_package() {
        // an IFR End op without its length byte
        let form_package = [0x05, 0x00, 0x00, 0x02, 0x29];
        let hiidb = package_list_with_guid([0x22; 16], &form_package);

        let Err(err) = read_db(&hiidb) else {
            panic!("read_db parsed a truncated IFR op");
        };

        let msg = format!("{err:#}");
        let want = "failed to parse package list 22222222-2222-2222-2222-222222222222: \
                    failed to parse a form package: ";
        assert!(
            msg.starts_with(want),
            "error names the list and package: {msg}"
        );
        assert!(
            err.chain().any(|cause| cause.is::<binrw::Error>()),
            "error keeps its cause: {msg}"
        );
    }

    /// read_db names the offset of a package list whose header it cannot
    /// parse.
    #[test]
    fn test_read_db_error_names_the_offset_of_an_unparsable_list() {
        let list = package_list(&END_PACKAGE);
        let hiidb = [&list[..], &package_list_header(0)].concat();

        let Err(err) = read_db(&hiidb) else {
            panic!("read_db parsed a package list shorter than its header");
        };

        let msg = format!("{err:#}");
        let want = format!(
            "failed to parse the package list at offset {:#x}: invalid package list length 0 ",
            list.len()
        );
        assert!(msg.starts_with(&want), "error names the offset: {msg}");
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
        assert_eq!(
            res.iter().filter(|list| !list.strings.is_empty()).count(),
            12,
            "package lists with strings"
        );

        // compare a certain string
        assert_eq!(
            list_with_guid(&res, "ABBCE13D-E25A-4D9F-A1F9-2F7710786892")
                .strings
                .first()
                .unwrap()
                .get(&8)
                .unwrap(),
            "MMIO Low Base"
        );

        // compare number of strings in the 0 indexed (1st) package of given package list
        assert_eq!(
            list_with_guid(&res, "ABBCE13D-E25A-4D9F-A1F9-2F7710786892")
                .strings
                .first()
                .unwrap()
                .len(),
            5714
        );

        // compare number of string packages in this package list
        assert_eq!(
            list_with_guid(&res, "ABBCE13D-E25A-4D9F-A1F9-2F7710786892")
                .strings
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

        let root_node = list_with_guid(&res, "ABBCE13D-E25A-4D9F-A1F9-2F7710786892")
            .forms
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
