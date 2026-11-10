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
use std::fmt;
use std::io::Seek;
use std::rc::Rc;
use std::str::FromStr;

use anyhow::ensure;
use anyhow::Context;
use anyhow::Result;
use binrw::io::Cursor;
use binrw::io::SeekFrom;
use binrw::BinRead;
use log::debug;
use serde::Serialize;
use serde::Serializer;

use crate::hii::forms;
use crate::hii::forms::IFROperation;
use crate::hii::strings;
use crate::hii::strings::ListTexts;
use crate::parse_error::ReadParsed;

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
pub(super) const PACKAGE_HEADER_SIZE: u32 = 4;

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
/// PackageList's BinRead takes it, so it is as visible as PackageList; its field
/// stays private.
pub(crate) struct AvailableBytes(u64);

/// PackageList is an EFI_HII_PACKAGE_LIST_HEADER followed by its packages.
/// Its import `available` counts the bytes from its start to the end of the
/// HiiDB; reading fails if its length is below the header size or above
/// `available`.
///
/// Example: get_package_lists reads each package list with
/// `db_cursor.parse_ne_args::<PackageList>(AvailableBytes(db_size - used_bytes))`.
#[derive(BinRead, Debug, PartialEq)]
#[br(little, import_raw(available: AvailableBytes))]
pub(crate) struct PackageList {
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
/// `pl_cursor.parse_ne_args::<Package>(AvailableBytes(pl_size - pl_cursor.position()))`.
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

// UEFI 2.10 §33.3.1.1
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
pub(crate) fn get_package_lists(source: &[u8]) -> Result<Vec<PackageList>> {
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
            .parse_ne_args(AvailableBytes(available))
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
pub(super) fn is_padding(bytes: &[u8]) -> bool {
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
        let package: Package = pl_cursor.parse_ne_args(AvailableBytes(available))?;

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

#[derive(PartialEq, Eq, PartialOrd, Ord, Hash, Copy, Clone, BinRead)]
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

/// The registry format that Display writes, such as 8BE4DF61-93CA-11D2-AA0D-00E098032B8C, in
/// either case.
impl FromStr for Guid {
    type Err = uguid::GuidFromStrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        uguid::Guid::try_parse(s).map(|guid| guid.to_bytes().into())
    }
}

/// The registry format that Display writes, as a string.
impl Serialize for Guid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

// EFI_GUID's bytes: Data1, Data2 and Data3 little-endian, then Data4 (UEFI 2.10 Appendix A)
impl From<Guid> for [u8; 16] {
    fn from(guid: Guid) -> Self {
        let [a, b, c, d] = guid.data1.to_le_bytes();
        let [e, f] = guid.data2.to_le_bytes();
        let [g, h] = guid.data3.to_le_bytes();
        let [i, j, k, l, m, n, o, p] = guid.data4;
        [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p]
    }
}

impl From<[u8; 16]> for Guid {
    fn from(bytes: [u8; 16]) -> Self {
        let [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p] = bytes;
        Self {
            data1: u32::from_le_bytes([a, b, c, d]),
            data2: u16::from_le_bytes([e, f]),
            data3: u16::from_le_bytes([g, h]),
            data4: [i, j, k, l, m, n, o, p],
        }
    }
}

/// The bytes of an EFI_DEVICE_PATH_PROTOCOL instance, as a device path package (UEFI 2.10
/// §33.3.4) and a configuration string's PATH carry them.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DevicePath(Vec<u8>);

impl From<Vec<u8>> for DevicePath {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl FromIterator<u8> for DevicePath {
    fn from_iter<I: IntoIterator<Item = u8>>(bytes: I) -> Self {
        Self(bytes.into_iter().collect())
    }
}

impl AsRef<[u8]> for DevicePath {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

type IFRNodeLink = Rc<RefCell<IFROperation>>;

/// The strings packages and the IFR root of each FormSet of one package list.
pub struct ParsedPackageList {
    pub guid: Guid,
    /// The device path of the driver handle that added the list, from its device path package
    /// (UEFI 2.10 §33.3.4), if it has one
    pub device_path: Option<DevicePath>,
    pub strings: Vec<strings::StringPackage>,
    pub forms: Vec<IFRNodeLink>,
    /// The IFR of its form packages that read_db ignores, whose PASSWORD questions are unknown
    pub ignored_ifr: Vec<forms::IgnoredIfr>,
    /// The VarStores and statements of its form packages outside the FormSets that read_db parses
    pub outside_ifr: Vec<forms::OutsideOp>,
    /// The VarStores of its form packages outside the FormSets that read_db parses that do not
    /// parse, whose VarStoreIds are unknown
    pub malformed_outside_stores: Vec<forms::IgnoredIfr>,
    /// The forms that read_db drops from `forms`, whose PASSWORD ops are kept and resolved where
    /// they parse
    pub disabled_forms: Vec<forms::DisabledForm>,
}

impl ParsedPackageList {
    /// The texts of the list's questions and other ops, as get, set, list-questions and show-ifr
    /// show and match them, shown in the language that ListTexts::new picks for `requested`, the
    /// stated language and PlatformLang, in that order, those that are given.
    pub(crate) fn texts(&self, requested: &[&str]) -> ListTexts<'_> {
        ListTexts::new(&self.strings, requested)
    }

    /// The records of the IFR of its form packages that read_db leaves out of `forms`, which may
    /// hold questions that no command reaches: that of `ignored_ifr`, then that of each of
    /// `disabled_forms`.
    pub fn ignored_records(&self) -> impl Iterator<Item = forms::IgnoredIfr> + '_ {
        self.ignored_ifr.iter().cloned().chain(
            self.disabled_forms
                .iter()
                .map(|disabled| disabled.record(self.guid)),
        )
    }

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
/// * device path -> save its bytes
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

/// Parses the strings and form packages of a package list, keeps its device path package and
/// skips the others.
fn read_package_list(package_list: &PackageList) -> Result<ParsedPackageList> {
    let mut string_packages = Vec::new();
    let mut roots: Vec<IFRNodeLink> = Vec::new();
    let mut ignored_ifr = Vec::new();
    let mut outside_ifr = Vec::new();
    let mut malformed_outside_stores = Vec::new();
    let mut disabled_forms = Vec::new();
    let mut device_path = None;

    for package in get_packages(package_list)? {
        let mut package_cursor = Cursor::new(&package.data);

        match package.package_type {
            PackageType::Strings => {
                // We can also continue to ignore the error because we already know the bounds of each package so we can skip to the next one.
                string_packages.push(
                    strings::handle_string_package(&package.data)
                        .context("failed to parse a strings package")?,
                );
            }
            PackageType::Form => {
                // We can also continue to ignore the error because we already know the bounds of each package so we can skip to the next one.
                let form_sets = forms::parse_form_sets(&mut package_cursor, package_list.guid)
                    .context("failed to parse a form package")?;
                roots.extend(form_sets.roots);
                ignored_ifr.extend(form_sets.ignored);
                outside_ifr.extend(form_sets.outside);
                malformed_outside_stores.extend(form_sets.malformed_stores);
                disabled_forms.extend(form_sets.disabled_forms);
            }
            // NewPackageList creates the one device path package of a list (UEFI 2.10 §33.3.4)
            PackageType::DevicePath => {
                ensure!(device_path.is_none(), "a second device path package");
                device_path = Some(package.data.into());
            }
            PackageType::Guid
            | PackageType::Fonts
            | PackageType::Images
            | PackageType::SimpleFonts
            | PackageType::KeyboardLayout
            | PackageType::End
            | PackageType::Unknown(_) => continue,
        }
    }

    // the PASSWORD ops of disabled forms keep their passwords in the variables of their VarNames
    let named: Vec<IFRNodeLink> = roots
        .iter()
        .chain(disabled_forms.iter().map(|disabled| &disabled.form))
        .cloned()
        .collect();
    forms::resolve_short_var_names(&named, &string_packages);
    Ok(ParsedPackageList {
        guid: package_list.guid,
        device_path,
        strings: string_packages,
        forms: roots,
        ignored_ifr,
        outside_ifr,
        malformed_outside_stores,
        disabled_forms,
    })
}

/// The largest HiiDB file that read_db_bytes reads; the HiiDB efivar's length and
/// `hiidb_driver.rs`'s cap on a read through the driver are bounded by it too. So are the JSON
/// configuration and capsule result tables, which firmware sizes, on every build that reads
/// them.
pub(crate) const MAX_ALLOWED_FILESIZE: u64 = 16 * 1024 * 1024;

#[cfg(hiidb_files)]
pub(crate) mod db_file;
#[cfg(test)]
pub(crate) mod hiidb_fixtures;

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::fs;
    use std::fs::File;
    use std::io::Read;
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use super::hiidb_fixtures::*;
    use super::*;
    use crate::hii::forms::ifr_fixtures::form;
    use crate::hii::forms::ifr_fixtures::form_set;
    use crate::hii::forms::ifr_fixtures::nested;
    use crate::hii::forms::ifr_fixtures::password_on;
    use crate::hii::forms::ifr_fixtures::scopeless_form_set;
    use crate::hii::forms::ifr_fixtures::subtitle_scope;
    use crate::hii::forms::ifr_fixtures::CHECKBOX;
    use crate::hii::forms::ifr_fixtures::END;
    use crate::hii::forms::MAX_SCOPE_NESTING;
    use crate::hii::scsu::tests::EDK2_LANGUAGE_WINDOW;
    use crate::hii::strings::StringMap;
    use crate::parse_error::ParseError;

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

    /// The string maps of `packages`, in order.
    fn maps_of(packages: &[strings::StringPackage]) -> Vec<StringMap> {
        packages
            .iter()
            .map(|package| package.strings.clone())
            .collect()
    }

    /// Pairs each list's GUID with its string maps, in order.
    fn strings_of_lists(lists: Vec<ParsedPackageList>) -> Vec<(String, Vec<StringMap>)> {
        lists
            .into_iter()
            .map(|list| (list.guid.to_string(), maps_of(&list.strings)))
            .collect()
    }

    /// Returns the first list with GUID `guid`.
    fn list_with_guid<'a>(lists: &'a [ParsedPackageList], guid: &str) -> &'a ParsedPackageList {
        lists
            .iter()
            .find(|list| list.guid.to_string() == guid)
            .unwrap_or_else(|| panic!("find package list {guid}"))
    }

    /// A FormSet of the Guid of 16 `guid` bytes, holding `body`.
    fn form_set_of_guid(guid: u8, body: &[u8]) -> Vec<u8> {
        [
            &[0x0E, 0x80 | 39][..], // FormSet: Length, Scope
            &[guid; 16],
            &[0x01, 0x00, 0x02, 0x00, 0x01], // FormSetTitle, Help, Flags: one ClassGuid
            &[0x22; 16],                     // ClassGuid
            body,
            &END,
        ]
        .concat()
    }

    /// The package list that read_db reads from a HiiDB of one list holding a form package of
    /// `ifr`.
    fn read_form_package(ifr: &[u8]) -> Result<ParsedPackageList> {
        let hiidb = package_list_with_guid(
            [0x22; 16],
            &[form_package_of(ifr), END_PACKAGE.to_vec()].concat(),
        );
        let mut lists = read_db(&hiidb)?;
        Ok(lists.remove(0))
    }

    /// The roots that read_db reads from a form package of `ifr`, each by the last byte of the
    /// Guid of the FormSet it holds, None if it holds no FormSet first.
    fn form_set_guids(ifr: Vec<u8>) -> Result<Vec<Option<u8>>> {
        let list = read_form_package(&ifr)?;
        Ok(list
            .forms
            .iter()
            .map(|root| {
                let root = root.borrow();
                let first = root.children.first()?.borrow();
                match &first.parsed_data {
                    forms::ParsedOperation::FormSet(parsed) => Some(parsed.guid.data4[7]),
                    _ => None,
                }
            })
            .collect())
    }

    /// read_db lists the IFR of a form package that its walk for FormSets leaves unread, at its
    /// offset: a later FormSet whose bytes do not parse or that nests too deep, named by its GUID
    /// if its data holds one; the bytes from an op where the walk ends, unless they are padding;
    /// and a FormSet, first or later, without its Scope bit, which edk2 parses on past the End
    /// that ends it here, once, as a FormSet that does not parse if it does not; not the FormSets
    /// it reads.
    #[test]
    fn test_read_db_lists_the_ifr_that_it_ignores() {
        let first = form_set_of_guid(0xA0, &[]);
        // the FormSet's own scope and these
        let too_deep = nested(&subtitle_scope(5), MAX_SCOPE_NESTING, &[]);
        let short_checkbox = [CHECKBOX, 0x03, 0x00]; // 1 of its data bytes
        let short = |form_set, op| {
            format!(
                "{form_set}, which holds, outside its forms, an op shorter than its minimum, which \
                 UEFI 2.11 §33.2.5.10.1 calls malformed, in no form for that section to disable: \
                 the {op} op at offset "
            )
        };
        let b0 = format!("the FormSet {}", Guid::from([0xB0; 16]));
        let nested_too_deep = format!(
            "{b0}, which nests too deep: IFR scopes nest deeper than {MAX_SCOPE_NESTING} at offset "
        );
        let opens_no_scope = |form_set| {
            format!(
                "{form_set} opens no scope, so edk2 parses its ops on to the end of the form \
                 package, past the End where uefisettings ends it (edk2-stable202211 \
                 SetupBrowserDxe IfrParse.c ParseOpCodes pushes a scope only for Scope != 0, and \
                 ends a FormSet only at the End of a FORM_SET scope)"
            )
        };
        let eleven = "the FormSet 11111111-1111-1111-1111-111111111111";
        // a form, then a form with a PASSWORD that edk2 parses into the FormSet before them
        let two_forms = [form(1, &[]), form(2, &[password_on(1, 1, 0, 0)])];
        let without_end = |form_set: Vec<u8>| form_set[..form_set.len() - END.len()].to_vec();
        let not_fit = |length| {
            format!(
                "an op that does not fit the form package, and the bytes after it: invalid IFR \
                 operation length {length}"
            )
        };
        let runs_past =
            "an op that does not fit the form package, and the bytes after it: ".to_string();
        let cases = [
            ("0xFF padding", vec![0xFF; 8], None),
            ("zero bytes", vec![0x00; 4], None),
            ("a FormSet", form_set_of_guid(0xB0, &[]), None),
            ("Length 1", vec![0x29, 0x01], Some(not_fit(1))),
            ("an op without its Length", vec![0x29], Some(runs_past)),
            (
                "zero bytes, then a FormSet",
                [&[0x00, 0x00][..], &form_set_of_guid(0xB0, &[])].concat(),
                Some(not_fit(0)),
            ),
            (
                "a FormSet with a malformed CheckBox, then a FormSet",
                [
                    form_set_of_guid(0xB0, &short_checkbox),
                    form_set_of_guid(0xC0, &[]),
                ]
                .concat(),
                Some(short(b0.as_str(), "EFI_IFR_CHECKBOX")),
            ),
            (
                "a FormSet too short for its GUID, then a FormSet",
                [&[0x0E, 0x84, 0xB0, 0xB0][..], &form_set_of_guid(0xC0, &[])].concat(),
                Some(short("a FormSet", "EFI_IFR_FORM_SET")),
            ),
            (
                "a FormSet nested too deep, then a FormSet",
                [
                    form_set_of_guid(0xB0, &too_deep),
                    form_set_of_guid(0xC0, &[]),
                ]
                .concat(),
                Some(nested_too_deep.clone()),
            ),
            (
                "a FormSet open at the package end",
                without_end(form_set_of_guid(0xB0, &[])),
                Some(format!(
                    "{b0}, which does not parse; uefisettings ignores it, where UEFI 2.11 \
                     §33.2.5.10.1 disables only the form of a malformed op and ignores only a \
                     malformed forms set: failed to parse IFR operation: "
                )),
            ),
            (
                "a FormSet nested too deep, open at the package end",
                without_end(form_set_of_guid(0xB0, &too_deep)),
                Some(nested_too_deep),
            ),
            (
                "a FormSet without its Scope bit, its second form holding a PASSWORD",
                scopeless_form_set(&two_forms),
                Some(opens_no_scope(eleven)),
            ),
            (
                "a FormSet without its Scope bit holding a malformed CheckBox",
                scopeless_form_set(&[short_checkbox.to_vec()]),
                Some(short(eleven, "EFI_IFR_CHECKBOX")),
            ),
        ];
        let after_first = u64::try_from(first.len()).expect("offset");
        for (name, trailing, want) in cases {
            let list = read_form_package(&[first.as_slice(), &trailing].concat())
                .unwrap_or_else(|error| panic!("read_db after {name}: {error:#}"));
            match (list.ignored_ifr.as_slice(), want) {
                ([], None) => {}
                ([ignored], Some(want)) => {
                    assert_eq!(ignored.offset, after_first, "offset ignored after {name}");
                    assert!(
                        ignored.reason.starts_with(&want),
                        "reason after {name}: {}",
                        ignored.reason
                    );
                }
                (got, want) => panic!("IFR ignored after {name}: {got:?}, want {want:?}"),
            }
        }

        let list = read_form_package(&scopeless_form_set(&two_forms)).unwrap_or_else(|error| {
            panic!("read_db of a first FormSet without its Scope bit: {error:#}")
        });
        let ignored: Vec<(u64, &str)> = list
            .ignored_ifr
            .iter()
            .map(|ignored| (ignored.offset, ignored.reason.as_str()))
            .collect();
        assert_eq!(
            ignored,
            [(0, opens_no_scope(eleven).as_str())],
            "IFR ignored with a first FormSet without its Scope bit"
        );
    }

    /// The FormIds of the FORM and FORM_MAP ops of the first FormSet of the first root of `list`.
    fn form_ids(list: &ParsedPackageList) -> Vec<u16> {
        let Some(root) = list.forms.first() else {
            return Vec::new();
        };
        let root = root.borrow();
        let Some(form_set) = root.children.first() else {
            return Vec::new();
        };
        let form_set = form_set.borrow();
        form_set
            .children
            .iter()
            .filter_map(|op| op.borrow().form_id())
            .collect()
    }

    /// read_db disables the form of an op shorter than the minimum of its opcode or than its
    /// fields require (UEFI 2.11 §33.2.5.10.1 "the entire form is disabled"), or that
    /// uefisettings does not decode: it drops the form, a FORM_MAP's too, its ops and scopes up to
    /// its End, keeps the other forms of its FormSet, and lists the form at the offset of its FORM
    /// or FORM_MAP op, that op's own form if it fails, named by the FormId that it carries; in a
    /// FormSet that it ignores, only that FormSet is listed.
    #[test]
    fn test_read_db_disables_the_form_of_a_malformed_op() {
        // a Subtitle of prompt `id`
        let subtitle = |id: u8| [0x02, 0x07, id, 0x00, 0x00, 0x00, 0x00];
        let form = |id: u8, body: &[u8]| {
            [
                &[0x01, 0x86, id, 0x00, 0x01, 0x00][..],
                &subtitle(id),
                body,
                &END,
            ]
            .concat()
        };
        let short_checkbox = [CHECKBOX, 0x03, 0x00]; // 1 of its data bytes
        let suppress_if = |body: &[u8]| [&[0x0A, 0x82][..], body, &END].concat();
        // a Subtitle that opens a scope, with 1 of its data bytes
        let short_subtitle = |body: &[u8]| [&[0x02, 0x83, 0x00][..], body, &END].concat();
        // a Form op with 1 of its data bytes
        let short_form = |body: &[u8]| [&[0x01, 0x83, 0x02][..], &subtitle(2), body, &END].concat();
        // a Form op of FormId 2 without its FormTitle
        let titleless_form =
            |body: &[u8]| [&[0x01, 0x84, 0x02, 0x00][..], &subtitle(2), body, &END].concat();
        // a FORM_MAP of FormId 2 with one Method, of MethodTitle 0 and a nil MethodIdentifier
        let form_map = |body: &[u8]| {
            [
                &[0x5D, 0x96, 0x02, 0x00, 0x00, 0x00][..],
                &[0x00; 16],
                &subtitle(2),
                body,
                &END,
            ]
            .concat()
        };
        // a ONE_OF_OPTION of Type EFI_IFR_TYPE_BUFFER with no byte of its buffer, which
        // uefisettings reads one byte of
        let buffer_option = [0x09, 0x06, 0x00, 0x00, 0x00, 0x0B];
        // a UINT64 NUMERIC of the Length of a UINT8 one
        let numeric = [
            &[0x07, 0x11][..],
            &[
                0x02, 0x00, 0x03, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            ], // header
            &[0x03, 0x00, 0xFF, 0x01], // Flags EFI_IFR_NUMERIC_SIZE_8, then 3 bytes
        ]
        .concat();
        let at = |parts: &[&[u8]]| {
            u64::try_from(parts.iter().map(|part| part.len()).sum::<usize>()).expect("offset")
        };
        let form_set_op = &form_set_of_guid(0xA0, &[])[..39];
        let first = form(1, &[]);
        let a0 = Guid::from([0xA0; 16]);
        let disabled = format!("the form 2 of the FormSet {a0}, whose");
        let checkbox_disabled = format!("{disabled} EFI_IFR_CHECKBOX op is malformed");
        let form_op = format!("a form of the FormSet {a0}, whose EFI_IFR_FORM op");
        let third = format!("the form 3 of the FormSet {a0}, whose");
        let b0 = format!(
            "the FormSet {}, which holds, outside its forms, an op shorter than its minimum",
            Guid::from([0xB0; 16])
        );
        let malformed =
            "op is malformed; UEFI 2.11 §33.2.5.10.1 disables the form of a malformed op: ";
        let short_of_its_flags = "whose EFI_IFR_NUMERIC op is malformed; UEFI 2.11 §33.2.5.10.1 \
            disables the form of a malformed op: the EFI_IFR_NUMERIC op at offset 67 of a form \
            package is 17 bytes long, shorter than the 38 bytes required by its Flags (UEFI 2.11 \
            §33.3.8.3)";
        // a name, a form package, its FormSets by the last byte of their GUID, the forms of the
        // first by FormId, and its records by offset, the start of their reason, and what they
        // hold
        type Case<'a> = (
            &'a str,
            Vec<u8>,
            &'a [u8],
            &'a [u16],
            Vec<(u64, &'a str, &'a str)>,
        );
        let cases: [Case<'_>; 12] = [
            (
                "a malformed op in a form",
                form_set_of_guid(
                    0xA0,
                    &[first.clone(), form(2, &short_checkbox), form(3, &[])].concat(),
                ),
                &[0xA0],
                &[1, 3],
                vec![(at(&[form_set_op, &first]), &disabled, malformed)],
            ),
            (
                "a malformed op in a scope of a form",
                form_set_of_guid(
                    0xA0,
                    &[
                        first.clone(),
                        form(2, &suppress_if(&short_checkbox)),
                        form(3, &[]),
                    ]
                    .concat(),
                ),
                &[0xA0],
                &[1, 3],
                vec![(at(&[form_set_op, &first]), &disabled, malformed)],
            ),
            (
                "a malformed op after a nested scope of its form",
                form_set_of_guid(
                    0xA0,
                    &[
                        first.clone(),
                        form(
                            2,
                            &[&suppress_if(&subtitle(9))[..], &short_checkbox].concat(),
                        ),
                        form(3, &[]),
                    ]
                    .concat(),
                ),
                &[0xA0],
                &[1, 3],
                vec![(at(&[form_set_op, &first]), &checkbox_disabled, malformed)],
            ),
            (
                "a malformed op in a FORM_MAP",
                form_set_of_guid(
                    0xA0,
                    &[first.clone(), form_map(&short_checkbox), form(3, &[])].concat(),
                ),
                &[0xA0],
                &[1, 3],
                vec![(at(&[form_set_op, &first]), &checkbox_disabled, malformed)],
            ),
            (
                "a malformed op that opens a scope",
                form_set_of_guid(
                    0xA0,
                    &[
                        first.clone(),
                        form(2, &short_subtitle(&[0x0A, 0x82, 0x29, 0x02])),
                        form(3, &[]),
                    ]
                    .concat(),
                ),
                &[0xA0],
                &[1, 3],
                vec![(at(&[form_set_op, &first]), &disabled, malformed)],
            ),
            (
                "a malformed Form op",
                form_set_of_guid(
                    0xA0,
                    &[first.clone(), short_form(&[]), form(3, &[])].concat(),
                ),
                &[0xA0],
                &[1, 3],
                vec![(at(&[form_set_op, &first]), &form_op, malformed)],
            ),
            (
                "a malformed Form op that carries its FormId",
                form_set_of_guid(
                    0xA0,
                    &[first.clone(), titleless_form(&[]), form(3, &[])].concat(),
                ),
                &[0xA0],
                &[1, 3],
                vec![(at(&[form_set_op, &first]), &disabled, malformed)],
            ),
            (
                "a malformed Form op without Scope",
                form_set_of_guid(
                    0xA0,
                    &[first.clone(), vec![0x01, 0x03, 0x02], form(3, &[])].concat(),
                ),
                &[0xA0],
                &[1, 3],
                vec![(at(&[form_set_op, &first]), &form_op, malformed)],
            ),
            (
                "an op shorter than its Flags require",
                form_set_of_guid(
                    0xA0,
                    &[first.clone(), form(2, &numeric), form(3, &[])].concat(),
                ),
                &[0xA0],
                &[1, 3],
                vec![(at(&[form_set_op, &first]), &disabled, short_of_its_flags)],
            ),
            (
                "an op that uefisettings does not decode",
                form_set_of_guid(
                    0xA0,
                    &[first.clone(), form(2, &buffer_option), form(3, &[])].concat(),
                ),
                &[0xA0],
                &[1, 3],
                vec![(
                    at(&[form_set_op, &first]),
                    &disabled,
                    "EFI_IFR_ONE_OF_OPTION op uefisettings does not decode: the \
                     EFI_IFR_ONE_OF_OPTION op at offset ",
                )],
            ),
            (
                "malformed ops in 2 forms",
                form_set_of_guid(
                    0xA0,
                    &[
                        first.clone(),
                        form(2, &short_checkbox),
                        form(3, &short_checkbox),
                    ]
                    .concat(),
                ),
                &[0xA0],
                &[1],
                vec![
                    (at(&[form_set_op, &first]), &disabled, malformed),
                    (
                        at(&[form_set_op, &first, &form(2, &short_checkbox)]),
                        &third,
                        malformed,
                    ),
                ],
            ),
            (
                "a disabled form in a FormSet that read_db ignores",
                [
                    form_set_of_guid(0xA0, &[]),
                    form_set_of_guid(
                        0xB0,
                        &[form(2, &short_checkbox), short_checkbox.to_vec()].concat(),
                    ),
                    form_set_of_guid(0xC0, &[]),
                ]
                .concat(),
                &[0xA0, 0xC0],
                &[],
                vec![(
                    at(&[&form_set_of_guid(0xA0, &[])]),
                    &b0,
                    "the EFI_IFR_CHECKBOX op at offset ",
                )],
            ),
        ];
        for (name, ifr, want_roots, want_forms, want_records) in cases {
            let list =
                read_form_package(&ifr).unwrap_or_else(|error| panic!("read_db {name}: {error:#}"));
            assert_eq!(
                form_ids(&list),
                want_forms,
                "forms of the first FormSet of {name}"
            );
            let roots: Vec<u8> = form_set_guids(ifr)
                .unwrap_or_else(|error| panic!("roots of {name}: {error:#}"))
                .into_iter()
                .map(|guid| guid.expect("a root holding a FormSet"))
                .collect();
            assert_eq!(
                roots, want_roots,
                "FormSets, by the last byte of their GUID, of {name}"
            );
            let records: Vec<forms::IgnoredIfr> = list.ignored_records().collect();
            let got: Vec<(u64, bool)> = records
                .iter()
                .zip(&want_records)
                .map(|(got, (_, start, holds))| {
                    let reason = &got.reason;
                    (
                        got.offset,
                        reason.starts_with(start)
                            && reason.contains(holds)
                            && !(holds.contains("does not decode") && reason.contains('§')),
                    )
                })
                .collect();
            assert_eq!(
                (records.len(), got),
                (
                    want_records.len(),
                    want_records
                        .iter()
                        .map(|(offset, _, _)| (*offset, true))
                        .collect::<Vec<_>>()
                ),
                "records of {name} (offset, reason as expected): {records:?}"
            );
        }
    }

    /// The scopes read up to the End of a disabled form close, so more than MAX_SCOPE_NESTING
    /// disabled forms leave their FormSet a root and its next form parsed.
    #[test]
    fn test_read_db_closes_the_scopes_of_disabled_forms() {
        let form = |id: u8, body: &[u8]| {
            [
                &[0x01, 0x86, id, 0x00, 0x01, 0x00][..],
                &[0x02, 0x07, id, 0x00, 0x00, 0x00, 0x00], // Subtitle
                body,
                &END,
            ]
            .concat()
        };
        let short_checkbox = [CHECKBOX, 0x03, 0x00]; // 1 of its data bytes
        let disabled = MAX_SCOPE_NESTING + 1;
        let ifr = form_set_of_guid(
            0xA0,
            &[form(2, &short_checkbox).repeat(disabled), form(3, &[])].concat(),
        );

        let list = read_form_package(&ifr).unwrap_or_else(|error| panic!("read_db: {error:#}"));

        assert_eq!(
            form_ids(&list),
            [3],
            "forms parsed after {disabled} disabled forms"
        );
        assert_eq!(
            list.ignored_records().count(),
            disabled,
            "records after {disabled} disabled forms: {:?}",
            list.ignored_records().last()
        );
    }

    /// read_db keeps each FormSet of a form package as a root of its own. The walk for FormSets
    /// after the first skips other ops and ends, without failing the package, at an op that does
    /// not fit it, and goes on after a FormSet whose bytes do not parse or whose scopes nest deeper
    /// than MAX_SCOPE_NESTING, the first one too, which it lists as the later ones.
    #[test]
    fn test_read_db_ends_the_form_set_walk_at_an_op_that_does_not_fit() {
        let read = |ifr| {
            form_set_guids(ifr).map(|roots| {
                roots
                    .into_iter()
                    .map(|guid| guid.expect("a root holding a FormSet"))
                    .collect::<Vec<u8>>()
            })
        };
        let short_checkbox = [CHECKBOX, 0x03, 0x00]; // 1 of its data bytes
        let subtitle = [0x02, 0x07, 0x05, 0x00, 0x06, 0x00, 0x00];
        // the FormSet's own scope and these
        let too_deep = nested(&subtitle_scope(5), MAX_SCOPE_NESTING, &[]);
        let cases: [(&str, Vec<u8>, &[u8]); 10] = [
            ("0xFF padding", vec![0xFF; 8], &[0xA0]),
            ("zero bytes", vec![0x00; 4], &[0xA0]),
            ("Length 1", vec![0x29, 0x01], &[0xA0]),
            (
                "zero bytes, then a FormSet",
                [&[0x00, 0x00][..], &form_set_of_guid(0xB0, &[])].concat(),
                &[0xA0],
            ),
            ("a FormSet", form_set_of_guid(0xB0, &[]), &[0xA0, 0xB0]),
            (
                "a Subtitle, then a FormSet",
                [&subtitle[..], &form_set_of_guid(0xB0, &[])].concat(),
                &[0xA0, 0xB0],
            ),
            (
                "a FormSet with a malformed CheckBox",
                form_set_of_guid(0xB0, &short_checkbox),
                &[0xA0],
            ),
            (
                "a FormSet with a malformed CheckBox, then a FormSet",
                [
                    form_set_of_guid(0xB0, &short_checkbox),
                    form_set_of_guid(0xC0, &[]),
                ]
                .concat(),
                &[0xA0, 0xC0],
            ),
            (
                "a FormSet nested too deep",
                form_set_of_guid(0xB0, &too_deep),
                &[0xA0],
            ),
            (
                "a FormSet nested too deep, then a FormSet",
                [
                    form_set_of_guid(0xB0, &too_deep),
                    form_set_of_guid(0xC0, &[]),
                ]
                .concat(),
                &[0xA0, 0xC0],
            ),
        ];
        for (name, trailing, want) in cases {
            let got = read([form_set_of_guid(0xA0, &[]), trailing].concat())
                .unwrap_or_else(|error| panic!("read_db after {name}: {error:#}"));
            assert_eq!(
                got, want,
                "FormSets, by the last byte of their GUID, after {name}"
            );
        }

        let a0 = format!("the FormSet {}", Guid::from([0xA0; 16]));
        let first_cases = [
            (
                "a malformed first FormSet",
                form_set_of_guid(0xA0, &short_checkbox),
                format!(
                    "{a0}, which holds, outside its forms, an op shorter than its minimum, which \
                     UEFI 2.11 §33.2.5.10.1 calls malformed, in no form for that section to \
                     disable: the EFI_IFR_CHECKBOX op at offset 39 of a form package is 3 bytes \
                     long, shorter than its minimum of 14 (UEFI 2.11 §33.3.8.3)"
                ),
            ),
            (
                "a first FormSet nested too deep",
                form_set_of_guid(0xA0, &too_deep),
                format!(
                    "{a0}, which nests too deep: IFR scopes nest deeper than {MAX_SCOPE_NESTING} \
                     at offset "
                ),
            ),
        ];
        for (name, first, reason) in first_cases {
            let got = read([first.clone(), form_set_of_guid(0xB0, &[])].concat())
                .unwrap_or_else(|error| panic!("read_db after {name}: {error:#}"));
            assert_eq!(
                got,
                [0xB0],
                "FormSets, by the last byte of their GUID, after {name}"
            );
            let list = read_form_package(&first)
                .unwrap_or_else(|error| panic!("read_db of {name}: {error:#}"));
            let ignored: Vec<(u64, bool)> = list
                .ignored_ifr
                .iter()
                .map(|ignored| (ignored.offset, ignored.reason.starts_with(&reason)))
                .collect();
            assert_eq!(
                (list.forms.len(), ignored),
                (0, vec![(0, true)]),
                "roots and IFR ignored (offset, reason as expected) of {name}: {:?}",
                list.ignored_ifr
            );
        }
    }

    /// read_db reads the FormSets after one that it ignores, as GetIfrBinaryData's walk finds
    /// them op by op (UEFI 2.11 §33.2.5.10.1 ignores only a malformed forms set), a FormSet in an
    /// ignored one too, with or without its Scope bit, and lists each ignored FormSet at its
    /// offset; past an op whose Length is below the header size, which that walk loops on or
    /// steps into, or runs past the package, it reads nothing more, and lists that op, in an
    /// ignored first FormSet too, where neither the package nor the HiiDB fails.
    #[test]
    fn test_read_db_reads_the_form_sets_after_one_that_it_ignores() {
        // the FormSet's own scope and these
        let too_deep = nested(&subtitle_scope(5), MAX_SCOPE_NESTING, &[]);
        let short_checkbox = [CHECKBOX, 0x03, 0x00]; // 1 of its data bytes
        let first = form_set_of_guid(0xA0, &[]);
        let malformed = |guid| form_set_of_guid(guid, &short_checkbox);
        let open = form_set_of_guid(0xB0, &[]);
        let open = &open[..open.len() - END.len()];
        let at = |parts: &[&[u8]]| {
            u64::try_from(parts.iter().map(|part| part.len()).sum::<usize>()).expect("offset")
        };
        let form_set_op = &first[..39];
        let does_not_parse = |guid: u8| {
            format!(
                "the FormSet {}, which does not parse; uefisettings ignores it, where UEFI 2.11 \
                 §33.2.5.10.1 disables only the form of a malformed op and ignores only a \
                 malformed forms set: ",
                Guid::from([guid; 16])
            )
        };
        let short_op = |guid: u8| {
            format!(
                "the FormSet {}, which holds, outside its forms, an op shorter than its minimum, \
                 which UEFI 2.11 §33.2.5.10.1 calls malformed, in no form for that section to \
                 disable: ",
                Guid::from([guid; 16])
            )
        };
        let nests_too_deep = format!(
            "the FormSet {}, which nests too deep: IFR scopes nest deeper than {MAX_SCOPE_NESTING} \
             at offset ",
            Guid::from([0xB0; 16])
        );
        let not_fit = "an op that does not fit the form package, and the bytes after it: invalid \
                       IFR operation length 1"
            .to_string();
        let runs_past =
            "an op that does not fit the form package, and the bytes after it: ".to_string();
        let first_length_1 = form_set_of_guid(0xB0, &[0x29, 0x01]);
        // a Subtitle whose Length runs past the package, 3 of its 7 bytes
        let runs_past_end = [form_set_op, &[0x02, 0x07, 0x05]].concat();
        // a name, a form package, its FormSets by the last byte of their GUID, and its ignored
        // IFR by offset and the start of its reason
        type Case<'a> = (&'a str, Vec<u8>, &'a [u8], Vec<(u64, String)>);
        let cases: [Case<'_>; 9] = [
            (
                "a malformed FormSet, then a FormSet",
                [&first[..], &malformed(0xB0), &form_set_of_guid(0xC0, &[])].concat(),
                &[0xA0, 0xC0],
                vec![(at(&[&first]), short_op(0xB0))],
            ),
            (
                "a FormSet without its End, then a FormSet",
                [&first[..], open, &form_set_of_guid(0xC0, &[])].concat(),
                &[0xA0, 0xC0],
                vec![(at(&[&first]), does_not_parse(0xB0))],
            ),
            (
                "a malformed FormSet holding a FormSet",
                [
                    &first[..],
                    &form_set_of_guid(
                        0xB0,
                        &[&form_set_of_guid(0xC0, &[])[..], &short_checkbox].concat(),
                    ),
                ]
                .concat(),
                &[0xA0, 0xC0],
                vec![(at(&[&first]), short_op(0xB0))],
            ),
            (
                "a malformed FormSet holding, in a scope, a FormSet without its Scope bit that \
                 the End of that scope ends",
                [
                    &first[..],
                    &form_set_of_guid(
                        0xB0,
                        &[
                            &scopeless_form_set(&[subtitle_scope(5), END.to_vec()])[..],
                            &short_checkbox,
                        ]
                        .concat(),
                    ),
                ]
                .concat(),
                &[0xA0, 0x11],
                vec![
                    (at(&[&first]), short_op(0xB0)),
                    (
                        at(&[&first, form_set_op]),
                        format!("the FormSet {} opens no scope", Guid::from([0x11; 16])),
                    ),
                ],
            ),
            (
                "a FormSet nested too deep, then a FormSet",
                [
                    &first[..],
                    &form_set_of_guid(0xB0, &too_deep),
                    &form_set_of_guid(0xC0, &[]),
                ]
                .concat(),
                &[0xA0, 0xC0],
                vec![(at(&[&first]), nests_too_deep)],
            ),
            (
                "2 malformed FormSets, then a FormSet",
                [
                    &first[..],
                    &malformed(0xB0),
                    &malformed(0xC0),
                    &form_set_of_guid(0xD0, &[]),
                ]
                .concat(),
                &[0xA0, 0xD0],
                vec![
                    (at(&[&first]), short_op(0xB0)),
                    (at(&[&first, &malformed(0xB0)]), short_op(0xC0)),
                ],
            ),
            (
                "a FormSet holding an op of Length 1, then a FormSet",
                [
                    &first[..],
                    &form_set_of_guid(0xB0, &[0x29, 0x01]),
                    &form_set_of_guid(0xC0, &[]),
                ]
                .concat(),
                &[0xA0],
                vec![
                    (at(&[&first]), does_not_parse(0xB0)),
                    (at(&[&first, form_set_op]), not_fit.clone()),
                ],
            ),
            (
                "a first FormSet holding an op of Length 1, then a FormSet",
                [&first_length_1[..], &form_set_of_guid(0xC0, &[])].concat(),
                &[],
                vec![(0, does_not_parse(0xB0)), (at(&[form_set_op]), not_fit)],
            ),
            (
                "a first FormSet whose last op runs past the package",
                runs_past_end,
                &[],
                vec![(0, does_not_parse(0xA0)), (at(&[form_set_op]), runs_past)],
            ),
        ];
        for (name, ifr, want_roots, want_ignored) in cases {
            let list =
                read_form_package(&ifr).unwrap_or_else(|error| panic!("read_db {name}: {error:#}"));
            let roots: Vec<u8> = form_set_guids(ifr)
                .unwrap_or_else(|error| panic!("roots of {name}: {error:#}"))
                .into_iter()
                .map(|guid| guid.expect("a root holding a FormSet"))
                .collect();
            assert_eq!(
                roots, want_roots,
                "FormSets, by the last byte of their GUID, of {name}"
            );
            let ignored: Vec<(u64, bool)> = list
                .ignored_ifr
                .iter()
                .zip(&want_ignored)
                .map(|(got, (_, reason))| (got.offset, got.reason.starts_with(reason.as_str())))
                .collect();
            let want: Vec<(u64, bool)> = want_ignored
                .iter()
                .map(|(offset, _)| (*offset, true))
                .collect();
            assert_eq!(
                (list.ignored_ifr.len(), ignored),
                (want_ignored.len(), want),
                "IFR ignored in {name} (count; offset, reason as expected): {:?}",
                list.ignored_ifr
            );
        }

        // another package list after one whose form package is first_length_1
        let hiidb = [
            package_list_with_guid(
                [0x22; 16],
                &[form_package_of(&first_length_1), END_PACKAGE.to_vec()].concat(),
            ),
            package_list_with_guid(
                [0x33; 16],
                &[form_package_of(&first), END_PACKAGE.to_vec()].concat(),
            ),
        ]
        .concat();
        let lists =
            read_db(&hiidb).unwrap_or_else(|error| panic!("read_db of 2 package lists: {error:#}"));
        let got: Vec<(usize, usize)> = lists
            .iter()
            .map(|list| (list.forms.len(), list.ignored_ifr.len()))
            .collect();
        assert_eq!(
            got,
            [(0, 2), (1, 0)],
            "roots and IFR ignored of each package list"
        );
    }

    /// read_db parses the ops of a run of FORM_SET ops without their Scope bit, which no End
    /// ends, about once in all, not once per FORM_SET op: the parse from each of them fails at the
    /// end of the form package, as the parse from the first does, so each is listed with the
    /// failure that a parse of its own gives, without one.
    #[test]
    fn test_read_db_parses_a_run_of_form_set_ops_without_scope_once() {
        let first = form_set_of_guid(0xA0, &[]);
        let scopeless = scopeless_form_set(&[]);
        let count = 2048;
        let ifr = [first.clone(), scopeless.repeat(count)].concat();
        let before = forms::OPS_PARSED.with(Cell::get);
        let list = read_form_package(&ifr).unwrap_or_else(|error| panic!("read_db: {error:#}"));
        let parsed = forms::OPS_PARSED.with(Cell::get) - before;
        // the FormSet and End of the first FormSet, then the FORM_SET ops
        let ops = 2 + count;
        assert!(parsed <= 2 * ops, "ops parsed: {parsed}, of {ops}");
        let offsets: Vec<u64> = list
            .ignored_ifr
            .iter()
            .map(|ignored| ignored.offset)
            .collect();
        let want: Vec<u64> = (0..count)
            .map(|index| u64::try_from(first.len() + index * scopeless.len()).expect("offset"))
            .collect();
        assert_eq!(offsets, want, "offsets of the IFR ignored");
        let eleven = "the FormSet 11111111-1111-1111-1111-111111111111, which does not parse";
        for ignored in [0, count / 2, count - 1].map(|index| &list.ignored_ifr[index]) {
            let mut cursor = Cursor::new(&ifr);
            cursor.set_position(ignored.offset);
            let error = forms::handle_form_set(&mut cursor)
                .expect_err("a FormSet that the end of the package ends");
            assert!(
                ignored.reason.starts_with(eleven)
                    && ignored.reason.ends_with(&format!("{error:#}")),
                "reason at {}: {}, its own parse: {error:#}",
                ignored.offset,
                ignored.reason
            );
        }
    }

    /// read_db reads a FormSet wherever edk2-stable202608 SetupBrowserDxe/Setup.c GetIfrBinaryData
    /// finds one outside another FormSet, walking the form package op by op, scopes unread: in the
    /// scope of an unknown op too.
    #[test]
    fn test_read_db_reads_a_form_set_in_an_unknown_scope() {
        let unknown = [0x70, 0x80 | 2]; // Length, Scope
        let cases: [(&str, Vec<u8>); 2] = [
            (
                "a FormSet in an unknown op's scope",
                [&unknown[..], &form_set_of_guid(0xB0, &[]), &END].concat(),
            ),
            (
                "an unknown op's scope, then a FormSet",
                [&unknown[..], &END, &form_set_of_guid(0xB0, &[])].concat(),
            ),
        ];
        for (name, ifr) in cases {
            let roots = form_set_guids(ifr).unwrap_or_else(|error| panic!("{name}: {error:#}"));
            assert_eq!(roots, [Some(0xB0)], "roots of {name}");
        }
    }

    /// read_db skips the ops that the walk for FormSets steps over before the first FormSet.
    #[test]
    fn test_read_db_skips_ops_before_the_first_form_set() {
        let subtitle = [0x02, 0x07, 0x05, 0x00, 0x06, 0x00, 0x00];
        let subtitle_scope = [0x02, 0x80 | 0x07, 0x05, 0x00, 0x06, 0x00, 0x00];
        let cases: [(&str, Vec<u8>); 3] = [
            ("a Subtitle", subtitle.to_vec()),
            ("a Subtitle's scope", [&subtitle_scope[..], &END].concat()),
            ("an unknown op", vec![0x70, 0x02]),
        ];
        for (name, before) in cases {
            let ifr = [before, form_set_of_guid(0xB0, &[])].concat();
            let roots = form_set_guids(ifr).unwrap_or_else(|error| panic!("{name}: {error:#}"));
            assert_eq!(roots, [Some(0xB0)], "roots after {name}");
        }
    }

    /// read_db ends the walk for FormSets at an op that does not fit it before the walk reads a
    /// FORM_SET op too, and lists the IFR from that op, without failing the package.
    #[test]
    fn test_read_db_ignores_an_op_that_does_not_fit_before_the_first_form_set() {
        let cases: [(&str, Vec<u8>, u64, &str); 5] = [
            (
                "Length 1, then a FormSet",
                [&[0x02, 0x01][..], &form_set_of_guid(0xB0, &[])].concat(),
                0,
                "invalid IFR operation length 1",
            ),
            (
                "a Subtitle, then Length 1, then a FormSet",
                [
                    &[0x02, 0x07, 0x05, 0x00, 0x06, 0x00, 0x00][..],
                    &[0x02, 0x01],
                    &form_set_of_guid(0xB0, &[]),
                ]
                .concat(),
                7,
                "invalid IFR operation length 1",
            ),
            (
                "zero bytes, then a FormSet",
                [&[0x00, 0x00][..], &form_set_of_guid(0xB0, &[])].concat(),
                0,
                "invalid IFR operation length 0",
            ),
            (
                "a Subtitle without its last data byte",
                vec![0x02, 0x07, 0x05, 0x00, 0x06, 0x00],
                0,
                "not enough bytes in reader",
            ),
            ("an End op without its Length", vec![0x29], 0, ""),
        ];
        for (name, ifr, offset, cause) in cases {
            let list = read_form_package(&ifr)
                .unwrap_or_else(|error| panic!("read_db of {name}: {error:#}"));
            let ignored: Vec<(u64, bool)> = list
                .ignored_ifr
                .iter()
                .map(|ignored| {
                    let reason = &ignored.reason;
                    let want = "an op that does not fit the form package, and the bytes after it: ";
                    (
                        ignored.offset,
                        reason.starts_with(want) && reason.contains(cause),
                    )
                })
                .collect();
            assert_eq!(
                (list.forms.len(), ignored),
                (0, vec![(offset, true)]),
                "roots and IFR ignored (offset, reason as expected) of {name}: {:?}",
                list.ignored_ifr
            );
        }
    }

    /// read_db keeps a FormSet inside another FormSet part of it, and walks on after the outer
    /// FormSet's End.
    #[test]
    fn test_read_db_keeps_a_form_set_inside_another_part_of_it() {
        let inner = form_set_of_guid(0xB0, &[]);
        let ifr = [form_set_of_guid(0xA0, &inner), form_set_of_guid(0xC0, &[])].concat();
        let roots = form_set_guids(ifr).expect("read nested FormSets");
        assert_eq!(
            roots,
            [Some(0xA0), Some(0xC0)],
            "roots of a FormSet holding a FormSet, then a FormSet"
        );
    }

    /// read_db reads no root from a form package without a FORM_SET op, as GetIfrBinaryData finds
    /// no FormSet there, and one root from a form package holding one.
    #[test]
    fn test_read_db_reads_no_root_without_a_form_set() {
        let cases: [(&str, Vec<u8>); 3] = [
            ("an End", END.to_vec()),
            ("a Subtitle", vec![0x02, 0x07, 0x05, 0x00, 0x06, 0x00, 0x00]),
            ("an unknown op's scope", vec![0x70, 0x80 | 2, 0x29, 0x02]),
        ];
        for (name, ifr) in cases {
            let roots = form_set_guids(ifr).unwrap_or_else(|error| panic!("{name}: {error:#}"));
            assert!(roots.is_empty(), "roots of {name}: {roots:?}");
        }
        let roots = form_set_guids(form_set_of_guid(0xB0, &[])).expect("read a FormSet");
        assert_eq!(roots, [Some(0xB0)], "roots of a FormSet");
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
                err.downcast_ref::<ParseError>()
                    .is_some_and(ParseError::is_eof),
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
                vec![StringMap::from([(1, "A".into())])],
            ),
            ("22222222-2222-2222-2222-222222222222".to_string(), vec![]),
            (
                "33333333-3333-3333-3333-333333333333".to_string(),
                vec![StringMap::from([(1, "B".into())])],
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
                err.downcast_ref::<ParseError>()
                    .expect("a ParseError")
                    .is_eof(),
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
                vec![StringMap::from([(1, "A".into())])],
            ),
            ("22222222-2222-2222-2222-222222222222".to_string(), vec![]),
            (
                "33333333-3333-3333-3333-333333333333".to_string(),
                vec![StringMap::from([(1, "B".into())])],
            ),
        ];
        assert_eq!(strings_of_lists(lists), want, "strings of the lists");
    }

    /// read_db keeps the Language of each strings package's header, in package order.
    #[test]
    fn test_read_db_keeps_each_strings_package_language() {
        // out of sorted order: the languages keep the packages' order
        let packages = [
            strings_package_of(b"x-UEFI-ns", &["iSCSIBootEnable"]),
            strings_package_of(b"en-US", &["My Keyword Namespace Test"]),
            END_PACKAGE.to_vec(),
        ]
        .concat();
        let hiidb = package_list_with_guid([0x11; 16], &packages);

        let lists = read_db(&hiidb).expect("read the HiiDB");

        let [list] = lists.as_slice() else {
            panic!("{} package lists, not 1", lists.len());
        };
        let languages: Vec<&strings::Language> = list
            .strings
            .iter()
            .map(|package| &package.language)
            .collect();
        assert_eq!(
            languages,
            ["x-UEFI-ns", "en-US"].map(language).each_ref(),
            "languages of the strings packages"
        );
        let want = ["iSCSIBootEnable", "My Keyword Namespace Test"]
            .map(|string| StringMap::from([(1, string.into())]));
        assert_eq!(
            maps_of(&list.strings),
            want,
            "strings of the strings packages"
        );
    }

    /// read_db reads a strings package whose Language is not ASCII, keeping its bytes and
    /// strings: only list_strings, which shows the Language, refuses it.
    #[test]
    fn test_read_db_reads_a_language_that_is_not_ascii() {
        let packages = [strings_package_of(b"en-\xe9", &["A"]), END_PACKAGE.to_vec()].concat();
        let hiidb = package_list_with_guid([0x22; 16], &packages);

        let lists = read_db(&hiidb).expect("read the HiiDB");

        let [list] = lists.as_slice() else {
            panic!("{} package lists, not 1", lists.len());
        };
        let want = [strings::StringPackage {
            language: strings::Language(b"en-\xe9".to_vec()),
            strings: StringMap::from([(1, "A".into())]),
        }];
        assert_eq!(list.strings, want, "the strings packages");
    }

    /// STRING_A_BLOCKS are the string blocks of string ID 1, "A": EFI_HII_SIBT_STRING_UCS2, then
    /// EFI_HII_SIBT_END.
    const STRING_A_BLOCKS: [u8; 6] = [0x14, b'A', 0x00, 0x00, 0x00, 0x00];

    /// The strings that STRING_A_BLOCKS hold.
    fn string_a() -> StringMap {
        StringMap::from([(1, "A".into())])
    }

    /// The Language `language` of a strings package header.
    fn language(language: &str) -> strings::Language {
        strings::Language(language.as_bytes().to_vec())
    }

    /// The Language and strings of each strings package that read_db reads from one package
    /// list of `packages` and the End package.
    fn strings_packages_of(packages: &[Vec<u8>]) -> Vec<(strings::Language, StringMap)> {
        let hiidb = package_list_with_guid(
            [0x22; 16],
            &[packages.concat(), END_PACKAGE.to_vec()].concat(),
        );
        let lists = read_db(&hiidb).expect("read the HiiDB");
        let [list] = lists.as_slice() else {
            panic!("{} package lists, not 1", lists.len());
        };
        list.strings
            .iter()
            .map(|package| (package.language.clone(), package.strings.clone()))
            .collect()
    }

    /// read_db's error, as it renders, for one package list 22..22 of `package` and the End
    /// package; panics if read_db parses the list.
    fn strings_package_refusal(package: Vec<u8>) -> String {
        let hiidb = package_list_with_guid([0x22; 16], &[package, END_PACKAGE.to_vec()].concat());
        match read_db(&hiidb) {
            Ok(lists) => panic!(
                "read_db parsed it: {:?}",
                lists.iter().map(|list| &list.strings).collect::<Vec<_>>()
            ),
            Err(err) => format!("{err:#}"),
        }
    }

    /// The error that strings_package_refusal returns when the header of the strings package is
    /// refused for `refusal`.
    fn strings_header_refusal(refusal: &str) -> String {
        format!(
            "failed to parse package list 22222222-2222-2222-2222-222222222222: \
             failed to parse a strings package: {refusal} (UEFI 2.11 §33.3.6.1)"
        )
    }

    /// The error that strings_package_refusal returns when a string block of the strings package
    /// is refused for `refusal`.
    fn strings_block_refusal(refusal: &str) -> String {
        format!(
            "failed to parse package list 22222222-2222-2222-2222-222222222222: \
             failed to parse a strings package: {refusal}"
        )
    }

    /// read_db reads a strings package whose header holds padding after Language's null
    /// terminator, covered by HdrSize and StringInfoOffset: whatever the padding's bytes, the
    /// strings start at StringInfoOffset.
    #[test]
    fn test_read_db_reads_strings_after_header_padding() {
        for padding in [[0x00; 3], [0xAA; 3]] {
            let package = strings_package_with_header(
                &[&b"en\0"[..], &padding].concat(),
                &[],
                &STRING_A_BLOCKS,
            );

            assert_eq!(
                strings_packages_of(&[package]),
                [(language("en"), string_a())],
                "padding {padding:02x?}"
            );
        }
    }

    /// read_db reads the strings at StringInfoOffset when it points past HdrSize, not at HdrSize.
    #[test]
    fn test_read_db_reads_strings_at_string_info_offset_past_hdr_size() {
        // 0xAA is no string block type (UEFI 2.11 §33.3.6.2)
        let package = strings_package_with_header(b"en\0", &[0xAA; 4], &STRING_A_BLOCKS);

        assert_eq!(
            strings_packages_of(&[package]),
            [(language("en"), string_a())]
        );
    }

    /// read_db reads a strings package whose HdrSize, 47, holds only the fixed header and
    /// Language's null terminator: an empty Language.
    #[test]
    fn test_read_db_reads_the_shortest_strings_package_header() {
        let package = strings_package_with_header(b"\0", &[], &STRING_A_BLOCKS);

        assert_eq!(
            strings_packages_of(&[package]),
            [(language(""), string_a())]
        );
    }

    /// read_db reads string information of one EFI_HII_SIBT_END block, the last byte of the
    /// package, as no strings.
    #[test]
    fn test_read_db_reads_string_information_of_only_an_end_block() {
        let package = strings_package_with_header(b"en\0\xAA\xAA\xAA", &[], &[0x00]);
        let length = u32::from_le_bytes([package[0], package[1], package[2], 0]);
        let string_info_offset = u32::from_le_bytes(
            package[8..12]
                .try_into()
                .expect("StringInfoOffset is 4 bytes"),
        );
        assert_eq!(string_info_offset, length - 1, "StringInfoOffset");

        assert_eq!(
            strings_packages_of(&[package]),
            [(language("en"), StringMap::new())]
        );
    }

    /// read_db reads each strings package of a list by its own header: a padded one and one
    /// whose strings follow Language's null terminator, as edk2's tools write them.
    #[test]
    fn test_read_db_reads_a_padded_and_an_edk2_shaped_strings_package_of_one_list() {
        let packages = [
            strings_package_with_header(b"en\0\xAA\xAA\xAA", &[], &STRING_A_BLOCKS),
            strings_package_of(b"fr", &["B"]),
        ];

        assert_eq!(
            strings_packages_of(&packages),
            [
                (language("en"), string_a()),
                (language("fr"), StringMap::from([(1, "B".into())])),
            ]
        );
    }

    /// read_db refuses a strings package whose HdrSize leaves no room for the fixed header and
    /// Language's null terminator, or runs past the package.
    #[test]
    fn test_read_db_refuses_a_hdr_size_outside_the_package() {
        // Language "en", then the blocks of "A" from offset 49
        let rest = [&b"en\0"[..], &STRING_A_BLOCKS].concat();
        let length = STRINGS_LANGUAGE_OFFSET
            + u32::try_from(rest.len()).expect("the fixture's lengths fit a u32");
        let below = |hdr_size: u32| {
            format!(
                "HdrSize {hdr_size} is below the 47 bytes of the fixed header and Language's null \
                 terminator"
            )
        };
        let past =
            |hdr_size: u32| format!("HdrSize {hdr_size} runs past the package Length {length}");
        let cases = [
            (0, below(0)),
            (STRINGS_LANGUAGE_OFFSET, below(STRINGS_LANGUAGE_OFFSET)),
            (length + 1, past(length + 1)),
            (u32::MAX, past(u32::MAX)),
        ];
        for (hdr_size, refusal) in cases {
            let package =
                strings_package_with_offsets(hdr_size, STRINGS_LANGUAGE_OFFSET + 3, &rest);

            assert_eq!(
                strings_package_refusal(package),
                strings_header_refusal(&refusal),
                "HdrSize {hdr_size}"
            );
        }
    }

    /// read_db refuses a strings package whose Language has no null terminator before HdrSize,
    /// including one whose only null terminator is the first byte of the string blocks.
    #[test]
    fn test_read_db_refuses_a_language_unterminated_within_hdr_size() {
        let cases: [(&str, &[u8]); 2] = [
            ("the blocks of \"A\"", &STRING_A_BLOCKS),
            ("an EFI_HII_SIBT_END block", &[0x00]),
        ];
        for (case, blocks) in cases {
            // HdrSize 48 ends after "en"
            let package = strings_package_with_header(b"en", &[], blocks);

            assert_eq!(
                strings_package_refusal(package),
                strings_header_refusal("Language has no null terminator within HdrSize 48"),
                "\"en\", then {case}"
            );
        }
    }

    /// read_db refuses a strings package whose StringInfoOffset points into its header or
    /// outside it.
    #[test]
    fn test_read_db_refuses_a_string_info_offset_outside_the_string_information() {
        // Language "en" and 3 bytes of padding make HdrSize 52, then the blocks of "A"
        let rest = [&b"en\0\xAA\xAA\xAA"[..], &STRING_A_BLOCKS].concat();
        let length = STRINGS_LANGUAGE_OFFSET
            + u32::try_from(rest.len()).expect("the fixture's lengths fit a u32");
        let outside = |string_info_offset: u32| {
            format!("StringInfoOffset {string_info_offset} is outside the package Length {length}")
        };
        let cases = [
            (
                51,
                "StringInfoOffset 51 is inside the 52-byte header".to_string(),
            ),
            (length, outside(length)),
            (u32::MAX, outside(u32::MAX)),
        ];
        for (string_info_offset, refusal) in cases {
            let package = strings_package_with_offsets(52, string_info_offset, &rest);

            assert_eq!(
                strings_package_refusal(package),
                strings_header_refusal(&refusal),
                "StringInfoOffset {string_info_offset}"
            );
        }
    }

    /// read_db checks a strings package header in order: HdrSize against the fixed header, then
    /// against the package, then Language, then StringInfoOffset, and names the first field
    /// that fails.
    #[test]
    fn test_read_db_checks_the_strings_package_header_in_order() {
        let terminated = [&b"en\0"[..], &STRING_A_BLOCKS].concat();
        let unterminated = [&b"en"[..], &STRING_A_BLOCKS].concat();
        let length = STRINGS_LANGUAGE_OFFSET
            + u32::try_from(terminated.len()).expect("the fixture's lengths fit a u32");
        let cases = [
            (
                (STRINGS_LANGUAGE_OFFSET, u32::MAX, &terminated),
                "HdrSize 46 is below the 47 bytes of the fixed header and Language's null \
                 terminator"
                    .to_string(),
            ),
            (
                (length + 1, 0, &terminated),
                format!(
                    "HdrSize {} runs past the package Length {length}",
                    length + 1
                ),
            ),
            // a HdrSize of the whole package holds Language's null terminator
            (
                (length, length, &terminated),
                format!("StringInfoOffset {length} is outside the package Length {length}"),
            ),
            (
                (48, 47, &unterminated),
                "Language has no null terminator within HdrSize 48".to_string(),
            ),
            // Language's check comes before StringInfoOffset's against Length
            (
                (48, length, &unterminated),
                "Language has no null terminator within HdrSize 48".to_string(),
            ),
        ];
        for ((hdr_size, string_info_offset, rest), refusal) in cases {
            let package = strings_package_with_offsets(hdr_size, string_info_offset, rest);

            assert_eq!(
                strings_package_refusal(package),
                strings_header_refusal(&refusal),
                "HdrSize {hdr_size}, StringInfoOffset {string_info_offset}"
            );
        }

        // HdrSize's check against the fixed header comes before its check against Length: in
        // a package of Length 14, HdrSize 20 fails both
        let short = [
            &strings_package_header(14)[..],
            &20u32.to_le_bytes(),
            &0u32.to_le_bytes(),
            &[0x00; 2],
        ]
        .concat();
        assert_eq!(
            strings_package_refusal(short),
            strings_header_refusal(
                "HdrSize 20 is below the 47 bytes of the fixed header and Language's null \
                 terminator"
            ),
            "HdrSize 20 in a package of Length 14"
        );
    }

    /// read_db refuses a strings package too short for HdrSize and StringInfoOffset, keeping
    /// binrw's error as the cause.
    #[test]
    fn test_read_db_refuses_a_strings_package_too_short_for_its_offsets() {
        // HdrSize and 1 of the 4 bytes of StringInfoOffset
        let data = [0x31, 0x00, 0x00, 0x00, 0x31];
        let length = PACKAGE_HEADER_SIZE
            + u32::try_from(data.len()).expect("the fixture's lengths fit a u32");
        let package = [&strings_package_header(length)[..], &data].concat();
        let hiidb = package_list_with_guid([0x22; 16], &[package, END_PACKAGE.to_vec()].concat());

        let Err(err) = read_db(&hiidb) else {
            panic!("read_db parsed a strings package of {} bytes", length);
        };

        let msg = format!("{err:#}");
        let want = "failed to parse package list 22222222-2222-2222-2222-222222222222: \
                    failed to parse a strings package: failed to parse string package header: ";
        assert!(msg.starts_with(want), "{msg}");
        assert!(
            err.chain().any(|cause| cause.is::<ParseError>()),
            "the cause is kept: {msg}"
        );
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
                vec![StringMap::from([(1, "A".into())])],
            ),
            (
                "11111111-1111-1111-1111-111111111111".to_string(),
                vec![StringMap::from([(1, "C".into())])],
            ),
            (
                "33333333-3333-3333-3333-333333333333".to_string(),
                vec![StringMap::from([(1, "B".into())])],
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
                    &form_set_package()[..],
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
            .map(|list| (list.forms.len(), maps_of(&list.strings)))
            .collect();
        let want = vec![
            (1, vec![StringMap::from([(1, "A".into())])]),
            (0, vec![StringMap::from([(1, "B".into())])]),
        ];
        assert_eq!(got, want, "forms stay with the strings of their list");
    }

    /// check_form_strings fails only for a list with forms but no strings
    /// packages.
    #[test]
    fn test_check_form_strings_fails_for_forms_without_strings() {
        let forms_only = [&form_set_package()[..], &END_PACKAGE].concat();
        let both = [
            &form_set_package()[..],
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
            // EFI_HII_SIBT_STRING_UCS2 "A", then no EFI_HII_SIBT_END
            (
                &[0x14, b'A', 0x00, 0x00, 0x00],
                "failed to read a string block type",
            ),
            // EFI_HII_SIBT_STRING_UCS2 "A" without its null terminator
            (
                &[0x14, b'A', 0x00],
                "the StringText of an EFI_HII_SIBT_STRING_UCS2 block has no null terminator",
            ),
            // EFI_HII_SIBT_SKIP2 with 1 of the 2 bytes of its count
            (
                &[0x21, 0x05],
                "failed to read the SkipCount of an EFI_HII_SIBT_SKIP2 block",
            ),
            // EFI_HII_SIBT_SKIP1 without its count
            (
                &[0x22],
                "failed to read the SkipCount of an EFI_HII_SIBT_SKIP1 block",
            ),
        ];
        for (blocks, read) in cases {
            let package = en_strings_package_with_blocks(blocks);
            let hiidb =
                package_list_with_guid([0x22; 16], &[package, END_PACKAGE.to_vec()].concat());

            let Err(err) = read_db(&hiidb) else {
                panic!("read_db parsed the string blocks {blocks:02x?}");
            };

            // the blocks are read without binrw, so no ParseError joins the chain: the text is
            // the whole error, on one line
            assert_eq!(
                format!("{err:#}"),
                format!(
                    "failed to parse package list 22222222-2222-2222-2222-222222222222: \
                     failed to parse a strings package: {read}"
                ),
                "blocks {blocks:02x?}"
            );
        }
    }

    /// The record of an op without data bytes, of each opcode that handle_opcode decodes, names
    /// the op, its Length and its minimum (UEFI 2.11 §33.2.5.10.1): that of its FormSet, or of its
    /// form for a FORM op.
    #[test]
    fn test_read_db_names_an_op_without_data_and_its_minimum() {
        let ops = [
            (0x01, "EFI_IFR_FORM", 6),
            (0x02, "EFI_IFR_SUBTITLE", 7),
            (0x03, "EFI_IFR_TEXT", 8),
            (0x05, "EFI_IFR_ONE_OF", 17),
            (0x06, "EFI_IFR_CHECKBOX", 14),
            (0x07, "EFI_IFR_NUMERIC", 17),
            (0x09, "EFI_IFR_ONE_OF_OPTION", 6),
            (0x0E, "EFI_IFR_FORM_SET", 23),
            (0x12, "EFI_IFR_EQ_ID_VAL", 6),
            (0x13, "EFI_IFR_EQ_ID_ID", 6),
            (0x14, "EFI_IFR_EQ_ID_VAL_LIST", 6),
            (0x24, "EFI_IFR_VARSTORE", 23),
            (0x25, "EFI_IFR_VARSTORE_NAME_VALUE", 20),
            (0x26, "EFI_IFR_VARSTORE_EFI", 24),
            (0x40, "EFI_IFR_QUESTION_REF1", 4),
            (0x5B, "EFI_IFR_DEFAULT", 5),
            (0x5C, "EFI_IFR_DEFAULTSTORE", 6),
        ];
        // after the FORM_SET op
        let at = form_set(&[]).len() - END.len();
        for (op_code, name, minimum) in ops {
            // in a FormSet, an op of Length 2: none of its data bytes
            let form_package = form_package(&[vec![op_code, 0x02]]);
            let hiidb = package_list_with_guid([0x22; 16], &form_package);

            let lists = read_db(&hiidb)
                .unwrap_or_else(|error| panic!("read_db of a {name} op without data: {error:#}"));

            let at_op = u64::try_from(at).expect("offset");
            let want_offsets: &[u64] = match op_code {
                0x01 => &[at_op],
                // the walk goes on from the op after the ignored FormSet's FORM_SET op
                0x0E => &[0, at_op],
                _ => &[0],
            };
            let want = format!(
                "the {name} op at offset {at} of a form package is 2 bytes long, shorter than its \
                 minimum of {minimum} (UEFI 2.11 §33.3.8.3)"
            );
            let records: Vec<(u64, bool)> = lists
                .iter()
                .flat_map(ParsedPackageList::ignored_records)
                .map(|record| (record.offset, record.reason.ends_with(&want)))
                .collect();
            let want_records: Vec<(u64, bool)> =
                want_offsets.iter().map(|&offset| (offset, true)).collect();
            assert_eq!(records, want_records, "{name}: {want}");
        }
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
                .strings
                .get(&8)
                .unwrap()
                .as_ref(),
            "MMIO Low Base"
        );

        // compare number of strings in the 0 indexed (1st) package of given package list
        assert_eq!(
            list_with_guid(&res, "ABBCE13D-E25A-4D9F-A1F9-2F7710786892")
                .strings
                .first()
                .unwrap()
                .strings
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

    /// PciRoot(0), then the End of Hardware Device Path node.
    const PCI_ROOT_DEVICE_PATH: [u8; 16] = [
        // ACPI PNP0A03, UID 0
        0x02, 0x01, 0x0C, 0x00, 0xD0, 0x41, 0x03, 0x0A, 0x00, 0x00, 0x00, 0x00,
        // End of Hardware Device Path
        0x7F, 0xFF, 0x04, 0x00,
    ];

    /// read_db keeps the bytes of a list's device path package beside its strings, and no
    /// device path for a list without one.
    #[test]
    fn test_read_db_keeps_the_device_path_package() {
        let with_path = [
            device_path_package(&PCI_ROOT_DEVICE_PATH),
            en_strings_package(b'A'),
            END_PACKAGE.to_vec(),
        ]
        .concat();
        let hiidb = [package_list(&with_path), en_strings_list([0x22; 16], b'B')].concat();

        let lists = read_db(&hiidb).expect("read the HiiDB");

        let got: Vec<_> = lists
            .iter()
            .map(|list| (list.device_path.clone(), maps_of(&list.strings)))
            .collect();
        assert_eq!(
            got,
            [
                (
                    Some(DevicePath::from(PCI_ROOT_DEVICE_PATH.to_vec())),
                    vec![StringMap::from([(1, "A".into())])]
                ),
                (None, vec![StringMap::from([(1, "B".into())])]),
            ],
            "lists with and without a device path package"
        );
    }

    /// read_db refuses a list with two device path packages, as NewPackageList creates one.
    #[test]
    fn test_read_db_refuses_a_second_device_path_package() {
        let path = device_path_package(&PCI_ROOT_DEVICE_PATH);
        let hiidb = package_list(&[path.clone(), path, END_PACKAGE.to_vec()].concat());

        let Err(err) = read_db(&hiidb) else {
            panic!("read_db accepted two device path packages");
        };

        assert!(
            format!("{err:#}").contains("a second device path package"),
            "two device path packages: {err:#}"
        );
    }

    /// read_db reads string ID 65535, the last EFI_STRING_ID (a UINT16, UEFI 2.11 §33.3.8.2.1),
    /// and a StringIdCurrent of 65536 that no block assigns; it refuses a string block that assigns
    /// a string ID past 65535 and a skip that takes StringIdCurrent past 65536 (§33.3.6.2).
    #[test]
    fn test_read_db_keeps_string_identifiers_within_a_uint16() {
        // EFI_HII_SIBT_SKIP2 of 0xFFFE and of 0xFFFF: StringIdCurrent 65535 and 65536
        let (to_65535, to_65536) = ([0x21, 0xFE, 0xFF], [0x21, 0xFF, 0xFF]);
        let ucs2_a = [0x14, b'A', 0x00, 0x00, 0x00];
        let past_65536 = "StringIdCurrent 65537 runs past 65536, one past the last string \
                          identifier 65535 (UEFI 2.11 §33.3.6.2, §33.3.8.2.1)";
        let read: [(&str, [&[u8]; 2], StringMap); 2] = [
            (
                "EFI_HII_SIBT_STRING_UCS2 at 65535",
                [&to_65535, &ucs2_a],
                StringMap::from([(65535, "A".into())]),
            ),
            (
                "EFI_HII_SIBT_SKIP1 to 65536",
                [&to_65535, &[0x22, 0x01]],
                StringMap::new(),
            ),
        ];
        let refused: [(&str, [&[u8]; 2], &str); 3] = [
            (
                "EFI_HII_SIBT_STRING_UCS2 at 65536",
                [&to_65536, &ucs2_a],
                "string identifier 65536 is past the last string identifier 65535 \
                 (UEFI 2.11 §33.3.8.2.1)",
            ),
            (
                "EFI_HII_SIBT_SKIP2 to 65537",
                [&to_65536, &[0x21, 0x01, 0x00]],
                past_65536,
            ),
            (
                "EFI_HII_SIBT_SKIP1 to 65537",
                [&to_65536, &[0x22, 0x01]],
                past_65536,
            ),
        ];
        for (case, [to, block], strings) in read {
            let package = en_strings_package_with_blocks(&[to, block, &[0x00]].concat());

            assert_eq!(
                strings_packages_of(&[package]),
                [(language("en"), strings)],
                "{case}"
            );
        }
        for (case, [to, block], refusal) in refused {
            let package = en_strings_package_with_blocks(&[to, block, &[0x00]].concat());

            assert_eq!(
                strings_package_refusal(package),
                strings_block_refusal(refusal),
                "{case}"
            );
        }
    }

    /// FONT_1 is an EFI_HII_SIBT_EXT2 block of BlockType2 EFI_HII_SIBT_FONT (UEFI 2.11
    /// §33.3.6.2.4): FontId 1, FontSize 16, FontStyle 0, FontName "F".
    const FONT_1: [u8; 15] = [
        0x31, 0x40, 0x0F, 0x00, 0x01, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, b'F', 0x00, 0x00, 0x00,
    ];

    /// FONT_1 with FontId `font_id`.
    fn font_block(font_id: u8) -> Vec<u8> {
        [&FONT_1[..4], &[font_id], &FONT_1[5..]].concat()
    }

    /// read_db reads every string block type of UEFI 2.11 §33.3.6.2 in one strings package:
    /// each string block assigns StringIdCurrent, DUPLICATE copies an earlier string, the skips
    /// leave IDs without strings, and the EXT1, EXT2 and EXT4 blocks of other BlockType2s are
    /// skipped by their Length. The fonts of the _FONT blocks are not shown.
    #[test]
    fn test_read_db_reads_every_string_block_type() {
        let blocks = [
            &FONT_1[..],
            // EFI_HII_SIBT_STRING_SCSU "A": 1
            &[0x10, b'A', 0x00],
            // EFI_HII_SIBT_STRING_SCSU_FONT of font 1 "B": 2
            &[0x11, 0x01, b'B', 0x00],
            // EFI_HII_SIBT_STRINGS_SCSU "C", "D": 3, 4
            &[0x12, 0x02, 0x00, b'C', 0x00, b'D', 0x00],
            // EFI_HII_SIBT_STRINGS_SCSU_FONT of font 0 "E": 5
            &[0x13, 0x00, 0x01, 0x00, b'E', 0x00],
            // EFI_HII_SIBT_STRING_UCS2 "F": 6
            &[0x14, b'F', 0x00, 0x00, 0x00],
            // EFI_HII_SIBT_STRING_UCS2_FONT of font 1 "G": 7
            &[0x15, 0x01, b'G', 0x00, 0x00, 0x00],
            // EFI_HII_SIBT_STRINGS_UCS2 "H", "I": 8, 9
            &[
                0x16, 0x02, 0x00, b'H', 0x00, 0x00, 0x00, b'I', 0x00, 0x00, 0x00,
            ],
            // EFI_HII_SIBT_STRINGS_UCS2_FONT of font 1 "J": 10
            &[0x17, 0x01, 0x01, 0x00, b'J', 0x00, 0x00, 0x00],
            // EFI_HII_SIBT_DUPLICATE of 6: 11
            &[0x20, 0x06, 0x00],
            // EFI_HII_SIBT_SKIP2 of 2, then EFI_HII_SIBT_SKIP1 of 1: 12-14
            &[0x21, 0x02, 0x00, 0x22, 0x01],
            // EFI_HII_SIBT_EXT1 of BlockType2 0x7E and Length 5
            &[0x30, 0x7E, 0x05, 0xAA, 0xBB],
            // EFI_HII_SIBT_EXT2 of BlockType2 0x7E and Length 4
            &[0x31, 0x7E, 0x04, 0x00],
            // EFI_HII_SIBT_EXT4 of BlockType2 0x41 and Length 7
            &[0x32, 0x41, 0x07, 0x00, 0x00, 0x00, 0xCC],
            // EFI_HII_SIBT_EXT1 of BlockType2 EFI_HII_SIBT_FONT, which only EXT2 carries
            &[0x30, 0x40, 0x03],
            // EFI_HII_SIBT_STRING_UCS2 "K": 15, then EFI_HII_SIBT_END
            &[0x14, b'K', 0x00, 0x00, 0x00, 0x00],
        ]
        .concat();

        let got = strings_packages_of(&[en_strings_package_with_window(
            &EDK2_LANGUAGE_WINDOW,
            &blocks,
        )]);

        let want = StringMap::from(
            [
                (1, "A"),
                (2, "B"),
                (3, "C"),
                (4, "D"),
                (5, "E"),
                (6, "F"),
                (7, "G"),
                (8, "H"),
                (9, "I"),
                (10, "J"),
                (11, "F"),
                (15, "K"),
            ]
            .map(|(id, string)| (id, string.into())),
        );
        assert_eq!(got, [(language("en"), want)], "strings of every block type");
    }

    /// read_db decodes each SCSU string of an EFI_HII_SIBT_STRINGS_SCSU block from the
    /// LanguageWindow, whatever windows the string before changed (UEFI 2.11 §33.3.6.1).
    #[test]
    fn test_read_db_restarts_each_scsu_string_from_the_language_window() {
        // 3 strings: SC5 0x82, SD0 0xFD (0x3040) 0x82, then 0x82 in dynamic window 0 at 0x0080
        let blocks = [
            0x12, 0x03, 0x00, 0x15, 0x82, 0x00, 0x18, 0xFD, 0x82, 0x00, 0x82, 0x00, 0x00,
        ];

        let got = strings_packages_of(&[en_strings_package_with_window(
            &EDK2_LANGUAGE_WINDOW,
            &blocks,
        )]);

        let want = StringMap::from(
            [(1, "\u{3042}"), (2, "\u{3042}"), (3, "\u{82}")]
                .map(|(id, string)| (id, string.into())),
        );
        assert_eq!(got, [(language("en"), want)], "strings of STRINGS_SCSU");
    }

    /// read_db reads a FONT block that holds bytes after its FontName, within its Length, and
    /// keeps its FontId: an EXT2 block's Length lets it "be easily skipped" (UEFI 2.11
    /// §33.3.6.2.3), and edk2 moves past a FONT block by its Length (edk2-stable202608
    /// MdeModulePkg/Universal/HiiDatabaseDxe/String.c FindStringBlock).
    #[test]
    fn test_read_db_reads_a_font_block_with_bytes_after_its_font_name() {
        // FONT_1 of Length 17 with 2 bytes after its FontName, then EFI_HII_SIBT_STRING_UCS2_FONT
        // of font 1 "A" and EFI_HII_SIBT_END
        let blocks = [
            &[0x31, 0x40, 0x11, 0x00][..],
            &FONT_1[4..],
            &[0xAA, 0xAA],
            &[0x15, 0x01, b'A', 0x00, 0x00, 0x00, 0x00],
        ]
        .concat();

        assert_eq!(
            strings_packages_of(&[en_strings_package_with_blocks(&blocks)]),
            [(language("en"), string_a())],
            "strings after a FONT block of 2 bytes after its FontName"
        );
    }

    /// read_db shares the text of a DUPLICATE's string with the string that it names, "a
    /// previously defined string with the exact same string text" (UEFI 2.11 §33.3.6.2.1),
    /// copying none.
    #[test]
    fn test_read_db_shares_the_text_of_duplicates() {
        // EFI_HII_SIBT_STRING_UCS2 "AB": 1, EFI_HII_SIBT_DUPLICATEs of 1 and 2: 2 and 3, then
        // EFI_HII_SIBT_END
        let blocks = [
            0x14, b'A', 0x00, b'B', 0x00, 0x00, 0x00, 0x20, 0x01, 0x00, 0x20, 0x02, 0x00, 0x00,
        ];

        let got = strings_packages_of(&[en_strings_package_with_blocks(&blocks)]);

        let [(_, strings)] = got.as_slice() else {
            panic!("{} strings packages, not 1", got.len());
        };
        assert_eq!(
            *strings,
            StringMap::from([(1, "AB".into()), (2, "AB".into()), (3, "AB".into())]),
            "strings of the DUPLICATEs"
        );
        for id in [2, 3] {
            assert!(
                Rc::ptr_eq(&strings[&1], &strings[&id]),
                "string {id} shares string 1's text"
            );
        }
    }

    /// read_db refuses a strings package whose strings decode to more than 16 characters per byte
    /// of its Length, at the string that takes them past it: 65534 DUPLICATEs of a 1024-character
    /// string would decode to 67 million characters from 198703 bytes.
    #[test]
    fn test_read_db_refuses_65534_duplicates_of_a_long_string() {
        // EFI_HII_SIBT_STRING_UCS2 of 1024 "A"s: 1, then 65534 EFI_HII_SIBT_DUPLICATEs of 1 and
        // EFI_HII_SIBT_END; the Length is 49 header bytes and 198654 of blocks, and the
        // DUPLICATE of string 3105 brings the characters to 3105 * 1024, past 16 * 198703
        let blocks = [
            &[0x14][..],
            &[b'A', 0x00].repeat(1024),
            &[0x00, 0x00],
            &[0x20, 0x01, 0x00].repeat(65534),
            &[0x00],
        ]
        .concat();
        let hiidb = package_list_with_guid(
            [0x22; 16],
            &[
                en_strings_package_with_blocks(&blocks),
                END_PACKAGE.to_vec(),
            ]
            .concat(),
        );

        match read_db(&hiidb) {
            Ok(lists) => panic!(
                "read_db read {} strings",
                lists
                    .iter()
                    .flat_map(|list| &list.strings)
                    .map(|package| package.strings.len())
                    .sum::<usize>()
            ),
            Err(err) => assert_eq!(
                format!("{err:#}"),
                strings_block_refusal(
                    "string 3105 brings the strings to 3179520 characters, past 16 per byte of \
                     the strings package's Length 198703"
                ),
                "65534 DUPLICATEs of a 1024-character string"
            ),
        }
    }

    /// SCAN_BUDGET is far more time than read_db takes to read the package of
    /// test_read_db_reads_scsu_strings_without_reading_past_each, and far less than reading on
    /// to the END block after each of its strings takes.
    const SCAN_BUDGET: Duration = Duration::from_secs(20);

    /// read_db reads 65535 SCSU strings that end without a 0x00 byte, before 3 MiB of EXT2 blocks
    /// without one: it looks for each string's first 0x00 byte within the string's own bytes.
    /// Looking on to the first 0x00 byte after each string, the END block's, reads 65535 times
    /// 3 MiB. Only the time shows how far each search reads, so the read runs on a thread of its
    /// own, which a test past SCAN_BUDGET leaves behind.
    #[test]
    fn test_read_db_reads_scsu_strings_without_reading_past_each() {
        // EFI_HII_SIBT_STRINGS_SCSU of 65535 strings `80`, each U+0000 through dynamic window 0
        // at 0x0000, under a zero LanguageWindow
        let strings = [&[0x12, 0xFF, 0xFF][..], &[0x80; 0xFFFF]].concat();
        // an EFI_HII_SIBT_EXT2 block of BlockType2 0x7E and Length 0xFFFF, of 0xFF bytes
        let ext2 = [&[0x31, 0x7E, 0xFF, 0xFF][..], &[0xFF; 0xFFFF - 4]].concat();
        let blocks = [strings, ext2.repeat(48), vec![0x00]].concat();
        let hiidb = package_list_with_guid(
            [0x22; 16],
            &[
                en_strings_package_with_window(&[0; 16], &blocks),
                END_PACKAGE.to_vec(),
            ]
            .concat(),
        );
        let (sender, receiver) = mpsc::channel();
        let reader = thread::spawn(move || {
            let read = read_db(&hiidb)
                .map(|lists| {
                    lists
                        .iter()
                        .flat_map(|list| &list.strings)
                        .map(|package| package.strings.len())
                        .sum::<usize>()
                })
                .map_err(|err| format!("{err:#}"));
            sender.send(read).expect("send what read_db read");
        });

        let read = receiver
            .recv_timeout(SCAN_BUDGET)
            .unwrap_or_else(|err| panic!("read_db within {SCAN_BUDGET:?}: {err}"));
        reader.join().expect("join the reader");
        assert_eq!(read, Ok(65535), "strings read");
    }

    /// read_db refuses a string block that breaks a rule of UEFI 2.11 §33.3.6.2: a DUPLICATE of
    /// no previously defined string, a FontIdentifier of no earlier FONT block, a FONT block
    /// whose FontId is not unique or whose fields do not fit its Length, an EXT block whose
    /// Length does not fit, an unknown block type, a string past string ID 65535, and an SCSU
    /// string that fails to decode.
    #[test]
    fn test_read_db_refuses_every_bad_string_block() {
        let edk2 = EDK2_LANGUAGE_WINDOW;
        let mut static_window_0_moved = EDK2_LANGUAGE_WINDOW;
        static_window_0_moved[0] = 0x0100;
        let ucs2_a = [0x14, b'A', 0x00, 0x00, 0x00];
        let to_65535 = [0x21, 0xFE, 0xFF];
        let font_2 = font_block(2);
        let undefined_font = "FontIdentifier 3 names no earlier EFI_HII_SIBT_FONT block";
        let past_65535 =
            "string identifier 65536 is past the last string identifier 65535 (UEFI 2.11 §33.3.8.2.1)";
        // an EFI_HII_SIBT_FONT of FontId 1 whose EXT2 Length is `length`, then `rest`
        let font_of_length = |length: u8, rest: &[u8]| -> Vec<u8> {
            [&[0x31, 0x40, length, 0x00][..], rest, &[0x00]].concat()
        };
        let cases: Vec<(&str, [u16; 16], Vec<u8>, &str)> =
            vec![
            (
                "DUPLICATE of an undefined string",
                edk2,
                vec![0x20, 0x07, 0x00, 0x00],
                "EFI_HII_SIBT_DUPLICATE StringId 7 names no previously defined string",
            ),
            (
                "DUPLICATE of itself",
                edk2,
                vec![0x20, 0x01, 0x00, 0x00],
                "EFI_HII_SIBT_DUPLICATE StringId 1 names no previously defined string",
            ),
            (
                "DUPLICATE of a later string",
                edk2,
                [&ucs2_a[..], &[0x20, 0x03, 0x00], &ucs2_a, &[0x00]].concat(),
                "EFI_HII_SIBT_DUPLICATE StringId 3 names no previously defined string",
            ),
            (
                "DUPLICATE of a skipped string",
                edk2,
                vec![0x22, 0x01, 0x20, 0x01, 0x00, 0x00],
                "EFI_HII_SIBT_DUPLICATE StringId 1 names no previously defined string",
            ),
            (
                "STRING_SCSU_FONT of an undefined font",
                edk2,
                vec![0x11, 0x03, b'A', 0x00, 0x00],
                undefined_font,
            ),
            (
                "STRINGS_SCSU_FONT of an undefined font",
                edk2,
                vec![0x13, 0x03, 0x01, 0x00, b'A', 0x00, 0x00],
                undefined_font,
            ),
            (
                "STRING_UCS2_FONT of an undefined font",
                edk2,
                vec![0x15, 0x03, b'A', 0x00, 0x00, 0x00, 0x00],
                undefined_font,
            ),
            (
                "STRINGS_UCS2_FONT of an undefined font",
                edk2,
                vec![0x17, 0x03, 0x01, 0x00, b'A', 0x00, 0x00, 0x00, 0x00],
                undefined_font,
            ),
            (
                "STRING_UCS2_FONT of a font before its FONT block",
                edk2,
                [&[0x15, 0x01, b'A', 0x00, 0x00, 0x00][..], &FONT_1, &[0x00]].concat(),
                "FontIdentifier 1 names no earlier EFI_HII_SIBT_FONT block",
            ),
            (
                "two FONT blocks of FontId 2",
                edk2,
                [&font_2[..], &font_2, &[0x00]].concat(),
                "EFI_HII_SIBT_FONT FontId 2 is not unique",
            ),
            (
                "FONT without its FontId",
                edk2,
                font_of_length(4, &[]),
                "failed to read the FontId of an EFI_HII_SIBT_FONT block",
            ),
            (
                "FONT without its FontSize",
                edk2,
                font_of_length(6, &[0x01, 0x10]),
                "failed to read the FontSize of an EFI_HII_SIBT_FONT block",
            ),
            (
                "FONT without its FontStyle",
                edk2,
                font_of_length(10, &[0x01, 0x10, 0x00, 0x00, 0x00, 0x00]),
                "failed to read the FontStyle of an EFI_HII_SIBT_FONT block",
            ),
            (
                "FONT whose FontName has no null terminator",
                edk2,
                font_of_length(13, &[0x01, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, b'F', 0x00]),
                "the FontName of an EFI_HII_SIBT_FONT block has no null terminator",
            ),
            (
                "EXT1 past the string information",
                edk2,
                vec![0x30, 0x7E, 0x09, 0x00],
                "EFI_HII_SIBT_EXT1 Length 9 runs past the string information",
            ),
            (
                "EXT2 past the string information",
                edk2,
                vec![0x31, 0x7E, 0x09, 0x00, 0x00],
                "EFI_HII_SIBT_EXT2 Length 9 runs past the string information",
            ),
            (
                "EXT4 past the string information",
                edk2,
                vec![0x32, 0x7E, 0x09, 0x00, 0x00, 0x00, 0x00],
                "EFI_HII_SIBT_EXT4 Length 9 runs past the string information",
            ),
            (
                "EXT1 of Length 0",
                edk2,
                vec![0x30, 0x7E, 0x00, 0x00],
                "EFI_HII_SIBT_EXT1 Length 0 is below its 3-byte header",
            ),
            (
                "EXT1 of Length 2",
                edk2,
                vec![0x30, 0x7E, 0x02, 0x00],
                "EFI_HII_SIBT_EXT1 Length 2 is below its 3-byte header",
            ),
            (
                "EXT2 of Length 3",
                edk2,
                vec![0x31, 0x7E, 0x03, 0x00, 0x00],
                "EFI_HII_SIBT_EXT2 Length 3 is below its 4-byte header",
            ),
            (
                "EXT4 of Length 5",
                edk2,
                vec![0x32, 0x7E, 0x05, 0x00, 0x00, 0x00, 0x00],
                "EFI_HII_SIBT_EXT4 Length 5 is below its 6-byte header",
            ),
            (
                "EFI_HII_SIBT_FONT as a block type",
                edk2,
                [&[0x40], &FONT_1[1..], &[0x00]].concat(),
                "unknown string block type 0x40",
            ),
            ("block type 0x41", edk2, vec![0x41], "unknown string block type 0x41"),
            ("block type 0x01", edk2, vec![0x01], "unknown string block type 0x01"),
            ("block type 0x18", edk2, vec![0x18], "unknown string block type 0x18"),
            ("block type 0x23", edk2, vec![0x23], "unknown string block type 0x23"),
            ("block type 0x33", edk2, vec![0x33], "unknown string block type 0x33"),
            ("block type 0xff", edk2, vec![0xFF], "unknown string block type 0xff"),
            (
                "STRINGS_UCS2 from 65535",
                edk2,
                [
                    &to_65535[..],
                    &[0x16, 0x02, 0x00, b'A', 0x00, 0x00, 0x00, b'B', 0x00, 0x00, 0x00, 0x00],
                ]
                .concat(),
                past_65535,
            ),
            (
                "STRINGS_SCSU from 65535",
                edk2,
                [&to_65535[..], &[0x12, 0x02, 0x00, b'A', 0x00, b'B', 0x00, 0x00]].concat(),
                past_65535,
            ),
            (
                "STRING_SCSU at 65536",
                edk2,
                [&to_65535[..], &[0x10, b'A', 0x00, 0x10, b'B', 0x00, 0x00]].concat(),
                past_65535,
            ),
            (
                "DUPLICATE at 65536",
                edk2,
                [&to_65535[..], &ucs2_a, &[0x20, 0xFF, 0xFF, 0x00]].concat(),
                past_65535,
            ),
            (
                "SCSU string without its null terminator",
                edk2,
                vec![0x10, b'A'],
                "failed to decode SCSU string 1: the SCSU string has no null terminator",
            ),
            (
                "SCSU string that static window 0 reads otherwise",
                static_window_0_moved,
                vec![0x10, b'A', 0x00, 0x00],
                "failed to decode SCSU string 1: static window 0 is 0x0100; UTS #6 reads bytes \
                 20-7F both through it and as Basic Latin (UEFI 2.11 §33.3.6.3.1)",
            ),
            (
                "second SCSU string of STRINGS_SCSU",
                edk2,
                vec![0x12, 0x02, 0x00, b'A', 0x00, 0x7F, 0x2C, 0x00, 0x00],
                "failed to decode SCSU string 2: unknown control code 0x7F 0x2c (UEFI 2.11 \
                 Table 33.3)",
            ),
        ];
        for (case, language_window, blocks, refusal) in cases {
            let package = en_strings_package_with_window(&language_window, &blocks);

            assert_eq!(
                strings_package_refusal(package),
                strings_block_refusal(refusal),
                "{case}"
            );
        }
    }

    /// read_db refuses a string block cut at any of its bytes, naming the field that the cut
    /// leaves short, and refuses the whole block without the EFI_HII_SIBT_END after it.
    #[test]
    fn test_read_db_refuses_every_string_block_cut_short() {
        let ucs2_a = [0x14, b'A', 0x00, 0x00, 0x00];
        let read =
            |field: &str, block: &str| format!("failed to read the {field} of an {block} block");
        let no_terminator =
            |block: &str| format!("the StringText of an {block} block has no null terminator");
        let scsu =
            "failed to decode SCSU string 1: the SCSU string has no null terminator".to_string();
        // each block, the blocks before it, and the refusal at each cut from 1 byte on
        type Case<'a> = (&'a str, &'a [u8], Vec<u8>, Vec<String>);
        let cases: [Case; 15] = [
            (
                "EFI_HII_SIBT_SKIP2",
                &[],
                vec![0x21, 0x01, 0x00],
                vec![read("SkipCount", "EFI_HII_SIBT_SKIP2"); 2],
            ),
            (
                "EFI_HII_SIBT_SKIP1",
                &[],
                vec![0x22, 0x01],
                vec![read("SkipCount", "EFI_HII_SIBT_SKIP1")],
            ),
            (
                "EFI_HII_SIBT_DUPLICATE",
                &ucs2_a,
                vec![0x20, 0x01, 0x00],
                vec![read("StringId", "EFI_HII_SIBT_DUPLICATE"); 2],
            ),
            (
                "EFI_HII_SIBT_STRING_UCS2",
                &[],
                ucs2_a.to_vec(),
                vec![no_terminator("EFI_HII_SIBT_STRING_UCS2"); 4],
            ),
            (
                "EFI_HII_SIBT_STRING_UCS2_FONT",
                &[],
                vec![0x15, 0x00, b'A', 0x00, 0x00, 0x00],
                [
                    vec![read("FontIdentifier", "EFI_HII_SIBT_STRING_UCS2_FONT")],
                    vec![no_terminator("EFI_HII_SIBT_STRING_UCS2_FONT"); 4],
                ]
                .concat(),
            ),
            (
                "EFI_HII_SIBT_STRINGS_UCS2",
                &[],
                vec![0x16, 0x01, 0x00, b'A', 0x00, 0x00, 0x00],
                [
                    vec![read("StringCount", "EFI_HII_SIBT_STRINGS_UCS2"); 2],
                    vec![no_terminator("EFI_HII_SIBT_STRINGS_UCS2"); 4],
                ]
                .concat(),
            ),
            (
                "EFI_HII_SIBT_STRINGS_UCS2_FONT",
                &[],
                vec![0x17, 0x00, 0x01, 0x00, b'A', 0x00, 0x00, 0x00],
                [
                    vec![read("FontIdentifier", "EFI_HII_SIBT_STRINGS_UCS2_FONT")],
                    vec![read("StringCount", "EFI_HII_SIBT_STRINGS_UCS2_FONT"); 2],
                    vec![no_terminator("EFI_HII_SIBT_STRINGS_UCS2_FONT"); 4],
                ]
                .concat(),
            ),
            (
                "EFI_HII_SIBT_STRING_SCSU",
                &[],
                vec![0x10, b'A', 0x00],
                vec![scsu.clone(); 2],
            ),
            (
                "EFI_HII_SIBT_STRING_SCSU_FONT",
                &[],
                vec![0x11, 0x00, b'A', 0x00],
                [
                    vec![read("FontIdentifier", "EFI_HII_SIBT_STRING_SCSU_FONT")],
                    vec![scsu.clone(); 2],
                ]
                .concat(),
            ),
            (
                "EFI_HII_SIBT_STRINGS_SCSU",
                &[],
                vec![0x12, 0x01, 0x00, b'A', 0x00],
                [
                    vec![read("StringCount", "EFI_HII_SIBT_STRINGS_SCSU"); 2],
                    vec![scsu.clone(); 2],
                ]
                .concat(),
            ),
            (
                "EFI_HII_SIBT_STRINGS_SCSU_FONT",
                &[],
                vec![0x13, 0x00, 0x01, 0x00, b'A', 0x00],
                [
                    vec![read("FontIdentifier", "EFI_HII_SIBT_STRINGS_SCSU_FONT")],
                    vec![read("StringCount", "EFI_HII_SIBT_STRINGS_SCSU_FONT"); 2],
                    vec![scsu.clone(); 2],
                ]
                .concat(),
            ),
            (
                "EFI_HII_SIBT_EXT1",
                &[],
                vec![0x30, 0x7E, 0x04, 0xAA],
                vec![
                    read("BlockType2", "EFI_HII_SIBT_EXT1"),
                    read("Length", "EFI_HII_SIBT_EXT1"),
                    "EFI_HII_SIBT_EXT1 Length 4 runs past the string information".to_string(),
                ],
            ),
            (
                "EFI_HII_SIBT_EXT2",
                &[],
                vec![0x31, 0x7E, 0x05, 0x00, 0xAA],
                [
                    vec![read("BlockType2", "EFI_HII_SIBT_EXT2")],
                    vec![read("Length", "EFI_HII_SIBT_EXT2"); 2],
                    vec!["EFI_HII_SIBT_EXT2 Length 5 runs past the string information".to_string()],
                ]
                .concat(),
            ),
            (
                "EFI_HII_SIBT_EXT4",
                &[],
                vec![0x32, 0x7E, 0x07, 0x00, 0x00, 0x00, 0xAA],
                [
                    vec![read("BlockType2", "EFI_HII_SIBT_EXT4")],
                    vec![read("Length", "EFI_HII_SIBT_EXT4"); 4],
                    vec!["EFI_HII_SIBT_EXT4 Length 7 runs past the string information".to_string()],
                ]
                .concat(),
            ),
            (
                "EFI_HII_SIBT_FONT",
                &[],
                FONT_1.to_vec(),
                [
                    vec![read("BlockType2", "EFI_HII_SIBT_EXT2")],
                    vec![read("Length", "EFI_HII_SIBT_EXT2"); 2],
                    vec![
                        "EFI_HII_SIBT_EXT2 Length 15 runs past the string information".to_string();
                        11
                    ],
                ]
                .concat(),
            ),
        ];
        for (block_name, before, block, refusals) in cases {
            assert_eq!(
                refusals.len(),
                block.len() - 1,
                "{block_name}: a refusal per cut"
            );
            let whole = [before, &block[..], &[0x00]].concat();
            strings_packages_of(&[en_strings_package_with_window(
                &EDK2_LANGUAGE_WINDOW,
                &whole,
            )]);

            for (cut, refusal) in (1..block.len()).zip(refusals) {
                let blocks = [before, &block[..cut]].concat();
                let package = en_strings_package_with_window(&EDK2_LANGUAGE_WINDOW, &blocks);

                assert_eq!(
                    strings_package_refusal(package),
                    strings_block_refusal(&refusal),
                    "{block_name} cut at {cut}"
                );
            }
            let package = en_strings_package_with_window(
                &EDK2_LANGUAGE_WINDOW,
                &[before, &block[..]].concat(),
            );
            assert_eq!(
                strings_package_refusal(package),
                strings_block_refusal("failed to read a string block type"),
                "{block_name} without EFI_HII_SIBT_END"
            );
        }
    }
}
