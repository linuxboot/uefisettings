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
use std::fs;
use std::io::Seek;
use std::rc::Rc;

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

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
struct PackageList {
    guid: Guid,  // 16 bytes
    length: u32, // 4 bytes
    #[br(count = length - 16 - 4)]
    data: Vec<u8>,
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
struct Package {
    // we need only 24 bits for length but are reading as u32 so discard the rest
    #[br(map = |x: u32| x  & 0x00FFFFFF)]
    length: u32,
    // now move cursor back by 32 - 24 = 8 bits = 1 byte
    #[br(seek_before = SeekFrom::Current(-1))]
    package_type: PackageType, // 8 bits
    #[br(count = length - 4)]
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
        let package_list: PackageList = match db_cursor.read_ne() {
            Err(why) => {
                error!("Can't parse more package lists: {}", why);
                // We can also break to skip the error and return the already parsed package lists.
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

    Ok(package_lists)
}

fn get_packages(package_list: &PackageList) -> Result<Vec<Package>> {
    let mut packages: Vec<Package> = Vec::new(); // packages of one package_list

    let mut pl_cursor = Cursor::new(&package_list.data);

    loop {
        let package: Package = match pl_cursor.read_ne() {
            Err(why) => {
                error!("Can't parse more packages in this package list {}", why);
                // We can also break to skip the error and save correctly parsed packages.
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
    /// HashMap<packagelist_guid_string, Vec<StringMap>>
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
    use std::fs::File;
    use std::io::Read;

    use super::*;

    #[test]
    fn test_read_db_strings() {
        let file_path = "testdata/hiidb.bin";
        if !fs::metadata(file_path).is_ok() {
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
                .get(0)
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
                .get(0)
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
        if !fs::metadata(file_path).is_ok() {
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
            .get(0)
            .unwrap()
            .borrow();

        // root element should only have one child
        assert_eq!(root_node.children.len(), 1);

        // root elements's child should be FormSet
        assert_eq!(
            root_node.children.get(0).unwrap().borrow().op_code,
            forms::IFROpCode::FormSet
        );

        // root elements's child FormSet should have open scope
        assert!(root_node.children.get(0).unwrap().borrow().open_scope);

        // root_node's child should be able to refer to it's parent which is root_node
        // root_node has a dummy opcode used only in root nodes so if they match
        // we can be sure it's referring to the correct node
        assert_eq!(
            root_node
                .children
                .get(0)
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
