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

//! Writing efivars dumps: the efivar files that the questions of a HiiDB read, copied from
//! efivarfs, with the HiiDB and a DumpManifest.

use std::collections::BTreeMap;
use std::fs;
use std::fs::DirBuilder;
use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::path::PathBuf;
use std::rc::Rc;

use anyhow::Context;
use anyhow::Result;
use log::warn;

use super::DumpManifest;
use super::EfivarRedaction;
use super::DUMP_FILE_NOUN;
use super::DUMP_FORMAT;
use super::DUMP_HIIDB;
use super::DUMP_MANIFEST;
use crate::efi_variables::enhanced_authenticated::metadata_end;
#[cfg(target_os = "linux")]
use crate::hii::efivarfs::EFIVARS_MOUNT_POINT;
use crate::hii::efivarfs_format::open_efivar;
use crate::hii::efivarfs_format::read_efivar_file_of;
use crate::hii::efivarfs_format::EfivarNotFound;
use crate::hii::forms::list_questions;
use crate::hii::forms::IncludedStates;
use crate::hii::forms::PasswordQuestions;
#[cfg(target_os = "linux")]
use crate::hii::package::read_db;
use crate::hii::package::ParsedPackageList;
use crate::hii::variables::efivar_parts;
use crate::hii::variables::DecodedValue;
use crate::hii::variables::EfivarFileName;
use crate::hii::variables::EfivarSource;
use crate::hii::variables::EFIVARFS_HEADER_SIZE;

/// The efivar files that a dump copied, and those that its questions read but do not exist.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct EfivarDump {
    /// The names of the efivar files copied into the dump directory
    pub copied: Vec<String>,
    /// The names of the efivar files that questions read but this machine's efivarfs lacks
    pub missing: Vec<String>,
}

/// Copies the efivar files that the questions of the HiiDB `db_bytes` read from this machine's
/// efivarfs into the new directory `dir`, as `redaction` says, with the HiiDB and a manifest.
#[cfg(target_os = "linux")]
pub(crate) fn dump_efivars(
    db_bytes: &[u8],
    dir: &Path,
    redaction: EfivarRedaction,
) -> Result<EfivarDump> {
    write_dump(
        db_bytes,
        &decoded_bytes(read_db(db_bytes)?)?,
        Path::new(EFIVARS_MOUNT_POINT),
        dir,
        redaction,
    )
}

/// The payload bytes that the questions of `package_lists`, in any state, decode, by efivar
/// file, found without reading any; none that a PASSWORD question that uefisettings finds holds.
/// One in IFR that read_db ignores, or whose VarStore is unknown, withholds no bytes: of_lists
/// warns of each.
fn decoded_bytes(
    package_lists: Vec<ParsedPackageList>,
) -> Result<BTreeMap<EfivarFileName, Vec<DecodedValue>>> {
    let mut reader = PasswordQuestions::of_lists(&package_lists)
        .reader(EfivarSource::Disabled.into_variables()?)?;
    for list in package_lists {
        list.check_form_strings()?;
        // which questions read which bytes holds in every language
        let texts = list.texts(&[]);
        for root in &list.forms {
            list_questions(
                Rc::clone(root),
                &texts,
                IncludedStates::CONDITIONS,
                None,
                &mut reader,
            );
        }
    }
    // by efivar file, which names that differ only in '/' and '!' share
    let mut files: BTreeMap<EfivarFileName, Vec<DecodedValue>> = BTreeMap::new();
    for (key, values) in reader.decoded {
        files
            .entry(EfivarFileName::from(&key))
            .or_default()
            .extend(values);
    }
    Ok(files)
}

/// Copies the efivar files that `decoded` names from `efivars` into the new directory `dir`,
/// keeping, as `redaction` says, only their `decoded` payload bytes, and saves `hiidb`, which
/// `decoded` comes from, as DUMP_HIIDB and then the DUMP_MANIFEST.
pub(super) fn write_dump(
    hiidb: &[u8],
    decoded: &BTreeMap<EfivarFileName, Vec<DecodedValue>>,
    efivars: &Path,
    dir: &Path,
    redaction: EfivarRedaction,
) -> Result<EfivarDump> {
    let mut partial = PartialDump::create(dir)?;
    let mut dump = EfivarDump::default();
    for (name, values) in decoded {
        let file = match open_efivar(efivars, name) {
            Ok(file) => file,
            Err(error) if error.is::<EfivarNotFound>() => {
                dump.missing.push(name.to_string());
                continue;
            }
            Err(error) => return Err(error),
        };
        let bytes = read_efivar_file_of(&file).with_context(|| {
            format!(
                "failed to read efivar file '{}'",
                efivars.join(name).display()
            )
        })?;
        let bytes = match redaction {
            EfivarRedaction::DecodedBytes => keep_decoded(&bytes, values),
            EfivarRedaction::Unredacted => bytes,
        };
        partial.write(name, &bytes)?;
        dump.copied.push(name.to_string());
    }
    partial.write(DUMP_HIIDB, hiidb)?;
    let manifest = DumpManifest {
        format: DUMP_FORMAT,
        uefisettings: env!("CARGO_PKG_VERSION").to_string(),
        redaction,
    };
    partial.write(DUMP_MANIFEST, &serde_json::to_vec_pretty(&manifest)?)?;
    partial.commit();
    Ok(dump)
}

/// The efivar file `bytes` with each payload byte zeroed unless one of `values` decodes it from
/// these bytes, or it is metadata that the value follows.
fn keep_decoded(bytes: &[u8], values: &[DecodedValue]) -> Vec<u8> {
    let mut kept = vec![0; bytes.len()];
    // the metadata of EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS that get accepts stays, so that
    // the dump decodes as its source does; behind metadata that it refuses, no value decodes
    let (start, values) = match value_start(bytes) {
        Some(start) => (start, values),
        None => (EFIVARFS_HEADER_SIZE, &[][..]),
    };
    let value_len = bytes.get(start..).map_or(0, <[u8]>::len);
    let payload = values
        .iter()
        .filter(|decoded| decoded.decodes_from(value_len))
        .map(|decoded| start + decoded.value.start..start + decoded.value.end);
    for range in std::iter::once(0..start).chain(payload) {
        let end = range.end.min(bytes.len());
        let start = range.start.min(end);
        if let (Some(to), Some(from)) = (kept.get_mut(start..end), bytes.get(start..end)) {
            to.copy_from_slice(from);
        }
    }
    kept
}

/// Where the value starts in the efivar file `bytes`: after the attributes word and the metadata
/// that metadata_end accepts. None where it refuses that metadata, so get decodes nothing.
fn value_start(bytes: &[u8]) -> Option<usize> {
    let Some((attributes, data)) = efivar_parts(bytes) else {
        return Some(EFIVARFS_HEADER_SIZE);
    };
    match metadata_end(attributes, data) {
        Ok(end) => Some(EFIVARFS_HEADER_SIZE + end),
        Err(_) => None,
    }
}

impl DecodedValue {
    /// Whether this value decodes from a variable whose value, behind any metadata, has `len`
    /// bytes: get reads `size` of them, so it fails on fewer.
    fn decodes_from(&self, len: usize) -> bool {
        len >= usize::from(self.size)
    }
}

/// A dump directory being written: dropped before commit, it removes its files and itself.
struct PartialDump<'a> {
    dir: &'a Path,
    files: Vec<PathBuf>,
    committed: bool,
}

impl<'a> PartialDump<'a> {
    /// Creates `dir`, which must not exist, for its owner only.
    fn create(dir: &'a Path) -> Result<Self> {
        DirBuilder::new()
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("failed to create efivars directory '{}'", dir.display()))?;
        Ok(Self {
            dir,
            files: Vec::new(),
            committed: false,
        })
    }

    /// Writes `bytes` to the new file `name`, for its owner only.
    fn write(&mut self, name: impl AsRef<Path>, bytes: &[u8]) -> Result<()> {
        let path = self.dir.join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("failed to create {DUMP_FILE_NOUN} '{}'", path.display()))?;
        let written = file
            .write_all(bytes)
            .with_context(|| format!("failed to write {DUMP_FILE_NOUN} '{}'", path.display()));
        self.files.push(path);
        written
    }

    /// Keeps the dump.
    fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for PartialDump<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        for file in &self.files {
            if let Err(error) = fs::remove_file(file) {
                warn!("failed to remove {}: {error}", file.display());
            }
        }
        if let Err(error) = fs::remove_dir(self.dir) {
            warn!("failed to remove {}: {error}", self.dir.display());
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::ffi::OsStr;
    use std::io::Cursor;
    use std::os::unix::fs::PermissionsExt;
    use std::rc::Rc;

    use super::super::tests::dump_dir;
    use super::super::tests::efivar;
    use super::super::tests::efivars;
    use super::super::tests::first_bytes;
    use super::super::tests::HIIDB;
    use super::*;
    use crate::efi_variables::enhanced_authenticated::fixture::timestamp_metadata;
    use crate::hii::efivarfs_format::tests::SETUP;
    use crate::hii::forms::handle_form_set;
    use crate::hii::forms::ifr_fixtures::checkbox;
    use crate::hii::forms::ifr_fixtures::checkbox_at;
    use crate::hii::forms::ifr_fixtures::checkbox_on;
    use crate::hii::forms::ifr_fixtures::conditional;
    use crate::hii::forms::ifr_fixtures::form;
    use crate::hii::forms::ifr_fixtures::form_set;
    use crate::hii::forms::ifr_fixtures::ifr_true;
    use crate::hii::forms::ifr_fixtures::operation;
    use crate::hii::forms::ifr_fixtures::parse_form_set;
    use crate::hii::forms::ifr_fixtures::password_on;
    use crate::hii::forms::ifr_fixtures::question_header_with;
    use crate::hii::forms::ifr_fixtures::var_store;
    use crate::hii::forms::ifr_fixtures::var_store_efi;
    use crate::hii::forms::ifr_fixtures::CHECKBOX;
    use crate::hii::forms::ifr_fixtures::DISABLE_IF;
    use crate::hii::forms::ifr_fixtures::NIL_GUID;
    use crate::hii::forms::ifr_fixtures::NUMERIC;
    use crate::hii::forms::ifr_fixtures::NV_BS_RT;
    use crate::hii::forms::ifr_fixtures::SUPPRESS_IF;
    use crate::hii::forms::IFROperation;
    use crate::hii::package::hiidb_fixtures::en_strings_package_of;
    use crate::hii::package::hiidb_fixtures::form_package;
    use crate::hii::package::hiidb_fixtures::package_list_with_guid;
    use crate::hii::package::hiidb_fixtures::END_PACKAGE;
    use crate::hii::package::read_db;
    use crate::hii::strings::Language;
    use crate::hii::strings::ListTexts;
    use crate::hii::strings::StringPackage;
    use crate::hii::variables::tests::NV_BS;
    use crate::hii::variables::EfivarReader;

    /// The redacted dump of a HiiDB with a UINT64 NUMERIC over bytes 0..8 of a PASSWORD's 40
    /// bytes keeps no byte of the password, and the CHECKBOX beside it: decoded_bytes never
    /// records a value over one.
    #[test]
    fn redacted_dump_keeps_no_password_byte() {
        let numeric = [
            question_header_with(4, 4, 2, 0, 0x00),
            vec![0x23], // EFI_IFR_NUMERIC_SIZE_8 | EFI_IFR_DISPLAY_UINT_HEX
            0u64.to_le_bytes().to_vec(),
            u64::MAX.to_le_bytes().to_vec(),
            1u64.to_le_bytes().to_vec(),
        ]
        .concat();
        let packages = [
            form_package(&[
                var_store(2, [0x44; 16], "AMITSESetup", 81),
                form(
                    1,
                    &[
                        password_on(3, 3, 2, 0),
                        operation(NUMERIC, false, &numeric),
                        checkbox_at(5, 5, 2, 80),
                    ],
                ),
            ]),
            en_strings_package_of(&["Q", "P", "Password", "N0", "O"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x55; 16], &packages.concat());
        let mut password: Vec<u8> = "hunter2secret"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        password.resize(40, 0);
        let file = [&NV_BS_RT.to_ne_bytes()[..], &password, &[0xAA; 40], &[1]].concat();

        let decoded = decoded_bytes(read_db(&hiidb).expect("read the HiiDB")).expect("decode");
        let values: Vec<DecodedValue> = decoded
            .iter()
            .filter(|(name, _)| name.to_string().starts_with("AMITSESetup-"))
            .flat_map(|(_, values)| values.iter().cloned())
            .collect();
        let kept = keep_decoded(&file, &values);

        assert_eq!(
            kept.get(EFIVARFS_HEADER_SIZE..EFIVARFS_HEADER_SIZE + 40),
            Some(&[0; 40][..]),
            "the password's bytes in the dump"
        );
        assert_eq!(
            kept.get(EFIVARFS_HEADER_SIZE + 80),
            Some(&1),
            "the CHECKBOX's byte in the dump"
        );
    }

    /// The redacted dump keeps no byte of a PASSWORD on "A/B" that the NUMERIC N0 on "A!B", the
    /// same efivar file, would decode, and keeps the CHECKBOX O on "A!B" beside it.
    #[test]
    fn redacted_dump_keeps_no_password_byte_under_an_aliased_name() {
        let numeric = [
            question_header_with(4, 4, 3, 0, 0x00),
            vec![0x23], // EFI_IFR_NUMERIC_SIZE_8 | EFI_IFR_DISPLAY_UINT_HEX
            0u64.to_le_bytes().to_vec(),
            u64::MAX.to_le_bytes().to_vec(),
            1u64.to_le_bytes().to_vec(),
        ]
        .concat();
        let packages = [
            form_package(&[
                var_store(2, [0x44; 16], "A/B", 81),
                var_store(3, [0x44; 16], "A!B", 81),
                form(
                    1,
                    &[
                        password_on(3, 3, 2, 0),
                        operation(NUMERIC, false, &numeric),
                        checkbox_at(5, 5, 3, 80),
                    ],
                ),
            ]),
            en_strings_package_of(&["Q", "P", "Password", "N0", "O"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x55; 16], &packages.concat());
        let mut password: Vec<u8> = "hunter2secret"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        password.resize(40, 0);
        let file = [&NV_BS_RT.to_ne_bytes()[..], &password, &[0xAA; 40], &[1]].concat();

        let decoded = decoded_bytes(read_db(&hiidb).expect("read the HiiDB")).expect("decode");
        let values: Vec<DecodedValue> = decoded
            .iter()
            .filter(|(name, _)| name.to_string().starts_with("A!B-"))
            .flat_map(|(_, values)| values.iter().cloned())
            .collect();
        let kept = keep_decoded(&file, &values);

        assert_eq!(
            kept.get(EFIVARFS_HEADER_SIZE..EFIVARFS_HEADER_SIZE + 40),
            Some(&[0; 40][..]),
            "the password's bytes in the dump"
        );
        assert_eq!(
            kept.get(EFIVARFS_HEADER_SIZE + 80),
            Some(&1),
            "the CHECKBOX's byte in the dump"
        );
    }

    /// The directory of the fixtures of tests/offline_golden.rs.
    const OFFLINE_FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/offline");
    /// The variable that makes offline_fixtures_are_current rewrite the fixtures.
    const BLESS: &str = "UEFISETTINGS_BLESS";

    /// Whether `value`, that of BLESS, asks for a rewrite: only "1" does, as in
    /// tests/golden/mod.rs, whose test crates cannot reach this module.
    fn blesses(value: Option<&OsStr>) -> bool {
        value.is_some_and(|value| value == "1")
    }

    #[test]
    fn only_bless_1_rewrites_the_fixtures() {
        for (value, want) in [
            (None, false),
            (Some(""), false),
            (Some("0"), false),
            (Some("1"), true),
        ] {
            assert_eq!(blesses(value.map(OsStr::new)), want, "{BLESS}={value:?}");
        }
    }

    /// The package list of `root`, with no strings.
    fn package_list(root: &Rc<RefCell<IFROperation>>) -> ParsedPackageList {
        ParsedPackageList {
            guid: NIL_GUID,
            device_path: None,
            strings: vec![StringPackage {
                language: Language::default(),
                strings: BTreeMap::new(),
            }],
            forms: vec![Rc::clone(root)],
            ignored_ifr: Vec::new(),
        }
    }

    /// The answers and states that list_questions gives for the questions of `root`,
    /// reading the efivar files in `efivars`.
    fn answers(root: &Rc<RefCell<IFROperation>>, efivars: &Path) -> Vec<String> {
        let source = EfivarSource::Directory(efivars.to_path_buf());
        list_questions(
            Rc::clone(root),
            &ListTexts::new(&[], &[]),
            IncludedStates::CONDITIONS,
            None,
            &mut EfivarReader::new(source).expect("create a reader of the efivars directory"),
        )
        .into_iter()
        .map(|(question, state)| format!("{}{}", question.value, state.annotation()))
        .collect()
    }

    /// The names of the files in `dir`, sorted.
    fn file_names(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .expect("list directory")
            .map(|entry| {
                entry
                    .expect("directory entry")
                    .file_name()
                    .into_string()
                    .expect("UTF-8 file name")
            })
            .collect();
        names.sort();
        names
    }

    #[test]
    fn redacted_dump_keeps_the_decoded_bytes() {
        let live = efivars(&[(&efivar("Setup"), &SETUP)]);
        let (_parent, dir) = dump_dir();
        let decoded = |value| DecodedValue { size: 10, value };
        let decoded = BTreeMap::from([(
            efivar("Setup"),
            vec![decoded(1..3), decoded(6..7), decoded(9..10)],
        )]);

        let dump = write_dump(
            HIIDB,
            &decoded,
            live.path(),
            &dir,
            EfivarRedaction::DecodedBytes,
        )
        .expect("dump efivars");

        assert_eq!(
            dump,
            EfivarDump {
                copied: vec![efivar("Setup").to_string()],
                missing: Vec::new(),
            },
            "dump"
        );
        assert_eq!(
            fs::read(dir.join(efivar("Setup"))).expect("read the dumped file"),
            [7, 0, 0, 0, 0, 2, 3, 0, 0, 0, 7, 0, 0, 10],
            "attributes, payload offsets 1, 2, 6 and 9"
        );
    }

    /// A redacted dump keeps the metadata of EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS and the
    /// decoded bytes behind it, so that it decodes as its source does, and none of a value
    /// shorter than its VarStore, which get does not decode.
    #[test]
    fn redacted_dump_keeps_the_metadata_and_the_decoded_bytes_behind_it() {
        let metadata = timestamp_metadata();
        for (case, value, kept) in [
            ("value of 4 bytes", &[9, 8, 7, 6][..], &[0, 8, 0, 0][..]),
            ("value of 3 bytes", &[9, 8, 7][..], &[0, 0, 0][..]),
        ] {
            let attributes = 0x87u32.to_ne_bytes();
            let file = [&attributes[..], &metadata, value].concat();
            let live = efivars(&[(&efivar("Setup"), &file)]);
            let (_parent, dir) = dump_dir();
            let decoded = BTreeMap::from([(
                efivar("Setup"),
                vec![DecodedValue {
                    size: 4,
                    value: 1..2,
                }],
            )]);

            write_dump(
                HIIDB,
                &decoded,
                live.path(),
                &dir,
                EfivarRedaction::DecodedBytes,
            )
            .expect("dump efivars");

            assert_eq!(
                fs::read(dir.join(efivar("Setup"))).expect("read the dumped file"),
                [&attributes[..], &metadata, kept].concat(),
                "{case}: attributes, metadata, value offset 1 of a VarStore of 4 bytes"
            );
        }
    }

    /// A redacted dump keeps the EFI_VARIABLE_AUTHENTICATION_3 metadata of a variable with
    /// EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS where get accepts it, and so decodes where its
    /// source does, and keeps neither the metadata nor bytes behind it where get refuses it. A
    /// variable with EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS alone has no metadata.
    #[test]
    fn redacted_dump_keeps_the_metadata_that_get_accepts() {
        let bytes = form_set(&[
            var_store_efi(1, "Setup", NV_BS_RT, 4),
            operation(CHECKBOX, false, &checkbox(1, 0x00)),
            operation(CHECKBOX, false, &checkbox(3, 0x00)),
        ]);
        let root = handle_form_set(&mut Cursor::new(&bytes)).expect("parse the FormSet");
        let mut version_2 = timestamp_metadata();
        version_2[0] = 2;
        for (case, attributes, metadata, accepted) in [
            ("0x87", 0x87u32, timestamp_metadata(), true),
            ("0xA7", 0xA7, timestamp_metadata(), false),
            ("0x87 of Version 2", 0x87, version_2, false),
            ("0x27", 0x27, Vec::new(), true),
        ] {
            let attributes = attributes.to_ne_bytes();
            // 0 and 1, not the 1 and 0 at bytes 1 and 3 of the metadata, which a read that
            // skips no metadata decodes
            let file = [&attributes[..], &metadata, &[0xAA, 0, 0xBB, 1]].concat();
            let live = efivars(&[(&efivar("Setup"), &file)]);
            let (_parent, dir) = dump_dir();

            let decoded = decoded_bytes(vec![package_list(&root)]).expect("find the decoded bytes");
            write_dump(
                HIIDB,
                &decoded,
                live.path(),
                &dir,
                EfivarRedaction::DecodedBytes,
            )
            .expect("dump efivars");

            let kept = match accepted {
                true => [&attributes[..], &metadata, &[0, 0, 0, 1]].concat(),
                false => [&attributes[..], &vec![0; metadata.len() + 4]].concat(),
            };
            assert_eq!(
                fs::read(dir.join(efivar("Setup"))).expect("read the dumped file"),
                kept,
                "{case}: dumped Setup"
            );
            assert_eq!(
                answers(&root, live.path()) == ["0", "1"],
                accepted,
                "{case}: get decodes the source: {:?}",
                answers(&root, live.path())
            );
            assert_eq!(
                answers(&root, &dir) == ["0", "1"],
                accepted,
                "{case}: get decodes the dump: {:?}",
                answers(&root, &dir)
            );
        }
    }

    #[test]
    fn unredacted_dump_copies_whole_files() {
        let live = efivars(&[(&efivar("Setup"), &SETUP)]);
        let (_parent, dir) = dump_dir();
        let decoded = first_bytes(&[&efivar("Setup")]);

        write_dump(
            HIIDB,
            &decoded,
            live.path(),
            &dir,
            EfivarRedaction::Unredacted,
        )
        .expect("dump efivars");

        assert_eq!(
            fs::read(dir.join(efivar("Setup"))).expect("read the dumped file"),
            SETUP,
            "unredacted"
        );
    }

    #[test]
    fn dump_is_for_its_owner_only() {
        let live = efivars(&[(&efivar("Setup"), &SETUP)]);
        let (_parent, dir) = dump_dir();
        let decoded = first_bytes(&[&efivar("Setup")]);
        let mode = |path: &Path| fs::metadata(path).expect("stat").permissions().mode() & 0o777;

        write_dump(
            HIIDB,
            &decoded,
            live.path(),
            &dir,
            EfivarRedaction::Unredacted,
        )
        .expect("dump efivars");

        assert_eq!(mode(&dir), 0o700, "directory mode");
        for name in [&efivar("Setup").to_string(), DUMP_HIIDB, DUMP_MANIFEST] {
            assert_eq!(mode(&dir.join(name)), 0o600, "{name}: file mode");
        }
    }

    #[test]
    fn dump_refuses_an_existing_directory() {
        let live = efivars(&[(&efivar("Setup"), &SETUP)]);
        let existing = efivars(&[(&efivar("Kept"), b"kept")]);
        let decoded = first_bytes(&[&efivar("Setup")]);

        let error = write_dump(
            HIIDB,
            &decoded,
            live.path(),
            existing.path(),
            EfivarRedaction::Unredacted,
        )
        .expect_err("dump into an existing directory");

        assert_eq!(
            format!("{error:#}"),
            format!(
                "failed to create efivars directory '{}': File exists (os error 17)",
                existing.path().display()
            ),
            "error"
        );
        assert_eq!(
            file_names(existing.path()),
            [efivar("Kept").to_string()],
            "existing directory"
        );
    }

    #[test]
    fn dump_lists_missing_variables() {
        let live = efivars(&[(&efivar("Setup"), &SETUP)]);
        let (_parent, dir) = dump_dir();
        let decoded = first_bytes(&[&efivar("Missing"), &efivar("Setup")]);

        let dump = write_dump(
            HIIDB,
            &decoded,
            live.path(),
            &dir,
            EfivarRedaction::Unredacted,
        )
        .expect("dump efivars");

        assert_eq!(
            dump,
            EfivarDump {
                copied: vec![efivar("Setup").to_string()],
                missing: vec![efivar("Missing").to_string()],
            },
            "dump"
        );
        assert!(
            !dir.join(efivar("Missing")).exists(),
            "file of the missing variable"
        );
    }

    #[test]
    fn failed_dump_removes_what_it_wrote() {
        let live = efivars(&[(&efivar("A"), &SETUP)]);
        fs::create_dir(live.path().join(efivar("B"))).expect("create a directory as B");
        let (_parent, dir) = dump_dir();
        let decoded = first_bytes(&[&efivar("A"), &efivar("B")]);

        let error = write_dump(
            HIIDB,
            &decoded,
            live.path(),
            &dir,
            EfivarRedaction::Unredacted,
        )
        .expect_err("dump a directory as a variable");

        assert_eq!(
            error.to_string(),
            format!(
                "efivar file '{}' is not a regular file",
                live.path().join(efivar("B")).display()
            ),
            "error"
        );
        assert!(!dir.exists(), "dump directory after the failure");
    }

    #[test]
    fn dump_files_stay_in_the_dump_directory() {
        let crafted = EfivarFileName::new("../x", NIL_GUID);
        let live = efivars(&[(&crafted, &SETUP)]);
        let (parent, dir) = dump_dir();
        let decoded = first_bytes(&[&crafted]);

        write_dump(
            HIIDB,
            &decoded,
            live.path(),
            &dir,
            EfivarRedaction::Unredacted,
        )
        .expect("dump efivars");

        assert_eq!(
            file_names(&dir),
            [
                crafted.to_string(),
                DUMP_HIIDB.to_string(),
                DUMP_MANIFEST.to_string()
            ],
            "dump directory"
        );
        assert_eq!(file_names(parent.path()), ["dump"], "its parent");
    }

    #[test]
    fn dump_saves_the_hiidb_and_a_manifest() {
        for (case, redaction, json) in [
            ("redacted", EfivarRedaction::DecodedBytes, "decoded-bytes"),
            ("unredacted", EfivarRedaction::Unredacted, "unredacted"),
        ] {
            let live = efivars(&[(&efivar("Setup"), &SETUP)]);
            let (_parent, dir) = dump_dir();

            write_dump(
                HIIDB,
                &first_bytes(&[&efivar("Setup")]),
                live.path(),
                &dir,
                redaction,
            )
            .unwrap_or_else(|error| panic!("dump efivars {case}: {error:#}"));

            assert_eq!(
                fs::read(dir.join(DUMP_HIIDB)).expect("read the saved HiiDB"),
                HIIDB,
                "{case}: HiiDB"
            );
            let manifest: serde_json::Value = serde_json::from_slice(
                &fs::read(dir.join(DUMP_MANIFEST)).expect("read the manifest"),
            )
            .expect("parse the manifest");
            assert_eq!(
                manifest,
                serde_json::json!({
                    "format": 1,
                    "uefisettings": env!("CARGO_PKG_VERSION"),
                    "redaction": json,
                }),
                "{case}: manifest"
            );
        }
    }

    #[test]
    fn redacted_dump_answers_as_its_source() {
        let bytes = form_set(&[
            var_store_efi(1, "Setup", NV_BS_RT, 4),
            operation(CHECKBOX, false, &checkbox(1, 0x00)),
            operation(CHECKBOX, false, &checkbox(3, 0x00)),
        ]);
        let root = handle_form_set(&mut Cursor::new(&bytes)).expect("parse the FormSet");
        let live = efivars(&[(&efivar("Setup"), &[7, 0, 0, 0, 0xAA, 1, 0xBB, 0])]);
        let (_parent, dir) = dump_dir();

        let decoded = decoded_bytes(vec![package_list(&root)]).expect("find the decoded bytes");
        write_dump(
            HIIDB,
            &decoded,
            live.path(),
            &dir,
            EfivarRedaction::DecodedBytes,
        )
        .expect("dump efivars");

        assert_eq!(
            fs::read(dir.join(efivar("Setup"))).expect("read the dumped file"),
            [7, 0, 0, 0, 0, 1, 0, 0],
            "dumped Setup"
        );
        assert_eq!(answers(&root, &dir), ["1", "0"], "answers from the dump");
        assert_eq!(
            answers(&root, &dir),
            answers(&root, live.path()),
            "answers from the source"
        );
    }

    #[test]
    fn redacted_dump_keeps_no_byte_past_the_var_store() {
        let bytes = form_set(&[
            var_store_efi(1, "Setup", NV_BS_RT, 4),
            operation(CHECKBOX, false, &checkbox(1, 0x00)),
            operation(CHECKBOX, false, &checkbox(6, 0x00)),
        ]);
        let root = handle_form_set(&mut Cursor::new(&bytes)).expect("parse the FormSet");
        let live = efivars(&[(
            &efivar("Setup"),
            &[7, 0, 0, 0, 0xAA, 1, 0xBB, 0, 0xCC, 0, 1, 0xDD],
        )]);
        let (_parent, dir) = dump_dir();

        let decoded = decoded_bytes(vec![package_list(&root)]).expect("find the decoded bytes");
        write_dump(
            HIIDB,
            &decoded,
            live.path(),
            &dir,
            EfivarRedaction::DecodedBytes,
        )
        .expect("dump efivars");

        assert_eq!(
            fs::read(dir.join(efivar("Setup"))).expect("read the dumped file"),
            [7, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0],
            "dumped Setup: not the byte at 6, past the VarStore's 4"
        );
        assert_eq!(
            answers(&root, &dir),
            [
                "1",
                "<ExtractEFIDataError: failed to fill whole buffer (offset: 6; buflen: 8)> \
                 <IFR default: 0>"
            ],
            "answers from the dump"
        );
        assert_eq!(
            answers(&root, &dir),
            answers(&root, live.path()),
            "answers from the source"
        );
    }

    #[test]
    fn redacted_dump_keeps_no_byte_of_a_file_shorter_than_its_var_store() {
        let root = parse_form_set(&[
            var_store_efi(1, "Setup", NV_BS_RT, 2),
            var_store_efi(2, "Short", NV_BS_RT, 4),
            form(1, &[checkbox_on(1, 3, 1), checkbox_on(2, 3, 2)]),
        ]);
        let live = efivars(&[
            (&efivar("Setup"), &[7, 0, 0, 0, 1, 0xAA]),
            // 3 of the 4 payload bytes that read_efivar reads
            (&efivar("Short"), &[7, 0, 0, 0, 1, 0xBB, 0xCC]),
        ]);
        let (_parent, dir) = dump_dir();
        let answers_in = |efivars: &Path| -> Vec<String> {
            answers(&root, efivars)
                .into_iter()
                .map(|answer| answer.replace(&efivars.display().to_string(), "DIR"))
                .collect()
        };

        let decoded = decoded_bytes(vec![package_list(&root)]).expect("find the decoded bytes");
        write_dump(
            HIIDB,
            &decoded,
            live.path(),
            &dir,
            EfivarRedaction::DecodedBytes,
        )
        .expect("dump efivars");

        assert_eq!(
            fs::read(dir.join(efivar("Short"))).expect("read the dumped file"),
            [7, 0, 0, 0, 0, 0, 0],
            "dumped Short: attributes only, as no question decodes it"
        );
        assert_eq!(
            fs::read(dir.join(efivar("Setup"))).expect("read the dumped file"),
            [7, 0, 0, 0, 1, 0],
            "dumped Setup: its question's byte"
        );
        assert_eq!(
            answers_in(&dir),
            answers_in(live.path()),
            "answers from the dump and from the source"
        );
    }

    /// A dump keeps the bytes that the questions of VarStores named with '/' and with '!'
    /// decode from the one efivar file of both names.
    #[test]
    fn redacted_dump_keeps_the_bytes_of_names_that_share_an_efivar_file() {
        let root = parse_form_set(&[
            var_store_efi(1, "A/B", NV_BS_RT, 2),
            var_store_efi(2, "A!B", NV_BS_RT, 2),
            checkbox_on(1, 3, 1),
            // Prompt 3, Help 4, QuestionId 2, VarStoreId 2, VarOffset 1
            operation(CHECKBOX, false, &[3, 0, 4, 0, 2, 0, 2, 0, 1, 0, 0, 0]),
        ]);
        let live = efivars(&[(&efivar("A!B"), &[7, 0, 0, 0, 1, 1, 0xAA])]);
        let (_parent, dir) = dump_dir();

        let decoded = decoded_bytes(vec![package_list(&root)]).expect("find the decoded bytes");
        write_dump(
            HIIDB,
            &decoded,
            live.path(),
            &dir,
            EfivarRedaction::DecodedBytes,
        )
        .expect("dump efivars");

        assert_eq!(
            fs::read(dir.join(efivar("A!B"))).expect("read the dumped file"),
            [7, 0, 0, 0, 1, 1, 0],
            "dumped A!B: the bytes of the questions of both names"
        );
        assert_eq!(answers(&root, &dir), ["1", "1"], "answers from the dump");
        assert_eq!(
            answers(&root, &dir),
            answers(&root, live.path()),
            "answers from the source"
        );
    }

    #[test]
    fn redacted_dump_keeps_the_bytes_of_suppressed_questions() {
        let root = parse_form_set(&[
            var_store_efi(1, "Setup", NV_BS_RT, 2),
            var_store_efi(2, "Hidden", NV_BS_RT, 2),
            form(
                1,
                &[
                    checkbox_on(1, 3, 1),
                    conditional(SUPPRESS_IF, ifr_true(), &[checkbox_on(2, 3, 2)]),
                ],
            ),
        ]);
        let live = efivars(&[
            (&efivar("Setup"), &[7, 0, 0, 0, 1, 0xAA]),
            (&efivar("Hidden"), &[7, 0, 0, 0, 1, 0xBB]),
        ]);
        let (_parent, dir) = dump_dir();

        let decoded = decoded_bytes(vec![package_list(&root)]).expect("find the decoded bytes");
        let dump = write_dump(
            HIIDB,
            &decoded,
            live.path(),
            &dir,
            EfivarRedaction::DecodedBytes,
        )
        .expect("dump efivars");

        assert_eq!(
            dump.copied,
            [efivar("Hidden").to_string(), efivar("Setup").to_string()],
            "copied files"
        );
        assert_eq!(
            fs::read(dir.join(efivar("Hidden"))).expect("read the dumped file"),
            [7, 0, 0, 0, 1, 0],
            "dumped Hidden: the suppressed question's byte only"
        );
        assert_eq!(
            answers(&root, &dir),
            ["1", "1 <suppressed>"],
            "answers from the dump"
        );
        assert_eq!(
            answers(&root, &dir),
            answers(&root, live.path()),
            "answers from the source"
        );
    }

    /// A dump keeps the bytes of a question that a DISABLE_IF disables too, as get reads it with
    /// disabled included.
    #[test]
    fn redacted_dump_keeps_the_bytes_of_disabled_questions() {
        let root = parse_form_set(&[
            var_store_efi(1, "Setup", NV_BS_RT, 2),
            var_store_efi(2, "Hidden", NV_BS_RT, 2),
            form(
                1,
                &[
                    checkbox_on(1, 3, 1),
                    conditional(DISABLE_IF, ifr_true(), &[checkbox_on(2, 3, 2)]),
                ],
            ),
        ]);
        let live = efivars(&[
            (&efivar("Setup"), &[7, 0, 0, 0, 1, 0xAA]),
            (&efivar("Hidden"), &[7, 0, 0, 0, 1, 0xBB]),
        ]);
        let (_parent, dir) = dump_dir();

        let decoded = decoded_bytes(vec![package_list(&root)]).expect("find the decoded bytes");
        let dump = write_dump(
            HIIDB,
            &decoded,
            live.path(),
            &dir,
            EfivarRedaction::DecodedBytes,
        )
        .expect("dump efivars");

        assert_eq!(
            dump.copied,
            [efivar("Hidden").to_string(), efivar("Setup").to_string()],
            "copied files"
        );
        assert_eq!(
            fs::read(dir.join(efivar("Hidden"))).expect("read the dumped file"),
            [7, 0, 0, 0, 1, 0],
            "dumped Hidden: the disabled question's byte only"
        );
        assert_eq!(
            answers(&root, &dir),
            ["1", "1 <disabled>"],
            "answers from the dump"
        );
        assert_eq!(
            answers(&root, &dir),
            answers(&root, live.path()),
            "answers from the source"
        );
    }

    /// A dump copies the variables of VARSTORE_EFIs that declare them boot-service-only, as get
    /// reads those that efivarfs lists, and lists those that it does not as missing.
    #[test]
    fn dump_copies_the_variables_of_boot_service_only_var_stores() {
        let root = parse_form_set(&[
            var_store_efi(1, "Setup", NV_BS, 2),
            var_store_efi(2, "Absent", NV_BS, 2),
            form(1, &[checkbox_on(1, 3, 1), checkbox_on(2, 3, 2)]),
        ]);
        let live = efivars(&[(&efivar("Setup"), &[7, 0, 0, 0, 1, 0xAA])]);
        let (_parent, dir) = dump_dir();

        let decoded = decoded_bytes(vec![package_list(&root)]).expect("find the decoded bytes");
        let dump = write_dump(
            HIIDB,
            &decoded,
            live.path(),
            &dir,
            EfivarRedaction::DecodedBytes,
        )
        .expect("dump efivars");

        assert_eq!(
            dump,
            EfivarDump {
                copied: vec![efivar("Setup").to_string()],
                missing: vec![efivar("Absent").to_string()],
            },
            "dump"
        );
        assert_eq!(
            fs::read(dir.join(efivar("Setup"))).expect("read the dumped file"),
            [7, 0, 0, 0, 1, 0],
            "dumped Setup: its question's byte"
        );
        assert_eq!(
            answers(&root, &dir).first().map(String::as_str),
            Some("1"),
            "answer of Setup from the dump"
        );
        assert_eq!(
            answers(&root, &dir),
            answers(&root, live.path()),
            "answers from the source"
        );
    }

    /// The HiiDB of the offline fixtures: CHECKBOXes Fast Boot and Wake on LAN on bytes 0 and 1 of
    /// the EFI variable Setup, of 3 bytes.
    fn offline_hiidb() -> Vec<u8> {
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, 3),
                form(1, &[checkbox_at(1, 2, 1, 0), checkbox_at(2, 3, 1, 1)]),
            ]),
            en_strings_package_of(&["Offline", "Fast Boot", "Wake on LAN", "Help"]),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid([0x55; 16], &packages.concat())
    }

    /// The dump of tests/offline_golden.rs is what dump-efivars writes from offline_hiidb and
    /// its Setup, Fast Boot on, but for the version in the manifest, which readers ignore.
    /// UEFISETTINGS_BLESS=1 rewrites it.
    #[test]
    fn offline_fixtures_are_current() {
        let hiidb = offline_hiidb();
        let live = efivars(&[(&efivar("Setup"), &[7, 0, 0, 0, 1, 0, 0xAA])]);
        let (_parent, dir) = dump_dir();
        let decoded =
            decoded_bytes(read_db(&hiidb).expect("parse the HiiDB")).expect("find decoded bytes");
        write_dump(
            &hiidb,
            &decoded,
            live.path(),
            &dir,
            EfivarRedaction::DecodedBytes,
        )
        .expect("dump efivars");
        let fixture = Path::new(OFFLINE_FIXTURES).join("dump");

        if blesses(std::env::var_os(BLESS).as_deref()) {
            match fs::remove_dir_all(&fixture) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => panic!("remove {}: {error}", fixture.display()),
            }
            fs::create_dir_all(&fixture).expect("create the fixture directory");
            for name in file_names(&dir) {
                fs::copy(dir.join(&name), fixture.join(&name)).expect("copy a fixture");
            }
            return;
        }
        assert_eq!(
            file_names(&fixture),
            file_names(&dir),
            "files of {}; {BLESS}=1 rewrites them",
            fixture.display()
        );
        for name in file_names(&dir) {
            let read = |dir: &Path| fs::read(dir.join(&name)).expect("read a dump file");
            let (fixed, written) = (read(&fixture), read(&dir));
            match name.as_str() {
                DUMP_MANIFEST => assert_eq!(
                    unversioned(&fixed),
                    unversioned(&written),
                    "{name}; {BLESS}=1 rewrites it"
                ),
                _ => assert_eq!(fixed, written, "{name}; {BLESS}=1 rewrites it"),
            }
        }
    }

    /// The DUMP_MANIFEST `json` without the version of the uefisettings that wrote it.
    fn unversioned(json: &[u8]) -> serde_json::Value {
        let mut manifest: serde_json::Value =
            serde_json::from_slice(json).expect("parse the manifest");
        let version = manifest
            .as_object_mut()
            .and_then(|fields| fields.remove("uefisettings"));
        assert!(
            version.is_some(),
            "a manifest without a version: {manifest}"
        );
        manifest
    }
}
