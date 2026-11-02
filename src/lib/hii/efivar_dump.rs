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

use std::io::Read;
use std::path::Path;
use std::path::PathBuf;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use serde::Deserialize;
use serde::Serialize;

use crate::hii::efivarfs_format::open_regular_file;
use crate::hii::package::db_file::read_db_bytes;
use crate::hii::package::db_file::read_db_file;
use crate::hii::variables::EfivarSource;

// what dump-efivars needs: this machine's efivarfs
#[cfg(target_os = "linux")]
mod write;

#[cfg(target_os = "linux")]
pub(crate) use write::dump_efivars;
#[cfg(target_os = "linux")]
pub use write::EfivarDump;

/// The file of an efivars dump that holds the HiiDB that its efivars were dumped with.
const DUMP_HIIDB: &str = "hiidb.bin";
/// The file of an efivars dump that describes it: a DumpManifest as JSON.
const DUMP_MANIFEST: &str = "uefisettings-dump.json";
/// The DumpManifest::format that this uefisettings writes and reads. Any change that a reader of
/// it would misread bumps it; readers ignore unknown fields and never act on uefisettings.
const DUMP_FORMAT: u32 = 1;
/// What errors call a file of an efivars dump.
const DUMP_FILE_NOUN: &str = "efivars dump file";
/// The largest DUMP_MANIFEST that SavedDump::open reads, far above the ~80 bytes of format 1.
const MAX_MANIFEST_SIZE: u64 = 64 * 1024;

/// Which bytes of an efivar file a dump keeps.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum EfivarRedaction {
    /// The attributes field and the payload bytes that questions decode; the others become zero.
    #[default]
    DecodedBytes,
    /// Every byte.
    Unredacted,
}

/// What an efivars dump records about itself in DUMP_MANIFEST.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DumpManifest {
    /// The DUMP_FORMAT of the uefisettings that wrote the dump
    format: u32,
    /// The version of the uefisettings that wrote the dump
    uefisettings: String,
    /// Which bytes of each efivar file the dump keeps
    redaction: EfivarRedaction,
}

impl DumpManifest {
    /// The manifest in `json`, which must be of DUMP_FORMAT: a later format may mean anything.
    fn parse(json: &[u8]) -> Result<Self> {
        /// The field that every format has
        #[derive(Deserialize)]
        struct Format {
            format: u32,
        }

        let Format { format } = serde_json::from_slice(json)?;
        if format != DUMP_FORMAT {
            return Err(anyhow!(
                "format {format}, which this uefisettings does not read: it reads format \
                 {DUMP_FORMAT}"
            ));
        }
        Ok(serde_json::from_slice(json)?)
    }
}

/// An efivars dump in a directory, which its DUMP_MANIFEST describes.
#[derive(Debug)]
pub(crate) struct SavedDump {
    dir: PathBuf,
    manifest: DumpManifest,
}

impl SavedDump {
    /// The dump in `dir`, or None if `dir` has no DUMP_MANIFEST, as a directory of efivar files
    /// that no dump wrote.
    pub(crate) fn open(dir: &Path) -> Result<Option<Self>> {
        let path = dir.join(DUMP_MANIFEST);
        let Some(file) = open_regular_file(&path, DUMP_FILE_NOUN)? else {
            return Ok(None);
        };
        // one byte past the maximum, so that a longer manifest shows
        let mut file = Read::take(file, MAX_MANIFEST_SIZE + 1);
        let mut json = Vec::new();
        file.read_to_end(&mut json)
            .with_context(|| format!("failed to read {DUMP_FILE_NOUN} '{}'", path.display()))?;
        if file.limit() == 0 {
            return Err(anyhow!(
                "{DUMP_FILE_NOUN} '{}' is longer than its maximum of {MAX_MANIFEST_SIZE} bytes",
                path.display()
            ));
        }
        let manifest = DumpManifest::parse(&json)
            .with_context(|| format!("failed to parse {DUMP_FILE_NOUN} '{}'", path.display()))?;
        Ok(Some(Self {
            dir: dir.to_path_buf(),
            manifest,
        }))
    }

    /// Reads the HiiDB that this dump saved in DUMP_HIIDB.
    fn read_hiidb(&self) -> Result<Vec<u8>> {
        let path = self.dir.join(DUMP_HIIDB);
        let mut file = open_regular_file(&path, DUMP_FILE_NOUN)?
            .ok_or_else(|| anyhow!("efivars dump '{}' has no {DUMP_HIIDB}", self.dir.display()))?;
        read_db_bytes(&mut file)
            .with_context(|| format!("failed to read {DUMP_FILE_NOUN} '{}'", path.display()))
    }

    /// Fails if this dump zeroes the bytes that no question of its own HiiDB decodes and
    /// `hiidb`, the HiiDB at `path`, is another: its other questions would read zeros as values.
    fn check_hiidb(&self, hiidb: &[u8], path: &Path) -> Result<()> {
        match self.manifest.redaction {
            EfivarRedaction::Unredacted => Ok(()),
            EfivarRedaction::DecodedBytes if self.read_hiidb()? == hiidb => Ok(()),
            EfivarRedaction::DecodedBytes => Err(anyhow!(
                "'{}' is not the HiiDB that the efivars dump '{}' was dumped with, and that dump \
                 is redacted to the bytes that its own HiiDB's questions decode, so other \
                 questions would read zeros as values",
                path.display(),
                self.dir.display()
            )),
        }
    }

    /// Reads the HiiDB that get, list-questions and show-ifr read with `efivars`, if one is given:
    /// the file `filename`, else the one that an efivars dump in `efivars` saved. A redacted dump
    /// refuses another `filename`, whose questions would read its zeros as values.
    pub(crate) fn read_given_hiidb(
        filename: Option<&Path>,
        efivars: &EfivarSource,
    ) -> Result<Option<Vec<u8>>> {
        let dump = match efivars {
            EfivarSource::Directory(dir) => Self::open(dir)?,
            #[cfg(system_variables)]
            EfivarSource::System => None,
            EfivarSource::Disabled => None,
        };
        match (filename, dump) {
            (Some(filename), None) => read_db_file(filename).map(Some),
            (Some(filename), Some(dump)) => {
                let hiidb = read_db_file(filename)?;
                dump.check_hiidb(&hiidb, filename)?;
                Ok(Some(hiidb))
            }
            (None, Some(dump)) => dump.read_hiidb().map(Some),
            (None, None) => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use tempfile::TempDir;

    use super::write::write_dump;
    use super::*;
    use crate::hii::efivarfs_format::tests::FIRST_STEP;
    use crate::hii::efivarfs_format::tests::SETUP;
    use crate::hii::efivarfs_format::EfivarFileName;
    use crate::hii::forms::ifr_fixtures::NIL_GUID;
    use crate::hii::variables::DecodedValue;

    /// The HiiDB that write_dump saves; it does not parse it.
    pub(super) const HIIDB: &[u8] = b"a HiiDB";

    /// The efivar file name of the variable `name` of the nil GUID.
    pub(super) fn efivar(name: &str) -> EfivarFileName {
        EfivarFileName::new(name, NIL_GUID)
    }

    /// A directory holding the efivar file of each (name, contents), as efivarfs does.
    pub(super) fn efivars(files: &[(&EfivarFileName, &[u8])]) -> TempDir {
        let dir = tempfile::tempdir().expect("create efivars directory");
        for (name, contents) in files {
            fs::write(dir.path().join(name), contents).expect("write efivar file");
        }
        dir
    }

    /// A directory to dump into, as "dump" in a new directory, which does not exist yet.
    pub(super) fn dump_dir() -> (TempDir, PathBuf) {
        let parent = tempfile::tempdir().expect("create parent directory");
        let dir = parent.path().join("dump");
        (parent, dir)
    }

    /// `names`, each decoded at its first payload byte, of a 1-byte VarStore.
    pub(super) fn first_bytes(
        names: &[&EfivarFileName],
    ) -> BTreeMap<EfivarFileName, Vec<DecodedValue>> {
        names
            .iter()
            .map(|&name| {
                (
                    name.clone(),
                    vec![DecodedValue {
                        size: 1,
                        value: 0..1,
                    }],
                )
            })
            .collect()
    }

    /// efivarfs names each file `<name>-<GUID>` (Linux v7.2 fs/efivarfs/vars.c
    /// efivar_get_utf8name()), as EfivarFileName does, so no efivar file has the name of a file
    /// that a dump adds.
    #[test]
    fn dump_files_are_no_efivar_file_names() {
        let ends_with_guid = |name: &str| {
            let groups: Vec<&str> = name.rsplitn(6, '-').collect();
            groups.len() == 6
                && groups
                    .iter()
                    .take(5)
                    .rev()
                    .map(|group| group.len())
                    .eq([8, 4, 4, 4, 12])
                && groups
                    .iter()
                    .take(5)
                    .all(|group| group.chars().all(|c| c.is_ascii_hexdigit()))
        };

        assert!(
            ends_with_guid(&efivar("Setup").to_string()),
            "an efivar file name ends with -<GUID>"
        );
        for name in [DUMP_HIIDB, DUMP_MANIFEST] {
            assert!(!ends_with_guid(name), "{name}");
        }
    }

    /// A dump of SETUP into a new directory, as `redaction` says.
    fn saved_dump(redaction: EfivarRedaction) -> (TempDir, PathBuf) {
        let live = efivars(&[(&efivar("Setup"), &SETUP)]);
        let (parent, dir) = dump_dir();
        write_dump(
            HIIDB,
            &first_bytes(&[&efivar("Setup")]),
            live.path(),
            &dir,
            redaction,
        )
        .expect("dump efivars");
        (parent, dir)
    }

    #[test]
    fn saved_dump_reads_its_hiidb() {
        for (case, redaction) in [
            ("redacted", EfivarRedaction::DecodedBytes),
            ("unredacted", EfivarRedaction::Unredacted),
        ] {
            let (_parent, dir) = saved_dump(redaction);

            let dump = SavedDump::open(&dir)
                .unwrap_or_else(|error| panic!("{case}: open the dump: {error:#}"))
                .unwrap_or_else(|| panic!("{case}: no dump"));

            assert_eq!(
                dump.read_hiidb()
                    .unwrap_or_else(|error| panic!("{case}: read the HiiDB: {error:#}")),
                HIIDB,
                "{case}: HiiDB"
            );
        }
    }

    /// A directory without a DUMP_MANIFEST holds plain efivar files, even with a DUMP_HIIDB.
    #[test]
    fn directory_without_a_manifest_is_no_dump() {
        let dir = efivars(&[(&efivar("Setup"), &SETUP)]);
        fs::write(dir.path().join(DUMP_HIIDB), HIIDB).expect("write a HiiDB");

        let dump = SavedDump::open(dir.path()).expect("open the directory");

        assert!(
            dump.is_none(),
            "a directory with a hiidb.bin and no manifest opened as a dump: {dump:?}"
        );
    }

    /// A DUMP_MANIFEST that is not of this format is an error, never plain efivar files: a later
    /// format may keep other bytes of them.
    #[test]
    fn saved_dump_refuses_a_manifest_of_another_format() {
        for (case, json, want) in [
            ("not JSON", "{", "EOF while parsing an object"),
            (
                "an earlier format",
                r#"{"format": 0, "uefisettings": "0.1.6", "redaction": "unredacted"}"#,
                "format 0, which this uefisettings does not read: it reads format 1",
            ),
            (
                "a later format",
                r#"{"format": 2, "redaction": "all-but-passwords"}"#,
                "format 2, which this uefisettings does not read: it reads format 1",
            ),
            (
                "no format",
                r#"{"uefisettings": "0.1.6", "redaction": "unredacted"}"#,
                "missing field `format`",
            ),
            (
                "an unknown redaction",
                r#"{"format": 1, "uefisettings": "0.1.6", "redaction": "all-but-passwords"}"#,
                "unknown variant `all-but-passwords`",
            ),
            (
                "no version",
                r#"{"format": 1, "redaction": "unredacted"}"#,
                "missing field `uefisettings`",
            ),
        ] {
            let (_parent, dir) = saved_dump(EfivarRedaction::DecodedBytes);
            let path = dir.join(DUMP_MANIFEST);
            fs::write(&path, json).expect("write the manifest");

            let error = SavedDump::open(&dir).expect_err(case);

            let error = format!("{error:#}");
            let context = format!("failed to parse efivars dump file '{}': ", path.display());
            assert!(
                error.starts_with(&context) && error.contains(want),
                "{case}: {error}"
            );
        }
    }

    /// SavedDump opens its files as open_efivar does: it refuses a symlink, or another file that
    /// is not regular, without opening it.
    #[test]
    fn saved_dump_opens_no_file_that_is_not_regular() {
        /// What takes the place of a file of the dump
        #[derive(Debug, Clone, Copy)]
        enum NotRegular {
            Directory,
            Symlink,
            Fifo,
        }

        for (not_regular, name) in [
            (NotRegular::Directory, DUMP_MANIFEST),
            (NotRegular::Symlink, DUMP_MANIFEST),
            (NotRegular::Fifo, DUMP_MANIFEST),
            (NotRegular::Symlink, DUMP_HIIDB),
        ] {
            let case = format!("{not_regular:?} as {name}");
            let (_parent, dir) = saved_dump(EfivarRedaction::DecodedBytes);
            let path = dir.join(name);
            let moved = dir.join("moved");
            fs::rename(&path, &moved).expect("move the file");
            let _writer = match not_regular {
                NotRegular::Directory => {
                    fs::create_dir(&path).expect("create a directory");
                    None
                }
                NotRegular::Fifo => {
                    nix::unistd::mkfifo(&path, nix::sys::stat::Mode::S_IRWXU)
                        .expect("create a FIFO");
                    // a writer, so that an open of the FIFO that is not O_PATH returns instead of
                    // blocking
                    Some(
                        fs::OpenOptions::new()
                            .read(true)
                            .write(true)
                            .open(&path)
                            .expect("hold the FIFO open"),
                    )
                }
                NotRegular::Symlink => {
                    // to the file itself, which a dump that follows symlinks reads
                    std::os::unix::fs::symlink(&moved, &path).expect("create a symlink");
                    None
                }
            };

            let read = SavedDump::open(&dir).and_then(|dump| match dump {
                Some(dump) => dump.read_hiidb(),
                None => panic!("{case}: no dump"),
            });

            assert_eq!(
                read.map_err(|error| format!("{error:#}")),
                Err(format!(
                    "efivars dump file '{}' is not a regular file",
                    path.display()
                )),
                "{case}"
            );
        }
    }

    /// A DUMP_MANIFEST that cannot be opened is an error, never plain efivar files.
    #[test]
    fn saved_dump_refuses_a_manifest_that_cannot_be_opened() {
        let file = tempfile::NamedTempFile::new().expect("create a file");

        let error = SavedDump::open(file.path()).expect_err("open a dump in a file");

        assert_eq!(
            format!("{error:#}"),
            format!(
                "failed to {FIRST_STEP} efivars dump file '{}': Not a directory (os error 20)",
                file.path().join(DUMP_MANIFEST).display()
            ),
            "a dump directory that is a regular file"
        );
    }

    /// A DUMP_MANIFEST of MAX_MANIFEST_SIZE bytes opens; one byte longer, it is refused for its
    /// size, unparsed, though whole it would parse.
    #[test]
    fn saved_dump_refuses_a_manifest_longer_than_its_maximum_size() {
        let (_parent, dir) = saved_dump(EfivarRedaction::DecodedBytes);
        let path = dir.join(DUMP_MANIFEST);
        let max = usize::try_from(MAX_MANIFEST_SIZE).expect("a usize size");
        let manifest = r#"{"format": 1, "uefisettings": "0.1.6", "redaction": "unredacted"}"#;
        // format! widths stop at u16::MAX, below MAX_MANIFEST_SIZE
        let padded = |size: usize| format!("{manifest}{}", " ".repeat(size - manifest.len()));

        fs::write(&path, padded(max)).expect("write a manifest of the maximum size");
        let dump = SavedDump::open(&dir)
            .expect("open a dump whose manifest has the maximum size")
            .expect("a dump");
        assert_eq!(
            dump.manifest.redaction,
            EfivarRedaction::Unredacted,
            "a manifest padded to MAX_MANIFEST_SIZE"
        );

        fs::write(&path, padded(max + 1))
            .expect("write a manifest one byte longer than the maximum");
        let error = SavedDump::open(&dir).expect_err("open a dump whose manifest is too long");
        assert_eq!(
            format!("{error:#}"),
            format!(
                "efivars dump file '{}' is longer than its maximum of {MAX_MANIFEST_SIZE} bytes",
                path.display()
            ),
            "a manifest padded past MAX_MANIFEST_SIZE"
        );
    }

    /// A DUMP_MANIFEST of DUMP_FORMAT with a field that this uefisettings does not know opens:
    /// readers ignore unknown fields.
    #[test]
    fn saved_dump_ignores_unknown_manifest_fields() {
        let (_parent, dir) = saved_dump(EfivarRedaction::DecodedBytes);
        fs::write(
            dir.join(DUMP_MANIFEST),
            r#"{"format": 1, "uefisettings": "0.1.6", "redaction": "unredacted", "later": 1}"#,
        )
        .expect("write the manifest");

        let dump = SavedDump::open(&dir)
            .expect("open a dump whose manifest has an unknown field")
            .expect("a dump");

        assert_eq!(
            dump.manifest.redaction,
            EfivarRedaction::Unredacted,
            "redaction of a manifest with an unknown field"
        );
    }

    #[test]
    fn saved_dump_without_its_hiidb_is_an_error() {
        let (_parent, dir) = saved_dump(EfivarRedaction::DecodedBytes);
        fs::remove_file(dir.join(DUMP_HIIDB)).expect("remove the HiiDB");
        let dump = SavedDump::open(&dir)
            .expect("open the dump")
            .expect("a dump");

        let error = dump.read_hiidb().expect_err("read a missing HiiDB");

        assert_eq!(
            format!("{error:#}"),
            format!("efivars dump '{}' has no hiidb.bin", dir.display()),
            "error"
        );
    }

    /// A redacted dump answers as its source only with its own HiiDB: the questions of another
    /// would read the bytes it zeroes as values. An unredacted dump zeroes none.
    #[test]
    fn redacted_dump_refuses_another_hiidb() {
        let another: &[u8] = b"another HiiDB";
        for (case, redaction, hiidb, refused) in [
            (
                "redacted, its HiiDB",
                EfivarRedaction::DecodedBytes,
                HIIDB,
                false,
            ),
            (
                "redacted, another HiiDB",
                EfivarRedaction::DecodedBytes,
                another,
                true,
            ),
            (
                "unredacted, another HiiDB",
                EfivarRedaction::Unredacted,
                another,
                false,
            ),
        ] {
            let (_parent, dir) = saved_dump(redaction);
            let dump = SavedDump::open(&dir)
                .expect("open the dump")
                .expect("a dump");

            let checked = dump.check_hiidb(hiidb, Path::new("hiidb.bin"));

            assert_eq!(
                checked.err().map(|error| format!("{error:#}")),
                refused.then(|| format!(
                    "'hiidb.bin' is not the HiiDB that the efivars dump '{}' was dumped with, and \
                     that dump is redacted to the bytes that its own HiiDB's questions decode, so \
                     other questions would read zeros as values",
                    dir.display()
                )),
                "{case}"
            );
        }
    }

    /// read_given_hiidb reads `filename` if given, else the HiiDB that an efivars dump saved, else
    /// none; a redacted dump refuses another `filename`.
    #[test]
    fn read_given_hiidb_reads_the_file_or_the_dump() {
        let dump = |redaction: &str| {
            let dir = tempfile::tempdir().expect("create a dump directory");
            fs::write(dir.path().join(DUMP_HIIDB), b"saved HiiDB").expect("write the HiiDB");
            fs::write(
                dir.path().join(DUMP_MANIFEST),
                format!(r#"{{"format": 1, "uefisettings": "0.1.6", "redaction": "{redaction}"}}"#),
            )
            .expect("write the manifest");
            dir
        };
        let (redacted, unredacted) = (dump("decoded-bytes"), dump("unredacted"));
        let plain = tempfile::tempdir().expect("create an efivars directory");
        fs::write(plain.path().join(DUMP_HIIDB), b"saved HiiDB").expect("write a HiiDB");
        let files = tempfile::tempdir().expect("create a directory");
        let (saved, other) = (
            files.path().join("saved.bin"),
            files.path().join("other.bin"),
        );
        fs::write(&saved, b"saved HiiDB").expect("write the saved HiiDB");
        fs::write(&other, b"other HiiDB").expect("write another HiiDB");
        let directory = |dir: &tempfile::TempDir| EfivarSource::Directory(dir.path().to_path_buf());
        let refused = format!(
            "'{}' is not the HiiDB that the efivars dump '{}' was dumped with",
            other.display(),
            redacted.path().display()
        );

        let cases = [
            (
                "a dump",
                None,
                directory(&redacted),
                Ok(Some("saved HiiDB")),
            ),
            (
                "the HiiDB of a redacted dump",
                Some(&saved),
                directory(&redacted),
                Ok(Some("saved HiiDB")),
            ),
            (
                "another HiiDB, an unredacted dump",
                Some(&other),
                directory(&unredacted),
                Ok(Some("other HiiDB")),
            ),
            (
                "a HiiDB, a directory without a manifest",
                Some(&other),
                directory(&plain),
                Ok(Some("other HiiDB")),
            ),
            (
                "a HiiDB, no efivars",
                Some(&other),
                EfivarSource::Disabled,
                Ok(Some("other HiiDB")),
            ),
            (
                "no HiiDB, a directory without a manifest",
                None,
                directory(&plain),
                Ok(None),
            ),
            (
                "no HiiDB, no efivars",
                None,
                EfivarSource::Disabled,
                Ok(None),
            ),
            (
                "another HiiDB, a redacted dump",
                Some(&other),
                directory(&redacted),
                Err(&refused),
            ),
        ];
        #[cfg(system_variables)]
        let cases = cases.into_iter().chain([(
            "a HiiDB, efivarfs",
            Some(&other),
            EfivarSource::System,
            Ok(Some("other HiiDB")),
        )]);

        for (case, filename, efivars, want) in cases {
            let got = SavedDump::read_given_hiidb(filename.map(|path| path.as_path()), &efivars);

            match (got, want) {
                (Ok(db), Ok(want)) => assert_eq!(db.as_deref(), want.map(str::as_bytes), "{case}"),
                (Err(error), Err(want)) => {
                    assert!(format!("{error:#}").starts_with(want), "{case}: {error:#}")
                }
                (got, want) => panic!(
                    "{case}: got {:?}, want {want:?}",
                    got.map_err(|error| format!("{error:#}"))
                ),
            }
        }
    }
}
