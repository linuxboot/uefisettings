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

use std::collections::BTreeMap;
use std::fs;
use std::fs::DirBuilder;
use std::fs::OpenOptions;
use std::io;
use std::io::Read;
use std::io::Write;
use std::os::unix::fs::DirBuilderExt;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::path::PathBuf;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use log::warn;
use serde::Deserialize;
use serde::Serialize;

use crate::hii::efivarfs::open_efivar;
use crate::hii::efivarfs::open_regular_file;
use crate::hii::efivarfs::DecodedValue;
use crate::hii::efivarfs::EfivarFileName;
use crate::hii::efivarfs::EfivarNotFound;
use crate::hii::efivarfs::EfivarReader;
use crate::hii::efivarfs::EfivarSource;
use crate::hii::efivarfs::EFIVARFS_HEADER_SIZE;
use crate::hii::efivarfs::EFIVARS_MOUNT_POINT;
use crate::hii::forms::list_questions;
use crate::hii::forms::IncludedStates;
use crate::hii::package::read_db;
use crate::hii::package::read_db_bytes;
use crate::hii::package::ParsedPackageList;

/// The largest efivar file that read_efivar_file reads, far above EDK2's largest EFI variables:
/// PcdMaxVariableSize is 0x400 by default (MdeModulePkg.dec) and 0x8400 in a 4 MiB OVMF
/// (OvmfPkgX64.dsc), as of edk2-stable202508.
const MAX_EFIVAR_FILE_SIZE: u64 = 16 * 1024 * 1024;
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

/// The efivar files that a dump copied, and those that its questions read but do not exist.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct EfivarDump {
    /// The names of the efivar files copied into the dump directory
    pub copied: Vec<String>,
    /// The names of the efivar files that questions read but this machine's efivarfs lacks
    pub missing: Vec<String>,
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
    pub(crate) fn read_hiidb(&self) -> Result<Vec<u8>> {
        let path = self.dir.join(DUMP_HIIDB);
        let mut file = open_regular_file(&path, DUMP_FILE_NOUN)?
            .ok_or_else(|| anyhow!("efivars dump '{}' has no {DUMP_HIIDB}", self.dir.display()))?;
        read_db_bytes(&mut file)
            .with_context(|| format!("failed to read {DUMP_FILE_NOUN} '{}'", path.display()))
    }

    /// Fails if this dump zeroes the bytes that no question of its own HiiDB decodes and
    /// `hiidb`, the HiiDB at `path`, is another: its other questions would read zeros as values.
    pub(crate) fn check_hiidb(&self, hiidb: &[u8], path: &Path) -> Result<()> {
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
}

/// Copies the efivar files that the questions of the HiiDB `db_bytes` read from this machine's
/// efivarfs into the new directory `dir`, as `redaction` says, with the HiiDB and a manifest.
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
/// file, found without reading any.
fn decoded_bytes(
    package_lists: Vec<ParsedPackageList>,
) -> Result<BTreeMap<EfivarFileName, Vec<DecodedValue>>> {
    let mut reader = EfivarReader::new(EfivarSource::Disabled)?;
    for list in package_lists {
        list.check_form_strings()?;
        for root in list.forms {
            list_questions(root, &list.strings, IncludedStates::all(), &mut reader);
        }
    }
    Ok(reader.decoded)
}

/// Copies the efivar files that `decoded` names from `efivars` into the new directory `dir`,
/// keeping, as `redaction` says, only their `decoded` payload bytes, and saves `hiidb`, which
/// `decoded` comes from, as DUMP_HIIDB and then the DUMP_MANIFEST.
fn write_dump(
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
        let bytes = file
            .metadata()
            .and_then(|metadata| read_efivar_file(&file, metadata.len()))
            .with_context(|| {
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

/// The bytes of the efivar `file`, of `size` bytes by its metadata, in one read() unless it grew
/// since: each efivarfs read() reads the whole variable from the firmware (Linux v7.2
/// fs/efivarfs/file.c efivarfs_file_read()). A file of more than MAX_EFIVAR_FILE_SIZE bytes, by
/// its metadata or as read, is an error.
fn read_efivar_file<R: Read>(file: R, size: u64) -> io::Result<Vec<u8>> {
    if size > MAX_EFIVAR_FILE_SIZE {
        return Err(efivar_file_too_large());
    }
    // one byte past the maximum, so that a file that grew past it shows
    let mut file = file.take(MAX_EFIVAR_FILE_SIZE + 1);
    let size = usize::try_from(size).map_err(io::Error::other)?;
    // one byte more than its size, so that a read() that fills it shows the file grew
    let capacity = size.saturating_add(1);
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(capacity)?;
    bytes.resize(capacity, 0);
    let read = loop {
        match file.read(&mut bytes) {
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            result => break result?,
        }
    };
    bytes.truncate(read);
    if read > size {
        file.read_to_end(&mut bytes)?;
    }
    if file.limit() == 0 {
        return Err(efivar_file_too_large());
    }
    Ok(bytes)
}

/// read_efivar_file's error for a file of more than MAX_EFIVAR_FILE_SIZE bytes.
fn efivar_file_too_large() -> io::Error {
    io::Error::new(
        io::ErrorKind::FileTooLarge,
        format!("longer than its maximum of {MAX_EFIVAR_FILE_SIZE} bytes"),
    )
}

/// The efivar file `bytes` with each payload byte zeroed unless one of `values` decodes it from
/// these bytes.
fn keep_decoded(bytes: &[u8], values: &[DecodedValue]) -> Vec<u8> {
    let mut kept = vec![0; bytes.len()];
    let payload = values
        .iter()
        .filter(|decoded| decoded.decodes_from(bytes.len()))
        .map(|decoded| {
            EFIVARFS_HEADER_SIZE + decoded.value.start..EFIVARFS_HEADER_SIZE + decoded.value.end
        });
    for range in std::iter::once(0..EFIVARFS_HEADER_SIZE).chain(payload) {
        let end = range.end.min(bytes.len());
        let start = range.start.min(end);
        if let (Some(to), Some(from)) = (kept.get_mut(start..end), bytes.get(start..end)) {
            to.copy_from_slice(from);
        }
    }
    kept
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
    use std::collections::HashMap;
    use std::collections::VecDeque;
    use std::fs::File;
    use std::io::Cursor;
    use std::os::unix::fs::PermissionsExt;
    use std::rc::Rc;

    use tempfile::TempDir;

    use super::*;
    use crate::hii::forms::handle_form_set;
    use crate::hii::forms::ifr_fixtures::checkbox;
    use crate::hii::forms::ifr_fixtures::checkbox_on;
    use crate::hii::forms::ifr_fixtures::conditional;
    use crate::hii::forms::ifr_fixtures::form;
    use crate::hii::forms::ifr_fixtures::form_set;
    use crate::hii::forms::ifr_fixtures::ifr_true;
    use crate::hii::forms::ifr_fixtures::operation;
    use crate::hii::forms::ifr_fixtures::parse_form_set;
    use crate::hii::forms::ifr_fixtures::var_store_efi;
    use crate::hii::forms::ifr_fixtures::CHECKBOX;
    use crate::hii::forms::ifr_fixtures::NIL_GUID;
    use crate::hii::forms::ifr_fixtures::NV_BS_RT;
    use crate::hii::forms::ifr_fixtures::SUPPRESS_IF;
    use crate::hii::forms::IFROperation;

    /// Attributes 7, then payload bytes 1 to 10.
    const SETUP: [u8; 14] = [7, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
    /// SETUP's size, as its metadata gives it.
    const SETUP_SIZE: u64 = SETUP.len() as u64;
    /// The HiiDB that write_dump saves; it does not parse it.
    const HIIDB: &[u8] = b"a HiiDB";

    /// The efivar file name of the variable `name` of the nil GUID.
    fn efivar(name: &str) -> EfivarFileName {
        EfivarFileName::new(name, NIL_GUID)
    }

    /// A directory holding the efivar file of each (name, contents), as efivarfs does.
    fn efivars(files: &[(&EfivarFileName, &[u8])]) -> TempDir {
        let dir = tempfile::tempdir().expect("create efivars directory");
        for (name, contents) in files {
            fs::write(dir.path().join(name), contents).expect("write efivar file");
        }
        dir
    }

    /// A directory to dump into, as "dump" in a new directory, which does not exist yet.
    fn dump_dir() -> (TempDir, PathBuf) {
        let parent = tempfile::tempdir().expect("create parent directory");
        let dir = parent.path().join("dump");
        (parent, dir)
    }

    /// `names`, each decoded at its first payload byte, of a 1-byte VarStore.
    fn first_bytes(names: &[&EfivarFileName]) -> BTreeMap<EfivarFileName, Vec<DecodedValue>> {
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

    /// The package list of `root`, with no strings.
    fn package_list(root: &Rc<RefCell<IFROperation>>) -> ParsedPackageList {
        ParsedPackageList {
            guid: NIL_GUID,
            strings: vec![HashMap::new()],
            forms: vec![Rc::clone(root)],
        }
    }

    /// The answers and states that list_questions gives for the questions of `root`,
    /// reading the efivar files in `efivars`.
    fn answers(root: &Rc<RefCell<IFROperation>>, efivars: &Path) -> Vec<String> {
        let source = EfivarSource::Directory(efivars.to_path_buf());
        list_questions(
            Rc::clone(root),
            &[HashMap::new()],
            IncludedStates::all(),
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
    fn efivar_files_read_whole() {
        let live = efivars(&[(&efivar("Setup"), &SETUP), (&efivar("Empty"), &[])]);
        let read = |name: &EfivarFileName| {
            let file = File::open(live.path().join(name)).expect("open the efivar file");
            let size = file.metadata().expect("stat the efivar file").len();
            read_efivar_file(&file, size).expect("read the efivar file")
        };

        assert_eq!(read(&efivar("Setup")), SETUP, "Setup");
        assert_eq!(read(&efivar("Empty")), [0; 0], "empty file");
    }

    /// A file longer than its metadata says, as an efivar written after open_efivar's fstat,
    /// still reads whole: procfs gives /proc/version the size 0.
    #[test]
    fn efivar_files_longer_than_their_size_read_whole() {
        let path = Path::new("/proc/version");
        let file = File::open(path).expect("open /proc/version");
        let size = file.metadata().expect("stat /proc/version").len();
        assert_eq!(size, 0, "size");

        let bytes = read_efivar_file(&file, size).expect("read /proc/version");

        assert!(bytes.len() > 1, "/proc/version: {bytes:?}");
        assert_eq!(
            bytes,
            fs::read(path).expect("read /proc/version"),
            "contents"
        );
    }

    /// A reader that gives one of `results` per read(), then end of file, counting its read()s.
    struct ScriptedReader {
        results: VecDeque<io::Result<Vec<u8>>>,
        reads: usize,
    }

    impl ScriptedReader {
        fn new(results: Vec<io::Result<Vec<u8>>>) -> Self {
            Self {
                results: results.into(),
                reads: 0,
            }
        }
    }

    impl Read for ScriptedReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.reads += 1;
            let chunk = match self.results.pop_front() {
                None => return Ok(0),
                Some(result) => result?,
            };
            buf.get_mut(..chunk.len())
                .expect("the scripted chunk fits the read() buffer")
                .copy_from_slice(&chunk);
            Ok(chunk.len())
        }
    }

    #[test]
    fn efivar_file_reads_in_one_read() {
        let whole: &[u8] = &SETUP;
        for (case, results, expected) in [
            ("whole", vec![Ok(SETUP.to_vec())], whole),
            (
                "short read, as end of file",
                vec![Ok(SETUP[..6].to_vec()), Ok(SETUP[6..].to_vec())],
                &SETUP[..6],
            ),
        ] {
            let mut reader = ScriptedReader::new(results);

            let bytes = read_efivar_file(&mut reader, SETUP_SIZE).expect("read the efivar file");

            assert_eq!(bytes, expected, "{case}: bytes");
            assert_eq!(reader.reads, 1, "{case}: read() calls");
        }
    }

    #[test]
    fn efivar_file_read_retries_eintr() {
        let mut reader = ScriptedReader::new(vec![
            Err(io::ErrorKind::Interrupted.into()),
            Ok(SETUP.to_vec()),
        ]);

        let bytes = read_efivar_file(&mut reader, SETUP_SIZE).expect("read the efivar file");

        assert_eq!(bytes, SETUP, "bytes");
        assert_eq!(
            reader.reads, 2,
            "read() calls: the interrupted one and the read"
        );
    }

    #[test]
    fn efivar_file_grown_since_its_metadata_reads_to_the_end() {
        let mut reader =
            ScriptedReader::new(vec![Ok(SETUP[..5].to_vec()), Ok(SETUP[5..].to_vec())]);

        let bytes = read_efivar_file(&mut reader, 4).expect("read the efivar file");

        assert_eq!(bytes, SETUP, "bytes");
        assert_eq!(
            reader.reads, 3,
            "read() calls: size + 1 bytes, the rest, end of file"
        );
    }

    /// A file of more than MAX_EFIVAR_FILE_SIZE bytes by its metadata is refused unread.
    #[test]
    fn efivar_file_larger_than_its_maximum_is_refused_unread() {
        let mut reader = ScriptedReader::new(vec![Ok(SETUP.to_vec())]);

        let error = read_efivar_file(&mut reader, MAX_EFIVAR_FILE_SIZE + 1)
            .expect_err("read a file larger than the maximum");

        assert_eq!(
            error.kind(),
            io::ErrorKind::FileTooLarge,
            "a file larger than the maximum by its metadata: {error}"
        );
        assert_eq!(reader.reads, 0, "read() calls");
    }

    /// A file that grew since its metadata reads to the end up to MAX_EFIVAR_FILE_SIZE bytes, and
    /// is refused once it holds more.
    #[test]
    fn efivar_file_grown_past_its_maximum_is_refused() {
        let max = usize::try_from(MAX_EFIVAR_FILE_SIZE).expect("a usize maximum");
        for (case, length, want) in [
            ("grown to the maximum", MAX_EFIVAR_FILE_SIZE, Some(max)),
            (
                "grown one byte past the maximum",
                MAX_EFIVAR_FILE_SIZE + 1,
                None,
            ),
        ] {
            let read = read_efivar_file(io::repeat(7).take(length), SETUP_SIZE);

            match (read, want) {
                (Ok(bytes), Some(want)) => assert_eq!(bytes.len(), want, "{case}: length"),
                (Err(error), None) => {
                    assert_eq!(error.kind(), io::ErrorKind::FileTooLarge, "{case}: {error}")
                }
                (read, want) => panic!(
                    "{case}: read {:?} bytes, want {want:?}",
                    read.map(|bytes| bytes.len())
                ),
            }
        }
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
                "failed to open efivars dump file '{}': Not a directory (os error 20)",
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
}
