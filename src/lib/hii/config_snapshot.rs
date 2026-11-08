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

//! The current configuration that firmware exports for the OS with ExportConfig() (UEFI 2.11
//! §33.2.11.1, §35.4.3), from which get, list-questions and show-ifr take the values of questions
//! whose variables are missing, such as those without runtime access. Set never reads it.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;
use std::ops::Range;
use std::rc::Rc;

use log::warn;
use thiserror::Error;

use crate::hii::config_string::BlockConfig;
use crate::hii::config_string::ConfigAltResp;
use crate::hii::config_string::ConfigElement;
use crate::hii::config_string::MultiConfigAltResp;
use crate::hii::config_string::Number;
use crate::hii::forms::PasswordQuestions;
use crate::hii::forms::UnresolvedPassword;
use crate::hii::package::DevicePath;
use crate::hii::package::Guid;
use crate::hii::package::ParsedPackageList;
use crate::hii::variables::EfivarReader;
use crate::hii::variables::VariableKey;
use crate::hii::variables::WithheldBytes;

/// ExportConfig()'s results as the firmware publishes them, a `<MultiConfigAltResp>`, which may
/// hold password bytes: Debug leaves the text out, and nothing else shows it.
pub(crate) struct ExportedConfig(String);

impl ExportedConfig {
    // only the builds that read the configuration table from Linux make one
    #[cfg(any(firmware_memory_maps, test))]
    pub(crate) fn new(text: String) -> Self {
        Self(text)
    }
}

impl fmt::Debug for ExportedConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExportedConfig").finish_non_exhaustive()
    }
}

/// The current values that an ExportedConfig holds for each storage, but no byte of a PASSWORD
/// question.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ConfigSnapshot {
    storages: BTreeMap<StorageKey, StorageValues>,
}

/// The storage that a `<ConfigHdr>` names: the device path of its driver's handle, and its GUID
/// and name, which is empty for name/value storage, as EDK2's SetupBrowserDxe
/// InitializeConfigHdr names it (edk2-stable202608 IfrParse.c).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct StorageKey {
    device_path: DevicePath,
    variable: VariableKey,
}

/// The values of one storage.
#[derive(Debug, Default, PartialEq, Eq)]
struct StorageValues {
    /// The bytes of its `<BlockConfig>`s
    buffer: SnapshotBuffer,
    /// The number of each `<NvConfig>` that holds one, by label
    numbers: BTreeMap<String, Number>,
}

/// The bytes of buffer storage that `<BlockConfig>`s set, by offset, and only those: a block
/// near the 0xFFFF block end takes as much memory as one at offset 0.
#[derive(Debug, Default, PartialEq, Eq)]
struct SnapshotBuffer(BTreeMap<usize, u8>);

impl SnapshotBuffer {
    /// Writes `block` over the bytes of earlier ones, as ConfigToBlock writes blocks in order
    /// (UEFI 2.11 §35.4.6), but its bytes `withheld`.
    fn write(&mut self, block: &BlockConfig, withheld: &[Range<usize>]) {
        self.0.extend(
            block
                .range()
                .zip(block.value().iter().copied())
                .filter(|(offset, _)| !withheld.iter().any(|bytes| bytes.contains(offset))),
        );
    }

    /// The bytes `range`, if blocks set every one.
    fn get(&self, range: Range<usize>) -> Option<Vec<u8>> {
        range.map(|offset| self.0.get(&offset).copied()).collect()
    }
}

impl ConfigSnapshot {
    /// The values of the `<ConfigResp>`s of `exported`, never of their ALTCFG blocks, which hold
    /// alternate configurations such as defaults (§35.4.3), without the bytes `withheld`,
    /// whatever their PATH. A `<ConfigAltResp>` that does not parse gives no values
    /// and hides no other (MultiConfigAltResp::parse_each); `exported` is refused when none
    /// parses. Why one does not parse stays out of the error and the log, as config_string's
    /// errors quote the text.
    pub(crate) fn parse(
        exported: &ExportedConfig,
        withheld: &WithheldBytes,
    ) -> Result<Self, SnapshotRefusal> {
        let mut snapshot = Self::default();
        // what ExportConfig() gives for a database of no storage
        if exported.0.is_empty() {
            return Ok(snapshot);
        }
        let resps = MultiConfigAltResp::parse_each(&exported.0);
        let unparsed = resps.iter().filter(|resp| resp.is_err()).count();
        if unparsed == resps.len() {
            return Err(SnapshotRefusal::NotMultiConfigAltResp);
        }
        if unparsed > 0 {
            warn!(
                "{unparsed} of the {} <ConfigAltResp>s of the ExportConfig snapshot do not parse, \
                 so their storages show no value from it",
                resps.len()
            );
        }
        for ConfigAltResp { resp, .. } in resps.iter().flatten() {
            // IFR VarStore names are ASCII (UEFI 2.11 §33.3.8.3.89, §33.3.8.3.91)
            let Ok(name) = String::from_utf16(&resp.header.name) else {
                continue;
            };
            let variable = VariableKey {
                name,
                guid: resp.header.guid,
            };
            let passwords = withheld.of(&variable);
            let key = StorageKey {
                device_path: resp.header.device_path.clone(),
                variable,
            };
            let values = snapshot.storages.entry(key).or_default();
            for element in &resp.body {
                match element {
                    ConfigElement::Block(block) => values.buffer.write(block, passwords),
                    ConfigElement::Nv(setting) => {
                        let label = setting.label().to_string();
                        match setting.number() {
                            Some(number) => values.numbers.insert(label, number),
                            None => values.numbers.remove(&label),
                        };
                    }
                }
            }
        }
        Ok(snapshot)
    }

    /// The values of the storage `variable` of the driver at `device_path`, if the snapshot
    /// holds any.
    fn storage(&self, device_path: &DevicePath, variable: VariableKey) -> Option<&StorageValues> {
        self.storages.get(&StorageKey {
            device_path: device_path.clone(),
            variable,
        })
    }

    /// The bytes `range` of the buffer storage `variable` of the driver at `device_path`, if the
    /// snapshot holds them.
    fn buffer(
        &self,
        device_path: &DevicePath,
        variable: &VariableKey,
        range: Range<usize>,
    ) -> Option<Vec<u8>> {
        self.storage(device_path, variable.clone())?
            .buffer
            .get(range)
    }

    /// The number that the name/value storage of `guid` of the driver at `device_path` holds
    /// under `label`, if any.
    fn number(&self, device_path: &DevicePath, guid: Guid, label: &str) -> Option<&Number> {
        let variable = VariableKey {
            name: String::new(),
            guid,
        };
        self.storage(device_path, variable)?.numbers.get(label)
    }

    /// The labels of the numbers of the name/value storages of the driver at `device_path`.
    fn labels(&self, device_path: &DevicePath) -> BTreeSet<&str> {
        self.storages
            .iter()
            .filter(|(key, _)| key.device_path == *device_path && key.variable.name.is_empty())
            .flat_map(|(_, values)| values.numbers.keys().map(String::as_str))
            .collect()
    }
}

/// Why get, list-questions and show-ifr show no value from an ExportedConfig.
#[derive(Debug, Error)]
pub(crate) enum SnapshotRefusal {
    #[error(
        "the ExportConfig snapshot is not a <MultiConfigAltResp>, so no value is shown from it"
    )]
    NotMultiConfigAltResp,
    /// PASSWORD ops whose VarStore is unknown, which could be any storage of the snapshot, also
    /// any that IFR the parser ignores may hold: none of their bytes can be withheld
    #[error(
        "{}; as the VarStore of that password is unknown, uefisettings cannot withhold its bytes, \
         so no value is shown from the ExportConfig snapshot",
        .0.iter().map(ToString::to_string).collect::<Vec<_>>().join("; ")
    )]
    UnresolvedPasswords(Vec<UnresolvedPassword>),
}

/// The ConfigSnapshot that an EfivarReader takes values from, for the package list that it
/// reads.
#[derive(Debug)]
pub(crate) struct SnapshotLookup {
    snapshot: ConfigSnapshot,
    /// The device path of the package list being read, if it has one
    device_path: Option<DevicePath>,
    /// The labels of the name/value storages of that list, by the string ID that names them there
    labels: BTreeMap<u16, Rc<str>>,
    /// How many values questions have taken from the snapshot (EfivarReader::snapshot_values_taken)
    taken: usize,
}

impl SnapshotLookup {
    /// The snapshot of `exported` without the bytes of `passwords` (ConfigSnapshot::parse), or why
    /// none is shown, also when a PASSWORD op's VarStore is unknown.
    pub(crate) fn new(
        exported: &ExportedConfig,
        passwords: &PasswordQuestions,
    ) -> Result<Self, SnapshotRefusal> {
        let withheld = passwords
            .withheld_from_snapshot()
            .map_err(|unresolved| SnapshotRefusal::UnresolvedPasswords(unresolved.to_vec()))?;
        Ok(Self {
            snapshot: ConfigSnapshot::parse(exported, &withheld)?,
            device_path: None,
            labels: BTreeMap::new(),
            taken: 0,
        })
    }

    /// Looks up the storages of `list` from now on: those of the driver at its device path, and
    /// the labels that its strings give, as find_corresponding_string takes each string from the
    /// first strings package that has it.
    fn enter(&mut self, list: &ParsedPackageList) {
        self.device_path = list.device_path.clone();
        let labels = self
            .device_path
            .as_ref()
            .map(|device_path| self.snapshot.labels(device_path))
            .unwrap_or_default();
        let mut taken = BTreeSet::new();
        self.labels = list
            .strings
            .iter()
            .flatten()
            .filter(|(id, _)| taken.insert(**id))
            .filter(|&(_, text)| labels.contains(&**text))
            .map(|(id, text)| (*id, Rc::clone(text)))
            .collect();
    }

    /// Counts a value that a question took from the snapshot.
    pub(crate) fn count_taken(&mut self) {
        self.taken = self.taken.saturating_add(1);
    }

    /// The bytes `range` of the buffer storage `variable` of the package list being read, if the
    /// snapshot holds them.
    pub(crate) fn buffer(&self, variable: &VariableKey, range: Range<usize>) -> Option<Vec<u8>> {
        let device_path = self.device_path.as_ref()?;
        self.snapshot.buffer(device_path, variable, range)
    }

    /// The number of the setting that the string `name` of the package list being read labels in
    /// its name/value storage of `guid`, if the snapshot holds one.
    pub(crate) fn number(&self, guid: Guid, name: u16) -> Option<&Number> {
        let device_path = self.device_path.as_ref()?;
        self.snapshot
            .number(device_path, guid, self.labels.get(&name)?)
    }
}

impl EfivarReader {
    /// This reader, taking the values of missing variables from `snapshot` too.
    pub(crate) fn with_snapshot(mut self, snapshot: SnapshotLookup) -> Self {
        self.snapshot = Some(snapshot);
        self
    }

    /// How many values questions have taken from the snapshot so far: one that grows while an
    /// expression is evaluated tells that the expression took one.
    pub(crate) fn snapshot_values_taken(&self) -> usize {
        self.snapshot.as_ref().map_or(0, |snapshot| snapshot.taken)
    }

    /// Takes snapshot values for the storages of `list` from now on, for the questions of its
    /// forms.
    pub(crate) fn enter_package_list(&mut self, list: &ParsedPackageList) {
        if let Some(snapshot) = &mut self.snapshot {
            snapshot.enter(list);
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::cell::RefCell;
    use std::sync::Once;

    use super::*;

    /// PciRoot(0), then the End of Hardware Device Path node: the device path of the driver of
    /// the fixtures.
    pub(crate) const DRIVER_PATH: [u8; 16] = [
        0x02, 0x01, 0x0C, 0x00, 0xD0, 0x41, 0x03, 0x0A, 0x00, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0x04,
        0x00,
    ];
    /// PciRoot(1): another driver's.
    const OTHER_PATH: [u8; 16] = [
        0x02, 0x01, 0x0C, 0x00, 0xD0, 0x41, 0x03, 0x0A, 0x01, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0x04,
        0x00,
    ];
    /// The GUID 8C78A505-BAA0-4C4A-869F-000000001401, as stored, of the buffer storage NStore,
    /// which no password names.
    pub(crate) const N_GUID: [u8; 16] = [
        0x05, 0xA5, 0x78, 0x8C, 0xA0, 0xBA, 0x4A, 0x4C, 0x86, 0x9F, 0x00, 0x00, 0x00, 0x00, 0x14,
        0x01,
    ];
    /// The GUID, as stored, of AMITSESetup, a password VarStore.
    pub(crate) const P_GUID: [u8; 16] = [0x44; 16];

    /// Lowercase hex digits of `bytes` in order.
    fn hex<'a>(bytes: impl IntoIterator<Item = &'a u8>) -> String {
        bytes
            .into_iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// The `<ConfigHdr>` of the storage `name` of `guid`, as stored, of the driver at
    /// `device_path`, as EDK2's HiiConstructConfigHdr writes it.
    pub(crate) fn config_hdr(guid: [u8; 16], name: &str, device_path: &[u8]) -> String {
        let name: String = name
            .encode_utf16()
            .map(|unit| format!("{unit:04x}"))
            .collect();
        format!("GUID={}&NAME={name}&PATH={}", hex(&guid), hex(device_path))
    }

    /// The `<ConfigResp>` of `hdr` with one `<BlockConfig>` of `value` at `offset`.
    pub(crate) fn block_resp(hdr: &str, offset: usize, value: &[u8]) -> String {
        // VALUE comes most significant first
        format!(
            "{hdr}&OFFSET={offset:x}&WIDTH={:x}&VALUE={}",
            value.len(),
            hex(value.iter().rev())
        )
    }

    fn key(guid: [u8; 16], name: &str) -> VariableKey {
        VariableKey {
            name: name.to_owned(),
            guid: Guid::from(guid),
        }
    }

    fn driver_path() -> DevicePath {
        DevicePath::from(DRIVER_PATH.to_vec())
    }

    /// ConfigSnapshot::parse of `text`, withholding no bytes.
    fn parse(text: String) -> ConfigSnapshot {
        ConfigSnapshot::parse(&ExportedConfig::new(text), &WithheldBytes::default())
            .expect("parse the snapshot")
    }

    /// A package list of the driver at `device_path`, if any, with the strings `strings`, one
    /// strings package each.
    fn package_list(device_path: Option<&[u8]>, strings: &[&[(u16, &str)]]) -> ParsedPackageList {
        ParsedPackageList {
            guid: Guid::from([0x55; 16]),
            device_path: device_path.map(|path| DevicePath::from(path.to_vec())),
            strings: strings
                .iter()
                .map(|package| {
                    package
                        .iter()
                        .map(|(id, text)| (*id, Rc::from(*text)))
                        .collect()
                })
                .collect(),
            string_languages: Vec::new(),
            forms: Vec::new(),
            ignored_ifr: Vec::new(),
        }
    }

    #[test]
    fn snapshot_takes_values_from_config_resp_bodies_only() {
        let hdr = config_hdr(N_GUID, "NStore", &DRIVER_PATH);
        let text = format!(
            "{}&{hdr}&ALTCFG=0000&OFFSET=0&WIDTH=4&VALUE=0d0c0b0a",
            block_resp(&hdr, 0, &[1, 2])
        );

        let snapshot = parse(text);

        let store = key(N_GUID, "NStore");
        assert_eq!(
            snapshot.buffer(&driver_path(), &store, 0..2),
            Some(vec![1, 2]),
            "bytes of the <ConfigResp>"
        );
        assert_eq!(
            snapshot.buffer(&driver_path(), &store, 1..3),
            None,
            "byte 2, in an ALTCFG block only"
        );
    }

    /// A <ConfigAltResp> that does not parse, here one whose WIDTH no address holds, as IA32
    /// OVMF's PlatformDxe writes "%016LX" of a 32-bit sizeof (edk2-stable202608
    /// OvmfPkg/PlatformDxe/Platform.c ExtractConfig()), hides none of the others: they keep their
    /// values, and it and its <AltResp> give none.
    #[test]
    fn snapshot_keeps_the_storages_that_parse() {
        let bad = config_hdr(N_GUID, "Bad", &DRIVER_PATH);
        let text = [
            block_resp(&config_hdr(N_GUID, "NStore", &DRIVER_PATH), 0, &[1]),
            format!("{bad}&OFFSET=0&WIDTH=3f00b1b0000000000000000000000024&VALUE=02"),
            format!("{bad}&ALTCFG=0000&OFFSET=0&WIDTH=1&VALUE=03"),
            block_resp(&config_hdr(N_GUID, "Later", &DRIVER_PATH), 0, &[4]),
        ]
        .join("&");

        let snapshot = parse(text);

        for (name, want) in [
            ("NStore", Some(vec![1])),
            ("Bad", None),
            ("Later", Some(vec![4])),
        ] {
            assert_eq!(
                snapshot.buffer(&driver_path(), &key(N_GUID, name), 0..1),
                want,
                "{name}"
            );
        }
    }

    /// A storage keeps the bytes of its blocks but those of PASSWORD questions, whatever its
    /// PATH, and a storage without such bytes keeps them all.
    #[test]
    fn snapshot_drops_password_bytes_whatever_their_path() {
        let password = key(P_GUID, "AMITSESetup");
        let mut withheld = WithheldBytes::default();
        withheld.insert(password.clone(), 2..6);
        let mut value = [0x11; 8];
        value[2..6].fill(0xA5);
        let text = [
            block_resp(&config_hdr(N_GUID, "NStore", &DRIVER_PATH), 2, &[1]),
            block_resp(&config_hdr(P_GUID, "AMITSESetup", &DRIVER_PATH), 0, &value),
            block_resp(&config_hdr(P_GUID, "AMITSESetup", &OTHER_PATH), 0, &value),
        ]
        .join("&");

        let snapshot = ConfigSnapshot::parse(&ExportedConfig::new(text), &withheld)
            .expect("parse the snapshot");

        let shown = format!("{snapshot:?}");
        assert!(!shown.contains("165"), "Debug of the snapshot: {shown}");
        for path in [DRIVER_PATH, OTHER_PATH] {
            let path = DevicePath::from(path.to_vec());
            for (bytes, want) in [
                (0..2, Some(vec![0x11, 0x11])),
                (6..8, Some(vec![0x11, 0x11])),
                (1..3, None),
                (5..7, None),
            ] {
                assert_eq!(
                    snapshot.buffer(&path, &password, bytes.clone()),
                    want,
                    "{path:?}: AMITSESetup bytes {bytes:?}"
                );
            }
        }
        assert_eq!(
            snapshot.buffer(&driver_path(), &key(N_GUID, "NStore"), 2..3),
            Some(vec![1]),
            "NStore"
        );
    }

    #[test]
    fn snapshot_refuses_what_is_no_multi_config_alt_resp_without_quoting_it() {
        // no WIDTH: config_string's error quotes the VALUE element instead
        let text = format!(
            "{}&OFFSET=0&VALUE={}",
            config_hdr(P_GUID, "AMITSESetup", &DRIVER_PATH),
            "a5".repeat(81)
        );
        let quoted = text
            .parse::<MultiConfigAltResp>()
            .expect_err("parse the text as config_string does");
        assert!(
            quoted.to_string().contains("a5a5"),
            "config_string's error: {quoted}"
        );

        let error = ConfigSnapshot::parse(&ExportedConfig::new(text), &WithheldBytes::default())
            .expect_err("parse the snapshot");

        assert_eq!(
            format!("{error}; {error:?}"),
            "the ExportConfig snapshot is not a <MultiConfigAltResp>, so no value is shown from \
             it; NotMultiConfigAltResp"
        );
    }

    #[test]
    fn exported_config_shows_no_text() {
        let exported = ExportedConfig::new("a5".repeat(8));

        assert_eq!(format!("{exported:?}"), "ExportedConfig { .. }");
    }

    #[test]
    fn snapshot_of_no_storage_is_empty() {
        assert_eq!(parse(String::new()), ConfigSnapshot::default());
    }

    #[test]
    fn snapshot_drops_storages_whose_name_is_no_utf16() {
        let hdr = config_hdr(N_GUID, "", &DRIVER_PATH).replace("NAME=", "NAME=d800");

        assert_eq!(parse(block_resp(&hdr, 0, &[1])), ConfigSnapshot::default());
    }

    #[test]
    fn later_blocks_and_numbers_replace_earlier_ones() {
        let hdr = config_hdr(N_GUID, "NStore", &DRIVER_PATH);
        let name_value = config_hdr(N_GUID, "", &DRIVER_PATH);
        let text = [
            block_resp(&hdr, 0, &[1, 2, 3]),
            block_resp(&hdr, 1, &[9]),
            format!("{name_value}&Var0=05&Var0=0102&Gone=07&Gone="),
        ]
        .join("&");

        let snapshot = parse(text);

        assert_eq!(
            snapshot.buffer(&driver_path(), &key(N_GUID, "NStore"), 0..3),
            Some(vec![1, 9, 3]),
            "blocks"
        );
        let guid = Guid::from(N_GUID);
        assert_eq!(
            snapshot
                .number(&driver_path(), guid, "Var0")
                .map(Number::as_bytes),
            Some(&[2, 1][..]),
            "Var0"
        );
        assert_eq!(
            snapshot.number(&driver_path(), guid, "Gone"),
            None,
            "Gone, emptied"
        );
    }

    /// A storage holds the bytes that its blocks give and nothing for those before them, so
    /// storages with a block near the 0xFFFF block end take memory as their text does.
    #[test]
    fn storages_hold_only_the_bytes_of_their_blocks() {
        let text = (0..1000)
            .map(|index| {
                block_resp(
                    &config_hdr(N_GUID, &format!("S{index}"), &DRIVER_PATH),
                    0xFFFE,
                    &[1],
                )
            })
            .collect::<Vec<_>>()
            .join("&");

        let snapshot = parse(text);

        assert_eq!(snapshot.storages.len(), 1000, "storages");
        for (storage, values) in &snapshot.storages {
            assert_eq!(values.buffer.0.len(), 1, "{storage:?}");
        }
        assert_eq!(
            snapshot.buffer(&driver_path(), &key(N_GUID, "S999"), 0xFFFE..0xFFFF),
            Some(vec![1]),
            "S999"
        );
    }

    #[test]
    fn lookup_takes_the_storages_of_the_package_list_being_read() {
        let text = [
            block_resp(&config_hdr(N_GUID, "NStore", &DRIVER_PATH), 0, &[1]),
            block_resp(&config_hdr(N_GUID, "NStore", &OTHER_PATH), 0, &[2]),
            format!("{}&Var0=07&Var1=08", config_hdr(N_GUID, "", &DRIVER_PATH)),
        ]
        .join("&");
        let mut lookup =
            SnapshotLookup::new(&ExportedConfig::new(text), &PasswordQuestions::default())
                .expect("look up the snapshot");
        let store = key(N_GUID, "NStore");
        let guid = Guid::from(N_GUID);
        // string 1 names Var0 in the first strings package, which a later one does not change
        let strings: &[&[(u16, &str)]] = &[&[(1, "Var0"), (2, "Other")], &[(1, "Var1")]];

        for (case, list, want_buffer, want_var0) in [
            (
                "the driver's list",
                package_list(Some(&DRIVER_PATH), strings),
                Some(vec![1]),
                Some(&[7][..]),
            ),
            (
                "another driver's list",
                package_list(Some(&OTHER_PATH), strings),
                Some(vec![2]),
                None,
            ),
            (
                "a list without a device path",
                package_list(None, strings),
                None,
                None,
            ),
        ] {
            lookup.enter(&list);

            assert_eq!(lookup.buffer(&store, 0..1), want_buffer, "{case}: NStore");
            assert_eq!(
                lookup.number(guid, 1).map(Number::as_bytes),
                want_var0,
                "{case}: string 1"
            );
            assert_eq!(lookup.number(guid, 2), None, "{case}: string 2");
        }
    }

    thread_local! {
        /// What the test logger keeps of this thread's messages, with their levels, while it
        /// keeps them.
        static LOGGED: RefCell<Option<Vec<(log::Level, String)>>> = const { RefCell::new(None) };
    }

    /// Keeps the messages of the threads that logged_by watches.
    struct ThreadLogger;

    impl log::Log for ThreadLogger {
        fn enabled(&self, _metadata: &log::Metadata<'_>) -> bool {
            true
        }

        fn log(&self, record: &log::Record<'_>) {
            LOGGED.with_borrow_mut(|logged| {
                if let Some(logged) = logged {
                    logged.push((record.level(), record.args().to_string()));
                }
            });
        }

        fn flush(&self) {}
    }

    static LOGGER: ThreadLogger = ThreadLogger;

    /// The messages that `run` logs on this thread, at any level.
    pub(crate) fn logged_by(run: impl FnOnce()) -> Vec<String> {
        leveled_by(run)
            .into_iter()
            .map(|(_, message)| message)
            .collect()
    }

    /// The messages that `run` logs on this thread, with their levels. The one test logger of the
    /// crate: log takes a single logger per process, and every test runs in it.
    pub(crate) fn leveled_by(run: impl FnOnce()) -> Vec<(log::Level, String)> {
        static INSTALL: Once = Once::new();
        INSTALL.call_once(|| {
            log::set_logger(&LOGGER).expect("install the test logger");
            log::set_max_level(log::LevelFilter::Trace);
        });
        LOGGED.set(Some(Vec::new()));
        run();
        LOGGED.take().expect("the messages of this thread")
    }
}
