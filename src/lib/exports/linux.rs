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

//! The exports that only the Linux build has: those that read the HiiDB of this machine or of an
//! efivars dump, dump efivars, iLO, and identify_machine.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::Result;
use log::debug;
use log::warn;
use serde_json::Value;

use uefisettings_backend_thrift::Backend;
use uefisettings_backend_thrift::GetResponse;
use uefisettings_backend_thrift::GetResponseList;
use uefisettings_backend_thrift::HiiDatabase;
use uefisettings_backend_thrift::IloAttributes;
use uefisettings_backend_thrift::MachineInfo;
use uefisettings_backend_thrift::Question;
use uefisettings_backend_thrift::SetResponse;
use uefisettings_backend_thrift::SetResponseList;

use super::DumpEfivarsOptions;
use super::HiiBackend;
use super::SettingsBackend;
use crate::hii::extract;
use crate::hii::package::db_file;
use crate::hii::EfivarDump;
use crate::hii::EfivarFiles;
use crate::hii::EfivarSource;
use crate::hii::FirmwareVariables;
use crate::hii::SavedDump;
use crate::ilorest::chif;
use crate::ilorest::requests;
use crate::ilorest::requests::Ilo5Dev;
use crate::ilorest::requests::IloDevice;
use crate::ilorest::requests::RedfishAttributes;
use crate::translation::ilo::get_qa_variations_ilo;
use crate::translation::ilo::IloTranslation;
use crate::translation::translate_response;

/// What set and get read and write when no file names them: this machine's HiiDB and efivarfs.
impl HiiBackend {
    /// This machine's HiiDB.
    pub(super) fn system_hiidb() -> Result<Vec<u8>> {
        extract::extract_db()
    }

    /// This machine's efivarfs.
    pub(super) fn system_variables() -> impl FirmwareVariables {
        EfivarFiles::system()
    }
}

impl HiiBackend {
    /// extract_db extracts HiiDB from efivarfs and returns it in bytes (in HiiDatabase's db field which is `Vec<u8>`)
    pub fn extract_db() -> Result<HiiDatabase> {
        let resp = HiiDatabase {
            db: extract::extract_db()?,
            ..Default::default()
        };
        Ok(resp)
    }

    /// Reads the HiiDB that get, list-questions and show-ifr read with `efivars`: the file
    /// `filename` if given, else the one that an efivars dump in `efivars` saved, else this
    /// machine's. A redacted dump refuses another `filename`, whose questions would read its
    /// zeros as values.
    pub fn read_hiidb(filename: Option<&Path>, efivars: &EfivarSource) -> Result<Vec<u8>> {
        let dump = match efivars {
            EfivarSource::Directory(dir) => SavedDump::open(dir)?,
            EfivarSource::System | EfivarSource::Disabled => None,
        };
        match (filename, dump) {
            (Some(filename), None) => db_file::read_db_file(filename),
            (Some(filename), Some(dump)) => {
                let hiidb = db_file::read_db_file(filename)?;
                dump.check_hiidb(&hiidb, filename)?;
                Ok(hiidb)
            }
            (None, Some(dump)) => dump.read_hiidb(),
            (None, None) => extract::extract_db(),
        }
    }

    /// Copies the efivar files that the questions of the HiiDB `db_bytes` read into the new
    /// directory `dir`, in efivarfs format, as `options` say, with the HiiDB and a manifest
    pub fn dump_efivars(
        db_bytes: &[u8],
        dir: &Path,
        options: &DumpEfivarsOptions,
    ) -> Result<EfivarDump> {
        crate::hii::dump_efivars(db_bytes, dir, options.redaction)
    }
}

pub struct IloBackend {}

impl IloBackend {
    /// list all bios setting attributes provided by ilo
    pub fn show_attributes() -> Result<Vec<IloAttributes>> {
        let mut resp = Vec::new();

        let machine_type = requests::identify_hpe_machine_type()?;
        let ilo_device = requests::get_device_instance(machine_type);

        // Regular BIOS Settings
        let ilo_bios_settings = IloAttributes {
            selector: ilo_device.bios_settings_selector(),
            attributes: btreemap_from_redfish_attributes(ilo_device.get_current_bios_settings()?),
            ..Default::default()
        };
        resp.push(ilo_bios_settings);

        if machine_type != IloDevice::Ilo4 {
            // Debug Settings
            let ilo_debug_settings = IloAttributes {
                selector: Ilo5Dev::debug_settings_selector(),
                attributes: btreemap_from_redfish_attributes(Ilo5Dev::get_current_debug_settings(
                    machine_type,
                )?),
                ..Default::default()
            };
            resp.push(ilo_debug_settings);

            // Service Settings
            let ilo_service_settings = IloAttributes {
                selector: Ilo5Dev::service_settings_selector(),
                attributes: btreemap_from_redfish_attributes(
                    Ilo5Dev::get_current_service_settings(machine_type)?,
                ),
                ..Default::default()
            };
            resp.push(ilo_service_settings);
        }

        Ok(resp)
    }

    /// list bios pending changes to attributes provided by ilo
    pub fn show_pending_attributes() -> Result<Vec<IloAttributes>> {
        let mut resp = Vec::new();

        let machine_type = requests::identify_hpe_machine_type()?;
        let ilo_device = requests::get_device_instance(machine_type);

        // Regular BIOS Settings
        let ilo_bios_settings = IloAttributes {
            selector: ilo_device.bios_settings_selector(),
            attributes: compare_redfish_attributes(
                ilo_device.get_current_bios_settings()?,
                ilo_device.get_pending_bios_settings()?,
            ),
            ..Default::default()
        };
        resp.push(ilo_bios_settings);

        if machine_type != IloDevice::Ilo4 {
            // Debug Settings
            let ilo_debug_settings = IloAttributes {
                selector: Ilo5Dev::debug_settings_selector(),
                attributes: compare_redfish_attributes(
                    Ilo5Dev::get_current_debug_settings(machine_type)?,
                    Ilo5Dev::get_pending_debug_settings(machine_type)?,
                ),
                ..Default::default()
            };
            resp.push(ilo_debug_settings);

            // Service Settings
            let ilo_service_settings = IloAttributes {
                selector: Ilo5Dev::service_settings_selector(),
                attributes: compare_redfish_attributes(
                    Ilo5Dev::get_current_service_settings(machine_type)?,
                    Ilo5Dev::get_pending_service_settings(machine_type)?,
                ),
                ..Default::default()
            };
            resp.push(ilo_service_settings);
        }

        Ok(resp)
    }
}

impl SettingsBackend for IloBackend {
    fn set(question: &str, new_value: &str, _selector: Option<&str>) -> Result<SetResponseList> {
        // TODO: use selector to only change values which match question + selector

        let mut resp = Vec::new();

        let ilo_translation = get_qa_variations_ilo(question, new_value);
        let (translated_question, translated_new_value, is_translated) = match ilo_translation {
            IloTranslation::Translated {
                translated_question,
                translated_answer,
            } => (translated_question, translated_answer, true),
            IloTranslation::NotTranslated { question, answer } => (question, answer, false),
        };

        let machine_type = requests::identify_hpe_machine_type()?;
        let ilo_device = requests::get_device_instance(machine_type);

        // BIOS Settings
        let current_bios_settings = ilo_device.get_current_bios_settings()?;
        if let Some(Value::String(_)) = current_bios_settings.get(&translated_question) {
            ilo_device.update_bios_setting(&translated_question, &translated_new_value)?;

            let set_resp = SetResponse {
                selector: ilo_device.bios_settings_selector(),
                backend: Backend::Ilo,
                is_translated,
                question: Question {
                    name: translated_question.to_owned(), // real question that was sent to ilo
                    answer: new_value.to_owned(),         // canonical answer
                    ..Default::default()
                },
                modified: true,
                ..Default::default()
            };

            resp.push(set_resp)
        }

        if machine_type != IloDevice::Ilo4 {
            // Debug Settings
            if let Some(Value::String(_)) =
                Ilo5Dev::get_current_debug_settings(machine_type)?.get(&translated_question)
            {
                Ilo5Dev::update_debug_setting(
                    machine_type,
                    &translated_question,
                    &translated_new_value,
                )?;

                let set_resp = SetResponse {
                    selector: Ilo5Dev::debug_settings_selector(),
                    backend: Backend::Ilo,
                    is_translated,
                    question: Question {
                        name: translated_question.to_owned(), // real question that was sent to ilo
                        answer: new_value.to_owned(),         // canonical answer
                        ..Default::default()
                    },
                    modified: true,
                    ..Default::default()
                };

                resp.push(set_resp)
            }

            // Service Settings
            if let Some(Value::String(_)) =
                Ilo5Dev::get_current_service_settings(machine_type)?.get(&translated_question)
            {
                Ilo5Dev::update_service_setting(
                    machine_type,
                    &translated_question,
                    &translated_new_value,
                )?;

                let set_resp = SetResponse {
                    selector: Ilo5Dev::service_settings_selector(),
                    backend: Backend::Ilo,
                    is_translated,
                    question: Question {
                        name: translated_question.to_owned(), // real question that was sent to ilo
                        answer: new_value.to_owned(),         // canonical answer
                        ..Default::default()
                    },
                    modified: true,
                    ..Default::default()
                };

                resp.push(set_resp)
            }
        }

        // TODO: fail when no attribute matches, and try every match before failing, as
        // HiiBackend::set_using does
        Ok(SetResponseList {
            responses: resp,
            ..Default::default()
        })
    }

    fn get(question: &str, _selector: Option<&str>) -> Result<GetResponseList> {
        // TODO: use selector to only get questions which match question + selector

        let mut resp = Vec::new();

        let machine_type = requests::identify_hpe_machine_type()?;
        let ilo_device = requests::get_device_instance(machine_type);

        let ilo_translation = get_qa_variations_ilo(question, "");
        let (translated_question, is_translated) = match ilo_translation {
            IloTranslation::Translated {
                translated_question,
                ..
            } => (translated_question, true),
            IloTranslation::NotTranslated { question, .. } => (question, false),
        };

        let mut setting_collections = vec![(
            ilo_device.get_current_bios_settings()?,
            ilo_device.bios_settings_selector(),
        )];
        if machine_type != IloDevice::Ilo4 {
            setting_collections.push((
                Ilo5Dev::get_current_debug_settings(machine_type)?,
                Ilo5Dev::debug_settings_selector(),
            ));
            setting_collections.push((
                Ilo5Dev::get_current_service_settings(machine_type)?,
                Ilo5Dev::service_settings_selector(),
            ));
        }

        // look for the question in all settings collections including bios and hidden collections like debug, service
        for (attributes, settings_selector) in setting_collections {
            if let Some(Value::String(s)) = attributes.get(&translated_question) {
                let mut get_resp = GetResponse {
                    selector: settings_selector,
                    backend: Backend::Ilo,
                    is_translated,
                    question: Question {
                        name: translated_question.to_owned(), // the question that was sent to ilo
                        answer: s.to_owned(),
                        ..Default::default()
                    },
                    ..Default::default()
                };

                if is_translated {
                    get_resp.question.answer =
                        translate_response(question, &get_resp.question.answer, Backend::Ilo);
                }

                resp.push(get_resp)
            }
        }

        Ok(GetResponseList {
            responses: resp,
            ..Default::default()
        })
    }
}

/// auto-identify backend and get hardware/bios-information
pub fn identify_machine() -> MachineInfo {
    let mut backend = BTreeSet::new();

    match extract::hii_db_published() {
        Ok(true) => {
            debug!("Backend Identified: Hii");
            backend.insert(Backend::Hii);
        }
        Ok(false) => {}
        // reading the database then reports the error
        Err(error) => {
            warn!("Cannot tell whether the firmware publishes its HII database: {error}");
            backend.insert(Backend::Hii);
        }
    }
    if chif::check_ilo_connectivity().is_ok() {
        debug!("Backend Identified: Ilo");
        backend.insert(Backend::Ilo);
    }

    if backend.is_empty() {
        backend.insert(Backend::Unknown);
    } else {
        debug!("Supported Backends: {:?}", backend);
    }

    MachineInfo {
        backend,
        // the entries in /sys/class/dmi/id/ are plaintext and populated by the kernel
        bios_vendor: read_file_contents(Path::new("/sys/class/dmi/id/bios_vendor")),
        bios_version: read_file_contents(Path::new("/sys/class/dmi/id/bios_version")),
        bios_release: read_file_contents(Path::new("/sys/class/dmi/id/bios_release")),
        bios_date: read_file_contents(Path::new("/sys/class/dmi/id/bios_date")),
        product_name: read_file_contents(Path::new("/sys/class/dmi/id/product_name")),
        product_family: read_file_contents(Path::new("/sys/class/dmi/id/product_family")),
        product_version: read_file_contents(Path::new("/sys/class/dmi/id/product_version")),
        ..Default::default()
    }
}

/// read_file_contents is a wrapper over std::fs::read_to_string but it
/// returns an empty string if file can't be read / doesn't exist
fn read_file_contents(file_path: &Path) -> String {
    match fs::read_to_string(file_path) {
        Ok(contents) => contents.trim().to_owned(),
        Err(why) => {
            debug!("Can't read {:?} because {}", file_path, why);
            "".to_owned()
        }
    }
}

fn btreemap_from_redfish_attributes(attributes: RedfishAttributes) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for (key, value) in attributes {
        if let Value::String(v) = value {
            map.insert(key, v);
        }
    }
    map
}

fn compare_redfish_attributes(
    old_attributes: RedfishAttributes,
    new_attributes: RedfishAttributes,
) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for (key, value) in &new_attributes {
        if let Value::String(new_value) = value {
            if let Some(Value::String(old_value)) = old_attributes.get(key) {
                if !old_value.eq(new_value) {
                    map.insert(key.to_owned(), new_value.to_owned());
                }
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    /// read_hiidb reads `filename` if given, else the HiiDB that an efivars dump saved; a
    /// redacted dump refuses another `filename`.
    #[test]
    fn read_hiidb_reads_the_file_or_the_dump() {
        let dump = |redaction: &str| {
            let dir = tempfile::tempdir().expect("create a dump directory");
            fs::write(dir.path().join("hiidb.bin"), b"saved HiiDB").expect("write the HiiDB");
            fs::write(
                dir.path().join("uefisettings-dump.json"),
                format!(r#"{{"format": 1, "uefisettings": "0.1.6", "redaction": "{redaction}"}}"#),
            )
            .expect("write the manifest");
            dir
        };
        let (redacted, unredacted) = (dump("decoded-bytes"), dump("unredacted"));
        let plain = tempfile::tempdir().expect("create an efivars directory");
        fs::write(plain.path().join("hiidb.bin"), b"saved HiiDB").expect("write a HiiDB");
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

        for (case, filename, efivars, want) in [
            ("a dump", None, directory(&redacted), Ok("saved HiiDB")),
            (
                "the HiiDB of a redacted dump",
                Some(&saved),
                directory(&redacted),
                Ok("saved HiiDB"),
            ),
            (
                "another HiiDB, an unredacted dump",
                Some(&other),
                directory(&unredacted),
                Ok("other HiiDB"),
            ),
            (
                "a HiiDB, a directory without a manifest",
                Some(&other),
                directory(&plain),
                Ok("other HiiDB"),
            ),
            (
                "a HiiDB, no efivars",
                Some(&other),
                EfivarSource::Disabled,
                Ok("other HiiDB"),
            ),
            (
                "a HiiDB, efivarfs",
                Some(&other),
                EfivarSource::System,
                Ok("other HiiDB"),
            ),
            (
                "another HiiDB, a redacted dump",
                Some(&other),
                directory(&redacted),
                Err(&refused),
            ),
        ] {
            let got = HiiBackend::read_hiidb(filename.map(|path| path.as_path()), &efivars);

            match (got, want) {
                (Ok(db), Ok(want)) => assert_eq!(db, want.as_bytes(), "{case}"),
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
