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
use std::collections::BTreeSet;
use std::fmt::Write;
use std::fs;
use std::path::Path;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use log::debug;
use serde_json::Value;

use uefisettings_backend_thrift::Backend;
use uefisettings_backend_thrift::GetResponse;
use uefisettings_backend_thrift::GetResponseList;
use uefisettings_backend_thrift::HiiDatabase;
use uefisettings_backend_thrift::HiiShowIfrResponse;
use uefisettings_backend_thrift::HiiStringsPackage;
use uefisettings_backend_thrift::IloAttributes;
use uefisettings_backend_thrift::MachineInfo;
use uefisettings_backend_thrift::Question;
use uefisettings_backend_thrift::SetResponse;
use uefisettings_backend_thrift::SetResponseList;

use crate::hii::extract;
use crate::hii::forms;
use crate::hii::forms::list_questions;
use crate::hii::package;
use crate::ilorest::chif;
use crate::ilorest::requests;
use crate::ilorest::requests::Ilo5Dev;
use crate::ilorest::requests::IloDevice;
use crate::ilorest::requests::RedfishAttributes;
use crate::translation::get_qa_variations_hii;
use crate::translation::get_qa_variations_ilo;
use crate::translation::translate_response;
use crate::translation::HiiTranslation;
use crate::translation::IloTranslation;

/// SettingsBackend is a trait which should be satisfied by all backends (like ilo, hii)
pub trait SettingsBackend {
    /// set changes the value of the UEFI question/attribute
    fn set(question: &str, new_value: &str, selector: Option<&str>) -> Result<SetResponseList>;
    /// get displays the value of the UEFI question/attribute
    fn get(question: &str, selector: Option<&str>) -> Result<GetResponseList>;
}

pub struct HiiBackend {}

impl HiiBackend {
    /// extract_db extracts HiiDB from efivarfs and returns it in bytes (in HiiDatabase's db field which is Vec<u8>)
    pub fn extract_db() -> Result<HiiDatabase> {
        let resp = HiiDatabase {
            db: extract::extract_db()?,
            ..Default::default()
        };
        Ok(resp)
    }

    /// show_ifr returns a human readable representation of the forms in Hii
    pub fn show_ifr(db_bytes: &[u8]) -> Result<HiiShowIfrResponse> {
        // We depend on the caller to provide us with the hiidb instead of calling extract here
        // because they might want to provide a file instead.

        let mut readable_representation = String::new();

        let parsed_db = package::read_db(db_bytes)?;

        for (guid, package_list) in parsed_db.forms {
            write!(readable_representation, "Packagelist {}", &guid)?;
            for form_package in package_list {
                readable_representation.push_str(&forms::display(
                    form_package,
                    0,
                    parsed_db
                        .strings
                        .get(&guid)
                        .context(format!("Failed to get string packages using GUID {}", guid))?,
                )?);
            }
        }

        let resp = HiiShowIfrResponse {
            readable_representation,
            ..Default::default()
        };
        Ok(resp)
    }

    /// list all strings-id, string pairs in HiiDB
    pub fn list_strings(db_bytes: &[u8]) -> Result<Vec<HiiStringsPackage>> {
        let mut resp = Vec::new();
        let parsed_db = package::read_db(db_bytes)?;

        for (guid, package_list) in parsed_db.strings {
            for string_package in package_list {
                let mut p = HiiStringsPackage {
                    package_list: guid.to_owned(),
                    ..Default::default()
                };
                for (string_id, string) in string_package {
                    p.string_package.insert(string_id, string);
                }
                resp.push(p);
            }
        }

        Ok(resp)
    }

    pub fn list_questions(db_bytes: &[u8]) -> Result<Vec<Question>> {
        let mut res = Vec::new();
        let parsed_db = package::read_db(db_bytes)?;
        for (guid, package_list) in parsed_db.forms {
            let string_packages = parsed_db
                .strings
                .get(&guid)
                .context(format!("Failed to get string packages using GUID {}", guid))?;

            for form_package in package_list {
                //  TODO: show form name, package list guid in the final response as well

                for question_descriptor in list_questions(form_package, string_packages) {
                    let mut question = Question {
                        name: question_descriptor.question,
                        answer: question_descriptor.value,
                        help: question_descriptor.help,
                        ..Default::default()
                    };
                    for opt in question_descriptor.possible_options {
                        question.options.push(opt.value);
                    }
                    // don't show it if everything is empty
                    if !(question.name.is_empty()
                        && question.answer.is_empty()
                        && question.help.is_empty()
                        && question.options.is_empty())
                    {
                        res.push(question);
                    }
                }
            }
        }
        Ok(res)
    }
}

impl SettingsBackend for HiiBackend {
    fn set(question: &str, new_value: &str, _selector: Option<&str>) -> Result<SetResponseList> {
        // TODO: use selector to only change values which match question + selector

        let mut resp = Vec::new();

        let db_bytes = extract::extract_db()?;
        let parsed_db = package::read_db(&db_bytes)?;

        let hii_translation = get_qa_variations_hii(question, new_value);
        let (question_variations, new_value_variations, is_translated) = match hii_translation {
            HiiTranslation::Translated {
                question_variations,
                answer_variations,
            } => (question_variations, answer_variations, true),
            HiiTranslation::NotTranslated {
                question_variations,
                answer_variations,
            } => (question_variations, answer_variations, false),
        };

        for (guid, package_list) in parsed_db.forms {
            let string_packages = parsed_db
                .strings
                .get(&guid)
                .context(format!("Failed to get string packages using GUID {}", guid))?;

            for form_package in package_list {
                // try to find the question
                if let Some(question_descriptor) =
                    forms::find_question(form_package, string_packages, &question_variations)
                {
                    let mut modified = false;
                    // if the question_descriptor provides options then set the closest one from new_value_variations
                    // (example whatever matches from [Enabled, Enable])
                    // else try setting the new_value because it might be some arbitrary value like a number
                    // (will return error if doesn't match constraints)
                    if !(question_descriptor.possible_options.is_empty()) {
                        // This is different from modified because if varstore doesn't exist for the question
                        // then we can't set answers but it isn't an error.
                        let mut found_option = false;
                        for opt in &(question_descriptor.possible_options) {
                            if found_option {
                                break;
                            }
                            for variation in &new_value_variations {
                                if variation.eq_ignore_ascii_case(&(opt.value)) {
                                    found_option = true;
                                    modified =
                                        forms::change_value(&question_descriptor, &(opt.value))?;
                                    break;
                                }
                            }
                        }
                        // if not a single option matched then error out
                        // we went though all options and if it still wasn't modified then this isn't in the options
                        if !found_option {
                            return Err(forms::ChangeValueError::InvalidOption.into());
                        }
                    } else {
                        modified = forms::change_value(&question_descriptor, new_value)?
                    }

                    if modified {
                        let mut set_resp = SetResponse {
                            selector: guid.to_owned(),
                            backend: Backend::Hii,
                            is_translated,
                            question: Question {
                                name: question_descriptor.question,
                                answer: new_value.to_owned(),
                                help: question_descriptor.help,
                                ..Default::default()
                            },
                            modified: true,
                            ..Default::default()
                        };

                        for opt in question_descriptor.possible_options {
                            set_resp.question.options.push(opt.value)
                        }

                        resp.push(set_resp);
                    }
                }
                // question not found in this form package
            }
        }

        Ok(SetResponseList {
            responses: resp,
            ..Default::default()
        })
    }

    fn get(question: &str, _selector: Option<&str>) -> Result<GetResponseList> {
        // TODO: use selector to only get questions which match question + selector

        let mut resp = Vec::new();

        let hii_translation = get_qa_variations_hii(question, "");
        let (question_variations, is_translated) = match hii_translation {
            HiiTranslation::Translated {
                question_variations,
                ..
            } => (question_variations, true),
            HiiTranslation::NotTranslated {
                question_variations,
                ..
            } => (question_variations, false),
        };

        let db_bytes = extract::extract_db()?;
        let parsed_db = package::read_db(&db_bytes)?;

        for (guid, package_list) in parsed_db.forms {
            for form_package in package_list {
                if let Some(question_descriptor) = forms::find_question(
                    form_package,
                    parsed_db
                        .strings
                        .get(&guid)
                        .context(format!("Failed to get string packages using GUID {}", guid))?,
                    &question_variations,
                ) {
                    let mut get_resp = GetResponse {
                        selector: guid.to_owned(),
                        backend: Backend::Hii,
                        is_translated,
                        // mapping the hii module's QuestionDescriptor to thrift codegen's Question
                        question: Question {
                            name: question_descriptor.question,
                            answer: question_descriptor.value,
                            help: question_descriptor.help,
                            ..Default::default()
                        },
                        ..Default::default()
                    };

                    if is_translated {
                        get_resp.question.answer =
                            translate_response(question, &get_resp.question.answer, Backend::Hii);
                    }

                    for opt in question_descriptor.possible_options {
                        get_resp.question.options.push(opt.value)
                    }

                    resp.push(get_resp)
                }
            }
        }

        Ok(GetResponseList {
            responses: resp,
            ..Default::default()
        })
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

    if Path::new(extract::OCP_HIIDB_PATH).exists() {
        backend.insert(Backend::Hii);
    }
    if chif::check_ilo_connectivity().is_ok() {
        debug!("Backend Identified: Hii");
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
