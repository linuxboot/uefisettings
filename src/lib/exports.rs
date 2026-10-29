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
use std::collections::HashSet;
use std::fmt::Write;
use std::fs;
use std::path::Path;

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
use crate::hii::forms::Choice;
use crate::hii::forms::QuestionDescriptor;
use crate::hii::package;
use crate::hii::EfivarReader;
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

pub use crate::hii::forms::IncludedStates;
pub use crate::hii::forms::QuestionState;
pub use crate::hii::forms::SelectionError;

/// SettingsBackend is a trait which should be satisfied by all backends (like ilo, hii)
pub trait SettingsBackend {
    /// set changes the value of the UEFI question/attribute
    fn set(question: &str, new_value: &str, selector: Option<&str>) -> Result<SetResponseList>;
    /// get displays the value of the UEFI question/attribute
    fn get(question: &str, selector: Option<&str>) -> Result<GetResponseList>;
}

pub struct HiiBackend {}

/// The options of HiiBackend::get_using.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct GetOptions {
    /// The states of the questions to select and of the options to list too
    pub include: IncludedStates,
}

/// The options of HiiBackend::set_using.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SetOptions {
    /// The states of the questions and options to select too
    pub include: IncludedStates,
}

/// The options of HiiBackend::list_questions_using.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ListQuestionsOptions {
    /// The states of the questions and options to list too
    pub include: IncludedStates,
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

    /// show_ifr returns a human readable representation of the forms in Hii
    pub fn show_ifr(db_bytes: &[u8]) -> Result<HiiShowIfrResponse> {
        // We depend on the caller to provide us with the hiidb instead of calling extract here
        // because they might want to provide a file instead.

        let mut readable_representation = String::new();

        let parsed_db = package::read_db(db_bytes)?;
        let mut reader = EfivarReader::default();

        for list in parsed_db {
            list.check_form_strings()?;
            // no header for a list without forms
            if list.forms.is_empty() {
                continue;
            }
            write!(readable_representation, "Packagelist {}", list.guid)?;
            for form_package in list.forms {
                readable_representation.push_str(&forms::display(
                    form_package,
                    0,
                    &list.strings,
                    &mut reader,
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

        for list in parsed_db {
            for string_package in list.strings {
                let mut p = HiiStringsPackage {
                    package_list: list.guid.to_string(),
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
        Self::list_questions_using(db_bytes, &ListQuestionsOptions::default())
    }

    /// list_questions with `options`
    pub fn list_questions_using(
        db_bytes: &[u8],
        options: &ListQuestionsOptions,
    ) -> Result<Vec<Question>> {
        let include = options.include;
        let mut res = Vec::new();
        let parsed_db = package::read_db(db_bytes)?;
        let mut reader = EfivarReader::default();
        for list in parsed_db {
            list.check_form_strings()?;

            for form_package in list.forms {
                //  TODO: show form name, package list guid in the final response as well

                for (question_descriptor, state) in
                    list_questions(form_package, &list.strings, include, &mut reader)
                {
                    let question = Question {
                        options: question_descriptor.listed_options(include),
                        name: question_descriptor.question,
                        answer: question_descriptor.value
                            + &question_descriptor.value_state.option_annotation()
                            + &state.annotation(),
                        help: question_descriptor.help,
                        ..Default::default()
                    };
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
    fn set(question: &str, new_value: &str, selector: Option<&str>) -> Result<SetResponseList> {
        Self::set_using(question, new_value, selector, &SetOptions::default())
    }

    fn get(question: &str, selector: Option<&str>) -> Result<GetResponseList> {
        Self::get_using(question, selector, &GetOptions::default())
    }
}

impl HiiBackend {
    /// set with `options`
    pub fn set_using(
        question: &str,
        new_value: &str,
        _selector: Option<&str>,
        options: &SetOptions,
    ) -> Result<SetResponseList> {
        // TODO: use selector to only change values which match question + selector
        let include = options.include;

        let mut resp = Vec::new();

        let db_bytes = extract::extract_db()?;
        let parsed_db = package::read_db(&db_bytes)?;
        // all lists before the first write, so that no error follows a write
        parsed_db
            .iter()
            .try_for_each(package::ParsedPackageList::check_form_strings)?;

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

        // TODO: set returns {"responses":[]} and exits 0 when no question matches or no matching
        // question has a varstore, and aborts on the first write error even if another match is
        // writable; report what was written and what failed, and fail unless every match was
        // written.

        // Every form package selects its question and option before the first write, so that a
        // selection error leaves every variable unchanged.
        let mut selected = Vec::new();
        let mut excluded = IncludedStates::empty();
        // one cache for the selection, which ends before the first write
        let mut reader = EfivarReader::default();
        for list in parsed_db {
            for form_package in list.forms {
                // try to find the question
                let selection = forms::find_question(
                    form_package,
                    &list.strings,
                    &question_variations,
                    include,
                    &mut reader,
                );
                match forms::choice_for_set(selection, question, &reader)? {
                    Choice::Chosen(question_descriptor, state) => {
                        if !(question_descriptor.possible_options.is_empty()) {
                            chosen_option(&question_descriptor, &new_value_variations, include)?;
                        }
                        selected.push((list.guid.to_string(), question_descriptor, state));
                    }
                    // question not found in this form package
                    // or only in states that `include` does not allow
                    Choice::Skipped(states) => excluded |= states,
                }
            }
        }
        if selected.is_empty() && !excluded.is_empty() {
            return Err(SelectionError::Excluded {
                question: question.to_owned(),
                states: excluded,
            }
            .into());
        }
        drop(reader);

        for (guid, question_descriptor, state) in selected {
            // if the question_descriptor provides options then set the closest one from new_value_variations
            // (example whatever matches from [Enabled, Enable])
            // else try setting the new_value because it might be some arbitrary value like a number
            // (will return error if doesn't match constraints)
            let (modified, option_annotation) =
                if !(question_descriptor.possible_options.is_empty()) {
                    let option =
                        chosen_option(&question_descriptor, &new_value_variations, include)?;
                    (
                        forms::change_option(&question_descriptor, option)?,
                        option.state.option_annotation(),
                    )
                } else {
                    (
                        forms::change_value(&question_descriptor, new_value)?,
                        String::new(),
                    )
                };

            if modified {
                let set_resp = SetResponse {
                    // TODO: GUIDs repeat, also in errors; identify lists by HiiDB index
                    selector: guid,
                    backend: Backend::Hii,
                    is_translated,
                    question: Question {
                        options: question_descriptor.listed_options(include),
                        name: question_descriptor.question,
                        answer: new_value.to_owned() + &option_annotation + &state.annotation(),
                        help: question_descriptor.help,
                        ..Default::default()
                    },
                    modified: true,
                    ..Default::default()
                };

                resp.push(set_resp);
            }
        }

        Ok(SetResponseList {
            responses: resp,
            ..Default::default()
        })
    }

    /// get with `options`
    pub fn get_using(
        question: &str,
        _selector: Option<&str>,
        options: &GetOptions,
    ) -> Result<GetResponseList> {
        // TODO: use selector to only get questions which match question + selector
        // TODO: take a form@packagelist selector to pick one of the form packages that select
        // the question
        let include = options.include;

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
        let mut reader = EfivarReader::default();

        let mut excluded = IncludedStates::empty();
        for list in parsed_db {
            list.check_form_strings()?;

            for form_package in list.forms {
                let selection = forms::find_question(
                    form_package,
                    &list.strings,
                    &question_variations,
                    include,
                    &mut reader,
                );
                let (question_descriptor, state) = match selection.for_get() {
                    Choice::Chosen(question_descriptor, state) => (question_descriptor, state),
                    Choice::Skipped(states) => {
                        excluded |= states;
                        continue;
                    }
                };
                let mut get_resp = GetResponse {
                    selector: list.guid.to_string(),
                    backend: Backend::Hii,
                    is_translated,
                    // mapping the hii module's QuestionDescriptor to thrift codegen's Question
                    question: Question {
                        options: question_descriptor.listed_options(include),
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
                // after translate_response, which matches whole answers
                get_resp.question.answer += &question_descriptor.value_state.option_annotation();
                get_resp.question.answer += &state.annotation();

                resp.push(get_resp)
            }
        }
        if resp.is_empty() && !excluded.is_empty() {
            return Err(SelectionError::Excluded {
                question: question.to_owned(),
                states: excluded,
            }
            .into());
        }

        Ok(GetResponseList {
            responses: resp,
            ..Default::default()
        })
    }
}

/// The option of `question` that set writes for one of `texts`.
fn chosen_option<'a>(
    question: &'a QuestionDescriptor,
    texts: &HashSet<String>,
    include: IncludedStates,
) -> Result<&'a forms::AnswerOption> {
    // if not a single option matched then error out
    question
        .select_option(texts, include)?
        .ok_or_else(|| forms::ChangeValueError::InvalidOption.into())
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

#[cfg(test)]
mod tests {
    use crate::hii::package::hiidb_fixtures::en_strings_list;
    use crate::hii::package::hiidb_fixtures::en_strings_package;
    use crate::hii::package::hiidb_fixtures::form_set_package;
    use crate::hii::package::hiidb_fixtures::package_list_with_guid;
    use crate::hii::package::hiidb_fixtures::END_ONLY_FORM_PACKAGE;
    use crate::hii::package::hiidb_fixtures::END_PACKAGE;

    use super::*;

    /// A package list with GUID `guid` holding a FormSet titled by the
    /// one-character string `title` of its own strings package.
    fn form_set_list(guid: [u8; 16], title: u8) -> Vec<u8> {
        let packages = [
            form_set_package(),
            en_strings_package(title),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid(guid, &packages.concat())
    }

    /// show_ifr titles the FormSet of each package list with the strings of
    /// that list, in HiiDB order, duplicate GUIDs included.
    #[test]
    fn test_show_ifr_titles_form_sets_with_their_own_strings_in_hiidb_order() {
        let hiidb = [
            form_set_list([0x33; 16], b'A'),
            form_set_list([0x11; 16], b'C'),
            form_set_list([0x33; 16], b'B'),
        ]
        .concat();

        let ifr = HiiBackend::show_ifr(&hiidb)
            .expect("show the IFR")
            .readable_representation;

        let got: Vec<(&str, &str)> = ifr
            .split("Packagelist ")
            .skip(1)
            .map(|list| {
                let title = list
                    .split("FormSet - ")
                    .nth(1)
                    .and_then(|form_set| form_set.split(" - GUID").next());
                (list.get(..36).unwrap_or(list), title.unwrap_or(""))
            })
            .collect();
        let want = [
            ("33333333-3333-3333-3333-333333333333", "A"),
            ("11111111-1111-1111-1111-111111111111", "C"),
            ("33333333-3333-3333-3333-333333333333", "B"),
        ];
        assert_eq!(got, want, "package lists and FormSet titles in {ifr:?}");
    }

    /// list_strings returns the strings packages in HiiDB order, duplicate
    /// GUIDs included.
    #[test]
    fn test_list_strings_keeps_hiidb_order() {
        let hiidb = [
            en_strings_list([0x33; 16], b'A'),
            en_strings_list([0x11; 16], b'C'),
            en_strings_list([0x33; 16], b'B'),
        ]
        .concat();

        let got: Vec<(String, BTreeMap<i32, String>)> = HiiBackend::list_strings(&hiidb)
            .expect("list the strings")
            .into_iter()
            .map(|package| (package.package_list, package.string_package))
            .collect();

        let want = [
            ("33333333-3333-3333-3333-333333333333", "A"),
            ("11111111-1111-1111-1111-111111111111", "C"),
            ("33333333-3333-3333-3333-333333333333", "B"),
        ]
        .map(|(guid, string)| (guid.to_string(), BTreeMap::from([(1, string.to_string())])));
        assert_eq!(got, want, "strings packages in HiiDB order");
    }

    /// show_ifr and list_questions fail for a package list with forms but no
    /// strings packages, rather than use those of a list of the same GUID.
    #[test]
    fn test_forms_without_strings_are_an_error() {
        let forms_only = [&END_ONLY_FORM_PACKAGE[..], &END_PACKAGE].concat();
        let hiidb = [
            package_list_with_guid([0x44; 16], &forms_only),
            en_strings_list([0x44; 16], b'S'),
        ]
        .concat();
        let want = "Failed to get string packages using GUID 44444444-4444-4444-4444-444444444444";

        let Err(err) = HiiBackend::show_ifr(&hiidb) else {
            panic!("show_ifr used the strings of another list");
        };
        assert_eq!(format!("{err:#}"), want, "show_ifr");

        let Err(err) = HiiBackend::list_questions(&hiidb) else {
            panic!("list_questions used the strings of another list");
        };
        assert_eq!(format!("{err:#}"), want, "list_questions");
    }
}
