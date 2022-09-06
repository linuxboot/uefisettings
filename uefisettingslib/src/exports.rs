use std::collections::BTreeSet;
use std::fmt::Write;
use std::fs;
use std::path::Path;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use log::debug;
use serde_json::Value;
use uefisettingslib_api::Backend;
use uefisettingslib_api::GetResponse;
use uefisettingslib_api::GetResponseList;
use uefisettingslib_api::HiiDatabase;
use uefisettingslib_api::HiiShowIfrResponse;
use uefisettingslib_api::HiiStringsPackage;
use uefisettingslib_api::IloAttributes;
use uefisettingslib_api::MachineInfo;
use uefisettingslib_api::Question;
use uefisettingslib_api::SetResponse;
use uefisettingslib_api::SetResponseList;

use crate::hii::extract;
use crate::hii::forms;
use crate::hii::package;
use crate::ilorest::chif;
use crate::ilorest::requests;
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
                        // we went though all options and if it still wasnt modified then this isnt in the options
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

        let mut ilo_settings = IloAttributes {
            selector: ilo_device.settings_selector(),
            ..Default::default()
        };
        for (key, value) in ilo_device.get_current_settings()? {
            if let Value::String(v) = value {
                ilo_settings.attributes.insert(key, v);
            }
        }
        resp.push(ilo_settings);

        // TODO: show hidden OEM settings based on the device type

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

        let current_bios_settings = ilo_device.get_current_settings()?;
        if let Some(Value::String(_)) = current_bios_settings.get(&translated_question) {
            ilo_device.update_setting(&translated_question, &translated_new_value)?;

            let set_resp = SetResponse {
                selector: ilo_device.settings_selector(),
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

        // TODO add more debug/hidden OEM settings here based on machine_type

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

        let current_bios_settings = ilo_device.get_current_settings()?;
        if let Some(Value::String(s)) = current_bios_settings.get(&translated_question) {
            let mut get_resp = GetResponse {
                selector: ilo_device.settings_selector(),
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

        // TODO add more debug/hidden OEM settings here based on machine_type

        Ok(GetResponseList {
            responses: resp,
            ..Default::default()
        })
    }
}

/// auto-identify backend and get hardware/bios-information
pub fn identify_machine() -> Result<MachineInfo> {
    let mut backend = BTreeSet::new();

    if Path::new(extract::OCP_HIIDB_PATH).exists() {
        backend.insert(Backend::Hii);
    }
    if chif::check_ilo_connectivity().is_ok() {
        debug!("Backend Identified: Hii");
        backend.insert(Backend::Ilo);
    }

    if backend.is_empty() {
        return Err(anyhow!("Cannot identify backend"));
    } else {
        debug!("Supported Backends: {:?}", backend);
    }

    let resp = MachineInfo {
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
    };

    Ok(resp)
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
