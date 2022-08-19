use std::fmt::Write;

use anyhow::Context;
use anyhow::Result;
use serde_json::Value;
use uefisettingslib_api::Backend;
use uefisettingslib_api::GetResponse;
use uefisettingslib_api::HiiDatabase;
use uefisettingslib_api::HiiShowIfrResponse;
use uefisettingslib_api::HiiStringsPackage;
use uefisettingslib_api::IloAttributes;
use uefisettingslib_api::Question;
use uefisettingslib_api::SetResponse;

use crate::hii::extract;
use crate::hii::forms;
use crate::hii::package;
use crate::ilorest::requests;

/// SettingsBackend is a trait which should be satisfied by all backends (like ilo, hii)
pub trait SettingsBackend {
    /// set changes the value of the UEFI question/attribute
    fn set(question: &str, new_value: &str, selector: Option<&str>) -> Result<Vec<SetResponse>>;
    /// get displays the value of the UEFI question/attribute
    fn get(question: &str, selector: Option<&str>) -> Result<Vec<GetResponse>>;
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
    fn set(question: &str, new_value: &str, _selector: Option<&str>) -> Result<Vec<SetResponse>> {
        // TODO: use selector to only change values which match question + selector

        let mut resp = Vec::new();

        let db_bytes = extract::extract_db()?;
        let parsed_db = package::read_db(&db_bytes)?;

        for (guid, package_list) in parsed_db.forms {
            for form_package in package_list {
                // string_phrases contains just one item (input from user) now, but eventually
                // we plan to have a database which whill match similar strings
                let string_phrases = Vec::from([question.to_owned()]);

                let modified = forms::change_value(
                    form_package,
                    parsed_db
                        .strings
                        .get(&guid)
                        .context(format!("Failed to get string packages using GUID {}", guid))?,
                    &string_phrases,
                    new_value,
                )?;

                if modified {
                    let set_resp = SetResponse {
                        selector: guid.to_owned(),
                        backend: Backend::Hii,
                        question: Question {
                            name: question.to_owned(),
                            answer: new_value.to_owned(),
                            ..Default::default()
                        },
                        modified: true,
                        ..Default::default()
                    };
                    // TODO: make find_question call here so we can fill in the options as well

                    resp.push(set_resp)
                }
            }
        }

        Ok(resp)
    }

    fn get(question: &str, _selector: Option<&str>) -> Result<Vec<GetResponse>> {
        // TODO: use selector to only get questions which match question + selector

        let mut resp = Vec::new();

        let db_bytes = extract::extract_db()?;
        let parsed_db = package::read_db(&db_bytes)?;

        for (guid, package_list) in parsed_db.forms {
            for form_package in package_list {
                // string_phrases contains just one item (input from user) now, but eventually
                // we plan to have a database which whill match similar strings
                let string_phrases = Vec::from([question]);

                if let Some(answer) = forms::find_question(
                    form_package,
                    parsed_db
                        .strings
                        .get(&guid)
                        .context(format!("Failed to get string packages using GUID {}", guid))?,
                    &string_phrases,
                ) {
                    let mut get_resp = GetResponse {
                        selector: guid.to_owned(),
                        backend: Backend::Hii,
                        // mapping the hii module's QuestionDescriptor to thrift codegen's Question
                        question: Question {
                            name: answer.question,
                            answer: answer.value,
                            help: answer.help,
                            ..Default::default()
                        },
                        ..Default::default()
                    };

                    for opt in answer.possible_options {
                        get_resp.question.options.push(opt.value)
                    }

                    resp.push(get_resp)
                }
            }
        }

        Ok(resp)
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
    fn set(question: &str, new_value: &str, _selector: Option<&str>) -> Result<Vec<SetResponse>> {
        // TODO: use selector to only change values which match question + selector

        let mut resp = Vec::new();

        let machine_type = requests::identify_hpe_machine_type()?;
        let ilo_device = requests::get_device_instance(machine_type);

        let current_bios_settings = ilo_device.get_current_settings()?;
        if let Some(Value::String(_)) = current_bios_settings.get(question) {
            ilo_device.update_setting(question, new_value)?;

            let set_resp = SetResponse {
                selector: ilo_device.settings_selector(),
                backend: Backend::Ilo,
                question: Question {
                    name: question.to_owned(),
                    answer: new_value.to_owned(),
                    ..Default::default()
                },
                modified: true,
                ..Default::default()
            };

            resp.push(set_resp)
        }

        // TODO add more debug/hidden OEM settings here based on machine_type

        Ok(resp)
    }

    fn get(question: &str, _selector: Option<&str>) -> Result<Vec<GetResponse>> {
        // TODO: use selector to only get questions which match question + selector

        let mut resp = Vec::new();

        let machine_type = requests::identify_hpe_machine_type()?;
        let ilo_device = requests::get_device_instance(machine_type);

        let current_bios_settings = ilo_device.get_current_settings()?;
        if let Some(Value::String(s)) = current_bios_settings.get(question) {
            let get_resp = GetResponse {
                selector: ilo_device.settings_selector(),
                backend: Backend::Ilo,
                question: Question {
                    name: question.to_owned(),
                    answer: s.to_owned(),
                    ..Default::default()
                },
                ..Default::default()
            };

            resp.push(get_resp)
        }

        // TODO add more debug/hidden OEM settings here based on machine_type

        Ok(resp)
    }
}
