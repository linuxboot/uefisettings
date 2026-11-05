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

use std::collections::BTreeSet;
use std::fmt::Write;
use std::rc::Rc;

use anyhow::Result;

use uefisettings_backend_thrift::Backend;
use uefisettings_backend_thrift::GetResponse;
use uefisettings_backend_thrift::GetResponseList;
use uefisettings_backend_thrift::HiiShowIfrResponse;
use uefisettings_backend_thrift::HiiStringsPackage;
use uefisettings_backend_thrift::Question;
use uefisettings_backend_thrift::SetResponse;
use uefisettings_backend_thrift::SetResponseList;

#[cfg(capsule_delivery)]
use crate::efi_variables::deliver_json_capsule;
#[cfg(variable_names)]
use crate::efi_variables::list_variables;
#[cfg(any(variable_names, variable_info))]
use crate::efi_variables::parse_vendor;
#[cfg(variable_storage_info)]
use crate::efi_variables::query_storage;
#[cfg(capsule_delivery)]
pub use crate::efi_variables::CapsuleCapabilities;
#[cfg(capsule_delivery)]
pub use crate::efi_variables::CapsuleDelivered;
#[cfg(capsule_delivery)]
pub use crate::efi_variables::ResetType;
#[cfg(variable_info)]
use crate::efi_variables::VariableInfoSource;
#[cfg(variable_storage_info)]
pub use crate::efi_variables::VariableStorage;
#[cfg(target_os = "linux")]
pub use crate::hii::extract::EfivarMemory;
use crate::hii::forms;
use crate::hii::forms::list_questions;
use crate::hii::forms::Choice;
use crate::hii::forms::PasswordQuestions;
use crate::hii::package;
#[cfg(any(variable_names, variable_info))]
pub use crate::hii::package::Guid;
#[cfg(target_os = "linux")]
pub use crate::hii::DenialCause;
#[cfg(target_os = "linux")]
pub use crate::hii::EfivarDump;
use crate::hii::EfivarReader;
#[cfg(target_os = "linux")]
pub use crate::hii::EfivarRedaction;
pub use crate::hii::EfivarSource;
use crate::hii::FirmwareVariables;
#[cfg(target_os = "linux")]
pub use crate::hii::LockdownMode;
#[cfg(target_os = "linux")]
pub use crate::hii::LockdownUnknown;
#[cfg(target_os = "linux")]
pub use crate::hii::MemoryAccessDenied;
#[cfg(target_os = "linux")]
pub use crate::hii::MemoryDevice;
#[cfg(target_os = "linux")]
pub use crate::hii::MemoryMapUnavailable;
#[cfg(target_os = "linux")]
pub use crate::hii::MemoryOperation;
/// Only on Linux x86, x86_64 and aarch64, where uefisettings reads a firmware memory map.
#[cfg(firmware_memory_maps)]
pub use crate::hii::MemoryType;
/// Only on Linux x86, x86_64 and aarch64, where uefisettings reads a firmware memory map.
#[cfg(firmware_memory_maps)]
pub use crate::hii::RangeRefusal;
#[cfg(variable_storage_info)]
pub use crate::hii::VariableAttributes;
#[cfg(any(variable_names, variable_info))]
pub use crate::hii::VariableKey;
use crate::translation::get_qa_variations_hii;
use crate::translation::translate_response;
use crate::translation::HiiTranslation;

pub use crate::hii::forms::AccessLevel;
pub use crate::hii::forms::IncludedStates;
pub use crate::hii::forms::QuestionState;
pub use crate::hii::forms::SelectionError;
pub use crate::hii::forms::SetupPasswordPolicy;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "uefi")]
mod uefi;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(variable_info)]
pub use crate::efi_variables::VariableInfo;
#[cfg(target_os = "linux")]
pub use linux::identify_machine;
#[cfg(target_os = "linux")]
pub use linux::IloBackend;

/// SettingsBackend is a trait which should be satisfied by all backends (like ilo, hii)
pub trait SettingsBackend {
    /// set changes the value of the UEFI question/attribute
    fn set(question: &str, new_value: &str, selector: Option<&str>) -> Result<SetResponseList>;
    /// get displays the value of the UEFI question/attribute
    fn get(question: &str, selector: Option<&str>) -> Result<GetResponseList>;
}

pub struct HiiBackend {}

/// The EFI variables of this machine, never their data (UEFI 2.10 §8.2).
#[cfg(any(variable_names, variable_info, variable_storage_info))]
pub struct VariableBackend {}

#[cfg(variable_names)]
impl VariableBackend {
    /// The name and vendor GUID of every EFI variable of this machine, sorted by name, then
    /// vendor; only those of the vendor GUID `vendor`, such as
    /// "8BE4DF61-93CA-11D2-AA0D-00E098032B8C", if given.
    pub fn list(vendor: Option<&str>) -> Result<Vec<VariableKey>> {
        let vendor = vendor.map(parse_vendor).transpose()?;
        list_variables(&Self::system_variable_names(), vendor)
    }
}

#[cfg(variable_info)]
impl VariableBackend {
    /// The VariableInfo of the EFI variable `name` of the vendor GUID `vendor`, such as
    /// "8BE4DF61-93CA-11D2-AA0D-00E098032B8C", without its data, which only the Windows build
    /// reads.
    pub fn info(name: &str, vendor: &str) -> Result<VariableInfo> {
        let key = VariableKey {
            name: name.to_owned(),
            guid: parse_vendor(vendor)?,
        };
        Self::system_variable_info()?.variable_info(&key)
    }
}

#[cfg(variable_storage_info)]
impl VariableBackend {
    /// What QueryVariableInfo() tells of the storage of this machine's EFI variables of
    /// `attributes`.
    pub fn storage(attributes: VariableAttributes) -> Result<VariableStorage> {
        query_storage(&Self::system_variable_storage(), attributes)
    }
}

/// The capsules for this machine's firmware (UEFI 2.11 §8.5.3).
#[cfg(capsule_delivery)]
pub struct CapsuleBackend {}

#[cfg(capsule_delivery)]
impl CapsuleBackend {
    /// Delivers `payload`, unchanged, to this machine's firmware as a JSON capsule whose
    /// EFI_JSON_CAPSULE_HEADER carries `capsule_id` (UEFI 2.11 §23.5); an empty payload is
    /// refused first. It never resets the machine.
    pub fn deliver_json(payload: &[u8], capsule_id: u32) -> Result<CapsuleDelivered> {
        deliver_json_capsule(&Self::system_capsule_delivery(), payload, capsule_id)
    }
}

/// The options of HiiBackend::get_using.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct GetOptions {
    /// The states of the questions to select and of the options to list too
    pub include: IncludedStates,
    /// Where to read question values
    pub efivars: EfivarSource,
    /// The AMI Setup access level that conditions read instead of the stored one, if stated
    pub access_level: Option<AccessLevel>,
}

/// The options of HiiBackend::set_using.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SetOptions {
    /// The states of the questions and options to select too
    pub include: IncludedStates,
    /// The AMI Setup access level that conditions read instead of the stored one, if stated
    pub access_level: Option<AccessLevel>,
    /// In the UEFI Shell, whether set writes in a HiiDB that declares a setup password question
    pub setup_password: SetupPasswordPolicy,
}

/// The options of HiiBackend::list_questions_using.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ListQuestionsOptions {
    /// The states of the questions and options to list too
    pub include: IncludedStates,
    /// Where to read question values
    pub efivars: EfivarSource,
    /// The AMI Setup access level that conditions read instead of the stored one, if stated
    pub access_level: Option<AccessLevel>,
}

/// The options of HiiBackend::show_ifr_using.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ShowIfrOptions {
    /// Where to read question values
    pub efivars: EfivarSource,
}

/// The options of HiiBackend::dump_efivars.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct DumpEfivarsOptions {
    /// Which bytes of each efivar file to keep
    pub redaction: EfivarRedaction,
}

impl HiiBackend {
    /// show_ifr returns a human readable representation of the forms in Hii
    pub fn show_ifr(db_bytes: &[u8]) -> Result<HiiShowIfrResponse> {
        Self::show_ifr_using(db_bytes, &ShowIfrOptions::default())
    }

    /// show_ifr with `options`
    pub fn show_ifr_using(db_bytes: &[u8], options: &ShowIfrOptions) -> Result<HiiShowIfrResponse> {
        Self::show_ifr_in(db_bytes, options.efivars.clone().into_variables()?)
    }

    /// show_ifr, reading question values from `variables`
    fn show_ifr_in(
        db_bytes: &[u8],
        variables: Box<dyn FirmwareVariables>,
    ) -> Result<HiiShowIfrResponse> {
        // We depend on the caller to provide us with the hiidb instead of calling extract here
        // because they might want to provide a file instead.

        let mut readable_representation = String::new();

        let (parsed_db, mut reader) = read_db_withholding(db_bytes, variables)?;

        for list in parsed_db {
            list.check_form_strings()?;
            // no header for a list without forms
            if list.forms.is_empty() {
                continue;
            }
            writeln!(readable_representation, "Packagelist {}", list.guid)?;
            for root in list.forms {
                readable_representation.push_str(&forms::display(
                    root,
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
        Self::list_questions_in(db_bytes, options, options.efivars.clone().into_variables()?)
    }

    /// list_questions with `options`, reading question values from `variables`
    fn list_questions_in(
        db_bytes: &[u8],
        options: &ListQuestionsOptions,
        variables: Box<dyn FirmwareVariables>,
    ) -> Result<Vec<Question>> {
        let include = options.include;
        let mut res = Vec::new();
        let (parsed_db, mut reader) = read_db_withholding(db_bytes, variables)?;
        forms::check_access_level(
            parsed_db.iter().flat_map(|list| &list.forms),
            options.access_level,
        )?;
        for list in parsed_db {
            list.check_form_strings()?;

            for root in list.forms {
                //  TODO: show form name, package list guid in the final response as well

                for (question_descriptor, state) in list_questions(
                    root,
                    &list.strings,
                    include,
                    options.access_level,
                    &mut reader,
                ) {
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

#[cfg(all(system_hiidb, system_variables))]
impl SettingsBackend for HiiBackend {
    fn set(question: &str, new_value: &str, selector: Option<&str>) -> Result<SetResponseList> {
        Self::set_using(question, new_value, selector, &SetOptions::default())
    }

    fn get(question: &str, selector: Option<&str>) -> Result<GetResponseList> {
        Self::get_using(
            &Self::system_hiidb()?,
            question,
            selector,
            &GetOptions::default(),
        )
    }
}

impl HiiBackend {
    /// set with `options`, in this machine's HiiDB and variables, as set_in does.
    #[cfg(all(system_hiidb, system_variables))]
    pub fn set_using(
        question: &str,
        new_value: &str,
        selector: Option<&str>,
        options: &SetOptions,
    ) -> Result<SetResponseList> {
        Self::set_in(
            &Self::system_hiidb()?,
            question,
            new_value,
            selector,
            options,
            EfivarSource::System.into_variables()?,
            &Self::system_variables()?,
        )
    }

    /// set in the HiiDB `db_bytes` with `options`, selecting by the values of `reads`, which it
    /// reads before the first write, and writing through `writes`, neither of them withheld
    /// variables (PasswordQuestions::withholding): fails with SelectionError::NotFound when no
    /// question has the text, and unless every selected match is written, also after writing the
    /// others.
    #[cfg_attr(
        not(system_variables),
        allow(
            dead_code,
            reason = "set writes only the variables of the machine, which this build does not reach"
        )
    )]
    fn set_in(
        db_bytes: &[u8],
        question: &str,
        new_value: &str,
        _selector: Option<&str>,
        options: &SetOptions,
        reads: Box<dyn FirmwareVariables>,
        writes: &dyn FirmwareVariables,
    ) -> Result<SetResponseList> {
        // TODO: use selector to only change values which match question + selector
        let include = options.include;

        let mut resp = Vec::new();

        let parsed_db = package::read_db(db_bytes)?;
        let passwords = PasswordQuestions::of(parsed_db.iter().flat_map(|list| &list.forms));
        let reader = EfivarReader::with_variables(Box::new(passwords.withholding(reads)?));
        let writes = passwords.withholding(writes)?;
        passwords.check_set(writes.reach(), options.setup_password)?;

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

        let selected = select_for_set(&parsed_db, question, &question_variations, options, reader)?;

        let option_annotations: Vec<String> = forms::set_questions(
            question,
            &selected
                .iter()
                .map(|(guid, question_descriptor, _)| (guid.as_str(), question_descriptor))
                .collect::<Vec<_>>(),
            new_value,
            &new_value_variations,
            include,
            &writes,
        )?
        .into_iter()
        .map(|chosen| chosen.map_or_else(String::new, |option| option.state.option_annotation()))
        .collect();

        for ((guid, question_descriptor, state), option_annotation) in
            selected.into_iter().zip(option_annotations)
        {
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

        Ok(SetResponseList {
            responses: resp,
            ..Default::default()
        })
    }

    /// get from the HiiDB `db_bytes`, with `options`
    pub fn get_using(
        db_bytes: &[u8],
        question: &str,
        selector: Option<&str>,
        options: &GetOptions,
    ) -> Result<GetResponseList> {
        Self::get_in(
            db_bytes,
            question,
            selector,
            options,
            options.efivars.clone().into_variables()?,
        )
    }

    /// get with `options`, reading question values from `variables`
    fn get_in(
        db_bytes: &[u8],
        question: &str,
        _selector: Option<&str>,
        options: &GetOptions,
        variables: Box<dyn FirmwareVariables>,
    ) -> Result<GetResponseList> {
        // TODO: use selector to only get questions which match question + selector
        // TODO: take a form@packagelist selector to pick one of the FormSets that select
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

        let (parsed_db, mut reader) = read_db_withholding(db_bytes, variables)?;
        forms::check_access_level(
            parsed_db.iter().flat_map(|list| &list.forms),
            options.access_level,
        )?;

        let mut excluded = IncludedStates::empty();
        for list in parsed_db {
            list.check_form_strings()?;

            for root in list.forms {
                let selection = forms::find_question(
                    root,
                    &list.strings,
                    &question_variations,
                    include,
                    options.access_level,
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

/// The package lists of the HiiDB `db_bytes`, and a reader of `variables` without the variables
/// that its password questions name, as their reach withholds (PasswordQuestions::withholding).
fn read_db_withholding(
    db_bytes: &[u8],
    variables: Box<dyn FirmwareVariables>,
) -> Result<(Vec<package::ParsedPackageList>, EfivarReader)> {
    let parsed_db = package::read_db(db_bytes)?;
    let passwords = PasswordQuestions::of(parsed_db.iter().flat_map(|list| &list.forms));
    let reader = EfivarReader::with_variables(Box::new(passwords.withholding(variables)?));
    Ok((parsed_db, reader))
}

/// set's phase before its first write, so that no error follows a write: checks every package
/// list of `parsed_db` and the stated access level, then selects, in each FormSet, the question
/// of `question_variations` that set writes, reading each range once with `reader`; returns them
/// with the GUID of their package list, or SelectionError::Excluded for `question` if each
/// FormSet skips it for its states.
fn select_for_set(
    parsed_db: &[package::ParsedPackageList],
    question: &str,
    question_variations: &BTreeSet<String>,
    options: &SetOptions,
    mut reader: EfivarReader,
) -> Result<Vec<(String, forms::QuestionDescriptor, forms::StateEvaluation)>> {
    forms::check_access_level(
        parsed_db.iter().flat_map(|list| &list.forms),
        options.access_level,
    )?;
    parsed_db
        .iter()
        .try_for_each(package::ParsedPackageList::check_form_strings)?;

    // Every FormSet selects its question and option before the first write, so that a
    // selection error leaves every variable unchanged.
    let mut selected = Vec::new();
    let mut excluded = IncludedStates::empty();
    for list in parsed_db {
        for root in &list.forms {
            // try to find the question
            let selection = forms::find_question(
                Rc::clone(root),
                &list.strings,
                question_variations,
                options.include,
                options.access_level,
                &mut reader,
            );
            match forms::choice_for_set(selection, question, &reader)? {
                Choice::Chosen(question_descriptor, state) => {
                    selected.push((list.guid.to_string(), question_descriptor, state));
                }
                // question not found in this FormSet
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
    Ok(selected)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    #[cfg(efivar_dumps)]
    use std::fs;
    use std::rc::Rc;

    use crate::hii::forms::ifr_fixtures::checkbox_at;
    use crate::hii::forms::ifr_fixtures::checkbox_on;
    use crate::hii::forms::ifr_fixtures::conditional;
    use crate::hii::forms::ifr_fixtures::eq_id_val_of;
    use crate::hii::forms::ifr_fixtures::form;
    use crate::hii::forms::ifr_fixtures::form_set;
    use crate::hii::forms::ifr_fixtures::nested;
    use crate::hii::forms::ifr_fixtures::on_small_stack;
    use crate::hii::forms::ifr_fixtures::operation;
    use crate::hii::forms::ifr_fixtures::password_on;
    use crate::hii::forms::ifr_fixtures::subtitle_scope;
    use crate::hii::forms::ifr_fixtures::var_store;
    use crate::hii::forms::ifr_fixtures::var_store_efi;
    use crate::hii::forms::ifr_fixtures::MemoryVariables;
    use crate::hii::forms::ifr_fixtures::VariableInterface;
    use crate::hii::forms::ifr_fixtures::VariableKey;
    use crate::hii::forms::ifr_fixtures::VariableReach;
    use crate::hii::forms::ifr_fixtures::END;
    use crate::hii::forms::ifr_fixtures::GRAY_OUT_IF;
    use crate::hii::forms::ifr_fixtures::NIL_GUID;
    use crate::hii::forms::ifr_fixtures::NV_BS;
    use crate::hii::forms::ifr_fixtures::NV_BS_RT;
    use crate::hii::forms::ifr_fixtures::SYSTEM_ACCESS_GUID;
    use crate::hii::forms::MAX_SCOPE_NESTING;
    use crate::hii::package::hiidb_fixtures::en_strings_list;
    use crate::hii::package::hiidb_fixtures::en_strings_package;
    use crate::hii::package::hiidb_fixtures::en_strings_package_of;
    use crate::hii::package::hiidb_fixtures::form_package;
    use crate::hii::package::hiidb_fixtures::form_set_package;
    use crate::hii::package::hiidb_fixtures::package_list_with_guid;
    use crate::hii::package::hiidb_fixtures::END_PACKAGE;
    use crate::hii::package::Guid;

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
        // no variables: on Windows, System enables a privilege that needs elevation
        let options = ShowIfrOptions {
            efivars: EfivarSource::Disabled,
        };

        let ifr = HiiBackend::show_ifr_using(&hiidb, &options)
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

    /// show_ifr ends the line of each package list's header before the forms of that list.
    #[test]
    fn test_show_ifr_ends_each_package_list_line_before_its_forms() {
        let hiidb = [
            form_set_list([0x33; 16], b'A'),
            form_set_list([0x11; 16], b'C'),
        ]
        .concat();
        // no variables: on Windows, System enables a privilege that needs elevation
        let options = ShowIfrOptions {
            efivars: EfivarSource::Disabled,
        };

        let ifr = HiiBackend::show_ifr_using(&hiidb, &options)
            .expect("show the IFR")
            .readable_representation;

        let lines: Vec<&str> = ifr.lines().collect();
        let headers: Vec<(&str, &str)> = lines
            .windows(2)
            .filter(|pair| pair[0].starts_with("Packagelist "))
            .map(|pair| (pair[0], pair[1]))
            .collect();
        let want = [
            (
                "Packagelist 33333333-3333-3333-3333-333333333333",
                "OpCode: ROOT",
            ),
            (
                "Packagelist 11111111-1111-1111-1111-111111111111",
                "OpCode: ROOT",
            ),
        ];
        assert_eq!(
            headers, want,
            "package list lines and the lines after them in {ifr:?}"
        );
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

    /// get, list-questions and show-ifr read question values from the source that their
    /// options name.
    #[cfg(efivar_dumps)]
    #[test]
    fn options_name_the_efivar_source() {
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, 1),
                form(1, &[checkbox_on(1, 1, 1)]),
            ]),
            en_strings_package(b'Q'),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x55; 16], &packages.concat());
        let efivars = tempfile::tempdir().expect("create efivars directory");
        fs::write(
            efivars
                .path()
                .join("Setup-00000000-0000-0000-0000-000000000000"),
            [7, 0, 0, 0, 1],
        )
        .expect("write efivar file");
        // show-ifr adds no IFR default
        let cases = [
            (
                "Directory",
                EfivarSource::Directory(efivars.path().to_path_buf()),
                "1",
                "1",
            ),
            (
                "Disabled",
                EfivarSource::Disabled,
                "<ValueUnavailable: EFI variables not read> <IFR default: 0>",
                "<ValueUnavailable: EFI variables not read>",
            ),
        ];

        for (case, efivars, want, want_shown) in cases {
            let get_options = GetOptions {
                efivars: efivars.clone(),
                ..GetOptions::default()
            };
            let list_options = ListQuestionsOptions {
                efivars: efivars.clone(),
                ..ListQuestionsOptions::default()
            };
            let got = HiiBackend::get_using(&hiidb, "Q", None, &get_options).expect("get");
            let listed =
                HiiBackend::list_questions_using(&hiidb, &list_options).expect("list questions");
            let ifr = HiiBackend::show_ifr_using(&hiidb, &ShowIfrOptions { efivars })
                .expect("show the IFR")
                .readable_representation;

            let answers: Vec<&str> = got
                .responses
                .iter()
                .map(|response| response.question.answer.as_str())
                .collect();
            assert_eq!(answers, [want], "{case}: get");
            let answers: Vec<&str> = listed
                .iter()
                .map(|question| question.answer.as_str())
                .collect();
            assert_eq!(answers, [want], "{case}: list-questions");
            assert!(
                ifr.contains(&format!("-Answer: {want_shown}\n")),
                "{case}: show-ifr {ifr:?}"
            );
        }
    }

    /// The variable of the EFI variable VarStore Setup of password_hiidb.
    fn setup() -> VariableKey {
        VariableKey {
            name: "Setup".to_string(),
            guid: NIL_GUID,
        }
    }

    /// The variable of the buffer VarStore AMITSESetup of password_hiidb.
    fn amitse_setup() -> VariableKey {
        VariableKey {
            name: "AMITSESetup".to_string(),
            guid: Guid {
                data1: 0x44444444,
                data2: 0x4444,
                data3: 0x4444,
                data4: [0x44; 8],
            },
        }
    }

    /// A HiiDB whose FormSet has the CHECKBOX Q at byte 0 of the EFI variable Setup and, on the
    /// buffer VarStore AMITSESetup of AMI's layout, a PASSWORD at byte 0 and the CHECKBOX P at
    /// byte 80.
    fn password_hiidb() -> Vec<u8> {
        password_hiidb_with(password_on(3, 3, 2, 0))
    }

    /// password_hiidb with the PASSWORD op `password`.
    fn password_hiidb_with(password: Vec<u8>) -> Vec<u8> {
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, 1),
                var_store(2, [0x44; 16], "AMITSESetup", 81),
                form(
                    1,
                    &[checkbox_on(1, 1, 1), password, checkbox_at(2, 2, 2, 80)],
                ),
            ]),
            en_strings_package_of(&["Q", "P", "Password"]),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid([0x55; 16], &packages.concat())
    }

    /// The variables of password_hiidb, which reach `reach` through `interface`: Setup holds 0,
    /// AMITSESetup 80 bytes of 0xAA, a password, and then 1.
    fn password_variables(
        reach: VariableReach,
        interface: VariableInterface,
    ) -> Rc<MemoryVariables> {
        let variables = MemoryVariables::new(reach, interface);
        variables.insert(setup(), NV_BS_RT, &[0]);
        variables.insert(
            amitse_setup(),
            NV_BS_RT,
            &[[0xAA; 80].as_slice(), &[1]].concat(),
        );
        Rc::new(variables)
    }

    /// `variables`, shared with the caller.
    fn shared(variables: &Rc<MemoryVariables>) -> Box<dyn FirmwareVariables> {
        Box::new(Rc::clone(variables))
    }

    /// Through variables that reach BootServices, get, list-questions and show-ifr read no data
    /// of a VarStore that a password question names, whose questions show why; through those
    /// that reach Runtime they read it, as before.
    #[test]
    fn password_var_stores_are_read_only_through_runtime_variables() {
        let cases = [
            (
                VariableReach::Runtime,
                VariableInterface::Efivarfs,
                "1",
                "1",
                vec![81],
            ),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
                "<ValueUnavailable: VarStore holds a password> <IFR default: 0>",
                "<ValueUnavailable: VarStore holds a password>",
                vec![],
            ),
        ];

        for (reach, interface, want, want_shown, want_reads) in cases {
            let variables = password_variables(reach, interface);
            let got = HiiBackend::get_in(
                &password_hiidb(),
                "P",
                None,
                &GetOptions::default(),
                shared(&variables),
            )
            .expect("get");
            let listed = HiiBackend::list_questions_in(
                &password_hiidb(),
                &ListQuestionsOptions::default(),
                shared(&variables),
            )
            .expect("list questions");
            let ifr = HiiBackend::show_ifr_in(&password_hiidb(), shared(&variables))
                .expect("show the IFR")
                .readable_representation;

            let answers: Vec<&str> = got
                .responses
                .iter()
                .map(|response| response.question.answer.as_str())
                .collect();
            assert_eq!(answers, [want], "{reach:?}: get");
            let answers: Vec<&str> = listed
                .iter()
                .filter(|question| question.name == "P")
                .map(|question| question.answer.as_str())
                .collect();
            assert_eq!(answers, [want], "{reach:?}: list-questions");
            assert!(
                ifr.contains(&format!("-Answer: {want_shown}\n")),
                "{reach:?}: show-ifr {ifr:?}"
            );
            assert_eq!(
                variables.reads_of(&amitse_setup()),
                want_reads.repeat(3),
                "{reach:?}: reads of AMITSESetup"
            );
        }
    }

    /// set through variables that reach BootServices, in a HiiDB that declares a password
    /// question, refuses unless the caller bypasses, and never reads or writes a VarStore that a
    /// password question names; set through those that reach Runtime writes either, as before;
    /// whatever their interface.
    #[test]
    fn set_follows_the_setup_password_policy() {
        let refusal = "this HiiDB declares a setup password question; the UEFI Shell runs no \
                       setup browser, so no password is asked or checked; pass \
                       --bypass-setup-password to write anyway";
        let withheld = "EFI variable AMITSESetup-44444444-4444-4444-4444-444444444444 holds a \
                        password, which the UEFI Shell build never reads or writes";
        let cases = [
            (
                VariableReach::Runtime,
                VariableInterface::Efivarfs,
                "Q",
                SetupPasswordPolicy::Refuse,
                Ok(()),
                vec![(0, vec![1])],
                vec![],
            ),
            (
                VariableReach::Runtime,
                VariableInterface::Efivarfs,
                "P",
                SetupPasswordPolicy::Refuse,
                Ok(()),
                vec![],
                vec![(80, vec![0])],
            ),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
                "Q",
                SetupPasswordPolicy::Refuse,
                Err(refusal),
                vec![],
                vec![],
            ),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
                "Q",
                SetupPasswordPolicy::Bypass,
                Ok(()),
                vec![(0, vec![1])],
                vec![],
            ),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
                "P",
                SetupPasswordPolicy::Refuse,
                Err(refusal),
                vec![],
                vec![],
            ),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
                "P",
                SetupPasswordPolicy::Bypass,
                Err(withheld),
                vec![],
                vec![],
            ),
            (
                VariableReach::BootServices,
                VariableInterface::Efivarfs,
                "Q",
                SetupPasswordPolicy::Refuse,
                Err(refusal),
                vec![],
                vec![],
            ),
            (
                VariableReach::BootServices,
                VariableInterface::Efivarfs,
                "P",
                SetupPasswordPolicy::Bypass,
                Err(withheld),
                vec![],
                vec![],
            ),
            (
                VariableReach::Runtime,
                VariableInterface::VariableServices,
                "P",
                SetupPasswordPolicy::Refuse,
                Ok(()),
                vec![],
                vec![(80, vec![0])],
            ),
        ];

        for (reach, interface, question, policy, want, want_setup, want_amitse_setup) in cases {
            let variables = password_variables(reach, interface);
            let options = SetOptions {
                setup_password: policy,
                ..SetOptions::default()
            };
            let value = match question {
                "Q" => "1",
                _ => "0",
            };

            let got = HiiBackend::set_in(
                &password_hiidb(),
                question,
                value,
                None,
                &options,
                shared(&variables),
                &*variables,
            );

            let case = format!("{reach:?}, {interface:?}, set {question} {value}, {policy:?}");
            assert_eq!(
                got.map(drop).map_err(|error| error.to_string()),
                want.map_err(str::to_string),
                "{case}"
            );
            assert_eq!(variables.writes_to(&setup()), want_setup, "{case}: Setup");
            assert_eq!(
                variables.writes_to(&amitse_setup()),
                want_amitse_setup,
                "{case}: AMITSESetup"
            );
            if reach == VariableReach::BootServices {
                assert_eq!(
                    variables.reads_of(&amitse_setup()),
                    Vec::<u16>::new(),
                    "{case}: reads of AMITSESetup"
                );
            }
        }
    }

    /// A HiiDB whose FormSet has the CHECKBOX Q at byte 0 of the EFI variable Setup, which its
    /// VARSTORE_EFI declares NV|BS.
    fn boot_service_only_hiidb() -> Vec<u8> {
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS, 1),
                form(1, &[checkbox_on(1, 1, 1)]),
            ]),
            en_strings_package_of(&["Q"]),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid([0x55; 16], &packages.concat())
    }

    /// set decides, through variables that reach Runtime, through efivarfs or the firmware
    /// environment calls, by the attributes of the variable of a VARSTORE_EFI declared NV|BS: it
    /// refuses the variable without EFI_VARIABLE_RUNTIME_ACCESS before any write, and writes the
    /// one with it, keeping them.
    #[test]
    fn set_decides_runtime_access_by_the_variables_own_attributes() {
        let refusal = "EFI variable Setup-00000000-0000-0000-0000-000000000000 has no \
                       EFI_VARIABLE_RUNTIME_ACCESS (attributes 0x3), so the firmware refuses to \
                       write it at OS runtime";
        let cases = [
            (NV_BS, Err(refusal), vec![], vec![3, 0, 0, 0, 0]),
            (NV_BS_RT, Ok(()), vec![(0, vec![1])], vec![7, 0, 0, 0, 1]),
        ];

        for interface in [
            VariableInterface::Efivarfs,
            VariableInterface::FirmwareEnvironment,
        ] {
            for (attributes, want, want_writes, want_bytes) in cases.clone() {
                let variables = MemoryVariables::new(VariableReach::Runtime, interface);
                variables.insert(setup(), attributes, &[0]);
                let variables = Rc::new(variables);

                let got = HiiBackend::set_in(
                    &boot_service_only_hiidb(),
                    "Q",
                    "1",
                    None,
                    &SetOptions::default(),
                    shared(&variables),
                    &*variables,
                );

                let case = format!("{interface:?}, attributes {attributes:#x}");
                assert_eq!(
                    got.map(drop).map_err(|error| error.to_string()),
                    want.map_err(str::to_string),
                    "{case}"
                );
                assert_eq!(variables.writes_to(&setup()), want_writes, "{case}: writes");
                assert_eq!(variables.bytes(&setup()), Some(want_bytes), "{case}: bytes");
            }
        }
    }

    /// Through variables that reach BootServices, a HiiDB with a PASSWORD op whose VarStore is
    /// unknown has get, list-questions, show-ifr and set read and write no variable, even with
    /// --bypass-setup-password; through those that reach Runtime they work, as before.
    #[test]
    fn unresolved_password_closes_every_variable_to_boot_services() {
        let hiidb = password_hiidb_with(password_on(3, 3, 9, 0));
        let closed = "PASSWORD question 0x0003 in FormSet 11111111-1111-1111-1111-111111111111: \
                      no supported varstore with matching id 0x0009 found; as the variable of \
                      that password is unknown, the UEFI Shell build reads and writes no variable \
                      of this HiiDB";
        let set = |variables: &Rc<MemoryVariables>, setup_password| {
            let options = SetOptions {
                setup_password,
                ..SetOptions::default()
            };
            HiiBackend::set_in(
                &hiidb,
                "Q",
                "1",
                None,
                &options,
                shared(variables),
                &**variables,
            )
            .map(drop)
            .map_err(|error| error.to_string())
        };

        let variables = password_variables(
            VariableReach::BootServices,
            VariableInterface::VariableServices,
        );
        let got = HiiBackend::get_in(
            &hiidb,
            "Q",
            None,
            &GetOptions::default(),
            shared(&variables),
        );
        let listed = HiiBackend::list_questions_in(
            &hiidb,
            &ListQuestionsOptions::default(),
            shared(&variables),
        );
        let shown = HiiBackend::show_ifr_in(&hiidb, shared(&variables));
        assert_eq!(
            got.map(drop).map_err(|error| error.to_string()),
            Err(closed.to_string()),
            "BootServices: get"
        );
        assert_eq!(
            listed.map(drop).map_err(|error| error.to_string()),
            Err(closed.to_string()),
            "BootServices: list-questions"
        );
        assert_eq!(
            shown.map(drop).map_err(|error| error.to_string()),
            Err(closed.to_string()),
            "BootServices: show-ifr"
        );
        assert_eq!(
            set(&variables, SetupPasswordPolicy::Refuse),
            Err(closed.to_string()),
            "BootServices: set"
        );
        assert_eq!(
            set(&variables, SetupPasswordPolicy::Bypass),
            Err(closed.to_string()),
            "BootServices: set --bypass-setup-password"
        );
        assert_eq!(variables.reads(), [], "BootServices: reads");
        assert_eq!(variables.writes_to(&setup()), [], "BootServices: writes");

        let variables = password_variables(VariableReach::Runtime, VariableInterface::Efivarfs);
        let got = HiiBackend::get_in(
            &hiidb,
            "Q",
            None,
            &GetOptions::default(),
            shared(&variables),
        )
        .expect("get through Runtime");
        let answers: Vec<&str> = got
            .responses
            .iter()
            .map(|response| response.question.answer.as_str())
            .collect();
        assert_eq!(answers, ["0"], "Runtime: get");
        assert_eq!(
            set(&variables, SetupPasswordPolicy::Refuse),
            Ok(()),
            "Runtime: set"
        );
        assert_eq!(
            variables.writes_to(&setup()),
            [(0, vec![1])],
            "Runtime: writes"
        );
    }

    /// A HiiDB of two package lists: one whose FormSet declares no VarStore, then one whose
    /// question Q, on the EFI variable Setup, is grayed out when question 2, on `var_store`, is 1.
    fn access_level_hiidb(var_store: Vec<u8>) -> Vec<u8> {
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, 1),
                var_store,
                form(
                    1,
                    &[
                        checkbox_on(2, 2, 2),
                        conditional(GRAY_OUT_IF, eq_id_val_of(2, 1), &[checkbox_on(1, 1, 1)]),
                    ],
                ),
            ]),
            en_strings_package(b'Q'),
            END_PACKAGE.to_vec(),
        ];
        [
            form_set_list([0x33; 16], b'A'),
            package_list_with_guid([0x55; 16], &packages.concat()),
        ]
        .concat()
    }

    /// set selects at a stated access level, before any write, and refuses one for a HiiDB that
    /// declares no SystemAccess.
    #[cfg(efivar_dumps)]
    #[test]
    fn set_selects_at_the_stated_access_level() {
        let ami = access_level_hiidb(var_store(2, SYSTEM_ACCESS_GUID, "SystemAccess", 1));
        let other = access_level_hiidb(var_store(2, [0; 16], "SystemAccess", 1));
        let efivars = tempfile::tempdir().expect("create efivars directory");
        fs::write(
            efivars
                .path()
                .join("Setup-00000000-0000-0000-0000-000000000000"),
            [7, 0, 0, 0, 1],
        )
        .expect("write efivar file");
        let select = |hiidb: &[u8], access_level| {
            let options = SetOptions {
                access_level,
                ..SetOptions::default()
            };
            select_for_set(
                &package::read_db(hiidb).expect("parse the HiiDB"),
                "Q",
                &BTreeSet::from(["Q".to_string()]),
                &options,
                EfivarReader::new(EfivarSource::Directory(efivars.path().to_path_buf()))
                    .expect("create a reader of the efivars directory"),
            )
            .map(|selected| {
                selected
                    .into_iter()
                    .map(|(_, question, _)| question.question)
                    .collect::<Vec<_>>()
            })
        };

        assert_eq!(
            select(&ami, Some(AccessLevel::Administrator)).expect("select as Administrator"),
            ["Q"],
            "Administrator"
        );
        let user = select(&ami, Some(AccessLevel::User)).expect_err("select as User");
        assert_eq!(
            user.downcast_ref::<SelectionError>(),
            Some(&SelectionError::Excluded {
                question: "Q".to_string(),
                states: IncludedStates::GRAYED_OUT,
            }),
            "User: {user:#}"
        );
        let no_level = select(&ami, None).expect_err("select without a level");
        assert!(
            matches!(
                no_level.downcast_ref::<SelectionError>(),
                Some(SelectionError::Undetermined { states, .. })
                    if *states == IncludedStates::GRAYED_OUT
            ),
            "no level: {no_level:#}"
        );
        for level in [AccessLevel::Administrator, AccessLevel::User] {
            assert_eq!(
                select(&other, Some(level)).map_err(|error| error.to_string()),
                Err(
                    "--access-level applies to AMI firmware whose HiiDB declares the \
                     SystemAccess VarStore; this HiiDB declares none"
                        .to_string()
                ),
                "{level:?}, SystemAccess of NIL_GUID"
            );
        }
    }

    /// get and list-questions evaluate the conditions on AMI firmware's SystemAccess at a
    /// stated access level, and refuse one for a HiiDB that declares no SystemAccess.
    #[test]
    fn options_state_the_access_level() {
        let ami = access_level_hiidb(var_store(2, SYSTEM_ACCESS_GUID, "SystemAccess", 1));
        let other = access_level_hiidb(var_store(2, [0; 16], "SystemAccess", 1));
        let get = |hiidb: &[u8], access_level| {
            let options = GetOptions {
                efivars: EfivarSource::Disabled,
                access_level,
                ..GetOptions::default()
            };
            HiiBackend::get_using(hiidb, "Q", None, &options).map(|got| {
                got.responses
                    .into_iter()
                    .map(|response| response.question.answer)
                    .collect::<Vec<_>>()
            })
        };
        let list = |hiidb: &[u8], access_level| {
            let options = ListQuestionsOptions {
                efivars: EfivarSource::Disabled,
                access_level,
                ..ListQuestionsOptions::default()
            };
            HiiBackend::list_questions_using(hiidb, &options).map(|listed| {
                listed
                    .into_iter()
                    .filter(|question| question.name == "Q")
                    .map(|question| question.answer)
                    .collect::<Vec<_>>()
            })
        };
        let not_read = "<ValueUnavailable: EFI variables not read> <IFR default: 0>";

        let administrator = Some(AccessLevel::Administrator);
        assert_eq!(
            get(&ami, administrator).expect("get as Administrator"),
            [not_read],
            "get as Administrator"
        );
        assert_eq!(
            list(&ami, administrator).expect("list as Administrator"),
            [not_read],
            "list-questions as Administrator"
        );
        let user = Some(AccessLevel::User);
        let error = get(&ami, user).expect_err("get as User");
        assert_eq!(
            error.downcast_ref::<SelectionError>(),
            Some(&SelectionError::Excluded {
                question: "Q".to_string(),
                states: IncludedStates::GRAYED_OUT,
            }),
            "get as User: {error:#}"
        );
        assert_eq!(
            list(&ami, user).expect("list as User"),
            Vec::<String>::new(),
            "list-questions as User"
        );

        let refusal = "--access-level applies to AMI firmware whose HiiDB declares the \
                       SystemAccess VarStore; this HiiDB declares none";
        for level in [administrator, user] {
            assert_eq!(
                get(&other, level).map_err(|error| error.to_string()),
                Err(refusal.to_string()),
                "get, {level:?}, SystemAccess of NIL_GUID"
            );
            assert_eq!(
                list(&other, level).map_err(|error| error.to_string()),
                Err(refusal.to_string()),
                "list-questions, {level:?}, SystemAccess of NIL_GUID"
            );
        }
        assert!(get(&other, None).is_ok(), "get, no level");
        assert!(list(&other, None).is_ok(), "list-questions, no level");
    }

    /// get, list-questions and show-ifr refuse an efivars directory that is not one, rather
    /// than read every question as missing.
    #[cfg(efivar_dumps)]
    #[test]
    fn options_refuse_an_efivars_directory_that_is_not_one() {
        let hiidb = package_list_with_guid(
            [0x55; 16],
            &[
                form_set_package(),
                en_strings_package(b'Q'),
                END_PACKAGE.to_vec(),
            ]
            .concat(),
        );
        let missing = tempfile::tempdir()
            .expect("create directory")
            .path()
            .join("missing");
        let want = format!("efivars directory {} is not a directory", missing.display());
        let efivars = EfivarSource::Directory(missing);
        let get_options = GetOptions {
            efivars: efivars.clone(),
            ..GetOptions::default()
        };
        let list_options = ListQuestionsOptions {
            efivars: efivars.clone(),
            ..ListQuestionsOptions::default()
        };

        let errors = [
            (
                "get",
                HiiBackend::get_using(&hiidb, "Q", None, &get_options).map(drop),
            ),
            (
                "list-questions",
                HiiBackend::list_questions_using(&hiidb, &list_options).map(drop),
            ),
            (
                "show-ifr",
                HiiBackend::show_ifr_using(&hiidb, &ShowIfrOptions { efivars }).map(drop),
            ),
        ];
        for (case, result) in errors {
            let error = result.expect_err("read from a directory that is not one");

            assert_eq!(error.to_string(), want, "{case}");
        }
    }

    /// show_ifr and list_questions fail for a package list with forms but no
    /// strings packages, rather than use those of a list of the same GUID.
    #[test]
    fn test_forms_without_strings_are_an_error() {
        let forms_only = [&form_set_package()[..], &END_PACKAGE].concat();
        let hiidb = [
            package_list_with_guid([0x44; 16], &forms_only),
            en_strings_list([0x44; 16], b'S'),
        ]
        .concat();
        let want = "Failed to get string packages using GUID 44444444-4444-4444-4444-444444444444";
        // no variables: on Windows, System enables a privilege that needs elevation
        let efivars = EfivarSource::Disabled;
        let show_options = ShowIfrOptions {
            efivars: efivars.clone(),
        };
        let list_options = ListQuestionsOptions {
            efivars,
            ..ListQuestionsOptions::default()
        };

        let Err(err) = HiiBackend::show_ifr_using(&hiidb, &show_options) else {
            panic!("show_ifr used the strings of another list");
        };
        assert_eq!(format!("{err:#}"), want, "show_ifr");

        let Err(err) = HiiBackend::list_questions_using(&hiidb, &list_options) else {
            panic!("list_questions used the strings of another list");
        };
        assert_eq!(format!("{err:#}"), want, "list_questions");
    }

    /// The scopes of the FormSet and the Form of nested_subtitles_hiidb
    const FORM_SCOPES: usize = 2;

    /// A HiiDB whose Form nests `subtitles` Subtitle scopes around a CheckBox prompted "Deep", in
    /// the scope of an unknown op if `in_unknown_scope`.
    fn nested_subtitles_hiidb(subtitles: usize, in_unknown_scope: bool) -> Vec<u8> {
        let nested = nested(&subtitle_scope(2), subtitles, &[checkbox_on(1, 2, 0)]);
        let body = match in_unknown_scope {
            true => [unknown_scope(), nested, END.to_vec()].concat(),
            false => nested,
        };
        let packages = [
            en_strings_package_of(&["FormSet", "Deep"]),
            form_package(&[form(1, &[body])]),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid([0x55; 16], &packages.concat())
    }

    /// An op of the unknown opcode 0x70 opening a scope.
    fn unknown_scope() -> Vec<u8> {
        operation(0x70, true, &[])
    }

    /// A command of the tests below: what it prints of a HiiDB, line by line.
    type Command = fn(&[u8]) -> Result<Vec<String>>;

    /// The commands of the tests below, each with its name.
    fn commands() -> [(&'static str, Command); 4] {
        [
            ("list-strings", |hiidb| {
                let strings = HiiBackend::list_strings(hiidb)?;
                Ok(strings
                    .into_iter()
                    .flat_map(|package| package.string_package.into_values())
                    .collect())
            }),
            ("list-questions", |hiidb| {
                let options = ListQuestionsOptions {
                    efivars: EfivarSource::Disabled,
                    include: IncludedStates::all(),
                    ..Default::default()
                };
                let questions = HiiBackend::list_questions_using(hiidb, &options)?;
                Ok(questions
                    .into_iter()
                    .map(|question| question.name)
                    .collect())
            }),
            ("show-ifr", |hiidb| {
                let options = ShowIfrOptions {
                    efivars: EfivarSource::Disabled,
                };
                let shown = HiiBackend::show_ifr_using(hiidb, &options)?;
                Ok(shown
                    .readable_representation
                    .lines()
                    .filter(|line| line.contains("CheckBox"))
                    .map(|line| line.trim().to_string())
                    .collect())
            }),
            ("get", |hiidb| {
                let options = GetOptions {
                    efivars: EfivarSource::Disabled,
                    ..Default::default()
                };
                let got = HiiBackend::get_using(hiidb, "Deep", None, &options)?;
                Ok(got
                    .responses
                    .into_iter()
                    .map(|response| response.question.name)
                    .collect())
            }),
        ]
    }

    /// Every command reads a HiiDB whose IFR scopes nest MAX_SCOPE_NESTING deep, unknown ones
    /// counted, on SMALL_STACK, and shows its CheckBox, unless an unknown op's scope, which edk2
    /// skips, holds it.
    #[test]
    fn commands_read_scopes_nested_to_the_limit_on_a_small_stack() {
        for in_unknown_scope in [false, true] {
            let subtitles = MAX_SCOPE_NESTING - FORM_SCOPES - usize::from(in_unknown_scope);
            let hiidb = nested_subtitles_hiidb(subtitles, in_unknown_scope);
            for (name, command) in commands() {
                let got = on_small_stack(name, || command(&hiidb)).unwrap_or_else(|error| {
                    panic!("{name}, in an unknown scope: {in_unknown_scope}: {error:#}")
                });
                let want: &[&str] = match (name, in_unknown_scope) {
                    ("list-strings", _) => &["FormSet", "Deep"],
                    (_, true) => &[],
                    ("show-ifr", false) => &["OpCode: CheckBox - Q: - Deep - Help: -"],
                    (_, false) => &["Deep"],
                };
                assert_eq!(got, want, "{name}, in an unknown scope: {in_unknown_scope}");
            }
        }
    }

    /// Every command refuses a HiiDB whose IFR scopes nest deeper than MAX_SCOPE_NESTING, unknown
    /// ones counted, by one or by 20000 Subtitles, naming the op past the limit, on SMALL_STACK.
    #[test]
    fn commands_refuse_scopes_nested_past_the_limit_on_a_small_stack() {
        let form_set_op = form_set(&[]).len() - END.len();
        let form_op = form(1, &[]).len() - END.len();
        let subtitle_op = subtitle_scope(2).len();
        for in_unknown_scope in [false, true] {
            let outer = FORM_SCOPES + usize::from(in_unknown_scope);
            let past_limit = form_set_op
                + form_op
                + usize::from(in_unknown_scope) * unknown_scope().len()
                + (MAX_SCOPE_NESTING - outer) * subtitle_op;
            let want = format!(
                "failed to parse package list 55555555-5555-5555-5555-555555555555: failed to \
                 parse a form package: IFR scopes nest deeper than {MAX_SCOPE_NESTING} at offset \
                 {past_limit} of a form package"
            );
            for subtitles in [MAX_SCOPE_NESTING - outer + 1, 20_000] {
                let hiidb = nested_subtitles_hiidb(subtitles, in_unknown_scope);
                for (name, command) in commands() {
                    let case = format!(
                        "{name}, {subtitles} Subtitles, in an unknown scope: {in_unknown_scope}"
                    );
                    let Err(error) = on_small_stack(name, || command(&hiidb)) else {
                        panic!("{case}: read past the limit");
                    };
                    assert_eq!(format!("{error:#}"), want, "{case}");
                }
            }
        }
    }
}
