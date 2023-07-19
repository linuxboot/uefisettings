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

use std::collections::HashSet;

use log::debug;
use log::info;

use uefisettings_spellings_db_thrift::consts::translation_db;
use uefisettings_backend_thrift::Backend;

pub enum HiiTranslation {
    Translated {
        question_variations: HashSet<String>,
        answer_variations: HashSet<String>,
    },
    NotTranslated {
        question_variations: HashSet<String>,
        answer_variations: HashSet<String>,
    },
}

/// get_qa_variations_hii translates canonical questions and answers into possible hii variants
/// If any part isn't in the translation database, it doesn't fail it just returns the original values in required form.
/// Ex: the canonical question "Hyper Threading" -> ["Hyper-Threading", "Enable LP", "Hyper-Threading [ALL]"]
/// and for it the canonical answer "Enabled" -> ["Enabled", "Enable"].
pub fn get_qa_variations_hii(question: &str, answer: &str) -> HiiTranslation {
    let mut question_variations = HashSet::from([question.to_owned()]);
    let mut answer_variations = HashSet::from([answer.to_owned()]);

    // if spellings_db has question variations, then use those instead
    if let Some(question_mapping) = translation_db.get(question) {
        if let Some(hii_question_mapping) = &question_mapping.hii_question {
            // use question variations
            if !hii_question_mapping.question_variations.is_empty() {
                question_variations = hii_question_mapping
                    .question_variations
                    .iter()
                    .cloned()
                    .collect();

                // also use answer_variations if those exist
                if let Some(answer_replacements) = &(hii_question_mapping.answer_replacements) {
                    for (key, value) in answer_replacements {
                        if key.eq_ignore_ascii_case(answer) {
                            answer_variations = value.iter().cloned().collect();
                            break;
                        }
                    }
                }
                info!(
                    "question_variations after translation: {:?} and new_value_variations {:?}",
                    question_variations, answer_variations
                );
                return HiiTranslation::Translated {
                    question_variations,
                    answer_variations,
                };
            }
        }
    }

    HiiTranslation::NotTranslated {
        question_variations,
        answer_variations,
    }
}

pub enum IloTranslation {
    Translated {
        translated_question: String,
        translated_answer: String,
    },
    NotTranslated {
        question: String,
        answer: String,
    },
}

/// get_qa_variations_ilo translates canonical questions and answers into ilo variants
/// If any part isn't in the translation database, it doesn't fail it just returns the original values.
/// Ex: the canonical question "TPM State" -> "TpmState" and for it the canonical answer "Enabled" -> "PresentEnabled".
pub fn get_qa_variations_ilo(question: &str, answer: &str) -> IloTranslation {
    if let Some(question_mapping) = translation_db.get(question) {
        if let Some(ilo_question_mapping) = &question_mapping.ilo_question {
            // use translated question name instead of canonical name
            let translated_question = ilo_question_mapping.question.to_owned();
            let mut translated_answer = answer.to_owned();

            // use translated answer to send to ilo instead of canonical answer
            if let Some(answer_replacements) = &(ilo_question_mapping.answer_replacements) {
                for (key, value) in answer_replacements {
                    if key.eq_ignore_ascii_case(answer) {
                        translated_answer = value.to_owned();
                        break;
                    }
                }
            }

            return IloTranslation::Translated {
                translated_question,
                translated_answer,
            };
        }
    }
    IloTranslation::NotTranslated {
        question: question.to_owned(),
        answer: answer.to_owned(),
    }
}

/// translate_response: If the question is using canonical spelling then we should
/// use the canonical spelling of the answer in the response to the user
/// i.e. basically reverse replacement from real answer to canonical answer
/// if something wasn't found in the db then return the real/original answer
pub fn translate_response(question: &str, answer: &str, backend: Backend) -> String {
    let question_mapping = translation_db.get(question);
    if question_mapping.is_none() {
        return answer.to_owned();
    }
    let question_mapping = question_mapping.unwrap();

    match backend {
        Backend::Hii => {
            if let Some(hii_question_mapping) = &question_mapping.hii_question {
                if let Some(answer_replacements) = &(hii_question_mapping.answer_replacements) {
                    for (key, value) in answer_replacements {
                        for replacement in value {
                            if replacement.eq_ignore_ascii_case(answer) {
                                info!("reverse translating {} to {}", replacement, key);
                                return key.to_owned();
                            }
                        }
                    }
                }
            }
        }
        Backend::Ilo => {
            if let Some(ilo_question_mapping) = &question_mapping.ilo_question {
                if let Some(answer_replacements) = &(ilo_question_mapping.answer_replacements) {
                    for (key, replacement) in answer_replacements {
                        if replacement.eq_ignore_ascii_case(answer) {
                            debug!("reverse translating {} to {}", replacement, key);
                            return key.to_owned();
                        }
                    }
                }
            }
        }
        _ => {}
    }
    answer.to_owned()
}
