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

use log::debug;
use log::info;

use uefisettings_backend_thrift::Backend;
use uefisettings_spellings_db_thrift::consts::translation_db;

pub(crate) mod ilo;

pub enum HiiTranslation {
    Translated {
        question_variations: BTreeSet<String>,
        answer_variations: BTreeSet<String>,
    },
    NotTranslated {
        question_variations: BTreeSet<String>,
        answer_variations: BTreeSet<String>,
    },
}

/// get_qa_variations_hii translates canonical questions and answers into possible hii variants
/// If any part isn't in the translation database, it doesn't fail it just returns the original values in required form.
/// Ex: the canonical question "Hyper Threading" -> ["Hyper-Threading", "Enable LP", "Hyper-Threading \[ALL\]"]
/// and for it the canonical answer "Enabled" -> ["Enabled", "Enable"].
pub fn get_qa_variations_hii(question: &str, answer: &str) -> HiiTranslation {
    let mut question_variations = BTreeSet::from([question.to_owned()]);
    let mut answer_variations = BTreeSet::from([answer.to_owned()]);

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

/// translate_response: If the question is using canonical spelling then we should
/// use the canonical spelling of the answer in the response to the user
/// i.e. basically reverse replacement from real answer to canonical answer
/// if something wasn't found in the db then return the real/original answer
pub fn translate_response(question: &str, answer: &str, backend: Backend) -> String {
    let Some(question_mapping) = translation_db.get(question) else {
        return answer.to_owned();
    };

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

#[cfg(test)]
mod tests {
    use uefisettings_spellings_db_thrift::consts::CQ_HYPER_THREADING;
    use uefisettings_spellings_db_thrift::consts::CQ_TPM_STATE;

    use super::*;

    /// translate_response gives the canonical answer for a spelling that the DB lists for the
    /// question and backend, and the answer unchanged for any other question, answer or backend.
    #[test]
    fn translate_response_reverses_only_the_spellings_in_the_db() {
        let cases = [
            (CQ_TPM_STATE, "Enable", Backend::Hii, "Enabled"),
            (CQ_TPM_STATE, "PresentEnabled", Backend::Ilo, "Enabled"),
            (CQ_TPM_STATE, "Enable", Backend::Ilo, "Enable"),
            (CQ_TPM_STATE, "Unknown", Backend::Hii, "Unknown"),
            (CQ_HYPER_THREADING, "Disable", Backend::Ilo, "Disable"),
            ("Not in the DB", "Enable", Backend::Hii, "Enable"),
        ];

        for (question, answer, backend, expected) in cases {
            assert_eq!(
                translate_response(question, answer, backend),
                expected,
                "{question:?} {answer:?} {backend:?}"
            );
        }
    }
}
