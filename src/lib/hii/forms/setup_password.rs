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

//! The setup password questions of a HiiDB, which no setup browser asks for where uefisettings
//! runs, and the bytes that hold their passwords, which questions never read or write.

use std::cell::RefCell;
use std::ops::Range;
use std::rc::Rc;

use binrw::io::Cursor;
use binrw::BinRead;
use log::warn;
use thiserror::Error;

use super::find_corresponding_varstore;
use super::walk_scopes;
use super::IFROpCode;
use super::IFROperation;
use super::ParsedOperation;
use super::QuestionHeader;
use super::Walk;
use crate::hii::package::Guid;
use crate::hii::package::ParsedPackageList;
use crate::hii::variables::EfivarReader;
use crate::hii::variables::FirmwareVariables;
use crate::hii::variables::VariableKey;
use crate::hii::variables::VariableReach;
use crate::hii::variables::WithheldBytes;
use crate::hii::variables::WithholdingVariables;
use crate::parse_error::ReadParsed;

/// The bytes of a CHAR16
const CHAR16_SIZE: usize = std::mem::size_of::<u16>();

/// The PASSWORD questions of a HiiDB (UEFI 2.10 §33.3.8.3.54): whether it declares any, those
/// with a VarStore, and the ops whose VarStore is unknown.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct PasswordQuestions {
    declared: bool,
    questions: Vec<PasswordQuestion>,
    unresolved: Vec<UnresolvedPassword>,
}

/// A PASSWORD question with a VarStore, EFI_IFR_FLAG_CALLBACK or not: its password takes MaxSize
/// CHAR16s from its VarOffset, the StorageWidth that edk2-stable202608
/// SetupBrowserDxe/IfrParse.c ParseOpCodes gives it, as a string question's NUL-padded string
/// (UEFI 2.11 §33.2.5.4.9).
#[derive(Debug, Clone, PartialEq, Eq)]
struct PasswordQuestion {
    key: VariableKey,
    offset: u16,
    max_size: u16,
}

/// An EFI_IFR_PASSWORD after its op header (UEFI 2.11 §33.3.8.3.54).
#[derive(BinRead)]
#[br(little)]
struct PasswordOp {
    question: QuestionHeader,
    _min_size: u16,
    max_size: u16,
}

impl PasswordQuestion {
    /// The value bytes of its variable that hold its password.
    fn bytes(&self) -> Range<usize> {
        let start = usize::from(self.offset);
        start..start + self.width()
    }

    /// The bytes of its password's storage: MaxSize × 2.
    fn width(&self) -> usize {
        usize::from(self.max_size) * CHAR16_SIZE
    }
}

impl PasswordQuestions {
    /// Those of the FormSets of `roots`.
    pub(crate) fn of<'a>(roots: impl IntoIterator<Item = &'a Rc<RefCell<IFROperation>>>) -> Self {
        let mut found = Self::default();
        for root in roots {
            found.add(root, None);
        }
        found
    }

    /// Those of the package lists `lists`: IFR that read_db ignores may hold any PASSWORD question,
    /// so each counts as one whose VarStore is unknown.
    pub(crate) fn of_lists(lists: &[ParsedPackageList]) -> Self {
        let mut found = Self::of(lists.iter().flat_map(|list| &list.forms));
        for list in lists {
            for ignored in &list.ignored_ifr {
                let unresolved = UnresolvedPassword::InIgnoredIfr {
                    package_list: list.guid,
                    offset: ignored.offset,
                    reason: ignored.reason.clone(),
                };
                warn!("{unresolved}");
                found.unresolved.push(unresolved);
            }
        }
        found
    }

    /// Adds those of `node`, in the FormSet `form_set` if any, and the ops in its scope.
    fn add(&mut self, node: &Rc<RefCell<IFROperation>>, form_set: Option<Guid>) {
        walk_scopes(std::slice::from_ref(node), form_set, |node, &form_set| {
            let op = node.borrow();
            let form_set = match &op.parsed_data {
                ParsedOperation::FormSet(form_set) => Some(form_set.guid),
                _ => form_set,
            };
            if op.op_code == IFROpCode::Password {
                self.declared = true;
                match password_question(node, &op, form_set) {
                    Ok(question) => self.questions.extend(question),
                    Err(unresolved) => {
                        warn!("{unresolved}");
                        self.unresolved.push(unresolved);
                    }
                }
            }
            Walk::Enter(form_set)
        });
    }

    /// The bytes that questions read and set through variables of `reach` withhold: those of
    /// every PASSWORD question with a VarStore, whatever the reach, so that no password byte is
    /// shown or written back. Through variables that reach BootServices, a PASSWORD op whose
    /// VarStore is unknown could keep its password in any variable, so this fails closed:
    /// UnresolvedPasswords, whatever the setup password policy, and no variable of the HiiDB is
    /// read or written; through those that reach Runtime it withholds the bytes of the others.
    fn withheld(&self, reach: VariableReach) -> Result<WithheldBytes, UnresolvedPasswords> {
        match (reach, self.unresolved.as_slice()) {
            (VariableReach::BootServices, [_, ..]) => {
                Err(UnresolvedPasswords(self.unresolved.clone()))
            }
            (VariableReach::Runtime, _) | (VariableReach::BootServices, []) => {
                let mut withheld = WithheldBytes::default();
                for question in &self.questions {
                    withheld.insert(question.key.clone(), question.bytes());
                }
                Ok(withheld)
            }
        }
    }

    /// `variables` without the bytes that questions set through them withhold.
    pub(crate) fn withholding<V: FirmwareVariables>(
        &self,
        variables: V,
    ) -> Result<WithholdingVariables<V>, UnresolvedPasswords> {
        let withheld = self.withheld(variables.reach())?;
        Ok(WithholdingVariables::new(variables, withheld))
    }

    /// A reader of `variables` without the bytes that questions read through them withhold,
    /// which no value decodes.
    pub(crate) fn reader(
        &self,
        variables: Box<dyn FirmwareVariables>,
    ) -> Result<EfivarReader, UnresolvedPasswords> {
        let withheld = self.withheld(variables.reach())?;
        Ok(EfivarReader::withholding(variables, withheld))
    }

    /// Refuses set through variables that reach BootServices, as in the UEFI Shell, in a HiiDB
    /// that declares a PASSWORD question, unless `policy` bypasses: no setup browser runs there,
    /// so none asks for the password. Set through variables that reach Runtime writes as before.
    pub(crate) fn check_set(
        &self,
        reach: VariableReach,
        policy: SetupPasswordPolicy,
    ) -> Result<(), SetupPasswordDeclared> {
        match (reach, self.declared, policy) {
            (VariableReach::BootServices, true, SetupPasswordPolicy::Refuse) => {
                Err(SetupPasswordDeclared)
            }
            (VariableReach::BootServices, true, SetupPasswordPolicy::Bypass)
            | (VariableReach::BootServices, false, _)
            | (VariableReach::Runtime, _, _) => Ok(()),
        }
    }
}

/// The PASSWORD question of the `op` at `node`, of the FormSet `form_set`; None for VarStoreId 0,
/// which names no VarStore (UEFI 2.10 §33.3.8.2.2): its driver keeps such a question's value
/// through callbacks or READ/WRITE ops (§33.2.5.6), in no variable that the IFR names.
fn password_question(
    node: &Rc<RefCell<IFROperation>>,
    op: &IFROperation,
    form_set: Option<Guid>,
) -> Result<Option<PasswordQuestion>, UnresolvedPassword> {
    let PasswordOp {
        question: header,
        max_size,
        ..
    } = Cursor::new(&op.data)
        .parse_ne()
        .map_err(|error| UnresolvedPassword::NoHeader {
            form_set,
            reason: error.to_string(),
        })?;
    if header.var_store_id == 0 {
        return Ok(None);
    }
    let store =
        find_corresponding_varstore(Rc::clone(node), header.var_store_id).map_err(|error| {
            UnresolvedPassword::NoVarStore {
                form_set,
                question_id: header.question_id,
                reason: error.to_string(),
            }
        })?;
    Ok(Some(PasswordQuestion {
        key: store.variable_key(),
        offset: header.var_store_info,
        max_size,
    }))
}

/// A PASSWORD op whose VarStore is unknown.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum UnresolvedPassword {
    #[error(
        "PASSWORD op without a question header, MinSize and MaxSize in FormSet {}: {reason}",
        FormSetName(*.form_set)
    )]
    NoHeader {
        form_set: Option<Guid>,
        reason: String,
    },
    #[error(
        "PASSWORD question {question_id:#06x} in FormSet {}: {reason}",
        FormSetName(*.form_set)
    )]
    NoVarStore {
        form_set: Option<Guid>,
        question_id: u16,
        reason: String,
    },
    #[error(
        "PASSWORD questions of package list {package_list} may be in the IFR that uefisettings \
         ignores at offset {offset} of a form package: {reason}"
    )]
    InIgnoredIfr {
        package_list: Guid,
        offset: u64,
        reason: String,
    },
}

/// The GUID of a FormSet, or "?" for an op outside one.
struct FormSetName(Option<Guid>);

impl std::fmt::Display for FormSetName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Some(guid) => write!(f, "{guid}"),
            None => f.write_str("?"),
        }
    }
}

/// The refusal, through variables that reach BootServices, of a HiiDB with PASSWORD ops whose
/// VarStore is unknown.
#[derive(Debug, Error)]
#[error(
    "{}; as the variable of that password is unknown, the UEFI Shell build reads and writes no \
     variable of this HiiDB",
    .0.iter().map(ToString::to_string).collect::<Vec<_>>().join("; ")
)]
pub(crate) struct UnresolvedPasswords(Vec<UnresolvedPassword>);

/// What set does in the UEFI Shell in a HiiDB that declares a setup password question, which no
/// setup browser there asks for.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub enum SetupPasswordPolicy {
    /// Write nothing
    #[default]
    Refuse,
    /// Write anyway; the bytes of PASSWORD questions stay unread as values and unwritten
    Bypass,
}

/// set's refusal, in the UEFI Shell, of a HiiDB that declares a setup password question.
#[derive(Debug, Error)]
#[error(
    "this HiiDB declares a setup password question; the UEFI Shell runs no setup browser, so no \
     password is asked or checked; pass --bypass-setup-password to write anyway"
)]
pub(crate) struct SetupPasswordDeclared;

#[cfg(test)]
mod tests {
    use super::super::ifr_fixtures::*;
    use super::super::QuestionFlags;
    use super::*;
    use crate::hii::package::Guid;
    use crate::hii::variables::VolatileWrites;
    use crate::hii::variables::VolatileWritingVariables;
    use crate::hii::variables::WithheldPassword;

    /// The Guid of the VarStore AMITSESetup of these tests, as stored.
    const TSE_GUID: [u8; 16] = [0x44; 16];

    /// The variable of the VarStore AMITSESetup of these tests.
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

    /// The variable of the VarStore Setup of these tests.
    fn setup() -> VariableKey {
        VariableKey {
            name: "Setup".to_string(),
            guid: Guid {
                data1: 0,
                data2: 0,
                data3: 0,
                data4: [0; 8],
            },
        }
    }

    /// A password_on question of AMITSESetup at `offset`: MaxSize 20.
    fn amitse_setup_password(offset: u16) -> PasswordQuestion {
        PasswordQuestion {
            key: amitse_setup(),
            offset,
            max_size: 20,
        }
    }

    /// A PASSWORD of QuestionId `question_id` and question Flags `flags` at VarOffset `offset`
    /// of VarStore `var_store_id`, of MinSize 0 and MaxSize `max_size`.
    fn password_with(
        question_id: u16,
        var_store_id: u16,
        offset: u16,
        flags: QuestionFlags,
        max_size: u16,
    ) -> Vec<u8> {
        let data = [
            question_header_with(question_id, 3, var_store_id, offset, flags.bits()),
            [&0u16.to_le_bytes()[..], &max_size.to_le_bytes()].concat(),
        ]
        .concat();
        operation(PASSWORD, false, &data)
    }

    /// The GUID of the FormSets of parse_form_set.
    const FORM_SET_GUID: Guid = Guid {
        data1: 0x11111111,
        data2: 0x1111,
        data3: 0x1111,
        data4: [0x11; 8],
    };

    /// A FormSet whose form holds `body`, with the VarStores Setup, an EFI variable, and
    /// AMITSESetup, a buffer, of AMI's layout: passwords at 0 and 40.
    fn form_set_of(body: &[Vec<u8>]) -> Rc<RefCell<IFROperation>> {
        parse_form_set(&[
            var_store_efi(1, "Setup", NV_BS_RT, 1),
            var_store(2, TSE_GUID, "AMITSESetup", 81),
            form(1, body),
        ])
    }

    /// The PasswordQuestions of form_set_of `body`.
    fn password_questions(body: &[Vec<u8>]) -> PasswordQuestions {
        PasswordQuestions::of([&form_set_of(body)])
    }

    /// A HiiDB declares a password question when a FormSet has one, whatever its VarStore, and
    /// those with a VarStore keep their passwords at their VarOffsets in MaxSize CHAR16s of its
    /// variable.
    #[test]
    fn password_questions_keep_their_passwords_in_their_var_stores() {
        let cases = [
            (
                "passwords on AMITSESetup",
                vec![
                    checkbox_on(1, 3, 1),
                    password_on(2, 3, 2, 0),
                    password_on(3, 3, 2, 40),
                    checkbox_at(4, 3, 2, 80),
                ],
                true,
                vec![amitse_setup_password(0), amitse_setup_password(40)],
            ),
            (
                "a password in a SUPPRESS_IF",
                vec![conditional(
                    SUPPRESS_IF,
                    ifr_true(),
                    &[password_on(2, 3, 2, 0)],
                )],
                true,
                vec![amitse_setup_password(0)],
            ),
            (
                "a CALLBACK password of MaxSize 4 on Setup",
                vec![password_with(2, 1, 0, QuestionFlags::CALLBACK, 4)],
                true,
                vec![PasswordQuestion {
                    key: setup(),
                    offset: 0,
                    max_size: 4,
                }],
            ),
            (
                "a password without a VarStore",
                vec![password_on(2, 3, 0, 0)],
                true,
                vec![],
            ),
            (
                "no password",
                vec![checkbox_on(1, 3, 1), checkbox_at(4, 3, 2, 80)],
                false,
                vec![],
            ),
        ];
        for (case, body, declared, questions) in cases {
            assert_eq!(
                password_questions(&body),
                PasswordQuestions {
                    declared,
                    questions,
                    unresolved: vec![],
                },
                "{case}"
            );
        }
    }

    /// A HiiDB declares a password question when any of its FormSets has one, not only the first.
    #[test]
    fn password_questions_of_every_form_set_count() {
        let without = form_set_of(&[checkbox_on(1, 3, 1)]);
        let with = form_set_of(&[password_on(2, 3, 2, 0)]);

        assert_eq!(
            PasswordQuestions::of([&without, &with]),
            PasswordQuestions {
                declared: true,
                questions: vec![amitse_setup_password(0)],
                unresolved: vec![],
            },
            "a password in the second FormSet"
        );
    }

    /// A PASSWORD op whose question header, MinSize and MaxSize do not parse, or whose
    /// VarStoreId names no VarStore, leaves its variable unknown.
    #[test]
    fn password_without_a_known_var_store_is_unresolved() {
        assert_eq!(
            password_questions(&[password_on(2, 3, 9, 0)]),
            PasswordQuestions {
                declared: true,
                questions: vec![],
                unresolved: vec![UnresolvedPassword::NoVarStore {
                    form_set: Some(FORM_SET_GUID),
                    question_id: 2,
                    reason: "no supported varstore with matching id 0x0009 found".to_string(),
                }],
            },
            "a password on VarStore 9"
        );

        let cases = [
            ("headless", vec![3, 0, 4, 0]),
            ("sizeless", question_header_on(2, 3, 2, 0)),
        ];
        for (case, data) in cases {
            let passwords = password_questions(&[operation(PASSWORD, false, &data)]);
            assert!(passwords.declared, "{case}: declared");
            assert_eq!(passwords.questions, vec![], "{case}: questions");
            assert!(
                matches!(
                    passwords.unresolved.as_slice(),
                    [UnresolvedPassword::NoHeader {
                        form_set: Some(FORM_SET_GUID),
                        ..
                    }]
                ),
                "{case}: {:?}",
                passwords.unresolved
            );
        }
    }

    /// A PASSWORD op whose question header does not parse gives its reason on one line: the
    /// fields being parsed, without the Rust source locations of binrw's backtrace frames.
    #[test]
    fn a_headless_password_gives_its_reason_on_one_line() {
        let headless = password_questions(&[operation(PASSWORD, false, &[3, 0, 4, 0])]);
        let [UnresolvedPassword::NoHeader { reason, .. }] = headless.unresolved.as_slice() else {
            panic!("headless: {:?}", headless.unresolved);
        };
        assert_eq!(
            reason,
            "failed to fill whole buffer (While parsing field 'question_id' in QuestionHeader; While \
             parsing field 'question' in PasswordOp)",
            "headless"
        );
    }

    /// Variables of either reach withhold the MaxSize × 2 bytes at the VarOffset of every
    /// PASSWORD question with a VarStore, CALLBACK ones too, and no other byte.
    #[test]
    fn every_reach_withholds_the_bytes_of_passwords() {
        let passwords = password_questions(&[
            password_on(2, 3, 2, 0),
            password_on(3, 3, 2, 40),
            password_with(4, 1, 0, QuestionFlags::CALLBACK, 4),
            password_with(5, 2, 80, QuestionFlags::empty(), 0),
            password_on(6, 3, 0, 0),
        ]);
        let mut want = WithheldBytes::default();
        want.insert(amitse_setup(), 0..40);
        want.insert(amitse_setup(), 40..80);
        want.insert(setup(), 0..8);

        for reach in [VariableReach::BootServices, VariableReach::Runtime] {
            assert_eq!(
                passwords.withheld(reach).map_err(|error| error.to_string()),
                Ok(want.clone()),
                "{reach:?}"
            );
        }
    }

    /// Through variables that reach BootServices, a PASSWORD op whose VarStore is unknown could
    /// keep its password in any variable: withheld fails. Through those that reach Runtime the
    /// bytes of the passwords with a known VarStore are withheld.
    #[test]
    fn boot_services_fail_closed_on_an_unresolved_password() {
        let passwords = password_questions(&[password_on(2, 3, 9, 0), password_on(3, 3, 2, 0)]);

        assert_eq!(
            passwords
                .withheld(VariableReach::BootServices)
                .map_err(|error| error.to_string()),
            Err(
                "PASSWORD question 0x0002 in FormSet 11111111-1111-1111-1111-111111111111: no \
                 supported varstore with matching id 0x0009 found; as the variable of that \
                 password is unknown, the UEFI Shell build reads and writes no variable of this \
                 HiiDB"
                    .to_string()
            ),
            "BootServices"
        );
        let mut known = WithheldBytes::default();
        known.insert(amitse_setup(), 0..40);
        assert_eq!(
            passwords
                .withheld(VariableReach::Runtime)
                .map_err(|error| error.to_string()),
            Ok(known),
            "Runtime"
        );
    }

    /// set's VolatileWritingVariables, which write through write_at_with, over the withholding
    /// variables write no byte of a password whatever the volatile policy, and write the bytes
    /// beside it.
    #[test]
    fn volatile_writing_variables_write_no_byte_of_a_password() {
        let passwords = password_questions(&[password_on(2, 3, 2, 0)]);
        for volatile in [VolatileWrites::Refuse, VolatileWrites::Allow] {
            let writes = MemoryVariables::new(
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            );
            writes.insert(
                amitse_setup(),
                NV_BS_RT,
                &[[0xAA; 80].as_slice(), &[1]].concat(),
            );
            let decorated = VolatileWritingVariables::new(
                passwords
                    .withholding(&writes)
                    .expect("resolve the VarStore of the PASSWORD question"),
                volatile,
            );

            let got = decorated.write_at(&amitse_setup(), 81, 10, &[0]);

            assert_eq!(
                got.map_err(|error| error
                    .downcast_ref::<WithheldPassword>()
                    .map(ToString::to_string)),
                Err(Some(
                    "EFI variable AMITSESetup-44444444-4444-4444-4444-444444444444 holds a \
                     password at bytes 0..40, which set never writes"
                        .to_string()
                )),
                "{volatile:?}: write over the password"
            );
            assert_eq!(
                writes.writes_to(&amitse_setup()),
                [],
                "{volatile:?}: writes over the password"
            );
            decorated
                .write_at(&amitse_setup(), 81, 80, &[0])
                .unwrap_or_else(|error| {
                    panic!("{volatile:?}: write beside the password: {error:#}")
                });
            assert_eq!(
                writes.writes_to(&amitse_setup()),
                [(80, vec![0])],
                "{volatile:?}: writes beside the password"
            );
        }
    }

    /// set through variables that reach BootServices refuses a HiiDB that declares a password
    /// question unless the caller bypasses; set through variables that reach Runtime, and set in
    /// a HiiDB without one, write.
    #[test]
    fn boot_services_refuse_set_with_a_declared_password() {
        let declared = password_questions(&[password_on(2, 3, 0, 0)]);
        let undeclared = password_questions(&[checkbox_on(1, 3, 1)]);
        let refusal = "this HiiDB declares a setup password question; the UEFI Shell runs no \
                       setup browser, so no password is asked or checked; pass \
                       --bypass-setup-password to write anyway";
        let cases = [
            (
                &declared,
                VariableReach::BootServices,
                SetupPasswordPolicy::Refuse,
                Err(refusal.to_string()),
            ),
            (
                &declared,
                VariableReach::BootServices,
                SetupPasswordPolicy::Bypass,
                Ok(()),
            ),
            (
                &declared,
                VariableReach::Runtime,
                SetupPasswordPolicy::Refuse,
                Ok(()),
            ),
            (
                &undeclared,
                VariableReach::BootServices,
                SetupPasswordPolicy::Refuse,
                Ok(()),
            ),
        ];
        for (passwords, reach, policy, want) in cases {
            assert_eq!(
                passwords
                    .check_set(reach, policy)
                    .map_err(|error| error.to_string()),
                want,
                "{reach:?}, {policy:?}, declared: {}",
                passwords.declared
            );
        }
    }
}
