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
//! runs.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::rc::Rc;

use binrw::io::Cursor;
use binrw::BinReaderExt;
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
use crate::hii::variables::FirmwareVariables;
use crate::hii::variables::VariableKey;
use crate::hii::variables::VariableReach;
use crate::hii::variables::WithholdingVariables;

/// The PASSWORD questions of a HiiDB (UEFI 2.10 §33.3.8.3.54): whether it declares any, the
/// variables of the VarStores that they name, and the ops whose VarStore is unknown.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct PasswordQuestions {
    declared: bool,
    var_stores: BTreeSet<VariableKey>,
    unresolved: Vec<UnresolvedPassword>,
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
                match password_var_store(node, &op, form_set) {
                    Ok(var_store) => self.var_stores.extend(var_store),
                    Err(unresolved) => {
                        warn!("{unresolved}");
                        self.unresolved.push(unresolved);
                    }
                }
            }
            Walk::Enter(form_set)
        });
    }

    /// The variables that questions read and set through variables of `reach` withhold:
    /// BootServices, as in the UEFI Shell, those of the VarStores that PASSWORD questions name, so
    /// that no password bytes are read, written back or shown; Runtime none, as before.
    /// Through variables that reach BootServices, a PASSWORD op whose VarStore is unknown
    /// could name any variable, so this fails closed: UnresolvedPasswords, whatever the setup
    /// password policy, and no variable of the HiiDB is read or written.
    fn withheld(&self, reach: VariableReach) -> Result<BTreeSet<VariableKey>, UnresolvedPasswords> {
        match (reach, self.unresolved.as_slice()) {
            (VariableReach::Runtime, _) => Ok(BTreeSet::new()),
            (VariableReach::BootServices, []) => Ok(self.var_stores.clone()),
            (VariableReach::BootServices, unresolved) => {
                Err(UnresolvedPasswords(unresolved.to_vec()))
            }
        }
    }

    /// `variables` without the variables that questions read and set through them withhold.
    pub(crate) fn withholding<V: FirmwareVariables>(
        &self,
        variables: V,
    ) -> Result<WithholdingVariables<V>, UnresolvedPasswords> {
        let withheld = self.withheld(variables.reach())?;
        Ok(WithholdingVariables::new(variables, withheld))
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

/// The variable of the VarStore that the PASSWORD `op` at `node`, of the FormSet `form_set`,
/// names; None for VarStoreId 0, which names no VarStore (UEFI 2.10 §33.3.8.2.2): its driver
/// keeps such a question's value through callbacks or READ/WRITE ops (§33.2.5.6), in no variable
/// that the IFR names.
fn password_var_store(
    node: &Rc<RefCell<IFROperation>>,
    op: &IFROperation,
    form_set: Option<Guid>,
) -> Result<Option<VariableKey>, UnresolvedPassword> {
    let header: QuestionHeader =
        Cursor::new(&op.data)
            .read_ne()
            .map_err(|error| UnresolvedPassword::NoHeader {
                form_set,
                reason: error.to_string(),
            })?;
    if header.var_store_id == 0 {
        return Ok(None);
    }
    find_corresponding_varstore(Rc::clone(node), header.var_store_id)
        .map(|store| Some(store.variable_key()))
        .map_err(|error| UnresolvedPassword::NoVarStore {
            form_set,
            question_id: header.question_id,
            reason: error.to_string(),
        })
}

/// A PASSWORD op whose VarStore is unknown.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum UnresolvedPassword {
    #[error("PASSWORD op without a question header in FormSet {}: {reason}", FormSetName(*.form_set))]
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
    /// Write anyway; the VarStores that PASSWORD questions name stay unread and unwritten
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
    use super::*;
    use crate::hii::package::Guid;

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
    /// the VarStores that they name are those of their variables.
    #[test]
    fn password_questions_name_their_var_stores() {
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
                BTreeSet::from([amitse_setup()]),
            ),
            (
                "a password in a SUPPRESS_IF",
                vec![conditional(
                    SUPPRESS_IF,
                    ifr_true(),
                    &[password_on(2, 3, 2, 0)],
                )],
                true,
                BTreeSet::from([amitse_setup()]),
            ),
            (
                "a password without a VarStore",
                vec![password_on(2, 3, 0, 0)],
                true,
                BTreeSet::new(),
            ),
            (
                "no password",
                vec![checkbox_on(1, 3, 1), checkbox_at(4, 3, 2, 80)],
                false,
                BTreeSet::new(),
            ),
        ];
        for (case, body, declared, var_stores) in cases {
            assert_eq!(
                password_questions(&body),
                PasswordQuestions {
                    declared,
                    var_stores,
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
                var_stores: BTreeSet::from([amitse_setup()]),
                unresolved: vec![],
            },
            "a password in the second FormSet"
        );
    }

    /// A PASSWORD op whose question header does not parse, or whose VarStoreId names no
    /// VarStore, leaves its variable unknown.
    #[test]
    fn password_without_a_known_var_store_is_unresolved() {
        assert_eq!(
            password_questions(&[password_on(2, 3, 9, 0)]),
            PasswordQuestions {
                declared: true,
                var_stores: BTreeSet::new(),
                unresolved: vec![UnresolvedPassword::NoVarStore {
                    form_set: Some(FORM_SET_GUID),
                    question_id: 2,
                    reason: "no supported varstore with matching id 0x0009 found".to_string(),
                }],
            },
            "a password on VarStore 9"
        );

        let headless = password_questions(&[operation(PASSWORD, false, &[3, 0, 4, 0])]);
        assert!(headless.declared, "headless: declared");
        assert_eq!(headless.var_stores, BTreeSet::new(), "headless: VarStores");
        assert!(
            matches!(
                headless.unresolved.as_slice(),
                [UnresolvedPassword::NoHeader {
                    form_set: Some(FORM_SET_GUID),
                    ..
                }]
            ),
            "headless: {:?}",
            headless.unresolved
        );
    }

    /// Variables that reach BootServices withhold those of password VarStores; variables that
    /// reach Runtime read them, as before.
    #[test]
    fn boot_services_withhold_password_var_stores() {
        let passwords = password_questions(&[password_on(2, 3, 2, 0)]);

        assert_eq!(
            passwords
                .withheld(VariableReach::BootServices)
                .map_err(|error| error.to_string()),
            Ok(BTreeSet::from([amitse_setup()])),
            "BootServices"
        );
        assert_eq!(
            passwords
                .withheld(VariableReach::Runtime)
                .map_err(|error| error.to_string()),
            Ok(BTreeSet::new()),
            "Runtime"
        );
    }

    /// Through variables that reach BootServices, a PASSWORD op whose VarStore is unknown makes
    /// every variable withheld: withheld fails. Through those that reach Runtime nothing is
    /// withheld, as before.
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
        assert_eq!(
            passwords
                .withheld(VariableReach::Runtime)
                .map_err(|error| error.to_string()),
            Ok(BTreeSet::new()),
            "Runtime"
        );
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
