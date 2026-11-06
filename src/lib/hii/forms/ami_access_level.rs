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

//! The access level of a Setup session of AMI firmware, which its IFR conditions read from the
//! VarStore SystemAccess.

use std::cell::RefCell;
use std::rc::Rc;

use thiserror::Error;

use super::storage::VarStoreVariable;
use super::Guid;
use super::IFROpCode;
use super::IFROperation;
use super::ParsedOperation;

/// Where AMI firmware's setup browser keeps the access level of its session: its IFR shows
/// Access Level Administrator at 0 and User at 1.
pub(super) const AMI_ACCESS_LEVEL: VarStoreVariable = VarStoreVariable {
    name: "SystemAccess",
    guid: Guid {
        data1: 0xE770_BB69,
        data2: 0xBCB4,
        data3: 0x4D04,
        data4: [0x9E, 0x97, 0x23, 0xFF, 0x94, 0x56, 0xFE, 0xAC],
    },
};

/// The access level that AMI firmware's Setup keeps in the VarStore SystemAccess,
/// E770BB69-BCB4-4D04-9E97-23FF9456FEAC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[non_exhaustive]
pub enum AccessLevel {
    Administrator = 0,
    User = 1,
}

impl From<AccessLevel> for u8 {
    fn from(level: AccessLevel) -> Self {
        level as u8
    }
}

/// An AccessLevel stated for a HiiDB whose FormSets declare no AMI_ACCESS_LEVEL.
#[derive(Debug, Error)]
#[error(
    "--access-level applies to AMI firmware whose HiiDB declares the SystemAccess VarStore; this \
     HiiDB declares none"
)]
pub(crate) struct NoAccessLevelVarStore;

/// Refuses `access_level` if stated for a HiiDB whose FormSets, `roots`, declare no
/// AMI_ACCESS_LEVEL.
pub(crate) fn check_access_level<'a>(
    roots: impl IntoIterator<Item = &'a Rc<RefCell<IFROperation>>>,
    access_level: Option<AccessLevel>,
) -> Result<(), NoAccessLevelVarStore> {
    match access_level {
        None => Ok(()),
        Some(_) if roots.into_iter().any(form_set_declares_ami_access_level) => Ok(()),
        Some(_) => Err(NoAccessLevelVarStore),
    }
}

/// Whether a FormSet of `root` declares AMI_ACCESS_LEVEL among the VarStores where
/// find_corresponding_varstore finds those of its questions.
fn form_set_declares_ami_access_level(root: &Rc<RefCell<IFROperation>>) -> bool {
    root.borrow().children.iter().any(|form_set| {
        let form_set = form_set.borrow();
        form_set.op_code == IFROpCode::FormSet
            && form_set
                .children
                .iter()
                .any(|op| declares_ami_access_level(&op.borrow()))
    })
}

/// Whether `op` declares AMI_ACCESS_LEVEL, as a buffer or EFI variable VarStore.
fn declares_ami_access_level(op: &IFROperation) -> bool {
    match &op.parsed_data {
        ParsedOperation::VarStore(store) => AMI_ACCESS_LEVEL.identifies(store),
        ParsedOperation::VarStoreEfi(store) => AMI_ACCESS_LEVEL.identifies(store),
        ParsedOperation::FormSet(_)
        | ParsedOperation::OneOf(_)
        | ParsedOperation::CheckBox(_)
        | ParsedOperation::OneOfOption(_)
        | ParsedOperation::VarStoreNameValue(_)
        | ParsedOperation::DefaultStore(_)
        | ParsedOperation::IFRDefault(_)
        | ParsedOperation::Form(_)
        | ParsedOperation::Text(_)
        | ParsedOperation::Subtitle(_)
        | ParsedOperation::Numeric(_)
        | ParsedOperation::QuestionRef1(_)
        | ParsedOperation::EqIdVal(_)
        | ParsedOperation::EqIdId(_)
        | ParsedOperation::EqIdValList(_)
        | ParsedOperation::Placeholder => false,
    }
}

#[cfg(test)]
mod tests {
    use super::super::ifr_fixtures::*;
    use super::*;

    /// check_access_level takes a stated level for a HiiDB with a FormSet that declares
    /// SystemAccess, buffer or EFI variable, and refuses it for one without.
    #[test]
    fn stated_access_level_needs_a_system_access_var_store() {
        let setup = || var_store_efi(1, "Setup", NV_BS_RT, 1);
        let cases = [
            ("no VarStore", vec![], false),
            ("Setup", vec![setup()], false),
            (
                "SystemAccess of NIL_GUID",
                vec![var_store(2, [0; 16], "SystemAccess", 1)],
                false,
            ),
            (
                "Setup of the SystemAccess Guid",
                vec![var_store(2, SYSTEM_ACCESS_GUID, "Setup", 1)],
                false,
            ),
            (
                "buffer SystemAccess",
                vec![setup(), var_store(2, SYSTEM_ACCESS_GUID, "SystemAccess", 1)],
                true,
            ),
            (
                "EFI variable SystemAccess",
                vec![var_store_efi_of(
                    2,
                    SYSTEM_ACCESS_GUID,
                    "SystemAccess",
                    NV_BS,
                    1,
                )],
                true,
            ),
        ];
        let without = parse_form_set(&[setup()]);
        for (name, declarations, declares) in cases {
            let with = parse_form_set(&declarations);
            for level in [AccessLevel::Administrator, AccessLevel::User] {
                let checked = check_access_level([&without, &with], Some(level))
                    .map_err(|error| error.to_string());
                let want = match declares {
                    true => Ok(()),
                    false => Err(
                        "--access-level applies to AMI firmware whose HiiDB declares \
                         the SystemAccess VarStore; this HiiDB declares none"
                            .to_string(),
                    ),
                };
                assert_eq!(checked, want, "{name}, {level:?}");
            }
            assert!(
                check_access_level([&without, &with], None).is_ok(),
                "{name}, no level"
            );
        }
    }
}
