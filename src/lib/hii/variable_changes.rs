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

//! The EFI variables that a driver's Callback() sequence changed: every variable that
//! GetNextVariableName() lists is read before and after, but those of uefisettings' own vendor
//! GUID, which are no driver's. The list only informs: a change outside the FormSet's stores may
//! be the driver's own business, as a question without a VarStore keeps its value somewhere.

use std::collections::BTreeMap;

use crate::efi_variables::VariableContents;
use crate::efi_variables::VariableData;
use crate::efi_variables::VariableNames;
use crate::efi_variables::UEFISETTINGS_VENDOR_GUID;
use crate::hii::VariableKey;

/// Every EFI variable but uefisettings' own, at one time, or why they could not be listed.
pub(crate) struct VariableSnapshot(Result<BTreeMap<VariableKey, Read>, String>);

/// What reading one listed variable gave.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Read {
    Contents(VariableContents),
    /// GetVariable() found none, although it was listed
    Absent,
    /// GetVariable()'s error, as `{:#}` shows it
    Failed(String),
}

impl VariableSnapshot {
    pub(crate) fn take(variables: &(impl VariableData + VariableNames)) -> Self {
        Self(read_all(variables))
    }

    /// Each variable that differs from this snapshot now, as `"<name>-<guid> (created)"`,
    /// `"(deleted)"` or `"(changed)"`, or why they could not be compared.
    pub(crate) fn changes(self, variables: &(impl VariableData + VariableNames)) -> Vec<String> {
        let (before, now) = match (self.0, read_all(variables)) {
            (Ok(before), Ok(now)) => (before, now),
            (Err(error), _) | (Ok(_), Err(error)) => {
                return vec![format!("not compared: GetNextVariableName(): {error}")]
            }
        };
        let deleted = before
            .keys()
            .filter(|key| !now.contains_key(*key))
            .map(|key| format!("{key} (deleted)"));
        let created_or_changed = now.iter().filter_map(|(key, read)| match before.get(key) {
            None => Some(format!("{key} (created)")),
            Some(earlier) if earlier != read => Some(format!("{key} (changed)")),
            Some(_) => None,
        });
        let mut changes: Vec<String> = deleted.chain(created_or_changed).collect();
        changes.sort();
        changes
    }
}

/// Reads every listed variable but uefisettings' own.
fn read_all(
    variables: &(impl VariableData + VariableNames),
) -> Result<BTreeMap<VariableKey, Read>, String> {
    let keys = variables
        .variable_names()
        .map_err(|error| format!("{error:#}"))?;
    Ok(keys
        .into_iter()
        .filter(|key| key.guid != UEFISETTINGS_VENDOR_GUID)
        .map(|key| {
            let read = match variables.variable_data(&key) {
                Ok(Some(contents)) => Read::Contents(contents),
                Ok(None) => Read::Absent,
                Err(error) => Read::Failed(format!("{error:#}")),
            };
            (key, read)
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::efi_variables::globals::tests::key;
    use crate::efi_variables::globals::tests::HeldVariables;
    use crate::efi_variables::globals::tests::NV_BS_RT;
    use crate::hii::form_set_stores::tests::STORE_GUID;

    fn contents(data: &[u8]) -> VariableContents {
        VariableContents::new(NV_BS_RT, data.to_vec()).expect("data")
    }

    #[test]
    fn lists_created_deleted_and_changed_variables_but_uefisettings_own() {
        let variables = HeldVariables::default()
            .with("Kept", STORE_GUID, &[1])
            .with("Changed", STORE_GUID, &[1])
            .with("Deleted", STORE_GUID, &[1]);
        let before = VariableSnapshot::take(&variables);
        {
            let mut held = variables.variables.borrow_mut();
            held.insert(key("Changed", STORE_GUID), contents(&[2]));
            held.remove(&key("Deleted", STORE_GUID));
            held.insert(key("Created", STORE_GUID), contents(&[3]));
            held.insert(key("Record", UEFISETTINGS_VENDOR_GUID), contents(&[4]));
        }

        let changes = before.changes(&variables);

        assert_eq!(
            changes,
            [
                format!("{} (changed)", key("Changed", STORE_GUID)),
                format!("{} (created)", key("Created", STORE_GUID)),
                format!("{} (deleted)", key("Deleted", STORE_GUID)),
            ],
            "the changes, without uefisettings' own variable"
        );
    }

    #[test]
    fn unchanged_variables_list_nothing() {
        let variables = HeldVariables::default().with("Kept", STORE_GUID, &[1]);
        let before = VariableSnapshot::take(&variables);

        assert!(
            before.changes(&variables).is_empty(),
            "no change, no listing"
        );
    }

    #[test]
    fn attributes_alone_count_as_a_change() {
        let variables = HeldVariables::default().with("Kept", STORE_GUID, &[1]);
        let before = VariableSnapshot::take(&variables);
        variables.variables.borrow_mut().insert(
            key("Kept", STORE_GUID),
            VariableContents::new(crate::hii::VariableAttributes::NON_VOLATILE, vec![1])
                .expect("data"),
        );

        assert_eq!(
            before.changes(&variables),
            [format!("{} (changed)", key("Kept", STORE_GUID))],
            "the new attributes"
        );
    }
}
