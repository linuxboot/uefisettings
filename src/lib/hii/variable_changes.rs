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

//! The EFI variables that a driver's code (DriverCode) changed: every variable that
//! GetNextVariableName() lists is read before and after, but those of uefisettings' own vendor
//! GUID, which are no driver's. The list only informs: a change outside the FormSet's stores may
//! be the driver's own business, as a question without a VarStore keeps its value somewhere.
//! A change of withheld bytes, those of a password, which reads give as zero, refuses instead,
//! as does a password whose bytes cannot be compared: uefisettings never writes them back. The
//! withheld bytes are compared in every variable that they were recorded for, listed or not,
//! uefisettings' own too, and in every listed variable that withholds any, each read once.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;

use crate::efi_variables::VariableContents;
use crate::efi_variables::VariableData;
use crate::efi_variables::VariableNames;
use crate::efi_variables::UEFISETTINGS_VENDOR_GUID;
use crate::hii::question_callbacks::ActionRequest;
use crate::hii::variables::WithheldWitness;
use crate::hii::VariableKey;
use crate::hii::WithholdingVariables;

/// The driver code that a VariableSnapshot is compared across, which its refusals name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DriverCode {
    /// The Callback()s of get's or set's sequence, with the reads and the restore of the
    /// FormSet's stores around them
    CallbackSequence,
    /// The reconnection that EFI_BROWSER_ACTION_REQUEST_RECONNECT asks for
    Reconnection,
    /// SetData() of EFI_CONFIG_KEYWORD_HANDLER_PROTOCOL, with the GetData() that reads it back
    SetData,
    /// GetData() of EFI_CONFIG_KEYWORD_HANDLER_PROTOCOL
    GetData,
}

impl fmt::Display for DriverCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CallbackSequence => write!(f, "the Callback sequence"),
            Self::Reconnection => write!(
                f,
                "the reconnection that {} asks for",
                ActionRequest::RECONNECT
            ),
            Self::SetData => write!(f, "SetData()"),
            Self::GetData => write!(f, "GetData()"),
        }
    }
}

/// Every EFI variable but uefisettings' own at one time, or why they could not be listed, and
/// the witnesses of the withheld bytes.
pub(crate) struct VariableSnapshot {
    listed: Result<BTreeMap<VariableKey, Read>, String>,
    /// For each variable whose withheld bytes are compared: their witness, None if it is
    /// absent, or why it could not be read
    witnesses: BTreeMap<VariableKey, Result<Option<WithheldWitness>, String>>,
}

/// What changed since a VariableSnapshot.
pub(crate) struct VariableChanges {
    /// Each variable that differs, as `"<name>-<guid> (created)"`, `"(deleted)"` or
    /// `"(changed)"`, or why they could not be compared
    pub(crate) listed: Vec<String>,
    withheld: Vec<WithheldRefusal>,
}

/// What reading one listed variable gave.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Read {
    Contents(VariableContents),
    /// GetVariable() found none, although it was listed
    Absent,
    /// GetVariable()'s error, as `{:#}` shows it
    Failed(String),
}

/// Why withheld bytes refuse what driver code did.
#[derive(Debug, Clone, PartialEq, Eq)]
enum WithheldRefusal {
    /// The withheld bytes of the variable changed, also by its creation or deletion
    Changed(VariableKey),
    /// The withheld bytes of the variable could not be read: the error, as `{:#}` shows it
    Unreadable { key: VariableKey, error: String },
    /// GetNextVariableName() failed where some variable withholds bytes: its error
    Unlisted(String),
}

impl VariableSnapshot {
    /// Refuses where withheld bytes could not be read or listed, as a change of them across `by`
    /// would go unseen.
    pub(crate) fn take<V: VariableData + VariableNames>(
        variables: &WithholdingVariables<V>,
        by: DriverCode,
    ) -> Result<Self, String> {
        let snapshot = Self::read(variables, []);
        let unreadable = snapshot.witnesses.iter().filter_map(|(key, witness)| {
            witness
                .as_ref()
                .err()
                .map(|error| WithheldRefusal::Unreadable {
                    key: key.clone(),
                    error: error.clone(),
                })
        });
        let refusals: Vec<WithheldRefusal> = unreadable
            .chain(unlisted(&snapshot.listed, variables))
            .collect();
        match refusal_text(&refusals, by) {
            Some(refusal) => Err(refusal),
            None => Ok(snapshot),
        }
    }

    /// What differs from this snapshot now. It can be compared again, after more driver code.
    pub(crate) fn changes<V: VariableData + VariableNames>(
        &self,
        variables: &WithholdingVariables<V>,
    ) -> VariableChanges {
        let now = Self::read(variables, self.witnesses.keys().cloned());
        let listed = match (&self.listed, &now.listed) {
            (Ok(before), Ok(now)) => listed_changes(before, now),
            (Err(error), _) | (Ok(_), Err(error)) => {
                vec![format!("not compared: GetNextVariableName(): {error}")]
            }
        };
        let keys: BTreeSet<&VariableKey> =
            self.witnesses.keys().chain(now.witnesses.keys()).collect();
        let witnessed = keys.into_iter().filter_map(|key| {
            match (
                witness_of(&self.witnesses, key),
                witness_of(&now.witnesses, key),
            ) {
                (Err(error), _) | (_, Err(error)) => Some(WithheldRefusal::Unreadable {
                    key: key.clone(),
                    error: error.to_owned(),
                }),
                (Ok(earlier), Ok(now)) => {
                    (earlier != now).then(|| WithheldRefusal::Changed(key.clone()))
                }
            }
        });
        let unlisted =
            unlisted(&self.listed, variables).or_else(|| unlisted(&now.listed, variables));
        VariableChanges {
            listed,
            withheld: witnessed.chain(unlisted).collect(),
        }
    }

    /// Reads every listed variable, and the withheld bytes of each that `variables` recorded
    /// them for, of each listed one that withholds any and of `also`, each once.
    fn read<V: VariableData + VariableNames>(
        variables: &WithholdingVariables<V>,
        also: impl IntoIterator<Item = VariableKey>,
    ) -> Self {
        let names = variables
            .variable_names()
            .map_err(|error| format!("{error:#}"));
        let listed_keys: BTreeSet<VariableKey> = names
            .iter()
            .flatten()
            .filter(|key| key.guid != UEFISETTINGS_VENDOR_GUID)
            .cloned()
            .collect();
        let witnessed_keys: BTreeSet<VariableKey> = variables
            .named()
            .cloned()
            .chain(also)
            .chain(
                names
                    .iter()
                    .flatten()
                    .filter(|key| variables.withholds(key))
                    .cloned(),
            )
            .collect();
        let mut listed = BTreeMap::new();
        let mut witnesses = BTreeMap::new();
        for key in listed_keys.union(&witnessed_keys) {
            let (read, witness) = match variables.witnessed_data(key) {
                Ok(Some((contents, witness))) => (Read::Contents(contents), Ok(witness)),
                Ok(None) => (Read::Absent, Ok(None)),
                Err(error) => {
                    let error = format!("{error:#}");
                    (Read::Failed(error.clone()), Err(error))
                }
            };
            if listed_keys.contains(key) {
                listed.insert(key.clone(), read);
            }
            if witnessed_keys.contains(key) {
                witnesses.insert(key.clone(), witness);
            }
        }
        Self {
            listed: names.map(|_| listed),
            witnesses,
        }
    }
}

impl VariableChanges {
    /// Why the withheld bytes refuse what `by` did, if they do: each variable whose withheld
    /// bytes changed or could not be compared.
    pub(crate) fn refusal(&self, by: DriverCode) -> Option<String> {
        refusal_text(&self.withheld, by)
    }
}

impl WithheldRefusal {
    /// The refusal in words, of what `by` did.
    fn text(&self, by: DriverCode) -> String {
        match self {
            Self::Changed(key) => format!(
                "{by} changed the password bytes of EFI variable {key}; they were not restored, \
                 as uefisettings never writes a password byte"
            ),
            Self::Unreadable { key, error } => format!(
                "cannot compare the password bytes of EFI variable {key} across {by}: {error}"
            ),
            Self::Unlisted(error) => format!(
                "cannot compare the password bytes of EFI variables across {by}: \
                 GetNextVariableName(): {error}"
            ),
        }
    }
}

/// The variables that differ from `before` to `now`, sorted.
fn listed_changes(
    before: &BTreeMap<VariableKey, Read>,
    now: &BTreeMap<VariableKey, Read>,
) -> Vec<String> {
    let deleted = before
        .keys()
        .filter(|key| !now.contains_key(*key))
        .map(|key| format!("{key} (deleted)"));
    let created_or_changed = now.iter().filter_map(|(key, read)| match before.get(key) {
        None => Some(format!("{key} (created)")),
        Some(earlier) if earlier != read => Some(format!("{key} (changed)")),
        Some(_) => None,
    });
    let mut listed: Vec<String> = deleted.chain(created_or_changed).collect();
    listed.sort();
    listed
}

/// The witness of the withheld bytes of `key` in `witnesses`, None where it has none: a
/// variable that was neither recorded nor listed did not exist then.
fn witness_of<'a>(
    witnesses: &'a BTreeMap<VariableKey, Result<Option<WithheldWitness>, String>>,
    key: &VariableKey,
) -> Result<Option<&'a WithheldWitness>, &'a str> {
    match witnesses.get(key) {
        Some(witness) => witness.as_ref().map(Option::as_ref).map_err(String::as_str),
        None => Ok(None),
    }
}

/// The refusal of a listing that failed, where some variable of `variables` may withhold bytes,
/// which a variable that it did not list may hold.
fn unlisted<V: VariableData>(
    listed: &Result<BTreeMap<VariableKey, Read>, String>,
    variables: &WithholdingVariables<V>,
) -> Option<WithheldRefusal> {
    match listed {
        Err(error) if variables.withholds_any() => Some(WithheldRefusal::Unlisted(error.clone())),
        Ok(_) | Err(_) => None,
    }
}

/// `refusals` in words, of what `by` did, if there are any.
fn refusal_text(refusals: &[WithheldRefusal], by: DriverCode) -> Option<String> {
    (!refusals.is_empty()).then(|| {
        refusals
            .iter()
            .map(|refusal| refusal.text(by))
            .collect::<Vec<_>>()
            .join("; ")
    })
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::cell::RefCell;
    use std::ops::Range;

    use anyhow::anyhow;
    use anyhow::Result;

    use super::*;
    use crate::efi_variables::globals::tests::key;
    use crate::efi_variables::globals::tests::HeldVariables;
    use crate::efi_variables::globals::tests::NV_BS_RT;
    use crate::hii::form_set_stores::tests::STORE_GUID;
    use crate::hii::package::Guid;
    use crate::hii::variables::VariableGuids;
    use crate::hii::variables::WithheldBytes;
    use crate::hii::VariableAttributes;
    use crate::hii::VariableInterface;

    /// The driver code that most tests compare across.
    const BY: DriverCode = DriverCode::CallbackSequence;

    fn contents(data: &[u8]) -> VariableContents {
        VariableContents::new(NV_BS_RT, data.to_vec()).expect("data")
    }

    /// `variables` with `bytes` of each named variable withheld.
    fn withholding<V>(variables: V, bytes: &[(&str, Range<usize>)]) -> WithholdingVariables<V> {
        let mut withheld = WithheldBytes::default();
        for (name, bytes) in bytes {
            withheld.insert(key(name, STORE_GUID), bytes.clone());
        }
        WithholdingVariables::new(variables, withheld)
    }

    #[test]
    fn lists_created_deleted_and_changed_variables_but_uefisettings_own() {
        let variables = HeldVariables::default()
            .with("Kept", STORE_GUID, &[1])
            .with("Changed", STORE_GUID, &[1])
            .with("Deleted", STORE_GUID, &[1]);
        let withheld = withholding(&variables, &[]);
        let before = VariableSnapshot::take(&withheld, BY).expect("snapshot");
        {
            let mut held = variables.variables.borrow_mut();
            held.insert(key("Changed", STORE_GUID), contents(&[2]));
            held.remove(&key("Deleted", STORE_GUID));
            held.insert(key("Created", STORE_GUID), contents(&[3]));
            held.insert(key("Record", UEFISETTINGS_VENDOR_GUID), contents(&[4]));
        }

        let changes = before.changes(&withheld);

        assert_eq!(
            changes.listed,
            [
                format!("{} (changed)", key("Changed", STORE_GUID)),
                format!("{} (created)", key("Created", STORE_GUID)),
                format!("{} (deleted)", key("Deleted", STORE_GUID)),
            ],
            "the changes, without uefisettings' own variable"
        );
        assert_eq!(
            changes.refusal(BY),
            None,
            "nothing withheld, nothing refused"
        );
    }

    #[test]
    fn unchanged_variables_list_nothing() {
        let variables = HeldVariables::default().with("Kept", STORE_GUID, &[1]);
        let withheld = withholding(&variables, &[]);
        let before = VariableSnapshot::take(&withheld, BY).expect("snapshot");

        let changes = before.changes(&withheld);

        assert!(changes.listed.is_empty(), "no change, no listing");
        assert_eq!(changes.refusal(BY), None, "no change, no refusal");
    }

    #[test]
    fn attributes_alone_count_as_a_change() {
        let variables = HeldVariables::default().with("Kept", STORE_GUID, &[1]);
        let withheld = withholding(&variables, &[]);
        let before = VariableSnapshot::take(&withheld, BY).expect("snapshot");
        variables.variables.borrow_mut().insert(
            key("Kept", STORE_GUID),
            VariableContents::new(VariableAttributes::NON_VOLATILE, vec![1]).expect("data"),
        );

        assert_eq!(
            before.changes(&withheld).listed,
            [format!("{} (changed)", key("Kept", STORE_GUID))],
            "the new attributes"
        );
    }

    /// The refusal of a change of the withheld bytes of `key` across the Callback sequence.
    fn overwritten(key: &VariableKey) -> String {
        format!(
            "the Callback sequence changed the password bytes of EFI variable {key}; they were \
             not restored, as uefisettings never writes a password byte"
        )
    }

    /// The refusal of a change of the withheld bytes of `name`.
    fn overwritten_refusal(name: &str) -> Option<String> {
        Some(overwritten(&key(name, STORE_GUID)))
    }

    #[test]
    fn withheld_bytes_refuse_whenever_they_change_and_only_then() {
        let listed = |name: &str, how: &str| vec![format!("{} {how}", key(name, STORE_GUID))];
        let one: &[(&str, Range<usize>)] = &[("Store", 1..3)];
        let two: &[(&str, Range<usize>)] = &[("Store", 0..1), ("Store", 2..3)];
        let cases = [
            (
                "kept",
                one,
                &[1, 2, 3, 4][..],
                Some(&[1, 2, 3, 4][..]),
                vec![],
                None,
            ),
            (
                "beside the withheld bytes",
                one,
                &[1, 2, 3, 4],
                Some(&[9, 2, 3, 4]),
                listed("Store", "(changed)"),
                None,
            ),
            (
                "withheld bytes",
                one,
                &[1, 2, 3, 4],
                Some(&[1, 9, 3, 4]),
                vec![],
                overwritten_refusal("Store"),
            ),
            (
                "cut off",
                one,
                &[1, 2, 3, 4],
                Some(&[1, 2]),
                listed("Store", "(changed)"),
                overwritten_refusal("Store"),
            ),
            (
                "grown into",
                one,
                &[1, 2],
                Some(&[1, 2, 3, 4]),
                listed("Store", "(changed)"),
                overwritten_refusal("Store"),
            ),
            (
                "deleted",
                one,
                &[1, 2, 3, 4],
                None,
                listed("Store", "(deleted)"),
                overwritten_refusal("Store"),
            ),
            (
                "between two withheld ranges",
                two,
                &[1, 2, 3, 4],
                Some(&[1, 9, 3, 4]),
                listed("Store", "(changed)"),
                None,
            ),
            (
                "the second of two withheld ranges",
                two,
                &[1, 2, 3, 4],
                Some(&[1, 2, 9, 4]),
                vec![],
                overwritten_refusal("Store"),
            ),
        ];
        for (name, ranges, before_data, now_data, want_listed, want_refusal) in cases {
            let variables = HeldVariables::default().with("Store", STORE_GUID, before_data);
            let withheld = withholding(&variables, ranges);
            let before = VariableSnapshot::take(&withheld, BY).expect("snapshot");
            {
                let mut held = variables.variables.borrow_mut();
                match now_data {
                    Some(data) => held.insert(key("Store", STORE_GUID), contents(data)),
                    None => held.remove(&key("Store", STORE_GUID)),
                };
            }

            let changes = before.changes(&withheld);

            assert_eq!(changes.listed, want_listed, "{name}: the listing");
            assert_eq!(changes.refusal(BY), want_refusal, "{name}: the refusal");
        }
    }

    #[test]
    fn withheld_bytes_to_the_end_of_the_value_refuse_when_they_change() {
        let mut past_end = WithheldBytes::default();
        past_end.insert(key("Store", STORE_GUID), 1..8);
        let mut whole = WithheldBytes::default();
        whole.insert(key("Store", STORE_GUID), 0..usize::MAX);
        let cases = [
            ("bytes past the end of the value", past_end),
            ("a whole variable", whole),
            ("the variables of a GUID", whole_variables(Some(STORE_GUID))),
            ("every variable", whole_variables(None)),
        ];
        for (name, bytes) in cases {
            let variables = HeldVariables::default().with("Store", STORE_GUID, &[1, 2, 3, 4]);
            let withheld = WithholdingVariables::new(&variables, bytes);
            let before = VariableSnapshot::take(&withheld, BY).expect("snapshot");
            variables
                .variables
                .borrow_mut()
                .insert(key("Store", STORE_GUID), contents(&[1, 2, 3, 9]));

            let changes = before.changes(&withheld);

            assert!(
                changes.listed.is_empty(),
                "{name}: no byte that a read shows changed: {:?}",
                changes.listed
            );
            assert_eq!(
                changes.refusal(BY),
                overwritten_refusal("Store"),
                "{name}: the refusal"
            );
        }
    }

    #[test]
    fn a_created_variable_refuses_where_it_withholds_bytes() {
        let variables = HeldVariables::default();
        let withheld = withholding(&variables, &[("Whole", 0..usize::MAX)]);
        let before = VariableSnapshot::take(&withheld, BY).expect("snapshot");
        {
            let mut held = variables.variables.borrow_mut();
            held.insert(key("Whole", STORE_GUID), contents(&[1]));
            held.insert(key("Other", STORE_GUID), contents(&[1]));
        }

        let changes = before.changes(&withheld);

        assert_eq!(
            changes.listed,
            [
                format!("{} (created)", key("Other", STORE_GUID)),
                format!("{} (created)", key("Whole", STORE_GUID)),
            ],
            "both listed"
        );
        assert_eq!(
            changes.refusal(BY),
            overwritten_refusal("Whole"),
            "only the variable that withholds bytes refuses"
        );
    }

    #[test]
    fn a_created_variable_of_a_guid_withheld_whole_refuses_as_changed() {
        let variables = HeldVariables::default();
        let withheld = WithholdingVariables::new(&variables, whole_variables(Some(STORE_GUID)));
        let before = VariableSnapshot::take(&withheld, BY).expect("snapshot");
        variables
            .variables
            .borrow_mut()
            .insert(key("Created", STORE_GUID), contents(&[1]));

        assert_eq!(
            before.changes(&withheld).refusal(BY),
            overwritten_refusal("Created"),
            "a variable that nothing named, created under a GUID withheld whole"
        );
    }

    /// Data whose metadata metadata_end refuses, which hides where the value starts.
    fn unreadable_value() -> VariableContents {
        VariableContents::new(
            NV_BS_RT | VariableAttributes::ENHANCED_AUTHENTICATED_ACCESS,
            vec![1],
        )
        .expect("data")
    }

    #[test]
    fn withheld_bytes_that_cannot_be_read_refuse() {
        let refusal = format!(
            "cannot compare the password bytes of EFI variable {} across the Callback sequence: ",
            key("Store", STORE_GUID)
        );
        let variables = HeldVariables::default();
        variables
            .variables
            .borrow_mut()
            .insert(key("Store", STORE_GUID), unreadable_value());
        let unwithheld = withholding(&variables, &[]);
        let withheld = withholding(&variables, &[("Store", 1..3)]);

        assert!(
            VariableSnapshot::take(&unwithheld, BY).is_ok(),
            "an unreadable variable that withholds nothing does not refuse"
        );
        assert!(
            matches!(VariableSnapshot::take(&withheld, BY), Err(reason) if reason.starts_with(&refusal)),
            "unreadable before"
        );

        variables
            .variables
            .borrow_mut()
            .insert(key("Store", STORE_GUID), contents(&[1, 2, 3, 4]));
        let before = VariableSnapshot::take(&withheld, BY).expect("snapshot");
        variables
            .variables
            .borrow_mut()
            .insert(key("Store", STORE_GUID), unreadable_value());
        let changes = before.changes(&withheld);
        assert!(
            matches!(&changes.refusal(BY), Some(reason) if reason.starts_with(&refusal)),
            "unreadable after: {:?}",
            changes.refusal(BY)
        );
    }

    /// Variables whose listing fails while `fails` holds.
    struct FlakyNames {
        variables: HeldVariables,
        fails: Cell<bool>,
    }

    impl VariableData for FlakyNames {
        fn interface(&self) -> VariableInterface {
            self.variables.interface()
        }

        fn variable_data(&self, key: &VariableKey) -> Result<Option<VariableContents>> {
            self.variables.variable_data(key)
        }

        fn set_variable(&self, key: &VariableKey, contents: &VariableContents) -> Result<()> {
            self.variables.set_variable(key, contents)
        }

        fn delete_variable(&self, key: &VariableKey) -> Result<()> {
            self.variables.delete_variable(key)
        }
    }

    impl VariableNames for FlakyNames {
        fn variable_names(&self) -> Result<Vec<VariableKey>> {
            match self.fails.get() {
                true => Err(anyhow!("EFI_DEVICE_ERROR")),
                false => self.variables.variable_names(),
            }
        }
    }

    /// The bytes of every variable of `guid` withheld, or of every variable for None.
    fn whole_variables(guid: Option<Guid>) -> WithheldBytes {
        let mut guids = VariableGuids::default();
        guids.insert(guid);
        let mut withheld = WithheldBytes::default();
        withheld.insert_guids(&guids);
        withheld
    }

    #[test]
    fn an_unlisted_variable_refuses_only_where_bytes_are_withheld() {
        let refusal = Some(
            "cannot compare the password bytes of EFI variables across the Callback sequence: \
             GetNextVariableName(): EFI_DEVICE_ERROR"
                .to_string(),
        );
        let note = vec!["not compared: GetNextVariableName(): EFI_DEVICE_ERROR".to_string()];
        let mut store_bytes = WithheldBytes::default();
        store_bytes.insert(key("Store", STORE_GUID), 1..3);
        let cases = [
            ("nothing withheld", WithheldBytes::default(), None),
            ("bytes of a variable", store_bytes, refusal.clone()),
            (
                "the variables of a GUID",
                whole_variables(Some(STORE_GUID)),
                refusal.clone(),
            ),
            ("every variable", whole_variables(None), refusal),
        ];
        for (name, bytes, want) in cases {
            let variables = FlakyNames {
                variables: HeldVariables::default().with("Store", STORE_GUID, &[1, 2, 3, 4]),
                fails: Cell::new(true),
            };
            let withheld = WithholdingVariables::new(&variables, bytes);

            assert_eq!(
                VariableSnapshot::take(&withheld, BY).err(),
                want,
                "{name}: unlisted before"
            );

            variables.fails.set(false);
            let before = VariableSnapshot::take(&withheld, BY).expect("snapshot");
            variables.fails.set(true);
            let changes = before.changes(&withheld);
            assert_eq!(changes.listed, note, "{name}: unlisted after, the note");
            assert_eq!(
                changes.refusal(BY),
                want,
                "{name}: unlisted after, the refusal"
            );
        }
    }

    /// Variables that GetNextVariableName() lists without `hidden`, if any, which GetVariable()
    /// reads, but `unreadable`, if any, which it fails.
    struct Unlisting {
        variables: HeldVariables,
        hidden: RefCell<Option<VariableKey>>,
        unreadable: Option<VariableKey>,
    }

    impl VariableData for Unlisting {
        fn interface(&self) -> VariableInterface {
            self.variables.interface()
        }

        fn variable_data(&self, key: &VariableKey) -> Result<Option<VariableContents>> {
            match self.unreadable.as_ref() == Some(key) {
                true => Err(anyhow!("EFI_DEVICE_ERROR")),
                false => self.variables.variable_data(key),
            }
        }

        fn set_variable(&self, key: &VariableKey, contents: &VariableContents) -> Result<()> {
            self.variables.set_variable(key, contents)
        }

        fn delete_variable(&self, key: &VariableKey) -> Result<()> {
            self.variables.delete_variable(key)
        }
    }

    impl VariableNames for Unlisting {
        fn variable_names(&self) -> Result<Vec<VariableKey>> {
            let mut keys = self.variables.variable_names()?;
            keys.retain(|key| Some(key) != self.hidden.borrow().as_ref());
            Ok(keys)
        }
    }

    #[test]
    fn a_recorded_variable_is_compared_whether_listed_or_not() {
        let unlisted = key("Store", STORE_GUID);
        let own = key("Record", UEFISETTINGS_VENDOR_GUID);
        let cases = [
            (
                "a variable that GetNextVariableName() skips",
                &unlisted,
                unlisted.clone(),
            ),
            (
                "uefisettings' own variable, listed",
                &own,
                key("Elsewhere", STORE_GUID),
            ),
        ];
        for (name, recorded, hidden) in cases {
            for (change, data, want) in [
                ("beside the withheld bytes", [9, 2, 3, 4], None),
                ("withheld bytes", [1, 9, 3, 4], Some(overwritten(recorded))),
            ] {
                let mut held = HeldVariables::default();
                held.variables
                    .get_mut()
                    .insert(recorded.clone(), contents(&[1, 2, 3, 4]));
                let variables = Unlisting {
                    variables: held,
                    hidden: RefCell::new(Some(hidden.clone())),
                    unreadable: None,
                };
                let mut bytes = WithheldBytes::default();
                bytes.insert(recorded.clone(), 1..3);
                let withheld = WithholdingVariables::new(&variables, bytes);
                let before = VariableSnapshot::take(&withheld, BY).expect("snapshot");
                variables
                    .variables
                    .variables
                    .borrow_mut()
                    .insert(recorded.clone(), contents(&data));

                let changes = before.changes(&withheld);

                assert!(
                    changes.listed.is_empty(),
                    "{name}, {change}: not listed: {:?}",
                    changes.listed
                );
                assert_eq!(changes.refusal(BY), want, "{name}, {change}: the refusal");
            }
        }
    }

    #[test]
    fn a_variable_withheld_through_shared_sets_is_compared_unlisted() {
        let unlisted = key("Store", STORE_GUID);
        for (change, data, want) in [
            ("beside the withheld bytes", [9, 2, 3, 4], None),
            ("withheld bytes", [1, 9, 3, 4], Some(overwritten(&unlisted))),
        ] {
            let mut held = HeldVariables::default();
            held.variables
                .get_mut()
                .insert(unlisted.clone(), contents(&[1, 2, 3, 4]));
            let variables = Unlisting {
                variables: held,
                hidden: RefCell::new(Some(unlisted.clone())),
                unreadable: None,
            };
            let mut bytes = WithheldBytes::default();
            let sets = bytes.share([vec![1..2, 2..3]]);
            bytes.withhold_shared(&unlisted, sets);
            let withheld = WithholdingVariables::new(&variables, bytes);
            let before = VariableSnapshot::take(&withheld, BY).expect("snapshot");
            variables
                .variables
                .variables
                .borrow_mut()
                .insert(unlisted.clone(), contents(&data));

            assert_eq!(
                before.changes(&withheld).refusal(BY),
                want,
                "{change}: the refusal"
            );
        }
    }

    #[test]
    fn a_withheld_variable_that_the_listing_drops_is_read_again_by_key() {
        let store = key("Store", STORE_GUID);
        for (change, data, want) in [
            ("kept", [1, 2, 3, 4], None),
            ("withheld bytes", [1, 2, 9, 4], Some(overwritten(&store))),
        ] {
            let variables = Unlisting {
                variables: HeldVariables::default().with("Store", STORE_GUID, &[1, 2, 3, 4]),
                hidden: RefCell::new(None),
                unreadable: None,
            };
            let withheld = WithholdingVariables::new(&variables, whole_variables(Some(STORE_GUID)));
            let before = VariableSnapshot::take(&withheld, BY).expect("snapshot");
            *variables.hidden.borrow_mut() = Some(store.clone());
            variables
                .variables
                .variables
                .borrow_mut()
                .insert(store.clone(), contents(&data));

            let changes = before.changes(&withheld);

            assert_eq!(
                changes.listed,
                [format!("{store} (deleted)")],
                "{change}: no longer listed"
            );
            assert_eq!(changes.refusal(BY), want, "{change}: the refusal");
        }
    }

    #[test]
    fn an_unreadable_variable_refuses_only_where_it_withholds_bytes() {
        let broken = key("Broken", STORE_GUID);
        let variables = Unlisting {
            variables: HeldVariables::default()
                .with("Store", STORE_GUID, &[1, 2, 3, 4])
                .with("Broken", STORE_GUID, &[1]),
            hidden: RefCell::new(None),
            unreadable: Some(broken.clone()),
        };

        let store_only = withholding(&variables, &[("Store", 1..3)]);
        let before = VariableSnapshot::take(&store_only, BY).expect("snapshot");
        let changes = before.changes(&store_only);
        assert!(
            changes.listed.is_empty(),
            "failed twice alike, not listed: {:?}",
            changes.listed
        );
        assert_eq!(changes.refusal(BY), None, "withholding nothing, no refusal");

        let both = withholding(&variables, &[("Store", 1..3), ("Broken", 0..1)]);
        assert_eq!(
            VariableSnapshot::take(&both, BY).err(),
            Some(format!(
                "cannot compare the password bytes of EFI variable {broken} across the Callback \
                 sequence: EFI_DEVICE_ERROR"
            )),
            "withholding bytes, the refusal"
        );
    }

    #[test]
    fn each_variable_is_read_once_per_snapshot() {
        let variables = HeldVariables::default()
            .with("Store", STORE_GUID, &[1, 2, 3, 4])
            .with("Other", STORE_GUID, &[1]);
        let withheld = withholding(&variables, &[("Store", 1..3)]);
        let once = [key("Other", STORE_GUID), key("Store", STORE_GUID)];

        let before = VariableSnapshot::take(&withheld, BY).expect("snapshot");
        assert_eq!(*variables.read.borrow(), once, "the reads of the snapshot");

        variables.read.borrow_mut().clear();
        let changes = before.changes(&withheld);
        assert_eq!(changes.refusal(BY), None, "no change");
        assert_eq!(*variables.read.borrow(), once, "the reads of the compare");
    }
}
