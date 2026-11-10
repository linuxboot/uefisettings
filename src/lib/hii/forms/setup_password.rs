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
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::ops::Range;
use std::rc::Rc;
use std::sync::Arc;

use binrw::io::Cursor;
use binrw::BinRead;
use log::debug;
use log::warn;
use thiserror::Error;

use super::conditions::enclosing_form_set;
use super::declared_store;
use super::decoded_store;
use super::named_records;
use super::storage::NameValueStore;
use super::storage::ShortEfiReason;
use super::storage::ShortEfiRefusal;
use super::undeclared_var_store;
use super::var_name_candidates;
use super::walk_scopes;
use super::DeclaredStorage;
use super::DeclaredStore;
use super::DisabledForm;
use super::FirstVarStores;
use super::IFROpCode;
use super::IFROperation;
use super::IgnoredPasswords;
use super::OutsideOp;
use super::OutsidePlace;
use super::ParsedOperation;
use super::QuestionHeader;
use super::ShortVarStoreEfi;
use super::Walk;
use crate::hii::package::Guid;
use crate::hii::package::ParsedPackageList;
use crate::hii::strings::StringPackage;
use crate::hii::variables::EfivarReader;
use crate::hii::variables::FirmwareVariables;
use crate::hii::variables::VariableKey;
use crate::hii::variables::VariableLayout;
use crate::hii::variables::VariableReach;
use crate::hii::variables::WithheldBytes;
use crate::hii::variables::WithholdingVariables;
use crate::parse_error::ParseError;
use crate::parse_error::ReadParsed;
use crate::unsafe_operations::UnsafeOperation;

/// The bytes of a CHAR16
const CHAR16_SIZE: usize = std::mem::size_of::<u16>();

/// The PASSWORD questions of a HiiDB (UEFI 2.10 §33.3.8.3.54): whether it declares any, those
/// with a VarStore, the ops whose VarStore is unknown, and the variables that may hold their
/// passwords where they are known (password_questions).
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct PasswordQuestions {
    declared: bool,
    questions: Vec<PasswordQuestion>,
    /// Those that more than one variable holds, by VarStoreId of a package list
    shared: Vec<SharedPasswords>,
    unresolved: Vec<UnresolvedPassword>,
    /// The records of the PASSWORDs that edk2 may route to a VARSTORE_NAME_VALUE, whose values
    /// its driver exposes, as UEFI 2.11 §33.2.5.6 says, through EFI_HII_CONFIG_ACCESS_PROTOCOL,
    /// in storage of its own choosing, so in any variable (Keeper::NameValueDriver)
    driver_held: Vec<UnresolvedPassword>,
    candidates: Vec<PasswordQuestion>,
    /// The storage that IFR that read_db ignores, or a VarStore outside any FormSet that does not
    /// parse, may keep a password in anywhere (IgnoredPasswords::Declared), and that VarStore ops
    /// of the FormSet of a PASSWORD that do not decode may (UndecodedStores), withheld whole
    storage: DeclaredStorage,
}

/// A PASSWORD question with a VarStore, EFI_IFR_FLAG_CALLBACK or not: its password takes MaxSize
/// CHAR16s from its VarOffset, or from byte 0 of the variable of its VarName on a VARSTORE_EFI
/// before UEFI 2.3.1, the StorageWidth that edk2-stable202608 SetupBrowserDxe/IfrParse.c
/// ParseOpCodes gives it, as a string question's NUL-padded string (UEFI 2.11 §33.2.5.4.9); every
/// byte from there on where its op ends before MaxSize.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PasswordQuestion {
    key: VariableKey,
    offset: u16,
    max_size: Option<u16>,
}

/// The EFI variable that the VarName of `password` names on the VARSTORE_EFI before UEFI 2.3.1
/// `store`, whose bytes password_bytes takes from byte 0, or why it names none: one without MaxSize
/// names none. Its StorageWidth in edk2-stable202608 SetupBrowserDxe/IfrParse.c, MaxSize CHAR16s
/// cast to UINT16 (:2252), has no reader: uefisettings neither reads nor writes a PASSWORD, and
/// keyword get and set refuse one before they look up its store (QuestionRefusal::Password).
fn short_password_variable(
    store: &ShortVarStoreEfi,
    password: &PasswordFields,
) -> Result<VariableKey, ShortEfiRefusal> {
    let id = store.var_store_id;
    if password.max_size.is_err() {
        let reason = ShortEfiReason::NotRead(IFROpCode::Password.spec_name());
        return Err(ShortEfiRefusal::new(id, reason));
    }
    store
        .variable_key(password.question.var_store_info)
        .map_err(|unresolved| ShortEfiRefusal::new(id, unresolved.into()))
}

/// The MinSize and MaxSize of an EFI_IFR_PASSWORD, after its question header (UEFI 2.11
/// §33.3.8.3.54).
#[derive(BinRead)]
#[br(little)]
struct PasswordSizes {
    _min_size: u16,
    max_size: u16,
}

/// The question header of a PASSWORD op, then its MaxSize, or why that does not parse: an op that
/// ends before MaxSize still names its VarStore and VarOffset.
struct PasswordFields {
    question: QuestionHeader,
    max_size: Result<u16, ParseError>,
    header: HeaderPlace,
}

/// Where a PASSWORD op's question header lies.
#[derive(Clone, Copy)]
enum HeaderPlace {
    /// In the op
    InOp,
    /// Past the op's Length, in the bytes of its form package after it, where edk2-stable202608
    /// SetupBrowserDxe/IfrParse.c CreateQuestion (:119-124) reads it all the same
    PastOp,
}

/// The bytes of the storage of a password of `max_size` CHAR16s: MaxSize × 2.
pub(super) fn password_width(max_size: u16) -> usize {
    usize::from(max_size) * CHAR16_SIZE
}

impl PasswordFields {
    /// Those of the PASSWORD `op`, its question header read past its Length where the op ends
    /// before it (IFROperation::keep_header_past_length), or why that header does not parse, as
    /// it runs past the form package. MaxSize is read from the op alone: one past its Length is
    /// unknown, as for an op that ends before its MaxSize, so every byte from the VarOffset on is
    /// withheld.
    fn of(op: &IFROperation) -> Result<Self, ParseError> {
        let mut fields = Cursor::new([op.data.as_slice(), &op.header_past_length].concat());
        let question = fields.parse_ne()?;
        Ok(Self {
            question,
            max_size: fields
                .parse_ne::<PasswordSizes>()
                .map(|sizes| sizes.max_size),
            header: match op.header_past_length.is_empty() {
                true => HeaderPlace::InOp,
                false => HeaderPlace::PastOp,
            },
        })
    }

    /// Its question on the variable `key` of the layout `layout`.
    fn on(&self, key: VariableKey, layout: VariableLayout) -> PasswordQuestion {
        PasswordQuestion {
            key,
            offset: layout.offset(self.question.var_store_info),
            max_size: self.max_size.as_ref().ok().copied(),
        }
    }

    /// The value bytes that hold its password at its VarOffset in each VARSTORE and VARSTORE_EFI
    /// that holds it.
    fn bytes(&self) -> Range<usize> {
        let offset = VariableLayout::Offsets.offset(self.question.var_store_info);
        password_bytes(offset, self.max_size.as_ref().ok().copied())
    }

    /// Its questions on the variables that its VarName may name on the VARSTORE_EFIs before UEFI
    /// 2.3.1 of the Guids `guids`, in the package list of the strings packages `strings`
    /// (var_name_candidates), each from byte 0.
    fn on_var_names<'a>(
        &self,
        guids: impl IntoIterator<Item = &'a Guid>,
        strings: &[StringPackage],
    ) -> Vec<PasswordQuestion> {
        guids
            .into_iter()
            .flat_map(|&guid| var_name_candidates(guid, self.question.var_store_info, strings))
            .map(|key| self.on(key, VariableLayout::OneValue))
            .collect()
    }
}

impl PasswordQuestion {
    /// The value bytes of its variable that hold its password.
    fn bytes(&self) -> Range<usize> {
        password_bytes(self.offset, self.max_size)
    }
}

/// The value bytes that hold the password of a PASSWORD of MaxSize `max_size` from `offset`: its
/// storage (password_width), or all from `offset` on without MaxSize.
fn password_bytes(offset: u16, max_size: Option<u16>) -> Range<usize> {
    let start = usize::from(offset);
    match max_size {
        Some(max_size) => start..start + password_width(max_size),
        None => start..usize::MAX,
    }
}

/// The PASSWORD questions of one VarStoreId of a package list that more than one variable holds,
/// with the variables of the VARSTOREs and VARSTORE_EFIs of that id: each password is recorded
/// once, not once for each variable that holds it.
#[derive(Debug, Default, PartialEq, Eq)]
struct SharedPasswords {
    /// Those in FormSets, by the index of the root of their FormSet in the package list
    /// (DisabledForm::root_index in a disabled form), which hold the passwords of the PASSWORDs of
    /// their FormSet and those outside any FormSet
    in_form_sets: BTreeMap<usize, Vec<VariableKey>>,
    /// Those outside any FormSet, which hold every password here
    outside: Vec<VariableKey>,
    /// The passwords of the PASSWORDs in FormSets, by the index of the root of their FormSet
    form_set_passwords: BTreeMap<usize, Vec<Range<usize>>>,
    /// The passwords of the PASSWORDs outside any FormSet
    outside_passwords: Vec<Range<usize>>,
}

impl SharedPasswords {
    /// Whether a variable here holds a password here.
    fn holds_any(&self) -> bool {
        let passwords = !(self.form_set_passwords.is_empty() && self.outside_passwords.is_empty());
        let variables = !(self.in_form_sets.is_empty() && self.outside.is_empty());
        passwords && variables
    }

    /// Whether `key` is the variable of a VarStore of the FormSet of root `root` or of one outside
    /// any FormSet, which hold the passwords of that FormSet's PASSWORDs.
    fn holds_form_set_passwords(&self, root: usize, key: &VariableKey) -> bool {
        let in_form_set = self.in_form_sets.get(&root).into_iter().flatten();
        in_form_set.chain(&self.outside).any(|held| held == key)
    }

    /// Withholds each password here once in `withheld`, in shared sets: one for the PASSWORDs of
    /// each FormSet, which its VarStores withhold, and one for the PASSWORDs outside any FormSet,
    /// which the VarStores in FormSets withhold too. The VarStores outside any FormSet withhold
    /// every set, so a variable that one of them declares takes no set as one of a FormSet too,
    /// as a VarStore in the scope of an unknown opcode of a FormSet is both.
    fn withhold(&self, withheld: &mut WithheldBytes) {
        let sets = withheld.share(
            self.form_set_passwords
                .values()
                .cloned()
                .chain([self.outside_passwords.clone()]),
        );
        let outside: BTreeSet<&VariableKey> = self.outside.iter().collect();
        for (set, root) in sets.clone().zip(self.form_set_passwords.keys()) {
            let in_form_set = self.in_form_sets.get(root).into_iter().flatten();
            for key in in_form_set.filter(|key| !outside.contains(key)) {
                withheld.withhold_shared(key, set..set + 1);
            }
        }
        if !self.outside_passwords.is_empty() {
            let in_form_sets = self.in_form_sets.values().flatten();
            for key in in_form_sets.filter(|key| !outside.contains(key)) {
                withheld.withhold_shared(key, sets.end - 1..sets.end);
            }
        }
        for key in &self.outside {
            withheld.withhold_shared(key, sets.clone());
        }
    }

    /// The variables and passwords that this records, which tests of the bound on its records
    /// count.
    #[cfg(test)]
    fn entries(&self) -> usize {
        self.in_form_sets.values().map(Vec::len).sum::<usize>()
            + self.outside.len()
            + self
                .form_set_passwords
                .values()
                .map(Vec::len)
                .sum::<usize>()
            + self.outside_passwords.len()
    }
}

/// The VarStores of each VarStoreId of a package list, read once for all its PASSWORDs, with the
/// passwords that they share, and the VarStore ops of each FormSet that do not decode, whose
/// VarStoreIds are unknown, by the index of its root in the package list.
#[derive(Default)]
struct VarStoreIds {
    ids: BTreeMap<u16, IdStores>,
    undecoded: BTreeMap<usize, UndecodedStores>,
}

/// The VarStore ops of a FormSet that do not decode: the first, and the storage that they may
/// declare (DeclaredStorage::declare_in_tree), where a PASSWORD of the FormSet of any VarStoreId
/// may keep its password, as find_corresponding_varstore takes a VarStore of the PASSWORD's
/// FormSet, and FindStorageFromVarId the first VarStore op of the id whatever its scope.
struct UndecodedStores {
    first: UnknownStore,
    storage: DeclaredStorage,
    /// Whether one is a VARSTORE_NAME_VALUE (DeclaredStorage::name_value), which `storage` no
    /// longer tells once withheld
    name_value: bool,
}

/// The VarStores of one VarStoreId of a package list.
#[derive(Default)]
struct IdStores {
    shared: SharedPasswords,
    /// The first VarStore of the id outside any FormSet, or in the scope of an unknown opcode,
    /// that names no variable, at this offset of a form package, and where it sits
    nameless: Option<(NamelessStore, u64, OutsidePlace)>,
    /// The Guids of the VARSTORE_EFIs before UEFI 2.3.1 of the id in FormSets, whose questions'
    /// VarNames name their variables
    short_in_form_sets: BTreeSet<Guid>,
    /// Those outside any FormSet
    short_outside: BTreeSet<Guid>,
    /// Those of each FormSet that name no variable of their own, by the index of its root
    form_sets: BTreeMap<usize, FormSetStores>,
}

impl IdStores {
    /// Whether a VARSTORE_NAME_VALUE of the id is in the FormSet of root `root`, if any.
    fn name_value_in(&self, root: Option<usize>) -> bool {
        root.and_then(|root| self.form_sets.get(&root))
            .is_some_and(|stores| stores.name_value.is_some())
    }
}

/// The VarStores of one VarStoreId in one FormSet, whatever the ops around them, that name no
/// variable of their own: edk2-stable202608 ConfigKeywordHandler.c FindStorageFromVarId
/// (:1519-1570) takes the first VarStore op of the id in the form package, whatever its scope,
/// so each may hold what a question of the id writes.
#[derive(Default)]
struct FormSetStores {
    /// Its VARSTORE_EFIs before UEFI 2.3.1, each at its position in the walk of its FormSet
    short: Vec<(usize, ShortVarStoreEfi)>,
    /// The first VARSTORE_NAME_VALUE, whose values only its driver holds
    name_value: Option<UnknownStore>,
}

/// A VarStore op of a FormSet whose variable is unknown, at its position in the walk of its
/// FormSet, and why.
#[derive(Clone)]
struct UnknownStore {
    at: usize,
    reason: String,
}

/// A VarStore that names no variable.
#[derive(Clone, Copy)]
enum NamelessStore {
    /// A VARSTORE_NAME_VALUE, whose values only its driver holds
    NameValue,
    /// A VARSTORE_EFI before UEFI 2.3.1
    ShortEfi,
}

/// The variable that a VarStore names, if any.
enum StoreVariable {
    /// That of a VARSTORE or VARSTORE_EFI, of its layout
    Named(VariableKey, VariableLayout),
    /// None: a VARSTORE_NAME_VALUE's values only its driver holds
    NameValue,
    /// None: the ops on a VARSTORE_EFI before UEFI 2.3.1 of the Guid name variables by their
    /// VarNames
    ShortEfi(Guid),
}

impl StoreVariable {
    /// That of `store`.
    fn of(store: &DeclaredStore) -> Self {
        match store {
            DeclaredStore::Variable(store) => Self::Named(store.variable_key(), store.layout()),
            DeclaredStore::NameValue(_) => Self::NameValue,
            DeclaredStore::ShortEfi(store) => Self::ShortEfi(store.guid),
        }
    }

    /// Why the password of the PASSWORD `question_id` of the FormSet `form_set` is unknown, where
    /// this is the variable of the first VarStore of its VarStoreId in its form package, which the
    /// FormSet `declared_by` declares: it names none.
    fn unresolved(
        &self,
        form_set: Option<Guid>,
        question_id: u16,
        declared_by: Option<Guid>,
    ) -> Option<UnresolvedPassword> {
        match self {
            Self::Named(..) => None,
            Self::NameValue => Some(UnresolvedPassword::NameValueOfAnotherFormSet {
                form_set,
                question_id,
                declared_by,
            }),
            Self::ShortEfi(_) => Some(UnresolvedPassword::ShortVarStoreEfiOfAnotherFormSet {
                form_set,
                question_id,
                declared_by,
            }),
        }
    }
}

impl VarStoreIds {
    /// Those of `list`, in its FormSets and the forms that read_db disables among them
    /// (in_form_sets), and outside any, but for those in the IFR that IgnoredPasswords::Declared
    /// covers, whose storage PasswordQuestions withholds whole.
    fn of(list: &ParsedPackageList) -> Self {
        let mut ids = Self::in_form_sets(&list.forms, &list.disabled_forms);
        for outside in list
            .outside_ifr
            .iter()
            .filter(|outside| !outside.in_ignored_ifr)
        {
            let Some((var_store_id, store)) = declared_store(&outside.op.parsed_data) else {
                continue;
            };
            let stores = ids.ids.entry(var_store_id).or_default();
            let nameless = match store {
                DeclaredStore::Variable(store) => {
                    stores.shared.outside.push(store.variable_key());
                    continue;
                }
                DeclaredStore::NameValue(_) => NamelessStore::NameValue,
                DeclaredStore::ShortEfi(store) => {
                    stores.short_outside.insert(store.guid);
                    NamelessStore::ShortEfi
                }
            };
            stores
                .nameless
                .get_or_insert((nameless, outside.offset, outside.place));
        }
        ids
    }

    /// Those of the FormSets of `roots`, one package list's, and of the forms `disabled` that
    /// their parse drops from them, each in the FormSet of its root (DisabledForm::root_index), in
    /// any scope: in forms and unknown ops too, whose VarStore ops decoded_store decodes.
    fn in_form_sets(roots: &[Rc<RefCell<IFROperation>>], disabled: &[DisabledForm]) -> Self {
        let mut ids = Self::default();
        let trees = roots.iter().enumerate().chain(
            disabled
                .iter()
                .map(|disabled| (disabled.root_index, &disabled.form)),
        );
        // one count for every walk: it orders the VarStores of a FormSet alone
        let mut at = 0;
        for (root, tree) in trees {
            walk_scopes(std::slice::from_ref(tree), (), |node, ()| {
                at += 1;
                match decoded_store(&node.borrow()) {
                    Ok(Some((var_store_id, store))) => ids.add(var_store_id, store, root, at),
                    Ok(None) => {}
                    Err(error) => ids.add_undecoded(&node.borrow(), &error, root, at),
                }
                Walk::Enter(())
            });
        }
        ids
    }

    /// Adds `store` of `var_store_id`, at `at` in the walk of the FormSet of root `root`.
    fn add(&mut self, var_store_id: u16, store: DeclaredStore, root: usize, at: usize) {
        let stores = self.ids.entry(var_store_id).or_default();
        match store {
            DeclaredStore::Variable(store) => stores
                .shared
                .in_form_sets
                .entry(root)
                .or_default()
                .push(store.variable_key()),
            DeclaredStore::ShortEfi(store) => {
                stores.short_in_form_sets.insert(store.guid);
                stores
                    .form_sets
                    .entry(root)
                    .or_default()
                    .short
                    .push((at, store));
            }
            DeclaredStore::NameValue(guid) => {
                let form_set = stores.form_sets.entry(root).or_default();
                form_set.name_value.get_or_insert(UnknownStore {
                    at,
                    reason: NameValueStore { guid }.to_string(),
                });
            }
        }
    }

    /// Adds the VarStore op `op`, which does not decode for `error`, at `at` in the walk of the
    /// FormSet of root `root`.
    fn add_undecoded(&mut self, op: &IFROperation, error: &anyhow::Error, root: usize, at: usize) {
        let undecoded = self
            .undecoded
            .entry(root)
            .or_insert_with(|| UndecodedStores {
                first: UnknownStore {
                    at,
                    reason: format!("{error:#}"),
                },
                storage: DeclaredStorage::default(),
                name_value: false,
            });
        undecoded.storage.declare_in_tree(op);
        undecoded.name_value |= undecoded.storage.name_value;
    }

    /// Who keeps the password of a PASSWORD of this package list whose VarStore is unknown, of
    /// VarStoreId `id`, or of any for one without a question header (None), in the FormSet of
    /// root `root` if any, of the form package of the FirstVarStores `package`: the driver of a
    /// VARSTORE_NAME_VALUE that edk2 may route it to, else its IFR. The Forms Browser gives a
    /// question of a FormSet the VarStore of its id there (SetupBrowserDxe/IfrParse.c
    /// CreateQuestion, :136-146), so a VARSTORE_NAME_VALUE of that id there counts, which
    /// IfrParse.c creates whatever its Length (:1885-1895), as does a VarStore op there that does
    /// not decode and is one; the Config Keyword Handler the first VarStore of the id in the
    /// question's form package (ConfigKeywordHandler.c FindStorageFromVarId, :1520-1567), so the
    /// first that is a VARSTORE_NAME_VALUE counts, in a FormSet or not, and none of another form
    /// package. VarStoreId 0 names no VarStore (UEFI 2.11 §33.3.8.2.2).
    fn keeper(
        &self,
        id: Option<u16>,
        root: Option<usize>,
        package: Option<&FirstVarStores>,
    ) -> Keeper {
        let undecoded = root
            .and_then(|root| self.undecoded.get(&root))
            .is_some_and(|undecoded| undecoded.name_value);
        let (form_set, first) = match id {
            Some(0) => return Keeper::Ifr,
            Some(id) => (
                self.ids
                    .get(&id)
                    .is_some_and(|stores| stores.name_value_in(root)),
                package.is_some_and(|package| package.name_value_first.contains(&id)),
            ),
            None => (
                self.ids.values().any(|stores| stores.name_value_in(root)),
                package.is_some_and(|package| !package.name_value_first.is_empty()),
            ),
        };
        Keeper::of(form_set || undecoded || first)
    }

    /// The storage of every VARSTORE and VARSTORE_EFI here: the variables that they name, and
    /// the Guids of those before UEFI 2.3.1, any variable of which a VarName may name.
    fn storage(&self) -> DeclaredStorage {
        let mut storage = DeclaredStorage::default();
        for stores in self.ids.values() {
            let shared = &stores.shared;
            let in_form_sets = shared.in_form_sets.values().flatten();
            storage
                .variables
                .extend(in_form_sets.chain(&shared.outside).cloned());
            for &guid in stores.short_in_form_sets.union(&stores.short_outside) {
                storage.guids.insert(Some(guid));
            }
        }
        storage
    }

    /// The SharedPasswords of each VarStoreId whose variables hold a password.
    fn into_shared(self) -> impl Iterator<Item = SharedPasswords> {
        self.ids
            .into_values()
            .map(|stores| stores.shared)
            .filter(SharedPasswords::holds_any)
    }
}

/// A PASSWORD in a FormSet with a VarStoreId, with its questions on the VARSTORE_EFIs before UEFI
/// 2.3.1 of that id in its FormSet whose variable its VarName names, and the variables that it may
/// name on those whose variable it does not (ShortVarStoreEfi::candidate_variables), each from
/// byte 0, and the variable of the first VarStore of the id in its form package, where another
/// FormSet declares it (password_questions).
struct FormSetPassword {
    password: PasswordFields,
    short: Vec<PasswordQuestion>,
    candidates: Vec<PasswordQuestion>,
    first: Option<StoreVariable>,
}

impl PasswordQuestions {
    /// Those of the FormSets of `roots`: outside the tests, of_lists finds them with the
    /// VarStores and PASSWORDs outside any FormSet.
    #[cfg(test)]
    pub(crate) fn of<'a>(roots: impl IntoIterator<Item = &'a Rc<RefCell<IFROperation>>>) -> Self {
        let roots: Vec<Rc<RefCell<IFROperation>>> = roots.into_iter().map(Rc::clone).collect();
        Self::of_forms(&roots, &[])
    }

    /// Those of the package lists `lists`, the forms that read_db disables too, as their ops are
    /// read. IFR that read_db ignores may hold any PASSWORD question, so each counts as one whose
    /// VarStore is unknown: one in a FormSet that it ignores, or past the End of one without Scope,
    /// keeps its password in the storage that IgnoredPasswords::Declared names, withheld whole;
    /// one past an op where the walk for FormSets ends, in any variable, which refuses every
    /// variable (AnyVariable). A PASSWORD outside any FormSet, which no Forms Browser shows but
    /// the Config Keyword Handler finds, counts as one whose VarStore is unknown too.
    pub(crate) fn of_lists(lists: &[ParsedPackageList]) -> Self {
        let mut found = Self::default();
        let mut ids: Vec<VarStoreIds> = lists.iter().map(VarStoreIds::of).collect();
        for (list, ids) in lists.iter().zip(&mut ids) {
            found.add_forms(
                &list.forms,
                &list.disabled_forms,
                &list.first_var_stores,
                ids,
                &list.strings,
            );
        }
        for (list, ids) in lists.iter().zip(&mut ids) {
            for (index, outside) in list.outside_ifr.iter().enumerate() {
                if outside.op.op_code == IFROpCode::Password {
                    let package =
                        package_of(&list.first_var_stores, index, |package| &package.outside);
                    found.add_outside(list, outside, package, ids);
                }
            }
        }
        found
            .shared
            .extend(ids.into_iter().flat_map(VarStoreIds::into_shared));
        // a malformed VarStore outside a FormSet may declare the VarStoreId of any PASSWORD
        if found.declared {
            for malformed in lists.iter().flat_map(|list| &list.malformed_outside_stores) {
                let keeper = match &malformed.passwords {
                    IgnoredPasswords::Declared(storage) => {
                        found.storage.extend(storage);
                        Keeper::of(storage.name_value)
                    }
                    IgnoredPasswords::AnyVariable | IgnoredPasswords::Found => Keeper::Ifr,
                };
                let unresolved = UnresolvedPassword::MalformedVarStoreOutsideFormSet {
                    package_list: malformed.package_list,
                    offset: malformed.offset,
                    reason: malformed.reason.clone(),
                };
                found.add_unresolved(unresolved, keeper);
            }
        }
        // one per form package, which its records share
        let mut declared: Vec<&Arc<DeclaredStorage>> = Vec::new();
        for ignored in lists.iter().flat_map(|list| &list.ignored_ifr) {
            let (package_list, offset, reason) =
                (ignored.package_list, ignored.offset, ignored.reason.clone());
            let (unresolved, keeper) = match &ignored.passwords {
                IgnoredPasswords::AnyVariable => (
                    UnresolvedPassword::AnyVariable {
                        package_list,
                        offset,
                        reason,
                    },
                    Keeper::Ifr,
                ),
                IgnoredPasswords::Declared(storage) => {
                    if !declared.iter().any(|seen| Arc::ptr_eq(seen, storage)) {
                        declared.push(storage);
                        found.storage.extend(storage);
                    }
                    let unresolved = UnresolvedPassword::InIgnoredIfr {
                        package_list,
                        offset,
                        reason,
                    };
                    (unresolved, Keeper::of(storage.name_value))
                }
                IgnoredPasswords::Found => (
                    UnresolvedPassword::InIgnoredIfr {
                        package_list,
                        offset,
                        reason,
                    },
                    Keeper::Ifr,
                ),
            };
            found.add_unresolved(unresolved, keeper);
        }
        found
    }

    /// Those of the FormSets of `roots` and of the forms `disabled` that their parse drops from
    /// them: outside the tests, of_lists finds them with the VarStores and PASSWORDs outside any
    /// FormSet.
    #[cfg(test)]
    fn of_forms(roots: &[Rc<RefCell<IFROperation>>], disabled: &[DisabledForm]) -> Self {
        let mut found = Self::default();
        let mut ids = VarStoreIds::in_form_sets(roots, disabled);
        found.add_forms(roots, disabled, &[], &mut ids, &[]);
        found.shared.extend(ids.into_shared());
        found
    }

    /// Adds those of the FormSets of `roots` and of the forms `disabled` that their parse drops
    /// from them, each in the FormSet of its root (DisabledForm::root_index), as their ops are
    /// read, with the FirstVarStores of their form packages, `packages`, which hold their roots,
    /// the VarStores of each VarStoreId of their package list, `ids`, and its strings packages,
    /// `strings`.
    fn add_forms(
        &mut self,
        roots: &[Rc<RefCell<IFROperation>>],
        disabled: &[DisabledForm],
        packages: &[FirstVarStores],
        ids: &mut VarStoreIds,
        strings: &[StringPackage],
    ) {
        for (root, tree) in roots.iter().enumerate() {
            let package = package_of(packages, root, |package| &package.form_sets);
            self.add(tree, None, root, package, ids, strings);
        }
        for disabled in disabled {
            let form_set = enclosing_form_set(&disabled.form.borrow())
                .and_then(|form_set| form_set_guid(&form_set.borrow()));
            let package = package_of(packages, disabled.root_index, |package| &package.form_sets);
            self.add(
                &disabled.form,
                form_set,
                disabled.root_index,
                package,
                ids,
                strings,
            );
        }
    }

    /// Adds those of `node`, in the FormSet `form_set` if any, of the root of index `root` in its
    /// package list, and the ops in its scope, with the FirstVarStores of their form package,
    /// `package`, the VarStores of each VarStoreId of their package list, `ids`, and its strings
    /// packages, `strings`.
    fn add(
        &mut self,
        node: &Rc<RefCell<IFROperation>>,
        form_set: Option<Guid>,
        root: usize,
        package: Option<&FirstVarStores>,
        ids: &mut VarStoreIds,
        strings: &[StringPackage],
    ) {
        walk_scopes(std::slice::from_ref(node), form_set, |node, &form_set| {
            let op = node.borrow();
            let form_set = form_set_guid(&op).or(form_set);
            if op.op_code == IFROpCode::Password {
                self.add_form_set_password(&op, form_set, root, package, ids, strings);
            }
            Walk::Enter(form_set)
        });
    }

    /// Adds the PASSWORD `op`, of the FormSet `form_set`, of the root of index `root` in its
    /// package list, with the FirstVarStores of its form package, `package`, the VarStores of each
    /// VarStoreId of that list, `ids`, and its strings packages, `strings`. One whose question
    /// header lies past its op is found by the Forms Browser in the VarStore of its id that its
    /// FormSet declares, and by the Config Keyword Handler in the first VarStore of that id in the
    /// form package (edk2-stable202608 ConfigKeywordHandler.c FindStorageFromVarId, :1520), so it
    /// is added as one outside any FormSet is (add_in_package_list) and is unresolved; one whose
    /// header runs past the form package names no VarStore, so every variable of each VarStore of
    /// its package list is withheld whole. Either way, what is withheld covers the first VarStore
    /// of its id in its form package, which password_questions adds for one whose header is in its
    /// op: each VARSTORE and VARSTORE_EFI of the id in the package list keeps the password from its
    /// VarOffset on, and the variables of the VarNames on those before UEFI 2.3.1 are withheld.
    /// Only one that passes those checks is added in the FormSet of its root (password_questions),
    /// with the storage of its VarStore ops that do not decode (withhold_undecoded). An unresolved
    /// one that edk2 may route to a VARSTORE_NAME_VALUE, in its FormSet or as the first VarStore
    /// of its id, or of any id for one without a header, in its form package, is driver-held
    /// (VarStoreIds::keeper).
    fn add_form_set_password(
        &mut self,
        op: &IFROperation,
        form_set: Option<Guid>,
        root: usize,
        package: Option<&FirstVarStores>,
        ids: &mut VarStoreIds,
        strings: &[StringPackage],
    ) {
        self.declared = true;
        let password = match PasswordFields::of(op) {
            Ok(password) => password,
            Err(error) => {
                self.storage.extend(&ids.storage());
                let reason = error.to_string();
                let unresolved = UnresolvedPassword::NoHeader { form_set, reason };
                self.add_unresolved(unresolved, ids.keeper(None, Some(root), package));
                return;
            }
        };
        if let HeaderPlace::PastOp = password.header {
            self.add_in_package_list(&password, ids, strings);
            let unresolved = UnresolvedPassword::HeaderPastOp {
                form_set,
                question_id: password.question.question_id,
            };
            let id = Some(password.question.var_store_id);
            self.add_unresolved(unresolved, ids.keeper(id, Some(root), package));
            return;
        }
        self.withhold_undecoded(&password, root, ids);
        let (password, unresolved) = password_questions(op, password, form_set, root, package, ids);
        if let Some(password) = password {
            self.add_in_form_set(password, root, ids, strings);
        }
        if let Some((unresolved, keeper)) = unresolved {
            self.add_unresolved(unresolved, keeper);
        }
    }

    /// Withholds whole, for the PASSWORD `password` of the FormSet of root `root`, the storage that
    /// the VarStore ops of that FormSet that do not decode may declare (UndecodedStores), once for
    /// all its PASSWORDs, unless `password` names VarStoreId 0, which names no VarStore.
    fn withhold_undecoded(
        &mut self,
        password: &PasswordFields,
        root: usize,
        ids: &mut VarStoreIds,
    ) {
        if password.question.var_store_id == 0 {
            return;
        }
        if let Some(undecoded) = ids.undecoded.get_mut(&root) {
            self.storage.extend(&std::mem::take(&mut undecoded.storage));
        }
    }

    /// Adds `password`, of the FormSet of root `root`: at its VarOffset in each VARSTORE and
    /// VARSTORE_EFI of its VarStoreId in its FormSet, whatever the ops around it, and in each
    /// outside any FormSet, which `ids` holds; as its question if one variable holds it, else once
    /// in their SharedPasswords. Through Runtime, as its password is unresolved then
    /// (password_questions), also in each variable that its VarName may name on a VARSTORE_EFI
    /// before UEFI 2.3.1 of that id outside any FormSet, in the package list of the strings
    /// packages `strings`. The first VarStore of that id in its form package, where another
    /// FormSet declares it, holds it likewise, unless its variable is one of those.
    fn add_in_form_set(
        &mut self,
        FormSetPassword {
            password,
            short,
            candidates,
            first,
        }: FormSetPassword,
        root: usize,
        ids: &mut VarStoreIds,
        strings: &[StringPackage],
    ) {
        self.questions.extend(short);
        self.candidates.extend(candidates);
        let stores = ids.ids.get_mut(&password.question.var_store_id);
        match first {
            Some(StoreVariable::Named(key, VariableLayout::Offsets))
                if stores
                    .as_ref()
                    .is_some_and(|stores| stores.shared.holds_form_set_passwords(root, &key)) => {}
            Some(StoreVariable::Named(key, layout)) => {
                self.questions.push(password.on(key, layout))
            }
            Some(StoreVariable::ShortEfi(guid)) => self
                .candidates
                .extend(password.on_var_names([&guid], strings)),
            Some(StoreVariable::NameValue) | None => {}
        }
        let Some(stores) = stores else {
            return;
        };
        self.candidates
            .extend(password.on_var_names(&stores.short_outside, strings));
        let in_form_set = stores.shared.in_form_sets.get(&root);
        match (
            in_form_set.map_or(&[][..], Vec::as_slice),
            stores.shared.outside.is_empty(),
        ) {
            ([], true) => {}
            ([key], true) => self
                .questions
                .push(password.on(key.clone(), VariableLayout::Offsets)),
            (_, _) => stores
                .shared
                .form_set_passwords
                .entry(root)
                .or_default()
                .push(password.bytes()),
        }
    }

    /// Adds the PASSWORD op `outside` of the package list `list`, outside any FormSet, with the
    /// FirstVarStores of its form package, `package`. Its
    /// VarStore is unknown: edk2-stable202608 ConfigKeywordHandler.c FindStorageFromVarId takes
    /// the first VarStore of its VarStoreId in the form package, in a FormSet or not, and other
    /// firmware may take another, so its password is withheld at its VarOffset in each VARSTORE
    /// and VARSTORE_EFI of that id in `list`, which `ids` holds, and through Runtime from byte 0
    /// of each variable that its VarName may name on a VARSTORE_EFI before UEFI 2.3.1 of that id.
    /// One of VarStoreId 0 names no VarStore, as one in a FormSet does not, and the Keyword
    /// Handler skips it (ExtractConfigRequest). One whose op ends before its MaxSize keeps every
    /// byte from its VarOffset on, and from byte 0 of each such variable. One in ignored IFR
    /// (OutsideOp::in_ignored_ifr) is withheld so too, as the Keyword Handler finds it there, and
    /// its record counts it already. One whose question header lies past its op is read there
    /// (PasswordFields::of); one whose header runs past the form package names no VarStore, so
    /// every variable of each VarStore of `list` is withheld whole. One that edk2 may route to a
    /// VARSTORE_NAME_VALUE, the first VarStore of its id, or of any id for one without a header,
    /// in its form package (VarStoreIds::keeper), is driver-held, with a record of its own in
    /// ignored IFR.
    fn add_outside(
        &mut self,
        list: &ParsedPackageList,
        outside: &OutsideOp,
        package: Option<&FirstVarStores>,
        ids: &mut VarStoreIds,
    ) {
        self.declared = true;
        let keeper = match PasswordFields::of(&outside.op) {
            Ok(password) if password.question.var_store_id == 0 => return,
            Ok(password) => {
                self.add_in_package_list(&password, ids, &list.strings);
                ids.keeper(Some(password.question.var_store_id), None, package)
            }
            Err(error) => {
                debug!(
                    "PASSWORD op outside a FormSet, at offset {}: {error}",
                    outside.offset
                );
                self.storage.extend(&ids.storage());
                ids.keeper(None, None, package)
            }
        };
        let (package_list, offset) = (list.guid, outside.offset);
        match (outside.in_ignored_ifr, keeper) {
            (false, _) => {
                let unresolved = UnresolvedPassword::OutsideFormSet {
                    package_list,
                    offset,
                };
                self.add_unresolved(unresolved, keeper);
            }
            (true, Keeper::Ifr) => {}
            (true, Keeper::NameValueDriver) => {
                self.driver_held.push(UnresolvedPassword::InIgnoredIfr {
                    package_list,
                    offset,
                    reason: "the PASSWORD op there, which edk2 may route to a VARSTORE_NAME_VALUE \
                             of its form package"
                        .to_owned(),
                })
            }
        }
    }

    /// Adds `password`, whose VarStore is unknown, at its VarOffset in each VARSTORE and
    /// VARSTORE_EFI of its VarStoreId in the package list whose VarStores are `ids`, and from
    /// byte 0 of each variable that its VarName may name on a VARSTORE_EFI before UEFI 2.3.1 of
    /// that id by the list's strings packages `strings`; none for VarStoreId 0, which names no
    /// VarStore.
    fn add_in_package_list(
        &mut self,
        password: &PasswordFields,
        ids: &mut VarStoreIds,
        strings: &[StringPackage],
    ) {
        let id = password.question.var_store_id;
        let Some(stores) = ids.ids.get_mut(&id).filter(|_| id != 0) else {
            return;
        };
        stores.shared.outside_passwords.push(password.bytes());
        self.candidates.extend(password.on_var_names(
            stores.short_in_form_sets.union(&stores.short_outside),
            strings,
        ));
    }

    /// Adds the PASSWORD op `unresolved`, whose VarStore is unknown, and whose password `keeper`
    /// keeps.
    fn add_unresolved(&mut self, unresolved: UnresolvedPassword, keeper: Keeper) {
        warn!("{unresolved}");
        match keeper {
            Keeper::Ifr => {}
            Keeper::NameValueDriver => self.driver_held.push(unresolved.clone()),
        }
        self.unresolved.push(unresolved);
    }

    /// The bytes that questions read and set through `variables` withhold: those of every
    /// PASSWORD question with a VarStore, and every byte of `storage`,
    /// whatever the reach, so that no password byte is shown or written back. Through
    /// variables that reach BootServices, a PASSWORD op whose VarStore is unknown could keep its
    /// password in any variable, so this fails closed: UnresolvedPasswords, whatever the setup
    /// password policy, and no variable of the HiiDB is read or written; through those that reach
    /// Runtime it withholds the bytes of the others, and those of the variables that may hold its
    /// password, where they are known, unless IFR past an op where the walk for FormSets ends may
    /// hold one, as read_db failed for such IFR before the first FormSet, or the driver of a
    /// VARSTORE_NAME_VALUE may keep one (driver_held): AnyVariablePasswords; variables that read
    /// nothing are not refused so.
    fn withheld(
        &self,
        variables: &dyn FirmwareVariables,
    ) -> Result<WithheldBytes, WithholdingRefusal> {
        match (variables.reach(), self.unresolved.as_slice()) {
            (VariableReach::BootServices, [_, ..]) => Err(WithholdingRefusal::BootServices(
                UnresolvedPasswords(self.unresolved.clone()),
            )),
            (VariableReach::Runtime, _) | (VariableReach::BootServices, []) => {
                match (self.check_bounded(), variables.reads_nothing()) {
                    (Err(refusal), false) => Err(WithholdingRefusal::AnyVariable(refusal)),
                    (Ok(()), _) | (Err(_), true) => {
                        let mut withheld = self.password_bytes();
                        for candidate in &self.candidates {
                            withheld.insert(candidate.key.clone(), candidate.bytes());
                        }
                        Ok(withheld)
                    }
                }
            }
        }
    }

    /// Refuses a HiiDB with IFR past an op where the walk for FormSets ends, whose PASSWORD ops,
    /// with no op boundary, may keep their passwords in any variable, or with a PASSWORD that edk2
    /// may route to a VARSTORE_NAME_VALUE, whose driver may keep it in any variable (driver_held).
    pub(crate) fn check_bounded(&self) -> Result<(), AnyVariablePasswords> {
        let unbounded: Vec<UnresolvedPassword> = self
            .unresolved
            .iter()
            .filter(|unresolved| matches!(unresolved, UnresolvedPassword::AnyVariable { .. }))
            .chain(&self.driver_held)
            .cloned()
            .collect();
        match unbounded.as_slice() {
            [] => Ok(()),
            [_, ..] => Err(AnyVariablePasswords(unbounded)),
        }
    }

    /// The bytes of every PASSWORD question with a VarStore, and every byte of `storage`.
    fn password_bytes(&self) -> WithheldBytes {
        let mut withheld = WithheldBytes::default();
        for question in &self.questions {
            withheld.insert(question.key.clone(), question.bytes());
        }
        for shared in &self.shared {
            shared.withhold(&mut withheld);
        }
        for key in &self.storage.variables {
            withheld.insert(key.clone(), 0..usize::MAX);
        }
        withheld.insert_guids(&self.storage.guids);
        withheld
    }

    /// The questions, variables and passwords that this records, which tests of the bound on its
    /// records count.
    #[cfg(test)]
    fn entries(&self) -> usize {
        self.questions.len()
            + self
                .shared
                .iter()
                .map(SharedPasswords::entries)
                .sum::<usize>()
    }

    /// The bytes of every PASSWORD question with a VarStore, which a ConfigSnapshot drops
    /// whatever the reach: ExportConfig() exports their storage though Linux, which reaches
    /// Runtime, may see none of them. Err holds the PASSWORD ops whose VarStore is unknown, which
    /// could keep their passwords in any bytes.
    pub(crate) fn withheld_from_snapshot(&self) -> Result<WithheldBytes, &[UnresolvedPassword]> {
        match self.unresolved.as_slice() {
            [] => Ok(self.password_bytes()),
            unresolved => Err(unresolved),
        }
    }

    /// `variables` without the bytes that questions set through them withhold.
    pub(crate) fn withholding<V: FirmwareVariables>(
        &self,
        variables: V,
    ) -> Result<WithholdingVariables<V>, WithholdingRefusal> {
        let withheld = self.withheld(&variables)?;
        Ok(WithholdingVariables::new(variables, withheld))
    }

    /// A reader of `variables` without the bytes that questions read through them withhold,
    /// which no value decodes.
    pub(crate) fn reader(
        &self,
        variables: Box<dyn FirmwareVariables>,
    ) -> Result<EfivarReader, WithholdingRefusal> {
        let withheld = self.withheld(variables.as_ref())?;
        Ok(EfivarReader::withholding(variables, withheld))
    }

    /// The unsafe operation of set through variables that reach `reach` in this HiiDB, if any:
    /// UnsafeOperation::SetupPassword through variables that reach BootServices, as in the UEFI
    /// Shell, where the HiiDB declares a PASSWORD question: no setup browser runs there, so none
    /// asks for the password. Set through variables that reach Runtime writes as before.
    pub(crate) fn setup_password_bypass(&self, reach: VariableReach) -> Option<UnsafeOperation> {
        match (reach, self.declared) {
            (VariableReach::BootServices, true) => Some(UnsafeOperation::SetupPassword),
            (VariableReach::BootServices, false) | (VariableReach::Runtime, _) => None,
        }
    }
}

/// The GUID of the FormSet that `op` opens, if it is a decoded FORM_SET op.
fn form_set_guid(op: &IFROperation) -> Option<Guid> {
    match &op.parsed_data {
        ParsedOperation::FormSet(form_set) => Some(form_set.guid),
        _ => None,
    }
}

#[cfg(test)]
thread_local! {
    /// The FirstVarStores that package_of has compared on this thread, which tests of the bound on
    /// PasswordQuestions' lookups of form packages count.
    static PACKAGES_COMPARED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// The FirstVarStores of `packages` whose range `of`, of their FormSets by the index of a root or
/// of their ops outside them by the index of one in the list's outside_ifr, holds `index`, the
/// packages in the order of those ranges.
fn package_of(
    packages: &[FirstVarStores],
    index: usize,
    of: impl Fn(&FirstVarStores) -> &Range<usize>,
) -> Option<&FirstVarStores> {
    let package = packages.partition_point(|package| {
        #[cfg(test)]
        PACKAGES_COMPARED.with(|compared| compared.set(compared.get() + 1));
        of(package).end <= index
    });
    packages
        .get(package)
        .filter(|package| of(package).contains(&index))
}

/// The PASSWORD `op`, of the FormSet `form_set`, of the root `root` of its package list, whose
/// VarStores of each VarStoreId `ids` holds: every VARSTORE and VARSTORE_EFI of its VarStoreId in
/// its FormSet, whatever the ops around it, in the forms that read_db disables too, holds its
/// password at its VarOffset, and each outside any FormSet or in the scope of an unknown opcode
/// too, as edk2-stable202608 ConfigKeywordHandler.c FindStorageFromVarId may take any of them
/// first (add_in_form_set). Each VARSTORE_EFI before UEFI 2.3.1 of that id in its FormSet holds it
/// from byte 0 of the variable that its VarName names, as form_set_varstore takes it.
/// With them, never instead of them, the first reason that its password may be in a variable that
/// they do not name: in its FormSet, a VarStore op that does not decode, a VARSTORE_NAME_VALUE of
/// that id or such a VARSTORE_EFI whose VarName names no variable, or no VarStore of that id at
/// all; outside any FormSet or in the scope of an unknown opcode, a VARSTORE_NAME_VALUE or
/// VARSTORE_EFI before UEFI 2.3.1 of that id, which names none. None for VarStoreId 0, which
/// names no VarStore (UEFI 2.10 §33.3.8.2.2): its driver keeps such a question's value through
/// callbacks or READ/WRITE ops (§33.2.5.6), in no variable that the IFR names. Its fields
/// `password` are read from its op: one that ends before MaxSize still names its VarStore and
/// VarOffset, so its questions take every byte from there on, and it is unresolved too.
/// The first VarStore of that id in its form package, which FindStorageFromVarId takes
/// (ConfigKeywordHandler.c:1520-1567), in `package`, holds the password too where a FormSet other
/// than the nearest around the PASSWORD declares it, a FormSet nested in that one or around it
/// among them: a VARSTORE or VARSTORE_EFI at its VarOffset, while a VARSTORE_NAME_VALUE or
/// VARSTORE_EFI before UEFI 2.3.1 leaves it unresolved. Only the first: a later FormSet's VarStore
/// of the id holds none of it, unless that FormSet is in the PASSWORD's root.
/// The reason comes with who keeps the password (VarStoreIds::keeper): the driver of a
/// VARSTORE_NAME_VALUE that edk2 may route the PASSWORD to, one of its id in its FormSet, or a
/// VarStore op there that does not decode and is one, or the first VarStore of its id in its form
/// package, in a FormSet or not (ConfigKeywordHandler.c:1547-1550), else its IFR.
fn password_questions(
    op: &IFROperation,
    password: PasswordFields,
    form_set: Option<Guid>,
    root: usize,
    package: Option<&FirstVarStores>,
    ids: &VarStoreIds,
) -> (
    Option<FormSetPassword>,
    Option<(UnresolvedPassword, Keeper)>,
) {
    let header = &password.question;
    let no_max_size = password
        .max_size
        .as_ref()
        .err()
        .map(|error| UnresolvedPassword::NoMaxSize {
            form_set,
            question_id: header.question_id,
            reason: error.to_string(),
        });
    if header.var_store_id == 0 {
        return (
            None,
            no_max_size.map(|unresolved| (unresolved, Keeper::Ifr)),
        );
    }
    let stores = ids.ids.get(&header.var_store_id);
    let in_form_set = stores.and_then(|stores| stores.form_sets.get(&root));
    let mut unknown = ids
        .undecoded
        .get(&root)
        .map(|undecoded| undecoded.first.clone());
    let mut short = Vec::new();
    let mut candidates = Vec::new();
    for (at, store) in in_form_set.into_iter().flat_map(|stores| &stores.short) {
        match short_password_variable(store, &password) {
            Ok(key) => short.push(password.on(key, VariableLayout::OneValue)),
            Err(refusal) => {
                unknown = first_unknown(
                    unknown,
                    UnknownStore {
                        at: *at,
                        reason: refusal.to_string(),
                    },
                );
                candidates.extend(
                    store
                        .candidate_variables(header.var_store_info)
                        .into_iter()
                        .map(|key| password.on(key, VariableLayout::OneValue)),
                );
            }
        }
    }
    if let Some(name_value) = in_form_set.and_then(|stores| stores.name_value.clone()) {
        unknown = first_unknown(unknown, name_value);
    }
    let variables = stores.is_some_and(|stores| stores.shared.in_form_sets.contains_key(&root));
    let reason = match unknown {
        Some(unknown) => Some(unknown.reason),
        None if !variables && short.is_empty() => {
            Some(undeclared_var_store(header.var_store_id).to_string())
        }
        None => None,
    };
    let question_id = header.question_id;
    let mut unresolved = match reason {
        Some(reason) => Some(UnresolvedPassword::NoVarStore {
            form_set,
            question_id,
            reason,
        }),
        None => no_max_size,
    };
    if let Some((nameless, offset, place)) = stores.and_then(|stores| stores.nameless) {
        unresolved.get_or_insert(match nameless {
            NamelessStore::NameValue => UnresolvedPassword::NameValueOutsideFormSet {
                form_set,
                question_id,
                offset,
                place,
            },
            NamelessStore::ShortEfi => UnresolvedPassword::ShortVarStoreEfiOutsideFormSet {
                form_set,
                question_id,
                offset,
                place,
            },
        });
    }
    let own_form_set = enclosing_form_set(op);
    let first = package
        .and_then(|package| package.declared_by.get(&header.var_store_id))
        .filter(|first| {
            !own_form_set
                .as_ref()
                .is_some_and(|own| Rc::ptr_eq(own, &first.form_set))
        })
        .and_then(|first| {
            let (_, store) = declared_store(&first.store.borrow().parsed_data)?;
            Some((
                StoreVariable::of(&store),
                form_set_guid(&first.form_set.borrow()),
            ))
        });
    if let Some(reason) = first.as_ref().and_then(|(variable, declared_by)| {
        variable.unresolved(form_set, header.question_id, *declared_by)
    }) {
        unresolved.get_or_insert(reason);
    }
    let keeper = ids.keeper(Some(header.var_store_id), Some(root), package);
    let first = first.map(|(variable, _)| variable);
    let password = FormSetPassword {
        password,
        short,
        candidates,
        first,
    };
    let unresolved = unresolved.map(|unresolved| (unresolved, keeper));
    (Some(password), unresolved)
}

/// Of `unknown`, if any, and `other`, the one that comes first in the walk of their FormSet.
fn first_unknown(unknown: Option<UnknownStore>, other: UnknownStore) -> Option<UnknownStore> {
    Some(match unknown {
        Some(unknown) if unknown.at <= other.at => unknown,
        Some(_) | None => other,
    })
}

/// Who keeps the password of a PASSWORD op whose VarStore is unknown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Keeper {
    /// The storage that its IFR names, which PasswordQuestions withholds where it is known
    Ifr,
    /// The driver of a VARSTORE_NAME_VALUE that edk2 may route it to, whose values its driver
    /// exposes, as UEFI 2.11 §33.2.5.6 says, through EFI_HII_CONFIG_ACCESS_PROTOCOL, in storage
    /// of its own choosing, so in any variable
    NameValueDriver,
}

impl Keeper {
    /// NameValueDriver where edk2 may route the PASSWORD to a VARSTORE_NAME_VALUE
    /// (`name_value`), else Ifr.
    fn of(name_value: bool) -> Self {
        match name_value {
            true => Self::NameValueDriver,
            false => Self::Ifr,
        }
    }
}

/// A PASSWORD op whose VarStore is unknown.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum UnresolvedPassword {
    /// Its question header runs past its form package, so every variable of each VarStore of its
    /// package list is withheld
    #[error(
        "PASSWORD op without a question header in FormSet {}: {reason}",
        FormSetName(*.form_set)
    )]
    NoHeader {
        form_set: Option<Guid>,
        reason: String,
    },
    /// Its question header, past its op, names its bytes from VarOffset on in each VarStore of
    /// its VarStoreId, which are withheld
    #[error(
        "PASSWORD question {question_id:#06x} in FormSet {}: its op ends before its question \
         header, which edk2 reads from the bytes of the form package after it",
        FormSetName(*.form_set)
    )]
    HeaderPastOp {
        form_set: Option<Guid>,
        question_id: u16,
    },
    /// Its question header names its bytes from VarOffset on, which are withheld
    #[error(
        "PASSWORD question {question_id:#06x} without MaxSize in FormSet {}: {reason}",
        FormSetName(*.form_set)
    )]
    NoMaxSize {
        form_set: Option<Guid>,
        question_id: u16,
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
    #[error(
        "PASSWORD op of package list {package_list} outside a FormSet, at offset {offset} of a \
         form package, which no Forms Browser shows but edk2's Config Keyword Handler finds"
    )]
    OutsideFormSet { package_list: Guid, offset: u64 },
    #[error(
        "PASSWORD questions of package list {package_list} may name the VarStoreId of the op at \
         offset {offset} of a form package, {reason}"
    )]
    MalformedVarStoreOutsideFormSet {
        package_list: Guid,
        offset: u64,
        reason: String,
    },
    /// One outside a FormSet or in the scope of an unknown opcode (`place`)
    #[error(
        "PASSWORD question {question_id:#06x} in FormSet {}: a VARSTORE_NAME_VALUE {place}, at \
         offset {offset} of a form package, declares its VarStoreId, and only its driver holds \
         its values",
        FormSetName(*.form_set)
    )]
    NameValueOutsideFormSet {
        form_set: Option<Guid>,
        question_id: u16,
        offset: u64,
        place: OutsidePlace,
    },
    /// One outside a FormSet or in the scope of an unknown opcode (`place`)
    #[error(
        "PASSWORD question {question_id:#06x} in FormSet {}: an {} {place}, at offset {offset} \
         of a form package, declares its VarStoreId, and edk2 sends the Config Keyword Handler's \
         requests on such a VarStore to its driver",
        FormSetName(*.form_set),
        ShortVarStoreEfi::LABEL
    )]
    ShortVarStoreEfiOutsideFormSet {
        form_set: Option<Guid>,
        question_id: u16,
        offset: u64,
        place: OutsidePlace,
    },
    #[error(
        "PASSWORD questions of package list {package_list} may be in the IFR that uefisettings \
         ignores at offset {offset} of a form package, which has no op boundary, so in any \
         variable: {reason}"
    )]
    AnyVariable {
        package_list: Guid,
        offset: u64,
        reason: String,
    },
    #[error(
        "PASSWORD question {question_id:#06x} in FormSet {}: the first VarStore of its VarStoreId \
         in its form package, which edk2's Config Keyword Handler takes, is a \
         VARSTORE_NAME_VALUE of FormSet {}, and only its driver holds its values",
        FormSetName(*.form_set),
        FormSetName(*.declared_by)
    )]
    NameValueOfAnotherFormSet {
        form_set: Option<Guid>,
        question_id: u16,
        declared_by: Option<Guid>,
    },
    #[error(
        "PASSWORD question {question_id:#06x} in FormSet {}: the first VarStore of its VarStoreId \
         in its form package, which edk2's Config Keyword Handler takes, is an {} of FormSet {}, \
         and edk2 sends the Config Keyword Handler's requests on such a VarStore to its driver",
        FormSetName(*.form_set),
        ShortVarStoreEfi::LABEL,
        FormSetName(*.declared_by)
    )]
    ShortVarStoreEfiOfAnotherFormSet {
        form_set: Option<Guid>,
        question_id: u16,
        declared_by: Option<Guid>,
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
    named_records(.0)
)]
pub(crate) struct UnresolvedPasswords(Vec<UnresolvedPassword>);

/// The refusal, through variables of either reach, of a HiiDB with IFR past an op where the walk
/// for FormSets ends, or with a PASSWORD that edk2 may route to a VARSTORE_NAME_VALUE.
#[derive(Debug, Error)]
#[error(
    "{}; as a PASSWORD there may keep its password in any variable, uefisettings reads and \
     writes no variable of this HiiDB",
    named_records(.0)
)]
pub(crate) struct AnyVariablePasswords(Vec<UnresolvedPassword>);

/// Why PasswordQuestions reads and writes no variable of a HiiDB.
#[derive(Debug, Error)]
pub(crate) enum WithholdingRefusal {
    #[error(transparent)]
    BootServices(UnresolvedPasswords),
    #[error(transparent)]
    AnyVariable(AnyVariablePasswords),
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use super::super::conditions::CONSTANT_CONDITIONS;
    use super::super::find_corresponding_varstore;
    use super::super::ifr_fixtures::*;
    use super::super::QuestionFlags;
    use super::super::DECLARATIONS_READ;
    use super::super::EFI_IFR_TYPE_NUM_SIZE_8;
    use super::super::ROOT_INDICES_SHIFTED;
    use super::*;
    use crate::hii::package::hiidb_fixtures::en_strings_package_of;
    use crate::hii::package::hiidb_fixtures::form_package;
    use crate::hii::package::hiidb_fixtures::form_package_of;
    use crate::hii::package::hiidb_fixtures::package_list_with_guid;
    use crate::hii::package::hiidb_fixtures::strings_package_of;
    use crate::hii::package::hiidb_fixtures::END_PACKAGE;
    use crate::hii::package::read_db;
    use crate::hii::package::Guid;
    use crate::hii::variables::tests::WriteAt;
    use crate::hii::variables::UnreadVariables;
    use crate::hii::variables::VariableGuids;
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
            max_size: Some(20),
        }
    }

    /// Variables of `reach` that hold none.
    fn reaching(reach: VariableReach) -> MemoryVariables {
        let interface = match reach {
            VariableReach::BootServices => VariableInterface::VariableServices,
            VariableReach::Runtime => VariableInterface::Efivarfs,
        };
        MemoryVariables::new(reach, interface)
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
        parse_form_set(&form_set_ops(body))
    }

    /// The ops of form_set_of `body`.
    fn form_set_ops(body: &[Vec<u8>]) -> [Vec<u8>; 3] {
        [
            var_store_efi(1, "Setup", NV_BS_RT, 1),
            var_store(2, TSE_GUID, "AMITSESetup", 81),
            form(1, body),
        ]
    }

    /// The PasswordQuestions of form_set_of `body`, its form disabled or not.
    fn password_questions(body: &[Vec<u8>]) -> PasswordQuestions {
        let (root, disabled) = parse_form_set_dropping(&form_set_ops(body));
        PasswordQuestions::of_forms(std::slice::from_ref(&root), &disabled)
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
                    max_size: Some(4),
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
                    shared: vec![],
                    unresolved: vec![],
                    driver_held: vec![],
                    candidates: vec![],
                    storage: DeclaredStorage::default(),
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
                shared: vec![],
                unresolved: vec![],
                driver_held: vec![],
                candidates: vec![],
                storage: DeclaredStorage::default(),
            },
            "a password in the second FormSet"
        );
    }

    /// A PASSWORD op whose question header does not parse, or whose VarStoreId names no VarStore,
    /// leaves its variable unknown.
    #[test]
    fn password_without_a_known_var_store_is_unresolved() {
        assert_eq!(
            password_questions(&[password_on(2, 3, 9, 0)]),
            PasswordQuestions {
                declared: true,
                questions: vec![],
                shared: vec![],
                unresolved: vec![UnresolvedPassword::NoVarStore {
                    form_set: Some(FORM_SET_GUID),
                    question_id: 2,
                    reason: "no supported varstore with matching id 0x0009 found".to_string(),
                }],
                driver_held: vec![],
                candidates: vec![],
                storage: DeclaredStorage::default(),
            },
            "a password on VarStore 9"
        );

        let headless = password_questions(&[operation(PASSWORD, false, &[3, 0, 4, 0])]);
        assert!(headless.declared, "headless: declared");
        assert_eq!(headless.questions, vec![], "headless: questions");
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

    /// A PASSWORD op that ends after its question header and MinSize still names its VarStore
    /// and VarOffset: its question takes every byte of its variable from there on, which variables
    /// of either reach withhold, and it is unresolved, which fails closed through BootServices.
    #[test]
    fn a_password_without_max_size_withholds_its_variable_from_its_offset_on() {
        let data = [question_header_on(2, 3, 2, 10), 1u16.to_le_bytes().to_vec()].concat();
        let passwords = password_questions(&[operation(PASSWORD, false, &data)]);

        assert_eq!(
            passwords.questions,
            vec![PasswordQuestion {
                key: amitse_setup(),
                offset: 10,
                max_size: None,
            }],
            "questions"
        );
        assert_eq!(
            passwords
                .unresolved
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["PASSWORD question 0x0002 without MaxSize in FormSet \
              11111111-1111-1111-1111-111111111111: failed to fill whole buffer (While parsing \
              field 'max_size' in PasswordSizes)"],
            "unresolved"
        );
        let mut want = WithheldBytes::default();
        want.insert(amitse_setup(), 10..usize::MAX);
        assert_eq!(
            passwords
                .withheld(&reaching(VariableReach::Runtime))
                .map_err(|error| error.to_string()),
            Ok(want),
            "Runtime"
        );
        assert!(
            passwords
                .withheld(&reaching(VariableReach::BootServices))
                .is_err_and(|error| error
                    .to_string()
                    .starts_with("PASSWORD question 0x0002 without MaxSize in FormSet ")),
            "BootServices"
        );
    }

    /// A PASSWORD op whose question header does not parse gives its reason on one line: the
    /// fields being parsed, without the Rust source locations of binrw's backtrace frames. Here
    /// the header runs past the form package, after the 4 bytes of the Ends there.
    #[test]
    fn a_headless_password_gives_its_reason_on_one_line() {
        let headless = password_questions(&[operation(PASSWORD, false, &[3, 0, 4, 0])]);
        let [UnresolvedPassword::NoHeader { reason, .. }] = headless.unresolved.as_slice() else {
            panic!("headless: {:?}", headless.unresolved);
        };
        assert_eq!(
            reason,
            "failed to fill whole buffer (While parsing field 'var_store_info' in QuestionHeader)",
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
                passwords
                    .withheld(&reaching(reach))
                    .map_err(|error| error.to_string()),
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
                .withheld(&reaching(VariableReach::BootServices))
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
                .withheld(&reaching(VariableReach::Runtime))
                .map_err(|error| error.to_string()),
            Ok(known),
            "Runtime"
        );
    }

    /// set's VolatileWritingVariables, which write through write_patches, over the withholding
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

    /// A PASSWORD op on a VARSTORE_EFI of the form before UEFI 2.3.1 whose VarName no string
    /// holds is unresolved: through variables that reach BootServices, withheld fails.
    #[test]
    fn password_on_a_var_store_efi_before_uefi_2_3_1_is_unresolved() {
        let root = parse_form_set(&[short_var_store_efi(7), form(1, &[password_on(2, 3, 7, 0)])]);

        let passwords = PasswordQuestions::of([&root]);

        assert_eq!(
            passwords
                .withheld(&reaching(VariableReach::BootServices))
                .map_err(|error| error.to_string()),
            Err(
                "PASSWORD question 0x0002 in FormSet 11111111-1111-1111-1111-111111111111: \
                 VarStore 0x0007 (EFI_IFR_VARSTORE_EFI before UEFI 2.3.1): no string 0x0000 \
                 holds its VarName; as the variable of that password is unknown, the UEFI Shell \
                 build reads and writes no variable of this HiiDB"
                    .to_string()
            ),
            "BootServices"
        );
    }

    /// The PASSWORD on a VARSTORE_EFI of the form before UEFI 2.3.1 keeps its password alone in
    /// the EFI variable of its VarName, of the store's Guid (edk2-stable202608
    /// SetupBrowserDxe/Setup.c GetQuestionValue): its MaxSize CHAR16s from byte 0 are withheld
    /// through variables of either reach, all of them where its UINT16 StorageWidth in
    /// edk2-stable202608 SetupBrowserDxe/IfrParse.c holds fewer. Where no string holds its
    /// VarName, or the strings packages differ on it, it is unresolved: through variables that
    /// reach BootServices, withheld fails; through those that reach Runtime, it withholds them
    /// from byte 0 of each variable that the VarName may name, the "!" that Setup.c GetToken
    /// takes for a missing string, or each string.
    #[test]
    fn password_on_a_short_var_store_withholds_the_variable_of_its_var_name() {
        // Prompt 3, VarName 5
        let strings = ["Q", "Help", "Password", "Help", "ShortVarPw"];
        let mut french = strings;
        french[4] = "MotDePasse";
        let withheld_of = |names: &[&str], bytes: std::ops::Range<usize>| {
            let mut withheld = WithheldBytes::default();
            for name in names {
                withheld.insert(
                    VariableKey {
                        name: name.to_string(),
                        guid: Guid::from(SHORT_VAR_STORE_GUID),
                    },
                    bytes.clone(),
                );
            }
            withheld
        };
        let withheld = withheld_of(&["ShortVarPw"], 0..40);
        let unresolved = |reason: &str| -> Result<WithheldBytes, String> {
            Err(format!(
                "PASSWORD question 0x0002 in FormSet 11111111-1111-1111-1111-111111111111: \
                 VarStore 0x0007 (EFI_IFR_VARSTORE_EFI before UEFI 2.3.1): {reason}; as the \
                 variable of that password is unknown, the UEFI Shell build reads and writes no \
                 variable of this HiiDB"
            ))
        };
        let cases = [
            (
                "its VarName",
                password_with(2, 7, 5, QuestionFlags::empty(), 20),
                vec![en_strings_package_of(&strings)],
                Ok(withheld.clone()),
                Ok(withheld),
            ),
            (
                "no string",
                password_with(2, 7, 9, QuestionFlags::empty(), 20),
                vec![en_strings_package_of(&strings)],
                unresolved("no string 0x0009 holds its VarName"),
                Ok(withheld_of(&["!"], 0..40)),
            ),
            (
                "strings that differ",
                password_with(2, 7, 5, QuestionFlags::empty(), 20),
                vec![
                    strings_package_of(b"en", &strings),
                    strings_package_of(b"fr", &french),
                ],
                unresolved(
                    "the strings packages differ on its VarName 0x0005: \"ShortVarPw\" in en, \
                     \"MotDePasse\" in fr",
                ),
                Ok(withheld_of(&["ShortVarPw", "MotDePasse"], 0..40)),
            ),
            (
                "MaxSize 40000",
                password_with(2, 7, 5, QuestionFlags::empty(), 40_000),
                vec![en_strings_package_of(&strings)],
                Ok(withheld_of(&["ShortVarPw"], 0..80_000)),
                Ok(withheld_of(&["ShortVarPw"], 0..80_000)),
            ),
        ];
        for (case, password, strings, boot_services, runtime) in cases {
            let packages = [
                form_package(&[short_var_store_efi(7), form(1, &[password])]),
                strings.concat(),
                END_PACKAGE.to_vec(),
            ];
            let lists = read_db(&package_list_with_guid([0x55; 16], &packages.concat()))
                .unwrap_or_else(|error| panic!("{case}: read the HiiDB: {error:#}"));
            let passwords = PasswordQuestions::of_lists(&lists);

            assert_eq!(
                passwords
                    .withheld(&reaching(VariableReach::BootServices))
                    .map_err(|error| error.to_string()),
                boot_services,
                "{case}: BootServices"
            );
            assert_eq!(
                passwords
                    .withheld(&reaching(VariableReach::Runtime))
                    .map_err(|error| error.to_string()),
                runtime,
                "{case}: Runtime"
            );
        }
    }

    /// A PASSWORD on a VARSTORE_EFI of the form before UEFI 2.3.1 inside the scope of an op that
    /// edk2-stable202608 SetupBrowserDxe/IfrParse.c IsUnKnownOpCode skips, which
    /// PasswordQuestions visits, takes the variable of its VarName as one outside does.
    #[test]
    fn password_on_a_short_var_store_in_a_skipped_scope_withholds_its_variable() {
        // an op past EFI_IFR_MATCH2_OP
        const UNKNOWN: u8 = 0x70;
        let strings = ["Q", "Help", "Password", "Help", "ShortVarPw"];
        let skipped = [
            operation(UNKNOWN, true, &[]),
            password_with(2, 7, 5, QuestionFlags::empty(), 20),
            END.to_vec(),
        ]
        .concat();
        let packages = [
            form_package(&[short_var_store_efi(7), form(1, &[skipped])]),
            en_strings_package_of(&strings),
            END_PACKAGE.to_vec(),
        ];
        let lists = read_db(&package_list_with_guid([0x55; 16], &packages.concat()))
            .expect("read the HiiDB");
        let mut withheld = WithheldBytes::default();
        withheld.insert(
            VariableKey {
                name: "ShortVarPw".to_string(),
                guid: Guid::from(SHORT_VAR_STORE_GUID),
            },
            0..40,
        );

        assert_eq!(
            PasswordQuestions::of_lists(&lists)
                .withheld(&reaching(VariableReach::BootServices))
                .map_err(|error| error.to_string()),
            Ok(withheld),
            "BootServices"
        );
    }

    /// A PASSWORD on a VARSTORE_EFI of the form before UEFI 2.3.1 in a disabled form keeps its
    /// password in the variable of its VarName, as one in a live form does: its MaxSize CHAR16s
    /// from byte 0 are withheld through variables that reach Runtime, every byte where its op
    /// ends before MaxSize, which disables its form itself and leaves it unresolved, so that
    /// withheld through variables that reach BootServices fails.
    #[test]
    fn a_password_on_a_short_var_store_in_a_disabled_form_withholds_its_variable() {
        let strings = ["Q", "Help", "Password", "Help", "ShortVarPw"];
        // VarStore 7, VarName 5, then MinSize alone
        let without_max_size = [
            question_header_with(2, 3, 7, 5, 0),
            1u16.to_le_bytes().to_vec(),
        ]
        .concat();
        let cases = [
            (
                "a short CHECKBOX after it",
                [
                    password_with(2, 7, 5, QuestionFlags::empty(), 20),
                    operation(CHECKBOX, false, &[0x00; 4]),
                ]
                .concat(),
                0..40,
                true,
            ),
            (
                "without MaxSize",
                operation(PASSWORD, false, &without_max_size),
                0..usize::MAX,
                false,
            ),
        ];
        for (case, ops, bytes, resolved) in cases {
            let packages = [
                form_package(&[short_var_store_efi(7), form(1, &[ops])]),
                en_strings_package_of(&strings),
                END_PACKAGE.to_vec(),
            ];
            let lists = read_db(&package_list_with_guid([0x55; 16], &packages.concat()))
                .unwrap_or_else(|error| panic!("{case}: read the HiiDB: {error:#}"));
            assert_eq!(lists[0].disabled_forms.len(), 1, "{case}: disabled forms");
            let passwords = PasswordQuestions::of_lists(&lists);
            let mut want = WithheldBytes::default();
            want.insert(
                VariableKey {
                    name: "ShortVarPw".to_string(),
                    guid: Guid::from(SHORT_VAR_STORE_GUID),
                },
                bytes,
            );

            assert_eq!(
                passwords
                    .withheld(&reaching(VariableReach::Runtime))
                    .map_err(|error| error.to_string()),
                Ok(want),
                "{case}: Runtime"
            );
            let got = passwords.withheld(&reaching(VariableReach::BootServices));
            assert_eq!(got.is_ok(), resolved, "{case}: BootServices: {got:?}");
        }
    }

    /// set through variables that reach BootServices bypasses the setup password of a HiiDB that
    /// declares a password question; set through variables that reach Runtime, and set in a
    /// HiiDB without one, bypass none.
    #[test]
    fn boot_services_bypass_a_declared_password() {
        let declared = password_questions(&[password_on(2, 3, 0, 0)]);
        let undeclared = password_questions(&[checkbox_on(1, 3, 1)]);
        let cases = [
            (
                &declared,
                VariableReach::BootServices,
                Some(UnsafeOperation::SetupPassword),
            ),
            (&declared, VariableReach::Runtime, None),
            (&undeclared, VariableReach::BootServices, None),
            (&undeclared, VariableReach::Runtime, None),
        ];
        for (passwords, reach, want) in cases {
            assert_eq!(
                passwords.setup_password_bypass(reach),
                want,
                "{reach:?}, declared: {}",
                passwords.declared
            );
        }
    }

    /// The package list that read_db reads from a HiiDB of one list whose form package holds
    /// `ifr`, FormSets and ops outside them.
    fn list_of(ifr: &[Vec<u8>]) -> ParsedPackageList {
        let hiidb = package_list_with_guid(
            [0x22; 16],
            &[form_package_of(&ifr.concat()), END_PACKAGE.to_vec()].concat(),
        );
        read_db(&hiidb).expect("read_db").remove(0)
    }

    /// A FormSet whose form holds `body`, with the VarStores of form_set_of.
    fn form_set_with(body: &[Vec<u8>]) -> Vec<u8> {
        form_set(&[
            var_store_efi(1, "Setup", NV_BS_RT, 1),
            var_store(2, TSE_GUID, "AMITSESetup", 81),
            form(1, body),
        ])
    }

    /// The variable of the VarStore Shadow of these tests, which they declare outside a FormSet.
    fn shadow() -> VariableKey {
        VariableKey {
            name: "Shadow".to_string(),
            guid: Guid::from(OTHER_GUID),
        }
    }

    /// The PasswordQuestions of the HiiDB of list_of `ifr`.
    fn passwords_of(ifr: &[Vec<u8>]) -> PasswordQuestions {
        PasswordQuestions::of_lists(&[list_of(ifr)])
    }

    /// The bytes that `ifr` withholds through variables of `reach`, or the refusal.
    fn withheld_of(ifr: &[Vec<u8>], reach: VariableReach) -> Result<WithheldBytes, String> {
        passwords_of(ifr)
            .withheld(&reaching(reach))
            .map_err(|error| error.to_string())
    }

    /// A PASSWORD outside any FormSet, which no Forms Browser shows but edk2's Config Keyword
    /// Handler finds (FindQuestionFromStringId walks the whole form package), names a password
    /// in a variable that no FormSet tells: the HiiDB declares a password, and through variables
    /// that reach BootServices its variables fail closed, also for a PASSWORD whose question
    /// header does not parse.
    #[test]
    fn a_password_outside_a_form_set_fails_closed() {
        let headless = operation(PASSWORD, false, &[3, 0, 4, 0]);
        for (case, ifr) in [
            (
                "before the FormSet",
                vec![
                    password_on(9, 3, 2, 0),
                    form_set_with(&[checkbox_on(1, 3, 2)]),
                ],
            ),
            (
                "after the FormSet",
                vec![
                    form_set_with(&[checkbox_on(1, 3, 2)]),
                    password_on(9, 3, 2, 0),
                ],
            ),
            (
                "headless",
                vec![headless, form_set_with(&[checkbox_on(1, 3, 2)])],
            ),
        ] {
            let passwords = passwords_of(&ifr);
            assert!(passwords.declared, "{case}: declared");
            assert!(
                matches!(
                    passwords.unresolved.as_slice(),
                    [UnresolvedPassword::OutsideFormSet { .. }]
                ),
                "{case}: {:?}",
                passwords.unresolved
            );
            assert!(
                passwords
                    .withheld(&reaching(VariableReach::BootServices))
                    .is_err(),
                "{case}: withheld through BootServices"
            );
            assert!(
                passwords
                    .setup_password_bypass(VariableReach::BootServices)
                    .is_some(),
                "{case}: set through BootServices"
            );
        }
    }

    /// Through variables that reach Runtime, which tolerate an unresolved PASSWORD, a PASSWORD
    /// outside any FormSet keeps its password at its VarOffset in MaxSize CHAR16s of every
    /// VARSTORE and VARSTORE_EFI of its VarStoreId, in a FormSet or not, as edk2-stable202608
    /// FindStorageFromVarId (ConfigKeywordHandler.c:1520) takes the first in the form package.
    #[test]
    fn a_password_outside_a_form_set_is_withheld_in_each_var_store_of_its_id() {
        let ifr = [
            var_store(7, OTHER_GUID, "Other", 81),
            password_on(9, 3, 2, 40),
            var_store(2, OTHER_GUID, "Shadow", 81),
            form_set_with(&[checkbox_on(1, 3, 1)]),
        ];
        let mut want = WithheldBytes::default();
        want.insert(amitse_setup(), 40..80);
        want.insert(shadow(), 40..80);

        assert_eq!(withheld_of(&ifr, VariableReach::Runtime), Ok(want));
    }

    /// A PASSWORD outside any FormSet of VarStoreId 0 names no variable, as one in a FormSet does
    /// not, and edk2-stable202608 ExtractConfigRequest skips it (ConfigKeywordHandler.c:2104): it
    /// only declares a password, so set refuses through variables that reach BootServices, which
    /// read the variables of the HiiDB.
    #[test]
    fn a_password_outside_a_form_set_without_a_var_store_only_declares_a_password() {
        let passwords = passwords_of(&[
            password_on(9, 3, 0, 0),
            form_set_with(&[checkbox_on(1, 3, 2)]),
        ]);

        assert_eq!(
            passwords,
            PasswordQuestions {
                declared: true,
                questions: vec![],
                shared: vec![],
                unresolved: vec![],
                driver_held: vec![],
                candidates: vec![],
                storage: DeclaredStorage::default(),
            }
        );
        assert!(
            passwords
                .setup_password_bypass(VariableReach::BootServices)
                .is_some(),
            "set through BootServices"
        );
    }

    /// A VarStore outside any FormSet of the VarStoreId of a PASSWORD in a FormSet keeps that
    /// password at the same VarOffset in MaxSize CHAR16s, in either reach: edk2-stable202608
    /// FindStorageFromVarId (ConfigKeywordHandler.c:1520) takes the first VarStore of the id in
    /// the form package, FormSet or not, and other firmware may take another.
    #[test]
    fn an_outside_var_store_of_a_password_s_id_is_withheld_too() {
        let password = form_set_with(&[password_on(2, 3, 2, 0)]);
        let outside = var_store(2, OTHER_GUID, "Shadow", 81);
        let mut want = WithheldBytes::default();
        want.insert(amitse_setup(), 0..40);
        want.insert(shadow(), 0..40);
        for (case, ifr) in [
            (
                "before the FormSet",
                vec![outside.clone(), password.clone()],
            ),
            ("after the FormSet", vec![password, outside]),
        ] {
            for reach in [VariableReach::BootServices, VariableReach::Runtime] {
                assert_eq!(
                    withheld_of(&ifr, reach),
                    Ok(want.clone()),
                    "{case}: {reach:?}"
                );
            }
        }
    }

    /// Asserts that the VarStore ops `outside`, outside any FormSet, before a FormSet with a
    /// PASSWORD of its VarStoreId 2 and VarStoreInfo 0, leaves that password `unresolved`, naming
    /// no variable that withholding could name: through variables that reach BootServices, fail
    /// closed; through those that reach Runtime, the password's bytes in its FormSet's VarStore,
    /// AMITSESetup 0..40, stay withheld, as do bytes 0..40 of the variables `candidates` that its
    /// VarName may name on a VARSTORE_EFI before UEFI 2.3.1 of `outside`, unless `keeper` is the
    /// driver of a VARSTORE_NAME_VALUE, who may keep it in any variable: then those refuse too.
    fn assert_fails_closed_keeping_the_form_set_s_bytes(
        outside: Vec<u8>,
        unresolved: UnresolvedPassword,
        candidates: &[VariableKey],
        keeper: Keeper,
    ) {
        let passwords = passwords_of(&[outside, form_set_with(&[password_on(2, 3, 2, 0)])]);
        let mut known = WithheldBytes::default();
        known.insert(amitse_setup(), 0..40);
        for candidate in candidates {
            known.insert(candidate.clone(), 0..40);
        }
        let (driver_held, runtime) = match keeper {
            Keeper::Ifr => (vec![], Ok(known)),
            Keeper::NameValueDriver => (
                vec![unresolved.clone()],
                Err(format!("{unresolved}{ANY_VARIABLE}")),
            ),
        };

        assert_eq!(passwords.unresolved, [unresolved], "unresolved");
        assert_eq!(passwords.driver_held, driver_held, "driver-held");
        assert!(
            passwords
                .withheld(&reaching(VariableReach::BootServices))
                .is_err(),
            "withheld through BootServices"
        );
        assert_eq!(
            passwords
                .withheld(&reaching(VariableReach::Runtime))
                .map_err(|error| error.to_string()),
            runtime,
            "withheld through Runtime"
        );
    }

    /// The end of the refusal of a HiiDB whose PASSWORDs may be in any variable
    /// (AnyVariablePasswords).
    const ANY_VARIABLE: &str = "; as a PASSWORD there may keep its password in any variable, \
                                uefisettings reads and writes no variable of this HiiDB";

    /// A VARSTORE_NAME_VALUE outside any FormSet of the VarStoreId of a PASSWORD, whose values
    /// only its driver holds, names no variable, so any may hold the password.
    #[test]
    fn an_outside_name_value_var_store_of_a_password_s_id_fails_closed() {
        assert_fails_closed_keeping_the_form_set_s_bytes(
            var_store_name_value(2, OTHER_GUID),
            UnresolvedPassword::NameValueOutsideFormSet {
                form_set: Some(FORM_SET_GUID),
                question_id: 2,
                offset: 0,
                place: OutsidePlace::NoFormSet,
            },
            &[],
            Keeper::NameValueDriver,
        );
    }

    /// A VARSTORE_EFI before UEFI 2.3.1 outside any FormSet of the VarStoreId of a PASSWORD names
    /// no variable: edk2-stable202608 ConfigRouting.c GetVarStoreType (:1902) takes no such
    /// VarStore for an EFI variable one, so ExtractConfig and RouteConfig send its requests to the
    /// driver. The variable of the PASSWORD's VarName, string 0, which no strings package holds,
    /// is "!" of the store's Guid (ShortVarStoreEfi::candidate_variables).
    #[test]
    fn an_outside_short_var_store_efi_of_a_password_s_id_fails_closed() {
        assert_fails_closed_keeping_the_form_set_s_bytes(
            short_var_store_efi(2),
            UnresolvedPassword::ShortVarStoreEfiOutsideFormSet {
                form_set: Some(FORM_SET_GUID),
                question_id: 2,
                offset: 0,
                place: OutsidePlace::NoFormSet,
            },
            &[short_variable("!")],
            Keeper::Ifr,
        );
    }

    /// Of the VarStores outside any FormSet of the VarStoreId of a PASSWORD that name no variable,
    /// the first gives the reason, and the VARSTORE_NAME_VALUE's driver may keep the password.
    #[test]
    fn the_first_outside_var_store_that_names_no_variable_gives_the_reason() {
        assert_fails_closed_keeping_the_form_set_s_bytes(
            [var_store_name_value(2, OTHER_GUID), short_var_store_efi(2)].concat(),
            UnresolvedPassword::NameValueOutsideFormSet {
                form_set: Some(FORM_SET_GUID),
                question_id: 2,
                offset: 0,
                place: OutsidePlace::NoFormSet,
            },
            &[short_variable("!")],
            Keeper::NameValueDriver,
        );
    }

    /// The variable `name` of a VARSTORE_EFI before UEFI 2.3.1 of short_var_store_efi.
    fn short_variable(name: &str) -> VariableKey {
        VariableKey {
            name: name.to_string(),
            guid: Guid::from(SHORT_VAR_STORE_GUID),
        }
    }

    /// The en-US strings of the tests of VarNames: string 5 is "ShortVarPw".
    const VAR_NAME_STRINGS: [&str; 5] = ["Q", "Help", "Password", "Help", "ShortVarPw"];

    /// list_of with an en-US strings package of `strings`.
    fn list_with_strings(ifr: &[Vec<u8>], strings: &[&str]) -> ParsedPackageList {
        let packages = [
            form_package_of(&ifr.concat()),
            en_strings_package_of(strings),
            END_PACKAGE.to_vec(),
        ];
        read_db(&package_list_with_guid([0x22; 16], &packages.concat()))
            .expect("read_db")
            .remove(0)
    }

    /// A PASSWORD outside any FormSet whose VarStoreId names a VARSTORE_EFI before UEFI 2.3.1, in
    /// a FormSet or outside any, stays unresolved: edk2-stable202608 ConfigRouting.c
    /// GetVarStoreType (:1902) takes no such VarStore for an EFI variable one, so the requests of
    /// the Config Keyword Handler on it go to the driver, and no variable is known to hold its
    /// password. Through variables that reach BootServices, fail closed; through those that reach
    /// Runtime, bytes 0..40 of the variable that its VarStoreInfo names as a VarName, string 5,
    /// ShortVarPw of the store's Guid, are withheld, which a question of that VarName reads.
    #[test]
    fn a_password_outside_a_form_set_on_the_id_of_a_short_var_store_withholds_its_var_name() {
        let password = password_on(9, 3, 7, 5);
        let mut runtime = WithheldBytes::default();
        runtime.insert(short_variable("ShortVarPw"), 0..40);
        for (case, ifr) in [
            (
                "a VARSTORE_EFI before UEFI 2.3.1 in a FormSet",
                vec![
                    password.clone(),
                    form_set(&[short_var_store_efi(7), form(1, &[checkbox_at(1, 3, 7, 5)])]),
                ],
            ),
            (
                "a VARSTORE_EFI before UEFI 2.3.1 outside any FormSet",
                vec![short_var_store_efi(7), password, form_set_with(&[])],
            ),
        ] {
            let passwords =
                PasswordQuestions::of_lists(&[list_with_strings(&ifr, &VAR_NAME_STRINGS)]);

            assert!(
                matches!(
                    passwords.unresolved.as_slice(),
                    [UnresolvedPassword::OutsideFormSet { .. }]
                ),
                "{case}: {:?}",
                passwords.unresolved
            );
            assert!(
                passwords
                    .withheld(&reaching(VariableReach::BootServices))
                    .is_err(),
                "{case}: BootServices"
            );
            assert_eq!(
                passwords
                    .withheld(&reaching(VariableReach::Runtime))
                    .map_err(|error| error.to_string()),
                Ok(runtime.clone()),
                "{case}: Runtime"
            );
        }
    }

    /// A PASSWORD on its FormSet's VARSTORE_EFI before UEFI 2.3.1 keeps its password from byte 0
    /// of the variable that its VarStoreInfo, string 5, names as a VarName, ShortVarPw, as
    /// edk2-stable202608 SetupBrowserDxe/Setup.c GetQuestionValue reads it, and at that
    /// VarOffset, 5, in Shadow, the variable of a VARSTORE of its VarStoreId outside any FormSet,
    /// which FindStorageFromVarId may take first: both are withheld, through variables of either
    /// reach.
    #[test]
    fn a_password_on_a_short_var_store_is_withheld_at_its_var_offset_outside_too() {
        let ifr = [
            var_store(7, OTHER_GUID, "Shadow", 81),
            form_set(&[short_var_store_efi(7), form(1, &[password_on(2, 3, 7, 5)])]),
        ];
        let passwords = PasswordQuestions::of_lists(&[list_with_strings(&ifr, &VAR_NAME_STRINGS)]);
        let mut want = WithheldBytes::default();
        want.insert(short_variable("ShortVarPw"), 0..40);
        want.insert(shadow(), 5..45);

        for reach in [VariableReach::BootServices, VariableReach::Runtime] {
            assert_eq!(
                passwords
                    .withheld(&reaching(reach))
                    .map_err(|error| error.to_string()),
                Ok(want.clone()),
                "{reach:?}"
            );
        }
    }

    /// A VARSTORE_EFI before UEFI 2.3.1 outside any FormSet of the VarStoreId of a PASSWORD in a
    /// FormSet leaves it unresolved, as an_outside_short_var_store_efi_of_a_password_s_id_fails_
    /// closed tells, and through variables that reach Runtime withholds bytes 0..40 of the
    /// variable that its VarStoreInfo names as a VarName, string 5, ShortVarPw of the store's Guid,
    /// besides bytes 5..45, at that VarOffset, of its FormSet's AMITSESetup.
    #[test]
    fn an_outside_short_var_store_efi_of_a_password_s_id_withholds_its_var_name() {
        let ifr = [
            short_var_store_efi(2),
            form_set_with(&[password_on(2, 3, 2, 5)]),
        ];
        let passwords = PasswordQuestions::of_lists(&[list_with_strings(&ifr, &VAR_NAME_STRINGS)]);
        let mut runtime = WithheldBytes::default();
        runtime.insert(amitse_setup(), 5..45);
        runtime.insert(short_variable("ShortVarPw"), 0..40);

        assert_eq!(
            passwords.unresolved,
            [UnresolvedPassword::ShortVarStoreEfiOutsideFormSet {
                form_set: Some(FORM_SET_GUID),
                question_id: 2,
                offset: 0,
                place: OutsidePlace::NoFormSet,
            }],
            "unresolved"
        );
        assert!(
            passwords
                .withheld(&reaching(VariableReach::BootServices))
                .is_err(),
            "BootServices"
        );
        assert_eq!(
            passwords
                .withheld(&reaching(VariableReach::Runtime))
                .map_err(|error| error.to_string()),
            Ok(runtime),
            "Runtime"
        );
    }

    /// The Guid, as stored, of the FormSet that declares the first VarStore of a VarStoreId in the
    /// tests of first declarations.
    const FIRST_FORM_SET: [u8; 16] = [0x12; 16];

    /// A FormSet of Guid FIRST_FORM_SET that declares `store`, with an empty form.
    fn first_form_set(store: Vec<u8>) -> Vec<u8> {
        form_set_with_guid(FIRST_FORM_SET, &[store, form(1, &[])])
    }

    /// The variable `name` of OTHER_GUID.
    fn other_variable(name: &str) -> VariableKey {
        VariableKey {
            name: name.to_string(),
            guid: Guid::from(OTHER_GUID),
        }
    }

    /// A VARSTORE that a FormSet declares for the VarStoreId of a PASSWORD of a later FormSet, the
    /// first VarStore of that id in their form package, keeps that password at its VarOffset in
    /// MaxSize CHAR16s: edk2-stable202608 ConfigKeywordHandler.c FindStorageFromVarId (:1520) takes
    /// it for a keyword request of the PASSWORD (GetWidth :1640). It is withheld with the
    /// PASSWORD's own VarStore, through variables of either reach and from a ConfigSnapshot;
    /// Third, a later VarStore of the id, is not.
    #[test]
    fn the_first_var_store_of_a_password_s_id_in_another_form_set_is_withheld_too() {
        let ifr = [
            first_form_set(var_store(2, OTHER_GUID, "Shadow", 81)),
            form_set_with(&[password_on(2, 3, 2, 5)]),
            form_set_with_guid(
                [0x13; 16],
                &[var_store(2, OTHER_GUID, "Third", 81), form(1, &[])],
            ),
        ];
        let mut want = WithheldBytes::default();
        want.insert(amitse_setup(), 5..45);
        want.insert(shadow(), 5..45);

        for reach in [VariableReach::BootServices, VariableReach::Runtime] {
            assert_eq!(withheld_of(&ifr, reach), Ok(want.clone()), "{reach:?}");
        }
        assert_eq!(
            passwords_of(&ifr).withheld_from_snapshot(),
            Ok(want),
            "ConfigSnapshot"
        );
    }

    /// Where another FormSet's first VarStore of a PASSWORD's VarStoreId names the variable of
    /// the PASSWORD's own VarStore, AMITSESetup, which holds the password at that VarOffset
    /// already, its bytes there are withheld once.
    #[test]
    fn a_first_var_store_of_the_password_s_own_variable_withholds_its_bytes_once() {
        let ifr = [
            first_form_set(var_store(2, TSE_GUID, "AMITSESetup", 81)),
            form_set_with(&[password_on(2, 3, 2, 5)]),
        ];
        let mut want = WithheldBytes::default();
        want.insert(amitse_setup(), 5..45);

        for reach in [VariableReach::BootServices, VariableReach::Runtime] {
            assert_eq!(withheld_of(&ifr, reach), Ok(want.clone()), "{reach:?}");
        }
    }

    /// The first VarStore of a VarStoreId in a form package is the first in IFR order, which a
    /// form of its FormSet may hold before the VarStores among the FormSet's children: Shadow,
    /// not Third, keeps the password of a later FormSet's PASSWORD of that id.
    #[test]
    fn the_first_var_store_of_a_password_s_id_is_the_first_in_ifr_order() {
        let ifr = [
            form_set_with_guid(
                FIRST_FORM_SET,
                &[
                    form(1, &[var_store(2, OTHER_GUID, "Shadow", 81)]),
                    var_store(2, OTHER_GUID, "Third", 81),
                ],
            ),
            form_set_with(&[password_on(2, 3, 2, 5)]),
        ];
        let mut want = WithheldBytes::default();
        want.insert(amitse_setup(), 5..45);
        want.insert(shadow(), 5..45);

        for reach in [VariableReach::BootServices, VariableReach::Runtime] {
            assert_eq!(withheld_of(&ifr, reach), Ok(want.clone()), "{reach:?}");
        }
    }

    /// Where the PASSWORD's own FormSet declares the first VarStore of its VarStoreId, or a
    /// VarStore outside any FormSet does, which an_outside_var_store_of_a_password_s_id_is_
    /// withheld_too withholds, a later FormSet's VarStore of that id, Third, holds none of its
    /// password.
    #[test]
    fn a_later_form_set_s_var_store_of_a_password_s_id_is_not_withheld() {
        let third = first_form_set(var_store(2, OTHER_GUID, "Third", 81));
        let password = form_set_with(&[password_on(2, 3, 2, 5)]);
        let mut own = WithheldBytes::default();
        own.insert(amitse_setup(), 5..45);
        let mut outside = own.clone();
        outside.insert(shadow(), 5..45);
        for (case, ifr, want) in [
            ("its own first", vec![password.clone(), third.clone()], own),
            (
                "one outside any FormSet first",
                vec![var_store(2, OTHER_GUID, "Shadow", 81), third, password],
                outside,
            ),
        ] {
            for reach in [VariableReach::BootServices, VariableReach::Runtime] {
                assert_eq!(
                    withheld_of(&ifr, reach),
                    Ok(want.clone()),
                    "{case}: {reach:?}"
                );
            }
        }
    }

    /// A PASSWORD whose FormSet declares no VarStore of its VarStoreId stays unresolved, as
    /// a_password_naming_only_an_outside_var_store_stays_unresolved tells; where a later FormSet
    /// declares the first VarStore of that id in their form package, Shadow, which the Keyword
    /// Handler takes, the password's bytes there are withheld through variables that reach
    /// Runtime.
    #[test]
    fn a_password_without_its_form_set_s_var_store_is_withheld_in_a_later_first_one() {
        let passwords = passwords_of(&[
            form_set_with(&[password_on(2, 3, 7, 5)]),
            first_form_set(var_store(7, OTHER_GUID, "Shadow", 81)),
        ]);
        let mut runtime = WithheldBytes::default();
        runtime.insert(shadow(), 5..45);

        assert!(
            matches!(
                passwords.unresolved.as_slice(),
                [UnresolvedPassword::NoVarStore { question_id: 2, .. }]
            ),
            "{:?}",
            passwords.unresolved
        );
        assert!(
            passwords
                .withheld(&reaching(VariableReach::BootServices))
                .is_err(),
            "BootServices"
        );
        assert_eq!(
            passwords
                .withheld(&reaching(VariableReach::Runtime))
                .map_err(|error| error.to_string()),
            Ok(runtime),
            "Runtime"
        );
    }

    /// A PASSWORD on its FormSet's VARSTORE_EFI before UEFI 2.3.1, the first VarStore of its
    /// VarStoreId in its form package, keeps its password from byte 0 of the variable of its
    /// VarName, ShortVarPw, alone, as password_on_a_short_var_store_withholds_the_variable_of_its_
    /// var_name tells: its own FormSet's first VarStore leaves it resolved, and Shadow, a later
    /// FormSet's VarStore of the id, holds none of it.
    #[test]
    fn a_password_on_its_form_set_s_first_short_var_store_stays_resolved() {
        let ifr = [
            form_set(&[short_var_store_efi(2), form(1, &[password_on(2, 3, 2, 5)])]),
            first_form_set(var_store(2, OTHER_GUID, "Shadow", 81)),
        ];
        let passwords = PasswordQuestions::of_lists(&[list_with_strings(&ifr, &VAR_NAME_STRINGS)]);
        let mut want = WithheldBytes::default();
        want.insert(short_variable("ShortVarPw"), 0..40);

        assert!(
            passwords.unresolved.is_empty(),
            "unresolved: {:?}",
            passwords.unresolved
        );
        for reach in [VariableReach::BootServices, VariableReach::Runtime] {
            assert_eq!(
                passwords
                    .withheld(&reaching(reach))
                    .map_err(|error| error.to_string()),
                Ok(want.clone()),
                "{reach:?}"
            );
        }
    }

    /// Asserts that `first`, which a FormSet before that of a PASSWORD of VarStoreId 2 and
    /// VarStoreInfo 5 declares, the first VarStore of that id in their form package, names no
    /// variable and leaves the password unresolved for the reason `reason`: through variables
    /// that reach BootServices, fail closed; through those that reach Runtime, the password's
    /// bytes in its FormSet's AMITSESetup, 5..45, stay withheld, as do bytes 0..40 of the
    /// variables `candidates` that its VarName, string 5, ShortVarPw, may name on `first`, unless
    /// `keeper` is the driver of a VARSTORE_NAME_VALUE, who may keep it in any variable: then
    /// those refuse too.
    fn assert_first_var_store_fails_closed(
        first: Vec<u8>,
        reason: &str,
        candidates: &[VariableKey],
        keeper: Keeper,
    ) {
        let ifr = [
            first_form_set(first),
            form_set_with(&[password_on(2, 3, 2, 5)]),
        ];
        let passwords = PasswordQuestions::of_lists(&[list_with_strings(&ifr, &VAR_NAME_STRINGS)]);
        let mut runtime = WithheldBytes::default();
        runtime.insert(amitse_setup(), 5..45);
        for candidate in candidates {
            runtime.insert(candidate.clone(), 0..40);
        }
        let reasons: Vec<String> = passwords
            .unresolved
            .iter()
            .map(ToString::to_string)
            .collect();
        let (driver_held, runtime) = match keeper {
            Keeper::Ifr => (0, Ok(runtime)),
            Keeper::NameValueDriver => (1, Err(format!("{reason}{ANY_VARIABLE}"))),
        };

        assert_eq!(reasons, [reason], "unresolved");
        assert_eq!(passwords.driver_held.len(), driver_held, "driver-held");
        assert!(
            passwords
                .withheld(&reaching(VariableReach::BootServices))
                .is_err(),
            "BootServices"
        );
        assert_eq!(
            passwords
                .withheld(&reaching(VariableReach::Runtime))
                .map_err(|error| error.to_string()),
            runtime,
            "Runtime"
        );
    }

    /// A VARSTORE_NAME_VALUE of another FormSet, the first VarStore of a PASSWORD's VarStoreId in
    /// its form package, which the Keyword Handler takes, names no variable: only its driver
    /// holds its values, in any variable.
    #[test]
    fn a_first_name_value_var_store_in_another_form_set_fails_closed() {
        assert_first_var_store_fails_closed(
            var_store_name_value(2, OTHER_GUID),
            &format!(
                "PASSWORD question 0x0002 in FormSet {FORM_SET_GUID}: the first VarStore of its \
                 VarStoreId in its form package, which edk2's Config Keyword Handler takes, is a \
                 VARSTORE_NAME_VALUE of FormSet {}, and only its driver holds its values",
                Guid::from(FIRST_FORM_SET)
            ),
            &[],
            Keeper::NameValueDriver,
        );
    }

    /// A VARSTORE_EFI before UEFI 2.3.1 of another FormSet, the first VarStore of a PASSWORD's
    /// VarStoreId in its form package, names no variable: edk2-stable202608 ConfigRouting.c
    /// GetVarStoreType (:1902) takes no such VarStore for an EFI variable one, so the Keyword
    /// Handler's requests on it go to the driver. Through variables that reach Runtime, the
    /// variable that the PASSWORD's VarStoreInfo names as a VarName on it is withheld too.
    #[test]
    fn a_first_short_var_store_efi_in_another_form_set_fails_closed() {
        assert_first_var_store_fails_closed(
            short_var_store_efi(2),
            &format!(
                "PASSWORD question 0x0002 in FormSet {FORM_SET_GUID}: the first VarStore of its \
                 VarStoreId in its form package, which edk2's Config Keyword Handler takes, is an \
                 EFI_IFR_VARSTORE_EFI before UEFI 2.3.1 of FormSet {}, and edk2 sends the Config \
                 Keyword Handler's requests on such a VarStore to its driver",
                Guid::from(FIRST_FORM_SET)
            ),
            &[short_variable("ShortVarPw")],
            Keeper::Ifr,
        );
    }

    /// The package list that read_db reads from a HiiDB of one list with a form package for each
    /// of `packages`, which holds its IFR, in order.
    fn list_of_packages(packages: &[Vec<Vec<u8>>]) -> ParsedPackageList {
        let forms: Vec<u8> = packages
            .iter()
            .flat_map(|ifr| form_package_of(&ifr.concat()))
            .collect();
        let hiidb = package_list_with_guid([0x22; 16], &[forms, END_PACKAGE.to_vec()].concat());
        read_db(&hiidb).expect("read_db").remove(0)
    }

    /// FindStorageFromVarId walks the form package of the question: in a package list of two form
    /// packages, Second, which the first FormSet of the second declares for VarStoreId 2, keeps
    /// the password of the PASSWORD of id 2 of that package's later FormSet, and First, which the
    /// first package declares, holds none of it.
    #[test]
    fn the_first_var_store_of_a_password_s_id_is_that_of_its_form_package() {
        let list = list_of_packages(&[
            vec![first_form_set(var_store(2, OTHER_GUID, "First", 81))],
            vec![
                first_form_set(var_store(2, OTHER_GUID, "Second", 81)),
                form_set_with(&[password_on(2, 3, 2, 5)]),
            ],
        ]);
        let mut want = WithheldBytes::default();
        want.insert(amitse_setup(), 5..45);
        want.insert(other_variable("Second"), 5..45);

        for reach in [VariableReach::BootServices, VariableReach::Runtime] {
            assert_eq!(
                PasswordQuestions::of_lists(std::slice::from_ref(&list))
                    .withheld(&reaching(reach))
                    .map_err(|error| error.to_string()),
                Ok(want.clone()),
                "{reach:?}"
            );
        }
    }

    /// Where the PASSWORD's form package declares the first VarStore of its VarStoreId outside
    /// any FormSet, Shadow, an earlier package's FormSet's First holds none of its password: its
    /// own AMITSESetup and Shadow do, through variables of either reach.
    #[test]
    fn a_package_whose_first_var_store_is_outside_takes_no_earlier_package_s() {
        let list = list_of_packages(&[
            vec![first_form_set(var_store(2, OTHER_GUID, "First", 81))],
            vec![
                var_store(2, OTHER_GUID, "Shadow", 81),
                form_set_with(&[password_on(2, 3, 2, 5)]),
            ],
        ]);
        let mut want = WithheldBytes::default();
        want.insert(amitse_setup(), 5..45);
        want.insert(shadow(), 5..45);

        for reach in [VariableReach::BootServices, VariableReach::Runtime] {
            assert_eq!(
                PasswordQuestions::of_lists(std::slice::from_ref(&list))
                    .withheld(&reaching(reach))
                    .map_err(|error| error.to_string()),
                Ok(want.clone()),
                "{reach:?}"
            );
        }
    }

    /// The GUID of the FormSet that declares the first VarStore of `var_store_id` in the first
    /// form package of `list`, as read_db records it.
    fn first_store_form_set(list: &ParsedPackageList, var_store_id: u16) -> Option<Guid> {
        let first = list
            .first_var_stores
            .first()?
            .declared_by
            .get(&var_store_id)?;
        form_set_guid(&first.form_set.borrow())
    }

    /// read_db records, for each form package, its FormSets by index in the list's forms, which its
    /// disabled forms name by the index of their roots, and the first VarStore of each
    /// VarStoreId that a FormSet declares, with that FormSet, in IFR order, ops outside any FormSet
    /// and disabled forms included: in the first package, a VarStore outside any FormSet declares
    /// VarStoreId 3 first, and VarStoreId 5 only follows the FormSets; in the second, the form that
    /// a short NUMERIC disables declares 6 before its FormSet declares 6 and 7 among its children.
    #[test]
    fn read_db_records_the_first_var_stores_of_each_form_package() {
        let list = list_of_packages(&[
            vec![
                var_store(3, OTHER_GUID, "S3", 1),
                form_set(&[
                    var_store(2, OTHER_GUID, "S2", 1),
                    var_store(3, OTHER_GUID, "T3", 1),
                ]),
                form_set(&[
                    var_store(2, OTHER_GUID, "T2", 1),
                    var_store(4, OTHER_GUID, "S4", 1),
                ]),
                var_store(5, OTHER_GUID, "S5", 1),
            ],
            vec![form_set(&[
                form(
                    1,
                    &[
                        var_store(6, OTHER_GUID, "S6", 1),
                        operation(NUMERIC, false, &[1, 2]),
                    ],
                ),
                var_store(6, OTHER_GUID, "T6", 1),
                var_store(7, OTHER_GUID, "S7", 1),
            ])],
        ]);
        let recorded: Vec<_> = list
            .first_var_stores
            .iter()
            .map(|package| {
                let declared_by: BTreeMap<u16, (String, Option<usize>)> = package
                    .declared_by
                    .iter()
                    .map(|(&var_store_id, first)| {
                        let name = match declared_store(&first.store.borrow().parsed_data) {
                            Some((_, DeclaredStore::Variable(store))) => store.variable_key().name,
                            _ => String::new(),
                        };
                        let form_set = list.forms.iter().position(|root| {
                            let root = root.borrow();
                            root.children
                                .first()
                                .is_some_and(|op| Rc::ptr_eq(op, &first.form_set))
                        });
                        (var_store_id, (name, form_set))
                    })
                    .collect();
                let disabled_roots: Vec<usize> = list
                    .disabled_forms
                    .iter()
                    .map(|disabled| disabled.root_index)
                    .filter(|root| package.form_sets.contains(root))
                    .collect();
                (package.form_sets.clone(), disabled_roots, declared_by)
            })
            .collect();
        let named = |name: &str, form_set: usize| (name.to_string(), Some(form_set));

        assert_eq!(list.disabled_forms.len(), 1, "disabled forms");
        assert_eq!(
            recorded,
            [
                (
                    0..2,
                    vec![],
                    BTreeMap::from([(2, named("S2", 0)), (4, named("S4", 1))])
                ),
                (
                    2..3,
                    vec![2],
                    BTreeMap::from([(6, named("S6", 2)), (7, named("S7", 2))])
                ),
            ]
        );
    }

    /// A disabled form's PASSWORD and VarStores count as those of its FormSet: where a FormSet's
    /// form that a short NUMERIC disables declares Shadow, the first VarStore of id 2, before a
    /// later FormSet's PASSWORD of id 2, and where an earlier FormSet declares Shadow before the
    /// PASSWORD in a disabled form of a later FormSet, in the first form package or in a second,
    /// whose disabled form is the list's first, Shadow keeps the password at its VarOffset,
    /// through variables of either reach.
    #[test]
    fn a_first_var_store_or_a_password_in_a_disabled_form_counts() {
        let short = operation(NUMERIC, false, &[1, 2]);
        let shadow_store = var_store(2, OTHER_GUID, "Shadow", 81);
        let disabled_password = form_set_with(&[password_on(2, 3, 2, 5), short.clone()]);
        let mut want = WithheldBytes::default();
        want.insert(amitse_setup(), 5..45);
        want.insert(shadow(), 5..45);
        for (case, list) in [
            (
                "Shadow in a disabled form",
                list_of(&[
                    form_set_with_guid(FIRST_FORM_SET, &[form(1, &[shadow_store.clone(), short])]),
                    form_set_with(&[password_on(2, 3, 2, 5)]),
                ]),
            ),
            (
                "the PASSWORD in a disabled form",
                list_of(&[
                    first_form_set(shadow_store.clone()),
                    disabled_password.clone(),
                ]),
            ),
            (
                "the PASSWORD in a disabled form of a second form package",
                list_of_packages(&[
                    vec![first_form_set(var_store(2, OTHER_GUID, "First", 81))],
                    vec![first_form_set(shadow_store), disabled_password],
                ]),
            ),
        ] {
            assert_eq!(list.disabled_forms.len(), 1, "{case}: disabled forms");
            for reach in [VariableReach::BootServices, VariableReach::Runtime] {
                assert_eq!(
                    PasswordQuestions::of_lists(std::slice::from_ref(&list))
                        .withheld(&reaching(reach))
                        .map_err(|error| error.to_string()),
                    Ok(want.clone()),
                    "{case}: {reach:?}"
                );
            }
        }
    }

    /// A disabled form finds its form package by its root's index in the list's forms: where
    /// each of two form packages holds a form that a short NUMERIC disables, and the second
    /// package's FormSet declares Shadow, the first VarStore of id 2, before a later FormSet whose
    /// PASSWORD of id 2 at VarOffset 5 is in the list's second disabled form, Shadow keeps the
    /// password beside AMITSESetup, through variables of either reach.
    #[test]
    fn a_password_in_a_later_package_s_disabled_form_after_another_finds_its_first_var_store() {
        let short = operation(NUMERIC, false, &[1, 2]);
        let list = list_of_packages(&[
            vec![form_set(&[form(1, std::slice::from_ref(&short))])],
            vec![
                first_form_set(var_store(2, OTHER_GUID, "Shadow", 81)),
                form_set_with(&[password_on(2, 3, 2, 5), short]),
            ],
        ]);
        let mut want = WithheldBytes::default();
        want.insert(amitse_setup(), 5..45);
        want.insert(shadow(), 5..45);

        assert_eq!(list.disabled_forms.len(), 2, "disabled forms");
        for reach in [VariableReach::BootServices, VariableReach::Runtime] {
            assert_eq!(
                PasswordQuestions::of_lists(std::slice::from_ref(&list))
                    .withheld(&reaching(reach))
                    .map_err(|error| error.to_string()),
                Ok(want.clone()),
                "{reach:?}"
            );
        }
    }

    /// A VarStore outside any FormSet after another FormSet's first VarStore of the id leaves that
    /// one first: of a FormSet that declares Shadow for VarStoreId 2, the VARSTORE Out of id 2
    /// outside any FormSet and the PASSWORD's FormSet, read_db records Shadow's FormSet as the one
    /// that declares the first VarStore of id 2, and the PASSWORD's own AMITSESetup, Out and
    /// Shadow keep its password, through variables of either reach.
    #[test]
    fn an_outside_var_store_after_another_form_set_s_first_leaves_that_one_first() {
        let list = list_of_packages(&[vec![
            first_form_set(var_store(2, OTHER_GUID, "Shadow", 81)),
            var_store(2, OTHER_GUID, "Out", 81),
            form_set_with(&[password_on(2, 3, 2, 5)]),
        ]]);
        let mut want = WithheldBytes::default();
        want.insert(amitse_setup(), 5..45);
        want.insert(other_variable("Out"), 5..45);
        want.insert(shadow(), 5..45);

        assert_eq!(
            first_store_form_set(&list, 2),
            Some(Guid::from(FIRST_FORM_SET)),
            "the FormSet of the first VarStore of id 2"
        );
        for reach in [VariableReach::BootServices, VariableReach::Runtime] {
            assert_eq!(
                PasswordQuestions::of_lists(std::slice::from_ref(&list))
                    .withheld(&reaching(reach))
                    .map_err(|error| error.to_string()),
                Ok(want.clone()),
                "{reach:?}"
            );
        }
    }

    /// Where another FormSet's first VarStore of a PASSWORD's VarStoreId names the variable of a
    /// VarStore of the id outside any FormSet, which holds the password at that VarOffset already,
    /// its bytes there are withheld once: of a FormSet that declares Shadow for VarStoreId 2, the
    /// VARSTORE Shadow of id 2 outside any FormSet and the PASSWORD's FormSet, Shadow's FormSet
    /// declares the first VarStore of id 2, and both reaches withhold AMITSESetup and Shadow at
    /// 5..45, each once.
    #[test]
    fn a_first_var_store_of_an_outside_var_store_s_variable_withholds_its_bytes_once() {
        let list = list_of_packages(&[vec![
            first_form_set(var_store(2, OTHER_GUID, "Shadow", 81)),
            var_store(2, OTHER_GUID, "Shadow", 81),
            form_set_with(&[password_on(2, 3, 2, 5)]),
        ]]);
        let mut want = WithheldBytes::default();
        want.insert(amitse_setup(), 5..45);
        want.insert(shadow(), 5..45);

        assert_eq!(
            first_store_form_set(&list, 2),
            Some(Guid::from(FIRST_FORM_SET)),
            "the FormSet of the first VarStore of id 2"
        );
        for reach in [VariableReach::BootServices, VariableReach::Runtime] {
            assert_eq!(
                PasswordQuestions::of_lists(std::slice::from_ref(&list))
                    .withheld(&reaching(reach))
                    .map_err(|error| error.to_string()),
                Ok(want.clone()),
                "{reach:?}"
            );
        }
    }

    /// FindStorageFromVarId walks the form package op by op, FORM_SET ops or not, so a FormSet
    /// nested in another is another FormSet either way round: where a FormSet declares Shadow for
    /// VarStoreId 2 and then nests the PASSWORD's FormSet, and where the PASSWORD's FormSet nests
    /// one that declares Shadow before its own AMITSESetup, Shadow keeps the password at its
    /// VarOffset, through variables of either reach and from a ConfigSnapshot. Where the nested
    /// PASSWORD's FormSet declares its AMITSESetup before the Shadow of the FormSet around it, its
    /// own is the first, and Shadow keeps the password too, as a VarStore of its id in the
    /// PASSWORD's root (password_questions).
    #[test]
    fn the_first_var_store_of_a_form_set_nesting_or_nested_in_the_password_s_is_withheld() {
        let shadow_store = var_store(2, OTHER_GUID, "Shadow", 81);
        let password_form_set = form_set_with(&[password_on(2, 3, 2, 5)]);
        let mut both = WithheldBytes::default();
        both.insert(amitse_setup(), 5..45);
        both.insert(shadow(), 5..45);
        for (case, ifr, want) in [
            (
                "the PASSWORD's FormSet nested after Shadow",
                form_set_with_guid(
                    FIRST_FORM_SET,
                    &[shadow_store.clone(), password_form_set.clone()],
                ),
                both.clone(),
            ),
            (
                "Shadow's FormSet nested first in the PASSWORD's",
                form_set_with_guid(
                    [0x13; 16],
                    &[
                        first_form_set(shadow_store.clone()),
                        var_store(2, TSE_GUID, "AMITSESetup", 81),
                        form(1, &[password_on(2, 3, 2, 5)]),
                    ],
                ),
                both.clone(),
            ),
            (
                "the PASSWORD's FormSet nested before Shadow",
                form_set_with_guid(FIRST_FORM_SET, &[password_form_set, shadow_store]),
                both,
            ),
        ] {
            let ifr = [ifr];
            for reach in [VariableReach::BootServices, VariableReach::Runtime] {
                assert_eq!(
                    withheld_of(&ifr, reach),
                    Ok(want.clone()),
                    "{case}: {reach:?}"
                );
            }
            assert_eq!(
                passwords_of(&ifr).withheld_from_snapshot(),
                Ok(want),
                "{case}: ConfigSnapshot"
            );
        }
    }

    /// A PASSWORD whose FormSet declares no VarStore of its VarStoreId stays unresolved for that
    /// reason, the first, also where another FormSet's VARSTORE_NAME_VALUE, the first VarStore of
    /// that id in their form package, leaves it unresolved too.
    #[test]
    fn a_password_without_its_form_set_s_var_store_keeps_that_reason_first() {
        let passwords = passwords_of(&[
            first_form_set(var_store_name_value(7, OTHER_GUID)),
            form_set_with(&[password_on(2, 3, 7, 5)]),
        ]);

        assert!(
            matches!(
                passwords.unresolved.as_slice(),
                [UnresolvedPassword::NoVarStore { question_id: 2, .. }]
            ),
            "{:?}",
            passwords.unresolved
        );
    }

    /// FindStorageFromVarId steps into the scope of an unknown opcode as into any other
    /// (ConfigKeywordHandler.c:1566), so a VarStore there counts in IFR order for the first
    /// VarStore of its VarStoreId in the form package. Where Shadow, in such a scope of an earlier
    /// FormSet, comes before Third, which another FormSet declares for that id, Shadow is the
    /// first: it is withheld as a VarStore outside any FormSet is, and Third holds none of the
    /// password. Where Third comes first, it keeps the password too. Through variables of either
    /// reach.
    #[test]
    fn a_var_store_in_an_unknown_scope_counts_for_the_first_of_its_id() {
        let unknown_scope = form_set(&[
            in_unknown_scope(&var_store(2, OTHER_GUID, "Shadow", 81)),
            form(1, &[]),
        ]);
        let third = first_form_set(var_store(2, OTHER_GUID, "Third", 81));
        let password = form_set_with(&[password_on(2, 3, 2, 5)]);
        let mut shadow_first = WithheldBytes::default();
        shadow_first.insert(amitse_setup(), 5..45);
        shadow_first.insert(shadow(), 5..45);
        let mut third_first = shadow_first.clone();
        third_first.insert(other_variable("Third"), 5..45);
        for (case, ifr, want) in [
            (
                "Shadow first",
                vec![unknown_scope.clone(), third.clone(), password.clone()],
                shadow_first,
            ),
            (
                "Third first",
                vec![third, unknown_scope, password],
                third_first,
            ),
        ] {
            for reach in [VariableReach::BootServices, VariableReach::Runtime] {
                assert_eq!(
                    withheld_of(&ifr, reach),
                    Ok(want.clone()),
                    "{case}: {reach:?}"
                );
            }
        }
    }

    /// A PASSWORD op that ends before its question header (HeaderPastOp) withholds no less than
    /// the first-VarStore rule does: from its VarOffset on, in each VARSTORE and VARSTORE_EFI of
    /// its VarStoreId in the package list, its FormSet's AMITSESetup, Shadow, the first of that id
    /// in the form package, which an earlier FormSet declares, and Third, a later FormSet's. It
    /// stays unresolved for that reason alone, and through variables that reach BootServices it
    /// fails closed.
    #[test]
    fn a_password_with_its_header_past_its_op_is_withheld_in_the_first_var_store_and_the_others() {
        // the SUBTITLE's data is the rest of the PASSWORD's question header: VarStoreId 2,
        // VarOffset 5 and Flags
        let short = [
            operation(PASSWORD, false, &[3, 0, 4, 0]),
            operation(SUBTITLE, false, &[2, 0, 5, 0, 0]),
        ];
        let passwords = passwords_of(&[
            first_form_set(var_store(2, OTHER_GUID, "Shadow", 81)),
            form_set_with(&short),
            form_set_with_guid(
                [0x13; 16],
                &[var_store(2, OTHER_GUID, "Third", 81), form(1, &[])],
            ),
        ]);
        let mut want = WithheldBytes::default();
        want.insert(amitse_setup(), 5..usize::MAX);
        want.insert(shadow(), 5..usize::MAX);
        want.insert(other_variable("Third"), 5..usize::MAX);

        assert!(
            matches!(
                passwords.unresolved.as_slice(),
                [UnresolvedPassword::HeaderPastOp {
                    question_id: 0x0702,
                    ..
                }]
            ),
            "unresolved {:?}",
            passwords.unresolved
        );
        assert!(
            passwords
                .withheld(&reaching(VariableReach::BootServices))
                .is_err(),
            "withheld through BootServices"
        );
        assert_eq!(
            passwords
                .withheld(&reaching(VariableReach::Runtime))
                .map_err(|error| error.to_string()),
            Ok(want),
            "withheld through Runtime"
        );
    }

    /// Each PASSWORD is withheld in the first VarStore of its VarStoreId of its own form package
    /// alone: 300 form packages of one list, each with a FormSet that declares the variable
    /// S<index> for VarStoreId 2 before a FormSet with a PASSWORD of id 2, give at most 2 entries
    /// per PASSWORD, its own VarStore and that first one, and that of the first package withholds
    /// 1 password. Each FormSet finds its package in a number of comparisons logarithmic in the
    /// packages, at most 10 for 300.
    #[test]
    fn first_var_stores_of_form_packages_cost_entries_linear_in_their_passwords() {
        let count = 300;
        let packages: Vec<Vec<Vec<u8>>> = (0..count)
            .map(|index| {
                vec![
                    first_form_set(var_store(2, OTHER_GUID, &format!("S{index}"), 81)),
                    form_set_with(&[password_on(2, 3, 2, 0)]),
                ]
            })
            .collect();
        let list = list_of_packages(&packages);
        let before = PACKAGES_COMPARED.with(Cell::get);
        let passwords = PasswordQuestions::of_lists(std::slice::from_ref(&list));
        let compared = PACKAGES_COMPARED.with(Cell::get) - before;
        let withheld = passwords
            .withheld(&reaching(VariableReach::BootServices))
            .unwrap_or_else(|error| panic!("withheld: {error}"));

        assert!(
            compared <= 10 * list.forms.len(),
            "packages compared {compared}, at most {}",
            10 * list.forms.len()
        );
        assert!(
            passwords.entries() <= 2 * count,
            "PasswordQuestions entries {}, at most {}",
            passwords.entries(),
            2 * count
        );
        assert!(
            withheld.entries() <= 2 * count,
            "WithheldBytes entries {}, at most {}",
            withheld.entries(),
            2 * count
        );
        assert_eq!(withheld.of(&other_variable("S0")).count(), 1, "S0");
    }

    /// A malformed VarStore op outside any FormSet hides its VarStoreId and variable: fail
    /// closed.
    #[test]
    fn a_malformed_var_store_outside_a_form_set_fails_closed() {
        let passwords = passwords_of(&[
            operation(VAR_STORE, false, &[2, 0]),
            form_set_with(&[password_on(2, 3, 2, 0)]),
        ]);

        assert!(
            matches!(
                passwords.unresolved.as_slice(),
                [UnresolvedPassword::MalformedVarStoreOutsideFormSet { .. }]
            ),
            "{:?}",
            passwords.unresolved
        );
        assert!(
            passwords
                .withheld(&reaching(VariableReach::BootServices))
                .is_err(),
            "withheld through BootServices"
        );
    }

    /// A malformed VarStore op outside any FormSet in a HiiDB that declares no PASSWORD hides no
    /// password: nothing is withheld, in either reach.
    #[test]
    fn a_malformed_var_store_outside_a_form_set_without_a_password_withholds_nothing() {
        for reach in [VariableReach::BootServices, VariableReach::Runtime] {
            assert_eq!(
                withheld_of(
                    &[
                        operation(VAR_STORE, false, &[2, 0]),
                        form_set_with(&[checkbox_on(1, 3, 2)]),
                    ],
                    reach
                ),
                Ok(WithheldBytes::default()),
                "{reach:?}"
            );
        }
    }

    /// After a FormSet without its Scope bit, whose rest up to the next FORM_SET op is ignored IFR,
    /// a VarStore outside any FormSet of a PASSWORD's VarStoreId keeps that password all the same:
    /// through variables that reach Runtime, which read past ignored IFR, it is withheld whole, as
    /// every variable that IFR declares is (IgnoredPasswords::Declared).
    #[test]
    fn an_outside_var_store_after_a_form_set_without_its_scope_bit_is_withheld_too() {
        let ifr = [
            // ends, for uefisettings, at its form's End; edk2 parses on into what follows
            scopeless_form_set(&[form(1, &[])]),
            var_store(2, OTHER_GUID, "Shadow", 81),
            form_set_with(&[password_on(2, 3, 2, 0)]),
        ];
        let mut want = WithheldBytes::default();
        want.insert(amitse_setup(), 0..40);
        want.insert(shadow(), 0..usize::MAX);

        assert_eq!(withheld_of(&ifr, VariableReach::Runtime), Ok(want));
    }

    /// A FormSet that does not parse, whose 1 data byte of a CHECKBOX is too few, and which
    /// read_db ignores, holding `body` too.
    fn ignored_form_set(body: &[Vec<u8>]) -> Vec<u8> {
        form_set(&[body.concat(), operation(CHECKBOX, false, &[0])])
    }

    /// A PASSWORD in a FormSet that read_db ignores, whose ops parse_form_sets' walk steps over as
    /// it looks for FormSets in it, is unresolved as one in ignored IFR, not as one outside any
    /// FormSet too.
    #[test]
    fn a_password_in_an_ignored_form_set_is_unresolved_once() {
        let passwords = passwords_of(&[
            ignored_form_set(&[form(1, &[password_on(2, 3, 2, 0)])]),
            form_set_with(&[checkbox_on(1, 3, 1)]),
        ]);

        assert!(
            matches!(
                passwords.unresolved.as_slice(),
                [UnresolvedPassword::InIgnoredIfr { offset: 0, .. }]
            ),
            "{:?}",
            passwords.unresolved
        );
    }

    /// The walk leaves a FormSet that read_db ignores at its End: a PASSWORD after it, outside
    /// any FormSet, fails closed through variables that reach BootServices and keeps its password
    /// in each VarStore of its VarStoreId through those that reach Runtime.
    #[test]
    fn a_password_after_an_ignored_form_set_is_outside_any_form_set() {
        let passwords = passwords_of(&[
            ignored_form_set(&[form(1, &[checkbox_on(1, 3, 1)])]),
            password_on(9, 3, 2, 40),
            form_set_with(&[checkbox_on(1, 3, 1)]),
        ]);
        let mut want = WithheldBytes::default();
        want.insert(amitse_setup(), 40..80);

        assert!(
            matches!(
                passwords.unresolved.as_slice(),
                [
                    UnresolvedPassword::OutsideFormSet { .. },
                    UnresolvedPassword::InIgnoredIfr { offset: 0, .. }
                ]
            ),
            "{:?}",
            passwords.unresolved
        );
        assert_eq!(
            passwords
                .withheld(&reaching(VariableReach::Runtime))
                .map_err(|error| error.to_string()),
            Ok(want),
            "withheld through Runtime"
        );
    }

    /// A VarStore in a FormSet that read_db ignores, of the VarStoreId of a PASSWORD in a FormSet
    /// that it reads, keeps that password as an outside one does: the Keyword Handler walks the
    /// whole form package, and through variables that reach Runtime, which read past ignored IFR,
    /// it is withheld whole, as every variable that ignored IFR declares is
    /// (IgnoredPasswords::Declared).
    #[test]
    fn a_var_store_in_an_ignored_form_set_of_a_password_s_id_is_withheld_too() {
        let ifr = [
            ignored_form_set(&[var_store(2, OTHER_GUID, "Shadow", 81)]),
            form_set_with(&[password_on(2, 3, 2, 0)]),
        ];
        let mut want = WithheldBytes::default();
        want.insert(amitse_setup(), 0..40);
        want.insert(shadow(), 0..usize::MAX);

        assert_eq!(withheld_of(&ifr, VariableReach::Runtime), Ok(want));
        assert!(
            withheld_of(&ifr, VariableReach::BootServices).is_err(),
            "withheld through BootServices"
        );
    }

    /// A PASSWORD in IFR that read_db ignores, in a FormSet that it ignores or past the End of a
    /// FormSet without its Scope bit up to the next FORM_SET op, keeps its password in each
    /// VarStore of its VarStoreId in its package list too: edk2-stable202608
    /// FindQuestionFromStringId finds it there, and FindStorageFromVarId takes the first VarStore
    /// of that id in the form package, here AMITSESetup of a FormSet that read_db reads. Through
    /// variables that reach Runtime its bytes there are withheld, and it is unresolved once, as
    /// IFR that read_db ignores.
    #[test]
    fn a_password_in_ignored_ifr_is_withheld_in_each_var_store_of_its_id() {
        for (case, ignored) in [
            (
                "in an ignored FormSet",
                ignored_form_set(&[form(1, &[password_on(2, 3, 2, 40)])]),
            ),
            (
                "past the End of a FormSet without its Scope bit",
                [
                    scopeless_form_set(&[form(1, &[])]),
                    password_on(2, 3, 2, 40),
                ]
                .concat(),
            ),
        ] {
            let passwords = passwords_of(&[ignored, form_set_with(&[checkbox_on(1, 3, 1)])]);
            let mut want = WithheldBytes::default();
            want.insert(amitse_setup(), 40..80);

            assert!(
                matches!(
                    passwords.unresolved.as_slice(),
                    [UnresolvedPassword::InIgnoredIfr { offset: 0, .. }]
                ),
                "{case}: {:?}",
                passwords.unresolved
            );
            assert_eq!(
                passwords
                    .withheld(&reaching(VariableReach::Runtime))
                    .map_err(|error| error.to_string()),
                Ok(want),
                "{case}: withheld through Runtime"
            );
        }
    }

    /// The IFR after a FormSet without its Scope bit is ignored up to the next FORM_SET op that the
    /// walk meets, which parse_form_sets reads as a FormSet of its own: a PASSWORD after that
    /// FormSet is outside any FormSet, unresolved as such, and a VarStore there of its VarStoreId
    /// keeps its password at its VarOffset, not whole.
    #[test]
    fn the_ifr_after_a_form_set_without_its_scope_bit_is_ignored_up_to_the_next_form_set() {
        let passwords = passwords_of(&[
            scopeless_form_set(&[form(1, &[])]),
            form_set_with(&[checkbox_on(1, 3, 1)]),
            password_on(9, 3, 7, 40),
            var_store(7, OTHER_GUID, "Shadow", 81),
        ]);
        let mut want = WithheldBytes::default();
        want.insert(shadow(), 40..80);

        assert!(
            matches!(
                passwords.unresolved.as_slice(),
                [
                    UnresolvedPassword::OutsideFormSet { .. },
                    UnresolvedPassword::InIgnoredIfr { offset: 0, .. }
                ]
            ),
            "{:?}",
            passwords.unresolved
        );
        assert_eq!(
            passwords
                .withheld(&reaching(VariableReach::Runtime))
                .map_err(|error| error.to_string()),
            Ok(want),
            "withheld through Runtime"
        );
    }

    /// A PASSWORD outside any FormSet whose op ends before its MaxSize still names its VarStoreId
    /// and VarOffset: through variables that reach Runtime every byte from its VarOffset on is
    /// withheld in each VarStore of that id, and every byte of each variable that its VarStoreInfo
    /// may name as a VarName on a VARSTORE_EFI before UEFI 2.3.1 of that id, as for one in a
    /// FormSet; through variables that reach BootServices it fails closed.
    #[test]
    fn a_password_outside_a_form_set_without_max_size_keeps_every_byte_from_its_var_offset() {
        let headed = |var_store_id, offset| {
            operation(
                PASSWORD,
                false,
                &question_header_on(9, 3, var_store_id, offset),
            )
        };
        let mut on_var_store = WithheldBytes::default();
        on_var_store.insert(amitse_setup(), 40..usize::MAX);
        let mut on_var_name = WithheldBytes::default();
        on_var_name.insert(short_variable("ShortVarPw"), 0..usize::MAX);
        for (case, ifr, want) in [
            (
                "on a VARSTORE",
                vec![headed(2, 40), form_set_with(&[checkbox_on(1, 3, 1)])],
                on_var_store,
            ),
            (
                "on a VARSTORE_EFI before UEFI 2.3.1",
                vec![short_var_store_efi(7), headed(7, 5), form_set_with(&[])],
                on_var_name,
            ),
        ] {
            let passwords =
                PasswordQuestions::of_lists(&[list_with_strings(&ifr, &VAR_NAME_STRINGS)]);

            assert!(
                passwords
                    .withheld(&reaching(VariableReach::BootServices))
                    .is_err(),
                "{case}: BootServices"
            );
            assert_eq!(
                passwords
                    .withheld(&reaching(VariableReach::Runtime))
                    .map_err(|error| error.to_string()),
                Ok(want),
                "{case}: Runtime"
            );
        }
    }

    /// A VarStore outside any FormSet that does not parse may declare the VarStoreId of any
    /// PASSWORD, and edk2-stable202608 FindStorageFromVarId reads it whatever its Length: through
    /// variables that reach Runtime, as its variable's name is unknown, every variable of the Guid
    /// that it holds is withheld whole, beside the bytes of the PASSWORD in its FormSet's store.
    #[test]
    fn a_malformed_var_store_outside_a_form_set_withholds_every_variable_of_its_guid() {
        // its Guid, VarStoreId 7 and Size, and no Name
        let malformed = operation(
            VAR_STORE,
            false,
            &[&OTHER_GUID[..], &7u16.to_le_bytes(), &81u16.to_le_bytes()].concat(),
        );
        let passwords = passwords_of(&[malformed, form_set_with(&[password_on(2, 3, 2, 0)])]);
        let mut guids = VariableGuids::default();
        guids.insert(Some(Guid::from(OTHER_GUID)));
        let mut want = WithheldBytes::default();
        want.insert(amitse_setup(), 0..40);
        want.insert_guids(&guids);

        assert!(
            matches!(
                passwords.unresolved.as_slice(),
                [UnresolvedPassword::MalformedVarStoreOutsideFormSet { offset: 0, .. }]
            ),
            "{:?}",
            passwords.unresolved
        );
        assert_eq!(
            passwords
                .withheld(&reaching(VariableReach::Runtime))
                .map_err(|error| error.to_string()),
            Ok(want),
            "withheld through Runtime"
        );
    }

    /// A VarStore in a form that a malformed op after it disables is still a VarStore of the
    /// package list, which edk2-stable202608 FindStorageFromVarId may take for a PASSWORD outside
    /// any FormSet: through variables that reach Runtime that password's bytes in its variable are
    /// withheld.
    #[test]
    fn a_password_outside_a_form_set_is_withheld_in_a_var_store_of_a_disabled_form() {
        let ifr = [
            password_on(9, 3, 7, 40),
            form_set_with(&[
                var_store(7, OTHER_GUID, "Shadow", 81),
                operation(CHECKBOX, false, &[0x00; 4]),
            ]),
        ];
        let mut want = WithheldBytes::default();
        want.insert(shadow(), 40..80);

        assert_eq!(withheld_of(&ifr, VariableReach::Runtime), Ok(want));
    }

    /// A VarStore op in a form that a malformed op disables, that op itself or one after it, ignores
    /// its FormSet, as edk2-stable202608 FindStorageFromVarId reads the VarStoreId of a VarStore op
    /// wherever it is, whatever its Length: through variables that reach BootServices every
    /// variable of the HiiDB is refused, and through those that reach Runtime the storage of the
    /// FormSet is withheld whole, every variable of its Guid for one whose name is unknown.
    #[test]
    fn a_var_store_in_a_disabled_form_ignores_its_form_set() {
        // its Guid alone, too short for its VarStoreId
        let short = operation(VAR_STORE, false, &OTHER_GUID);
        let mut short_guid = VariableGuids::default();
        short_guid.insert(Some(Guid::from(OTHER_GUID)));
        let mut when_short = WithheldBytes::default();
        when_short.insert(setup(), 0..usize::MAX);
        when_short.insert(amitse_setup(), 0..usize::MAX);
        when_short.insert_guids(&short_guid);
        let mut after = WithheldBytes::default();
        after.insert(setup(), 0..usize::MAX);
        after.insert(amitse_setup(), 0..usize::MAX);
        after.insert(shadow(), 0..usize::MAX);
        for (case, body, want) in [
            (
                "a malformed VARSTORE in a form",
                vec![checkbox_on(1, 3, 1), short],
                when_short,
            ),
            (
                "a VARSTORE after the op that disables its form",
                vec![
                    operation(CHECKBOX, false, &[0x00; 4]),
                    var_store(7, OTHER_GUID, "Shadow", 81),
                ],
                after,
            ),
        ] {
            let passwords = passwords_of(&[form_set_with(&body)]);

            assert!(
                matches!(
                    passwords.unresolved.as_slice(),
                    [UnresolvedPassword::InIgnoredIfr { offset: 0, reason, .. }]
                        if reason.contains("a VarStore op in a form that a malformed op disables")
                ),
                "{case}: {:?}",
                passwords.unresolved
            );
            assert!(
                passwords
                    .withheld(&reaching(VariableReach::BootServices))
                    .is_err(),
                "{case}: BootServices"
            );
            assert_eq!(
                passwords
                    .withheld(&reaching(VariableReach::Runtime))
                    .map_err(|error| error.to_string()),
                Ok(want),
                "{case}: Runtime"
            );
        }
    }

    /// A PASSWORD in a FormSet that does not declare its VarStoreId stays unresolved, though a
    /// VarStore outside any FormSet declares it: UEFI 2.11 §33.3.8.2.2 EFI_IFR_QUESTION_HEADER
    /// names a VarStore of its form set, and the Keyword Handler may take another FormSet's.
    /// Through variables that reach Runtime its bytes in that outside VarStore, which the Keyword
    /// Handler takes, are withheld all the same.
    #[test]
    fn a_password_naming_only_an_outside_var_store_stays_unresolved() {
        let passwords = passwords_of(&[
            var_store(5, OTHER_GUID, "Shadow", 81),
            form_set_with(&[password_on(2, 3, 5, 0)]),
        ]);
        let mut outside = WithheldBytes::default();
        outside.insert(shadow(), 0..40);

        assert_eq!(
            passwords.unresolved,
            [UnresolvedPassword::NoVarStore {
                form_set: Some(FORM_SET_GUID),
                question_id: 2,
                reason: "no supported varstore with matching id 0x0005 found".to_string(),
            }]
        );
        assert_eq!(
            passwords
                .withheld(&reaching(VariableReach::Runtime))
                .map_err(|error| error.to_string()),
            Ok(outside),
            "withheld through Runtime"
        );
    }

    /// Ops outside any FormSet that name no password withhold nothing more: a VarStore of an id
    /// that no PASSWORD names, and a CHECKBOX.
    #[test]
    fn outside_ops_without_a_password_withhold_nothing_more() {
        let mut want = WithheldBytes::default();
        want.insert(amitse_setup(), 0..40);
        for reach in [VariableReach::BootServices, VariableReach::Runtime] {
            assert_eq!(
                withheld_of(
                    &[
                        var_store(7, OTHER_GUID, "Shadow", 81),
                        checkbox_on(8, 3, 7),
                        form_set_with(&[password_on(2, 3, 2, 0)]),
                    ],
                    reach
                ),
                Ok(want.clone()),
                "{reach:?}"
            );
        }
    }

    /// A question of a FormSet whose VarStoreId only a VarStore outside any FormSet declares has
    /// no store: UEFI 2.11 §33.2.5.1 declares variable stores within a form set, and
    /// edk2-stable202608 SetupBrowserDxe/IfrParse.c CreateQuestion finds none in the FormSet's
    /// storage list.
    #[test]
    fn a_question_naming_a_var_store_outside_its_form_set_has_no_store() {
        let list = list_of(&[
            var_store(5, OTHER_GUID, "Shadow", 81),
            form_set_with(&[checkbox_on(1, 3, 5)]),
        ]);
        let mut checkbox = None;
        walk_scopes(&list.forms, (), |node, ()| {
            if node.borrow().op_code == IFROpCode::CheckBox {
                checkbox = Some(Rc::clone(node));
            }
            Walk::Enter(())
        });

        let error = find_corresponding_varstore(checkbox.expect("the CHECKBOX"), 5)
            .err()
            .map(|error| error.to_string());

        assert_eq!(
            error.as_deref(),
            Some("no supported varstore with matching id 0x0005 found")
        );
    }

    /// `count` VARSTOREs of the VarStoreId `var_store_id` outside any FormSet, each of its own
    /// variable.
    fn outside_var_stores(var_store_id: u16, count: u16) -> Vec<Vec<u8>> {
        (0..count)
            .map(|index| var_store(var_store_id, OTHER_GUID, &format!("S{index}"), 81))
            .collect()
    }

    /// `count` PASSWORDs of VarStoreId `var_store_id` at VarOffsets 0 to `count`-1.
    fn passwords_on(var_store_id: u16, count: u16) -> Vec<Vec<u8>> {
        (0..count)
            .map(|offset| password_on(9, 3, var_store_id, offset))
            .collect()
    }

    /// p PASSWORDs of a VarStoreId and o VarStores of that id outside any FormSet are recorded
    /// once each, not once for each pair, by PasswordQuestions and by the bytes that it withholds:
    /// 1000 PASSWORDs outside any FormSet and 1000 outside VARSTOREs of their id give at most p + o
    /// entries, and 1000 PASSWORDs in a FormSet one more, the VarStore of their FormSet. Each
    /// outside VARSTORE withholds each password once all the same.
    #[test]
    fn passwords_and_outside_var_stores_of_an_id_cost_entries_linear_in_them() {
        let (p, o) = (1000, 1000);
        let cases = [
            (
                "PASSWORDs outside any FormSet",
                [
                    outside_var_stores(7, o),
                    passwords_on(7, p),
                    vec![form_set_with(&[checkbox_on(1, 3, 1)])],
                ]
                .concat(),
                usize::from(p + o),
            ),
            (
                "PASSWORDs in a FormSet",
                [
                    outside_var_stores(2, o),
                    vec![form_set_with(&passwords_on(2, p))],
                ]
                .concat(),
                usize::from(p + o) + 1,
            ),
        ];
        for (case, ifr, most) in cases {
            let passwords = passwords_of(&ifr);
            let withheld = passwords
                .withheld(&reaching(VariableReach::Runtime))
                .unwrap_or_else(|error| panic!("{case}: {error}"));
            let s0 = VariableKey {
                name: "S0".to_string(),
                guid: Guid::from(OTHER_GUID),
            };

            assert!(
                passwords.entries() <= most,
                "{case}: PasswordQuestions entries {}, at most {most}",
                passwords.entries()
            );
            assert!(
                withheld.entries() <= most,
                "{case}: WithheldBytes entries {}, at most {most}",
                withheld.entries()
            );
            assert_eq!(withheld.of(&s0).count(), usize::from(p), "{case}: S0");
        }
    }

    /// PasswordQuestions reads the VarStores of a package list once, not once for each PASSWORD
    /// outside any FormSet: 8000 of them read at most as many VarStore declarations as the list
    /// has ops.
    #[test]
    fn outside_passwords_read_the_var_stores_of_their_list_once() {
        let count = 8000;
        let list = list_of(
            &[
                passwords_on(2, count),
                vec![form_set_with(&[checkbox_on(1, 3, 1)])],
            ]
            .concat(),
        );
        let mut ops = list.outside_ifr.len();
        walk_scopes(&list.forms, (), |_, ()| {
            ops += 1;
            Walk::Enter(())
        });

        let before = DECLARATIONS_READ.with(Cell::get);
        let passwords = PasswordQuestions::of_lists(std::slice::from_ref(&list));
        let read = DECLARATIONS_READ.with(Cell::get) - before;

        assert!(
            read <= ops,
            "VarStore declarations read: {read}, of {ops} ops"
        );
        assert_eq!(passwords.unresolved.len(), usize::from(count), "unresolved");
        assert_eq!(
            passwords
                .withheld(&reaching(VariableReach::Runtime))
                .map(|withheld| withheld.of(&amitse_setup()).count())
                .map_err(|error| error.to_string()),
            Ok(usize::from(count)),
            "AMITSESetup's withheld bytes"
        );
    }

    /// A PASSWORD op shorter than its question header keeps its password where edk2-stable202608
    /// SetupBrowserDxe/IfrParse.c CreateQuestion (:119-124) reads that header whatever the op's
    /// Length: in the bytes of the form package after it, here those of the SUBTITLE that follows,
    /// VarStoreId 2 (AMITSESetup) and VarOffset 0. Its MaxSize lies past the op too, so through
    /// variables that reach Runtime every byte of AMITSESetup from that VarOffset on is withheld,
    /// and no byte of Setup, in a disabled form and outside any FormSet; through those that reach
    /// BootServices it fails closed. As edk2-stable202608 ConfigKeywordHandler.c
    /// FindStorageFromVarId (:1520) takes the first VarStore of its id in the form package, one of
    /// that id in another FormSet keeps it too. At VarOffset 5 it is withheld from byte 5 on. A
    /// header of VarStoreId 0 names no VarStore (IfrParse.c CreateQuestion, :126), so through
    /// variables that reach Runtime no byte is withheld, not even of a VarStore that declares
    /// that id.
    #[test]
    fn a_password_op_short_of_its_question_header_keeps_its_password_past_the_op() {
        // the SUBTITLE's data is the rest of that header: VarStoreId, VarOffset and Flags
        let short_at = |var_store_id: u8, var_offset: u8| {
            [
                operation(PASSWORD, false, &[3, 0, 4, 0]),
                operation(SUBTITLE, false, &[var_store_id, 0, var_offset, 0, 0]),
            ]
        };
        let short = short_at(2, 0);
        let mut want = WithheldBytes::default();
        want.insert(amitse_setup(), 0..usize::MAX);
        let mut with_other = want.clone();
        with_other.insert(shadow(), 0..usize::MAX);
        let mut from_byte_5 = WithheldBytes::default();
        from_byte_5.insert(amitse_setup(), 5..usize::MAX);
        let in_form: fn(&[UnresolvedPassword]) -> bool = |unresolved| {
            matches!(
                unresolved,
                [UnresolvedPassword::HeaderPastOp {
                    question_id: 0x0702,
                    ..
                }]
            )
        };
        let outside: fn(&[UnresolvedPassword]) -> bool =
            |unresolved| matches!(unresolved, [UnresolvedPassword::OutsideFormSet { .. }]);
        for (case, ifr, unresolved, want) in [
            (
                "in a disabled form",
                vec![form_set_with(&short)],
                in_form,
                want.clone(),
            ),
            (
                "in a disabled form, its id in another FormSet too",
                vec![
                    form_set_with(&short),
                    form_set(&[var_store(2, OTHER_GUID, "Shadow", 81), form(1, &[])]),
                ],
                in_form,
                with_other,
            ),
            (
                "in a disabled form, at VarOffset 5",
                vec![form_set_with(&short_at(2, 5))],
                in_form,
                from_byte_5,
            ),
            (
                "in a disabled form, of VarStoreId 0, which a VarStore declares",
                vec![
                    form_set(&[var_store(0, OTHER_GUID, "Shadow", 81), form(1, &[])]),
                    form_set_with(&short_at(0, 5)),
                ],
                in_form,
                WithheldBytes::default(),
            ),
            (
                "outside any FormSet",
                vec![short.concat(), form_set_with(&[checkbox_on(1, 3, 1)])],
                outside,
                want,
            ),
        ] {
            let passwords = passwords_of(&ifr);

            assert!(
                unresolved(&passwords.unresolved),
                "{case}: unresolved {:?}",
                passwords.unresolved
            );
            assert!(
                passwords
                    .withheld(&reaching(VariableReach::BootServices))
                    .is_err(),
                "{case}: withheld through BootServices"
            );
            assert_eq!(
                passwords
                    .withheld(&reaching(VariableReach::Runtime))
                    .map_err(|error| error.to_string()),
                Ok(want),
                "{case}: withheld through Runtime"
            );
        }
    }

    /// A PASSWORD op whose question header runs past the end of its form package may keep its
    /// password in any VarStore of its package list: through variables that reach Runtime every
    /// variable of each VARSTORE and VARSTORE_EFI of the list is withheld whole, those of its
    /// FormSet and the one outside any, and every variable of the Guid of a VARSTORE_EFI before
    /// UEFI 2.3.1, whose VarName may name any; through those that reach BootServices it fails
    /// closed.
    #[test]
    fn a_password_whose_question_header_runs_past_the_package_withholds_every_var_store_whole() {
        let headless = operation(PASSWORD, false, &[3, 0, 4, 0]);
        let shadow_store = var_store(7, OTHER_GUID, "Shadow", 81);
        let mut want = WithheldBytes::default();
        for key in [setup(), amitse_setup()] {
            want.insert(key, 0..usize::MAX);
        }
        let mut with_shadow = want.clone();
        with_shadow.insert(shadow(), 0..usize::MAX);
        let mut short_guid = VariableGuids::default();
        short_guid.insert(Some(Guid::from(SHORT_VAR_STORE_GUID)));
        let mut with_short_guid = want;
        with_short_guid.insert_guids(&short_guid);
        let in_form: fn(&[UnresolvedPassword]) -> bool =
            |unresolved| matches!(unresolved, [UnresolvedPassword::NoHeader { .. }]);
        let outside: fn(&[UnresolvedPassword]) -> bool =
            |unresolved| matches!(unresolved, [UnresolvedPassword::OutsideFormSet { .. }]);
        for (case, ifr, unresolved, want) in [
            // the Ends of its form and FormSet are the last 4 bytes of the package
            (
                "in a disabled form",
                vec![
                    shadow_store.clone(),
                    form_set_with(std::slice::from_ref(&headless)),
                ],
                in_form,
                with_shadow.clone(),
            ),
            (
                "outside any FormSet",
                vec![
                    shadow_store,
                    form_set_with(&[checkbox_on(1, 3, 1)]),
                    headless.clone(),
                ],
                outside,
                with_shadow,
            ),
            (
                "in a disabled form, beside a VARSTORE_EFI before UEFI 2.3.1",
                vec![
                    form_set(&[short_var_store_efi(7), form(1, &[])]),
                    form_set_with(std::slice::from_ref(&headless)),
                ],
                in_form,
                with_short_guid,
            ),
        ] {
            let passwords = passwords_of(&ifr);

            assert!(
                unresolved(&passwords.unresolved),
                "{case}: unresolved {:?}",
                passwords.unresolved
            );
            assert!(
                passwords
                    .withheld(&reaching(VariableReach::BootServices))
                    .is_err(),
                "{case}: withheld through BootServices"
            );
            assert_eq!(
                passwords
                    .withheld(&reaching(VariableReach::Runtime))
                    .map_err(|error| error.to_string()),
                Ok(want),
                "{case}: withheld through Runtime"
            );
        }
    }

    /// edk2-stable202608 ConfigKeywordHandler.c FindStorageFromVarId (:1520) takes a VarStore in
    /// the scope of an unknown opcode as any, so a PASSWORD outside any FormSet of its VarStoreId
    /// keeps its password there: through variables that reach Runtime its bytes at its VarOffset
    /// are withheld, with the VarStore in a form and beside the forms; through those that reach
    /// BootServices it fails closed.
    #[test]
    fn an_outside_password_is_withheld_in_a_var_store_in_an_unknown_scope() {
        let shadow_store = in_unknown_scope(&var_store(7, OTHER_GUID, "Shadow", 81));
        let mut want = WithheldBytes::default();
        want.insert(shadow(), 0..40);
        for (case, form_set_ifr) in [
            (
                "in a form",
                form_set_with(std::slice::from_ref(&shadow_store)),
            ),
            (
                "beside the forms",
                form_set(&[shadow_store.clone(), form(1, &[])]),
            ),
        ] {
            let passwords = passwords_of(&[form_set_ifr, password_on(2, 3, 7, 0)]);

            assert!(
                matches!(
                    passwords.unresolved.as_slice(),
                    [UnresolvedPassword::OutsideFormSet { .. }]
                ),
                "{case}: unresolved {:?}",
                passwords.unresolved
            );
            assert!(
                passwords
                    .withheld(&reaching(VariableReach::BootServices))
                    .is_err(),
                "{case}: withheld through BootServices"
            );
            assert_eq!(
                passwords
                    .withheld(&reaching(VariableReach::Runtime))
                    .map_err(|error| error.to_string()),
                Ok(want.clone()),
                "{case}: withheld through Runtime"
            );
        }
    }

    /// A VarStore in the scope of an unknown opcode, before the FormSet of a PASSWORD of its
    /// VarStoreId, is the first VarStore of that id in the form package, which
    /// FindStorageFromVarId takes for that PASSWORD: its bytes at its VarOffset are withheld
    /// there too, beside those in the VarStore of its FormSet, through variables of either reach.
    #[test]
    fn a_form_set_password_is_withheld_in_a_var_store_of_its_id_in_an_unknown_scope() {
        let passwords = passwords_of(&[
            form_set(&[
                in_unknown_scope(&var_store(2, OTHER_GUID, "Shadow", 81)),
                form(1, &[]),
            ]),
            form_set_with(&[password_on(2, 3, 2, 0)]),
        ]);
        let mut want = WithheldBytes::default();
        want.insert(amitse_setup(), 0..40);
        want.insert(shadow(), 0..40);

        for reach in [VariableReach::BootServices, VariableReach::Runtime] {
            assert_eq!(
                passwords
                    .withheld(&reaching(reach))
                    .map_err(|error| error.to_string()),
                Ok(want.clone()),
                "{reach:?}"
            );
        }
    }

    /// A VarStore in the scope of an unknown opcode of a PASSWORD's own FormSet is a VarStore of
    /// that FormSet and one of those outside any FormSet at once: the PASSWORD resolves, and its
    /// bytes at its VarOffset are withheld there once, beside those in the other VarStore of its
    /// id in its FormSet, through variables of either reach.
    #[test]
    fn a_var_store_in_an_unknown_scope_of_its_form_set_withholds_a_password_once() {
        let passwords = passwords_of(&[form_set(&[
            var_store(2, TSE_GUID, "AMITSESetup", 81),
            in_unknown_scope(&var_store(2, OTHER_GUID, "Shadow", 81)),
            form(1, &[password_on(2, 3, 2, 0)]),
        ])]);
        let mut want = WithheldBytes::default();
        want.insert(amitse_setup(), 0..40);
        want.insert(shadow(), 0..40);

        assert_eq!(passwords.unresolved, vec![], "unresolved");
        for reach in [VariableReach::BootServices, VariableReach::Runtime] {
            assert_eq!(
                passwords
                    .withheld(&reaching(reach))
                    .map_err(|error| error.to_string()),
                Ok(want.clone()),
                "{reach:?}"
            );
        }
    }

    /// A VarStore in the scope of an unknown opcode that does not parse may declare the
    /// VarStoreId of any PASSWORD, as one outside any FormSet may: through variables that reach
    /// Runtime every variable of the Guid that it holds is withheld whole, beside the bytes of
    /// the PASSWORD in its FormSet's store; through those that reach BootServices it fails
    /// closed. The PASSWORD of its FormSet is unresolved for it too, as an undecoded VarStore op
    /// of its FormSet (UndecodedStores).
    #[test]
    fn a_malformed_var_store_in_an_unknown_scope_withholds_every_variable_of_its_guid() {
        // its Guid, VarStoreId 7 and Size, and no Name
        let malformed = operation(
            VAR_STORE,
            false,
            &[&OTHER_GUID[..], &7u16.to_le_bytes(), &81u16.to_le_bytes()].concat(),
        );
        let passwords = passwords_of(&[form_set_with(&[
            in_unknown_scope(&malformed),
            password_on(2, 3, 2, 0),
        ])]);
        let mut guids = VariableGuids::default();
        guids.insert(Some(Guid::from(OTHER_GUID)));
        let mut want = WithheldBytes::default();
        want.insert(amitse_setup(), 0..40);
        want.insert_guids(&guids);

        assert!(
            matches!(
                passwords.unresolved.as_slice(),
                [
                    UnresolvedPassword::NoVarStore { reason: undecoded, .. },
                    UnresolvedPassword::MalformedVarStoreOutsideFormSet { reason, .. },
                ] if undecoded.starts_with("failed to parse VarStore's data: ")
                    && reason.starts_with("a malformed EFI_IFR_VARSTORE in the scope of an unknown opcode: ")
            ),
            "{:?}",
            passwords.unresolved
        );
        assert!(
            passwords
                .withheld(&reaching(VariableReach::BootServices))
                .is_err(),
            "withheld through BootServices"
        );
        assert_eq!(
            passwords
                .withheld(&reaching(VariableReach::Runtime))
                .map_err(|error| error.to_string()),
            Ok(want),
            "withheld through Runtime"
        );
    }

    /// A VARSTORE_NAME_VALUE in the scope of an unknown opcode, before the FormSet of a PASSWORD
    /// of its VarStoreId, is the first VarStore of that id in the form package, which
    /// FindStorageFromVarId takes for that PASSWORD, and only its driver holds its values, in any
    /// variable, so the PASSWORD is unresolved and driver-held: variables that read anything, of
    /// either reach, fail closed; those that read nothing withhold its bytes in the VarStore of
    /// its FormSet.
    #[test]
    fn a_name_value_var_store_in_an_unknown_scope_of_a_password_s_id_leaves_it_unresolved() {
        let passwords = passwords_of(&[
            form_set(&[
                in_unknown_scope(&var_store_name_value(2, OTHER_GUID)),
                form(1, &[]),
            ]),
            form_set_with(&[password_on(2, 3, 2, 0)]),
        ]);
        let mut want = WithheldBytes::default();
        want.insert(amitse_setup(), 0..40);
        let refusal = passwords
            .unresolved
            .first()
            .map(|unresolved| format!("{unresolved}{ANY_VARIABLE}"));
        let unread = UnreadVariables {
            reach: VariableReach::Runtime,
            interface: VariableInterface::Efivarfs,
        };

        assert_eq!(passwords.driver_held, passwords.unresolved, "driver-held");
        assert!(
            matches!(
                passwords.unresolved.as_slice(),
                [UnresolvedPassword::NameValueOutsideFormSet {
                    place: OutsidePlace::UnknownScope,
                    ..
                }]
            ),
            "unresolved {:?}",
            passwords.unresolved
        );
        assert!(
            passwords
                .withheld(&reaching(VariableReach::BootServices))
                .is_err(),
            "withheld through BootServices"
        );
        assert_eq!(
            passwords
                .withheld(&reaching(VariableReach::Runtime))
                .map_err(|error| Some(error.to_string())),
            Err(refusal),
            "withheld through Runtime"
        );
        assert_eq!(
            passwords
                .withheld(&unread)
                .map_err(|error| error.to_string()),
            Ok(want),
            "withheld through variables that read nothing"
        );
    }

    /// A VARSTORE_EFI before UEFI 2.3.1 in the scope of an unknown opcode names no variable, as
    /// one outside any FormSet does not, so a PASSWORD of a FormSet of its VarStoreId, which
    /// FindStorageFromVarId may send to its driver, is unresolved: through variables that reach
    /// BootServices it fails closed; through those that reach Runtime its bytes in the VarStore
    /// of its FormSet are withheld, and from byte 0 of the variable of the store's Guid that its
    /// VarName names, "!" here, as no string holds it (edk2-stable202608
    /// SetupBrowserDxe/Setup.c GetToken takes "!" for a missing string, :65, :1071).
    #[test]
    fn a_short_var_store_in_an_unknown_scope_of_a_password_s_id_leaves_it_unresolved() {
        let passwords = passwords_of(&[
            form_set(&[in_unknown_scope(&short_var_store_efi(2)), form(1, &[])]),
            form_set_with(&[password_on(2, 3, 2, 0)]),
        ]);
        let mut want = WithheldBytes::default();
        want.insert(amitse_setup(), 0..40);
        want.insert(
            VariableKey {
                name: "!".to_string(),
                guid: Guid::from(SHORT_VAR_STORE_GUID),
            },
            0..40,
        );

        assert!(
            matches!(
                passwords.unresolved.as_slice(),
                [UnresolvedPassword::ShortVarStoreEfiOutsideFormSet {
                    place: OutsidePlace::UnknownScope,
                    ..
                }]
            ),
            "unresolved {:?}",
            passwords.unresolved
        );
        assert!(
            passwords
                .withheld(&reaching(VariableReach::BootServices))
                .is_err(),
            "withheld through BootServices"
        );
        assert_eq!(
            passwords
                .withheld(&reaching(VariableReach::Runtime))
                .map_err(|error| error.to_string()),
            Ok(want),
            "withheld through Runtime"
        );
    }

    /// The IFR that read_db ignores starts at the FORM_SET op of a FormSet that it ignores, or of
    /// one without its Scope bit: a VarStore outside any FormSet before that op, of the VarStoreId
    /// of a PASSWORD of a FormSet, keeps that password at its VarOffset, as any VarStore outside a
    /// FormSet does, and is not withheld whole, through variables that reach Runtime.
    #[test]
    fn an_outside_var_store_before_ignored_ifr_keeps_a_password_at_its_var_offset() {
        let mut want = WithheldBytes::default();
        want.insert(amitse_setup(), 0..40);
        want.insert(shadow(), 0..40);
        for (case, ignored) in [
            ("an ignored FormSet", ignored_form_set(&[form(1, &[])])),
            (
                "a FormSet without its Scope bit",
                scopeless_form_set(&[form(1, &[])]),
            ),
        ] {
            let ifr = [
                var_store(2, OTHER_GUID, "Shadow", 81),
                ignored,
                form_set_with(&[password_on(2, 3, 2, 0)]),
            ];

            assert_eq!(
                withheld_of(&ifr, VariableReach::Runtime),
                Ok(want.clone()),
                "before {case}"
            );
        }
    }

    /// A FORM_SET op without its Scope bit in a FormSet that read_db ignores, which it ignores too,
    /// makes the IFR from the outer FORM_SET op on ignored up to the end of the walk, past the outer
    /// FormSet's End, as edk2 parses a FormSet without Scope to the end of the form package: a
    /// VarStore after that End, of the VarStoreId of a PASSWORD of a FormSet, is withheld whole
    /// through variables that reach Runtime, and so is each variable that the FormSet after it
    /// declares.
    #[test]
    fn the_ifr_of_a_form_set_without_its_scope_bit_in_an_ignored_one_runs_past_its_end() {
        let ifr = [
            ignored_form_set(&[scopeless_form_set(&[])]),
            var_store(2, OTHER_GUID, "Shadow", 81),
            form_set_with(&[password_on(2, 3, 2, 0)]),
        ];
        let withheld = withheld_of(&ifr, VariableReach::Runtime).expect("withheld through Runtime");

        for key in [setup(), amitse_setup(), shadow()] {
            let bytes: Vec<&Range<usize>> = withheld.of(&key).collect();
            assert!(
                bytes.contains(&&(0..usize::MAX)),
                "{} withheld whole: {bytes:?}",
                key.name
            );
        }
    }

    /// A password_on question of `key` at byte 0: MaxSize 20.
    fn password_at_0(key: VariableKey) -> PasswordQuestion {
        PasswordQuestion {
            key,
            offset: 0,
            max_size: Some(20),
        }
    }

    /// `body` in the scope of an op above EFI_IFR_MATCH2_OP, which edk2's ParseOpCodes skips
    /// (IsUnKnownOpCode).
    fn in_unknown_op(body: &[u8]) -> Vec<u8> {
        nested(&operation(0x70, true, &[]), 1, &[body.to_vec()])
    }

    /// The variable that find_corresponding_varstore finds for a CHECKBOX of VarStoreId 2 in the
    /// form of a FormSet whose `declarations` come before that form, or why it finds none.
    fn checkbox_store(declarations: &[Vec<u8>]) -> Result<VariableKey, String> {
        let root = parse_form_set(&[declarations.concat(), form(1, &[checkbox_on(1, 3, 2)])]);
        let mut checkbox = None;
        walk_scopes(std::slice::from_ref(&root), (), |node, ()| {
            if node.borrow().op_code == IFROpCode::CheckBox {
                checkbox = Some(Rc::clone(node));
            }
            Walk::Enter(())
        });
        find_corresponding_varstore(checkbox.expect("the CHECKBOX"), 2)
            .map(|store| store.variable_key())
            .map_err(|error| error.to_string())
    }

    /// A VarStore under a SUPPRESS_IF of the FormSet, or a DISABLE_IF of it whose constant
    /// condition is FALSE, declares its VarStoreId: UEFI 2.11 §33.2.5.1's form-set-list admits
    /// both, and edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes creates such a store
    /// (CreateStorage).
    #[test]
    fn a_question_finds_its_var_store_under_a_form_set_suppress_if_or_false_disable_if() {
        let amitse = var_store(2, TSE_GUID, "AMITSESetup", 81);
        for (case, declarations) in [
            (
                "SUPPRESS_IF TRUE",
                vec![conditional(
                    SUPPRESS_IF,
                    ifr_true(),
                    std::slice::from_ref(&amitse),
                )],
            ),
            (
                "DISABLE_IF FALSE",
                vec![conditional(
                    DISABLE_IF,
                    ifr_false(),
                    std::slice::from_ref(&amitse),
                )],
            ),
            (
                "DISABLE_IF FALSE in a SUPPRESS_IF",
                vec![conditional(
                    SUPPRESS_IF,
                    ifr_false(),
                    &[conditional(
                        DISABLE_IF,
                        ifr_false(),
                        std::slice::from_ref(&amitse),
                    )],
                )],
            ),
        ] {
            assert_eq!(checkbox_store(&declarations), Ok(amitse_setup()), "{case}");
        }
    }

    /// A VarStore in a form is outside the form-set-list where UEFI 2.11 §33.2.5.1 and VfrCompile
    /// declare VarStores: no store of its questions, though edk2's ParseOpCodes creates one there.
    /// Nor is one in the scope of an unknown op, which ParseOpCodes skips (IsUnKnownOpCode).
    #[test]
    fn a_var_store_in_a_form_or_an_unknown_op_is_no_store() {
        let amitse = var_store(2, TSE_GUID, "AMITSESetup", 81);
        for (case, declaration) in [
            ("a form", form(2, std::slice::from_ref(&amitse))),
            (
                "a form map",
                form_map(&[(1, STANDARD_FORM_GUID)], std::slice::from_ref(&amitse)),
            ),
            ("an unknown op", in_unknown_op(&amitse)),
        ] {
            assert_eq!(
                checkbox_store(&[declaration]),
                Err("no supported varstore with matching id 0x0002 found".to_owned()),
                "{case}"
            );
        }
    }

    /// Of two declarations of a VarStoreId under DISABLE_IFs of the FormSet, a question takes the
    /// one that edk2 creates, whose constant condition is FALSE: ParseOpCodes skips the scope of
    /// one whose condition is TRUE (IfrParse.c:1392, :3045-3059).
    #[test]
    fn a_form_set_disable_if_picks_the_var_store_that_edk2_creates() {
        let variants = [
            conditional(
                DISABLE_IF,
                ifr_true(),
                &[var_store(2, OTHER_GUID, "Shadow", 81)],
            ),
            conditional(
                DISABLE_IF,
                ifr_false(),
                &[var_store(2, TSE_GUID, "AMITSESetup", 81)],
            ),
        ];
        assert_eq!(checkbox_store(&variants), Ok(amitse_setup()));
    }

    /// A VarStore only under a DISABLE_IF of the FormSet whose constant condition is TRUE is no
    /// store of its questions, as edk2 creates none.
    #[test]
    fn a_var_store_under_a_true_form_set_disable_if_is_no_store() {
        let refusal = checkbox_store(&[conditional(
            DISABLE_IF,
            ifr_true(),
            &[var_store(2, TSE_GUID, "AMITSESetup", 81)],
        )]);
        assert_eq!(
            refusal,
            Err("no supported varstore with matching id 0x0002 found".to_owned())
        );
    }

    /// A GET or SET of the UINT8 at VarOffset 0 of VarStore `id`.
    fn store_op(op_code: u8, id: u16) -> Vec<u8> {
        let data = [
            &id.to_le_bytes()[..],
            &0u16.to_le_bytes(),
            &[EFI_IFR_TYPE_NUM_SIZE_8],
        ]
        .concat();
        operation(op_code, false, &data)
    }

    /// A DISABLE_IF of the FormSet whose condition relies on a question or a VarStore, where UEFI
    /// 2.11 §33.3.8.3.14 allows only constants, leaves a VarStore under it undetermined, whichever
    /// op it relies on: no store, with that reason. The GET and SET are of the VarStore Shadow.
    #[test]
    fn a_var_store_under_a_form_set_disable_if_that_is_not_constant_is_undetermined() {
        const EQ_ID_ID: u8 = 0x13;
        const EQ_ID_VAL_LIST: u8 = 0x14;
        const GET: u8 = 0x2B;
        const SET: u8 = 0x2C;
        const THIS: u8 = 0x58;
        let cases = [
            ("EQ_ID_VAL", "EQ_ID_VAL", eq_id_val_of(1, 0)),
            (
                "EQ_ID_ID",
                "EQ_ID_ID",
                operation(EQ_ID_ID, false, &[1, 0, 1, 0]),
            ),
            (
                "EQ_ID_VAL_LIST",
                "EQ_ID_VAL_LIST",
                operation(EQ_ID_VAL_LIST, false, &[1, 0, 1, 0, 0, 0]),
            ),
            (
                "QUESTION_REF1",
                "QUESTION_REF1",
                operation(QUESTION_REF1, false, &[1, 0]),
            ),
            ("THIS", "THIS", operation(THIS, false, &[])),
            ("GET", "GET", store_op(GET, 5)),
            ("SET", "SET", [uint8(1), store_op(SET, 5)].concat()),
            (
                "GET in the scope of the expression's first op",
                "GET",
                scoped_expression(
                    &[uint8(1), store_op(GET, 5), operation(EQUAL, false, &[])],
                    0,
                ),
            ),
        ];
        for (case, name, condition) in cases {
            let refusal = checkbox_store(&[
                var_store(5, OTHER_GUID, "Shadow", 81),
                conditional(
                    DISABLE_IF,
                    condition,
                    &[var_store(2, TSE_GUID, "AMITSESetup", 81)],
                ),
            ]);
            let want = format!(
                "it relies on EFI_IFR_{name}, where a DISABLE_IF outside forms must only rely on \
                 constants"
            );
            assert!(
                matches!(&refusal, Err(reason) if reason.contains(&want)),
                "{case}: {refusal:?}"
            );
        }
    }

    /// A DISABLE_IF of the FormSet whose condition is TRUE hides the VarStores in its scope
    /// whatever the conditions of the DISABLE_IFs inside it, which edk2's ParseOpCodes never
    /// evaluates (IfrParse.c:1390-1413), and whatever those around it: a question takes the
    /// VarStore of its id under the DISABLE_IF FALSE after it.
    #[test]
    fn a_true_form_set_disable_if_hides_its_var_stores_whatever_the_other_conditions() {
        let hidden = [var_store(2, OTHER_GUID, "Shadow", 81)];
        let cases = [
            (
                "TRUE around one not known",
                conditional(
                    DISABLE_IF,
                    ifr_true(),
                    &[conditional(DISABLE_IF, eq_id_val_of(1, 0), &hidden)],
                ),
            ),
            (
                "one not known around TRUE",
                conditional(
                    DISABLE_IF,
                    eq_id_val_of(1, 0),
                    &[conditional(DISABLE_IF, ifr_true(), &hidden)],
                ),
            ),
        ];
        for (case, declaration) in cases {
            let store = checkbox_store(&[
                declaration,
                conditional(
                    DISABLE_IF,
                    ifr_false(),
                    &[var_store(2, TSE_GUID, "AMITSESetup", 81)],
                ),
            ]);
            assert_eq!(store, Ok(amitse_setup()), "{case}");
        }
    }

    /// A PASSWORD whose VarStore a SUPPRESS_IF of the FormSet declares withholds its bytes there,
    /// instead of failing closed for the whole HiiDB.
    #[test]
    fn a_password_on_a_var_store_under_a_form_set_suppress_if_is_withheld() {
        let found = PasswordQuestions::of([&parse_form_set(&[
            conditional(
                SUPPRESS_IF,
                ifr_true(),
                &[var_store(2, TSE_GUID, "AMITSESetup", 81)],
            ),
            form(1, &[password_on(2, 3, 2, 0)]),
        ])]);
        assert_eq!(
            (found.questions, found.unresolved),
            (vec![password_at_0(amitse_setup())], vec![])
        );
    }

    /// A PASSWORD withholds its bytes in every VarStore of its VarStoreId in its FormSet, under
    /// DISABLE_IFs whatever their conditions, TRUE, FALSE or not known, in a form or an unknown op:
    /// edk2's Config Keyword Handler takes the first VarStore of the id in the form package
    /// (ConfigKeywordHandler.c FindStorageFromVarId), whatever the scopes around it, so a
    /// condition never opens one.
    #[test]
    fn a_password_withholds_every_var_store_of_its_id_whatever_the_scopes() {
        let amitse = var_store(2, TSE_GUID, "AMITSESetup", 81);
        let shadow_store = var_store(2, OTHER_GUID, "Shadow", 81);
        for (case, declarations, want) in [
            (
                "TRUE",
                vec![conditional(
                    DISABLE_IF,
                    ifr_true(),
                    std::slice::from_ref(&amitse),
                )],
                vec![amitse_setup()],
            ),
            (
                "not constant",
                vec![conditional(
                    DISABLE_IF,
                    eq_id_val_of(1, 0),
                    std::slice::from_ref(&amitse),
                )],
                vec![amitse_setup()],
            ),
            (
                "TRUE then FALSE",
                vec![
                    conditional(DISABLE_IF, ifr_true(), std::slice::from_ref(&shadow_store)),
                    conditional(DISABLE_IF, ifr_false(), std::slice::from_ref(&amitse)),
                ],
                vec![shadow(), amitse_setup()],
            ),
            (
                "in a form",
                vec![form(2, std::slice::from_ref(&amitse))],
                vec![amitse_setup()],
            ),
            (
                "in an unknown op, then created",
                vec![in_unknown_op(&shadow_store), amitse.clone()],
                vec![shadow(), amitse_setup()],
            ),
        ] {
            let found = PasswordQuestions::of([&parse_form_set(&[
                declarations.concat(),
                form(1, &[password_on(2, 3, 2, 0)]),
            ])]);
            let mut withheld = WithheldBytes::default();
            for key in want {
                withheld.insert(key, 0..40);
            }
            assert_eq!(found.unresolved, vec![], "{case}: unresolved");
            assert_eq!(
                found
                    .withheld(&reaching(VariableReach::BootServices))
                    .map_err(|error| error.to_string()),
                Ok(withheld),
                "{case}: withheld"
            );
        }
    }

    /// A VarStore op in the scope of an unknown op that does not decode may be of a PASSWORD's
    /// VarStoreId, so the PASSWORD is unresolved, whatever other VarStore of its id it has.
    #[test]
    fn an_undecoded_var_store_in_an_unknown_op_leaves_a_password_unresolved() {
        let found = PasswordQuestions::of([&parse_form_set(&[
            in_unknown_op(&operation(VAR_STORE, false, &[0x00; 3])),
            var_store(2, TSE_GUID, "AMITSESetup", 81),
            form(1, &[password_on(2, 3, 2, 0)]),
        ])]);
        assert_eq!(found.questions, vec![password_at_0(amitse_setup())]);
        assert!(
            matches!(
                found.unresolved.as_slice(),
                [UnresolvedPassword::NoVarStore { question_id: 2, reason, .. }]
                    if reason.contains("VarStore's data")
            ),
            "{:?}",
            found.unresolved
        );
    }

    /// A VarStore of a PASSWORD's VarStoreId whose EFI variable uefisettings does not know, a
    /// short VARSTORE_EFI or a VARSTORE_NAME_VALUE, leaves the PASSWORD unresolved wherever it
    /// sits, here under a DISABLE_IF TRUE, without dropping the VarStore of the id under a
    /// DISABLE_IF FALSE: a CHECKBOX takes that one, and every reach withholds it. Through
    /// BootServices, the HiiDB of this legal VFR variant is refused, and through Runtime too
    /// beside the VARSTORE_NAME_VALUE, whose driver may keep the password in any variable.
    #[test]
    fn a_store_of_an_unknown_variable_leaves_a_password_unresolved_beside_a_known_one() {
        let cases = [
            (
                "short VARSTORE_EFI",
                short_var_store_efi(2),
                "VarStore 0x0002 (EFI_IFR_VARSTORE_EFI before UEFI 2.3.1): no string 0x0000 \
                 holds its VarName",
                vec![short_variable("!")],
                Keeper::Ifr,
            ),
            (
                "VARSTORE_NAME_VALUE",
                var_store_name_value(2, [0x66; 16]),
                "HII name/value varstore requires EFI_HII_CONFIG_ACCESS_PROTOCOL",
                vec![],
                Keeper::NameValueDriver,
            ),
        ];
        for (case, unknown, reason, candidates, keeper) in cases {
            let declarations = [
                conditional(DISABLE_IF, ifr_true(), &[unknown]),
                conditional(
                    DISABLE_IF,
                    ifr_false(),
                    &[var_store(2, TSE_GUID, "AMITSESetup", 81)],
                ),
            ];
            assert_eq!(
                checkbox_store(&declarations),
                Ok(amitse_setup()),
                "{case}: CHECKBOX"
            );

            let found = PasswordQuestions::of([&parse_form_set(&[
                declarations.concat(),
                form(1, &[password_on(2, 3, 2, 0)]),
            ])]);

            assert_eq!(
                found.questions,
                vec![password_at_0(amitse_setup())],
                "{case}: questions"
            );
            assert!(
                matches!(
                    found.unresolved.as_slice(),
                    [UnresolvedPassword::NoVarStore { question_id: 2, reason: got, .. }]
                        if got.contains(reason)
                ),
                "{case}: {:?}",
                found.unresolved
            );
            assert!(
                found
                    .withheld(&reaching(VariableReach::BootServices))
                    .is_err(),
                "{case}: BootServices"
            );
            let mut known = WithheldBytes::default();
            known.insert(amitse_setup(), 0..40);
            for candidate in candidates {
                known.insert(candidate, 0..40);
            }
            let runtime = match keeper {
                Keeper::Ifr => Ok(known),
                Keeper::NameValueDriver => Err(found
                    .unresolved
                    .iter()
                    .map(|unresolved| format!("{unresolved}{ANY_VARIABLE}"))
                    .collect()),
            };
            assert_eq!(
                found
                    .withheld(&reaching(VariableReach::Runtime))
                    .map_err(|error| error.to_string()),
                runtime,
                "{case}: Runtime"
            );
        }
    }

    /// edk2's ParseOpCodes creates a VarStore in a FORM or FORM_MAP too (IfrParse.c:1873-1884,
    /// :477), and CreateQuestion binds a question to the first store of its id (:136-145): a
    /// VarStore of the id in a FORM or FORM_MAP before the one of the form-set-list refuses the
    /// lookup, and one after it leaves the question on the one of the form-set-list.
    #[test]
    fn a_var_store_in_a_form_before_the_form_set_list_one_refuses_the_lookup() {
        let shadow_store = || var_store(2, OTHER_GUID, "Shadow", 81);
        let amitse = || var_store(2, TSE_GUID, "AMITSESetup", 81);
        for (op, form_op) in [
            ("EFI_IFR_FORM", form(2, &[shadow_store()])),
            (
                "EFI_IFR_FORM_MAP",
                form_map(&[(1, STANDARD_FORM_GUID)], &[shadow_store()]),
            ),
        ] {
            let refusal = checkbox_store(&[form_op.clone(), amitse()]);
            let want = format!(
                "VarStore 0x0002 is declared in an {op} of its FormSet before the one of its \
                 form-set-list"
            );
            assert!(
                matches!(&refusal, Err(reason) if reason.contains(&want)),
                "{op} first: {refusal:?}"
            );
            assert_eq!(
                checkbox_store(&[amitse(), form_op]),
                Ok(amitse_setup()),
                "{op} after"
            );
        }
    }

    /// A question takes the first VarStore of its id in IFR order that edk2 creates: a TRUE
    /// DISABLE_IF hides its scope inside a FALSE one; of two created, the first; an undetermined
    /// one before the created one refuses the lookup, after it changes nothing; and of nested
    /// DISABLE_IFs whose conditions are not known, the outermost gives the reason.
    #[test]
    fn a_question_takes_the_first_var_store_of_its_id_that_edk2_creates() {
        let shadow_store = || var_store(2, OTHER_GUID, "Shadow", 81);
        let amitse = || var_store(2, TSE_GUID, "AMITSESetup", 81);
        let eq_id_val_reason = "it relies on EFI_IFR_EQ_ID_VAL";
        let cases = [
            (
                "DISABLE_IF FALSE around DISABLE_IF TRUE, then created",
                vec![
                    conditional(
                        DISABLE_IF,
                        ifr_false(),
                        &[conditional(DISABLE_IF, ifr_true(), &[shadow_store()])],
                    ),
                    amitse(),
                ],
                Ok(amitse_setup()),
            ),
            (
                "two created",
                vec![amitse(), shadow_store()],
                Ok(amitse_setup()),
            ),
            (
                "not known, then DISABLE_IF FALSE",
                vec![
                    conditional(DISABLE_IF, eq_id_val_of(1, 0), &[shadow_store()]),
                    conditional(DISABLE_IF, ifr_false(), &[amitse()]),
                ],
                Err(eq_id_val_reason),
            ),
            (
                "created, then not known",
                vec![
                    amitse(),
                    conditional(DISABLE_IF, eq_id_val_of(1, 0), &[shadow_store()]),
                ],
                Ok(amitse_setup()),
            ),
            (
                "EQ_ID_VAL around QUESTION_REF1",
                vec![conditional(
                    DISABLE_IF,
                    eq_id_val_of(1, 0),
                    &[conditional(
                        DISABLE_IF,
                        operation(QUESTION_REF1, false, &[1, 0]),
                        &[shadow_store()],
                    )],
                )],
                Err(eq_id_val_reason),
            ),
        ];
        for (case, declarations, want) in cases {
            let store = checkbox_store(&declarations);
            match want {
                Ok(key) => assert_eq!(store, Ok(key), "{case}"),
                Err(reason) => assert!(
                    matches!(&store, Err(got) if got.contains(reason)),
                    "{case}: {store:?}"
                ),
            }
        }
    }

    /// edk2's ParseOpCodes takes the condition of a SUPPRESS_IF or GRAY_OUT_IF of the
    /// form-set-list in the scope of a DISABLE_IF for that DISABLE_IF's (IfrParse.c:1690-1704,
    /// :3045-3059), so a TRUE one skips the rest of the DISABLE_IF's scope (:1390-1413), where UEFI
    /// 2.11 §33.3.8.3.75 has it only hide: a VarStore after one whose condition is TRUE or not
    /// known, around it or before it in that scope, is refused, and one after a FALSE one, or
    /// under a SUPPRESS_IF outside any DISABLE_IF, is taken. Each PASSWORD of the id withholds its
    /// bytes in every VarStore of the id all the same.
    #[test]
    fn a_form_set_suppress_if_in_a_disable_if_leaves_the_var_stores_after_it_undetermined() {
        let shadow_store = || var_store(2, OTHER_GUID, "Shadow", 81);
        let in_disable_if = |body: &[Vec<u8>]| conditional(DISABLE_IF, ifr_false(), body);
        let suppressed =
            |condition: Vec<u8>| conditional(SUPPRESS_IF, condition, &[shadow_store()]);
        let after_true = "follows an EFI_IFR_SUPPRESS_IF in the scope of a DISABLE_IF of its \
                          FormSet, whose condition is TRUE";
        let cases = [
            (
                "DISABLE_IF FALSE { SUPPRESS_IF TRUE { Shadow } }",
                in_disable_if(&[suppressed(ifr_true())]),
                Err(after_true),
            ),
            (
                "DISABLE_IF FALSE { SUPPRESS_IF TRUE {} Shadow }",
                in_disable_if(&[conditional(SUPPRESS_IF, ifr_true(), &[]), shadow_store()]),
                Err(after_true),
            ),
            (
                "DISABLE_IF FALSE { SUPPRESS_IF eq_id_val { Shadow } }",
                in_disable_if(&[suppressed(eq_id_val_of(1, 0))]),
                Err("whose condition is not known: it relies on EFI_IFR_EQ_ID_VAL"),
            ),
            (
                "DISABLE_IF FALSE { GRAY_OUT_IF TRUE { Shadow } }",
                in_disable_if(&[conditional(GRAY_OUT_IF, ifr_true(), &[shadow_store()])]),
                Err("follows an EFI_IFR_GRAY_OUT_IF in the scope of a DISABLE_IF"),
            ),
            (
                "DISABLE_IF FALSE { SUPPRESS_IF FALSE { Shadow } }",
                in_disable_if(&[suppressed(ifr_false())]),
                Ok(shadow()),
            ),
            (
                "SUPPRESS_IF TRUE { Shadow }",
                suppressed(ifr_true()),
                Ok(shadow()),
            ),
            (
                "SUPPRESS_IF TRUE { DISABLE_IF FALSE { Shadow } }",
                conditional(SUPPRESS_IF, ifr_true(), &[in_disable_if(&[shadow_store()])]),
                Ok(shadow()),
            ),
        ];
        for (case, declaration, want) in cases {
            let declarations = [declaration, var_store(2, TSE_GUID, "AMITSESetup", 81)];
            let store = checkbox_store(&declarations);
            match want {
                Ok(key) => assert_eq!(store, Ok(key), "{case}"),
                Err(reason) => assert!(
                    matches!(&store, Err(got) if got.contains(reason)),
                    "{case}: {store:?}"
                ),
            }

            let found = PasswordQuestions::of([&parse_form_set(&[
                declarations.concat(),
                form(1, &[password_on(2, 3, 2, 0)]),
            ])]);
            let mut withheld = WithheldBytes::default();
            withheld.insert(shadow(), 0..40);
            withheld.insert(amitse_setup(), 0..40);
            assert_eq!(
                found
                    .withheld(&reaching(VariableReach::BootServices))
                    .map_err(|error| error.to_string()),
                Ok(withheld),
                "{case}: withheld"
            );
        }
    }

    /// A PASSWORD on a VARSTORE_EFI before UEFI 2.3.1 that a SUPPRESS_IF of its FormSet declares
    /// keeps its password from byte 0 of the variable that its VarStoreInfo names as a VarName, as
    /// form_set_varstore takes it: bytes 0..40 of it are withheld, through variables of either
    /// reach, whatever the string ID of its VarName.
    #[test]
    fn a_password_on_a_short_var_store_under_a_form_set_suppress_if_withholds_its_var_name() {
        for (var_name, name) in [(5, "ShortVarPw"), (1, "Q")] {
            let ifr = [form_set(&[
                conditional(SUPPRESS_IF, ifr_true(), &[short_var_store_efi(7)]),
                form(1, &[password_on(2, 3, 7, var_name)]),
            ])];
            let passwords =
                PasswordQuestions::of_lists(&[list_with_strings(&ifr, &VAR_NAME_STRINGS)]);
            let mut want = WithheldBytes::default();
            want.insert(short_variable(name), 0..40);

            for reach in [VariableReach::Runtime, VariableReach::BootServices] {
                assert_eq!(
                    passwords
                        .withheld(&reaching(reach))
                        .map_err(|error| error.to_string()),
                    Ok(want.clone()),
                    "VarName {var_name}, {reach:?}"
                );
            }
        }
    }

    /// A PASSWORD on the VarStoreId of a VARSTORE_EFI before UEFI 2.3.1 that edk2 does not
    /// create, under a DISABLE_IF TRUE, beside a VARSTORE of that id that a question takes, keeps
    /// its password from byte 0 of the variable that its VarName names on the first, which
    /// FindStorageFromVarId may take, and at its VarOffset in the second: both are withheld,
    /// through variables of either reach.
    #[test]
    fn a_password_on_the_id_of_a_short_var_store_that_edk2_skips_withholds_its_var_name() {
        let ifr = [form_set(&[
            conditional(DISABLE_IF, ifr_true(), &[short_var_store_efi(7)]),
            var_store(7, OTHER_GUID, "Shadow", 81),
            form(1, &[password_on(2, 3, 7, 5)]),
        ])];
        let passwords = PasswordQuestions::of_lists(&[list_with_strings(&ifr, &VAR_NAME_STRINGS)]);
        let mut want = WithheldBytes::default();
        want.insert(short_variable("ShortVarPw"), 0..40);
        want.insert(shadow(), 5..45);

        for reach in [VariableReach::Runtime, VariableReach::BootServices] {
            assert_eq!(
                passwords
                    .withheld(&reaching(reach))
                    .map_err(|error| error.to_string()),
                Ok(want.clone()),
                "{reach:?}"
            );
        }
    }

    /// A PASSWORD whose VarStore a SUPPRESS_IF of its FormSet declares, of a VarStoreId that a
    /// VARSTORE outside any FormSet declares too, withholds its bytes in both, through variables of
    /// either reach; beside a VARSTORE_NAME_VALUE of the id outside any FormSet instead, it is
    /// unresolved, and its driver may keep the password in any variable, so either reach refuses.
    #[test]
    fn a_password_on_a_var_store_under_a_suppress_if_keeps_the_stores_outside_any_form_set() {
        let suppressed_store = || {
            form_set(&[
                conditional(
                    SUPPRESS_IF,
                    ifr_true(),
                    &[var_store(2, TSE_GUID, "AMITSESetup", 81)],
                ),
                form(1, &[password_on(2, 3, 2, 0)]),
            ])
        };
        let mut both = WithheldBytes::default();
        both.insert(shadow(), 0..40);
        both.insert(amitse_setup(), 0..40);
        for reach in [VariableReach::Runtime, VariableReach::BootServices] {
            assert_eq!(
                withheld_of(
                    &[var_store(2, OTHER_GUID, "Shadow", 81), suppressed_store()],
                    reach
                ),
                Ok(both.clone()),
                "an outside VARSTORE, {reach:?}"
            );
        }

        let ifr = [var_store_name_value(2, OTHER_GUID), suppressed_store()];
        assert!(
            withheld_of(&ifr, VariableReach::Runtime)
                .is_err_and(|refusal| refusal.ends_with(ANY_VARIABLE)),
            "an outside VARSTORE_NAME_VALUE, Runtime"
        );
        assert!(
            withheld_of(&ifr, VariableReach::BootServices).is_err(),
            "an outside VARSTORE_NAME_VALUE, BootServices"
        );
    }

    /// The lookup of a VarStore evaluates each DISABLE_IF of the form-set-list once, and none in
    /// the scope of a TRUE one: 250 nested DISABLE_IF FALSE holding 400 DISABLE_IF TRUE, each
    /// around a VarStore of the id, then a created one, cost 650 evaluations, not one for each
    /// DISABLE_IF around each VarStore of the id.
    #[test]
    fn a_var_store_lookup_evaluates_each_form_set_condition_once() {
        let mut body = [
            vec![
                conditional(
                    DISABLE_IF,
                    ifr_true(),
                    &[var_store(2, OTHER_GUID, "Shadow", 81)]
                );
                400
            ],
            vec![var_store(2, TSE_GUID, "AMITSESetup", 81)],
        ]
        .concat()
        .concat();
        for _ in 0..250 {
            body = conditional(DISABLE_IF, ifr_false(), &[body]);
        }
        let root = parse_form_set(&[body, form(1, &[checkbox_on(1, 3, 2)])]);
        let mut checkbox = None;
        walk_scopes(std::slice::from_ref(&root), (), |node, ()| {
            if node.borrow().op_code == IFROpCode::CheckBox {
                checkbox = Some(Rc::clone(node));
            }
            Walk::Enter(())
        });

        let before = CONSTANT_CONDITIONS.with(Cell::get);
        let store = find_corresponding_varstore(checkbox.expect("the CHECKBOX"), 2)
            .map(|store| store.variable_key());
        let evaluated = CONSTANT_CONDITIONS.with(Cell::get) - before;

        assert_eq!(store.map_err(|error| error.to_string()), Ok(amitse_setup()));
        assert!(evaluated <= 650, "conditions evaluated: {evaluated}");
    }

    /// A CHECKBOX that a malformed op after it disables its form (UEFI 2.11 §33.2.5.10.1).
    fn short_checkbox() -> Vec<u8> {
        operation(CHECKBOX, false, &[0x00])
    }

    /// A VarStore op of the id in a form that read_db disables leaves the tree, so its place among
    /// the others is unknown, and edk2-stable202608 SetupBrowserDxe/IfrParse.c, which disables no
    /// form, creates it all the same: the lookup is refused, the form before or after the
    /// form-set-list store. A disabled form without a VarStore of the id changes nothing.
    #[test]
    fn a_var_store_in_a_disabled_form_refuses_the_lookup() {
        let disabled_with = |store: Vec<u8>| form(2, &[store, short_checkbox()]);
        let amitse = var_store(2, TSE_GUID, "AMITSESetup", 81);
        let disabled = disabled_with(var_store(2, OTHER_GUID, "Shadow", 81));
        let refused = "VarStore 0x0002 is declared in a form of its FormSet that uefisettings \
                       disables, before or after the one of its form-set-list";
        for (case, declarations) in [
            (
                "disabled form first",
                vec![disabled.clone(), amitse.clone()],
            ),
            (
                "disabled form after",
                vec![amitse.clone(), disabled.clone()],
            ),
        ] {
            let store = checkbox_store(&declarations);
            assert!(
                matches!(&store, Err(reason) if reason.starts_with(refused)),
                "{case}: {store:?}"
            );
        }
        let other_id = disabled_with(var_store(3, OTHER_GUID, "Shadow", 81));
        assert_eq!(
            checkbox_store(&[other_id, amitse]),
            Ok(amitse_setup()),
            "a disabled form of another id"
        );
    }

    /// A PASSWORD whose VarStoreId only a form that read_db disables declares, before the op that
    /// disables it, keeps its password there: edk2, which disables no form, creates that store and
    /// binds the PASSWORD to it, so it is withheld through variables of either reach, the
    /// PASSWORD resolved.
    #[test]
    fn a_password_on_a_var_store_of_a_disabled_form_is_withheld_there() {
        let (root, disabled) = parse_form_set_dropping(&[
            form(
                2,
                &[var_store(2, OTHER_GUID, "Shadow", 81), short_checkbox()],
            ),
            form(1, &[password_on(2, 3, 2, 0)]),
        ]);
        assert_eq!(disabled.len(), 1, "form 2 disabled");
        let found = PasswordQuestions::of_forms(std::slice::from_ref(&root), &disabled);

        let mut want = WithheldBytes::default();
        want.insert(shadow(), 0..40);
        assert_eq!(found.unresolved, vec![], "unresolved");
        for reach in [VariableReach::Runtime, VariableReach::BootServices] {
            assert_eq!(
                found
                    .withheld(&reaching(reach))
                    .map_err(|error| error.to_string()),
                Ok(want.clone()),
                "{reach:?}"
            );
        }
    }

    /// A VarStore op in the scope of an unknown op that does not decode may be the VarStore of a
    /// PASSWORD of its FormSet of any VarStoreId, so every variable of its Guid, read from its op,
    /// is withheld whole, as for a VarStore of ignored IFR (DeclaredStorage), and every variable
    /// where its Guid runs past its Length; a PASSWORD of VarStoreId 0, which names no VarStore,
    /// withholds none of it.
    #[test]
    fn an_undecoded_var_store_in_an_unknown_op_withholds_its_guid_whole() {
        let guid_only = [&TSE_GUID[..], &2u16.to_le_bytes()].concat();
        let mut every = VariableGuids::default();
        every.insert(None);
        let mut tse = VariableGuids::default();
        tse.insert(Some(Guid::from(TSE_GUID)));
        let cases = [
            ("a Guid past its Length", vec![0x00; 3], 2, every),
            ("its Guid alone", guid_only, 2, tse),
            (
                "a PASSWORD of VarStoreId 0",
                vec![0x00; 3],
                0,
                VariableGuids::default(),
            ),
        ];
        for (case, data, var_store_id, guids) in cases {
            let found = PasswordQuestions::of([&parse_form_set(&[
                in_unknown_op(&operation(VAR_STORE, false, &data)),
                form(1, &[password_on(2, 3, var_store_id, 0)]),
            ])]);
            assert_eq!(
                found.storage,
                DeclaredStorage {
                    variables: BTreeSet::new(),
                    guids,
                    name_value: false,
                },
                "{case}"
            );
        }
    }

    /// A VarStore of a PASSWORD's VarStoreId in another FormSet of its package list is none of
    /// that PASSWORD's stores: a PASSWORD whose FormSet declares none of its id stays unresolved,
    /// so BootServices fails closed, and one whose FormSet declares one resolves.
    #[test]
    fn a_var_store_of_another_form_set_resolves_no_password() {
        let other = form_set_with_guid(
            [0x12; 16],
            &[var_store(2, OTHER_GUID, "Shadow", 81), form(1, &[])],
        );
        for (case, own, resolved) in [
            ("no VarStore of the id in its FormSet", vec![], false),
            (
                "its FormSet's VarStore of the id",
                vec![var_store(2, TSE_GUID, "AMITSESetup", 81)],
                true,
            ),
        ] {
            let password_form_set = form_set(&[own.concat(), form(1, &[password_on(2, 3, 2, 0)])]);
            let passwords = passwords_of(&[other.clone(), password_form_set]);

            assert_eq!(
                passwords.unresolved.is_empty(),
                resolved,
                "{case}: unresolved {:?}",
                passwords.unresolved
            );
            assert_eq!(
                passwords
                    .withheld(&reaching(VariableReach::BootServices))
                    .is_ok(),
                resolved,
                "{case}: BootServices"
            );
        }
    }

    /// read_db records with each form that it disables the index of the root of its FormSet, so
    /// that grouping them by FormSet searches no roots: over n FormSets in two form packages, each
    /// with a disabled form, that takes at most one step per disabled form in each of the two
    /// parses that collect it, each index names the root that holds its form, and each PASSWORD
    /// is withheld in the VarStore of its own FormSet, whether the disabled form holds the
    /// PASSWORD or the VarStore, and in the first VarStore of its id in its form package where
    /// another FormSet declares it (password_questions).
    #[test]
    fn disabled_forms_are_grouped_by_the_root_index_of_their_parse() {
        let name = |index: u16| format!("V{index}");
        for count in [2_000_u16, 16_000] {
            let form_sets: Vec<Vec<u8>> = (0..count)
                .map(|index| {
                    let store = var_store(2, OTHER_GUID, &name(index), 81);
                    let password = password_on(2, 3, 2, 0);
                    match index % 2 {
                        0 => form_set(&[store, form(1, &[password, short_checkbox()])]),
                        _ => form_set(&[form(2, &[store, short_checkbox()]), form(1, &[password])]),
                    }
                })
                .collect();
            let (first, second) = form_sets.split_at(usize::from(count / 2));
            let hiidb = package_list_with_guid(
                [0x22; 16],
                &[
                    form_package_of(&first.concat()),
                    form_package_of(&second.concat()),
                    END_PACKAGE.to_vec(),
                ]
                .concat(),
            );

            let before = ROOT_INDICES_SHIFTED.with(Cell::get);
            let list = read_db(&hiidb).expect("read_db").remove(0);
            let shifted = ROOT_INDICES_SHIFTED.with(Cell::get) - before;

            let disabled = list.disabled_forms.len();
            assert_eq!(disabled, usize::from(count), "{count}: disabled forms");
            assert!(
                shifted <= 2 * disabled,
                "{count}: root-index steps {shifted}, of {disabled} disabled forms"
            );
            for form in &list.disabled_forms {
                let top = std::iter::successors(Some(Rc::clone(&form.form)), |node| {
                    node.borrow()
                        .parent
                        .as_ref()
                        .and_then(std::rc::Weak::upgrade)
                })
                .last()
                .expect("the top of the form's tree");
                assert!(
                    list.forms
                        .get(form.root_index)
                        .is_some_and(|root| Rc::ptr_eq(root, &top)),
                    "{count}: the form at offset {} of root index {}",
                    form.offset,
                    form.root_index
                );
            }
            let passwords = PasswordQuestions::of_lists(std::slice::from_ref(&list));
            let key = |index: u16| VariableKey {
                name: name(index),
                guid: Guid::from(OTHER_GUID),
            };
            let mut want = WithheldBytes::default();
            for index in 0..count {
                want.insert(key(index), 0..40);
                // the first FormSet of each form package declares its first VarStore of id 2
                let first = if index < count / 2 { 0 } else { count / 2 };
                if index != first {
                    want.insert(key(first), 0..40);
                }
            }
            assert_eq!(passwords.unresolved, vec![], "{count}: unresolved");
            assert_eq!(
                passwords
                    .withheld(&reaching(VariableReach::BootServices))
                    .map_err(|error| error.to_string()),
                Ok(want),
                "{count}: withheld"
            );
        }
    }
}
