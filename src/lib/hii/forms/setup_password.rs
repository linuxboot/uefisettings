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
use super::find_corresponding_varstore;
use super::named_records;
use super::short_var_store_of;
use super::var_name_candidates;
use super::walk_scopes;
use super::DeclaredStorage;
use super::DeclaredStore;
use super::DisabledForm;
use super::IFROpCode;
use super::IFROperation;
use super::IgnoredPasswords;
use super::OutsideOp;
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

/// The bytes of a CHAR16
const CHAR16_SIZE: usize = std::mem::size_of::<u16>();

/// The PASSWORD questions of a HiiDB (UEFI 2.10 §33.3.8.3.54): whether it declares any, those
/// with a VarStore, the ops whose VarStore is unknown, and the variables that may hold their
/// passwords where they are known (candidate_questions).
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct PasswordQuestions {
    declared: bool,
    questions: Vec<PasswordQuestion>,
    /// Those that VarStores outside their FormSet hold, by VarStoreId of a package list
    shared: Vec<SharedPasswords>,
    unresolved: Vec<UnresolvedPassword>,
    candidates: Vec<PasswordQuestion>,
    /// The storage that IFR that read_db ignores, or a VarStore outside any FormSet that does not
    /// parse, may keep a password in anywhere (IgnoredPasswords::Declared), withheld whole
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

/// An EFI_IFR_PASSWORD after its op header (UEFI 2.11 §33.3.8.3.54): its question header and
/// MaxSize.
pub(super) struct PasswordOp {
    pub(super) question: QuestionHeader,
    pub(super) max_size: u16,
}

impl PasswordOp {
    /// The PASSWORD `op`, if it is one and holds its question header, MinSize and MaxSize.
    pub(super) fn of(op: &IFROperation) -> Option<Self> {
        match op.op_code {
            IFROpCode::Password => {
                let fields = PasswordFields::of(op).ok()?;
                Some(Self {
                    question: fields.question,
                    max_size: fields.max_size.ok()?,
                })
            }
            _ => None,
        }
    }
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
}

/// The bytes of the storage of a password of `max_size` CHAR16s: MaxSize × 2.
pub(super) fn password_width(max_size: u16) -> usize {
    usize::from(max_size) * CHAR16_SIZE
}

/// The StorageWidth that edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes gives a
/// PASSWORD of `max_size` CHAR16s, MaxSize × 2 cast to UINT16 (:2252), which drops the bits past
/// 16 of the password_width of a MaxSize over 32767.
pub(super) fn password_storage_width(max_size: u16) -> u16 {
    max_size.wrapping_mul(2)
}

impl PasswordFields {
    /// Those of the PASSWORD `op`, or why its question header does not parse.
    fn of(op: &IFROperation) -> Result<Self, ParseError> {
        let mut data = Cursor::new(&op.data);
        let question = data.parse_ne()?;
        Ok(Self {
            question,
            max_size: data.parse_ne::<PasswordSizes>().map(|sizes| sizes.max_size),
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
        password_bytes(
            self.question.var_store_info,
            self.max_size.as_ref().ok().copied(),
        )
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

/// The PASSWORD questions of one VarStoreId of a package list that VarStores outside their
/// FormSet hold, with the variables of the VARSTOREs and VARSTORE_EFIs of that id: each password
/// is recorded once, not once for each variable that holds it.
#[derive(Debug, Default, PartialEq, Eq)]
struct SharedPasswords {
    /// Those in FormSets, which hold the passwords of the PASSWORDs outside any FormSet
    in_form_sets: Vec<VariableKey>,
    /// Those outside any FormSet, which hold every password here
    outside: Vec<VariableKey>,
    /// The passwords of the PASSWORDs in FormSets, each with the VarStore of its FormSet, if any
    form_set_passwords: Vec<(Option<VariableKey>, Range<usize>)>,
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

    /// Withholds each password here once in `withheld`, in shared sets: one for each VarStore of
    /// a FormSet that the PASSWORDs in FormSets name, one for those that name none, and one for
    /// the PASSWORDs outside any FormSet, which the VarStores in FormSets withhold too. The
    /// VarStores outside any FormSet withhold every set.
    fn withhold(&self, withheld: &mut WithheldBytes) {
        let mut own: BTreeMap<&VariableKey, Vec<Range<usize>>> = BTreeMap::new();
        let mut storeless = Vec::new();
        for (key, bytes) in &self.form_set_passwords {
            match key {
                Some(key) => own.entry(key).or_default().push(bytes.clone()),
                None => storeless.push(bytes.clone()),
            }
        }
        let keys: Vec<&VariableKey> = own.keys().copied().collect();
        let sets = withheld.share(
            own.into_values()
                .chain([storeless, self.outside_passwords.clone()]),
        );
        for (set, key) in sets.clone().zip(keys) {
            withheld.withhold_shared(key, set..set + 1);
        }
        if !self.outside_passwords.is_empty() {
            for key in &self.in_form_sets {
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
        self.in_form_sets.len()
            + self.outside.len()
            + self.form_set_passwords.len()
            + self.outside_passwords.len()
    }
}

/// The VarStores of each VarStoreId of a package list, read once for all its PASSWORDs, with the
/// passwords that they share.
#[derive(Default)]
struct VarStoreIds(BTreeMap<u16, IdStores>);

/// The VarStores of one VarStoreId of a package list.
#[derive(Default)]
struct IdStores {
    shared: SharedPasswords,
    /// The first VarStore of the id outside any FormSet that names no variable, at this offset of
    /// a form package
    nameless: Option<(NamelessStore, u64)>,
    /// The Guids of the VARSTORE_EFIs before UEFI 2.3.1 of the id in FormSets, whose questions'
    /// VarNames name their variables
    short_in_form_sets: BTreeSet<Guid>,
    /// Those outside any FormSet
    short_outside: BTreeSet<Guid>,
}

/// A VarStore that names no variable.
#[derive(Clone, Copy)]
enum NamelessStore {
    /// A VARSTORE_NAME_VALUE, whose values only its driver holds
    NameValue,
    /// A VARSTORE_EFI before UEFI 2.3.1
    ShortEfi,
}

impl VarStoreIds {
    /// Those of `list`, in its FormSets, the forms that read_db disables among them too, and
    /// outside any, but for those in the IFR that IgnoredPasswords::Declared covers, whose storage
    /// PasswordQuestions withholds whole.
    fn of(list: &ParsedPackageList) -> Self {
        let mut ids = Self::default();
        ids.add_in_form_sets(&list.forms);
        for disabled in &list.disabled_forms {
            ids.add_in_form_sets(std::slice::from_ref(&disabled.form));
        }
        for outside in list
            .outside_ifr
            .iter()
            .filter(|outside| !outside.in_ignored_ifr)
        {
            let Some((var_store_id, store)) = declared_store(&outside.op) else {
                continue;
            };
            let stores = ids.0.entry(var_store_id).or_default();
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
            stores.nameless.get_or_insert((nameless, outside.offset));
        }
        ids
    }

    /// Adds those of the FormSets of `roots`, or of the forms that it holds.
    fn add_in_form_sets(&mut self, roots: &[Rc<RefCell<IFROperation>>]) {
        walk_scopes(roots, (), |node, ()| {
            if let Some((var_store_id, store)) = declared_store(&node.borrow()) {
                let stores = self.0.entry(var_store_id).or_default();
                match store {
                    DeclaredStore::Variable(store) => {
                        stores.shared.in_form_sets.push(store.variable_key());
                    }
                    DeclaredStore::ShortEfi(store) => {
                        stores.short_in_form_sets.insert(store.guid);
                    }
                    DeclaredStore::NameValue(_) => {}
                }
            }
            Walk::Enter(())
        });
    }

    /// The SharedPasswords of each VarStoreId whose variables hold a password.
    fn into_shared(self) -> impl Iterator<Item = SharedPasswords> {
        self.0
            .into_values()
            .map(|stores| stores.shared)
            .filter(SharedPasswords::holds_any)
    }
}

/// A PASSWORD in a FormSet with a VarStoreId, and the variable of the VarStore of that id that its
/// FormSet declares, with its layout, if any.
struct FormSetPassword {
    password: PasswordFields,
    store: Option<(VariableKey, VariableLayout)>,
}

impl PasswordQuestions {
    /// Those of the FormSets of `roots`: outside the tests, of_lists finds them with the
    /// VarStores and PASSWORDs outside any FormSet.
    #[cfg(test)]
    pub(crate) fn of<'a>(roots: impl IntoIterator<Item = &'a Rc<RefCell<IFROperation>>>) -> Self {
        let mut found = Self::default();
        let mut ids = VarStoreIds::default();
        for root in roots {
            found.add(root, None, &mut ids, &[]);
        }
        found
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
            found.add_forms(&list.forms, &list.disabled_forms, ids, &list.strings);
        }
        for (list, ids) in lists.iter().zip(&mut ids) {
            for outside in &list.outside_ifr {
                if outside.op.op_code == IFROpCode::Password {
                    found.add_outside(list, outside, ids);
                }
            }
        }
        found
            .shared
            .extend(ids.into_iter().flat_map(VarStoreIds::into_shared));
        // a malformed VarStore outside a FormSet may declare the VarStoreId of any PASSWORD
        if found.declared {
            for malformed in lists.iter().flat_map(|list| &list.malformed_outside_stores) {
                match &malformed.passwords {
                    IgnoredPasswords::Declared(storage) => found.storage.extend(storage),
                    IgnoredPasswords::AnyVariable | IgnoredPasswords::Found => {}
                }
                found.add_unresolved(UnresolvedPassword::MalformedVarStoreOutsideFormSet {
                    package_list: malformed.package_list,
                    offset: malformed.offset,
                    reason: malformed.reason.clone(),
                });
            }
        }
        // one per form package, which its records share
        let mut declared: Vec<&Arc<DeclaredStorage>> = Vec::new();
        for ignored in lists.iter().flat_map(|list| &list.ignored_ifr) {
            let (package_list, offset, reason) =
                (ignored.package_list, ignored.offset, ignored.reason.clone());
            let unresolved = match &ignored.passwords {
                IgnoredPasswords::AnyVariable => UnresolvedPassword::AnyVariable {
                    package_list,
                    offset,
                    reason,
                },
                IgnoredPasswords::Declared(storage) => {
                    if !declared.iter().any(|seen| Arc::ptr_eq(seen, storage)) {
                        declared.push(storage);
                        found.storage.extend(storage);
                    }
                    UnresolvedPassword::InIgnoredIfr {
                        package_list,
                        offset,
                        reason,
                    }
                }
                IgnoredPasswords::Found => UnresolvedPassword::InIgnoredIfr {
                    package_list,
                    offset,
                    reason,
                },
            };
            found.add_unresolved(unresolved);
        }
        found
    }

    /// Those of the FormSets of `roots` and of the forms `disabled` that their parse drops from
    /// them: outside the tests, of_lists finds them with the VarStores and PASSWORDs outside any
    /// FormSet.
    #[cfg(test)]
    fn of_forms(roots: &[Rc<RefCell<IFROperation>>], disabled: &[DisabledForm]) -> Self {
        let mut found = Self::default();
        found.add_forms(roots, disabled, &mut VarStoreIds::default(), &[]);
        found
    }

    /// Adds those of the FormSets of `roots` and of the forms `disabled` that their parse drops
    /// from them, as their ops are read, with the VarStores of each VarStoreId of their package
    /// list, `ids`, and its strings packages, `strings`.
    fn add_forms(
        &mut self,
        roots: &[Rc<RefCell<IFROperation>>],
        disabled: &[DisabledForm],
        ids: &mut VarStoreIds,
        strings: &[StringPackage],
    ) {
        for root in roots {
            self.add(root, None, ids, strings);
        }
        for disabled in disabled {
            let form_set = enclosing_form_set(&disabled.form.borrow())
                .and_then(|form_set| form_set_guid(&form_set.borrow()));
            self.add(&disabled.form, form_set, ids, strings);
        }
    }

    /// Adds those of `node`, in the FormSet `form_set` if any, and the ops in its scope, with the
    /// VarStores of each VarStoreId of their package list, `ids`, and its strings packages,
    /// `strings`.
    fn add(
        &mut self,
        node: &Rc<RefCell<IFROperation>>,
        form_set: Option<Guid>,
        ids: &mut VarStoreIds,
        strings: &[StringPackage],
    ) {
        walk_scopes(std::slice::from_ref(node), form_set, |node, &form_set| {
            let op = node.borrow();
            let form_set = form_set_guid(&op).or(form_set);
            if op.op_code == IFROpCode::Password {
                self.declared = true;
                let (password, unresolved) = password_questions(node, &op, form_set, ids);
                if let Some(password) = password {
                    self.add_in_form_set(password, ids, strings);
                }
                if let Some(unresolved) = unresolved {
                    self.add_unresolved(unresolved);
                    self.candidates.extend(candidate_questions(&op));
                }
            }
            Walk::Enter(form_set)
        });
    }

    /// Adds `password`, of a FormSet: on the VarStore of its FormSet alone, if it has one, unless
    /// `ids` has VarStores of its VarStoreId outside any FormSet, which hold it too: a VARSTORE or
    /// VARSTORE_EFI at its VarOffset, and through Runtime, as its password is unresolved then
    /// (password_questions), a VARSTORE_EFI before UEFI 2.3.1 in each variable that its VarName
    /// may name in the package list of the strings packages `strings`.
    fn add_in_form_set(
        &mut self,
        FormSetPassword { password, store }: FormSetPassword,
        ids: &mut VarStoreIds,
        strings: &[StringPackage],
    ) {
        let Some(stores) = ids.0.get_mut(&password.question.var_store_id) else {
            self.questions
                .extend(store.map(|(key, layout)| password.on(key, layout)));
            return;
        };
        self.candidates
            .extend(password.on_var_names(&stores.short_outside, strings));
        match (store, stores.shared.outside.is_empty()) {
            (Some((key, VariableLayout::Offsets)), false) => stores
                .shared
                .form_set_passwords
                .push((Some(key), password.bytes())),
            // no VarStore of its FormSet, or one that holds it from byte 0 of a VarName's variable
            (store, false) => {
                stores
                    .shared
                    .form_set_passwords
                    .push((None, password.bytes()));
                self.questions
                    .extend(store.map(|(key, layout)| password.on(key, layout)));
            }
            (store, true) => self
                .questions
                .extend(store.map(|(key, layout)| password.on(key, layout))),
        }
    }

    /// Adds the PASSWORD op `outside` of the package list `list`, outside any FormSet. Its
    /// VarStore is unknown: edk2-stable202608 ConfigKeywordHandler.c FindStorageFromVarId takes
    /// the first VarStore of its VarStoreId in the form package, in a FormSet or not, and other
    /// firmware may take another, so its password is withheld at its VarOffset in each VARSTORE
    /// and VARSTORE_EFI of that id in `list`, which `ids` holds, and through Runtime from byte 0
    /// of each variable that its VarName may name on a VARSTORE_EFI before UEFI 2.3.1 of that id.
    /// One of VarStoreId 0 names no VarStore, as one in a FormSet does not, and the Keyword
    /// Handler skips it (ExtractConfigRequest). One whose op ends before its MaxSize keeps every
    /// byte from its VarOffset on, and from byte 0 of each such variable. One in ignored IFR
    /// (OutsideOp::in_ignored_ifr) is withheld so too, as the Keyword Handler finds it there, and
    /// its record counts it already.
    fn add_outside(
        &mut self,
        list: &ParsedPackageList,
        outside: &OutsideOp,
        ids: &mut VarStoreIds,
    ) {
        self.declared = true;
        match PasswordFields::of(&outside.op) {
            Ok(password) if password.question.var_store_id == 0 => return,
            Ok(password) => {
                if let Some(stores) = ids.0.get_mut(&password.question.var_store_id) {
                    stores.shared.outside_passwords.push(password.bytes());
                    self.candidates.extend(password.on_var_names(
                        stores.short_in_form_sets.union(&stores.short_outside),
                        &list.strings,
                    ));
                }
            }
            Err(error) => debug!(
                "PASSWORD op outside a FormSet, at offset {}: {error}",
                outside.offset
            ),
        }
        if !outside.in_ignored_ifr {
            self.add_unresolved(UnresolvedPassword::OutsideFormSet {
                package_list: list.guid,
                offset: outside.offset,
            });
        }
    }

    /// Adds the PASSWORD op `unresolved`, whose VarStore is unknown.
    fn add_unresolved(&mut self, unresolved: UnresolvedPassword) {
        warn!("{unresolved}");
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
    /// hold one (AnyVariablePasswords), as read_db failed for such IFR before the first FormSet;
    /// variables that read nothing are not refused so.
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
    /// with no op boundary, may keep their passwords in any variable.
    pub(crate) fn check_bounded(&self) -> Result<(), AnyVariablePasswords> {
        let unbounded: Vec<UnresolvedPassword> = self
            .unresolved
            .iter()
            .filter(|unresolved| matches!(unresolved, UnresolvedPassword::AnyVariable { .. }))
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

/// The GUID of the FormSet that `op` opens, if it is a decoded FORM_SET op.
fn form_set_guid(op: &IFROperation) -> Option<Guid> {
    match &op.parsed_data {
        ParsedOperation::FormSet(form_set) => Some(form_set.guid),
        _ => None,
    }
}

/// The PASSWORD of the `op` at `node`, of the FormSet `form_set`, with the variable of the VarStore
/// of its VarStoreId that its FormSet declares and its layout, if any: each VarStore of that id
/// outside any
/// FormSet of its package list, in `ids`, which edk2-stable202608 ConfigKeywordHandler.c
/// FindStorageFromVarId may take first, holds its password too, at the same VarOffset and MaxSize.
/// With it, never instead of it, the first reason that its password may be in a variable that they
/// do not name. None for VarStoreId 0, which names no VarStore (UEFI 2.10 §33.3.8.2.2): its driver
/// keeps such a question's value through callbacks or READ/WRITE ops (§33.2.5.6), in no variable
/// that the IFR names. A FormSet without a VarStore of that id that names a variable leaves the
/// password unresolved, as does an outside VARSTORE_NAME_VALUE or VARSTORE_EFI before UEFI 2.3.1 of
/// that id, which names none. Its question header is read first: an op that ends before MaxSize
/// still names its VarStore and VarOffset, so its question takes every byte from there on, and it
/// is unresolved too.
fn password_questions(
    node: &Rc<RefCell<IFROperation>>,
    op: &IFROperation,
    form_set: Option<Guid>,
    ids: &VarStoreIds,
) -> (Option<FormSetPassword>, Option<UnresolvedPassword>) {
    let password = match PasswordFields::of(op) {
        Ok(password) => password,
        Err(error) => {
            let reason = error.to_string();
            return (
                None,
                Some(UnresolvedPassword::NoHeader { form_set, reason }),
            );
        }
    };
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
        return (None, no_max_size);
    }
    let (store, mut unresolved) =
        match find_corresponding_varstore(Rc::clone(node), header.var_store_id) {
            Ok(store) => (Some((store.variable_key(), store.layout())), no_max_size),
            Err(error) => (
                None,
                Some(UnresolvedPassword::NoVarStore {
                    form_set,
                    question_id: header.question_id,
                    reason: error.to_string(),
                }),
            ),
        };
    let nameless = ids
        .0
        .get(&header.var_store_id)
        .and_then(|stores| stores.nameless);
    if let Some((nameless, offset)) = nameless {
        let question_id = header.question_id;
        unresolved.get_or_insert(match nameless {
            NamelessStore::NameValue => UnresolvedPassword::NameValueOutsideFormSet {
                form_set,
                question_id,
                offset,
            },
            NamelessStore::ShortEfi => UnresolvedPassword::ShortVarStoreEfiOutsideFormSet {
                form_set,
                question_id,
                offset,
            },
        });
    }
    (Some(FormSetPassword { password, store }), unresolved)
}

/// The variables that may hold the password of the PASSWORD `op`, whose VarStore is unknown: on
/// a VARSTORE_EFI before UEFI 2.3.1, those that its VarName may name
/// (ShortVarStoreEfi::candidate_variables), each from byte 0, all of it where the op ends before
/// MaxSize.
fn candidate_questions(op: &IFROperation) -> Vec<PasswordQuestion> {
    let Ok(password) = PasswordFields::of(op) else {
        return Vec::new();
    };
    let Some(store) = short_var_store_of(op, password.question.var_store_id) else {
        return Vec::new();
    };
    store
        .candidate_variables(password.question.var_store_info)
        .into_iter()
        .map(|key| password.on(key, VariableLayout::OneValue))
        .collect()
}

/// A PASSWORD op whose VarStore is unknown.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum UnresolvedPassword {
    #[error(
        "PASSWORD op without a question header in FormSet {}: {reason}",
        FormSetName(*.form_set)
    )]
    NoHeader {
        form_set: Option<Guid>,
        reason: String,
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
    #[error(
        "PASSWORD question {question_id:#06x} in FormSet {}: a VARSTORE_NAME_VALUE outside a \
         FormSet, at offset {offset} of a form package, declares its VarStoreId, and only its \
         driver holds its values",
        FormSetName(*.form_set)
    )]
    NameValueOutsideFormSet {
        form_set: Option<Guid>,
        question_id: u16,
        offset: u64,
    },
    #[error(
        "PASSWORD question {question_id:#06x} in FormSet {}: an {} outside a FormSet, at offset \
         {offset} of a form package, declares its VarStoreId, and edk2 sends the Config Keyword \
         Handler's requests on such a VarStore to its driver",
        FormSetName(*.form_set),
        ShortVarStoreEfi::LABEL
    )]
    ShortVarStoreEfiOutsideFormSet {
        form_set: Option<Guid>,
        question_id: u16,
        offset: u64,
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
/// for FormSets ends.
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
    use std::cell::Cell;

    use super::super::ifr_fixtures::*;
    use super::super::QuestionFlags;
    use super::super::DECLARATIONS_READ;
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
    /// fields being parsed, without the Rust source locations of binrw's backtrace frames.
    #[test]
    fn a_headless_password_gives_its_reason_on_one_line() {
        let headless = password_questions(&[operation(PASSWORD, false, &[3, 0, 4, 0])]);
        let [UnresolvedPassword::NoHeader { reason, .. }] = headless.unresolved.as_slice() else {
            panic!("headless: {:?}", headless.unresolved);
        };
        assert_eq!(
            reason,
            "failed to fill whole buffer (While parsing field 'question_id' in QuestionHeader)",
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
                    .check_set(VariableReach::BootServices, SetupPasswordPolicy::Refuse)
                    .is_err(),
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
                candidates: vec![],
                storage: DeclaredStorage::default(),
            }
        );
        assert!(
            passwords
                .check_set(VariableReach::BootServices, SetupPasswordPolicy::Refuse)
                .is_err(),
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
    /// VarName may name on a VARSTORE_EFI before UEFI 2.3.1 of `outside`.
    fn assert_fails_closed_keeping_the_form_set_s_bytes(
        outside: Vec<u8>,
        unresolved: UnresolvedPassword,
        candidates: &[VariableKey],
    ) {
        let passwords = passwords_of(&[outside, form_set_with(&[password_on(2, 3, 2, 0)])]);
        let mut known = WithheldBytes::default();
        known.insert(amitse_setup(), 0..40);
        for candidate in candidates {
            known.insert(candidate.clone(), 0..40);
        }

        assert_eq!(passwords.unresolved, [unresolved], "unresolved");
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
            Ok(known),
            "withheld through Runtime"
        );
    }

    /// A VARSTORE_NAME_VALUE outside any FormSet of the VarStoreId of a PASSWORD, whose values
    /// only its driver holds, names no variable.
    #[test]
    fn an_outside_name_value_var_store_of_a_password_s_id_fails_closed() {
        assert_fails_closed_keeping_the_form_set_s_bytes(
            var_store_name_value(2, OTHER_GUID),
            UnresolvedPassword::NameValueOutsideFormSet {
                form_set: Some(FORM_SET_GUID),
                question_id: 2,
                offset: 0,
            },
            &[],
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
            },
            &[short_variable("!")],
        );
    }

    /// Of the VarStores outside any FormSet of the VarStoreId of a PASSWORD that name no variable,
    /// the first gives the reason.
    #[test]
    fn the_first_outside_var_store_that_names_no_variable_gives_the_reason() {
        assert_fails_closed_keeping_the_form_set_s_bytes(
            [var_store_name_value(2, OTHER_GUID), short_var_store_efi(2)].concat(),
            UnresolvedPassword::NameValueOutsideFormSet {
                form_set: Some(FORM_SET_GUID),
                question_id: 2,
                offset: 0,
            },
            &[short_variable("!")],
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
}
