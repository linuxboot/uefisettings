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

//! The stores that a FormSet declares (UEFI 2.11 §33.3.8.3.89-§33.3.8.3.91), read before a
//! driver's Callback() runs outside a forms browser and after, so that whatever the Callback()s
//! changed in them is found and restored.
//!
//! A forms browser holds the FormSet's stores in its edit buffer while its Callback()s run, and a
//! Callback() reaches them only through EFI_FORM_BROWSER2_PROTOCOL.BrowserCallback(), which
//! no browser serves here; a Callback() that writes a store directly instead is caught here.
//! Buffer and Name/Value stores are read as a browser reads them before it opens a form: by
//! EFI_HII_CONFIG_ROUTING_PROTOCOL.ExtractConfig() of a `<ConfigRequest>` naming each question's
//! setting (edk2-stable202608 SetupBrowserDxe IfrParse.c InitializeRequestElement); EFI
//! variable stores by GetVariable(). Settings that differ between two reads back-to-back change
//! on their own, as a timestamp does, so they are left out of the comparison.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::fmt;

use thiserror::Error;
use zeroize::Zeroizing;

use crate::efi_variables::VariableContents;
use crate::efi_variables::VariableData;
use crate::hii::config_routing::ConfigRouting;
use crate::hii::config_routing::ConfigRoutingError;
use crate::hii::config_string::BlockConfig;
use crate::hii::config_string::BlockName;
use crate::hii::config_string::ConfigElement;
use crate::hii::config_string::ConfigHdr;
use crate::hii::config_string::ConfigRequest;
use crate::hii::config_string::ConfigResp;
use crate::hii::config_string::ConfigStringError;
use crate::hii::config_string::Label;
use crate::hii::config_string::NvConfig;
use crate::hii::config_string::RequestElement;
use crate::hii::forms::DeclaredKind;
use crate::hii::forms::StoreDeclaration;
use crate::hii::package::DevicePath;
use crate::hii::VariableKey;

/// A store whose settings this module reads and restores.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FormSetStore {
    /// A Buffer or Name/Value store: the settings that `request` names, which are all but those
    /// of PASSWORD questions, if `holds_password`
    Config {
        id: u16,
        kind: ConfigKind,
        request: ConfigRequest,
        holds_password: bool,
    },
    /// An EFI variable store, whose PASSWORD questions' bytes, if `holds_password`, read as zero
    /// through withholding variables
    EfiVariable {
        id: u16,
        key: VariableKey,
        holds_password: bool,
    },
}

/// The kind of a FormSetStore::Config, which labels name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ConfigKind {
    Buffer,
    NameValue,
}

impl FormSetStore {
    /// The store of `declaration`, in a package list whose driver handle has the device path of
    /// `device_path`, which a `<ConfigHdr>` names; None for a Buffer or Name/Value store that no
    /// question requests a setting of.
    pub(crate) fn of(
        declaration: &StoreDeclaration,
        device_path: Option<&DevicePath>,
    ) -> Result<Option<Self>, StoreRefusal> {
        let id = declaration.id;
        let (kind, name, elements) = match &declaration.kind {
            DeclaredKind::EfiVariable { name } => {
                let key = VariableKey {
                    name: name.clone(),
                    guid: declaration.guid,
                };
                return Ok(Some(Self::EfiVariable {
                    id,
                    key,
                    holds_password: declaration.holds_password,
                }));
            }
            DeclaredKind::Buffer { name, blocks } => {
                let elements = blocks
                    .iter()
                    .map(|&(offset, width)| {
                        BlockName::new(usize::from(offset), width).map(RequestElement::Block)
                    })
                    .collect::<Result<Vec<_>, _>>();
                (ConfigKind::Buffer, name.encode_utf16().collect(), elements)
            }
            // A NULL Name, as a forms browser names Name/Value storage (edk2-stable202608
            // SetupBrowserDxe IfrParse.c CreateStorage)
            DeclaredKind::NameValue { names } => {
                let elements = names
                    .iter()
                    .map(|name| Label::try_from(name.as_str()).map(RequestElement::Label))
                    .collect::<Result<Vec<_>, _>>();
                (ConfigKind::NameValue, Vec::new(), elements)
            }
        };
        let label = StoreLabel::of(id, kind, &name);
        let elements = elements.map_err(|error| StoreRefusal::Element {
            store: label.clone(),
            error,
        })?;
        if elements.is_empty() {
            return Ok(None);
        }
        // A forms browser builds no <ConfigHdr> for a driver handle without a device path
        // (edk2-stable202608 UefiHiiLib HiiLib.c HiiConstructConfigHdr), which the HII database
        // keeps as the list's device path package (UEFI 2.11 §33.3.4)
        let device_path = device_path.ok_or(StoreRefusal::NoDevicePath(label))?;
        let header = ConfigHdr {
            guid: declaration.guid,
            name,
            device_path: device_path.clone(),
        };
        let request =
            ConfigRequest::new(header, elements).map_err(|error| StoreRefusal::Element {
                store: StoreLabel::of(id, kind, &[]),
                error,
            })?;
        Ok(Some(Self::Config {
            id,
            kind,
            request,
            holds_password: declaration.holds_password,
        }))
    }

    /// How messages name the store.
    pub(crate) fn label(&self) -> StoreLabel {
        match self {
            Self::Config {
                id, kind, request, ..
            } => StoreLabel::of(*id, *kind, &request.header().name),
            Self::EfiVariable { id, key, .. } => {
                StoreLabel(format!("VARSTORE_EFI {id:#06x} {key}"))
            }
        }
    }

    /// The settings of the store now: ExtractConfig() of its request, whose `<ConfigResp>` for
    /// the request's `<ConfigHdr>` must give exactly the requested settings, its `<AltResp>`s
    /// aside; or GetVariable().
    pub(crate) fn read(
        &self,
        routing: &impl ConfigRouting,
        variables: &impl VariableData,
    ) -> Result<Settings, StoreError> {
        let request = match self {
            Self::EfiVariable { key, .. } => {
                let contents = variables
                    .variable_data(key)
                    .map_err(|error| StoreError::Variable(format!("{error:#}")))?;
                return Ok(Settings::from([(
                    SettingKey::Variable,
                    Setting::Variable(contents),
                )]));
            }
            Self::Config { request, .. } => request,
        };
        let results = routing
            .extract_config(request)
            .map_err(StoreError::Routing)?;
        let resp = results
            .as_slice()
            .iter()
            .map(|alt| &alt.resp)
            .find(|resp| resp.header == *request.header())
            .ok_or(StoreError::NoResp)?;
        requested_settings(request, resp)
    }
}

/// The `<ConfigResp>` that writes `settings` to the Buffer or Name/Value store of `request`: one
/// element per setting of the request, in its order, as a forms browser routes a whole store.
pub(crate) fn config_resp(
    request: &ConfigRequest,
    settings: &Settings,
) -> Result<ConfigResp, StoreError> {
    let body = request
        .elements()
        .iter()
        .map(|element| {
            let key = SettingKey::of(element);
            let element = match (element, settings.get(&key)) {
                (RequestElement::Block(block), Some(Setting::Bytes(bytes))) => {
                    BlockConfig::new(block.offset(), bytes.to_vec()).map(ConfigElement::Block)
                }
                (RequestElement::Label(label), Some(Setting::Digits(digits))) => {
                    NvConfig::new(label.clone(), digits).map(ConfigElement::Nv)
                }
                (
                    RequestElement::Block(_),
                    Some(Setting::Digits(_) | Setting::Variable(_)) | None,
                )
                | (
                    RequestElement::Label(_),
                    Some(Setting::Bytes(_) | Setting::Variable(_)) | None,
                ) => return Err(StoreError::SettingMissing(key)),
            };
            element.map_err(StoreError::Resp)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ConfigResp {
        header: request.header().clone(),
        body,
    })
}

/// The settings that `resp` gives for `request`: each requested block at the same OFFSET and
/// WIDTH and each requested name once, and nothing else.
fn requested_settings(request: &ConfigRequest, resp: &ConfigResp) -> Result<Settings, StoreError> {
    let requested: BTreeSet<SettingKey> = request.elements().iter().map(SettingKey::of).collect();
    let mut settings = Settings::new();
    for element in &resp.body {
        let (key, setting) = match element {
            ConfigElement::Block(config) => (
                SettingKey::Block {
                    offset: config.offset(),
                    width: config.value().len(),
                },
                Setting::Bytes(Zeroizing::new(config.value().to_vec())),
            ),
            ConfigElement::Nv(config) => (
                SettingKey::Name(config.label().to_string()),
                Setting::Digits(Zeroizing::new(config.value().to_owned())),
            ),
        };
        if !requested.contains(&key) {
            return Err(StoreError::Unrequested(key));
        }
        if let Some(_repeated) = settings.insert(key.clone(), setting) {
            return Err(StoreError::Repeated(key));
        }
    }
    match requested
        .into_iter()
        .find(|key| !settings.contains_key(key))
    {
        Some(missing) => Err(StoreError::SettingMissing(missing)),
        None => Ok(settings),
    }
}

/// How messages name a store: its IFR op, VarStoreId and name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoreLabel(String);

impl StoreLabel {
    fn of(id: u16, kind: ConfigKind, name: &[u16]) -> Self {
        let name = String::from_utf16_lossy(name);
        Self(match kind {
            ConfigKind::Buffer => format!("VARSTORE {id:#06x} {name}"),
            ConfigKind::NameValue => format!("VARSTORE_NAME_VALUE {id:#06x}"),
        })
    }
}

impl fmt::Display for StoreLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A setting of a store: a block or a name of its request, or the whole EFI variable.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SettingKey {
    Block { offset: usize, width: usize },
    Name(String),
    Variable,
}

impl SettingKey {
    /// The setting that `element` requests.
    fn of(element: &RequestElement) -> Self {
        match element {
            RequestElement::Block(block) => Self::Block {
                offset: block.offset(),
                width: block.width().get(),
            },
            RequestElement::Label(label) => Self::Name(label.to_string()),
        }
    }
}

impl fmt::Display for SettingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Block { offset, width } => write!(f, "OFFSET={offset:04x}&WIDTH={width:04x}"),
            Self::Name(name) => f.write_str(name),
            Self::Variable => f.write_str("its data and attributes"),
        }
    }
}

/// The value of a setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Setting {
    /// A block's bytes, as they lie in the buffer
    Bytes(Zeroizing<Vec<u8>>),
    /// A name's hex digits
    Digits(Zeroizing<String>),
    /// The variable's data and attributes, or None if it is absent
    Variable(Option<VariableContents>),
}

/// The settings of a store, by key.
pub(crate) type Settings = BTreeMap<SettingKey, Setting>;

/// Why the settings of a store were not read, or no `<ConfigResp>` of them was built.
#[derive(Debug, Error)]
pub(crate) enum StoreError {
    #[error("{0}")]
    Routing(ConfigRoutingError),
    #[error("ExtractConfig() returned no <ConfigResp> for its <ConfigHdr>")]
    NoResp,
    #[error("ExtractConfig() returned no value for {0}")]
    SettingMissing(SettingKey),
    #[error("ExtractConfig() returned {0}, which its <ConfigRequest> did not request")]
    Unrequested(SettingKey),
    #[error("ExtractConfig() returned {0} twice")]
    Repeated(SettingKey),
    #[error("the <ConfigResp> of its settings: {0}")]
    Resp(ConfigStringError),
    /// GetVariable()'s error, as `{:#}` shows it
    #[error("{0}")]
    Variable(String),
}

/// Why no Callback() runs: a store that cannot be read, so that a change to it would go unseen.
#[derive(Debug, Error)]
pub(crate) enum StoreRefusal {
    #[error("cannot snapshot store {store}: {error}")]
    Unreadable {
        store: StoreLabel,
        error: StoreError,
    },
    #[error(
        "cannot snapshot store {0}: its package list has no device path package, so no \
         <ConfigHdr> names its driver for EFI_HII_CONFIG_ROUTING_PROTOCOL"
    )]
    NoDevicePath(StoreLabel),
    #[error("cannot snapshot store {store}: {error}")]
    Element {
        store: StoreLabel,
        error: ConfigStringError,
    },
}

/// The settings of the FormSet's stores before the first Callback(), without those that changed
/// between two reads back-to-back.
pub(crate) struct Baseline {
    stores: Vec<(FormSetStore, Settings)>,
    /// The settings left out of the comparison, by store label
    dynamic: Vec<(StoreLabel, SettingKey)>,
}

impl Baseline {
    /// Reads each of `stores` twice, back-to-back; refuses if any read fails.
    pub(crate) fn take(
        stores: Vec<FormSetStore>,
        routing: &impl ConfigRouting,
        variables: &impl VariableData,
    ) -> Result<Self, StoreRefusal> {
        let first = read_all(&stores, routing, variables)?;
        let second = read_all(&stores, routing, variables)?;
        let mut dynamic = Vec::new();
        let stores = stores
            .into_iter()
            .zip(first.into_iter().zip(second))
            .map(|(store, (first, mut second))| {
                second.retain(|key, setting| {
                    let same = first.get(key) == Some(setting);
                    if !same {
                        dynamic.push((store.label(), key.clone()));
                    }
                    same
                });
                (store, second)
            })
            .collect();
        Ok(Self { stores, dynamic })
    }

    /// The settings left out of the comparison, as `"<store>: <setting>"`.
    pub(crate) fn dynamic(&self) -> Vec<String> {
        self.dynamic
            .iter()
            .map(|(store, key)| format!("{store}: {key}"))
            .collect()
    }

    /// Reads the stores again; restores, through `routing` and `variables`, each store whose
    /// settings differ from the baseline, then reads it once more to verify.
    pub(crate) fn check(
        &self,
        routing: &impl ConfigRouting,
        variables: &impl VariableData,
    ) -> StoresCheck {
        let mut changed = Vec::new();
        let mut unreadable = Vec::new();
        for (store, baseline) in &self.stores {
            match store.read(routing, variables) {
                Ok(now) => {
                    let keys = changed_settings(baseline, &now);
                    if !keys.is_empty() {
                        changed.push(ChangedStore {
                            store: store.clone(),
                            baseline: baseline.clone(),
                            now,
                            keys,
                        });
                    }
                }
                Err(error) => unreadable.push((store.label(), error)),
            }
        }
        let (withheld, restorable): (Vec<_>, Vec<_>) =
            changed
                .into_iter()
                .partition(|changed| match changed.store {
                    FormSetStore::Config { holds_password, .. }
                    | FormSetStore::EfiVariable { holds_password, .. } => holds_password,
                });
        let restoration =
            (!restorable.is_empty()).then(|| restore(&restorable, routing, variables));
        StoresCheck {
            changed: restorable.iter().map(|store| store.store.label()).collect(),
            unrestored: withheld.into_iter().map(|store| store.store).collect(),
            unreadable,
            restoration,
        }
    }
}

/// The settings of each of `stores`, read once; refuses if any read fails.
fn read_all(
    stores: &[FormSetStore],
    routing: &impl ConfigRouting,
    variables: &impl VariableData,
) -> Result<Vec<Settings>, StoreRefusal> {
    stores
        .iter()
        .map(|store| {
            store
                .read(routing, variables)
                .map_err(|error| StoreRefusal::Unreadable {
                    store: store.label(),
                    error,
                })
        })
        .collect()
}

/// The keys of `baseline` whose settings `now` holds otherwise, or lacks.
fn changed_settings(baseline: &Settings, now: &Settings) -> BTreeSet<SettingKey> {
    baseline
        .iter()
        .filter(|(key, setting)| now.get(*key) != Some(*setting))
        .map(|(key, _)| key.clone())
        .collect()
}

/// A store whose settings `keys` changed from `baseline` to `now`.
struct ChangedStore {
    store: FormSetStore,
    baseline: Settings,
    now: Settings,
    keys: BTreeSet<SettingKey>,
}

/// Writes each changed store back, then reads the stores to verify.
fn restore(
    changed: &[ChangedStore],
    routing: &impl ConfigRouting,
    variables: &impl VariableData,
) -> Restoration {
    let failures: Vec<String> = changed
        .iter()
        .filter_map(|store| {
            restore_store(store, routing, variables)
                .err()
                .map(|error| format!("{}: {error}", store.store.label()))
        })
        .collect();
    if !failures.is_empty() {
        return Restoration::Failed(failures);
    }
    let unverified: Vec<String> = changed
        .iter()
        .filter_map(|store| match store.store.read(routing, variables) {
            Ok(now) => {
                let still = changed_settings(&store.baseline, &now);
                let still: Vec<String> = still
                    .intersection(&store.keys)
                    .map(SettingKey::to_string)
                    .collect();
                (!still.is_empty())
                    .then(|| format!("{}: {} differ", store.store.label(), still.join(", ")))
            }
            Err(error) => Some(format!("{}: {error}", store.store.label())),
        })
        .collect();
    match unverified.is_empty() {
        true => Restoration::Verified,
        false => Restoration::NotVerified(unverified),
    }
}

/// Writes `changed` back. A Buffer or Name/Value store gets RouteConfig() of one `<ConfigResp>`
/// of every setting of its request, as a forms browser routes a whole store, and as a driver that
/// zeroes its copy before ConfigToBlock() needs (edk2-stable202608 HttpBootConfig.c:441-449):
/// the changed settings take their baseline values, the others, those left out as dynamic among
/// them, the values read after the Callback()s. An EFI variable store gets SetVariable() of the
/// saved data and attributes, deleting the variable first only when its attributes changed, as
/// SetVariable() cannot change them, or deleting it when it was absent (UEFI 2.11 §8.2.3).
fn restore_store(
    changed: &ChangedStore,
    routing: &impl ConfigRouting,
    variables: &impl VariableData,
) -> Result<(), RestoreError> {
    let request = match &changed.store {
        FormSetStore::EfiVariable { key, .. } => {
            let saved = match changed.baseline.get(&SettingKey::Variable) {
                Some(Setting::Variable(saved)) => saved,
                Some(Setting::Bytes(_) | Setting::Digits(_)) | None => {
                    return Err(RestoreError::NoBaseline(SettingKey::Variable))
                }
            };
            let now = match changed.now.get(&SettingKey::Variable) {
                Some(Setting::Variable(now)) => now.as_ref(),
                Some(Setting::Bytes(_) | Setting::Digits(_)) | None => None,
            };
            return restore_variable(key, saved.as_ref(), now, variables);
        }
        FormSetStore::Config { request, .. } => request,
    };
    let mut settings = changed.now.clone();
    for key in &changed.keys {
        let saved = changed
            .baseline
            .get(key)
            .ok_or_else(|| RestoreError::NoBaseline(key.clone()))?;
        settings.insert(key.clone(), saved.clone());
    }
    let resp = config_resp(request, &settings).map_err(RestoreError::Resp)?;
    routing.route_config(&resp).map_err(RestoreError::Routing)
}

/// SetVariable() of `saved` over `now`, as restore_store describes.
fn restore_variable(
    key: &VariableKey,
    saved: Option<&VariableContents>,
    now: Option<&VariableContents>,
    variables: &impl VariableData,
) -> Result<(), RestoreError> {
    match (saved, now) {
        (None, Some(_)) => variables
            .delete_variable(key)
            .map_err(RestoreError::variable),
        (None, None) => Ok(()),
        (Some(saved), now) => {
            if now.is_some_and(|now| now.attributes() != saved.attributes()) {
                variables
                    .delete_variable(key)
                    .map_err(RestoreError::variable)?;
            }
            variables
                .set_variable(key, saved)
                .map_err(RestoreError::variable)
        }
    }
}

/// Why a restore failed.
#[derive(Debug, Error)]
enum RestoreError {
    #[error("{0}")]
    Routing(ConfigRoutingError),
    #[error("{0}")]
    Resp(StoreError),
    #[error("no saved value of {0}")]
    NoBaseline(SettingKey),
    /// SetVariable()'s error, as `{:#}` shows it
    #[error("{0}")]
    Variable(String),
}

impl RestoreError {
    /// SetVariable()'s or the deletion's `error`, as Variable holds it.
    fn variable(error: anyhow::Error) -> Self {
        Self::Variable(format!("{error:#}"))
    }
}

/// What Baseline::check found.
#[derive(Debug)]
pub(crate) struct StoresCheck {
    /// The stores whose settings changed, which were restored
    pub(crate) changed: Vec<StoreLabel>,
    /// The stores whose settings changed but that hold a password, which were not restored
    pub(crate) unrestored: Vec<FormSetStore>,
    /// The stores that could not be read after the Callback()s, so were not compared
    pub(crate) unreadable: Vec<(StoreLabel, StoreError)>,
    /// The restore of the changed stores, if any changed
    pub(crate) restoration: Option<Restoration>,
}

/// How the restore of changed stores ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Restoration {
    Verified,
    /// A read after the restore still differs, or failed
    NotVerified(Vec<String>),
    Failed(Vec<String>),
}

impl StoresCheck {
    /// Why the change is not applied, if the Callback()s changed a store or one could not be
    /// read again: `"the Callback sequence changed stores of the FormSet: <stores>; restored
    /// and verified"`, or how the restore failed, each store left as changed because it holds a
    /// password, and the unreadable stores.
    pub(crate) fn refusal(&self) -> Option<String> {
        let mut reasons = Vec::new();
        if let Some(restoration) = &self.restoration {
            let stores: Vec<String> = self.changed.iter().map(StoreLabel::to_string).collect();
            let restored = match restoration {
                Restoration::Verified => "restored and verified".to_string(),
                Restoration::NotVerified(stores) => {
                    format!("restore did not verify: {}", stores.join("; "))
                }
                Restoration::Failed(errors) => format!("restore failed: {}", errors.join("; ")),
            };
            reasons.push(format!(
                "the Callback sequence changed stores of the FormSet: {}; {restored}",
                stores.join(", ")
            ));
        }
        reasons.extend(self.unrestored.iter().map(|store| match store {
            FormSetStore::Config { id, .. } => format!(
                "the Callback sequence changed VarStore {id:#06x}, which holds a PASSWORD \
                 question; it was not restored, because a RouteConfig() without the password \
                 bytes may clear it"
            ),
            FormSetStore::EfiVariable { id, .. } => format!(
                "the Callback sequence changed VarStore {id:#06x}, which holds a PASSWORD \
                 question; it was not restored, because SetVariable() writes every byte of the \
                 variable, the password's too, which uefisettings never writes"
            ),
        }));
        reasons.extend(self.unreadable.iter().map(|(store, error)| {
            format!(
                "cannot snapshot store {store} after the Callback sequence: {error}; its \
                 settings were not compared"
            )
        }));
        (!reasons.is_empty()).then(|| reasons.join("; "))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::cell::Cell;
    use std::cell::RefCell;
    use std::num::NonZeroUsize;

    use super::*;
    use crate::efi_variables::globals::tests::key;
    use crate::efi_variables::globals::tests::HeldVariables;
    use crate::efi_variables::globals::tests::NV_BS_RT;
    use crate::hii::config_string::MultiConfigAltResp;
    use crate::hii::package::Guid;
    use crate::hii::VariableAttributes;

    pub(crate) const STORE_GUID: Guid = Guid {
        data1: 0x8c78_a505,
        data2: 0xbaa0,
        data3: 0x4c4a,
        data4: [0x86, 0x9f, 0, 0, 0, 0, 0x02, 0x01],
    };
    /// A vendor device path node of the test GUID, then an End node: what a driver installs on
    /// its handle.
    pub(crate) fn device_path() -> DevicePath {
        let mut path = vec![0x01, 0x04, 0x14, 0x00];
        path.extend(<[u8; 16]>::from(STORE_GUID));
        path.extend([0x7F, 0xFF, 0x04, 0x00]);
        path.into()
    }

    /// Buffer and Name/Value storage that a driver holds, behind a fake
    /// EFI_HII_CONFIG_ROUTING_PROTOCOL: per <ConfigHdr>, its bytes and its names' digits.
    #[derive(Default)]
    pub(crate) struct FakeRouting {
        pub(crate) buffers: RefCell<BTreeMap<String, Vec<u8>>>,
        pub(crate) names: RefCell<BTreeMap<String, BTreeMap<String, String>>>,
        /// Headers that ExtractConfig() answers with another <ConfigHdr>
        pub(crate) answers_other: RefCell<BTreeSet<String>>,
        /// The offsets of the requested blocks that ExtractConfig() leaves out
        pub(crate) omitted: RefCell<BTreeSet<usize>>,
        /// Elements that ExtractConfig() adds to its answer
        pub(crate) extra: RefCell<Vec<String>>,
        /// ExtractConfig() fails from this call on, counting from 0
        pub(crate) extract_fails_from: Cell<Option<usize>>,
        /// Bytes that each ExtractConfig() increments, as a timestamp changes
        pub(crate) ticking: RefCell<Vec<usize>>,
        pub(crate) route_fails: Cell<bool>,
        /// RouteConfig() writes nothing but succeeds
        pub(crate) route_ignored: Cell<bool>,
        pub(crate) extracts: Cell<usize>,
        pub(crate) routed: RefCell<Vec<String>>,
    }

    impl FakeRouting {
        pub(crate) fn with_buffer(self, header: &ConfigHdr, bytes: &[u8]) -> Self {
            self.buffers
                .borrow_mut()
                .insert(header.to_string(), bytes.to_vec());
            self
        }

        pub(crate) fn with_names(self, header: &ConfigHdr, names: &[(&str, &str)]) -> Self {
            let names = names
                .iter()
                .map(|(name, digits)| (name.to_string(), digits.to_string()))
                .collect();
            self.names.borrow_mut().insert(header.to_string(), names);
            self
        }

        pub(crate) fn buffer(&self, header: &ConfigHdr) -> Vec<u8> {
            self.buffers.borrow()[&header.to_string()].clone()
        }
    }

    impl ConfigRouting for FakeRouting {
        fn extract_config(
            &self,
            request: &ConfigRequest,
        ) -> Result<MultiConfigAltResp, ConfigRoutingError> {
            let call = self.extracts.get();
            self.extracts.set(call + 1);
            if self
                .extract_fails_from
                .get()
                .is_some_and(|from| call >= from)
            {
                return Err(ConfigRoutingError::Status {
                    function: "ExtractConfig",
                    status: crate::efi_status::EfiStatus::NOT_FOUND,
                    progress: 0,
                });
            }
            let header = request.header().to_string();
            for &at in self.ticking.borrow().iter() {
                if let Some(bytes) = self.buffers.borrow_mut().get_mut(&header) {
                    bytes[at] = bytes[at].wrapping_add(1);
                }
            }
            let mut body = Vec::new();
            for element in request.elements() {
                match element {
                    RequestElement::Block(block) => {
                        if self.omitted.borrow().contains(&block.offset()) {
                            continue;
                        }
                        let buffers = self.buffers.borrow();
                        let bytes = &buffers[&header][block.offset()..][..block.width().get()];
                        // most significant first, as edk2's BlockToConfig writes VALUE
                        let value: String = bytes
                            .iter()
                            .rev()
                            .map(|byte| format!("{byte:02x}"))
                            .collect();
                        body.push(format!(
                            "OFFSET={:04x}&WIDTH={:04x}&VALUE={value}",
                            block.offset(),
                            block.width()
                        ));
                    }
                    RequestElement::Label(label) => {
                        let names = self.names.borrow();
                        body.push(format!("{label}={}", names[&header][&label.to_string()]));
                    }
                }
            }
            body.extend(self.extra.borrow().iter().cloned());
            let shown = match self.answers_other.borrow().contains(&header) {
                true => header.replacen("GUID=0", "GUID=f", 1),
                false => header,
            };
            let text = format!("{shown}&{}", body.join("&"));
            Ok(text.parse().expect("a <MultiConfigAltResp>"))
        }

        fn route_config(&self, resp: &ConfigResp) -> Result<(), ConfigRoutingError> {
            self.routed.borrow_mut().push(resp.to_string());
            if self.route_fails.get() {
                return Err(ConfigRoutingError::Status {
                    function: "RouteConfig",
                    status: crate::efi_status::EfiStatus::DEVICE_ERROR,
                    progress: 0,
                });
            }
            if self.route_ignored.get() {
                return Ok(());
            }
            let header = resp.header.to_string();
            for element in &resp.body {
                match element {
                    ConfigElement::Block(config) => {
                        let mut buffers = self.buffers.borrow_mut();
                        let bytes = buffers.get_mut(&header).expect("a known buffer");
                        config.write_to(bytes).expect("block inside the buffer");
                    }
                    ConfigElement::Nv(config) => {
                        self.names
                            .borrow_mut()
                            .get_mut(&header)
                            .expect("known names")
                            .insert(config.label().to_string(), config.value().to_string());
                    }
                }
            }
            Ok(())
        }
    }

    pub(crate) fn width(width: usize) -> NonZeroUsize {
        NonZeroUsize::new(width).expect("nonzero width")
    }

    pub(crate) fn buffer_declaration(
        id: u16,
        name: &str,
        blocks: &[(u16, usize)],
    ) -> StoreDeclaration {
        StoreDeclaration {
            id,
            guid: STORE_GUID,
            kind: DeclaredKind::Buffer {
                name: name.to_string(),
                blocks: blocks
                    .iter()
                    .map(|&(offset, size)| (offset, width(size)))
                    .collect(),
            },
            holds_password: false,
        }
    }

    fn name_value_declaration(id: u16, names: &[&str]) -> StoreDeclaration {
        StoreDeclaration {
            id,
            guid: STORE_GUID,
            kind: DeclaredKind::NameValue {
                names: names.iter().map(|name| name.to_string()).collect(),
            },
            holds_password: false,
        }
    }

    pub(crate) fn efi_declaration(id: u16, name: &str) -> StoreDeclaration {
        StoreDeclaration {
            id,
            guid: STORE_GUID,
            kind: DeclaredKind::EfiVariable {
                name: name.to_string(),
            },
            holds_password: false,
        }
    }

    pub(crate) fn store(declaration: &StoreDeclaration) -> FormSetStore {
        FormSetStore::of(declaration, Some(&device_path()))
            .expect("a store")
            .expect("a store with settings")
    }

    pub(crate) fn header_of(store: &FormSetStore) -> ConfigHdr {
        match store {
            FormSetStore::Config { request, .. } => request.header().clone(),
            FormSetStore::EfiVariable { .. } => panic!("an EFI variable store has no header"),
        }
    }

    /// The fixture of most tests: a 4-byte Buffer store whose questions request bytes 0-1 and
    /// 3, a Name/Value store of "Mode" and "Level", and an EFI variable store; with their routing
    /// and variables.
    struct Fixture {
        stores: Vec<FormSetStore>,
        buffer: ConfigHdr,
        names: ConfigHdr,
        variable: VariableKey,
        routing: FakeRouting,
        variables: HeldVariables,
    }

    fn fixture() -> Fixture {
        let stores = vec![
            store(&buffer_declaration(2, "Buffer", &[(0, 2), (3, 1)])),
            store(&name_value_declaration(3, &["Mode", "Level"])),
            store(&efi_declaration(1, "Store")),
        ];
        let buffer = header_of(&stores[0]);
        let names = header_of(&stores[1]);
        let routing = FakeRouting::default()
            .with_buffer(&buffer, &[0x10, 0x11, 0x12, 0x13])
            .with_names(&names, &[("Mode", "1"), ("Level", "5")]);
        let variables = HeldVariables::default().with("Store", STORE_GUID, &[0x5A; 4]);
        Fixture {
            stores,
            buffer,
            names,
            variable: key("Store", STORE_GUID),
            routing,
            variables,
        }
    }

    fn baseline(fixture: &Fixture) -> Baseline {
        Baseline::take(fixture.stores.clone(), &fixture.routing, &fixture.variables)
            .expect("read every store")
    }

    fn variable_data(variables: &HeldVariables, key: &VariableKey) -> Option<(u32, Vec<u8>)> {
        variables
            .variables
            .borrow()
            .get(key)
            .map(|contents| (contents.attributes().bits(), contents.data().to_vec()))
    }

    #[test]
    fn request_names_each_question_setting_of_a_buffer_store() {
        let store = store(&buffer_declaration(2, "Buffer", &[(0, 2), (3, 1)]));
        let FormSetStore::Config { request, .. } = &store else {
            panic!("a Buffer store is a Config store");
        };
        let path: String = device_path()
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        assert_eq!(
            request.to_string(),
            format!(
                "GUID=05a5788ca0ba4a4c869f000000000201&NAME=004200750066006600650072&PATH={path}\
                 &OFFSET=0000&WIDTH=0002&OFFSET=0003&WIDTH=0001"
            ),
            "the <ConfigRequest> of a Buffer store"
        );
    }

    #[test]
    fn request_names_each_question_name_of_a_name_value_store_with_a_null_name() {
        let store = store(&name_value_declaration(3, &["Mode", "Level"]));
        let FormSetStore::Config { request, .. } = &store else {
            panic!("a Name/Value store is a Config store");
        };
        assert!(
            request.to_string().contains("&NAME=&PATH=")
                && request.to_string().ends_with("&Mode&Level"),
            "the <ConfigRequest> of a Name/Value store: {request}"
        );
    }

    #[test]
    fn config_store_without_device_path_is_refused_and_one_without_settings_skipped() {
        let declaration = buffer_declaration(2, "Buffer", &[(0, 1)]);
        let refused = FormSetStore::of(&declaration, None).expect_err("no device path");
        assert_eq!(
            refused.to_string(),
            "cannot snapshot store VARSTORE 0x0002 Buffer: its package list has no device path \
             package, so no <ConfigHdr> names its driver for EFI_HII_CONFIG_ROUTING_PROTOCOL",
            "a Buffer store without a device path"
        );
        let empty = buffer_declaration(2, "Buffer", &[]);
        assert_eq!(
            FormSetStore::of(&empty, None).expect("no settings to read"),
            None,
            "a Buffer store that no question requests"
        );
        let efi = FormSetStore::of(&efi_declaration(1, "Store"), None).expect("no path needed");
        assert!(
            matches!(efi, Some(FormSetStore::EfiVariable { .. })),
            "an EFI variable store needs no device path: {efi:?}"
        );
    }

    #[test]
    fn unchanged_stores_pass_and_nothing_is_written() {
        let fixture = fixture();
        let baseline = baseline(&fixture);

        let check = baseline.check(&fixture.routing, &fixture.variables);

        assert_eq!(check.refusal(), None, "unchanged stores: {check:?}");
        assert!(check.restoration.is_none(), "no restore");
        assert!(
            fixture.routing.routed.borrow().is_empty(),
            "no RouteConfig()"
        );
        assert!(
            fixture.variables.set.borrow().is_empty(),
            "no SetVariable()"
        );
    }

    #[test]
    fn a_changed_buffer_store_is_restored_whole_and_verified() {
        let fixture = fixture();
        let baseline = baseline(&fixture);
        // the Callback writes byte 1, which a question requests, and byte 2, which none does
        fixture
            .routing
            .buffers
            .borrow_mut()
            .get_mut(&fixture.buffer.to_string())
            .expect("buffer")[1..3]
            .copy_from_slice(&[0xB1, 0xB2]);

        let check = baseline.check(&fixture.routing, &fixture.variables);

        assert_eq!(
            check.refusal().as_deref(),
            Some(
                "the Callback sequence changed stores of the FormSet: VARSTORE 0x0002 Buffer; \
                 restored and verified"
            ),
            "a changed Buffer store"
        );
        assert_eq!(
            *fixture.routing.routed.borrow(),
            [format!(
                "{}&OFFSET=0000&WIDTH=0002&VALUE=1110&OFFSET=0003&WIDTH=0001&VALUE=13",
                fixture.buffer
            )],
            "RouteConfig() of every setting of the store, the changed one saved"
        );
        assert_eq!(
            fixture.routing.buffer(&fixture.buffer),
            [0x10, 0x11, 0xB2, 0x13],
            "the requested bytes restored, the others as the Callback left them"
        );
    }

    #[test]
    fn a_changed_name_is_restored() {
        let fixture = fixture();
        let baseline = baseline(&fixture);
        fixture
            .routing
            .names
            .borrow_mut()
            .get_mut(&fixture.names.to_string())
            .expect("names")
            .insert("Mode".into(), "2".into());

        let check = baseline.check(&fixture.routing, &fixture.variables);

        assert_eq!(
            check.restoration,
            Some(Restoration::Verified),
            "a changed name: {check:?}"
        );
        assert_eq!(
            *fixture.routing.routed.borrow(),
            [format!("{}&Mode=1&Level=5", fixture.names)],
            "RouteConfig() of every name, the changed one's saved digits"
        );
    }

    #[test]
    fn a_changed_variable_is_set_back_without_a_delete() {
        let fixture = fixture();
        let baseline = baseline(&fixture);
        fixture
            .variables
            .set_variable(
                &fixture.variable,
                &VariableContents::new(NV_BS_RT, vec![1, 0xC1, 0xC2, 0xC3]).expect("data"),
            )
            .expect("the Callback writes");
        fixture.variables.set.borrow_mut().clear();

        let check = baseline.check(&fixture.routing, &fixture.variables);

        assert_eq!(
            check.refusal().as_deref(),
            Some(&*format!(
                "the Callback sequence changed stores of the FormSet: VARSTORE_EFI 0x0001 {}; \
                 restored and verified",
                fixture.variable
            )),
            "a changed EFI variable store"
        );
        assert_eq!(
            variable_data(&fixture.variables, &fixture.variable),
            Some((NV_BS_RT.bits(), vec![0x5A; 4])),
            "the saved data and attributes"
        );
        assert!(
            fixture.variables.deleted.borrow().is_empty(),
            "no delete with the same attributes"
        );
    }

    #[test]
    fn a_variable_whose_attributes_changed_is_deleted_then_set() {
        let fixture = fixture();
        let baseline = baseline(&fixture);
        let nv_bs = VariableAttributes::NON_VOLATILE | VariableAttributes::BOOTSERVICE_ACCESS;
        fixture
            .variables
            .set_variable(
                &fixture.variable,
                &VariableContents::new(nv_bs, vec![1]).expect("data"),
            )
            .expect("the Callback writes");

        baseline.check(&fixture.routing, &fixture.variables);

        assert_eq!(
            *fixture.variables.deleted.borrow(),
            std::slice::from_ref(&fixture.variable),
            "deleted first"
        );
        assert_eq!(
            variable_data(&fixture.variables, &fixture.variable),
            Some((NV_BS_RT.bits(), vec![0x5A; 4])),
            "then set with the saved attributes"
        );
    }

    #[test]
    fn a_variable_that_was_absent_is_deleted_and_a_deleted_one_set_back() {
        let fixture = fixture();
        let absent = key("Absent", STORE_GUID);
        let stores = vec![
            store(&efi_declaration(4, "Absent")),
            fixture.stores[2].clone(),
        ];
        let baseline = Baseline::take(stores, &fixture.routing, &fixture.variables).expect("read");
        fixture
            .variables
            .set_variable(
                &absent,
                &VariableContents::new(NV_BS_RT, vec![9]).expect("data"),
            )
            .expect("the Callback creates it");
        fixture
            .variables
            .delete_variable(&fixture.variable)
            .expect("the Callback deletes it");
        fixture.variables.deleted.borrow_mut().clear();

        let check = baseline.check(&fixture.routing, &fixture.variables);

        assert_eq!(check.restoration, Some(Restoration::Verified), "{check:?}");
        assert_eq!(
            variable_data(&fixture.variables, &absent),
            None,
            "created one deleted"
        );
        assert_eq!(
            variable_data(&fixture.variables, &fixture.variable),
            Some((NV_BS_RT.bits(), vec![0x5A; 4])),
            "deleted one set back"
        );
    }

    #[test]
    fn a_failed_restore_is_reported_with_its_error() {
        let fixture = fixture();
        let baseline = baseline(&fixture);
        fixture
            .routing
            .buffers
            .borrow_mut()
            .get_mut(&fixture.buffer.to_string())
            .expect("buffer")[0] = 0;
        fixture.routing.route_fails.set(true);

        let check = baseline.check(&fixture.routing, &fixture.variables);

        assert_eq!(
            check.refusal().as_deref(),
            Some(
                "the Callback sequence changed stores of the FormSet: VARSTORE 0x0002 Buffer; \
                 restore failed: VARSTORE 0x0002 Buffer: RouteConfig() returned \
                 EFI_DEVICE_ERROR at CHAR16 0 of its string"
            ),
            "a failed RouteConfig()"
        );
    }

    /// The variables `0`, whose SetVariable() and deletions fail.
    struct WriteProtected<'a>(&'a HeldVariables);

    impl VariableData for WriteProtected<'_> {
        fn interface(&self) -> crate::hii::VariableInterface {
            self.0.interface()
        }

        fn variable_data(&self, key: &VariableKey) -> anyhow::Result<Option<VariableContents>> {
            self.0.variable_data(key)
        }

        fn set_variable(
            &self,
            key: &VariableKey,
            _contents: &VariableContents,
        ) -> anyhow::Result<()> {
            Err(anyhow::anyhow!(
                "SetVariable() of {key}: EFI_WRITE_PROTECTED"
            ))
        }

        fn delete_variable(&self, key: &VariableKey) -> anyhow::Result<()> {
            Err(anyhow::anyhow!("deletion of {key}: EFI_WRITE_PROTECTED"))
        }
    }

    /// A restore whose deletion of a variable that the Callback()s created fails, or whose
    /// SetVariable() of the saved data fails, is reported with that error, each by its store.
    #[test]
    fn a_failed_deletion_or_set_variable_of_a_restore_is_reported_with_its_error() {
        let fixture = fixture();
        let absent = key("Absent", STORE_GUID);
        let stores = vec![
            store(&efi_declaration(4, "Absent")),
            fixture.stores[2].clone(),
        ];
        let baseline = Baseline::take(stores, &fixture.routing, &fixture.variables).expect("read");
        fixture
            .variables
            .set_variable(
                &absent,
                &VariableContents::new(NV_BS_RT, vec![9]).expect("data"),
            )
            .expect("the Callback creates it");
        fixture
            .variables
            .set_variable(
                &fixture.variable,
                &VariableContents::new(NV_BS_RT, vec![1]).expect("data"),
            )
            .expect("the Callback writes");

        let check = baseline.check(&fixture.routing, &WriteProtected(&fixture.variables));

        assert_eq!(
            check.refusal().as_deref(),
            Some(&*format!(
                "the Callback sequence changed stores of the FormSet: VARSTORE_EFI 0x0004 \
                 {absent}, VARSTORE_EFI 0x0001 {variable}; restore failed: VARSTORE_EFI 0x0004 \
                 {absent}: deletion of {absent}: EFI_WRITE_PROTECTED; VARSTORE_EFI 0x0001 \
                 {variable}: SetVariable() of {variable}: EFI_WRITE_PROTECTED",
                variable = fixture.variable
            )),
            "a failed deletion and a failed SetVariable()"
        );
    }

    #[test]
    fn a_restore_that_writes_nothing_does_not_verify() {
        let fixture = fixture();
        let baseline = baseline(&fixture);
        fixture
            .routing
            .buffers
            .borrow_mut()
            .get_mut(&fixture.buffer.to_string())
            .expect("buffer")[3] = 0;
        fixture.routing.route_ignored.set(true);

        let check = baseline.check(&fixture.routing, &fixture.variables);

        assert_eq!(
            check.restoration,
            Some(Restoration::NotVerified(vec![
                "VARSTORE 0x0002 Buffer: OFFSET=0003&WIDTH=0001 differ".to_string()
            ])),
            "a RouteConfig() that ignores the settings"
        );
    }

    #[test]
    fn settings_that_change_between_two_reads_are_left_out() {
        let fixture = fixture();
        // byte 3 ticks at every ExtractConfig(), as a timestamp would
        fixture.routing.ticking.borrow_mut().push(3);
        let baseline = baseline(&fixture);

        let check = baseline.check(&fixture.routing, &fixture.variables);

        assert_eq!(
            baseline.dynamic(),
            ["VARSTORE 0x0002 Buffer: OFFSET=0003&WIDTH=0001"],
            "the ticking setting"
        );
        assert_eq!(
            check.refusal(),
            None,
            "a ticking setting is no change: {check:?}"
        );
        assert!(
            fixture.routing.routed.borrow().is_empty(),
            "nothing restored"
        );
    }

    #[test]
    fn a_changed_setting_beside_a_dynamic_one_is_still_caught() {
        let fixture = fixture();
        fixture.routing.ticking.borrow_mut().push(3);
        let baseline = baseline(&fixture);
        fixture
            .routing
            .buffers
            .borrow_mut()
            .get_mut(&fixture.buffer.to_string())
            .expect("buffer")[0] = 0;

        let check = baseline.check(&fixture.routing, &fixture.variables);

        assert_eq!(check.changed.len(), 1, "the changed store: {check:?}");
        let routed = fixture.routing.routed.borrow();
        // byte 3 ticked at the two reads of the baseline and the one after the Callback()s
        assert!(
            routed.len() == 1
                && routed[0].ends_with(
                    "&OFFSET=0000&WIDTH=0002&VALUE=1110&OFFSET=0003&WIDTH=0001&VALUE=16"
                ),
            "the changed setting saved, the dynamic one as read after the Callback()s: \
             {routed:?}"
        );
    }

    #[test]
    fn an_unreadable_store_refuses_before_any_callback() {
        let fixture = fixture();
        fixture.routing.extract_fails_from.set(Some(0));

        let refusal = Baseline::take(fixture.stores.clone(), &fixture.routing, &fixture.variables)
            .err()
            .expect("ExtractConfig() fails");

        assert_eq!(
            refusal.to_string(),
            "cannot snapshot store VARSTORE 0x0002 Buffer: ExtractConfig() returned \
             EFI_NOT_FOUND at CHAR16 0 of its string",
            "the store that failed"
        );
    }

    #[test]
    fn a_store_missing_from_the_result_refuses() {
        let fixture = fixture();
        fixture
            .routing
            .answers_other
            .borrow_mut()
            .insert(fixture.buffer.to_string());

        let refusal = Baseline::take(fixture.stores.clone(), &fixture.routing, &fixture.variables)
            .err()
            .expect("no <ConfigResp> for the store");

        assert_eq!(
            refusal.to_string(),
            "cannot snapshot store VARSTORE 0x0002 Buffer: ExtractConfig() returned no \
             <ConfigResp> for its <ConfigHdr>",
            "a result without the store"
        );
    }

    #[test]
    fn a_setting_missing_from_the_result_refuses() {
        let fixture = fixture();
        fixture.routing.omitted.borrow_mut().insert(0);

        let refusal = Baseline::take(fixture.stores.clone(), &fixture.routing, &fixture.variables)
            .err()
            .expect("a setting missing");

        assert_eq!(
            refusal.to_string(),
            "cannot snapshot store VARSTORE 0x0002 Buffer: ExtractConfig() returned no value \
             for OFFSET=0000&WIDTH=0002",
            "a result without one requested setting"
        );
    }

    #[test]
    fn a_setting_beyond_the_request_or_repeated_refuses() {
        let cases = [
            (
                "OFFSET=0002&WIDTH=0001&VALUE=12",
                "ExtractConfig() returned OFFSET=0002&WIDTH=0001, which its <ConfigRequest> did \
                 not request",
            ),
            (
                "OFFSET=0000&WIDTH=0001&VALUE=10",
                "ExtractConfig() returned OFFSET=0000&WIDTH=0001, which its <ConfigRequest> did \
                 not request",
            ),
            (
                "OFFSET=0003&WIDTH=0001&VALUE=13",
                "ExtractConfig() returned OFFSET=0003&WIDTH=0001 twice",
            ),
        ];
        for (extra, want) in cases {
            let fixture = fixture();
            fixture.routing.extra.borrow_mut().push(extra.to_string());

            let refusal =
                Baseline::take(fixture.stores.clone(), &fixture.routing, &fixture.variables)
                    .err()
                    .unwrap_or_else(|| panic!("{extra} refuses"));

            assert_eq!(
                refusal.to_string(),
                format!("cannot snapshot store VARSTORE 0x0002 Buffer: {want}"),
                "an answer with {extra}"
            );
        }
    }

    #[test]
    fn a_changed_store_holding_a_password_is_not_restored() {
        let fixture = fixture();
        let declaration = StoreDeclaration {
            holds_password: true,
            ..buffer_declaration(2, "Buffer", &[(0, 2), (3, 1)])
        };
        let baseline = Baseline::take(
            vec![store(&declaration), fixture.stores[2].clone()],
            &fixture.routing,
            &fixture.variables,
        )
        .expect("read");
        fixture
            .routing
            .buffers
            .borrow_mut()
            .get_mut(&fixture.buffer.to_string())
            .expect("buffer")[0] = 0;

        let check = baseline.check(&fixture.routing, &fixture.variables);

        assert_eq!(
            check.refusal().as_deref(),
            Some(
                "the Callback sequence changed VarStore 0x0002, which holds a PASSWORD question; \
                 it was not restored, because a RouteConfig() without the password bytes may \
                 clear it"
            ),
            "the store with a password"
        );
        assert!(
            fixture.routing.routed.borrow().is_empty(),
            "no RouteConfig() of a store with a password"
        );
        assert_eq!(
            fixture.routing.buffer(&fixture.buffer)[0],
            0,
            "the change stays"
        );
    }

    /// An EFI variable store whose PASSWORD question's bytes the withholding variables read as
    /// zero is not set back, which would write those zeros over the password.
    #[test]
    fn a_changed_efi_variable_store_holding_a_password_is_not_set_back() {
        let fixture = fixture();
        let declaration = StoreDeclaration {
            holds_password: true,
            ..efi_declaration(1, "Store")
        };
        let baseline = Baseline::take(
            vec![store(&declaration)],
            &fixture.routing,
            &fixture.variables,
        )
        .expect("read");
        fixture
            .variables
            .set_variable(
                &fixture.variable,
                &VariableContents::new(NV_BS_RT, vec![1, 0xC1, 0xC2, 0xC3]).expect("data"),
            )
            .expect("the Callback writes");
        fixture.variables.set.borrow_mut().clear();

        let check = baseline.check(&fixture.routing, &fixture.variables);

        assert_eq!(
            check.refusal().as_deref(),
            Some(
                "the Callback sequence changed VarStore 0x0001, which holds a PASSWORD question; \
                 it was not restored, because SetVariable() writes every byte of the variable, \
                 the password's too, which uefisettings never writes"
            ),
            "the EFI variable store with a password"
        );
        assert!(
            fixture.variables.set.borrow().is_empty()
                && fixture.variables.deleted.borrow().is_empty(),
            "no SetVariable() or deletion of a store with a password"
        );
        assert_eq!(
            variable_data(&fixture.variables, &fixture.variable),
            Some((NV_BS_RT.bits(), vec![1, 0xC1, 0xC2, 0xC3])),
            "the change stays"
        );
    }

    #[test]
    fn a_store_unreadable_after_the_callbacks_is_reported_and_others_still_restored() {
        let fixture = fixture();
        let baseline = baseline(&fixture);
        fixture
            .variables
            .set_variable(
                &fixture.variable,
                &VariableContents::new(NV_BS_RT, vec![1]).expect("data"),
            )
            .expect("the Callback writes");
        // both reads of the baseline took 2 ExtractConfig()s each
        fixture.routing.extract_fails_from.set(Some(4));

        let check = baseline.check(&fixture.routing, &fixture.variables);

        assert_eq!(
            check.refusal().as_deref(),
            Some(&*format!(
                "the Callback sequence changed stores of the FormSet: VARSTORE_EFI 0x0001 {}; \
                 restored and verified; cannot snapshot store VARSTORE 0x0002 Buffer after the \
                 Callback sequence: ExtractConfig() returned EFI_NOT_FOUND at CHAR16 0 of its \
                 string; its settings were not compared; cannot snapshot store \
                 VARSTORE_NAME_VALUE 0x0003 after the Callback sequence: ExtractConfig() \
                 returned EFI_NOT_FOUND at CHAR16 0 of its string; its settings were not \
                 compared",
                fixture.variable
            )),
            "an unreadable store beside a restored one"
        );
        assert_eq!(
            variable_data(&fixture.variables, &fixture.variable),
            Some((NV_BS_RT.bits(), vec![0x5A; 4])),
            "the readable store restored"
        );
    }
}
