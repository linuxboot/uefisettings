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

//! A set staged for the next boot. Boot services, and with them every driver's Callback(), end at
//! ExitBootServices(), so set cannot reach a question that only its driver holds from an OS;
//! it stages the request instead. uefisettings.efi starts once, before the OS, from a Boot####
//! load option that BootNext names (UEFI 2.11 §3.1.2), and applies the staged requests. Here are
//! the records of such a set, in uefisettings' own EFI variables, and what the OS side makes of
//! them.

use std::fmt;
use std::str::FromStr;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use log::warn;
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde::Serialize;
use sha2::Digest;
use sha2::Sha256;
use thiserror::Error;

use crate::efi_variables::globals::bit_names;
use crate::efi_variables::globals::boot_next;
use crate::efi_variables::globals::boot_option_support;
use crate::efi_variables::globals::boot_order;
use crate::efi_variables::globals::read_os_indications;
use crate::efi_variables::globals::BootOptionFlags;
use crate::efi_variables::globals::LoadOptionKind;
use crate::efi_variables::globals::LoadOptionName;
use crate::efi_variables::globals::OsIndications;
use crate::efi_variables::globals::EFI_GLOBAL_VARIABLE;
use crate::efi_variables::globals::WRITABLE_ATTRIBUTES;
use crate::efi_variables::load_option::DevicePathNode;
use crate::efi_variables::load_option::FilePathList;
use crate::efi_variables::load_option::HardDrive;
use crate::efi_variables::load_option::LoadOption;
use crate::efi_variables::load_option::LoadOptionAttributes;
use crate::efi_variables::load_option::LoadOptionError;
use crate::efi_variables::load_option::Ucs2String;
use crate::efi_variables::VariableContents;
use crate::efi_variables::VariableData;
use crate::efi_variables::UEFISETTINGS_VENDOR_GUID;
use crate::hii::forms::AccessLevel;
use crate::hii::forms::IfrValueType;
use crate::hii::forms::IncludedStates;
use crate::hii::package::Guid;
use crate::hii::VariableAttributes;
use crate::hii::VariableKey;
use crate::unsafe_operations::UnsafeOperations;

#[cfg(target_os = "linux")]
pub(crate) mod linux;

/// The variables of UEFISETTINGS_VENDOR_GUID that hold the staged set, and the outcome of the
/// last staged set's boot
const STAGED_SET: &str = "UefisettingsStagedSet";
const STAGED_OUTCOME: &str = "UefisettingsStagedOutcome";
/// NV, BS, RT: the records outlive resets, and the OS reads them as uefisettings.efi does
const RECORD_ATTRIBUTES: VariableAttributes = VariableAttributes::NON_VOLATILE
    .union(VariableAttributes::BOOTSERVICE_ACCESS)
    .union(VariableAttributes::RUNTIME_ACCESS);
/// The command line of a staged set's Boot#### before its nonce: the image, then its command
const APPLY_STAGED: &str = "uefisettings.efi apply-staged";
/// uefisettings' directory on the EFI system partition, and the path of a staged set's image in
/// it, as File Path nodes name them
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "only the Linux build reaches the ESP yet")
)]
pub(crate) const IMAGE_DIRECTORY: &str = "\\EFI\\uefisettings";
pub(crate) const IMAGE_PATH: &str = "\\EFI\\uefisettings\\uefisettings.efi";
/// The directory of capsules on disk, which the firmware processes at the next boot when
/// OsIndications has FILE_CAPSULE_DELIVERY_SUPPORTED, letter case ignored (UEFI 2.11 §8.5.5)
#[cfg_attr(
    not(target_os = "linux"),
    allow(dead_code, reason = "only the Linux build reaches the ESP yet")
)]
pub(crate) const CAPSULE_DIRECTORY: &str = "\\EFI\\UpdateCapsule";
/// The Description of a staged set's Boot####
const DESCRIPTION: &str = "uefisettings: a set staged for this boot";
/// The OsIndications that keep the boot manager from starting BootNext's option unattended: it
/// stops at a firmware user interface, or skips to recovery (UEFI 2.11 §8.5.4). With
/// FILE_CAPSULE_DELIVERY_SUPPORTED, capsules on disk do too (StageRefusal::CapsulesOnDisk).
const BEFORE_BOOT_NEXT: OsIndications = OsIndications::BOOT_TO_FW_UI
    .union(OsIndications::START_OS_RECOVERY)
    .union(OsIndications::START_PLATFORM_RECOVERY);

/// The 128 random bits that tie a staged set's Boot#### option and outcome to its record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Nonce(pub(crate) [u8; 16]);

/// A SHA-256 digest (FIPS 180-4), such as a staged image's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Sha256Digest(pub(crate) [u8; 32]);

/// Lowercase hexadecimal digits, two per byte.
impl fmt::Display for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

/// Lowercase hexadecimal digits, two per byte.
impl fmt::Display for Sha256Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_hex(f, &self.0)
    }
}

/// The digits that Display writes.
impl FromStr for Nonce {
    type Err = RecordError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        lowercase_hex(text).map(Self)
    }
}

/// The digits that Display writes.
impl FromStr for Sha256Digest {
    type Err = RecordError;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        lowercase_hex(text).map(Self)
    }
}

/// Writes `bytes` in lowercase hexadecimal digits, two per byte.
fn write_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    bytes.iter().try_for_each(|byte| write!(f, "{byte:02x}"))
}

/// The `N` bytes that `text` writes in lowercase hexadecimal digits, two per byte.
fn lowercase_hex<const N: usize>(text: &str) -> Result<[u8; N], RecordError> {
    let bytes: Option<Vec<u8>> = match text.as_bytes().as_chunks::<2>() {
        (pairs, []) => pairs
            .iter()
            .map(|&[high, low]| Some((lowercase_digit(high)? << 4) | lowercase_digit(low)?))
            .collect(),
        (_, _) => None,
    };
    bytes
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| RecordError::Hex {
            text: text.to_owned(),
            digits: 2 * N,
        })
}

/// The value of the lowercase hexadecimal digit `byte`.
fn lowercase_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

/// A request that set staged: to set the question `question_id` of the FormSet `form_set`, which
/// its driver holds, to `value`, selected with `include` and `access_level` as set selected it,
/// with set's grant of `unsafe_operations`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StagedRequest {
    /// The question as set named it
    pub(crate) question: String,
    #[serde(with = "as_text")]
    pub(crate) form_set: Guid,
    pub(crate) question_id: u16,
    #[serde(with = "as_text")]
    pub(crate) value_type: IfrValueType,
    pub(crate) value: u64,
    /// The states of questions that set selected too, as --include names them
    #[serde(with = "included_states")]
    pub(crate) include: IncludedStates,
    /// The access level that set's conditions read instead of the stored one, if stated
    #[serde(with = "access_level")]
    pub(crate) access_level: Option<AccessLevel>,
    /// Whether set had --i-am-fine-to-brick-this-system, which apply-staged checks the unsafe
    /// operations of applying the request against
    #[serde(with = "unsafe_operations")]
    pub(crate) unsafe_operations: UnsafeOperations,
}

/// The image that a staged set's Boot#### starts: its path on the EFI system partition, as its
/// File Path node names it, and its SHA-256 as staged.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StagedImage {
    pub(crate) path: String,
    #[serde(with = "as_text")]
    pub(crate) sha256: Sha256Digest,
}

/// The record of the staged set: its nonce, the number of its Boot####, its image and its
/// requests, in the order set staged them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct StagedSet {
    #[serde(with = "as_text")]
    pub(crate) nonce: Nonce,
    pub(crate) boot_option: u16,
    pub(crate) image: StagedImage,
    pub(crate) requests: Vec<StagedRequest>,
}

/// A staged request and what applying it did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RequestOutcome {
    pub(crate) request: StagedRequest,
    pub(crate) applied: bool,
    /// What set answers of it
    pub(crate) result: String,
}

/// What became of a staged set's boot, each echoing the set's nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub(crate) enum Outcome {
    /// uefisettings.efi started, and records this before the first Callback()
    Started {
        #[serde(with = "as_text")]
        nonce: Nonce,
    },
    /// uefisettings.efi applied the requests
    Finished {
        #[serde(with = "as_text")]
        nonce: Nonce,
        results: Vec<RequestOutcome>,
    },
    /// uefisettings.efi started and recorded no outcome: the requests may be partly applied
    Interrupted {
        #[serde(with = "as_text")]
        nonce: Nonce,
        requests: Vec<StagedRequest>,
    },
    /// The boot is over and uefisettings.efi never started
    NotStarted {
        #[serde(with = "as_text")]
        nonce: Nonce,
        requests: Vec<StagedRequest>,
    },
}

impl Outcome {
    fn nonce(&self) -> Nonce {
        match self {
            Self::Started { nonce }
            | Self::Finished { nonce, .. }
            | Self::Interrupted { nonce, .. }
            | Self::NotStarted { nonce, .. } => *nonce,
        }
    }
}

/// The OptionalData of a staged set's Boot####, which the boot manager passes to the image as
/// its LoadOptions: the command line `uefisettings.efi apply-staged <nonce>` in CHAR16s.
pub(crate) fn optional_data(nonce: Nonce) -> Result<Vec<u8>, LoadOptionError> {
    Ucs2String::try_from(format!("{APPLY_STAGED} {nonce}").as_str())
        .map(|command| command.to_char16_bytes())
}

/// What uefisettings' records tell of the staged set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StagedState {
    /// No set is staged; the outcome of the last staged set's boot, if recorded
    Idle(Option<Outcome>),
    /// A staged set waits for its boot: BootNext names its Boot####
    Pending(StagedSet),
    /// A staged set whose boot is over, and its outcome: the one recorded with its nonce, else,
    /// if uefisettings.efi recorded that it started, Interrupted, and if not, NotStarted
    Over(StagedSet, Outcome),
}

impl StagedState {
    /// What the records that `variables` hold tell, with BootNext.
    pub(crate) fn read(variables: &impl VariableData) -> Result<Self> {
        let recorded: Option<Outcome> = read_record(variables, STAGED_OUTCOME)?;
        let Some(set) = read_record::<StagedSet>(variables, STAGED_SET)? else {
            return Ok(Self::Idle(recorded));
        };
        let outcome = match recorded.filter(|outcome| outcome.nonce() == set.nonce) {
            Some(Outcome::Started { nonce }) => Outcome::Interrupted {
                nonce,
                requests: set.requests.clone(),
            },
            Some(
                outcome @ (Outcome::Finished { .. }
                | Outcome::Interrupted { .. }
                | Outcome::NotStarted { .. }),
            ) => outcome,
            None => match boot_next(variables)? {
                Some(next) if next.number == set.boot_option => return Ok(Self::Pending(set)),
                Some(_) | None => Outcome::NotStarted {
                    nonce: set.nonce,
                    requests: set.requests.clone(),
                },
            },
        };
        Ok(Self::Over(set, outcome))
    }
}

/// The files of staged images on the EFI system partition, as the OS reaches them.
pub(crate) trait StagedFiles {
    /// The paths of the files in uefisettings' directory, \EFI\uefisettings, as File Path nodes
    /// name them.
    fn list(&self) -> Result<Vec<String>>;

    /// The SHA-256 of the file at `path`, None if there is none.
    fn sha256(&self, path: &str) -> Result<Option<Sha256Digest>>;

    /// The paths of the files in \EFI\UpdateCapsule, the directory of capsules on disk (UEFI 2.11
    /// §8.5.5), as File Path nodes name them.
    fn capsules(&self) -> Result<Vec<String>>;

    /// Deletes the file at `path`, then uefisettings' directory if it is empty.
    fn delete(&self, path: &str) -> Result<()>;

    /// Writes `image` to a new file at `path`, creating uefisettings' directory if missing, and
    /// reads it back: the SHA-256 of what it read. Fails if `path` exists, and leaves no file if
    /// it fails.
    fn place(&self, path: &str, image: &[u8]) -> Result<Sha256Digest>;
}

/// What settle leaves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Settled {
    /// No set is staged; the outcome of the last staged set's boot, if recorded
    Idle(Option<Outcome>),
    /// A staged set waits for its boot
    Pending(StagedSet),
}

/// Settles a staged set whose boot is over: records its outcome, deletes its Boot#### and BootNext
/// if it names that, its image, then its record. A Boot#### that holds another command line and
/// an image whose SHA-256 changed stay, as they are no longer the set's. A set that waits for its
/// boot stays.
pub(crate) fn settle(variables: &impl VariableData, files: &impl StagedFiles) -> Result<Settled> {
    let (set, outcome) = match StagedState::read(variables)? {
        StagedState::Idle(last) => return Ok(Settled::Idle(last)),
        StagedState::Pending(set) => return Ok(Settled::Pending(set)),
        StagedState::Over(set, outcome) => (set, outcome),
    };
    write_record(variables, STAGED_OUTCOME, &outcome)?;
    remove_boot_option(variables, &set)?;
    remove_image(files, &set.image)?;
    variables.delete_variable(&record_key(STAGED_SET))?;
    Ok(Settled::Idle(Some(outcome)))
}

/// The Boot#### of `number`.
fn boot_option_name(number: u16) -> LoadOptionName {
    LoadOptionName {
        kind: LoadOptionKind::Boot,
        number,
    }
}

/// Deletes the Boot#### of `set` if it holds the set's command line, after BootNext if that
/// names it.
fn remove_boot_option(variables: &impl VariableData, set: &StagedSet) -> Result<()> {
    let option = LoadOptionName {
        kind: LoadOptionKind::Boot,
        number: set.boot_option,
    };
    let Some(contents) = variables.variable_data(&option.key())? else {
        return Ok(());
    };
    let command = optional_data(set.nonce)?;
    if !LoadOption::decode(contents.data())
        .is_ok_and(|load_option| load_option.optional_data == command)
    {
        warn!(
            "kept {option}: it no longer starts the staged set {}",
            set.nonce
        );
        return Ok(());
    }
    if boot_next(variables)? == Some(option) {
        variables.delete_variable(&boot_next_key())?;
    }
    variables.delete_variable(&option.key())
}

/// Deletes the staged image if it is unchanged.
fn remove_image(files: &impl StagedFiles, image: &StagedImage) -> Result<()> {
    match files.sha256(&image.path)? {
        Some(digest) if digest == image.sha256 => files.delete(&image.path),
        Some(digest) => {
            warn!(
                "kept {}: its SHA-256 is {digest}, not the staged image's {}",
                image.path, image.sha256
            );
            Ok(())
        }
        None => Ok(()),
    }
}

/// How staging a request goes on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StagePlan {
    /// Append it to the pending set, which keeps its Boot####
    Append(StagedSet),
    /// Stage a new set
    New,
}

/// Settles the records, then plans staging a request: appended to the pending set, else a new
/// set. Refused while BootNext names another option, while OsIndications keeps the boot manager
/// from starting BootNext's option unattended, also through capsules on disk, and while
/// uefisettings' directory on the EFI system partition holds a file that the pending set does
/// not name.
pub(crate) fn plan_stage(
    variables: &impl VariableData,
    files: &impl StagedFiles,
) -> Result<StagePlan> {
    let pending = match settle(variables, files)? {
        Settled::Idle(_) => None,
        Settled::Pending(set) => Some(set),
    };

    if let Some(next) = boot_next(variables)? {
        if pending.as_ref().map(|set| set.boot_option) != Some(next.number) {
            return Err(StageRefusal::ForeignBootNext(next).into());
        }
    }
    let indications = read_os_indications(variables)?.unwrap_or_else(OsIndications::empty);
    let blocking = indications.intersection(BEFORE_BOOT_NEXT);
    if !blocking.is_empty() {
        return Err(StageRefusal::OsIndications(blocking).into());
    }
    if indications.contains(OsIndications::FILE_CAPSULE_DELIVERY_SUPPORTED) {
        let capsules = files.capsules()?;
        if !capsules.is_empty() {
            return Err(StageRefusal::CapsulesOnDisk(capsules).into());
        }
    }
    let foreign: Vec<String> = files
        .list()?
        .into_iter()
        .filter(|path| {
            !pending
                .as_ref()
                .is_some_and(|set| set.image.path.eq_ignore_ascii_case(path))
        })
        .collect();
    if !foreign.is_empty() {
        return Err(StageRefusal::ForeignFiles(foreign).into());
    }

    Ok(match pending {
        Some(set) => StagePlan::Append(set),
        None => StagePlan::New,
    })
}

/// Records `set` as the staged set.
pub(crate) fn record_set(variables: &impl VariableData, set: &StagedSet) -> Result<()> {
    write_record(variables, STAGED_SET, set)
}

/// Stages `request` in a new set of `nonce`, for StagePlan::New: writes `image` to IMAGE_PATH
/// and reads it back, records the set, writes its Boot####, the lowest free one, which starts the
/// image on the partition of `hard_drive` with the set's command line, then BootNext. A step that
/// fails undoes the steps before it; an image file that exists already fails it before any write,
/// and stays, as a set staged at the same time may have placed it.
pub(crate) fn stage_new(
    variables: &impl VariableData,
    files: &impl StagedFiles,
    hard_drive: HardDrive,
    request: StagedRequest,
    image: &[u8],
    nonce: Nonce,
) -> Result<StagedSet> {
    let sha256 = Sha256Digest(Sha256::digest(image).into());
    let set = StagedSet {
        nonce,
        boot_option: free_boot_option(variables)?,
        image: StagedImage {
            path: IMAGE_PATH.to_owned(),
            sha256,
        },
        requests: vec![request],
    };
    let load_option = LoadOption {
        attributes: LoadOptionAttributes::ACTIVE
            | LoadOptionAttributes::HIDDEN
            | category(variables)?,
        description: Ucs2String::try_from(DESCRIPTION)?,
        file_paths: FilePathList::of(&[
            DevicePathNode::HardDrive(hard_drive),
            DevicePathNode::FilePath(Ucs2String::try_from(IMAGE_PATH)?),
        ])?,
        optional_data: optional_data(nonce)?,
    };

    let read_back = files.place(&set.image.path, image)?;
    match write_new_set(variables, files, &set, &load_option, read_back) {
        Ok(()) => Ok(set),
        // nothing of a set that failed to stage stays
        Err(error) => Err(match undo_new_set(variables, files, &set) {
            Ok(()) => error,
            Err(undo) => anyhow!("{error:#}; undoing the staging failed too: {undo:#}"),
        }),
    }
}

/// The steps of stage_new after it placed the image, which read back as `read_back`.
fn write_new_set(
    variables: &impl VariableData,
    files: &impl StagedFiles,
    set: &StagedSet,
    load_option: &LoadOption,
    read_back: Sha256Digest,
) -> Result<()> {
    if read_back != set.image.sha256 {
        files.delete(&set.image.path)?;
        return Err(anyhow!(
            "{} reads back with SHA-256 {read_back}, not the image's {}",
            set.image.path,
            set.image.sha256
        ));
    }
    record_set(variables, set)?;
    variables.set_variable(
        &boot_option_name(set.boot_option).key(),
        &VariableContents::new(WRITABLE_ATTRIBUTES, load_option.encode())?,
    )?;
    variables.set_variable(
        &boot_next_key(),
        &VariableContents::new(WRITABLE_ATTRIBUTES, set.boot_option.to_le_bytes().to_vec())?,
    )
}

/// Undoes the steps of stage_new that wrote, as settle does.
fn undo_new_set(
    variables: &impl VariableData,
    files: &impl StagedFiles,
    set: &StagedSet,
) -> Result<()> {
    remove_boot_option(variables, set)?;
    if variables.variable_data(&record_key(STAGED_SET))?.is_some() {
        variables.delete_variable(&record_key(STAGED_SET))?;
    }
    remove_image(files, &set.image)
}

/// The LOAD_OPTION_CATEGORY of a staged set's Boot####: LOAD_OPTION_CATEGORY_APP if
/// BootOptionSupport has EFI_BOOT_OPTION_SUPPORT_APP, else LOAD_OPTION_CATEGORY_BOOT (UEFI 2.11
/// §3.1.4).
fn category(variables: &impl VariableData) -> Result<LoadOptionAttributes> {
    let supports_apps = boot_option_support(variables)?
        .is_some_and(|support| support.flags.contains(BootOptionFlags::APP));
    Ok(match supports_apps {
        true => LoadOptionAttributes::CATEGORY_APP,
        false => LoadOptionAttributes::empty(),
    })
}

/// The number of the lowest Boot#### that `variables` lack and that neither BootOrder lists, so
/// that no boot starts it unattended, nor BootNext names, as edk2-stable202608
/// UefiBootManagerLib BmGetFreeOptionNumber() skips both (BmLoadOption.c).
fn free_boot_option(variables: &impl VariableData) -> Result<u16> {
    let taken: Vec<LoadOptionName> = boot_order(variables)?
        .into_iter()
        .flatten()
        .chain(boot_next(variables)?)
        .collect();
    for number in 0..=u16::MAX {
        let option = boot_option_name(number);
        if !taken.contains(&option) && variables.variable_data(&option.key())?.is_none() {
            return Ok(number);
        }
    }
    Err(anyhow!(
        "every Boot#### from Boot0000 to BootFFFF exists or BootOrder or BootNext holds it"
    ))
}

fn record_key(name: &str) -> VariableKey {
    VariableKey {
        name: name.to_owned(),
        guid: UEFISETTINGS_VENDOR_GUID,
    }
}

fn boot_next_key() -> VariableKey {
    VariableKey {
        name: "BootNext".to_owned(),
        guid: EFI_GLOBAL_VARIABLE,
    }
}

/// The record `name` that `variables` hold, None if absent; refused unless it has
/// RECORD_ATTRIBUTES and its data is the JSON of a T.
fn read_record<T: DeserializeOwned>(
    variables: &impl VariableData,
    name: &str,
) -> Result<Option<T>> {
    let key = record_key(name);
    let Some(contents) = variables.variable_data(&key)? else {
        return Ok(None);
    };
    if contents.attributes() != RECORD_ATTRIBUTES {
        return Err(RecordError::Attributes {
            key,
            attributes: contents.attributes(),
        }
        .into());
    }
    serde_json::from_slice(contents.data())
        .map(Some)
        .with_context(|| format!("EFI variable {key} is malformed"))
}

/// Sets the record `name` to the JSON of `record`.
fn write_record(variables: &impl VariableData, name: &str, record: &impl Serialize) -> Result<()> {
    let key = record_key(name);
    let data = serde_json::to_vec(record).with_context(|| format!("EFI variable {key}"))?;
    let contents = VariableContents::new(RECORD_ATTRIBUTES, data)
        .with_context(|| format!("EFI variable {key}"))?;
    variables.set_variable(&key, &contents)
}

/// Serde of a record's field as the text that Display writes and FromStr reads.
mod as_text {
    use std::fmt::Display;
    use std::str::FromStr;

    use serde::de::Error;
    use serde::Deserialize;
    use serde::Deserializer;
    use serde::Serializer;

    pub(super) fn serialize<S: Serializer>(
        value: &impl Display,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_str(value)
    }

    pub(super) fn deserialize<'de, T, D>(deserializer: D) -> Result<T, D::Error>
    where
        T: FromStr<Err: Display>,
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(D::Error::custom)
    }
}

/// IncludedStates as the list of the states that --include names.
mod included_states {
    use serde::de::Error;
    use serde::Deserialize;
    use serde::Deserializer;
    use serde::Serializer;

    use super::IncludedStates;

    /// The names of the states of `include`, as --include takes them, in the order of
    /// IncludedStates' flags.
    fn names(include: IncludedStates) -> Vec<String> {
        include.iter().map(|state| state.to_string()).collect()
    }

    pub(super) fn serialize<S: Serializer>(
        include: &IncludedStates,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(names(*include))
    }

    /// Refuses names that serialize does not write: unknown, repeated or out of order.
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<IncludedStates, D::Error> {
        let written = Vec::<String>::deserialize(deserializer)?;
        let include = IncludedStates::all()
            .iter()
            .filter(|state| written.contains(&state.to_string()))
            .collect();
        match names(include) == written {
            true => Ok(include),
            false => Err(D::Error::custom(format!(
                "{written:?} are not the states of --include, each once, in the order {:?}",
                names(IncludedStates::all())
            ))),
        }
    }
}

/// A grant of unsafe operations: "allow" with --i-am-fine-to-brick-this-system, else "refuse".
mod unsafe_operations {
    use serde::de::Error;
    use serde::Deserialize;
    use serde::Deserializer;
    use serde::Serializer;

    use super::UnsafeOperations;

    fn name(grant: UnsafeOperations) -> &'static str {
        match grant {
            UnsafeOperations::Refuse => "refuse",
            UnsafeOperations::Allow => "allow",
        }
    }

    pub(super) fn serialize<S: Serializer>(
        grant: &UnsafeOperations,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(name(*grant))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<UnsafeOperations, D::Error> {
        let text = String::deserialize(deserializer)?;
        [UnsafeOperations::Refuse, UnsafeOperations::Allow]
            .into_iter()
            .find(|&grant| name(grant) == text)
            .ok_or_else(|| D::Error::custom(format!("{text:?} is no grant of unsafe operations")))
    }
}

/// An access level as --access-level names it, or null.
mod access_level {
    use serde::de::Error;
    use serde::Deserialize;
    use serde::Deserializer;
    use serde::Serializer;

    use super::AccessLevel;

    fn name(level: AccessLevel) -> &'static str {
        match level {
            AccessLevel::Administrator => "administrator",
            AccessLevel::User => "user",
        }
    }

    pub(super) fn serialize<S: Serializer>(
        level: &Option<AccessLevel>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match level {
            Some(level) => serializer.serialize_some(name(*level)),
            None => serializer.serialize_none(),
        }
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<AccessLevel>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|text| {
                [AccessLevel::Administrator, AccessLevel::User]
                    .into_iter()
                    .find(|&level| name(level) == text)
                    .ok_or_else(|| D::Error::custom(format!("{text:?} is no access level")))
            })
            .transpose()
    }
}

/// Why staging refuses, before it writes anything.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum StageRefusal {
    #[error(
        "BootNext names {0}, which uefisettings did not stage; staging would replace it, as \
         BootNext names one option"
    )]
    ForeignBootNext(LoadOptionName),
    #[error(
        "OsIndications holds {}, so the next boot does not start BootNext's option unattended",
        bit_names(*.0)
    )]
    OsIndications(OsIndications),
    #[error(
        "the EFI system partition holds {}, which no staged set names",
        .0.join(", ")
    )]
    ForeignFiles(Vec<String>),
    #[error(
        "OsIndications holds FILE_CAPSULE_DELIVERY_SUPPORTED and the EFI system partition holds \
         {}, so the next boot processes capsules and clears BootNext without starting its option \
         (UEFI 2.11 §8.5.5)",
        .0.join(", ")
    )]
    CapsulesOnDisk(Vec<String>),
}

/// A record that uefisettings refuses to read.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum RecordError {
    #[error("EFI variable {key} has attributes {attributes}, not those of uefisettings' records, {RECORD_ATTRIBUTES}")]
    Attributes {
        key: VariableKey,
        attributes: VariableAttributes,
    },
    #[error("{text:?} is not {digits} lowercase hexadecimal digits")]
    Hex { text: String, digits: usize },
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::btree_map::Entry;
    use std::collections::BTreeMap;

    use super::*;
    use crate::efi_variables::globals::tests::key;
    use crate::efi_variables::globals::tests::HeldVariables;
    use crate::efi_variables::load_option::DevicePathNode;
    use crate::efi_variables::load_option::FilePathList;
    use crate::efi_variables::load_option::LoadOptionAttributes;
    use crate::hii::VariableInterface;

    const NONCE: Nonce = Nonce([
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF,
    ]);
    const OTHER_NONCE: Nonce = Nonce([0xA5; 16]);
    const IMAGE: &str = "\\EFI\\uefisettings\\uefisettings.efi";
    const DIGEST: Sha256Digest = Sha256Digest([0x42; 32]);
    const FORM_SET: &str = "8C78A505-BAA0-4C4A-869F-000000001A09";
    /// The staged set's Boot####
    const BOOT_OPTION: u16 = 0x0007;

    fn request(value: u64) -> StagedRequest {
        StagedRequest {
            question: "Generic Question".to_owned(),
            form_set: FORM_SET.parse().expect("FORM_SET"),
            question_id: 0x0201,
            value_type: IfrValueType::NumSize8,
            value,
            include: IncludedStates::empty(),
            access_level: None,
            unsafe_operations: UnsafeOperations::Refuse,
        }
    }

    /// request(2), selected with every state and access level of a user, staged with
    /// --i-am-fine-to-brick-this-system.
    fn including_request() -> StagedRequest {
        StagedRequest {
            include: IncludedStates::all(),
            access_level: Some(AccessLevel::User),
            unsafe_operations: UnsafeOperations::Allow,
            ..request(2)
        }
    }

    fn staged_set() -> StagedSet {
        StagedSet {
            nonce: NONCE,
            boot_option: BOOT_OPTION,
            image: StagedImage {
                path: IMAGE.to_owned(),
                sha256: DIGEST,
            },
            requests: vec![request(1), including_request()],
        }
    }

    fn started(nonce: Nonce) -> Outcome {
        Outcome::Started { nonce }
    }

    fn finished(nonce: Nonce) -> Outcome {
        Outcome::Finished {
            nonce,
            results: vec![RequestOutcome {
                request: request(1),
                applied: true,
                result: "applied".to_owned(),
            }],
        }
    }

    fn interrupted() -> Outcome {
        Outcome::Interrupted {
            nonce: NONCE,
            requests: staged_set().requests,
        }
    }

    fn not_started() -> Outcome {
        Outcome::NotStarted {
            nonce: NONCE,
            requests: staged_set().requests,
        }
    }

    /// The JSON of `record`.
    fn json(record: &impl Serialize) -> Vec<u8> {
        serde_json::to_vec(record).expect("JSON of a record")
    }

    /// A Boot#### whose OptionalData is the command line of `nonce`.
    fn boot_option(nonce: Nonce) -> Vec<u8> {
        let image = Ucs2String::try_from(IMAGE).expect("IMAGE in UCS-2");
        LoadOption {
            attributes: LoadOptionAttributes::ACTIVE
                | LoadOptionAttributes::HIDDEN
                | LoadOptionAttributes::CATEGORY_APP,
            description: Ucs2String::try_from("uefisettings").expect("a description"),
            file_paths: FilePathList::of(&[DevicePathNode::FilePath(image)])
                .expect("a FilePathList"),
            optional_data: optional_data(nonce).expect("the command line"),
        }
        .encode()
    }

    /// Variables that hold the record of staged_set(), its Boot####, BootNext if given and the
    /// outcome if given.
    fn staged(boot_next: Option<u16>, outcome: Option<&Outcome>) -> HeldVariables {
        let held = HeldVariables::default()
            .with(STAGED_SET, UEFISETTINGS_VENDOR_GUID, &json(&staged_set()))
            .with("Boot0007", EFI_GLOBAL_VARIABLE, &boot_option(NONCE));
        let held = match boot_next {
            Some(number) => held.with("BootNext", EFI_GLOBAL_VARIABLE, &number.to_le_bytes()),
            None => held,
        };
        match outcome {
            Some(outcome) => held.with(STAGED_OUTCOME, UEFISETTINGS_VENDOR_GUID, &json(outcome)),
            None => held,
        }
    }

    /// The record `name` that `variables` hold, None if absent.
    fn record<T: DeserializeOwned>(variables: &HeldVariables, name: &str) -> Option<T> {
        read_record(variables, name).expect("a record")
    }

    fn held(variables: &HeldVariables, name: &str, vendor: Guid) -> bool {
        variables
            .variables
            .borrow()
            .contains_key(&key(name, vendor))
    }

    /// Files of staged images in memory, by path, each with its SHA-256; records each deletion.
    /// A placed image reads back as `read_back` if given.
    #[derive(Default)]
    struct HeldFiles {
        files: RefCell<BTreeMap<String, Sha256Digest>>,
        deleted: RefCell<Vec<String>>,
        read_back: Option<Sha256Digest>,
        capsules: Vec<String>,
    }

    impl HeldFiles {
        fn with(self, path: &str, sha256: Sha256Digest) -> Self {
            self.files.borrow_mut().insert(path.to_owned(), sha256);
            self
        }
    }

    impl StagedFiles for HeldFiles {
        fn list(&self) -> Result<Vec<String>> {
            Ok(self.files.borrow().keys().cloned().collect())
        }

        fn sha256(&self, path: &str) -> Result<Option<Sha256Digest>> {
            Ok(self.files.borrow().get(path).copied())
        }

        fn capsules(&self) -> Result<Vec<String>> {
            Ok(self.capsules.clone())
        }

        fn delete(&self, path: &str) -> Result<()> {
            self.deleted.borrow_mut().push(path.to_owned());
            self.files.borrow_mut().remove(path);
            Ok(())
        }

        fn place(&self, path: &str, image: &[u8]) -> Result<Sha256Digest> {
            let digest = self
                .read_back
                .unwrap_or_else(|| Sha256Digest(Sha256::digest(image).into()));
            match self.files.borrow_mut().entry(path.to_owned()) {
                Entry::Occupied(_) => Err(anyhow!("{path} exists")),
                Entry::Vacant(entry) => Ok(*entry.insert(digest)),
            }
        }
    }

    /// VariableData that fail to set `failing`, else are `held`.
    struct FailingSet<'a> {
        held: &'a HeldVariables,
        failing: VariableKey,
    }

    impl VariableData for FailingSet<'_> {
        fn interface(&self) -> VariableInterface {
            self.held.interface()
        }

        fn variable_data(&self, key: &VariableKey) -> Result<Option<VariableContents>> {
            self.held.variable_data(key)
        }

        fn set_variable(&self, key: &VariableKey, contents: &VariableContents) -> Result<()> {
            match *key == self.failing {
                true => Err(anyhow!("no space for {key}")),
                false => self.held.set_variable(key, contents),
            }
        }

        fn delete_variable(&self, key: &VariableKey) -> Result<()> {
            self.held.delete_variable(key)
        }
    }

    /// The image that stage_new stages here.
    const IMAGE_BYTES: &[u8] = b"MZ an image";

    /// The Hard Drive node that stage_new names the image's partition by here.
    fn hard_drive() -> HardDrive {
        HardDrive {
            partition_number: 1,
            start: 2048,
            size: 2048,
            signature: crate::efi_variables::load_option::PartitionSignature::Gpt(
                "8C78A505-BAA0-4C4A-869F-000000001A0E"
                    .parse()
                    .expect("a GUID"),
            ),
        }
    }

    /// The data and attributes of the variable `name` of `vendor`, if held.
    fn data(
        variables: &HeldVariables,
        name: &str,
        vendor: Guid,
    ) -> Option<(Vec<u8>, VariableAttributes)> {
        variables
            .variables
            .borrow()
            .get(&key(name, vendor))
            .map(|contents| (contents.data().to_vec(), contents.attributes()))
    }

    #[test]
    fn records_are_json_with_their_ids_and_digests_as_text() {
        let set = r#"{"nonce":"00112233445566778899aabbccddeeff","boot_option":7,"image":{"path":"\\EFI\\uefisettings\\uefisettings.efi","sha256":"4242424242424242424242424242424242424242424242424242424242424242"},"requests":[{"question":"Generic Question","form_set":"8C78A505-BAA0-4C4A-869F-000000001A09","question_id":513,"value_type":"EFI_IFR_TYPE_NUM_SIZE_8","value":1,"include":[],"access_level":null,"unsafe_operations":"refuse"},{"question":"Generic Question","form_set":"8C78A505-BAA0-4C4A-869F-000000001A09","question_id":513,"value_type":"EFI_IFR_TYPE_NUM_SIZE_8","value":2,"include":["grayed-out","suppressed","disabled"],"access_level":"user","unsafe_operations":"allow"}]}"#;
        let request_json = r#"{"question":"Generic Question","form_set":"8C78A505-BAA0-4C4A-869F-000000001A09","question_id":513,"value_type":"EFI_IFR_TYPE_NUM_SIZE_8","value":1,"include":[],"access_level":null,"unsafe_operations":"refuse"}"#;
        let outcomes = [
            (
                started(NONCE),
                r#"{"state":"started","nonce":"00112233445566778899aabbccddeeff"}"#.to_owned(),
            ),
            (
                finished(NONCE),
                format!(
                    r#"{{"state":"finished","nonce":"00112233445566778899aabbccddeeff","results":[{{"request":{request_json},"applied":true,"result":"applied"}}]}}"#
                ),
            ),
            (
                Outcome::NotStarted {
                    nonce: NONCE,
                    requests: vec![request(1)],
                },
                format!(
                    r#"{{"state":"not-started","nonce":"00112233445566778899aabbccddeeff","requests":[{request_json}]}}"#
                ),
            ),
            (
                Outcome::Interrupted {
                    nonce: NONCE,
                    requests: vec![request(1)],
                },
                format!(
                    r#"{{"state":"interrupted","nonce":"00112233445566778899aabbccddeeff","requests":[{request_json}]}}"#
                ),
            ),
        ];

        assert_eq!(
            serde_json::to_string(&staged_set()).ok(),
            Some(set.to_owned()),
            "StagedSet"
        );
        assert_eq!(
            serde_json::from_str::<StagedSet>(set).ok(),
            Some(staged_set()),
            "StagedSet read back"
        );
        for (outcome, text) in outcomes {
            assert_eq!(
                serde_json::to_string(&outcome).ok(),
                Some(text.clone()),
                "{text}"
            );
            assert_eq!(
                serde_json::from_str::<Outcome>(&text).ok(),
                Some(outcome),
                "{text} read back"
            );
        }
    }

    #[test]
    fn records_and_fields_that_are_not_what_they_write_are_refused() {
        let nonce = "00112233445566778899aabbccddeeff";
        assert_eq!(nonce.parse(), Ok(NONCE), "a nonce");
        for text in [
            "00112233445566778899AABBCCDDEEFF",
            "00112233445566778899aabbccddeef",
            "00112233445566778899aabbccddeeff0",
            "00112233445566778899aabbccddeefg",
            "",
        ] {
            assert_eq!(
                text.parse::<Nonce>(),
                Err(RecordError::Hex {
                    text: text.to_owned(),
                    digits: 32
                }),
                "nonce {text:?}"
            );
        }
        assert_eq!(
            "42".repeat(32).parse::<Sha256Digest>(),
            Ok(DIGEST),
            "a SHA-256"
        );
        assert!("42".repeat(31).parse::<Sha256Digest>().is_err(), "31 bytes");
        for value_type in [
            IfrValueType::NumSize8,
            IfrValueType::NumSize16,
            IfrValueType::NumSize32,
            IfrValueType::NumSize64,
            IfrValueType::Boolean,
        ] {
            assert_eq!(
                value_type.to_string().parse(),
                Ok(value_type),
                "{value_type} read back"
            );
        }

        let set = String::from_utf8(json(&staged_set())).expect("JSON");
        for (case, text) in [
            ("an unknown field", set.replacen("{", r#"{"extra":1,"#, 1)),
            (
                "an unknown value type",
                set.replace("EFI_IFR_TYPE_NUM_SIZE_8", "EFI_IFR_TYPE_STRING"),
            ),
            ("a missing field", set.replace(r#""boot_option":7,"#, "")),
            (
                "an unknown state",
                set.replace(r#""suppressed","#, r#""hidden","#),
            ),
            (
                "a state twice named",
                set.replace(r#""suppressed","#, r#""disabled","#),
            ),
            (
                "states out of order",
                set.replace(
                    r#""grayed-out","suppressed""#,
                    r#""suppressed","grayed-out""#,
                ),
            ),
            (
                "an unknown access level",
                set.replace(r#""access_level":"user""#, r#""access_level":"root""#),
            ),
            (
                "an unknown grant of unsafe operations",
                set.replace(
                    r#""unsafe_operations":"allow""#,
                    r#""unsafe_operations":"ask""#,
                ),
            ),
            (
                "no grant of unsafe operations",
                set.replace(r#","unsafe_operations":"allow""#, ""),
            ),
            (
                "the state read-only, which no condition gives",
                set.replace(r#""disabled"]"#, r#""disabled","read-only"]"#),
            ),
        ] {
            assert!(serde_json::from_str::<StagedSet>(&text).is_err(), "{case}");
        }
        for text in [
            r#"{"state":"applied","nonce":"00112233445566778899aabbccddeeff"}"#,
            r#"{"state":"started","nonce":"00112233445566778899aabbccddeeff","extra":1}"#,
        ] {
            assert!(serde_json::from_str::<Outcome>(text).is_err(), "{text}");
        }
    }

    #[test]
    fn a_staged_set_s_command_line_is_its_nonce_after_the_image_and_command() {
        let command: Vec<u8> = "uefisettings.efi apply-staged 00112233445566778899aabbccddeeff"
            .encode_utf16()
            .chain([0])
            .flat_map(u16::to_le_bytes)
            .collect();

        assert_eq!(
            optional_data(NONCE),
            Ok(command),
            "the OptionalData of NONCE"
        );
        assert_ne!(
            optional_data(OTHER_NONCE),
            optional_data(NONCE),
            "another nonce's"
        );
    }

    #[test]
    fn the_state_follows_the_records_their_nonces_and_boot_next() {
        let pending = StagedState::Pending(staged_set());
        let over = |outcome| StagedState::Over(staged_set(), outcome);
        let cases = [
            (
                "no record",
                HeldVariables::default(),
                StagedState::Idle(None),
            ),
            (
                "an outcome only",
                HeldVariables::default().with(
                    STAGED_OUTCOME,
                    UEFISETTINGS_VENDOR_GUID,
                    &json(&finished(OTHER_NONCE)),
                ),
                StagedState::Idle(Some(finished(OTHER_NONCE))),
            ),
            (
                "BootNext naming the set's Boot####",
                staged(Some(BOOT_OPTION), None),
                pending.clone(),
            ),
            ("no BootNext", staged(None, None), over(not_started())),
            (
                "BootNext naming another option",
                staged(Some(0x0001), None),
                over(not_started()),
            ),
            (
                "started, BootNext naming the set's Boot####",
                staged(Some(BOOT_OPTION), Some(&started(NONCE))),
                over(interrupted()),
            ),
            (
                "another set started, BootNext naming this one's Boot####",
                staged(Some(BOOT_OPTION), Some(&started(OTHER_NONCE))),
                pending,
            ),
            (
                "another set started, no BootNext",
                staged(None, Some(&started(OTHER_NONCE))),
                over(not_started()),
            ),
            (
                "another set finished, no BootNext",
                staged(None, Some(&finished(OTHER_NONCE))),
                over(not_started()),
            ),
            (
                "finished",
                staged(Some(BOOT_OPTION), Some(&finished(NONCE))),
                over(finished(NONCE)),
            ),
            (
                "settled as not started",
                staged(Some(BOOT_OPTION), Some(&not_started())),
                over(not_started()),
            ),
        ];
        for (case, variables, want) in cases {
            let got = StagedState::read(&variables).expect("the state");

            assert_eq!(got, want, "{case}");
        }
    }

    #[test]
    fn records_of_other_attributes_or_data_are_refused() {
        let variables = HeldVariables::default().with_attributes(
            STAGED_SET,
            UEFISETTINGS_VENDOR_GUID,
            VariableAttributes::NON_VOLATILE | VariableAttributes::BOOTSERVICE_ACCESS,
            &json(&staged_set()),
        );
        assert_eq!(
            StagedState::read(&variables).map_err(|err| format!("{err:#}")),
            Err(
                "EFI variable UefisettingsStagedSet-dd16f539-09ed-41b9-8b64-d85d6cd93a8e has \
                 attributes NON_VOLATILE | BOOTSERVICE_ACCESS, not those of uefisettings' \
                 records, NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS"
                    .to_owned()
            ),
            "NV, BS"
        );

        let variables =
            HeldVariables::default().with(STAGED_OUTCOME, UEFISETTINGS_VENDOR_GUID, b"started");
        let got = StagedState::read(&variables).map_err(|err| format!("{err:#}"));
        assert!(
            got.as_ref().is_err_and(|err| err.starts_with(
                "EFI variable UefisettingsStagedOutcome-dd16f539-09ed-41b9-8b64-d85d6cd93a8e is \
                 malformed: "
            )),
            "an outcome of no JSON: {got:?}"
        );
    }

    #[test]
    fn settling_records_the_outcome_and_deletes_what_is_still_the_set_s() {
        let image = || HeldFiles::default().with(IMAGE, DIGEST);
        let cases = [
            (
                "finished",
                staged(Some(BOOT_OPTION), Some(&finished(NONCE))),
                finished(NONCE),
            ),
            ("not started", staged(None, None), not_started()),
            (
                "interrupted",
                staged(Some(BOOT_OPTION), Some(&started(NONCE))),
                interrupted(),
            ),
        ];
        for (case, variables, outcome) in cases {
            let files = image();

            let got = settle(&variables, &files).expect("settle");

            assert_eq!(got, Settled::Idle(Some(outcome.clone())), "{case}");
            assert_eq!(
                record(&variables, STAGED_OUTCOME),
                Some(outcome),
                "{case}: the outcome"
            );
            assert_eq!(
                record::<StagedSet>(&variables, STAGED_SET),
                None,
                "{case}: the record"
            );
            for name in ["Boot0007", "BootNext"] {
                assert!(
                    !held(&variables, name, EFI_GLOBAL_VARIABLE),
                    "{case}: {name}"
                );
            }
            assert_eq!(*files.deleted.borrow(), [IMAGE], "{case}: the image");

            // nothing is left to settle
            variables.set.borrow_mut().clear();
            variables.deleted.borrow_mut().clear();
            let again = settle(&variables, &files).expect("settle again");
            assert_eq!(again, got, "{case}: again");
            assert!(
                variables.set.borrow().is_empty(),
                "{case}: nothing set again"
            );
            assert!(
                variables.deleted.borrow().is_empty(),
                "{case}: nothing deleted again"
            );
            assert_eq!(
                files.deleted.borrow().len(),
                1,
                "{case}: no file deleted again"
            );
        }
    }

    #[test]
    fn settling_keeps_a_boot_option_and_image_that_are_no_longer_the_set_s() {
        // Boot0007 starts another set, and BootNext names it
        let variables = staged(Some(BOOT_OPTION), Some(&started(NONCE))).with(
            "Boot0007",
            EFI_GLOBAL_VARIABLE,
            &boot_option(OTHER_NONCE),
        );
        let files = HeldFiles::default().with(IMAGE, Sha256Digest([0x24; 32]));

        let got = settle(&variables, &files).expect("settle");

        assert_eq!(got, Settled::Idle(Some(interrupted())), "the outcome");
        assert_eq!(
            variables
                .variables
                .borrow()
                .get(&key("Boot0007", EFI_GLOBAL_VARIABLE))
                .map(|contents| contents.data().to_vec()),
            Some(boot_option(OTHER_NONCE)),
            "another set's Boot0007"
        );
        assert!(
            held(&variables, "BootNext", EFI_GLOBAL_VARIABLE),
            "BootNext"
        );
        assert!(files.deleted.borrow().is_empty(), "a changed image");
        assert_eq!(
            record::<StagedSet>(&variables, STAGED_SET),
            None,
            "the record"
        );

        // no Boot0007 and no image
        let variables = staged(None, None);
        variables
            .variables
            .borrow_mut()
            .remove(&key("Boot0007", EFI_GLOBAL_VARIABLE));
        let files = HeldFiles::default();
        assert_eq!(
            settle(&variables, &files).expect("settle"),
            Settled::Idle(Some(not_started())),
            "nothing to delete but the record"
        );
        assert!(files.deleted.borrow().is_empty(), "no image");
    }

    #[test]
    fn settling_leaves_a_pending_set_and_no_set_alone() {
        let cases = [
            (
                "pending",
                staged(Some(BOOT_OPTION), None),
                Settled::Pending(staged_set()),
            ),
            (
                "idle",
                HeldVariables::default().with(
                    STAGED_OUTCOME,
                    UEFISETTINGS_VENDOR_GUID,
                    &json(&finished(OTHER_NONCE)),
                ),
                Settled::Idle(Some(finished(OTHER_NONCE))),
            ),
        ];
        for (case, variables, want) in cases {
            let files = HeldFiles::default().with(IMAGE, DIGEST);

            let got = settle(&variables, &files).expect("settle");

            assert_eq!(got, want, "{case}");
            assert!(variables.set.borrow().is_empty(), "{case}: nothing set");
            assert!(
                variables.deleted.borrow().is_empty(),
                "{case}: nothing deleted"
            );
            assert!(files.deleted.borrow().is_empty(), "{case}: no file deleted");
        }
    }

    #[test]
    fn a_request_appended_to_the_pending_set_keeps_its_boot_option() {
        let variables = staged(Some(BOOT_OPTION), None);
        let files = HeldFiles::default().with(IMAGE, DIGEST);
        let Ok(StagePlan::Append(mut set)) = plan_stage(&variables, &files) else {
            panic!("no pending set to append to");
        };

        set.requests.push(request(3));
        record_set(&variables, &set).expect("record the set");

        let want = StagedSet {
            requests: vec![request(1), including_request(), request(3)],
            ..staged_set()
        };
        assert_eq!(
            StagedState::read(&variables).expect("the state"),
            StagedState::Pending(want),
            "the pending set"
        );
        assert_eq!(
            variables
                .variables
                .borrow()
                .get(&key("Boot0007", EFI_GLOBAL_VARIABLE))
                .map(|contents| contents.data().to_vec()),
            Some(boot_option(NONCE)),
            "its Boot0007"
        );
    }

    /// Staging waits while OsIndications has FILE_CAPSULE_DELIVERY_SUPPORTED and the ESP holds a
    /// capsule on disk, whose processing clears BootNext without starting its option.
    #[test]
    fn staging_waits_while_a_capsule_on_disk_would_clear_boot_next() {
        let capsule = "\\EFI\\UpdateCapsule\\update.cap";
        let with_bits = |bits: OsIndications| {
            HeldVariables::default().with(
                "OsIndications",
                EFI_GLOBAL_VARIABLE,
                &bits.bits().to_le_bytes(),
            )
        };
        let cases = [
            (
                "FILE_CAPSULE_DELIVERY_SUPPORTED and a capsule",
                with_bits(OsIndications::FILE_CAPSULE_DELIVERY_SUPPORTED),
                vec![capsule.to_owned()],
                Err(format!(
                    "OsIndications holds FILE_CAPSULE_DELIVERY_SUPPORTED and the EFI system \
                     partition holds {capsule}, so the next boot processes capsules and clears \
                     BootNext without starting its option (UEFI 2.11 §8.5.5)"
                )),
            ),
            (
                "FILE_CAPSULE_DELIVERY_SUPPORTED without a capsule",
                with_bits(OsIndications::FILE_CAPSULE_DELIVERY_SUPPORTED),
                Vec::new(),
                Ok(StagePlan::New),
            ),
            (
                "a capsule without FILE_CAPSULE_DELIVERY_SUPPORTED",
                with_bits(OsIndications::TIMESTAMP_REVOCATION),
                vec![capsule.to_owned()],
                Ok(StagePlan::New),
            ),
        ];
        for (case, variables, capsules, want) in cases {
            let files = HeldFiles {
                capsules,
                ..HeldFiles::default()
            };
            assert_eq!(
                plan_stage(&variables, &files).map_err(|err| format!("{err:#}")),
                want,
                "{case}"
            );
            assert!(variables.set.borrow().is_empty(), "{case}: nothing written");
        }
    }

    #[test]
    fn a_new_set_writes_its_image_then_its_record_boot_option_and_boot_next() {
        let image_digest = Sha256Digest(Sha256::digest(IMAGE_BYTES).into());
        let support = |flags: u32| {
            HeldVariables::default()
                .with("Boot0000", EFI_GLOBAL_VARIABLE, &boot_option(OTHER_NONCE))
                .with("Boot0001", EFI_GLOBAL_VARIABLE, &boot_option(OTHER_NONCE))
                .with(
                    "BootOptionSupport",
                    EFI_GLOBAL_VARIABLE,
                    &flags.to_le_bytes(),
                )
        };
        let cases = [
            (
                "BootOptionSupport with EFI_BOOT_OPTION_SUPPORT_APP",
                support(0x0000_0103),
                LoadOptionAttributes::CATEGORY_APP,
            ),
            (
                "BootOptionSupport without it",
                support(0x0000_0001),
                LoadOptionAttributes::empty(),
            ),
            (
                "no BootOptionSupport",
                HeldVariables::default()
                    .with("Boot0000", EFI_GLOBAL_VARIABLE, &boot_option(OTHER_NONCE))
                    .with("Boot0001", EFI_GLOBAL_VARIABLE, &boot_option(OTHER_NONCE)),
                LoadOptionAttributes::empty(),
            ),
        ];
        for (case, variables, category) in cases {
            let files = HeldFiles::default();

            let set = stage_new(
                &variables,
                &files,
                hard_drive(),
                request(1),
                IMAGE_BYTES,
                NONCE,
            )
            .expect("stage a new set");

            let want = StagedSet {
                nonce: NONCE,
                boot_option: 0x0002,
                image: StagedImage {
                    path: IMAGE.to_owned(),
                    sha256: image_digest,
                },
                requests: vec![request(1)],
            };
            assert_eq!(set, want, "{case}: the set");
            assert_eq!(
                files.files.borrow().get(IMAGE),
                Some(&image_digest),
                "{case}: the image"
            );
            assert_eq!(
                record(&variables, STAGED_SET),
                Some(want),
                "{case}: the record"
            );
            let load_option = LoadOption {
                attributes: LoadOptionAttributes::ACTIVE | LoadOptionAttributes::HIDDEN | category,
                description: Ucs2String::try_from("uefisettings: a set staged for this boot")
                    .expect("a description"),
                file_paths: FilePathList::of(&[
                    DevicePathNode::HardDrive(hard_drive()),
                    DevicePathNode::FilePath(Ucs2String::try_from(IMAGE).expect("IMAGE")),
                ])
                .expect("a FilePathList"),
                optional_data: optional_data(NONCE).expect("the command line"),
            };
            let nv_bs_rt = VariableAttributes::NON_VOLATILE
                | VariableAttributes::BOOTSERVICE_ACCESS
                | VariableAttributes::RUNTIME_ACCESS;
            assert_eq!(
                data(&variables, "Boot0002", EFI_GLOBAL_VARIABLE),
                Some((load_option.encode(), nv_bs_rt)),
                "{case}: Boot0002"
            );
            assert_eq!(
                data(&variables, "BootNext", EFI_GLOBAL_VARIABLE),
                Some((vec![0x02, 0x00], nv_bs_rt)),
                "{case}: BootNext"
            );
            assert_eq!(
                *variables.set.borrow(),
                [
                    key(STAGED_SET, UEFISETTINGS_VENDOR_GUID),
                    key("Boot0002", EFI_GLOBAL_VARIABLE),
                    key("BootNext", EFI_GLOBAL_VARIABLE),
                ],
                "{case}: the writes, in order"
            );
            assert_eq!(
                StagedState::read(&variables).expect("the state"),
                StagedState::Pending(set),
                "{case}: the state"
            );
        }
    }

    #[test]
    fn a_new_set_that_fails_to_stage_leaves_nothing_of_it() {
        for failing in [
            key(STAGED_SET, UEFISETTINGS_VENDOR_GUID),
            key("Boot0000", EFI_GLOBAL_VARIABLE),
            key("BootNext", EFI_GLOBAL_VARIABLE),
        ] {
            let held = HeldVariables::default();
            let variables = FailingSet {
                held: &held,
                failing: failing.clone(),
            };
            let files = HeldFiles::default();

            let got = stage_new(
                &variables,
                &files,
                hard_drive(),
                request(1),
                IMAGE_BYTES,
                NONCE,
            )
            .map_err(|err| format!("{err:#}"));

            assert_eq!(got, Err(format!("no space for {failing}")), "{failing}");
            assert!(
                held.variables.borrow().is_empty(),
                "{failing}: no variable stays"
            );
            assert!(files.files.borrow().is_empty(), "{failing}: no image stays");
        }

        // the image reads back as other bytes
        let variables = HeldVariables::default();
        let files = HeldFiles {
            read_back: Some(DIGEST),
            ..HeldFiles::default()
        };
        let got = stage_new(
            &variables,
            &files,
            hard_drive(),
            request(1),
            IMAGE_BYTES,
            NONCE,
        )
        .map_err(|err| format!("{err:#}"));
        assert_eq!(
            got,
            Err(format!(
                "\\EFI\\uefisettings\\uefisettings.efi reads back with SHA-256 {DIGEST}, not the \
                 image's {}",
                Sha256Digest(Sha256::digest(IMAGE_BYTES).into())
            )),
            "a changed read-back"
        );
        assert!(
            variables.variables.borrow().is_empty(),
            "read back: no variable"
        );
        assert_eq!(
            *files.deleted.borrow(),
            [IMAGE],
            "read back: the image deleted"
        );
    }

    /// A new set takes the lowest Boot#### that no load option, BootOrder entry or BootNext
    /// holds, so that no BootOrder entry boots it unattended.
    #[test]
    fn a_new_set_takes_a_number_that_neither_boot_order_nor_boot_next_holds() {
        // Boot0001 is gone, but BootOrder still lists it; BootNext names Boot0002, gone too
        let variables = HeldVariables::default()
            .with("Boot0000", EFI_GLOBAL_VARIABLE, &boot_option(OTHER_NONCE))
            .with("BootOrder", EFI_GLOBAL_VARIABLE, &[0x01, 0x00, 0x00, 0x00])
            .with("BootNext", EFI_GLOBAL_VARIABLE, &[0x02, 0x00]);

        let set = stage_new(
            &variables,
            &HeldFiles::default(),
            hard_drive(),
            request(1),
            IMAGE_BYTES,
            NONCE,
        )
        .expect("stage a new set");

        assert_eq!(set.boot_option, 0x0003, "the set's Boot####");
        assert!(
            held(&variables, "Boot0003", EFI_GLOBAL_VARIABLE),
            "Boot0003 written"
        );
        assert!(
            !held(&variables, "Boot0001", EFI_GLOBAL_VARIABLE),
            "no Boot0001, which BootOrder lists"
        );
    }

    /// A new set whose image file exists, as a set staged at the same time may have placed it,
    /// fails and keeps that file: its undoing deletes only an image that it placed.
    #[test]
    fn a_new_set_over_an_existing_image_fails_and_keeps_it() {
        let image_digest = Sha256Digest(Sha256::digest(IMAGE_BYTES).into());
        let variables = HeldVariables::default();
        let files = HeldFiles::default().with(IMAGE, image_digest);

        let got = stage_new(
            &variables,
            &files,
            hard_drive(),
            request(1),
            IMAGE_BYTES,
            NONCE,
        )
        .map_err(|err| format!("{err:#}"));

        assert_eq!(got, Err(format!("{IMAGE} exists")), "the refusal");
        assert_eq!(
            files.files.borrow().get(IMAGE),
            Some(&image_digest),
            "the image stays"
        );
        assert!(files.deleted.borrow().is_empty(), "nothing deleted");
        assert!(
            variables.variables.borrow().is_empty(),
            "no variable written"
        );
    }

    #[test]
    fn staging_appends_to_the_pending_set_or_stages_a_new_one() {
        let os_indications = |bits: OsIndications| {
            HeldVariables::default().with(
                "OsIndications",
                EFI_GLOBAL_VARIABLE,
                &bits.bits().to_le_bytes(),
            )
        };
        let other_file = "\\EFI\\uefisettings\\other.efi";
        let cases = [
            (
                "no set",
                HeldVariables::default(),
                HeldFiles::default(),
                Ok(StagePlan::New),
            ),
            (
                "a pending set, its image named in another case",
                staged(Some(BOOT_OPTION), None),
                HeldFiles::default().with(&IMAGE.to_ascii_uppercase(), DIGEST),
                Ok(StagePlan::Append(staged_set())),
            ),
            (
                "a set whose boot is over, and its image",
                staged(None, Some(&finished(NONCE))),
                HeldFiles::default().with(IMAGE, DIGEST),
                Ok(StagePlan::New),
            ),
            (
                "OsIndications of other bits",
                os_indications(
                    OsIndications::TIMESTAMP_REVOCATION
                        | OsIndications::FILE_CAPSULE_DELIVERY_SUPPORTED,
                ),
                HeldFiles::default(),
                Ok(StagePlan::New),
            ),
            (
                "BootNext naming an option of no set",
                HeldVariables::default().with("BootNext", EFI_GLOBAL_VARIABLE, &[1, 0]),
                HeldFiles::default(),
                Err(
                    "BootNext names Boot0001, which uefisettings did not stage; staging would \
                     replace it, as BootNext names one option",
                ),
            ),
            (
                "BootNext naming an option other than the set's",
                staged(Some(0x0001), None),
                HeldFiles::default(),
                Err(
                    "BootNext names Boot0001, which uefisettings did not stage; staging would \
                     replace it, as BootNext names one option",
                ),
            ),
            (
                "OsIndications BOOT_TO_FW_UI",
                os_indications(OsIndications::BOOT_TO_FW_UI),
                HeldFiles::default(),
                Err(
                    "OsIndications holds BOOT_TO_FW_UI, so the next boot does not start \
                     BootNext's option unattended",
                ),
            ),
            (
                "OsIndications START_OS_RECOVERY and others",
                os_indications(
                    OsIndications::START_OS_RECOVERY | OsIndications::TIMESTAMP_REVOCATION,
                ),
                HeldFiles::default(),
                Err(
                    "OsIndications holds START_OS_RECOVERY, so the next boot does not start \
                     BootNext's option unattended",
                ),
            ),
            (
                "OsIndications START_PLATFORM_RECOVERY",
                os_indications(OsIndications::START_PLATFORM_RECOVERY),
                HeldFiles::default(),
                Err(
                    "OsIndications holds START_PLATFORM_RECOVERY, so the next boot does not \
                     start BootNext's option unattended",
                ),
            ),
            (
                "a file of no set",
                HeldVariables::default(),
                HeldFiles::default().with(other_file, DIGEST),
                Err(
                    "the EFI system partition holds \\EFI\\uefisettings\\other.efi, which no \
                     staged set names",
                ),
            ),
            (
                "a pending set and a file it does not name",
                staged(Some(BOOT_OPTION), None),
                HeldFiles::default()
                    .with(IMAGE, DIGEST)
                    .with(other_file, DIGEST),
                Err(
                    "the EFI system partition holds \\EFI\\uefisettings\\other.efi, which no \
                     staged set names",
                ),
            ),
        ];
        for (case, variables, files, want) in cases {
            let got = plan_stage(&variables, &files).map_err(|err| format!("{err:#}"));

            assert_eq!(got, want.map_err(str::to_owned), "{case}");
        }
    }
}
