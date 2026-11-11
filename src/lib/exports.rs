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
use std::path::PathBuf;
use std::rc::Rc;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
#[cfg(firmware_memory_maps)]
use log::debug;
use log::warn;

use uefisettings_backend_thrift::Backend;
use uefisettings_backend_thrift::GetResponse;
use uefisettings_backend_thrift::GetResponseList;
use uefisettings_backend_thrift::HiiIgnoredIfr;
use uefisettings_backend_thrift::HiiShowIfrResponse;
use uefisettings_backend_thrift::HiiStringsPackage;
use uefisettings_backend_thrift::Question;
use uefisettings_backend_thrift::QuestionDefault;
use uefisettings_backend_thrift::QuestionKeyword;
use uefisettings_backend_thrift::SetResponse;
use uefisettings_backend_thrift::SetResponseList;

#[cfg(variable_data)]
use crate::efi_variables::authenticated::sign_and_write;
#[cfg(variable_data)]
use crate::efi_variables::authenticated::sign_and_write_enhanced;
#[cfg(variable_data)]
use crate::efi_variables::authenticated::signing::PlatformSeed;
#[cfg(variable_data)]
use crate::efi_variables::authenticated::signing::Signer;
#[cfg(variable_data)]
use crate::efi_variables::authenticated::write_signed;
#[cfg(variable_data)]
use crate::efi_variables::authenticated::EnhancedSignedWrite;
#[cfg(variable_data)]
pub use crate::efi_variables::authenticated::SetupModeReading;
#[cfg(variable_data)]
pub use crate::efi_variables::authenticated::SignatureDigest;
#[cfg(variable_data)]
use crate::efi_variables::authenticated::SignedWrite;
#[cfg(variable_data)]
pub use crate::efi_variables::authenticated::TimeStamp;
#[cfg(variable_data)]
pub use crate::efi_variables::authenticated::TimeStampError;
#[cfg(capsule_delivery)]
use crate::efi_variables::deliver_json_capsule;
#[cfg(variable_data)]
pub use crate::efi_variables::enhanced_authenticated::Freshness;
#[cfg(variable_data)]
pub use crate::efi_variables::enhanced_authenticated::Nonce;
#[cfg(variable_data)]
pub use crate::efi_variables::enhanced_authenticated::NonceError;
#[cfg(variable_data)]
use crate::efi_variables::globals::read_global;
#[cfg(variable_data)]
use crate::efi_variables::globals::write_global;
#[cfg(variable_data)]
pub use crate::efi_variables::globals::BootOptionFlags;
#[cfg(variable_data)]
pub use crate::efi_variables::globals::BootOptionSupport;
#[cfg(variable_data)]
pub use crate::efi_variables::globals::GlobalContents;
#[cfg(variable_data)]
pub use crate::efi_variables::globals::GlobalValue;
#[cfg(variable_data)]
pub use crate::efi_variables::globals::GlobalVariable;
#[cfg(variable_data)]
pub use crate::efi_variables::globals::LoadOptionKind;
#[cfg(variable_data)]
pub use crate::efi_variables::globals::LoadOptionName;
#[cfg(variable_data)]
pub use crate::efi_variables::globals::OsIndications;
#[cfg(variable_data)]
pub use crate::efi_variables::globals::Signature;
#[cfg(variable_data)]
pub use crate::efi_variables::globals::SignatureList;
#[cfg(variable_data)]
pub use crate::efi_variables::globals::Timeout;
#[cfg(variable_names)]
use crate::efi_variables::list_capsule_results;
#[cfg(variable_names)]
use crate::efi_variables::list_variables;
#[cfg(any(variable_names, variable_info, variable_data))]
use crate::efi_variables::parse_vendor;
#[cfg(target_os = "windows")]
use crate::efi_variables::probe_capsule_results;
#[cfg(variable_storage_info)]
use crate::efi_variables::query_storage;
#[cfg(configuration_tables)]
use crate::efi_variables::read_json_capsule_result;
#[cfg(configuration_tables)]
use crate::efi_variables::read_json_config_data;
#[cfg(variable_data)]
use crate::efi_variables::secure_boot_mode::set_mode;
#[cfg(variable_data)]
use crate::efi_variables::secure_boot_mode::ModeRequest;
#[cfg(variable_data)]
pub use crate::efi_variables::secure_boot_mode::ModeTransition;
#[cfg(variable_data)]
pub use crate::efi_variables::secure_boot_mode::ModeTransitionStatus;
#[cfg(variable_data)]
pub use crate::efi_variables::secure_boot_mode::ModeTransitionWrite;
#[cfg(capsule_delivery)]
pub use crate::efi_variables::CapsuleCapabilities;
#[cfg(capsule_delivery)]
pub use crate::efi_variables::CapsuleDelivered;
#[cfg(variable_data)]
pub use crate::efi_variables::CapsuleResult;
#[cfg(variable_data)]
pub use crate::efi_variables::CapsuleResultDetails;
#[cfg(variable_data)]
pub use crate::efi_variables::CapsuleResultError;
#[cfg(variable_data)]
pub use crate::efi_variables::CapsuleResults;
#[cfg(variable_data)]
pub use crate::efi_variables::EfiTime;
#[cfg(variable_data)]
pub use crate::efi_variables::FmpCapsuleResult;
#[cfg(variable_data)]
pub use crate::efi_variables::JsonCapsuleResult;
#[cfg(configuration_tables)]
pub use crate::efi_variables::JsonConfigData;
#[cfg(variable_data)]
pub use crate::efi_variables::NamedCapsuleResult;
#[cfg(capsule_delivery)]
pub use crate::efi_variables::ResetType;
#[cfg(variable_data)]
pub use crate::efi_variables::ResultName;
#[cfg(variable_data)]
pub use crate::efi_variables::TextOrHex;
#[cfg(variable_data)]
pub use crate::efi_variables::Undecoded;
#[cfg(variable_info)]
use crate::efi_variables::VariableInfoSource;
#[cfg(variable_storage_info)]
pub use crate::efi_variables::VariableStorage;
use crate::hii::config_snapshot::ExportedConfig;
use crate::hii::config_snapshot::SnapshotLookup;
#[cfg(target_os = "linux")]
pub use crate::hii::extract::EfivarMemory;
#[cfg(target_os = "linux")]
pub use crate::hii::extract::HiiDbVariableAbsent;
#[cfg(target_os = "linux")]
pub use crate::hii::extract::HiiMethod;
#[cfg(target_os = "linux")]
pub use crate::hii::extract::HiiMethodError;
#[cfg(target_os = "linux")]
pub use crate::hii::extract::HiiSource;
#[cfg(target_os = "linux")]
pub use crate::hii::extract::HiiSourceOptions;
#[cfg(target_os = "linux")]
pub use crate::hii::extract::NoHiiDatabase;
use crate::hii::forms;
use crate::hii::forms::keywords::KeywordRefusal;
use crate::hii::forms::keywords::KeywordStatement;
use crate::hii::forms::list_questions;
use crate::hii::forms::Choice;
use crate::hii::forms::DeclaredDefault;
use crate::hii::forms::DriverHeldQuestion;
use crate::hii::forms::DriverStore;
use crate::hii::forms::Exclusion;
use crate::hii::forms::ExpressionBesideCallback;
use crate::hii::forms::PasswordQuestions;
use crate::hii::forms::QuestionDescriptor;
use crate::hii::forms::QuestionExpression;
use crate::hii::forms::QuestionFlags;
use crate::hii::package;
use crate::hii::package::DevicePath;
#[cfg(any(variable_names, variable_info, variable_data))]
pub use crate::hii::package::Guid;
use crate::hii::time_services::TimeServices;
#[cfg(target_os = "linux")]
pub use crate::hii::DenialCause;
#[cfg(target_os = "linux")]
pub use crate::hii::EfivarDump;
use crate::hii::EfivarReader;
#[cfg(target_os = "linux")]
pub use crate::hii::EfivarRedaction;
pub use crate::hii::EfivarSource;
/// Only on Linux x86, x86_64 and aarch64, where uefisettings reads a firmware memory map.
#[cfg(firmware_memory_maps)]
pub use crate::hii::ExportedConfigError;
use crate::hii::FirmwareVariables;
/// Only on Linux x86, x86_64 and aarch64, where uefisettings reads a firmware memory map.
#[cfg(firmware_memory_maps)]
pub use crate::hii::HiiExportError;
#[cfg(target_os = "uefi")]
pub use crate::hii::KeywordFilterBy;
#[cfg(target_os = "uefi")]
pub use crate::hii::KeywordGetOptions;
#[cfg(target_os = "uefi")]
pub use crate::hii::KeywordInfoSource;
#[cfg(target_os = "uefi")]
pub use crate::hii::KeywordValues;
#[cfg(target_os = "linux")]
pub use crate::hii::LockdownMode;
#[cfg(target_os = "linux")]
pub use crate::hii::LockdownUnknown;
#[cfg(target_os = "linux")]
pub use crate::hii::MemoryAccessDenied;
#[cfg(target_os = "linux")]
pub use crate::hii::MemoryDevice;
#[cfg(target_os = "linux")]
pub use crate::hii::MemoryMapUnavailable;
#[cfg(target_os = "linux")]
pub use crate::hii::MemoryOperation;
/// Only on Linux x86, x86_64 and aarch64, where uefisettings reads a firmware memory map.
#[cfg(firmware_memory_maps)]
pub use crate::hii::MemoryType;
/// Only on Linux x86, x86_64 and aarch64, where uefisettings reads a firmware memory map.
#[cfg(firmware_memory_maps)]
pub use crate::hii::RangeRefusal;
/// Only on Linux x86, x86_64 and aarch64, where uefisettings reads a firmware memory map.
#[cfg(firmware_memory_maps)]
pub use crate::hii::SystemTableError;
#[cfg(any(variable_storage_info, variable_data))]
pub use crate::hii::VariableAttributes;
#[cfg(any(variable_names, variable_info))]
pub use crate::hii::VariableKey;
use crate::hii::VariableReach;
use crate::hii::WithholdingVariables;
use crate::hii::VOLATILE_ANNOTATION;
#[cfg(variable_data)]
use crate::secret_file::Secret;
#[cfg(all(variable_data, any(target_os = "uefi", test)))]
use crate::staged_set::StagedRequest;
use crate::terminal_text::TextLines;
use crate::translation::get_qa_variations_hii;
use crate::translation::translate_response;
use crate::translation::HiiTranslation;
use crate::unsafe_operations::PendingOperations;

pub use crate::hii::forms::AccessLevel;
pub use crate::hii::forms::IgnoredIfr;
pub use crate::hii::forms::IncludedStates;
pub use crate::hii::forms::KeywordError;
pub use crate::hii::forms::KeywordName;
pub use crate::hii::forms::KeywordNamespace;
pub use crate::hii::forms::OptionMatch;
pub use crate::hii::forms::PromptMatch;
pub use crate::hii::forms::QuestionAddress;
pub use crate::hii::forms::QuestionAddressError;
pub use crate::hii::forms::QuestionSelector;
pub use crate::hii::forms::QuestionState;
pub use crate::hii::forms::SelectionError;
pub use crate::hii::VolatileWrites;
pub use crate::unsafe_operations::LiftedOperations;
pub use crate::unsafe_operations::UnsafeOperation;
pub use crate::unsafe_operations::UnsafeOperationRefused;
pub use crate::unsafe_operations::UnsafeOperations;
pub use crate::unsafe_operations::UNSAFE_OPERATIONS_FLAG;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "uefi")]
mod uefi;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(variable_info)]
pub use crate::efi_variables::MetadataInfo;
#[cfg(variable_info)]
pub use crate::efi_variables::VariableInfo;
#[cfg(target_os = "linux")]
pub use linux::identify_machine;
#[cfg(target_os = "linux")]
pub use linux::identify_machine_using;
#[cfg(target_os = "linux")]
pub use linux::IloBackend;
#[cfg(target_os = "uefi")]
pub use uefi::KeywordSetOptions;

/// SettingsBackend is a trait which should be satisfied by all backends (like ilo, hii)
pub trait SettingsBackend {
    /// set changes the value of the UEFI question/attribute
    fn set(question: &str, new_value: &str, selector: Option<&str>) -> Result<SetResponseList>;
    /// get displays the value of the UEFI question/attribute
    fn get(question: &str, selector: Option<&str>) -> Result<GetResponseList>;
}

pub struct HiiBackend {}

/// The EFI variables of this machine (UEFI 2.10 §8.2).
#[cfg(any(variable_names, variable_info, variable_storage_info, variable_data))]
pub struct VariableBackend {}

#[cfg(variable_names)]
impl VariableBackend {
    /// The name and vendor GUID of every EFI variable of this machine, sorted by name, then
    /// vendor; only those of the vendor GUID `vendor`, such as
    /// "8BE4DF61-93CA-11D2-AA0D-00E098032B8C", if given.
    pub fn list(vendor: Option<&str>) -> Result<Vec<VariableKey>> {
        let vendor = vendor.map(parse_vendor).transpose()?;
        list_variables(&Self::system_variable_names(), vendor)
    }
}

#[cfg(variable_info)]
impl VariableBackend {
    /// The VariableInfo of the EFI variable `name` of the vendor GUID `vendor`, such as
    /// "8BE4DF61-93CA-11D2-AA0D-00E098032B8C", without its data, of which it shows only the
    /// EFI_VARIABLE_AUTHENTICATION_3 metadata of a variable with
    /// EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS (VariableInfo::metadata).
    pub fn info(name: &str, vendor: &str) -> Result<VariableInfo> {
        let key = VariableKey {
            name: name.to_owned(),
            guid: parse_vendor(vendor)?,
        };
        Self::system_variable_info()?.variable_info(&key)
    }
}

#[cfg(variable_data)]
impl VariableBackend {
    /// The global variable `name` of UEFI 2.11 §3.3, or the signature database `name` of §32.7.1
    /// or §32.7.2, decoded, or that it is absent; of the vendor GUID `vendor`, such as
    /// "8BE4DF61-93CA-11D2-AA0D-00E098032B8C", if given, which must be its own.
    pub fn get(name: &str, vendor: Option<&str>) -> Result<GlobalVariable> {
        let vendor = vendor.map(parse_vendor).transpose()?;
        read_global(&Self::system_variable_data()?, name, vendor)
    }

    /// Sets the global variable `name` of UEFI 2.11 §3.3 that the OS may write to `value`,
    /// which names its value as get decodes it, after checking it; returns what it wrote.
    pub fn set(name: &str, value: &str) -> Result<GlobalVariable> {
        write_global(&Self::system_variable_data()?, name, value)
    }

    /// Sets the global variable `name`, AuditMode or DeployedMode, to `value`, 1, as set does, to
    /// make its Secure Boot mode transition of UEFI 2.11 §32.3 (ModeTransition::of_variable),
    /// which only the UEFI Shell build makes, as AuditMode and DeployedMode each "Always becomes
    /// read-only after ExitBootServices() is called" (§3.3). Refuses, before it opens the
    /// variables, another variable or value and the builds that run after ExitBootServices();
    /// before any write, a transition that the current mode does not allow, and then, unless
    /// `unsafe_operations` allows it, the transition, an unsafe operation. Returns what it wrote
    /// and what SetVariable() returned, and the transition, lifted.
    pub fn set_mode(
        name: &str,
        value: &str,
        unsafe_operations: UnsafeOperations,
    ) -> Result<(ModeTransitionWrite, Vec<UnsafeOperation>)> {
        let request = ModeRequest::new(Self::SYSTEM_VARIABLE_REACH, name, value)?;
        set_mode(&Self::system_variable_data()?, request, unsafe_operations)
    }

    /// Writes `payload`, an EFI_VARIABLE_AUTHENTICATION_2 descriptor and the new data of the EFI
    /// variable `name` of the vendor GUID `vendor`, such as
    /// "8BE4DF61-93CA-11D2-AA0D-00E098032B8C" (UEFI 2.11 §8.2.6), with `attributes` and
    /// EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS; the firmware verifies its signature.
    /// Refuses, before any write, other attributes, a payload without a complete descriptor,
    /// attributes without access or a payload that would delete the variable, and then, unless
    /// `unsafe_operations` allows it, a Secure Boot Policy Variable or a device signature
    /// database (any variable of EFI_DEVICE_SECURITY_DATABASE_GUID) in Setup Mode; returns the
    /// unsafe operations that it lifted.
    pub fn write_signed(
        name: &str,
        vendor: &str,
        attributes: VariableAttributes,
        payload: &[u8],
        unsafe_operations: UnsafeOperations,
    ) -> Result<Vec<UnsafeOperation>> {
        let key = VariableKey {
            name: name.to_owned(),
            guid: parse_vendor(vendor)?,
        };
        write_signed(
            &Self::system_variable_data()?,
            &key,
            attributes,
            payload,
            unsafe_operations,
        )
    }

    /// Signs `write` with the PEM RSA key `signing_key` into an EFI_VARIABLE_AUTHENTICATION_2
    /// (UEFI 2.11 §8.2.6) that carries `certificates`, a PEM bundle of the key's certificate,
    /// then any others, blinded over this platform's random source (EFI_RNG_PROTOCOL in the UEFI
    /// Shell, getrandom elsewhere), and writes it, then the data. Refuses what write_signed
    /// refuses before it signs, but the unsafe operations, which it checks after it signs and
    /// returns as write_signed does.
    pub fn sign_and_write(
        write: &SignedVariableWrite<'_>,
        signing_key: &Secret,
        certificates: &[u8],
    ) -> Result<Vec<UnsafeOperation>> {
        let key = VariableKey {
            name: write.name.to_owned(),
            guid: parse_vendor(write.vendor)?,
        };
        let signer = Signer::from_pem(signing_key, certificates, write.digest)?;
        sign_and_write(
            &Self::system_variable_data()?,
            &SignedWrite {
                key: &key,
                attributes: write.attributes,
                data: write.data,
                timestamp: write.timestamp,
                unsafe_operations: write.unsafe_operations,
            },
            &signer,
            &mut PlatformSeed::default(),
        )
    }

    /// Signs `write` with the PEM RSA key `signing_key` into an EFI_VARIABLE_AUTHENTICATION_3
    /// (UEFI 2.11 §8.2.5) whose SigningCert carries `certificates`, a PEM bundle of the key's
    /// certificate, then any others, and whose NewCert, if `write` names a new authority, hands
    /// the variable to it, blinded as sign_and_write blinds, and writes it, then the data, with
    /// the attributes and EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS. Refuses before it signs a
    /// Secure Boot Policy Variable, a write that would delete the variable, and, on Linux, every
    /// such write, which efivarfs cannot make; after it signs, a device signature database while
    /// SetupMode is 1 or tells no mode unless `write` allows it. Returns the unsafe operations
    /// that it lifted.
    pub fn sign_and_write_enhanced(
        write: &EnhancedVariableWrite<'_>,
        signing_key: &Secret,
        certificates: &[u8],
    ) -> Result<Vec<UnsafeOperation>> {
        let key = VariableKey {
            name: write.name.to_owned(),
            guid: parse_vendor(write.vendor)?,
        };
        let (signer, new_authority) = enhanced_signers(write, signing_key, certificates)?;
        sign_and_write_enhanced(
            &Self::system_variable_data()?,
            &EnhancedSignedWrite {
                key: &key,
                attributes: write.attributes,
                data: write.data,
                freshness: write.freshness,
                unsafe_operations: write.unsafe_operations,
            },
            &signer,
            new_authority.as_ref(),
            &mut PlatformSeed::default(),
        )
    }
}

/// The Signers of the EFI_VARIABLE_AUTHENTICATION_3 that VariableBackend::sign_and_write_enhanced
/// writes: of `signing_key` with `certificates`, for the SigningCert, and of the new authority of
/// `write`, if any, for the NewCert, whose refusals name that authority's flags.
#[cfg(variable_data)]
fn enhanced_signers(
    write: &EnhancedVariableWrite<'_>,
    signing_key: &Secret,
    certificates: &[u8],
) -> Result<(Signer, Option<Signer>)> {
    let signer = Signer::from_pem(signing_key, certificates, write.digest)?;
    let new_authority = write
        .new_authority
        .map(|authority| {
            Signer::from_pem(authority.key, authority.certificates, write.digest).context(
                "the new authority of the NewCert, --new-signing-key-file and \
                 --new-signing-certificate-file",
            )
        })
        .transpose()?;
    Ok((signer, new_authority))
}

/// A write that VariableBackend::sign_and_write_enhanced signs.
#[cfg(variable_data)]
#[derive(Debug, Clone, Copy)]
pub struct EnhancedVariableWrite<'a> {
    /// The EFI variable
    pub name: &'a str,
    /// Its vendor GUID, such as "8BE4DF61-93CA-11D2-AA0D-00E098032B8C"
    pub vendor: &'a str,
    /// The attributes, to which the write adds EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS
    pub attributes: VariableAttributes,
    /// The new data of the variable
    pub data: &'a [u8],
    /// The Type of the EFI_VARIABLE_AUTHENTICATION_3 and its Secondary Descriptor
    pub freshness: &'a Freshness,
    /// The digest of the signatures
    pub digest: SignatureDigest,
    /// The authority that a NewCert hands the variable to, if any
    pub new_authority: Option<NewAuthority<'a>>,
    /// Whether to do the unsafe operations that it meets, which it returns: a write of a device
    /// signature database while SetupMode is 1 or tells no mode
    pub unsafe_operations: UnsafeOperations,
}

/// The authority that the NewCert of an EFI_VARIABLE_AUTHENTICATION_3 hands a variable to (UEFI
/// 2.11 §8.2.5).
#[cfg(variable_data)]
#[derive(Debug, Clone, Copy)]
pub struct NewAuthority<'a> {
    /// Its PEM RSA private key, which signs its certificate's tbsCertificate
    pub key: &'a Secret,
    /// A PEM bundle of its certificate, then any others
    pub certificates: &'a [u8],
}

/// A write that VariableBackend::sign_and_write signs.
#[cfg(variable_data)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedVariableWrite<'a> {
    /// The EFI variable
    pub name: &'a str,
    /// Its vendor GUID, such as "8BE4DF61-93CA-11D2-AA0D-00E098032B8C"
    pub vendor: &'a str,
    /// The attributes, to which the write adds EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS
    pub attributes: VariableAttributes,
    /// The new data of the variable
    pub data: &'a [u8],
    /// The TimeStamp of the descriptor
    pub timestamp: TimeStamp,
    /// The digest of the signature
    pub digest: SignatureDigest,
    /// Whether to do the unsafe operations that it meets, which it returns: a write of a Secure
    /// Boot Policy Variable or a device signature database (any variable of
    /// EFI_DEVICE_SECURITY_DATABASE_GUID) while SetupMode is 1 or tells no mode
    pub unsafe_operations: UnsafeOperations,
}

#[cfg(variable_storage_info)]
impl VariableBackend {
    /// What QueryVariableInfo() tells of the storage of this machine's EFI variables of
    /// `attributes`.
    pub fn storage(attributes: VariableAttributes) -> Result<VariableStorage> {
        query_storage(&Self::system_variable_storage(), attributes)
    }
}

/// The capsules for this machine's firmware (UEFI 2.11 §8.5.3), the configuration data that
/// it reports for them (§23.5.2), and the results of their processing (§8.5.6, §23.5.3).
#[cfg(any(capsule_delivery, configuration_tables, variable_data))]
pub struct CapsuleBackend {}

#[cfg(capsule_delivery)]
impl CapsuleBackend {
    /// Delivers `payload`, unchanged, to this machine's firmware as a JSON capsule whose
    /// EFI_JSON_CAPSULE_HEADER carries `capsule_id` (UEFI 2.11 §23.5); an empty payload is
    /// refused first. It never resets the machine.
    pub fn deliver_json(payload: &[u8], capsule_id: u32) -> Result<CapsuleDelivered> {
        deliver_json_capsule(&Self::system_capsule_delivery(), payload, capsule_id)
    }
}

#[cfg(configuration_tables)]
impl CapsuleBackend {
    /// The configuration data that this machine's firmware reports in its JSON configuration
    /// table (UEFI 2.11 §23.5.2), which it must list.
    pub fn json_config_data() -> Result<JsonConfigData> {
        read_json_config_data(Self::system_json_config_data_table()?)
    }

    /// The result of processing a JSON capsule that this machine's firmware reports in its JSON
    /// capsule result table (UEFI 2.11 §23.5.3), which it must list.
    pub fn json_capsule_result() -> Result<CapsuleResult> {
        read_json_capsule_result(Self::system_json_capsule_result_table()?)
    }
}

#[cfg(variable_names)]
impl CapsuleBackend {
    /// The results of capsule processing that this machine's firmware reports in its result
    /// variables (UEFI 2.11 §8.5.6), which its variables list.
    pub fn results() -> Result<CapsuleResults> {
        list_capsule_results(
            &VariableBackend::system_variable_names(),
            &VariableBackend::system_variable_data()?,
            Self::system_firmware_width()?,
        )
    }
}

#[cfg(target_os = "windows")]
impl CapsuleBackend {
    /// The results of capsule processing that this machine's firmware reports in its result
    /// variables (UEFI 2.11 §8.5.6), read by name from Capsule0000 up to the greater of
    /// CapsuleMax and CapsuleLast, as the firmware environment calls list no variables.
    pub fn results() -> Result<CapsuleResults> {
        probe_capsule_results(
            &VariableBackend::system_variable_data()?,
            Self::system_firmware_width()?,
        )
    }
}

/// The options of HiiBackend::get_using.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct GetOptions {
    /// The states of the questions to select and of the options to list too
    pub include: IncludedStates,
    /// Where to read question values
    pub efivars: EfivarSource,
    /// The AMI Setup access level that conditions read instead of the stored one, if stated
    pub access_level: Option<AccessLevel>,
    /// The language to show texts in instead of the platform language (PlatformLang), if stated
    pub language: Option<String>,
}

/// The value that HiiBackend::set_using gives a question.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SetValue {
    /// The text of a value, or of an option
    Text(String),
    /// The texts of the options of an ORDERED_LIST, in order, one per container
    Items(Vec<String>),
}

/// The options of HiiBackend::set_using.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SetOptions {
    /// The states of the questions and options to select too
    pub include: IncludedStates,
    /// The AMI Setup access level that conditions read instead of the stored one, if stated
    pub access_level: Option<AccessLevel>,
    /// Whether set does the unsafe operations that it meets, which it returns: in the UEFI
    /// Shell, a write in a HiiDB that declares a setup password question; a write of a question
    /// that EFI_IFR_FLAG_READ_ONLY makes read-only
    pub unsafe_operations: UnsafeOperations,
    /// Whether set writes a volatile variable: only through variables that reach BootServices, as
    /// in the UEFI Shell
    pub volatile: VolatileWrites,
    /// The language to show texts in instead of the platform language (PlatformLang), if stated
    pub language: Option<String>,
    /// On Linux and Windows, the uefisettings.efi that set copies to the EFI system partition when
    /// it stages a question that its driver holds for the next boot
    pub staging_image: Option<PathBuf>,
    /// On Windows, where the user mounted the EFI system partition, such as S:\ after
    /// `mountvol S: /s`: set writes the staged files through it instead of the partition's volume
    /// GUID path, once it checks that the volume there is the ESP that it finds
    pub staging_esp: Option<PathBuf>,
}

/// The options of HiiBackend::list_questions_using.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ListQuestionsOptions {
    /// The states of the questions and options to list too
    pub include: IncludedStates,
    /// Where to read question values
    pub efivars: EfivarSource,
    /// The AMI Setup access level that conditions read instead of the stored one, if stated
    pub access_level: Option<AccessLevel>,
    /// The language to show texts in instead of the platform language (PlatformLang), if stated
    pub language: Option<String>,
}

/// The options of HiiBackend::show_ifr_using.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct ShowIfrOptions {
    /// Where to read question values
    pub efivars: EfivarSource,
    /// The language to show texts in instead of the platform language (PlatformLang), if stated
    pub language: Option<String>,
}

/// The options of HiiBackend::dump_efivars.
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct DumpEfivarsOptions {
    /// Which bytes of each efivar file to keep
    pub redaction: EfivarRedaction,
}

/// show-ifr's text in thrift, its lines each ended with `\n`.
impl From<TextLines> for HiiShowIfrResponse {
    fn from(lines: TextLines) -> Self {
        Self {
            readable_representation: lines.to_string(),
            ..Default::default()
        }
    }
}

/// Where set reads and writes the values of the questions it selects.
struct SetAccess<'a> {
    reads: Box<dyn FirmwareVariables>,
    writes: &'a dyn FirmwareVariables,
    /// The drivers of the questions whose value only their driver holds, where this build
    /// reaches them
    held: Option<&'a dyn DriverHeldValues>,
}

/// The package list of a question in the HiiDB that get and set read.
#[cfg_attr(
    not(target_os = "uefi"),
    allow(
        dead_code,
        reason = "only the UEFI Shell build reaches the list's driver"
    )
)]
pub(crate) struct QuestionList<'a> {
    /// Its index in the HiiDB
    pub(crate) index: usize,
    /// The device path of the driver handle that registered it, from its device path package
    pub(crate) device_path: Option<&'a DevicePath>,
}

/// What get and set do with a question whose value only its driver holds (UEFI 2.11 §33.2.5.6),
/// which each build reaches in its own way, if at all.
pub(crate) trait DriverHeldValues {
    /// How set's errors name the store of a question that this holds, after the selector of its
    /// package list: `its driver`, or where set puts the value instead.
    fn store_name(&self) -> &'static str;

    /// get's answer for `question` of `list`, or why get fails.
    fn get(
        &self,
        list: &QuestionList<'_>,
        question: &QuestionDescriptor,
        held: &DriverHeldQuestion,
    ) -> Result<String>;

    /// Refuses what set of `question` of `list` would refuse before it reaches the driver, with
    /// set's refusal, so that set refuses it before its first write.
    fn check_set(
        &self,
        list: &QuestionList<'_>,
        question: &QuestionDescriptor,
        held: &DriverHeldQuestion,
    ) -> Result<()>;

    /// Sets `question` of `list` to `value`, which driver_held_value and check_set checked;
    /// returns the annotation of set's answer.
    fn set(
        &self,
        list: &QuestionList<'_>,
        question: &QuestionDescriptor,
        held: &DriverHeldQuestion,
        value: u64,
    ) -> Result<String>;
}

/// The refusal of set of `question` for `reason`.
#[cfg_attr(
    not(any(target_os = "uefi", target_os = "linux", target_os = "windows")),
    allow(
        dead_code,
        reason = "only the UEFI Shell build reaches a question's driver, and only the Linux and \
                  Windows builds stage a set for it"
    )
)]
pub(crate) fn set_refusal(question: &str, reason: impl std::fmt::Display) -> anyhow::Error {
    anyhow!("cannot set question {question:?}: {reason}")
}

/// The driver that holds the value of `descriptor`, through `held`, and what it needs; None if
/// get and set read and write its VarStore, or, without one, show and refuse it (storageless.rs).
fn driver_of<'h, 'd>(
    held: Option<&'h dyn DriverHeldValues>,
    descriptor: &'d QuestionDescriptor,
) -> Option<(&'h dyn DriverHeldValues, &'d DriverHeldQuestion)> {
    held.zip(descriptor.driver_held())
}

impl HiiBackend {
    /// show_ifr returns a human readable representation of the forms in Hii
    ///
    /// It reads values as `EfivarSource::System` does, so on Linux also from the ExportConfig
    /// snapshot in physical memory.
    pub fn show_ifr(db_bytes: &[u8]) -> Result<HiiShowIfrResponse> {
        Self::show_ifr_using(db_bytes, &ShowIfrOptions::default())
    }

    /// show_ifr with `options`
    ///
    /// Under `EfivarSource::System`, on Linux it also reads the ExportConfig snapshot from
    /// physical memory.
    pub fn show_ifr_using(db_bytes: &[u8], options: &ShowIfrOptions) -> Result<HiiShowIfrResponse> {
        Self::show_ifr_lines_using(db_bytes, options).map(HiiShowIfrResponse::from)
    }

    /// show_ifr_using's text in lines, which a text that a line shows may break itself: the CLI
    /// prints each line escaped, so that such a break forges no line
    pub fn show_ifr_lines_using(db_bytes: &[u8], options: &ShowIfrOptions) -> Result<TextLines> {
        Self::show_ifr_in(
            db_bytes,
            options,
            options.efivars.clone().into_variables()?,
            system_snapshot(&options.efivars),
            options.efivars.platform_lang()?.as_deref(),
        )
    }

    /// show_ifr with `options`, reading question values from `variables`, or from the snapshot
    /// `exported` where they miss a variable, on a platform of PlatformLang `platform_lang`, if
    /// any
    fn show_ifr_in(
        db_bytes: &[u8],
        options: &ShowIfrOptions,
        variables: Box<dyn FirmwareVariables>,
        exported: Option<ExportedConfig>,
        platform_lang: Option<&str>,
    ) -> Result<TextLines> {
        // We depend on the caller to provide us with the hiidb instead of calling extract here
        // because they might want to provide a file instead.

        let mut lines = Vec::new();

        let (parsed_db, mut reader) = read_db_withholding(db_bytes, variables, exported)?;

        for list in parsed_db {
            list.check_form_strings()?;
            // no header for a list without forms
            if list.forms.is_empty() {
                continue;
            }
            lines.push(format!("Packagelist {}", list.guid));
            let texts = list.texts(&text_languages(options.language.as_deref(), platform_lang));
            reader.enter_package_list(&list, &texts);
            for root in &list.forms {
                lines.extend(forms::display(Rc::clone(root), 0, &texts, &mut reader)?.0);
            }
            for disabled in &list.disabled_forms {
                lines.push(format!(
                    "Disabled at offset {}: {}",
                    disabled.offset, disabled.reason
                ));
            }
        }

        Ok(TextLines(lines))
    }

    /// list all strings-id, string pairs in HiiDB
    pub fn list_strings(db_bytes: &[u8]) -> Result<Vec<HiiStringsPackage>> {
        let mut resp = Vec::new();
        let parsed_db = package::read_db(db_bytes)?;

        for list in parsed_db {
            for string_package in list.strings {
                let mut p = HiiStringsPackage {
                    package_list: list.guid.to_string(),
                    language: string_package.language.to_ascii_string().with_context(|| {
                        format!(
                            "failed to list a strings package of package list {}",
                            list.guid
                        )
                    })?,
                    ..Default::default()
                };
                for (string_id, string) in string_package.strings {
                    p.string_package
                        .insert(i32::from(string_id), string.to_string());
                }
                resp.push(p);
            }
        }

        Ok(resp)
    }

    /// list_questions with the default options, which read values as `EfivarSource::System`
    /// does, so on Linux also from the ExportConfig snapshot in physical memory
    pub fn list_questions(db_bytes: &[u8]) -> Result<Vec<Question>> {
        Self::list_questions_using(db_bytes, &ListQuestionsOptions::default())
    }

    /// The IFR that uefisettings ignores in the HiiDB `db_bytes`, which may hold questions that
    /// list_questions does not list.
    pub fn ignored_ifr(db_bytes: &[u8]) -> Result<Vec<IgnoredIfr>> {
        Ok(package::read_db(db_bytes)?
            .iter()
            .flat_map(package::ParsedPackageList::ignored_records)
            .collect())
    }

    /// list_questions with `options`
    ///
    /// Under `EfivarSource::System`, on Linux it also reads the ExportConfig snapshot from
    /// physical memory.
    pub fn list_questions_using(
        db_bytes: &[u8],
        options: &ListQuestionsOptions,
    ) -> Result<Vec<Question>> {
        Self::list_questions_in(
            db_bytes,
            options,
            options.efivars.clone().into_variables()?,
            system_snapshot(&options.efivars),
            options.efivars.platform_lang()?.as_deref(),
        )
    }

    /// list_questions_using, and ignored_ifr of the same parse of the HiiDB
    pub fn list_questions_and_ignored_ifr_using(
        db_bytes: &[u8],
        options: &ListQuestionsOptions,
    ) -> Result<(Vec<Question>, Vec<IgnoredIfr>)> {
        Self::list_questions_and_ignored_ifr_in(
            db_bytes,
            options,
            options.efivars.clone().into_variables()?,
            system_snapshot(&options.efivars),
            options.efivars.platform_lang()?.as_deref(),
        )
    }

    /// list_questions with `options`, reading question values from `variables`, or from the
    /// snapshot `exported` where they miss a variable, on a platform of PlatformLang
    /// `platform_lang`, if any
    fn list_questions_in(
        db_bytes: &[u8],
        options: &ListQuestionsOptions,
        variables: Box<dyn FirmwareVariables>,
        exported: Option<ExportedConfig>,
        platform_lang: Option<&str>,
    ) -> Result<Vec<Question>> {
        Ok(Self::list_questions_and_ignored_ifr_in(
            db_bytes,
            options,
            variables,
            exported,
            platform_lang,
        )?
        .0)
    }

    /// list_questions_in, and the IFR that uefisettings ignores in the HiiDB
    fn list_questions_and_ignored_ifr_in(
        db_bytes: &[u8],
        options: &ListQuestionsOptions,
        variables: Box<dyn FirmwareVariables>,
        exported: Option<ExportedConfig>,
        platform_lang: Option<&str>,
    ) -> Result<(Vec<Question>, Vec<IgnoredIfr>)> {
        let include = options.include;
        let mut res = Vec::new();
        let (parsed_db, mut reader) = read_db_withholding(db_bytes, variables, exported)?;
        let ignored_ifr = parsed_db
            .iter()
            .flat_map(package::ParsedPackageList::ignored_records)
            .collect();
        forms::check_access_level(
            parsed_db.iter().flat_map(|list| &list.forms),
            options.access_level,
        )?;
        let requested = text_languages(options.language.as_deref(), platform_lang);
        for list in parsed_db {
            list.check_form_strings()?;
            let texts = list.texts(&requested);
            reader.enter_package_list(&list, &texts);

            for root in &list.forms {
                //  TODO: show form name, package list guid in the final response as well

                for (question_descriptor, state) in list_questions(
                    Rc::clone(root),
                    &texts,
                    include,
                    options.access_level,
                    &mut reader,
                ) {
                    let annotation = String::from(question_descriptor.value_source.annotation())
                        + &question_descriptor.value_state.option_annotation()
                        + &state.annotation();
                    let mut question = question_of(question_descriptor, include);
                    question.answer += &annotation;
                    // don't show it if everything is empty
                    if !(question.name.is_empty()
                        && question.answer.is_empty()
                        && question.help.is_empty()
                        && question.options.is_empty())
                    {
                        res.push(question);
                    }
                }
            }
        }
        Ok((res, ignored_ifr))
    }
}

#[cfg(all(system_hiidb, system_variables))]
impl SettingsBackend for HiiBackend {
    fn set(question: &str, new_value: &str, selector: Option<&str>) -> Result<SetResponseList> {
        // the default options lift no unsafe operation
        Self::set_using(
            question,
            &SetValue::Text(new_value.to_owned()),
            selector,
            &SetOptions::default(),
        )
        .map(|(responses, _)| responses)
    }

    fn get(question: &str, selector: Option<&str>) -> Result<GetResponseList> {
        Self::get_using(
            &Self::system_hiidb()?,
            question,
            selector,
            &GetOptions::default(),
        )
    }
}

impl HiiBackend {
    /// set with `options`, in this machine's HiiDB and variables, as set_in does, and the unsafe
    /// operations that it lifted.
    #[cfg(all(system_hiidb, system_variables))]
    pub fn set_using(
        question: impl Into<QuestionSelector>,
        value: &SetValue,
        selector: Option<&str>,
        options: &SetOptions,
    ) -> Result<(SetResponseList, Vec<UnsafeOperation>)> {
        Self::set_in_system(&Self::system_hiidb()?, question, value, selector, options)
    }

    /// set with `options`, in the HiiDB `db_bytes` and this machine's variables, as set_in does,
    /// and the unsafe operations that it lifted.
    #[cfg(all(system_hiidb, system_variables))]
    fn set_in_system(
        db_bytes: &[u8],
        question: impl Into<QuestionSelector>,
        value: &SetValue,
        selector: Option<&str>,
        options: &SetOptions,
    ) -> Result<(SetResponseList, Vec<UnsafeOperation>)> {
        let held = Self::driver_held_setter(db_bytes, options)?;
        Self::set_in(
            db_bytes,
            question,
            value,
            selector,
            options,
            SetAccess {
                reads: EfivarSource::System.into_variables()?,
                writes: &Self::system_variables()?,
                held: held.as_deref(),
            },
            EfivarSource::System.platform_lang()?.as_deref(),
        )
    }

    /// set of the questions that `question` selects in the HiiDB `db_bytes` with `options`,
    /// selecting by the values of `reads`, which it reads before the first write, and writing
    /// through `writes`, neither of them the bytes of password questions
    /// (PasswordQuestions::reader and withholding), and a question whose driver holds its value
    /// through `held`, on a platform of PlatformLang `platform_lang`, if any: fails with
    /// SelectionError::NotFound when it selects none, and unless every selected match is written,
    /// also after writing the others. It checks its unsafe operations against `options` after
    /// every refusal that they cannot lift, right before its first write, which for a question
    /// whose driver holds its value is its first Callback(), and returns those that it lifted.
    #[cfg_attr(
        not(system_variables),
        allow(
            dead_code,
            reason = "set writes only the variables of the machine, which this build does not reach"
        )
    )]
    fn set_in(
        db_bytes: &[u8],
        question: impl Into<QuestionSelector>,
        value: &SetValue,
        _selector: Option<&str>,
        options: &SetOptions,
        access: SetAccess<'_>,
        platform_lang: Option<&str>,
    ) -> Result<(SetResponseList, Vec<UnsafeOperation>)> {
        let SetAccess {
            reads,
            writes,
            held,
        } = access;
        // TODO: use selector to only change values which match question + selector
        let include = options.include;

        let mut resp = Vec::new();

        let parsed_db = package::read_db(db_bytes)?;
        let ignored_ifr = listed_ignored_ifr(&parsed_db)?;
        let passwords = PasswordQuestions::of_lists(&parsed_db);
        let mut reader = passwords.reader(reads)?.with_time_services(time_services());
        let writes = passwords.withholding(writes)?;
        let mut unsafe_operations = PendingOperations::new(options.unsafe_operations);
        if let Some(bypass) = passwords.setup_password_bypass(writes.reach()) {
            unsafe_operations.add(bypass);
        }

        let question = question.into();
        let name = question.to_string();
        // only the question of items has spellings: the database spells one answer
        let new_value = match value {
            SetValue::Text(text) => text.as_str(),
            SetValue::Items(_) => "",
        };
        let (question_variations, new_value_variations, is_translated) =
            spellings(&question, new_value);

        let selected = select_for_set(
            &parsed_db,
            &question,
            &question_variations,
            options,
            &text_languages(options.language.as_deref(), platform_lang),
            &mut unsafe_operations,
            &mut reader,
            held,
        )?;

        // From an OS, set stages a question that its driver holds for the next boot
        // (staged_set.rs); in the UEFI Shell, setup_password_bypass above took the setup password
        // in.
        let stages = writes.reach() == VariableReach::Runtime
            && selected
                .iter()
                .any(|selected| driver_of(held, &selected.descriptor).is_some());
        if let Some(staged) = passwords.staged_setup_password().filter(|_| stages) {
            unsafe_operations.add(staged);
        }
        let answer = match value {
            SetValue::Text(text) => forms::NewAnswer::Text {
                text,
                variations: &new_value_variations,
            },
            SetValue::Items(items) => forms::NewAnswer::Items(items),
        };
        let (written, lifted) = set_selected(
            &name,
            &selected,
            answer,
            include,
            &mut reader,
            options.access_level,
            options.volatile,
            unsafe_operations,
            &writes,
            held,
        )?;

        for (
            selected,
            SetAnswer {
                answer,
                items,
                volatile,
            },
        ) in selected.into_iter().zip(written)
        {
            let Selected {
                guid,
                descriptor: question_descriptor,
                state,
                ..
            } = selected;
            let volatile_annotation = match volatile {
                true => VOLATILE_ANNOTATION,
                false => "",
            };
            let set_resp = SetResponse {
                // TODO: GUIDs repeat, also in errors; identify lists by HiiDB index
                selector: guid,
                backend: Backend::Hii,
                is_translated,
                question: Question {
                    answer: answer + &state.annotation() + volatile_annotation,
                    items,
                    ..question_of(question_descriptor, include)
                },
                modified: true,
                ..Default::default()
            };

            resp.push(set_resp);
        }

        Ok((
            SetResponseList {
                responses: resp,
                ignored_ifr,
                ..Default::default()
            },
            lifted,
        ))
    }

    /// get from the HiiDB `db_bytes`, with `options`
    ///
    /// Under `EfivarSource::System`, on Linux it also reads the ExportConfig snapshot from
    /// physical memory.
    pub fn get_using(
        db_bytes: &[u8],
        question: impl Into<QuestionSelector>,
        selector: Option<&str>,
        options: &GetOptions,
    ) -> Result<GetResponseList> {
        Self::get_in(
            db_bytes,
            question,
            selector,
            options,
            options.efivars.clone().into_variables()?,
            system_snapshot(&options.efivars),
            options.efivars.platform_lang()?.as_deref(),
            Self::driver_held_values(db_bytes, &options.efivars).as_deref(),
        )
    }

    /// get with `options`, reading question values from `variables`, or from the snapshot
    /// `exported` where they miss a variable, on a platform of PlatformLang `platform_lang`, if
    /// any, and a question whose driver holds its value through `held`
    #[expect(
        clippy::too_many_arguments,
        reason = "get's inputs: the HiiDB, the question, the selector, the options, the variables, \
                  the snapshot, the platform language and the driver-held values"
    )]
    fn get_in(
        db_bytes: &[u8],
        question: impl Into<QuestionSelector>,
        _selector: Option<&str>,
        options: &GetOptions,
        variables: Box<dyn FirmwareVariables>,
        exported: Option<ExportedConfig>,
        platform_lang: Option<&str>,
        held: Option<&dyn DriverHeldValues>,
    ) -> Result<GetResponseList> {
        // TODO: use selector to only get questions which match question + selector
        // TODO: take a form@packagelist selector to pick one of the FormSets that select
        // the question
        let include = options.include;

        let mut resp = Vec::new();

        let question = question.into();
        let name = question.to_string();
        let (question_variations, _, is_translated) = spellings(&question, "");

        let (parsed_db, mut reader) = read_db_withholding(db_bytes, variables, exported)?;
        forms::check_access_level(
            parsed_db.iter().flat_map(|list| &list.forms),
            options.access_level,
        )?;
        let ignored_ifr = listed_ignored_ifr(&parsed_db)?;
        check_unambiguous(&parsed_db, &question, &question_variations)?;
        let statements = keyword_statements(&parsed_db, &question)?;

        let requested = text_languages(options.language.as_deref(), platform_lang);
        let mut excluded = Exclusion::NONE;
        for (index, list) in parsed_db.iter().enumerate() {
            list.check_form_strings()?;
            let texts = list.texts(&requested);
            reader.enter_package_list(list, &texts);

            for root in &list.forms {
                let selection = forms::find_question(
                    Rc::clone(root),
                    &texts,
                    &question.matching(&question_variations, &statements),
                    include,
                    options.access_level,
                    &mut reader,
                );
                let (question_descriptor, state) = match selection.for_get() {
                    Choice::Chosen(question_descriptor, state) => (question_descriptor, state),
                    Choice::Skipped(exclusion) => {
                        excluded |= exclusion;
                        continue;
                    }
                };
                let source_annotation = question_descriptor.value_source.annotation();
                let option_annotation = question_descriptor.value_state.option_annotation();
                let answer = match driver_of(held, &question_descriptor) {
                    Some((held, driver_held)) => {
                        let list = QuestionList {
                            index,
                            device_path: list.device_path.as_ref(),
                        };
                        held.get(&list, &question_descriptor, driver_held)?
                    }
                    None => question_descriptor.value.clone(),
                };
                let mut get_resp = GetResponse {
                    selector: list.guid.to_string(),
                    backend: Backend::Hii,
                    is_translated,
                    question: Question {
                        answer,
                        ..question_of(question_descriptor, include)
                    },
                    ..Default::default()
                };

                if is_translated {
                    get_resp.question.answer =
                        translate_response(&name, &get_resp.question.answer, Backend::Hii);
                }
                // after translate_response, which matches whole answers
                get_resp.question.answer += source_annotation;
                get_resp.question.answer += &option_annotation;
                get_resp.question.answer += &state.annotation();

                resp.push(get_resp)
            }
        }
        if resp.is_empty() && !excluded.is_empty() {
            return Err(excluded.question_error(&name).into());
        }

        Ok(GetResponseList {
            responses: resp,
            ignored_ifr,
            ..Default::default()
        })
    }
}

/// The ExportConfig snapshot of this machine's firmware (UEFI 2.11 §33.2.11.1), from which get,
/// list-questions and show-ifr take the values of the variables that `efivars`, if this
/// machine's, miss; none of other sources, or where it cannot be read, which the debug log says.
fn system_snapshot(efivars: &EfivarSource) -> Option<ExportedConfig> {
    match efivars {
        #[cfg(system_variables)]
        EfivarSource::System => read_system_snapshot(),
        #[cfg(efivar_dumps)]
        EfivarSource::Directory(_) => None,
        EfivarSource::Disabled => None,
    }
}

/// The ExportConfig snapshot that this machine's configuration table lists, if it can be read.
#[cfg(firmware_memory_maps)]
fn read_system_snapshot() -> Option<ExportedConfig> {
    match crate::hii::exported_config() {
        Ok(Some(exported)) => Some(exported),
        Ok(None) => {
            debug!("no ExportConfig snapshot: the configuration table lists none");
            None
        }
        Err(error) => {
            debug!("no ExportConfig snapshot: {error:#}");
            None
        }
    }
}

/// No ExportConfig snapshot on the builds that read no configuration table from the OS: Windows
/// reads no physical memory, Linux reads it on x86 and arm64 only, and the UEFI Shell can ask
/// EFI_HII_CONFIG_ROUTING_PROTOCOL for current values instead.
#[cfg(all(system_variables, not(firmware_memory_maps)))]
fn read_system_snapshot() -> Option<ExportedConfig> {
    None
}

/// The package lists of the HiiDB `db_bytes`, and a reader of `variables` without the bytes of
/// its password questions (PasswordQuestions::reader). It takes the values of the variables that
/// they miss from the snapshot `exported`, without the bytes of password questions either
/// (SnapshotLookup::new), unless it cannot, which the warning log says.
fn read_db_withholding(
    db_bytes: &[u8],
    variables: Box<dyn FirmwareVariables>,
    exported: Option<ExportedConfig>,
) -> Result<(Vec<package::ParsedPackageList>, EfivarReader)> {
    let parsed_db = package::read_db(db_bytes)?;
    let passwords = PasswordQuestions::of_lists(&parsed_db);
    let reader = passwords
        .reader(variables)?
        .with_time_services(time_services());
    let Some(exported) = exported else {
        return Ok((parsed_db, reader));
    };
    let reader = match SnapshotLookup::new(&exported, &passwords) {
        Ok(snapshot) => reader.with_snapshot(snapshot),
        Err(refusal) => {
            warn!("{refusal}");
            reader
        }
    };
    Ok((parsed_db, reader))
}

/// The languages that ParsedPackageList::texts takes, in order: `stated` (--language), then
/// `platform` (PlatformLang), those that are given.
fn text_languages<'a>(stated: Option<&'a str>, platform: Option<&'a str>) -> Vec<&'a str> {
    [stated, platform].into_iter().flatten().collect()
}

/// The spellings of `question`'s prompt and of `value` that the spellings database holds,
/// themselves if it holds none, and whether it holds any. A question selected by QuestionId or
/// keyword has no prompt to spell, and its value no spellings.
fn spellings(
    question: &QuestionSelector,
    value: &str,
) -> (BTreeSet<String>, BTreeSet<String>, bool) {
    let QuestionSelector::Prompt(text) = question else {
        return (BTreeSet::new(), BTreeSet::from([value.to_owned()]), false);
    };
    match get_qa_variations_hii(text, value) {
        HiiTranslation::Translated {
            question_variations,
            answer_variations,
        } => (question_variations, answer_variations, true),
        HiiTranslation::NotTranslated {
            question_variations,
            answer_variations,
        } => (question_variations, answer_variations, false),
    }
}

/// Refuses a `question` that names questions ambiguously in `parsed_db`: by prompt, unless one
/// language holds it as the prompt of every question that its `variations` name
/// (forms::check_prompt_language); by address, if two questions of one FormSet hold it
/// (forms::check_address_unique). keyword_statements refuses a keyword's.
fn check_unambiguous(
    parsed_db: &[package::ParsedPackageList],
    question: &QuestionSelector,
    variations: &BTreeSet<String>,
) -> Result<()> {
    let mut matches = Vec::new();
    for list in parsed_db {
        // whichever language texts show in, QUESTION matches those of every language
        let texts = list.texts(&[]);
        for root in &list.forms {
            match question {
                QuestionSelector::Prompt(_) => {
                    matches.extend(forms::prompt_matches(root, &texts, variations));
                }
                QuestionSelector::Address(address) => {
                    forms::check_address_unique(root, &texts, address)?;
                }
                QuestionSelector::Keyword { .. } => {}
            }
        }
    }
    forms::check_prompt_language(&question.to_string(), matches)?;
    Ok(())
}

/// The statements that the keyword of `question` names in `parsed_db`, as the Keyword Handler
/// finds them (KeywordStatement::resolve_offline), none for another selector or a keyword that
/// names none; refuses statements whose questions are of more than one NAMESPACE
/// (forms::check_keyword_namespace).
fn keyword_statements<'a>(
    parsed_db: &'a [package::ParsedPackageList],
    question: &QuestionSelector,
) -> Result<Vec<KeywordStatement<'a>>> {
    let QuestionSelector::Keyword { keyword, namespace } = question else {
        return Ok(Vec::new());
    };
    let statements = match KeywordStatement::resolve_offline(
        parsed_db,
        namespace.as_ref().map(KeywordNamespace::namespace),
        keyword.keyword(),
    ) {
        Ok(statements) => statements,
        // a keyword that names no statement selects none, as a QUESTION that no prompt is
        Err(KeywordRefusal::NotFound { .. } | KeywordRefusal::NoStatement(_)) => Vec::new(),
        Err(refusal) => return Err(refusal.into()),
    };
    forms::check_keyword_namespace(&question.to_string(), &statements)?;
    Ok(statements)
}

/// The Time Services through which DATE and TIME questions of EFI Date/Time Storage read and set
/// writes: this firmware's.
#[cfg(system_time)]
fn time_services() -> Option<Rc<dyn TimeServices>> {
    Some(Rc::new(HiiBackend::system_time_services()))
}

/// None: this build reaches no Time Services, so DATE and TIME questions of EFI Date/Time Storage
/// have no value and set refuses them.
#[cfg(not(system_time))]
fn time_services() -> Option<Rc<dyn TimeServices>> {
    None
}

/// A question that set writes, with its package list.
struct Selected<'a> {
    /// The GUID of its package list
    guid: String,
    list: QuestionList<'a>,
    descriptor: QuestionDescriptor,
    state: forms::StateEvaluation,
}

/// set's phase before its first write, so that no error follows a write: checks every package
/// list of `parsed_db`, the stated access level and that `question` is unambiguous
/// (check_unambiguous), then
/// selects, in each FormSet, the question of `question` that set writes, by prompt any of
/// `question_variations`, its texts shown in the languages `requested` takes
/// (ParsedPackageList::texts), reading each range once with `reader`; returns them with their
/// package list, or SelectionError::Excluded for `question` if each FormSet skips
/// it for its states, or else MaybeInIgnoredIfr if none holds it and read_db ignores IFR of
/// `parsed_db`. It takes the write of each that EFI_IFR_FLAG_READ_ONLY makes read-only into
/// `unsafe_operations`.
#[expect(
    clippy::too_many_arguments,
    reason = "select's inputs, the unsafe operations it takes in, and the driver that holds the \
              values of the others"
)]
fn select_for_set<'a>(
    parsed_db: &'a [package::ParsedPackageList],
    question: &QuestionSelector,
    question_variations: &BTreeSet<String>,
    options: &SetOptions,
    requested: &[&str],
    unsafe_operations: &mut PendingOperations,
    reader: &mut EfivarReader,
    held: Option<&dyn DriverHeldValues>,
) -> Result<Vec<Selected<'a>>> {
    forms::check_access_level(
        parsed_db.iter().flat_map(|list| &list.forms),
        options.access_level,
    )?;
    parsed_db
        .iter()
        .try_for_each(package::ParsedPackageList::check_form_strings)?;
    check_unambiguous(parsed_db, question, question_variations)?;
    let statements = keyword_statements(parsed_db, question)?;

    // Every FormSet selects its question and option before the first write, so that a
    // selection error leaves every variable unchanged.
    let mut selected = Vec::new();
    let mut excluded = Exclusion::NONE;
    for (index, list) in parsed_db.iter().enumerate() {
        let texts = list.texts(requested);
        for root in &list.forms {
            // try to find the question
            let selection = forms::find_question(
                Rc::clone(root),
                &texts,
                &question.matching(question_variations, &statements),
                options.include,
                options.access_level,
                reader,
            );
            // its driver takes the value of a question that set may write, whatever the reach
            // of `reader`
            let through_driver = selection
                .written_or_likely()
                .is_some_and(|((candidate, _), _)| driver_of(held, candidate).is_some());
            let writer = forms::ReadOnlyWriter::Set(&mut *unsafe_operations);
            let choice = match through_driver {
                true => forms::read_only_choice(selection, &question.to_string(), writer)?,
                false => forms::choice_for_set(
                    selection,
                    &question.to_string(),
                    options,
                    writer,
                    reader,
                )?,
            };
            match choice {
                Choice::Chosen(descriptor, state) => selected.push(Selected {
                    guid: list.guid.to_string(),
                    list: QuestionList {
                        index,
                        device_path: list.device_path.as_ref(),
                    },
                    descriptor,
                    state,
                }),
                // question not found in this FormSet
                // or only in states that `include` does not allow
                Choice::Skipped(exclusion) => excluded |= exclusion,
            }
        }
    }
    if selected.is_empty() && !excluded.is_empty() {
        return Err(excluded.question_error(&question.to_string()).into());
    }
    let mut ignored = parsed_db
        .iter()
        .flat_map(package::ParsedPackageList::ignored_records)
        .peekable();
    if selected.is_empty() && ignored.peek().is_some() {
        return Err(SelectionError::MaybeInIgnoredIfr {
            question: question.to_string(),
            ignored: ignored.collect(),
        }
        .into());
    }
    Ok(selected)
}

/// The Question of `descriptor` that get, set and list-questions show, its answer the value as
/// read, with the options that `include` allows.
fn question_of(descriptor: forms::QuestionDescriptor, include: IncludedStates) -> Question {
    Question {
        options: descriptor.listed_options(include),
        items: descriptor.items(),
        name: descriptor.question,
        answer: descriptor.value,
        help: descriptor.help,
        flags: listed_flags(descriptor.flags),
        defaults: listed_defaults(descriptor.defaults),
        question_id: Some(i32::from(descriptor.identity.question_id)),
        form_set_guid: descriptor.identity.form_set.map(|guid| guid.to_string()),
        keywords: listed_keywords(descriptor.identity.keywords),
        ..Default::default()
    }
}

/// `keywords` as Question lists them: None, which --json leaves out, for none.
fn listed_keywords(keywords: Vec<forms::Keyword>) -> Option<Vec<QuestionKeyword>> {
    (!keywords.is_empty()).then(|| {
        keywords
            .into_iter()
            .map(|keyword| QuestionKeyword {
                namespace_id: keyword.namespace,
                keyword: keyword.keyword,
                ..Default::default()
            })
            .collect()
    })
}

/// The names of `flags`, as Question lists them: None, which --json leaves out, for none.
fn listed_flags(flags: QuestionFlags) -> Option<Vec<String>> {
    (!flags.is_empty()).then(|| {
        flags
            .iter_names()
            .map(|(name, _)| name.to_owned())
            .collect()
    })
}

/// The IFR that read_db ignores in `lists`, as GetResponseList and SetResponseList list it: None,
/// which --json leaves out, for none.
fn listed_ignored_ifr(lists: &[package::ParsedPackageList]) -> Result<Option<Vec<HiiIgnoredIfr>>> {
    let listed = lists
        .iter()
        .flat_map(package::ParsedPackageList::ignored_records)
        .map(|ignored| {
            Ok(HiiIgnoredIfr {
                package_list: ignored.package_list.to_string(),
                offset: i64::try_from(ignored.offset)
                    .context("the offset of ignored IFR does not fit an i64")?,
                reason: ignored.reason,
                ..Default::default()
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((!listed.is_empty()).then_some(listed))
}

/// `defaults` as Question lists them: None, which --json leaves out, for none.
fn listed_defaults(defaults: Vec<DeclaredDefault>) -> Option<Vec<QuestionDefault>> {
    (!defaults.is_empty()).then(|| {
        defaults
            .into_iter()
            .map(|default| QuestionDefault {
                default_id: Some(i32::from(default.default_id.0)),
                default_store_name: default.store_name,
                value: Some(default.value.to_string()),
                ..Default::default()
            })
            .collect()
    })
}

/// Sets each of the `selected` questions to `answer` with `include`, through set_questions with
/// `reader`, `access_level`, `volatile`, `unsafe_operations` and `writes`: those with a VarStore
/// in their variables, then each of those whose driver holds the value through `held`
/// (DriverHeldSet), after refusing questions of more than one kind (check_one_kind) and checking
/// every value and what each driver would refuse first, and the unsafe operations before the
/// first write, also before the first Callback(). Returns the SetAnswer of each, in `selected`
/// order, and the unsafe operations that it lifted.
#[expect(
    clippy::too_many_arguments,
    reason = "set_questions' inputs, and the driver that holds the values of the others"
)]
fn set_selected(
    question: &str,
    selected: &[Selected<'_>],
    answer: forms::NewAnswer<'_>,
    include: IncludedStates,
    reader: &mut EfivarReader,
    access_level: Option<AccessLevel>,
    volatile: VolatileWrites,
    unsafe_operations: PendingOperations,
    writes: &WithholdingVariables<impl FirmwareVariables>,
    held: Option<&dyn DriverHeldValues>,
) -> Result<(Vec<SetAnswer>, Vec<UnsafeOperation>)> {
    forms::check_one_kind(
        question,
        &selected
            .iter()
            .map(|selected| (selected.guid.as_str(), &selected.descriptor))
            .collect::<Vec<_>>(),
    )?;
    let held_sets = selected
        .iter()
        .filter_map(|selected| {
            let (held, driver_held) = driver_of(held, &selected.descriptor)?;
            // refused before any write, as the driver's Callback()s would refuse it
            let value = match driver_held.write_expression {
                true => Err(ExpressionBesideCallback(QuestionExpression::Write).into()),
                false => selected
                    .descriptor
                    .driver_held_value(answer, include)
                    .map_err(anyhow::Error::from),
            };
            Some(value.and_then(|value| {
                held.check_set(&selected.list, &selected.descriptor, driver_held)?;
                Ok(DriverHeldSet {
                    selected,
                    held,
                    driver_held,
                    value,
                })
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let stored: Vec<(&str, &QuestionDescriptor)> = selected
        .iter()
        .filter(|selected| driver_of(held, &selected.descriptor).is_none())
        .map(|selected| (selected.guid.as_str(), &selected.descriptor))
        .collect();
    let drivers: Vec<&dyn DriverStore> = held_sets
        .iter()
        .map(|held_set| held_set as &dyn DriverStore)
        .collect();

    let (written, held_annotations, lifted) = forms::set_questions(
        question,
        &stored,
        answer,
        include,
        reader,
        access_level,
        volatile,
        unsafe_operations,
        writes,
        &drivers,
    )?;
    let text = match answer {
        forms::NewAnswer::Text { text, .. } => text,
        forms::NewAnswer::Items(_) => "",
    };
    let mut stored_answers = written.iter().map(|written| SetAnswer {
        answer: written.given.answer(text),
        items: written.given.items(),
        volatile: written.volatile,
    });
    // a driver keeps the value, in no variable
    let mut held_answers = held_annotations.into_iter().map(|annotation| SetAnswer {
        answer: text.to_owned() + &annotation,
        items: None,
        volatile: false,
    });
    let answers = selected
        .iter()
        .map(|selected| {
            let answer = match driver_of(held, &selected.descriptor) {
                Some(_) => held_answers.next(),
                None => stored_answers.next(),
            };
            answer.unwrap_or_default()
        })
        .collect();
    Ok((answers, lifted))
}

/// What set shows of a question that it set: its answer, the items of an ORDERED_LIST, and whether
/// set wrote a volatile variable for it.
#[derive(Default)]
struct SetAnswer {
    answer: String,
    items: Option<Vec<String>>,
    volatile: bool,
}

/// A question whose driver holds its value, with the value that set checked for it: set
/// applies it through `held` after the variable writes.
struct DriverHeldSet<'s> {
    selected: &'s Selected<'s>,
    held: &'s dyn DriverHeldValues,
    driver_held: &'s DriverHeldQuestion,
    value: u64,
}

impl DriverStore for DriverHeldSet<'_> {
    fn label(&self) -> String {
        format!("{} ({})", self.selected.guid, self.held.store_name())
    }

    fn apply(&self) -> Result<String> {
        self.held.set(
            &self.selected.list,
            &self.selected.descriptor,
            self.driver_held,
            self.value,
        )
    }
}

/// The question that apply-staged sets for `request` in `parsed_db`: the one whose driver holds its
/// value as QuestionId `request.question_id` of the FormSet `request.form_set`, with its package
/// list and how its driver holds it, and the unsafe operations that setting it lifts. Refused
/// unless exactly one question is that, the states of `request.include` cover each state it may be
/// in, with conditions reading `request.access_level` if stated, as set's selection reads them with
/// `reader`, it takes the request's value type, and no EFI_IFR_VALUE makes it read-only. A HiiDB
/// that declares a setup password question, and a question that EFI_IFR_FLAG_READ_ONLY makes
/// read-only, are unsafe operations, checked against `request.unsafe_operations`, set's grant, as
/// set checks them. Its texts show in the languages `requested` takes (ParsedPackageList::texts).
#[cfg(all(variable_data, any(target_os = "uefi", test)))]
fn staged_question<'a>(
    parsed_db: &'a [package::ParsedPackageList],
    request: &StagedRequest,
    requested: &[&str],
    reader: &mut EfivarReader,
) -> Result<(
    QuestionList<'a>,
    QuestionDescriptor,
    DriverHeldQuestion,
    Vec<UnsafeOperation>,
)> {
    let mut unsafe_operations = PendingOperations::new(request.unsafe_operations);
    if let Some(staged) = PasswordQuestions::of_lists(parsed_db).staged_setup_password() {
        unsafe_operations.add(staged);
    }
    forms::check_access_level(
        parsed_db.iter().flat_map(|list| &list.forms),
        request.access_level,
    )?;
    let mut found = Vec::new();
    for (index, list) in parsed_db.iter().enumerate() {
        let texts = list.texts(requested);
        for root in &list.forms {
            let questions = list_questions(
                Rc::clone(root),
                &texts,
                IncludedStates::all(),
                request.access_level,
                reader,
            );
            found.extend(
                questions
                    .into_iter()
                    .filter(|(descriptor, _)| {
                        descriptor.driver_held().is_some_and(|held| {
                            held.form_set == request.form_set
                                && held.question_id == request.question_id
                        })
                    })
                    .map(|(descriptor, state)| {
                        let list = QuestionList {
                            index,
                            device_path: list.device_path.as_ref(),
                        };
                        (list, descriptor, state)
                    }),
            );
        }
    }

    let named = format!(
        "question {:?}, QuestionId {:#06x} of FormSet {}",
        request.question, request.question_id, request.form_set
    );
    let (list, descriptor, state) = match <[_; 1]>::try_from(found) {
        Ok([question]) => question,
        Err(found) if found.is_empty() => {
            return Err(anyhow!(
                "the HII database holds no {named} whose driver holds its value"
            ))
        }
        Err(found) => {
            return Err(anyhow!(
                "{} package lists of the HII database hold {named}",
                found.len()
            ))
        }
    };
    if !state.is_allowed(request.include) {
        return Err(anyhow!(
            "{named} is{} now, which set did not include",
            state.annotation()
        ));
    }
    let held = match descriptor.driver_held() {
        Some(held) if held.value_type == request.value_type => held.clone(),
        Some(held) => {
            return Err(anyhow!(
                "{named} takes {} now, not {}",
                held.value_type,
                request.value_type
            ))
        }
        None => return Err(anyhow!("{named} has a VarStore now")),
    };
    forms::check_staged_read_only(
        descriptor.question.clone(),
        state.read_only(),
        forms::ReadOnlyWriter::Set(&mut unsafe_operations),
    )?;
    let lifted = unsafe_operations.check()?;
    Ok((list, descriptor, held, lifted))
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::BTreeMap;
    #[cfg(efivar_dumps)]
    use std::fs;
    use std::rc::Rc;

    use fbthrift::simplejson_protocol;

    #[cfg(variable_data)]
    use crate::efi_variables::authenticated::signing::tests::other_pems;
    #[cfg(variable_data)]
    use crate::efi_variables::authenticated::signing::tests::test_pems;
    use crate::efi_variables::enhanced_authenticated::fixture::timestamp_metadata;
    use crate::hii::config_snapshot::tests::block_resp;
    use crate::hii::config_snapshot::tests::config_hdr;
    use crate::hii::config_snapshot::tests::logged_by;
    use crate::hii::forms::ifr_fixtures::checkbox_at;
    use crate::hii::forms::ifr_fixtures::checkbox_on;
    use crate::hii::forms::ifr_fixtures::conditional;
    use crate::hii::forms::ifr_fixtures::default_store_named;
    use crate::hii::forms::ifr_fixtures::eq_id_val_of;
    use crate::hii::forms::ifr_fixtures::flagged_option;
    use crate::hii::forms::ifr_fixtures::flagged_string_on;
    use crate::hii::forms::ifr_fixtures::form;
    use crate::hii::forms::ifr_fixtures::form_set;
    use crate::hii::forms::ifr_fixtures::form_set_with_guid;
    use crate::hii::forms::ifr_fixtures::ifr_default;
    use crate::hii::forms::ifr_fixtures::ifr_default_2;
    use crate::hii::forms::ifr_fixtures::ifr_false;
    use crate::hii::forms::ifr_fixtures::ifr_true;
    use crate::hii::forms::ifr_fixtures::in_unknown_scope;
    use crate::hii::forms::ifr_fixtures::locked_op;
    use crate::hii::forms::ifr_fixtures::nested;
    use crate::hii::forms::ifr_fixtures::on_small_stack;
    use crate::hii::forms::ifr_fixtures::one_of_at;
    use crate::hii::forms::ifr_fixtures::operation;
    use crate::hii::forms::ifr_fixtures::other_option;
    use crate::hii::forms::ifr_fixtures::password_on;
    use crate::hii::forms::ifr_fixtures::question_header_with;
    use crate::hii::forms::ifr_fixtures::scoped_expression;
    use crate::hii::forms::ifr_fixtures::scopeless_form_set;
    use crate::hii::forms::ifr_fixtures::short_var_store_efi;
    use crate::hii::forms::ifr_fixtures::short_var_store_efi_of;
    use crate::hii::forms::ifr_fixtures::string_default;
    use crate::hii::forms::ifr_fixtures::string_on;
    use crate::hii::forms::ifr_fixtures::string_option;
    use crate::hii::forms::ifr_fixtures::subtitle_scope;
    use crate::hii::forms::ifr_fixtures::uint16_option;
    use crate::hii::forms::ifr_fixtures::uint8;
    use crate::hii::forms::ifr_fixtures::uint8_numeric_with;
    use crate::hii::forms::ifr_fixtures::value_of;
    use crate::hii::forms::ifr_fixtures::var_store;
    use crate::hii::forms::ifr_fixtures::var_store_efi;
    use crate::hii::forms::ifr_fixtures::var_store_efi_of;
    use crate::hii::forms::ifr_fixtures::var_store_name_value;
    use crate::hii::forms::ifr_fixtures::MemoryVariables;
    use crate::hii::forms::ifr_fixtures::VariableInterface;
    use crate::hii::forms::ifr_fixtures::VariableKey;
    use crate::hii::forms::ifr_fixtures::VariableReach;
    use crate::hii::forms::ifr_fixtures::BIT_VARSTORE_GUID;
    use crate::hii::forms::ifr_fixtures::BS_RT;
    use crate::hii::forms::ifr_fixtures::CHECKBOX;
    use crate::hii::forms::ifr_fixtures::DATE;
    use crate::hii::forms::ifr_fixtures::DEFAULT_STORE;
    use crate::hii::forms::ifr_fixtures::DISABLE_IF;
    use crate::hii::forms::ifr_fixtures::END;
    use crate::hii::forms::ifr_fixtures::GRAY_OUT_IF;
    use crate::hii::forms::ifr_fixtures::GUID;
    use crate::hii::forms::ifr_fixtures::NIL_GUID;
    use crate::hii::forms::ifr_fixtures::NUMERIC;
    use crate::hii::forms::ifr_fixtures::NV_BS;
    use crate::hii::forms::ifr_fixtures::NV_BS_RT;
    use crate::hii::forms::ifr_fixtures::ONE_OF;
    use crate::hii::forms::ifr_fixtures::ORDERED_LIST;
    use crate::hii::forms::ifr_fixtures::OTHER_GUID;
    use crate::hii::forms::ifr_fixtures::PASSWORD;
    use crate::hii::forms::ifr_fixtures::QUESTION_REF1;
    use crate::hii::forms::ifr_fixtures::READ;
    use crate::hii::forms::ifr_fixtures::REF;
    use crate::hii::forms::ifr_fixtures::SHORT_VAR_STORE_GUID;
    use crate::hii::forms::ifr_fixtures::SUBTITLE;
    use crate::hii::forms::ifr_fixtures::SUPPRESS_IF;
    use crate::hii::forms::ifr_fixtures::SYSTEM_ACCESS_GUID;
    use crate::hii::forms::ifr_fixtures::THIS;
    use crate::hii::forms::ifr_fixtures::TIME;
    use crate::hii::forms::ifr_fixtures::VALUE;
    use crate::hii::forms::ifr_fixtures::VAR_STORE;
    use crate::hii::forms::ifr_fixtures::VAR_STORE_EFI;
    use crate::hii::forms::ifr_fixtures::VAR_STORE_NAME_VALUE;
    #[cfg(variable_data)]
    use crate::hii::forms::ifr_fixtures::WRITE;
    #[cfg(variable_data)]
    use crate::hii::forms::IfrValueType;
    use crate::hii::forms::StoragelessRefusal;
    use crate::hii::forms::MAX_SCOPE_NESTING;
    use crate::hii::package::hiidb_fixtures::device_path_package;
    use crate::hii::package::hiidb_fixtures::en_strings_list;
    use crate::hii::package::hiidb_fixtures::en_strings_package;
    use crate::hii::package::hiidb_fixtures::en_strings_package_of;
    use crate::hii::package::hiidb_fixtures::form_package;
    use crate::hii::package::hiidb_fixtures::form_package_of;
    use crate::hii::package::hiidb_fixtures::form_package_with_guid;
    use crate::hii::package::hiidb_fixtures::form_set_package;
    use crate::hii::package::hiidb_fixtures::other_store;
    use crate::hii::package::hiidb_fixtures::package_list_with_guid;
    use crate::hii::package::hiidb_fixtures::password_past_the_walk_hiidb;
    use crate::hii::package::hiidb_fixtures::password_store;
    use crate::hii::package::hiidb_fixtures::password_store_hiidb;
    use crate::hii::package::hiidb_fixtures::strings_package_of;
    use crate::hii::package::hiidb_fixtures::END_PACKAGE;
    use crate::hii::package::hiidb_fixtures::PAST_THE_WALK_LIST_GUID;
    use crate::hii::package::Guid;
    use crate::hii::VariableAttributes;
    #[cfg(variable_data)]
    use crate::secret_file::read_secret_file;
    #[cfg(variable_data)]
    use crate::secret_file::MAX_SECRET_LEN;

    use super::*;

    /// HiiBackend::set_in, without the unsafe operations that it lifted.
    fn set_responses(
        db_bytes: &[u8],
        question: impl Into<QuestionSelector>,
        new_value: &SetValue,
        selector: Option<&str>,
        options: &SetOptions,
        access: SetAccess<'_>,
        platform_lang: Option<&str>,
    ) -> Result<SetResponseList> {
        HiiBackend::set_in(
            db_bytes,
            question,
            new_value,
            selector,
            options,
            access,
            platform_lang,
        )
        .map(|(responses, _)| responses)
    }

    /// The refusal of enhanced_signers for the Signers of `write`, of `key` and `certificates`.
    #[cfg(variable_data)]
    fn signers_refusal(
        write: &EnhancedVariableWrite<'_>,
        key: &Secret,
        certificates: &[u8],
    ) -> String {
        match enhanced_signers(write, key, certificates) {
            Ok(_) => panic!("Signers of {}", write.name),
            Err(error) => format!("{error:#}"),
        }
    }

    /// enhanced_signers refuses a new authority whose key is no PEM RSA private key, or whose
    /// certificate holds another key, naming the NewCert's flags, so that the refusal differs
    /// from the same one of the signing key.
    #[cfg(variable_data)]
    #[test]
    fn enhanced_signers_name_a_broken_new_authority() {
        let (key, certificates) = test_pems();
        let not_a_key = read_secret_file(&b"not a key"[..], MAX_SECRET_LEN).expect("a secret");
        let freshness = Freshness::Nonce {
            nonce: "01".parse().expect("a nonce"),
            current: None,
        };
        let write = |new_authority| EnhancedVariableWrite {
            name: "Example",
            vendor: "DE145B29-C3CD-455F-91DE-A76237B67C52",
            attributes: VariableAttributes::NON_VOLATILE,
            data: b"data",
            freshness: &freshness,
            digest: SignatureDigest::Sha256,
            new_authority,
            unsafe_operations: UnsafeOperations::Refuse,
        };
        for (new_key, refused) in [
            (
                &not_a_key,
                "the signing key is neither a PEM PKCS #8 nor a PEM PKCS #1 RSA private key",
            ),
            (
                &other_pems().0,
                "the first certificate of the bundle does not hold the public key of the signing key",
            ),
        ] {
            let new_authority = NewAuthority {
                key: new_key,
                certificates: certificates.as_bytes(),
            };

            let as_new_authority =
                signers_refusal(&write(Some(new_authority)), key, certificates.as_bytes());
            let as_signing_key = signers_refusal(&write(None), new_key, certificates.as_bytes());

            assert_eq!(
                as_new_authority,
                format!(
                    "the new authority of the NewCert, --new-signing-key-file and \
                     --new-signing-certificate-file: {refused}"
                ),
                "new authority"
            );
            assert_eq!(as_signing_key, refused, "signing key");
            assert_ne!(as_new_authority, as_signing_key, "{refused}");
        }
    }

    /// A package list with GUID `guid` holding a FormSet titled by the
    /// one-character string `title` of its own strings package.
    fn form_set_list(guid: [u8; 16], title: u8) -> Vec<u8> {
        let packages = [
            form_set_package(),
            en_strings_package(title),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid(guid, &packages.concat())
    }

    /// show_ifr titles the FormSet of each package list with the strings of
    /// that list, in HiiDB order, duplicate GUIDs included.
    #[test]
    fn test_show_ifr_titles_form_sets_with_their_own_strings_in_hiidb_order() {
        let hiidb = [
            form_set_list([0x33; 16], b'A'),
            form_set_list([0x11; 16], b'C'),
            form_set_list([0x33; 16], b'B'),
        ]
        .concat();
        // no variables: on Windows, System enables a privilege that needs elevation
        let options = ShowIfrOptions {
            efivars: EfivarSource::Disabled,
            ..Default::default()
        };

        let ifr = HiiBackend::show_ifr_using(&hiidb, &options)
            .expect("show the IFR")
            .readable_representation;

        let got: Vec<(&str, &str)> = ifr
            .split("Packagelist ")
            .skip(1)
            .map(|list| {
                let title = list
                    .split("FormSet - ")
                    .nth(1)
                    .and_then(|form_set| form_set.split(" - GUID").next());
                (list.get(..36).unwrap_or(list), title.unwrap_or(""))
            })
            .collect();
        let want = [
            ("33333333-3333-3333-3333-333333333333", "A"),
            ("11111111-1111-1111-1111-111111111111", "C"),
            ("33333333-3333-3333-3333-333333333333", "B"),
        ];
        assert_eq!(got, want, "package lists and FormSet titles in {ifr:?}");
    }

    /// show_ifr ends the line of each package list's header before the forms of that list.
    #[test]
    fn test_show_ifr_ends_each_package_list_line_before_its_forms() {
        let hiidb = [
            form_set_list([0x33; 16], b'A'),
            form_set_list([0x11; 16], b'C'),
        ]
        .concat();
        // no variables: on Windows, System enables a privilege that needs elevation
        let options = ShowIfrOptions {
            efivars: EfivarSource::Disabled,
            ..Default::default()
        };

        let ifr = HiiBackend::show_ifr_using(&hiidb, &options)
            .expect("show the IFR")
            .readable_representation;

        let lines: Vec<&str> = ifr.lines().collect();
        let headers: Vec<(&str, &str)> = lines
            .windows(2)
            .filter(|pair| pair[0].starts_with("Packagelist "))
            .map(|pair| (pair[0], pair[1]))
            .collect();
        let want = [
            (
                "Packagelist 33333333-3333-3333-3333-333333333333",
                "OpCode: ROOT",
            ),
            (
                "Packagelist 11111111-1111-1111-1111-111111111111",
                "OpCode: ROOT",
            ),
        ];
        assert_eq!(
            headers, want,
            "package list lines and the lines after them in {ifr:?}"
        );
    }

    /// Each line of show_ifr_in holds no line break of its own: display_op pushes a line per
    /// line of each of its arms, and show_ifr_in one per package list and disabled form, so that
    /// the CLI, which escapes a line break inside a line, shows each on a line of its own.
    #[test]
    fn show_ifr_lines_hold_no_line_break() {
        let header = |question_id, offset| question_header_with(question_id, 2, 1, offset, 0x00);
        let questions = [
            [subtitle_scope(2), END.to_vec()].concat(),
            one_of_at(1, 2, 1, 0, &[(2, 0)]),
            uint8_numeric_with(2, 2, 1, 0x00, &[]),
            checkbox_at(3, 2, 1, 2),
            operation(DATE, false, &[header(4, 3), vec![0x00]].concat()),
            operation(TIME, false, &[header(5, 7), vec![0x00]].concat()),
            [
                operation(ORDERED_LIST, true, &[header(6, 10), vec![1, 0x00]].concat()),
                flagged_option(2, 0x00, 1),
                END.to_vec(),
            ]
            .concat(),
            operation(REF, false, &header(7, 11)),
            string_on(9, 2, (1, 12), (0, 4), &[]),
            in_unknown_scope(&checkbox_at(8, 2, 1, 2)),
            locked_op(),
        ];
        let packages = [
            form_package(&[
                var_store(1, [0x22; 16], "Store", 40),
                var_store_name_value(2, [0x33; 16]),
                form(1, &questions),
                form(2, &[operation(CHECKBOX, false, &[0x00; 4])]),
            ]),
            en_strings_package_of(&["FormSet", "Text"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x55; 16], &packages.concat());

        let shown = HiiBackend::show_ifr_in(
            &hiidb,
            &ShowIfrOptions::default(),
            shared(&Rc::new(MemoryVariables::default())),
            None,
            None,
        )
        .expect("show the IFR");

        let starts = [
            "Packagelist ",
            "OpCode: ROOT",
            "OpCode: FormSet - ",
            "OpCode: VarStore - Name: ",
            "OpCode: VarStoreNameValue - Id: ",
            "OpCode: Subtitle - S: ",
            "OpCode: OneOf - Q: ",
            "OpCode: OneOfOption - S: ",
            "-ValueType:",
            "-Value:",
            "OpCode: Numeric - Q: ",
            "OpCode: CheckBox - Q: - ",
            "OpCode: Date - Q: ",
            "OpCode: Time - Q: ",
            "-Flags: ",
            "OpCode: OrderedList - Q: ",
            "-MaxContainers: ",
            "OpCode: Ref - Q: ",
            "OpCode: String - Q: ",
            "-MinSize: ",
            "-Answer: ",
            "OpCode: Unknown(0xf0) - skipped",
            "OpCode: Locked",
            "Disabled at offset ",
        ];
        for start in starts {
            assert!(
                shown
                    .lines()
                    .any(|line| line.trim_start().starts_with(start)),
                "a line starts with {start:?}: {shown}"
            );
        }
        for line in shown.lines() {
            assert!(!line.contains(['\n', '\r']), "line {line:?} breaks");
        }
    }

    /// list_strings returns the strings packages in HiiDB order, duplicate
    /// GUIDs included.
    #[test]
    fn test_list_strings_keeps_hiidb_order() {
        let hiidb = [
            en_strings_list([0x33; 16], b'A'),
            en_strings_list([0x11; 16], b'C'),
            en_strings_list([0x33; 16], b'B'),
        ]
        .concat();

        let got: Vec<(String, BTreeMap<i32, String>)> = HiiBackend::list_strings(&hiidb)
            .expect("list the strings")
            .into_iter()
            .map(|package| (package.package_list, package.string_package))
            .collect();

        let want = [
            ("33333333-3333-3333-3333-333333333333", "A"),
            ("11111111-1111-1111-1111-111111111111", "C"),
            ("33333333-3333-3333-3333-333333333333", "B"),
        ]
        .map(|(guid, string)| (guid.to_string(), BTreeMap::from([(1, string.to_string())])));
        assert_eq!(got, want, "strings packages in HiiDB order");
    }

    /// list_strings names each strings package's language, that of its header, beside its own
    /// strings.
    #[test]
    fn test_list_strings_names_each_package_language() {
        let hiidb = [
            package_list_with_guid(
                [0x11; 16],
                &[
                    // out of sorted order: each package keeps its own language
                    strings_package_of(b"x-UEFI-ns", &["iSCSIBootEnable"]),
                    strings_package_of(b"en-US", &["Boot"]),
                    END_PACKAGE.to_vec(),
                ]
                .concat(),
            ),
            package_list_with_guid(
                [0x33; 16],
                &[
                    strings_package_of(b"fr-FR", &["D\u{e9}marrage"]),
                    END_PACKAGE.to_vec(),
                ]
                .concat(),
            ),
        ]
        .concat();

        let got: Vec<(String, String, BTreeMap<i32, String>)> = HiiBackend::list_strings(&hiidb)
            .expect("list the strings")
            .into_iter()
            .map(|package| {
                (
                    package.package_list,
                    package.language,
                    package.string_package,
                )
            })
            .collect();

        let want = [
            (
                "11111111-1111-1111-1111-111111111111",
                "x-UEFI-ns",
                "iSCSIBootEnable",
            ),
            ("11111111-1111-1111-1111-111111111111", "en-US", "Boot"),
            (
                "33333333-3333-3333-3333-333333333333",
                "fr-FR",
                "D\u{e9}marrage",
            ),
        ]
        .map(|(guid, language, string)| {
            (
                guid.to_string(),
                language.to_string(),
                BTreeMap::from([(1, string.to_string())]),
            )
        });
        assert_eq!(got, want, "languages and strings of the strings packages");
    }

    /// list_strings refuses a strings package whose Language is not ASCII, as UEFI 2.11
    /// §33.3.6.1 defines it, valid UTF-8 or not, and lists one whose Language is.
    #[test]
    fn test_list_strings_refuses_a_language_that_is_not_ascii() {
        let list = |language: &[u8]| {
            let package = strings_package_of(language, &["A"]);
            package_list_with_guid([0x22; 16], &[package, END_PACKAGE.to_vec()].concat())
        };
        let cases: [(&[u8], &str); 3] = [
            ("en-\u{e9}".as_bytes(), r"en-\xc3\xa9"),
            (b"en-\xe9", r"en-\xe9"),
            (b"\xff", r"\xff"),
        ];
        for (language, shown) in cases {
            let Err(err) = HiiBackend::list_strings(&list(language)) else {
                panic!("list_strings listed the Language {language:02x?}");
            };

            let msg = format!("{err:#}");
            let want = format!(
                "failed to list a strings package of package list \
                 22222222-2222-2222-2222-222222222222: its Language \"{shown}\" is not ASCII"
            );
            assert_eq!(msg, want, "Language {language:02x?}");
        }

        let packages = HiiBackend::list_strings(&list(b"en-US")).expect("list the Language en-US");
        let languages: Vec<&str> = packages.iter().map(|p| p.language.as_str()).collect();
        assert_eq!(languages, ["en-US"], "languages of the strings packages");
    }

    /// list_questions and show_ifr read a HiiDB whose strings package's Language is not ASCII:
    /// neither shows a Language.
    #[test]
    fn test_questions_and_ifr_read_a_language_that_is_not_ascii() {
        let packages = [strings_package_of(b"en-\xe9", &["A"]), END_PACKAGE.to_vec()].concat();
        let hiidb = package_list_with_guid([0x22; 16], &packages);

        let questions = ListQuestionsOptions {
            efivars: EfivarSource::Disabled,
            ..ListQuestionsOptions::default()
        };
        HiiBackend::list_questions_using(&hiidb, &questions).expect("list the questions");
        let ifr = ShowIfrOptions {
            efivars: EfivarSource::Disabled,
            ..Default::default()
        };
        HiiBackend::show_ifr_using(&hiidb, &ifr).expect("show the IFR");
    }

    /// Prompts come from the first strings package of a language that is no x- configuration
    /// language, here after an x-UEFI-ns package, else from another such package that holds the
    /// string, and never from an x- package: a string that only one holds shows as "".
    #[test]
    fn texts_never_come_from_a_configuration_language() {
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, 3),
                form(
                    1,
                    &[
                        checkbox_at(1, 1, 1, 0),
                        checkbox_at(2, 2, 1, 1),
                        checkbox_at(3, 3, 1, 2),
                    ],
                ),
            ]),
            strings_package_of(
                b"x-UEFI-ns",
                &["BootEnable", "SecondKeyword", "ThirdKeyword"],
            ),
            strings_package_of(b"en-US", &["Boot"]),
            strings_package_of(b"fr-FR", &["D\u{e9}marrage", "Seconde"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x66; 16], &packages.concat());

        let names: Vec<String> = HiiBackend::list_questions_in(
            &hiidb,
            &ListQuestionsOptions::default(),
            Box::new(MemoryVariables::default()),
            None,
            None,
        )
        .expect("list the questions")
        .into_iter()
        .map(|question| question.name)
        .collect();

        assert_eq!(names, ["Boot", "Seconde", ""], "names of the questions");
    }

    /// A package list whose only strings package is of a configuration language names its
    /// questions "": the texts of x- packages are never shown, even with no other package.
    #[test]
    fn a_list_of_configuration_texts_only_names_no_question() {
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, 1),
                form(1, &[checkbox_at(1, 1, 1, 0)]),
            ]),
            strings_package_of(b"x-UEFI-ns", &["BootEnable"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x6D; 16], &packages.concat());

        let names = names_listed(&hiidb, &ListQuestionsOptions::default(), None);

        assert_eq!(names, [""], "names of the questions");
    }

    /// get and set select no question by a QUESTION that only a package of a configuration
    /// language holds as its prompt, and set writes nothing; a QUESTION of a display language
    /// selects as before.
    #[test]
    fn questions_match_no_text_of_a_configuration_language() {
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, 2),
                form(1, &[checkbox_at(1, 1, 1, 0), checkbox_at(2, 2, 1, 1)]),
            ]),
            strings_package_of(b"x-UEFI-ns", &["BootEnable", "SecondKeyword"]),
            strings_package_of(b"en-US", &["Boot", "Second"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x6F; 16], &packages.concat());
        let variables = Rc::new(MemoryVariables::default());
        variables.insert(setup(), 7, &[0, 0]);

        let got = HiiBackend::get_in(
            &hiidb,
            "BootEnable",
            None,
            &GetOptions::default(),
            shared(&variables),
            None,
            None,
            None,
        )
        .expect("get BootEnable");
        let set = set_responses(
            &hiidb,
            "BootEnable",
            &SetValue::Text("1".to_owned()),
            None,
            &SetOptions::default(),
            SetAccess {
                reads: shared(&variables),
                writes: &*variables,
                held: None,
            },
            None,
        );
        let keyword_writes = variables.writes_to(&setup());
        let boot = set_responses(
            &hiidb,
            "Boot",
            &SetValue::Text("1".to_owned()),
            None,
            &SetOptions::default(),
            SetAccess {
                reads: shared(&variables),
                writes: &*variables,
                held: None,
            },
            None,
        )
        .expect("set Boot 1");

        assert_eq!(got.responses.len(), 0, "get BootEnable answers");
        assert_eq!(
            set.map(drop).map_err(|error| error.to_string()),
            Err("no question \"BootEnable\" in the HiiDB".to_string()),
            "set BootEnable 1"
        );
        assert_eq!(keyword_writes, [], "set BootEnable 1 writes");
        let names: Vec<&str> = boot
            .responses
            .iter()
            .map(|response| response.question.name.as_str())
            .collect();
        assert_eq!(names, ["Boot"], "set Boot 1");
        assert_eq!(
            variables.writes_to(&setup()),
            [(0, vec![1])],
            "set Boot 1 writes"
        );
    }

    /// A package of a language whose "x-" is in upper case is a configuration language too: its
    /// texts are never shown.
    #[test]
    fn an_upper_case_x_language_is_a_configuration_language() {
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, 2),
                form(1, &[checkbox_at(1, 1, 1, 0), checkbox_at(2, 2, 1, 1)]),
            ]),
            strings_package_of(b"X-UEFI-ns", &["BootEnable", "SecondKeyword"]),
            strings_package_of(b"en-US", &["Boot"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x6E; 16], &packages.concat());

        let names = names_listed(&hiidb, &ListQuestionsOptions::default(), None);

        assert_eq!(names, ["Boot", ""], "names of the questions");
    }

    /// The names of the questions that list-questions lists in `hiidb` with `options`, whose
    /// variables hold nothing, on a platform of PlatformLang `platform`, if any.
    fn names_listed(
        hiidb: &[u8],
        options: &ListQuestionsOptions,
        platform: Option<&str>,
    ) -> Vec<String> {
        HiiBackend::list_questions_in(
            hiidb,
            options,
            Box::new(MemoryVariables::default()),
            None,
            platform,
        )
        .expect("list the questions")
        .into_iter()
        .map(|question| question.name)
        .collect()
    }

    /// A HiiDB whose CHECKBOXes 1, 2 and 3 are prompted by strings 1, 2 and 3, of which the
    /// x-UEFI-ns package holds all three, the en-US package 1 and 2, and the fr-FR package 1.
    fn translated_hiidb() -> Vec<u8> {
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, 3),
                form(
                    1,
                    &[
                        checkbox_at(1, 1, 1, 0),
                        checkbox_at(2, 2, 1, 1),
                        checkbox_at(3, 3, 1, 2),
                    ],
                ),
            ]),
            strings_package_of(
                b"x-UEFI-ns",
                &["BootEnable", "SecondKeyword", "ThirdKeyword"],
            ),
            strings_package_of(b"en-US", &["Boot", "Second"]),
            strings_package_of(b"fr-FR", &["D\u{e9}marrage"]),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid([0x66; 16], &packages.concat())
    }

    /// Texts come from the strings package that edk2 GetBestLanguage picks for --language,
    /// ignoring ASCII case, else from the first package of no x- language; a string that the
    /// chosen package lacks comes from another package of no x- language, never from an x- one.
    #[test]
    fn prompts_come_from_the_best_language_package() {
        let french = ["D\u{e9}marrage", "Second", ""];
        let cases = [
            (None, ["Boot", "Second", ""]),
            (Some("fr-FR"), french),
            (Some("fr"), french),
            (Some("fr-CA"), french),
            (Some("FR-fr"), french),
            (Some("de-DE"), ["Boot", "Second", ""]),
            (
                Some("x-UEFI-ns"),
                ["BootEnable", "SecondKeyword", "ThirdKeyword"],
            ),
        ];
        for (language, want) in cases {
            let options = ListQuestionsOptions {
                language: language.map(str::to_string),
                ..ListQuestionsOptions::default()
            };

            let names = names_listed(&translated_hiidb(), &options, None);

            assert_eq!(names, want, "--language {language:?}");
        }
    }

    /// Without --language, texts come from the package that PlatformLang picks; --language
    /// picks before it.
    #[test]
    fn platform_lang_picks_below_the_stated_language() {
        let cases = [
            (None, Some("fr-FR"), "D\u{e9}marrage"),
            (Some("en-US"), Some("fr-FR"), "Boot"),
            (None, Some("de-DE"), "Boot"),
            (None, None, "Boot"),
        ];
        for (language, platform, want) in cases {
            let options = ListQuestionsOptions {
                language: language.map(str::to_string),
                ..ListQuestionsOptions::default()
            };

            let names = names_listed(&translated_hiidb(), &options, platform);

            assert_eq!(
                names.first().map(String::as_str),
                Some(want),
                "--language {language:?}, PlatformLang {platform:?}"
            );
        }
    }

    /// The efivar file of PlatformLang holding `data` after the attributes NV+BS+RT.
    #[cfg(all(efivar_dumps, variable_data))]
    fn platform_lang_file(dir: &std::path::Path, data: &[u8]) {
        fs::write(
            dir.join("PlatformLang-8be4df61-93ca-11d2-aa0d-00e098032b8c"),
            [&[7, 0, 0, 0][..], data].concat(),
        )
        .expect("write the efivar file of PlatformLang");
    }

    /// The name of the first question that list-questions lists in translated_hiidb() through
    /// --efivars DIR, where DIR holds `platform_lang`, if any, as the data of PlatformLang, with
    /// --language `language`, if any.
    #[cfg(all(efivar_dumps, variable_data))]
    fn first_name_listed(platform_lang: Option<&[u8]>, language: Option<&str>) -> Option<String> {
        let efivars = tempfile::tempdir().expect("create efivars directory");
        if let Some(data) = platform_lang {
            platform_lang_file(efivars.path(), data);
        }
        let options = ListQuestionsOptions {
            efivars: EfivarSource::Directory(efivars.path().to_path_buf()),
            language: language.map(str::to_string),
            ..ListQuestionsOptions::default()
        };

        HiiBackend::list_questions_using(&translated_hiidb(), &options)
            .expect("list the questions")
            .into_iter()
            .map(|question| question.name)
            .next()
    }

    /// list-questions through --efivars DIR shows texts in the language of the PlatformLang that
    /// DIR holds, unless --language picks one: an absent PlatformLang, or one that is no
    /// null-terminated ASCII string (UEFI 2.11 §3.3), picks none.
    #[cfg(all(efivar_dumps, variable_data))]
    #[test]
    fn platform_lang_chooses_the_texts() {
        let cases: [(Option<&[u8]>, &str); 4] = [
            (Some(b"fr-FR\0"), "D\u{e9}marrage"),
            (Some(b"fr\0"), "D\u{e9}marrage"),
            (None, "Boot"),
            (Some(b"fr-FR"), "Boot"),
        ];
        for (data, want) in cases {
            let name = first_name_listed(data, None);

            assert_eq!(name.as_deref(), Some(want), "PlatformLang {data:?}");
        }
        let stated = first_name_listed(Some(b"fr-FR\0"), Some("en-US"));
        assert_eq!(
            stated.as_deref(),
            Some("Boot"),
            "PlatformLang fr-FR, --language en-US"
        );
    }

    /// get and show-ifr through --efivars DIR show texts in the language of DIR's PlatformLang,
    /// and get still selects the question by its en-US prompt.
    #[cfg(all(efivar_dumps, variable_data))]
    #[test]
    fn efivars_dump_platform_lang_chooses_the_texts() {
        let efivars = tempfile::tempdir().expect("create efivars directory");
        platform_lang_file(efivars.path(), b"fr-FR\0");
        let source = EfivarSource::Directory(efivars.path().to_path_buf());
        let get = GetOptions {
            efivars: source.clone(),
            ..GetOptions::default()
        };
        let ifr = ShowIfrOptions {
            efivars: source,
            ..ShowIfrOptions::default()
        };

        let got = HiiBackend::get_using(&translated_hiidb(), "Boot", None, &get).expect("get Boot");
        let shown = HiiBackend::show_ifr_using(&translated_hiidb(), &ifr)
            .expect("show the IFR")
            .readable_representation;

        let names: Vec<&str> = got
            .responses
            .iter()
            .map(|response| response.question.name.as_str())
            .collect();
        assert_eq!(names, ["D\u{e9}marrage"], "get Boot");
        assert!(
            shown.contains("Q: - D\u{e9}marrage -"),
            "show-ifr shows the fr-FR prompt: {shown}"
        );
        assert!(
            !shown.contains("Q: - Boot -"),
            "show-ifr shows no en-US prompt: {shown}"
        );
    }

    /// A HiiDB whose CHECKBOX 0xA is prompted "Start" in en-US and "Boot" in fr-FR, and whose
    /// CHECKBOX 0x14 is prompted "Boot" in en-US.
    fn crossed_prompts_hiidb() -> Vec<u8> {
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, 2),
                form(1, &[checkbox_at(0xA, 1, 1, 0), checkbox_at(0x14, 2, 1, 1)]),
            ]),
            strings_package_of(b"en-US", &["Start", "Boot"]),
            strings_package_of(b"fr-FR", &["Boot", "D\u{e9}marrage"]),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid([0x67; 16], &packages.concat())
    }

    /// get and set refuse a QUESTION that no one language holds as the prompt of every question
    /// it names, naming each, and set writes nothing; a QUESTION that one language holds as the
    /// prompt of every question it names selects as before.
    #[test]
    fn get_refuses_a_prompt_of_different_questions_in_different_languages() {
        let variables = Rc::new(MemoryVariables::default());
        variables.insert(setup(), 7, &[0, 0]);
        let want = "\"Boot\" is the prompt of QuestionId 0x000A of FormSet \
                    11111111-1111-1111-1111-111111111111 in fr-FR and of QuestionId 0x0014 of \
                    FormSet 11111111-1111-1111-1111-111111111111 in en-US: no one language holds \
                    it as the prompt of every question it names";

        let got = HiiBackend::get_in(
            &crossed_prompts_hiidb(),
            "Boot",
            None,
            &GetOptions::default(),
            shared(&variables),
            None,
            None,
            None,
        );
        let set = set_responses(
            &crossed_prompts_hiidb(),
            "Boot",
            &SetValue::Text("1".to_owned()),
            None,
            &SetOptions::default(),
            SetAccess {
                reads: shared(&variables),
                writes: &*variables,
                held: None,
            },
            None,
        );
        let started = HiiBackend::get_in(
            &crossed_prompts_hiidb(),
            "Start",
            None,
            &GetOptions::default(),
            shared(&variables),
            None,
            Some("fr-FR"),
            None,
        )
        .expect("get Start");

        assert_eq!(
            got.map(drop).map_err(|error| error.to_string()),
            Err(want.to_string()),
            "get Boot"
        );
        assert_eq!(
            set.map(drop).map_err(|error| error.to_string()),
            Err(want.to_string()),
            "set Boot 1"
        );
        assert_eq!(variables.writes_to(&setup()), [], "set Boot 1 writes");
        let names: Vec<&str> = started
            .responses
            .iter()
            .map(|response| response.question.name.as_str())
            .collect();
        assert_eq!(names, ["Boot"], "get Start shows its fr-FR prompt");
    }

    /// A HiiDB whose ONE_OF "Mode" at byte 0 of Setup has the options 0 and 1, of strings 2 and
    /// 3, which `en_us` and `fr_fr` translate.
    fn mode_hiidb(en_us: [&str; 3], fr_fr: [&str; 3]) -> Vec<u8> {
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, 1),
                form(1, &[one_of_at(1, 1, 1, 0, &[(2, 0), (3, 1)])]),
            ]),
            strings_package_of(b"en-US", &en_us),
            strings_package_of(b"fr-FR", &fr_fr),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid([0x68; 16], &packages.concat())
    }

    /// On a platform of PlatformLang fr-FR, set selects a question and an option by their
    /// en-US texts and writes the option's value, and get shows their fr-FR texts.
    #[test]
    fn english_question_and_value_select_on_a_french_platform() {
        let hiidb = mode_hiidb(
            ["Mode", "Disabled", "Enabled"],
            [
                "Mode de d\u{e9}marrage",
                "D\u{e9}sactiv\u{e9}",
                "Activ\u{e9}",
            ],
        );
        let variables = Rc::new(MemoryVariables::default());
        variables.insert(setup(), 7, &[0]);

        set_responses(
            &hiidb,
            "Mode",
            &SetValue::Text("Enabled".to_owned()),
            None,
            &SetOptions::default(),
            SetAccess {
                reads: shared(&variables),
                writes: &*variables,
                held: None,
            },
            Some("fr-FR"),
        )
        .expect("set Mode Enabled");
        let got = HiiBackend::get_in(
            &hiidb,
            "Mode",
            None,
            &GetOptions::default(),
            shared(&variables),
            None,
            Some("fr-FR"),
            None,
        )
        .expect("get Mode");

        assert_eq!(variables.writes_to(&setup()), [(0, vec![1])], "set writes");
        let shown: Vec<(&str, &str)> = got
            .responses
            .iter()
            .map(|response| {
                (
                    response.question.name.as_str(),
                    response.question.answer.as_str(),
                )
            })
            .collect();
        assert_eq!(
            shown,
            [("Mode de d\u{e9}marrage", "Activ\u{e9}")],
            "get Mode"
        );
    }

    /// set matches VALUE against raw option texts only: a VALUE that holds an escape, as pasted
    /// from TerminalText's spelling of an option's text, names only an option whose raw text it
    /// is, which a HiiDB may hold, and never the option that shows so.
    #[test]
    fn set_matches_value_against_raw_option_texts_only() {
        let control = "A\u{1b}B";
        let shown = crate::terminal_text::TerminalText(control).to_string();
        let cases = [
            ([control, shown.as_str()], shown.as_str(), Some(1)),
            ([control, "Other"], shown.as_str(), None),
            ([control, shown.as_str()], control, Some(0)),
        ];
        for (options, value, want) in cases {
            let hiidb = mode_hiidb(
                ["Mode", options[0], options[1]],
                ["Mode", options[0], options[1]],
            );
            let variables = Rc::new(MemoryVariables::default());
            variables.insert(setup(), 7, &[0]);

            let set = HiiBackend::set_in(
                &hiidb,
                "Mode",
                &SetValue::Text(value.to_owned()),
                None,
                &SetOptions::default(),
                SetAccess {
                    reads: shared(&variables),
                    writes: &*variables,
                    held: None,
                },
                None,
            );

            let case = format!("options {options:?}, VALUE {value:?}");
            assert_eq!(set.is_ok(), want.is_some(), "{case}: {set:?}");
            let writes: Vec<(u16, Vec<u8>)> =
                want.map(|option| (0, vec![option])).into_iter().collect();
            assert_eq!(variables.writes_to(&setup()), writes, "{case}: writes");
        }
    }

    /// set refuses a VALUE that no one language holds as the text of every option it names,
    /// naming each, and writes nothing.
    #[test]
    fn set_refuses_a_value_of_different_options_in_different_languages() {
        let hiidb = mode_hiidb(["Mode", "Off", "Stop"], ["Mode", "Arr\u{ea}t", "Off"]);
        let variables = Rc::new(MemoryVariables::default());
        variables.insert(setup(), 7, &[1]);

        let got = set_responses(
            &hiidb,
            "Mode",
            &SetValue::Text("Off".to_owned()),
            None,
            &SetOptions::default(),
            SetAccess {
                reads: shared(&variables),
                writes: &*variables,
                held: None,
            },
            None,
        );

        assert_eq!(
            got.map(drop).map_err(|error| error.to_string()),
            Err(
                "the value is the text of option \"Off\" of question \"Mode\" in en-US and of \
                 option \"Stop\" in fr-FR: no one language holds it as the text of every option \
                 it names"
                    .to_string()
            ),
            "set Mode Off"
        );
        assert_eq!(variables.writes_to(&setup()), [], "set Mode Off writes");
    }

    /// The GUIDs of keyed_hiidb's FormSet and of its package list.
    const KEYED_FORM_SET: &str = "8C78A505-BAA0-4C4A-869F-000000000800";
    const KEYED_LIST: &str = "8C78A505-BAA0-4C4A-869F-000000000801";

    /// The EFI_GUID bytes of the GUID `text`.
    fn guid_bytes(text: &str) -> [u8; 16] {
        text.parse::<Guid>().expect("parse the GUID").into()
    }

    /// A HiiDB whose FormSet of Guid KEYED_FORM_SET holds the CHECKBOX of QuestionId 0x8001
    /// and en-US prompt `keyed`, which x-UEFI-ns and x-i-UEFI translate, and the CHECKBOX
    /// "Plain", whose prompt no package of a configuration language holds.
    fn keyed_hiidb(keyed: &str) -> Vec<u8> {
        let packages = [
            form_package_with_guid(
                guid_bytes(KEYED_FORM_SET),
                &[
                    var_store_efi(1, "Setup", NV_BS_RT, 2),
                    form(1, &[checkbox_at(0x8001, 3, 1, 0), checkbox_at(2, 5, 1, 1)]),
                ],
            ),
            strings_package_of(b"x-UEFI-ns", &["", "", "Keyword:5"]),
            strings_package_of(b"en-US", &["Title", "Help", keyed, "Help text", "Plain"]),
            strings_package_of(b"x-i-UEFI", &["", "", "Other"]),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid(guid_bytes(KEYED_LIST), &packages.concat())
    }

    /// The QuestionId, FormSet GUID and keywords of `question`, as --json prints them.
    fn identity_json(question: &Question) -> [Option<serde_json::Value>; 3] {
        ["question_id", "form_set_guid", "keywords"].map(|field| json_field(question, field))
    }

    /// list-questions, get and set show each question's QuestionId, its FormSet's GUID and its
    /// prompt in each package of a configuration language, by package order; --json leaves
    /// keywords out for a question without any.
    #[test]
    fn questions_show_their_question_id_form_set_guid_and_keywords() {
        let form_set = Some(serde_json::json!(KEYED_FORM_SET));
        let keyed = [
            Some(serde_json::json!(32769)),
            form_set.clone(),
            Some(serde_json::json!([
                {"namespace_id": "x-UEFI-ns", "keyword": "Keyword:5"},
                {"namespace_id": "x-i-UEFI", "keyword": "Other"},
            ])),
        ];
        let plain = [Some(serde_json::json!(2)), form_set, None];
        let variables = Rc::new(MemoryVariables::default());
        variables.insert(setup(), 7, &[0, 0]);

        let listed = HiiBackend::list_questions_in(
            &keyed_hiidb("Keyed"),
            &ListQuestionsOptions::default(),
            shared(&variables),
            None,
            None,
        )
        .expect("list the questions");
        let got = HiiBackend::get_in(
            &keyed_hiidb("Keyed"),
            "Keyed",
            None,
            &GetOptions::default(),
            shared(&variables),
            None,
            None,
            None,
        )
        .expect("get Keyed");
        let set = set_responses(
            &keyed_hiidb("Keyed"),
            "Keyed",
            &SetValue::Text("1".to_owned()),
            None,
            &SetOptions::default(),
            SetAccess {
                reads: shared(&variables),
                writes: &*variables,
                held: None,
            },
            None,
        )
        .expect("set Keyed 1");

        let listed: Vec<(&str, [Option<serde_json::Value>; 3])> = listed
            .iter()
            .map(|question| (question.name.as_str(), identity_json(question)))
            .collect();
        assert_eq!(
            listed,
            [("Keyed", keyed.clone()), ("Plain", plain)],
            "list-questions"
        );
        let got: Vec<[Option<serde_json::Value>; 3]> = got
            .responses
            .iter()
            .map(|response| identity_json(&response.question))
            .collect();
        assert_eq!(got, std::slice::from_ref(&keyed), "get Keyed");
        let set: Vec<[Option<serde_json::Value>; 3]> = set
            .responses
            .iter()
            .map(|response| identity_json(&response.question))
            .collect();
        assert_eq!(set, [keyed], "set Keyed 1");
    }

    /// list-questions shows a prompt as a keyword only where a <KeywordRequest> can name it: in a
    /// strings package whose language is a NAMESPACE, and as a <Keyword>, without '&' and with at
    /// most 4 instance digits.
    #[test]
    fn questions_show_only_keywords_that_a_keyword_request_names() {
        let packages = [
            form_package_with_guid(
                guid_bytes(KEYED_FORM_SET),
                &[
                    var_store_efi(1, "Setup", NV_BS_RT, 2),
                    form(1, &[checkbox_at(0x8001, 3, 1, 0)]),
                ],
            ),
            strings_package_of(b"en-US", &["Title", "Help", "Keyed"]),
            strings_package_of(b"x-UEFI-ns", &["", "", "Keyword:5"]),
            strings_package_of(b"x-UEFI-amp", &["", "", "Key&word"]),
            strings_package_of(b"x-UEFI-digits", &["", "", "Keyword:12345"]),
            strings_package_of(b"x-UEFI=ns", &["", "", "Keyword"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid(guid_bytes(KEYED_LIST), &packages.concat());
        let variables = Rc::new(MemoryVariables::default());
        variables.insert(setup(), 7, &[0, 0]);

        let listed = HiiBackend::list_questions_in(
            &hiidb,
            &ListQuestionsOptions::default(),
            shared(&variables),
            None,
            None,
        )
        .expect("list the questions");

        let keywords: Vec<Option<serde_json::Value>> = listed
            .iter()
            .map(|question| json_field(question, "keywords"))
            .collect();
        assert_eq!(
            keywords,
            [Some(serde_json::json!([
                {"namespace_id": "x-UEFI-ns", "keyword": "Keyword:5"},
            ]))],
            "keywords of Keyed"
        );
    }

    /// What get and set of a question select, by name and QuestionId.
    #[derive(Debug, PartialEq)]
    struct Selected {
        got: Vec<(String, Option<i32>)>,
        /// set's error if it fails
        set: std::result::Result<Vec<(String, Option<i32>)>, String>,
        writes: Vec<(u16, Vec<u8>)>,
    }

    /// What get of `question`, and set of `question` to 1, select in keyed_hiidb of a nameless
    /// question 0x8001.
    fn selected_in_keyed_hiidb(question: &QuestionSelector) -> Selected {
        let identified = |question: &Question| (question.name.clone(), question.question_id);
        let variables = Rc::new(MemoryVariables::default());
        variables.insert(setup(), 7, &[0, 0]);

        let got = HiiBackend::get_in(
            &keyed_hiidb(""),
            question.clone(),
            None,
            &GetOptions::default(),
            shared(&variables),
            None,
            None,
            None,
        )
        .unwrap_or_else(|error| panic!("get {question}: {error}"));
        let set = set_responses(
            &keyed_hiidb(""),
            question.clone(),
            &SetValue::Text("1".to_owned()),
            None,
            &SetOptions::default(),
            SetAccess {
                reads: shared(&variables),
                writes: &*variables,
                held: None,
            },
            None,
        );

        Selected {
            got: got
                .responses
                .iter()
                .map(|response| identified(&response.question))
                .collect(),
            set: set
                .map(|set| {
                    set.responses
                        .iter()
                        .map(|response| identified(&response.question))
                        .collect()
                })
                .map_err(|error| error.to_string()),
            writes: variables.writes_to(&setup()),
        }
    }

    fn by_address(text: &str) -> QuestionSelector {
        QuestionSelector::Address(text.parse().expect("parse the address"))
    }

    fn by_keyword(keyword: &str, namespace: Option<&str>) -> QuestionSelector {
        QuestionSelector::Keyword {
            keyword: keyword.parse().expect("parse the keyword"),
            namespace: namespace.map(|text| text.parse().expect("parse the namespace")),
        }
    }

    /// get and set select a question, a nameless one too, by its FormSet's GUID and its
    /// QuestionId, in decimal or 0x hex, and by its prompt in a strings package whose language
    /// starts with the namespace.
    #[test]
    fn questions_select_by_question_id_or_keyword() {
        let nameless = vec![(String::new(), Some(0x8001))];
        for question in [
            by_address(&format!("{KEYED_FORM_SET}:0x8001")),
            by_address(&format!("{KEYED_FORM_SET}:32769")),
            by_keyword("Keyword:5", None),
            by_keyword("Other", Some("x-i-UEFI")),
        ] {
            assert_eq!(
                selected_in_keyed_hiidb(&question),
                Selected {
                    got: nameless.clone(),
                    set: Ok(nameless.clone()),
                    writes: vec![(0, vec![1])],
                },
                "{question:?}"
            );
        }
    }

    /// get and set select no question by its keyword in another case or without its instance
    /// suffix, by its keyword under a namespace that does not hold it, by a prompt of a display
    /// language, nor by its QuestionId in another FormSet; set writes nothing.
    #[test]
    fn questions_select_by_question_id_or_keyword_only_exactly() {
        for question in [
            by_keyword("keyword:5", None),
            by_keyword("Keyword", None),
            by_keyword("Keyword:5", Some("x-i-UEFI")),
            by_keyword("Plain", None),
            by_address("8C78A505-BAA0-4C4A-869F-000000000802:0x8001"),
            by_address(&format!("{KEYED_FORM_SET}:0x8002")),
        ] {
            let not_found = format!("no question {:?} in the HiiDB", question.to_string());
            assert_eq!(
                selected_in_keyed_hiidb(&question),
                Selected {
                    got: vec![],
                    set: Err(not_found),
                    writes: vec![],
                },
                "{question:?}"
            );
        }
    }

    /// A keyword that prompts a CHECKBOX outside any FormSet, alone or with the CHECKBOX 0x8001 of
    /// a FormSet, which the Keyword Handler may take instead (edk2-stable202608
    /// ConfigKeywordHandler.c FindQuestionFromStringId), selects neither none nor 0x8001: get and
    /// set refuse it, and set writes nothing.
    #[test]
    fn keywords_that_prompt_a_statement_outside_a_form_set_are_refused() {
        for (case, prompt, refusal) in [
            (
                "alone",
                5,
                KeywordRefusal::OutsideFormSet {
                    keyword: "Keyword:5".to_owned(),
                    op: "EFI_IFR_CHECKBOX",
                    offset: 0,
                },
            ),
            (
                "with 0x8001",
                3,
                KeywordRefusal::AmbiguousStatements {
                    keyword: "Keyword:5".to_owned(),
                    count: 2,
                },
            ),
        ] {
            let packages = [
                form_package_of(
                    &[
                        checkbox_at(9, 3, 1, 1),
                        form_set(&[
                            var_store_efi(1, "Setup", NV_BS_RT, 2),
                            form(1, &[checkbox_at(0x8001, prompt, 1, 0)]),
                        ]),
                    ]
                    .concat(),
                ),
                strings_package_of(b"x-UEFI-ns", &["", "", "Keyword:5"]),
                strings_package_of(b"en-US", &["Title", "Help", "Keyed", "Help text", "Plain"]),
                END_PACKAGE.to_vec(),
            ];
            let hiidb = package_list_with_guid(guid_bytes(KEYED_LIST), &packages.concat());
            let question = by_keyword("Keyword:5", None);
            let variables = Rc::new(MemoryVariables::default());
            variables.insert(setup(), 7, &[0, 0]);

            let got = HiiBackend::get_in(
                &hiidb,
                question.clone(),
                None,
                &GetOptions::default(),
                shared(&variables),
                None,
                None,
                None,
            )
            .map(|got| got.responses.len())
            .map_err(|error| format!("{error:#}"));
            let set = set_responses(
                &hiidb,
                question.clone(),
                &SetValue::Text("1".to_owned()),
                None,
                &SetOptions::default(),
                SetAccess {
                    reads: shared(&variables),
                    writes: &*variables,
                    held: None,
                },
                None,
            )
            .map(|set| set.responses.len())
            .map_err(|error| format!("{error:#}"));

            for (action, result) in [("get", &got), ("set", &set)] {
                assert!(
                    result
                        .as_ref()
                        .is_err_and(|error| error.contains(&refusal.to_string())),
                    "{case}: {action}: {result:?}"
                );
            }
            assert_eq!(variables.writes_to(&setup()), [], "{case}: set writes");
        }
    }

    /// A keyword that prompts a DATE, TIME, ORDERED_LIST or REF of a FormSet and a CHECKBOX outside
    /// any FormSet selects neither, as for a CHECKBOX of the FormSet
    /// (keywords_that_prompt_a_statement_outside_a_form_set_are_refused): get and set refuse it,
    /// and set writes nothing.
    #[test]
    fn keywords_that_prompt_a_statement_outside_a_form_set_refuse_each_kind() {
        let header = question_header_with(0x8001, 3, 1, 0, 0x00);
        let cases = [
            (
                "DATE",
                operation(DATE, false, &[header.clone(), vec![0x00]].concat()),
                SetValue::Text("2027-01-02".to_owned()),
            ),
            (
                "TIME",
                operation(TIME, false, &[header.clone(), vec![0x00]].concat()),
                SetValue::Text("01:02:03".to_owned()),
            ),
            (
                "ORDERED_LIST",
                [
                    operation(
                        ORDERED_LIST,
                        true,
                        &[header.clone(), vec![2, 0x00]].concat(),
                    ),
                    // A and B, strings 5 and 6
                    flagged_option(5, 0x00, 1),
                    flagged_option(6, 0x00, 2),
                    END.to_vec(),
                ]
                .concat(),
                SetValue::Items(vec!["B".to_owned(), "A".to_owned()]),
            ),
            (
                "REF",
                operation(REF, false, &header),
                SetValue::Text("x".to_owned()),
            ),
        ];
        let refusal = KeywordRefusal::AmbiguousStatements {
            keyword: "Keyword:5".to_owned(),
            count: 2,
        };
        for (kind, question, value) in cases {
            let packages = [
                form_package_of(
                    &[
                        checkbox_at(9, 3, 1, 1),
                        form_set(&[
                            var_store_efi(1, "Setup", NV_BS_RT, 22),
                            form(1, &[question]),
                        ]),
                    ]
                    .concat(),
                ),
                strings_package_of(b"x-UEFI-ns", &["", "", "Keyword:5"]),
                strings_package_of(b"en-US", &["Title", "Help", "Keyed", "Help text", "A", "B"]),
                END_PACKAGE.to_vec(),
            ];
            let hiidb = package_list_with_guid(guid_bytes(KEYED_LIST), &packages.concat());
            let question = by_keyword("Keyword:5", None);
            let variables = Rc::new(MemoryVariables::default());
            variables.insert(setup(), 7, &[0; 22]);

            let got = HiiBackend::get_in(
                &hiidb,
                question.clone(),
                None,
                &GetOptions::default(),
                shared(&variables),
                None,
                None,
                None,
            )
            .map(|got| got.responses.len())
            .map_err(|error| format!("{error:#}"));
            let set = set_responses(
                &hiidb,
                question.clone(),
                &value,
                None,
                &SetOptions::default(),
                SetAccess {
                    reads: shared(&variables),
                    writes: &*variables,
                    held: None,
                },
                None,
            )
            .map(|set| set.responses.len())
            .map_err(|error| format!("{error:#}"));

            for (action, result) in [("get", &got), ("set", &set)] {
                assert!(
                    result
                        .as_ref()
                        .is_err_and(|error| error.contains(&refusal.to_string())),
                    "{kind}: {action}: {result:?}"
                );
            }
            assert_eq!(variables.writes_to(&setup()), [], "{kind}: set writes");
        }
    }

    /// A HiiDB as keyed_hiidb's whose FormSet holds only `question`, an op of QuestionId 0x8001
    /// and prompt string 3, "Keyed" in en-US and Keyword:5 in x-UEFI-ns, on Setup, a VarStore of
    /// `size` bytes, and en-US strings `strings` from string 6.
    fn keyed_question_hiidb(question: Vec<u8>, size: u16, strings: &[&str]) -> Vec<u8> {
        let en_us = [&["Title", "Help", "Keyed", "Help text", "Plain"], strings].concat();
        let packages = [
            form_package_with_guid(
                guid_bytes(KEYED_FORM_SET),
                &[
                    var_store_efi(1, "Setup", NV_BS_RT, size),
                    form(1, &[question]),
                ],
            ),
            strings_package_of(b"x-UEFI-ns", &["", "", "Keyword:5"]),
            strings_package_of(b"en-US", &en_us),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid(guid_bytes(KEYED_LIST), &packages.concat())
    }

    /// A HiiDB whose FormSet holds only `question`, an op prompted by string 3 with help string 4,
    /// on Setup, a VarStore of `size` bytes, and strings packages of x-UEFI-ns, en-US and fr-FR,
    /// in that order: `en_us` and `fr_fr` translate the strings from 3, and x-UEFI-ns gives each
    /// of them a keyword that no text shows.
    fn translated_question_hiidb(
        question: Vec<u8>,
        size: u16,
        en_us: &[&str],
        fr_fr: &[&str],
    ) -> Vec<u8> {
        let keywords: Vec<String> = (3..3 + en_us.len()).map(|id| format!("x{id}:1")).collect();
        let keywords: Vec<&str> = keywords.iter().map(String::as_str).collect();
        let packages = [
            form_package_with_guid(
                guid_bytes(KEYED_FORM_SET),
                &[
                    var_store_efi(1, "Setup", NV_BS_RT, size),
                    form(1, &[question]),
                ],
            ),
            strings_package_of(b"x-UEFI-ns", &[&["", ""][..], &keywords].concat()),
            strings_package_of(b"en-US", &[&["Title", "Help"][..], en_us].concat()),
            strings_package_of(b"fr-FR", &[&["Titre", "Aide"][..], fr_fr].concat()),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid(guid_bytes(KEYED_LIST), &packages.concat())
    }

    /// What list-questions and show-ifr show of `hiidb`, whose Setup holds `stored`, on a
    /// platform of PlatformLang `platform_lang`, if any.
    fn listed_and_shown(
        hiidb: &[u8],
        stored: &[u8],
        platform_lang: Option<&str>,
    ) -> (Vec<Question>, String) {
        let variables = Rc::new(MemoryVariables::default());
        variables.insert(setup(), 7, stored);
        let listed = HiiBackend::list_questions_in(
            hiidb,
            &ListQuestionsOptions::default(),
            shared(&variables),
            None,
            platform_lang,
        )
        .expect("list the questions");
        let shown = HiiBackend::show_ifr_in(
            hiidb,
            &ShowIfrOptions::default(),
            shared(&variables),
            None,
            platform_lang,
        )
        .expect("show the IFR")
        .to_string();
        (listed, shown)
    }

    /// list-questions and show-ifr show the prompt and the help of a DATE and a TIME in the
    /// platform language, else in the first display language, never in the configuration
    /// language before them.
    #[test]
    fn dates_and_times_show_their_texts_in_the_platform_language() {
        let cases = [
            (DATE, &[0xE8, 0x07, 2, 29][..], "2024-02-29"),
            (TIME, &[12, 34, 56][..], "12:34:56"),
        ];
        for (op_code, stored, answer) in cases {
            let data = [question_header_with(0x8001, 3, 1, 0, 0x00), vec![0x00]].concat();
            let hiidb = translated_question_hiidb(
                operation(op_code, false, &data),
                u16::try_from(stored.len()).expect("a short VarStore"),
                &["When", "When help"],
                &["Quand", "Aide de quand"],
            );
            for (platform_lang, name, help) in [
                (None, "When", "When help"),
                (Some("fr-FR"), "Quand", "Aide de quand"),
            ] {
                let (listed, shown) = listed_and_shown(&hiidb, stored, platform_lang);

                let listed: Vec<[&str; 3]> = listed
                    .iter()
                    .map(|question| [&*question.name, &*question.help, &*question.answer])
                    .collect();
                assert_eq!(
                    listed,
                    [[name, help, answer]],
                    "{op_code:#04x} {platform_lang:?}: list-questions"
                );
                assert!(
                    shown.contains(&format!("Q: {name} - Help: {help}\n")),
                    "{op_code:#04x} {platform_lang:?}: show-ifr: {shown}"
                );
            }
        }
    }

    /// What get of a question answers and set of it writes.
    #[derive(Debug, PartialEq)]
    struct Answered {
        got: Vec<String>,
        /// set's error if it fails
        set: std::result::Result<(), String>,
        writes: Vec<(u16, Vec<u8>)>,
    }

    /// Asserts that get of the question 0x8001 of `hiidb`, a keyed_question_hiidb whose Setup
    /// holds `stored`, and set of it to `value`, give `want` by its prompt, by its QuestionId and
    /// by its keyword alike.
    #[track_caller]
    fn assert_answered_by_each_selector(
        hiidb: &[u8],
        stored: &[u8],
        value: &SetValue,
        want: &Answered,
    ) {
        for question in [
            QuestionSelector::from("Keyed"),
            by_address(&format!("{KEYED_FORM_SET}:0x8001")),
            by_keyword("Keyword:5", None),
        ] {
            let variables = Rc::new(MemoryVariables::default());
            variables.insert(setup(), 7, stored);
            let got = HiiBackend::get_in(
                hiidb,
                question.clone(),
                None,
                &GetOptions::default(),
                shared(&variables),
                None,
                None,
                None,
            )
            .unwrap_or_else(|error| panic!("get {question}: {error}"));
            // each answer shows the QuestionId, the FormSet's GUID and the keyword of 0x8001
            let identity = [
                Some(serde_json::json!(0x8001)),
                Some(serde_json::json!(KEYED_FORM_SET)),
                Some(serde_json::json!([{"namespace_id": "x-UEFI-ns", "keyword": "Keyword:5"}])),
            ];
            for response in &got.responses {
                assert_eq!(
                    identity_json(&response.question),
                    identity,
                    "{question:?}: identity of {:?}",
                    response.question.answer
                );
            }
            let set = HiiBackend::set_in(
                hiidb,
                question.clone(),
                value,
                None,
                &SetOptions::default(),
                SetAccess {
                    reads: shared(&variables),
                    writes: &*variables,
                    held: None,
                },
                None,
            );
            let answered = Answered {
                got: got
                    .responses
                    .into_iter()
                    .map(|response| response.question.answer)
                    .collect(),
                set: set.map(drop).map_err(|error| format!("{error:#}")),
                writes: variables.writes_to(&setup()),
            };
            assert_eq!(&answered, want, "{question:?}");
        }
    }

    /// get by QuestionId and by keyword answers a DATE and a TIME on a VarStore as by prompt,
    /// and set by each writes the same EFI_HII_DATE or EFI_HII_TIME.
    #[test]
    fn dates_and_times_select_by_question_id_or_keyword_as_by_prompt() {
        let cases = [
            (
                DATE,
                &[0xE8, 0x07, 2, 29][..],
                "2024-02-29",
                "2027-01-02",
                vec![0xEB, 0x07, 1, 2],
            ),
            (
                TIME,
                &[12, 34, 56][..],
                "12:34:56",
                "01:02:03",
                vec![1, 2, 3],
            ),
        ];
        for (op_code, stored, shown, value, written) in cases {
            let data = [question_header_with(0x8001, 3, 1, 0, 0x00), vec![0x00]].concat();
            let hiidb = keyed_question_hiidb(
                operation(op_code, false, &data),
                u16::try_from(stored.len()).expect("a short VarStore"),
                &[],
            );
            assert_answered_by_each_selector(
                &hiidb,
                stored,
                &SetValue::Text(value.to_owned()),
                &Answered {
                    got: vec![shown.to_owned()],
                    set: Ok(()),
                    writes: vec![(0, written)],
                },
            );
        }
    }

    /// get and set by prompt, by QuestionId and by keyword alike find no DATE or TIME of the
    /// reserved UEFI Storage 0x30, which list-questions does not list either.
    #[test]
    fn dates_and_times_of_reserved_storage_select_by_no_selector() {
        for op_code in [DATE, TIME] {
            let data = [question_header_with(0x8001, 3, 1, 0, 0x00), vec![0x30]].concat();
            let hiidb = keyed_question_hiidb(operation(op_code, false, &data), 4, &[]);
            for question in [
                QuestionSelector::from("Keyed"),
                by_address(&format!("{KEYED_FORM_SET}:0x8001")),
                by_keyword("Keyword:5", None),
            ] {
                let variables = Rc::new(MemoryVariables::default());
                variables.insert(setup(), 7, &[0; 4]);
                let got = HiiBackend::get_in(
                    &hiidb,
                    question.clone(),
                    None,
                    &GetOptions::default(),
                    shared(&variables),
                    None,
                    None,
                    None,
                )
                .unwrap_or_else(|error| panic!("get {question}: {error}"));
                let set = HiiBackend::set_in(
                    &hiidb,
                    question.clone(),
                    &SetValue::Text("1".to_owned()),
                    None,
                    &SetOptions::default(),
                    SetAccess {
                        reads: shared(&variables),
                        writes: &*variables,
                        held: None,
                    },
                    None,
                );
                let not_found = format!("no question {:?} in the HiiDB", question.to_string());
                assert_eq!(
                    (
                        got.responses.len(),
                        set.map(drop).map_err(|error| error.to_string()),
                        variables.writes_to(&setup()),
                    ),
                    (0, Err(not_found), vec![]),
                    "{op_code:#04x} {question:?}"
                );
            }
        }
    }

    /// get and set by QuestionId and by keyword of a DATE of the system time with a VarStore, in
    /// a build without Time Services, show and refuse it as by prompt, writing nothing.
    #[test]
    fn dates_of_time_storage_select_by_question_id_or_keyword_as_by_prompt() {
        let data = [question_header_with(0x8001, 3, 1, 0, 0x00), vec![0x10]].concat();
        let hiidb = keyed_question_hiidb(operation(DATE, false, &data), 4, &[]);
        assert_answered_by_each_selector(
            &hiidb,
            &[0xE8, 0x07, 2, 29],
            &SetValue::Text("2027-01-02".to_owned()),
            &Answered {
                got: vec![
                    "<ValueUnavailable: EFI Date/Time Storage (UEFI 2.11 §33.2.5.6) is read \
                           only through GetTime(); run uefisettings.efi in the UEFI Shell>"
                        .to_owned(),
                ],
                set: Err(
                    "cannot set question \"Keyed\": EFI Date/Time Storage (UEFI 2.11 \
                          §33.2.5.6) is written only through SetTime(); run uefisettings.efi in \
                          the UEFI Shell"
                        .to_owned(),
                ),
                writes: vec![],
            },
        );
    }

    /// list-questions and show-ifr show the prompt, the help and the option texts of an
    /// ORDERED_LIST in the platform language, else in the first display language, never in the
    /// configuration language before them; set on a platform of PlatformLang fr-FR takes en-US
    /// items and answers in fr-FR.
    #[test]
    fn ordered_lists_show_their_texts_in_the_platform_language() {
        let list = [
            operation(
                ORDERED_LIST,
                true,
                &[question_header_with(0x8001, 3, 1, 0, 0x00), vec![2, 0x00]].concat(),
            ),
            flagged_option(5, 0x00, 1),
            flagged_option(6, 0x00, 2),
            END.to_vec(),
        ];
        let en_us = ["Order", "Order help", "First", "Second"];
        let fr_fr = ["Ordre", "Aide de l'ordre", "Premier", "Deuxieme"];
        let hiidb = translated_question_hiidb(list.concat(), 2, &en_us, &fr_fr);
        for (platform_lang, [name, help, first, second]) in [(None, en_us), (Some("fr-FR"), fr_fr)]
        {
            let (listed, shown) = listed_and_shown(&hiidb, &[2, 1], platform_lang);

            let listed: Vec<_> = listed
                .into_iter()
                .map(|question| {
                    let texts = [question.name, question.help, question.answer];
                    (texts, question.options, question.items)
                })
                .collect();
            let strings = |texts: &[&str]| texts.iter().map(|&text| text.to_owned()).collect();
            assert_eq!(
                listed,
                [(
                    [name, help, &format!("{second}, {first}")].map(str::to_owned),
                    strings(&[first, second]),
                    Some(strings(&[second, first])),
                )],
                "{platform_lang:?}: list-questions"
            );
            for line in [
                format!("Q: {name} - Help: {help}\n"),
                format!("-Answer: {second}, {first}\n"),
            ] {
                assert!(
                    shown.contains(&line),
                    "{platform_lang:?}: show-ifr shows {line:?}: {shown}"
                );
            }
        }

        let variables = Rc::new(MemoryVariables::default());
        variables.insert(setup(), 7, &[1, 2]);
        let set = set_responses(
            &hiidb,
            "Order",
            &SetValue::Items(vec!["Second".to_owned(), "First".to_owned()]),
            None,
            &SetOptions::default(),
            SetAccess {
                reads: shared(&variables),
                writes: &*variables,
                held: None,
            },
            Some("fr-FR"),
        )
        .expect("set Order");
        let answers: Vec<String> = set
            .responses
            .into_iter()
            .map(|response| response.question.answer)
            .collect();
        assert_eq!(
            (answers, variables.writes_to(&setup())),
            (vec!["Deuxieme, Premier".to_owned()], vec![(0, vec![2, 1])]),
            "set Order --item Second --item First"
        );
    }

    /// get by QuestionId and by keyword answers an ORDERED_LIST on a VarStore as by prompt, and
    /// set of its items by each writes the same values.
    #[test]
    fn ordered_lists_select_by_question_id_or_keyword_as_by_prompt() {
        let list = [
            operation(
                ORDERED_LIST,
                true,
                &[question_header_with(0x8001, 3, 1, 0, 0x00), vec![2, 0x00]].concat(),
            ),
            flagged_option(6, 0x00, 1),
            flagged_option(7, 0x00, 2),
            END.to_vec(),
        ];
        let hiidb = keyed_question_hiidb(list.concat(), 2, &["A", "B"]);
        assert_answered_by_each_selector(
            &hiidb,
            &[1, 2],
            &SetValue::Items(vec!["B".to_owned(), "A".to_owned()]),
            &Answered {
                got: vec!["A, B".to_owned()],
                set: Ok(()),
                writes: vec![(0, vec![2, 1])],
            },
        );
    }

    /// list-questions and show-ifr show the prompt and the help of a REF on a VarStore, and the
    /// text of its DevicePath, in the platform language, else in the first display language,
    /// never in the configuration language before them.
    #[test]
    fn cross_references_show_their_texts_in_the_platform_language() {
        let data = question_header_with(0x8001, 3, 1, 0, 0x00);
        let en_us = ["Link", "Link help", "Path"];
        let fr_fr = ["Lien", "Aide du lien", "Chemin"];
        let hiidb = translated_question_hiidb(operation(REF, false, &data), 22, &en_us, &fr_fr);
        let stored = [&[5, 0, 1, 0][..], &[0x11; 16], &[5, 0]].concat();
        for (platform_lang, [name, help, path]) in [(None, en_us), (Some("fr-FR"), fr_fr)] {
            let (listed, shown) = listed_and_shown(&hiidb, &stored, platform_lang);

            let answer = format!(
                "QuestionId 0x0005, FormId 0x0001, FormSetGuid \
                 11111111-1111-1111-1111-111111111111, DevicePath {path:?}"
            );
            let listed: Vec<[String; 3]> = listed
                .into_iter()
                .map(|question| [question.name, question.help, question.answer])
                .collect();
            assert_eq!(
                listed,
                [[name, help, &answer].map(str::to_owned)],
                "{platform_lang:?}: list-questions"
            );
            for line in [
                format!("Q: {name} - Help: {help}\n"),
                format!("-Answer: {answer}\n"),
            ] {
                assert!(
                    shown.contains(&line),
                    "{platform_lang:?}: show-ifr shows {line:?}: {shown}"
                );
            }
        }
    }

    /// get by QuestionId and by keyword answers a REF on a VarStore as by prompt, its DevicePath
    /// a string of the display language, and set by each refuses it alike, writing nothing.
    #[test]
    fn cross_references_select_by_question_id_or_keyword_as_by_prompt() {
        let data = question_header_with(0x8001, 3, 1, 0, 0x00);
        let hiidb = keyed_question_hiidb(operation(REF, false, &data), 22, &["Path"]);
        let stored = [&[5, 0, 1, 0][..], &[0x11; 16], &[6, 0]].concat();
        assert_answered_by_each_selector(
            &hiidb,
            &stored,
            &SetValue::Text("x".to_owned()),
            &Answered {
                got: vec!["QuestionId 0x0005, FormId 0x0001, FormSetGuid \
                     11111111-1111-1111-1111-111111111111, DevicePath \"Path\""
                    .to_owned()],
                set: Err(
                    "cannot set question \"Keyed\": set does not write the EFI_HII_REF of \
                          a cross-reference question, the target of its link (UEFI 2.11 \
                          §33.2.5.4.10)"
                        .to_owned(),
                ),
                writes: vec![],
            },
        );
    }

    /// The GUID of driver_held_keyed_hiidb's FormSet.
    const HELD_FORM_SET: &str = "8C78A505-BAA0-4C4A-869F-000000001A13";

    /// A HiiDB whose FormSet of Guid HELD_FORM_SET holds the CHECKBOX of QuestionId 7 without a
    /// VarStore, flagged EFI_IFR_FLAG_CALLBACK, prompted "Held" in en-US, "Tenu" in fr-FR and
    /// "Keyword:5" in x-UEFI-ns.
    fn driver_held_keyed_hiidb() -> Vec<u8> {
        let storageless = [
            &1u16.to_le_bytes()[..],  // Prompt
            &2u16.to_le_bytes(),      // Help
            &7u16.to_le_bytes(),      // QuestionId
            &0u16.to_le_bytes(),      // VarStoreId
            &0xFFFFu16.to_le_bytes(), // VarStoreInfo
            &[0x04, 0x00],            // EFI_IFR_FLAG_CALLBACK, CHECKBOX Flags
        ]
        .concat();
        let packages = [
            form_package_with_guid(
                guid_bytes(HELD_FORM_SET),
                &[form(1, &[operation(CHECKBOX, false, &storageless)])],
            ),
            strings_package_of(b"en-US", &["Held", "Help"]),
            strings_package_of(b"fr-FR", &["Tenu", "Aide"]),
            strings_package_of(b"x-UEFI-ns", &["Keyword:5", ""]),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid([0x66; 16], &packages.concat())
    }

    /// list-questions, get and set show a question whose driver holds its value as any other:
    /// with its QuestionId, its FormSet's GUID and its keywords, and its prompt and help in the
    /// language that ParsedPackageList::texts picks for --language. get and set select it by its
    /// QuestionId, its keyword or its prompt in any language, and take it to its driver.
    #[test]
    fn driver_held_questions_show_their_identity_and_texts_and_select_by_question_id() {
        let identity = [
            Some(serde_json::json!(7)),
            Some(serde_json::json!(HELD_FORM_SET)),
            Some(serde_json::json!([
                {"namespace_id": "x-UEFI-ns", "keyword": "Keyword:5"},
            ])),
        ];
        let hiidb = driver_held_keyed_hiidb();
        let english = ("Held", "Help");
        let french = ("Tenu", "Aide");
        for (question, language, (prompt, help)) in [
            (QuestionSelector::from("Held"), None, english),
            (by_address(&format!("{HELD_FORM_SET}:7")), None, english),
            (by_keyword("Keyword:5", None), None, english),
            (QuestionSelector::from("Held"), Some("fr-FR"), french),
            (
                by_address(&format!("{HELD_FORM_SET}:0x7")),
                Some("fr-FR"),
                french,
            ),
            (QuestionSelector::from("Tenu"), Some("fr-FR"), french),
            (QuestionSelector::from("Tenu"), None, english),
        ] {
            let case = format!("{question:?} under --language {language:?}");
            let shown = |question: &Question, answer: &str| {
                assert_eq!(
                    (question.name.as_str(), question.help.as_str()),
                    (prompt, help),
                    "{case}: texts"
                );
                assert_eq!(question.answer, answer, "{case}: answer");
                assert_eq!(identity_json(question), identity, "{case}: identity");
            };
            let language = language.map(str::to_owned);
            let driver = RecordingDriver::default();
            let variables = Rc::new(MemoryVariables::default());

            let listed = HiiBackend::list_questions_in(
                &hiidb,
                &ListQuestionsOptions {
                    language: language.clone(),
                    ..ListQuestionsOptions::default()
                },
                shared(&variables),
                None,
                None,
            )
            .unwrap_or_else(|error| panic!("{case}: list the questions: {error:#}"));
            let got = HiiBackend::get_in(
                &hiidb,
                question.clone(),
                None,
                &GetOptions {
                    language: language.clone(),
                    ..GetOptions::default()
                },
                shared(&variables),
                None,
                None,
                Some(&driver),
            )
            .unwrap_or_else(|error| panic!("{case}: get: {error:#}"));
            let set = set_responses(
                &hiidb,
                question.clone(),
                &SetValue::Text("1".to_owned()),
                None,
                &SetOptions {
                    language,
                    ..SetOptions::default()
                },
                SetAccess {
                    reads: shared(&variables),
                    writes: &*variables,
                    held: Some(&driver),
                },
                None,
            )
            .unwrap_or_else(|error| panic!("{case}: set 1: {error:#}"));

            assert_eq!(listed.len(), 1, "{case}: listed questions");
            let unreached = listed[0].answer.clone();
            assert!(
                unreached.starts_with("<ValueUnavailable: question has no VarStore"),
                "{case}: list-questions reaches no driver: {unreached}"
            );
            shown(&listed[0], &unreached);
            assert_eq!(got.responses.len(), 1, "{case}: get answers");
            shown(&got.responses[0].question, "from the driver");
            assert_eq!(set.responses.len(), 1, "{case}: set answers");
            shown(
                &set.responses[0].question,
                "1 <set by the driver of QuestionId 7>",
            );
            assert_eq!(*driver.gets.borrow(), [7], "{case}: the driver's gets");
            assert_eq!(*driver.sets.borrow(), [(7, 1)], "{case}: the driver's sets");
            assert_eq!(variables.writes_to(&setup()), [], "{case}: writes");
        }
    }

    /// A HiiDB whose FormSet holds the CHECKBOXes 0xA at byte 0 and 0x14 at byte 1 of Setup,
    /// prompted "First" and "Second" in en-US, of which x-UEFI-ns names 0xA "Foo" and x-UEFI-AMI
    /// names 0x14 "Foo".
    fn crossed_keywords_hiidb() -> Vec<u8> {
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, 2),
                form(1, &[checkbox_at(0xA, 1, 1, 0), checkbox_at(0x14, 2, 1, 1)]),
            ]),
            strings_package_of(b"en-US", &["First", "Second"]),
            strings_package_of(b"x-UEFI-ns", &["Foo", ""]),
            strings_package_of(b"x-UEFI-AMI", &["", "Foo"]),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid([0x6A; 16], &packages.concat())
    }

    /// A HiiDB of two package lists, whose FormSets of GUIDs KEYED_FORM_SET and
    /// 8C78A505-BAA0-4C4A-869F-000000000803 hold the CHECKBOX 0xA, at byte 0 and byte 1 of
    /// Setup, prompted "First" and "Second" in en-US, and named "Foo" in the configuration
    /// languages `first` and `second`.
    fn keyword_in_two_lists_hiidb(first: &[u8], second: &[u8]) -> Vec<u8> {
        keyword_in_two_lists_hiidb_of(first, second, 2, |offset| checkbox_at(0xA, 1, 1, offset))
    }

    /// keyword_in_two_lists_hiidb with `question(offset)`, an op of QuestionId 0xA and prompt
    /// string 1 at byte `offset` of Setup, in place of each CHECKBOX, Setup a VarStore of `size`
    /// bytes, and the en-US string 2 "On".
    fn keyword_in_two_lists_hiidb_of(
        first: &[u8],
        second: &[u8],
        size: u16,
        question: impl Fn(u16) -> Vec<u8>,
    ) -> Vec<u8> {
        let list = |form_set: &str, offset: u16, prompt: &str, namespace: &[u8], guid: u8| {
            let packages = [
                form_package_with_guid(
                    guid_bytes(form_set),
                    &[
                        var_store_efi(1, "Setup", NV_BS_RT, size),
                        form(1, &[question(offset)]),
                    ],
                ),
                strings_package_of(b"en-US", &[prompt, "On"]),
                strings_package_of(namespace, &["Foo"]),
                END_PACKAGE.to_vec(),
            ];
            package_list_with_guid([guid; 16], &packages.concat())
        };
        [
            list(KEYED_FORM_SET, 0, "First", first, 0x6B),
            list(
                "8C78A505-BAA0-4C4A-869F-000000000803",
                1,
                "Second",
                second,
                0x6C,
            ),
        ]
        .concat()
    }

    /// What get of `question`, and set of `question` to 1, select in `hiidb`, by name and
    /// QuestionId, and set's writes to Setup.
    fn selected_in(hiidb: &[u8], question: &QuestionSelector) -> Selected {
        selected_by_set_of(hiidb, question, &[0, 0], &SetValue::Text("1".to_owned()))
    }

    /// selected_in with Setup holding `stored`, and set of `question` to `value`.
    fn selected_by_set_of(
        hiidb: &[u8],
        question: &QuestionSelector,
        stored: &[u8],
        value: &SetValue,
    ) -> Selected {
        let identified = |question: &Question| (question.name.clone(), question.question_id);
        let variables = Rc::new(MemoryVariables::default());
        variables.insert(setup(), 7, stored);

        let got = HiiBackend::get_in(
            hiidb,
            question.clone(),
            None,
            &GetOptions::default(),
            shared(&variables),
            None,
            None,
            None,
        );
        let set = set_responses(
            hiidb,
            question.clone(),
            value,
            None,
            &SetOptions::default(),
            SetAccess {
                reads: shared(&variables),
                writes: &*variables,
                held: None,
            },
            None,
        );

        Selected {
            got: match got {
                Ok(got) => got
                    .responses
                    .iter()
                    .map(|response| identified(&response.question))
                    .collect(),
                Err(error) => vec![(error.to_string(), None)],
            },
            set: set
                .map(|set| {
                    set.responses
                        .iter()
                        .map(|response| identified(&response.question))
                        .collect()
                })
                .map_err(|error| error.to_string()),
            writes: variables.writes_to(&setup()),
        }
    }

    /// The Selected of get and set failing with `error`, without a write.
    fn refused(error: &str) -> Selected {
        Selected {
            got: vec![(error.to_owned(), None)],
            set: Err(error.to_owned()),
            writes: vec![],
        }
    }

    /// get and set refuse a --keyword that strings packages of two namespaces hold in one package
    /// list, as the Keyword Handler does, and one that names questions of two namespaces in two
    /// package lists, naming each; set writes nothing. Under a namespace that holds one of them,
    /// or with every match in one namespace, it selects as before, in one write of their variable.
    #[test]
    fn get_and_set_refuse_a_keyword_of_questions_in_different_namespaces() {
        let other = "8C78A505-BAA0-4C4A-869F-000000000803";
        let ambiguous = |matches: String| {
            refused(&format!(
                "\"keyword Foo of a namespace starting with x-UEFI\" is the prompt {matches}: no \
                 one language holds it as the prompt of every question it names"
            ))
        };
        let selected = |question: (&str, i32), writes: Vec<(u16, Vec<u8>)>| {
            let question = vec![(question.0.to_owned(), Some(question.1))];
            Selected {
                got: question.clone(),
                set: Ok(question),
                writes,
            }
        };
        let both = vec![
            ("First".to_owned(), Some(0xA)),
            ("Second".to_owned(), Some(0xA)),
        ];
        let cases = [
            (
                "one package list",
                crossed_keywords_hiidb(),
                None,
                refused(
                    "keyword Foo: strings packages of the languages [\"x-UEFI-ns\", \
                     \"x-UEFI-AMI\"] of one package list hold it, which firmware may search in \
                     another order",
                ),
            ),
            (
                "one package list, x-UEFI-AMI",
                crossed_keywords_hiidb(),
                Some("x-UEFI-AMI"),
                selected(("Second", 0x14), vec![(1, vec![1])]),
            ),
            (
                "two lists",
                keyword_in_two_lists_hiidb(b"x-UEFI-ns", b"x-UEFI-AMI"),
                None,
                ambiguous(format!(
                    "of QuestionId 0x000A of FormSet {KEYED_FORM_SET} in x-UEFI-ns and of \
                     QuestionId 0x000A of FormSet {other} in x-UEFI-AMI"
                )),
            ),
            (
                "two lists, x-UEFI-ns",
                keyword_in_two_lists_hiidb(b"x-UEFI-ns", b"x-UEFI-AMI"),
                Some("x-UEFI-ns"),
                selected(("First", 0xA), vec![(0, vec![1])]),
            ),
            (
                "two lists, one namespace",
                keyword_in_two_lists_hiidb(b"x-UEFI-ns", b"x-UEFI-ns"),
                None,
                Selected {
                    got: both.clone(),
                    set: Ok(both),
                    writes: vec![(0, vec![1, 1])],
                },
            ),
        ];
        for (case, hiidb, namespace, want) in cases {
            assert_eq!(
                selected_in(&hiidb, &by_keyword("Foo", namespace)),
                want,
                "{case}"
            );
        }
    }

    /// get and set weigh every listed question of a --keyword in its namespaces, an ORDERED_LIST
    /// or a REF on a VarStore as a CHECKBOX
    /// (get_and_set_refuse_a_keyword_of_questions_in_different_namespaces): they refuse a keyword
    /// that names one in each of two package lists, of x-UEFI-ns and x-UEFI-AMI, naming each, and
    /// set --item writes nothing; under x-UEFI-ns they select the first list's alone, and set
    /// --item writes the ORDERED_LIST and refuses the REF, as for any REF.
    #[test]
    fn get_and_set_weigh_every_listed_question_in_the_namespaces_of_a_keyword() {
        let other = "8C78A505-BAA0-4C4A-869F-000000000803";
        let ambiguous = || {
            refused(&format!(
                "\"keyword Foo of a namespace starting with x-UEFI\" is the prompt of QuestionId \
                 0x000A of FormSet {KEYED_FORM_SET} in x-UEFI-ns and of QuestionId 0x000A of \
                 FormSet {other} in x-UEFI-AMI: no one language holds it as the prompt of every \
                 question it names"
            ))
        };
        let first = vec![("First".to_owned(), Some(0xA))];
        // an ORDERED_LIST of one UINT8 container, whose option On holds 1
        let ordered_list = |offset| {
            let data = [question_header_with(0xA, 1, 1, offset, 0x00), vec![1, 0x00]].concat();
            [
                operation(ORDERED_LIST, true, &data),
                flagged_option(2, 0x00, 1),
                END.to_vec(),
            ]
            .concat()
        };
        // an EFI_IFR_REF5 on Setup
        let reference =
            |offset| operation(REF, false, &question_header_with(0xA, 1, 1, offset, 0x00));
        let cases = [
            (
                "ORDERED_LIST",
                keyword_in_two_lists_hiidb_of(b"x-UEFI-ns", b"x-UEFI-AMI", 2, ordered_list),
                &[0, 0][..],
                Selected {
                    got: first.clone(),
                    set: Ok(first.clone()),
                    writes: vec![(0, vec![1])],
                },
            ),
            (
                "REF",
                // its 22 bytes at byte 1 of the second list's Setup
                keyword_in_two_lists_hiidb_of(b"x-UEFI-ns", b"x-UEFI-AMI", 23, reference),
                &[0; 23][..],
                Selected {
                    got: first,
                    set: Err(
                        "cannot set question \"First\": set does not write the EFI_HII_REF \
                              of a cross-reference question, the target of its link (UEFI 2.11 \
                              §33.2.5.4.10)"
                            .to_owned(),
                    ),
                    writes: vec![],
                },
            ),
        ];
        let items = SetValue::Items(vec!["On".to_owned()]);
        for (kind, hiidb, stored, under_ns) in cases {
            assert_eq!(
                selected_by_set_of(&hiidb, &by_keyword("Foo", None), stored, &items),
                ambiguous(),
                "{kind}"
            );
            assert_eq!(
                selected_by_set_of(
                    &hiidb,
                    &by_keyword("Foo", Some("x-UEFI-ns")),
                    stored,
                    &items
                ),
                under_ns,
                "{kind}, x-UEFI-ns"
            );
        }
    }

    /// get and set refuse a --keyword that prompts two statements of its package list, as the
    /// Keyword Handler does (KeywordRefusal::AmbiguousStatements); set writes nothing.
    #[test]
    fn get_and_set_refuse_a_keyword_of_two_statements() {
        let packages = [
            form_package_with_guid(
                guid_bytes(KEYED_FORM_SET),
                &[
                    var_store_efi(1, "Setup", NV_BS_RT, 2),
                    form(
                        1,
                        &[checkbox_at(0x8001, 3, 1, 0), checkbox_at(0x8002, 3, 1, 1)],
                    ),
                ],
            ),
            strings_package_of(b"x-UEFI-ns", &["", "", "Keyword:5"]),
            strings_package_of(b"en-US", &["Title", "Help", "Keyed"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid(guid_bytes(KEYED_LIST), &packages.concat());

        assert_eq!(
            selected_in(&hiidb, &by_keyword("Keyword:5", None)),
            refused(
                "keyword Keyword:5: it prompts 2 statements of its package list, of which \
                 firmware may take another than the first"
            ),
            "Keyword:5 of two statements"
        );
    }

    /// No selector, QUESTION, --question-id or --keyword, reaches a CHECKBOX in the scope of an
    /// unknown opcode, which the walk skips, and set writes nothing; each selects the same
    /// CHECKBOX outside that scope.
    #[test]
    fn selectors_skip_a_question_in_ignored_ifr() {
        let checkbox = checkbox_at(0x8001, 3, 1, 0);
        let ignored = [unknown_scope(), checkbox.clone(), END.to_vec()].concat();
        for (case, statements, reached) in [
            ("in ignored IFR", ignored, false),
            ("outside", checkbox, true),
        ] {
            let packages = [
                form_package_with_guid(
                    guid_bytes(KEYED_FORM_SET),
                    &[
                        var_store_efi(1, "Setup", NV_BS_RT, 2),
                        form(1, &[statements]),
                    ],
                ),
                strings_package_of(b"x-UEFI-ns", &["", "", "Keyword:5"]),
                strings_package_of(b"en-US", &["Title", "Help", "Keyed"]),
                END_PACKAGE.to_vec(),
            ];
            let hiidb = package_list_with_guid(guid_bytes(KEYED_LIST), &packages.concat());
            let selectors = [
                ("prompt", QuestionSelector::Prompt("Keyed".to_owned())),
                ("address", by_address(&format!("{KEYED_FORM_SET}:0x8001"))),
                ("keyword", by_keyword("Keyword:5", None)),
            ];
            for (name, selector) in selectors {
                let selected = selected_in(&hiidb, &selector);

                let got_it = selected.got.iter().any(|(_, id)| *id == Some(0x8001));
                assert_eq!(got_it, reached, "{case}, {name}: get {selected:?}");
                let set_it = selected
                    .set
                    .as_ref()
                    .is_ok_and(|set| set.iter().any(|(_, id)| *id == Some(0x8001)));
                assert_eq!(set_it, reached, "{case}, {name}: set {selected:?}");
                assert_eq!(
                    !selected.writes.is_empty(),
                    reached,
                    "{case}, {name}: writes {selected:?}"
                );
            }
        }
    }

    /// A HiiDB whose FormSet of GUID KEYED_FORM_SET holds the CHECKBOXes "First" and "Second" of
    /// QuestionId 7, at bytes 0 and 1 of Setup, and "Third" of QuestionId 8, at byte 1 too.
    fn shared_question_id_hiidb() -> Vec<u8> {
        let packages = [
            form_package_with_guid(
                guid_bytes(KEYED_FORM_SET),
                &[
                    var_store_efi(1, "Setup", NV_BS_RT, 2),
                    form(
                        1,
                        &[
                            checkbox_at(7, 1, 1, 0),
                            checkbox_at(7, 2, 1, 1),
                            checkbox_at(8, 3, 1, 1),
                        ],
                    ),
                ],
            ),
            strings_package_of(b"en-US", &["First", "Second", "Third"]),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid(guid_bytes(KEYED_LIST), &packages.concat())
    }

    /// get and set refuse a --question-id that two questions of one FormSet hold, naming them,
    /// and set writes nothing; the QuestionId of one question selects it.
    #[test]
    fn get_and_set_refuse_a_question_id_of_two_questions() {
        let shared = selected_in(
            &shared_question_id_hiidb(),
            &by_address(&format!("{KEYED_FORM_SET}:7")),
        );
        let unique = selected_in(
            &shared_question_id_hiidb(),
            &by_address(&format!("{KEYED_FORM_SET}:8")),
        );

        assert_eq!(
            shared,
            refused(&format!(
                "QuestionId 0x0007 of FormSet {KEYED_FORM_SET} is that of the questions \"First\" \
                 and \"Second\": a QuestionId identifies one question of its FormSet"
            )),
            "QuestionId 7"
        );
        let third = vec![("Third".to_owned(), Some(8))];
        assert_eq!(
            unique,
            Selected {
                got: third.clone(),
                set: Ok(third),
                writes: vec![(1, vec![1])],
            },
            "QuestionId 8"
        );
    }

    /// get and set refuse a --question-id that an ORDERED_LIST or a REF on a VarStore shares with
    /// a NUMERIC of its FormSet, naming both, as for two CHECKBOXes
    /// (get_and_set_refuse_a_question_id_of_two_questions); set writes nothing.
    #[test]
    fn get_and_set_refuse_a_question_id_that_a_listed_question_shares() {
        // a UINT8 NUMERIC "First" of QuestionId 7 at byte 0 of Setup
        let numeric = [
            question_header_with(7, 1, 1, 0, 0x00),
            vec![0x10, 0, 255, 1],
        ]
        .concat();
        // an ORDERED_LIST "Second" of QuestionId 7 at byte 1, of one UINT8 container
        let list = [question_header_with(7, 2, 1, 1, 0x00), vec![1, 0x00]].concat();
        let cases = [
            (
                "ORDERED_LIST",
                2,
                [
                    operation(ORDERED_LIST, true, &list),
                    flagged_option(3, 0x00, 1),
                    END.to_vec(),
                ]
                .concat(),
            ),
            (
                "REF",
                // an EFI_IFR_REF5 "Second" of QuestionId 7, its 22 bytes at byte 1
                23,
                operation(REF, false, &question_header_with(7, 2, 1, 1, 0x00)),
            ),
        ];
        for (kind, size, question) in cases {
            let packages = [
                form_package_with_guid(
                    guid_bytes(KEYED_FORM_SET),
                    &[
                        var_store_efi(1, "Setup", NV_BS_RT, size),
                        form(1, &[operation(NUMERIC, false, &numeric), question]),
                    ],
                ),
                strings_package_of(b"en-US", &["First", "Second", "On"]),
                END_PACKAGE.to_vec(),
            ];
            let hiidb = package_list_with_guid(guid_bytes(KEYED_LIST), &packages.concat());

            assert_eq!(
                selected_in(&hiidb, &by_address(&format!("{KEYED_FORM_SET}:7"))),
                refused(&format!(
                    "QuestionId 0x0007 of FormSet {KEYED_FORM_SET} is that of the questions \
                     \"First\" and \"Second\": a QuestionId identifies one question of its FormSet"
                )),
                "{kind}"
            );
        }
    }

    /// A HiiDB whose FormSet of GUID KEYED_FORM_SET holds, at byte 0 of Setup, the CHECKBOX of
    /// QuestionId 0x8001 that a SUPPRESS_IF TRUE suppresses, which x-UEFI-ns names "Hidden", and,
    /// at byte 1, that of QuestionId 0x8003 that a GRAY_OUT_IF TRUE grays out, named "Grayed".
    fn conditioned_keyed_hiidb() -> Vec<u8> {
        let packages = [
            form_package_with_guid(
                guid_bytes(KEYED_FORM_SET),
                &[
                    var_store_efi(1, "Setup", NV_BS_RT, 2),
                    form(
                        1,
                        &[
                            conditional(SUPPRESS_IF, ifr_true(), &[checkbox_at(0x8001, 1, 1, 0)]),
                            conditional(GRAY_OUT_IF, ifr_true(), &[checkbox_at(0x8003, 2, 1, 1)]),
                        ],
                    ),
                ],
            ),
            strings_package_of(b"en-US", &["Suppressed", "Grayed out"]),
            strings_package_of(b"x-UEFI-ns", &["Hidden", "Grayed"]),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid(guid_bytes(KEYED_LIST), &packages.concat())
    }

    /// The names of the questions that get or set selects, or the SelectionError that it fails
    /// with, if any.
    type Outcome = std::result::Result<Vec<String>, Option<SelectionError>>;

    /// What get and set select in conditioned_keyed_hiidb by `question` with `include`, set
    /// setting it to 1, and set's writes to Setup.
    fn selected_including(
        question: &QuestionSelector,
        include: IncludedStates,
    ) -> ([Outcome; 2], Vec<(u16, Vec<u8>)>) {
        let selection_error = |error: anyhow::Error| error.downcast::<SelectionError>().ok();
        let variables = Rc::new(MemoryVariables::default());
        variables.insert(setup(), 7, &[0, 0]);

        let got = HiiBackend::get_in(
            &conditioned_keyed_hiidb(),
            question.clone(),
            None,
            &GetOptions {
                include,
                ..GetOptions::default()
            },
            shared(&variables),
            None,
            None,
            None,
        );
        let set = set_responses(
            &conditioned_keyed_hiidb(),
            question.clone(),
            &SetValue::Text("1".to_owned()),
            None,
            &SetOptions {
                include,
                ..SetOptions::default()
            },
            SetAccess {
                reads: shared(&variables),
                writes: &*variables,
                held: None,
            },
            None,
        );

        let got = got
            .map(|got| {
                got.responses
                    .into_iter()
                    .map(|response| response.question.name)
                    .collect()
            })
            .map_err(selection_error);
        let set = set
            .map(|set| {
                set.responses
                    .into_iter()
                    .map(|response| response.question.name)
                    .collect()
            })
            .map_err(selection_error);
        ([got, set], variables.writes_to(&setup()))
    }

    /// get and set by --question-id and by --keyword refuse a suppressed or grayed-out question
    /// unless --include names its state, and set writes nothing; with its state included they
    /// select it, and set writes it.
    #[test]
    fn selectors_select_a_question_in_a_state_only_if_included() {
        let cases = [
            (
                "Suppressed",
                0x8001,
                "Hidden",
                0,
                IncludedStates::SUPPRESSED,
            ),
            (
                "Grayed out",
                0x8003,
                "Grayed",
                1,
                IncludedStates::GRAYED_OUT,
            ),
        ];
        for (prompt, question_id, keyword, offset, state) in cases {
            for question in [
                by_address(&format!("{KEYED_FORM_SET}:{question_id}")),
                by_keyword(keyword, None),
            ] {
                let excluded = Err(Some(SelectionError::Excluded {
                    question: question.to_string(),
                    states: state,
                }));
                let names = Ok(vec![prompt.to_owned()]);

                assert_eq!(
                    selected_including(&question, IncludedStates::empty()),
                    ([excluded.clone(), excluded], vec![]),
                    "{question:?} without --include"
                );
                assert_eq!(
                    selected_including(&question, state),
                    ([names.clone(), names], vec![(offset, vec![1])]),
                    "{question:?} with {state:?}"
                );
            }
        }
    }

    /// get takes a QUESTION as a &String, as it did before it took a QuestionSelector.
    #[test]
    fn get_takes_a_question_as_a_string_reference() {
        let question = String::from("Plain");
        let options = GetOptions {
            efivars: EfivarSource::Disabled,
            ..GetOptions::default()
        };

        let got = HiiBackend::get_using(&keyed_hiidb("Keyed"), &question, None, &options)
            .expect("get Plain");

        let names: Vec<&str> = got
            .responses
            .iter()
            .map(|response| response.question.name.as_str())
            .collect();
        assert_eq!(names, ["Plain"], "get Plain");
    }

    /// get, list-questions and show-ifr read question values from the source that their
    /// options name.
    #[cfg(efivar_dumps)]
    #[test]
    fn options_name_the_efivar_source() {
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, 1),
                form(1, &[checkbox_on(1, 1, 1)]),
            ]),
            en_strings_package(b'Q'),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x55; 16], &packages.concat());
        let efivars = tempfile::tempdir().expect("create efivars directory");
        fs::write(
            efivars
                .path()
                .join("Setup-00000000-0000-0000-0000-000000000000"),
            [7, 0, 0, 0, 1],
        )
        .expect("write efivar file");
        // show-ifr adds no IFR default
        let cases = [
            (
                "Directory",
                EfivarSource::Directory(efivars.path().to_path_buf()),
                "1",
                "1",
            ),
            (
                "Disabled",
                EfivarSource::Disabled,
                "<ValueUnavailable: EFI variables not read> <IFR default: 0>",
                "<ValueUnavailable: EFI variables not read>",
            ),
        ];

        for (case, efivars, want, want_shown) in cases {
            let get_options = GetOptions {
                efivars: efivars.clone(),
                ..GetOptions::default()
            };
            let list_options = ListQuestionsOptions {
                efivars: efivars.clone(),
                ..ListQuestionsOptions::default()
            };
            let got = HiiBackend::get_using(&hiidb, "Q", None, &get_options).expect("get");
            let listed =
                HiiBackend::list_questions_using(&hiidb, &list_options).expect("list questions");
            let ifr = HiiBackend::show_ifr_using(
                &hiidb,
                &ShowIfrOptions {
                    efivars,
                    ..Default::default()
                },
            )
            .expect("show the IFR")
            .readable_representation;

            let answers: Vec<&str> = got
                .responses
                .iter()
                .map(|response| response.question.answer.as_str())
                .collect();
            assert_eq!(answers, [want], "{case}: get");
            let answers: Vec<&str> = listed
                .iter()
                .map(|question| question.answer.as_str())
                .collect();
            assert_eq!(answers, [want], "{case}: list-questions");
            assert!(
                ifr.contains(&format!("-Answer: {want_shown}\n")),
                "{case}: show-ifr {ifr:?}"
            );
        }
    }

    /// The variable of the EFI variable VarStore Setup of password_hiidb.
    fn setup() -> VariableKey {
        VariableKey {
            name: "Setup".to_string(),
            guid: NIL_GUID,
        }
    }

    /// The variable of the buffer VarStore AMITSESetup of password_hiidb.
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

    /// A HiiDB whose FormSet has the CHECKBOX Q at byte 0 of the EFI variable Setup and, on the
    /// buffer VarStore AMITSESetup of AMI's layout, a PASSWORD at byte 0 and the CHECKBOX P at
    /// byte 80.
    fn password_hiidb() -> Vec<u8> {
        password_hiidb_with(password_on(3, 3, 2, 0))
    }

    /// password_hiidb with the PASSWORD op `password`.
    fn password_hiidb_with(password: Vec<u8>) -> Vec<u8> {
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, 1),
                var_store(2, [0x44; 16], "AMITSESetup", 81),
                form(
                    1,
                    &[checkbox_on(1, 1, 1), password, checkbox_at(2, 2, 2, 80)],
                ),
            ]),
            en_strings_package_of(&["Q", "P", "Password"]),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid([0x55; 16], &packages.concat())
    }

    /// The variables of password_hiidb, which reach `reach` through `interface`: Setup holds 0,
    /// AMITSESetup 80 bytes of 0xAA, a password, and then 1.
    fn password_variables(
        reach: VariableReach,
        interface: VariableInterface,
    ) -> Rc<MemoryVariables> {
        let variables = MemoryVariables::new(reach, interface);
        variables.insert(setup(), NV_BS_RT, &[0]);
        variables.insert(
            amitse_setup(),
            NV_BS_RT,
            &[[0xAA; 80].as_slice(), &[1]].concat(),
        );
        Rc::new(variables)
    }

    /// `variables`, shared with the caller.
    fn shared(variables: &Rc<MemoryVariables>) -> Box<dyn FirmwareVariables> {
        Box::new(Rc::clone(variables))
    }

    /// A package list with GUID `guid` whose form holds `questions` on the 3 bytes of the EFI
    /// variable Setup, each prompted string 1, `prompt`.
    fn one_form_list(guid: [u8; 16], prompt: &str, questions: &[Vec<u8>]) -> Vec<u8> {
        let packages = [
            form_package(&[var_store_efi(1, "Setup", NV_BS_RT, 3), form(1, questions)]),
            en_strings_package_of(&[prompt]),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid(guid, &packages.concat())
    }

    /// A UINT8 NUMERIC prompted string 1 at byte `offset` of Setup with the question Flags
    /// `flags`: 0x01 is EFI_IFR_FLAG_READ_ONLY.
    fn numeric_at(question_id: u16, offset: u16, flags: u8) -> Vec<u8> {
        uint8_numeric_with(question_id, 1, offset, flags, &[])
    }

    /// A UINT8 NUMERIC prompted string 1 at byte `offset` of Setup with the question Flags
    /// `flags`, whose EFI_IFR_VALUE gives it 2.
    fn value_numeric(question_id: u16, offset: u16, flags: u8) -> Vec<u8> {
        uint8_numeric_with(question_id, 1, offset, flags, &[value_of(uint8(2))])
    }

    /// `questions` in the scope of a GRAY_OUT_IF TRUE.
    fn grayed_out(questions: &[Vec<u8>]) -> Vec<u8> {
        conditional(GRAY_OUT_IF, ifr_true(), questions)
    }

    /// set's refusal of `question`, which EFI_IFR_FLAG_READ_ONLY makes read-only, followed by
    /// `then`.
    fn flag_refusal(question: &str, then: &str) -> Result<(), String> {
        Err(format!(
            "cannot set question {question:?}: EFI_IFR_FLAG_READ_ONLY makes it read-only (UEFI \
             2.11 §33.3.8.2.2); pass --i-am-fine-to-brick-this-system to write it{then}"
        ))
    }

    /// What flag_refusal follows with where including grayed-out questions selects a writable
    /// twin.
    const GRAYED_OUT_TWIN: &str = ", or also include grayed-out questions to select a writable one";

    /// A package list with GUID `guid` whose form holds the CHECKBOX "U", question 3, on the
    /// EFI variable Other, which set_to_9 does not hold, then `questions`, each prompted string
    /// 1, "T".
    fn undetermined_list(guid: [u8; 16], questions: &[Vec<u8>]) -> Vec<u8> {
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, 3),
                var_store_efi(2, "Other", NV_BS_RT, 1),
                form(1, &[&[checkbox_on(3, 2, 2)][..], questions].concat()),
            ]),
            en_strings_package_of(&["T", "U"]),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid(guid, &packages.concat())
    }

    /// set's refusal of `question`, which an EFI_IFR_VALUE makes read-only, followed by `then`.
    fn value_refusal(question: &str, then: &str) -> Result<(), String> {
        Err(format!(
            "cannot set question {question:?}: its EFI_IFR_VALUE expression makes it read-only \
             (UEFI 2.11 §33.3.8.3.88){then}"
        ))
    }

    /// Of two NUMERICs "T" in one form, the first read-only, set writes the second, the
    /// writable one, with UnsafeOperations::Allow or not, which then lifts nothing, as select
    /// prefers a selectable match to a grayed-out one.
    #[test]
    fn set_writes_the_writable_twin_of_a_read_only_question() {
        let hiidb = one_form_list(
            [0x66; 16],
            "T",
            &[numeric_at(1, 0, 0x01), numeric_at(2, 1, 0)],
        );
        for grant in [UnsafeOperations::Refuse, UnsafeOperations::Allow] {
            let (got, writes) = set_to_9_lifting(&hiidb, "T", IncludedStates::empty(), grant);
            assert_eq!(got, Ok(vec![]), "set T, {grant:?}");
            assert_eq!(writes, [(1, vec![9])], "set T, {grant:?}: writes");
        }
    }

    /// set refuses a question that EFI_IFR_FLAG_READ_ONLY makes read-only before any write,
    /// whichever condition states it includes, and writes it with UnsafeOperations::Allow, which
    /// it returns as lifted.
    #[test]
    fn flag_is_refused_without_unsafe_operations() {
        let hiidb = one_form_list([0x68; 16], "R", &[numeric_at(1, 0, 0x01)]);
        let lifted = UnsafeOperation::ReadOnlyQuestion {
            question: "R".to_owned(),
            writable: IncludedStates::empty(),
        };
        let cases = [
            (
                IncludedStates::empty(),
                UnsafeOperations::Refuse,
                Err(flag_refusal("R", "").unwrap_err()),
                vec![],
            ),
            (
                IncludedStates::CONDITIONS,
                UnsafeOperations::Refuse,
                Err(flag_refusal("R", "").unwrap_err()),
                vec![],
            ),
            (
                IncludedStates::empty(),
                UnsafeOperations::Allow,
                Ok(vec![lifted]),
                vec![(0, vec![9])],
            ),
        ];
        for (include, grant, want, want_writes) in cases {
            let (got, writes) = set_to_9_lifting(&hiidb, "R", include, grant);
            assert_eq!(got, want, "set R --include {include}, {grant:?}");
            assert_eq!(
                writes, want_writes,
                "set R --include {include}, {grant:?}: writes"
            );
        }
    }

    /// set refuses an ORDERED_LIST that EFI_IFR_FLAG_READ_ONLY makes read-only before any write,
    /// as it does a NUMERIC, and writes its items with UnsafeOperations::Allow, which it returns
    /// as lifted.
    #[test]
    fn ordered_list_flag_is_refused_without_unsafe_operations() {
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, 2),
                form(
                    1,
                    &[
                        operation(
                            ORDERED_LIST,
                            true,
                            &[question_header_with(1, 1, 1, 0, 0x01), vec![2, 0x00]].concat(),
                        ),
                        flagged_option(2, 0x00, 1),
                        flagged_option(3, 0x00, 2),
                        END.to_vec(),
                    ],
                ),
            ]),
            en_strings_package_of(&["L", "A", "B"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x5C; 16], &packages.concat());
        let lifted = UnsafeOperation::ReadOnlyQuestion {
            question: "L".to_owned(),
            writable: IncludedStates::empty(),
        };
        let cases = [
            (
                UnsafeOperations::Refuse,
                Err(flag_refusal("L", "").unwrap_err()),
                vec![],
            ),
            (
                UnsafeOperations::Allow,
                Ok(vec![lifted]),
                vec![(0, vec![2, 1])],
            ),
        ];
        for (grant, want, want_writes) in cases {
            let variables =
                MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);
            variables.insert(setup(), NV_BS_RT, &[1, 2]);
            let variables = Rc::new(variables);

            let got = HiiBackend::set_in(
                &hiidb,
                "L",
                &SetValue::Items(vec!["B".to_owned(), "A".to_owned()]),
                None,
                &SetOptions {
                    unsafe_operations: grant,
                    ..SetOptions::default()
                },
                SetAccess {
                    reads: shared(&variables),
                    writes: &*variables,
                    held: None,
                },
                None,
            )
            .map(|(_, lifted)| lifted)
            .map_err(|error| error.to_string());

            assert_eq!(got, want, "set L B A, {grant:?}");
            assert_eq!(
                variables.writes_to(&setup()),
                want_writes,
                "set L B A, {grant:?}: writes"
            );
        }
    }

    /// Of two ORDERED_LISTs "L", the first read-only at byte 0 and the second writable at byte 2,
    /// set without UnsafeOperations::Allow writes the writable one alone, as select ranks a
    /// read-only match after a writable one, and lifts nothing.
    #[test]
    fn set_ranks_a_read_only_ordered_list_after_a_writable_twin() {
        let list = |offset: u16, flags: u8| {
            vec![
                operation(
                    ORDERED_LIST,
                    true,
                    &[question_header_with(1, 1, 1, offset, flags), vec![2, 0x00]].concat(),
                ),
                flagged_option(2, 0x00, 1),
                flagged_option(3, 0x00, 2),
                END.to_vec(),
            ]
        };
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, 4),
                form(1, &[list(0, 0x01), list(2, 0x00)].concat()),
            ]),
            en_strings_package_of(&["L", "A", "B"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x5E; 16], &packages.concat());
        let variables = MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);
        variables.insert(setup(), NV_BS_RT, &[1, 2, 1, 2]);
        let variables = Rc::new(variables);

        let got = HiiBackend::set_in(
            &hiidb,
            "L",
            &SetValue::Items(vec!["B".to_owned(), "A".to_owned()]),
            None,
            &SetOptions::default(),
            SetAccess {
                reads: shared(&variables),
                writes: &*variables,
                held: None,
            },
            None,
        )
        .map(|(_, lifted)| lifted)
        .map_err(|error| error.to_string());

        assert_eq!(got, Ok(vec![]), "set L B A");
        assert_eq!(
            variables.writes_to(&setup()),
            [(2, vec![2, 1])],
            "set L B A: writes"
        );
    }

    /// select ranks a read-only match after a writable one in any state: of "T" read-only at byte
    /// 0 and "T" grayed out at byte 1, set writes the grayed-out one once grayed-out is
    /// included, with UnsafeOperations::Allow or not, and else the read-only one with Allow;
    /// with neither, its refusal names both ways.
    #[test]
    fn read_only_ranks_after_the_condition_states() {
        let hiidb = one_form_list(
            [0x69; 16],
            "T",
            &[numeric_at(1, 0, 0x01), grayed_out(&[numeric_at(2, 1, 0)])],
        );
        let cases = [
            (
                IncludedStates::empty(),
                UnsafeOperations::Refuse,
                flag_refusal("T", GRAYED_OUT_TWIN),
                vec![],
            ),
            (
                IncludedStates::empty(),
                UnsafeOperations::Allow,
                Ok(()),
                vec![(0, vec![9])],
            ),
            (
                IncludedStates::GRAYED_OUT,
                UnsafeOperations::Refuse,
                Ok(()),
                vec![(1, vec![9])],
            ),
            (
                IncludedStates::GRAYED_OUT,
                UnsafeOperations::Allow,
                Ok(()),
                vec![(1, vec![9])],
            ),
        ];
        for (include, grant, want, want_writes) in cases {
            let (got, writes) = set_to_9_with(&hiidb, "T", include, grant);
            assert_eq!(got, want, "set T --include {include}, {grant:?}");
            assert_eq!(
                writes, want_writes,
                "set T --include {include}, {grant:?}: writes"
            );
        }
    }

    /// An EFI_IFR_VALUE makes a question read-only whatever set includes, EFI_IFR_FLAG_READ_ONLY
    /// set or not, and UnsafeOperations::Allow does not lift it: its refusal names no flag. set
    /// writes a writable twin instead.
    #[test]
    fn value_is_refused_whatever_is_included() {
        for flags in [0x00, 0x01] {
            let hiidb = one_form_list([0x6A; 16], "V", &[value_numeric(1, 0, flags)]);
            for (include, grant) in [
                (IncludedStates::empty(), UnsafeOperations::Refuse),
                (IncludedStates::empty(), UnsafeOperations::Allow),
                (IncludedStates::all(), UnsafeOperations::Allow),
            ] {
                let (got, writes) = set_to_9_with(&hiidb, "V", include, grant);
                let case = format!("set V (Flags {flags:#04x}) --include {include}, {grant:?}");
                assert_eq!(got, value_refusal("V", ""), "{case}");
                assert_eq!(writes, [], "{case}: writes");
            }
        }

        let twin = one_form_list(
            [0x6B; 16],
            "V",
            &[value_numeric(1, 0, 0), numeric_at(2, 1, 0)],
        );
        let (got, writes) = set_to_9(&twin, "V", IncludedStates::empty());
        assert_eq!(got, Ok(()), "set V with a writable twin");
        assert_eq!(writes, [(1, vec![9])], "set V with a writable twin: writes");
    }

    /// The refusal of a question that an EFI_IFR_VALUE makes read-only names the states to
    /// include to select a writable twin, as a grayed-out one, and those of a twin that
    /// EFI_IFR_FLAG_READ_ONLY makes read-only only with UnsafeOperations::Allow, with which set
    /// writes that twin; without it, set selects that twin with them and refuses it, naming the
    /// flag.
    #[test]
    fn value_refusal_names_the_states_of_a_twin_that_set_writes() {
        let cases = [
            (
                "a writable twin",
                0x00,
                IncludedStates::empty(),
                UnsafeOperations::Refuse,
                value_refusal(
                    "V",
                    "; also include grayed-out questions to select one that set writes",
                ),
                vec![],
            ),
            (
                "a writable twin",
                0x00,
                IncludedStates::GRAYED_OUT,
                UnsafeOperations::Refuse,
                Ok(()),
                vec![(1, vec![9])],
            ),
            (
                "a read-only twin",
                0x01,
                IncludedStates::empty(),
                UnsafeOperations::Refuse,
                value_refusal("V", ""),
                vec![],
            ),
            (
                "a read-only twin",
                0x01,
                IncludedStates::empty(),
                UnsafeOperations::Allow,
                value_refusal(
                    "V",
                    "; also include grayed-out questions to select one that set writes",
                ),
                vec![],
            ),
            (
                "a read-only twin",
                0x01,
                IncludedStates::GRAYED_OUT,
                UnsafeOperations::Refuse,
                flag_refusal("V", ""),
                vec![],
            ),
            (
                "a read-only twin",
                0x01,
                IncludedStates::GRAYED_OUT,
                UnsafeOperations::Allow,
                Ok(()),
                vec![(1, vec![9])],
            ),
        ];
        for (case, flags, include, grant, want, want_writes) in cases {
            let hiidb = one_form_list(
                [0x73; 16],
                "V",
                &[
                    value_numeric(1, 0, 0),
                    grayed_out(&[numeric_at(2, 1, flags)]),
                ],
            );
            let (got, writes) = set_to_9_with(&hiidb, "V", include, grant);
            assert_eq!(got, want, "{case}: set V --include {include}, {grant:?}");
            assert_eq!(
                writes, want_writes,
                "{case}: set V --include {include}, {grant:?}: writes"
            );
        }
    }

    /// Of a "V" that an EFI_IFR_VALUE makes read-only and a "V" that EFI_IFR_FLAG_READ_ONLY does,
    /// select ranks the second first, which set writes with UnsafeOperations::Allow.
    #[test]
    fn flag_ranks_before_value() {
        let hiidb = one_form_list(
            [0x6F; 16],
            "V",
            &[value_numeric(1, 0, 0), numeric_at(2, 1, 0x01)],
        );
        let cases = [
            (UnsafeOperations::Refuse, flag_refusal("V", ""), vec![]),
            (UnsafeOperations::Allow, Ok(()), vec![(1, vec![9])]),
        ];
        for (grant, want, want_writes) in cases {
            let (got, writes) = set_to_9_with(&hiidb, "V", IncludedStates::empty(), grant);
            assert_eq!(got, want, "set V, {grant:?}");
            assert_eq!(writes, want_writes, "set V, {grant:?}: writes");
        }
    }

    /// Where one FormSet selects a writable "T" and another a read-only one, set refuses before
    /// it writes either; with UnsafeOperations::Allow it writes both, in one write of their
    /// variable, and lifts the write of the read-only one once.
    #[test]
    fn read_only_refusal_comes_before_any_write() {
        let hiidb = [
            one_form_list([0x6C; 16], "T", &[numeric_at(1, 0, 0)]),
            one_form_list([0x6D; 16], "T", &[numeric_at(1, 1, 0x01)]),
        ]
        .concat();
        let (got, writes) = set_to_9(&hiidb, "T", IncludedStates::empty());
        assert_eq!(got, flag_refusal("T", ""), "set T");
        assert_eq!(writes, [], "set T: writes");

        let (got, writes) = set_to_9_lifting(
            &hiidb,
            "T",
            IncludedStates::empty(),
            UnsafeOperations::Allow,
        );
        assert_eq!(
            got,
            Ok(vec![UnsafeOperation::ReadOnlyQuestion {
                question: "T".to_owned(),
                writable: IncludedStates::empty(),
            }]),
            "set T, Allow"
        );
        assert_eq!(writes, [(0, vec![9, 9])], "set T, Allow: writes");
    }

    /// get shows the writable twin that set writes rather than the read-only one before it, and
    /// a read-only question that has no writable twin.
    #[test]
    fn get_shows_the_match_that_set_writes() {
        let variables = MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);
        variables.insert(setup(), NV_BS_RT, &[1, 2, 0]);
        let variables = Rc::new(variables);
        let twins = one_form_list(
            [0x66; 16],
            "T",
            &[numeric_at(1, 0, 0x01), numeric_at(2, 1, 0)],
        );
        let read_only = one_form_list([0x6E; 16], "R", &[numeric_at(1, 0, 0x01)]);
        for (hiidb, question, want) in [(twins, "T", "2"), (read_only, "R", "1")] {
            let got = HiiBackend::get_in(
                &hiidb,
                question,
                None,
                &GetOptions::default(),
                shared(&variables),
                None,
                None,
                None,
            )
            .expect("get");
            let answers: Vec<&str> = got
                .responses
                .iter()
                .map(|response| response.question.answer.as_str())
                .collect();
            assert_eq!(answers, [want], "get {question}");
        }
    }

    /// Of twins "T" that a GRAY_OUT_IF on the unreadable question 3 may gray out, the first
    /// read-only, get shows the writable one, and set refuses them as undetermined, not for the
    /// read-only flag.
    #[test]
    fn undetermined_twins_rank_read_only_last() {
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, 3),
                var_store_efi(2, "Other", NV_BS_RT, 1),
                form(
                    1,
                    &[
                        checkbox_on(3, 2, 2),
                        conditional(
                            GRAY_OUT_IF,
                            eq_id_val_of(3, 1),
                            &[numeric_at(1, 0, 0x01), numeric_at(2, 1, 0)],
                        ),
                    ],
                ),
            ]),
            en_strings_package_of(&["T", "U"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x70; 16], &packages.concat());

        let variables = MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);
        variables.insert(setup(), NV_BS_RT, &[1, 2, 0]);
        let variables = Rc::new(variables);
        let got = HiiBackend::get_in(
            &hiidb,
            "T",
            None,
            &GetOptions::default(),
            shared(&variables),
            None,
            None,
            None,
        )
        .expect("get T");
        let answers: Vec<Option<&str>> = got
            .responses
            .iter()
            .map(|response| response.question.answer.split_whitespace().next())
            .collect();
        assert_eq!(answers, [Some("2")], "get T");

        let (got, writes) = set_to_9(&hiidb, "T", IncludedStates::empty());
        assert!(
            got.as_ref()
                .is_err_and(|error| error.starts_with("cannot tell whether question \"T\" is")),
            "set T: {got:?}"
        );
        assert_eq!(writes, [], "set T: writes");
    }

    /// Of a writable "T" grayed out and a "T" that EFI_IFR_FLAG_READ_ONLY makes read-only and
    /// that a SUPPRESS_IF on the unreadable question 3 may suppress, the likely match, set
    /// refuses the second as undetermined, which UnsafeOperations::Allow does not lift; with
    /// suppressed included, for the read-only flag, naming the states that select the first;
    /// and writes either with its states included, the second with Allow too.
    #[test]
    fn undetermined_read_only_refusal_names_a_grayed_out_writable_twin() {
        let hiidb = undetermined_list(
            [0x75; 16],
            &[
                grayed_out(&[numeric_at(2, 1, 0)]),
                conditional(SUPPRESS_IF, eq_id_val_of(3, 1), &[numeric_at(1, 0, 0x01)]),
            ],
        );
        for grant in [UnsafeOperations::Refuse, UnsafeOperations::Allow] {
            let (got, writes) = set_to_9_with(&hiidb, "T", IncludedStates::empty(), grant);
            assert!(
                got.as_ref().is_err_and(|error| {
                    error.starts_with("cannot tell whether question \"T\" is suppressed: ")
                }),
                "set T, {grant:?}: {got:?}"
            );
            assert_eq!(writes, [], "set T, {grant:?}: writes");
        }
        let cases = [
            (
                IncludedStates::SUPPRESSED,
                UnsafeOperations::Refuse,
                flag_refusal("T", GRAYED_OUT_TWIN),
                vec![],
            ),
            (
                IncludedStates::SUPPRESSED,
                UnsafeOperations::Allow,
                Ok(()),
                vec![(0, vec![9])],
            ),
            (
                IncludedStates::GRAYED_OUT,
                UnsafeOperations::Refuse,
                Ok(()),
                vec![(1, vec![9])],
            ),
        ];
        for (include, grant, want, want_writes) in cases {
            let (got, writes) = set_to_9_with(&hiidb, "T", include, grant);
            assert_eq!(got, want, "set T --include {include}, {grant:?}");
            assert_eq!(
                writes, want_writes,
                "set T --include {include}, {grant:?}: writes"
            );
        }
    }

    /// select ranks a match that include certainly allows before a likely one, whatever their
    /// Ranks: of a "T" that EFI_IFR_FLAG_READ_ONLY makes read-only and a writable "T" that a
    /// GRAY_OUT_IF on the unreadable question 3 may gray out, get shows the first and set refuses
    /// it, naming the states that select the second, which it writes with them.
    #[test]
    fn certain_read_only_match_ranks_before_an_undetermined_writable_one() {
        let hiidb = undetermined_list(
            [0x76; 16],
            &[
                numeric_at(1, 0, 0x01),
                conditional(GRAY_OUT_IF, eq_id_val_of(3, 1), &[numeric_at(2, 1, 0)]),
            ],
        );
        let variables = MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);
        variables.insert(setup(), NV_BS_RT, &[1, 2, 0]);
        let got = HiiBackend::get_in(
            &hiidb,
            "T",
            None,
            &GetOptions::default(),
            shared(&Rc::new(variables)),
            None,
            None,
            None,
        )
        .expect("get T");
        let answers: Vec<&str> = got
            .responses
            .iter()
            .map(|response| response.question.answer.as_str())
            .collect();
        assert_eq!(answers, ["1"], "get T");

        let cases = [
            (
                IncludedStates::empty(),
                UnsafeOperations::Refuse,
                flag_refusal("T", GRAYED_OUT_TWIN),
                vec![],
            ),
            (
                IncludedStates::empty(),
                UnsafeOperations::Allow,
                Ok(()),
                vec![(0, vec![9])],
            ),
            (
                IncludedStates::GRAYED_OUT,
                UnsafeOperations::Refuse,
                Ok(()),
                vec![(1, vec![9])],
            ),
        ];
        for (include, grant, want, want_writes) in cases {
            let (got, writes) = set_to_9_with(&hiidb, "T", include, grant);
            assert_eq!(got, want, "set T --include {include}, {grant:?}");
            assert_eq!(
                writes, want_writes,
                "set T --include {include}, {grant:?}: writes"
            );
        }
    }

    /// set refuses an undetermined match that EFI_IFR_FLAG_READ_ONLY makes read-only as
    /// undetermined, whose refusal names no flag, with UnsafeOperations::Allow or not, as
    /// Allow does not lift it; with its states included, for the read-only
    /// flag; and writes a "T" that a GRAY_OUT_IF on the unreadable question 3 may gray out with
    /// grayed-out included and Allow.
    #[test]
    fn undetermined_read_only_match_is_refused_as_undetermined_first() {
        let hiidb = undetermined_list(
            [0x78; 16],
            &[conditional(
                GRAY_OUT_IF,
                eq_id_val_of(3, 1),
                &[numeric_at(1, 0, 0x01)],
            )],
        );
        for grant in [UnsafeOperations::Refuse, UnsafeOperations::Allow] {
            let (got, writes) = set_to_9_with(&hiidb, "T", IncludedStates::empty(), grant);
            assert!(
                got.as_ref().is_err_and(|error| {
                    error.starts_with("cannot tell whether question \"T\" is grayed-out: ")
                        && !error.contains(UNSAFE_OPERATIONS_FLAG)
                }),
                "set T, {grant:?}: {got:?}"
            );
            assert_eq!(writes, [], "set T, {grant:?}: writes");
        }

        let grayed_out = IncludedStates::GRAYED_OUT;
        let (got, writes) = set_to_9(&hiidb, "T", grayed_out);
        assert_eq!(got, flag_refusal("T", ""), "set T --include {grayed_out}");
        assert_eq!(writes, [], "set T --include {grayed_out}: writes");

        let (got, writes) = set_to_9_with(&hiidb, "T", grayed_out, UnsafeOperations::Allow);
        assert_eq!(got, Ok(()), "set T --include {grayed_out}, Allow");
        assert_eq!(
            writes,
            [(0, vec![9])],
            "set T --include {grayed_out}, Allow: writes"
        );
    }

    /// An EFI_IFR_VALUE in an EFI_IFR_DEFAULT_2 of a question gives its default, not its value
    /// (edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes, InScopeDefault), so set writes
    /// it.
    #[test]
    fn value_in_a_default_leaves_the_question_writable() {
        let question = uint8_numeric_with(1, 1, 0, 0, &[ifr_default_2(0, uint8(2))]);
        let hiidb = one_form_list([0x71; 16], "D", &[question]);
        let (got, writes) = set_to_9(&hiidb, "D", IncludedStates::empty());
        assert_eq!(got, Ok(()), "set D");
        assert_eq!(writes, [(0, vec![9])], "set D: writes");
    }

    /// set names the missing EFI variable of a question that EFI_IFR_FLAG_READ_ONLY makes
    /// read-only, with UnsafeOperations::Allow or not, as it refuses what Allow cannot lift before
    /// what it lifts.
    #[test]
    fn efivar_checks_precede_the_read_only_flag() {
        let packages = [
            form_package(&[
                var_store_efi(1, "Missing", NV_BS_RT, 3),
                form(1, &[numeric_at(1, 0, 0x01)]),
            ]),
            en_strings_package_of(&["R"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x72; 16], &packages.concat());
        for grant in [UnsafeOperations::Refuse, UnsafeOperations::Allow] {
            let (got, writes) = set_to_9_with(&hiidb, "R", IncludedStates::empty(), grant);
            assert!(
                got.as_ref().is_err_and(|error| {
                    error.contains("Missing-00000000-0000-0000-0000-000000000000")
                        && error.contains("the firmware has not created it or does not expose it")
                        && !error.contains(UNSAFE_OPERATIONS_FLAG)
                }),
                "set R, {grant:?}: {got:?}"
            );
            assert_eq!(writes, [], "set R, {grant:?}: writes");
        }
    }

    /// set refuses a value that a question of EFI_IFR_FLAG_READ_ONLY cannot take, 300 for a UINT8
    /// NUMERIC, with the same refusal with and without UnsafeOperations::Allow, which names
    /// neither the read-only flag nor --i-am-fine-to-brick-this-system: it checks the value
    /// before what Allow lifts.
    #[test]
    fn value_checks_precede_the_read_only_flag() {
        let hiidb = one_form_list([0x77; 16], "R", &[numeric_at(1, 0, 0x01)]);
        let got = [UnsafeOperations::Refuse, UnsafeOperations::Allow].map(|grant| {
            let variables =
                MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);
            variables.insert(setup(), NV_BS_RT, &[0; 3]);
            let variables = Rc::new(variables);
            let options = SetOptions {
                unsafe_operations: grant,
                ..SetOptions::default()
            };
            let got = set_responses(
                &hiidb,
                "R",
                &SetValue::Text("300".to_owned()),
                None,
                &options,
                SetAccess {
                    reads: shared(&variables),
                    writes: &*variables,
                    held: None,
                },
                None,
            )
            .map(drop)
            .map_err(|error| format!("{error:#}"));
            (got, variables.writes_to(&setup()))
        });

        let [(refused, refused_writes), (allowed, allowed_writes)] = got;
        assert!(
            refused
                .as_ref()
                .is_err_and(|error| !error.contains("EFI_IFR_FLAG_READ_ONLY")
                    && !error.contains(UNSAFE_OPERATIONS_FLAG)),
            "set R 300, Refuse: {refused:?}"
        );
        assert_eq!(allowed, refused, "set R 300: Allow as Refuse");
        assert_eq!(
            (refused_writes, allowed_writes),
            (vec![], vec![]),
            "set R 300: writes"
        );
    }

    /// An EFI_IFR_VALUE anywhere in a question's scope makes it read-only, as edk2-stable202608
    /// SetupBrowserDxe/IfrParse.c ParseOpCodes gives it to the question's ValueExpression, but not
    /// one in the scope of a statement nested in it, whose own it is.
    #[test]
    fn value_anywhere_in_the_question_scope_makes_it_read_only() {
        let nested_guid = [
            operation(GUID, true, &OTHER_GUID),
            value_of(uint8(2)),
            END.to_vec(),
        ]
        .concat();
        let cases = [
            (
                "in a SUPPRESS_IF FALSE",
                conditional(SUPPRESS_IF, ifr_false(), &[value_of(uint8(2))]),
                value_refusal("W", ""),
                vec![],
            ),
            (
                "in a GUID op nested in it",
                nested_guid,
                Ok(()),
                vec![(0, vec![9])],
            ),
        ];
        for (case, body, want, want_writes) in cases {
            let hiidb = one_form_list([0x74; 16], "W", &[uint8_numeric_with(1, 1, 0, 0, &[body])]);
            let (got, writes) = set_to_9(&hiidb, "W", IncludedStates::empty());
            assert_eq!(got, want, "{case}: set W");
            assert_eq!(writes, want_writes, "{case}: set W: writes");
        }
    }

    /// A question of flags_hiidb.
    struct Flagged {
        prompt: &'static str,
        op_code: u8,
        /// The data after the question header
        data: &'static [u8],
        /// The question Flags
        flags: u8,
        /// The names that --json lists for `flags` (UEFI 2.11 §33.3.8.2.2), without the reserved
        /// bits 0x02 and 0x08
        names: &'static [&'static str],
    }

    /// The questions of flags_hiidb.
    const FLAGGED: [Flagged; 6] = [
        Flagged {
            prompt: "Mixed",
            op_code: NUMERIC,
            data: NUMERIC_0_TO_255,
            flags: 0x11,
            names: &["READ_ONLY", "RESET_REQUIRED"],
        },
        Flagged {
            prompt: "Plain",
            op_code: NUMERIC,
            data: NUMERIC_0_TO_255,
            flags: 0x00,
            names: &[],
        },
        Flagged {
            prompt: "Reserved",
            op_code: NUMERIC,
            data: NUMERIC_0_TO_255,
            flags: 0x0A,
            names: &[],
        },
        Flagged {
            prompt: "All",
            op_code: NUMERIC,
            data: NUMERIC_0_TO_255,
            flags: 0xFF,
            names: &[
                "READ_ONLY",
                "CALLBACK",
                "RESET_REQUIRED",
                "REST_STYLE",
                "RECONNECT_REQUIRED",
                "OPTIONS_ONLY",
            ],
        },
        Flagged {
            prompt: "Box",
            op_code: CHECKBOX,
            data: &[0x00],
            flags: 0x40,
            names: &["RECONNECT_REQUIRED"],
        },
        Flagged {
            prompt: "Pick",
            op_code: ONE_OF,
            data: &[0x00, 0, 1, 1],
            flags: 0x84,
            names: &["CALLBACK", "OPTIONS_ONLY"],
        },
    ];

    /// The NUMERIC Flags, EFI_IFR_NUMERIC_SIZE_1 shown as EFI_IFR_DISPLAY_UINT_DEC, MinValue,
    /// MaxValue and Step of a UINT8 NUMERIC from 0 to 255.
    const NUMERIC_0_TO_255: &[u8] = &[0x10, 0, 255, 1];

    /// A HiiDB whose EFI variable Setup holds the questions of FLAGGED, the first at byte 0,
    /// each prompted by its own string.
    fn flags_hiidb() -> Vec<u8> {
        let questions: Vec<Vec<u8>> = FLAGGED
            .iter()
            .zip(1..)
            .map(|(question, id)| {
                let header = question_header_with(id, id, 1, id - 1, question.flags);
                operation(
                    question.op_code,
                    false,
                    &[&header[..], question.data].concat(),
                )
            })
            .collect();
        let size = u16::try_from(FLAGGED.len()).expect("FLAGGED fits a VarStore");
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, size),
                form(1, &questions),
            ]),
            en_strings_package_of(&FLAGGED.map(|question| question.prompt)),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid([0x55; 16], &packages.concat())
    }

    /// The value of `field` in the JSON that --json prints for `question`, if it prints one.
    fn json_field(question: &Question, field: &str) -> Option<serde_json::Value> {
        let json: serde_json::Value =
            serde_json::from_slice(&simplejson_protocol::serialize(question))
                .expect("parse the JSON of a question");
        json.get(field).cloned()
    }

    /// The flags that --json lists for `question`, if it lists any.
    fn json_flags(question: &Question) -> Option<Vec<String>> {
        json_field(question, "flags")
            .map(|flags| serde_json::from_value(flags).expect("flags are a list of strings"))
    }

    /// What json_flags gives for a question with the flags `names`: None for none.
    fn want_flags(names: &[&str]) -> Option<Vec<String>> {
        (!names.is_empty()).then(|| names.iter().map(ToString::to_string).collect())
    }

    /// get and list-questions list the flags of each kind of question by their UEFI names,
    /// without the reserved bits, and print no flags for a question with none.
    #[test]
    fn get_and_list_questions_name_the_question_flags() {
        let hiidb = flags_hiidb();
        let listed = HiiBackend::list_questions_using(
            &hiidb,
            &ListQuestionsOptions {
                efivars: EfivarSource::Disabled,
                ..ListQuestionsOptions::default()
            },
        )
        .expect("list questions");
        let listed: Vec<(String, Option<Vec<String>>)> = listed
            .iter()
            .map(|question| (question.name.clone(), json_flags(question)))
            .collect();
        let want: Vec<(String, Option<Vec<String>>)> = FLAGGED
            .iter()
            .map(|question| (question.prompt.to_string(), want_flags(question.names)))
            .collect();
        assert_eq!(listed, want, "list-questions");

        for Flagged { prompt, names, .. } in FLAGGED {
            let got = HiiBackend::get_using(
                &hiidb,
                prompt,
                None,
                &GetOptions {
                    efivars: EfivarSource::Disabled,
                    ..GetOptions::default()
                },
            )
            .unwrap_or_else(|error| panic!("get {prompt}: {error:#}"));
            let got: Vec<Option<Vec<String>>> = got
                .responses
                .iter()
                .map(|response| json_flags(&response.question))
                .collect();
            assert_eq!(got, [want_flags(names)], "get {prompt}");
        }
    }

    /// A HiiDB of two package lists. The first FormSet declares the DEFAULTSTOREs STANDARD "Std",
    /// 0x4001 "Platform" and 0x4001 "Late name", and on the EFI variable Setup, from byte 0, the
    /// UINT8 questions Numbers (EFI_IFR_DEFAULT STANDARD 5, 0x0001 6 and 0x4001 7), Undeclared
    /// (EFI_IFR_DEFAULT 0x4000 9), Options (the options Zero, One flagged DEFAULT and Two flagged
    /// DEFAULT_MFG), Mfg box (a CHECKBOX flagged DEFAULT_MFG), Plain box (a CHECKBOX without
    /// flags) and None (no default). The second declares only MANUFACTURING "Mfg", and Bare box, a
    /// CHECKBOX flagged DEFAULT, and Mfg store box, a CHECKBOX without flags.
    fn defaults_hiidb() -> Vec<u8> {
        let header = |id: u16| question_header_with(id, id, 1, id - 1, 0x00);
        let numeric = |id: u16, children: &[Vec<u8>]| {
            let data = [header(id), NUMERIC_0_TO_255.to_vec()].concat();
            [
                operation(NUMERIC, true, &data),
                children.concat(),
                END.to_vec(),
            ]
            .concat()
        };
        let checkbox =
            |id: u16, flags: u8| operation(CHECKBOX, false, &[header(id), vec![flags]].concat());
        let one_of = [
            operation(ONE_OF, true, &[header(3), vec![0x00, 0, 2, 1]].concat()),
            flagged_option(9, 0x00, 0),
            flagged_option(10, 0x10, 1),
            flagged_option(11, 0x20, 2),
            END.to_vec(),
        ]
        .concat();
        let first = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, 6),
                default_store_named(7, 0x0000),
                default_store_named(8, 0x4001),
                default_store_named(12, 0x4001),
                form(
                    1,
                    &[
                        numeric(
                            1,
                            &[
                                ifr_default(0x0000, 5),
                                ifr_default(0x0001, 6),
                                ifr_default(0x4001, 7),
                            ],
                        ),
                        numeric(2, &[ifr_default(0x4000, 9)]),
                        one_of,
                        checkbox(4, 0x02),
                        checkbox(5, 0x00),
                        numeric(6, &[]),
                    ],
                ),
            ]),
            en_strings_package_of(&[
                "Numbers",
                "Undeclared",
                "Options",
                "Mfg box",
                "Plain box",
                "None",
                "Std",
                "Platform",
                "Zero",
                "One",
                "Two",
                "Late name",
            ]),
            END_PACKAGE.to_vec(),
        ];
        let second = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, 2),
                default_store_named(3, 0x0001),
                form(1, &[checkbox(1, 0x01), checkbox(2, 0x00)]),
            ]),
            en_strings_package_of(&["Bare box", "Mfg store box", "Mfg"]),
            END_PACKAGE.to_vec(),
        ];
        [
            package_list_with_guid([0x55; 16], &first.concat()),
            package_list_with_guid([0x66; 16], &second.concat()),
        ]
        .concat()
    }

    /// The questions of defaults_hiidb and the defaults that --json lists for each, if any.
    fn want_defaults() -> [(&'static str, Option<serde_json::Value>); 8] {
        [
            (
                "Numbers",
                Some(serde_json::json!([
                    {"default_id": 0, "default_store_name": "Std", "value": "5"},
                    {"default_id": 1, "value": "6"},
                    {"default_id": 0x4001, "default_store_name": "Platform", "value": "7"},
                ])),
            ),
            (
                "Undeclared",
                Some(serde_json::json!([{"default_id": 0x4000, "value": "9"}])),
            ),
            (
                "Options",
                Some(serde_json::json!([
                    {"default_id": 0, "default_store_name": "Std", "value": "One"},
                    {"default_id": 1, "value": "Two"},
                ])),
            ),
            (
                "Mfg box",
                Some(serde_json::json!([
                    {"default_id": 0, "default_store_name": "Std", "value": "0"},
                    {"default_id": 1, "value": "1"},
                ])),
            ),
            (
                "Plain box",
                Some(serde_json::json!([
                    {"default_id": 0, "default_store_name": "Std", "value": "0"},
                ])),
            ),
            ("None", None),
            (
                "Bare box",
                Some(serde_json::json!([
                    {"default_id": 0, "value": "1"},
                    {"default_id": 1, "default_store_name": "Mfg", "value": "0"},
                ])),
            ),
            (
                "Mfg store box",
                Some(serde_json::json!([
                    {"default_id": 0, "value": "0"},
                    {"default_id": 1, "default_store_name": "Mfg", "value": "0"},
                ])),
            ),
        ]
    }

    /// get and list-questions list each default that the IFR declares for a question, per
    /// DefaultId, ascending, with the name of the first DEFAULTSTORE of that DefaultId if the
    /// FormSet declares one: from EFI_IFR_DEFAULT, also of a DefaultId that no DEFAULTSTORE
    /// declares, from the DEFAULT and DEFAULT_MFG flags of the options and of a CHECKBOX, also
    /// without a manufacturing DEFAULTSTORE, the cleared flag of a CHECKBOX for each declared
    /// DEFAULTSTORE, and none for a question without.
    #[test]
    fn get_and_list_questions_list_the_declared_defaults() {
        let hiidb = defaults_hiidb();
        let listed = HiiBackend::list_questions_using(
            &hiidb,
            &ListQuestionsOptions {
                efivars: EfivarSource::Disabled,
                ..ListQuestionsOptions::default()
            },
        )
        .expect("list questions");
        let listed: Vec<(String, Option<serde_json::Value>)> = listed
            .iter()
            .map(|question| (question.name.clone(), json_field(question, "defaults")))
            .collect();
        let want = want_defaults().map(|(name, defaults)| (name.to_string(), defaults));
        assert_eq!(listed, want, "list-questions");

        for (name, defaults) in want_defaults() {
            let got = HiiBackend::get_using(
                &hiidb,
                name,
                None,
                &GetOptions {
                    efivars: EfivarSource::Disabled,
                    ..GetOptions::default()
                },
            )
            .unwrap_or_else(|error| panic!("get {name}: {error:#}"));
            let got: Vec<Option<serde_json::Value>> = got
                .responses
                .iter()
                .map(|response| json_field(&response.question, "defaults"))
                .collect();
            assert_eq!(got, [defaults], "get {name}");
        }
    }

    /// set's response lists the defaults of the question it wrote, and none for one without.
    #[test]
    fn set_lists_the_declared_defaults() {
        let [numbers, _, _, _, _, none, _, _] = want_defaults();
        for (name, defaults) in [numbers, none] {
            let variables =
                MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);
            variables.insert(setup(), NV_BS_RT, &[0; 6]);
            let variables = Rc::new(variables);
            let got = set_responses(
                &defaults_hiidb(),
                name,
                &SetValue::Text("3".to_owned()),
                None,
                &SetOptions::default(),
                SetAccess {
                    reads: shared(&variables),
                    writes: &*variables,
                    held: None,
                },
                None,
            )
            .unwrap_or_else(|error| panic!("set {name}: {error:#}"));
            let got: Vec<Option<serde_json::Value>> = got
                .responses
                .iter()
                .map(|response| json_field(&response.question, "defaults"))
                .collect();
            assert_eq!(got, [defaults], "set {name}");
        }
    }

    /// A UINT8 NUMERIC from 0 to 255 of QuestionId and prompt string `id`, at byte `id - 1` of
    /// VarStore 1, holding `children` in its scope.
    fn numeric_holding(id: u16, children: &[Vec<u8>]) -> Vec<u8> {
        let data = [
            question_header_with(id, id, 1, id - 1, 0x00),
            NUMERIC_0_TO_255.to_vec(),
        ]
        .concat();
        [
            operation(NUMERIC, true, &data),
            children.concat(),
            END.to_vec(),
        ]
        .concat()
    }

    /// The questions of locked_hiidb, each at the byte of its index of the EFI variable Setup,
    /// and whether an EFI_IFR_LOCKED grays it out.
    const LOCKED_QUESTIONS: [(&str, bool); 3] =
        [("Open", false), ("Locked", true), ("In locked form", true)];

    /// A HiiDB whose EFI variable Setup holds the UINT8 NUMERICs of LOCKED_QUESTIONS: Open,
    /// Locked, which holds an EFI_IFR_LOCKED in its scope, and, in a FORM that holds one, In
    /// locked form.
    fn locked_hiidb() -> Vec<u8> {
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, 3),
                form(
                    1,
                    &[numeric_holding(1, &[]), numeric_holding(2, &[locked_op()])],
                ),
                form(2, &[locked_op(), numeric_holding(3, &[])]),
            ]),
            en_strings_package_of(&LOCKED_QUESTIONS.map(|(name, _)| name)),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid([0x55; 16], &packages.concat())
    }

    /// What set does: its result, the error as text, and its writes to Setup, by offset.
    type SetOutcome = (Result<(), String>, Vec<(u16, Vec<u8>)>);

    /// SetOutcome, its result the unsafe operations that set lifted.
    type LiftingOutcome = (Result<Vec<UnsafeOperation>, String>, Vec<(u16, Vec<u8>)>);

    /// set of `question` to 9 in `hiidb`, selecting `include` too, with Setup of 3 bytes.
    fn set_to_9(hiidb: &[u8], question: &str, include: IncludedStates) -> SetOutcome {
        set_to_9_with(hiidb, question, include, UnsafeOperations::Refuse)
    }

    /// set_to_9, with `grant` for its unsafe operations.
    fn set_to_9_with(
        hiidb: &[u8],
        question: &str,
        include: IncludedStates,
        grant: UnsafeOperations,
    ) -> SetOutcome {
        let (got, writes) = set_to_9_lifting(hiidb, question, include, grant);
        (got.map(drop), writes)
    }

    /// set_to_9_with, its result the unsafe operations that it lifted.
    fn set_to_9_lifting(
        hiidb: &[u8],
        question: &str,
        include: IncludedStates,
        grant: UnsafeOperations,
    ) -> LiftingOutcome {
        let variables = MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);
        variables.insert(setup(), NV_BS_RT, &[0; 3]);
        let variables = Rc::new(variables);
        let got = HiiBackend::set_in(
            hiidb,
            question,
            &SetValue::Text("9".to_owned()),
            None,
            &SetOptions {
                include,
                unsafe_operations: grant,
                ..SetOptions::default()
            },
            SetAccess {
                reads: shared(&variables),
                writes: &*variables,
                held: None,
            },
            None,
        );
        (
            got.map(|(_, lifted)| lifted)
                .map_err(|error| error.to_string()),
            variables.writes_to(&setup()),
        )
    }

    /// set refuses a question that an EFI_IFR_LOCKED in its scope or in its FORM grays out, as
    /// edk2-stable202608 SetupBrowserDxe does, before any write, unless --include selects
    /// grayed-out questions, and writes the others.
    #[test]
    fn set_refuses_questions_that_a_locked_scope_grays_out() {
        let hiidb = locked_hiidb();
        for ((name, locked), offset) in LOCKED_QUESTIONS.into_iter().zip(0..) {
            let written = (Ok(()), vec![(offset, vec![9])]);
            let refused = (
                Err(format!(
                    "question {name:?} is grayed-out; also include grayed-out questions to \
                     select it"
                )),
                vec![],
            );
            let want = if locked { refused } else { written.clone() };
            assert_eq!(
                set_to_9(&hiidb, name, IncludedStates::empty()),
                want,
                "set {name}"
            );
            assert_eq!(
                set_to_9(&hiidb, name, IncludedStates::GRAYED_OUT),
                written,
                "set {name} with --include grayed-out"
            );
        }
    }

    /// list-questions leaves out a question that an EFI_IFR_LOCKED grays out, unless --include
    /// selects grayed-out questions, and then shows its state.
    #[test]
    fn list_questions_grays_out_questions_in_a_locked_scope() {
        let hiidb = locked_hiidb();
        let list = |include| {
            HiiBackend::list_questions_using(
                &hiidb,
                &ListQuestionsOptions {
                    include,
                    efivars: EfivarSource::Disabled,
                    ..ListQuestionsOptions::default()
                },
            )
            .expect("list questions")
            .into_iter()
            .map(|question| (question.name, question.answer))
            .collect::<Vec<_>>()
        };
        let not_read = "<ValueUnavailable: EFI variables not read>";
        let answer = |locked| match locked {
            true => format!("{not_read} <grayed-out>"),
            false => not_read.to_string(),
        };

        let selectable: Vec<(String, String)> = LOCKED_QUESTIONS
            .iter()
            .filter(|(_, locked)| !locked)
            .map(|&(name, locked)| (name.to_string(), answer(locked)))
            .collect();
        assert_eq!(list(IncludedStates::empty()), selectable, "list-questions");
        let all: Vec<(String, String)> = LOCKED_QUESTIONS
            .iter()
            .map(|&(name, locked)| (name.to_string(), answer(locked)))
            .collect();
        assert_eq!(
            list(IncludedStates::GRAYED_OUT),
            all,
            "list-questions --include grayed-out"
        );
    }

    /// An EFI_IFR_LOCKED in a statement nested in a question's scope locks that statement and
    /// leaves the question writable (edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes).
    #[test]
    fn locked_in_a_nested_statement_leaves_the_question_writable() {
        let guid = [
            operation(GUID, true, &[0x77; 16]),
            locked_op(),
            END.to_vec(),
        ]
        .concat();
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, 3),
                form(1, &[numeric_holding(1, &[guid])]),
            ]),
            en_strings_package_of(&["N"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x55; 16], &packages.concat());

        assert_eq!(
            set_to_9(&hiidb, "N", IncludedStates::empty()),
            (Ok(()), vec![(0, vec![9])]),
            "set N"
        );
    }

    /// set's response lists the flags of the question it wrote, and none for one without; Mixed
    /// is EFI_IFR_FLAG_READ_ONLY, which set writes with UnsafeOperations::Allow.
    #[test]
    fn set_names_the_question_flags() {
        let options = SetOptions {
            unsafe_operations: UnsafeOperations::Allow,
            ..SetOptions::default()
        };
        for (prompt, want) in [("Mixed", want_flags(FLAGGED[0].names)), ("Plain", None)] {
            let variables =
                MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);
            variables.insert(setup(), NV_BS_RT, &[0; FLAGGED.len()]);
            let variables = Rc::new(variables);
            let got = set_responses(
                &flags_hiidb(),
                prompt,
                &SetValue::Text("9".to_owned()),
                None,
                &options,
                SetAccess {
                    reads: shared(&variables),
                    writes: &*variables,
                    held: None,
                },
                None,
            )
            .unwrap_or_else(|error| panic!("set {prompt}: {error:#}"));
            let got: Vec<Option<Vec<String>>> = got
                .responses
                .iter()
                .map(|response| json_flags(&response.question))
                .collect();
            assert_eq!(got, [want], "set {prompt}");
        }
    }

    /// set_from after a read of firmware-reserved memory (set_after_read): a set that
    /// fails after it lifted the setup password keeps the read's operation, then set's
    /// (LiftedOperations), beside set's error, and one that succeeds returns both.
    #[cfg(firmware_memory_maps)]
    #[test]
    fn a_failed_set_after_a_lifted_read_keeps_both_operations() {
        let read = || {
            (
                b"the HiiDB".to_vec(),
                vec![UnsafeOperation::FirmwareReservedMemory],
            )
        };
        let both = vec![
            UnsafeOperation::FirmwareReservedMemory,
            UnsafeOperation::SetupPassword,
        ];

        let error = HiiBackend::set_after_read(read(), |db| {
            assert_eq!(db, b"the HiiDB", "the HiiDB that set reads");
            Err(LiftedOperations::attach(
                vec![UnsafeOperation::SetupPassword],
                anyhow::anyhow!("write failed"),
            ))
        })
        .expect_err("a failed set");
        let set = HiiBackend::set_after_read(read(), |_| {
            Ok((
                SetResponseList::default(),
                vec![UnsafeOperation::SetupPassword],
            ))
        })
        .expect("a set that succeeds");

        assert_eq!(
            error.downcast_ref::<LiftedOperations>(),
            Some(&LiftedOperations(both.clone())),
            "failed set: lifted"
        );
        assert_eq!(
            format!("{error:#}"),
            "after 2 unsafe operation(s) that --i-am-fine-to-brick-this-system let through: \
             write failed",
            "failed set: the error"
        );
        assert_eq!(set, (SetResponseList::default(), both), "set");
    }

    /// Through variables of either reach, get, list-questions and show-ifr read the questions
    /// beside a password in its VarStore: P at byte 80 of AMITSESetup.
    #[test]
    fn questions_beside_passwords_are_read_through_either_reach() {
        for (reach, interface) in [
            (VariableReach::Runtime, VariableInterface::Efivarfs),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            ),
        ] {
            let variables = password_variables(reach, interface);
            let got = HiiBackend::get_in(
                &password_hiidb(),
                "P",
                None,
                &GetOptions::default(),
                shared(&variables),
                None,
                None,
                None,
            )
            .expect("get");
            let listed = HiiBackend::list_questions_in(
                &password_hiidb(),
                &ListQuestionsOptions::default(),
                shared(&variables),
                None,
                None,
            )
            .expect("list questions");
            let ifr = HiiBackend::show_ifr_in(
                &password_hiidb(),
                &ShowIfrOptions::default(),
                shared(&variables),
                None,
                None,
            )
            .expect("show the IFR")
            .to_string();

            let answers: Vec<&str> = got
                .responses
                .iter()
                .map(|response| response.question.answer.as_str())
                .collect();
            assert_eq!(answers, ["1"], "{reach:?}: get");
            let answers: Vec<&str> = listed
                .iter()
                .filter(|question| question.name == "P")
                .map(|question| question.answer.as_str())
                .collect();
            assert_eq!(answers, ["1"], "{reach:?}: list-questions");
            assert!(ifr.contains("-Answer: 1\n"), "{reach:?}: show-ifr {ifr:?}");
            assert_eq!(
                variables.reads_of(&amitse_setup()),
                [81].repeat(3),
                "{reach:?}: reads of AMITSESetup"
            );
        }
    }

    /// set through variables that reach BootServices, in a HiiDB that declares a password
    /// question, refuses unless UnsafeOperations allows it, and then returns
    /// UnsafeOperation::SetupPassword, lifted; set through those that reach Runtime writes, as
    /// before, and lifts nothing; whatever their interface and whether volatile writes are
    /// allowed. Either writes P, beside the password.
    #[test]
    fn set_follows_the_unsafe_operations_grant_for_a_setup_password() {
        let refusal = "this HiiDB declares a setup password question, and the UEFI Shell runs no \
                       setup browser, so no password is asked or checked; pass \
                       --i-am-fine-to-brick-this-system to write without it";
        let cases = [
            (
                VariableReach::Runtime,
                VariableInterface::Efivarfs,
                "Q",
                UnsafeOperations::Refuse,
                Ok(vec![]),
                vec![(0, vec![1])],
                vec![],
            ),
            (
                VariableReach::Runtime,
                VariableInterface::Efivarfs,
                "P",
                UnsafeOperations::Refuse,
                Ok(vec![]),
                vec![],
                vec![(80, vec![0])],
            ),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
                "Q",
                UnsafeOperations::Refuse,
                Err(refusal),
                vec![],
                vec![],
            ),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
                "Q",
                UnsafeOperations::Allow,
                Ok(vec![UnsafeOperation::SetupPassword]),
                vec![(0, vec![1])],
                vec![],
            ),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
                "P",
                UnsafeOperations::Refuse,
                Err(refusal),
                vec![],
                vec![],
            ),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
                "P",
                UnsafeOperations::Allow,
                Ok(vec![UnsafeOperation::SetupPassword]),
                vec![],
                vec![(80, vec![0])],
            ),
            (
                VariableReach::BootServices,
                VariableInterface::Efivarfs,
                "Q",
                UnsafeOperations::Refuse,
                Err(refusal),
                vec![],
                vec![],
            ),
            (
                VariableReach::BootServices,
                VariableInterface::Efivarfs,
                "P",
                UnsafeOperations::Allow,
                Ok(vec![UnsafeOperation::SetupPassword]),
                vec![],
                vec![(80, vec![0])],
            ),
            (
                VariableReach::Runtime,
                VariableInterface::VariableServices,
                "P",
                UnsafeOperations::Refuse,
                Ok(vec![]),
                vec![],
                vec![(80, vec![0])],
            ),
        ];

        let cases = [VolatileWrites::Refuse, VolatileWrites::Allow]
            .into_iter()
            .flat_map(|volatile| cases.clone().map(|case| (volatile, case)));
        for (volatile, (reach, interface, question, policy, want, want_setup, want_amitse_setup)) in
            cases
        {
            let variables = password_variables(reach, interface);
            let options = SetOptions {
                unsafe_operations: policy,
                volatile,
                ..SetOptions::default()
            };
            let value = match question {
                "Q" => "1",
                _ => "0",
            };

            let got = HiiBackend::set_in(
                &password_hiidb(),
                question,
                &SetValue::Text(value.to_owned()),
                None,
                &options,
                SetAccess {
                    reads: shared(&variables),
                    writes: &*variables,
                    held: None,
                },
                None,
            );

            let case = format!(
                "{reach:?}, {interface:?}, set {question} {value}, {policy:?}, {volatile:?}"
            );
            assert_eq!(
                got.map(|(_, lifted)| lifted)
                    .map_err(|error| error.to_string()),
                want.map_err(str::to_string),
                "{case}"
            );
            assert_eq!(variables.writes_to(&setup()), want_setup, "{case}: Setup");
            assert_eq!(
                variables.writes_to(&amitse_setup()),
                want_amitse_setup,
                "{case}: AMITSESetup"
            );
        }
    }

    /// set through variables that reach BootServices, in a HiiDB that declares a password
    /// question, refuses what UnsafeOperations cannot lift before the setup password, with the
    /// same refusal with and without Allow, which names no --i-am-fine-to-brick-this-system, and
    /// writes nothing: a question that no prompt names, a value above the CHECKBOX's maximum, and
    /// a volatile variable.
    #[test]
    fn set_refuses_what_unsafe_operations_cannot_lift_before_the_setup_password() {
        let cases = [
            ("R", "1", NV_BS_RT, "no question \"R\" in the HiiDB"),
            ("Q", "2", NV_BS_RT, "exceeded max possible value"),
            (
                "Q",
                "1",
                BS_RT,
                "is volatile (no EFI_VARIABLE_NON_VOLATILE)",
            ),
        ];
        for (question, value, setup_attributes, refusal) in cases {
            let case = format!("set {question} {value}, Setup of Attributes {setup_attributes:#x}");
            let got = [UnsafeOperations::Refuse, UnsafeOperations::Allow].map(|grant| {
                let variables = password_variables(
                    VariableReach::BootServices,
                    VariableInterface::VariableServices,
                );
                variables.insert(setup(), setup_attributes, &[0]);
                let options = SetOptions {
                    unsafe_operations: grant,
                    ..SetOptions::default()
                };
                let got = set_responses(
                    &password_hiidb(),
                    question,
                    &SetValue::Text(value.to_owned()),
                    None,
                    &options,
                    SetAccess {
                        reads: shared(&variables),
                        writes: &*variables,
                        held: None,
                    },
                    None,
                )
                .map(drop)
                .map_err(|error| format!("{error:#}"));
                let writes = [setup(), amitse_setup()].map(|key| variables.writes_to(&key));
                (got, writes)
            });

            let [(refused, refused_writes), (allowed, allowed_writes)] = got;
            assert!(
                refused.as_ref().is_err_and(
                    |error| error.contains(refusal) && !error.contains(UNSAFE_OPERATIONS_FLAG)
                ),
                "{case}, Refuse: {refused:?}"
            );
            assert_eq!(allowed, refused, "{case}: Allow as Refuse");
            assert_eq!(
                (refused_writes, allowed_writes),
                ([vec![], vec![]], [vec![], vec![]]),
                "{case}: writes"
            );
        }
    }

    /// password_hiidb with the CHECKBOX O at byte 10 of AMITSESetup too, inside the PASSWORD's 40
    /// bytes.
    fn overlapping_password_hiidb() -> Vec<u8> {
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, 1),
                var_store(2, [0x44; 16], "AMITSESetup", 81),
                form(
                    1,
                    &[
                        checkbox_on(1, 1, 1),
                        password_on(3, 3, 2, 0),
                        checkbox_at(2, 2, 2, 80),
                        checkbox_at(4, 4, 2, 10),
                    ],
                ),
            ]),
            en_strings_package_of(&["Q", "P", "Password", "O"]),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid([0x55; 16], &packages.concat())
    }

    /// The answers of `question` that get gives in the HiiDB `hiidb` through `variables`.
    fn answers_of(hiidb: &[u8], question: &str, variables: &Rc<MemoryVariables>) -> Vec<String> {
        HiiBackend::get_in(
            hiidb,
            question,
            None,
            &GetOptions::default(),
            shared(variables),
            None,
            None,
            None,
        )
        .unwrap_or_else(|error| panic!("get {question}: {error:#}"))
        .responses
        .into_iter()
        .map(|response| response.question.answer)
        .collect()
    }

    /// set of `question` to `value` in the HiiDB `hiidb` through `variables` with
    /// UnsafeOperations::Allow, as the CLI prints an error.
    fn set_bypassing(
        hiidb: &[u8],
        question: &str,
        value: &str,
        variables: &Rc<MemoryVariables>,
    ) -> Result<(), String> {
        let options = SetOptions {
            unsafe_operations: UnsafeOperations::Allow,
            ..SetOptions::default()
        };
        set_responses(
            hiidb,
            question,
            &SetValue::Text(value.to_owned()),
            None,
            &options,
            SetAccess {
                reads: shared(variables),
                writes: &**variables,
                held: None,
            },
            None,
        )
        .map(drop)
        .map_err(|error| format!("{error:#}"))
    }

    /// The answer of a value whose bytes overlap a password's.
    const PASSWORD_BYTES: &str = "<ValueUnavailable: its bytes hold a password>";

    /// The end of the refusal of a HiiDB whose PASSWORDs may be in any variable
    /// (AnyVariablePasswords).
    const ANY_VARIABLE: &str = "; as a PASSWORD there may keep its password in any variable, \
                                uefisettings reads and writes no variable of this HiiDB";

    /// Whatever their reach, get and list-questions read a question of a VarStore that a password
    /// question names, P at byte 80, and set writes it, keeping the password's bytes; a question
    /// whose bytes overlap the password's, O at byte 10, is neither read nor written.
    #[test]
    fn only_the_bytes_of_password_questions_are_withheld() {
        let hiidb = overlapping_password_hiidb();
        for (reach, interface) in [
            (VariableReach::Runtime, VariableInterface::Efivarfs),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            ),
        ] {
            let variables = password_variables(reach, interface);
            let listed: BTreeMap<String, String> = HiiBackend::list_questions_in(
                &hiidb,
                &ListQuestionsOptions::default(),
                shared(&variables),
                None,
                None,
            )
            .expect("list questions")
            .into_iter()
            .map(|question| (question.name, question.answer))
            .collect();

            assert_eq!(
                answers_of(&hiidb, "P", &variables),
                ["1"],
                "{reach:?}: get P"
            );
            assert_eq!(
                answers_of(&hiidb, "O", &variables),
                [format!("{PASSWORD_BYTES} <IFR default: 0>")],
                "{reach:?}: get O"
            );
            assert_eq!(
                listed.get("P").map(String::as_str),
                Some("1"),
                "{reach:?}: list-questions P"
            );
            assert_eq!(
                listed.get("O"),
                Some(&format!("{PASSWORD_BYTES} <IFR default: 0>")),
                "{reach:?}: list-questions O"
            );

            assert_eq!(
                set_bypassing(&hiidb, "P", "0", &variables),
                Ok(()),
                "{reach:?}: set P"
            );
            let set = set_bypassing(&hiidb, "O", "0", &variables);
            assert!(
                set.as_ref().is_err_and(|error| error
                    .contains("holds a password at bytes 0..40, which set never writes")),
                "{reach:?}: set O: {set:?}"
            );
            assert_eq!(
                variables.writes_to(&amitse_setup()),
                [(80, vec![0])],
                "{reach:?}: writes to AMITSESetup"
            );
            assert_eq!(
                variables.bytes(&amitse_setup()),
                Some([&NV_BS_RT.to_ne_bytes()[..], &[0xAA; 80], &[0]].concat()),
                "{reach:?}: AMITSESetup keeps its password bytes"
            );
        }
    }

    /// The UCS-2 password "hunter2secret", NUL-padded to the 40 bytes of a PASSWORD of MaxSize 20.
    fn plaintext_password() -> Vec<u8> {
        let mut bytes: Vec<u8> = "hunter2secret"
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect();
        bytes.resize(40, 0);
        bytes
    }

    /// password_hiidb with the UINT64 NUMERICs N0, N8 and N16, shown in hex, at bytes 0, 8 and 16
    /// of AMITSESetup, inside the PASSWORD's 40 bytes.
    fn numerics_over_password_hiidb() -> Vec<u8> {
        let numeric = |id: u16, offset: u16| {
            let data = [
                question_header_with(id, id, 2, offset, 0x00),
                vec![0x23], // EFI_IFR_NUMERIC_SIZE_8 | EFI_IFR_DISPLAY_UINT_HEX
                0u64.to_le_bytes().to_vec(),
                u64::MAX.to_le_bytes().to_vec(),
                1u64.to_le_bytes().to_vec(),
            ]
            .concat();
            operation(NUMERIC, false, &data)
        };
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, 1),
                var_store(2, [0x44; 16], "AMITSESetup", 81),
                form(
                    1,
                    &[
                        checkbox_on(1, 1, 1),
                        password_on(3, 3, 2, 0),
                        checkbox_at(2, 2, 2, 80),
                        numeric(4, 0),
                        numeric(5, 8),
                        numeric(6, 16),
                    ],
                ),
            ]),
            en_strings_package_of(&["Q", "P", "Password", "N0", "N8", "N16"]),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid([0x55; 16], &packages.concat())
    }

    /// Through variables of either reach, get, list-questions and show-ifr show no byte of a
    /// password through the NUMERICs over it, each of which answers that its bytes hold one.
    #[test]
    fn numerics_over_a_password_show_no_byte_of_it() {
        let password = plaintext_password();
        let groups: Vec<(usize, u64)> = [0, 8, 16]
            .into_iter()
            .map(|offset| {
                let mut group = [0; 8];
                group.copy_from_slice(&password[offset..offset + 8]);
                (offset, u64::from_le_bytes(group))
            })
            .collect();
        let hiidb = numerics_over_password_hiidb();
        for (reach, interface) in [
            (VariableReach::Runtime, VariableInterface::Efivarfs),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            ),
        ] {
            let variables = MemoryVariables::new(reach, interface);
            variables.insert(setup(), NV_BS_RT, &[0]);
            variables.insert(
                amitse_setup(),
                NV_BS_RT,
                &[password.as_slice(), &[0xAA; 40], &[1]].concat(),
            );
            let variables = Rc::new(variables);
            let answers: Vec<String> = ["N0", "N8", "N16"]
                .into_iter()
                .flat_map(|name| answers_of(&hiidb, name, &variables))
                .collect();
            let listed: Vec<String> = HiiBackend::list_questions_in(
                &hiidb,
                &ListQuestionsOptions::default(),
                shared(&variables),
                None,
                None,
            )
            .expect("list questions")
            .into_iter()
            .filter(|question| question.name.starts_with('N'))
            .map(|question| question.answer)
            .collect();
            let ifr = HiiBackend::show_ifr_in(
                &hiidb,
                &ShowIfrOptions::default(),
                shared(&variables),
                None,
                None,
            )
            .expect("show the IFR")
            .to_string();

            let shown = format!("{answers:?} {listed:?} {ifr}").to_lowercase();
            let leaked: Vec<String> = groups
                .iter()
                .filter(|(_, value)| {
                    shown.contains(&format!("{value:x}")) || shown.contains(&value.to_string())
                })
                .map(|(offset, value)| {
                    let units: Vec<u16> = value
                        .to_le_bytes()
                        .chunks(2)
                        .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))
                        .collect();
                    format!(
                        "bytes {offset}..{}: {:?}",
                        offset + 8,
                        String::from_utf16_lossy(&units)
                    )
                })
                .collect();
            assert_eq!(
                leaked,
                Vec::<String>::new(),
                "{reach:?}: answers that show password bytes"
            );
            assert_eq!(answers, [PASSWORD_BYTES; 3], "{reach:?}: get");
            assert_eq!(listed, [PASSWORD_BYTES; 3], "{reach:?}: list-questions");
            assert_eq!(
                ifr.matches(&format!("-Answer: {PASSWORD_BYTES}\n")).count(),
                3,
                "{reach:?}: show-ifr {ifr:?}"
            );
        }
    }

    /// A VARSTORE_NAME_VALUE, or a VARSTORE_EFI before UEFI 2.3.1, of VarStoreId 2 outside any
    /// FormSet, before them, names no variable that edk2-stable202608 ConfigKeywordHandler.c
    /// FindStorageFromVarId, which takes the first VarStore of the id in the form package, would
    /// read a PASSWORD of that id from. The PASSWORD's FormSet declares AMITSESetup at its top,
    /// and the UINT64 NUMERIC N0 of a FormSet before it is over bytes 0..8 of that password: get
    /// N0 answers that its bytes hold a password through variables that reach Runtime, and fails
    /// closed through those that reach BootServices. Beside the VARSTORE_NAME_VALUE, whose driver
    /// may keep the password in any variable, it fails closed through Runtime too.
    #[test]
    fn an_outside_var_store_of_a_password_s_id_without_a_variable_shows_no_password_byte() {
        let numeric = [
            question_header_with(4, 4, 2, 0, 0x00),
            vec![0x23], // EFI_IFR_NUMERIC_SIZE_8 | EFI_IFR_DISPLAY_UINT_HEX
            0u64.to_le_bytes().to_vec(),
            u64::MAX.to_le_bytes().to_vec(),
            1u64.to_le_bytes().to_vec(),
        ]
        .concat();
        for (case, outside, runtime) in [
            (
                "a VARSTORE_NAME_VALUE",
                var_store_name_value(2, [0x66; 16]),
                Err(ANY_VARIABLE),
            ),
            (
                "an EFI_IFR_VARSTORE_EFI before UEFI 2.3.1",
                short_var_store_efi(2),
                Ok(vec![PASSWORD_BYTES.to_string()]),
            ),
        ] {
            let packages = [
                form_package_of(
                    &[
                        outside,
                        form_set(&[
                            var_store(2, [0x44; 16], "AMITSESetup", 81),
                            form(1, &[operation(NUMERIC, false, &numeric)]),
                        ]),
                        form_set(&[
                            var_store(2, [0x44; 16], "AMITSESetup", 81),
                            form(1, &[password_on(3, 3, 2, 0)]),
                        ]),
                    ]
                    .concat(),
                ),
                en_strings_package_of(&["Q", "P", "Password", "N0"]),
                END_PACKAGE.to_vec(),
            ];
            let hiidb = package_list_with_guid([0x55; 16], &packages.concat());
            for (reach, interface) in [
                (VariableReach::Runtime, VariableInterface::Efivarfs),
                (
                    VariableReach::BootServices,
                    VariableInterface::VariableServices,
                ),
            ] {
                let variables = MemoryVariables::new(reach, interface);
                variables.insert(
                    amitse_setup(),
                    NV_BS_RT,
                    &[plaintext_password().as_slice(), &[0xAA; 40], &[1]].concat(),
                );

                let got = answers_or_error_of(&hiidb, "N0", &Rc::new(variables));

                match reach {
                    VariableReach::Runtime => match &runtime {
                        Ok(want) => assert_eq!(got.as_ref(), Ok(want), "{case}: {reach:?}"),
                        Err(suffix) => assert!(
                            got.as_ref().is_err_and(|error| error.ends_with(suffix)),
                            "{case}: {reach:?}: {got:?}"
                        ),
                    },
                    VariableReach::BootServices => assert!(
                        got.as_ref().is_err_and(|error| error.contains(&format!(
                            "{case} outside a FormSet, at offset 0 of a form package, declares \
                             its VarStoreId"
                        ))),
                        "{case}: {reach:?}: {got:?}"
                    ),
                }
            }
        }
    }

    /// A question selected by its FormSet's GUID and QuestionId, the UINT64 NUMERIC N0 over bytes
    /// 0..8 of AMITSESetup, keeps the bytes of a PASSWORD outside any FormSet of its VarStoreId
    /// withheld: through variables that reach Runtime get answers that its bytes hold a password
    /// and set refuses it; through those that reach BootServices both fail closed; set writes
    /// nothing.
    #[test]
    fn a_question_selected_by_question_id_keeps_an_outside_password_withheld() {
        let numeric = [
            question_header_with(4, 4, 2, 0, 0x00),
            vec![0x23], // EFI_IFR_NUMERIC_SIZE_8 | EFI_IFR_DISPLAY_UINT_HEX
            0u64.to_le_bytes().to_vec(),
            u64::MAX.to_le_bytes().to_vec(),
            1u64.to_le_bytes().to_vec(),
        ]
        .concat();
        let packages = [
            form_package_of(
                &[
                    password_on(3, 3, 2, 0),
                    form_set(&[
                        var_store(2, [0x44; 16], "AMITSESetup", 81),
                        form(1, &[operation(NUMERIC, false, &numeric)]),
                    ]),
                ]
                .concat(),
            ),
            en_strings_package_of(&["Q", "P", "Password", "N0"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x55; 16], &packages.concat());
        let question = by_address("11111111-1111-1111-1111-111111111111:4");
        let stored = [plaintext_password().as_slice(), &[0xAA; 40], &[1]].concat();
        let options = SetOptions {
            unsafe_operations: UnsafeOperations::Allow,
            ..SetOptions::default()
        };
        for (reach, interface) in [
            (VariableReach::Runtime, VariableInterface::Efivarfs),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            ),
        ] {
            let variables = MemoryVariables::new(reach, interface);
            variables.insert(amitse_setup(), NV_BS_RT, &stored);
            let variables = Rc::new(variables);

            let got = HiiBackend::get_in(
                &hiidb,
                question.clone(),
                None,
                &GetOptions::default(),
                shared(&variables),
                None,
                None,
                None,
            )
            .map(|got| {
                got.responses
                    .into_iter()
                    .map(|response| response.question.answer)
                    .collect::<Vec<_>>()
            })
            .map_err(|error| format!("{error:#}"));
            let set = set_responses(
                &hiidb,
                question.clone(),
                &SetValue::Text("1".to_owned()),
                None,
                &options,
                SetAccess {
                    reads: shared(&variables),
                    writes: &*variables,
                    held: None,
                },
                None,
            )
            .map(|_| ())
            .map_err(|error| format!("{error:#}"));

            let (got_refusal, set_refusal) = match reach {
                VariableReach::Runtime => {
                    assert_eq!(got, Ok(vec![PASSWORD_BYTES.to_string()]), "{reach:?}: get");
                    (
                        None,
                        "holds a password at bytes 0..40, which set never writes",
                    )
                }
                VariableReach::BootServices => {
                    let outside = "outside a FormSet, at offset 0 of a form package";
                    (Some(outside), outside)
                }
            };
            if let Some(refusal) = got_refusal {
                assert!(
                    got.as_ref().is_err_and(|error| error.contains(refusal)),
                    "{reach:?}: get: {got:?}"
                );
            }
            assert!(
                set.as_ref().is_err_and(|error| error.contains(set_refusal)),
                "{reach:?}: set: {set:?}"
            );
            assert_eq!(
                variables.writes_to(&amitse_setup()),
                [],
                "{reach:?}: writes to AMITSESetup"
            );
        }
    }

    /// A PASSWORD outside any FormSet whose VarStoreId names a VARSTORE_EFI before UEFI 2.3.1 of a
    /// FormSet, VarStoreInfo 5, keeps the variable that string 5 names as a VarName withheld: the
    /// CHECKBOX C of that VarName, at byte 0 of ShortVarPw of the store's Guid, answers that its
    /// bytes hold a password through variables that reach Runtime, and set refuses it; through
    /// those that reach BootServices both fail closed; set writes nothing.
    #[test]
    fn a_password_outside_a_form_set_keeps_the_variable_of_its_var_name_withheld() {
        let ifr = [
            password_on(9, 3, 7, 5),
            form_set(&[short_var_store_efi(7), form(1, &[checkbox_at(4, 4, 7, 5)])]),
        ];
        let packages = [
            form_package_of(&ifr.concat()),
            en_strings_package_of(&["Q", "P", "Password", "C", "ShortVarPw"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x55; 16], &packages.concat());
        for (reach, interface) in [
            (VariableReach::Runtime, VariableInterface::Efivarfs),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            ),
        ] {
            let variables = MemoryVariables::new(reach, interface);
            variables.insert(short_key("ShortVarPw"), NV_BS_RT, &plaintext_password());
            let variables = Rc::new(variables);

            let got = answers_or_error_of(&hiidb, "C", &variables);
            let set = set_bypassing(&hiidb, "C", "0", &variables);

            let (got_ok, refusal) = match reach {
                VariableReach::Runtime => (true, "holds a password at bytes 0..40"),
                VariableReach::BootServices => {
                    (false, "outside a FormSet, at offset 0 of a form package")
                }
            };
            if got_ok {
                assert!(
                    got.as_ref().is_ok_and(
                        |answers| answers.len() == 1 && answers[0].starts_with(PASSWORD_BYTES)
                    ),
                    "{reach:?}: get: {got:?}"
                );
            } else {
                assert!(
                    got.as_ref().is_err_and(|error| error.contains(refusal)),
                    "{reach:?}: get: {got:?}"
                );
            }
            assert!(
                set.as_ref().is_err_and(|error| error.contains(refusal)),
                "{reach:?}: set: {set:?}"
            );
            assert_eq!(
                variables.writes_to(&short_key("ShortVarPw")),
                [],
                "{reach:?}: writes to ShortVarPw"
            );
        }
    }

    /// The HiiDB of one package list whose form package holds `ifr` and whose strings are those of
    /// the tests of first declarations: string 4 is N0 and string 5 ShortVarPw.
    fn first_declarations_hiidb(ifr: &[Vec<u8>]) -> Vec<u8> {
        let packages = [
            form_package_of(&ifr.concat()),
            en_strings_package_of(&["Q", "P", "Password", "N0", "ShortVarPw"]),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid([0x55; 16], &packages.concat())
    }

    /// The FormSet B of the tests of first declarations: its PASSWORD of VarStoreId 2 and
    /// VarStoreInfo 5 on its AMITSESetup.
    fn form_set_b() -> Vec<u8> {
        form_set(&[
            var_store(2, [0x44; 16], "AMITSESetup", 81),
            form(1, &[password_on(3, 3, 2, 5)]),
        ])
    }

    /// The variable Other of the tests of first declarations.
    fn other() -> VariableKey {
        VariableKey {
            name: "Other".to_string(),
            guid: Guid::from([0x77; 16]),
        }
    }

    /// MemoryVariables of `reach` and `interface` with AMITSESetup and Other, whose bytes 0..5
    /// hold 1, bytes 5..45 the password plaintext_password, and the rest 0xAA.
    fn first_declarations_variables(
        reach: VariableReach,
        interface: VariableInterface,
    ) -> Rc<MemoryVariables> {
        let variables = MemoryVariables::new(reach, interface);
        variables.insert(amitse_setup(), NV_BS_RT, &[0; 81]);
        variables.insert(
            other(),
            NV_BS_RT,
            &[&[1; 5][..], &plaintext_password(), &[0xAA; 36]].concat(),
        );
        Rc::new(variables)
    }

    /// The children of the FormSet A of the tests of first declarations: its VarStore Other of
    /// VarStoreId 2 and a form with the UINT64 NUMERIC N0 over Other's bytes 5..13.
    fn form_set_a_children() -> [Vec<u8>; 2] {
        let n0 = operation(
            NUMERIC,
            false,
            &[
                question_header_with(4, 4, 2, 5, 0x00),
                vec![0x13], // EFI_IFR_NUMERIC_SIZE_8 | EFI_IFR_DISPLAY_UINT_DEC
                0u64.to_le_bytes().to_vec(),
                u64::MAX.to_le_bytes().to_vec(),
                1u64.to_le_bytes().to_vec(),
            ]
            .concat(),
        );
        [var_store(2, [0x77; 16], "Other", 81), form(1, &[n0])]
    }

    /// Asserts that through variables of either reach, N0 of `hiidb` answers that its bytes hold
    /// a password and set refuses it, with nothing written to Other, in the case `case`.
    fn assert_n0_withheld(case: &str, hiidb: &[u8]) {
        for (reach, interface) in [
            (VariableReach::Runtime, VariableInterface::Efivarfs),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            ),
        ] {
            let variables = first_declarations_variables(reach, interface);

            let got = answers_or_error_of(hiidb, "N0", &variables);
            let set = set_bypassing(hiidb, "N0", "1", &variables);

            assert!(
                got.as_ref().is_ok_and(
                    |answers| answers.len() == 1 && answers[0].starts_with(PASSWORD_BYTES)
                ),
                "{case}: {reach:?}: get: {got:?}"
            );
            assert!(
                set.as_ref()
                    .is_err_and(|error| error.contains("holds a password at bytes 5..45")),
                "{case}: {reach:?}: set: {set:?}"
            );
            assert_eq!(
                variables.writes_to(&other()),
                [],
                "{case}: {reach:?}: writes to Other"
            );
        }
    }

    /// Other, which FormSet A declares for VarStoreId 2 before FormSet B, whose PASSWORD is on id
    /// 2 at VarOffset 5, is the first VarStore of that id in their form package, where a keyword
    /// request of that PASSWORD lands (edk2-stable202608 ConfigKeywordHandler.c
    /// FindStorageFromVarId :1520): the UINT64 NUMERIC N0 of FormSet A over its bytes 5..13, which
    /// hold that password, answers that they do and set refuses it, through variables of either
    /// reach, with nothing written. Where FormSet B comes first, its own AMITSESetup is the
    /// first, and N0 reads Other.
    #[test]
    fn the_first_var_store_of_a_password_s_id_in_an_earlier_form_set_is_withheld() {
        let form_set_a = form_set_with_guid([0x12; 16], &form_set_a_children());
        // "hunt", the first 4 CHAR16s of the password, as N0 reads them
        let hunt = "32651569752506472".to_string();
        for (case, ifr, withheld) in [
            ("Other first", [form_set_a.clone(), form_set_b()], true),
            ("AMITSESetup first", [form_set_b(), form_set_a], false),
        ] {
            let hiidb = first_declarations_hiidb(&ifr);
            if withheld {
                assert_n0_withheld(case, &hiidb);
                continue;
            }
            for (reach, interface) in [
                (VariableReach::Runtime, VariableInterface::Efivarfs),
                (
                    VariableReach::BootServices,
                    VariableInterface::VariableServices,
                ),
            ] {
                let variables = first_declarations_variables(reach, interface);

                let got = answers_or_error_of(&hiidb, "N0", &variables);

                assert_eq!(got, Ok(vec![hunt.clone()]), "{case}: {reach:?}: get");
            }
        }
    }

    /// A FormSet nested in another is another FormSet either way round, as FindStorageFromVarId
    /// walks the form package op by op: where FormSet A declares Other for VarStoreId 2 and then
    /// nests FormSet B, whose PASSWORD is on id 2 of its own AMITSESetup, and where a FormSet C
    /// nests A first, with C's PASSWORD on C's AMITSESetup, Other is the first VarStore of id 2
    /// and keeps the password: N0 of A answers that its bytes hold a password and set refuses it,
    /// writing nothing, through variables of either reach.
    #[test]
    fn the_first_var_store_of_a_nesting_or_nested_form_set_is_withheld() {
        let b_nested_in_a =
            form_set_with_guid([0x12; 16], &[form_set_a_children().concat(), form_set_b()]);
        let a_nested_in_c = form_set_with_guid(
            [0x13; 16],
            &[
                form_set_with_guid([0x12; 16], &form_set_a_children()),
                var_store(2, [0x44; 16], "AMITSESetup", 81),
                form(2, &[password_on(3, 3, 2, 5)]),
            ],
        );
        for (case, ifr) in [
            ("B nested in A after Other", b_nested_in_a),
            ("A nested first in C, C's PASSWORD", a_nested_in_c),
        ] {
            assert_n0_withheld(case, &first_declarations_hiidb(&[ifr]));
        }
    }

    /// Where FormSet A declares a VARSTORE_NAME_VALUE or a VARSTORE_EFI before UEFI 2.3.1 for
    /// VarStoreId 2 before FormSet B, whose PASSWORD is on id 2, the first VarStore of that id in
    /// their form package names no variable, and no variable is known to hold the password:
    /// through variables that reach BootServices, get and set of the CHECKBOX N0 of FormSet A
    /// fail closed, writing nothing. Through those that reach Runtime, beside the
    /// VARSTORE_NAME_VALUE, whose driver may keep the password in any variable, N0 on VarStore 5,
    /// Other, fails closed too; N0 of the VarName that the PASSWORD's VarStoreInfo names on the
    /// short VarStore, string 5, at byte 0 of ShortVarPw of its Guid, answers that its bytes hold
    /// a password and set refuses it.
    #[test]
    fn a_first_var_store_naming_no_variable_in_an_earlier_form_set_fails_closed() {
        for (case, store, n0, refusal, runtime_withheld) in [
            (
                "VARSTORE_NAME_VALUE",
                var_store_name_value(2, [0x77; 16]),
                checkbox_at(4, 4, 5, 0),
                "is a VARSTORE_NAME_VALUE of FormSet",
                false,
            ),
            (
                "VARSTORE_EFI before UEFI 2.3.1",
                short_var_store_efi(2),
                checkbox_at(4, 4, 2, 5),
                "is an EFI_IFR_VARSTORE_EFI before UEFI 2.3.1 of FormSet",
                true,
            ),
        ] {
            let form_set_a = form_set_with_guid(
                [0x12; 16],
                &[store, var_store(5, [0x77; 16], "Other", 81), form(1, &[n0])],
            );
            let hiidb = first_declarations_hiidb(&[form_set_a, form_set_b()]);
            for (reach, interface) in [
                (VariableReach::Runtime, VariableInterface::Efivarfs),
                (
                    VariableReach::BootServices,
                    VariableInterface::VariableServices,
                ),
            ] {
                let variables = first_declarations_variables(reach, interface);
                variables.insert(short_key("ShortVarPw"), NV_BS_RT, &plaintext_password());

                let got = answers_or_error_of(&hiidb, "N0", &variables);
                let set = set_bypassing(&hiidb, "N0", "0", &variables);

                match (reach, runtime_withheld) {
                    (VariableReach::BootServices, _) => {
                        for (step, result) in [("get", got.map(drop)), ("set", set)] {
                            assert!(
                                result.as_ref().is_err_and(|error| error.contains(refusal)),
                                "{case}: {reach:?}: {step}: {result:?}"
                            );
                        }
                    }
                    (VariableReach::Runtime, true) => {
                        assert!(
                            got.as_ref().is_ok_and(|answers| answers.len() == 1
                                && answers[0].starts_with(PASSWORD_BYTES)),
                            "{case}: {reach:?}: get: {got:?}"
                        );
                        assert!(
                            set.as_ref().is_err_and(
                                |error| error.contains("holds a password at bytes 0..40")
                            ),
                            "{case}: {reach:?}: set: {set:?}"
                        );
                    }
                    (VariableReach::Runtime, false) => {
                        for (step, result) in [("get", got.map(drop)), ("set", set)] {
                            assert!(
                                result.as_ref().is_err_and(|error| error.contains(refusal)
                                    && error.ends_with(ANY_VARIABLE)),
                                "{case}: {reach:?}: {step}: {result:?}"
                            );
                        }
                    }
                }
                assert_eq!(
                    variables.writes_to(&short_key("ShortVarPw")),
                    [],
                    "{case}: {reach:?}: writes to ShortVarPw"
                );
                if (reach, runtime_withheld) != (VariableReach::Runtime, true) {
                    assert_eq!(
                        variables.writes_to(&other()),
                        [],
                        "{case}: {reach:?}: writes to Other"
                    );
                }
            }
        }
    }

    /// A HiiDB whose AMITSESetup has a PASSWORD at bytes 40..80, the UINT16 NUMERIC S at bytes
    /// 39..41, across its start, and the UINT16 NUMERIC E at bytes 79..81, across its end.
    fn straddling_password_hiidb() -> Vec<u8> {
        let uint16 = |id: u16, offset: u16| {
            let data = [
                question_header_with(id, id, 1, offset, 0x00),
                vec![0x11], // EFI_IFR_NUMERIC_SIZE_2 | EFI_IFR_DISPLAY_UINT_DEC
                0u16.to_le_bytes().to_vec(),
                u16::MAX.to_le_bytes().to_vec(),
                1u16.to_le_bytes().to_vec(),
            ]
            .concat();
            operation(NUMERIC, false, &data)
        };
        let packages = [
            form_package(&[
                var_store(1, [0x44; 16], "AMITSESetup", 81),
                form(1, &[password_on(3, 3, 1, 40), uint16(1, 39), uint16(2, 79)]),
            ]),
            en_strings_package_of(&["S", "E", "Password"]),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid([0x55; 16], &packages.concat())
    }

    /// Through variables of either reach, a value across the start or the end of a password's
    /// bytes is neither read nor written: get answers that its bytes hold a password, and set
    /// refuses it with nothing written.
    #[test]
    fn values_across_the_edges_of_a_password_are_neither_read_nor_written() {
        let hiidb = straddling_password_hiidb();
        let stored = [&[0x11; 40][..], &plaintext_password(), &[1]].concat();
        for (reach, interface) in [
            (VariableReach::Runtime, VariableInterface::Efivarfs),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            ),
        ] {
            let variables = MemoryVariables::new(reach, interface);
            variables.insert(amitse_setup(), NV_BS_RT, &stored);
            let variables = Rc::new(variables);

            for question in ["S", "E"] {
                assert_eq!(
                    answers_of(&hiidb, question, &variables),
                    [PASSWORD_BYTES],
                    "{reach:?}: get {question}"
                );
                let set = set_bypassing(&hiidb, question, "1", &variables);
                assert!(
                    set.as_ref().is_err_and(|error| error
                        .contains("holds a password at bytes 40..80, which set never writes")),
                    "{reach:?}: set {question}: {set:?}"
                );
            }
            assert_eq!(
                variables.writes_to(&amitse_setup()),
                [],
                "{reach:?}: writes to AMITSESetup"
            );
            assert_eq!(
                variables.bytes(&amitse_setup()),
                Some([&NV_BS_RT.to_ne_bytes()[..], &stored].concat()),
                "{reach:?}: AMITSESetup"
            );
        }
    }

    /// set of the NUMERIC W, at byte 0 of the EFI variable Setup, whose WRITE expression sets Setup
    /// and then byte 10 of AMITSESetup, inside the PASSWORD's 40 bytes, refuses before any write
    /// through variables of each interface: neither Setup nor AMITSESetup is written.
    #[test]
    fn a_plan_over_two_variables_writes_nothing() {
        const AND: u8 = 0x15;
        const SET: u8 = 0x2C;
        const THIS: u8 = 0x58;
        const WRITE: u8 = 0x2E;
        // a SET of a UINT8 (EFI_IFR_TYPE_NUM_SIZE_8)
        let set = |var_store_id: u16, offset: u16| {
            let data = [
                &var_store_id.to_le_bytes()[..],
                &offset.to_le_bytes(),
                &[0x00],
            ]
            .concat();
            operation(SET, false, &data)
        };
        let numeric = [
            operation(
                NUMERIC,
                true,
                &[
                    question_header_with(4, 4, 1, 0, 0x00),
                    // EFI_IFR_NUMERIC_SIZE_1 | EFI_IFR_DISPLAY_UINT_DEC, from 0 to 255, step 1
                    vec![0x10, 0, 255, 1],
                ]
                .concat(),
            ),
            operation(WRITE, false, &[]),
            operation(THIS, true, &[]),
            set(1, 0),
            operation(THIS, false, &[]),
            set(2, 10),
            operation(AND, false, &[]),
            END.to_vec(),
            END.to_vec(),
        ]
        .concat();
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, 1),
                var_store(2, [0x44; 16], "AMITSESetup", 81),
                form(1, &[password_on(3, 3, 2, 0), numeric]),
            ]),
            en_strings_package_of(&["Q", "P", "Password", "W"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x55; 16], &packages.concat());

        for (reach, interface) in [
            (VariableReach::Runtime, VariableInterface::Efivarfs),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            ),
            (
                VariableReach::Runtime,
                VariableInterface::FirmwareEnvironment,
            ),
        ] {
            let variables = password_variables(reach, interface);

            let set = set_bypassing(&hiidb, "W", "5", &variables);

            assert_eq!(
                set,
                Err("cannot set question \"W\": EFI variable \
                     AMITSESetup-44444444-4444-4444-4444-444444444444 holds a password at bytes \
                     0..40, which set never writes"
                    .to_string()),
                "{interface:?}: set W"
            );
            assert_eq!(
                variables.writes_to(&setup()),
                [],
                "{interface:?}: writes to Setup"
            );
            assert_eq!(
                variables.writes_to(&amitse_setup()),
                [],
                "{interface:?}: writes to AMITSESetup"
            );
        }
    }

    /// The VarStores "A/B" and "A!B" of one GUID are one efivar file: efivarfs names a variable's
    /// file with '!' for each '/' (Linux v7.2 fs/efivarfs/vars.c efivar_get_utf8name()). get and
    /// list-questions show no byte of a PASSWORD on "A/B" through the NUMERIC N0 on "A!B" over
    /// it, and show the CHECKBOX O on "A!B" beside it.
    #[cfg(efivar_dumps)]
    #[test]
    fn a_password_under_an_aliased_var_store_name_is_withheld() {
        let numeric = [
            question_header_with(4, 4, 2, 0, 0x00),
            vec![0x23], // EFI_IFR_NUMERIC_SIZE_8 | EFI_IFR_DISPLAY_UINT_HEX
            0u64.to_le_bytes().to_vec(),
            u64::MAX.to_le_bytes().to_vec(),
            1u64.to_le_bytes().to_vec(),
        ]
        .concat();
        let packages = [
            form_package(&[
                var_store(1, [0x44; 16], "A/B", 81),
                var_store(2, [0x44; 16], "A!B", 81),
                form(
                    1,
                    &[
                        password_on(3, 3, 1, 0),
                        operation(NUMERIC, false, &numeric),
                        checkbox_at(5, 5, 2, 80),
                    ],
                ),
            ]),
            en_strings_package_of(&["Q", "P", "Password", "N0", "O"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x55; 16], &packages.concat());
        let dir = tempfile::tempdir().expect("create efivars directory");
        let key = VariableKey {
            name: "A/B".to_string(),
            guid: amitse_setup().guid,
        };
        std::fs::write(
            dir.path().join(key.to_string()),
            [
                &NV_BS_RT.to_ne_bytes()[..],
                &plaintext_password(),
                &[0xAA; 40],
                &[1],
            ]
            .concat(),
        )
        .expect("write the efivar file");
        let variables = || {
            EfivarSource::Directory(dir.path().to_path_buf())
                .into_variables()
                .expect("variables of the directory")
        };

        for (question, want) in [("N0", PASSWORD_BYTES), ("O", "1")] {
            let got: Vec<String> = HiiBackend::get_in(
                &hiidb,
                question,
                None,
                &GetOptions::default(),
                variables(),
                None,
                None,
                None,
            )
            .unwrap_or_else(|error| panic!("get {question}: {error:#}"))
            .responses
            .into_iter()
            .map(|response| response.question.answer)
            .collect();
            let listed: Vec<String> = HiiBackend::list_questions_in(
                &hiidb,
                &ListQuestionsOptions::default(),
                variables(),
                None,
                None,
            )
            .expect("list questions")
            .into_iter()
            .filter(|listed| listed.name == question)
            .map(|listed| listed.answer)
            .collect();

            assert_eq!(got, [want], "get {question}");
            assert_eq!(listed, [want], "list-questions {question}");
        }
    }

    /// Through variables of either reach, a password in a variable with
    /// EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS is withheld where its value starts, after the
    /// metadata (UEFI 2.11 §8.2.1): O, over the password, answers that its bytes hold one, and P,
    /// beside it, shows its value.
    #[test]
    fn a_password_behind_metadata_is_withheld_where_the_value_starts() {
        let hiidb = overlapping_password_hiidb();
        for (reach, interface) in [
            (VariableReach::Runtime, VariableInterface::Efivarfs),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            ),
        ] {
            let variables = MemoryVariables::new(reach, interface);
            variables.insert(setup(), NV_BS_RT, &[0]);
            variables.insert(
                amitse_setup(),
                NV_BS_RT | VariableAttributes::ENHANCED_AUTHENTICATED_ACCESS.bits(),
                &[&timestamp_metadata()[..], &[0xAA; 80], &[1]].concat(),
            );
            let variables = Rc::new(variables);

            assert_eq!(
                answers_of(&hiidb, "P", &variables),
                ["1"],
                "{reach:?}: get P"
            );
            assert_eq!(
                answers_of(&hiidb, "O", &variables),
                [format!("{PASSWORD_BYTES} <IFR default: 0>")],
                "{reach:?}: get O"
            );
        }
    }

    /// A HiiDB whose FormSet has the CHECKBOX Q at byte 0 of the EFI variable Setup, which its
    /// VARSTORE_EFI declares NV|BS.
    fn boot_service_only_hiidb() -> Vec<u8> {
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS, 1),
                form(1, &[checkbox_on(1, 1, 1)]),
            ]),
            en_strings_package_of(&["Q"]),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid([0x55; 16], &packages.concat())
    }

    /// set decides, through variables that reach Runtime, through efivarfs or the firmware
    /// environment calls, by the attributes of the variable of a VARSTORE_EFI declared NV|BS: it
    /// refuses the variable without EFI_VARIABLE_RUNTIME_ACCESS before any write, and writes the
    /// one with it, keeping them.
    #[test]
    fn set_decides_runtime_access_by_the_variables_own_attributes() {
        let refusal = "EFI variable Setup-00000000-0000-0000-0000-000000000000 has no \
                       EFI_VARIABLE_RUNTIME_ACCESS (attributes 0x3), so the firmware refuses to \
                       write it at OS runtime";
        let cases = [
            (NV_BS, Err(refusal), vec![], vec![3, 0, 0, 0, 0]),
            (NV_BS_RT, Ok(()), vec![(0, vec![1])], vec![7, 0, 0, 0, 1]),
        ];

        for interface in [
            VariableInterface::Efivarfs,
            VariableInterface::FirmwareEnvironment,
        ] {
            for (attributes, want, want_writes, want_bytes) in cases.clone() {
                let variables = MemoryVariables::new(VariableReach::Runtime, interface);
                variables.insert(setup(), attributes, &[0]);
                let variables = Rc::new(variables);

                let got = set_responses(
                    &boot_service_only_hiidb(),
                    "Q",
                    &SetValue::Text("1".to_owned()),
                    None,
                    &SetOptions::default(),
                    SetAccess {
                        reads: shared(&variables),
                        writes: &*variables,
                        held: None,
                    },
                    None,
                );

                let case = format!("{interface:?}, attributes {attributes:#x}");
                assert_eq!(
                    got.map(drop).map_err(|error| error.to_string()),
                    want.map_err(str::to_string),
                    "{case}"
                );
                assert_eq!(variables.writes_to(&setup()), want_writes, "{case}: writes");
                assert_eq!(variables.bytes(&setup()), Some(want_bytes), "{case}: bytes");
            }
        }
    }

    /// Through variables that reach BootServices, set with VolatileWrites::Allow writes a volatile
    /// variable (UEFI 2.11 §8.2.3: only ExitBootServices ends volatile writes), past both
    /// choice_for_set and the backend's check, and its answer says that the value is volatile; a
    /// non-volatile variable's answer does not.
    #[test]
    fn set_writes_a_volatile_variable_if_allowed_before_exit_boot_services() {
        let cases = [
            (
                BS_RT,
                "1 <volatile: lasts until the next reset or power cycle>",
            ),
            (NV_BS_RT, "1"),
        ];
        for (attributes, want_answer) in cases {
            let variables = MemoryVariables::new(
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            );
            variables.insert(setup(), attributes, &[0]);
            let variables = Rc::new(variables);
            let options = SetOptions {
                volatile: VolatileWrites::Allow,
                ..SetOptions::default()
            };

            let got = set_responses(
                &boot_service_only_hiidb(),
                "Q",
                &SetValue::Text("1".to_owned()),
                None,
                &options,
                SetAccess {
                    reads: shared(&variables),
                    writes: &*variables,
                    held: None,
                },
                None,
            );

            let case = format!("attributes {attributes:#x}");
            let answers = got.map(|list| {
                list.responses
                    .into_iter()
                    .map(|response| response.question.answer)
                    .collect::<Vec<_>>()
            });
            assert_eq!(
                answers.map_err(|error| error.to_string()),
                Ok(vec![want_answer.to_string()]),
                "{case}: answers"
            );
            assert_eq!(
                variables.writes_to(&setup()),
                vec![(0, vec![1])],
                "{case}: writes"
            );
            assert_eq!(
                variables.bytes(&setup()),
                Some([&attributes.to_ne_bytes()[..], &[1]].concat()),
                "{case}: bytes"
            );
        }
    }

    /// set refuses a volatile variable before any write without VolatileWrites::Allow, and
    /// through variables that reach Runtime whatever the policy, keeping it.
    #[test]
    fn set_refuses_a_volatile_variable_unless_allowed_before_exit_boot_services() {
        let cases = [
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
                VolatileWrites::Refuse,
                ", so a write would not outlast a power cycle; pass --allow-volatile to write it \
                 anyway",
            ),
            (
                VariableReach::Runtime,
                VariableInterface::Efivarfs,
                VolatileWrites::Allow,
                " and cannot be written through efivarfs",
            ),
            (
                VariableReach::Runtime,
                VariableInterface::FirmwareEnvironment,
                VolatileWrites::Allow,
                ", so a write would not outlast a power cycle",
            ),
        ];
        for (reach, interface, volatile, refusal) in cases {
            let variables = MemoryVariables::new(reach, interface);
            variables.insert(setup(), BS_RT, &[0]);
            let variables = Rc::new(variables);
            let options = SetOptions {
                volatile,
                ..SetOptions::default()
            };

            let got = set_responses(
                &boot_service_only_hiidb(),
                "Q",
                &SetValue::Text("1".to_owned()),
                None,
                &options,
                SetAccess {
                    reads: shared(&variables),
                    writes: &*variables,
                    held: None,
                },
                None,
            );

            let case = format!("{reach:?}, {interface:?}, {volatile:?}");
            assert_eq!(
                got.map(drop).map_err(|error| error.to_string()),
                Err(format!(
                    "EFI variable Setup-00000000-0000-0000-0000-000000000000 is volatile (no \
                     EFI_VARIABLE_NON_VOLATILE){refusal}"
                )),
                "{case}"
            );
            assert_eq!(variables.writes_to(&setup()), vec![], "{case}: writes");
            assert_eq!(
                variables.bytes(&setup()),
                Some(vec![6, 0, 0, 0, 0]),
                "{case}: bytes"
            );
        }
    }

    /// set's write follows SetOptions::volatile past choice_for_set: a variable that the read finds
    /// non-volatile and the write finds volatile is refused by the backend's check under
    /// VolatileWrites::Refuse, writing nothing, and written under Allow.
    #[test]
    fn set_writes_by_the_volatile_policy_past_choice_for_set() {
        let refusal = "EFI variable Setup-00000000-0000-0000-0000-000000000000 is volatile (no \
                       EFI_VARIABLE_NON_VOLATILE), so a write would not outlast a power cycle; \
                       pass --allow-volatile to write it anyway";
        let cases = [
            (VolatileWrites::Refuse, Err(refusal), vec![]),
            (VolatileWrites::Allow, Ok(()), vec![(0, vec![1])]),
        ];
        let variables_reaching_boot_services = || {
            MemoryVariables::new(
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            )
        };
        for (volatile, want, want_writes) in cases {
            let reads = variables_reaching_boot_services();
            reads.insert(setup(), NV_BS_RT, &[0]);
            let reads = Rc::new(reads);
            let writes = variables_reaching_boot_services();
            writes.insert(setup(), BS_RT, &[0]);
            let options = SetOptions {
                volatile,
                ..SetOptions::default()
            };

            let got = set_responses(
                &boot_service_only_hiidb(),
                "Q",
                &SetValue::Text("1".to_owned()),
                None,
                &options,
                SetAccess {
                    reads: shared(&reads),
                    writes: &writes,
                    held: None,
                },
                None,
            );

            assert_eq!(
                got.map(drop).map_err(|error| error.to_string()),
                want.map_err(str::to_string),
                "{volatile:?}"
            );
            assert_eq!(
                writes.writes_to(&setup()),
                want_writes,
                "{volatile:?}: writes"
            );
        }
    }

    /// set of the items of an ORDERED_LIST on a volatile variable follows SetOptions::volatile:
    /// refused before any write under VolatileWrites::Refuse, written under Allow with an answer
    /// that says that the value is volatile.
    #[test]
    fn set_of_an_ordered_list_on_a_volatile_variable_follows_the_volatile_policy() {
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, 2),
                form(
                    1,
                    &[
                        operation(
                            ORDERED_LIST,
                            true,
                            &[question_header_with(1, 1, 1, 0, 0x00), vec![2, 0x00]].concat(),
                        ),
                        flagged_option(2, 0x00, 1),
                        flagged_option(3, 0x00, 2),
                        END.to_vec(),
                    ],
                ),
            ]),
            en_strings_package_of(&["L", "A", "B"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x55; 16], &packages.concat());
        let refusal = "EFI variable Setup-00000000-0000-0000-0000-000000000000 is volatile (no \
                       EFI_VARIABLE_NON_VOLATILE), so a write would not outlast a power cycle; \
                       pass --allow-volatile to write it anyway";
        let cases = [
            (VolatileWrites::Refuse, Err(refusal.to_string()), vec![]),
            (
                VolatileWrites::Allow,
                Ok(vec![
                    "B, A <volatile: lasts until the next reset or power cycle>".to_string(),
                ]),
                vec![(0, vec![2, 1])],
            ),
        ];
        for (volatile, want, want_writes) in cases {
            let variables = MemoryVariables::new(
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            );
            variables.insert(setup(), BS_RT, &[1, 2]);
            let variables = Rc::new(variables);
            let options = SetOptions {
                volatile,
                ..SetOptions::default()
            };

            let got = set_responses(
                &hiidb,
                "L",
                &SetValue::Items(vec!["B".to_owned(), "A".to_owned()]),
                None,
                &options,
                SetAccess {
                    reads: shared(&variables),
                    writes: &*variables,
                    held: None,
                },
                None,
            );

            let answers = got.map(|list| {
                list.responses
                    .into_iter()
                    .map(|response| response.question.answer)
                    .collect::<Vec<_>>()
            });
            assert_eq!(
                answers.map_err(|error| error.to_string()),
                want,
                "{volatile:?}"
            );
            assert_eq!(
                variables.writes_to(&setup()),
                want_writes,
                "{volatile:?}: writes"
            );
        }
    }

    /// Under VolatileWrites::Allow, choice_for_set still refuses an authenticated variable before
    /// set's first write, so that the question of another package list is not written first.
    #[test]
    fn set_refuses_an_authenticated_variable_before_any_write_if_volatile_writes_are_allowed() {
        let list = |guid: u8, name: &str| {
            let packages = [
                form_package(&[
                    var_store_efi(1, name, NV_BS, 1),
                    form(1, &[checkbox_on(1, 1, 1)]),
                ]),
                en_strings_package_of(&["Q"]),
                END_PACKAGE.to_vec(),
            ];
            package_list_with_guid([guid; 16], &packages.concat())
        };
        let hiidb = [list(0x55, "Setup"), list(0x66, "Signed")].concat();
        let signed = VariableKey {
            name: "Signed".to_string(),
            guid: NIL_GUID,
        };
        let variables = MemoryVariables::new(
            VariableReach::BootServices,
            VariableInterface::VariableServices,
        );
        variables.insert(setup(), BS_RT, &[0]);
        // EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS
        variables.insert(signed.clone(), BS_RT | 0x20, &[0]);
        let variables = Rc::new(variables);
        let options = SetOptions {
            volatile: VolatileWrites::Allow,
            ..SetOptions::default()
        };

        let got = set_responses(
            &hiidb,
            "Q",
            &SetValue::Text("1".to_owned()),
            None,
            &options,
            SetAccess {
                reads: shared(&variables),
                writes: &*variables,
                held: None,
            },
            None,
        );

        assert_eq!(
            got.map(drop).map_err(|error| error.to_string()),
            Err(
                "EFI variable Signed-00000000-0000-0000-0000-000000000000 has authenticated \
                 access (attributes 0x26), which uefisettings does not write"
                    .to_string()
            ),
            "refusal"
        );
        assert_eq!(variables.writes_to(&setup()), vec![], "writes of Setup");
        assert_eq!(variables.writes_to(&signed), vec![], "writes of Signed");
    }

    /// A driver that records each get and set it is asked for, and fails get of the QuestionId
    /// `refused_get`, refuses the QuestionId `refused_check` before it reaches the driver, and
    /// `refused_set` when it sets it.
    #[derive(Default)]
    struct RecordingDriver {
        gets: RefCell<Vec<u16>>,
        sets: RefCell<Vec<(u16, u64)>>,
        refused_get: Option<u16>,
        refused_check: Option<u16>,
        refused_set: Option<u16>,
    }

    impl DriverHeldValues for RecordingDriver {
        fn store_name(&self) -> &'static str {
            "its driver"
        }

        fn get(
            &self,
            _list: &QuestionList<'_>,
            question: &QuestionDescriptor,
            held: &DriverHeldQuestion,
        ) -> Result<String> {
            self.gets.borrow_mut().push(held.question_id);
            match self.refused_get == Some(held.question_id) {
                true => Err(anyhow!("cannot get question {:?}", question.question)),
                false => Ok("from the driver".to_string()),
            }
        }

        fn check_set(
            &self,
            _list: &QuestionList<'_>,
            question: &QuestionDescriptor,
            held: &DriverHeldQuestion,
        ) -> Result<()> {
            match self.refused_check == Some(held.question_id) {
                true => Err(set_refusal(&question.question, "the driver is unreachable")),
                false => Ok(()),
            }
        }

        fn set(
            &self,
            _list: &QuestionList<'_>,
            question: &QuestionDescriptor,
            held: &DriverHeldQuestion,
            value: u64,
        ) -> Result<String> {
            self.sets.borrow_mut().push((held.question_id, value));
            match self.refused_set == Some(held.question_id) {
                true => Err(set_refusal(
                    &question.question,
                    format!("the driver refused QuestionId {}", held.question_id),
                )),
                false => Ok(format!(
                    " <set by the driver of QuestionId {}>",
                    held.question_id
                )),
            }
        }
    }

    /// A package list of GUID `guid` whose FormSet holds `children`, its string 1 "Q".
    fn q_list(guid: [u8; 16], children: &[Vec<u8>]) -> Vec<u8> {
        let packages = [
            form_package(children),
            en_strings_package_of(&["Q"]),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid(guid, &packages.concat())
    }

    /// The package list of GUID `guid` with the CHECKBOX Q of QuestionId 7 without a VarStore,
    /// flagged EFI_IFR_FLAG_CALLBACK.
    fn driver_held_list(guid: [u8; 16]) -> Vec<u8> {
        let storageless = [
            &1u16.to_le_bytes()[..],  // Prompt
            &1u16.to_le_bytes(),      // Help
            &7u16.to_le_bytes(),      // QuestionId
            &0u16.to_le_bytes(),      // VarStoreId
            &0xFFFFu16.to_le_bytes(), // VarStoreInfo
            &[0x04, 0x00],            // EFI_IFR_FLAG_CALLBACK, CHECKBOX Flags
        ]
        .concat();
        q_list(
            guid,
            &[form(1, &[operation(CHECKBOX, false, &storageless)])],
        )
    }

    /// A HiiDB of two FormSets with the CHECKBOX Q: driver_held_list's of GUID [0x66; 16], then
    /// one at byte 0 of the EFI variable Setup.
    fn driver_held_hiidb() -> Vec<u8> {
        [
            driver_held_list([0x66; 16]),
            q_list(
                [0x55; 16],
                &[
                    var_store_efi(1, "Setup", NV_BS_RT, 1),
                    form(1, &[checkbox_on(1, 1, 1)]),
                ],
            ),
        ]
        .concat()
    }

    /// set refuses a question whose driver holds its value and that has a WRITE expression before
    /// any write, whatever the variables' reach: uefisettings does not evaluate WRITE beside the
    /// driver's Callback()s.
    #[cfg(variable_data)]
    #[test]
    fn set_refuses_a_write_expression_beside_callbacks_before_any_write() {
        let storageless = [
            &1u16.to_le_bytes()[..],  // Prompt
            &1u16.to_le_bytes(),      // Help
            &7u16.to_le_bytes(),      // QuestionId
            &0u16.to_le_bytes(),      // VarStoreId
            &0xFFFFu16.to_le_bytes(), // VarStoreInfo
            &[0x04, 0x00],            // EFI_IFR_FLAG_CALLBACK, CHECKBOX Flags
        ]
        .concat();
        let with_write = [
            operation(CHECKBOX, true, &storageless),
            operation(WRITE, false, &[]),
            ifr_true(),
            END.to_vec(),
        ]
        .concat();
        let hiidb = [
            package_list_with_guid(
                [0x66; 16],
                &[
                    form_package(&[form(1, &[with_write])]),
                    en_strings_package_of(&["Q"]),
                    END_PACKAGE.to_vec(),
                ]
                .concat(),
            ),
            package_list_with_guid(
                [0x55; 16],
                &[
                    form_package(&[
                        var_store_efi(1, "Setup", NV_BS_RT, 1),
                        form(1, &[checkbox_on(1, 1, 1)]),
                    ]),
                    en_strings_package_of(&["Q"]),
                    END_PACKAGE.to_vec(),
                ]
                .concat(),
            ),
        ]
        .concat();
        for (reach, interface) in [
            (VariableReach::Runtime, VariableInterface::Efivarfs),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            ),
        ] {
            let driver = RecordingDriver::default();
            let variables = MemoryVariables::new(reach, interface);
            variables.insert(setup(), NV_BS_RT, &[0]);
            let variables = Rc::new(variables);

            let set = HiiBackend::set_in(
                &hiidb,
                "Q",
                &SetValue::Text("1".to_owned()),
                None,
                &SetOptions::default(),
                SetAccess {
                    reads: shared(&variables),
                    writes: &*variables,
                    held: Some(&driver),
                },
                None,
            );

            assert_eq!(
                set.map(drop).map_err(|error| format!("{error:#}")),
                Err(ExpressionBesideCallback(QuestionExpression::Write).to_string()),
                "{reach:?}"
            );
            assert!(driver.sets.borrow().is_empty(), "{reach:?}: no driver set");
            assert!(
                variables.writes_to(&setup()).is_empty(),
                "{reach:?}: Setup unwritten"
            );
        }
    }

    /// The refusal, without --i-am-fine-to-brick-this-system, of a set staged for the next boot
    /// in a HiiDB that declares a setup password question.
    const STAGED_PASSWORD_REFUSAL: &str = "this HiiDB declares a setup password question, and a \
                                           set staged for the next boot is applied before the \
                                           OS, where no setup browser asks for or checks the \
                                           password; pass --i-am-fine-to-brick-this-system to \
                                           stage it";

    /// apply-staged finds a staged request's question by its FormSet GUID and QuestionId among
    /// those that their driver holds, and refuses one that is gone, held twice, in a state that
    /// set did not include, or of another value type.
    #[cfg(variable_data)]
    #[test]
    fn apply_staged_finds_the_question_of_a_request_as_set_selected_it() {
        // FormSet 11111111-…: Q (QuestionId 7) and, grayed out, R (8), both held by their
        // driver; a FormSet whose Q (1) is at byte 0 of Setup
        let held = |guid| {
            let packages = [
                form_package(&[form(
                    1,
                    &[
                        callback_checkbox(7, 1),
                        conditional(GRAY_OUT_IF, ifr_true(), &[callback_checkbox(8, 2)]),
                    ],
                )]),
                en_strings_package_of(&["Q", "R"]),
                strings_package_of(b"fr-FR", &["Q-fr", "R-fr"]),
                END_PACKAGE.to_vec(),
            ];
            package_list_with_guid(guid, &packages.concat())
        };
        let stored = package_list_with_guid(
            [0x55; 16],
            &[
                form_package(&[
                    var_store_efi(1, "Setup", NV_BS_RT, 1),
                    form(1, &[checkbox_on(1, 1, 1)]),
                ]),
                en_strings_package_of(&["Q"]),
                END_PACKAGE.to_vec(),
            ]
            .concat(),
        );
        let form_set: Guid = "11111111-1111-1111-1111-111111111111"
            .parse()
            .expect("a GUID");
        let request = |question_id, include| StagedRequest {
            question: "Q".to_owned(),
            form_set,
            question_id,
            value_type: IfrValueType::Boolean,
            value: 1,
            include,
            access_level: None,
            unsafe_operations: UnsafeOperations::Refuse,
        };
        let found = |hiidb: &[u8], request: &StagedRequest| {
            let parsed = package::read_db(hiidb).expect("the HiiDB");
            let mut reader = EfivarReader::with_variables(Box::new(MemoryVariables::new(
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            )));
            staged_question(&parsed, request, &[], &mut reader)
                .map(|(list, descriptor, _, _)| (list.index, descriptor.question))
                .map_err(|error| format!("{error:#}"))
        };
        let hiidb = [stored.clone(), held([0x66; 16])].concat();
        let named = |id: u16| format!("question \"Q\", QuestionId {id:#06x} of FormSet {form_set}");

        let cases = [
            (
                "Q",
                request(7, IncludedStates::empty()),
                Ok((1, "Q".to_owned())),
            ),
            (
                "grayed-out R, included",
                request(8, IncludedStates::GRAYED_OUT),
                Ok((1, "R".to_owned())),
            ),
            (
                "grayed-out R",
                request(8, IncludedStates::empty()),
                Err(format!(
                    "{} is <grayed-out> now, which set did not include",
                    named(8)
                )),
            ),
            (
                "a QuestionId that no driver holds",
                request(1, IncludedStates::empty()),
                Err(format!(
                    "the HII database holds no {} whose driver holds its value",
                    named(1)
                )),
            ),
            (
                "another FormSet",
                StagedRequest {
                    form_set: "22222222-2222-2222-2222-222222222222"
                        .parse()
                        .expect("a GUID"),
                    ..request(7, IncludedStates::empty())
                },
                Err(
                    "the HII database holds no question \"Q\", QuestionId 0x0007 of FormSet \
                     22222222-2222-2222-2222-222222222222 whose driver holds its value"
                        .to_owned(),
                ),
            ),
            (
                "another value type",
                StagedRequest {
                    value_type: IfrValueType::NumSize8,
                    ..request(7, IncludedStates::empty())
                },
                Err(format!(
                    "{} takes EFI_IFR_TYPE_BOOLEAN now, not EFI_IFR_TYPE_NUM_SIZE_8",
                    named(7)
                )),
            ),
            (
                "an access level without AMI's VarStore",
                StagedRequest {
                    access_level: Some(AccessLevel::User),
                    ..request(7, IncludedStates::empty())
                },
                Err(
                    "--access-level applies to AMI firmware whose HiiDB declares the \
                     SystemAccess VarStore; this HiiDB declares none"
                        .to_owned(),
                ),
            ),
        ];
        for (case, request, want) in cases {
            assert_eq!(found(&hiidb, &request), want, "{case}");
        }
        // its texts show in the languages requested (ParsedPackageList::texts), as set's do
        let parsed = package::read_db(&hiidb).expect("the HiiDB");
        let mut reader = EfivarReader::with_variables(Box::new(MemoryVariables::new(
            VariableReach::BootServices,
            VariableInterface::VariableServices,
        )));
        let (_, descriptor, _, _) = staged_question(
            &parsed,
            &request(7, IncludedStates::empty()),
            &["fr-FR"],
            &mut reader,
        )
        .expect("Q under fr-FR");
        assert_eq!(descriptor.question, "Q-fr", "Q under fr-FR");
        // a PASSWORD outside any FormSet declares a password too
        let outside_password = package_list_with_guid(
            [0x77; 16],
            &[
                form_package_of(
                    &[
                        password_on(3, 3, 2, 0),
                        // the fixture, which `form_set` shadows here
                        crate::hii::forms::ifr_fixtures::form_set(&[
                            var_store(2, [0x44; 16], "AMITSESetup", 81),
                            form(1, &[checkbox_at(2, 2, 2, 80)]),
                        ]),
                    ]
                    .concat(),
                ),
                en_strings_package_of(&["Q", "P", "Password"]),
                END_PACKAGE.to_vec(),
            ]
            .concat(),
        );
        assert_eq!(
            found(
                &[held([0x66; 16]), outside_password].concat(),
                &request(7, IncludedStates::empty())
            ),
            Err(STAGED_PASSWORD_REFUSAL.to_owned()),
            "a HiiDB with a PASSWORD outside any FormSet"
        );
        assert_eq!(
            found(
                &[held([0x66; 16]), password_hiidb()].concat(),
                &request(7, IncludedStates::empty())
            ),
            Err(STAGED_PASSWORD_REFUSAL.to_owned()),
            "a HiiDB that declares a setup password question"
        );
        // staged with --i-am-fine-to-brick-this-system, which lifts the setup password
        let password_db = [held([0x66; 16]), password_hiidb()].concat();
        let parsed = package::read_db(&password_db).expect("the HiiDB");
        let allowed = StagedRequest {
            unsafe_operations: UnsafeOperations::Allow,
            ..request(7, IncludedStates::empty())
        };
        let (list, descriptor, _, lifted) = staged_question(&parsed, &allowed, &[], &mut reader)
            .expect("Q staged with --i-am-fine-to-brick-this-system");
        assert_eq!(
            (list.index, descriptor.question, lifted),
            (
                0,
                "Q".to_owned(),
                vec![UnsafeOperation::StagedSetupPassword]
            ),
            "a HiiDB that declares a setup password question, staged with \
             --i-am-fine-to-brick-this-system"
        );
        assert_eq!(
            found(
                &[held([0x66; 16]), held([0x77; 16])].concat(),
                &request(7, IncludedStates::empty())
            ),
            Err(format!(
                "2 package lists of the HII database hold {}",
                named(7)
            )),
            "Q in two package lists"
        );
    }

    /// apply-staged checks again whether a request's question is read-only: one that
    /// EFI_IFR_FLAG_READ_ONLY makes read-only is an unsafe operation, lifted only by the grant
    /// that set recorded with the request, and one that an EFI_IFR_VALUE makes read-only, which
    /// no driver holds then, is refused with either grant; a writable one lifts nothing.
    #[cfg(variable_data)]
    #[test]
    fn apply_staged_checks_a_read_only_question_against_set_s_grant() {
        // W (QuestionId 6), Q (7), flagged EFI_IFR_FLAG_READ_ONLY, and V (8), which an
        // EFI_IFR_VALUE makes read-only, each held by its driver
        let header = |question_id: u16, prompt: u16, flags: u8| {
            [
                &prompt.to_le_bytes()[..],
                &1u16.to_le_bytes(),        // Help
                &question_id.to_le_bytes(), // QuestionId
                &0u16.to_le_bytes(),        // VarStoreId
                &0xFFFFu16.to_le_bytes(),   // VarStoreInfo
                &[flags, 0x00],             // question flags, CHECKBOX Flags
            ]
            .concat()
        };
        let hiidb = package_list_with_guid(
            [0x66; 16],
            &[
                form_package(&[form(
                    1,
                    &[
                        callback_checkbox(6, 3),
                        // EFI_IFR_FLAG_CALLBACK | EFI_IFR_FLAG_READ_ONLY
                        operation(CHECKBOX, false, &header(7, 1, 0x05)),
                        [
                            operation(CHECKBOX, true, &header(8, 2, 0x04)),
                            value_of(ifr_true()),
                            END.to_vec(),
                        ]
                        .concat(),
                    ],
                )]),
                en_strings_package_of(&["Q", "V", "W"]),
                END_PACKAGE.to_vec(),
            ]
            .concat(),
        );
        let parsed = package::read_db(&hiidb).expect("the HiiDB");
        let lifted = |question_id, grant| {
            let request = StagedRequest {
                question: "Q".to_owned(),
                form_set: "11111111-1111-1111-1111-111111111111"
                    .parse()
                    .expect("a GUID"),
                question_id,
                value_type: IfrValueType::Boolean,
                value: 1,
                include: IncludedStates::empty(),
                access_level: None,
                unsafe_operations: grant,
            };
            let mut reader = EfivarReader::with_variables(Box::new(MemoryVariables::new(
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            )));
            staged_question(&parsed, &request, &[], &mut reader)
                .map(|(_, _, _, lifted)| lifted)
                .map_err(|error| format!("{error:#}"))
        };
        let read_only_q = UnsafeOperation::ReadOnlyQuestion {
            question: "Q".to_owned(),
            writable: IncludedStates::empty(),
        };
        // its EFI_IFR_VALUE gives V's value, so no driver holds it (StoragelessQuestion::route)
        let no_driver_held_v = "the HII database holds no question \"Q\", QuestionId 0x0008 of \
                                FormSet 11111111-1111-1111-1111-111111111111 whose driver holds \
                                its value"
            .to_owned();

        let cases = [
            ("W", 6, UnsafeOperations::Refuse, Ok(Vec::new())),
            ("W, allowed", 6, UnsafeOperations::Allow, Ok(Vec::new())),
            (
                "Q",
                7,
                UnsafeOperations::Refuse,
                flag_refusal("Q", "").map(|()| Vec::new()),
            ),
            (
                "Q, allowed",
                7,
                UnsafeOperations::Allow,
                Ok(vec![read_only_q]),
            ),
            (
                "V",
                8,
                UnsafeOperations::Refuse,
                Err(no_driver_held_v.clone()),
            ),
            (
                "V, allowed",
                8,
                UnsafeOperations::Allow,
                Err(no_driver_held_v),
            ),
        ];
        for (case, question_id, grant, want) in cases {
            assert_eq!(lifted(question_id, grant), want, "{case}");
        }
    }

    /// apply-staged finds no question whose driver holds its value for a request of C or L of
    /// callback_and_strings_list, a STRING and an ORDERED_LIST flagged EFI_IFR_FLAG_CALLBACK and
    /// without a VarStore, which no driver holds: it refuses the request with either grant, before
    /// any Callback(). That of Q, which its driver holds, it finds.
    #[cfg(variable_data)]
    #[test]
    fn apply_staged_finds_no_driver_for_a_string_or_an_ordered_list() {
        let parsed = package::read_db(&callback_and_strings_list()).expect("the HiiDB");
        let found = |question: &str, question_id, grant| {
            let request = StagedRequest {
                question: question.to_owned(),
                form_set: "11111111-1111-1111-1111-111111111111"
                    .parse()
                    .expect("a GUID"),
                question_id,
                value_type: IfrValueType::Boolean,
                value: 1,
                include: IncludedStates::empty(),
                access_level: None,
                unsafe_operations: grant,
            };
            let mut reader = EfivarReader::with_variables(Box::new(MemoryVariables::new(
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            )));
            staged_question(&parsed, &request, &[], &mut reader)
                .map(|(_, descriptor, held, lifted)| {
                    (descriptor.question, held.question_id, lifted)
                })
                .map_err(|error| format!("{error:#}"))
        };

        for grant in [UnsafeOperations::Refuse, UnsafeOperations::Allow] {
            for (question, question_id) in [("C", 10), ("L", 11)] {
                assert_eq!(
                    found(question, question_id, grant),
                    Err(format!(
                        "the HII database holds no question {question:?}, QuestionId \
                         {question_id:#06x} of FormSet 11111111-1111-1111-1111-111111111111 whose \
                         driver holds its value"
                    )),
                    "{question}, {grant:?}"
                );
            }
            assert_eq!(
                found("Q", 9, grant),
                Ok(("Q".to_owned(), 9, Vec::new())),
                "Q, {grant:?}"
            );
        }
    }

    /// set gives one value to questions of one kind, and items to an ORDERED_LIST only, also where
    /// a driver holds a question's value: a CHECKBOX that its driver holds and a DATE on Setup of
    /// its prompt are refused as two kinds, and --item for that CHECKBOX as for any other, before
    /// its driver applies a value and before any write.
    #[test]
    fn set_refuses_two_kinds_and_items_beside_a_driver_held_question() {
        let date = operation(
            DATE,
            false,
            &[question_header_with(1, 1, 1, 0, 0x00), vec![0x00]].concat(),
        );
        let date_list = q_list(
            [0x55; 16],
            &[var_store_efi(1, "Setup", NV_BS_RT, 4), form(1, &[date])],
        );
        let cases = [
            (
                "a DATE beside",
                [driver_held_list([0x44; 16]), date_list].concat(),
                SetValue::Text("2027-01-02".to_owned()),
                "question \"Q\" selects questions of more than one kind: ONE_OF, NUMERIC or \
                 CHECKBOX (in 44444444-4444-4444-4444-444444444444), DATE (in \
                 55555555-5555-5555-5555-555555555555); set gives one value to questions of one \
                 kind",
            ),
            (
                "--item",
                driver_held_list([0x44; 16]),
                SetValue::Items(vec!["1".to_owned()]),
                "cannot set question \"Q\": --item gives the options of an ORDERED_LIST; this \
                 question takes VALUE",
            ),
        ];
        for (case, hiidb, value, want) in cases {
            let driver = RecordingDriver::default();
            let variables =
                MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);
            variables.insert(setup(), NV_BS_RT, &[0x00, 0x00, 0x01, 0x01]);
            let variables = Rc::new(variables);

            let set = HiiBackend::set_in(
                &hiidb,
                "Q",
                &value,
                None,
                &SetOptions::default(),
                SetAccess {
                    reads: shared(&variables),
                    writes: &*variables,
                    held: Some(&driver),
                },
                None,
            );

            assert_eq!(
                set.map(drop).map_err(|error| format!("{error:#}")),
                Err(want.to_owned()),
                "{case}"
            );
            assert!(
                driver.sets.borrow().is_empty(),
                "{case}: no set by the driver"
            );
            assert!(
                variables.writes_to(&setup()).is_empty(),
                "{case}: the refusal comes before any write"
            );
        }
    }

    /// get and set take a question whose driver holds its value to that driver where one is
    /// reached; elsewhere get shows why it has no value, and set refuses it before any write.
    #[test]
    fn driver_held_questions_go_to_their_driver_only_where_one_is_reached() {
        let unreached = "question has no VarStore; its driver keeps the value, which only \
                         EFI_HII_CONFIG_ACCESS_PROTOCOL.CallBack() reaches (UEFI 2.11 §33.2.5.6), \
                         and after ExitBootServices() no EFI device-handle-based protocol may be \
                         used (UEFI 2.11 §7.4.6); use uefisettings.efi in the UEFI Shell";
        let hiidb = driver_held_hiidb();
        for reached in [true, false] {
            let driver = RecordingDriver::default();
            let held = reached.then_some(&driver as &dyn DriverHeldValues);
            let variables =
                MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);
            variables.insert(setup(), NV_BS_RT, &[0]);
            let variables = Rc::new(variables);

            let got = HiiBackend::get_in(
                &hiidb,
                "Q",
                None,
                &GetOptions::default(),
                shared(&variables),
                None,
                None,
                held,
            )
            .expect("get Q");
            let set = set_responses(
                &hiidb,
                "Q",
                &SetValue::Text("1".to_owned()),
                None,
                &SetOptions::default(),
                SetAccess {
                    reads: shared(&variables),
                    writes: &*variables,
                    held,
                },
                None,
            );

            let answer = &got.responses[0].question.answer;
            let answers = set.map(|set| {
                set.responses
                    .into_iter()
                    .map(|response| response.question.answer)
                    .collect::<Vec<_>>()
            });
            match reached {
                true => {
                    assert_eq!(answer, "from the driver", "get through the driver");
                    assert_eq!(
                        answers.map_err(|error| error.to_string()),
                        Ok(vec![
                            "1 <set by the driver of QuestionId 7>".to_string(),
                            "1".to_string()
                        ]),
                        "set through the driver"
                    );
                    assert_eq!(*driver.gets.borrow(), [7], "the driver's gets");
                    assert_eq!(*driver.sets.borrow(), [(7, 1)], "the driver's sets");
                    assert_eq!(
                        variables.writes_to(&setup()),
                        [(0, vec![1])],
                        "Setup written"
                    );
                }
                false => {
                    assert!(
                        answer.starts_with(&format!("<ValueUnavailable: {unreached}>")),
                        "get without a driver: {answer}"
                    );
                    assert_eq!(
                        answers.map_err(|error| error.to_string()),
                        Err(format!("cannot set question \"Q\": {unreached}")),
                        "set without a driver"
                    );
                    assert!(driver.gets.borrow().is_empty(), "no get by the driver");
                    assert!(driver.sets.borrow().is_empty(), "no set by the driver");
                    assert!(
                        variables.writes_to(&setup()).is_empty(),
                        "the refusal comes before any write"
                    );
                }
            }
        }
    }

    /// A package list with GUID `guid` whose form holds the CHECKBOX Q, QuestionId
    /// `question_id`, without a VarStore and with the question flags `flags`.
    fn storageless_checkbox_list(guid: [u8; 16], question_id: u16, flags: u8) -> Vec<u8> {
        let storageless = [
            &1u16.to_le_bytes()[..],    // Prompt
            &1u16.to_le_bytes(),        // Help
            &question_id.to_le_bytes(), // QuestionId
            &0u16.to_le_bytes(),        // VarStoreId
            &0xFFFFu16.to_le_bytes(),   // VarStoreInfo
            &[flags, 0x00],             // question flags, CHECKBOX Flags
        ]
        .concat();
        let packages = [
            form_package(&[form(1, &[operation(CHECKBOX, false, &storageless)])]),
            en_strings_package_of(&["Q"]),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid(guid, &packages.concat())
    }

    /// set writes a question that its driver holds and that EFI_IFR_FLAG_READ_ONLY makes
    /// read-only only as an unsafe operation, as a stored one: refused before its driver unless
    /// UnsafeOperations::Allow lifts it, which set then returns as lifted. So it does through
    /// either reach: in the UEFI Shell, where the driver's Callback() takes the value, and from an
    /// OS, where set stages it for the next boot.
    #[test]
    fn set_refuses_a_read_only_question_that_its_driver_holds_unless_the_flag_allows_it() {
        // EFI_IFR_FLAG_CALLBACK | EFI_IFR_FLAG_READ_ONLY
        let hiidb = storageless_checkbox_list([0x66; 16], 7, 0x05);
        let read_only = UnsafeOperation::ReadOnlyQuestion {
            question: "Q".to_owned(),
            writable: IncludedStates::empty(),
        };
        for (reach, interface, unsafe_operations, want, want_sets) in [
            (
                VariableReach::Runtime,
                VariableInterface::Efivarfs,
                UnsafeOperations::Refuse,
                flag_refusal("Q", ""),
                vec![],
            ),
            (
                VariableReach::Runtime,
                VariableInterface::Efivarfs,
                UnsafeOperations::Allow,
                Ok(()),
                vec![(7, 1)],
            ),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
                UnsafeOperations::Refuse,
                flag_refusal("Q", ""),
                vec![],
            ),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
                UnsafeOperations::Allow,
                Ok(()),
                vec![(7, 1)],
            ),
        ] {
            let driver = RecordingDriver::default();
            let variables = Rc::new(MemoryVariables::new(reach, interface));
            let got = HiiBackend::set_in(
                &hiidb,
                "Q",
                &SetValue::Text("1".to_owned()),
                None,
                &SetOptions {
                    unsafe_operations,
                    ..SetOptions::default()
                },
                SetAccess {
                    reads: shared(&variables),
                    writes: &*variables,
                    held: Some(&driver),
                },
                None,
            );
            assert_eq!(
                got.as_ref()
                    .map(|(_, lifted)| lifted.clone())
                    .map_err(|error| error.to_string()),
                want.map(|()| vec![read_only.clone()]),
                "set through {reach:?} with {unsafe_operations:?}"
            );
            assert_eq!(
                *driver.sets.borrow(),
                want_sets,
                "the driver's sets through {reach:?} with {unsafe_operations:?}"
            );
        }
    }

    /// In the UEFI Shell, in a HiiDB that declares a setup password question, set of a question
    /// that its driver holds is an unsafe operation, as that of a stored one: refused before any
    /// Callback() unless UnsafeOperations::Allow lifts it, which set then returns as lifted.
    #[test]
    fn set_through_a_driver_beside_a_setup_password_takes_the_flag() {
        let storageless = [
            &4u16.to_le_bytes()[..],  // Prompt
            &4u16.to_le_bytes(),      // Help
            &9u16.to_le_bytes(),      // QuestionId
            &0u16.to_le_bytes(),      // VarStoreId
            &0xFFFFu16.to_le_bytes(), // VarStoreInfo
            &[0x04, 0x00],            // EFI_IFR_FLAG_CALLBACK, CHECKBOX Flags
        ]
        .concat();
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, 1),
                var_store(2, [0x44; 16], "AMITSESetup", 81),
                form(
                    1,
                    &[
                        checkbox_on(1, 1, 1),
                        password_on(3, 3, 2, 0),
                        operation(CHECKBOX, false, &storageless),
                    ],
                ),
            ]),
            en_strings_package_of(&["Q", "P", "Password", "D"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x55; 16], &packages.concat());
        let refusal = "this HiiDB declares a setup password question, and the UEFI Shell runs no \
                       setup browser, so no password is asked or checked; pass \
                       --i-am-fine-to-brick-this-system to write without it";
        for (unsafe_operations, want, want_sets) in [
            (UnsafeOperations::Refuse, Err(refusal.to_owned()), vec![]),
            (
                UnsafeOperations::Allow,
                Ok(vec![UnsafeOperation::SetupPassword]),
                vec![(9, 1)],
            ),
        ] {
            let driver = RecordingDriver::default();
            let variables = password_variables(
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            );
            let got = HiiBackend::set_in(
                &hiidb,
                "D",
                &SetValue::Text("1".to_owned()),
                None,
                &SetOptions {
                    unsafe_operations,
                    ..SetOptions::default()
                },
                SetAccess {
                    reads: shared(&variables),
                    writes: &*variables,
                    held: Some(&driver),
                },
                None,
            );
            assert_eq!(
                got.map(|(_, lifted)| lifted)
                    .map_err(|error| error.to_string()),
                want,
                "set with {unsafe_operations:?}"
            );
            assert_eq!(
                *driver.sets.borrow(),
                want_sets,
                "the driver's sets with {unsafe_operations:?}"
            );
            assert_eq!(
                variables.writes_to(&amitse_setup()),
                vec![],
                "no write of the password's VarStore with {unsafe_operations:?}"
            );
        }
    }

    /// A question without a VarStore, flagged EFI_IFR_FLAG_CALLBACK, whose QuestionId a PASSWORD
    /// of its FormSet also has, never goes to its driver: a CallBack() names its question only
    /// by QuestionId, so its driver could take it for the PASSWORD. get shows why, set refuses
    /// it, and the driver is asked for nothing.
    #[test]
    fn a_question_that_shares_its_question_id_with_a_password_never_goes_to_its_driver() {
        let storageless = [
            &1u16.to_le_bytes()[..],  // Prompt
            &1u16.to_le_bytes(),      // Help
            &7u16.to_le_bytes(),      // QuestionId
            &0u16.to_le_bytes(),      // VarStoreId
            &0xFFFFu16.to_le_bytes(), // VarStoreInfo
            &[0x04, 0x00],            // EFI_IFR_FLAG_CALLBACK, CHECKBOX Flags
        ]
        .concat();
        let packages = [
            form_package(&[
                var_store(1, [0x77; 16], "PasswordStore", 40),
                form(
                    1,
                    &[
                        operation(CHECKBOX, false, &storageless),
                        // on a VarStore: one of VarStoreId 0 closes every variable
                        password_on(7, 2, 1, 0),
                    ],
                ),
            ]),
            en_strings_package_of(&["Q", "P"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x66; 16], &packages.concat());
        let refusal = StoragelessRefusal::CallbackSharedQuestionId("EFI_IFR_PASSWORD");
        let driver = RecordingDriver::default();
        let variables = Rc::new(MemoryVariables::new(
            VariableReach::Runtime,
            VariableInterface::Efivarfs,
        ));

        let got = HiiBackend::get_in(
            &hiidb,
            "Q",
            None,
            &GetOptions::default(),
            shared(&variables),
            None,
            None,
            Some(&driver as &dyn DriverHeldValues),
        )
        .expect("get Q");
        let set = HiiBackend::set_in(
            &hiidb,
            "Q",
            &SetValue::Text("1".to_owned()),
            None,
            &SetOptions::default(),
            SetAccess {
                reads: shared(&variables),
                writes: &*variables,
                held: Some(&driver),
            },
            None,
        );

        let answer = &got.responses[0].question.answer;
        assert!(
            answer.starts_with(&format!("<ValueUnavailable: {refusal}>")),
            "get: {answer}"
        );
        assert!(driver.gets.borrow().is_empty(), "no get by the driver");
        assert!(driver.sets.borrow().is_empty(), "no set by the driver");
        assert_eq!(
            set.map(drop).map_err(|error| error.to_string()),
            Err(format!("cannot set question \"Q\": {refusal}")),
            "set"
        );
    }

    /// The package list of a form that holds the CHECKBOX Q, QuestionId 9, which its driver holds
    /// (callback_checkbox), and, flagged EFI_IFR_FLAG_CALLBACK and without a VarStore, the STRING
    /// C, QuestionId 10, and the ORDERED_LIST L, QuestionId 11, which EFI_IFR_FLAG_READ_ONLY makes
    /// read-only; then the STRINGs of MaxSize 4 on the EFI variable Setup: S, QuestionId 1, at
    /// byte 0, and R, QuestionId 2, at byte 8, which EFI_IFR_FLAG_READ_ONLY makes read-only.
    fn callback_and_strings_list() -> Vec<u8> {
        // EFI_IFR_FLAG_CALLBACK | EFI_IFR_FLAG_READ_ONLY; MaxContainers 2, no Flags
        let ordered_list = [question_header_with(11, 3, 0, 0, 0x05), vec![2, 0x00]].concat();
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, 16),
                form(
                    1,
                    &[
                        callback_checkbox(9, 1),
                        // EFI_IFR_FLAG_CALLBACK
                        flagged_string_on(10, 2, (0, 0), (0, 4), (0x04, 0x00), &[]),
                        [
                            operation(ORDERED_LIST, true, &ordered_list),
                            flagged_option(6, 0x00, 1),
                            flagged_option(7, 0x00, 2),
                            END.to_vec(),
                        ]
                        .concat(),
                        string_on(1, 4, (1, 0), (0, 4), &[]),
                        // EFI_IFR_FLAG_READ_ONLY
                        flagged_string_on(2, 5, (1, 8), (0, 4), (0x01, 0x00), &[]),
                    ],
                ),
            ]),
            en_strings_package_of(&["Q", "C", "L", "S", "R", "A", "B"]),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid([0x5D; 16], &packages.concat())
    }

    /// The variables of callback_and_strings_list through `reach`, Setup holding "AB" for S and
    /// "CD" for R.
    fn strings_beside_a_driver(reach: VariableReach) -> Rc<MemoryVariables> {
        let interface = match reach {
            VariableReach::BootServices => VariableInterface::VariableServices,
            VariableReach::Runtime => VariableInterface::Efivarfs,
        };
        let variables = MemoryVariables::new(reach, interface);
        let stored = [
            [0x41, 0, 0x42, 0, 0, 0, 0, 0],
            [0x43, 0, 0x44, 0, 0, 0, 0, 0],
        ]
        .concat();
        variables.insert(setup(), NV_BS_RT, &stored);
        Rc::new(variables)
    }

    /// get of a STRING beside a question that its driver holds asks no driver, and answers as
    /// without one, through either reach: C, flagged EFI_IFR_FLAG_CALLBACK and without a
    /// VarStore, shows why it has no value, as uefisettings exchanges no STRING with a CallBack()
    /// (StoragelessRefusal::CallbackUndecoded), and S and R show the characters of Setup. get of
    /// Q asks the driver.
    #[test]
    fn get_asks_no_driver_for_a_string() {
        let hiidb = callback_and_strings_list();
        let undecoded = format!(
            "<ValueUnavailable: {}>",
            StoragelessRefusal::CallbackUndecoded("EFI_IFR_STRING")
        );
        for reach in [VariableReach::Runtime, VariableReach::BootServices] {
            let driver = RecordingDriver::default();
            let get = |question: &str, held: Option<&dyn DriverHeldValues>| {
                HiiBackend::get_in(
                    &hiidb,
                    question,
                    None,
                    &GetOptions::default(),
                    shared(&strings_beside_a_driver(reach)),
                    None,
                    None,
                    held,
                )
                .map(|response| {
                    response
                        .responses
                        .into_iter()
                        .map(|response| response.question.answer)
                        .collect::<Vec<_>>()
                })
                .map_err(|error| format!("{error:#}"))
            };

            for (question, want) in [("C", undecoded.as_str()), ("S", "AB"), ("R", "CD")] {
                let got = get(question, Some(&driver));
                assert_eq!(got, Ok(vec![want.to_owned()]), "{reach:?}: get {question}");
                assert_eq!(
                    got,
                    get(question, None),
                    "{reach:?}: get {question} without a driver"
                );
            }
            assert!(
                driver.gets.borrow().is_empty(),
                "{reach:?}: no get by the driver"
            );
            assert_eq!(
                get("Q", Some(&driver)),
                Ok(vec!["from the driver".to_owned()]),
                "{reach:?}: get Q"
            );
            assert_eq!(*driver.gets.borrow(), [9], "{reach:?}: the driver's gets");
        }
    }

    /// set of a STRING beside a question that its driver holds asks no driver, and does as
    /// without one, through either reach and with either grant: C, flagged EFI_IFR_FLAG_CALLBACK
    /// and without a VarStore, is refused before any write, as get_asks_no_driver_for_a_string
    /// shows it; S is written to Setup; R, which EFI_IFR_FLAG_READ_ONLY makes read-only, is
    /// refused unless UnsafeOperations::Allow, then written and returned as lifted. L, an
    /// ORDERED_LIST of C's flags that EFI_IFR_FLAG_READ_ONLY makes read-only, is refused as C is
    /// with either grant: no driver holds an ORDERED_LIST.
    #[test]
    fn set_asks_no_driver_for_a_string_or_an_ordered_list() {
        let hiidb = callback_and_strings_list();
        let undecoded = |question: &str, op| {
            Err(format!(
                "cannot set question {question:?}: {}",
                StoragelessRefusal::CallbackUndecoded(op)
            ))
        };
        let xyz = SetValue::Text("XYZ".to_owned());
        let items = SetValue::Items(vec!["B".to_owned(), "A".to_owned()]);
        let written = vec![0x58, 0, 0x59, 0, 0x5A, 0, 0, 0];
        let read_only_r = UnsafeOperation::ReadOnlyQuestion {
            question: "R".to_owned(),
            writable: IncludedStates::empty(),
        };
        for reach in [VariableReach::Runtime, VariableReach::BootServices] {
            for unsafe_operations in [UnsafeOperations::Refuse, UnsafeOperations::Allow] {
                let driver = RecordingDriver::default();
                let set =
                    |question: &str, value: &SetValue, held: Option<&dyn DriverHeldValues>| {
                        let variables = strings_beside_a_driver(reach);
                        let set = HiiBackend::set_in(
                            &hiidb,
                            question,
                            value,
                            None,
                            &SetOptions {
                                unsafe_operations,
                                ..SetOptions::default()
                            },
                            SetAccess {
                                reads: shared(&variables),
                                writes: &*variables,
                                held,
                            },
                            None,
                        )
                        .map(|(_, lifted)| lifted)
                        .map_err(|error| format!("{error:#}"));
                        (set, variables.writes_to(&setup()))
                    };
                let r = match unsafe_operations {
                    UnsafeOperations::Refuse => {
                        (flag_refusal("R", "").map(|()| Vec::new()), vec![])
                    }
                    UnsafeOperations::Allow => {
                        (Ok(vec![read_only_r.clone()]), vec![(8, written.clone())])
                    }
                };
                let cases = [
                    ("C", &xyz, (undecoded("C", "EFI_IFR_STRING"), vec![])),
                    (
                        "L",
                        &items,
                        (undecoded("L", "EFI_IFR_ORDERED_LIST"), vec![]),
                    ),
                    ("S", &xyz, (Ok(Vec::new()), vec![(0, written.clone())])),
                    ("R", &xyz, r),
                ];

                let case = format!("{reach:?}, {unsafe_operations:?}");
                for (question, value, want) in cases {
                    let got = set(question, value, Some(&driver));
                    assert_eq!(got, want, "{case}: set {question}");
                    assert_eq!(
                        got,
                        set(question, value, None),
                        "{case}: set {question} without a driver"
                    );
                }
                assert!(
                    driver.sets.borrow().is_empty(),
                    "{case}: no set by the driver"
                );
            }
        }
    }

    /// A CHECKBOX of QuestionId `question_id` prompted by string `prompt`, without a VarStore,
    /// flagged EFI_IFR_FLAG_CALLBACK.
    fn callback_checkbox(question_id: u16, prompt: u16) -> Vec<u8> {
        let data = [
            &prompt.to_le_bytes()[..],
            &1u16.to_le_bytes(),        // Help
            &question_id.to_le_bytes(), // QuestionId
            &0u16.to_le_bytes(),        // VarStoreId
            &0xFFFFu16.to_le_bytes(),   // VarStoreInfo
            &[0x04, 0x00],              // EFI_IFR_FLAG_CALLBACK, CHECKBOX Flags
        ]
        .concat();
        operation(CHECKBOX, false, &data)
    }

    /// The IFR of name_value_hiidb's first list with a CHECKBOX C of its own, QuestionId 9, which
    /// its driver holds (callback_checkbox), beside the VARSTORE_NAME_VALUE of VarStoreId 3 and B
    /// on Backing, and with the PASSWORD on Pin of VarStoreId `password`, if any, in a form of
    /// its own: edk2 may route one of VarStoreId 3 to the VARSTORE_NAME_VALUE, one of VarStoreId
    /// 0 names no VarStore, and one of VarStoreId 1 is on Backing.
    fn name_value_callback_ifr(password: Option<u16>) -> Vec<Vec<u8>> {
        type I = NameValueIfr;
        let mut children = vec![
            I::name_value(),
            I::backing(),
            form(1, &[callback_checkbox(9, 1), I::b()]),
        ];
        if let Some(var_store_id) = password {
            children.push(form(2, &[I::password(var_store_id)]));
        }
        vec![form_set(&children)]
    }

    /// What the refusal of a HiiDB with a PASSWORD of VarStoreId 0 says of it, after its
    /// QuestionId and FormSet.
    const VAR_STORE_ID_0: &str = ": VarStoreId 0 names no VarStore, so its callbacks or READ and \
                                  WRITE ops keep its password where uefisettings cannot tell";

    /// In a HiiDB with a PASSWORD that its driver may keep in any variable, one of VarStoreId 0,
    /// which names no VarStore, or one that edk2 may route to a VARSTORE_NAME_VALUE, get of a
    /// question that its driver holds asks that driver nothing and reads no variable: through
    /// variables that reach Runtime it refuses the HiiDB as such (AnyVariablePasswords), through
    /// those that reach BootServices as the password is unresolved. Beside a PASSWORD on Backing,
    /// or none, get asks the driver.
    #[test]
    fn get_asks_no_driver_where_a_driver_may_keep_a_password_in_any_variable() {
        for (reach, refusal) in [
            (VariableReach::Runtime, ANY_VARIABLE),
            (VariableReach::BootServices, BOOT_SERVICES_REFUSAL),
        ] {
            for password in [Some(0), Some(3), Some(1), None] {
                let hiidb = name_value_hiidb(&name_value_callback_ifr(password));
                let variables = name_value_variables(reach);
                let driver = RecordingDriver::default();

                let got = HiiBackend::get_in(
                    &hiidb,
                    "C",
                    None,
                    &GetOptions::default(),
                    shared(&variables),
                    None,
                    None,
                    Some(&driver as &dyn DriverHeldValues),
                )
                .map(|response| {
                    response
                        .responses
                        .into_iter()
                        .map(|response| response.question.answer)
                        .collect::<Vec<_>>()
                })
                .map_err(|error| format!("{error:#}"));

                let case = format!("{reach:?}, the PASSWORD of VarStoreId {password:?}");
                match password {
                    Some(var_store_id @ (0 | 3)) => {
                        assert!(
                            got.as_ref().is_err_and(|error| {
                                error.starts_with("PASSWORD question 0x0003 in FormSet ")
                                    && error.ends_with(refusal)
                                    && (var_store_id == 3 || error.contains(VAR_STORE_ID_0))
                            }),
                            "{case}: get C: {got:?}"
                        );
                        assert!(
                            driver.gets.borrow().is_empty(),
                            "{case}: no get by the driver"
                        );
                        assert_eq!(variables.reads(), [], "{case}: no variable read");
                    }
                    Some(_) | None => {
                        assert_eq!(got, Ok(vec!["from the driver".to_owned()]), "{case}: get C");
                        assert_eq!(*driver.gets.borrow(), [9], "{case}: the driver's gets");
                    }
                }
            }
        }
    }

    /// In a HiiDB with a PASSWORD that its driver may keep in any variable, of VarStoreId 0 or one
    /// that edk2 may route to a VARSTORE_NAME_VALUE, set of a question that its driver holds asks
    /// that driver nothing and reads and writes no variable, as
    /// get_asks_no_driver_where_a_driver_may_keep_a_password_in_any_variable refuses, also with
    /// UnsafeOperations::Allow, which lifts no withholding and which the refusal does not name.
    /// Without a PASSWORD, set asks the driver, lifting nothing.
    #[test]
    fn set_asks_no_driver_where_a_driver_may_keep_a_password_in_any_variable() {
        for (reach, refusal) in [
            (VariableReach::Runtime, ANY_VARIABLE),
            (VariableReach::BootServices, BOOT_SERVICES_REFUSAL),
        ] {
            for unsafe_operations in [UnsafeOperations::Refuse, UnsafeOperations::Allow] {
                for password in [Some(0), Some(3), None] {
                    let hiidb = name_value_hiidb(&name_value_callback_ifr(password));
                    let variables = name_value_variables(reach);
                    let driver = RecordingDriver::default();
                    let options = SetOptions {
                        unsafe_operations,
                        ..SetOptions::default()
                    };

                    let set = HiiBackend::set_in(
                        &hiidb,
                        "C",
                        &SetValue::Text("1".to_owned()),
                        None,
                        &options,
                        SetAccess {
                            reads: shared(&variables),
                            writes: &*variables,
                            held: Some(&driver),
                        },
                        None,
                    )
                    .map(|(_, lifted)| lifted)
                    .map_err(|error| format!("{error:#}"));

                    let case = format!(
                        "{reach:?}, {unsafe_operations:?}, the PASSWORD of VarStoreId {password:?}"
                    );
                    match password {
                        Some(var_store_id) => {
                            assert!(
                                set.as_ref().is_err_and(|error| {
                                    error.starts_with("PASSWORD question 0x0003 in FormSet ")
                                        && error.ends_with(refusal)
                                        && (var_store_id != 0 || error.contains(VAR_STORE_ID_0))
                                        && !error.contains(UNSAFE_OPERATIONS_FLAG)
                                }),
                                "{case}: set C: {set:?}"
                            );
                            assert!(
                                driver.sets.borrow().is_empty(),
                                "{case}: no set by the driver"
                            );
                            assert_eq!(variables.reads(), [], "{case}: no variable read");
                        }
                        None => {
                            assert_eq!(set, Ok(Vec::new()), "{case}: set C");
                            assert_eq!(
                                *driver.sets.borrow(),
                                [(9, 1)],
                                "{case}: the driver's sets"
                            );
                        }
                    }
                    for (name, guid) in [("Backing", P_GUID), ("Other", OTHER_GUID)] {
                        let key = VariableKey {
                            name: name.to_owned(),
                            guid: Guid::from(guid),
                        };
                        assert_eq!(variables.writes_to(&key), [], "{case}: writes to {name}");
                    }
                }
            }
        }
    }

    /// set writes the stored matches, then asks each driver that holds a match, in order, and
    /// stops at the first one that refuses, as at a failed variable write: its refusal names the
    /// stores written and applied before it and those not attempted after it.
    #[test]
    fn set_stops_at_the_first_driver_that_refuses() {
        let applying: Guid = "8C78A505-BAA0-4C4A-869F-000000001A11"
            .parse()
            .expect("a GUID");
        let refusing: Guid = "8C78A505-BAA0-4C4A-869F-000000001A12"
            .parse()
            .expect("a GUID");
        // the list of driver_held_hiidb whose driver holds Q
        let held = Guid::from([0x66; 16]);
        let hiidb = [
            storageless_checkbox_list(applying.into(), 7, 0x04),
            storageless_checkbox_list(refusing.into(), 8, 0x04),
            driver_held_hiidb(),
        ]
        .concat();
        let driver = RecordingDriver {
            refused_set: Some(8),
            ..RecordingDriver::default()
        };
        let variables = MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);
        variables.insert(setup(), NV_BS_RT, &[0]);
        let variables = Rc::new(variables);

        let got = HiiBackend::set_in(
            &hiidb,
            "Q",
            &SetValue::Text("1".to_owned()),
            None,
            &SetOptions::default(),
            SetAccess {
                reads: shared(&variables),
                writes: &*variables,
                held: Some(&driver),
            },
            None,
        );

        assert_eq!(
            got.map(drop).map_err(|error| error.to_string()),
            Err(format!(
                "question \"Q\" was not set everywhere: cannot set question \"Q\": the driver \
                 refused QuestionId 8 (in {refusing} (its driver)); written in: \
                 55555555-5555-5555-5555-555555555555 (EFI variable {}), {applying} (its \
                 driver); not attempted: {held} (its driver)",
                setup()
            )),
            "the refusal"
        );
        assert_eq!(
            *driver.sets.borrow(),
            [(7, 1), (8, 1)],
            "the drivers asked, in order, up to the refusing one"
        );
        assert_eq!(
            variables.writes_to(&setup()),
            [(0, vec![1])],
            "Setup written"
        );
    }

    /// set of one question, whose driver refuses it, fails with that refusal alone, as set of
    /// one stored question fails with its write's error.
    #[test]
    fn set_of_one_driver_held_question_fails_with_its_refusal() {
        let hiidb = storageless_checkbox_list([0x77; 16], 8, 0x04);
        let driver = RecordingDriver {
            refused_set: Some(8),
            ..RecordingDriver::default()
        };
        let variables = Rc::new(MemoryVariables::new(
            VariableReach::Runtime,
            VariableInterface::Efivarfs,
        ));

        let got = HiiBackend::set_in(
            &hiidb,
            "Q",
            &SetValue::Text("1".to_owned()),
            None,
            &SetOptions::default(),
            SetAccess {
                reads: shared(&variables),
                writes: &*variables,
                held: Some(&driver),
            },
            None,
        );

        assert_eq!(
            got.map(drop).map_err(|error| error.to_string()),
            Err("cannot set question \"Q\": the driver refused QuestionId 8".to_string()),
            "the refusal"
        );
        assert_eq!(*driver.sets.borrow(), [(8, 1)], "the driver asked");
    }

    /// get of a question whose driver fails get fails with that error, as where driver code
    /// changed password bytes.
    #[test]
    fn get_of_a_driver_held_question_fails_with_its_driver_s_error() {
        let hiidb = storageless_checkbox_list([0x77; 16], 8, 0x04);
        let driver = RecordingDriver {
            refused_get: Some(8),
            ..RecordingDriver::default()
        };
        let variables = Rc::new(MemoryVariables::new(
            VariableReach::Runtime,
            VariableInterface::Efivarfs,
        ));

        let got = HiiBackend::get_in(
            &hiidb,
            "Q",
            None,
            &GetOptions::default(),
            shared(&variables),
            None,
            None,
            Some(&driver),
        );

        assert_eq!(
            got.map(drop).map_err(|error| error.to_string()),
            Err("cannot get question \"Q\"".to_string()),
            "the error"
        );
        assert_eq!(*driver.gets.borrow(), [8], "the driver asked");
    }

    /// set answers each match that a driver holds with that driver's own annotation, in the order
    /// of the matches, among the stored ones.
    #[test]
    fn each_driver_held_answer_carries_its_own_driver_s_annotation() {
        let hiidb = [
            storageless_checkbox_list([0x77; 16], 8, 0x04),
            driver_held_hiidb(),
            storageless_checkbox_list([0x88; 16], 9, 0x04),
        ]
        .concat();
        let driver = RecordingDriver::default();
        let variables = MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);
        variables.insert(setup(), NV_BS_RT, &[0]);
        let variables = Rc::new(variables);

        let got = set_responses(
            &hiidb,
            "Q",
            &SetValue::Text("1".to_owned()),
            None,
            &SetOptions::default(),
            SetAccess {
                reads: shared(&variables),
                writes: &*variables,
                held: Some(&driver),
            },
            None,
        );

        assert_eq!(
            got.map(|set| {
                set.responses
                    .into_iter()
                    .map(|response| response.question.answer)
                    .collect::<Vec<_>>()
            })
            .map_err(|error| error.to_string()),
            Ok(vec![
                "1 <set by the driver of QuestionId 8>".to_owned(),
                "1 <set by the driver of QuestionId 7>".to_owned(),
                "1".to_owned(),
                "1 <set by the driver of QuestionId 9>".to_owned(),
            ]),
            "the answers, in the order of the matches"
        );
        assert_eq!(
            *driver.sets.borrow(),
            [(8, 1), (7, 1), (9, 1)],
            "the drivers asked, in order"
        );
    }

    /// set names a question that it stages for the next boot, in its errors, by its package list
    /// followed by `(staged for the next boot)`.
    #[cfg(any(target_os = "linux", target_os = "windows"))]
    #[test]
    fn a_staged_question_s_store_is_named_staged_for_the_next_boot() {
        let parsed = package::read_db(&storageless_checkbox_list([0x77; 16], 7, 0x04))
            .expect("parse the HiiDB");
        let staging =
            crate::staged_set::next_boot::NextBootStaging::of(&SetOptions::default(), &parsed);
        let selected = select_for_set(
            &parsed,
            &QuestionSelector::from("Q"),
            &BTreeSet::from(["Q".to_string()]),
            &SetOptions::default(),
            &[],
            &mut PendingOperations::new(UnsafeOperations::Refuse),
            &mut EfivarReader::with_variables(Box::new(MemoryVariables::default())),
            Some(&staging),
        )
        .expect("select Q");
        let [question] = selected.as_slice() else {
            panic!("one match of Q, not {}", selected.len());
        };
        let driver_held = question
            .descriptor
            .driver_held()
            .expect("held by its driver");
        let store = DriverHeldSet {
            selected: question,
            held: &staging,
            driver_held,
            value: 1,
        };

        assert_eq!(
            store.label(),
            format!("{} (staged for the next boot)", question.guid),
            "the label of Q's store"
        );
    }

    /// set refuses before any write when a driver-held match would be refused before its driver,
    /// also when a stored match comes first.
    #[test]
    fn set_checks_every_driver_held_match_before_the_first_write() {
        let hiidb = [
            storageless_checkbox_list([0x77; 16], 8, 0x04),
            driver_held_hiidb(),
        ]
        .concat();
        let driver = RecordingDriver {
            refused_check: Some(8),
            ..RecordingDriver::default()
        };
        let variables = MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);
        variables.insert(setup(), NV_BS_RT, &[0]);
        let variables = Rc::new(variables);

        let got = HiiBackend::set_in(
            &hiidb,
            "Q",
            &SetValue::Text("1".to_owned()),
            None,
            &SetOptions::default(),
            SetAccess {
                reads: shared(&variables),
                writes: &*variables,
                held: Some(&driver),
            },
            None,
        );

        assert_eq!(
            got.map(drop).map_err(|error| error.to_string()),
            Err("cannot set question \"Q\": the driver is unreachable".to_string()),
            "the refusal"
        );
        assert!(driver.sets.borrow().is_empty(), "no driver asked to set");
        assert!(variables.writes_to(&setup()).is_empty(), "Setup unwritten");
    }

    /// In a HiiDB that declares a setup password question, set from an OS stages a question that
    /// its driver holds only with --i-am-fine-to-brick-this-system, which lifts
    /// UnsafeOperation::StagedSetupPassword, as the next boot applies it where no setup browser
    /// asks for the password, and no other option lifts it; set of a stored one from an OS
    /// writes as before, the flag lifting nothing, and in the UEFI Shell with the flag, lifting
    /// UnsafeOperation::SetupPassword.
    #[test]
    fn set_from_an_os_stages_beside_a_setup_password_question_only_with_the_flag() {
        let callback = package_list_with_guid(
            [0x66; 16],
            &[
                form_package(&[form(1, &[callback_checkbox(7, 1)])]),
                en_strings_package_of(&["Q"]),
                END_PACKAGE.to_vec(),
            ]
            .concat(),
        );
        let through_driver = || {
            vec![
                "1 <set by the driver of QuestionId 7>".to_owned(),
                "1".to_owned(),
            ]
        };
        let granting = |unsafe_operations| SetOptions {
            unsafe_operations,
            ..SetOptions::default()
        };
        let cases = [
            (
                "from an OS",
                [callback.clone(), password_hiidb()].concat(),
                VariableReach::Runtime,
                granting(UnsafeOperations::Refuse),
                Err(STAGED_PASSWORD_REFUSAL.to_owned()),
                Vec::new(),
            ),
            (
                "from an OS, with every other option",
                [callback.clone(), password_hiidb()].concat(),
                VariableReach::Runtime,
                // --access-level needs AMI's SystemAccess VarStore, which this HiiDB lacks
                SetOptions {
                    include: IncludedStates::all(),
                    volatile: VolatileWrites::Allow,
                    language: Some("en-US".to_owned()),
                    staging_image: Some(PathBuf::from("uefisettings.efi")),
                    ..granting(UnsafeOperations::Refuse)
                },
                Err(STAGED_PASSWORD_REFUSAL.to_owned()),
                Vec::new(),
            ),
            (
                "from an OS, allowed",
                [callback.clone(), password_hiidb()].concat(),
                VariableReach::Runtime,
                granting(UnsafeOperations::Allow),
                Ok((through_driver(), vec![UnsafeOperation::StagedSetupPassword])),
                vec![(7, 1)],
            ),
            (
                "from an OS, without a question that its driver holds",
                password_hiidb(),
                VariableReach::Runtime,
                granting(UnsafeOperations::Refuse),
                Ok((vec!["1".to_owned()], Vec::new())),
                Vec::new(),
            ),
            (
                "from an OS, allowed, without a question that its driver holds",
                password_hiidb(),
                VariableReach::Runtime,
                granting(UnsafeOperations::Allow),
                Ok((vec!["1".to_owned()], Vec::new())),
                Vec::new(),
            ),
            (
                "in the UEFI Shell, allowed",
                [callback, password_hiidb()].concat(),
                VariableReach::BootServices,
                granting(UnsafeOperations::Allow),
                Ok((through_driver(), vec![UnsafeOperation::SetupPassword])),
                vec![(7, 1)],
            ),
        ];
        for (case, hiidb, reach, options, want, sets) in cases {
            let driver = RecordingDriver::default();
            let variables = password_variables(reach, VariableInterface::VariableServices);

            let set = HiiBackend::set_in(
                &hiidb,
                "Q",
                &SetValue::Text("1".to_owned()),
                None,
                &options,
                SetAccess {
                    reads: shared(&variables),
                    writes: &*variables,
                    held: Some(&driver),
                },
                None,
            );

            assert_eq!(
                set.map(|(set, lifted)| {
                    let answers = set
                        .responses
                        .into_iter()
                        .map(|response| response.question.answer)
                        .collect::<Vec<_>>();
                    (answers, lifted)
                })
                .map_err(|error| format!("{error:#}")),
                want,
                "{case}"
            );
            assert_eq!(*driver.sets.borrow(), sets, "{case}: the driver's sets");
            assert_eq!(
                variables.writes_to(&setup()).is_empty(),
                want.is_err(),
                "{case}: Setup written unless refused"
            );
        }
    }

    /// Through variables that reach BootServices, a HiiDB with a PASSWORD op whose VarStore is
    /// unknown has get, list-questions, show-ifr and set read and write no variable, even with
    /// UnsafeOperations::Allow, which lifts no refusal that would disclose a password; through
    /// those that reach Runtime they work, as before.
    #[test]
    fn unresolved_password_closes_every_variable_to_boot_services() {
        // VarStoreId 9 of the VARSTORE AMITSESetup that another FormSet of the form package
        // declares, which the Forms Browser of edk2-stable202608 does not find for the PASSWORD
        // (SetupBrowserDxe/IfrParse.c:136-148), while FindStorageFromVarId of its
        // HiiDatabaseDxe/ConfigKeywordHandler.c does (:1520-1569)
        let hiidb = {
            let packages = [
                form_package_of(
                    &[
                        form_set_with_guid(
                            [0x11; 16],
                            &[
                                var_store_efi(1, "Setup", NV_BS_RT, 1),
                                var_store(2, [0x44; 16], "AMITSESetup", 81),
                                form(
                                    1,
                                    &[
                                        checkbox_on(1, 1, 1),
                                        password_on(3, 3, 9, 0),
                                        checkbox_at(2, 2, 2, 80),
                                    ],
                                ),
                            ],
                        ),
                        form_set_with_guid(
                            [0x13; 16],
                            &[var_store(9, [0x44; 16], "AMITSESetup", 81), form(3, &[])],
                        ),
                    ]
                    .concat(),
                ),
                en_strings_package_of(&["Q", "P", "Password"]),
                END_PACKAGE.to_vec(),
            ];
            package_list_with_guid([0x55; 16], &packages.concat())
        };
        let closed = "PASSWORD question 0x0003 in FormSet 11111111-1111-1111-1111-111111111111: \
                      no supported varstore with matching id 0x0009 found; as the variable of \
                      that password is unknown, the UEFI Shell build reads and writes no variable \
                      of this HiiDB";
        let set = |variables: &Rc<MemoryVariables>, unsafe_operations| {
            let options = SetOptions {
                unsafe_operations,
                ..SetOptions::default()
            };
            set_responses(
                &hiidb,
                "Q",
                &SetValue::Text("1".to_owned()),
                None,
                &options,
                SetAccess {
                    reads: shared(variables),
                    writes: &**variables,
                    held: None,
                },
                None,
            )
            .map(drop)
            .map_err(|error| error.to_string())
        };

        let variables = password_variables(
            VariableReach::BootServices,
            VariableInterface::VariableServices,
        );
        let got = HiiBackend::get_in(
            &hiidb,
            "Q",
            None,
            &GetOptions::default(),
            shared(&variables),
            None,
            None,
            None,
        );
        let listed = HiiBackend::list_questions_in(
            &hiidb,
            &ListQuestionsOptions::default(),
            shared(&variables),
            None,
            None,
        );
        let shown = HiiBackend::show_ifr_in(
            &hiidb,
            &ShowIfrOptions::default(),
            shared(&variables),
            None,
            None,
        );
        assert_eq!(
            got.map(drop).map_err(|error| error.to_string()),
            Err(closed.to_string()),
            "BootServices: get"
        );
        assert_eq!(
            listed.map(drop).map_err(|error| error.to_string()),
            Err(closed.to_string()),
            "BootServices: list-questions"
        );
        assert_eq!(
            shown.map(drop).map_err(|error| error.to_string()),
            Err(closed.to_string()),
            "BootServices: show-ifr"
        );
        assert_eq!(
            set(&variables, UnsafeOperations::Refuse),
            Err(closed.to_string()),
            "BootServices: set"
        );
        assert_eq!(
            set(&variables, UnsafeOperations::Allow),
            Err(closed.to_string()),
            "BootServices: set with UnsafeOperations::Allow"
        );
        assert_eq!(variables.reads(), [], "BootServices: reads");
        assert_eq!(variables.writes_to(&setup()), [], "BootServices: writes");

        let variables = password_variables(VariableReach::Runtime, VariableInterface::Efivarfs);
        let got = HiiBackend::get_in(
            &hiidb,
            "Q",
            None,
            &GetOptions::default(),
            shared(&variables),
            None,
            None,
            None,
        )
        .expect("get through Runtime");
        let answers: Vec<&str> = got
            .responses
            .iter()
            .map(|response| response.question.answer.as_str())
            .collect();
        assert_eq!(answers, ["0"], "Runtime: get");
        assert_eq!(
            set(&variables, UnsafeOperations::Refuse),
            Ok(()),
            "Runtime: set"
        );
        assert_eq!(
            variables.writes_to(&setup()),
            [(0, vec![1])],
            "Runtime: writes"
        );
    }

    /// The Guid of dropped_password_store, as stored.
    const DROPPED_PASSWORD_STORE_GUID: [u8; 16] = [0x88; 16];

    /// The GUID of the package list of dropped_password_hiidb, as stored.
    const DROPPED_PASSWORD_LIST_GUID: [u8; 16] = [0x99; 16];

    /// The EFI variable that both FormSets of dropped_password_hiidb name.
    fn dropped_password_store() -> VariableKey {
        VariableKey {
            name: "UefisettingsTest".to_string(),
            guid: Guid::from(DROPPED_PASSWORD_STORE_GUID),
        }
    }

    /// The VARSTORE_EFI of dropped_password_store, VarStore 1.
    fn dropped_password_var_store() -> Vec<u8> {
        var_store_efi_of(
            1,
            DROPPED_PASSWORD_STORE_GUID,
            "UefisettingsTest",
            NV_BS_RT,
            20,
        )
    }

    /// The Guid of the variable of ignored_form_set_var_store, as stored.
    const IGNORED_FORM_SET_STORE_GUID: [u8; 16] = [0x7A; 16];

    /// The VARSTORE_EFI, VarStore 2, of a variable apart from dropped_password_store, for a
    /// FormSet that uefisettings ignores beside questions on dropped_password_store that read:
    /// each variable that an ignored FormSet declares is withheld whole, and a PASSWORD there is
    /// withheld in each VarStore of its VarStoreId in the form package too.
    fn ignored_form_set_var_store() -> Vec<u8> {
        var_store_efi_of(
            2,
            IGNORED_FORM_SET_STORE_GUID,
            "UefisettingsIgnored",
            NV_BS_RT,
            20,
        )
    }

    /// The first FormSet of dropped_password_hiidb, with the CHECKBOX Q at byte 0 of
    /// dropped_password_store.
    fn dropped_password_first_form_set() -> Vec<u8> {
        form_set(&[
            dropped_password_var_store(),
            form(1, &[checkbox_on(1, 1, 1)]),
        ])
    }

    /// The ops of a second FormSet of dropped_password_hiidb: a form, a form with a PASSWORD at
    /// byte 0 of dropped_password_store, and then `tail`, outside its forms.
    fn dropped_password_second_ops(tail: Vec<u8>) -> [Vec<u8>; 4] {
        [
            dropped_password_var_store(),
            form(1, &[]),
            form(2, &[password_on(2, 2, 1, 0)]),
            tail,
        ]
    }

    /// A HiiDB of one package list holding dropped_password_first_form_set, the ops `between`
    /// and then the FormSet `second`.
    fn dropped_password_hiidb(between: Vec<u8>, second: Vec<u8>) -> Vec<u8> {
        let first = dropped_password_first_form_set();
        let packages = [
            form_package_of(&[first, between, second].concat()),
            en_strings_package_of(&["Q", "Password"]),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid(DROPPED_PASSWORD_LIST_GUID, &packages.concat())
    }

    /// A HiiDB of two FormSets with dropped_password_store of 60 bytes, each 0x01, and these
    /// CHECKBOXes on it: in the first, Q1 at byte 50 in form 1, Q2 at byte 52 then `ops` in form
    /// 2, and Q3 at byte 51 in form 3; in the second, O at byte 10; and the offset of form 2 in
    /// its form package.
    fn disabled_form_hiidb(ops: Vec<u8>) -> (Vec<u8>, usize) {
        let store = var_store_efi_of(
            1,
            DROPPED_PASSWORD_STORE_GUID,
            "UefisettingsTest",
            NV_BS_RT,
            60,
        );
        let first = [store.clone(), form(1, &[checkbox_at(1, 1, 1, 50)])];
        let ifr = [
            form_set(&[
                first[0].clone(),
                first[1].clone(),
                form(2, &[checkbox_at(2, 2, 1, 52), ops]),
                form(3, &[checkbox_at(3, 3, 1, 51)]),
            ]),
            form_set(&[store, form(1, &[checkbox_at(5, 5, 1, 10)])]),
        ]
        .concat();
        let packages = [
            form_package_of(&ifr),
            en_strings_package_of(&["Q1", "Q2", "Q3", "Password", "O"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid(DROPPED_PASSWORD_LIST_GUID, &packages.concat());
        (hiidb, form_set(&first).len() - END.len())
    }

    /// The variables of disabled_form_hiidb, of `reach` through `interface`.
    fn disabled_form_variables(
        reach: VariableReach,
        interface: VariableInterface,
    ) -> Rc<MemoryVariables> {
        let variables = MemoryVariables::new(reach, interface);
        variables.insert(dropped_password_store(), NV_BS_RT, &[0x01; 60]);
        Rc::new(variables)
    }

    /// A form that a malformed op disables is dropped (UEFI 2.11 §33.2.5.10.1): through variables
    /// of either reach, get and list-questions read the questions of the forms beside it, not its
    /// own, and list its record, which show-ifr prints and set's refusal of its question names;
    /// its PASSWORD stays known, so O, over that password's bytes, reads no value. Where the
    /// FormSet of that form was ignored, variables that reach Runtime withheld none of them.
    #[test]
    fn a_disabled_form_is_dropped_and_its_password_withheld() {
        let (hiidb, offset) = disabled_form_hiidb(
            [
                password_on(4, 4, 1, 0),
                operation(CHECKBOX, false, &[0x00; 4]),
            ]
            .concat(),
        );
        let record = format!(
            "the form 2 of the FormSet {}, whose EFI_IFR_CHECKBOX op is malformed; UEFI 2.11 \
             §33.2.5.10.1 disables the form of a malformed op: the EFI_IFR_CHECKBOX op at offset ",
            Guid::from([0x11; 16])
        );
        let list = Guid::from(DROPPED_PASSWORD_LIST_GUID).to_string();
        let records_of = |ignored: Option<Vec<HiiIgnoredIfr>>| -> Vec<(String, i64, bool)> {
            ignored
                .unwrap_or_default()
                .into_iter()
                .map(|ignored| {
                    (
                        ignored.package_list,
                        ignored.offset,
                        ignored.reason.starts_with(&record),
                    )
                })
                .collect()
        };
        let want_records = vec![(list, i64::try_from(offset).expect("offset"), true)];
        for (reach, interface) in [
            (VariableReach::Runtime, VariableInterface::Efivarfs),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            ),
        ] {
            let variables = disabled_form_variables(reach, interface);
            for (question, want) in [
                ("O", vec![format!("{PASSWORD_BYTES} <IFR default: 0>")]),
                ("Q1", vec!["1".to_string()]),
                ("Q2", vec![]),
                ("Q3", vec!["1".to_string()]),
            ] {
                let got = HiiBackend::get_in(
                    &hiidb,
                    question,
                    None,
                    &GetOptions::default(),
                    shared(&variables),
                    None,
                    None,
                    None,
                )
                .unwrap_or_else(|error| panic!("{reach:?}: get {question}: {error:#}"));
                let answers: Vec<String> = got
                    .responses
                    .into_iter()
                    .map(|response| response.question.answer)
                    .collect();
                assert_eq!(answers, want, "{reach:?}: get {question}");
                assert_eq!(
                    records_of(got.ignored_ifr),
                    want_records,
                    "{reach:?}: get {question}: ignored_ifr"
                );
            }
            let (listed, records) = HiiBackend::list_questions_and_ignored_ifr_in(
                &hiidb,
                &ListQuestionsOptions::default(),
                shared(&variables),
                None,
                None,
            )
            .unwrap_or_else(|error| panic!("{reach:?}: list-questions: {error:#}"));
            let names: Vec<String> = listed.into_iter().map(|question| question.name).collect();
            let records: Vec<(u64, bool)> = records
                .iter()
                .map(|ignored| (ignored.offset, ignored.reason.starts_with(&record)))
                .collect();
            assert_eq!(
                (names, records),
                (
                    vec!["Q1".to_string(), "Q3".to_string(), "O".to_string()],
                    vec![(u64::try_from(offset).expect("offset"), true)]
                ),
                "{reach:?}: list-questions"
            );
            let set = set_bypassing(&hiidb, "Q2", "0", &variables);
            assert!(
                set.as_ref()
                    .is_err_and(|error| error.contains(&format!("offset {offset}"))
                        && error.contains(&record)),
                "{reach:?}: set Q2: {set:?}"
            );
            assert_eq!(
                variables.writes_to(&dropped_password_store()),
                [],
                "{reach:?}: writes"
            );
        }

        let shown = HiiBackend::show_ifr_using(
            &hiidb,
            &ShowIfrOptions {
                efivars: EfivarSource::Disabled,
                ..Default::default()
            },
        )
        .expect("show-ifr")
        .readable_representation;
        assert!(
            shown.contains(&format!("Disabled at offset {offset}: {record}")),
            "show-ifr: {shown}"
        );
    }

    /// A PASSWORD op of a disabled form without its question header is unresolved: edk2 reads
    /// that header from the bytes after the op, here those of its form's End and the next FORM,
    /// QuestionId 0x0229 and VarStoreId 0x8601, which no VarStore declares, so its password may be
    /// in any variable: through variables of either reach, get reads no variable.
    #[test]
    fn a_headless_password_in_a_disabled_form_closes_every_variable() {
        let (hiidb, _) = disabled_form_hiidb(operation(PASSWORD, false, &[3, 0, 4, 0]));

        let boot_services = disabled_form_variables(
            VariableReach::BootServices,
            VariableInterface::VariableServices,
        );
        let want = format!(
            "PASSWORD question 0x0229 in FormSet {}: its op ends before its question header",
            Guid::from([0x11; 16])
        );
        for question in ["Q1", "Q3"] {
            let got = HiiBackend::get_in(
                &hiidb,
                question,
                None,
                &GetOptions::default(),
                shared(&boot_services),
                None,
                None,
                None,
            )
            .map(drop)
            .map_err(|error| error.to_string());
            assert!(
                got.as_ref().is_err_and(|error| error.starts_with(&want)),
                "BootServices: get {question}: {got:?}"
            );
        }
        assert_eq!(boot_services.reads(), [], "BootServices: reads");

        let runtime = disabled_form_variables(VariableReach::Runtime, VariableInterface::Efivarfs);
        for question in ["Q1", "Q3", "O"] {
            let got = HiiBackend::get_in(
                &hiidb,
                question,
                None,
                &GetOptions::default(),
                shared(&runtime),
                None,
                None,
                None,
            )
            .map(drop)
            .map_err(|error| error.to_string());
            assert!(
                got.as_ref()
                    .is_err_and(|error| error.starts_with(&want) && error.ends_with(ANY_VARIABLE)),
                "Runtime: get {question}: {got:?}"
            );
        }
        assert_eq!(runtime.reads(), [], "Runtime: reads");
    }

    /// The variables of password_store_hiidb, of `reach`, each byte 0x01.
    fn password_store_variables(reach: VariableReach) -> Rc<MemoryVariables> {
        let interface = match reach {
            VariableReach::Runtime => VariableInterface::Efivarfs,
            VariableReach::BootServices => VariableInterface::VariableServices,
        };
        let variables = MemoryVariables::new(reach, interface);
        variables.insert(password_store(), NV_BS_RT, &[0x01; 60]);
        variables.insert(other_store(), NV_BS_RT, &[0x01]);
        Rc::new(variables)
    }

    /// A PASSWORD op that ends after its question header and MinSize disables its form (UEFI 2.11
    /// §33.2.5.10.1) but still names its VarStore and VarOffset: through variables that reach
    /// Runtime, every byte of its variable from there on is withheld, so O, over its first byte,
    /// and Q1, past it, read no value, while Q2, before it, and Q3, on another variable, read;
    /// through variables that reach BootServices it is unresolved, so get reads no variable. The
    /// whole PASSWORD withholds its 40 bytes alone.
    #[test]
    fn a_password_without_max_size_withholds_its_variable_from_its_var_offset_on() {
        let without_max_size = operation(
            PASSWORD,
            false,
            &[
                question_header_with(4, 4, 1, 10, 0x00),
                1u16.to_le_bytes().to_vec(), // MinSize
            ]
            .concat(),
        );
        let read = || Ok(vec!["1".to_string()]);
        let withheld = || Ok(vec![format!("{PASSWORD_BYTES} <IFR default: 0>")]);
        // each with what Runtime get of Q1 answers, and the start of BootServices get's refusal
        for (case, password, q1, refusal) in [
            ("the whole PASSWORD", password_on(4, 4, 1, 10), read(), None),
            (
                "a PASSWORD without MaxSize",
                without_max_size,
                withheld(),
                Some("PASSWORD question 0x0004 without MaxSize in FormSet "),
            ),
        ] {
            let hiidb = password_store_hiidb(Vec::new(), password);

            let runtime = password_store_variables(VariableReach::Runtime);
            for (question, want) in [
                ("O", withheld()),
                ("Q1", q1.clone()),
                ("Q2", read()),
                ("Q3", read()),
            ] {
                assert_eq!(
                    answers_or_error_of(&hiidb, question, &runtime),
                    want,
                    "{case}: Runtime: get {question}"
                );
            }

            let boot_services = password_store_variables(VariableReach::BootServices);
            let got = answers_or_error_of(&hiidb, "Q3", &boot_services);
            match refusal {
                None => assert_eq!(got, read(), "{case}: BootServices: get Q3"),
                Some(refusal) => {
                    assert!(
                        got.as_ref().is_err_and(|error| error.starts_with(refusal)),
                        "{case}: BootServices: get Q3: {got:?}"
                    );
                    assert_eq!(boot_services.reads(), [], "{case}: BootServices: reads");
                }
            }
        }
    }

    /// Each variable that a VARSTORE or VARSTORE_EFI op of a FormSet that uefisettings ignores
    /// declares is withheld whole through variables that reach Runtime, as a PASSWORD in that
    /// FormSet may name any of them: O and Q2, on the variable of its VarStore 1, read no
    /// value and that variable is never read, while Q3, on another variable, reads; through
    /// variables that reach BootServices get reads no variable.
    #[test]
    fn the_variables_that_an_ignored_form_set_declares_are_withheld_whole() {
        // a DEFAULTSTORE op of 4 bytes, shorter than its minimum of 6, outside the forms
        let short_default_store = operation(DEFAULT_STORE, false, &[0x00, 0x00]);
        let hiidb = password_store_hiidb(short_default_store, password_on(4, 4, 1, 10));

        let runtime = password_store_variables(VariableReach::Runtime);
        let withheld = Ok(vec![format!("{PASSWORD_BYTES} <IFR default: 0>")]);
        for (question, want) in [
            ("O", withheld.clone()),
            ("Q2", withheld),
            ("Q3", Ok(vec!["1".to_string()])),
        ] {
            assert_eq!(
                answers_or_error_of(&hiidb, question, &runtime),
                want,
                "Runtime: get {question}"
            );
        }
        assert_eq!(runtime.reads(), [(other_store(), 1)], "Runtime: reads");

        let boot_services = password_store_variables(VariableReach::BootServices);
        let got = answers_or_error_of(&hiidb, "Q3", &boot_services);
        assert!(
            got.as_ref()
                .is_err_and(|error| error.starts_with("PASSWORD questions of package list ")),
            "BootServices: get Q3: {got:?}"
        );
        assert_eq!(boot_services.reads(), [], "BootServices: reads");
    }

    /// IFR past an op where the walk for FormSets ends has no op boundary, so a PASSWORD in it may
    /// name any variable: through variables of either reach, get and list-questions read no
    /// variable of the HiiDB and refuse, naming that IFR; list-questions and show-ifr without
    /// efivars still list the questions of the FormSets that uefisettings reads.
    #[test]
    fn ifr_past_the_end_of_the_form_set_walk_closes_every_variable() {
        let hiidb = password_past_the_walk_hiidb();
        let want = format!(
            "PASSWORD questions of package list {} may be in the IFR that uefisettings ignores at \
             offset 0 of a form package, which has no op boundary, so in any variable: an op that \
             does not fit the form package, and the bytes after it: ",
            Guid::from(PAST_THE_WALK_LIST_GUID)
        );
        for reach in [VariableReach::Runtime, VariableReach::BootServices] {
            let variables = password_store_variables(reach);
            for question in ["O", "Q3"] {
                let got = answers_or_error_of(&hiidb, question, &variables);
                assert!(
                    got.as_ref().is_err_and(|error| error.starts_with(&want)),
                    "{reach:?}: get {question}: {got:?}"
                );
            }
            let listed = HiiBackend::list_questions_and_ignored_ifr_in(
                &hiidb,
                &ListQuestionsOptions::default(),
                shared(&variables),
                None,
                None,
            )
            .map(drop)
            .map_err(|error| error.to_string());
            assert!(
                listed.as_ref().is_err_and(|error| error.starts_with(&want)),
                "{reach:?}: list-questions: {listed:?}"
            );
            assert_eq!(variables.reads(), [], "{reach:?}: reads");
        }

        let (listed, _) = HiiBackend::list_questions_and_ignored_ifr_in(
            &hiidb,
            &ListQuestionsOptions::default(),
            EfivarSource::Disabled
                .into_variables()
                .expect("variables that read nothing"),
            None,
            None,
        )
        .expect("list-questions without efivars");
        let names: Vec<String> = listed.into_iter().map(|question| question.name).collect();
        assert_eq!(
            names,
            ["Q1", "O", "Q2", "Q3"],
            "list-questions without efivars"
        );
        let shown = HiiBackend::show_ifr_using(
            &hiidb,
            &ShowIfrOptions {
                efivars: EfivarSource::Disabled,
                ..Default::default()
            },
        )
        .expect("show-ifr without efivars")
        .readable_representation;
        assert!(shown.contains("Q3"), "show-ifr without efivars: {shown}");
    }

    /// Through variables that reach BootServices, a HiiDB whose form package holds IFR that
    /// uefisettings ignores, a FormSet that does not parse or nests too deep, the ops after one
    /// where its walk for FormSets ends or a FormSet without its Scope bit, whose second form edk2
    /// parses into it, has get and set read and write no variable: a PASSWORD question in it
    /// could name any variable. A HiiDB without that IFR withholds the PASSWORD's bytes as
    /// before. Through variables that reach Runtime, the variables that an ignored FormSet or the
    /// FormSet without its Scope bit declares are withheld whole, and the ops after an op where
    /// the walk ends close every variable.
    #[test]
    fn ignored_ifr_closes_every_variable_to_boot_services() {
        let offset = dropped_password_first_form_set().len();
        let ignored = format!(
            "PASSWORD questions of package list {} may be in the IFR that uefisettings ignores at \
             offset {offset} of a form package: ",
            Guid::from(DROPPED_PASSWORD_LIST_GUID)
        );
        let second = "the FormSet 11111111-1111-1111-1111-111111111111";
        let past_the_walk = format!(
            "PASSWORD questions of package list {} may be in the IFR that uefisettings ignores at \
             offset {offset} of a form package, which has no op boundary, so in any variable: ",
            Guid::from(DROPPED_PASSWORD_LIST_GUID)
        );
        let closed = "; as the variable of that password is unknown, the UEFI Shell build reads \
                      and writes no variable of this HiiDB";
        let refused = "; as a PASSWORD there may keep its password in any variable, uefisettings \
                       reads and writes no variable of this HiiDB";
        let withheld = Ok(vec![format!("{PASSWORD_BYTES} <IFR default: 0>")]);
        // a VARSTORE op that ends after 4 of the 20 bytes before its Name
        let malformed = operation(VAR_STORE, false, &[0x00; 4]);
        // the FormSet's own scope and these
        let too_deep = nested(&subtitle_scope(5), MAX_SCOPE_NESTING, &[]);
        // the Subtitle past the limit, after the second FormSet's other ops
        let too_deep_at = offset + form_set(&dropped_password_second_ops(Vec::new())).len()
            - END.len()
            + (MAX_SCOPE_NESTING - 1) * subtitle_scope(5).len();
        let dropped = [
            (
                "malformed",
                Vec::new(),
                form_set(&dropped_password_second_ops(malformed)),
                format!(
                    "{ignored}{second}, which holds, outside its forms, an op shorter than its \
                     minimum, which UEFI 2.11 §33.2.5.10.1 calls malformed, in no form for that \
                     section to disable: the EFI_IFR_VARSTORE op at offset "
                ),
                (withheld.clone(), &[][..]),
            ),
            (
                "nested too deep",
                Vec::new(),
                form_set(&dropped_password_second_ops(too_deep)),
                format!(
                    "{ignored}{second}, which nests too deep: IFR scopes nest deeper than \
                     {MAX_SCOPE_NESTING} at offset {too_deep_at} of a form package{closed}"
                ),
                (withheld.clone(), &[]),
            ),
            (
                "an End op of Length 1 before it",
                vec![0x29, 0x01],
                form_set(&dropped_password_second_ops(Vec::new())),
                format!(
                    "{past_the_walk}an op that does not fit the form package, and the bytes after \
                     it: invalid IFR operation length 1"
                ),
                (
                    Err(format!(
                        "{past_the_walk}an op that does not fit the form package, and the bytes \
                         after it: invalid IFR operation length 1 at {offset:#x}{refused}"
                    )),
                    &[],
                ),
            ),
            (
                "without its Scope bit",
                Vec::new(),
                scopeless_form_set(&dropped_password_second_ops(Vec::new())),
                format!(
                    "{ignored}{second} opens no scope, so edk2 parses its ops on to the end of the \
                     form package, past the End where uefisettings ends it (edk2-stable202211 \
                     SetupBrowserDxe IfrParse.c ParseOpCodes pushes a scope only for Scope != 0, \
                     and ends a FormSet only at the End of a FORM_SET scope){closed}"
                ),
                (withheld, &[]),
            ),
        ];
        let get = |hiidb: &[u8], variables: &Rc<MemoryVariables>| {
            HiiBackend::get_in(
                hiidb,
                "Q",
                None,
                &GetOptions::default(),
                shared(variables),
                None,
                None,
                None,
            )
            .map(|got| {
                got.responses
                    .iter()
                    .map(|response| response.question.answer.clone())
                    .collect::<Vec<_>>()
            })
        };
        let set = |hiidb: &[u8], variables: &Rc<MemoryVariables>| {
            set_responses(
                hiidb,
                "Q",
                &SetValue::Text("0".to_owned()),
                None,
                &SetOptions::default(),
                SetAccess {
                    reads: shared(variables),
                    writes: &**variables,
                    held: None,
                },
                None,
            )
            .map(drop)
        };
        let variables_of = |reach, interface| {
            let variables = MemoryVariables::new(reach, interface);
            variables.insert(dropped_password_store(), NV_BS_RT, &[0xAA; 20]);
            Rc::new(variables)
        };

        for (case, between, second_form_set, want, (runtime, reads)) in dropped {
            let hiidb = dropped_password_hiidb(between, second_form_set);
            let variables = variables_of(
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            );
            for (command, got) in [
                (
                    "get",
                    get(&hiidb, &variables).map(|answers| format!("{answers:?}")),
                ),
                ("set", set(&hiidb, &variables).map(|()| String::new())),
            ] {
                let got = got.map_err(|error| error.to_string());
                assert!(
                    got.as_ref()
                        .is_err_and(|error| error.starts_with(&want) && error.ends_with(closed)),
                    "{case}: BootServices: {command}: {got:?}, reads {:?}",
                    variables.reads()
                );
            }
            assert_eq!(variables.reads(), [], "{case}: BootServices: reads");
            assert_eq!(
                variables.writes_to(&dropped_password_store()),
                [],
                "{case}: BootServices: writes"
            );

            let variables = variables_of(VariableReach::Runtime, VariableInterface::Efivarfs);
            assert_eq!(
                get(&hiidb, &variables).map_err(|error| error.to_string()),
                runtime,
                "{case}: Runtime: get"
            );
            let reads: Vec<(VariableKey, u16)> = reads
                .iter()
                .map(|&size| (dropped_password_store(), size))
                .collect();
            assert_eq!(variables.reads(), reads, "{case}: Runtime: reads");
        }

        let variables = variables_of(
            VariableReach::BootServices,
            VariableInterface::VariableServices,
        );
        assert_eq!(
            get(
                &dropped_password_hiidb(
                    Vec::new(),
                    form_set(&dropped_password_second_ops(Vec::new())),
                ),
                &variables
            )
            .map_err(|error| error.to_string()),
            Ok(vec![format!("{PASSWORD_BYTES} <IFR default: 0>")]),
            "no drop: BootServices: get"
        );
        assert_eq!(variables.reads(), [], "no drop: BootServices: reads");
    }

    /// A HiiDB of one package list, of DROPPED_PASSWORD_LIST_GUID, holding a form package of
    /// `ifr` and the strings Q1, Password and Q3 of string IDs 1 to 3.
    fn three_questions_hiidb(ifr: &[u8]) -> Vec<u8> {
        let packages = [
            form_package_of(ifr),
            en_strings_package_of(&["Q1", "Password", "Q3"]),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid(DROPPED_PASSWORD_LIST_GUID, &packages.concat())
    }

    /// The answers of get of `question` in `hiidb`, reading `variables`, or its error.
    fn answers_or_error_of(
        hiidb: &[u8],
        question: &str,
        variables: &Rc<MemoryVariables>,
    ) -> Result<Vec<String>, String> {
        HiiBackend::get_in(
            hiidb,
            question,
            None,
            &GetOptions::default(),
            shared(variables),
            None,
            None,
            None,
        )
        .map(|got| {
            got.responses
                .iter()
                .map(|response| response.question.answer.clone())
                .collect()
        })
        .map_err(|error| error.to_string())
    }

    /// The number of questions that set of `question` to "0" in `hiidb` under `policy` sets,
    /// reading and writing `variables`, or its error.
    fn set_count_of(
        hiidb: &[u8],
        question: &str,
        policy: UnsafeOperations,
        variables: &Rc<MemoryVariables>,
    ) -> Result<usize, String> {
        let options = SetOptions {
            unsafe_operations: policy,
            ..SetOptions::default()
        };
        set_responses(
            hiidb,
            question,
            &SetValue::Text("0".to_owned()),
            None,
            &options,
            SetAccess {
                reads: shared(variables),
                writes: &**variables,
                held: None,
            },
            None,
        )
        .map(|got| got.responses.len())
        .map_err(|error| error.to_string())
    }

    /// A VARSTORE op that ends after 4 of the 20 bytes before its Name: UEFI 2.11 §33.2.5.10.1
    /// calls it malformed.
    fn short_var_store() -> Vec<u8> {
        operation(VAR_STORE, false, &[0x00; 4])
    }

    /// The prefix of the refusal, through variables that reach BootServices, of a HiiDB of
    /// three_questions_hiidb with IFR that uefisettings ignores.
    fn three_questions_refusal() -> String {
        format!(
            "PASSWORD questions of package list {} may be in the IFR that uefisettings ignores at \
             offset ",
            Guid::from(DROPPED_PASSWORD_LIST_GUID)
        )
    }

    /// Through variables that reach Runtime, get reads the questions of a FormSet after one that
    /// uefisettings ignores, as edk2-stable202608 GetIfrBinaryData finds it, and those before, on
    /// a variable that the ignored one does not declare; through variables that reach
    /// BootServices, the PASSWORD of the ignored FormSet still closes every variable of the HiiDB.
    #[test]
    fn form_sets_after_an_ignored_one_are_read() {
        let ifr = [
            form_set(&[
                dropped_password_var_store(),
                form(1, &[checkbox_on(1, 1, 1)]),
            ]),
            form_set(&[
                ignored_form_set_var_store(),
                form(1, &[password_on(2, 2, 2, 0)]),
                short_var_store(),
            ]),
            form_set(&[
                dropped_password_var_store(),
                form(1, &[checkbox_on(3, 3, 1)]),
            ]),
        ]
        .concat();
        let hiidb = three_questions_hiidb(&ifr);
        let variables_of = |reach, interface| {
            let variables = MemoryVariables::new(reach, interface);
            variables.insert(dropped_password_store(), NV_BS_RT, &[0xAA; 20]);
            Rc::new(variables)
        };

        let runtime = variables_of(VariableReach::Runtime, VariableInterface::Efivarfs);
        for question in ["Q1", "Q3"] {
            assert_eq!(
                answers_or_error_of(&hiidb, question, &runtime),
                Ok(vec!["1".to_string()]),
                "Runtime: get {question}"
            );
        }

        let boot_services = variables_of(
            VariableReach::BootServices,
            VariableInterface::VariableServices,
        );
        for question in ["Q1", "Q3"] {
            let got = answers_or_error_of(&hiidb, question, &boot_services);
            assert!(
                got.as_ref()
                    .is_err_and(|error| error.starts_with(&three_questions_refusal())),
                "BootServices: get {question}: {got:?}"
            );
        }
        assert_eq!(boot_services.reads(), [], "BootServices: reads");
    }

    /// Through variables that reach Runtime, the variables that the ops from the FORM_SET op of a
    /// FormSet without its Scope bit to the next FORM_SET op declare, past its End too, are withheld
    /// whole, as edk2 parses a PASSWORD there into that FormSet; a question on a variable that the
    /// next FormSet declares reads. Through variables that reach BootServices, get refuses.
    #[test]
    fn variables_past_the_end_of_a_scopeless_form_set_are_withheld() {
        const OTHER_STORE_GUID: [u8; 16] = [0x5B; 16];
        let other_key = VariableKey {
            name: "UefisettingsOther".to_string(),
            guid: Guid::from(OTHER_STORE_GUID),
        };
        let ifr = [
            // which uefisettings ends at the End of form 1
            scopeless_form_set(&[
                form(1, &[]),
                dropped_password_var_store(),
                form(2, &[password_on(2, 2, 1, 0)]),
            ]),
            form_set_with_guid(
                [0x22; 16],
                &[
                    dropped_password_var_store(),
                    var_store_efi_of(2, OTHER_STORE_GUID, "UefisettingsOther", NV_BS_RT, 20),
                    form(1, &[checkbox_on(1, 1, 1), checkbox_on(3, 3, 2)]),
                ],
            ),
        ]
        .concat();
        let hiidb = three_questions_hiidb(&ifr);
        let variables_of = |reach, interface| {
            let variables = MemoryVariables::new(reach, interface);
            variables.insert(dropped_password_store(), NV_BS_RT, &[0xAA; 20]);
            variables.insert(other_key.clone(), NV_BS_RT, &[0xAA; 20]);
            Rc::new(variables)
        };

        let boot_services = variables_of(
            VariableReach::BootServices,
            VariableInterface::VariableServices,
        );
        let got = answers_or_error_of(&hiidb, "Q3", &boot_services);
        assert!(
            got.as_ref()
                .is_err_and(|error| error.starts_with(&three_questions_refusal())),
            "BootServices: get Q3: {got:?}"
        );
        assert_eq!(boot_services.reads(), [], "BootServices: reads");

        let runtime = variables_of(VariableReach::Runtime, VariableInterface::Efivarfs);
        assert_eq!(
            answers_or_error_of(&hiidb, "Q1", &runtime),
            Ok(vec![format!("{PASSWORD_BYTES} <IFR default: 0>")]),
            "Runtime: get Q1"
        );
        assert_eq!(
            answers_or_error_of(&hiidb, "Q3", &runtime),
            Ok(vec!["1".to_string()]),
            "Runtime: get Q3"
        );
        assert_eq!(runtime.reads(), [(other_key, 20)], "Runtime: reads");
    }

    /// Through variables that reach Runtime, every variable of the GUID of a VARSTORE_EFI of the
    /// form before UEFI 2.3.1 in a FormSet that uefisettings ignores is withheld whole, as the
    /// VarName of a PASSWORD on it, which is not read, names its variable by any string: a
    /// question on another variable of that GUID shows none, one on a variable of another GUID
    /// reads. Every variable is withheld where the Guid of that VARSTORE_EFI runs past the form
    /// package, so is unknown. Through variables that reach BootServices, get refuses.
    #[test]
    fn every_variable_of_a_short_var_store_in_ignored_ifr_is_withheld() {
        let short_store_variable = VariableKey {
            name: "UefisettingsShort".to_string(),
            guid: Guid::from(SHORT_VAR_STORE_GUID),
        };
        let parsed = form_set(&[
            var_store_efi_of(1, SHORT_VAR_STORE_GUID, "UefisettingsShort", NV_BS_RT, 20),
            var_store_efi_of(
                2,
                DROPPED_PASSWORD_STORE_GUID,
                "UefisettingsTest",
                NV_BS_RT,
                20,
            ),
            form(1, &[checkbox_on(1, 1, 1), checkbox_on(3, 3, 2)]),
        ]);
        // VarName 2, "Password"
        let password = form(1, &[password_on(2, 2, 1, 2)]);
        let withheld = Ok(vec![format!("{PASSWORD_BYTES} <IFR default: 0>")]);
        let cases = [
            (
                "a short CHECKBOX outside its forms",
                [
                    form_set_with_guid(
                        [0x44; 16],
                        &[
                            short_var_store_efi_of(1, SHORT_VAR_STORE_GUID, NV_BS_RT),
                            password.clone(),
                            operation(CHECKBOX, false, &[0x00; 4]),
                        ],
                    ),
                    parsed.clone(),
                ]
                .concat(),
                Ok(vec!["1".to_string()]),
                vec![(dropped_password_store(), 20)],
            ),
            (
                "a VARSTORE_EFI that ends after its VarStoreId, last",
                [
                    parsed,
                    form_set_with_guid(
                        [0x44; 16],
                        &[
                            password,
                            operation(VAR_STORE_EFI, false, &1u16.to_le_bytes()),
                        ],
                    ),
                ]
                .concat(),
                withheld.clone(),
                vec![],
            ),
        ];
        for (case, ifr, q3, reads) in cases {
            let hiidb = three_questions_hiidb(&ifr);
            let variables_of = |reach, interface| {
                let variables = MemoryVariables::new(reach, interface);
                variables.insert(dropped_password_store(), NV_BS_RT, &[0xAA; 20]);
                variables.insert(short_store_variable.clone(), NV_BS_RT, &[0xAA; 20]);
                Rc::new(variables)
            };

            let boot_services = variables_of(
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            );
            let got = answers_or_error_of(&hiidb, "Q3", &boot_services);
            assert!(
                got.as_ref()
                    .is_err_and(|error| error.starts_with(&three_questions_refusal())),
                "{case}: BootServices: get Q3: {got:?}"
            );
            assert_eq!(boot_services.reads(), [], "{case}: BootServices: reads");

            let runtime = variables_of(VariableReach::Runtime, VariableInterface::Efivarfs);
            assert_eq!(
                answers_or_error_of(&hiidb, "Q1", &runtime),
                withheld,
                "{case}: Runtime: get Q1"
            );
            assert_eq!(
                answers_or_error_of(&hiidb, "Q3", &runtime),
                q3,
                "{case}: Runtime: get Q3"
            );
            assert_eq!(runtime.reads(), reads, "{case}: Runtime: reads");
        }
    }

    /// By QuestionId, a question of a disabled form or of an ignored FormSet is refused as by its
    /// prompt: get answers none and lists the same records, and set's MaybeInIgnoredIfr names
    /// them.
    #[test]
    fn question_ids_in_ignored_ifr_are_refused_as_prompts() {
        let (disabled_form, _) = disabled_form_hiidb(operation(CHECKBOX, false, &[0x00; 4]));
        let ignored_form_set = three_questions_hiidb(
            &[
                form_set(&[
                    dropped_password_var_store(),
                    form(1, &[checkbox_on(1, 1, 1)]),
                ]),
                form_set_with_guid(
                    [0x33; 16],
                    &[
                        dropped_password_var_store(),
                        form(1, &[checkbox_on(3, 3, 1)]),
                        short_var_store(),
                    ],
                ),
            ]
            .concat(),
        );
        let options = SetOptions {
            unsafe_operations: UnsafeOperations::Allow,
            ..SetOptions::default()
        };
        let cases = [
            ("a disabled form", disabled_form, "Q2", [0x11; 16], 2),
            ("an ignored FormSet", ignored_form_set, "Q3", [0x33; 16], 3),
        ];
        for (case, hiidb, prompt, form_set, question_id) in cases {
            let refusals = [
                QuestionSelector::from(prompt),
                by_address(&format!("{}:{question_id}", Guid::from(form_set))),
            ]
            .map(|question| {
                let variables =
                    disabled_form_variables(VariableReach::Runtime, VariableInterface::Efivarfs);
                let got = HiiBackend::get_in(
                    &hiidb,
                    question.clone(),
                    None,
                    &GetOptions::default(),
                    shared(&variables),
                    None,
                    None,
                    None,
                )
                .unwrap_or_else(|error| panic!("{case}: get {question}: {error:#}"));
                let set = set_responses(
                    &hiidb,
                    question.clone(),
                    &SetValue::Text("0".to_owned()),
                    None,
                    &options,
                    SetAccess {
                        reads: shared(&variables),
                        writes: &*variables,
                        held: None,
                    },
                    None,
                )
                .map(drop)
                .map_err(|error| error.to_string());
                let records = set.as_ref().err().and_then(|error| {
                    error
                        .strip_prefix(&format!(
                            "no question {:?} in the HiiDB, but it may be in ",
                            question.to_string()
                        ))
                        .map(str::to_owned)
                });
                assert!(records.is_some(), "{case}: set {question}: {set:?}");
                (got.responses.len(), got.ignored_ifr, records)
            });
            let [by_prompt, by_question_id] = refusals;
            assert_eq!(by_prompt.0, 0, "{case}: get by prompt");
            assert!(
                by_prompt
                    .1
                    .as_ref()
                    .is_some_and(|records| !records.is_empty()),
                "{case}: get by prompt: ignored_ifr"
            );
            assert_eq!(by_question_id, by_prompt, "{case}: by QuestionId");
        }
    }

    /// Through variables that reach BootServices, get and set, with and without the setup
    /// password bypass, refuse and touch no variable when a PASSWORD may sit in IFR that the
    /// parser does not read: a FormSet that it ignores, a FormSet after one, and a FormSet in one
    /// that has its End, which edk2's walk for FormSets finds. Through variables that reach
    /// Runtime, the questions around that IFR read, but those on a variable that a VARSTORE or
    /// VARSTORE_EFI op in an ignored FormSet declares, which is withheld whole. Without IFR that it
    /// ignores, the PASSWORD that it reads leaves get and the bypassed set open.
    #[test]
    fn unread_password_regions_close_boot_services() {
        const PASSWORD_STORE_GUID: [u8; 16] = [0x5A; 16];
        let password_key = VariableKey {
            name: "UefisettingsPw".to_string(),
            guid: Guid::from(PASSWORD_STORE_GUID),
        };
        let password_store =
            || var_store_efi_of(2, PASSWORD_STORE_GUID, "UefisettingsPw", NV_BS_RT, 20);
        let q1 = form_set(&[
            dropped_password_var_store(),
            form(1, &[checkbox_on(1, 1, 1)]),
        ]);
        let q3 = form_set(&[
            dropped_password_var_store(),
            form(1, &[checkbox_on(3, 3, 1)]),
        ]);
        // Q3 and a PASSWORD on the variable of password_key
        let q3_and_password = || {
            form_set(&[
                dropped_password_var_store(),
                password_store(),
                form(1, &[checkbox_on(3, 3, 1), password_on(2, 2, 2, 0)]),
            ])
        };
        let read = Ok(vec!["1".to_string()]);
        let withheld = Ok(vec![format!("{PASSWORD_BYTES} <IFR default: 0>")]);
        // each with what get of Q1 and Q3 answers through variables that reach Runtime
        let cases: [(&str, Vec<u8>, _); 4] = [
            (
                "a PASSWORD in an ignored FormSet",
                [
                    q1.clone(),
                    form_set(&[
                        password_store(),
                        form(1, &[password_on(2, 2, 2, 0)]),
                        short_var_store(),
                    ]),
                    q3,
                ]
                .concat(),
                read.clone(),
            ),
            (
                "a PASSWORD in a FormSet after an ignored one",
                [
                    q1.clone(),
                    form_set(&[password_store(), short_var_store()]),
                    q3_and_password(),
                ]
                .concat(),
                read.clone(),
            ),
            (
                // the nested FormSet's VARSTORE_EFI of dropped_password_store is in the ignored one
                "a PASSWORD in a FormSet in an ignored one that has its End",
                [
                    q1.clone(),
                    form_set(&[
                        dropped_password_var_store(),
                        short_var_store(),
                        q3_and_password(),
                    ]),
                ]
                .concat(),
                withheld,
            ),
            (
                "control: a PASSWORD in a FormSet after a FormSet that parses",
                [
                    q1,
                    form_set(&[dropped_password_var_store()]),
                    q3_and_password(),
                ]
                .concat(),
                read,
            ),
        ];
        let variables_of = |reach, interface| {
            let variables = MemoryVariables::new(reach, interface);
            variables.insert(dropped_password_store(), NV_BS_RT, &[0xAA; 20]);
            variables.insert(password_key.clone(), NV_BS_RT, &[0x00; 20]);
            Rc::new(variables)
        };
        let refused = three_questions_refusal();
        for (name, ifr, runtime_answers) in cases {
            let hiidb = three_questions_hiidb(&ifr);

            let runtime = variables_of(VariableReach::Runtime, VariableInterface::Efivarfs);
            for question in ["Q1", "Q3"] {
                assert_eq!(
                    answers_or_error_of(&hiidb, question, &runtime),
                    runtime_answers,
                    "{name}: Runtime: get {question}"
                );
            }

            let control = name.starts_with("control");
            for question in ["Q1", "Q3"] {
                // each question on its own variables: a bypassed set writes byte 0, which both
                // CHECKBOXes read
                let boot_services = variables_of(
                    VariableReach::BootServices,
                    VariableInterface::VariableServices,
                );
                let got = answers_or_error_of(&hiidb, question, &boot_services);
                match control {
                    false => assert!(
                        got.as_ref().is_err_and(|error| error.starts_with(&refused)),
                        "{name}: BootServices: get {question}: {got:?}"
                    ),
                    true => assert_eq!(
                        got,
                        Ok(vec!["1".to_string()]),
                        "{name}: BootServices: get {question}"
                    ),
                }
                for policy in [UnsafeOperations::Refuse, UnsafeOperations::Allow] {
                    let got = set_count_of(&hiidb, question, policy, &boot_services);
                    match (control, policy) {
                        (false, _) => assert!(
                            got.as_ref().is_err_and(|error| error.starts_with(&refused)),
                            "{name}: BootServices: set {question} {policy:?}: {got:?}"
                        ),
                        (true, UnsafeOperations::Refuse) => assert!(
                            got.as_ref().is_err_and(|error| error
                                .starts_with("this HiiDB declares a setup password question")),
                            "{name}: BootServices: set {question} {policy:?}: {got:?}"
                        ),
                        (true, _) => assert_eq!(
                            got,
                            Ok(1),
                            "{name}: BootServices: set {question} {policy:?}"
                        ),
                    }
                }
                match control {
                    false => {
                        assert_eq!(
                            boot_services.reads(),
                            [],
                            "{name}: BootServices: {question}: reads"
                        );
                        assert_eq!(
                            boot_services.writes_to(&dropped_password_store()),
                            [],
                            "{name}: BootServices: {question}: writes"
                        );
                    }
                    true => assert_eq!(
                        boot_services.writes_to(&dropped_password_store()),
                        [(0, vec![0])],
                        "{name}: BootServices: {question}: the bypassed set writes"
                    ),
                }
                assert_eq!(
                    boot_services.reads_of(&password_key),
                    Vec::<u16>::new(),
                    "{name}: BootServices: {question}: the PASSWORD's variable stays unread"
                );
                assert_eq!(
                    boot_services.writes_to(&password_key),
                    [],
                    "{name}: BootServices: {question}: no PASSWORD write"
                );
            }
        }
    }

    /// A first FormSet that does not parse or nests too deep is ignored like a later one: through
    /// variables that reach Runtime the FormSet after it reads, and through variables that reach
    /// BootServices a PASSWORD in it still closes get and set, bypassed or not, with no variable
    /// read or written.
    #[test]
    fn a_malformed_first_form_set_is_ignored_like_a_later_one() {
        // the FormSet's own scope and these
        let too_deep = nested(&subtitle_scope(5), MAX_SCOPE_NESTING, &[]);
        let q3 = form_set(&[
            dropped_password_var_store(),
            form(1, &[checkbox_on(3, 3, 1)]),
        ]);
        let cases = [
            (
                "a first FormSet that does not parse",
                form_set(&[
                    ignored_form_set_var_store(),
                    form(1, &[password_on(2, 2, 2, 0)]),
                    short_var_store(),
                ]),
            ),
            (
                "a first FormSet nested too deep",
                form_set(&[
                    ignored_form_set_var_store(),
                    form(1, &[password_on(2, 2, 2, 0)]),
                    too_deep,
                ]),
            ),
        ];
        let refused = format!("{}0 of a form package: ", three_questions_refusal());
        let variables_of = |reach, interface| {
            let variables = MemoryVariables::new(reach, interface);
            variables.insert(dropped_password_store(), NV_BS_RT, &[0xAA; 20]);
            Rc::new(variables)
        };
        for (name, first) in cases {
            let hiidb = three_questions_hiidb(&[first, q3.clone()].concat());

            let runtime = variables_of(VariableReach::Runtime, VariableInterface::Efivarfs);
            assert_eq!(
                answers_or_error_of(&hiidb, "Q3", &runtime),
                Ok(vec!["1".to_string()]),
                "{name}: Runtime: get Q3"
            );

            let boot_services = variables_of(
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            );
            let got = answers_or_error_of(&hiidb, "Q3", &boot_services);
            assert!(
                got.as_ref().is_err_and(|error| error.starts_with(&refused)),
                "{name}: BootServices: get Q3: {got:?}"
            );
            for policy in [UnsafeOperations::Refuse, UnsafeOperations::Allow] {
                let got = set_count_of(&hiidb, "Q3", policy, &boot_services);
                assert!(
                    got.as_ref().is_err_and(|error| error.starts_with(&refused)),
                    "{name}: BootServices: set Q3 {policy:?}: {got:?}"
                );
            }
            assert_eq!(boot_services.reads(), [], "{name}: BootServices: reads");
            assert_eq!(
                boot_services.writes_to(&dropped_password_store()),
                [],
                "{name}: BootServices: writes"
            );
        }
    }

    /// The offsets of the records of IFR that uefisettings ignores that `error` names, in order.
    fn offsets_named(error: &str) -> Vec<String> {
        error
            .split("uefisettings ignores at offset ")
            .skip(1)
            .map(|rest| rest.split(' ').next().unwrap_or_default().to_string())
            .collect()
    }

    /// Through variables that reach BootServices, get's refusal names each FormSet that
    /// uefisettings ignores, at its offset.
    #[test]
    fn the_refusal_names_every_ignored_form_set() {
        let q1 = form_set(&[
            dropped_password_var_store(),
            form(1, &[checkbox_on(1, 1, 1)]),
        ]);
        let ignored = form_set(&[dropped_password_var_store(), short_var_store()]);
        let hiidb = three_questions_hiidb(&[q1.clone(), ignored.clone(), ignored.clone()].concat());
        let variables = MemoryVariables::new(
            VariableReach::BootServices,
            VariableInterface::VariableServices,
        );
        variables.insert(dropped_password_store(), NV_BS_RT, &[0xAA; 20]);
        let error = answers_or_error_of(&hiidb, "Q1", &Rc::new(variables))
            .expect_err("BootServices: get Q1");
        let want = [q1.len(), q1.len() + ignored.len()].map(|offset| offset.to_string());
        assert_eq!(offsets_named(&error), want, "{error}");
    }

    /// The refusals that name the IFR that uefisettings ignores name its first 16 records and
    /// count the rest: get's through variables that reach BootServices, and set's of a question
    /// that no FormSet that it reads holds, through variables that reach Runtime.
    #[test]
    fn refusals_name_16_ignored_form_sets_and_count_the_rest() {
        let q1 = form_set(&[
            dropped_password_var_store(),
            form(1, &[checkbox_on(1, 1, 1)]),
        ]);
        let ignored = form_set(&[dropped_password_var_store(), short_var_store()]);
        let hiidb = three_questions_hiidb(&[q1.clone(), ignored.repeat(17)].concat());
        let want: Vec<String> = (0..16)
            .map(|index| (q1.len() + index * ignored.len()).to_string())
            .collect();
        let variables_of = |reach, interface| {
            let variables = MemoryVariables::new(reach, interface);
            variables.insert(dropped_password_store(), NV_BS_RT, &[0xAA; 20]);
            Rc::new(variables)
        };

        let boot_services = variables_of(
            VariableReach::BootServices,
            VariableInterface::VariableServices,
        );
        let error =
            answers_or_error_of(&hiidb, "Q1", &boot_services).expect_err("BootServices: get Q1");
        assert_eq!(offsets_named(&error), want, "BootServices: get Q1: {error}");
        assert!(
            error.contains("; and 1 more; as the variable of that password is unknown"),
            "BootServices: get Q1: {error}"
        );

        let runtime = variables_of(VariableReach::Runtime, VariableInterface::Efivarfs);
        let error = set_count_of(&hiidb, "Q2", UnsafeOperations::Refuse, &runtime)
            .expect_err("Runtime: set Q2");
        assert_eq!(offsets_named(&error), want, "Runtime: set Q2: {error}");
        assert!(error.ends_with("; and 1 more"), "Runtime: set Q2: {error}");
    }

    /// get and set name the IFR that uefisettings ignores in a HiiDB, through variables that
    /// reach Runtime too, where it closes nothing: get and set list it in the ignored_ifr of their
    /// answer, a question in it or not, and set's refusal of a question that no FormSet it reads
    /// holds names it. Without such IFR, neither answer has an ignored_ifr and the refusal names
    /// the question alone.
    #[test]
    fn get_and_set_name_the_ifr_that_uefisettings_ignores() {
        let q1 = form_set(&[
            dropped_password_var_store(),
            form(1, &[checkbox_on(1, 1, 1)]),
        ]);
        // a FormSet that uefisettings ignores, with the CHECKBOX Q2 of string ID 2
        let ignored = form_set(&[
            ignored_form_set_var_store(),
            form(1, &[checkbox_on(2, 2, 2)]),
            short_var_store(),
        ]);
        let q3 = form_set(&[
            dropped_password_var_store(),
            form(1, &[checkbox_on(3, 3, 1)]),
        ]);
        let hiidb = three_questions_hiidb(&[q1.clone(), ignored, q3.clone()].concat());
        let without = three_questions_hiidb(&[q1.clone(), q3].concat());
        let list = Guid::from(DROPPED_PASSWORD_LIST_GUID).to_string();
        let reason = format!(
            "the FormSet {}, which holds, outside its forms, an op shorter than its minimum, which \
             UEFI 2.11 §33.2.5.10.1 calls malformed, in no form for that section to disable: the \
             EFI_IFR_VARSTORE op at offset ",
            Guid::from([0x11; 16])
        );
        let offset = q1.len();
        let variables = || {
            let variables =
                MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);
            variables.insert(dropped_password_store(), NV_BS_RT, &[0xAA; 20]);
            Rc::new(variables)
        };
        // the ignored_ifr of the JSON of `answer`: (package list, offset, whether the reason is
        // `reason`), None if unset
        let ignored_ifr_of = |answer: Vec<u8>| -> Option<Vec<(String, u64, bool)>> {
            let answer: serde_json::Value =
                serde_json::from_slice(&answer).expect("parse the JSON of an answer");
            let records = answer.get("ignored_ifr")?.as_array()?;
            Some(
                records
                    .iter()
                    .map(|record| {
                        (
                            record["package_list"]
                                .as_str()
                                .unwrap_or_default()
                                .to_string(),
                            record["offset"].as_u64().unwrap_or(u64::MAX),
                            record["reason"]
                                .as_str()
                                .is_some_and(|got| got.starts_with(&reason)),
                        )
                    })
                    .collect(),
            )
        };
        let want = Some(vec![(
            list.clone(),
            u64::try_from(offset).expect("offset"),
            true,
        )]);
        let get = |hiidb: &[u8], question: &str| {
            HiiBackend::get_in(
                hiidb,
                question,
                None,
                &GetOptions::default(),
                shared(&variables()),
                None,
                None,
                None,
            )
            .unwrap_or_else(|error| panic!("get {question}: {error:#}"))
        };
        let set = |hiidb: &[u8], question: &str| {
            let variables = variables();
            set_responses(
                hiidb,
                question,
                &SetValue::Text("0".to_owned()),
                None,
                &SetOptions::default(),
                SetAccess {
                    reads: shared(&variables),
                    writes: &*variables,
                    held: None,
                },
                None,
            )
            .map_err(|error| error.to_string())
        };

        for (question, answers) in [("Q3", vec!["1"]), ("Q2", vec![])] {
            let got = get(&hiidb, question);
            let got_answers: Vec<&str> = got
                .responses
                .iter()
                .map(|response| response.question.answer.as_str())
                .collect();
            assert_eq!(got_answers, answers, "get {question}: answers");
            assert_eq!(
                ignored_ifr_of(simplejson_protocol::serialize(&got).to_vec()),
                want,
                "get {question}: ignored_ifr"
            );
        }
        assert_eq!(
            ignored_ifr_of(simplejson_protocol::serialize(get(&without, "Q3")).to_vec()),
            None,
            "get Q3 without ignored IFR: ignored_ifr"
        );

        let set_q3 = set(&hiidb, "Q3").unwrap_or_else(|error| panic!("set Q3: {error}"));
        assert_eq!(set_q3.responses.len(), 1, "set Q3: responses");
        assert_eq!(
            ignored_ifr_of(simplejson_protocol::serialize(&set_q3).to_vec()),
            want,
            "set Q3: ignored_ifr"
        );
        let set_q3 = set(&without, "Q3").unwrap_or_else(|error| panic!("set Q3: {error}"));
        assert_eq!(
            ignored_ifr_of(simplejson_protocol::serialize(&set_q3).to_vec()),
            None,
            "set Q3 without ignored IFR: ignored_ifr"
        );

        let got = set(&hiidb, "Q2");
        let refusal = format!(
            "no question \"Q2\" in the HiiDB, but it may be in the IFR that uefisettings ignores \
             at offset {offset} of a form package of package list {list}: {reason}"
        );
        assert!(
            got.as_ref().is_err_and(|error| error.starts_with(&refusal)),
            "set Q2: {got:?}"
        );
        assert_eq!(
            set(&without, "Q2").map(drop),
            Err("no question \"Q2\" in the HiiDB".to_string()),
            "set Q2 without ignored IFR"
        );
    }

    /// A HiiDB of two package lists: one whose FormSet declares no VarStore, then one whose
    /// question Q, on the EFI variable Setup, is grayed out when question 2, on `var_store`, is 1.
    fn access_level_hiidb(var_store: Vec<u8>) -> Vec<u8> {
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, 1),
                var_store,
                form(
                    1,
                    &[
                        checkbox_on(2, 2, 2),
                        conditional(GRAY_OUT_IF, eq_id_val_of(2, 1), &[checkbox_on(1, 1, 1)]),
                    ],
                ),
            ]),
            en_strings_package(b'Q'),
            END_PACKAGE.to_vec(),
        ];
        [
            form_set_list([0x33; 16], b'A'),
            package_list_with_guid([0x55; 16], &packages.concat()),
        ]
        .concat()
    }

    /// set selects at a stated access level, before any write, and refuses one for a HiiDB that
    /// declares no SystemAccess.
    #[cfg(efivar_dumps)]
    #[test]
    fn set_selects_at_the_stated_access_level() {
        let ami = access_level_hiidb(var_store(2, SYSTEM_ACCESS_GUID, "SystemAccess", 1));
        let other = access_level_hiidb(var_store(2, [0; 16], "SystemAccess", 1));
        let efivars = tempfile::tempdir().expect("create efivars directory");
        fs::write(
            efivars
                .path()
                .join("Setup-00000000-0000-0000-0000-000000000000"),
            [7, 0, 0, 0, 1],
        )
        .expect("write efivar file");
        let select = |hiidb: &[u8], access_level| {
            let options = SetOptions {
                access_level,
                ..SetOptions::default()
            };
            select_for_set(
                &package::read_db(hiidb).expect("parse the HiiDB"),
                &QuestionSelector::from("Q"),
                &BTreeSet::from(["Q".to_string()]),
                &options,
                &[],
                &mut PendingOperations::new(UnsafeOperations::Refuse),
                &mut EfivarReader::new(EfivarSource::Directory(efivars.path().to_path_buf()))
                    .expect("create a reader of the efivars directory"),
                None,
            )
            .map(|selected| {
                selected
                    .into_iter()
                    .map(|selected| selected.descriptor.question)
                    .collect::<Vec<_>>()
            })
        };

        assert_eq!(
            select(&ami, Some(AccessLevel::Administrator)).expect("select as Administrator"),
            ["Q"],
            "Administrator"
        );
        let user = select(&ami, Some(AccessLevel::User)).expect_err("select as User");
        assert_eq!(
            user.downcast_ref::<SelectionError>(),
            Some(&SelectionError::Excluded {
                question: "Q".to_string(),
                states: IncludedStates::GRAYED_OUT,
            }),
            "User: {user:#}"
        );
        let no_level = select(&ami, None).expect_err("select without a level");
        assert!(
            matches!(
                no_level.downcast_ref::<SelectionError>(),
                Some(SelectionError::Undetermined { states, .. })
                    if *states == IncludedStates::GRAYED_OUT
            ),
            "no level: {no_level:#}"
        );
        for level in [AccessLevel::Administrator, AccessLevel::User] {
            assert_eq!(
                select(&other, Some(level)).map_err(|error| error.to_string()),
                Err(
                    "--access-level applies to AMI firmware whose HiiDB declares the \
                     SystemAccess VarStore; this HiiDB declares none"
                        .to_string()
                ),
                "{level:?}, SystemAccess of NIL_GUID"
            );
        }
    }

    /// get and list-questions evaluate the conditions on AMI firmware's SystemAccess at a
    /// stated access level, and refuse one for a HiiDB that declares no SystemAccess.
    #[test]
    fn options_state_the_access_level() {
        let ami = access_level_hiidb(var_store(2, SYSTEM_ACCESS_GUID, "SystemAccess", 1));
        let other = access_level_hiidb(var_store(2, [0; 16], "SystemAccess", 1));
        let get = |hiidb: &[u8], access_level| {
            let options = GetOptions {
                efivars: EfivarSource::Disabled,
                access_level,
                ..GetOptions::default()
            };
            HiiBackend::get_using(hiidb, "Q", None, &options).map(|got| {
                got.responses
                    .into_iter()
                    .map(|response| response.question.answer)
                    .collect::<Vec<_>>()
            })
        };
        let list = |hiidb: &[u8], access_level| {
            let options = ListQuestionsOptions {
                efivars: EfivarSource::Disabled,
                access_level,
                ..ListQuestionsOptions::default()
            };
            HiiBackend::list_questions_using(hiidb, &options).map(|listed| {
                listed
                    .into_iter()
                    .filter(|question| question.name == "Q")
                    .map(|question| question.answer)
                    .collect::<Vec<_>>()
            })
        };
        let not_read = "<ValueUnavailable: EFI variables not read> <IFR default: 0>";

        let administrator = Some(AccessLevel::Administrator);
        assert_eq!(
            get(&ami, administrator).expect("get as Administrator"),
            [not_read],
            "get as Administrator"
        );
        assert_eq!(
            list(&ami, administrator).expect("list as Administrator"),
            [not_read],
            "list-questions as Administrator"
        );
        let user = Some(AccessLevel::User);
        let error = get(&ami, user).expect_err("get as User");
        assert_eq!(
            error.downcast_ref::<SelectionError>(),
            Some(&SelectionError::Excluded {
                question: "Q".to_string(),
                states: IncludedStates::GRAYED_OUT,
            }),
            "get as User: {error:#}"
        );
        assert_eq!(
            list(&ami, user).expect("list as User"),
            Vec::<String>::new(),
            "list-questions as User"
        );

        let refusal = "--access-level applies to AMI firmware whose HiiDB declares the \
                       SystemAccess VarStore; this HiiDB declares none";
        for level in [administrator, user] {
            assert_eq!(
                get(&other, level).map_err(|error| error.to_string()),
                Err(refusal.to_string()),
                "get, {level:?}, SystemAccess of NIL_GUID"
            );
            assert_eq!(
                list(&other, level).map_err(|error| error.to_string()),
                Err(refusal.to_string()),
                "list-questions, {level:?}, SystemAccess of NIL_GUID"
            );
        }
        assert!(get(&other, None).is_ok(), "get, no level");
        assert!(list(&other, None).is_ok(), "list-questions, no level");
    }

    /// get, list-questions and show-ifr refuse an efivars directory that is not one, rather
    /// than read every question as missing.
    #[cfg(efivar_dumps)]
    #[test]
    fn options_refuse_an_efivars_directory_that_is_not_one() {
        let hiidb = package_list_with_guid(
            [0x55; 16],
            &[
                form_set_package(),
                en_strings_package(b'Q'),
                END_PACKAGE.to_vec(),
            ]
            .concat(),
        );
        let missing = tempfile::tempdir()
            .expect("create directory")
            .path()
            .join("missing");
        let want = format!("efivars directory {} is not a directory", missing.display());
        let efivars = EfivarSource::Directory(missing);
        let get_options = GetOptions {
            efivars: efivars.clone(),
            ..GetOptions::default()
        };
        let list_options = ListQuestionsOptions {
            efivars: efivars.clone(),
            ..ListQuestionsOptions::default()
        };

        let errors = [
            (
                "get",
                HiiBackend::get_using(&hiidb, "Q", None, &get_options).map(drop),
            ),
            (
                "list-questions",
                HiiBackend::list_questions_using(&hiidb, &list_options).map(drop),
            ),
            (
                "show-ifr",
                HiiBackend::show_ifr_using(
                    &hiidb,
                    &ShowIfrOptions {
                        efivars,
                        ..Default::default()
                    },
                )
                .map(drop),
            ),
        ];
        for (case, result) in errors {
            let error = result.expect_err("read from a directory that is not one");

            assert_eq!(error.to_string(), want, "{case}");
        }
    }

    /// show_ifr and list_questions fail for a package list with forms but no
    /// strings packages, rather than use those of a list of the same GUID.
    #[test]
    fn test_forms_without_strings_are_an_error() {
        let forms_only = [&form_set_package()[..], &END_PACKAGE].concat();
        let hiidb = [
            package_list_with_guid([0x44; 16], &forms_only),
            en_strings_list([0x44; 16], b'S'),
        ]
        .concat();
        let want = "Failed to get string packages using GUID 44444444-4444-4444-4444-444444444444";
        // no variables: on Windows, System enables a privilege that needs elevation
        let efivars = EfivarSource::Disabled;
        let show_options = ShowIfrOptions {
            efivars: efivars.clone(),
            ..Default::default()
        };
        let list_options = ListQuestionsOptions {
            efivars,
            ..ListQuestionsOptions::default()
        };

        let Err(err) = HiiBackend::show_ifr_using(&hiidb, &show_options) else {
            panic!("show_ifr used the strings of another list");
        };
        assert_eq!(format!("{err:#}"), want, "show_ifr");

        let Err(err) = HiiBackend::list_questions_using(&hiidb, &list_options) else {
            panic!("list_questions used the strings of another list");
        };
        assert_eq!(format!("{err:#}"), want, "list_questions");
    }

    /// The scopes of the FormSet and the Form of nested_subtitles_hiidb
    const FORM_SCOPES: usize = 2;

    /// A HiiDB whose Form nests `subtitles` Subtitle scopes around a CheckBox prompted "Deep", in
    /// the scope of an unknown op if `in_unknown_scope`.
    fn nested_subtitles_hiidb(subtitles: usize, in_unknown_scope: bool) -> Vec<u8> {
        let nested = nested(&subtitle_scope(2), subtitles, &[checkbox_on(1, 2, 0)]);
        let body = match in_unknown_scope {
            true => [unknown_scope(), nested, END.to_vec()].concat(),
            false => nested,
        };
        let packages = [
            en_strings_package_of(&["FormSet", "Deep"]),
            form_package(&[form(1, &[body])]),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid([0x55; 16], &packages.concat())
    }

    /// An op of the unknown opcode 0x70 opening a scope.
    fn unknown_scope() -> Vec<u8> {
        operation(0x70, true, &[])
    }

    /// Every command ignores the FormSet of a HiiDB whose VarStore op ends inside its Name, and
    /// the record of that FormSet, which list-questions prints on stderr and refusals name, gives
    /// the error on one line: the fields being parsed, without the Rust source locations of
    /// binrw's backtrace frames.
    #[test]
    fn commands_ignore_a_truncated_var_store_and_name_it_on_one_line() {
        // EFI_IFR_VARSTORE of the Length of an empty Name, whose last byte is no NUL
        let var_store = operation(0x24, false, &[&[0x11; 20][..], b"A"].concat());
        let packages = [
            en_strings_package_of(&["FormSet"]),
            form_package(&[var_store]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x55; 16], &packages.concat());
        let want = format!(
            "the IFR that uefisettings ignores at offset 0 of a form package of package list \
             55555555-5555-5555-5555-555555555555: the FormSet {}, which holds, outside its \
             forms, an op that uefisettings does not decode: the EFI_IFR_VARSTORE op at offset \
             39 of a form package: failed to parse op_code VarStore properly: failed to parse \
             VarStore's data: failed to fill whole buffer (While parsing field 'name' in \
             VarStore)",
            Guid::from([0x11; 16])
        );
        for (name, command) in commands() {
            let got = command(&hiidb).unwrap_or_else(|error| panic!("{name}: {error:#}"));
            let want: &[&str] = match name {
                "list-strings" => &["FormSet"],
                _ => &[],
            };
            assert_eq!(got, want, "{name}");
        }
        let records: Vec<String> = HiiBackend::ignored_ifr(&hiidb)
            .unwrap_or_else(|error| panic!("ignored_ifr: {error:#}"))
            .iter()
            .map(ToString::to_string)
            .collect();
        for record in &records {
            assert!(
                !record.contains('\n') && !record.contains("src/"),
                "{record:?}"
            );
        }
        assert_eq!(records, [want], "ignored_ifr");
    }

    /// A command of the tests below: what it prints of a HiiDB, line by line.
    type Command = fn(&[u8]) -> Result<Vec<String>>;

    /// The commands of the tests below, each with its name.
    fn commands() -> [(&'static str, Command); 4] {
        [
            ("list-strings", |hiidb| {
                let strings = HiiBackend::list_strings(hiidb)?;
                Ok(strings
                    .into_iter()
                    .flat_map(|package| package.string_package.into_values())
                    .collect())
            }),
            ("list-questions", |hiidb| {
                let options = ListQuestionsOptions {
                    efivars: EfivarSource::Disabled,
                    include: IncludedStates::CONDITIONS,
                    ..Default::default()
                };
                let questions = HiiBackend::list_questions_using(hiidb, &options)?;
                Ok(questions
                    .into_iter()
                    .map(|question| question.name)
                    .collect())
            }),
            ("show-ifr", |hiidb| {
                let options = ShowIfrOptions {
                    efivars: EfivarSource::Disabled,
                    ..Default::default()
                };
                let shown = HiiBackend::show_ifr_using(hiidb, &options)?;
                Ok(shown
                    .readable_representation
                    .lines()
                    .filter(|line| line.contains("CheckBox"))
                    .map(|line| line.trim().to_string())
                    .collect())
            }),
            ("get", |hiidb| {
                let options = GetOptions {
                    efivars: EfivarSource::Disabled,
                    ..Default::default()
                };
                let got = HiiBackend::get_using(hiidb, "Deep", None, &options)?;
                Ok(got
                    .responses
                    .into_iter()
                    .map(|response| response.question.name)
                    .collect())
            }),
        ]
    }

    /// Every command reads a HiiDB whose IFR scopes nest MAX_SCOPE_NESTING deep, unknown ones
    /// counted, on SMALL_STACK, and shows its CheckBox, unless an unknown op's scope, which edk2
    /// skips, holds it.
    #[test]
    fn commands_read_scopes_nested_to_the_limit_on_a_small_stack() {
        for in_unknown_scope in [false, true] {
            let subtitles = MAX_SCOPE_NESTING - FORM_SCOPES - usize::from(in_unknown_scope);
            let hiidb = nested_subtitles_hiidb(subtitles, in_unknown_scope);
            for (name, command) in commands() {
                let got = on_small_stack(name, || command(&hiidb)).unwrap_or_else(|error| {
                    panic!("{name}, in an unknown scope: {in_unknown_scope}: {error:#}")
                });
                let want: &[&str] = match (name, in_unknown_scope) {
                    ("list-strings", _) => &["FormSet", "Deep"],
                    (_, true) => &[],
                    ("show-ifr", false) => &["OpCode: CheckBox - Q: - Deep - Help: -"],
                    (_, false) => &["Deep"],
                };
                assert_eq!(got, want, "{name}, in an unknown scope: {in_unknown_scope}");
            }
        }
    }

    /// Every command reads a HiiDB whose only FormSet nests IFR scopes deeper than
    /// MAX_SCOPE_NESTING, unknown ones counted, by one or by 20000 Subtitles, on SMALL_STACK, and
    /// ignores that FormSet, as a later one: it shows no question, and names the FormSet and the
    /// op past the limit as the IFR that it ignores at offset 0. Through variables that reach
    /// BootServices, get refuses the HiiDB.
    #[test]
    fn commands_ignore_a_form_set_nested_past_the_limit_on_a_small_stack() {
        let form_set_op = form_set(&[]).len() - END.len();
        let form_op = form(1, &[]).len() - END.len();
        let subtitle_op = subtitle_scope(2).len();
        for in_unknown_scope in [false, true] {
            let outer = FORM_SCOPES + usize::from(in_unknown_scope);
            let past_limit = form_set_op
                + form_op
                + usize::from(in_unknown_scope) * unknown_scope().len()
                + (MAX_SCOPE_NESTING - outer) * subtitle_op;
            let ignored = format!(
                "the FormSet {}, which nests too deep: IFR scopes nest deeper than \
                 {MAX_SCOPE_NESTING} at offset {past_limit} of a form package",
                Guid::from([0x11; 16])
            );
            for subtitles in [MAX_SCOPE_NESTING - outer + 1, 20_000] {
                let hiidb = nested_subtitles_hiidb(subtitles, in_unknown_scope);
                let case =
                    format!("{subtitles} Subtitles, in an unknown scope: {in_unknown_scope}");
                for (name, command) in commands() {
                    let got = on_small_stack(name, || command(&hiidb))
                        .unwrap_or_else(|error| panic!("{name}, {case}: {error:#}"));
                    let want: &[&str] = match name {
                        "list-strings" => &["FormSet", "Deep"],
                        _ => &[],
                    };
                    assert_eq!(got, want, "{name}, {case}");
                }

                let records: Vec<(u64, String)> =
                    on_small_stack("ignored_ifr", || HiiBackend::ignored_ifr(&hiidb))
                        .unwrap_or_else(|error| panic!("ignored_ifr, {case}: {error:#}"))
                        .into_iter()
                        .map(|ignored| (ignored.offset, ignored.reason))
                        .collect();
                assert_eq!(records, [(0, ignored.clone())], "ignored_ifr, {case}");

                let variables = Rc::new(MemoryVariables::new(
                    VariableReach::BootServices,
                    VariableInterface::VariableServices,
                ));
                assert_eq!(
                    answers_or_error_of(&hiidb, "Deep", &variables),
                    Err(format!(
                        "PASSWORD questions of package list 55555555-5555-5555-5555-555555555555 \
                         may be in the IFR that uefisettings ignores at offset 0 of a form \
                         package: {ignored}; as the variable of that password is unknown, the \
                         UEFI Shell build reads and writes no variable of this HiiDB"
                    )),
                    "BootServices: get, {case}"
                );
            }
        }
    }

    /// The device path of the driver of snapshot_hiidb.
    const DRIVER_PATH: [u8; 16] = crate::hii::config_snapshot::tests::DRIVER_PATH;
    /// The GUIDs, as stored, of NStore and AMITSESetup.
    const N_GUID: [u8; 16] = crate::hii::config_snapshot::tests::N_GUID;
    const P_GUID: [u8; 16] = crate::hii::config_snapshot::tests::P_GUID;
    /// The answer of N of snapshot_hiidb without a variable or snapshot value.
    const MISSING_N_STORE: &str = "<ValueUnavailable: no EFI variable \
        NStore-8c78a505-baa0-4c4a-869f-000000001401; HII buffer varstore requires \
        EFI_HII_CONFIG_ACCESS_PROTOCOL> <IFR default: 0>";
    /// The answer of X of snapshot_hiidb, over the password's bytes; the NUMERIC declares no
    /// default.
    const WITHHELD: &str = "<ValueUnavailable: its bytes hold a password>";

    /// A UINT16 NUMERIC of QuestionId `question_id`, prompted string `prompt`, from 0 to 65535,
    /// at VarOffset, or VarName, `info` of VarStore `var_store_id`.
    fn uint16_numeric(question_id: u16, prompt: u16, var_store_id: u16, info: u16) -> Vec<u8> {
        let data = [
            question_header_with(question_id, prompt, var_store_id, info, 0x00),
            // Flags EFI_IFR_NUMERIC_SIZE_2, MinValue, MaxValue, Step
            vec![0x01, 0x00, 0x00, 0xFF, 0xFF, 0x01, 0x00],
        ]
        .concat();
        operation(NUMERIC, false, &data)
    }

    /// A UINT8 ONE_OF of QuestionId `question_id`, prompted string `prompt`, at VarOffset
    /// `offset` of VarStore `var_store_id`, with `options`.
    fn uint8_one_of(
        question_id: u16,
        prompt: u16,
        var_store_id: u16,
        offset: u16,
        options: &[Vec<u8>],
    ) -> Vec<u8> {
        let data = [
            question_header_with(question_id, prompt, var_store_id, offset, 0x00),
            // Flags EFI_IFR_NUMERIC_SIZE_1, MinValue, MaxValue, Step
            vec![0x00, 0x00, 0xFF, 0x01],
        ]
        .concat();
        [
            operation(ONE_OF, true, &data),
            options.concat(),
            END.to_vec(),
        ]
        .concat()
    }

    /// The variable of NStore.
    fn n_store() -> VariableKey {
        VariableKey {
            name: "NStore".to_owned(),
            guid: Guid::from(N_GUID),
        }
    }

    /// A HiiDB of the driver at DRIVER_PATH, whose FormSet has the CHECKBOX N at byte 0, the
    /// UINT16 NUMERIC W at byte 1 and the ONE_OF O of "Off" 0 and "On" 1 at byte 0 of the buffer
    /// VarStore NStore, then, on the buffer VarStore AMITSESetup of AMI's layout, `password`, the
    /// CHECKBOX P at byte 80, and the UINT16 NUMERICs S at byte 40 and X at byte 38.
    fn snapshot_hiidb_with(password: Vec<u8>) -> Vec<u8> {
        snapshot_hiidb_beside(password, &[])
    }

    /// snapshot_hiidb_with `password`, with the FormSets `form_sets` after its FormSet in its form
    /// package.
    fn snapshot_hiidb_beside(password: Vec<u8>, form_sets: &[Vec<u8>]) -> Vec<u8> {
        let form_set = form_set_with_guid(
            [0x11; 16],
            &[
                var_store(1, N_GUID, "NStore", 3),
                var_store(2, P_GUID, "AMITSESetup", 81),
                form(
                    1,
                    &[
                        checkbox_on(1, 1, 1),
                        uint16_numeric(2, 2, 1, 1),
                        uint8_one_of(
                            5,
                            5,
                            1,
                            0,
                            &[flagged_option(6, 0x00, 0), flagged_option(7, 0x00, 1)],
                        ),
                        password,
                        checkbox_at(4, 3, 2, 80),
                        uint16_numeric(8, 8, 2, 40),
                        uint16_numeric(9, 9, 2, 38),
                    ],
                ),
            ],
        );
        let packages = [
            device_path_package(&DRIVER_PATH),
            form_package_of(&[form_set, form_sets.concat()].concat()),
            en_strings_package_of(&["N", "W", "P", "Password", "O", "Off", "On", "S", "X"]),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid([0x55; 16], &packages.concat())
    }

    /// snapshot_hiidb_with a PASSWORD of 20 CHAR16s at byte 0 of AMITSESetup: X's bytes end in
    /// its last 2, and S's follow them.
    fn snapshot_hiidb() -> Vec<u8> {
        snapshot_hiidb_with(password_on(3, 4, 2, 0))
    }

    /// The snapshot of snapshot_hiidb's driver: NStore holds 1, then 0x1234; AMITSESetup 40
    /// bytes of 0xA5 for the password, then S's 0x5678, zeros, and P's 1.
    fn snapshot_text() -> String {
        let mut amitse_setup = [0; 81];
        amitse_setup[..40].fill(0xA5);
        amitse_setup[40..42].copy_from_slice(&[0x78, 0x56]);
        amitse_setup[80] = 1;
        [
            block_resp(
                &config_hdr(N_GUID, "NStore", &DRIVER_PATH),
                0,
                &[1, 0x34, 0x12],
            ),
            block_resp(
                &config_hdr(P_GUID, "AMITSESetup", &DRIVER_PATH),
                0,
                &amitse_setup,
            ),
        ]
        .join("&")
    }

    /// Variables that reach Runtime through efivarfs and hold none of snapshot_hiidb's.
    fn no_variables() -> Rc<MemoryVariables> {
        Rc::new(MemoryVariables::new(
            VariableReach::Runtime,
            VariableInterface::Efivarfs,
        ))
    }

    /// The answers that get and list-questions give for each question of `names` of `hiidb`
    /// through `variables` with the snapshot `text`, and what show-ifr shows; each response as
    /// text and as JSON, after them.
    fn answers_with_snapshot(
        hiidb: &[u8],
        names: &[&str],
        variables: &Rc<MemoryVariables>,
        text: &str,
    ) -> (Vec<String>, Vec<String>, String, Vec<String>) {
        let exported = || Some(ExportedConfig::new(text.to_owned()));
        let mut outputs = Vec::new();
        let mut got = Vec::new();
        for name in names {
            let response = HiiBackend::get_in(
                hiidb,
                *name,
                None,
                &GetOptions::default(),
                shared(variables),
                exported(),
                None,
                None,
            )
            .unwrap_or_else(|error| panic!("get {name}: {error:#}"));
            got.extend(
                response
                    .responses
                    .iter()
                    .map(|response| response.question.answer.clone()),
            );
            outputs.push(format!("{response:#?}"));
            outputs
                .push(String::from_utf8_lossy(&simplejson_protocol::serialize(&response)).into());
        }
        let questions = HiiBackend::list_questions_in(
            hiidb,
            &ListQuestionsOptions::default(),
            shared(variables),
            exported(),
            None,
        )
        .expect("list questions");
        let listed = names
            .iter()
            .flat_map(|name| {
                questions
                    .iter()
                    .filter(move |question| question.name == *name)
                    .map(|question| question.answer.clone())
            })
            .collect();
        for question in &questions {
            outputs.push(format!("{question:#?}"));
            outputs.push(String::from_utf8_lossy(&simplejson_protocol::serialize(question)).into());
        }
        let ifr = HiiShowIfrResponse::from(
            HiiBackend::show_ifr_in(
                hiidb,
                &ShowIfrOptions::default(),
                shared(variables),
                exported(),
                None,
            )
            .expect("show the IFR"),
        );
        outputs.push(format!("{ifr:#?}"));
        outputs.push(String::from_utf8_lossy(&simplejson_protocol::serialize(&ifr)).into());
        (got, listed, ifr.readable_representation, outputs)
    }

    /// Asserts that no output of `outputs` shows a byte of the 0xA5 of a password.
    #[track_caller]
    fn assert_no_password_byte(outputs: &[String]) {
        for output in outputs {
            for needle in ["a5a5", "A5A5", "165"] {
                assert!(!output.contains(needle), "{needle} in {output}");
            }
        }
    }

    /// get, list-questions and show-ifr, as text and as JSON, take the values of questions whose
    /// variable is missing from the ExportConfig snapshot, tagged, also of those beside a password
    /// in its VarStore, but show a question over the password's bytes withheld, and never those
    /// bytes.
    #[test]
    fn missing_variables_show_snapshot_values_but_password_bytes_stay_withheld() {
        let (got, listed, ifr, outputs) = answers_with_snapshot(
            &snapshot_hiidb(),
            &["N", "W", "O", "P", "S", "X"],
            &no_variables(),
            &snapshot_text(),
        );

        let want = [
            "1 <snapshot>",
            "4660 <snapshot>",
            "On <snapshot>",
            "1 <snapshot>",
            "22136 <snapshot>",
            WITHHELD,
        ];
        assert_eq!(got, want, "get");
        assert_eq!(listed, want, "list-questions");
        for shown in [
            "1 <snapshot>",
            "4660 <snapshot>",
            "22136 <snapshot>",
            WITHHELD,
        ] {
            assert!(
                ifr.contains(&format!("-Answer: {shown}\n")),
                "show-ifr lacks {shown:?}: {ifr}"
            );
        }
        assert_no_password_byte(&outputs);
    }

    /// The snapshot fills in only missing variables of the package list's driver, and none in a
    /// HiiDB with a PASSWORD op whose VarStore is unknown, which could be any, or with IFR that the
    /// parser drops, which could hold one: the warning says that the password cannot be withheld.
    #[test]
    fn snapshot_values_show_only_for_missing_variables_of_their_driver() {
        const REFUSED: &str = "; as the VarStore of that password is unknown, uefisettings \
            cannot withhold its bytes, so no value is shown from the ExportConfig snapshot";
        let with_n_store = no_variables();
        with_n_store.insert(n_store(), NV_BS_RT, &[0, 0, 0]);
        let short_n_store = no_variables();
        short_n_store.insert(n_store(), NV_BS_RT, &[0]);
        let without_path = {
            let packages = [
                form_package(&[
                    var_store(1, N_GUID, "NStore", 3),
                    form(1, &[checkbox_on(1, 1, 1)]),
                ]),
                en_strings_package_of(&["N"]),
                END_PACKAGE.to_vec(),
            ];
            package_list_with_guid([0x55; 16], &packages.concat())
        };
        let other_driver = snapshot_text().replace(
            &config_hdr(N_GUID, "NStore", &DRIVER_PATH),
            &config_hdr(N_GUID, "NStore", &[0x7F, 0xFF, 0x04, 0x00]),
        );
        let withheld_n = format!("{PASSWORD_BYTES} <IFR default: 0>");
        let dropped_form_set = {
            // a VARSTORE op that ends after 4 of the 20 bytes before its Name
            let malformed = operation(VAR_STORE, false, &[0x00; 4]);
            let packages = [
                device_path_package(&DRIVER_PATH),
                form_package_of(
                    &[
                        form_set(&[
                            var_store(1, N_GUID, "NStore", 3),
                            form(1, &[checkbox_on(1, 1, 1)]),
                        ]),
                        form_set(&dropped_password_second_ops(malformed)),
                    ]
                    .concat(),
                ),
                en_strings_package_of(&["N", "Password"]),
                END_PACKAGE.to_vec(),
            ];
            package_list_with_guid([0x55; 16], &packages.concat())
        };
        for (case, hiidb, variables, text, want, refused) in [
            (
                "a variable that exists",
                snapshot_hiidb(),
                with_n_store,
                snapshot_text(),
                "0",
                false,
            ),
            (
                "a variable shorter than its VarStore",
                snapshot_hiidb(),
                short_n_store,
                snapshot_text(),
                "<VStoreError: EFI variable NStore-8c78a505-baa0-4c4a-869f-000000001401 \
                 holds 1 data bytes, fewer than the 3 of its VarStore> <IFR default: 0>",
                false,
            ),
            (
                "a list without a device path package",
                without_path,
                no_variables(),
                snapshot_text(),
                MISSING_N_STORE,
                false,
            ),
            (
                "another driver's NStore",
                snapshot_hiidb(),
                no_variables(),
                other_driver,
                MISSING_N_STORE,
                false,
            ),
            (
                "a PASSWORD op on VarStore 9, which only another FormSet declares",
                snapshot_hiidb_beside(
                    password_on(3, 4, 9, 0),
                    &[form_set_with_guid(
                        [0x13; 16],
                        &[var_store(9, P_GUID, "AMITSESetup", 81), form(3, &[])],
                    )],
                ),
                no_variables(),
                snapshot_text(),
                MISSING_N_STORE,
                true,
            ),
            (
                "a FormSet that the parser drops, whose PASSWORD ops are unknown, and whose \
                 VARSTORE's Guid runs past the form package, so every variable is withheld",
                dropped_form_set,
                no_variables(),
                snapshot_text(),
                withheld_n.as_str(),
                true,
            ),
        ] {
            let mut answers = None;
            let logged = logged_by(|| {
                answers = Some(answers_with_snapshot(&hiidb, &["N"], &variables, &text));
            });
            let (got, listed, _, outputs) = answers.expect("the answers");

            assert_eq!(got, [want], "{case}: get");
            assert_eq!(listed, [want], "{case}: list-questions");
            assert_no_password_byte(&outputs);
            assert_eq!(
                logged.iter().any(|message| message.ends_with(REFUSED)),
                refused,
                "{case}: the refusal in {logged:?}"
            );
        }
    }

    /// The snapshot drops the passwords of IFR outside any FormSet as get withholds them
    /// (PasswordQuestions::of_lists). The FormSet of snapshot_hiidb's N and its PASSWORD on
    /// AMITSESetup, VarStoreId 2, follows `outside`, then a FormSet whose UINT16 NUMERIC T is at
    /// byte 0 of Shadow, whose 40 snapshot bytes are 0xA5 too:
    /// - a VARSTORE outside any FormSet of VarStoreId 2 for Shadow keeps the password there too, so
    ///   T shows withheld while N shows its snapshot value;
    /// - a PASSWORD outside any FormSet leaves the password's bytes unknown, so the snapshot shows
    ///   nothing, which the warning says;
    /// - a VARSTORE_NAME_VALUE there of VarStoreId 2, whose driver may keep the password in any
    ///   variable, closes every variable, and the snapshot with them.
    #[test]
    fn the_snapshot_drops_the_passwords_of_ifr_outside_any_form_set() {
        const REFUSED: &str = "; as the VarStore of that password is unknown, uefisettings \
            cannot withhold its bytes, so no value is shown from the ExportConfig snapshot";
        let hiidb = |outside: Vec<u8>| {
            let packages = [
                device_path_package(&DRIVER_PATH),
                form_package_of(
                    &[
                        outside,
                        form_set(&[
                            var_store(1, N_GUID, "NStore", 3),
                            var_store(2, P_GUID, "AMITSESetup", 81),
                            form(1, &[checkbox_on(1, 1, 1), password_on(3, 4, 2, 0)]),
                        ]),
                        form_set(&[
                            var_store(7, OTHER_GUID, "Shadow", 81),
                            form(2, &[uint16_numeric(8, 8, 7, 0)]),
                        ]),
                    ]
                    .concat(),
                ),
                en_strings_package_of(&["N", "W", "P", "Password", "O", "Off", "On", "T"]),
                END_PACKAGE.to_vec(),
            ];
            package_list_with_guid([0x55; 16], &packages.concat())
        };
        let text = [
            snapshot_text(),
            block_resp(
                &config_hdr(OTHER_GUID, "Shadow", &DRIVER_PATH),
                0,
                &[[0xA5; 40].as_slice(), &[0; 41]].concat(),
            ),
        ]
        .join("&");
        for (case, outside, want, refused) in [
            (
                "a VARSTORE of VarStoreId 2 for Shadow",
                var_store(2, OTHER_GUID, "Shadow", 81),
                ["1 <snapshot>", WITHHELD],
                false,
            ),
            (
                "a PASSWORD",
                password_on(9, 4, 2, 0),
                [
                    MISSING_N_STORE,
                    "<ValueUnavailable: no EFI variable \
                  Shadow-33333333-3333-3333-3333-333333333333; HII buffer varstore requires \
                  EFI_HII_CONFIG_ACCESS_PROTOCOL>",
                ],
                true,
            ),
        ] {
            let mut answers = None;
            let logged = logged_by(|| {
                answers = Some(answers_with_snapshot(
                    &hiidb(outside),
                    &["N", "T"],
                    &no_variables(),
                    &text,
                ));
            });
            let (got, listed, _, outputs) = answers.expect("the answers");

            assert_eq!(got, want, "{case}: get");
            assert_eq!(listed, want, "{case}: list-questions");
            assert_no_password_byte(&outputs);
            assert_eq!(
                logged.iter().any(|message| message.ends_with(REFUSED)),
                refused,
                "{case}: the refusal in {logged:?}"
            );
        }

        let hiidb = hiidb(var_store_name_value(2, OTHER_GUID));
        for name in ["N", "T"] {
            let got = HiiBackend::get_in(
                &hiidb,
                name,
                None,
                &GetOptions::default(),
                shared(&no_variables()),
                Some(ExportedConfig::new(text.clone())),
                None,
                None,
            )
            .map(|response| format!("{response:#?}"))
            .map_err(|error| format!("{error:#}"));
            assert!(
                got.as_ref()
                    .is_err_and(|error| error.ends_with(ANY_VARIABLE)),
                "a VARSTORE_NAME_VALUE of VarStoreId 2: get {name}: {got:?}"
            );
            assert_no_password_byte(&[got.unwrap_or_else(|error| error)]);
        }
    }

    /// A form that a malformed op disables (UEFI 2.11 §33.2.5.10.1) has no question that the
    /// snapshot answers, and the snapshot withholds the bytes of its PASSWORD as get does: a
    /// question over them shows none, the other bytes of that storage show. A PASSWORD op there
    /// without its question header leaves its bytes unknown, so the snapshot is not read.
    #[test]
    fn the_snapshot_answers_no_question_of_a_disabled_form_and_withholds_its_password() {
        const REFUSED: &str = "; as the VarStore of that password is unknown, uefisettings \
            cannot withhold its bytes, so no value is shown from the ExportConfig snapshot";
        // the forms of snapshot_hiidb, with W and the PASSWORD in a form 2 that a CHECKBOX op
        // ending after 4 of the 12 bytes of its data disables, whose first 2 give VarStoreId 2 to
        // the question header of a PASSWORD op that runs on into it
        let hiidb_with = |password: Vec<u8>| {
            let packages = [
                device_path_package(&DRIVER_PATH),
                form_package(&[
                    var_store(1, N_GUID, "NStore", 3),
                    var_store(2, P_GUID, "AMITSESetup", 81),
                    form(
                        1,
                        &[
                            checkbox_on(1, 1, 1),
                            uint16_numeric(8, 8, 2, 40),
                            uint16_numeric(9, 9, 2, 38),
                        ],
                    ),
                    form(
                        2,
                        &[
                            uint16_numeric(2, 2, 1, 1),
                            password,
                            operation(CHECKBOX, false, &[0x02, 0x00, 0x00, 0x00]),
                        ],
                    ),
                ]),
                en_strings_package_of(&["N", "W", "P", "Password", "O", "Off", "On", "S", "X"]),
                END_PACKAGE.to_vec(),
            ];
            package_list_with_guid([0x55; 16], &packages.concat())
        };
        for (case, password, names, want, refused) in [
            (
                "a PASSWORD",
                password_on(3, 4, 2, 0),
                &["N", "W", "S", "X"][..],
                &["1 <snapshot>", "22136 <snapshot>", WITHHELD][..],
                false,
            ),
            (
                "a PASSWORD op without its question header",
                operation(PASSWORD, false, &[3, 0, 4, 0]),
                &["N", "W"],
                &[MISSING_N_STORE],
                true,
            ),
        ] {
            let mut answers = None;
            let logged = logged_by(|| {
                answers = Some(answers_with_snapshot(
                    &hiidb_with(password),
                    names,
                    &no_variables(),
                    &snapshot_text(),
                ));
            });
            let (got, listed, ifr, outputs) = answers.expect("the answers");

            assert_eq!(got, want, "{case}: get");
            assert_eq!(listed, want, "{case}: list-questions");
            assert!(
                !ifr.contains("4660"),
                "{case}: show-ifr shows W's snapshot value: {ifr}"
            );
            assert_no_password_byte(&outputs);
            assert_eq!(
                logged.iter().any(|message| message.ends_with(REFUSED)),
                refused,
                "{case}: the refusal in {logged:?}"
            );
        }
    }

    /// The questions of a VARSTORE_EFI without runtime access, whose variable Linux does not
    /// see, take their values from the snapshot.
    #[test]
    fn boot_service_only_efi_variables_show_snapshot_values() {
        let packages = [
            device_path_package(&DRIVER_PATH),
            form_package(&[
                var_store_efi(1, "Setup", NV_BS, 1),
                form(1, &[checkbox_on(1, 1, 1)]),
            ]),
            en_strings_package_of(&["Q"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x55; 16], &packages.concat());
        let text = block_resp(&config_hdr([0; 16], "Setup", &DRIVER_PATH), 0, &[1]);

        let (got, listed, ifr, _) = answers_with_snapshot(&hiidb, &["Q"], &no_variables(), &text);

        assert_eq!(got, ["1 <snapshot>"], "get");
        assert_eq!(listed, ["1 <snapshot>"], "list-questions");
        assert!(ifr.contains("-Answer: 1 <snapshot>\n"), "show-ifr: {ifr}");
    }

    /// A value that an EFI_IFR_VALUE or READ expression gives is tagged when the snapshot gave
    /// THIS or a value that the expression took, and only then.
    #[test]
    fn expression_values_show_whether_the_snapshot_gave_them() {
        const LIVE: u16 = 2;
        let live = VariableKey {
            name: "Live".to_owned(),
            guid: Guid::from(N_GUID),
        };
        let variables = no_variables();
        variables.insert(live, NV_BS_RT, &[0; 4]);
        // a UINT8 NUMERIC of QuestionId and prompt `id` at VarOffset `offset` of `var_store_id`,
        // whose `expression` op holds `ops`
        let numeric = |id: u16, var_store_id: u16, offset: u16, expression: u8, ops: Vec<u8>| {
            let data = [
                question_header_with(id, id, var_store_id, offset, 0x00),
                vec![0x00, 0, 255, 1], // Flags, MinValue, MaxValue, Step
            ]
            .concat();
            [
                operation(NUMERIC, true, &data),
                operation(expression, true, &[]),
                ops,
                END.to_vec(),
                END.to_vec(),
            ]
            .concat()
        };
        let n = || operation(QUESTION_REF1, false, &1u16.to_le_bytes());
        let packages = [
            device_path_package(&DRIVER_PATH),
            form_package(&[
                var_store(1, N_GUID, "NStore", 3),
                var_store(LIVE, N_GUID, "Live", 4),
                form(
                    1,
                    &[
                        checkbox_on(1, 1, 1),
                        numeric(2, LIVE, 0, VALUE, n()),
                        numeric(3, LIVE, 1, VALUE, uint8(7)),
                        numeric(4, LIVE, 2, READ, n()),
                        numeric(5, LIVE, 3, READ, uint8(5)),
                        numeric(6, 1, 1, READ, operation(THIS, false, &[])),
                    ],
                ),
            ]),
            en_strings_package_of(&["N", "VN", "VC", "RN", "RC", "RT"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x55; 16], &packages.concat());

        let (got, listed, ifr, _) = answers_with_snapshot(
            &hiidb,
            &["N", "VN", "VC", "RN", "RC", "RT"],
            &variables,
            &snapshot_text(),
        );

        let want = [
            "1 <snapshot>",
            "1 <snapshot>",
            "7",
            "1 <snapshot>",
            "5",
            "52 <snapshot>",
        ];
        assert_eq!(got, want, "get");
        assert_eq!(listed, want, "list-questions");
        for shown in want {
            assert!(
                ifr.contains(&format!("-Answer: {shown}\n")),
                "show-ifr lacks {shown:?}: {ifr}"
            );
        }
    }

    /// The questions of name/value storage take their numbers from the snapshot by the labels
    /// that their VarName strings give, unless a number does not fit the question; zeros before
    /// its digits do.
    #[test]
    fn name_value_questions_show_snapshot_numbers() {
        let packages = [
            device_path_package(&DRIVER_PATH),
            form_package(&[
                var_store_name_value(3, N_GUID),
                form(
                    1,
                    &[
                        checkbox_at(1, 1, 3, 5),
                        uint16_numeric(2, 2, 3, 6),
                        checkbox_at(3, 3, 3, 7),
                        checkbox_at(4, 4, 3, 8),
                        checkbox_at(5, 9, 3, 10),
                    ],
                ),
            ]),
            en_strings_package_of(&[
                "C", "V", "X", "U", "Flag", "Word", "Wide", "Unset", "Z", "Padded",
            ]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x55; 16], &packages.concat());
        let text = format!(
            "{}&Flag=01&Word=1234&Wide=0102&Padded=0001",
            config_hdr(N_GUID, "", &DRIVER_PATH)
        );

        let (got, listed, ifr, _) =
            answers_with_snapshot(&hiidb, &["C", "V", "X", "U", "Z"], &no_variables(), &text);

        let want = [
            "1 <snapshot>",
            "4660 <snapshot>",
            "<ValueUnavailable: its number in the ExportConfig snapshot does not fit in 8 bits> \
             <IFR default: 0>",
            "<ValueUnavailable: HII name/value varstore requires EFI_HII_CONFIG_ACCESS_PROTOCOL> \
             <IFR default: 0>",
            "1 <snapshot>",
        ];
        assert_eq!(got, want, "get");
        assert_eq!(listed, want, "list-questions");
        for shown in ["1 <snapshot>", "4660 <snapshot>"] {
            assert!(
                ifr.contains(&format!("-Answer: {shown}\n")),
                "show-ifr lacks {shown:?}: {ifr}"
            );
        }
    }

    /// A STRING of name/value storage, of MaxSize 4, takes its characters from its snapshot
    /// setting, 4 hex digits each, as edk2-stable202608 SetupBrowserDxe/Setup.c BufferToValue
    /// reads them (:1564-1579), while a CHECKBOX there takes its number: up to a NULL, as UEFI
    /// 2.11 §33.2.5.4.9 ends the hex dump, or MaxSize characters, as Setup.c sets its own
    /// (:2139-2148), and NULLs past them; an empty setting is an empty string, as Setup.c writes
    /// one. A setting of digits that are no `<String>` (UEFI 2.11 §35.2.1.2) or of more than
    /// MaxSize characters gives none, where Setup.c would cut them (:1557-1561); one that the
    /// snapshot lacks says why it has no value, as a CHECKBOX does, and so does a CHECKBOX of an
    /// empty setting, whose number Setup.c would not write (:1580-1590). An ORDERED_LIST there
    /// takes its setting as a number, least significant byte first, as BufferToValue reads every
    /// question that holds no string (:1505, :1580-1590).
    #[test]
    fn name_value_strings_take_their_characters_from_the_snapshot() {
        let ordered_list = [
            operation(
                ORDERED_LIST,
                true,
                &[question_header_with(21, 21, 3, 22, 0x00), vec![4, 0x00]].concat(),
            ),
            flagged_option(23, 0x00, 1),
            flagged_option(24, 0x00, 2),
            flagged_option(25, 0x00, 3),
            flagged_option(26, 0x00, 4),
            END.to_vec(),
        ]
        .concat();
        let packages = [
            device_path_package(&DRIVER_PATH),
            form_package(&[
                var_store_name_value(3, N_GUID),
                form(
                    1,
                    &[
                        string_on(1, 1, (3, 3), (0, 4), &[]),
                        checkbox_at(2, 2, 3, 4),
                        string_on(5, 5, (3, 6), (0, 4), &[]),
                        string_on(7, 7, (3, 8), (0, 4), &[]),
                        string_on(9, 9, (3, 10), (0, 4), &[]),
                        string_on(11, 11, (3, 12), (0, 4), &[]),
                        string_on(13, 13, (3, 14), (0, 4), &[]),
                        string_on(15, 15, (3, 16), (0, 4), &[]),
                        string_on(17, 17, (3, 18), (0, 4), &[]),
                        checkbox_at(19, 19, 3, 20),
                        ordered_list,
                    ],
                ),
            ]),
            en_strings_package_of(&[
                "S",
                "C",
                "Text",
                "Flag",
                "Unset",
                "Gone",
                "Nul",
                "NulText",
                "Odd",
                "OddText",
                "Long",
                "LongText",
                "Full",
                "FullText",
                "Padded",
                "PaddedText",
                "Empty",
                "EmptyText",
                "Cl",
                "Cleared",
                "L",
                "Order",
                "One",
                "Two",
                "Three",
                "Four",
            ]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x55; 16], &packages.concat());
        let text = format!(
            "{}&Text=00410042&Flag=01&NulText=004100420000&OddText=004100\
             &LongText=00410042004300440045&FullText=0041004200430044\
             &PaddedText=00410042004300440000&EmptyText=&Cleared=&Order=01020304",
            config_hdr(N_GUID, "", &DRIVER_PATH)
        );
        let names = [
            "S", "C", "Unset", "Nul", "Odd", "Long", "Full", "Padded", "Empty", "Cl", "L",
        ];

        let (got, listed, ifr, _) = answers_with_snapshot(&hiidb, &names, &no_variables(), &text);

        let want = [
            "AB <snapshot>",
            "1 <snapshot>",
            "<ValueUnavailable: HII name/value varstore requires EFI_HII_CONFIG_ACCESS_PROTOCOL>",
            "AB <snapshot>",
            "<ValueUnavailable: its setting in the ExportConfig snapshot is no <String>: 4 hex \
             digits per CHAR16>",
            "<ValueUnavailable: its setting in the ExportConfig snapshot holds more than its \
             MaxSize of 4 characters>",
            "ABCD <snapshot>",
            "ABCD <snapshot>",
            " <snapshot>",
            "<ValueUnavailable: HII name/value varstore requires EFI_HII_CONFIG_ACCESS_PROTOCOL> \
             <IFR default: 0>",
            "Four, Three, Two, One <snapshot>",
        ];
        assert_eq!(got, want, "get");
        assert_eq!(listed, want, "list-questions");
        for shown in [
            "AB <snapshot>",
            "ABCD <snapshot>",
            "Four, Three, Two, One <snapshot>",
        ] {
            assert!(
                ifr.contains(&format!("-Answer: {shown}\n")),
                "show-ifr lacks {shown:?}: {ifr}"
            );
        }
    }

    /// A STRING of name/value storage shows its snapshot characters, in get, list-questions and
    /// show-ifr, only where a PASSWORD lets the snapshot be read: beside none, or one on the
    /// buffer VarStore Backing, it shows them through variables of either kind, also on a second
    /// VARSTORE_NAME_VALUE and on Pin, the name that the PASSWORD is on; beside one that edk2 may
    /// route to a VARSTORE_NAME_VALUE, also in another package list of its driver, through
    /// variables that read anything the HiiDB is refused, and through those that read
    /// nothing it takes nothing from the snapshot, which stays off: on that VARSTORE_NAME_VALUE,
    /// on the PASSWORD's own name there, and on a second VARSTORE_NAME_VALUE, as its driver may
    /// keep the password in any of its settings; so it does beside a PASSWORD of VarStoreId 0, in
    /// its form or outside any FormSet, whose callbacks or READ and WRITE ops may keep it in any of
    /// them, and beside one whose VarStoreId no VarStore declares, which refuses the HiiDB through
    /// variables that read anything too; through BootServices the HiiDB is refused.
    #[test]
    fn name_value_strings_keep_to_the_password_refusals() {
        type I = NameValueIfr;
        /// The GUID of the second VARSTORE_NAME_VALUE, VarStoreId 4.
        const SECOND_NAME_VALUE_GUID: [u8; 16] = [0x57; 16];
        /// The labels Pin and Flag: strings 4 and 5 of NAME_VALUE_STRINGS.
        const PIN: u16 = 4;
        const FLAG: u16 = 5;
        /// Where the PASSWORD on Pin of a VarStoreId is.
        enum Password {
            Absent,
            InForm(u16),
            BeforeFormSet(u16),
            /// In a FormSet of the first VARSTORE_NAME_VALUE in a third package list of the driver
            InAnotherList(u16),
        }
        /// What get of W gives through variables of either kind.
        enum Want {
            /// Its snapshot characters
            Shown,
            /// A refusal through variables that read anything, no value through those that read
            /// nothing
            Refused,
        }
        // a package list of the driver whose FormSet holds the PASSWORD on Pin of VarStoreId `id`
        // beside the first VARSTORE_NAME_VALUE
        let another_list = |id: u16| {
            let form_set =
                form_set_with_guid([0x59; 16], &[I::name_value(), form(1, &[I::password(id)])]);
            package_list_with_guid(
                [0x58; 16],
                &[
                    device_path_package(&DRIVER_PATH),
                    form_package_of(&form_set),
                    en_strings_package_of(&NAME_VALUE_STRINGS),
                    END_PACKAGE.to_vec(),
                ]
                .concat(),
            )
        };
        // the STRING W, of MaxSize 4, on the label `label` of the VARSTORE_NAME_VALUE
        // `var_store_id`: 3, which the PASSWORD's VarStoreId 3 names, or the second, 4
        let hiidb = |(var_store_id, label): (u16, u16), password: &Password| {
            let string = string_on(9, 2, (var_store_id, label), (0, 4), &[]);
            let (in_form, outside, other_list) = match *password {
                Password::Absent => (vec![], vec![], vec![]),
                Password::InForm(id) => (vec![I::password(id)], vec![], vec![]),
                Password::BeforeFormSet(id) => (vec![], vec![I::password(id)], vec![]),
                Password::InAnotherList(id) => (vec![], vec![], another_list(id)),
            };
            let questions = [vec![I::b(), I::p(), string], in_form].concat();
            let forms = form_set(&[
                I::name_value(),
                var_store_name_value(4, SECOND_NAME_VALUE_GUID),
                I::backing(),
                form(1, &questions),
            ]);
            [
                name_value_hiidb(&[outside, vec![forms]].concat()),
                other_list,
            ]
            .concat()
        };
        let snapshot = format!(
            "{}&Flag=00410042&Pin=7a5b&{}&Flag=00410042",
            config_hdr(N_GUID, "", &DRIVER_PATH),
            config_hdr(SECOND_NAME_VALUE_GUID, "", &DRIVER_PATH)
        );
        let pin_snapshot = format!("{}&Pin=00410042", config_hdr(N_GUID, "", &DRIVER_PATH));
        let unread = |hiidb: &[u8], snapshot: &str| {
            HiiBackend::get_in(
                hiidb,
                "W",
                None,
                &GetOptions::default(),
                EfivarSource::Disabled
                    .into_variables()
                    .expect("variables that read nothing"),
                Some(ExportedConfig::new(snapshot.to_owned())),
                None,
                None,
            )
            .map(|response| {
                response
                    .responses
                    .into_iter()
                    .map(|response| response.question.answer)
                    .collect::<Vec<_>>()
            })
            .map_err(|error| format!("{error:#}"))
        };
        // list-questions' answers of W through `variables`, or the error
        let listed = |hiidb: &[u8], variables: Box<dyn FirmwareVariables>, snapshot: &str| {
            HiiBackend::list_questions_in(
                hiidb,
                &ListQuestionsOptions::default(),
                variables,
                Some(ExportedConfig::new(snapshot.to_owned())),
                None,
            )
            .map(|questions| {
                questions
                    .into_iter()
                    .filter(|question| question.name == "W")
                    .map(|question| question.answer)
                    .collect::<Vec<_>>()
            })
            .map_err(|error| format!("{error:#}"))
        };
        // what show-ifr shows through `variables`, or the error
        let shown_ifr = |hiidb: &[u8], variables: Box<dyn FirmwareVariables>, snapshot: &str| {
            HiiBackend::show_ifr_in(
                hiidb,
                &ShowIfrOptions::default(),
                variables,
                Some(ExportedConfig::new(snapshot.to_owned())),
                None,
            )
            .map(|ifr| HiiShowIfrResponse::from(ifr).readable_representation)
            .map_err(|error| format!("{error:#}"))
        };
        let read_nothing = || {
            EfivarSource::Disabled
                .into_variables()
                .expect("variables that read nothing")
        };
        let shown = Ok(vec!["AB <snapshot>".to_owned()]);
        let no_value_text =
            "<ValueUnavailable: HII name/value varstore requires EFI_HII_CONFIG_ACCESS_PROTOCOL>";
        let no_value = Ok(vec![no_value_text.to_owned()]);
        let runtime = name_value_variables(VariableReach::Runtime);
        let boot_services = name_value_variables(VariableReach::BootServices);

        for (case, location, password, snapshot, want) in [
            (
                "no PASSWORD",
                (3, FLAG),
                Password::Absent,
                &snapshot,
                Want::Shown,
            ),
            (
                "on Backing",
                (3, FLAG),
                Password::InForm(1),
                &snapshot,
                Want::Shown,
            ),
            (
                "the second VARSTORE_NAME_VALUE, no PASSWORD",
                (4, FLAG),
                Password::Absent,
                &snapshot,
                Want::Shown,
            ),
            (
                "on Pin, the PASSWORD on Backing",
                (3, PIN),
                Password::InForm(1),
                &pin_snapshot,
                Want::Shown,
            ),
            (
                "on the VARSTORE_NAME_VALUE",
                (3, FLAG),
                Password::InForm(3),
                &snapshot,
                Want::Refused,
            ),
            (
                "the second VARSTORE_NAME_VALUE, on the first",
                (4, FLAG),
                Password::InForm(3),
                &snapshot,
                Want::Refused,
            ),
            (
                "on Pin, the PASSWORD's own name",
                (3, PIN),
                Password::InForm(3),
                &pin_snapshot,
                Want::Refused,
            ),
            (
                "of VarStoreId 0 in the form",
                (3, FLAG),
                Password::InForm(0),
                &snapshot,
                Want::Refused,
            ),
            (
                "of VarStoreId 0 outside any FormSet",
                (3, FLAG),
                Password::BeforeFormSet(0),
                &snapshot,
                Want::Refused,
            ),
            (
                "in another package list of the driver",
                (3, FLAG),
                Password::InAnotherList(3),
                &snapshot,
                Want::Refused,
            ),
        ] {
            let hiidb = hiidb(location, &password);
            let got = name_value_get(&hiidb, "W", &runtime, Some(snapshot));
            let unread_got = unread(&hiidb, snapshot);
            let runtime_listed = listed(&hiidb, shared(&runtime), snapshot);
            let unread_listed = listed(&hiidb, read_nothing(), snapshot);
            let runtime_ifr = shown_ifr(&hiidb, shared(&runtime), snapshot);
            let unread_ifr = shown_ifr(&hiidb, read_nothing(), snapshot);
            match want {
                Want::Shown => {
                    assert_eq!(got, shown, "{case}: Runtime");
                    assert_eq!(unread_got, shown, "{case}: variables that read nothing");
                    assert_eq!(runtime_listed, shown, "{case}: list-questions, Runtime");
                    assert_eq!(
                        unread_listed, shown,
                        "{case}: list-questions, variables that read nothing"
                    );
                    for (variables, ifr) in [
                        ("Runtime", &runtime_ifr),
                        ("variables that read nothing", &unread_ifr),
                    ] {
                        assert!(
                            ifr.as_ref()
                                .is_ok_and(|ifr| ifr.contains("-Answer: AB <snapshot>\n")),
                            "{case}: show-ifr, {variables}: {ifr:?}"
                        );
                    }
                }
                Want::Refused => {
                    assert!(
                        got.as_ref()
                            .is_err_and(|error| error.ends_with(ANY_VARIABLE)),
                        "{case}: Runtime: {got:?}"
                    );
                    assert_eq!(unread_got, no_value, "{case}: variables that read nothing");
                    assert!(
                        runtime_listed
                            .as_ref()
                            .is_err_and(|error| error.ends_with(ANY_VARIABLE)),
                        "{case}: list-questions, Runtime: {runtime_listed:?}"
                    );
                    assert_eq!(
                        unread_listed, no_value,
                        "{case}: list-questions, variables that read nothing"
                    );
                    assert!(
                        runtime_ifr
                            .as_ref()
                            .is_err_and(|error| error.ends_with(ANY_VARIABLE)),
                        "{case}: show-ifr, Runtime: {runtime_ifr:?}"
                    );
                    assert!(
                        unread_ifr.as_ref().is_ok_and(|ifr| {
                            ifr.contains(&format!("-Answer: {no_value_text}\n"))
                                && !ifr.contains("AB <snapshot>")
                        }),
                        "{case}: show-ifr, variables that read nothing: {unread_ifr:?}"
                    );
                }
            }
        }

        let routed = hiidb((3, FLAG), &Password::InForm(3));
        let got = name_value_get(&routed, "W", &boot_services, Some(&snapshot));
        assert!(
            got.as_ref()
                .is_err_and(|error| error.ends_with(BOOT_SERVICES_REFUSAL)),
            "on the VARSTORE_NAME_VALUE: BootServices: {got:?}"
        );

        let unknown = hiidb((3, FLAG), &Password::InForm(9));
        let got = name_value_get(&unknown, "W", &runtime, Some(&snapshot));
        assert!(
            got.as_ref()
                .is_err_and(|error| error.contains(UNDECLARED_9) && error.ends_with(ANY_VARIABLE)),
            "of an undeclared VarStoreId: Runtime: {got:?}"
        );
        assert_eq!(
            unread(&unknown, &snapshot),
            no_value,
            "of an undeclared VarStoreId: variables that read nothing"
        );
        let runtime_listed = listed(&unknown, shared(&runtime), &snapshot);
        assert!(
            runtime_listed
                .as_ref()
                .is_err_and(|error| error.contains(UNDECLARED_9) && error.ends_with(ANY_VARIABLE)),
            "of an undeclared VarStoreId: list-questions, Runtime: {runtime_listed:?}"
        );
        assert_eq!(
            listed(&unknown, read_nothing(), &snapshot),
            no_value,
            "of an undeclared VarStoreId: list-questions, variables that read nothing"
        );
        let runtime_ifr = shown_ifr(&unknown, shared(&runtime), &snapshot);
        assert!(
            runtime_ifr
                .as_ref()
                .is_err_and(|error| error.contains(UNDECLARED_9) && error.ends_with(ANY_VARIABLE)),
            "of an undeclared VarStoreId: show-ifr, Runtime: {runtime_ifr:?}"
        );
        let unread_ifr = shown_ifr(&unknown, read_nothing(), &snapshot);
        assert!(
            unread_ifr
                .as_ref()
                .is_ok_and(|ifr| ifr.contains(&format!("-Answer: {no_value_text}\n"))
                    && !ifr.contains("AB <snapshot>")),
            "of an undeclared VarStoreId: show-ifr, variables that read nothing: {unread_ifr:?}"
        );
    }

    /// A name/value question takes its snapshot number by the label that its VarName string
    /// shows in the language of the other texts: PlatformLang, or --language before it.
    #[test]
    fn snapshot_labels_follow_the_text_language() {
        let packages = [
            device_path_package(&DRIVER_PATH),
            form_package(&[
                var_store_name_value(3, N_GUID),
                form(1, &[checkbox_at(1, 1, 3, 2)]),
            ]),
            strings_package_of(b"en-US", &["C", "Flag"]),
            strings_package_of(b"fr-FR", &["C", "Drapeau"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x55; 16], &packages.concat());
        let text = format!(
            "{}&Flag=00&Drapeau=01",
            config_hdr(N_GUID, "", &DRIVER_PATH)
        );
        let exported = || Some(ExportedConfig::new(text.clone()));
        let variables = no_variables();

        for (case, language, platform, want) in [
            ("no language", None, None, "0 <snapshot>"),
            ("PlatformLang fr-FR", None, Some("fr-FR"), "1 <snapshot>"),
            (
                "--language fr-FR",
                Some("fr-FR"),
                Some("en-US"),
                "1 <snapshot>",
            ),
        ] {
            let language = language.map(str::to_owned);
            let got = HiiBackend::get_in(
                &hiidb,
                "C",
                None,
                &GetOptions {
                    language: language.clone(),
                    ..GetOptions::default()
                },
                shared(&variables),
                exported(),
                platform,
                None,
            )
            .unwrap_or_else(|error| panic!("{case}: get: {error:#}"));
            let listed = HiiBackend::list_questions_in(
                &hiidb,
                &ListQuestionsOptions {
                    language: language.clone(),
                    ..ListQuestionsOptions::default()
                },
                shared(&variables),
                exported(),
                platform,
            )
            .unwrap_or_else(|error| panic!("{case}: list-questions: {error:#}"));
            let ifr = HiiBackend::show_ifr_in(
                &hiidb,
                &ShowIfrOptions {
                    language,
                    ..ShowIfrOptions::default()
                },
                shared(&variables),
                exported(),
                platform,
            )
            .unwrap_or_else(|error| panic!("{case}: show-ifr: {error:#}"))
            .to_string();

            let answers = |questions: Vec<&Question>| {
                questions
                    .into_iter()
                    .map(|question| question.answer.clone())
                    .collect::<Vec<_>>()
            };
            assert_eq!(
                answers(
                    got.responses
                        .iter()
                        .map(|response| &response.question)
                        .collect()
                ),
                [want],
                "{case}: get"
            );
            assert_eq!(
                answers(listed.iter().collect()),
                [want],
                "{case}: list-questions"
            );
            assert!(
                ifr.contains(&format!("-Answer: {want}\n")),
                "{case}: show-ifr lacks {want:?}: {ifr}"
            );
        }
    }

    /// A storage's later <BlockConfig> past the end of the bytes so far, as ExportConfig() gives
    /// a buffer of one block per question, extends it.
    #[test]
    fn snapshot_blocks_past_the_end_extend_their_storage() {
        let hdr = config_hdr(N_GUID, "NStore", &DRIVER_PATH);
        let text = format!("{}&OFFSET=1&WIDTH=2&VALUE=1234", block_resp(&hdr, 0, &[1]));

        let (got, listed, ifr, _) =
            answers_with_snapshot(&snapshot_hiidb(), &["N", "W"], &no_variables(), &text);

        let want = ["1 <snapshot>", "4660 <snapshot>"];
        assert_eq!(got, want, "get");
        assert_eq!(listed, want, "list-questions");
        assert!(
            ifr.contains("-Answer: 4660 <snapshot>\n"),
            "show-ifr: {ifr}"
        );
    }

    /// A HiiDB of the driver at DRIVER_PATH whose FormSet has the CHECKBOX P on the VarStore
    /// `p_store`, of id 1, and `question`, prompted string 2, on the VARSTORE_EFI Other of id 2,
    /// whose variable holds 0; its strings are P, Q, Off and On.
    fn condition_hiidb(p_store: Vec<u8>, question: Vec<u8>) -> Vec<u8> {
        let packages = [
            device_path_package(&DRIVER_PATH),
            form_package(&[
                p_store,
                var_store_efi_of(2, N_GUID, "Other", NV_BS_RT, 1),
                form(1, &[checkbox_on(1, 1, 1), question]),
            ]),
            en_strings_package_of(&["P", "Q", "Off", "On"]),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid([0x55; 16], &packages.concat())
    }

    /// Variables that hold condition_hiidb's Other, 0, and none of its P.
    fn other_variables() -> Rc<MemoryVariables> {
        other_variables_holding(0)
    }

    /// Variables that hold condition_hiidb's Other, `value`, and none of its P.
    fn other_variables_holding(value: u8) -> Rc<MemoryVariables> {
        let variables = no_variables();
        let other = VariableKey {
            name: "Other".to_owned(),
            guid: Guid::from(N_GUID),
        };
        variables.insert(other, NV_BS_RT, &[value]);
        variables
    }

    /// What get of question Q of `hiidb` gives with `include` through `variables` and the
    /// snapshot `text`, if any, and the answers that list-questions gives for it.
    fn condition_answers(
        hiidb: &[u8],
        include: IncludedStates,
        variables: &Rc<MemoryVariables>,
        text: Option<&str>,
    ) -> (Result<Vec<String>, String>, Vec<String>) {
        let exported = || text.map(|text| ExportedConfig::new(text.to_owned()));
        let got = HiiBackend::get_in(
            hiidb,
            "Q",
            None,
            &GetOptions {
                include,
                ..GetOptions::default()
            },
            shared(variables),
            exported(),
            None,
            None,
        )
        .map(|got| {
            got.responses
                .iter()
                .map(|response| response.question.answer.clone())
                .collect()
        })
        .map_err(|error| format!("{error:#}"));
        let listed = HiiBackend::list_questions_in(
            hiidb,
            &ListQuestionsOptions {
                include,
                ..ListQuestionsOptions::default()
            },
            shared(variables),
            exported(),
            None,
        )
        .expect("list questions")
        .into_iter()
        .filter(|question| question.name == "Q")
        .map(|question| question.answer)
        .collect();
        (got, listed)
    }

    /// A state that a condition decides from a value of the snapshot is tagged, as values are:
    /// get's refusal names the snapshot, and so do the answers of get and list-questions that
    /// include the state. Without the snapshot, the condition cannot be evaluated.
    #[test]
    fn states_that_snapshot_values_decide_are_tagged() {
        let variables = other_variables();
        let setup = block_resp(&config_hdr([0; 16], "Setup", &DRIVER_PATH), 0, &[1]);
        for (case, p_store, text) in [
            (
                "a missing variable",
                var_store(1, N_GUID, "NStore", 3),
                snapshot_text(),
            ),
            (
                "a variable without runtime access",
                var_store_efi(1, "Setup", NV_BS, 1),
                setup,
            ),
        ] {
            // the CHECKBOX Q on Other under GRAY_OUT_IF P == 1, where only the snapshot holds
            // P, 1
            let hiidb = condition_hiidb(
                p_store,
                conditional(GRAY_OUT_IF, eq_id_val_of(1, 1), &[checkbox_on(2, 2, 2)]),
            );

            let (got, listed) =
                condition_answers(&hiidb, IncludedStates::empty(), &variables, Some(&text));
            assert_eq!(
                got,
                Err(
                    "question \"Q\" is grayed-out by a value of the ExportConfig snapshot; also \
                     include grayed-out questions to select it"
                        .to_owned()
                ),
                "{case}: get"
            );
            assert_eq!(listed, Vec::<String>::new(), "{case}: list-questions");

            let (got, listed) =
                condition_answers(&hiidb, IncludedStates::GRAYED_OUT, &variables, Some(&text));
            let want = ["0 <grayed-out> <snapshot>"];
            assert_eq!(
                got,
                Ok(want.map(str::to_owned).to_vec()),
                "{case}: get, grayed-out"
            );
            assert_eq!(listed, want, "{case}: list-questions, grayed-out");

            for include in [IncludedStates::empty(), IncludedStates::GRAYED_OUT] {
                let (got, listed) = condition_answers(&hiidb, include, &variables, None);
                let got = got.unwrap_or_else(|error| panic!("{case}: get without it: {error}"));
                for answers in [got, listed] {
                    let [answer] = answers.as_slice() else {
                        panic!("{case}: {include:?} without the snapshot: {answers:?}");
                    };
                    assert!(
                        answer.starts_with(
                            "0 <selectable or grayed-out: EFI_IFR_EQ_ID_VAL of question 0x0001: \
                             <ValueUnavailable: "
                        ) && !answer.contains("snapshot"),
                        "{case}: {include:?} without the snapshot: {answer}"
                    );
                }
            }
        }
    }

    /// The snapshot tags just the states that its values decide: a false condition on one leaves
    /// the question selectable by the snapshot, a condition on one under a true DISABLE_IF
    /// decides nothing, and the stored option of a ONE_OF under a SUPPRESS_IF on one is tagged
    /// as its question is.
    #[test]
    fn snapshot_tags_just_the_states_that_its_values_decide() {
        let variables = other_variables();
        let check_box = || checkbox_on(2, 2, 2);
        let one_of = uint8_one_of(
            2,
            2,
            2,
            0,
            &[
                conditional(
                    SUPPRESS_IF,
                    eq_id_val_of(1, 1),
                    &[flagged_option(3, 0x00, 0)],
                ),
                flagged_option(4, 0x00, 1),
            ],
        );
        for (case, question, include, want) in [
            (
                "a false condition",
                conditional(GRAY_OUT_IF, eq_id_val_of(1, 0), &[check_box()]),
                IncludedStates::empty(),
                "0 <selectable> <snapshot>",
            ),
            (
                "a condition under a true DISABLE_IF",
                conditional(
                    DISABLE_IF,
                    ifr_true(),
                    &[conditional(GRAY_OUT_IF, eq_id_val_of(1, 1), &[check_box()])],
                ),
                IncludedStates::GRAYED_OUT | IncludedStates::DISABLED,
                "0 <disabled>",
            ),
            (
                "the stored option under a SUPPRESS_IF",
                one_of,
                IncludedStates::empty(),
                "Off <option suppressed> <snapshot>",
            ),
        ] {
            let hiidb = condition_hiidb(var_store(1, N_GUID, "NStore", 3), question);

            let (got, listed) =
                condition_answers(&hiidb, include, &variables, Some(&snapshot_text()));

            assert_eq!(got, Ok(vec![want.to_owned()]), "{case}: get");
            assert_eq!(listed, [want], "{case}: list-questions");
        }
    }

    /// show-ifr shows the condition ops of a question by their OpCode, untagged, beside the values
    /// that it tags: P's from the snapshot, and that of Q, under a GRAY_OUT_IF on P, from its
    /// variable.
    #[test]
    fn show_ifr_tags_snapshot_values_beside_condition_ops() {
        let hiidb = condition_hiidb(
            var_store(1, N_GUID, "NStore", 3),
            conditional(GRAY_OUT_IF, eq_id_val_of(1, 1), &[checkbox_on(2, 2, 2)]),
        );

        let (_, _, ifr, _) =
            answers_with_snapshot(&hiidb, &[], &other_variables(), &snapshot_text());

        let shown: Vec<&str> = ifr
            .lines()
            .map(str::trim_start)
            .skip_while(|line| *line != "OpCode: Form")
            .map(|line| line.split(" - ").next().unwrap_or(line))
            .collect();
        assert_eq!(
            shown,
            [
                "OpCode: Form",
                "OpCode: CheckBox",
                "-Answer: 1 <snapshot>",
                "OpCode: GrayOutIf",
                "OpCode: EqIdVal",
                "OpCode: CheckBox",
                "-Answer: 0",
            ],
            "{ifr}"
        );
    }

    /// The option that a ONE_OF answers is tagged when values that options of Type OTHER took
    /// from the snapshot decide it: the option took its value from there, or one before it that
    /// did would show if it matched, or none shows; one after it decides nothing. A stored value
    /// from the snapshot tags an OTHER option of a constant VALUE as it tags any option.
    #[test]
    fn options_whose_values_the_snapshot_gives_tag_the_one_of_answer() {
        // EFI_IFR_QUESTION_REF1 of P, which only the snapshot holds: 1
        let p = || vec![operation(QUESTION_REF1, false, &1u16.to_le_bytes())];
        let off = || flagged_option(3, 0x00, 0);
        let on_p = || other_option(4, 0x00, &p());
        for (case, var_store_id, stored, options, want) in [
            (
                "the shown option's VALUE takes P",
                2,
                1,
                [off(), on_p()],
                "On <snapshot>",
            ),
            (
                "an option before the shown one takes P",
                2,
                0,
                [on_p(), off()],
                "Off <snapshot>",
            ),
            (
                "an option after the shown one takes P",
                2,
                0,
                [off(), on_p()],
                "Off",
            ),
            (
                "no option shows, one takes P",
                2,
                2,
                [off(), on_p()],
                "2 (no matching option) <snapshot>",
            ),
            (
                "a stored value from the snapshot, an OTHER option of VALUE 1",
                1,
                0,
                [off(), other_option(4, 0x00, &[uint8(1)])],
                "On <snapshot>",
            ),
        ] {
            let hiidb = condition_hiidb(
                var_store(1, N_GUID, "NStore", 3),
                uint8_one_of(2, 2, var_store_id, 0, &options),
            );

            let (got, listed) = condition_answers(
                &hiidb,
                IncludedStates::empty(),
                &other_variables_holding(stored),
                Some(&snapshot_text()),
            );

            assert_eq!(got, Ok(vec![want.to_owned()]), "{case}: get");
            assert_eq!(listed, [want], "{case}: list-questions");
        }
    }

    /// set never takes a value from the snapshot: on a question whose value only the snapshot
    /// holds, it refuses as without one, and writes nothing.
    #[test]
    fn set_refuses_a_question_whose_value_only_the_snapshot_holds() {
        let variables = no_variables();
        let (got, _, _, _) =
            answers_with_snapshot(&snapshot_hiidb(), &["N"], &variables, &snapshot_text());
        assert_eq!(got, ["1 <snapshot>"], "get");

        let error = set_responses(
            &snapshot_hiidb(),
            "N",
            &SetValue::Text("0".to_owned()),
            None,
            &SetOptions::default(),
            SetAccess {
                reads: shared(&variables),
                writes: &*variables,
                held: None,
            },
            None,
        )
        .expect_err("set N");

        assert_eq!(
            format!("{error:#}"),
            "no EFI variable NStore-8c78a505-baa0-4c4a-869f-000000001401: the firmware has not \
             created it or does not expose it to the OS, so its questions cannot be set from \
             Linux; change them in the firmware setup, or ask the board vendor for firmware that \
             exposes it; see https://github.com/linuxboot/uefisettings/issues/2",
            "set N"
        );
        assert_eq!(variables.writes_to(&n_store()), [], "writes");
    }

    /// set's refusal of a question of NStore, whose variable only the snapshot holds.
    const N_STORE_NOT_EXPOSED: &str = "no EFI variable \
        NStore-8c78a505-baa0-4c4a-869f-000000001401: the firmware has not created it or does not \
        expose it to the OS, so its questions cannot be set from Linux; change them in the \
        firmware setup, or ask the board vendor for firmware that exposes it; see \
        https://github.com/linuxboot/uefisettings/issues/2";

    /// A HiiDB of the driver at DRIVER_PATH whose FormSet has `body` after the buffer VarStore
    /// NStore of `size` bytes, of id 1; its strings are `strings`.
    fn n_store_hiidb(size: u16, body: &[Vec<u8>], strings: &[&str]) -> Vec<u8> {
        let packages = [
            device_path_package(&DRIVER_PATH),
            form_package(&[var_store(1, N_GUID, "NStore", size), form(1, body)]),
            en_strings_package_of(strings),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid([0x55; 16], &packages.concat())
    }

    /// The snapshot of the driver of n_store_hiidb, whose NStore holds `bytes`.
    fn n_store_snapshot(bytes: &[u8]) -> String {
        block_resp(&config_hdr(N_GUID, "NStore", &DRIVER_PATH), 0, bytes)
    }

    /// The error of set of `question` of `hiidb` to `value` through no variables, after
    /// asserting that it wrote nothing.
    #[track_caller]
    fn set_error_without_variables(hiidb: &[u8], question: &str, value: SetValue) -> String {
        let variables = no_variables();
        let error = HiiBackend::set_in(
            hiidb,
            question,
            &value,
            None,
            &SetOptions::default(),
            SetAccess {
                reads: shared(&variables),
                writes: &*variables,
                held: None,
            },
            None,
        )
        .expect_err(question);
        assert_eq!(variables.writes_to(&n_store()), [], "{question}: writes");
        format!("{error:#}")
    }

    /// A NUMERIC that displays hexadecimal shows its value from the snapshot in decimal, tagged,
    /// as get shows any NUMERIC; set refuses a hexadecimal value of it as a decimal one, as it
    /// never takes the snapshot.
    #[test]
    fn hexadecimal_numerics_show_snapshot_values_and_set_refuses_them() {
        // a UINT16 NUMERIC at byte 1, EFI_IFR_DISPLAY_UINT_HEX, from 0 to 65535
        let data = [
            question_header_with(1, 1, 1, 1, 0x00),
            vec![0x21, 0x00, 0x00, 0xFF, 0xFF, 0x01, 0x00],
        ]
        .concat();
        let hiidb = n_store_hiidb(3, &[operation(NUMERIC, false, &data)], &["H"]);
        let text = n_store_snapshot(&[0, 0x34, 0x12]);

        let (got, listed, ifr, _) = answers_with_snapshot(&hiidb, &["H"], &no_variables(), &text);

        assert_eq!(got, ["4660 <snapshot>"], "get");
        assert_eq!(listed, ["4660 <snapshot>"], "list-questions");
        assert!(
            ifr.contains("-Answer: 4660 <snapshot>\n"),
            "show-ifr: {ifr}"
        );
        for value in ["0x1E", "30"] {
            assert_eq!(
                set_error_without_variables(&hiidb, "H", SetValue::Text(value.to_owned())),
                N_STORE_NOT_EXPOSED,
                "set {value}"
            );
        }
    }

    /// A DATE and a TIME on a VarStore whose variable is missing show their values from the
    /// snapshot, tagged, as get shows a NUMERIC's; set refuses them, as it never takes the
    /// snapshot.
    #[test]
    fn dates_and_times_show_snapshot_values_and_set_refuses_them() {
        let date = [question_header_with(1, 1, 1, 0, 0x00), vec![0x00]].concat();
        let time = [question_header_with(2, 2, 1, 4, 0x00), vec![0x00]].concat();
        let hiidb = n_store_hiidb(
            7,
            &[operation(DATE, false, &date), operation(TIME, false, &time)],
            &["D", "T"],
        );
        // the EFI_HII_DATE 2026-11-10 and the EFI_HII_TIME 12:34:56
        let text = n_store_snapshot(&[0xEA, 0x07, 11, 10, 12, 34, 56]);

        let (got, listed, ifr, _) =
            answers_with_snapshot(&hiidb, &["D", "T"], &no_variables(), &text);

        let want = ["2026-11-10 <snapshot>", "12:34:56 <snapshot>"];
        assert_eq!(got, want, "get");
        assert_eq!(listed, want, "list-questions");
        for shown in want {
            assert!(
                ifr.contains(&format!("-Answer: {shown}\n")),
                "show-ifr lacks {shown:?}: {ifr}"
            );
        }
        for (question, value) in [("D", "2027-01-02"), ("T", "01:02:03")] {
            assert_eq!(
                set_error_without_variables(&hiidb, question, SetValue::Text(value.to_owned())),
                N_STORE_NOT_EXPOSED,
                "set {question}"
            );
        }
    }

    /// A DATE or TIME of EFI Date/Time Storage keeps its value there (UEFI 2.11 §33.2.5.6), not
    /// in the snapshot, which holds the bytes of VarStores only: on Linux, which reaches no Time
    /// Services, it shows why it has no value, untagged, also when the snapshot holds the bytes
    /// of its VarStore.
    #[test]
    fn dates_and_times_of_time_storage_take_no_snapshot_value() {
        // the system time's date at byte 0 of NStore, the wake-up time's time at byte 4, and the
        // system time's date without a VarStore
        let date = [question_header_with(1, 1, 1, 0, 0x00), vec![0x10]].concat();
        let time = [question_header_with(2, 2, 1, 4, 0x00), vec![0x20]].concat();
        let only = [question_header_with(3, 3, 0, 0, 0x00), vec![0x10]].concat();
        let hiidb = n_store_hiidb(
            7,
            &[
                operation(DATE, false, &date),
                operation(TIME, false, &time),
                operation(DATE, false, &only),
            ],
            &["D", "W", "S"],
        );
        let text = n_store_snapshot(&[0xEA, 0x07, 11, 10, 12, 34, 56]);

        let (got, listed, ifr, outputs) =
            answers_with_snapshot(&hiidb, &["D", "W", "S"], &no_variables(), &text);

        let unread = |service: &str| {
            format!(
                "<ValueUnavailable: EFI Date/Time Storage (UEFI 2.11 §33.2.5.6) is read only \
                 through {service}; run uefisettings.efi in the UEFI Shell>"
            )
        };
        let want = [
            unread("GetTime()"),
            unread("GetWakeupTime()"),
            unread("GetTime()"),
        ];
        assert_eq!(got, want, "get");
        assert_eq!(listed, want, "list-questions");
        for shown in &want {
            assert!(
                ifr.contains(&format!("-Answer: {shown}\n")),
                "show-ifr lacks {shown:?}: {ifr}"
            );
        }
        for output in outputs {
            assert!(!output.contains("<snapshot>"), "{output}");
        }
    }

    /// An ORDERED_LIST on a VarStore whose variable is missing shows its items from the snapshot,
    /// tagged, as get shows a ONE_OF's option; set refuses new items, as it never takes the
    /// snapshot.
    #[test]
    fn ordered_lists_show_snapshot_items_and_set_refuses_them() {
        let list = [
            operation(
                ORDERED_LIST,
                true,
                &[question_header_with(1, 1, 1, 0, 0x00), vec![2, 0x00]].concat(),
            ),
            flagged_option(2, 0x00, 1),
            flagged_option(3, 0x00, 2),
            END.to_vec(),
        ]
        .concat();
        let hiidb = n_store_hiidb(2, &[list], &["L", "A", "B"]);

        let (got, listed, ifr, _) =
            answers_with_snapshot(&hiidb, &["L"], &no_variables(), &n_store_snapshot(&[2, 1]));

        assert_eq!(got, ["B, A <snapshot>"], "get");
        assert_eq!(listed, ["B, A <snapshot>"], "list-questions");
        assert!(
            ifr.contains("-Answer: B, A <snapshot>\n"),
            "show-ifr: {ifr}"
        );
        let items = SetValue::Items(vec!["A".to_owned(), "B".to_owned()]);
        assert_eq!(
            set_error_without_variables(&hiidb, "L", items),
            N_STORE_NOT_EXPOSED,
            "set"
        );
    }

    /// A REF on a VarStore whose variable is missing shows the EFI_HII_REF that the snapshot
    /// holds, tagged, as get shows other values.
    #[test]
    fn cross_references_show_snapshot_values() {
        // an EFI_IFR_REF5 at byte 0 of NStore
        let reference = operation(REF, false, &question_header_with(1, 1, 1, 0, 0x00));
        let hiidb = n_store_hiidb(22, &[reference], &["R"]);
        // QuestionId 5, FormId 1, FormSetGuid N_GUID, DevicePath 0
        let stored = [
            &5u16.to_le_bytes()[..],
            &1u16.to_le_bytes(),
            &N_GUID,
            &0u16.to_le_bytes(),
        ]
        .concat();

        let (got, listed, ifr, _) =
            answers_with_snapshot(&hiidb, &["R"], &no_variables(), &n_store_snapshot(&stored));

        let want = "QuestionId 0x0005, FormId 0x0001, FormSetGuid \
            8C78A505-BAA0-4C4A-869F-000000001401, DevicePath none <snapshot>";
        assert_eq!(got, [want], "get");
        assert_eq!(listed, [want], "list-questions");
        assert!(
            ifr.contains(&format!("-Answer: {want}\n")),
            "show-ifr: {ifr}"
        );
    }

    /// The records of staged sets that NextBootStaging's get reads, as `0` holds them.
    #[cfg(target_os = "linux")]
    struct StagingRecords<'a>(&'a crate::efi_variables::globals::tests::HeldVariables);

    #[cfg(target_os = "linux")]
    impl DriverHeldValues for StagingRecords<'_> {
        fn store_name(&self) -> &'static str {
            "staged for the next boot"
        }

        fn get(
            &self,
            _list: &QuestionList<'_>,
            question: &QuestionDescriptor,
            held: &DriverHeldQuestion,
        ) -> Result<String> {
            Ok(crate::staged_set::next_boot::NextBootStaging::answer(
                Ok(self.0),
                question,
                held,
            ))
        }

        fn check_set(
            &self,
            _list: &QuestionList<'_>,
            _question: &QuestionDescriptor,
            _held: &DriverHeldQuestion,
        ) -> Result<()> {
            Err(anyhow!("get only"))
        }

        fn set(
            &self,
            _list: &QuestionList<'_>,
            _question: &QuestionDescriptor,
            _held: &DriverHeldQuestion,
            _value: u64,
        ) -> Result<String> {
            Err(anyhow!("get only"))
        }
    }

    /// On Linux, get of a question whose driver holds its value reads nothing of the ExportConfig
    /// snapshot, whose <ConfigResp>s hold the bytes of VarStores only: beside the snapshot, as
    /// without it, it shows why the question has no value and its IFR default, with what the
    /// records of staged sets tell of it, and no `<snapshot>` mark, while a stored question of the
    /// same prompt reads the snapshot.
    #[cfg(target_os = "linux")]
    #[test]
    fn linux_get_of_a_driver_held_question_reads_nothing_of_the_snapshot() {
        use crate::efi_variables::globals::tests::HeldVariables;
        use crate::efi_variables::globals::EFI_GLOBAL_VARIABLE;
        use crate::staged_set::record_set;
        use crate::staged_set::Nonce;
        use crate::staged_set::Sha256Digest;
        use crate::staged_set::StagedImage;
        use crate::staged_set::StagedRequest;
        use crate::staged_set::StagedSet;

        // snapshot_hiidb's N, at byte 0 of NStore, which the snapshot holds as 1; then N of
        // FormSet 11111111-…, QuestionId 7, held by its driver
        let held = package_list_with_guid(
            [0x66; 16],
            &[
                form_package(&[form(1, &[callback_checkbox(7, 1)])]),
                en_strings_package_of(&["N"]),
                END_PACKAGE.to_vec(),
            ]
            .concat(),
        );
        let hiidb = [snapshot_hiidb(), held].concat();
        // a set that waits for its boot, Boot0007, with a request of 1 for the held N
        let records =
            HeldVariables::default().with("BootNext", EFI_GLOBAL_VARIABLE, &7u16.to_le_bytes());
        let request = StagedRequest {
            question: "N".to_owned(),
            form_set: "11111111-1111-1111-1111-111111111111"
                .parse()
                .expect("a GUID"),
            question_id: 7,
            value_type: IfrValueType::Boolean,
            value: 1,
            include: IncludedStates::empty(),
            access_level: None,
            unsafe_operations: UnsafeOperations::Refuse,
        };
        let staged = StagedSet {
            nonce: Nonce([0x5A; 16]),
            boot_option: 7,
            image: StagedImage {
                path: "\\EFI\\uefisettings\\uefisettings.efi".to_owned(),
                sha256: Sha256Digest([0x42; 32]),
            },
            requests: vec![request],
        };
        record_set(&records, &staged).expect("record the staged set");
        let unreached = "question has no VarStore; its driver keeps the value, which only \
                         EFI_HII_CONFIG_ACCESS_PROTOCOL.CallBack() reaches (UEFI 2.11 §33.2.5.6), \
                         and after ExitBootServices() no EFI device-handle-based protocol may be \
                         used (UEFI 2.11 §7.4.6); use uefisettings.efi in the UEFI Shell";

        let held_answer = format!(
            "<ValueUnavailable: {unreached}> <IFR default: 0> <1 is staged for the next boot, as \
             Boot0007: restart to apply>"
        );

        for (case, exported, stored_from_snapshot) in [
            (
                "beside the snapshot",
                Some(ExportedConfig::new(snapshot_text())),
                true,
            ),
            ("without the snapshot", None, false),
        ] {
            let got = HiiBackend::get_in(
                &hiidb,
                "N",
                None,
                &GetOptions::default(),
                shared(&no_variables()),
                exported,
                None,
                Some(&StagingRecords(&records)),
            )
            .unwrap_or_else(|error| panic!("get N {case}: {error:#}"));

            let answers: Vec<&str> = got
                .responses
                .iter()
                .map(|response| response.question.answer.as_str())
                .collect();
            assert_eq!(answers.len(), 2, "the stored N and the held N {case}");
            assert_eq!(answers[1], held_answer, "the held N {case}");
            assert_eq!(
                answers[0] == "1 <snapshot>",
                stored_from_snapshot,
                "the stored N {case}: {}",
                answers[0]
            );
        }
    }

    /// Reading a snapshot logs none of its bytes, at any level, also when it is no
    /// <MultiConfigAltResp> or holds a <ConfigAltResp> that does not parse.
    #[test]
    fn snapshot_bytes_are_never_logged() {
        let malformed = format!(
            "{}&OFFSET=0&VALUE={}",
            config_hdr(P_GUID, "AMITSESetup", &DRIVER_PATH),
            "a5".repeat(81)
        );
        let partly_malformed = format!("{}&{malformed}", snapshot_text());

        let logged = logged_by(|| {
            for text in [snapshot_text(), malformed, partly_malformed] {
                answers_with_snapshot(&snapshot_hiidb(), &["N", "P"], &no_variables(), &text);
            }
        });

        for (what, logs) in [
            (
                "the refusal of the malformed snapshot",
                "not a <MultiConfigAltResp>",
            ),
            (
                "the storage that does not parse",
                "1 of the 3 <ConfigAltResp>s",
            ),
        ] {
            assert!(
                logged.iter().any(|message| message.contains(logs)),
                "{what} is not logged: {logged:?}"
            );
        }
        assert_no_password_byte(&logged);
    }

    /// The strings of short_store_hiidb from ID 1: the prompts of the questions A to F, the
    /// VarNames of A to E, and the texts of the options of C.
    const SHORT_STRINGS: [&str; 13] = [
        "A",
        "B",
        "C",
        "D",
        "E",
        "F",
        "ShortVarA",
        "ShortVarB",
        "ShortVarC",
        "ShortVarD",
        "ShortVarE",
        "Off",
        "On",
    ];
    /// The VarNames of the questions A to E of short_store_hiidb.
    const SHORT_VAR_NAMES: [&str; 5] = [
        "ShortVarA",
        "ShortVarB",
        "ShortVarC",
        "ShortVarD",
        "ShortVarE",
    ];

    /// A NUMERIC of QuestionId `question_id`, prompted string `prompt`, on VarStore 1 with VarName
    /// `var_name`, of Flags `flags` and the MinValue, MaxValue and Step `range`.
    fn short_numeric(
        question_id: u16,
        prompt: u16,
        var_name: u16,
        flags: u8,
        range: &[u8],
    ) -> Vec<u8> {
        let data = [
            question_header_with(question_id, prompt, 1, var_name, 0x00),
            vec![flags],
            range.to_vec(),
        ]
        .concat();
        operation(NUMERIC, false, &data)
    }

    /// The UINT8 NUMERIC A, from 0 to 255, on VarName 7, ShortVarA.
    fn short_numeric_a() -> Vec<u8> {
        // EFI_IFR_NUMERIC_SIZE_1 | EFI_IFR_DISPLAY_UINT_DEC
        short_numeric(1, 1, 7, 0x10, &[0, 255, 1])
    }

    /// The questions A to E of short_store_hiidb, each on the VarName that SHORT_VAR_NAMES names
    /// in its place: the NUMERIC A, the CHECKBOX B, the ONE_OF C of Off (0) and On (1), the
    /// UINT16 NUMERIC D and the UINT32 NUMERIC E.
    fn short_questions() -> Vec<Vec<u8>> {
        let one_of = [question_header_with(3, 3, 1, 9, 0x00), vec![0x10, 0, 1, 1]].concat();
        let uint16_range = [0, u16::MAX, 1].map(u16::to_le_bytes).concat();
        let uint32_range = [0, u32::MAX, 1].map(u32::to_le_bytes).concat();
        vec![
            short_numeric_a(),
            checkbox_at(2, 2, 1, 8),
            [
                operation(ONE_OF, true, &one_of),
                flagged_option(12, 0x00, 0),
                flagged_option(13, 0x00, 1),
                END.to_vec(),
            ]
            .concat(),
            // EFI_IFR_NUMERIC_SIZE_2 | EFI_IFR_DISPLAY_UINT_DEC
            short_numeric(4, 4, 10, 0x11, &uint16_range),
            // EFI_IFR_NUMERIC_SIZE_4 | EFI_IFR_DISPLAY_UINT_DEC
            short_numeric(5, 5, 11, 0x12, &uint32_range),
        ]
    }

    /// A package list holding a FormSet of `children` and the strings packages `strings`.
    fn short_store_list(children: &[Vec<u8>], strings: &[Vec<u8>]) -> Vec<u8> {
        let packages = [
            form_package(children),
            strings.concat(),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid([0x55; 16], &packages.concat())
    }

    /// A HiiDB whose FormSet declares the VARSTORE_EFI before UEFI 2.3.1 of VarStoreId 1,
    /// SHORT_VAR_STORE_GUID and `attributes`, then holds `questions` in a form, with the strings
    /// SHORT_STRINGS.
    fn short_store_hiidb(attributes: u32, questions: &[Vec<u8>]) -> Vec<u8> {
        short_store_list(
            &[
                short_var_store_efi_of(1, SHORT_VAR_STORE_GUID, attributes),
                form(1, questions),
            ],
            &[en_strings_package_of(&SHORT_STRINGS)],
        )
    }

    /// The EFI variable `name` of SHORT_VAR_STORE_GUID.
    fn short_key(name: &str) -> VariableKey {
        VariableKey {
            name: name.to_string(),
            guid: Guid::from(SHORT_VAR_STORE_GUID),
        }
    }

    /// The variables of the questions A to E of short_store_hiidb, each NV|BS|RT, which reach
    /// `reach` through `interface`: A holds 5, B 1, C 0, D 0x1234 and E 0x12345678.
    fn short_variables(reach: VariableReach, interface: VariableInterface) -> Rc<MemoryVariables> {
        let variables = MemoryVariables::new(reach, interface);
        let values = [
            vec![5],
            vec![1],
            vec![0],
            0x1234u16.to_le_bytes().to_vec(),
            0x1234_5678u32.to_le_bytes().to_vec(),
        ];
        for (name, value) in SHORT_VAR_NAMES.into_iter().zip(values) {
            variables.insert(short_key(name), NV_BS_RT, &value);
        }
        Rc::new(variables)
    }

    /// short_variables through efivarfs.
    fn short_efivarfs_variables() -> Rc<MemoryVariables> {
        short_variables(VariableReach::Runtime, VariableInterface::Efivarfs)
    }

    /// set of `question` to `value` in the HiiDB `hiidb` through `variables`, as the CLI prints an
    /// error.
    fn set_of(
        hiidb: &[u8],
        question: &str,
        value: &str,
        variables: &Rc<MemoryVariables>,
    ) -> Result<(), String> {
        set_responses(
            hiidb,
            question,
            &SetValue::Text(value.to_owned()),
            None,
            &SetOptions::default(),
            SetAccess {
                reads: shared(variables),
                writes: &**variables,
                held: None,
            },
            None,
        )
        .map(drop)
        .map_err(|error| format!("{error:#}"))
    }

    /// Each ONE_OF, NUMERIC and CHECKBOX on a VARSTORE_EFI before UEFI 2.3.1 reads and sets the
    /// EFI variable that its VarName names, of the store's Guid, from byte 0 as wide as its value,
    /// as edk2-stable202608 SetupBrowserDxe/Setup.c GetQuestionValue and SetQuestionValue do; set
    /// writes no other variable.
    #[test]
    fn questions_of_a_short_var_store_read_and_set_the_variables_of_their_var_names() {
        let hiidb = short_store_hiidb(NV_BS_RT, &short_questions());
        let cases = [
            ("A", "5", "9", vec![9]),
            ("B", "1", "0", vec![0]),
            ("C", "Off", "On", vec![1]),
            ("D", "4660", "513", vec![0x01, 0x02]),
            ("E", "305419896", "70000", 70_000u32.to_le_bytes().to_vec()),
        ];
        for ((question, value, new_value, written), name) in cases.into_iter().zip(SHORT_VAR_NAMES)
        {
            let variables = short_efivarfs_variables();

            assert_eq!(
                answers_of(&hiidb, question, &variables),
                [value],
                "get {question}"
            );
            assert_eq!(
                set_of(&hiidb, question, new_value, &variables),
                Ok(()),
                "set {question}"
            );

            for other in SHORT_VAR_NAMES {
                let want = match other == name {
                    true => vec![(0, written.clone())],
                    false => vec![],
                };
                assert_eq!(
                    variables.writes_to(&short_key(other)),
                    want,
                    "set {question}: writes of {other}"
                );
            }
            assert_eq!(
                answers_of(&hiidb, question, &variables),
                [new_value],
                "get {question} after set"
            );
        }
    }

    /// A question on a VARSTORE_EFI before UEFI 2.3.1 whose VarName no string holds names no
    /// variable, where edk2-stable202608 SetupBrowserDxe/Setup.c GetToken takes the unknown string
    /// "!": get shows why and set refuses it, while the question beside it reads.
    #[test]
    fn a_short_var_store_question_without_a_var_name_string_is_refused() {
        let hiidb = short_store_hiidb(
            NV_BS_RT,
            &[
                short_numeric_a(),
                short_numeric(6, 6, 99, 0x10, &[0, 255, 1]),
            ],
        );
        let variables = short_efivarfs_variables();
        let why =
            "VarStore 0x0001 (EFI_IFR_VARSTORE_EFI before UEFI 2.3.1): no string 0x0063 holds \
                   its VarName";

        assert_eq!(
            answers_of(&hiidb, "F", &variables),
            [format!("<ValueUnavailable: {why}>")],
            "get F"
        );
        assert_eq!(
            set_of(&hiidb, "F", "1", &variables),
            Err(format!("cannot set question \"F\": {why}")),
            "set F"
        );
        assert_eq!(answers_of(&hiidb, "A", &variables), ["5"], "get A");
        assert_eq!(
            variables.writes_to(&short_key("ShortVarA")),
            vec![],
            "writes of ShortVarA"
        );
    }

    /// A question on a VARSTORE_EFI before UEFI 2.3.1 is shown and selected as any question:
    /// list-questions shows its QuestionId, its FormSet's GUID and its keyword, show-ifr its
    /// FormSet's GUID and its answer, and get and set select it by QuestionId and by keyword, and
    /// read and set its variable. Here the NUMERIC A, of QuestionId 1 in form_package's FormSet,
    /// whose prompt x-UEFI-ns names "ShortKeyA", on ShortVarA, which holds 5.
    #[test]
    fn short_var_store_questions_show_their_identity_and_select_by_question_id_or_keyword() {
        let hiidb = short_store_list(
            &[
                short_var_store_efi_of(1, SHORT_VAR_STORE_GUID, NV_BS_RT),
                form(1, &[short_numeric_a()]),
            ],
            &[
                en_strings_package_of(&SHORT_STRINGS),
                strings_package_of(b"x-UEFI-ns", &["ShortKeyA"]),
            ],
        );
        let form_set = Guid::from([0x11; 16]).to_string();
        let variables = short_efivarfs_variables();

        let listed = HiiBackend::list_questions_in(
            &hiidb,
            &ListQuestionsOptions::default(),
            shared(&variables),
            None,
            None,
        )
        .expect("list the questions");
        let ifr = HiiBackend::show_ifr_in(
            &hiidb,
            &ShowIfrOptions::default(),
            shared(&variables),
            None,
            None,
        )
        .expect("show the IFR")
        .to_string();

        let listed: Vec<(&str, &str, [Option<serde_json::Value>; 3])> = listed
            .iter()
            .map(|question| {
                (
                    question.name.as_str(),
                    question.answer.as_str(),
                    identity_json(question),
                )
            })
            .collect();
        let identity = [
            Some(serde_json::json!(1)),
            Some(serde_json::json!(form_set)),
            Some(serde_json::json!([{"namespace_id": "x-UEFI-ns", "keyword": "ShortKeyA"}])),
        ];
        assert_eq!(listed, [("A", "5", identity)], "list-questions");
        assert!(
            ifr.contains(&format!("GUID {form_set}")) && ifr.contains("Q: A - Help:"),
            "show-ifr: {ifr}"
        );
        assert!(ifr.contains("-Answer: 5\n"), "show-ifr: {ifr}");
        for (question, value) in [
            (by_address(&format!("{form_set}:1")), 9),
            (by_keyword("ShortKeyA", None), 10),
        ] {
            let variables = short_efivarfs_variables();

            let got = HiiBackend::get_in(
                &hiidb,
                question.clone(),
                None,
                &GetOptions::default(),
                shared(&variables),
                None,
                None,
                None,
            )
            .unwrap_or_else(|error| panic!("get {question}: {error:#}"));
            let set = set_responses(
                &hiidb,
                question.clone(),
                &SetValue::Text(value.to_string()),
                None,
                &SetOptions::default(),
                SetAccess {
                    reads: shared(&variables),
                    writes: &*variables,
                    held: None,
                },
                None,
            )
            .map(drop)
            .map_err(|error| format!("{error:#}"));

            let got: Vec<&str> = got
                .responses
                .iter()
                .map(|response| response.question.answer.as_str())
                .collect();
            assert_eq!(got, ["5"], "get {question}");
            assert_eq!(set, Ok(()), "set {question} {value}");
            assert_eq!(
                variables.writes_to(&short_key("ShortVarA")),
                [(0, vec![value])],
                "set {question} {value}: writes of ShortVarA"
            );
        }
    }

    /// A question on a VARSTORE_EFI before UEFI 2.3.1 takes no value from the ExportConfig
    /// snapshot, as edk2-stable202608 ExportConfig() asks a driver's ExtractConfig() only for the
    /// storages that HiiDatabaseDxe/ConfigRouting.c ParseIfrData finds, which skips the short op
    /// (:2485): no <ConfigResp> holds the variable of a VarName, and one under the VarName's name
    /// and the store's Guid is another storage. get, list-questions and show-ifr show the
    /// variable, or why it has no value, untagged, here beside such a <ConfigResp> of 7.
    #[test]
    fn short_var_store_questions_take_no_snapshot_value() {
        let key = "ShortVarA-8c78a505-baa0-4c4a-869f-000000000b01";
        let text = block_resp(
            &config_hdr(SHORT_VAR_STORE_GUID, "ShortVarA", &DRIVER_PATH),
            0,
            &[7],
        );
        let cases = [
            (
                NV_BS_RT,
                None,
                format!("<ValueUnavailable: no EFI variable {key}>"),
            ),
            (
                NV_BS,
                None,
                format!(
                    "<ValueUnavailable: EFI variable {key} is not present at OS runtime: efivarfs \
                     does not list it, and its form declares it boot-service-only (no \
                     EFI_VARIABLE_RUNTIME_ACCESS)>"
                ),
            ),
            (NV_BS_RT, Some(5), "5".to_string()),
        ];
        for (attributes, held, want) in cases {
            let packages = [
                device_path_package(&DRIVER_PATH),
                form_package(&[
                    short_var_store_efi_of(1, SHORT_VAR_STORE_GUID, attributes),
                    form(1, &[short_numeric_a()]),
                ]),
                en_strings_package_of(&SHORT_STRINGS),
                END_PACKAGE.to_vec(),
            ];
            let hiidb = package_list_with_guid([0x55; 16], &packages.concat());
            let variables = no_variables();
            if let Some(value) = held {
                variables.insert(short_key("ShortVarA"), attributes, &[value]);
            }

            let (got, listed, ifr, _) = answers_with_snapshot(&hiidb, &["A"], &variables, &text);

            let case = format!("attributes {attributes:#x}, ShortVarA {held:?}");
            assert_eq!(got, [want], "get, {case}");
            assert_eq!(listed, got, "list-questions, {case}");
            assert!(!ifr.contains("<snapshot>"), "show-ifr, {case}: {ifr}");
        }
    }

    /// get shows a missing per-question variable as missing, through variables that reach Runtime
    /// in the words of the runtime access that its VARSTORE_EFI declares: one declared without
    /// EFI_VARIABLE_RUNTIME_ACCESS is not present at OS runtime.
    #[test]
    fn a_missing_per_question_variable_is_shown_as_its_var_store_declares_it() {
        let key = "ShortVarA-8c78a505-baa0-4c4a-869f-000000000b01";
        let cases = [
            (NV_BS_RT, format!("no EFI variable {key}")),
            (
                NV_BS,
                format!(
                    "EFI variable {key} is not present at OS runtime: efivarfs does not list it, \
                     and its form declares it boot-service-only (no EFI_VARIABLE_RUNTIME_ACCESS)"
                ),
            ),
        ];
        for (attributes, why) in cases {
            let hiidb = short_store_hiidb(attributes, &[short_numeric_a()]);
            let variables = Rc::new(MemoryVariables::default());

            assert_eq!(
                answers_of(&hiidb, "A", &variables),
                [format!("<ValueUnavailable: {why}>")],
                "get, attributes {attributes:#x}"
            );
        }
    }

    /// set creates a missing per-question variable with the Attributes of its VARSTORE_EFI, as
    /// edk2-stable202608 SetupBrowserDxe/Setup.c SetQuestionValue does ("This service can be used
    /// to create a new variable", UEFI 2.11 §8.2.3 SetVariable), of its question's width, through
    /// efivarfs and Variable Services; get then reads it. It refuses, creating nothing, through
    /// variables that reach Runtime a store without EFI_VARIABLE_RUNTIME_ACCESS, whose variable no
    /// SetVariable() sets once ExitBootServices() is performed (§8.2.3), the Attributes of a
    /// volatile or authenticated variable, as of an existing one, and creation through the
    /// firmware environment calls of Windows.
    #[test]
    fn set_creates_a_missing_per_question_variable_with_the_attributes_of_its_var_store() {
        // EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS
        const TIME_BASED_AUTHENTICATED: u32 = 0x20;
        let linux = (VariableReach::Runtime, VariableInterface::Efivarfs);
        let shell = (
            VariableReach::BootServices,
            VariableInterface::VariableServices,
        );
        let windows = (
            VariableReach::Runtime,
            VariableInterface::FirmwareEnvironment,
        );
        let key = "ShortVarA-8c78a505-baa0-4c4a-869f-000000000b01";
        let created =
            |attributes: u32, value: &[u8]| Ok([&attributes.to_ne_bytes()[..], value].concat());
        let cases = [
            (linux, NV_BS_RT, "A", "9", created(NV_BS_RT, &[9])),
            (linux, NV_BS_RT, "D", "513", created(NV_BS_RT, &[1, 2])),
            (shell, NV_BS, "A", "9", created(NV_BS, &[9])),
            (shell, NV_BS_RT, "D", "513", created(NV_BS_RT, &[1, 2])),
            (
                linux,
                NV_BS,
                "A",
                "9",
                Err(format!(
                    "EFI variable {key} is not present at OS runtime: efivarfs does not list it, \
                     and its form declares it boot-service-only (no EFI_VARIABLE_RUNTIME_ACCESS)"
                )),
            ),
            (
                linux,
                BS_RT,
                "A",
                "9",
                Err(format!(
                    "EFI variable {key} is volatile (no EFI_VARIABLE_NON_VOLATILE) and cannot be \
                     written through efivarfs"
                )),
            ),
            (
                linux,
                NV_BS_RT | TIME_BASED_AUTHENTICATED,
                "A",
                "9",
                Err(format!(
                    "EFI variable {key} has authenticated access (attributes 0x27), which \
                     uefisettings does not write"
                )),
            ),
            (
                windows,
                NV_BS_RT,
                "A",
                "9",
                Err(format!(
                    "no EFI variable {key}: the firmware has not created it or does not expose it \
                     to the OS, so its questions cannot be set from Windows; change them in the \
                     firmware setup, or ask the board vendor for firmware that exposes it; see \
                     https://github.com/linuxboot/uefisettings/issues/2"
                )),
            ),
        ];
        for ((reach, interface), attributes, question, value, want) in cases {
            let hiidb = short_store_hiidb(attributes, &short_questions());
            let variables = Rc::new(MemoryVariables::new(reach, interface));
            let name = match question {
                "A" => "ShortVarA",
                _ => "ShortVarD",
            };
            let case = format!("{interface:?}, attributes {attributes:#x}, set {question}");

            let set = set_of(&hiidb, question, value, &variables);

            assert_eq!(
                set.map(|()| variables.bytes(&short_key(name))),
                want.clone().map(Some),
                "{case}"
            );
            if want.is_ok() {
                assert_eq!(
                    answers_of(&hiidb, question, &variables),
                    [value],
                    "{case}: get"
                );
            }
            for other in SHORT_VAR_NAMES.into_iter().filter(|&other| other != name) {
                assert_eq!(variables.bytes(&short_key(other)), None, "{case}: {other}");
            }
        }
    }

    /// set creates a missing per-question variable at one width: where a question's WRITE SETs
    /// its own VarName at another width, set refuses to create it, as the variable would hold the
    /// value of neither; where the variable holds the question's value, the SET of another width
    /// stores nothing, as edk2-stable202608 would resize it, and set writes the question's value.
    #[test]
    fn set_creates_a_per_question_variable_at_one_width() {
        const SET: u8 = 0x2C;
        const WRITE: u8 = 0x2E;
        const THIS: u8 = 0x58;
        // the UINT8 NUMERIC A on ShortVarA, whose WRITE sets ShortVarA as a UINT16
        // (EFI_IFR_TYPE_NUM_SIZE_16)
        let set_as_uint16 = operation(
            SET,
            false,
            &[&1u16.to_le_bytes()[..], &7u16.to_le_bytes(), &[0x01]].concat(),
        );
        let numeric_a = [
            operation(
                NUMERIC,
                true,
                &[
                    question_header_with(1, 1, 1, 7, 0x00),
                    // EFI_IFR_NUMERIC_SIZE_1 | EFI_IFR_DISPLAY_UINT_DEC, from 0 to 255, step 1
                    vec![0x10, 0, 255, 1],
                ]
                .concat(),
            ),
            operation(WRITE, false, &[]),
            [operation(THIS, true, &[]), set_as_uint16, END.to_vec()].concat(),
            END.to_vec(),
        ]
        .concat();
        let hiidb = short_store_hiidb(NV_BS_RT, &[numeric_a]);
        let shell = (
            VariableReach::BootServices,
            VariableInterface::VariableServices,
        );
        for (reach, interface) in [(VariableReach::Runtime, VariableInterface::Efivarfs), shell] {
            let variables = Rc::new(MemoryVariables::new(reach, interface));

            assert_eq!(
                set_of(&hiidb, "A", "9", &variables),
                Err(
                    "EFI variable ShortVarA-8c78a505-baa0-4c4a-869f-000000000b01 holds the value \
                     of one question, which set would write as 2 bytes and as 1"
                        .to_string()
                ),
                "{interface:?}: set A without ShortVarA"
            );
            assert_eq!(
                variables.bytes(&short_key("ShortVarA")),
                None,
                "{interface:?}: ShortVarA"
            );

            variables.insert(short_key("ShortVarA"), NV_BS_RT, &[5]);
            assert_eq!(
                set_of(&hiidb, "A", "9", &variables),
                Ok(()),
                "{interface:?}: set A"
            );
            assert_eq!(
                variables.writes_to(&short_key("ShortVarA")),
                [(0, vec![9])],
                "{interface:?}: writes of ShortVarA"
            );
        }
    }

    /// set of a question whose VARSTORE_EFI before UEFI 2.3.1 lacks EFI_VARIABLE_NON_VOLATILE
    /// creates its volatile variable through Variable Services only with VolatileWrites::Allow,
    /// and its answer says that the value is volatile.
    #[test]
    fn set_creates_a_volatile_per_question_variable_if_allowed() {
        // EFI_VARIABLE_BOOTSERVICE_ACCESS alone
        const BS: u32 = 0x02;
        let hiidb = short_store_hiidb(BS, &[short_numeric_a()]);
        let cases = [
            (
                VolatileWrites::Allow,
                Ok(vec![format!("9{VOLATILE_ANNOTATION}")]),
                Some([&BS.to_ne_bytes()[..], &[9]].concat()),
            ),
            (
                VolatileWrites::Refuse,
                Err(
                    "EFI variable ShortVarA-8c78a505-baa0-4c4a-869f-000000000b01 is volatile (no \
                     EFI_VARIABLE_NON_VOLATILE), so a write would not outlast a power cycle; pass \
                     --allow-volatile to write it anyway"
                        .to_string(),
                ),
                None,
            ),
        ];
        for (volatile, want, bytes) in cases {
            let variables = Rc::new(MemoryVariables::new(
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            ));
            let options = SetOptions {
                volatile,
                ..SetOptions::default()
            };

            let got = set_responses(
                &hiidb,
                "A",
                &SetValue::Text("9".to_owned()),
                None,
                &options,
                SetAccess {
                    reads: shared(&variables),
                    writes: &*variables,
                    held: None,
                },
                None,
            );

            let answers = got.map(|list| {
                list.responses
                    .into_iter()
                    .map(|response| response.question.answer)
                    .collect::<Vec<_>>()
            });
            assert_eq!(
                answers.map_err(|error| format!("{error:#}")),
                want,
                "{volatile:?}: answers"
            );
            assert_eq!(
                variables.bytes(&short_key("ShortVarA")),
                bytes,
                "{volatile:?}: ShortVarA"
            );
        }
    }

    /// get and set refuse a per-question variable whose data is not exactly as wide as its
    /// question's value, naming both sizes, where edk2-stable202608 SetupBrowserDxe/Setup.c
    /// GetQuestionValue would show a value that it did not read, or a part of one, and
    /// SetQuestionValue would change the variable's size; set writes nothing.
    #[test]
    fn a_per_question_variable_of_another_size_is_refused() {
        let hiidb = short_store_hiidb(NV_BS_RT, &short_questions());
        let cases: [(&str, &[u8], usize, u8); 3] =
            [("A", &[5, 0], 2, 1), ("A", &[], 0, 1), ("D", &[0x34], 1, 2)];
        for (question, data, held, width) in cases {
            let name = format!("ShortVar{question}");
            let variables = Rc::new(MemoryVariables::default());
            variables.insert(short_key(&name), NV_BS_RT, data);
            let case = format!("{question} on {held} bytes");
            let why = format!(
                "EFI variable {name}-8c78a505-baa0-4c4a-869f-000000000b01 holds {held} bytes; the \
                 question takes {width}"
            );

            assert_eq!(
                answers_of(&hiidb, question, &variables),
                [format!("<ValueUnavailable: {why}>")],
                "{case}: get"
            );
            assert_eq!(
                set_of(&hiidb, question, "1", &variables),
                Err(why),
                "{case}: set"
            );
            assert_eq!(
                variables.writes_to(&short_key(&name)),
                vec![],
                "{case}: writes"
            );
        }
    }

    /// A question in a FormSet's own scope, outside any form, reads its value from a VARSTORE_EFI
    /// before UEFI 2.3.1 and from one of UEFI 2.3.1 alike, without a panic, and one there whose
    /// VarStore no op declares has no value.
    #[test]
    fn a_question_outside_a_form_reads_its_var_store() {
        let variables = short_efivarfs_variables();
        let long = VariableKey {
            name: "Long".to_string(),
            guid: NIL_GUID,
        };
        variables.insert(long, NV_BS_RT, &[7]);
        let on_var_store_9 = [
            question_header_with(1, 1, 9, 7, 0x00),
            vec![0x10, 0, 255, 1],
        ]
        .concat();
        let cases = [
            (
                "before UEFI 2.3.1",
                short_var_store_efi_of(1, SHORT_VAR_STORE_GUID, NV_BS_RT),
                short_numeric_a(),
                "5",
            ),
            (
                "UEFI 2.3.1",
                var_store_efi(1, "Long", NV_BS_RT, 1),
                short_numeric(1, 1, 0, 0x10, &[0, 255, 1]),
                "7",
            ),
            (
                "undeclared",
                short_var_store_efi_of(1, SHORT_VAR_STORE_GUID, NV_BS_RT),
                operation(NUMERIC, false, &on_var_store_9),
                "<ValueUnavailable: no supported varstore with matching id 0x0009 found>",
            ),
        ];
        for (case, store, question, value) in cases {
            let hiidb =
                short_store_list(&[store, question], &[en_strings_package_of(&SHORT_STRINGS)]);

            assert_eq!(answers_of(&hiidb, "A", &variables), [value], "{case}");
        }
    }

    /// A VarName whose strings differ between the strings packages of its package list names no
    /// variable, as edk2-stable202608 SetupBrowserDxe/Setup.c GetToken takes the string in the
    /// platform language, which uefisettings does not know: its question refuses, naming the
    /// VarName and the languages. One that every package holding it agrees on names its variable,
    /// also when a package, as an x-UEFI-ns one, lacks it.
    #[test]
    fn strings_packages_that_differ_on_a_var_name_refuse_its_question() {
        let mut french = SHORT_STRINGS;
        french[6] = "VarCourteA";
        let hiidb = short_store_list(
            &[
                short_var_store_efi_of(1, SHORT_VAR_STORE_GUID, NV_BS_RT),
                form(1, &short_questions()[..2]),
            ],
            &[
                strings_package_of(b"en", &SHORT_STRINGS),
                strings_package_of(b"fr", &french),
                strings_package_of(b"x-UEFI-ns", &SHORT_STRINGS[..6]),
            ],
        );
        let variables = short_efivarfs_variables();
        let why = "VarStore 0x0001 (EFI_IFR_VARSTORE_EFI before UEFI 2.3.1): the strings packages \
                   differ on its VarName 0x0007: \"ShortVarA\" in en, \"VarCourteA\" in fr";

        assert_eq!(
            answers_of(&hiidb, "A", &variables),
            [format!("<ValueUnavailable: {why}>")],
            "get A"
        );
        assert_eq!(
            set_of(&hiidb, "A", "9", &variables),
            Err(format!("cannot set question \"A\": {why}")),
            "set A"
        );
        assert_eq!(answers_of(&hiidb, "B", &variables), ["1"], "get B");
    }

    /// A question in the scope of the GUID op of an EDKII bit varstore field, on a VARSTORE_EFI
    /// before UEFI 2.3.1, is refused by name: there its VarStoreInfo is a VarName, not the bit
    /// offset that the field takes it for.
    #[test]
    fn an_edkii_bit_field_on_a_short_var_store_is_refused() {
        let uint32_range = [0, u32::MAX, 1].map(u32::to_le_bytes).concat();
        let bit_field = [
            operation(GUID, true, &BIT_VARSTORE_GUID),
            // a field of 8 bits
            short_numeric(1, 1, 7, 0x08, &uint32_range),
            END.to_vec(),
        ]
        .concat();
        let hiidb = short_store_hiidb(NV_BS_RT, &[bit_field]);
        let variables = short_efivarfs_variables();
        let why = "VarStore 0x0001 (EFI_IFR_VARSTORE_EFI before UEFI 2.3.1): the question is an \
                   EDKII bit varstore field, whose VarStoreInfo is a bit offset, not a VarName";

        assert_eq!(
            answers_of(&hiidb, "A", &variables),
            [format!("<ValueUnavailable: {why}>")],
            "get A"
        );
        assert_eq!(
            set_of(&hiidb, "A", "9", &variables),
            Err(format!("cannot set question \"A\": {why}")),
            "set A"
        );
        assert_eq!(
            variables.writes_to(&short_key("ShortVarA")),
            vec![],
            "writes of ShortVarA"
        );
    }

    /// A question that precedes the VARSTORE_EFI before UEFI 2.3.1 that it names is refused by
    /// name: it took its VarStoreInfo for a VarOffset, as its VarStoreId names a previously
    /// declared variable store (UEFI 2.11 §33.3.8.2.2 EFI_IFR_QUESTION_HEADER).
    #[test]
    fn a_question_before_its_short_var_store_is_refused() {
        let why = "VarStore 0x0001 (EFI_IFR_VARSTORE_EFI before UEFI 2.3.1): declared after the \
                   question, which took its VarStoreInfo for a VarOffset; a question names a \
                   previously declared VarStore (UEFI 2.11 §33.3.8.2.2 EFI_IFR_QUESTION_HEADER)";
        // VarStoreInfo 7 and 0, which the question takes for VarOffsets
        for var_store_info in [7, 0] {
            let hiidb = short_store_list(
                &[
                    form(
                        1,
                        &[short_numeric(1, 1, var_store_info, 0x10, &[0, 255, 1])],
                    ),
                    short_var_store_efi_of(1, SHORT_VAR_STORE_GUID, NV_BS_RT),
                ],
                &[en_strings_package_of(&SHORT_STRINGS)],
            );
            let variables = short_efivarfs_variables();

            assert_eq!(
                answers_of(&hiidb, "A", &variables),
                [format!("<ValueUnavailable: {why}>")],
                "VarStoreInfo {var_store_info}: get A"
            );
            assert_eq!(
                set_of(&hiidb, "A", "9", &variables),
                Err(format!("cannot set question \"A\": {why}")),
                "VarStoreInfo {var_store_info}: set A"
            );
        }
    }

    /// A DATE and a TIME on a VARSTORE_EFI before UEFI 2.3.1 read and set the EFI variable that
    /// their VarName names, their EFI_HII_DATE or EFI_HII_TIME from byte 0, as a NUMERIC there
    /// does; set writes no other variable. A DATE before the store took its VarStoreInfo for a
    /// VarOffset and is refused as a NUMERIC is.
    #[test]
    fn dates_and_times_of_a_short_var_store_read_and_set_the_variables_of_their_var_names() {
        // prompts "Day" and "Hour", strings 1 and 2, on the VarNames 3 and 4
        let date = operation(
            DATE,
            false,
            &[question_header_with(1, 1, 1, 3, 0x00), vec![0x00]].concat(),
        );
        let time = operation(
            TIME,
            false,
            &[question_header_with(2, 2, 1, 4, 0x00), vec![0x00]].concat(),
        );
        let strings = [en_strings_package_of(&[
            "Day",
            "Hour",
            "ShortDate",
            "ShortTime",
        ])];
        let short_store = short_var_store_efi_of(1, SHORT_VAR_STORE_GUID, NV_BS_RT);
        let hiidb = short_store_list(
            &[short_store.clone(), form(1, &[date.clone(), time])],
            &strings,
        );
        // the EFI_HII_DATE 2026-11-10 and the EFI_HII_TIME 12:34:56
        let stored = [
            ("ShortDate", vec![0xEA, 0x07, 11, 10]),
            ("ShortTime", vec![12, 34, 56]),
        ];
        let variables = || {
            let variables =
                MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);
            for (name, value) in &stored {
                variables.insert(short_key(name), NV_BS_RT, value);
            }
            Rc::new(variables)
        };
        let cases = [
            (
                "Day",
                "2026-11-10",
                "2027-01-02",
                "ShortDate",
                vec![0xEB, 0x07, 1, 2],
            ),
            ("Hour", "12:34:56", "01:02:03", "ShortTime", vec![1, 2, 3]),
        ];

        for (question, value, new_value, name, written) in cases {
            let variables = variables();

            assert_eq!(
                answers_of(&hiidb, question, &variables),
                [value],
                "get {question}"
            );
            assert_eq!(
                set_of(&hiidb, question, new_value, &variables),
                Ok(()),
                "set {question}"
            );

            for (other, _) in &stored {
                let want = match *other == name {
                    true => vec![(0, written.clone())],
                    false => vec![],
                };
                assert_eq!(
                    variables.writes_to(&short_key(other)),
                    want,
                    "set {question}: writes of {other}"
                );
            }
            assert_eq!(
                answers_of(&hiidb, question, &variables),
                [new_value],
                "get {question} after set"
            );
        }

        let declared_after = short_store_list(&[form(1, &[date]), short_store], &strings);
        let why = "VarStore 0x0001 (EFI_IFR_VARSTORE_EFI before UEFI 2.3.1): declared after the \
                   question, which took its VarStoreInfo for a VarOffset; a question names a \
                   previously declared VarStore (UEFI 2.11 §33.3.8.2.2 EFI_IFR_QUESTION_HEADER)";
        let variables = variables();
        assert_eq!(
            answers_of(&declared_after, "Day", &variables),
            [format!("<ValueUnavailable: {why}>")],
            "get of the DATE before its store"
        );
        assert_eq!(
            set_of(&declared_after, "Day", "2027-01-02", &variables),
            Err(format!("cannot set question \"Day\": {why}")),
            "set of the DATE before its store"
        );
    }

    /// A DATE and a TIME over the bytes of a PASSWORD outside any FormSet of their VarStoreId keep
    /// them withheld, as a NUMERIC does: get answers that their bytes hold a password, and set
    /// refuses them and writes nothing.
    #[test]
    fn dates_and_times_keep_an_outside_password_withheld() {
        let date = [question_header_with(4, 4, 2, 0, 0x00), vec![0x00]].concat();
        let time = [question_header_with(5, 5, 2, 4, 0x00), vec![0x00]].concat();
        let packages = [
            form_package_of(
                &[
                    password_on(3, 3, 2, 0),
                    form_set(&[
                        var_store(2, [0x44; 16], "AMITSESetup", 81),
                        form(
                            1,
                            &[operation(DATE, false, &date), operation(TIME, false, &time)],
                        ),
                    ]),
                ]
                .concat(),
            ),
            en_strings_package_of(&["Q", "P", "Password", "D", "T"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x55; 16], &packages.concat());
        let stored = [plaintext_password().as_slice(), &[0xAA; 40], &[1]].concat();

        for (question, value) in [("D", "2027-01-02"), ("T", "01:02:03")] {
            let variables =
                MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);
            variables.insert(amitse_setup(), NV_BS_RT, &stored);
            let variables = Rc::new(variables);

            assert_eq!(
                answers_of(&hiidb, question, &variables),
                [PASSWORD_BYTES],
                "get {question}"
            );
            let set = set_bypassing(&hiidb, question, value, &variables);
            assert!(
                set.as_ref().is_err_and(|error| error
                    .contains("holds a password at bytes 0..40, which set never writes")),
                "set {question}: {set:?}"
            );
            assert_eq!(
                variables.writes_to(&amitse_setup()),
                [],
                "set {question}: writes to AMITSESetup"
            );
        }
    }

    /// An ORDERED_LIST on a VARSTORE_EFI before UEFI 2.3.1 reads and sets its MaxContainers
    /// containers, of UINT8 or UINT16 options, as the whole EFI variable that its VarName names,
    /// as edk2-stable202608 SetupBrowserDxe/Setup.c GetQuestionValue and SetQuestionValue do
    /// through its BufferValue; a variable of another size is refused and not written. One before
    /// the store took its VarStoreInfo for a VarOffset and is refused as a NUMERIC is.
    #[test]
    fn ordered_lists_of_a_short_var_store_read_and_set_the_variables_of_their_var_names() {
        // prompt "L", string 1, on the VarName 4
        let list = [
            operation(
                ORDERED_LIST,
                true,
                &[question_header_with(1, 1, 1, 4, 0x00), vec![2, 0x00]].concat(),
            ),
            flagged_option(2, 0x00, 1),
            flagged_option(3, 0x00, 2),
            END.to_vec(),
        ]
        .concat();
        let strings = [en_strings_package_of(&["L", "A", "B", "ShortList"])];
        let short_store = short_var_store_efi_of(1, SHORT_VAR_STORE_GUID, NV_BS_RT);
        let hiidb = short_store_list(
            &[short_store.clone(), form(1, std::slice::from_ref(&list))],
            &strings,
        );
        let variables = |value: &[u8]| {
            let variables =
                MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);
            variables.insert(short_key("ShortList"), NV_BS_RT, value);
            Rc::new(variables)
        };
        let set_items = |hiidb: &[u8], variables: &Rc<MemoryVariables>| {
            HiiBackend::set_in(
                hiidb,
                "L",
                &SetValue::Items(vec!["B".to_owned(), "A".to_owned()]),
                None,
                &SetOptions::default(),
                SetAccess {
                    reads: shared(variables),
                    writes: &**variables,
                    held: None,
                },
                None,
            )
            .map(drop)
            .map_err(|error| format!("{error:#}"))
        };

        let stored = variables(&[1, 2]);
        assert_eq!(answers_of(&hiidb, "L", &stored), ["A, B"], "get");
        assert_eq!(set_items(&hiidb, &stored), Ok(()), "set");
        assert_eq!(
            stored.writes_to(&short_key("ShortList")),
            [(0, vec![2, 1])],
            "writes of ShortList"
        );
        assert_eq!(answers_of(&hiidb, "L", &stored), ["B, A"], "get after set");

        let wider = variables(&[1, 2, 0]);
        let why = "EFI variable ShortList-8c78a505-baa0-4c4a-869f-000000000b01 holds 3 bytes; \
                   the question takes 2";
        assert_eq!(
            answers_of(&hiidb, "L", &wider),
            [format!("<ValueUnavailable: {why}>")],
            "get of 3 bytes"
        );
        let set = set_items(&hiidb, &wider);
        assert!(
            set.as_ref().is_err_and(|error| error.ends_with(why)),
            "set of 3 bytes: {set:?}"
        );
        assert_eq!(
            wider.writes_to(&short_key("ShortList")),
            [],
            "writes of 3 bytes"
        );

        // 2 containers of EFI_IFR_TYPE_NUM_SIZE_16 options, 4 bytes
        let wide_list = [
            operation(
                ORDERED_LIST,
                true,
                &[question_header_with(1, 1, 1, 4, 0x00), vec![2, 0x00]].concat(),
            ),
            uint16_option(2, 1),
            uint16_option(3, 2),
            END.to_vec(),
        ]
        .concat();
        let wide = short_store_list(&[short_store.clone(), form(1, &[wide_list])], &strings);
        let stored = variables(&[1, 0, 2, 0]);
        assert_eq!(
            answers_of(&wide, "L", &stored),
            ["A, B"],
            "get of UINT16 items"
        );
        assert_eq!(set_items(&wide, &stored), Ok(()), "set of UINT16 items");
        assert_eq!(
            stored.writes_to(&short_key("ShortList")),
            [(0, vec![2, 0, 1, 0])],
            "writes of UINT16 items"
        );

        let declared_after = short_store_list(&[form(1, &[list]), short_store], &strings);
        let why = "VarStore 0x0001 (EFI_IFR_VARSTORE_EFI before UEFI 2.3.1): declared after the \
                   question, which took its VarStoreInfo for a VarOffset; a question names a \
                   previously declared VarStore (UEFI 2.11 §33.3.8.2.2 EFI_IFR_QUESTION_HEADER)";
        let stored = variables(&[1, 2]);
        assert_eq!(
            answers_of(&declared_after, "L", &stored),
            [format!("<ValueUnavailable: {why}>")],
            "get of the ORDERED_LIST before its store"
        );
        assert_eq!(
            set_items(&declared_after, &stored),
            Err(format!("cannot set question \"L\": {why}")),
            "set of the ORDERED_LIST before its store"
        );
    }

    /// A STRING on a VARSTORE_EFI before UEFI 2.3.1 reads and sets its MaxSize CHAR16s as the
    /// whole EFI variable that its VarName names, as an ORDERED_LIST does; a variable of another
    /// size is refused, and one before the store took its VarStoreInfo for a VarOffset and is
    /// refused as declared after it.
    #[test]
    fn strings_of_a_short_var_store_read_and_set_the_variables_of_their_var_names() {
        // prompt "S", string 1, on the VarName 2; MinSize 0, MaxSize 4
        let string = flagged_string_on(1, 1, (1, 2), (0, 4), (0x00, 0x00), &[]);
        let strings = [en_strings_package_of(&["S", "ShortStr"])];
        let short_store = short_var_store_efi_of(1, SHORT_VAR_STORE_GUID, NV_BS_RT);
        let hiidb = short_store_list(
            &[short_store.clone(), form(1, std::slice::from_ref(&string))],
            &strings,
        );
        let variables = |value: &[u8]| {
            let variables =
                MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);
            variables.insert(short_key("ShortStr"), NV_BS_RT, value);
            Rc::new(variables)
        };

        let stored = variables(&[0x41, 0, 0x42, 0, 0, 0, 0, 0]);
        assert_eq!(answers_of(&hiidb, "S", &stored), ["AB"], "get");
        assert_eq!(set_of(&hiidb, "S", "XYZ", &stored), Ok(()), "set");
        assert_eq!(
            stored.writes_to(&short_key("ShortStr")),
            [(0, vec![0x58, 0, 0x59, 0, 0x5A, 0, 0, 0])],
            "writes of ShortStr"
        );

        let wider = variables(&[0x41, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        let why = "EFI variable ShortStr-8c78a505-baa0-4c4a-869f-000000000b01 holds 10 bytes; \
                   the question takes 8";
        assert_eq!(
            answers_of(&hiidb, "S", &wider),
            [format!("<ValueUnavailable: {why}>")],
            "get of 10 bytes"
        );
        assert_eq!(
            set_of(&hiidb, "S", "XYZ", &wider),
            Err(why.to_owned()),
            "set of 10 bytes"
        );
        assert_eq!(
            wider.writes_to(&short_key("ShortStr")),
            Vec::<(u16, Vec<u8>)>::new(),
            "writes of 10 bytes"
        );

        let declared_after = short_store_list(&[form(1, &[string]), short_store], &strings);
        let why = "VarStore 0x0001 (EFI_IFR_VARSTORE_EFI before UEFI 2.3.1): declared after the \
                   question, which took its VarStoreInfo for a VarOffset; a question names a \
                   previously declared VarStore (UEFI 2.11 §33.3.8.2.2 EFI_IFR_QUESTION_HEADER)";
        let stored = variables(&[0x41, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            answers_of(&declared_after, "S", &stored),
            [format!("<ValueUnavailable: {why}>")],
            "get of the STRING before its store"
        );
        assert_eq!(
            set_of(&declared_after, "S", "XYZ", &stored),
            Err(format!("cannot set question \"S\": {why}")),
            "set of the STRING before its store"
        );
        assert_eq!(
            stored.writes_to(&short_key("ShortStr")),
            Vec::<(u16, Vec<u8>)>::new(),
            "writes of the STRING before its store"
        );
    }

    /// set of an ORDERED_LIST on a VARSTORE_EFI before UEFI 2.3.1 whose variable is missing
    /// creates it with the store's Attributes, holding the new items and empty containers after
    /// them, as edk2-stable202608 SetupBrowserDxe writes the zeroed BufferValue that it keeps
    /// (IfrParse.c:2493; Setup.c:1779-1782, :5725-5727, :2069-2075), while get answers the
    /// variable missing and lists no items. It creates none at OS runtime without
    /// EFI_VARIABLE_RUNTIME_ACCESS, nor through Windows, and writes nothing then. A variable of
    /// another size, and the missing variable of a VARSTORE_EFI of Name and Size, still refuse
    /// set before any write.
    #[test]
    fn set_of_an_ordered_list_creates_its_missing_short_var_store_variable() {
        // prompt "L", string 1, on the VarName 4: 3 containers of UINT8 options
        let list = [
            operation(
                ORDERED_LIST,
                true,
                &[question_header_with(1, 1, 1, 4, 0x00), vec![3, 0x00]].concat(),
            ),
            flagged_option(2, 0x00, 1),
            flagged_option(3, 0x00, 2),
            END.to_vec(),
        ]
        .concat();
        let strings = [en_strings_package_of(&["L", "A", "B", "ShortList"])];
        let short_store_hiidb = |attributes: u32| {
            short_store_list(
                &[
                    short_var_store_efi_of(1, SHORT_VAR_STORE_GUID, attributes),
                    form(1, std::slice::from_ref(&list)),
                ],
                &strings,
            )
        };
        let get = |hiidb: &[u8], variables: &Rc<MemoryVariables>| {
            HiiBackend::get_in(
                hiidb,
                "L",
                None,
                &GetOptions::default(),
                shared(variables),
                None,
                None,
                None,
            )
            .expect("get L")
            .responses
            .into_iter()
            .map(|response| (response.question.answer, response.question.items))
            .collect::<Vec<_>>()
        };
        let set_items = |hiidb: &[u8], variables: &Rc<MemoryVariables>| {
            HiiBackend::set_in(
                hiidb,
                "L",
                &SetValue::Items(vec!["B".to_owned(), "A".to_owned()]),
                None,
                &SetOptions::default(),
                SetAccess {
                    reads: shared(variables),
                    writes: &**variables,
                    held: None,
                },
                None,
            )
            .map(drop)
            .map_err(|error| format!("{error:#}"))
        };
        let linux = (VariableReach::Runtime, VariableInterface::Efivarfs);
        let shell = (
            VariableReach::BootServices,
            VariableInterface::VariableServices,
        );
        let windows = (
            VariableReach::Runtime,
            VariableInterface::FirmwareEnvironment,
        );
        let key = "ShortList-8c78a505-baa0-4c4a-869f-000000000b01";
        let missing = format!("<ValueUnavailable: no EFI variable {key}>");
        let created = |attributes: u32| Ok([&attributes.to_ne_bytes()[..], &[2, 1, 0]].concat());
        let cases = [
            (linux, NV_BS_RT, missing.clone(), created(NV_BS_RT)),
            (shell, NV_BS, missing.clone(), created(NV_BS)),
            (
                linux,
                NV_BS,
                format!(
                    "<ValueUnavailable: EFI variable {key} is not present at OS runtime: \
                     efivarfs does not list it, and its form declares it boot-service-only (no \
                     EFI_VARIABLE_RUNTIME_ACCESS)>"
                ),
                Err(format!(
                    "EFI variable {key} is not present at OS runtime: efivarfs does not list it, \
                     and its form declares it boot-service-only (no EFI_VARIABLE_RUNTIME_ACCESS)"
                )),
            ),
            (
                windows,
                NV_BS_RT,
                missing,
                Err(format!(
                    "no EFI variable {key}: the firmware has not created it or does not expose it \
                     to the OS, so its questions cannot be set from Windows; change them in the \
                     firmware setup, or ask the board vendor for firmware that exposes it; see \
                     https://github.com/linuxboot/uefisettings/issues/2"
                )),
            ),
        ];
        for ((reach, interface), attributes, answer, want) in cases {
            let hiidb = short_store_hiidb(attributes);
            let variables = Rc::new(MemoryVariables::new(reach, interface));
            let case = format!("{interface:?}, attributes {attributes:#x}");

            assert_eq!(get(&hiidb, &variables), [(answer, None)], "{case}: get");
            let set = set_items(&hiidb, &variables);

            assert_eq!(
                set.map(|()| variables.bytes(&short_key("ShortList"))),
                want.clone().map(Some),
                "{case}: set"
            );
            if want.is_ok() {
                let items = Some(vec!["B".to_owned(), "A".to_owned()]);
                assert_eq!(
                    get(&hiidb, &variables),
                    [("B, A".to_owned(), items)],
                    "{case}: get after set"
                );
            }
        }

        let wider = Rc::new(MemoryVariables::new(linux.0, linux.1));
        wider.insert(short_key("ShortList"), NV_BS_RT, &[1, 2, 0, 0]);
        assert_eq!(
            set_items(&short_store_hiidb(NV_BS_RT), &wider),
            Err(format!(
                "EFI variable {key} holds 4 bytes; the question takes 3"
            )),
            "set of 4 bytes"
        );
        assert_eq!(
            wider.writes_to(&short_key("ShortList")),
            [],
            "writes of 4 bytes"
        );

        // the VARSTORE_EFI ShortList of Size 3, whose variable holds the containers at VarOffset 0
        let named = short_store_list(
            &[
                var_store_efi_of(1, SHORT_VAR_STORE_GUID, "ShortList", NV_BS_RT, 3),
                form(1, &[list]),
            ],
            &strings,
        );
        let variables = Rc::new(MemoryVariables::new(linux.0, linux.1));
        assert_eq!(
            set_items(&named, &variables),
            Err(format!(
                "no EFI variable {key}: the firmware has not created it or does not expose it to \
                 the OS, so its questions cannot be set from Linux; change them in the firmware \
                 setup, or ask the board vendor for firmware that exposes it; see \
                 https://github.com/linuxboot/uefisettings/issues/2"
            )),
            "set of a missing variable of a VARSTORE_EFI of Name and Size"
        );
        assert_eq!(
            variables.bytes(&short_key("ShortList")),
            None,
            "the variable of a VARSTORE_EFI of Name and Size"
        );
    }

    /// An ORDERED_LIST without options on a VARSTORE_EFI before UEFI 2.3.1, to which
    /// edk2-stable202608 SetupBrowserDxe/IfrParse.c gives no StorageWidth, is refused for that
    /// cause by get and set, whether the variable of its VarName exists or not, and set writes
    /// nothing.
    #[test]
    fn ordered_lists_without_options_of_a_short_var_store_are_refused() {
        // prompt "L", string 1, on the VarName 2: 2 containers, no option
        let list = [
            operation(
                ORDERED_LIST,
                true,
                &[question_header_with(1, 1, 1, 2, 0x00), vec![2, 0x00]].concat(),
            ),
            END.to_vec(),
        ]
        .concat();
        let hiidb = short_store_list(
            &[
                short_var_store_efi_of(1, SHORT_VAR_STORE_GUID, NV_BS_RT),
                form(1, &[list]),
            ],
            &[en_strings_package_of(&["L", "ShortList"])],
        );
        let why = "VarStore 0x0001 (EFI_IFR_VARSTORE_EFI before UEFI 2.3.1): the ORDERED_LIST has \
                   no option, so its containers have no width";
        for stored in [Some(&[1, 2][..]), None] {
            let variables =
                MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);
            if let Some(value) = stored {
                variables.insert(short_key("ShortList"), NV_BS_RT, value);
            }
            let variables = Rc::new(variables);

            assert_eq!(
                answers_of(&hiidb, "L", &variables),
                [format!("<ValueUnavailable: {why}>")],
                "get, variable {stored:?}"
            );
            let set = HiiBackend::set_in(
                &hiidb,
                "L",
                &SetValue::Items(vec![]),
                None,
                &SetOptions::default(),
                SetAccess {
                    reads: shared(&variables),
                    writes: &*variables,
                    held: None,
                },
                None,
            )
            .map(drop)
            .map_err(|error| format!("{error:#}"));
            assert_eq!(
                set,
                Err(format!("cannot set question \"L\": {why}")),
                "set, variable {stored:?}"
            );
            assert_eq!(
                variables.writes_to(&short_key("ShortList")),
                [],
                "writes, variable {stored:?}"
            );
        }
    }

    /// set of an ORDERED_LIST of MaxContainers 0 on a VARSTORE_EFI before UEFI 2.3.1, whose
    /// StorageWidth is 0, to no items refuses to create its missing variable of no bytes, as a
    /// SetVariable() of DataSize 0 deletes a variable (UEFI 2.11 §8.2.3), and writes nothing,
    /// through efivarfs and through GetVariable() and SetVariable().
    #[test]
    fn set_creates_no_short_var_store_variable_of_no_bytes() {
        // prompt "L", string 1, on the VarName 3: no container, one UINT8 option
        let list = [
            operation(
                ORDERED_LIST,
                true,
                &[question_header_with(1, 1, 1, 3, 0x00), vec![0, 0x00]].concat(),
            ),
            flagged_option(2, 0x00, 1),
            END.to_vec(),
        ]
        .concat();
        let hiidb = short_store_list(
            &[
                short_var_store_efi_of(1, SHORT_VAR_STORE_GUID, NV_BS_RT),
                form(1, &[list]),
            ],
            &[en_strings_package_of(&["L", "A", "ShortList"])],
        );
        for (reach, interface) in [
            (VariableReach::Runtime, VariableInterface::Efivarfs),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            ),
        ] {
            let variables = Rc::new(MemoryVariables::new(reach, interface));

            let set = HiiBackend::set_in(
                &hiidb,
                "L",
                &SetValue::Items(vec![]),
                None,
                &SetOptions::default(),
                SetAccess {
                    reads: shared(&variables),
                    writes: &*variables,
                    held: None,
                },
                None,
            )
            .map(drop)
            .map_err(|error| format!("{error:#}"));

            assert_eq!(
                set,
                Err("a variable write without bytes".to_owned()),
                "{interface:?}: set"
            );
            assert_eq!(
                variables.bytes(&short_key("ShortList")),
                None,
                "{interface:?}: ShortList"
            );
        }
    }

    /// An ORDERED_LIST on the VarName of a PASSWORD on a VARSTORE_EFI before UEFI 2.3.1 reads
    /// none of the password's variable, which get and set withhold whole: get answers that its
    /// bytes hold a password, and set refuses new items and writes nothing. The list is as wide
    /// as the variable, and its VarName, read as a VarOffset, as large, so that only the
    /// withholding of bytes 0..40 refuses it.
    #[test]
    fn an_ordered_list_on_the_var_name_of_a_short_var_store_password_keeps_it_withheld() {
        // prompt "L", string 1, on the VarName 40 of the PASSWORD's prompt 4: 40 containers
        let list = [
            operation(
                ORDERED_LIST,
                true,
                &[question_header_with(1, 1, 1, 40, 0x00), vec![40, 0x00]].concat(),
            ),
            flagged_option(2, 0x00, 1),
            flagged_option(3, 0x00, 2),
            END.to_vec(),
        ]
        .concat();
        let mut strings = vec!["L", "A", "B", "Password"];
        strings.resize(39, "Unused");
        strings.push("ShortVarPw");
        let hiidb = short_store_list(
            &[
                short_var_store_efi_of(1, SHORT_VAR_STORE_GUID, NV_BS_RT),
                form(1, &[password_on(6, 4, 1, 40), list]),
            ],
            &[en_strings_package_of(&strings)],
        );
        let password = short_key("ShortVarPw");
        let variables = MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);
        variables.insert(password.clone(), NV_BS_RT, &plaintext_password());
        let variables = Rc::new(variables);

        assert_eq!(answers_of(&hiidb, "L", &variables), [PASSWORD_BYTES], "get");
        let set = HiiBackend::set_in(
            &hiidb,
            "L",
            &SetValue::Items(vec!["B".to_owned(), "A".to_owned()]),
            None,
            &SetOptions {
                unsafe_operations: UnsafeOperations::Allow,
                ..SetOptions::default()
            },
            SetAccess {
                reads: shared(&variables),
                writes: &*variables,
                held: None,
            },
            None,
        )
        .map(drop)
        .map_err(|error| format!("{error:#}"));
        assert_eq!(
            set,
            Err(
                "cannot set question \"L\": its items cannot be read, so set cannot keep those of \
                 hidden options: its bytes hold a password"
                    .to_owned()
            ),
            "set"
        );
        assert_eq!(variables.writes_to(&password), [], "writes of ShortVarPw");
    }

    /// An ORDERED_LIST over the bytes of a PASSWORD outside any FormSet of its VarStoreId keeps
    /// them withheld, as a NUMERIC does: get answers that its bytes hold a password, and set
    /// refuses new items, whose hidden ones it cannot keep unread, and writes nothing.
    #[test]
    fn ordered_lists_keep_an_outside_password_withheld() {
        let list = [
            operation(
                ORDERED_LIST,
                true,
                &[question_header_with(4, 4, 2, 0, 0x00), vec![2, 0x00]].concat(),
            ),
            flagged_option(5, 0x00, 1),
            flagged_option(6, 0x00, 2),
            END.to_vec(),
        ]
        .concat();
        let packages = [
            form_package_of(
                &[
                    password_on(3, 3, 2, 0),
                    form_set(&[
                        var_store(2, [0x44; 16], "AMITSESetup", 81),
                        form(1, &[list]),
                    ]),
                ]
                .concat(),
            ),
            en_strings_package_of(&["Q", "P", "Password", "L", "A", "B"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x55; 16], &packages.concat());
        let stored = [plaintext_password().as_slice(), &[0xAA; 40], &[1]].concat();
        let variables = MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);
        variables.insert(amitse_setup(), NV_BS_RT, &stored);
        let variables = Rc::new(variables);
        let options = SetOptions {
            unsafe_operations: UnsafeOperations::Allow,
            ..SetOptions::default()
        };

        assert_eq!(answers_of(&hiidb, "L", &variables), [PASSWORD_BYTES], "get");
        let set = HiiBackend::set_in(
            &hiidb,
            "L",
            &SetValue::Items(vec!["B".to_owned(), "A".to_owned()]),
            None,
            &options,
            SetAccess {
                reads: shared(&variables),
                writes: &*variables,
                held: None,
            },
            None,
        )
        .map(drop)
        .map_err(|error| format!("{error:#}"));
        assert_eq!(
            set,
            Err(
                "cannot set question \"L\": its items cannot be read, so set cannot keep those of \
                 hidden options: its bytes hold a password"
                    .to_owned()
            ),
            "set"
        );
        assert_eq!(
            variables.writes_to(&amitse_setup()),
            [],
            "writes to AMITSESetup"
        );
    }

    /// A REF on a VARSTORE_EFI before UEFI 2.3.1 shows the EFI_HII_REF that the whole EFI
    /// variable of its VarName holds, its StorageWidth in edk2-stable202608
    /// SetupBrowserDxe/IfrParse.c, as Setup.c GetQuestionValue reads it there; a variable of
    /// another size is refused, and set refuses the REF as on any VarStore, writing nothing. One
    /// before the store took its VarStoreInfo for a VarOffset and is refused as a NUMERIC is.
    #[test]
    fn cross_references_of_a_short_var_store_show_the_hii_refs_of_their_var_names() {
        // an EFI_IFR_REF5 of prompt "R", string 1, on the VarName 2
        let reference = operation(REF, false, &question_header_with(1, 1, 1, 2, 0x00));
        let strings = [en_strings_package_of(&["R", "ShortRef"])];
        let short_store = short_var_store_efi_of(1, SHORT_VAR_STORE_GUID, NV_BS_RT);
        let hiidb = short_store_list(
            &[
                short_store.clone(),
                form(1, std::slice::from_ref(&reference)),
            ],
            &strings,
        );
        let variables = |value: &[u8]| {
            let variables =
                MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);
            variables.insert(short_key("ShortRef"), NV_BS_RT, value);
            Rc::new(variables)
        };
        // QuestionId 5, FormId 1, FormSetGuid 0x11 × 16, DevicePath string 0
        let stored = [&[5, 0, 1, 0][..], &[0x11; 16], &[0, 0]].concat();

        let short = variables(&stored);
        assert_eq!(
            answers_of(&hiidb, "R", &short),
            ["QuestionId 0x0005, FormId 0x0001, FormSetGuid \
                 11111111-1111-1111-1111-111111111111, DevicePath none"],
            "get"
        );
        let set = set_of(&hiidb, "R", "0", &short);
        assert!(
            set.as_ref()
                .is_err_and(|error| error.contains("set does not write the EFI_HII_REF")),
            "set: {set:?}"
        );
        assert_eq!(short.writes_to(&short_key("ShortRef")), [], "writes");

        let longer = variables(&[stored.as_slice(), &[0]].concat());
        assert_eq!(
            answers_of(&hiidb, "R", &longer),
            [
                "<ValueUnavailable: EFI variable ShortRef-8c78a505-baa0-4c4a-869f-000000000b01 \
                 holds 23 bytes; the question takes 22>"
            ],
            "get of 23 bytes"
        );

        let declared_after = short_store_list(&[form(1, &[reference]), short_store], &strings);
        assert_eq!(
            answers_of(&declared_after, "R", &short),
            [
                "<ValueUnavailable: VarStore 0x0001 (EFI_IFR_VARSTORE_EFI before UEFI 2.3.1): \
                 declared after the question, which took its VarStoreInfo for a VarOffset; a \
                 question names a previously declared VarStore (UEFI 2.11 §33.3.8.2.2 \
                 EFI_IFR_QUESTION_HEADER)>"
            ],
            "get of the REF before its store"
        );
    }

    /// A REF over the bytes of a PASSWORD outside any FormSet of its VarStoreId keeps them
    /// withheld, as a NUMERIC does: get answers that its bytes hold a password.
    #[test]
    fn cross_references_keep_an_outside_password_withheld() {
        // an EFI_IFR_REF5 at byte 0 of AMITSESetup
        let reference = operation(REF, false, &question_header_with(4, 4, 2, 0, 0x00));
        let packages = [
            form_package_of(
                &[
                    password_on(3, 3, 2, 0),
                    form_set(&[
                        var_store(2, [0x44; 16], "AMITSESetup", 81),
                        form(1, &[reference]),
                    ]),
                ]
                .concat(),
            ),
            en_strings_package_of(&["Q", "P", "Password", "R"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x55; 16], &packages.concat());
        let stored = [plaintext_password().as_slice(), &[0xAA; 40], &[1]].concat();
        let variables = MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);
        variables.insert(amitse_setup(), NV_BS_RT, &stored);
        let variables = Rc::new(variables);

        assert_eq!(answers_of(&hiidb, "R", &variables), [PASSWORD_BYTES], "get");
    }

    /// A package list with GUID `guid` whose form holds the STRING "S", string 1, of MinSize and
    /// MaxSize `sizes` and the Flags `flags`, holding `children`, at byte 0 of the EFI variable
    /// Setup of `var_size` bytes, with the texts `strings`.
    fn string_list_of(
        guid: [u8; 16],
        (sizes, flags): ((u8, u8), u8),
        children: &[Vec<u8>],
        var_size: u16,
        strings: &[&str],
    ) -> Vec<u8> {
        let string = flagged_string_on(1, 1, (1, 0), sizes, (0x00, flags), children);
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, var_size),
                form(1, &[string]),
            ]),
            en_strings_package_of(strings),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid(guid, &packages.concat())
    }

    /// string_list_of without Flags, its Setup of MaxSize CHAR16s, string 2 "Hello".
    fn string_list(guid: [u8; 16], sizes: (u8, u8), children: &[Vec<u8>]) -> Vec<u8> {
        let var_size = u16::from(sizes.1) * 2;
        string_list_of(guid, (sizes, 0x00), children, var_size, &["S", "Hello"])
    }

    /// The variables of a HiiDB that reach Runtime through efivarfs, Setup holding `stored`.
    fn setup_holding(stored: &[u8]) -> Rc<MemoryVariables> {
        let variables = MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);
        variables.insert(setup(), NV_BS_RT, stored);
        Rc::new(variables)
    }

    /// The answer of a STRING without its variable Setup.
    const MISSING_SETUP: &str =
        "<ValueUnavailable: no EFI variable Setup-00000000-0000-0000-0000-000000000000>";

    /// get, list-questions and show-ifr show a STRING on a VarStore as the UCS-2 characters of its
    /// MaxSize CHAR16s up to the first NULL, all of them without one, as edk2-stable202608
    /// SetupBrowserDxe/IfrParse.c:2229 keeps one more CHAR16, zero, after them; a UTF-16
    /// surrogate, which UCS-2 has no character for (UEFI 2.11 §33.2.6.2.2), gives no value.
    #[test]
    fn strings_show_their_characters_up_to_the_first_null() {
        let hiidb = string_list([0x71; 16], (0, 4), &[]);
        let surrogate = "<ValueUnavailable: its character 1 is CHAR16 0xd83d, a UTF-16 surrogate, \
                         which UCS-2 has no character for (UEFI 2.11 §33.2.6.2.2)>";
        let cases: [(&str, [u8; 8], &str); 6] = [
            ("null-terminated", [0x41, 0, 0x42, 0, 0, 0, 0, 0], "AB"),
            ("no null", [0x41, 0, 0x42, 0, 0x43, 0, 0x44, 0], "ABCD"),
            ("empty", [0; 8], ""),
            ("after the null", [0x41, 0, 0, 0, 0x43, 0, 0x44, 0], "A"),
            ("beyond ASCII", [0xE9, 0, 0xAC, 0x20, 0, 0, 0, 0], "é€"),
            (
                "surrogate",
                [0x41, 0, 0x3D, 0xD8, 0x00, 0xDE, 0, 0],
                surrogate,
            ),
        ];
        for (case, stored, answer) in cases {
            let (listed, shown) = listed_and_shown(&hiidb, &stored, None);
            let listed: Vec<(&str, &str)> = listed
                .iter()
                .map(|question| (&*question.name, &*question.answer))
                .collect();

            assert_eq!(
                answers_of(&hiidb, "S", &setup_holding(&stored)),
                [answer],
                "{case}: get"
            );
            assert_eq!(listed, [("S", answer)], "{case}: list-questions");
            assert!(
                shown.contains(&format!("-Answer: {answer}\n")),
                "{case}: show-ifr: {shown}"
            );
        }
    }

    /// A STRING of MaxSize 4 reads its 8 bytes alone of a variable of 12 whose characters go on
    /// past them without a NULL.
    #[test]
    fn strings_read_no_character_past_their_max_size() {
        let hiidb = string_list_of([0x77; 16], ((0, 4), 0x00), &[], 12, &["S", "Hello"]);
        let stored = [0x41, 0, 0x42, 0, 0x43, 0, 0x44, 0, 0x45, 0, 0x46, 0];
        let (listed, shown) = listed_and_shown(&hiidb, &stored, None);
        let listed: Vec<(&str, &str)> = listed
            .iter()
            .map(|question| (&*question.name, &*question.answer))
            .collect();

        assert_eq!(
            answers_of(&hiidb, "S", &setup_holding(&stored)),
            ["ABCD"],
            "get"
        );
        assert_eq!(listed, [("S", "ABCD")], "list-questions");
        assert!(shown.contains("-Answer: ABCD\n"), "show-ifr: {shown}");
    }

    /// A STRING without a value shows its default of Type STRING, the text of that string, cut to
    /// MaxSize characters, as edk2-stable202608 SetupBrowserDxe/Setup.c:4507-4511
    /// GetQuestionDefault copies at most StorageWidth bytes of it; a string that the package list
    /// lacks, or one with a character beyond UCS-2 (UEFI 2.11 §33.2.6.2.2), gives no default.
    #[test]
    fn strings_without_a_variable_show_their_string_default() {
        let unknown_text = "unknown (EFI_IFR_TYPE_STRING default: string 0x0002 holds \
                            '\u{1F600}' (U+1F600), which UCS-2 has no character for (UEFI 2.11 \
                            §33.2.6.2.2))";
        let cases = [
            ("MaxSize 8", 8, 2, ["S", "Hello"], "Hello"),
            ("MaxSize 4", 4, 2, ["S", "Hello"], "Hell"),
            ("MaxSize 5", 5, 2, ["S", "Hello"], "Hello"),
            (
                "missing string",
                8,
                9,
                ["S", "Hello"],
                "unknown (EFI_IFR_TYPE_STRING default: string 0x0009 not found)",
            ),
            ("beyond UCS-2", 8, 2, ["S", "A\u{1F600}"], unknown_text),
        ];
        for (case, max_size, string_id, strings, default) in cases {
            let hiidb = string_list_of(
                [0x72; 16],
                ((0, max_size), 0x00),
                &[string_default(0, string_id)],
                u16::from(max_size) * 2,
                &strings,
            );
            let variables =
                MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);

            assert_eq!(
                answers_of(&hiidb, "S", &Rc::new(variables)),
                [format!("{MISSING_SETUP} <IFR default: {default}>")],
                "{case}"
            );
        }
    }

    /// A STRING without a value shows the default of a flagged EFI_IFR_ONE_OF_OPTION of Type
    /// EFI_IFR_TYPE_STRING in its scope, the text of the option's Value, below an EFI_IFR_DEFAULT,
    /// as EFI_IFR_STRING (UEFI 2.11 §33.3.8.3.70) orders them; an option of no default flag, or one
    /// that a SUPPRESS_IF hides, gives none.
    #[test]
    fn strings_show_the_defaults_of_their_flagged_options() {
        const OPTION_DEFAULT: u8 = 0x10;
        let option = || string_option(3, OPTION_DEFAULT, 4);
        let cases = [
            ("flagged option", vec![option()], " <IFR default: Bonjour>"),
            (
                "flagged option and EFI_IFR_DEFAULT",
                vec![option(), string_default(0, 2)],
                " <IFR default: Hello>",
            ),
            ("option of no flag", vec![string_option(3, 0x00, 4)], ""),
            (
                "suppressed flagged option",
                vec![conditional(SUPPRESS_IF, ifr_true(), &[option()])],
                "",
            ),
        ];
        for (case, children, default) in cases {
            let hiidb = string_list_of(
                [0x7F; 16],
                ((0, 8), 0x00),
                &children,
                16,
                &["S", "Hello", "Option", "Bonjour"],
            );
            let variables =
                MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);

            assert_eq!(
                answers_of(&hiidb, "S", &Rc::new(variables)),
                [format!("{MISSING_SETUP}{default}")],
                "{case}"
            );
        }
    }

    /// A ONE_OF whose flagged EFI_IFR_ONE_OF_OPTION is of Type EFI_IFR_TYPE_STRING shows its
    /// default as unknown, naming the Type mismatch: a ONE_OF stores a number.
    #[test]
    fn one_ofs_show_a_string_option_default_as_unknown() {
        let data = [
            question_header_with(1, 1, 1, 0, 0x00),
            // Flags EFI_IFR_NUMERIC_SIZE_1, MinValue, MaxValue, Step
            vec![0x00, 0x00, 0xFF, 0x01],
        ]
        .concat();
        let one_of = [
            operation(ONE_OF, true, &data),
            string_option(2, 0x10, 2),
            END.to_vec(),
        ]
        .concat();
        let packages = [
            form_package(&[var_store_efi(1, "Setup", NV_BS_RT, 1), form(1, &[one_of])]),
            en_strings_package_of(&["O", "Hello"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x5F; 16], &packages.concat());
        let variables = MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);

        assert_eq!(
            answers_of(&hiidb, "O", &Rc::new(variables)),
            [format!(
                "{MISSING_SETUP} <IFR default: unknown (a default of EFI_IFR_TYPE_STRING where the \
                 question stores a number)>"
            )],
            "get"
        );
    }

    /// set writes at most MaxSize − 1 characters of a STRING as UCS-2, NULL-padded to its MaxSize
    /// CHAR16s, so that a NULL ends them (UEFI 2.11 §33.2.5.4.9); get shows them then.
    #[test]
    fn set_writes_a_string_null_padded_to_max_size() {
        let hiidb = string_list([0x73; 16], (0, 4), &[]);
        let cases: [(&str, [u8; 8]); 5] = [
            ("Hi", [0x48, 0, 0x69, 0, 0, 0, 0, 0]),
            ("é€", [0xE9, 0, 0xAC, 0x20, 0, 0, 0, 0]),
            ("XYZ", [0x58, 0, 0x59, 0, 0x5A, 0, 0, 0]),
            ("\u{F900}", [0x00, 0xF9, 0, 0, 0, 0, 0, 0]),
            ("", [0; 8]),
        ];
        for (text, written) in cases {
            let variables = setup_holding(&[0x41, 0, 0x42, 0, 0x43, 0, 0x44, 0]);

            assert_eq!(
                set_of(&hiidb, "S", text, &variables),
                Ok(()),
                "set {text:?}"
            );
            assert_eq!(
                variables.writes_to(&setup()),
                [(0, written.to_vec())],
                "set {text:?}: writes"
            );
            assert_eq!(
                answers_of(&hiidb, "S", &variables),
                [text],
                "set {text:?}: get"
            );
        }
    }

    /// set --keyword selects a STRING by its keyword as set by its prompt does, and writes its
    /// text with set's checks: NULL-padded to MaxSize CHAR16s, and nothing for a text that set
    /// refuses.
    #[test]
    fn strings_set_by_keyword_as_by_prompt() {
        let string = flagged_string_on(1, 1, (1, 0), (0, 4), (0x00, 0x00), &[]);
        let packages = [
            form_package(&[var_store_efi(1, "Setup", NV_BS_RT, 8), form(1, &[string])]),
            en_strings_package_of(&["S"]),
            strings_package_of(b"x-UEFI-ns", &["KString"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x62; 16], &packages.concat());
        let set = |text: &str, variables: &Rc<MemoryVariables>| {
            let by_keyword = QuestionSelector::Keyword {
                keyword: "KString".parse().expect("parse the keyword"),
                namespace: None,
            };
            set_responses(
                &hiidb,
                by_keyword,
                &SetValue::Text(text.to_owned()),
                None,
                &SetOptions::default(),
                SetAccess {
                    reads: shared(variables),
                    writes: &**variables,
                    held: None,
                },
                None,
            )
            .map(drop)
            .map_err(|error| format!("{error:#}"))
        };

        let variables = setup_holding(&[0; 8]);
        assert_eq!(set("AB", &variables), Ok(()), "set AB");
        assert_eq!(
            variables.writes_to(&setup()),
            [(0, vec![0x41, 0, 0x42, 0, 0, 0, 0, 0])],
            "writes of AB"
        );

        let refused = setup_holding(&[0; 8]);
        assert_eq!(
            set("ABCD", &refused),
            Err(
                "cannot set question \"S\": the STRING takes at most 3 characters, its last \
                 CHAR16 of MaxSize 4 holding the NULL (UEFI 2.11 §33.2.5.4.9), not 4"
                    .to_owned()
            ),
            "set ABCD"
        );
        assert_eq!(
            refused.writes_to(&setup()),
            Vec::<(u16, Vec<u8>)>::new(),
            "writes of ABCD"
        );
    }

    /// set of a STRING through `hiidb`'s variables with `value`, as the CLI prints an error, and
    /// what it wrote to Setup, which held `stored`.
    fn string_set(hiidb: &[u8], value: &SetValue, stored: &[u8]) -> SetOutcome {
        let variables = setup_holding(stored);
        let got = HiiBackend::set_in(
            hiidb,
            "S",
            value,
            None,
            &SetOptions::default(),
            SetAccess {
                reads: shared(&variables),
                writes: &*variables,
                held: None,
            },
            None,
        )
        .map(drop)
        .map_err(|error| format!("{error:#}"));
        (got, variables.writes_to(&setup()))
    }

    /// set refuses, before any write, MaxSize characters, which leave no CHAR16 for the NULL
    /// (UEFI 2.11 §33.2.5.4.9), fewer than MinSize, as edk2-stable202608
    /// DisplayEngineDxe/InputHandler.c:209 does, a character that UCS-2 has none for, one of the
    /// Private Use Area (UEFI 2.11 §33.2.6.2.1), a line break without EFI_IFR_STRING_MULTI_LINE, a
    /// NULL, which ends a STRING, and items.
    #[test]
    fn set_refuses_a_string_that_its_sizes_or_ucs_2_cannot_hold() {
        let hiidb = string_list([0x74; 16], (2, 4), &[]);
        let refusal = |reason: &str| Err(format!("cannot set question \"S\": {reason}"));
        let line_break = "the STRING is single-line (no EFI_IFR_STRING_MULTI_LINE, UEFI 2.11 \
                          §33.3.8.3.70), so it takes no line break";
        let cases = [
            (
                SetValue::Text("ABCD".to_owned()),
                refusal(
                    "the STRING takes at most 3 characters, its last CHAR16 of MaxSize 4 holding \
                     the NULL (UEFI 2.11 §33.2.5.4.9), not 4",
                ),
            ),
            (
                SetValue::Text("A".to_owned()),
                refusal("the STRING takes at least 2 characters (MinSize), not 1"),
            ),
            (
                SetValue::Text("A\u{1F600}".to_owned()),
                refusal(
                    "'\u{1F600}' (U+1F600) has no UCS-2 character, which the STRING stores \
                     (UEFI 2.11 §33.2.6.2.2)",
                ),
            ),
            (
                SetValue::Text("A\u{E000}".to_owned()),
                refusal(
                    "'\\u{e000}' (U+E000) lies in the Private Use Area, U+E000..U+F8FF, which \
                     UEFI 2.11 §33.2.6.2.1 prohibits",
                ),
            ),
            (
                SetValue::Text("\u{F6FF}B".to_owned()),
                refusal(
                    "'\\u{f6ff}' (U+F6FF) lies in the Private Use Area, U+E000..U+F8FF, which \
                     UEFI 2.11 §33.2.6.2.1 prohibits",
                ),
            ),
            (SetValue::Text("A\nB".to_owned()), refusal(line_break)),
            (SetValue::Text("A\rB".to_owned()), refusal(line_break)),
            (
                SetValue::Text("A\0B".to_owned()),
                refusal(
                    "a NULL character ends a STRING, which takes none within (UEFI 2.11 \
                     §33.2.5.4.9)",
                ),
            ),
            (
                SetValue::Items(vec!["AB".to_owned()]),
                refusal("--item gives the options of an ORDERED_LIST; this question takes VALUE"),
            ),
        ];
        for (value, want) in cases {
            assert_eq!(
                string_set(&hiidb, &value, &[0; 8]),
                (want, Vec::new()),
                "set {value:?}"
            );
        }
    }

    /// set refuses, before any write, every VALUE of a STRING of MaxSize 0, which has no CHAR16
    /// for the NULL, and of one whose MinSize is above MaxSize − 1, naming both bounds.
    #[test]
    fn set_refuses_every_value_of_a_string_without_a_length() {
        let refusal = |reason: &str| Err(format!("cannot set question \"S\": {reason}"));
        let no_null = refusal(
            "the STRING of MaxSize 0 has no CHAR16 for the NULL that ends it (UEFI 2.11 \
             §33.2.5.4.9), so it takes no VALUE",
        );
        let no_length = refusal(
            "the STRING takes at least 4 characters (MinSize) and at most 3, its last CHAR16 of \
             MaxSize 4 holding the NULL (UEFI 2.11 §33.2.5.4.9), so it takes no VALUE",
        );
        let cases = [
            ("MaxSize 0", (0, 0), 2, "", no_null.clone()),
            ("MaxSize 0", (0, 0), 2, "A", no_null),
            ("MinSize 4 MaxSize 4", (4, 4), 8, "ABC", no_length.clone()),
            ("MinSize 4 MaxSize 4", (4, 4), 8, "ABCD", no_length),
        ];
        for (case, sizes, var_size, text, want) in cases {
            let hiidb = string_list_of([0x78; 16], (sizes, 0x00), &[], var_size, &["S"]);
            let value = SetValue::Text(text.to_owned());

            assert_eq!(
                string_set(&hiidb, &value, &vec![0x41; usize::from(var_size)]),
                (want, Vec::new()),
                "{case}: set {text:?}"
            );
        }
    }

    /// set writes line breaks into a STRING with EFI_IFR_STRING_MULTI_LINE (UEFI 2.11
    /// §33.3.8.3.70) in its Flags, and refuses them before any write into one without.
    #[test]
    fn set_writes_line_breaks_with_multi_line_alone() {
        let text = SetValue::Text("A\r\nB".to_owned());
        let multi_line = string_list_of([0x79; 16], ((0, 8), 0x01), &[], 16, &["S"]);
        let single_line = string_list_of([0x7A; 16], ((0, 8), 0xFE), &[], 16, &["S"]);
        let written = [0x41, 0, 0x0D, 0, 0x0A, 0, 0x42, 0, 0, 0, 0, 0, 0, 0, 0, 0];

        assert_eq!(
            string_set(&multi_line, &text, &[0; 16]),
            (Ok(()), vec![(0, written.to_vec())]),
            "Flags 0x01"
        );
        assert_eq!(
            string_set(&single_line, &text, &[0; 16]),
            (
                Err("cannot set question \"S\": the STRING is single-line (no \
                     EFI_IFR_STRING_MULTI_LINE, UEFI 2.11 §33.3.8.3.70), so it takes no line \
                     break"
                    .to_owned()),
                Vec::new()
            ),
            "Flags 0xFE"
        );
    }

    /// set refuses a STRING with a WRITE expression, which takes its characters, before any write,
    /// and get shows why one with a READ expression has no value: uefisettings evaluates neither.
    #[test]
    fn strings_with_read_or_write_expressions_take_no_value() {
        const WRITE: u8 = 0x2E;
        let expression =
            |op_code| [operation(op_code, true, &[]), ifr_true(), END.to_vec()].concat();
        let write = string_list([0x7B; 16], (0, 4), &[expression(WRITE)]);
        let read = string_list([0x7C; 16], (0, 4), &[expression(READ)]);

        assert_eq!(
            string_set(&write, &SetValue::Text("AB".to_owned()), &[0; 8]),
            (
                Err(
                    "cannot set question \"S\": its WRITE expression takes the CHAR16s of a \
                     STRING, which uefisettings does not evaluate"
                        .to_owned()
                ),
                Vec::new()
            ),
            "set with a WRITE expression"
        );
        assert_eq!(
            answers_of(&read, "S", &setup_holding(&[0x41, 0, 0, 0, 0, 0, 0, 0])),
            [
                "<ValueUnavailable: its READ expression gives the CHAR16s of a STRING, which \
              uefisettings does not evaluate>"
            ],
            "get with a READ expression"
        );
    }

    /// A STRING whose EFI_IFR_DEFAULT, or flagged option, is of a numeric Type shows that default
    /// as unknown, naming the Type mismatch, and takes no string of that number for its id.
    #[test]
    fn strings_show_a_numeric_default_as_unknown() {
        let unknown = " <IFR default: unknown (a default of a number where the question stores a \
                       string)>";
        for (case, child) in [
            ("UINT8 EFI_IFR_DEFAULT", ifr_default(0, 2)),
            ("flagged UINT8 option", flagged_option(2, 0x10, 2)),
        ] {
            let hiidb = string_list_of([0x60; 16], ((0, 8), 0x00), &[child], 16, &["S", "Hello"]);
            let variables =
                MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);

            assert_eq!(
                answers_of(&hiidb, "S", &Rc::new(variables)),
                [format!("{MISSING_SETUP}{unknown}")],
                "{case}"
            );
        }
    }

    /// A STRING without a VarStore is listed with why it has no value, and set refuses it before
    /// any write.
    #[test]
    fn storageless_strings_are_listed_and_refused() {
        let reason = "question has no VarStore, READ or WRITE expression, or \
                      EFI_IFR_FLAG_CALLBACK, one of which UEFI 2.11 §33.2.5.6 requires";
        let string = flagged_string_on(1, 1, (0, 0), (0, 4), (0x00, 0x00), &[]);
        let packages = [
            form_package(&[var_store_efi(1, "Setup", NV_BS_RT, 8), form(1, &[string])]),
            en_strings_package_of(&["S"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x61; 16], &packages.concat());
        let variables = setup_holding(&[0; 8]);
        let (listed, _) = listed_and_shown(&hiidb, &[0; 8], None);
        let listed: Vec<(&str, &str)> = listed
            .iter()
            .map(|question| (&*question.name, &*question.answer))
            .collect();

        assert_eq!(
            listed,
            [("S", &*format!("<ValueUnavailable: {reason}>"))],
            "list-questions"
        );
        assert_eq!(
            set_of(&hiidb, "S", "AB", &variables),
            Err(format!("cannot set question \"S\": {reason}")),
            "set AB"
        );
        assert_eq!(
            variables.writes_to(&setup()),
            Vec::<(u16, Vec<u8>)>::new(),
            "set AB: writes"
        );
    }

    /// A HiiDB whose form holds the STRING "S" of MaxSize 4 at byte 0 of the EFI variable Setup,
    /// of the question Flags `flags`, and password_hiidb's PASSWORD on the buffer VarStore
    /// AMITSESetup.
    fn string_and_password_list(flags: u8) -> Vec<u8> {
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, 8),
                var_store(2, [0x44; 16], "AMITSESetup", 81),
                form(
                    1,
                    &[
                        flagged_string_on(1, 1, (1, 0), (0, 4), (flags, 0x00), &[]),
                        password_on(3, 3, 2, 0),
                    ],
                ),
            ]),
            en_strings_package_of(&["S", "Hello", "Password"]),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid([0x7D; 16], &packages.concat())
    }

    /// set of a STRING takes UnsafeOperations as the other kinds do. One that
    /// EFI_IFR_FLAG_READ_ONLY makes read-only it refuses before any write, and writes with
    /// UnsafeOperations::Allow, which it returns as lifted. Through variables that reach
    /// BootServices, in a HiiDB that declares a password question, it refuses unless Allow, and
    /// then returns UnsafeOperation::SetupPassword, lifted before the read-only flag. A VALUE that
    /// the STRING cannot hold it refuses before either, with and without Allow.
    #[test]
    fn string_set_follows_the_unsafe_operations_grant() {
        let read_only = UnsafeOperation::ReadOnlyQuestion {
            question: "S".to_owned(),
            writable: IncludedStates::empty(),
        };
        let password = "this HiiDB declares a setup password question, and the UEFI Shell runs no \
                        setup browser, so no password is asked or checked; pass \
                        --i-am-fine-to-brick-this-system to write without it"
            .to_owned();
        let too_long = "cannot set question \"S\": the STRING takes at most 3 characters, its \
                        last CHAR16 of MaxSize 4 holding the NULL (UEFI 2.11 §33.2.5.4.9), not 4"
            .to_owned();
        let runtime = (VariableReach::Runtime, VariableInterface::Efivarfs);
        let boot_services = (
            VariableReach::BootServices,
            VariableInterface::VariableServices,
        );
        // (variables, question Flags, VALUE, what set gives with UnsafeOperations::Refuse, Allow)
        let cases = [
            (
                runtime,
                0x01,
                "AB",
                [
                    flag_refusal("S", "").map(|()| vec![]),
                    Ok(vec![read_only.clone()]),
                ],
            ),
            (
                runtime,
                0x01,
                "ABCD",
                [Err(too_long.clone()), Err(too_long.clone())],
            ),
            (
                boot_services,
                0x00,
                "AB",
                [
                    Err(password.clone()),
                    Ok(vec![UnsafeOperation::SetupPassword]),
                ],
            ),
            (
                boot_services,
                0x01,
                "AB",
                [
                    Err(password),
                    Ok(vec![UnsafeOperation::SetupPassword, read_only]),
                ],
            ),
            (
                boot_services,
                0x00,
                "ABCD",
                [Err(too_long.clone()), Err(too_long)],
            ),
        ];
        for ((reach, interface), flags, text, wants) in cases {
            let grants = [UnsafeOperations::Refuse, UnsafeOperations::Allow];
            for (grant, want) in grants.into_iter().zip(wants) {
                let variables = password_variables(reach, interface);
                variables.insert(setup(), NV_BS_RT, &[0; 8]);
                let want_writes = match want {
                    Ok(_) => vec![(0, vec![0x41, 0, 0x42, 0, 0, 0, 0, 0])],
                    Err(_) => vec![],
                };

                let got = HiiBackend::set_in(
                    &string_and_password_list(flags),
                    "S",
                    &SetValue::Text(text.to_owned()),
                    None,
                    &SetOptions {
                        unsafe_operations: grant,
                        ..SetOptions::default()
                    },
                    SetAccess {
                        reads: shared(&variables),
                        writes: &*variables,
                        held: None,
                    },
                    None,
                )
                .map(|(_, lifted)| lifted)
                .map_err(|error| format!("{error:#}"));

                let case =
                    format!("{reach:?}, question Flags {flags:#04x}, set S {text}, {grant:?}");
                assert_eq!(got, want, "{case}");
                assert_eq!(variables.writes_to(&setup()), want_writes, "{case}: writes");
            }
        }
    }

    /// A STRING over the bytes of a PASSWORD keeps them withheld, as a NUMERIC does: get answers
    /// that its bytes hold a password and set writes nothing, while a STRING after them is read
    /// and written; the PASSWORD, whose characters a STRING would show, stays no question that
    /// get selects.
    #[test]
    fn strings_keep_the_bytes_of_a_password_withheld() {
        let packages = [
            form_package_of(&form_set(&[
                var_store(2, [0x44; 16], "AMITSESetup", 81),
                form(
                    1,
                    &[
                        password_on(3, 3, 2, 0),
                        string_on(4, 4, (2, 10), (0, 4), &[]),
                        string_on(5, 5, (2, 40), (0, 4), &[]),
                    ],
                ),
            ])),
            en_strings_package_of(&["Q", "P", "Password", "Over", "After"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x55; 16], &packages.concat());
        let after: Vec<u8> = [0x41, 0, 0x42, 0, 0, 0, 0, 0].into();
        let stored = [plaintext_password().as_slice(), &after, &[0; 33]].concat();
        let variables = MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);
        variables.insert(amitse_setup(), NV_BS_RT, &stored);
        let variables = Rc::new(variables);

        assert_eq!(
            answers_of(&hiidb, "Over", &variables),
            [PASSWORD_BYTES],
            "get Over"
        );
        assert_eq!(answers_of(&hiidb, "After", &variables), ["AB"], "get After");
        assert_eq!(
            answers_of(&hiidb, "Password", &variables),
            Vec::<String>::new(),
            "get Password"
        );
        let set = set_bypassing(&hiidb, "Over", "ab", &variables);
        assert!(
            set.as_ref()
                .is_err_and(|error| error
                    .contains("holds a password at bytes 0..40, which set never writes")),
            "set Over: {set:?}"
        );
        assert_eq!(variables.writes_to(&amitse_setup()), [], "set Over: writes");
        assert_eq!(
            set_bypassing(&hiidb, "After", "Z", &variables),
            Ok(()),
            "set After"
        );
        assert_eq!(
            variables.writes_to(&amitse_setup()),
            [(40, vec![0x5A, 0, 0, 0, 0, 0, 0, 0])],
            "set After: writes"
        );
    }

    /// list-questions and show-ifr withhold the bytes of a PASSWORD under a STRING, and show no
    /// character of the password, while they show a STRING after it.
    #[test]
    fn strings_list_and_show_no_password_character() {
        let packages = [
            form_package(&[
                var_store_efi(1, "Setup", NV_BS_RT, 48),
                form(
                    1,
                    &[
                        password_on(3, 3, 1, 0),
                        string_on(4, 4, (1, 2), (0, 4), &[]),
                        string_on(5, 5, (1, 40), (0, 4), &[]),
                    ],
                ),
            ]),
            en_strings_package_of(&["Q", "P", "Password", "Over", "After"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x7D; 16], &packages.concat());
        let stored = [
            plaintext_password().as_slice(),
            &[0x41, 0, 0x42, 0, 0, 0, 0, 0],
        ]
        .concat();

        let (listed, shown) = listed_and_shown(&hiidb, &stored, None);

        let listed: Vec<(&str, &str)> = listed
            .iter()
            .map(|question| (&*question.name, &*question.answer))
            .collect();
        assert_eq!(
            listed,
            [("Over", PASSWORD_BYTES), ("After", "AB")],
            "list-questions"
        );
        assert!(
            shown.contains(&format!("-Answer: {PASSWORD_BYTES}\n")),
            "show-ifr: {shown}"
        );
        assert!(shown.contains("-Answer: AB\n"), "show-ifr: {shown}");
        for output in [format!("{listed:?}"), shown] {
            assert!(
                !output.contains("unter"),
                "a password character in {output}"
            );
        }
    }

    /// A STRING of a VARSTORE whose bytes the ExportConfig snapshot holds shows " <snapshot>" in
    /// get, list-questions and show-ifr, and one over a PASSWORD's bytes in the snapshot shows
    /// none of them, as bytes or as characters, in any text or JSON output.
    #[test]
    fn snapshot_strings_show_their_source_and_no_password() {
        let packages = [
            device_path_package(&DRIVER_PATH),
            form_package(&[
                var_store(1, N_GUID, "NStore", 8),
                var_store(2, P_GUID, "AMITSESetup", 81),
                form(
                    1,
                    &[
                        string_on(1, 1, (1, 0), (0, 4), &[]),
                        password_on(3, 4, 2, 0),
                        string_on(5, 5, (2, 2), (0, 4), &[]),
                    ],
                ),
            ]),
            en_strings_package_of(&["S", "W", "P", "Password", "Over"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x7E; 16], &packages.concat());
        let mut amitse_setup = [0; 81];
        amitse_setup[..40].fill(0xA5);
        let text = [
            block_resp(
                &config_hdr(N_GUID, "NStore", &DRIVER_PATH),
                0,
                &[0x41, 0, 0x42, 0, 0, 0, 0, 0],
            ),
            block_resp(
                &config_hdr(P_GUID, "AMITSESetup", &DRIVER_PATH),
                0,
                &amitse_setup,
            ),
        ]
        .join("&");

        let (got, listed, shown, outputs) =
            answers_with_snapshot(&hiidb, &["S", "Over"], &no_variables(), &text);

        assert_eq!(got, ["AB <snapshot>", PASSWORD_BYTES], "get");
        assert_eq!(listed, got, "list-questions");
        assert!(
            shown.contains("-Answer: AB <snapshot>\n"),
            "show-ifr: {shown}"
        );
        assert!(
            shown.contains(&format!("-Answer: {PASSWORD_BYTES}\n")),
            "show-ifr: {shown}"
        );
        assert_no_password_byte(&outputs);
        for output in &outputs {
            assert!(!output.contains('\u{A5A5}'), "U+A5A5 in {output}");
        }
    }

    /// set refuses a STRING and a NUMERIC that one prompt selects in two FormSets before it
    /// writes either: it gives one value to questions of one kind.
    #[test]
    fn set_refuses_a_string_and_a_numeric_of_one_prompt() {
        let hiidb = [
            string_list([0x75; 16], (0, 1), &[]),
            one_form_list([0x76; 16], "S", &[numeric_at(1, 0, 0)]),
        ]
        .concat();
        let variables = setup_holding(&[0; 3]);

        let set = set_of(&hiidb, "S", "1", &variables);
        assert!(
            set.as_ref()
                .is_err_and(|error| error.contains("STRING (in ")
                    && error.contains("set gives one value to questions of one kind")),
            "set S: {set:?}"
        );
        assert_eq!(variables.writes_to(&setup()), [], "set S: writes");
    }

    /// Two VARSTORE_EFIs before UEFI 2.3.1 of two Guids each take the VarNames of their questions
    /// from the strings of the package list: the NUMERIC A, inside a SUPPRESS_IF and a
    /// GRAY_OUT_IF, reads and sets ShortVarA of the first store's Guid, the CHECKBOX B ShortVarB
    /// of the second's, and set writes no variable of the other Guid.
    #[test]
    fn two_short_var_stores_set_the_variables_of_their_own_guids() {
        let nested_a = conditional(
            SUPPRESS_IF,
            ifr_false(),
            &[conditional(GRAY_OUT_IF, ifr_false(), &[short_numeric_a()])],
        );
        let hiidb = short_store_list(
            &[
                short_var_store_efi_of(1, SHORT_VAR_STORE_GUID, NV_BS_RT),
                short_var_store_efi_of(2, OTHER_GUID, NV_BS_RT),
                form(1, &[nested_a, checkbox_at(2, 2, 2, 8)]),
            ],
            &[en_strings_package_of(&SHORT_STRINGS)],
        );
        let other = |name: &str| VariableKey {
            name: name.to_string(),
            guid: Guid::from(OTHER_GUID),
        };
        let variables = short_efivarfs_variables();
        variables.insert(other("ShortVarB"), NV_BS_RT, &[0]);

        assert_eq!(answers_of(&hiidb, "A", &variables), ["5"], "get A");
        assert_eq!(answers_of(&hiidb, "B", &variables), ["0"], "get B");
        assert_eq!(set_of(&hiidb, "A", "9", &variables), Ok(()), "set A");
        assert_eq!(set_of(&hiidb, "B", "1", &variables), Ok(()), "set B");
        let writes = [
            (short_key("ShortVarA"), vec![(0, vec![9])]),
            (other("ShortVarA"), vec![]),
            (other("ShortVarB"), vec![(0, vec![1])]),
            (short_key("ShortVarB"), vec![]),
        ];
        for (key, want) in writes {
            assert_eq!(variables.writes_to(&key), want, "writes of {key}");
        }
    }

    /// The PASSWORD on a VARSTORE_EFI before UEFI 2.3.1 keeps its password in the EFI variable of
    /// its VarName, which get and set through variables of either reach withhold: the CHECKBOX B
    /// on that VarName is neither read nor written, the NUMERIC A beside it is, and the variable
    /// keeps the password. Through variables that reach BootServices, set refuses the HiiDB
    /// without UnsafeOperations::Allow.
    #[test]
    fn the_variable_of_a_short_var_store_password_is_withheld() {
        // "Password" is string 14 and "ShortVarPw" string 15
        let strings = [&SHORT_STRINGS[..], &["Password", "ShortVarPw"]].concat();
        let packages = [
            form_package(&[
                short_var_store_efi_of(1, SHORT_VAR_STORE_GUID, NV_BS_RT),
                form(
                    1,
                    &[
                        short_numeric_a(),
                        password_on(6, 14, 1, 15),
                        checkbox_at(2, 2, 1, 15),
                    ],
                ),
            ]),
            en_strings_package_of(&strings),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x55; 16], &packages.concat());
        let password = short_key("ShortVarPw");
        let password_variable = [&NV_BS_RT.to_ne_bytes()[..], &plaintext_password()].concat();
        let refusal = "cannot set question \"B\": EFI variable \
                       ShortVarPw-8c78a505-baa0-4c4a-869f-000000000b01 holds a password at bytes \
                       0..40, which set never writes";
        let reaches = [
            (VariableReach::Runtime, VariableInterface::Efivarfs),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            ),
        ];
        for (reach, interface) in reaches {
            let variables = short_variables(reach, interface);
            variables.insert(password.clone(), NV_BS_RT, &plaintext_password());

            assert_eq!(
                answers_of(&hiidb, "B", &variables),
                [format!("{PASSWORD_BYTES} <IFR default: 0>")],
                "{reach:?}: get B"
            );
            assert_eq!(
                answers_of(&hiidb, "A", &variables),
                ["5"],
                "{reach:?}: get A"
            );
            assert_eq!(
                set_bypassing(&hiidb, "B", "1", &variables),
                Err(refusal.to_string()),
                "{reach:?}: set B"
            );
            assert_eq!(
                set_bypassing(&hiidb, "A", "9", &variables),
                Ok(()),
                "{reach:?}: set A"
            );
            assert_eq!(
                variables.writes_to(&password),
                vec![],
                "{reach:?}: writes of ShortVarPw"
            );
            assert_eq!(
                variables.bytes(&password),
                Some(password_variable.clone()),
                "{reach:?}: ShortVarPw keeps its password"
            );
        }

        let variables = short_variables(
            VariableReach::BootServices,
            VariableInterface::VariableServices,
        );
        variables.insert(password, NV_BS_RT, &plaintext_password());
        assert_eq!(
            set_of(&hiidb, "A", "9", &variables),
            Err(
                "this HiiDB declares a setup password question, and the UEFI Shell runs no setup \
                 browser, so no password is asked or checked; pass \
                 --i-am-fine-to-brick-this-system to write without it"
                    .to_string()
            ),
            "set A without UnsafeOperations::Allow"
        );
    }

    /// A GET and a SET of the VARSTORE_EFI before UEFI 2.3.1 reach the EFI variables of their
    /// VarNames through set, through variables of either reach: set refuses the CHECKBOX F, which
    /// a SUPPRESS_IF hides while the GET of ShortVarA gives 5, and sets it once set of A wrote 9
    /// there; that set writes ShortVarD by the SET of A's WRITE expression, then ShortVarA, and,
    /// without ShortVarD, creates it with the store's Attributes, as edk2-stable202608
    /// SetupBrowserDxe/Expression.c EvaluateExpression does by SetVariable(). Through the firmware
    /// environment calls of Windows, which create no variable, that SET stores nothing.
    #[test]
    fn get_and_set_of_a_short_var_store_reach_the_variables_of_their_var_names() {
        const GET: u8 = 0x2B;
        const SET: u8 = 0x2C;
        const WRITE: u8 = 0x2E;
        const EQUAL: u8 = 0x2F;
        const THIS: u8 = 0x58;
        // a GET or SET of VarStore 1 at VarName `var_name`, of VarStoreType `value_type`
        let store_op = |op_code: u8, var_name: u16, value_type: u8| {
            let data = [
                &1u16.to_le_bytes()[..],
                &var_name.to_le_bytes(),
                &[value_type],
            ]
            .concat();
            operation(op_code, false, &data)
        };
        // the UINT8 NUMERIC A on ShortVarA, whose WRITE sets ShortVarD, a UINT16
        // (EFI_IFR_TYPE_NUM_SIZE_16), to its value
        let numeric_a = [
            operation(
                NUMERIC,
                true,
                &[
                    question_header_with(1, 1, 1, 7, 0x00),
                    // EFI_IFR_NUMERIC_SIZE_1 | EFI_IFR_DISPLAY_UINT_DEC, from 0 to 255, step 1
                    vec![0x10, 0, 255, 1],
                ]
                .concat(),
            ),
            operation(WRITE, false, &[]),
            scoped_expression(&[operation(THIS, false, &[]), store_op(SET, 10, 0x01)], 0),
            END.to_vec(),
        ]
        .concat();
        // the CHECKBOX F on ShortVarC, suppressed where ShortVarA holds the UINT8
        // (EFI_IFR_TYPE_NUM_SIZE_8) 5
        let hidden_f = conditional(
            SUPPRESS_IF,
            scoped_expression(
                &[
                    store_op(GET, 7, 0x00),
                    uint8(5),
                    operation(EQUAL, false, &[]),
                ],
                0,
            ),
            &[checkbox_at(6, 6, 1, 9)],
        );
        let hiidb = short_store_hiidb(NV_BS_RT, &[numeric_a, hidden_f]);
        let reaches = [
            (VariableReach::Runtime, VariableInterface::Efivarfs),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            ),
        ];
        for (reach, interface) in reaches {
            let variables = short_variables(reach, interface);

            assert_eq!(
                set_of(&hiidb, "F", "1", &variables),
                Err(
                    "question \"F\" is suppressed; also include suppressed questions to select it"
                        .to_string()
                ),
                "{reach:?}: set F while ShortVarA holds 5"
            );
            assert_eq!(
                set_of(&hiidb, "A", "9", &variables),
                Ok(()),
                "{reach:?}: set A"
            );
            assert_eq!(
                variables.writes_to(&short_key("ShortVarD")),
                [(0, vec![9, 0])],
                "{reach:?}: set A: writes of ShortVarD"
            );
            assert_eq!(
                variables.writes_to(&short_key("ShortVarA")),
                [(0, vec![9])],
                "{reach:?}: set A: writes of ShortVarA"
            );
            assert_eq!(
                set_of(&hiidb, "F", "1", &variables),
                Ok(()),
                "{reach:?}: set F once ShortVarA holds 9"
            );
            assert_eq!(
                variables.writes_to(&short_key("ShortVarC")),
                [(0, vec![1])],
                "{reach:?}: set F: writes of ShortVarC"
            );

            let variables = MemoryVariables::new(reach, interface);
            variables.insert(short_key("ShortVarA"), NV_BS_RT, &[5]);
            let variables = Rc::new(variables);
            assert_eq!(
                set_of(&hiidb, "A", "9", &variables),
                Ok(()),
                "{reach:?}: set A without ShortVarD"
            );
            assert_eq!(
                variables.writes_to(&short_key("ShortVarA")),
                [(0, vec![9])],
                "{reach:?}: set A without ShortVarD: writes of ShortVarA"
            );
            assert_eq!(
                variables.bytes(&short_key("ShortVarD")),
                Some([&NV_BS_RT.to_ne_bytes()[..], &[9, 0]].concat()),
                "{reach:?}: set A without ShortVarD: ShortVarD"
            );
        }

        let variables = MemoryVariables::new(
            VariableReach::Runtime,
            VariableInterface::FirmwareEnvironment,
        );
        variables.insert(short_key("ShortVarA"), NV_BS_RT, &[5]);
        let variables = Rc::new(variables);
        assert_eq!(
            set_of(&hiidb, "A", "9", &variables),
            Ok(()),
            "Windows: set A without ShortVarD"
        );
        assert_eq!(
            variables.writes_to(&short_key("ShortVarA")),
            [(0, vec![9])],
            "Windows: set A without ShortVarD: writes of ShortVarA"
        );
        assert_eq!(
            variables.bytes(&short_key("ShortVarD")),
            None,
            "Windows: set A without ShortVarD: ShortVarD"
        );
    }

    /// set writes an existing per-question variable at its question's width with the variable's
    /// own attributes, not those that the VARSTORE_EFI declares: "If a preexisting variable is
    /// rewritten with different attributes, SetVariable() shall not modify the variable" (UEFI
    /// 2.11 §8.2.3 SetVariable).
    #[test]
    fn set_keeps_the_attributes_of_a_per_question_variable() {
        let hiidb = short_store_hiidb(NV_BS_RT, &[short_numeric_a()]);
        let variables = Rc::new(MemoryVariables::new(
            VariableReach::BootServices,
            VariableInterface::VariableServices,
        ));
        variables.insert(short_key("ShortVarA"), NV_BS, &[5]);

        assert_eq!(set_of(&hiidb, "A", "9", &variables), Ok(()), "set A");
        assert_eq!(
            variables.bytes(&short_key("ShortVarA")),
            Some([&NV_BS.to_ne_bytes()[..], &[9]].concat()),
            "ShortVarA"
        );
    }

    /// Two FormSets that declare AMITSESetup: the first at its top, with the UINT64 NUMERIC N0
    /// over bytes 0..8, shown in hex; the second after `declarations`, with a PASSWORD at bytes
    /// 0..40.
    fn password_after_hiidb(declarations: &[Vec<u8>]) -> Vec<u8> {
        let numeric = [
            question_header_with(4, 4, 2, 0, 0x00),
            vec![0x23], // EFI_IFR_NUMERIC_SIZE_8 | EFI_IFR_DISPLAY_UINT_HEX
            0u64.to_le_bytes().to_vec(),
            u64::MAX.to_le_bytes().to_vec(),
            1u64.to_le_bytes().to_vec(),
        ]
        .concat();
        let packages = [
            form_package_of(
                &[
                    form_set(&[
                        var_store(2, [0x44; 16], "AMITSESetup", 81),
                        form(1, &[operation(NUMERIC, false, &numeric)]),
                    ]),
                    form_set(&[declarations.concat(), form(1, &[password_on(3, 3, 2, 0)])]),
                ]
                .concat(),
            ),
            en_strings_package_of(&["Q", "P", "Password", "N0"]),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid([0x55; 16], &packages.concat())
    }

    /// get of N0 in `hiidb` through variables of `reach`, AMITSESetup holding a password in its
    /// bytes 0..40: its answers, or why it refuses.
    fn get_over_password(hiidb: &[u8], reach: VariableReach) -> Result<Vec<String>, String> {
        let interface = match reach {
            VariableReach::Runtime => VariableInterface::Efivarfs,
            VariableReach::BootServices => VariableInterface::VariableServices,
        };
        let variables = MemoryVariables::new(reach, interface);
        variables.insert(
            amitse_setup(),
            NV_BS_RT,
            &[plaintext_password().as_slice(), &[0xAA; 40], &[1]].concat(),
        );
        HiiBackend::get_in(
            hiidb,
            "N0",
            None,
            &GetOptions::default(),
            shared(&Rc::new(variables)),
            None,
            None,
            None,
        )
        .map(|got| {
            got.responses
                .iter()
                .map(|response| response.question.answer.clone())
                .collect()
        })
        .map_err(|error| error.to_string())
    }

    /// Through variables of either reach, a NUMERIC over a password whose VarStore a SUPPRESS_IF
    /// of its FormSet declares shows none of its bytes: get answers that they hold a password.
    #[test]
    fn a_password_on_a_var_store_under_a_suppress_if_withholds_its_bytes() {
        let hiidb = password_after_hiidb(&[conditional(
            SUPPRESS_IF,
            ifr_true(),
            &[var_store(2, [0x44; 16], "AMITSESetup", 81)],
        )]);
        for reach in [VariableReach::Runtime, VariableReach::BootServices] {
            assert_eq!(
                get_over_password(&hiidb, reach),
                Ok(vec![PASSWORD_BYTES.to_string()]),
                "{reach:?}"
            );
        }
    }

    /// A VarStore of a PASSWORD's VarStoreId whose EFI variable is unknown never drops the known
    /// VarStore of the id beside it: through Runtime, a NUMERIC over the password shows none of
    /// its bytes; through BootServices, get refuses the HiiDB as the password is unresolved. A
    /// VARSTORE_NAME_VALUE of the id in the PASSWORD's FormSet, whose driver may keep the password
    /// in any variable, has get refuse the HiiDB through Runtime too.
    #[test]
    fn a_store_of_an_unknown_variable_keeps_a_password_withheld_through_runtime() {
        let amitse = || var_store(2, [0x44; 16], "AMITSESetup", 81);
        let withheld = Ok(vec![PASSWORD_BYTES.to_string()]);
        let cases = [
            (
                "a VarStore op that does not decode, in an unknown op",
                vec![
                    nested(
                        &operation(0x70, true, &[]),
                        1,
                        &[operation(VAR_STORE, false, &[0x00; 3])],
                    ),
                    amitse(),
                ],
                withheld.clone(),
            ),
            (
                "a VARSTORE_NAME_VALUE in a form",
                vec![amitse(), form(7, &[var_store_name_value(2, [0x66; 16])])],
                Err(ANY_VARIABLE),
            ),
            (
                "a VARSTORE_NAME_VALUE under DISABLE_IF TRUE",
                vec![
                    conditional(
                        DISABLE_IF,
                        ifr_true(),
                        &[var_store_name_value(2, [0x66; 16])],
                    ),
                    conditional(DISABLE_IF, ifr_false(), &[amitse()]),
                ],
                Err(ANY_VARIABLE),
            ),
            (
                "a short VARSTORE_EFI under DISABLE_IF TRUE",
                vec![
                    conditional(DISABLE_IF, ifr_true(), &[short_var_store_efi(2)]),
                    conditional(DISABLE_IF, ifr_false(), &[amitse()]),
                ],
                withheld,
            ),
        ];
        for (case, declarations, runtime) in cases {
            let hiidb = password_after_hiidb(&declarations);
            let got = get_over_password(&hiidb, VariableReach::Runtime);
            match &runtime {
                Ok(want) => assert_eq!(got.as_ref(), Ok(want), "{case}: Runtime"),
                Err(suffix) => assert!(
                    got.as_ref().is_err_and(|error| error.ends_with(suffix)),
                    "{case}: Runtime: {got:?}"
                ),
            }
            let refusal = get_over_password(&hiidb, VariableReach::BootServices);
            assert!(
                matches!(&refusal, Err(reason) if reason.contains(
                    "the UEFI Shell build reads and writes no variable of this HiiDB"
                )),
                "{case}: BootServices: {refusal:?}"
            );
        }
    }

    /// The end of the refusal through variables that reach BootServices of a HiiDB with a
    /// PASSWORD whose VarStore is unknown (UnresolvedPasswords).
    const BOOT_SERVICES_REFUSAL: &str = "; as the variable of that password is unknown, the UEFI \
                                         Shell build reads and writes no variable of this HiiDB";

    /// Strings 1 C, 2 W, 3 Password, 4 Pin, 5 Flag, 6 B, 7 O and 8 P of the package lists of
    /// name_value_hiidb.
    const NAME_VALUE_STRINGS: [&str; 8] = ["C", "W", "Password", "Pin", "Flag", "B", "O", "P"];

    /// The ExportConfig snapshot of name_value_hiidb: Pin 0x7A5B, Flag 1.
    fn name_value_snapshot() -> String {
        format!("{}&Pin=7a5b&Flag=01", config_hdr(N_GUID, "", &DRIVER_PATH))
    }

    /// A HiiDB of two package lists of the driver at DRIVER_PATH, with NAME_VALUE_STRINGS: the
    /// first of the IFR `ifr`, the second with the UINT16 NUMERIC O at byte 0 of the buffer
    /// VarStore Other, VarStoreId 2.
    fn name_value_hiidb(ifr: &[Vec<u8>]) -> Vec<u8> {
        name_value_hiidb_of_packages(&[ifr.concat()])
    }

    /// name_value_hiidb with a form package in the first list for each IFR of `packages`.
    fn name_value_hiidb_of_packages(packages: &[Vec<u8>]) -> Vec<u8> {
        let list = |guid: [u8; 16], forms: &[Vec<u8>]| {
            let packages = [
                vec![device_path_package(&DRIVER_PATH)],
                forms.iter().map(|ifr| form_package_of(ifr)).collect(),
                vec![
                    en_strings_package_of(&NAME_VALUE_STRINGS),
                    END_PACKAGE.to_vec(),
                ],
            ];
            package_list_with_guid(guid, &packages.concat().concat())
        };
        let other = form_set_with_guid(
            OTHER_GUID,
            &[
                var_store(2, OTHER_GUID, "Other", 2),
                form(1, &[uint16_numeric(1, 7, 2, 0)]),
            ],
        );
        [list([0x55; 16], packages), list([0x56; 16], &[other])].concat()
    }

    /// Variables of `reach` with Backing of name_value_hiidb, B 0x7A5B at bytes 0..2 and 0x2211
    /// at bytes 4..6, and Other, O 0x1122.
    fn name_value_variables(reach: VariableReach) -> Rc<MemoryVariables> {
        let interface = match reach {
            VariableReach::BootServices => VariableInterface::VariableServices,
            VariableReach::Runtime => VariableInterface::Efivarfs,
        };
        let variables = MemoryVariables::new(reach, interface);
        let key = |name: &str, guid| VariableKey {
            name: name.to_owned(),
            guid: Guid::from(guid),
        };
        variables.insert(
            key("Backing", P_GUID),
            NV_BS_RT,
            &[0x5B, 0x7A, 0, 0, 0x11, 0x22, 0, 0],
        );
        variables.insert(key("Other", OTHER_GUID), NV_BS_RT, &[0x22, 0x11]);
        Rc::new(variables)
    }

    /// get of `question` in `hiidb` through `variables`, with the ExportConfig snapshot `exported`
    /// if any: the answers, or the error.
    fn name_value_get(
        hiidb: &[u8],
        question: &str,
        variables: &Rc<MemoryVariables>,
        exported: Option<&str>,
    ) -> Result<Vec<String>, String> {
        HiiBackend::get_in(
            hiidb,
            question,
            None,
            &GetOptions::default(),
            shared(variables),
            exported.map(|text| ExportedConfig::new(text.to_owned())),
            None,
            None,
        )
        .map(|response| {
            response
                .responses
                .into_iter()
                .map(|response| response.question.answer)
                .collect()
        })
        .map_err(|error| format!("{error:#}"))
    }

    /// The IFR of the questions and stores of name_value_hiidb's first list: the CHECKBOX C on
    /// the label Flag and the UINT16 NUMERIC W on the label Pin of the VARSTORE_NAME_VALUE of
    /// VarStoreId 3, the UINT16 NUMERIC B at byte 0 and P at byte 4 of the buffer VarStore
    /// Backing, VarStoreId 1, and the PASSWORD on Pin.
    struct NameValueIfr;

    impl NameValueIfr {
        fn c() -> Vec<u8> {
            checkbox_at(1, 1, 3, 5)
        }

        fn w() -> Vec<u8> {
            uint16_numeric(2, 2, 3, 4)
        }

        fn b() -> Vec<u8> {
            uint16_numeric(6, 6, 1, 0)
        }

        fn p() -> Vec<u8> {
            uint16_numeric(8, 8, 1, 4)
        }

        fn backing() -> Vec<u8> {
            var_store(1, P_GUID, "Backing", 8)
        }

        fn name_value() -> Vec<u8> {
            var_store_name_value(3, N_GUID)
        }

        /// The PASSWORD on Pin, VarStoreId `var_store_id`.
        fn password(var_store_id: u16) -> Vec<u8> {
            password_on(3, 3, var_store_id, 4)
        }

        /// A VARSTORE_NAME_VALUE op that ends after its VarStoreId 3, before its Guid.
        fn short_name_value() -> Vec<u8> {
            operation(VAR_STORE_NAME_VALUE, false, &3u16.to_le_bytes())
        }
    }

    /// A PASSWORD that edk2 may route to a VARSTORE_NAME_VALUE, whose values its driver exposes,
    /// as UEFI 2.11 §33.2.5.6 says, through EFI_HII_CONFIG_ACCESS_PROTOCOL, in storage of its own
    /// choosing, may keep its password in any variable, also one that another package list
    /// declares, as one driver may publish several (edk2-stable202608 DriverSample.c installs one
    /// EFI_HII_CONFIG_ACCESS_PROTOCOL for two package lists, :1870-1918). So
    /// through variables that read anything, get, set and the snapshot refuse the whole HiiDB, as
    /// for IFR without an op boundary, set writing nothing, also with UnsafeOperations::Allow,
    /// whose flag lifts no withholding and which the refusal does not name; list-questions reads
    /// without efivars; through BootServices the HiiDB is refused as before. Each layout names the
    /// record that the refusal holds. edk2 routes the PASSWORD there by a VARSTORE_NAME_VALUE of
    /// its VarStoreId in its FormSet, before or after it, under a condition, beside it in a
    /// disabled form, also after a VarStore of its id outside any FormSet, and for one whose
    /// question header lies past its op; by the first VarStore of its id in its form package, in
    /// another FormSet, outside any FormSet, before or after every FormSet, or in an unknown scope,
    /// also for a PASSWORD outside any FormSet, in IFR that uefisettings ignores, or whose question
    /// header lies past its op; for one without a header, by one of any id in its FormSet or the
    /// first of any id in its form package, in a FormSet or outside any; and by one that does not
    /// decode, as edk2 creates its storage whatever its Length
    /// (SetupBrowserDxe/IfrParse.c:1885-1895, ConfigKeywordHandler.c:1547-1550): in an unknown op
    /// of its FormSet, outside any FormSet, or in IFR that uefisettings ignores.
    #[test]
    fn passwords_that_edk2_may_route_to_a_name_value_store_close_every_variable() {
        type I = NameValueIfr;
        // a CHECKBOX op ending after 4 of the 12 bytes of its data, which disables its form
        let disabler = || operation(CHECKBOX, false, &[0x00; 4]);
        // a PASSWORD op of Prompt 3 and Help 4 whose question header runs on into the SUBTITLE
        // after it, VarStoreId 3 and VarStoreInfo 4 (QuestionId 0x0702: the SUBTITLE's header)
        let header_past_op = || {
            [
                operation(PASSWORD, false, &[3, 0, 4, 0]),
                operation(SUBTITLE, false, &[3, 0, 4, 0, 0]),
            ]
            .concat()
        };
        let in_its_form_set = "PASSWORD question 0x0003 in FormSet \
            11111111-1111-1111-1111-111111111111: HII name/value varstore requires \
            EFI_HII_CONFIG_ACCESS_PROTOCOL";
        let cases = [
            (
                "in its FormSet, before it",
                vec![form_set(&[
                    I::name_value(),
                    I::backing(),
                    form(1, &[I::c(), I::w(), I::b(), I::password(3)]),
                ])],
                in_its_form_set,
            ),
            (
                "in its FormSet, after a VARSTORE of its id outside any FormSet",
                vec![
                    var_store(3, P_GUID, "Backing", 8),
                    form_set(&[
                        I::name_value(),
                        I::backing(),
                        form(1, &[I::c(), I::w(), I::b(), I::password(3)]),
                    ]),
                ],
                in_its_form_set,
            ),
            (
                "in its FormSet, after it",
                vec![form_set(&[
                    I::backing(),
                    form(1, &[I::b(), I::password(3)]),
                    I::name_value(),
                    form(2, &[I::c(), I::w()]),
                ])],
                in_its_form_set,
            ),
            (
                "under a SUPPRESS_IF of its FormSet",
                vec![form_set(&[
                    I::backing(),
                    form(1, &[I::b(), I::password(3)]),
                    conditional(SUPPRESS_IF, ifr_true(), &[I::name_value()]),
                ])],
                in_its_form_set,
            ),
            (
                "beside it in a disabled form",
                vec![form_set(&[
                    I::name_value(),
                    I::backing(),
                    form(1, &[I::c(), I::w(), I::b()]),
                    form(2, &[I::password(3), disabler()]),
                ])],
                in_its_form_set,
            ),
            (
                "beside its form under a SUPPRESS_IF of its FormSet",
                vec![form_set(&[
                    I::name_value(),
                    I::backing(),
                    form(1, &[I::c(), I::w(), I::b()]),
                    conditional(SUPPRESS_IF, ifr_true(), &[form(2, &[I::password(3)])]),
                ])],
                in_its_form_set,
            ),
            (
                "the first VarStore of its id in its form package, in another FormSet",
                vec![
                    form_set_with_guid(
                        [0x12; 16],
                        &[
                            I::name_value(),
                            I::backing(),
                            form(1, &[I::c(), I::w(), I::b()]),
                        ],
                    ),
                    form_set(&[
                        var_store(3, P_GUID, "Backing", 8),
                        form(2, &[I::password(3)]),
                    ]),
                ],
                "the first VarStore of its VarStoreId in its form package, which edk2's Config \
                 Keyword Handler takes, is a VARSTORE_NAME_VALUE",
            ),
            (
                "outside any FormSet",
                vec![
                    I::name_value(),
                    form_set(&[
                        I::backing(),
                        var_store(3, P_GUID, "Backing", 8),
                        form(1, &[I::b(), I::password(3)]),
                    ]),
                ],
                "a VARSTORE_NAME_VALUE outside a FormSet, at offset 0 of a form package, \
                 declares its VarStoreId",
            ),
            (
                "in an unknown scope of another FormSet",
                vec![
                    form_set_with_guid(
                        [0x12; 16],
                        &[in_unknown_scope(&I::name_value()), form(1, &[])],
                    ),
                    form_set(&[
                        I::backing(),
                        var_store(3, P_GUID, "Backing", 8),
                        form(1, &[I::b(), I::password(3)]),
                    ]),
                ],
                "a VARSTORE_NAME_VALUE in the scope of an unknown opcode",
            ),
            (
                "an undecodable one in an unknown op of its FormSet, beside a PASSWORD on Backing",
                vec![form_set(&[
                    nested(&operation(0x70, true, &[]), 1, &[I::short_name_value()]),
                    I::backing(),
                    form(1, &[I::b(), I::password(1)]),
                ])],
                "PASSWORD question 0x0003 in FormSet 11111111-1111-1111-1111-111111111111: \
                 failed to parse VarStoreNameValue's data",
            ),
            (
                "of its id, the PASSWORD outside any FormSet",
                vec![
                    I::password(3),
                    form_set(&[
                        I::name_value(),
                        I::backing(),
                        form(1, &[I::c(), I::w(), I::b()]),
                    ]),
                ],
                "PASSWORD op of package list 55555555-5555-5555-5555-555555555555 outside a \
                 FormSet, at offset 0 of a form package",
            ),
            (
                "of its id outside any FormSet, the PASSWORD outside any FormSet too",
                vec![
                    I::name_value(),
                    I::password(3),
                    form_set(&[I::backing(), form(1, &[I::b(), I::p()])]),
                ],
                "PASSWORD op of package list 55555555-5555-5555-5555-555555555555 outside a \
                 FormSet, at offset 20 of a form package",
            ),
            (
                "of its id after every FormSet, the PASSWORD outside any FormSet",
                vec![
                    form_set(&[I::backing(), form(1, &[I::b(), I::p()])]),
                    I::password(3),
                    I::name_value(),
                ],
                "PASSWORD op of package list 55555555-5555-5555-5555-555555555555 outside a \
                 FormSet, at offset ",
            ),
            (
                "of its id, the PASSWORD's question header past its op",
                vec![form_set(&[
                    I::name_value(),
                    I::backing(),
                    form(1, &[I::c(), I::w(), I::b()]),
                    form(2, &[header_past_op()]),
                ])],
                "PASSWORD question 0x0702 in FormSet 11111111-1111-1111-1111-111111111111: its \
                 op ends before its question header",
            ),
            (
                "of its id in its FormSet, after a VARSTORE of its id outside any FormSet, the \
                 PASSWORD's question header past its op",
                vec![
                    var_store(3, P_GUID, "Backing", 8),
                    form_set(&[
                        I::name_value(),
                        I::backing(),
                        form(1, &[I::c(), I::w(), I::b()]),
                        form(2, &[header_past_op()]),
                    ]),
                ],
                "PASSWORD question 0x0702 in FormSet 11111111-1111-1111-1111-111111111111: its \
                 op ends before its question header",
            ),
            (
                "beside a PASSWORD without its question header",
                vec![form_set(&[
                    I::name_value(),
                    I::backing(),
                    form(1, &[I::c(), I::w(), I::b()]),
                    form(2, &[operation(PASSWORD, false, &[3, 0, 4, 0])]),
                ])],
                "PASSWORD op without a question header in FormSet \
                 11111111-1111-1111-1111-111111111111",
            ),
            (
                "beside a PASSWORD without its question header, after a VARSTORE of its id \
                 outside any FormSet",
                vec![
                    var_store(3, P_GUID, "Backing", 8),
                    form_set(&[
                        I::name_value(),
                        I::backing(),
                        form(1, &[I::c(), I::w(), I::b()]),
                        form(2, &[operation(PASSWORD, false, &[3, 0, 4, 0])]),
                    ]),
                ],
                "PASSWORD op without a question header in FormSet \
                 11111111-1111-1111-1111-111111111111",
            ),
            (
                "beside a PASSWORD outside any FormSet without its question header",
                vec![
                    form_set(&[I::name_value(), I::backing(), form(1, &[I::b(), I::p()])]),
                    operation(PASSWORD, false, &[3, 0, 4, 0]),
                ],
                "PASSWORD op of package list 55555555-5555-5555-5555-555555555555 outside a \
                 FormSet, at offset ",
            ),
            (
                "an undecodable one outside any FormSet, beside a PASSWORD on Backing",
                vec![
                    I::short_name_value(),
                    form_set(&[I::backing(), form(1, &[I::b(), I::password(1)])]),
                ],
                "may name the VarStoreId of the op at offset 0 of a form package, a malformed \
                 EFI_IFR_VARSTORE_NAME_VALUE outside a FormSet",
            ),
            (
                "an undecodable one in a FormSet that uefisettings ignores",
                vec![
                    form_set(&[I::backing(), form(1, &[I::b()])]),
                    form_set_with_guid(
                        [0x12; 16],
                        &[I::short_name_value(), form(2, &[I::password(3)])],
                    ),
                ],
                "the EFI_IFR_VARSTORE_NAME_VALUE op at offset",
            ),
            (
                "of its id, the PASSWORD in a FormSet that uefisettings ignores",
                vec![
                    form_set(&[
                        I::name_value(),
                        I::backing(),
                        form(1, &[I::c(), I::w(), I::b()]),
                    ]),
                    form_set_with_guid(
                        [0x12; 16],
                        &[
                            operation(DEFAULT_STORE, false, &[0x00, 0x00]),
                            form(2, &[I::password(3)]),
                        ],
                    ),
                ],
                "the PASSWORD op there, which edk2 may route to a VARSTORE_NAME_VALUE of its \
                 form package",
            ),
        ];
        for (case, ifr, record) in cases {
            assert_closes_every_variable(case, &ifr, record);
        }
    }

    /// Through Runtime, get of B and O of the name_value_hiidb of `ifr`, from the snapshot too,
    /// show-ifr, and set of O with UnsafeOperations::Allow refuse the HiiDB with
    /// AnyVariablePasswords naming `record`, set writing nothing; list-questions reads without
    /// efivars; through BootServices
    /// get refuses it as for a PASSWORD whose VarStore is unknown.
    /// Through Runtime list-questions refuses it too.
    fn assert_closes_every_variable(case: &str, ifr: &[Vec<u8>], record: &str) {
        let hiidb = name_value_hiidb(ifr);
        let runtime = name_value_variables(VariableReach::Runtime);
        let refused = |error: Option<&String>| {
            error.is_some_and(|error| error.contains(record) && error.ends_with(ANY_VARIABLE))
        };

        for question in ["B", "O"] {
            let got = name_value_get(&hiidb, question, &runtime, None);
            assert!(
                refused(got.as_ref().err()),
                "{case}: Runtime: get {question}: {got:?}"
            );
            let snapshot = name_value_snapshot();
            let got = name_value_get(&hiidb, question, &runtime, Some(&snapshot));
            assert!(
                refused(got.as_ref().err())
                    && got.as_ref().is_err_and(|error| !error.contains("31323")),
                "{case}: Runtime, with the snapshot: get {question}: {got:?}"
            );
        }
        let set = set_bypassing(&hiidb, "O", "5", &runtime);
        assert!(
            refused(set.as_ref().err())
                && set
                    .as_ref()
                    .is_err_and(|error| !error.contains(UNSAFE_OPERATIONS_FLAG)),
            "{case}: Runtime, with UnsafeOperations::Allow: set O: {set:?}"
        );
        let shown = HiiBackend::show_ifr_in(
            &hiidb,
            &ShowIfrOptions::default(),
            shared(&runtime),
            None,
            None,
        )
        .map(drop)
        .map_err(|error| format!("{error:#}"));
        assert!(
            refused(shown.as_ref().err()),
            "{case}: Runtime: show-ifr: {shown:?}"
        );
        let listed_at_runtime = HiiBackend::list_questions_in(
            &hiidb,
            &ListQuestionsOptions::default(),
            shared(&runtime),
            None,
            None,
        )
        .map(drop)
        .map_err(|error| format!("{error:#}"));
        assert!(
            refused(listed_at_runtime.as_ref().err()),
            "{case}: Runtime: list-questions: {listed_at_runtime:?}"
        );
        for (name, guid) in [("Backing", P_GUID), ("Other", OTHER_GUID)] {
            let key = VariableKey {
                name: name.to_owned(),
                guid: Guid::from(guid),
            };
            assert_eq!(runtime.writes_to(&key), [], "{case}: writes to {name}");
        }
        let listed = HiiBackend::list_questions_in(
            &hiidb,
            &ListQuestionsOptions::default(),
            EfivarSource::Disabled
                .into_variables()
                .expect("variables that read nothing"),
            None,
            None,
        )
        .map(|questions| {
            questions
                .into_iter()
                .map(|question| question.name)
                .filter(|name| ["B", "O"].contains(&name.as_str()))
                .collect::<Vec<_>>()
        })
        .map_err(|error| format!("{error:#}"));
        assert_eq!(
            listed,
            Ok(vec!["B".to_owned(), "O".to_owned()]),
            "{case}: list-questions without efivars"
        );
        let boot_services = name_value_variables(VariableReach::BootServices);
        let got = name_value_get(&hiidb, "O", &boot_services, None);
        assert!(
            got.as_ref()
                .is_err_and(|error| error.ends_with(BOOT_SERVICES_REFUSAL)),
            "{case}: BootServices: get O: {got:?}"
        );
    }

    /// The middle of the record of a PASSWORD of VarStoreId 0 (UnresolvedPassword::OwnDriver).
    const OWN_DRIVER: &str =
        "VarStoreId 0 names no VarStore, so its callbacks or READ and WRITE ops \
         keep its password where uefisettings cannot tell";

    /// A PASSWORD of VarStoreId 0 names no VarStore (UEFI 2.11 §33.3.8.2.2): its callbacks or READ
    /// and WRITE ops (§33.2.5.6) keep its password where uefisettings cannot tell, so in any
    /// variable, EFI_IFR_FLAG_CALLBACK or not, with no VARSTORE_NAME_VALUE in the HiiDB. So get,
    /// set and the snapshot refuse the whole HiiDB as for a PASSWORD that edk2 may route to a
    /// VARSTORE_NAME_VALUE: one in a form or a disabled form of its FormSet, one without MaxSize,
    /// outside any FormSet, in a FormSet that uefisettings ignores, one whose question header past
    /// its op names VarStoreId 0, and one without a question header, whose VarStoreId may be 0,
    /// also in a FormSet that uefisettings ignores. Each names its record.
    #[test]
    fn passwords_of_var_store_id_0_close_every_variable() {
        type I = NameValueIfr;
        let password_of = |flags: u8, sizes: &[u16]| {
            let sizes = sizes.iter().flat_map(|size| size.to_le_bytes());
            let data = [question_header_with(3, 3, 0, 0, flags), sizes.collect()].concat();
            operation(PASSWORD, false, &data)
        };
        // a CHECKBOX op ending after 4 of the 12 bytes of its data, which disables its form
        let disabler = || operation(CHECKBOX, false, &[0x00; 4]);
        // a PASSWORD op of Prompt 3 and Help 4 whose question header runs on into the SUBTITLE
        // after it, VarStoreId 0 and VarStoreInfo 4 (QuestionId 0x0702: the SUBTITLE's header)
        let header_past_op = [
            operation(PASSWORD, false, &[3, 0, 4, 0]),
            operation(SUBTITLE, false, &[0, 0, 4, 0, 0]),
        ]
        .concat();
        let backing_with = |forms: &[Vec<u8>]| {
            let first = form(1, &[I::b(), I::p()]);
            form_set(&[[I::backing(), first].as_slice(), forms].concat())
        };
        // a FormSet that uefisettings ignores, for its short DEFAULTSTORE op, with `password`
        let ignored_with = |password: Vec<u8>| {
            form_set_with_guid(
                [0x12; 16],
                &[
                    operation(DEFAULT_STORE, false, &[0x00, 0x00]),
                    form(2, &[password]),
                ],
            )
        };
        let in_its_form_set: &str = &format!(
            "PASSWORD question 0x0003 in FormSet 11111111-1111-1111-1111-111111111111: {OWN_DRIVER}"
        );
        let outside: &str = &format!("PASSWORD question 0x0003 in FormSet ?: {OWN_DRIVER}");
        let cases = [
            (
                "in its form",
                vec![form_set(&[
                    I::backing(),
                    form(1, &[I::b(), I::p(), I::password(0)]),
                ])],
                in_its_form_set,
            ),
            (
                "of EFI_IFR_FLAG_CALLBACK",
                vec![backing_with(&[form(2, &[password_of(0x04, &[1, 20])])])],
                in_its_form_set,
            ),
            (
                "without MaxSize",
                vec![backing_with(&[form(2, &[password_of(0x00, &[1])])])],
                in_its_form_set,
            ),
            (
                "in a disabled form",
                vec![backing_with(&[form(2, &[I::password(0), disabler()])])],
                in_its_form_set,
            ),
            (
                "outside any FormSet",
                vec![I::password(0), backing_with(&[])],
                outside,
            ),
            (
                "in a FormSet that uefisettings ignores",
                vec![backing_with(&[]), ignored_with(I::password(0))],
                outside,
            ),
            (
                "its question header past its op",
                vec![backing_with(&[form(2, &[header_past_op])])],
                "PASSWORD question 0x0702 in FormSet 11111111-1111-1111-1111-111111111111: its \
                 op ends before its question header",
            ),
            (
                "without its question header",
                vec![backing_with(&[form(
                    2,
                    &[operation(PASSWORD, false, &[3, 0, 4, 0])],
                )])],
                "PASSWORD op without a question header in FormSet \
                 11111111-1111-1111-1111-111111111111",
            ),
            (
                "without its question header, in a FormSet that uefisettings ignores",
                vec![
                    backing_with(&[]),
                    ignored_with(operation(PASSWORD, false, &[3, 0, 4, 0])),
                ],
                "the PASSWORD op there, whose question header does not parse, so whose \
                 VarStoreId may be 0, which names no VarStore",
            ),
        ];
        for (case, ifr, record) in cases {
            assert_closes_every_variable(case, &ifr, record);
        }
    }

    /// A STRING beside a PASSWORD of VarStoreId 0, EFI_IFR_FLAG_CALLBACK or not, is refused like the
    /// NUMERICs: get, also with the ExportConfig snapshot, and set with UnsafeOperations::Allow
    /// fail before any variable read, through Runtime naming the PASSWORD's record and through
    /// BootServices as for a PASSWORD whose VarStore is unknown; beside a PASSWORD on Backing that
    /// ends before it, get reads it.
    #[test]
    fn a_string_beside_a_password_of_var_store_id_0_reads_no_variable() {
        type I = NameValueIfr;
        // the STRING P at bytes 4..8 of Backing, of 0 to 2 characters
        let string = || string_on(8, 8, (1, 4), (0, 2), &[]);
        let hiidb_beside = |var_store_id: u16, flags: u8| {
            let password = [
                question_header_with(3, 3, var_store_id, 0, flags),
                [1u16, 2]
                    .iter()
                    .flat_map(|size| size.to_le_bytes())
                    .collect(), // MinSize, MaxSize
            ]
            .concat();
            let password = operation(PASSWORD, false, &password);
            name_value_hiidb(&[form_set(&[
                I::backing(),
                form(1, &[I::b(), string(), password]),
            ])])
        };
        let record = format!(
            "PASSWORD question 0x0003 in FormSet 11111111-1111-1111-1111-111111111111: {OWN_DRIVER}"
        );

        for flags in [0x00, 0x04] {
            let hiidb = hiidb_beside(0, flags);
            for (reach, end) in [
                (VariableReach::Runtime, ANY_VARIABLE),
                (VariableReach::BootServices, BOOT_SERVICES_REFUSAL),
            ] {
                let case = format!("Flags {flags:#04x}, {reach:?}");
                let refused = |error: Option<&String>| {
                    error.is_some_and(|error| error.contains(&record) && error.ends_with(end))
                };
                let variables = name_value_variables(reach);
                let got = name_value_get(&hiidb, "P", &variables, None);
                assert!(refused(got.as_ref().err()), "{case}: get P: {got:?}");
                let snapshot = name_value_snapshot();
                let got = name_value_get(&hiidb, "P", &variables, Some(&snapshot));
                assert!(
                    refused(got.as_ref().err()),
                    "{case}, with the snapshot: get P: {got:?}"
                );
                let set = set_bypassing(&hiidb, "P", "ab", &variables);
                assert!(refused(set.as_ref().err()), "{case}: set P: {set:?}");
                assert_eq!(variables.reads(), [], "{case}: reads");
                for (name, guid) in [("Backing", P_GUID), ("Other", OTHER_GUID)] {
                    let key = VariableKey {
                        name: name.to_owned(),
                        guid: Guid::from(guid),
                    };
                    assert_eq!(variables.writes_to(&key), [], "{case}: writes to {name}");
                }
            }
        }

        let variables = name_value_variables(VariableReach::Runtime);
        assert_eq!(
            name_value_get(&hiidb_beside(1, 0x00), "P", &variables, None),
            Ok(vec!["\u{2211}".to_owned()]),
            "beside a password on Backing: get P"
        );
    }

    /// The middle of the record of a PASSWORD in a FormSet whose VarStoreId 9 no VarStore declares.
    const UNDECLARED_9: &str = "PASSWORD question 0x0003 in FormSet \
                                11111111-1111-1111-1111-111111111111: no supported varstore with \
                                matching id 0x0009 found";

    /// A PASSWORD whose VarStoreId no VarStore of its form package that decodes declares names no
    /// VarStore: UEFI 2.11 §33.3.8.2.2 asks for "a previously declared variable store", and
    /// edk2-stable202608 finds none for it in the Forms Browser (SetupBrowserDxe/IfrParse.c
    /// CreateQuestion, :136-148) nor in the Config Keyword Handler (ConfigKeywordHandler.c
    /// FindStorageFromVarId, :1520-1569) but a VarStore op that does not decode, which each reads
    /// whatever the op's Length: the Forms Browser one of its FormSet outside an unknown opcode's
    /// scope (IfrParse.c ParseOpCodes, :1873-1918), FindStorageFromVarId the first in the form
    /// package (:1538-1555), so its password may be in any variable, as for VarStoreId 0. So get,
    /// set and the snapshot refuse the whole HiiDB, EFI_IFR_FLAG_CALLBACK or not: one in its form,
    /// in a disabled form, outside any FormSet, in a FormSet that uefisettings ignores, one whose
    /// question header past its op names such an id, one whose id only a VarStore op that does not
    /// decode names, in an unknown opcode's scope or in its FormSet, which uefisettings ignores
    /// for that op, one in a form package that declares no VarStore, and one whose id only another
    /// package list declares. Each names its record.
    #[test]
    fn passwords_of_undeclared_var_store_ids_close_every_variable() {
        type I = NameValueIfr;
        let callback = || {
            let data = [
                question_header_with(3, 3, 9, 4, 0x04),
                [1u8, 0, 20, 0].to_vec(),
            ]
            .concat();
            operation(PASSWORD, false, &data)
        };
        // a CHECKBOX op ending after 4 of the 12 bytes of its data, which disables its form
        let disabler = || operation(CHECKBOX, false, &[0x00; 4]);
        // a PASSWORD op of Prompt 3 and Help 4 whose question header runs on into the SUBTITLE
        // after it, VarStoreId 9 and VarStoreInfo 4 (QuestionId 0x0702: the SUBTITLE's header)
        let header_past_op = [
            operation(PASSWORD, false, &[3, 0, 4, 0]),
            operation(SUBTITLE, false, &[9, 0, 4, 0, 0]),
        ]
        .concat();
        let backing_with = |forms: &[Vec<u8>]| {
            let first = form(1, &[I::b(), I::p()]);
            form_set(&[[I::backing(), first].as_slice(), forms].concat())
        };
        // a FormSet that uefisettings ignores, for its short DEFAULTSTORE op, with `password`
        let ignored_with = |password: Vec<u8>| {
            form_set_with_guid(
                [0x12; 16],
                &[
                    operation(DEFAULT_STORE, false, &[0x00, 0x00]),
                    form(2, &[password]),
                ],
            )
        };
        let cases = [
            (
                "in its form",
                vec![form_set(&[
                    I::backing(),
                    form(1, &[I::b(), I::p(), I::password(9)]),
                ])],
                UNDECLARED_9,
            ),
            (
                "of EFI_IFR_FLAG_CALLBACK",
                vec![backing_with(&[form(2, &[callback()])])],
                UNDECLARED_9,
            ),
            (
                "in a disabled form",
                vec![backing_with(&[form(2, &[I::password(9), disabler()])])],
                UNDECLARED_9,
            ),
            (
                "outside any FormSet",
                vec![I::password(9), backing_with(&[])],
                "PASSWORD op of package list 55555555-5555-5555-5555-555555555555 outside a \
                 FormSet, at offset 0 of a form package",
            ),
            (
                "in a FormSet that uefisettings ignores",
                vec![backing_with(&[]), ignored_with(I::password(9))],
                "the PASSWORD op there, whose VarStoreId 0x0009 names no VarStore of its form \
                 package",
            ),
            (
                "its question header past its op",
                vec![backing_with(&[form(2, &[header_past_op])])],
                "PASSWORD question 0x0702 in FormSet 11111111-1111-1111-1111-111111111111: its \
                 op ends before its question header",
            ),
            (
                "its id only of a VarStore op that does not decode",
                vec![form_set(&[
                    I::backing(),
                    in_unknown_scope(&operation(
                        VAR_STORE,
                        false,
                        &[&OTHER_GUID[..], &9u16.to_le_bytes()].concat(),
                    )),
                    form(1, &[I::b(), I::p(), I::password(9)]),
                ])],
                "PASSWORD question 0x0003 in FormSet 11111111-1111-1111-1111-111111111111: \
                 failed to parse VarStore's data",
            ),
            (
                "its id only of a VarStore op of its FormSet that does not decode",
                vec![
                    backing_with(&[]),
                    form_set_with_guid(
                        [0x12; 16],
                        &[
                            operation(
                                VAR_STORE,
                                false,
                                &[&OTHER_GUID[..], &9u16.to_le_bytes()].concat(),
                            ),
                            form(2, &[I::password(9)]),
                        ],
                    ),
                ],
                "the PASSWORD op there, whose VarStoreId 0x0009 names no VarStore of its form \
                 package",
            ),
            (
                "in a form package that declares no VarStore",
                vec![form_set(&[form(1, &[I::b(), I::p(), I::password(9)])])],
                UNDECLARED_9,
            ),
            (
                "its id declared only by another package list",
                vec![backing_with(&[form(2, &[I::password(2)])])],
                "PASSWORD question 0x0003 in FormSet 11111111-1111-1111-1111-111111111111: no \
                 supported varstore with matching id 0x0002 found",
            ),
        ];
        for (case, ifr, record) in cases {
            assert_closes_every_variable(case, &ifr, record);
        }
    }

    /// Of a package list with two form packages, a PASSWORD whose VarStoreId only the other
    /// package declares names no VarStore of its own: neither the Forms Browser nor
    /// FindStorageFromVarId, which walks one form package, finds one, so get refuses the HiiDB,
    /// for one in its form, one whose question header past its op names the id, and one outside
    /// any FormSet.
    #[test]
    fn a_password_of_an_id_that_only_another_form_package_declares_closes_every_variable() {
        type I = NameValueIfr;
        // a PASSWORD op of Prompt 3 and Help 4 whose question header runs on into the SUBTITLE
        // after it, VarStoreId 9 and VarStoreInfo 4 (QuestionId 0x0702: the SUBTITLE's header)
        let header_past_op = [
            operation(PASSWORD, false, &[3, 0, 4, 0]),
            operation(SUBTITLE, false, &[9, 0, 4, 0, 0]),
        ]
        .concat();
        let cases = [
            (
                "in its form",
                form_set(&[I::backing(), form(1, &[I::b(), I::p(), I::password(9)])]),
                UNDECLARED_9,
            ),
            (
                "its question header past its op",
                form_set(&[
                    I::backing(),
                    form(1, &[I::b(), I::p()]),
                    form(2, &[header_past_op]),
                ]),
                "PASSWORD question 0x0702 in FormSet 11111111-1111-1111-1111-111111111111: its \
                 op ends before its question header",
            ),
            (
                "outside any FormSet",
                [
                    I::password(9),
                    form_set(&[I::backing(), form(1, &[I::b(), I::p()])]),
                ]
                .concat(),
                "PASSWORD op of package list 55555555-5555-5555-5555-555555555555 outside a \
                 FormSet, at offset 0 of a form package",
            ),
        ];
        let runtime = name_value_variables(VariableReach::Runtime);

        for (case, ifr, record) in cases {
            let hiidb = name_value_hiidb_of_packages(&[
                ifr,
                form_set_with_guid(
                    [0x14; 16],
                    &[var_store(9, P_GUID, "Backing", 8), form(3, &[])],
                ),
            ]);
            for question in ["B", "O"] {
                let got = name_value_get(&hiidb, question, &runtime, None);
                assert!(
                    got.as_ref().is_err_and(
                        |error| error.contains(record) && error.ends_with(ANY_VARIABLE)
                    ),
                    "{case}: get {question}: {got:?}"
                );
            }
        }
    }

    /// A PASSWORD whose VarStoreId a VarStore of its form package declares, though not one of its
    /// FormSet before it, stays bounded: FindStorageFromVarId takes that VarStore, the first of
    /// the id in the form package (edk2-stable202608 ConfigKeywordHandler.c:1520-1569), so
    /// through Runtime the password's bytes there are withheld and the others read, its id declared
    /// by another FormSet, by its own after it, or outside any FormSet.
    #[test]
    fn passwords_of_ids_that_their_form_package_declares_stay_bounded() {
        type I = NameValueIfr;
        let backing_9 = || var_store(9, P_GUID, "Backing", 8);
        let in_its_form = || form(1, &[I::b(), I::p(), I::password(9)]);
        let cases = [
            (
                "by another FormSet",
                vec![
                    form_set(&[I::backing(), in_its_form()]),
                    form_set_with_guid([0x13; 16], &[backing_9(), form(3, &[])]),
                ],
            ),
            (
                "by its FormSet after it",
                vec![form_set(&[I::backing(), in_its_form(), backing_9()])],
            ),
            (
                "outside any FormSet",
                vec![backing_9(), form_set(&[I::backing(), in_its_form()])],
            ),
        ];
        let runtime = name_value_variables(VariableReach::Runtime);

        for (case, ifr) in cases {
            let hiidb = name_value_hiidb(&ifr);
            assert_eq!(
                name_value_get(&hiidb, "B", &runtime, None),
                Ok(vec!["31323".to_owned()]),
                "{case}: get B"
            );
            assert_eq!(
                name_value_get(&hiidb, "P", &runtime, None),
                Ok(vec![PASSWORD_BYTES.to_owned()]),
                "{case}: get P"
            );
        }
    }

    /// A PASSWORD that edk2 does not route to a VARSTORE_NAME_VALUE keeps its password where its
    /// IFR says, so through Runtime its bytes alone are withheld, beside one: one on its FormSet's
    /// VARSTORE of an id that a VARSTORE_NAME_VALUE of a later FormSet declares (VarStoreIds are
    /// unique within a form set, §33.3.8.3.90), which edk2 takes first, or one outside any FormSet
    /// after it: edk2-stable202608 SetupBrowserDxe/IfrParse.c gives a question the VarStore of its
    /// id in its FormSet (:136-146), and ConfigKeywordHandler.c FindStorageFromVarId the first of
    /// the id in its form package (:1520-1567); one outside any FormSet of an id whose first
    /// VarStore in its form package is a VARSTORE, beside a VARSTORE_NAME_VALUE of the id in
    /// another form package, which FindStorageFromVarId does not walk; one on a buffer VarStore
    /// beside a VARSTORE_NAME_VALUE of another id, in its FormSet or, for a PASSWORD outside any
    /// FormSet, in its form package, in a FormSet or outside any. P over the password's bytes
    /// shows withheld, B beside them and O of the other list show. The snapshot answers the
    /// questions of the VARSTORE_NAME_VALUE, where the layout has W, unless the PASSWORD is
    /// unresolved, and so does BootServices.
    #[test]
    fn passwords_that_edk2_does_not_route_to_a_name_value_store_keep_withholding_their_bytes() {
        type I = NameValueIfr;
        let unavailable = "<ValueUnavailable: HII name/value varstore requires \
                           EFI_HII_CONFIG_ACCESS_PROTOCOL>";
        let shown = "31323 <snapshot>";
        // FormSet 0x11 with the PASSWORD of VarStoreId 3 on its VARSTORE 3, Backing too
        let own_var_store = || {
            form_set(&[
                I::backing(),
                var_store(3, P_GUID, "Backing", 8),
                form(1, &[I::b(), I::p(), I::password(3)]),
            ])
        };
        let cases = [
            (
                "its FormSet's VARSTORE first, a later FormSet's VARSTORE_NAME_VALUE",
                name_value_hiidb(&[
                    own_var_store(),
                    form_set_with_guid([0x12; 16], &[I::name_value(), form(2, &[I::w()])]),
                ]),
                ["31323", WITHHELD],
                Some(shown),
            ),
            (
                "its FormSet's VARSTORE first, a VARSTORE_NAME_VALUE outside any FormSet after it",
                name_value_hiidb(&[own_var_store(), I::name_value()]),
                ["31323", WITHHELD],
                None,
            ),
            (
                "outside any FormSet, its form package's VARSTORE first, a VARSTORE_NAME_VALUE in \
                 another form package",
                name_value_hiidb_of_packages(&[
                    [
                        I::password(3),
                        form_set(&[
                            I::backing(),
                            var_store(3, P_GUID, "Backing", 8),
                            form(1, &[I::b(), I::p()]),
                        ]),
                    ]
                    .concat(),
                    form_set_with_guid([0x12; 16], &[I::name_value(), form(2, &[I::w()])]),
                ]),
                ["31323", WITHHELD],
                Some(unavailable),
            ),
            (
                "on Backing, a VARSTORE_NAME_VALUE of another id in its FormSet",
                name_value_hiidb(&[form_set(&[
                    I::name_value(),
                    I::backing(),
                    form(1, &[I::c(), I::w(), I::b(), I::p(), I::password(1)]),
                ])]),
                ["31323", WITHHELD],
                Some(shown),
            ),
            (
                "on Backing outside any FormSet, a VARSTORE_NAME_VALUE of another id",
                name_value_hiidb(&[
                    I::password(1),
                    form_set(&[
                        I::name_value(),
                        I::backing(),
                        form(1, &[I::c(), I::w(), I::b(), I::p()]),
                    ]),
                ]),
                ["31323", WITHHELD],
                Some(unavailable),
            ),
            (
                "on Backing outside any FormSet, a VARSTORE_NAME_VALUE of another id outside any \
                 FormSet before it",
                name_value_hiidb(&[
                    I::name_value(),
                    I::password(1),
                    form_set(&[I::backing(), form(1, &[I::b(), I::p()])]),
                ]),
                ["31323", WITHHELD],
                None,
            ),
        ];
        for (case, hiidb, [b, p], w) in cases {
            let runtime = name_value_variables(VariableReach::Runtime);
            let snapshot = name_value_snapshot();
            let resolved = w == Some(shown);

            for (question, want) in [("B", b), ("P", p), ("O", "4386")] {
                assert_eq!(
                    name_value_get(&hiidb, question, &runtime, None),
                    Ok(vec![want.to_owned()]),
                    "{case}: Runtime: get {question}"
                );
            }
            if let Some(w) = w {
                assert_eq!(
                    name_value_get(&hiidb, "W", &runtime, Some(&snapshot)),
                    Ok(vec![w.to_owned()]),
                    "{case}: Runtime, with the snapshot: get W"
                );
            }
            let boot_services = name_value_variables(VariableReach::BootServices);
            let got = name_value_get(&hiidb, "O", &boot_services, None);
            match resolved {
                true => assert_eq!(got, Ok(vec!["4386".to_owned()]), "{case}: BootServices"),
                false => assert!(
                    got.as_ref()
                        .is_err_and(|error| error.ends_with(BOOT_SERVICES_REFUSAL)),
                    "{case}: BootServices: {got:?}"
                ),
            }
        }
    }

    /// A HiiDB whose FormSet holds the VARSTORE_EFI Setup of id 1, over 4 bytes, and then the ops
    /// `list` of its form-set-list; its strings are Hidden, Shown, Gate, After, First and Outside.
    fn form_set_list_hiidb(list: &[Vec<u8>]) -> Vec<u8> {
        let children = [vec![var_store_efi(1, "Setup", NV_BS_RT, 4)], list.to_vec()].concat();
        let packages = [
            form_package(&children),
            en_strings_package_of(&["Hidden", "Shown", "Gate", "After", "First", "Outside"]),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid([0x55; 16], &packages.concat())
    }

    /// The names and answers of the questions that list-questions lists in `hiidb` with
    /// `include` through `variables`.
    fn names_and_answers(
        hiidb: &[u8],
        include: IncludedStates,
        variables: &Rc<MemoryVariables>,
    ) -> Vec<(String, String)> {
        let options = ListQuestionsOptions {
            include,
            ..ListQuestionsOptions::default()
        };
        HiiBackend::list_questions_in(hiidb, &options, shared(variables), None, None)
            .expect("list the questions")
            .into_iter()
            .map(|question| (question.name, question.answer))
            .collect()
    }

    /// What get of `question` in `hiidb` gives with `include` through `variables`.
    fn got_with(
        hiidb: &[u8],
        question: &str,
        include: IncludedStates,
        variables: &Rc<MemoryVariables>,
    ) -> Result<Vec<String>, String> {
        let options = GetOptions {
            include,
            ..GetOptions::default()
        };
        HiiBackend::get_in(
            hiidb,
            question,
            None,
            &options,
            shared(variables),
            None,
            None,
            None,
        )
        .map(|got| {
            got.responses
                .into_iter()
                .map(|response| response.question.answer)
                .collect()
        })
        .map_err(|error| format!("{error:#}"))
    }

    /// What set of `question` in `hiidb` to 1 gives with `include` and UnsafeOperations::Allow
    /// through `variables`, as the CLI prints an error.
    fn set_with(
        hiidb: &[u8],
        question: &str,
        include: IncludedStates,
        variables: &Rc<MemoryVariables>,
    ) -> Result<(), String> {
        let options = SetOptions {
            include,
            unsafe_operations: UnsafeOperations::Allow,
            ..SetOptions::default()
        };
        set_responses(
            hiidb,
            question,
            &SetValue::Text("1".to_owned()),
            None,
            &options,
            SetAccess {
                reads: shared(variables),
                writes: &**variables,
                held: None,
            },
            None,
        )
        .map(drop)
        .map_err(|error| format!("{error:#}"))
    }

    /// edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes skips a FORM under a true
    /// DISABLE_IF outside forms, so no --include and no unsafe operation offers its question
    /// Hidden: get and set answer as for Absent, which the FormSet does not have. Shown, in a form
    /// after it, stays a question.
    #[test]
    fn questions_under_a_true_form_set_disable_if_are_none_of_its_questions() {
        let hiidb = form_set_list_hiidb(&[
            conditional(
                DISABLE_IF,
                ifr_true(),
                &[form(1, &[checkbox_at(1, 1, 1, 0)])],
            ),
            form(2, &[checkbox_at(2, 2, 1, 1)]),
        ]);
        for include in [IncludedStates::empty(), IncludedStates::all()] {
            let variables = setup_holding(&[0; 4]);

            assert_eq!(
                names_and_answers(&hiidb, include, &variables),
                [("Shown".to_owned(), "0".to_owned())],
                "{include:?}: list-questions"
            );
            assert_eq!(
                got_with(&hiidb, "Hidden", include, &variables),
                got_with(&hiidb, "Absent", include, &variables),
                "{include:?}: get Hidden"
            );
            assert_eq!(
                got_with(&hiidb, "Shown", include, &variables),
                Ok(vec!["0".to_owned()]),
                "{include:?}: get Shown"
            );
            let set = set_with(&hiidb, "Hidden", include, &variables);
            assert!(set.is_err(), "{include:?}: set Hidden: {set:?}");
            assert_eq!(
                set.map_err(|error| error.replace("Hidden", "Absent")),
                set_with(&hiidb, "Absent", include, &variables),
                "{include:?}: set Hidden"
            );
            assert_eq!(
                variables.writes_to(&setup()),
                [],
                "{include:?}: writes of set Hidden"
            );
            assert_eq!(
                set_with(&hiidb, "Shown", include, &variables),
                Ok(()),
                "{include:?}: set Shown"
            );
            assert_eq!(
                variables.writes_to(&setup()),
                [(1, vec![1])],
                "{include:?}: writes of set Shown"
            );
        }
    }

    /// --keyword finds a statement in a form under a true DISABLE_IF outside forms, also in a
    /// false SUPPRESS_IF there, as edk2-stable202608 HiiDatabaseDxe/ConfigKeywordHandler.c, which
    /// evaluates no condition, finds it: get and set select it as a disabled question.
    #[test]
    fn a_keyword_selects_a_question_under_a_true_form_set_disable_if_as_disabled() {
        let hidden = || form(1, &[checkbox_at(1, 1, 1, 0)]);
        for (shape, held) in [
            ("in the DISABLE_IF", hidden()),
            (
                "in a false SUPPRESS_IF in the DISABLE_IF",
                conditional(SUPPRESS_IF, ifr_false(), &[hidden()]),
            ),
        ] {
            let packages = [
                form_package(&[
                    var_store_efi(1, "Setup", NV_BS_RT, 4),
                    conditional(DISABLE_IF, ifr_true(), &[held]),
                ]),
                en_strings_package_of(&["Hidden"]),
                strings_package_of(b"x-UEFI-ns", &["HiddenKeyword"]),
                END_PACKAGE.to_vec(),
            ];
            let hiidb = package_list_with_guid([0x55; 16], &packages.concat());
            for (include, selected) in [
                (IncludedStates::empty(), false),
                (IncludedStates::DISABLED, true),
            ] {
                let variables = setup_holding(&[0; 4]);
                let options = GetOptions {
                    include,
                    ..GetOptions::default()
                };
                let got = HiiBackend::get_in(
                    &hiidb,
                    by_keyword("HiddenKeyword", None),
                    None,
                    &options,
                    shared(&variables),
                    None,
                    None,
                    None,
                )
                .map(|got| {
                    got.responses
                        .into_iter()
                        .map(|response| response.question.answer)
                        .collect::<Vec<_>>()
                });
                let options = SetOptions {
                    include,
                    ..SetOptions::default()
                };
                let set = set_responses(
                    &hiidb,
                    by_keyword("HiddenKeyword", None),
                    &SetValue::Text("1".to_owned()),
                    None,
                    &options,
                    SetAccess {
                        reads: shared(&variables),
                        writes: &*variables,
                        held: None,
                    },
                    None,
                );
                match selected {
                    true => {
                        assert_eq!(
                            got.map_err(|error| format!("{error:#}")),
                            Ok(vec!["0 <disabled>".to_owned()]),
                            "{shape}: {include:?}: get"
                        );
                        assert!(set.is_ok(), "{shape}: {include:?}: set: {set:?}");
                        assert_eq!(
                            variables.writes_to(&setup()),
                            [(0, vec![1])],
                            "{shape}: {include:?}: writes"
                        );
                    }
                    false => {
                        assert!(got.is_err(), "{shape}: {include:?}: get: {got:?}");
                        assert!(set.is_err(), "{shape}: {include:?}: set: {set:?}");
                        assert_eq!(
                            variables.writes_to(&setup()),
                            [],
                            "{shape}: {include:?}: writes"
                        );
                    }
                }
            }
        }
    }

    /// A condition on a question that ParseOpCodes skips under a true DISABLE_IF outside forms
    /// gives UNDEFINED, as edk2-stable202608 SetupBrowserDxe/Expression.c IdToQuestion finds no
    /// such question, which IsTrue takes as FALSE: Shown is not suppressed, though Hidden's
    /// variable holds 1. Under a false DISABLE_IF, Hidden is a question and Shown suppressed.
    #[test]
    fn a_reference_to_a_question_under_a_true_form_set_disable_if_is_undefined() {
        for (case, disable_if, want_listed) in [
            ("a true DISABLE_IF", ifr_true(), vec![("Shown", "1")]),
            ("a false DISABLE_IF", ifr_false(), vec![("Hidden", "1")]),
        ] {
            let hiidb = form_set_list_hiidb(&[
                conditional(
                    DISABLE_IF,
                    disable_if,
                    &[form(1, &[checkbox_at(1, 1, 1, 0)])],
                ),
                form(
                    2,
                    &[conditional(
                        SUPPRESS_IF,
                        eq_id_val_of(1, 1),
                        &[checkbox_at(2, 2, 1, 1)],
                    )],
                ),
            ]);
            let variables = setup_holding(&[1, 1, 0, 0]);

            let want: Vec<(String, String)> = want_listed
                .iter()
                .map(|&(name, answer)| (name.to_owned(), answer.to_owned()))
                .collect();
            assert_eq!(
                names_and_answers(&hiidb, IncludedStates::empty(), &variables),
                want,
                "{case}: list-questions"
            );
        }
    }

    /// Why a DISABLE_IF outside forms on Gate, by an EQ_ID_VAL, may skip the questions in it.
    const NOT_CONSTANT: &str = "it relies on EFI_IFR_EQ_ID_VAL, where a DISABLE_IF outside forms \
                                must only rely on constants (UEFI 2.11 §33.3.8.3.14)";

    /// The refusal of set of After, which conditions may disable for `reason`.
    fn after_undetermined(reason: &str) -> String {
        undetermined_refusal("After", reason)
    }

    /// The refusal of set of `question`, which conditions may disable for `reason`.
    fn undetermined_refusal(question: &str, reason: &str) -> String {
        format!(
            "cannot tell whether question {question:?} is disabled: {reason}; also include \
             disabled questions to select it regardless"
        )
    }

    /// UEFI 2.11 §33.3.8.3.14 has a DISABLE_IF outside forms rely on constants only, and
    /// ParseOpCodes evaluates one on a question before it reads any value: whatever Gate holds,
    /// whether a browser parses After, in a form, Outside, outside forms, or First, in a form in a
    /// false SUPPRESS_IF there, is not known, so set refuses to write any of them unless --include
    /// names the disabled state, and get shows both states.
    #[test]
    fn a_form_set_disable_if_that_is_not_constant_leaves_its_questions_undetermined() {
        let hiidb = form_set_list_hiidb(&[
            form(1, &[checkbox_at(3, 3, 1, 0)]),
            conditional(
                DISABLE_IF,
                eq_id_val_of(3, 1),
                &[
                    form(2, &[checkbox_at(4, 4, 1, 1)]),
                    checkbox_at(6, 6, 1, 2),
                    conditional(
                        SUPPRESS_IF,
                        ifr_false(),
                        &[form(3, &[checkbox_at(5, 5, 1, 3)])],
                    ),
                ],
            ),
        ]);
        for gate in [0, 1] {
            for (question, offset) in [("After", 1), ("Outside", 2), ("First", 3)] {
                let variables = setup_holding(&[gate, 0, 0, 0]);

                assert_eq!(
                    set_with(&hiidb, question, IncludedStates::empty(), &variables),
                    Err(undetermined_refusal(question, NOT_CONSTANT)),
                    "Gate {gate}: set {question}"
                );
                assert_eq!(
                    variables.writes_to(&setup()),
                    [],
                    "Gate {gate}: writes of set {question}"
                );
                assert_eq!(
                    got_with(&hiidb, question, IncludedStates::empty(), &variables),
                    Ok(vec![format!("0 <selectable or disabled: {NOT_CONSTANT}>")]),
                    "Gate {gate}: get {question}"
                );
                assert_eq!(
                    set_with(&hiidb, question, IncludedStates::DISABLED, &variables),
                    Ok(()),
                    "Gate {gate}: set {question}, including disabled questions"
                );
                assert_eq!(
                    variables.writes_to(&setup()),
                    [(offset, vec![1])],
                    "Gate {gate}: writes of set {question}, including disabled questions"
                );
            }
        }
    }

    /// A condition in a form that ParseOpCodes may skip reads a question of that form, which
    /// ParseOpCodes parses with it: After, grayed out where First holds 1, is undetermined by the
    /// DISABLE_IF around its form alone, as where First is in a form before it, and set writes it
    /// with disabled questions included.
    #[test]
    fn a_condition_in_an_undetermined_form_reads_a_question_of_that_form() {
        for (case, same_form) in [
            ("First in After's form", true),
            ("First in the form before", false),
        ] {
            let gate = checkbox_at(3, 3, 1, 0);
            let first = checkbox_at(5, 5, 1, 2);
            let after = conditional(GRAY_OUT_IF, eq_id_val_of(5, 1), &[checkbox_at(4, 4, 1, 1)]);
            let (gate_form, after_form) = match same_form {
                true => (form(1, &[gate]), form(2, &[first, after])),
                false => (form(1, &[gate, first]), form(2, &[after])),
            };
            let hiidb = form_set_list_hiidb(&[
                gate_form,
                conditional(DISABLE_IF, eq_id_val_of(3, 1), &[after_form]),
            ]);
            let variables = setup_holding(&[0; 4]);

            assert_eq!(
                got_with(&hiidb, "After", IncludedStates::empty(), &variables),
                Ok(vec![format!("0 <selectable or disabled: {NOT_CONSTANT}>")]),
                "{case}: get After"
            );
            assert_eq!(
                set_with(&hiidb, "After", IncludedStates::DISABLED, &variables),
                Ok(()),
                "{case}: set After, including disabled questions"
            );
            assert_eq!(
                variables.writes_to(&setup()),
                [(1, vec![1])],
                "{case}: writes"
            );
        }
    }

    /// Why After may be skipped after a true `op`, which UEFI 2.11 has do `role` instead.
    fn after_true(op: &str, role: &str) -> String {
        after_hiding(op, "TRUE", role)
    }

    /// Why After may be skipped after an `op` whose condition is `condition`, which UEFI 2.11 has
    /// do `role` instead.
    fn after_hiding(op: &str, condition: &str, role: &str) -> String {
        format!(
            "it is after an {op} in the scope of a DISABLE_IF of its FormSet, whose condition is \
             {condition}: edk2-stable202608 SetupBrowserDxe/IfrParse.c takes that condition for \
             the DISABLE_IF's, which may skip the rest of its scope (:1690-1704, :3045-3059), \
             where UEFI 2.11 {role}"
        )
    }

    /// ParseOpCodes takes the condition of a SUPPRESS_IF, GRAY_OUT_IF or VALUE in the scope of a
    /// DISABLE_IF outside forms for the DISABLE_IF's, so a true one skips the rest of that scope,
    /// After, in the DISABLE_IFs nested there too, unless a DISABLE_IF ends between them
    /// (:2654-2655, :3007-3014), where UEFI 2.11 has it only hide, gray out or give a value; so
    /// may one whose condition is not known: whether a browser parses After is not known, so set
    /// refuses to write it. First, before it, is a question, as After is after a false
    /// SUPPRESS_IF, without one, and after a DISABLE_IF that holds a true one, as ParseOpCodes
    /// skips to that DISABLE_IF's END only (:1395-1410).
    #[test]
    fn a_suppress_if_in_a_form_set_disable_if_leaves_the_forms_after_it_undetermined() {
        let first = || form(1, &[checkbox_at(5, 5, 1, 0)]);
        let after = || form(2, &[checkbox_at(4, 4, 1, 1)]);
        let after_suppress_if = after_true("EFI_IFR_SUPPRESS_IF", "§33.3.8.3.75 has it only hide");
        let after_value = after_true("EFI_IFR_VALUE", "§33.3.8.3.88 has it only give a value");
        // Outside, a CHECKBOX outside forms whose scope holds a VALUE of TRUE
        let outside_with_value = || {
            let mut outside = checkbox_at(6, 6, 1, 2);
            outside[1] |= 0x80;
            [outside, value_of(ifr_true()), END.to_vec()].concat()
        };
        for (case, list, want_set) in [
            (
                "after a true SUPPRESS_IF",
                vec![first(), conditional(SUPPRESS_IF, ifr_true(), &[]), after()],
                Err(after_undetermined(&after_suppress_if)),
            ),
            (
                "after a true GRAY_OUT_IF",
                vec![first(), conditional(GRAY_OUT_IF, ifr_true(), &[]), after()],
                Err(after_undetermined(&after_true(
                    "EFI_IFR_GRAY_OUT_IF",
                    "§33.3.8.3.28 has it only gray out",
                ))),
            ),
            (
                "a true SUPPRESS_IF, then After in an inner DISABLE_IF",
                vec![
                    first(),
                    conditional(SUPPRESS_IF, ifr_true(), &[]),
                    conditional(DISABLE_IF, ifr_false(), &[after()]),
                ],
                Err(after_undetermined(&after_suppress_if)),
            ),
            (
                "a true SUPPRESS_IF in an inner DISABLE_IF, then After",
                vec![
                    first(),
                    conditional(
                        DISABLE_IF,
                        ifr_false(),
                        &[conditional(SUPPRESS_IF, ifr_true(), &[])],
                    ),
                    after(),
                ],
                Ok(()),
            ),
            (
                "a DISABLE_IF ends, then a true SUPPRESS_IF, then After",
                vec![
                    conditional(DISABLE_IF, ifr_false(), &[first()]),
                    conditional(SUPPRESS_IF, ifr_true(), &[]),
                    after(),
                ],
                Ok(()),
            ),
            (
                "a DISABLE_IF in First's form ends, then a true SUPPRESS_IF, then After",
                vec![
                    form(
                        1,
                        &[conditional(
                            DISABLE_IF,
                            ifr_false(),
                            &[checkbox_at(5, 5, 1, 0)],
                        )],
                    ),
                    conditional(SUPPRESS_IF, ifr_true(), &[]),
                    after(),
                ],
                Ok(()),
            ),
            (
                "a true DISABLE_IF ends, then a true SUPPRESS_IF, then After",
                vec![
                    first(),
                    conditional(
                        DISABLE_IF,
                        ifr_true(),
                        &[form(3, &[checkbox_at(1, 1, 1, 2)])],
                    ),
                    conditional(SUPPRESS_IF, ifr_true(), &[]),
                    after(),
                ],
                Ok(()),
            ),
            (
                "a true SUPPRESS_IF, then a DISABLE_IF ends, then After",
                vec![
                    first(),
                    conditional(SUPPRESS_IF, ifr_true(), &[]),
                    conditional(
                        DISABLE_IF,
                        ifr_false(),
                        &[form(3, &[checkbox_at(1, 1, 1, 2)])],
                    ),
                    after(),
                ],
                Err(after_undetermined(&after_suppress_if)),
            ),
            (
                "a DISABLE_IF ends, then After after a true SUPPRESS_IF in another",
                vec![
                    first(),
                    conditional(
                        DISABLE_IF,
                        ifr_false(),
                        &[form(3, &[checkbox_at(1, 1, 1, 2)])],
                    ),
                    conditional(
                        DISABLE_IF,
                        ifr_false(),
                        &[conditional(SUPPRESS_IF, ifr_true(), &[]), after()],
                    ),
                ],
                Err(after_undetermined(&after_suppress_if)),
            ),
            (
                "after a VALUE of TRUE in a question outside forms",
                vec![first(), outside_with_value(), after()],
                Err(after_undetermined(&after_value)),
            ),
            (
                "after a VALUE of TRUE outside forms",
                vec![first(), value_of(ifr_true()), after()],
                Err(after_undetermined(&after_value)),
            ),
            (
                "a DISABLE_IF ends, then a VALUE of TRUE outside forms, then After",
                vec![
                    first(),
                    conditional(
                        DISABLE_IF,
                        ifr_false(),
                        &[form(3, &[checkbox_at(1, 1, 1, 2)])],
                    ),
                    value_of(ifr_true()),
                    after(),
                ],
                Ok(()),
            ),
            (
                "after a SUPPRESS_IF that is not constant",
                vec![
                    first(),
                    conditional(SUPPRESS_IF, eq_id_val_of(5, 1), &[]),
                    after(),
                ],
                Err(after_undetermined(&after_hiding(
                    "EFI_IFR_SUPPRESS_IF",
                    &format!("not known: {NOT_CONSTANT}"),
                    "§33.3.8.3.75 has it only hide",
                ))),
            ),
            (
                "after a false SUPPRESS_IF",
                vec![first(), conditional(SUPPRESS_IF, ifr_false(), &[]), after()],
                Ok(()),
            ),
            ("without a SUPPRESS_IF", vec![first(), after()], Ok(())),
        ] {
            let hiidb = form_set_list_hiidb(&[conditional(DISABLE_IF, ifr_false(), &list)]);
            let variables = setup_holding(&[0; 4]);

            assert_eq!(
                set_with(&hiidb, "First", IncludedStates::empty(), &variables),
                Ok(()),
                "{case}: set First"
            );
            let want_writes = match want_set {
                Ok(()) => vec![(0, vec![1]), (1, vec![1])],
                Err(_) => vec![(0, vec![1])],
            };
            assert_eq!(
                set_with(&hiidb, "After", IncludedStates::empty(), &variables),
                want_set,
                "{case}: set After"
            );
            assert_eq!(variables.writes_to(&setup()), want_writes, "{case}: writes");
        }
    }

    /// A HiiDB with a PASSWORD on AMITSESetup at bytes 0..40 in a form under a true DISABLE_IF
    /// outside forms, and Q, P at byte 80 and O at byte 10, inside the password's bytes, in a form
    /// after it. `password_store` declares AMITSESetup as VarStore 2 in that DISABLE_IF's scope,
    /// or before it if None; then VarStore 5 declares it again after the DISABLE_IF, for P. O is
    /// on VarStore `o_store`. Its keywords are its prompts with "Key" after them.
    fn disabled_password_hiidb(password_store: Option<PasswordStore>, o_store: u16) -> Vec<u8> {
        let amitse_setup = |id| var_store(id, [0x44; 16], "AMITSESetup", 81);
        let password_form = form(2, &[password_on(3, 3, 2, 0)]);
        let (before, disabled, after, p_store) = match password_store {
            None => (
                vec![amitse_setup(2)],
                conditional(DISABLE_IF, ifr_true(), &[password_form]),
                vec![],
                2,
            ),
            Some(PasswordStore::InTheDisableIf) => (
                vec![],
                conditional(DISABLE_IF, ifr_true(), &[amitse_setup(2), password_form]),
                vec![amitse_setup(5)],
                5,
            ),
            Some(PasswordStore::InANestedDisableIf) => (
                vec![],
                conditional(
                    DISABLE_IF,
                    ifr_false(),
                    &[conditional(
                        DISABLE_IF,
                        ifr_true(),
                        &[amitse_setup(2), password_form],
                    )],
                ),
                vec![amitse_setup(5)],
                5,
            ),
        };
        let questions = form(
            1,
            &[
                checkbox_on(1, 1, 1),
                checkbox_at(2, 2, p_store, 80),
                checkbox_at(4, 4, o_store, 10),
            ],
        );
        let ifr = [
            vec![var_store_efi(1, "Setup", NV_BS_RT, 1)],
            before,
            vec![disabled],
            after,
            vec![questions],
        ]
        .concat();
        let packages = [
            form_package(&ifr),
            en_strings_package_of(&["Q", "P", "Password", "O"]),
            strings_package_of(b"x-UEFI-ns", &["QKey", "PKey", "PasswordKey", "OKey"]),
            END_PACKAGE.to_vec(),
        ];
        package_list_with_guid([0x55; 16], &packages.concat())
    }

    /// Where disabled_password_hiidb declares the PASSWORD's VarStore.
    #[derive(Debug, Clone, Copy)]
    enum PasswordStore {
        /// In the true DISABLE_IF's scope
        InTheDisableIf,
        /// In the scope of a true DISABLE_IF nested in a false one
        InANestedDisableIf,
    }

    /// A PASSWORD in a form under a true DISABLE_IF outside forms keeps its bytes withheld,
    /// whatever the reach and wherever its VarStore is declared: O, whose bytes overlap them, is
    /// read and written by no prompt and no keyword, with every --include and
    /// UnsafeOperations::Allow, while P is.
    #[test]
    fn a_password_under_a_true_form_set_disable_if_stays_withheld() {
        let withheld = format!("{PASSWORD_BYTES} <IFR default: 0>");
        let no_store_2 = "<ValueUnavailable: no supported varstore with matching id 0x0002 found> \
                          <IFR default: 0>";
        let password_bytes = "holds a password at bytes 0..40, which set never writes";
        let no_var_store = "no supported varstore with matching id 0x0002";
        for (case, password_store, o_store, want_o, want_refusal) in [
            (
                "its VarStore before the DISABLE_IF",
                None,
                2,
                withheld.as_str(),
                password_bytes,
            ),
            (
                "its VarStore in the DISABLE_IF, O on the later one",
                Some(PasswordStore::InTheDisableIf),
                5,
                withheld.as_str(),
                password_bytes,
            ),
            (
                "its VarStore in the DISABLE_IF, O on it",
                Some(PasswordStore::InTheDisableIf),
                2,
                no_store_2,
                no_var_store,
            ),
            (
                "its VarStore in a nested DISABLE_IF, O on the later one",
                Some(PasswordStore::InANestedDisableIf),
                5,
                withheld.as_str(),
                password_bytes,
            ),
            (
                "its VarStore in a nested DISABLE_IF, O on it",
                Some(PasswordStore::InANestedDisableIf),
                2,
                no_store_2,
                no_var_store,
            ),
        ] {
            let hiidb = disabled_password_hiidb(password_store, o_store);
            for (reach, interface) in [
                (VariableReach::Runtime, VariableInterface::Efivarfs),
                (
                    VariableReach::BootServices,
                    VariableInterface::VariableServices,
                ),
            ] {
                let variables = password_variables(reach, interface);
                let options = GetOptions {
                    include: IncludedStates::all(),
                    ..GetOptions::default()
                };
                let keyword_got = HiiBackend::get_in(
                    &hiidb,
                    by_keyword("OKey", None),
                    None,
                    &options,
                    shared(&variables),
                    None,
                    None,
                    None,
                )
                .map(|got| {
                    got.responses
                        .into_iter()
                        .map(|response| response.question.answer)
                        .collect::<Vec<_>>()
                })
                .map_err(|error| format!("{error:#}"));
                let options = SetOptions {
                    include: IncludedStates::all(),
                    unsafe_operations: UnsafeOperations::Allow,
                    ..SetOptions::default()
                };
                let keyword_set = set_responses(
                    &hiidb,
                    by_keyword("OKey", None),
                    &SetValue::Text("1".to_owned()),
                    None,
                    &options,
                    SetAccess {
                        reads: shared(&variables),
                        writes: &*variables,
                        held: None,
                    },
                    None,
                )
                .map(drop)
                .map_err(|error| format!("{error:#}"));

                assert_eq!(
                    got_with(&hiidb, "O", IncludedStates::all(), &variables),
                    Ok(vec![want_o.to_owned()]),
                    "{case}, {reach:?}: get O"
                );
                assert_eq!(
                    keyword_got,
                    Ok(vec![want_o.to_owned()]),
                    "{case}, {reach:?}: get OKey"
                );
                let listed = names_and_answers(&hiidb, IncludedStates::all(), &variables);
                assert!(
                    listed.contains(&("O".to_owned(), want_o.to_owned())),
                    "{case}, {reach:?}: list-questions O: {listed:?}"
                );
                let set = set_with(&hiidb, "O", IncludedStates::all(), &variables);
                assert!(
                    set.as_ref()
                        .is_err_and(|error| error.contains(want_refusal)),
                    "{case}, {reach:?}: set O: {set:?}"
                );
                assert!(
                    keyword_set
                        .as_ref()
                        .is_err_and(|error| error.contains(want_refusal)),
                    "{case}, {reach:?}: set OKey: {keyword_set:?}"
                );
                assert_eq!(
                    set_with(&hiidb, "P", IncludedStates::all(), &variables),
                    Ok(()),
                    "{case}, {reach:?}: set P"
                );
                assert_eq!(
                    variables.bytes(&amitse_setup()),
                    Some([&NV_BS_RT.to_ne_bytes()[..], &[0xAA; 80], &[1]].concat()),
                    "{case}, {reach:?}: AMITSESetup keeps its password bytes"
                );
            }
        }
    }
}
