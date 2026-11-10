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
use std::fmt::Write;
use std::rc::Rc;

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
pub use crate::efi_variables::authenticated::SetupModeWrite;
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
use crate::hii::forms::Exclusion;
use crate::hii::forms::PasswordQuestions;
use crate::hii::forms::QuestionFlags;
use crate::hii::package;
#[cfg(any(variable_names, variable_info, variable_data))]
pub use crate::hii::package::Guid;
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
use crate::hii::VOLATILE_ANNOTATION;
#[cfg(variable_data)]
use crate::secret_file::Secret;
use crate::translation::get_qa_variations_hii;
use crate::translation::translate_response;
use crate::translation::HiiTranslation;

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
pub use crate::hii::forms::SetupPasswordPolicy;
pub use crate::hii::VolatileWrites;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "uefi")]
mod uefi;
#[cfg(target_os = "windows")]
mod windows;

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
    /// "8BE4DF61-93CA-11D2-AA0D-00E098032B8C", without its data, which only the Windows build
    /// reads.
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

    /// Sets the global variable `name` to `value`, as set does, to make the Secure Boot mode
    /// transition `transition` of UEFI 2.11 §32.3, which only the UEFI Shell build makes, as
    /// AuditMode and DeployedMode each "Always becomes read-only after ExitBootServices() is
    /// called" (§3.3). Refuses, before it opens the variables, another variable or value and the
    /// builds that run after ExitBootServices(), and, before any write, a transition that the
    /// current mode does not allow; returns what it wrote and what SetVariable() returned.
    pub fn set_mode(
        name: &str,
        value: &str,
        transition: ModeTransition,
    ) -> Result<ModeTransitionWrite> {
        let request = ModeRequest::new(transition, Self::SYSTEM_VARIABLE_REACH, name, value)?;
        set_mode(&Self::system_variable_data()?, request)
    }

    /// Writes `payload`, an EFI_VARIABLE_AUTHENTICATION_2 descriptor and the new data of the EFI
    /// variable `name` of the vendor GUID `vendor`, such as
    /// "8BE4DF61-93CA-11D2-AA0D-00E098032B8C" (UEFI 2.11 §8.2.6), with `attributes` and
    /// EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS; the firmware verifies its signature.
    /// Refuses, before any write, other attributes, a payload without a complete descriptor,
    /// attributes without access or a payload that would delete the variable, and, unless
    /// `setup_mode` allows it, a Secure Boot Policy Variable or a device signature database (any
    /// variable of EFI_DEVICE_SECURITY_DATABASE_GUID) in Setup Mode.
    pub fn write_signed(
        name: &str,
        vendor: &str,
        attributes: VariableAttributes,
        payload: &[u8],
        setup_mode: SetupModeWrite,
    ) -> Result<()> {
        let key = VariableKey {
            name: name.to_owned(),
            guid: parse_vendor(vendor)?,
        };
        write_signed(
            &Self::system_variable_data()?,
            &key,
            attributes,
            payload,
            setup_mode,
        )
    }

    /// Signs `write` with the PEM RSA key `signing_key` into an EFI_VARIABLE_AUTHENTICATION_2
    /// (UEFI 2.11 §8.2.6) that carries `certificates`, a PEM bundle of the key's certificate,
    /// then any others, blinded over this platform's random source (EFI_RNG_PROTOCOL in the UEFI
    /// Shell, getrandom elsewhere), and writes it, then the data. Refuses what write_signed
    /// refuses before it signs.
    pub fn sign_and_write(
        write: &SignedVariableWrite<'_>,
        signing_key: &Secret,
        certificates: &[u8],
    ) -> Result<()> {
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
                setup_mode: write.setup_mode,
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
    /// Secure Boot Policy Variable, a write that would delete the variable, a device signature
    /// database while SetupMode is 1 unless `write` allows it, and, on Linux, every such write,
    /// which efivarfs cannot make.
    pub fn sign_and_write_enhanced(
        write: &EnhancedVariableWrite<'_>,
        signing_key: &Secret,
        certificates: &[u8],
    ) -> Result<()> {
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
                setup_mode: write.setup_mode,
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
    /// Whether a device signature database is written while SetupMode is 1
    pub setup_mode: SetupModeWrite,
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
    /// Whether a Secure Boot Policy Variable or a device signature database (any variable of
    /// EFI_DEVICE_SECURITY_DATABASE_GUID) is written while SetupMode is 1
    pub setup_mode: SetupModeWrite,
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

/// The options of HiiBackend::set_using.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct SetOptions {
    /// The states of the questions and options to select too
    pub include: IncludedStates,
    /// The AMI Setup access level that conditions read instead of the stored one, if stated
    pub access_level: Option<AccessLevel>,
    /// In the UEFI Shell, whether set writes in a HiiDB that declares a setup password question
    pub setup_password: SetupPasswordPolicy,
    /// Whether set writes a volatile variable: only through variables that reach BootServices, as
    /// in the UEFI Shell
    pub volatile: VolatileWrites,
    /// The language to show texts in instead of the platform language (PlatformLang), if stated
    pub language: Option<String>,
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
    ) -> Result<HiiShowIfrResponse> {
        // We depend on the caller to provide us with the hiidb instead of calling extract here
        // because they might want to provide a file instead.

        let mut readable_representation = String::new();

        let (parsed_db, mut reader) = read_db_withholding(db_bytes, variables, exported)?;

        for list in parsed_db {
            list.check_form_strings()?;
            // no header for a list without forms
            if list.forms.is_empty() {
                continue;
            }
            writeln!(readable_representation, "Packagelist {}", list.guid)?;
            let texts = list.texts(&text_languages(options.language.as_deref(), platform_lang));
            reader.enter_package_list(&list, &texts);
            for root in &list.forms {
                readable_representation.push_str(&forms::display(
                    Rc::clone(root),
                    0,
                    &texts,
                    &mut reader,
                )?);
            }
        }

        let resp = HiiShowIfrResponse {
            readable_representation,
            ..Default::default()
        };
        Ok(resp)
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
            .into_iter()
            .flat_map(|list| list.ignored_ifr)
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
            .flat_map(|list| list.ignored_ifr.iter().cloned())
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
        Self::set_using(question, new_value, selector, &SetOptions::default())
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
    /// set with `options`, in this machine's HiiDB and variables, as set_in does.
    #[cfg(all(system_hiidb, system_variables))]
    pub fn set_using(
        question: impl Into<QuestionSelector>,
        new_value: &str,
        selector: Option<&str>,
        options: &SetOptions,
    ) -> Result<SetResponseList> {
        Self::set_in(
            &Self::system_hiidb()?,
            question,
            new_value,
            selector,
            options,
            EfivarSource::System.into_variables()?,
            &Self::system_variables()?,
            EfivarSource::System.platform_lang()?.as_deref(),
        )
    }

    /// set of the questions that `question` selects in the HiiDB `db_bytes` with `options`,
    /// selecting by the values of `reads`, which it reads before the first write, and writing
    /// through `writes`, neither of them the bytes of password questions
    /// (PasswordQuestions::reader and withholding), on a platform of PlatformLang
    /// `platform_lang`, if any: fails with SelectionError::NotFound when it selects none, and
    /// unless every selected match is written, also after writing the others.
    #[cfg_attr(
        not(system_variables),
        allow(
            dead_code,
            reason = "set writes only the variables of the machine, which this build does not reach"
        )
    )]
    #[expect(
        clippy::too_many_arguments,
        reason = "set's inputs: the HiiDB, the question, the value, the selector, the options, the \
                  variables to read and write, and the platform language"
    )]
    fn set_in(
        db_bytes: &[u8],
        question: impl Into<QuestionSelector>,
        new_value: &str,
        _selector: Option<&str>,
        options: &SetOptions,
        reads: Box<dyn FirmwareVariables>,
        writes: &dyn FirmwareVariables,
        platform_lang: Option<&str>,
    ) -> Result<SetResponseList> {
        // TODO: use selector to only change values which match question + selector
        let include = options.include;

        let mut resp = Vec::new();

        let parsed_db = package::read_db(db_bytes)?;
        let ignored_ifr = listed_ignored_ifr(&parsed_db)?;
        let passwords = PasswordQuestions::of_lists(&parsed_db);
        let mut reader = passwords.reader(reads)?;
        let writes = passwords.withholding(writes)?;
        passwords.check_set(writes.reach(), options.setup_password)?;

        let question = question.into();
        let name = question.to_string();
        let (question_variations, new_value_variations, is_translated) =
            spellings(&question, new_value);

        let selected = select_for_set(
            &parsed_db,
            &question,
            &question_variations,
            options,
            &text_languages(options.language.as_deref(), platform_lang),
            &mut reader,
        )?;

        let annotations: Vec<(String, bool)> = forms::set_questions(
            &name,
            &selected
                .iter()
                .map(|(guid, question_descriptor, _)| (guid.as_str(), question_descriptor))
                .collect::<Vec<_>>(),
            new_value,
            &new_value_variations,
            include,
            &mut reader,
            options.access_level,
            options.volatile,
            &writes,
        )?
        .into_iter()
        .map(|written| {
            let option_annotation = written
                .option
                .map_or_else(String::new, |option| option.state.option_annotation());
            (option_annotation, written.volatile)
        })
        .collect();

        for ((guid, question_descriptor, state), (option_annotation, volatile)) in
            selected.into_iter().zip(annotations)
        {
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
                    answer: new_value.to_owned()
                        + &option_annotation
                        + &state.annotation()
                        + volatile_annotation,
                    ..question_of(question_descriptor, include)
                },
                modified: true,
                ..Default::default()
            };

            resp.push(set_resp);
        }

        Ok(SetResponseList {
            responses: resp,
            ignored_ifr,
            ..Default::default()
        })
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
        )
    }

    /// get with `options`, reading question values from `variables`, or from the snapshot
    /// `exported` where they miss a variable, on a platform of PlatformLang `platform_lang`, if
    /// any
    fn get_in(
        db_bytes: &[u8],
        question: impl Into<QuestionSelector>,
        _selector: Option<&str>,
        options: &GetOptions,
        variables: Box<dyn FirmwareVariables>,
        exported: Option<ExportedConfig>,
        platform_lang: Option<&str>,
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
        for list in &parsed_db {
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
                let mut get_resp = GetResponse {
                    selector: list.guid.to_string(),
                    backend: Backend::Hii,
                    is_translated,
                    question: question_of(question_descriptor, include),
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
    let reader = passwords.reader(variables)?;
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

/// set's phase before its first write, so that no error follows a write: checks every package
/// list of `parsed_db`, the stated access level and that `question` is unambiguous
/// (check_unambiguous), then
/// selects, in each FormSet, the question of `question` that set writes, by prompt any of
/// `question_variations`, its texts shown in the languages `requested` takes
/// (ParsedPackageList::texts), reading each range once with `reader`; returns them with the
/// GUID of their package list, or SelectionError::Excluded for `question` if each FormSet skips
/// it for its states, or else MaybeInIgnoredIfr if none holds it and read_db ignores IFR of
/// `parsed_db`.
fn select_for_set(
    parsed_db: &[package::ParsedPackageList],
    question: &QuestionSelector,
    question_variations: &BTreeSet<String>,
    options: &SetOptions,
    requested: &[&str],
    reader: &mut EfivarReader,
) -> Result<Vec<(String, forms::QuestionDescriptor, forms::StateEvaluation)>> {
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
    for list in parsed_db {
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
            // set may include every state, READ_ONLY too
            match forms::choice_for_set(
                selection,
                &question.to_string(),
                options,
                IncludedStates::all(),
                reader,
            )? {
                Choice::Chosen(question_descriptor, state) => {
                    selected.push((list.guid.to_string(), question_descriptor, state));
                }
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
        .flat_map(|list| &list.ignored_ifr)
        .peekable();
    if selected.is_empty() && ignored.peek().is_some() {
        return Err(SelectionError::MaybeInIgnoredIfr {
            question: question.to_string(),
            ignored: ignored.cloned().collect(),
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
        .flat_map(|list| &list.ignored_ifr)
        .map(|ignored| {
            Ok(HiiIgnoredIfr {
                package_list: ignored.package_list.to_string(),
                offset: i64::try_from(ignored.offset)
                    .context("the offset of ignored IFR does not fit an i64")?,
                reason: ignored.reason.clone(),
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

#[cfg(test)]
mod tests {
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
    use crate::hii::forms::ifr_fixtures::form;
    use crate::hii::forms::ifr_fixtures::form_set;
    use crate::hii::forms::ifr_fixtures::ifr_default;
    use crate::hii::forms::ifr_fixtures::ifr_default_2;
    use crate::hii::forms::ifr_fixtures::ifr_false;
    use crate::hii::forms::ifr_fixtures::ifr_true;
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
    use crate::hii::forms::ifr_fixtures::subtitle_scope;
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
    use crate::hii::forms::ifr_fixtures::DISABLE_IF;
    use crate::hii::forms::ifr_fixtures::END;
    use crate::hii::forms::ifr_fixtures::GRAY_OUT_IF;
    use crate::hii::forms::ifr_fixtures::GUID;
    use crate::hii::forms::ifr_fixtures::NIL_GUID;
    use crate::hii::forms::ifr_fixtures::NUMERIC;
    use crate::hii::forms::ifr_fixtures::NV_BS;
    use crate::hii::forms::ifr_fixtures::NV_BS_RT;
    use crate::hii::forms::ifr_fixtures::ONE_OF;
    use crate::hii::forms::ifr_fixtures::OTHER_GUID;
    use crate::hii::forms::ifr_fixtures::QUESTION_REF1;
    use crate::hii::forms::ifr_fixtures::READ;
    use crate::hii::forms::ifr_fixtures::SHORT_VAR_STORE_GUID;
    use crate::hii::forms::ifr_fixtures::SUPPRESS_IF;
    use crate::hii::forms::ifr_fixtures::SYSTEM_ACCESS_GUID;
    use crate::hii::forms::ifr_fixtures::THIS;
    use crate::hii::forms::ifr_fixtures::VALUE;
    use crate::hii::forms::ifr_fixtures::VAR_STORE;
    use crate::hii::forms::MAX_SCOPE_NESTING;
    use crate::hii::package::hiidb_fixtures::device_path_package;
    use crate::hii::package::hiidb_fixtures::en_strings_list;
    use crate::hii::package::hiidb_fixtures::en_strings_package;
    use crate::hii::package::hiidb_fixtures::en_strings_package_of;
    use crate::hii::package::hiidb_fixtures::form_package;
    use crate::hii::package::hiidb_fixtures::form_package_of;
    use crate::hii::package::hiidb_fixtures::form_package_with_guid;
    use crate::hii::package::hiidb_fixtures::form_set_package;
    use crate::hii::package::hiidb_fixtures::package_list_with_guid;
    use crate::hii::package::hiidb_fixtures::strings_package_of;
    use crate::hii::package::hiidb_fixtures::END_PACKAGE;
    use crate::hii::package::Guid;
    use crate::hii::VariableAttributes;
    #[cfg(variable_data)]
    use crate::secret_file::read_secret_file;
    #[cfg(variable_data)]
    use crate::secret_file::MAX_SECRET_LEN;

    use super::*;

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
            setup_mode: SetupModeWrite::Refuse,
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
        )
        .expect("get BootEnable");
        let set = HiiBackend::set_in(
            &hiidb,
            "BootEnable",
            "1",
            None,
            &SetOptions::default(),
            shared(&variables),
            &*variables,
            None,
        );
        let keyword_writes = variables.writes_to(&setup());
        let boot = HiiBackend::set_in(
            &hiidb,
            "Boot",
            "1",
            None,
            &SetOptions::default(),
            shared(&variables),
            &*variables,
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
        );
        let set = HiiBackend::set_in(
            &crossed_prompts_hiidb(),
            "Boot",
            "1",
            None,
            &SetOptions::default(),
            shared(&variables),
            &*variables,
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

        HiiBackend::set_in(
            &hiidb,
            "Mode",
            "Enabled",
            None,
            &SetOptions::default(),
            shared(&variables),
            &*variables,
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

    /// set refuses a VALUE that no one language holds as the text of every option it names,
    /// naming each, and writes nothing.
    #[test]
    fn set_refuses_a_value_of_different_options_in_different_languages() {
        let hiidb = mode_hiidb(["Mode", "Off", "Stop"], ["Mode", "Arr\u{ea}t", "Off"]);
        let variables = Rc::new(MemoryVariables::default());
        variables.insert(setup(), 7, &[1]);

        let got = HiiBackend::set_in(
            &hiidb,
            "Mode",
            "Off",
            None,
            &SetOptions::default(),
            shared(&variables),
            &*variables,
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
        )
        .expect("get Keyed");
        let set = HiiBackend::set_in(
            &keyed_hiidb("Keyed"),
            "Keyed",
            "1",
            None,
            &SetOptions::default(),
            shared(&variables),
            &*variables,
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
        )
        .unwrap_or_else(|error| panic!("get {question}: {error}"));
        let set = HiiBackend::set_in(
            &keyed_hiidb(""),
            question.clone(),
            "1",
            None,
            &SetOptions::default(),
            shared(&variables),
            &*variables,
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
            )
            .map(|got| got.responses.len())
            .map_err(|error| format!("{error:#}"));
            let set = HiiBackend::set_in(
                &hiidb,
                question.clone(),
                "1",
                None,
                &SetOptions::default(),
                shared(&variables),
                &*variables,
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
        let list = |form_set: &str, offset: u16, prompt: &str, namespace: &[u8], guid: u8| {
            let packages = [
                form_package_with_guid(
                    guid_bytes(form_set),
                    &[
                        var_store_efi(1, "Setup", NV_BS_RT, 2),
                        form(1, &[checkbox_at(0xA, 1, 1, offset)]),
                    ],
                ),
                strings_package_of(b"en-US", &[prompt]),
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
        let identified = |question: &Question| (question.name.clone(), question.question_id);
        let variables = Rc::new(MemoryVariables::default());
        variables.insert(setup(), 7, &[0, 0]);

        let got = HiiBackend::get_in(
            hiidb,
            question.clone(),
            None,
            &GetOptions::default(),
            shared(&variables),
            None,
            None,
        );
        let set = HiiBackend::set_in(
            hiidb,
            question.clone(),
            "1",
            None,
            &SetOptions::default(),
            shared(&variables),
            &*variables,
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
        );
        let set = HiiBackend::set_in(
            &conditioned_keyed_hiidb(),
            question.clone(),
            "1",
            None,
            &SetOptions {
                include,
                ..SetOptions::default()
            },
            shared(&variables),
            &*variables,
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
        flag_refusal_with(question, "read-only", then)
    }

    /// flag_refusal, naming `states` as the ones that write `question`.
    fn flag_refusal_with(question: &str, states: &str, then: &str) -> Result<(), String> {
        Err(format!(
            "cannot set question {question:?}: EFI_IFR_FLAG_READ_ONLY makes it read-only (UEFI \
             2.11 §33.3.8.2.2); also include {states} questions to write it{then}"
        ))
    }

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
    /// writable one, with read-only included or not, as select prefers a selectable match to a
    /// grayed-out one.
    #[test]
    fn set_writes_the_writable_twin_of_a_read_only_question() {
        let hiidb = one_form_list(
            [0x66; 16],
            "T",
            &[numeric_at(1, 0, 0x01), numeric_at(2, 1, 0)],
        );
        for include in [IncludedStates::empty(), IncludedStates::READ_ONLY] {
            let (got, writes) = set_to_9(&hiidb, "T", include);
            assert_eq!(got, Ok(()), "set T --include {include}");
            assert_eq!(writes, [(1, vec![9])], "set T --include {include}: writes");
        }
    }

    /// set refuses a question that EFI_IFR_FLAG_READ_ONLY makes read-only before any write,
    /// whichever condition states it includes, and writes it with read-only included.
    #[test]
    fn flag_is_refused_unless_read_only_is_included() {
        let hiidb = one_form_list([0x68; 16], "R", &[numeric_at(1, 0, 0x01)]);
        let cases = [
            (IncludedStates::empty(), flag_refusal("R", ""), vec![]),
            (IncludedStates::CONDITIONS, flag_refusal("R", ""), vec![]),
            (IncludedStates::READ_ONLY, Ok(()), vec![(0, vec![9])]),
        ];
        for (include, want, want_writes) in cases {
            let (got, writes) = set_to_9(&hiidb, "R", include);
            assert_eq!(got, want, "set R --include {include}");
            assert_eq!(writes, want_writes, "set R --include {include}: writes");
        }
    }

    /// select ranks a read-only match after a writable one in any state: of "T" read-only at byte
    /// 0 and "T" grayed out at byte 1, set writes the grayed-out one once grayed-out is
    /// included, read-only too or not; with neither, its refusal names both ways.
    #[test]
    fn read_only_ranks_after_the_condition_states() {
        let hiidb = one_form_list(
            [0x69; 16],
            "T",
            &[numeric_at(1, 0, 0x01), grayed_out(&[numeric_at(2, 1, 0)])],
        );
        let both = IncludedStates::GRAYED_OUT | IncludedStates::READ_ONLY;
        let cases = [
            (
                IncludedStates::empty(),
                flag_refusal("T", ", or grayed-out questions to select a writable one"),
                vec![],
            ),
            (IncludedStates::READ_ONLY, Ok(()), vec![(0, vec![9])]),
            (IncludedStates::GRAYED_OUT, Ok(()), vec![(1, vec![9])]),
            (both, Ok(()), vec![(1, vec![9])]),
        ];
        for (include, want, want_writes) in cases {
            let (got, writes) = set_to_9(&hiidb, "T", include);
            assert_eq!(got, want, "set T --include {include}");
            assert_eq!(writes, want_writes, "set T --include {include}: writes");
        }
    }

    /// An EFI_IFR_VALUE makes a question read-only whatever set includes, EFI_IFR_FLAG_READ_ONLY
    /// set or not; set writes a writable twin instead.
    #[test]
    fn value_is_refused_whatever_is_included() {
        for flags in [0x00, 0x01] {
            let hiidb = one_form_list([0x6A; 16], "V", &[value_numeric(1, 0, flags)]);
            for include in [
                IncludedStates::empty(),
                IncludedStates::READ_ONLY,
                IncludedStates::all(),
            ] {
                let (got, writes) = set_to_9(&hiidb, "V", include);
                let case = format!("set V (Flags {flags:#04x}) --include {include}");
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
    /// include to select a twin that set writes, but not those that set includes: a grayed-out
    /// writable one, or a grayed-out one that EFI_IFR_FLAG_READ_ONLY makes read-only, with
    /// read-only too.
    #[test]
    fn value_refusal_names_the_states_of_a_twin_that_set_writes() {
        let refusal = |states: &str| {
            value_refusal(
                "V",
                &format!("; also include {states} questions to select one that set writes"),
            )
        };
        let both = IncludedStates::GRAYED_OUT | IncludedStates::READ_ONLY;
        let cases = [
            (
                "a writable twin",
                0x00,
                IncludedStates::empty(),
                refusal("grayed-out"),
                vec![],
            ),
            (
                "a writable twin",
                0x00,
                IncludedStates::GRAYED_OUT,
                Ok(()),
                vec![(1, vec![9])],
            ),
            (
                "a read-only twin",
                0x01,
                IncludedStates::empty(),
                refusal("grayed-out,read-only"),
                vec![],
            ),
            (
                "a read-only twin",
                0x01,
                IncludedStates::READ_ONLY,
                refusal("grayed-out"),
                vec![],
            ),
            ("a read-only twin", 0x01, both, Ok(()), vec![(1, vec![9])]),
        ];
        for (case, flags, include, want, want_writes) in cases {
            let hiidb = one_form_list(
                [0x73; 16],
                "V",
                &[
                    value_numeric(1, 0, 0),
                    grayed_out(&[numeric_at(2, 1, flags)]),
                ],
            );
            let (got, writes) = set_to_9(&hiidb, "V", include);
            assert_eq!(got, want, "{case}: set V --include {include}");
            assert_eq!(
                writes, want_writes,
                "{case}: set V --include {include}: writes"
            );
        }
    }

    /// Of a "V" that an EFI_IFR_VALUE makes read-only and a "V" that EFI_IFR_FLAG_READ_ONLY does,
    /// select ranks the second first, which set writes with read-only included.
    #[test]
    fn flag_ranks_before_value() {
        let hiidb = one_form_list(
            [0x6F; 16],
            "V",
            &[value_numeric(1, 0, 0), numeric_at(2, 1, 0x01)],
        );
        let cases = [
            (IncludedStates::empty(), flag_refusal("V", ""), vec![]),
            (IncludedStates::READ_ONLY, Ok(()), vec![(1, vec![9])]),
        ];
        for (include, want, want_writes) in cases {
            let (got, writes) = set_to_9(&hiidb, "V", include);
            assert_eq!(got, want, "set V --include {include}");
            assert_eq!(writes, want_writes, "set V --include {include}: writes");
        }
    }

    /// Where one FormSet selects a writable "T" and another a read-only one, set refuses before
    /// it writes either; with read-only included it writes both, in one write of their variable.
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

        let (got, writes) = set_to_9(&hiidb, "T", IncludedStates::READ_ONLY);
        assert_eq!(got, Ok(()), "set T --include read-only");
        assert_eq!(
            writes,
            [(0, vec![9, 9])],
            "set T --include read-only: writes"
        );
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
    /// refuses the second, naming the states that write it and those that select the first, and
    /// writes either with its states included.
    #[test]
    fn undetermined_read_only_refusal_names_a_grayed_out_writable_twin() {
        let hiidb = undetermined_list(
            [0x75; 16],
            &[
                grayed_out(&[numeric_at(2, 1, 0)]),
                conditional(SUPPRESS_IF, eq_id_val_of(3, 1), &[numeric_at(1, 0, 0x01)]),
            ],
        );
        let cases = [
            (
                IncludedStates::empty(),
                flag_refusal_with(
                    "T",
                    "read-only,suppressed",
                    ", or grayed-out questions to select a writable one",
                ),
                vec![],
            ),
            (
                IncludedStates::READ_ONLY | IncludedStates::SUPPRESSED,
                Ok(()),
                vec![(0, vec![9])],
            ),
            (IncludedStates::GRAYED_OUT, Ok(()), vec![(1, vec![9])]),
        ];
        for (include, want, want_writes) in cases {
            let (got, writes) = set_to_9(&hiidb, "T", include);
            assert_eq!(got, want, "set T --include {include}");
            assert_eq!(writes, want_writes, "set T --include {include}: writes");
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
                flag_refusal("T", ", or grayed-out questions to select a writable one"),
                vec![],
            ),
            (IncludedStates::GRAYED_OUT, Ok(()), vec![(1, vec![9])]),
        ];
        for (include, want, want_writes) in cases {
            let (got, writes) = set_to_9(&hiidb, "T", include);
            assert_eq!(got, want, "set T --include {include}");
            assert_eq!(writes, want_writes, "set T --include {include}: writes");
        }
    }

    /// The refusal of an undetermined match that EFI_IFR_FLAG_READ_ONLY makes read-only names
    /// every state that writes it: set writes a "T" that a GRAY_OUT_IF on the unreadable question
    /// 3 may gray out with read-only and grayed-out included, not with read-only alone.
    #[test]
    fn undetermined_read_only_refusal_names_the_states_to_write_it() {
        let hiidb = undetermined_list(
            [0x78; 16],
            &[conditional(
                GRAY_OUT_IF,
                eq_id_val_of(3, 1),
                &[numeric_at(1, 0, 0x01)],
            )],
        );
        let (got, writes) = set_to_9(&hiidb, "T", IncludedStates::empty());
        assert_eq!(
            got,
            flag_refusal_with("T", "read-only,grayed-out", ""),
            "set T"
        );
        assert_eq!(writes, [], "set T: writes");

        let (got, writes) = set_to_9(&hiidb, "T", IncludedStates::READ_ONLY);
        assert!(
            got.as_ref().is_err_and(|error| {
                error.starts_with("cannot tell whether question \"T\" is grayed-out: ")
            }),
            "set T --include read-only: {got:?}"
        );
        assert_eq!(writes, [], "set T --include read-only: writes");

        let both = IncludedStates::READ_ONLY | IncludedStates::GRAYED_OUT;
        let (got, writes) = set_to_9(&hiidb, "T", both);
        assert_eq!(got, Ok(()), "set T --include {both}");
        assert_eq!(writes, [(0, vec![9])], "set T --include {both}: writes");
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

    /// set names the read-only flag of a question whose EFI variable is also missing, as it
    /// refuses a read-only question before the efivar checks.
    #[test]
    fn read_only_precedes_the_efivar_checks() {
        let packages = [
            form_package(&[
                var_store_efi(1, "Missing", NV_BS_RT, 3),
                form(1, &[numeric_at(1, 0, 0x01)]),
            ]),
            en_strings_package_of(&["R"]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x72; 16], &packages.concat());
        let (got, writes) = set_to_9(&hiidb, "R", IncludedStates::empty());
        assert_eq!(got, flag_refusal("R", ""), "set R");
        assert_eq!(writes, [], "set R: writes");
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
            let got = HiiBackend::set_in(
                &defaults_hiidb(),
                name,
                "3",
                None,
                &SetOptions::default(),
                shared(&variables),
                &*variables,
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

    /// set of `question` to 9 in `hiidb`, selecting `include` too, with Setup of 3 bytes.
    fn set_to_9(hiidb: &[u8], question: &str, include: IncludedStates) -> SetOutcome {
        let variables = MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);
        variables.insert(setup(), NV_BS_RT, &[0; 3]);
        let variables = Rc::new(variables);
        let got = HiiBackend::set_in(
            hiidb,
            question,
            "9",
            None,
            &SetOptions {
                include,
                ..SetOptions::default()
            },
            shared(&variables),
            &*variables,
            None,
        );
        (
            got.map(drop).map_err(|error| error.to_string()),
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
    /// is EFI_IFR_FLAG_READ_ONLY, which set writes with read-only included.
    #[test]
    fn set_names_the_question_flags() {
        let options = SetOptions {
            include: IncludedStates::READ_ONLY,
            ..SetOptions::default()
        };
        for (prompt, want) in [("Mixed", want_flags(FLAGGED[0].names)), ("Plain", None)] {
            let variables =
                MemoryVariables::new(VariableReach::Runtime, VariableInterface::Efivarfs);
            variables.insert(setup(), NV_BS_RT, &[0; FLAGGED.len()]);
            let variables = Rc::new(variables);
            let got = HiiBackend::set_in(
                &flags_hiidb(),
                prompt,
                "9",
                None,
                &options,
                shared(&variables),
                &*variables,
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
            .readable_representation;

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
    /// question, refuses unless the caller bypasses; set through those that reach Runtime writes,
    /// as before; whatever their interface and whether volatile writes are allowed. Either writes
    /// P, beside the password.
    #[test]
    fn set_follows_the_setup_password_policy() {
        let refusal = "this HiiDB declares a setup password question; the UEFI Shell runs no \
                       setup browser, so no password is asked or checked; pass \
                       --bypass-setup-password to write anyway";
        let cases = [
            (
                VariableReach::Runtime,
                VariableInterface::Efivarfs,
                "Q",
                SetupPasswordPolicy::Refuse,
                Ok(()),
                vec![(0, vec![1])],
                vec![],
            ),
            (
                VariableReach::Runtime,
                VariableInterface::Efivarfs,
                "P",
                SetupPasswordPolicy::Refuse,
                Ok(()),
                vec![],
                vec![(80, vec![0])],
            ),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
                "Q",
                SetupPasswordPolicy::Refuse,
                Err(refusal),
                vec![],
                vec![],
            ),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
                "Q",
                SetupPasswordPolicy::Bypass,
                Ok(()),
                vec![(0, vec![1])],
                vec![],
            ),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
                "P",
                SetupPasswordPolicy::Refuse,
                Err(refusal),
                vec![],
                vec![],
            ),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
                "P",
                SetupPasswordPolicy::Bypass,
                Ok(()),
                vec![],
                vec![(80, vec![0])],
            ),
            (
                VariableReach::BootServices,
                VariableInterface::Efivarfs,
                "Q",
                SetupPasswordPolicy::Refuse,
                Err(refusal),
                vec![],
                vec![],
            ),
            (
                VariableReach::BootServices,
                VariableInterface::Efivarfs,
                "P",
                SetupPasswordPolicy::Bypass,
                Ok(()),
                vec![],
                vec![(80, vec![0])],
            ),
            (
                VariableReach::Runtime,
                VariableInterface::VariableServices,
                "P",
                SetupPasswordPolicy::Refuse,
                Ok(()),
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
                setup_password: policy,
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
                value,
                None,
                &options,
                shared(&variables),
                &*variables,
                None,
            );

            let case = format!(
                "{reach:?}, {interface:?}, set {question} {value}, {policy:?}, {volatile:?}"
            );
            assert_eq!(
                got.map(drop).map_err(|error| error.to_string()),
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
        )
        .unwrap_or_else(|error| panic!("get {question}: {error:#}"))
        .responses
        .into_iter()
        .map(|response| response.question.answer)
        .collect()
    }

    /// set of `question` to `value` in the HiiDB `hiidb` through `variables` with
    /// --bypass-setup-password, as the CLI prints an error.
    fn set_bypassing(
        hiidb: &[u8],
        question: &str,
        value: &str,
        variables: &Rc<MemoryVariables>,
    ) -> Result<(), String> {
        let options = SetOptions {
            setup_password: SetupPasswordPolicy::Bypass,
            ..SetOptions::default()
        };
        HiiBackend::set_in(
            hiidb,
            question,
            value,
            None,
            &options,
            shared(variables),
            &**variables,
            None,
        )
        .map(drop)
        .map_err(|error| format!("{error:#}"))
    }

    /// The answer of a value whose bytes overlap a password's.
    const PASSWORD_BYTES: &str = "<ValueUnavailable: its bytes hold a password>";

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
            .readable_representation;

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
    /// closed through those that reach BootServices.
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
        for (case, outside) in [
            ("a VARSTORE_NAME_VALUE", var_store_name_value(2, [0x66; 16])),
            (
                "an EFI_IFR_VARSTORE_EFI before UEFI 2.3.1",
                short_var_store_efi(2),
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
                    VariableReach::Runtime => assert_eq!(
                        got,
                        Ok(vec![PASSWORD_BYTES.to_string()]),
                        "{case}: {reach:?}"
                    ),
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
            setup_password: SetupPasswordPolicy::Bypass,
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
            )
            .map(|got| {
                got.responses
                    .into_iter()
                    .map(|response| response.question.answer)
                    .collect::<Vec<_>>()
            })
            .map_err(|error| format!("{error:#}"));
            let set = HiiBackend::set_in(
                &hiidb,
                question.clone(),
                "1",
                None,
                &options,
                shared(&variables),
                &*variables,
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

                let got = HiiBackend::set_in(
                    &boot_service_only_hiidb(),
                    "Q",
                    "1",
                    None,
                    &SetOptions::default(),
                    shared(&variables),
                    &*variables,
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

            let got = HiiBackend::set_in(
                &boot_service_only_hiidb(),
                "Q",
                "1",
                None,
                &options,
                shared(&variables),
                &*variables,
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

            let got = HiiBackend::set_in(
                &boot_service_only_hiidb(),
                "Q",
                "1",
                None,
                &options,
                shared(&variables),
                &*variables,
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

            let got = HiiBackend::set_in(
                &boot_service_only_hiidb(),
                "Q",
                "1",
                None,
                &options,
                shared(&reads),
                &writes,
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

        let got = HiiBackend::set_in(
            &hiidb,
            "Q",
            "1",
            None,
            &options,
            shared(&variables),
            &*variables,
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

    /// Through variables that reach BootServices, a HiiDB with a PASSWORD op whose VarStore is
    /// unknown has get, list-questions, show-ifr and set read and write no variable, even with
    /// --bypass-setup-password; through those that reach Runtime they work, as before.
    #[test]
    fn unresolved_password_closes_every_variable_to_boot_services() {
        let hiidb = password_hiidb_with(password_on(3, 3, 9, 0));
        let closed = "PASSWORD question 0x0003 in FormSet 11111111-1111-1111-1111-111111111111: \
                      no supported varstore with matching id 0x0009 found; as the variable of \
                      that password is unknown, the UEFI Shell build reads and writes no variable \
                      of this HiiDB";
        let set = |variables: &Rc<MemoryVariables>, setup_password| {
            let options = SetOptions {
                setup_password,
                ..SetOptions::default()
            };
            HiiBackend::set_in(
                &hiidb,
                "Q",
                "1",
                None,
                &options,
                shared(variables),
                &**variables,
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
            set(&variables, SetupPasswordPolicy::Refuse),
            Err(closed.to_string()),
            "BootServices: set"
        );
        assert_eq!(
            set(&variables, SetupPasswordPolicy::Bypass),
            Err(closed.to_string()),
            "BootServices: set --bypass-setup-password"
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
        )
        .expect("get through Runtime");
        let answers: Vec<&str> = got
            .responses
            .iter()
            .map(|response| response.question.answer.as_str())
            .collect();
        assert_eq!(answers, ["0"], "Runtime: get");
        assert_eq!(
            set(&variables, SetupPasswordPolicy::Refuse),
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

    /// Through variables that reach BootServices, a HiiDB whose form package holds IFR that
    /// uefisettings ignores, a FormSet that does not parse or nests too deep, the ops after one
    /// where its walk for FormSets ends or a FormSet without its Scope bit, whose second form edk2
    /// parses into it, has get and set read and write no variable: a PASSWORD question in it
    /// could name any variable. A HiiDB without that IFR withholds the PASSWORD's bytes as
    /// before, and through variables that reach Runtime each reads as before.
    #[test]
    fn ignored_ifr_closes_every_variable_to_boot_services() {
        let offset = dropped_password_first_form_set().len();
        let ignored = format!(
            "PASSWORD questions of package list {} may be in the IFR that uefisettings ignores at \
             offset {offset} of a form package: ",
            Guid::from(DROPPED_PASSWORD_LIST_GUID)
        );
        let second = "the FormSet 11111111-1111-1111-1111-111111111111";
        let closed = "; as the variable of that password is unknown, the UEFI Shell build reads \
                      and writes no variable of this HiiDB";
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
                    "{ignored}{second}, which does not parse; uefisettings ignores it, where UEFI \
                     2.11 §33.2.5.10.1 disables only the form of a malformed op and ignores only \
                     a malformed forms set: failed to parse op_code VarStore properly: failed to \
                     parse VarStore's data: "
                ),
            ),
            (
                "nested too deep",
                Vec::new(),
                form_set(&dropped_password_second_ops(too_deep)),
                format!(
                    "{ignored}{second}, which nests too deep: IFR scopes nest deeper than \
                     {MAX_SCOPE_NESTING} at offset {too_deep_at} of a form package{closed}"
                ),
            ),
            (
                "an End op of Length 1 before it",
                vec![0x29, 0x01],
                form_set(&dropped_password_second_ops(Vec::new())),
                format!(
                    "{ignored}an op that does not fit the form package, and the bytes after it: \
                     invalid IFR operation length 1"
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
            )
            .map(|got| {
                got.responses
                    .iter()
                    .map(|response| response.question.answer.clone())
                    .collect::<Vec<_>>()
            })
        };
        let set = |hiidb: &[u8], variables: &Rc<MemoryVariables>| {
            HiiBackend::set_in(
                hiidb,
                "Q",
                "0",
                None,
                &SetOptions::default(),
                shared(variables),
                &**variables,
                None,
            )
            .map(drop)
        };
        let variables_of = |reach, interface| {
            let variables = MemoryVariables::new(reach, interface);
            variables.insert(dropped_password_store(), NV_BS_RT, &[0xAA; 20]);
            Rc::new(variables)
        };

        for (case, between, second_form_set, want) in dropped {
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
                Ok(vec!["1".to_string()]),
                "{case}: Runtime: get"
            );
            assert_eq!(
                variables.reads_of(&dropped_password_store()),
                [20],
                "{case}: Runtime: reads"
            );
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
        policy: SetupPasswordPolicy,
        variables: &Rc<MemoryVariables>,
    ) -> Result<usize, String> {
        let options = SetOptions {
            setup_password: policy,
            ..SetOptions::default()
        };
        HiiBackend::set_in(
            hiidb,
            question,
            "0",
            None,
            &options,
            shared(variables),
            &**variables,
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
    /// uefisettings ignores, as edk2-stable202608 GetIfrBinaryData finds it, and those before;
    /// through variables that reach BootServices, the PASSWORD of the ignored FormSet still closes
    /// every variable of the HiiDB.
    #[test]
    fn form_sets_after_an_ignored_one_are_read() {
        let ifr = [
            form_set(&[
                dropped_password_var_store(),
                form(1, &[checkbox_on(1, 1, 1)]),
            ]),
            form_set(&[
                dropped_password_var_store(),
                form(1, &[password_on(2, 2, 1, 0)]),
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

    /// Through variables that reach BootServices, get and set, with and without the setup
    /// password bypass, refuse and touch no variable when a PASSWORD may sit in IFR that the
    /// parser does not read: a FormSet that it ignores, a FormSet after one, and a FormSet in one
    /// that has its End, which edk2's walk for FormSets finds. Through variables that reach
    /// Runtime, the questions around that IFR read. Without IFR that it ignores, the PASSWORD that
    /// it reads leaves get and the bypassed set open.
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
        let cases: [(&str, Vec<u8>); 4] = [
            (
                "a PASSWORD in an ignored FormSet",
                [
                    q1.clone(),
                    form_set(&[
                        dropped_password_var_store(),
                        form(1, &[password_on(2, 2, 1, 0)]),
                        short_var_store(),
                    ]),
                    q3,
                ]
                .concat(),
            ),
            (
                "a PASSWORD in a FormSet after an ignored one",
                [
                    q1.clone(),
                    form_set(&[dropped_password_var_store(), short_var_store()]),
                    q3_and_password(),
                ]
                .concat(),
            ),
            (
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
            ),
            (
                "control: a PASSWORD in a FormSet after a FormSet that parses",
                [
                    q1,
                    form_set(&[dropped_password_var_store()]),
                    q3_and_password(),
                ]
                .concat(),
            ),
        ];
        let variables_of = |reach, interface| {
            let variables = MemoryVariables::new(reach, interface);
            variables.insert(dropped_password_store(), NV_BS_RT, &[0xAA; 20]);
            variables.insert(password_key.clone(), NV_BS_RT, &[0x00; 20]);
            Rc::new(variables)
        };
        let refused = three_questions_refusal();
        for (name, ifr) in cases {
            let hiidb = three_questions_hiidb(&ifr);

            let runtime = variables_of(VariableReach::Runtime, VariableInterface::Efivarfs);
            for question in ["Q1", "Q3"] {
                assert_eq!(
                    answers_or_error_of(&hiidb, question, &runtime),
                    Ok(vec!["1".to_string()]),
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
                for policy in [SetupPasswordPolicy::Refuse, SetupPasswordPolicy::Bypass] {
                    let got = set_count_of(&hiidb, question, policy, &boot_services);
                    match (control, policy) {
                        (false, _) => assert!(
                            got.as_ref().is_err_and(|error| error.starts_with(&refused)),
                            "{name}: BootServices: set {question} {policy:?}: {got:?}"
                        ),
                        (true, SetupPasswordPolicy::Refuse) => assert!(
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
                    dropped_password_var_store(),
                    form(1, &[password_on(2, 2, 1, 0)]),
                    short_var_store(),
                ]),
            ),
            (
                "a first FormSet nested too deep",
                form_set(&[
                    dropped_password_var_store(),
                    form(1, &[password_on(2, 2, 1, 0)]),
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
            for policy in [SetupPasswordPolicy::Refuse, SetupPasswordPolicy::Bypass] {
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
        let error = set_count_of(&hiidb, "Q2", SetupPasswordPolicy::Refuse, &runtime)
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
            dropped_password_var_store(),
            form(1, &[checkbox_on(2, 2, 1)]),
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
            "the FormSet {}, which does not parse; uefisettings ignores it, where UEFI 2.11 \
             §33.2.5.10.1 disables only the form of a malformed op and ignores only a malformed \
             forms set: failed to parse op_code VarStore properly: failed to parse VarStore's \
             data: ",
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
            )
            .unwrap_or_else(|error| panic!("get {question}: {error:#}"))
        };
        let set = |hiidb: &[u8], question: &str| {
            let variables = variables();
            HiiBackend::set_in(
                hiidb,
                question,
                "0",
                None,
                &SetOptions::default(),
                shared(&variables),
                &*variables,
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
                &mut EfivarReader::new(EfivarSource::Directory(efivars.path().to_path_buf()))
                    .expect("create a reader of the efivars directory"),
            )
            .map(|selected| {
                selected
                    .into_iter()
                    .map(|(_, question, _)| question.question)
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

    /// Every command ignores the FormSet of a HiiDB whose VarStore op ends inside its Guid, and
    /// the record of that FormSet, which list-questions prints on stderr and refusals name, gives
    /// the error on one line: the fields being parsed, without the Rust source locations of
    /// binrw's backtrace frames.
    #[test]
    fn commands_ignore_a_truncated_var_store_and_name_it_on_one_line() {
        // EFI_IFR_VARSTORE, whose 5 bytes end in the Data2 of its Guid
        let var_store = operation(0x24, false, &[0x11; 5]);
        let packages = [
            en_strings_package_of(&["FormSet"]),
            form_package(&[var_store]),
            END_PACKAGE.to_vec(),
        ];
        let hiidb = package_list_with_guid([0x55; 16], &packages.concat());
        let want = format!(
            "the IFR that uefisettings ignores at offset 0 of a form package of package list \
             55555555-5555-5555-5555-555555555555: the FormSet {}, which does not parse; \
             uefisettings ignores it, where UEFI 2.11 §33.2.5.10.1 disables only the form of a \
             malformed op and ignores only a malformed forms set: failed to parse op_code \
             VarStore properly: failed to parse VarStore's data: failed to fill whole buffer \
             (While parsing field 'data2' in Guid; While parsing field 'guid' in VarStore)",
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
        let packages = [
            device_path_package(&DRIVER_PATH),
            form_package(&[
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
            ]),
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
        let ifr = HiiBackend::show_ifr_in(
            hiidb,
            &ShowIfrOptions::default(),
            shared(variables),
            exported(),
            None,
        )
        .expect("show the IFR");
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
                "a PASSWORD op on VarStore 9, which the FormSet does not declare",
                snapshot_hiidb_with(password_on(3, 4, 9, 0)),
                no_variables(),
                snapshot_text(),
                MISSING_N_STORE,
                true,
            ),
            (
                "a FormSet that the parser drops, whose PASSWORD ops are unknown",
                dropped_form_set,
                no_variables(),
                snapshot_text(),
                MISSING_N_STORE,
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
    /// - a PASSWORD outside any FormSet, or a VARSTORE_NAME_VALUE there of VarStoreId 2, leaves
    ///   the password's bytes unknown, so the snapshot shows nothing, which the warning says.
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
            (
                "a VARSTORE_NAME_VALUE of VarStoreId 2",
                var_store_name_value(2, OTHER_GUID),
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
            .readable_representation;

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

        let error = HiiBackend::set_in(
            &snapshot_hiidb(),
            "N",
            "0",
            None,
            &SetOptions::default(),
            shared(&variables),
            &*variables,
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
        HiiBackend::set_in(
            hiidb,
            question,
            value,
            None,
            &SetOptions::default(),
            shared(variables),
            &**variables,
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
        .readable_representation;

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
            )
            .unwrap_or_else(|error| panic!("get {question}: {error:#}"));
            let set = HiiBackend::set_in(
                &hiidb,
                question.clone(),
                &value.to_string(),
                None,
                &SetOptions::default(),
                shared(&variables),
                &*variables,
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

            let got = HiiBackend::set_in(
                &hiidb,
                "A",
                "9",
                None,
                &options,
                shared(&variables),
                &*variables,
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
    /// without --bypass-setup-password.
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
                "this HiiDB declares a setup password question; the UEFI Shell runs no setup \
                 browser, so no password is asked or checked; pass --bypass-setup-password to \
                 write anyway"
                    .to_string()
            ),
            "set A without --bypass-setup-password"
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
}
