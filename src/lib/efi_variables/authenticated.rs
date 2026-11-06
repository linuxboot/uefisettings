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

//! Writes of time-based authenticated EFI variables (UEFI 2.11 §8.2.6), which `variable
//! write-signed` makes: a payload that the caller brings, an EFI_VARIABLE_AUTHENTICATION_2
//! descriptor and the variable's new data, goes to SetVariable() unchanged, as its signature
//! covers the name, vendor GUID, attributes and time stamp that it was made for; new data that a
//! caller's key signs (signing.rs) goes after the descriptor that uefisettings makes.
//! uefisettings checks that a payload's descriptor is complete and refuses, before any write, a
//! write that would delete the variable and one that the firmware may make without checking the
//! signature. With EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS, the same for an
//! EFI_VARIABLE_AUTHENTICATION_3 and its descriptors (§8.2.5, enhanced_authenticated.rs), which
//! no Secure Boot policy variable takes and Linux's efivarfs cannot write.
//! The backends' VariableData does the I/O: efivarfs on Linux (hii/efivarfs.rs), SetVariable() in
//! the UEFI Shell (hii/variable_services.rs), and SetFirmwareEnvironmentVariableExW on Windows
//! (hii/firmware_environment.rs), whose dwAttributes carries
//! VARIABLE_ATTRIBUTE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS (Microsoft Learn, updated
//! 2024-11-20).

pub(crate) mod signing;

use std::fmt;

use anyhow::Result;
use thiserror::Error;

use self::signing::seeded_rng;
use self::signing::AuthenticatedWrite;
use self::signing::EnhancedWrite;
use self::signing::SeedSource;
pub use self::signing::SignatureDigest;
use self::signing::Signer;
pub use self::signing::TimeStamp;
pub use self::signing::TimeStampError;
use super::enhanced_authenticated::authentication_3_value;
use super::enhanced_authenticated::Freshness;
use super::globals::EFI_DEVICE_SECURITY_DATABASE;
use super::globals::EFI_GLOBAL_VARIABLE;
use super::globals::EFI_IMAGE_SECURITY_DATABASE;
use super::is_gmt_time_stamp;
use super::secure_boot_mode::mode_variable;
use super::secure_boot_mode::ModeVariableError;
use super::secure_boot_mode::SETUP_MODE;
use super::RuntimeAccessWithoutBootServiceAccess;
use super::VariableContents;
use super::VariableData;
use super::EFI_TIME_SIZE;
use crate::hii::package::Guid;
use crate::hii::VariableAttributes;
use crate::hii::VariableInterface;
use crate::hii::VariableKey;
use crate::unsafe_operations::LiftedOperations;
use crate::unsafe_operations::PendingOperations;
use crate::unsafe_operations::UnsafeOperation;
use crate::unsafe_operations::UnsafeOperations;

/// The size of a WIN_CERTIFICATE_UEFI_GUID before its CertData: the dwLength, wRevision and
/// wCertificateType of its Hdr, and its CertType (UEFI 2.11 §32.2.4.1, §32.2.4.3).
pub(super) const CERTIFICATE_HEADER_SIZE: usize = 24;
/// WIN_CERTIFICATE.wRevision (UEFI 2.11 §32.2.4.1).
pub(super) const WIN_CERT_REVISION: u16 = 0x0200;
/// WIN_CERT_TYPE_EFI_GUID (UEFI 2.11 §32.2.4.1).
pub(super) const WIN_CERT_TYPE_EFI_GUID: u16 = 0x0EF1;
/// EFI_CERT_TYPE_PKCS7_GUID (UEFI 2.11 §32.2.4.3), the only CertType that an
/// EFI_VARIABLE_AUTHENTICATION_2 takes (§8.2.3), and that an EFI_VARIABLE_AUTHENTICATION_3's
/// certificates take (§8.2.5).
pub(super) const EFI_CERT_TYPE_PKCS7_GUID: Guid = Guid {
    data1: 0x4AAF_D29D,
    data2: 0x68DF,
    data3: 0x49EE,
    data4: [0x8A, 0xA9, 0x34, 0x7D, 0x37, 0x56, 0x65, 0xA7],
};
/// The Secure Boot Policy Variables of EFI_GLOBAL_VARIABLE (UEFI 2.11 §3.3).
const GLOBAL_POLICY_VARIABLES: [&str; 3] = ["PK", "KEK", "OsRecoveryOrder"];
/// What the name of an OsRecovery#### variable, a Secure Boot Policy Variable of any vendor
/// (UEFI 2.11 §3.3), starts with, before four upper-case hexadecimal digits, as in every load
/// option's name (§3.1.1).
const OS_RECOVERY_PREFIX: &str = "OsRecovery";
/// The number of hexadecimal digits of a load option's name (UEFI 2.11 §3.1.1).
const OPTION_NUMBER_DIGITS: usize = 4;
/// The attributes that a signed write takes.
const SIGNED_WRITE_ATTRIBUTES: VariableAttributes = VariableAttributes::NON_VOLATILE
    .union(VariableAttributes::BOOTSERVICE_ACCESS)
    .union(VariableAttributes::RUNTIME_ACCESS)
    .union(VariableAttributes::APPEND_WRITE)
    .union(VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS)
    .union(VariableAttributes::ENHANCED_AUTHENTICATED_ACCESS);

/// Writes `payload`, an EFI_VARIABLE_AUTHENTICATION_2 descriptor and the new data of the
/// variable `key` (UEFI 2.11 §8.2.6), through `variables` with `attributes` and
/// EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS. Before any write, it refuses other
/// attributes, attributes without access, a payload without a complete descriptor, one without
/// data unless it appends, either of which would delete the variable, and then, unless
/// `unsafe_operations` allows it, a Secure Boot Policy Variable or a device signature database
/// while SetupMode is 1 or tells no mode (write_checked), which it returns as lifted if it writes
/// it.
/// With EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS in `attributes`, `payload` is an
/// EFI_VARIABLE_AUTHENTICATION_3 and its descriptors, then the new data (§8.2.5), written with
/// `attributes` alone, as write_enhanced refuses.
pub(crate) fn write_signed(
    variables: &impl VariableData,
    key: &VariableKey,
    attributes: VariableAttributes,
    payload: &[u8],
    unsafe_operations: UnsafeOperations,
) -> Result<Vec<UnsafeOperation>> {
    let attributes = signed_write_attributes(attributes)?;
    if attributes.contains(VariableAttributes::ENHANCED_AUTHENTICATED_ACCESS) {
        return write_enhanced(variables, key, attributes, payload, unsafe_operations);
    }
    let value = auth2_value(payload)?;
    refuse_deletion(key, attributes, value)?;
    let contents = VariableContents::new(attributes, payload.to_vec())?;
    write_checked(variables, key, &contents, unsafe_operations)
}

/// A write that sign_and_write signs: `data`, the new data of the variable `key`, with
/// `attributes`, to which it adds EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS, at
/// `timestamp`, and whether it does its unsafe operations.
#[derive(Debug, Clone, Copy)]
pub(crate) struct SignedWrite<'a> {
    pub(crate) key: &'a VariableKey,
    pub(crate) attributes: VariableAttributes,
    pub(crate) data: &'a [u8],
    pub(crate) timestamp: TimeStamp,
    pub(crate) unsafe_operations: UnsafeOperations,
}

/// Signs `write` with `signer` into an EFI_VARIABLE_AUTHENTICATION_2 (UEFI 2.11 §8.2.6), blinded
/// over a ChaCha20Rng that `seed` seeds, and writes it, then the data. It refuses what
/// write_signed refuses before it seeds, but its unsafe operations, which it checks after it
/// signs, and returns as write_signed does; a failing seed source refuses before any write.
pub(crate) fn sign_and_write(
    variables: &impl VariableData,
    write: &SignedWrite<'_>,
    signer: &Signer,
    seed: &mut impl SeedSource,
) -> Result<Vec<UnsafeOperation>> {
    let attributes = signed_write_attributes(write.attributes)?;
    refuse_deletion(write.key, attributes, write.data)?;
    let mut rng = seeded_rng(seed)?;
    let payload = signer.authentication_2(
        &AuthenticatedWrite {
            key: write.key,
            attributes,
            timestamp: write.timestamp,
            data: write.data,
        },
        &mut rng,
    )?;
    let contents = VariableContents::new(attributes, payload)?;
    write_checked(variables, write.key, &contents, write.unsafe_operations)
}

/// Writes `payload`, an EFI_VARIABLE_AUTHENTICATION_3 of the variable `key` with its descriptors
/// and new data (UEFI 2.11 §8.2.5), through `variables` with `attributes`, which hold
/// EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS. Before any write, it refuses what
/// refuse_enhanced_write refuses, a payload whose descriptors are malformed, one without data
/// and without a NewCert, which would delete the variable, and then, unless `unsafe_operations`
/// allows it, a device signature database while SetupMode is 1 or tells no mode, which it
/// returns as lifted if it writes it.
fn write_enhanced(
    variables: &impl VariableData,
    key: &VariableKey,
    attributes: VariableAttributes,
    payload: &[u8],
    unsafe_operations: UnsafeOperations,
) -> Result<Vec<UnsafeOperation>> {
    refuse_enhanced_write(variables, key)?;
    let value = authentication_3_value(payload)?;
    refuse_enhanced_deletion(key, value.data, value.new_cert)?;
    let contents = VariableContents::new(attributes, payload.to_vec())?;
    write_checked(variables, key, &contents, unsafe_operations)
}

/// A write that sign_and_write_enhanced signs: `data`, the new data of the variable `key`, with
/// `attributes`, to which it adds EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS, and `freshness`,
/// and whether it does its unsafe operations.
#[derive(Debug, Clone, Copy)]
pub(crate) struct EnhancedSignedWrite<'a> {
    pub(crate) key: &'a VariableKey,
    pub(crate) attributes: VariableAttributes,
    pub(crate) data: &'a [u8],
    pub(crate) freshness: &'a Freshness,
    pub(crate) unsafe_operations: UnsafeOperations,
}

/// Signs `write` with `signer` into an EFI_VARIABLE_AUTHENTICATION_3 (UEFI 2.11 §8.2.5) that
/// carries the NewCert of `new_authority` if given, blinded over a ChaCha20Rng that `seed` seeds,
/// and writes it, then the data. It refuses what write_enhanced refuses before it seeds, but its
/// unsafe operations, which it checks after it signs, and returns as write_enhanced does; a
/// failing seed source refuses before any write.
pub(crate) fn sign_and_write_enhanced(
    variables: &impl VariableData,
    write: &EnhancedSignedWrite<'_>,
    signer: &Signer,
    new_authority: Option<&Signer>,
    seed: &mut impl SeedSource,
) -> Result<Vec<UnsafeOperation>> {
    let attributes = signed_write_attributes(
        write
            .attributes
            .union(VariableAttributes::ENHANCED_AUTHENTICATED_ACCESS),
    )?;
    refuse_enhanced_write(variables, write.key)?;
    refuse_enhanced_deletion(write.key, write.data, new_authority.is_some())?;
    let mut rng = seeded_rng(seed)?;
    let payload = signer.authentication_3(
        &EnhancedWrite {
            key: write.key,
            attributes,
            freshness: write.freshness,
            data: write.data,
        },
        new_authority,
        &mut rng,
    )?;
    let contents = VariableContents::new(attributes, payload)?;
    write_checked(variables, write.key, &contents, write.unsafe_operations)
}

/// Refuses an EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS write of `key` through Linux's
/// efivarfs, which refuses the attribute before the firmware sees it, and one of a Secure Boot
/// Policy Variable, which takes only an EFI_VARIABLE_AUTHENTICATION_2 (UEFI 2.11 §3.3, §8.2.3).
fn refuse_enhanced_write(variables: &impl VariableData, key: &VariableKey) -> Result<()> {
    match variables.interface() {
        VariableInterface::Efivarfs => {
            return Err(SignedWriteRefusal::EnhancedThroughEfivarfs(key.clone()).into())
        }
        VariableInterface::VariableServices | VariableInterface::FirmwareEnvironment => {}
    }
    if is_secure_boot_policy_variable(key) {
        return Err(SignedWriteRefusal::EnhancedPolicyVariable(key.clone()).into());
    }
    Ok(())
}

/// Refuses an EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS write of `key` whose new data `data` is
/// empty while it carries no NewCert, as `new_cert` tells: it would delete the variable (UEFI
/// 2.11 §8.2.3). Empty data with a NewCert updates the certificate alone.
fn refuse_enhanced_deletion(key: &VariableKey, data: &[u8], new_cert: bool) -> Result<()> {
    match (data.is_empty(), new_cert) {
        (true, false) => Err(SignedWriteRefusal::EnhancedDelete(key.clone()).into()),
        (true, true) | (false, _) => Ok(()),
    }
}

/// Refuses a write of `value`, the new data of `key`, with `attributes`, that would delete the
/// variable, as no data without APPEND_WRITE does (UEFI 2.11 §8.2.3).
fn refuse_deletion(key: &VariableKey, attributes: VariableAttributes, value: &[u8]) -> Result<()> {
    match value.is_empty() && !attributes.contains(VariableAttributes::APPEND_WRITE) {
        true => Err(SignedWriteRefusal::Delete(key.clone()).into()),
        false => Ok(()),
    }
}

/// Writes `contents`, signed, to `key` through `variables` unless check_setup_mode_write refuses
/// it with `unsafe_operations`; returns what that lifted, which a failed write carries too
/// (LiftedOperations).
fn write_checked(
    variables: &impl VariableData,
    key: &VariableKey,
    contents: &VariableContents,
    unsafe_operations: UnsafeOperations,
) -> Result<Vec<UnsafeOperation>> {
    let lifted = check_setup_mode_write(variables, key, unsafe_operations)?;
    let ((), lifted) = LiftedOperations::after(lifted, variables.set_variable(key, contents))?;
    Ok(lifted)
}

/// Refuses, unless `unsafe_operations` allows it, a signed write of `key` through `variables`
/// while SetupMode is 1 or tells no mode (setup_mode_write), and returns it as lifted where it
/// allows it.
fn check_setup_mode_write(
    variables: &impl VariableData,
    key: &VariableKey,
    unsafe_operations: UnsafeOperations,
) -> Result<Vec<UnsafeOperation>> {
    let mut pending = PendingOperations::new(unsafe_operations);
    if let Some(operation) = setup_mode_write(variables, key) {
        pending.add(operation);
    }
    Ok(pending.check()?)
}

/// The unsafe operation of a signed write of `key` through `variables`, if any: of a Secure Boot
/// Policy Variable while SetupMode is 1, which the firmware makes without checking the signature
/// (UEFI 2.11 §8.2.6, §32.3), or of a device signature database, any variable of
/// EFI_DEVICE_SECURITY_DATABASE_GUID, which it may make so (§32.6.3), and which takes an
/// EFI_VARIABLE_AUTHENTICATION_3 too, as refuse_enhanced_write refuses every Secure Boot Policy
/// Variable first; or of either while SetupMode tells no mode (setup_mode_reading). It reads
/// SetupMode only for those.
fn setup_mode_write(variables: &impl VariableData, key: &VariableKey) -> Option<UnsafeOperation> {
    let policy = is_secure_boot_policy_variable(key);
    if !policy && key.guid != EFI_DEVICE_SECURITY_DATABASE {
        return None;
    }
    let setup_mode = setup_mode_reading(variables)?;
    let variable = key.clone();
    Some(match policy {
        true => UnsafeOperation::SetupModePolicyWrite {
            variable,
            setup_mode,
        },
        false => UnsafeOperation::SetupModeDeviceDatabaseWrite {
            variable,
            setup_mode,
        },
    })
}

/// What a signed write of a Secure Boot Policy Variable or a device signature database reads of
/// SetupMode where it lets the firmware write the variable without checking the signature: 1,
/// as in Setup Mode and in Audit Mode (UEFI 2.11 §32.3.3), or no mode, as a read that fails or
/// finds other than a UINT8 of 0 or 1 tells, which may be 1 too (fail-closed).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SetupModeReading {
    /// SetupMode is 1
    One,
    /// The read of SetupMode failed, with this error
    Unreadable(String),
    /// SetupMode holds other than a UINT8 of 0 or 1, as this tells
    Malformed(String),
}

impl SetupModeReading {
    /// Why SetupMode tells no mode, if it does not.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::One => None,
            Self::Unreadable(reason) | Self::Malformed(reason) => Some(reason),
        }
    }
}

impl fmt::Display for SetupModeReading {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::One => "SetupMode is 1",
            Self::Unreadable(_) => "SetupMode could not be read",
            Self::Malformed(_) => "SetupMode is malformed",
        })
    }
}

/// What `variables` tell of SetupMode where a signed write may go unchecked (SetupModeReading),
/// if they tell that. Firmware without SetupMode, which a firmware with Secure Boot creates
/// (§3.3), checks the signature, as one where SetupMode is 0.
fn setup_mode_reading(variables: &impl VariableData) -> Option<SetupModeReading> {
    match mode_variable(variables, SETUP_MODE) {
        Ok(Some((_, true))) => Some(SetupModeReading::One),
        Ok(Some((_, false)) | None) => None,
        Err(error) if error.is::<ModeVariableError>() => {
            Some(SetupModeReading::Malformed(error.to_string()))
        }
        Err(error) => Some(SetupModeReading::Unreadable(format!("{error:#}"))),
    }
}

/// What write_signed refuses before any write. The messages spell "section", as edk2's
/// terminals but VT-UTF8 show '?' for '§' (edk2-stable202508 TerminalDxe/TerminalConOut.c
/// TerminalConOutOutputString()).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
enum SignedWriteRefusal {
    #[error(
        "{0}: a signed write takes only NON_VOLATILE, BOOTSERVICE_ACCESS, RUNTIME_ACCESS, \
         APPEND_WRITE and ENHANCED_AUTHENTICATED_ACCESS, and adds \
         TIME_BASED_AUTHENTICATED_WRITE_ACCESS without ENHANCED_AUTHENTICATED_ACCESS"
    )]
    Attributes(VariableAttributes),
    #[error(
        "{0}: SetVariable() returns EFI_INVALID_PARAMETER for both \
         TIME_BASED_AUTHENTICATED_WRITE_ACCESS and ENHANCED_AUTHENTICATED_ACCESS (UEFI 2.11 \
         section 8.2.3)"
    )]
    TimeBasedAndEnhanced(VariableAttributes),
    #[error(
        "Linux's efivarfs cannot write EFI variable {0} with ENHANCED_AUTHENTICATED_ACCESS: its \
         EFI_VARIABLE_MASK (include/linux/efi.h) lacks the attribute, so efivarfs_file_write() \
         (fs/efivarfs/file.c) refuses the write with EINVAL; write it with uefisettings.efi in \
         the UEFI Shell"
    )]
    EnhancedThroughEfivarfs(VariableKey),
    #[error(
        "EFI variable {0} is a Secure Boot policy variable, which takes only an \
         EFI_VARIABLE_AUTHENTICATION_2 with TIME_BASED_AUTHENTICATED_WRITE_ACCESS (UEFI 2.11 \
         sections 3.3 and 8.2.3)"
    )]
    EnhancedPolicyVariable(VariableKey),
    #[error(
        "the write holds no data after its EFI_VARIABLE_AUTHENTICATION_3 descriptors and no \
         NewCert, so it would delete EFI variable {0} (UEFI 2.11 section 8.2.3), which a signed \
         write does not do"
    )]
    EnhancedDelete(VariableKey),
    #[error(
        "the payload holds {0} bytes, fewer than the {} of the TimeStamp and the AuthInfo header \
         of an EFI_VARIABLE_AUTHENTICATION_2 (UEFI 2.11 section 8.2.3)",
        EFI_TIME_SIZE + CERTIFICATE_HEADER_SIZE
    )]
    Truncated(usize),
    #[error(
        "the payload's AuthInfo.Hdr.wCertificateType is {0:#06x}, not WIN_CERT_TYPE_EFI_GUID \
         ({WIN_CERT_TYPE_EFI_GUID:#06x}) (UEFI 2.11 section 32.2.4.1)"
    )]
    CertificateType(u16),
    #[error(
        "the payload's AuthInfo.CertType is {0}, not EFI_CERT_TYPE_PKCS7_GUID \
         ({EFI_CERT_TYPE_PKCS7_GUID}) (UEFI 2.11 section 8.2.3)"
    )]
    CertType(Guid),
    #[error(
        "the payload's AuthInfo.Hdr.dwLength is {0}, which leaves no CertData after the \
         {CERTIFICATE_HEADER_SIZE} bytes of the Hdr and CertType of a WIN_CERTIFICATE_UEFI_GUID \
         (UEFI 2.11 section 32.2.4.3)"
    )]
    NoCertData(u32),
    #[error(
        "the payload's AuthInfo.Hdr.dwLength is {length}, more than the {available} bytes after \
         its TimeStamp"
    )]
    CertificateTruncated { length: u32, available: usize },
    #[error(
        "the payload's TimeStamp has a Pad1, Nanosecond, TimeZone, Daylight or Pad2 other than \
         0, which an EFI_VARIABLE_AUTHENTICATION_2 needs (UEFI 2.11 section 8.2.3)"
    )]
    TimeStampNotGmt,
    #[error(
        "the payload holds no data after its EFI_VARIABLE_AUTHENTICATION_2, so without \
         APPEND_WRITE it would delete EFI variable {0} (UEFI 2.11 section 8.2.3), which a signed \
         write does not do"
    )]
    Delete(VariableKey),
    #[error(
        "{0}: without BOOTSERVICE_ACCESS and RUNTIME_ACCESS, a write deletes the variable: \
         \"Setting a data variable with no access attributes causes it to be deleted\" (UEFI 2.11 \
         section 8.2.3), which a signed write does not do"
    )]
    NoAccess(VariableAttributes),
}

/// `attributes` and EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS, or `attributes` alone
/// with EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS, unless they hold an attribute that a signed
/// write does not take, runtime access without boot service access, no access attribute, with
/// which a write deletes the variable, or both authentication attributes, which SetVariable()
/// refuses (UEFI 2.11 §8.2.3).
fn signed_write_attributes(attributes: VariableAttributes) -> Result<VariableAttributes> {
    let refused = attributes.difference(SIGNED_WRITE_ATTRIBUTES);
    if !refused.is_empty() {
        return Err(SignedWriteRefusal::Attributes(refused).into());
    }
    if attributes.contains(VariableAttributes::RUNTIME_ACCESS)
        && !attributes.contains(VariableAttributes::BOOTSERVICE_ACCESS)
    {
        return Err(RuntimeAccessWithoutBootServiceAccess(attributes).into());
    }
    if !attributes
        .intersects(VariableAttributes::BOOTSERVICE_ACCESS | VariableAttributes::RUNTIME_ACCESS)
    {
        return Err(SignedWriteRefusal::NoAccess(attributes).into());
    }
    match (
        attributes.contains(VariableAttributes::ENHANCED_AUTHENTICATED_ACCESS),
        attributes.contains(VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS),
    ) {
        (true, true) => Err(SignedWriteRefusal::TimeBasedAndEnhanced(attributes).into()),
        (true, false) => Ok(attributes),
        (false, _) => {
            Ok(attributes.union(VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS))
        }
    }
}

/// The new data of the variable in `payload`, after its EFI_VARIABLE_AUTHENTICATION_2 (UEFI 2.11
/// §8.2.3): a TimeStamp in GMT, then a WIN_CERTIFICATE_UEFI_GUID of WIN_CERT_TYPE_EFI_GUID and
/// EFI_CERT_TYPE_PKCS7_GUID whose dwLength covers some CertData, within the payload. It reads no
/// wRevision, whose 0x0200 the spec calls only the current revision (§32.2.4.1), and which
/// edk2-stable202508's AuthService.c VerifyTimeBasedPayload() reads neither; the firmware
/// verifies the signature in CertData.
fn auth2_value(payload: &[u8]) -> std::result::Result<&[u8], SignedWriteRefusal> {
    let Some((time_stamp, after_time_stamp)) = payload.split_first_chunk::<EFI_TIME_SIZE>() else {
        return Err(SignedWriteRefusal::Truncated(payload.len()));
    };
    let Some((header, _)) = after_time_stamp.split_first_chunk::<CERTIFICATE_HEADER_SIZE>() else {
        return Err(SignedWriteRefusal::Truncated(payload.len()));
    };
    let [l0, l1, l2, l3, _, _, t0, t1, cert_type @ ..] = *header;
    let certificate_type = u16::from_le_bytes([t0, t1]);
    if certificate_type != WIN_CERT_TYPE_EFI_GUID {
        return Err(SignedWriteRefusal::CertificateType(certificate_type));
    }
    let cert_type = Guid::from(cert_type);
    if cert_type != EFI_CERT_TYPE_PKCS7_GUID {
        return Err(SignedWriteRefusal::CertType(cert_type));
    }
    let length = u32::from_le_bytes([l0, l1, l2, l3]);
    let certificate = usize::try_from(length)
        .ok()
        .filter(|&certificate| certificate > CERTIFICATE_HEADER_SIZE)
        .ok_or(SignedWriteRefusal::NoCertData(length))?;
    let Some(value) = after_time_stamp.get(certificate..) else {
        return Err(SignedWriteRefusal::CertificateTruncated {
            length,
            available: after_time_stamp.len(),
        });
    };
    if !is_gmt_time_stamp(time_stamp) {
        return Err(SignedWriteRefusal::TimeStampNotGmt);
    }
    Ok(value)
}

/// Whether `key` is a Secure Boot Policy Variable (UEFI 2.11 §3.3): PK, KEK or OsRecoveryOrder
/// of EFI_GLOBAL_VARIABLE, an OsRecovery#### of any vendor, or any variable of
/// EFI_IMAGE_SECURITY_DATABASE_GUID.
fn is_secure_boot_policy_variable(key: &VariableKey) -> bool {
    match key.guid {
        EFI_IMAGE_SECURITY_DATABASE => true,
        EFI_GLOBAL_VARIABLE if GLOBAL_POLICY_VARIABLES.contains(&key.name.as_str()) => true,
        _ => is_os_recovery_name(&key.name),
    }
}

/// Whether `name` is OsRecovery####, with four upper-case hexadecimal digits (UEFI 2.11 §3.1.1).
fn is_os_recovery_name(name: &str) -> bool {
    name.strip_prefix(OS_RECOVERY_PREFIX).is_some_and(|number| {
        number.len() == OPTION_NUMBER_DIGITS
            && number
                .bytes()
                .all(|digit| matches!(digit, b'0'..=b'9' | b'A'..=b'F'))
    })
}

#[cfg(test)]
mod tests {
    use rand_core::SeedableRng;

    use super::*;
    use crate::efi_variables::enhanced_authenticated::authentication_3_payload;
    use crate::efi_variables::enhanced_authenticated::fixture::win_certificate_of;
    use crate::efi_variables::enhanced_authenticated::Nonce;
    use crate::efi_variables::globals::tests::key;
    use crate::efi_variables::globals::tests::HeldVariables;
    use crate::efi_variables::globals::tests::DEVDB_VENDOR;
    use crate::efi_variables::globals::tests::NV_BS_RT;
    use crate::unsafe_operations::UnsafeOperationRefused;

    /// A stand-in for the DER of a PKCS #7 SignedData, which uefisettings does not parse.
    const CERT_DATA: &[u8] = b"\x30\x80signed data";
    /// The new data of the variables that the payloads write.
    const VALUE: &[u8] = b"a signature list";
    /// Both grants, for what the flag does not change.
    const GRANTS: [UnsafeOperations; 2] = [UnsafeOperations::Refuse, UnsafeOperations::Allow];
    /// A vendor GUID of no Secure Boot Policy Variable.
    const VENDOR: Guid = Guid {
        data1: 0xDE14_5B29,
        data2: 0xC3CD,
        data3: 0x455F,
        data4: [0x91, 0xDE, 0xA7, 0x62, 0x37, 0xB6, 0x7C, 0x52],
    };
    /// EFI_CERT_TYPE_RSA2048_SHA256_GUID (UEFI 2.11 §32.2.4.3), a CertType that an
    /// EFI_VARIABLE_AUTHENTICATION_2 does not take.
    const EFI_CERT_TYPE_RSA2048_SHA256_GUID: Guid = Guid {
        data1: 0xA771_7414,
        data2: 0xC616,
        data3: 0x4977,
        data4: [0x94, 0x20, 0x84, 0x47, 0x12, 0xA7, 0x35, 0xBF],
    };
    /// The offsets of the TimeStamp fields that an EFI_VARIABLE_AUTHENTICATION_2 sets to 0, by
    /// name: Pad1, the bytes of Nanosecond and TimeZone, Daylight and Pad2 (UEFI 2.11 §8.3.1).
    const GMT_FIELDS: [(&str, usize); 9] = [
        ("Pad1", 7),
        ("Nanosecond byte 0", 8),
        ("Nanosecond byte 1", 9),
        ("Nanosecond byte 2", 10),
        ("Nanosecond byte 3", 11),
        ("TimeZone byte 0", 12),
        ("TimeZone byte 1", 13),
        ("Daylight", 14),
        ("Pad2", 15),
    ];

    /// An EFI_VARIABLE_AUTHENTICATION_2 of 2026-11-05 12:34:56 GMT and CERT_DATA, then `value`.
    fn auth2(value: &[u8]) -> Vec<u8> {
        let time_stamp = [0xEA, 0x07, 11, 5, 12, 34, 56, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let length = u32::try_from(CERTIFICATE_HEADER_SIZE + CERT_DATA.len()).expect("dwLength");
        [
            &time_stamp[..],
            &length.to_le_bytes(),
            &0x0200_u16.to_le_bytes(),
            &WIN_CERT_TYPE_EFI_GUID.to_le_bytes(),
            &<[u8; 16]>::from(EFI_CERT_TYPE_PKCS7_GUID),
            CERT_DATA,
            value,
        ]
        .concat()
    }

    /// The variables of a firmware whose SetupMode holds `setup_mode`, or of one without
    /// SetupMode.
    fn firmware(setup_mode: Option<&[u8]>) -> HeldVariables {
        let variables = HeldVariables::default();
        match setup_mode {
            Some(data) => variables.with(SETUP_MODE, EFI_GLOBAL_VARIABLE, data),
            None => variables,
        }
    }

    /// What `variables` hold as `key`.
    fn held(variables: &HeldVariables, key: &VariableKey) -> Option<VariableContents> {
        variables.variables.borrow().get(key).cloned()
    }

    /// What a signed write of `payload` with `attributes` passes to SetVariable().
    fn written(attributes: u32, payload: &[u8]) -> Option<VariableContents> {
        let attributes = VariableAttributes::from_bits_retain(attributes);
        Some(VariableContents::new(attributes, payload.to_vec()).expect("a payload"))
    }

    /// write_signed passes the payload to SetVariable() byte for byte, with the attributes and
    /// EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS, whatever the TimeStamp's date.
    #[test]
    fn write_signed_passes_the_payload_and_the_attributes_unchanged() {
        let mut zero_time_stamp = auth2(VALUE);
        zero_time_stamp
            .get_mut(..EFI_TIME_SIZE)
            .expect("a TimeStamp")
            .fill(0);
        let cases = [
            (
                "db append",
                key("db", EFI_IMAGE_SECURITY_DATABASE),
                NV_BS_RT | VariableAttributes::APPEND_WRITE,
                auth2(VALUE),
                0x67,
            ),
            (
                "write of another variable",
                key("Signed", VENDOR),
                NV_BS_RT,
                auth2(VALUE),
                0x27,
            ),
            (
                "boot service variable",
                key("Signed", VENDOR),
                VariableAttributes::BOOTSERVICE_ACCESS,
                auth2(VALUE),
                0x22,
            ),
            (
                "attributes that name time-based authenticated write access",
                key("Signed", VENDOR),
                NV_BS_RT | VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
                auth2(VALUE),
                0x27,
            ),
            (
                "append with the zero time of a platform without a time source",
                key("db", EFI_IMAGE_SECURITY_DATABASE),
                NV_BS_RT | VariableAttributes::APPEND_WRITE,
                zero_time_stamp,
                0x67,
            ),
            (
                "append of no data, which can change the time stamp only",
                key("db", EFI_IMAGE_SECURITY_DATABASE),
                NV_BS_RT | VariableAttributes::APPEND_WRITE,
                auth2(&[]),
                0x67,
            ),
        ];
        for (case, key, attributes, payload, set_attributes) in cases {
            let variables = firmware(Some(&[0]));

            let lifted = write_signed(
                &variables,
                &key,
                attributes,
                &payload,
                UnsafeOperations::Refuse,
            )
            .unwrap_or_else(|error| panic!("{case}: {error:#}"));

            assert_eq!(
                held(&variables, &key),
                written(set_attributes, &payload),
                "{case}"
            );
            assert_eq!(lifted, [], "{case}: lifted");
            assert_eq!(*variables.set.borrow(), [key], "{case}: writes");
        }
    }

    /// write_signed refuses a payload without a complete EFI_VARIABLE_AUTHENTICATION_2, and
    /// writes nothing then.
    #[test]
    fn write_signed_refuses_a_payload_without_a_complete_descriptor() {
        let complete = auth2(VALUE);
        let with = |offset: usize, bytes: &[u8]| {
            let mut payload = complete.clone();
            payload
                .get_mut(offset..offset + bytes.len())
                .expect("bytes in the payload")
                .copy_from_slice(bytes);
            payload
        };
        let whole = u32::try_from(complete.len() - EFI_TIME_SIZE).expect("dwLength");
        let mut cases = vec![
            (
                "no payload".to_string(),
                vec![],
                "the payload holds 0 bytes, fewer than the 40 of the TimeStamp and the AuthInfo \
                 header of an EFI_VARIABLE_AUTHENTICATION_2 (UEFI 2.11 section 8.2.3)"
                    .to_string(),
            ),
            (
                "a TimeStamp only".to_string(),
                complete[..EFI_TIME_SIZE].to_vec(),
                "the payload holds 16 bytes, fewer than the 40 of the TimeStamp and the AuthInfo \
                 header of an EFI_VARIABLE_AUTHENTICATION_2 (UEFI 2.11 section 8.2.3)"
                    .to_string(),
            ),
            (
                "the AuthInfo header but its last byte".to_string(),
                complete[..39].to_vec(),
                "the payload holds 39 bytes, fewer than the 40 of the TimeStamp and the AuthInfo \
                 header of an EFI_VARIABLE_AUTHENTICATION_2 (UEFI 2.11 section 8.2.3)"
                    .to_string(),
            ),
            (
                "WIN_CERT_TYPE_EFI_PKCS115".to_string(),
                with(22, &0x0EF0_u16.to_le_bytes()),
                "the payload's AuthInfo.Hdr.wCertificateType is 0x0ef0, not \
                 WIN_CERT_TYPE_EFI_GUID (0x0ef1) (UEFI 2.11 section 32.2.4.1)"
                    .to_string(),
            ),
            (
                "WIN_CERT_TYPE_PKCS_SIGNED_DATA".to_string(),
                with(22, &0x0002_u16.to_le_bytes()),
                "the payload's AuthInfo.Hdr.wCertificateType is 0x0002, not \
                 WIN_CERT_TYPE_EFI_GUID (0x0ef1) (UEFI 2.11 section 32.2.4.1)"
                    .to_string(),
            ),
            (
                "EFI_CERT_TYPE_RSA2048_SHA256_GUID".to_string(),
                with(24, &<[u8; 16]>::from(EFI_CERT_TYPE_RSA2048_SHA256_GUID)),
                "the payload's AuthInfo.CertType is A7717414-C616-4977-9420-844712A735BF, not \
                 EFI_CERT_TYPE_PKCS7_GUID (4AAFD29D-68DF-49EE-8AA9-347D375665A7) (UEFI 2.11 \
                 section 8.2.3)"
                    .to_string(),
            ),
            (
                "no CertData".to_string(),
                with(16, &24_u32.to_le_bytes()),
                "the payload's AuthInfo.Hdr.dwLength is 24, which leaves no CertData after the 24 \
                 bytes of the Hdr and CertType of a WIN_CERTIFICATE_UEFI_GUID (UEFI 2.11 section \
                 32.2.4.3)"
                    .to_string(),
            ),
            (
                "a dwLength of 0".to_string(),
                with(16, &0_u32.to_le_bytes()),
                "the payload's AuthInfo.Hdr.dwLength is 0, which leaves no CertData after the 24 \
                 bytes of the Hdr and CertType of a WIN_CERTIFICATE_UEFI_GUID (UEFI 2.11 section \
                 32.2.4.3)"
                    .to_string(),
            ),
            (
                "a dwLength past the payload".to_string(),
                with(16, &(whole + 1).to_le_bytes()),
                format!(
                    "the payload's AuthInfo.Hdr.dwLength is {}, more than the {whole} bytes after \
                     its TimeStamp",
                    whole + 1
                ),
            ),
            (
                "CertData cut short".to_string(),
                complete[..42].to_vec(),
                format!(
                    "the payload's AuthInfo.Hdr.dwLength is {}, more than the 26 bytes after its \
                     TimeStamp",
                    CERTIFICATE_HEADER_SIZE + CERT_DATA.len()
                ),
            ),
        ];
        for (field, offset) in GMT_FIELDS {
            cases.push((
                format!("a TimeStamp {field} of 1"),
                with(offset, &[1]),
                "the payload's TimeStamp has a Pad1, Nanosecond, TimeZone, Daylight or Pad2 other \
                 than 0, which an EFI_VARIABLE_AUTHENTICATION_2 needs (UEFI 2.11 section 8.2.3)"
                    .to_string(),
            ));
        }
        let db = key("db", EFI_IMAGE_SECURITY_DATABASE);
        for (case, payload, refusal) in cases {
            let variables = firmware(Some(&[0]));

            let error = write_signed(
                &variables,
                &db,
                NV_BS_RT | VariableAttributes::APPEND_WRITE,
                &payload,
                UnsafeOperations::Refuse,
            )
            .expect_err(&case);

            assert_eq!(error.to_string(), refusal, "{case}");
            assert_eq!(*variables.set.borrow(), [], "{case}: writes");
            assert_eq!(*variables.read.borrow(), [], "{case}: reads");
        }
    }

    /// write_signed refuses a payload that holds no data, which deletes the variable without
    /// EFI_VARIABLE_APPEND_WRITE (UEFI 2.11 §8.2.3).
    #[test]
    fn write_signed_refuses_to_delete() {
        let variables = firmware(Some(&[0]));
        let signed = key("Signed", VENDOR);

        let error = write_signed(
            &variables,
            &signed,
            NV_BS_RT,
            &auth2(&[]),
            UnsafeOperations::Refuse,
        )
        .expect_err("write a payload without data");

        assert_eq!(
            error.to_string(),
            "the payload holds no data after its EFI_VARIABLE_AUTHENTICATION_2, so without \
             APPEND_WRITE it would delete EFI variable \
             Signed-de145b29-c3cd-455f-91de-a76237b67c52 (UEFI 2.11 section 8.2.3), which a \
             signed write does not do",
            "refusal"
        );
        assert_eq!(*variables.set.borrow(), [], "writes");
    }

    /// The refusal of a write of `key`, a Secure Boot policy variable, while SetupMode is 1.
    fn policy_refusal(key: &VariableKey) -> String {
        format!(
            "EFI variable {key} is a Secure Boot policy variable and SetupMode is 1, so the \
             firmware would write it without checking the payload's signature (UEFI 2.11 \
             sections 3.3 and 8.2.6); pass --i-am-fine-to-brick-this-system to write it unchecked"
        )
    }

    /// write_signed refuses each Secure Boot Policy Variable (UEFI 2.11 §3.3) while SetupMode is
    /// 1, an OsRecovery#### of EFI_DEVICE_SECURITY_DATABASE_GUID as one too, and writes it,
    /// lifting nothing, when SetupMode is 0 or absent; it writes any other variable whatever
    /// SetupMode is, without reading it, and lifts nothing there with the flag either.
    #[test]
    fn write_signed_refuses_policy_variables_in_setup_mode() {
        let policy = [
            key("PK", EFI_GLOBAL_VARIABLE),
            key("KEK", EFI_GLOBAL_VARIABLE),
            key("OsRecoveryOrder", EFI_GLOBAL_VARIABLE),
            key("OsRecovery0000", VENDOR),
            key("OsRecovery09AF", EFI_GLOBAL_VARIABLE),
            key("OsRecoveryFFFF", VENDOR),
            key("OsRecovery0000", DEVDB_VENDOR),
            key("db", EFI_IMAGE_SECURITY_DATABASE),
            key("dbx", EFI_IMAGE_SECURITY_DATABASE),
            key("dbt", EFI_IMAGE_SECURITY_DATABASE),
            key("dbr", EFI_IMAGE_SECURITY_DATABASE),
            key("Other", EFI_IMAGE_SECURITY_DATABASE),
        ];
        let others = [
            key("PK", VENDOR),
            key("KEK", VENDOR),
            key("OsRecoveryOrder", VENDOR),
            key("db", EFI_GLOBAL_VARIABLE),
            key("devdb", EFI_GLOBAL_VARIABLE),
            key("devdb", VENDOR),
            key("PKDefault", EFI_GLOBAL_VARIABLE),
            key("SecureBoot", EFI_GLOBAL_VARIABLE),
            key("OsRecovery09af", VENDOR),
            key("OsRecovery000G", VENDOR),
            key("OsRecovery000", VENDOR),
            key("OsRecovery00000", VENDOR),
            key("osrecovery0000", VENDOR),
        ];
        let attributes = NV_BS_RT | VariableAttributes::APPEND_WRITE;
        let payload = auth2(VALUE);

        for key in &policy {
            let variables = firmware(Some(&[1]));

            let error = write_signed(
                &variables,
                key,
                attributes,
                &payload,
                UnsafeOperations::Refuse,
            )
            .expect_err(&key.to_string());

            assert_eq!(error.to_string(), policy_refusal(key), "{key}");
            assert_eq!(*variables.set.borrow(), [], "{key}: writes");
        }
        for (setup_mode, case) in [(Some(&[0][..]), "SetupMode 0"), (None, "no SetupMode")] {
            for key in &policy {
                let variables = firmware(setup_mode);

                let lifted = write_signed(
                    &variables,
                    key,
                    attributes,
                    &payload,
                    UnsafeOperations::Refuse,
                )
                .unwrap_or_else(|error| panic!("{key}, {case}: {error:#}"));

                assert_eq!(
                    held(&variables, key),
                    written(0x67, &payload),
                    "{key}, {case}"
                );
                assert_eq!(lifted, [], "{key}, {case}: lifted");
            }
        }
        for key in &others {
            for grant in GRANTS {
                let variables = firmware(Some(&[1]));

                let lifted = write_signed(&variables, key, attributes, &payload, grant)
                    .unwrap_or_else(|error| panic!("{key}, {grant:?}: {error:#}"));

                assert_eq!(
                    held(&variables, key),
                    written(0x67, &payload),
                    "{key}, {grant:?}"
                );
                assert_eq!(lifted, [], "{key}, {grant:?}: lifted");
                assert_eq!(*variables.read.borrow(), [], "{key}, {grant:?}: reads");
            }
        }
    }

    /// write_signed refuses each variable of EFI_DEVICE_SECURITY_DATABASE_GUID while SetupMode is
    /// 1, when the firmware may write it "without a signature validation" (UEFI 2.11 §32.6.3),
    /// and writes it when SetupMode is 0 or absent, lifting nothing, or when allowed, lifting the
    /// write only while SetupMode is 1.
    #[test]
    fn write_signed_refuses_device_signature_databases_in_setup_mode() {
        let databases = [key("devdb", DEVDB_VENDOR), key("Other", DEVDB_VENDOR)];
        let attributes = NV_BS_RT | VariableAttributes::APPEND_WRITE;
        let payload = auth2(VALUE);

        for key in &databases {
            let variables = firmware(Some(&[1]));

            let error = write_signed(
                &variables,
                key,
                attributes,
                &payload,
                UnsafeOperations::Refuse,
            )
            .expect_err(&key.to_string());

            assert_eq!(error.to_string(), device_database_refusal(key), "{key}");
            assert_eq!(*variables.set.borrow(), [], "{key}: writes");
        }
        for (setup_mode, grant, lifts, case) in [
            (
                Some(&[0][..]),
                UnsafeOperations::Refuse,
                false,
                "SetupMode 0",
            ),
            (None, UnsafeOperations::Refuse, false, "no SetupMode"),
            (
                Some(&[0][..]),
                UnsafeOperations::Allow,
                false,
                "SetupMode 0, allowed",
            ),
            (
                Some(&[1][..]),
                UnsafeOperations::Allow,
                true,
                "SetupMode 1, allowed",
            ),
        ] {
            for key in &databases {
                let variables = firmware(setup_mode);

                let lifted = write_signed(&variables, key, attributes, &payload, grant)
                    .unwrap_or_else(|error| panic!("{key}, {case}: {error:#}"));

                assert_eq!(
                    held(&variables, key),
                    written(0x67, &payload),
                    "{key}, {case}"
                );
                let operation = UnsafeOperation::SetupModeDeviceDatabaseWrite {
                    variable: key.clone(),
                    setup_mode: SetupModeReading::One,
                };
                assert_eq!(
                    lifted,
                    lifts.then_some(operation).into_iter().collect::<Vec<_>>(),
                    "{key}, {case}: lifted"
                );
            }
        }
    }

    /// write_signed, sign_and_write and sign_and_write_enhanced take a Secure Boot Policy Variable
    /// or a device signature database while SetupMode holds other than a UINT8 of 0 or 1 for one
    /// while SetupMode is 1, as the firmware may then write it without checking the signature
    /// (check_setup_mode_writes).
    #[test]
    fn write_signed_refuses_a_malformed_setup_mode() {
        let cases = [
            (
                &[1, 0][..],
                "SetupMode holds 2 bytes, not the 1 of a UINT8 (UEFI 2.11 section 3.3)",
            ),
            (
                &[2],
                "SetupMode is 2, neither 0 nor 1 (UEFI 2.11 section 3.3)",
            ),
        ];
        for key in [
            key("db", EFI_IMAGE_SECURITY_DATABASE),
            key("devdb", DEVDB_VENDOR),
        ] {
            for (setup_mode, reason) in cases {
                check_setup_mode_writes(
                    || firmware(Some(setup_mode)),
                    &key,
                    SetupModeReading::Malformed(reason.to_owned()),
                    "SetupMode is malformed",
                );
            }
        }
    }

    /// VariableData that record the variables set.
    trait RecordsSets: VariableData {
        fn sets(&self) -> Vec<VariableKey>;
    }

    impl RecordsSets for HeldVariables {
        fn sets(&self) -> Vec<VariableKey> {
            self.set.borrow().clone()
        }
    }

    /// A signed write by name, what it returned, and the variables that it set.
    type SetupModeWrite = (&'static str, Result<Vec<UnsafeOperation>>, Vec<VariableKey>);

    /// The signed writes of `key` that read SetupMode, with `grant`, through fresh `variables`:
    /// write_signed of auth2(VALUE), sign_and_write and, for a device signature database,
    /// sign_and_write_enhanced.
    fn setup_mode_writes<V: RecordsSets>(
        variables: impl Fn() -> V,
        key: &VariableKey,
        grant: UnsafeOperations,
    ) -> Vec<SetupModeWrite> {
        let attributes = NV_BS_RT | VariableAttributes::APPEND_WRITE;
        let signer = signing::tests::test_signer();
        let timestamp = signing::tests::TIME.parse().expect("the test TimeStamp");
        let freshness = Freshness::TimeStamp(timestamp);
        let mut got = Vec::new();

        let held = variables();
        let lifted = write_signed(&held, key, attributes, &auth2(VALUE), grant);
        got.push(("write_signed", lifted, held.sets()));

        let held = variables();
        let write = SignedWrite {
            key,
            attributes,
            data: VALUE,
            timestamp,
            unsafe_operations: grant,
        };
        let lifted = sign_and_write(
            &held,
            &write,
            &signer,
            &mut signing::tests::FakeSeed(Some(1)),
        );
        got.push(("sign_and_write", lifted, held.sets()));

        if key.guid == EFI_DEVICE_SECURITY_DATABASE {
            let held = variables();
            let write = EnhancedSignedWrite {
                unsafe_operations: grant,
                ..enhanced_signed_write(key, NV_BS_RT, VALUE, &freshness)
            };
            let lifted = sign_and_write_enhanced(
                &held,
                &write,
                &signer,
                None,
                &mut signing::tests::FakeSeed(Some(1)),
            );
            got.push(("sign_and_write_enhanced", lifted, held.sets()));
        }
        got
    }

    /// Each signed write of `key`, a Secure Boot Policy Variable or a device signature database,
    /// through `variables`, whose SetupMode tells `setup_mode` (`state`), refuses it without
    /// UnsafeOperations::Allow, naming why SetupMode tells no mode and the flag, and writes
    /// nothing; with Allow it writes it and returns it as lifted.
    fn check_setup_mode_writes<V: RecordsSets>(
        variables: impl Fn() -> V,
        key: &VariableKey,
        setup_mode: SetupModeReading,
        state: &str,
    ) {
        let reason = setup_mode.reason().expect("a SetupMode of no mode");
        let (operation, refusal) = match key.guid == EFI_DEVICE_SECURITY_DATABASE {
            true => (
                UnsafeOperation::SetupModeDeviceDatabaseWrite {
                    variable: key.clone(),
                    setup_mode: setup_mode.clone(),
                },
                format!(
                    "EFI variable {key} is a device signature database and {state}, so the \
                     firmware may write it without checking the payload's signature (UEFI 2.11 \
                     section 32.6.3): {reason}; pass --i-am-fine-to-brick-this-system to write it \
                     unchecked"
                ),
            ),
            false => (
                UnsafeOperation::SetupModePolicyWrite {
                    variable: key.clone(),
                    setup_mode: setup_mode.clone(),
                },
                format!(
                    "EFI variable {key} is a Secure Boot policy variable and {state}, so the \
                     firmware may write it without checking the payload's signature (UEFI 2.11 \
                     sections 3.3 and 8.2.6): {reason}; pass --i-am-fine-to-brick-this-system to \
                     write it unchecked"
                ),
            ),
        };

        for (name, got, sets) in setup_mode_writes(&variables, key, UnsafeOperations::Refuse) {
            let got = got.map_err(|error| format!("{error:#}"));
            assert_eq!(got, Err(refusal.clone()), "{key}, {state}: {name}");
            assert_eq!(sets, [], "{key}, {state}: {name}: writes");
        }
        for (name, got, sets) in setup_mode_writes(&variables, key, UnsafeOperations::Allow) {
            let got = got.map_err(|error| format!("{error:#}"));
            assert_eq!(
                got,
                Ok(vec![operation.clone()]),
                "{key}, {state}: {name}, Allow"
            );
            assert_eq!(
                sets,
                std::slice::from_ref(key),
                "{key}, {state}: {name}, Allow: writes"
            );
        }
    }

    /// write_signed refuses attributes that a signed write does not take, runtime access
    /// without boot service access, and no access attribute, which deletes the variable (UEFI
    /// 2.11 §8.2.3), and writes nothing then.
    #[test]
    fn write_signed_refuses_other_attributes() {
        let cases = [
            (
                VariableAttributes::HARDWARE_ERROR_RECORD | NV_BS_RT,
                "HARDWARE_ERROR_RECORD: a signed write takes only NON_VOLATILE, \
                 BOOTSERVICE_ACCESS, RUNTIME_ACCESS, APPEND_WRITE and \
                 ENHANCED_AUTHENTICATED_ACCESS, and adds TIME_BASED_AUTHENTICATED_WRITE_ACCESS \
                 without ENHANCED_AUTHENTICATED_ACCESS",
            ),
            (
                VariableAttributes::AUTHENTICATED_WRITE_ACCESS | NV_BS_RT,
                "AUTHENTICATED_WRITE_ACCESS: a signed write takes only NON_VOLATILE, \
                 BOOTSERVICE_ACCESS, RUNTIME_ACCESS, APPEND_WRITE and \
                 ENHANCED_AUTHENTICATED_ACCESS, and adds TIME_BASED_AUTHENTICATED_WRITE_ACCESS \
                 without ENHANCED_AUTHENTICATED_ACCESS",
            ),
            (
                VariableAttributes::ENHANCED_AUTHENTICATED_ACCESS
                    | VariableAttributes::HARDWARE_ERROR_RECORD,
                "HARDWARE_ERROR_RECORD: a signed write takes only NON_VOLATILE, \
                 BOOTSERVICE_ACCESS, RUNTIME_ACCESS, APPEND_WRITE and \
                 ENHANCED_AUTHENTICATED_ACCESS, and adds TIME_BASED_AUTHENTICATED_WRITE_ACCESS \
                 without ENHANCED_AUTHENTICATED_ACCESS",
            ),
            (
                VariableAttributes::from_bits_retain(0x100) | NV_BS_RT,
                "0x100: a signed write takes only NON_VOLATILE, BOOTSERVICE_ACCESS, \
                 RUNTIME_ACCESS, APPEND_WRITE and ENHANCED_AUTHENTICATED_ACCESS, and adds \
                 TIME_BASED_AUTHENTICATED_WRITE_ACCESS without ENHANCED_AUTHENTICATED_ACCESS",
            ),
            (
                VariableAttributes::NON_VOLATILE | VariableAttributes::RUNTIME_ACCESS,
                "NON_VOLATILE | RUNTIME_ACCESS: runtime access implies boot service access (UEFI \
                 2.10 section 8.2.3)",
            ),
            (
                VariableAttributes::NON_VOLATILE,
                "NON_VOLATILE: without BOOTSERVICE_ACCESS and RUNTIME_ACCESS, a write deletes the \
                 variable: \"Setting a data variable with no access attributes causes it to be \
                 deleted\" (UEFI 2.11 section 8.2.3), which a signed write does not do",
            ),
            (
                VariableAttributes::NON_VOLATILE | VariableAttributes::APPEND_WRITE,
                "NON_VOLATILE | APPEND_WRITE: without BOOTSERVICE_ACCESS and RUNTIME_ACCESS, a \
                 write deletes the variable: \"Setting a data variable with no access attributes \
                 causes it to be deleted\" (UEFI 2.11 section 8.2.3), which a signed write does \
                 not do",
            ),
        ];
        let signed = key("Signed", VENDOR);
        for (attributes, refusal) in cases {
            let variables = firmware(Some(&[0]));

            let error = write_signed(
                &variables,
                &signed,
                attributes,
                &auth2(VALUE),
                UnsafeOperations::Refuse,
            )
            .expect_err(&attributes.to_string());

            assert_eq!(error.to_string(), refusal, "{attributes}");
            assert_eq!(*variables.set.borrow(), [], "{attributes}: writes");
        }
    }

    /// VariableData whose every read fails, and which hold what is set.
    struct UnreadableVariables(HeldVariables);

    impl VariableData for UnreadableVariables {
        fn interface(&self) -> VariableInterface {
            self.0.interface()
        }

        fn variable_data(&self, key: &VariableKey) -> Result<Option<VariableContents>> {
            Err(anyhow::anyhow!("cannot read EFI variable {key}"))
        }

        fn set_variable(&self, key: &VariableKey, contents: &VariableContents) -> Result<()> {
            self.0.set_variable(key, contents)
        }

        fn delete_variable(&self, key: &VariableKey) -> Result<()> {
            self.0.delete_variable(key)
        }
    }

    impl RecordsSets for UnreadableVariables {
        fn sets(&self) -> Vec<VariableKey> {
            self.0.sets()
        }
    }

    /// write_signed, sign_and_write and sign_and_write_enhanced take a Secure Boot Policy Variable
    /// or a device signature database whose SetupMode cannot be read for one while SetupMode is
    /// 1, as the firmware may then write it without checking the signature
    /// (check_setup_mode_writes).
    #[test]
    fn write_signed_refuses_policy_variables_and_devdb_when_setup_mode_is_unreadable() {
        let reason = "cannot read EFI variable SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c";
        for key in [
            key("db", EFI_IMAGE_SECURITY_DATABASE),
            key("devdb", DEVDB_VENDOR),
        ] {
            check_setup_mode_writes(
                || UnreadableVariables(HeldVariables::default()),
                &key,
                SetupModeReading::Unreadable(reason.to_owned()),
                "SetupMode could not be read",
            );
        }
    }

    /// VariableData that hold what HeldVariables hold, and whose every write fails.
    struct FailingWrites(HeldVariables);

    impl VariableData for FailingWrites {
        fn interface(&self) -> VariableInterface {
            self.0.interface()
        }

        fn variable_data(&self, key: &VariableKey) -> Result<Option<VariableContents>> {
            self.0.variable_data(key)
        }

        fn set_variable(&self, key: &VariableKey, _contents: &VariableContents) -> Result<()> {
            Err(anyhow::anyhow!("cannot write EFI variable {key}"))
        }

        fn delete_variable(&self, key: &VariableKey) -> Result<()> {
            Err(anyhow::anyhow!("cannot delete EFI variable {key}"))
        }
    }

    impl RecordsSets for FailingWrites {
        fn sets(&self) -> Vec<VariableKey> {
            self.0.sets()
        }
    }

    /// With UnsafeOperations::Allow, the error of a signed write that fails after it lifted its
    /// unsafe operation carries it (LiftedOperations), beside the write's own error.
    #[test]
    fn a_failed_signed_write_keeps_the_lifted_operation() {
        let devdb = key("devdb", DEVDB_VENDOR);
        let operation = UnsafeOperation::SetupModeDeviceDatabaseWrite {
            variable: devdb.clone(),
            setup_mode: SetupModeReading::One,
        };
        let failing = || FailingWrites(firmware(Some(&[1])));

        for (name, got, _) in setup_mode_writes(failing, &devdb, UnsafeOperations::Allow) {
            let error = got.expect_err(name);
            assert_eq!(
                error.downcast_ref::<LiftedOperations>(),
                Some(&LiftedOperations(vec![operation.clone()])),
                "{name}: lifted"
            );
            assert_eq!(
                error.root_cause().to_string(),
                format!("cannot write EFI variable {devdb}"),
                "{name}: the error"
            );
        }
    }

    /// With UnsafeOperations::Allow, write_signed writes a Secure Boot Policy Variable or a
    /// device signature database while SetupMode is 1, which it reads to return the write as
    /// lifted.
    #[test]
    fn write_signed_writes_policy_variables_and_devdb_in_setup_mode_when_allowed() {
        let kek = key("KEK", EFI_GLOBAL_VARIABLE);
        let devdb = key("devdb", DEVDB_VENDOR);
        let attributes = NV_BS_RT | VariableAttributes::APPEND_WRITE;
        for (key, operation) in [
            (
                &kek,
                UnsafeOperation::SetupModePolicyWrite {
                    variable: kek.clone(),
                    setup_mode: SetupModeReading::One,
                },
            ),
            (
                &devdb,
                UnsafeOperation::SetupModeDeviceDatabaseWrite {
                    variable: devdb.clone(),
                    setup_mode: SetupModeReading::One,
                },
            ),
        ] {
            let variables = firmware(Some(&[1]));

            let lifted = write_signed(
                &variables,
                key,
                attributes,
                &auth2(VALUE),
                UnsafeOperations::Allow,
            )
            .expect("write in Setup Mode with the flag");

            assert_eq!(held(&variables, key), written(0x67, &auth2(VALUE)), "{key}");
            assert_eq!(lifted, [operation], "{key}: lifted");
            assert_eq!(
                *variables.read.borrow(),
                [key_of(SETUP_MODE)],
                "{key}: reads"
            );
        }
    }

    /// The key of the global variable `name`.
    fn key_of(name: &str) -> VariableKey {
        key(name, EFI_GLOBAL_VARIABLE)
    }

    /// write_signed refuses, with the flag and without, writing nothing and reading no SetupMode,
    /// what the flag cannot lift in a write of a Secure Boot policy variable or a device
    /// signature database while SetupMode is 1: other attributes, a payload that is no
    /// EFI_VARIABLE_AUTHENTICATION_2, one without data and without APPEND_WRITE, which edk2
    /// takes as a deletion in Setup Mode (edk2-stable202608 AuthService.c:725-727), and an
    /// EFI_VARIABLE_AUTHENTICATION_3 through efivarfs.
    #[test]
    fn write_signed_refuses_what_the_flag_cannot_lift_before_setup_mode() {
        let kek = key_of("KEK");
        let devdb = key("devdb", DEVDB_VENDOR);
        let cases = [
            (
                "other attributes",
                &kek,
                VariableAttributes::HARDWARE_ERROR_RECORD | NV_BS_RT,
                VariableInterface::VariableServices,
                auth2(VALUE),
                "HARDWARE_ERROR_RECORD: a signed write takes only NON_VOLATILE, \
                 BOOTSERVICE_ACCESS, RUNTIME_ACCESS, APPEND_WRITE and \
                 ENHANCED_AUTHENTICATED_ACCESS, and adds TIME_BASED_AUTHENTICATED_WRITE_ACCESS \
                 without ENHANCED_AUTHENTICATED_ACCESS"
                    .to_owned(),
            ),
            (
                "a bare signature list",
                &kek,
                NV_BS_RT | VariableAttributes::APPEND_WRITE,
                VariableInterface::VariableServices,
                VALUE.to_vec(),
                "the payload holds 16 bytes, fewer than the 40 of the TimeStamp and the AuthInfo \
                 header of an EFI_VARIABLE_AUTHENTICATION_2 (UEFI 2.11 section 8.2.3)"
                    .to_owned(),
            ),
            (
                "a deletion",
                &kek,
                NV_BS_RT,
                VariableInterface::VariableServices,
                auth2(&[]),
                format!(
                    "the payload holds no data after its EFI_VARIABLE_AUTHENTICATION_2, so \
                     without APPEND_WRITE it would delete EFI variable {kek} (UEFI 2.11 section \
                     8.2.3), which a signed write does not do"
                ),
            ),
            (
                "an EFI_VARIABLE_AUTHENTICATION_3 through efivarfs",
                &devdb,
                NV_BS_RT_ENHANCED,
                VariableInterface::Efivarfs,
                auth3(VALUE, false),
                format!(
                    "Linux's efivarfs cannot write EFI variable {devdb} with \
                     ENHANCED_AUTHENTICATED_ACCESS: its EFI_VARIABLE_MASK (include/linux/efi.h) \
                     lacks the attribute, so efivarfs_file_write() (fs/efivarfs/file.c) refuses \
                     the write with EINVAL; write it with uefisettings.efi in the UEFI Shell"
                ),
            ),
        ];
        for (case, key, attributes, interface, payload, refusal) in &cases {
            for grant in GRANTS {
                let variables = firmware(Some(&[1])).through(*interface);

                let error = write_signed(&variables, key, *attributes, payload, grant)
                    .map_err(|error| error.to_string());

                assert_eq!(error, Err(refusal.clone()), "{case}, {grant:?}");
                assert_eq!(*variables.set.borrow(), [], "{case}, {grant:?}: writes");
                assert_eq!(*variables.read.borrow(), [], "{case}, {grant:?}: reads");
            }
        }
    }

    /// sign_and_write refuses a signed KEK while SetupMode is 1 unless allowed: the firmware
    /// would not check the signature. Allowed, it writes KEK and returns the write as lifted.
    #[test]
    fn sign_and_write_refuses_setup_mode_unless_allowed() {
        let kek = key("KEK", EFI_GLOBAL_VARIABLE);
        let signer = signing::tests::test_signer();
        let write = |variables: &HeldVariables, unsafe_operations| {
            sign_and_write(
                variables,
                &SignedWrite {
                    key: &kek,
                    attributes: NV_BS_RT,
                    data: VALUE,
                    timestamp: signing::tests::TIME.parse().expect("the test TimeStamp"),
                    unsafe_operations,
                },
                &signer,
                &mut signing::tests::FakeSeed(Some(1)),
            )
        };
        let operation = UnsafeOperation::SetupModePolicyWrite {
            variable: kek.clone(),
            setup_mode: SetupModeReading::One,
        };

        let refused = firmware(Some(&[1]));
        let error = write(&refused, UnsafeOperations::Refuse).expect_err("KEK in Setup Mode");
        assert_eq!(
            error.downcast_ref::<UnsafeOperationRefused>(),
            Some(&UnsafeOperationRefused {
                operation: operation.clone()
            }),
            "refusal: {error}"
        );
        assert_eq!(*refused.set.borrow(), [], "writes without the flag");

        let allowed = firmware(Some(&[1]));
        let lifted = write(&allowed, UnsafeOperations::Allow).expect("KEK with the flag");
        assert!(held(&allowed, &kek).is_some(), "KEK written with the flag");
        assert_eq!(lifted, [operation], "lifted with the flag");
    }

    /// sign_and_write refuses a signed devdb while SetupMode is 1 unless allowed, as write_signed
    /// does: the firmware may not check the signature (UEFI 2.11 §32.6.3). Allowed, it writes
    /// what the key signs, reading SetupMode to return the write as lifted.
    #[test]
    fn sign_and_write_refuses_devdb_in_setup_mode_unless_allowed() {
        let devdb = key("devdb", DEVDB_VENDOR);
        let signer = signing::tests::test_signer();
        let timestamp = signing::tests::TIME.parse().expect("the test TimeStamp");
        let write = |variables: &HeldVariables, unsafe_operations| {
            sign_and_write(
                variables,
                &SignedWrite {
                    key: &devdb,
                    attributes: NV_BS_RT | VariableAttributes::APPEND_WRITE,
                    data: VALUE,
                    timestamp,
                    unsafe_operations,
                },
                &signer,
                &mut signing::tests::FakeSeed(Some(1)),
            )
        };

        let refused = firmware(Some(&[1]));
        let error = write(&refused, UnsafeOperations::Refuse).expect_err("devdb in Setup Mode");
        assert_eq!(
            error.to_string(),
            device_database_refusal(&devdb),
            "refusal"
        );
        assert_eq!(*refused.set.borrow(), [], "writes without the flag");

        let allowed = firmware(Some(&[1]));
        let lifted = write(&allowed, UnsafeOperations::Allow).expect("devdb with the flag");
        let expected = signer
            .authentication_2(
                &AuthenticatedWrite {
                    key: &devdb,
                    attributes: signing::tests::append_attributes(),
                    timestamp,
                    data: VALUE,
                },
                &mut rand_chacha::ChaCha20Rng::seed_from_u64(0),
            )
            .expect("sign");
        assert_eq!(
            held(&allowed, &devdb),
            written(0x67, &expected),
            "devdb written with the flag"
        );
        assert_eq!(
            lifted,
            [UnsafeOperation::SetupModeDeviceDatabaseWrite {
                variable: devdb.clone(),
                setup_mode: SetupModeReading::One,
            }],
            "lifted with the flag"
        );
        assert_eq!(
            *allowed.read.borrow(),
            [key_of(SETUP_MODE)],
            "reads with the flag"
        );
    }

    /// sign_and_write writes the descriptor that the key signs, then the data, with the
    /// attributes it signed; without a seed source it refuses naming it and writes nothing.
    #[test]
    fn sign_and_write_writes_what_the_key_signs() {
        let db = signing::tests::db();
        let timestamp = signing::tests::TIME.parse().expect("the test TimeStamp");
        let write = SignedWrite {
            key: &db,
            attributes: NV_BS_RT | VariableAttributes::APPEND_WRITE,
            data: VALUE,
            timestamp,
            unsafe_operations: UnsafeOperations::Refuse,
        };
        let signer = signing::tests::test_signer();
        let variables = firmware(Some(&[0]));

        let lifted = sign_and_write(
            &variables,
            &write,
            &signer,
            &mut signing::tests::FakeSeed(Some(1)),
        )
        .expect("sign and write db");
        assert_eq!(lifted, [], "lifted of db while SetupMode is 0");

        let expected = signer
            .authentication_2(
                &AuthenticatedWrite {
                    key: &db,
                    attributes: signing::tests::append_attributes(),
                    timestamp,
                    data: VALUE,
                },
                &mut rand_chacha::ChaCha20Rng::seed_from_u64(0),
            )
            .expect("sign");
        assert_eq!(held(&variables, &db), written(0x67, &expected), "db");

        let variables = firmware(Some(&[0]));
        let error = sign_and_write(
            &variables,
            &write,
            &signer,
            &mut signing::tests::FakeSeed(None),
        )
        .expect_err("sign without a seed source");
        assert_eq!(
            format!("{error:#}"),
            "cannot seed RSA blinding from EFI_RNG_PROTOCOL: no handle has it: NOT_FOUND",
            "refusal"
        );
        assert_eq!(*variables.set.borrow(), [], "writes");
    }

    /// sign_and_write refuses other attributes and a write without data, which deletes the
    /// variable, before it seeds: without a seed source, the refusal is these, and nothing is
    /// written.
    #[test]
    fn sign_and_write_refuses_before_seeding() {
        let signed = key("Signed", VENDOR);
        let cases = [
            (
                "other attributes",
                VariableAttributes::HARDWARE_ERROR_RECORD | NV_BS_RT,
                VALUE,
                "HARDWARE_ERROR_RECORD: a signed write takes only NON_VOLATILE, \
                 BOOTSERVICE_ACCESS, RUNTIME_ACCESS, APPEND_WRITE and \
                 ENHANCED_AUTHENTICATED_ACCESS, and adds TIME_BASED_AUTHENTICATED_WRITE_ACCESS \
                 without ENHANCED_AUTHENTICATED_ACCESS",
            ),
            (
                "no data",
                NV_BS_RT,
                &[][..],
                "the payload holds no data after its EFI_VARIABLE_AUTHENTICATION_2, so without \
                 APPEND_WRITE it would delete EFI variable \
                 Signed-de145b29-c3cd-455f-91de-a76237b67c52 (UEFI 2.11 section 8.2.3), which a \
                 signed write does not do",
            ),
        ];
        let signer = signing::tests::test_signer();
        for (case, attributes, data, refusal) in cases {
            let variables = firmware(Some(&[1]));
            let write = SignedWrite {
                key: &signed,
                attributes,
                data,
                timestamp: signing::tests::TIME.parse().expect("the test TimeStamp"),
                unsafe_operations: UnsafeOperations::Refuse,
            };

            let error = sign_and_write(
                &variables,
                &write,
                &signer,
                &mut signing::tests::FakeSeed(None),
            )
            .expect_err(case);

            assert_eq!(format!("{error:#}"), refusal, "{case}");
            assert_eq!(*variables.set.borrow(), [], "{case}: writes");
        }
    }

    /// sign_and_write checks a Secure Boot Policy Variable against SetupMode only after it signs,
    /// which the flag cannot lift: without a seed source, KEK fails at the seed while SetupMode is
    /// 1, with the flag and without, reading no SetupMode and writing nothing.
    #[test]
    fn sign_and_write_checks_setup_mode_after_signing() {
        let kek = key("KEK", EFI_GLOBAL_VARIABLE);
        let signer = signing::tests::test_signer();
        for grant in GRANTS {
            let variables = firmware(Some(&[1]));
            let write = SignedWrite {
                key: &kek,
                attributes: NV_BS_RT,
                data: VALUE,
                timestamp: signing::tests::TIME.parse().expect("the test TimeStamp"),
                unsafe_operations: grant,
            };

            let error = sign_and_write(
                &variables,
                &write,
                &signer,
                &mut signing::tests::FakeSeed(None),
            )
            .map_err(|error| format!("{error:#}"));

            assert_eq!(
                error,
                Err(
                    "cannot seed RSA blinding from EFI_RNG_PROTOCOL: no handle has it: NOT_FOUND"
                        .to_owned()
                ),
                "{grant:?}"
            );
            assert_eq!(*variables.set.borrow(), [], "{grant:?}: writes");
            assert_eq!(*variables.read.borrow(), [], "{grant:?}: reads");
        }
    }

    /// NV+BS+RT and ENHANCED_AUTHENTICATED_ACCESS.
    const NV_BS_RT_ENHANCED: VariableAttributes =
        NV_BS_RT.union(VariableAttributes::ENHANCED_AUTHENTICATED_ACCESS);

    /// A timestamp-type EFI_VARIABLE_AUTHENTICATION_3 payload of `data`, with a NewCert if
    /// `new_cert`, whose certificates carry CERT_DATA.
    fn auth3(data: &[u8], new_cert: bool) -> Vec<u8> {
        let freshness =
            Freshness::TimeStamp(signing::tests::TIME.parse().expect("the test TimeStamp"));
        let new_cert = new_cert.then(|| win_certificate_of(CERT_DATA));
        authentication_3_payload(
            &freshness,
            new_cert.as_deref(),
            &win_certificate_of(CERT_DATA),
            data,
        )
        .expect("a payload")
    }

    /// write_signed passes a pre-signed EFI_VARIABLE_AUTHENTICATION_3 payload with
    /// ENHANCED_AUTHENTICATED_ACCESS to SetVariable() unchanged, adding no
    /// TIME_BASED_AUTHENTICATED_WRITE_ACCESS, and that of a certificate-only update too: empty
    /// data with a NewCert.
    #[test]
    fn write_signed_writes_enhanced_authenticated_payloads_unchanged() {
        let signed = key("Signed", VENDOR);
        for (case, payload) in [
            ("data", auth3(VALUE, false)),
            ("data and a NewCert", auth3(VALUE, true)),
            ("a certificate-only update", auth3(&[], true)),
        ] {
            let variables = firmware(Some(&[0]));

            write_signed(
                &variables,
                &signed,
                NV_BS_RT_ENHANCED,
                &payload,
                UnsafeOperations::Refuse,
            )
            .unwrap_or_else(|error| panic!("{case}: {error:#}"));

            assert_eq!(held(&variables, &signed), written(0x87, &payload), "{case}");
            assert_eq!(
                *variables.set.borrow(),
                std::slice::from_ref(&signed),
                "{case}: writes"
            );
        }
    }

    /// write_signed refuses, writing nothing, both authentication attributes, an enhanced write
    /// through efivarfs, of a Secure Boot policy variable, without data or a NewCert, which would
    /// delete the variable, and with a broken descriptor.
    #[test]
    fn write_signed_refuses_enhanced_authenticated_payloads_before_any_write() {
        let signed = key("Signed", VENDOR);
        let db = key("db", EFI_IMAGE_SECURITY_DATABASE);
        let mut broken = auth3(VALUE, false);
        broken[0] = 2;
        let cases = [
            (
                &signed,
                NV_BS_RT_ENHANCED | VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
                VariableInterface::VariableServices,
                auth3(VALUE, false),
                "NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS | \
                 TIME_BASED_AUTHENTICATED_WRITE_ACCESS | ENHANCED_AUTHENTICATED_ACCESS: \
                 SetVariable() returns EFI_INVALID_PARAMETER for both \
                 TIME_BASED_AUTHENTICATED_WRITE_ACCESS and ENHANCED_AUTHENTICATED_ACCESS (UEFI 2.11 \
                 section 8.2.3)"
                    .to_owned(),
            ),
            (
                &signed,
                NV_BS_RT_ENHANCED,
                VariableInterface::Efivarfs,
                auth3(VALUE, false),
                format!(
                    "Linux's efivarfs cannot write EFI variable {signed} with \
                     ENHANCED_AUTHENTICATED_ACCESS: its EFI_VARIABLE_MASK (include/linux/efi.h) \
                     lacks the attribute, so efivarfs_file_write() (fs/efivarfs/file.c) refuses \
                     the write with EINVAL; write it with uefisettings.efi in the UEFI Shell"
                ),
            ),
            (
                &db,
                NV_BS_RT_ENHANCED,
                VariableInterface::VariableServices,
                auth3(VALUE, false),
                format!(
                    "EFI variable {db} is a Secure Boot policy variable, which takes only an \
                     EFI_VARIABLE_AUTHENTICATION_2 with TIME_BASED_AUTHENTICATED_WRITE_ACCESS \
                     (UEFI 2.11 sections 3.3 and 8.2.3)"
                ),
            ),
            (
                &signed,
                NV_BS_RT_ENHANCED,
                VariableInterface::VariableServices,
                auth3(&[], false),
                format!(
                    "the write holds no data after its EFI_VARIABLE_AUTHENTICATION_3 descriptors \
                     and no NewCert, so it would delete EFI variable {signed} (UEFI 2.11 section \
                     8.2.3), which a signed write does not do"
                ),
            ),
            (
                &signed,
                NV_BS_RT_ENHANCED,
                VariableInterface::VariableServices,
                broken,
                "the payload's EFI_VARIABLE_AUTHENTICATION_3 Version is 2, not 1 (UEFI 2.11 \
                 section 8.2.3)"
                    .to_owned(),
            ),
        ];
        for (key, attributes, interface, payload, refusal) in cases {
            let variables = firmware(Some(&[0])).through(interface);

            let error = write_signed(
                &variables,
                key,
                attributes,
                &payload,
                UnsafeOperations::Refuse,
            )
            .expect_err(&refusal);

            assert_eq!(
                error.to_string(),
                refusal,
                "{key} {attributes} {interface:?}"
            );
            assert_eq!(
                *variables.set.borrow(),
                [],
                "{key} {attributes} {interface:?}: writes"
            );
        }
    }

    /// The EFI_VARIABLE_AUTHENTICATION_3 path refuses every Secure Boot policy variable (UEFI
    /// 2.11 §3.3), of EFI_GLOBAL_VARIABLE, any vendor's OsRecovery#### and every variable of
    /// EFI_IMAGE_SECURITY_DATABASE_GUID, before it reads the payload, writing nothing.
    #[test]
    fn enhanced_refuses_every_policy_variable() {
        for key in [
            key("PK", EFI_GLOBAL_VARIABLE),
            key("KEK", EFI_GLOBAL_VARIABLE),
            key("OsRecoveryOrder", EFI_GLOBAL_VARIABLE),
            key("OsRecovery0001", VENDOR),
            key("db", EFI_IMAGE_SECURITY_DATABASE),
            key("dbx", EFI_IMAGE_SECURITY_DATABASE),
        ] {
            let variables = firmware(Some(&[0]));

            let error = write_signed(
                &variables,
                &key,
                NV_BS_RT_ENHANCED,
                &[0; 64],
                UnsafeOperations::Allow,
            )
            .expect_err("a policy variable");

            assert_eq!(
                error.downcast_ref::<SignedWriteRefusal>(),
                Some(&SignedWriteRefusal::EnhancedPolicyVariable(key.clone())),
                "{key}: {error}"
            );
            assert_eq!(*variables.set.borrow(), [], "{key}: writes");
        }
    }

    /// A write that sign_and_write_enhanced signs at the test TimeStamp, or as a nonce-type
    /// update.
    fn enhanced_signed_write<'a>(
        key: &'a VariableKey,
        attributes: VariableAttributes,
        data: &'a [u8],
        freshness: &'a Freshness,
    ) -> EnhancedSignedWrite<'a> {
        EnhancedSignedWrite {
            key,
            attributes,
            data,
            freshness,
            unsafe_operations: UnsafeOperations::Refuse,
        }
    }

    /// sign_and_write_enhanced writes, with ENHANCED_AUTHENTICATED_ACCESS added, the
    /// EFI_VARIABLE_AUTHENTICATION_3 that the key signs, with the NewCert of a new authority if
    /// given, and then the data, which a certificate-only update leaves empty.
    #[test]
    fn sign_and_write_enhanced_writes_what_the_key_signs() {
        let signed = key("Signed", VENDOR);
        let timestamp =
            Freshness::TimeStamp(signing::tests::TIME.parse().expect("the test TimeStamp"));
        let update = Freshness::Nonce {
            nonce: Nonce::new(vec![9; 5]).expect("the nonce"),
            current: Some(Nonce::new(vec![7; 3]).expect("the current nonce")),
        };
        let signer = signing::tests::test_signer();
        let (authority_key, authority_certificate) = signing::tests::other_pems();
        let authority = Signer::from_pem(
            authority_key,
            authority_certificate.as_bytes(),
            SignatureDigest::Sha256,
        )
        .expect("the new authority");
        let cases = [
            ("timestamp", &timestamp, VALUE, None),
            ("nonce update", &update, VALUE, None),
            ("new authority", &update, VALUE, Some(&authority)),
            ("certificate only", &update, &[][..], Some(&authority)),
        ];
        for (case, freshness, data, new_authority) in cases {
            let variables = firmware(Some(&[0]));

            sign_and_write_enhanced(
                &variables,
                &enhanced_signed_write(&signed, NV_BS_RT, data, freshness),
                &signer,
                new_authority,
                &mut signing::tests::FakeSeed(Some(1)),
            )
            .unwrap_or_else(|error| panic!("{case}: {error:#}"));

            let expected = signer
                .authentication_3(
                    &EnhancedWrite {
                        key: &signed,
                        attributes: NV_BS_RT_ENHANCED,
                        freshness,
                        data,
                    },
                    new_authority,
                    &mut rand_chacha::ChaCha20Rng::seed_from_u64(0),
                )
                .expect("sign");
            assert_eq!(
                held(&variables, &signed),
                written(0x87, &expected),
                "{case}"
            );
        }
    }

    /// sign_and_write_enhanced refuses both authentication attributes, a write through
    /// efivarfs, a Secure Boot policy variable and a write without data or a NewCert before it
    /// seeds: without a seed source, the refusal is these, and nothing is written; a write that
    /// it takes then fails at the seed.
    #[test]
    fn sign_and_write_enhanced_refuses_before_seeding() {
        let signed = key("Signed", VENDOR);
        let kek = key("KEK", EFI_GLOBAL_VARIABLE);
        let freshness =
            Freshness::TimeStamp(signing::tests::TIME.parse().expect("the test TimeStamp"));
        let cases = [
            (
                "both authentications",
                &signed,
                NV_BS_RT | VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
                VALUE,
                VariableInterface::VariableServices,
                "NON_VOLATILE | BOOTSERVICE_ACCESS | RUNTIME_ACCESS | \
                 TIME_BASED_AUTHENTICATED_WRITE_ACCESS | ENHANCED_AUTHENTICATED_ACCESS: \
                 SetVariable() returns EFI_INVALID_PARAMETER for both \
                 TIME_BASED_AUTHENTICATED_WRITE_ACCESS and ENHANCED_AUTHENTICATED_ACCESS (UEFI 2.11 \
                 section 8.2.3)"
                    .to_owned(),
            ),
            (
                "efivarfs",
                &signed,
                NV_BS_RT,
                VALUE,
                VariableInterface::Efivarfs,
                format!(
                    "Linux's efivarfs cannot write EFI variable {signed} with \
                     ENHANCED_AUTHENTICATED_ACCESS: its EFI_VARIABLE_MASK (include/linux/efi.h) \
                     lacks the attribute, so efivarfs_file_write() (fs/efivarfs/file.c) refuses \
                     the write with EINVAL; write it with uefisettings.efi in the UEFI Shell"
                ),
            ),
            (
                "a policy variable",
                &kek,
                NV_BS_RT,
                VALUE,
                VariableInterface::VariableServices,
                format!(
                    "EFI variable {kek} is a Secure Boot policy variable, which takes only an \
                     EFI_VARIABLE_AUTHENTICATION_2 with TIME_BASED_AUTHENTICATED_WRITE_ACCESS \
                     (UEFI 2.11 sections 3.3 and 8.2.3)"
                ),
            ),
            (
                "no data",
                &signed,
                NV_BS_RT,
                &[][..],
                VariableInterface::VariableServices,
                format!(
                    "the write holds no data after its EFI_VARIABLE_AUTHENTICATION_3 descriptors \
                     and no NewCert, so it would delete EFI variable {signed} (UEFI 2.11 section \
                     8.2.3), which a signed write does not do"
                ),
            ),
            (
                "a write that it takes",
                &signed,
                NV_BS_RT,
                VALUE,
                VariableInterface::VariableServices,
                "cannot seed RSA blinding from EFI_RNG_PROTOCOL: no handle has it: NOT_FOUND"
                    .to_owned(),
            ),
        ];
        let signer = signing::tests::test_signer();
        for (case, key, attributes, data, interface, refusal) in cases {
            let variables = firmware(Some(&[0])).through(interface);

            let error = sign_and_write_enhanced(
                &variables,
                &enhanced_signed_write(key, attributes, data, &freshness),
                &signer,
                None,
                &mut signing::tests::FakeSeed(None),
            )
            .expect_err(case);

            assert_eq!(format!("{error:#}"), refusal, "{case}");
            assert_eq!(*variables.set.borrow(), [], "{case}: writes");
        }
    }

    /// The refusal of a write of `key`, a device signature database, while SetupMode is 1.
    fn device_database_refusal(key: &VariableKey) -> String {
        format!(
            "EFI variable {key} is a device signature database and SetupMode is 1, so the \
             firmware may write it without checking the payload's signature (UEFI 2.11 section \
             32.6.3); pass --i-am-fine-to-brick-this-system to write it unchecked"
        )
    }

    /// write_signed refuses an EFI_VARIABLE_AUTHENTICATION_3 write of each variable of
    /// EFI_DEVICE_SECURITY_DATABASE_GUID while SetupMode is 1 (UEFI 2.11 §32.6.3), as for an
    /// EFI_VARIABLE_AUTHENTICATION_2, and writes it when SetupMode is 0 or absent, lifting
    /// nothing, or when allowed, lifting the write.
    #[test]
    fn write_signed_refuses_enhanced_device_signature_databases_in_setup_mode() {
        let databases = [key("devdb", DEVDB_VENDOR), key("Other", DEVDB_VENDOR)];
        let payload = auth3(VALUE, false);

        for key in &databases {
            let variables = firmware(Some(&[1]));

            let error = write_signed(
                &variables,
                key,
                NV_BS_RT_ENHANCED,
                &payload,
                UnsafeOperations::Refuse,
            )
            .map_err(|error| error.to_string());

            assert_eq!(error, Err(device_database_refusal(key)), "{key}");
            assert_eq!(*variables.set.borrow(), [], "{key}: writes");
        }
        for (setup_mode, grant, lifts, case) in [
            (
                Some(&[0][..]),
                UnsafeOperations::Refuse,
                false,
                "SetupMode 0",
            ),
            (None, UnsafeOperations::Refuse, false, "no SetupMode"),
            (
                Some(&[1][..]),
                UnsafeOperations::Allow,
                true,
                "SetupMode 1, allowed",
            ),
        ] {
            for key in &databases {
                let variables = firmware(setup_mode);

                let lifted = write_signed(&variables, key, NV_BS_RT_ENHANCED, &payload, grant)
                    .unwrap_or_else(|error| panic!("{key}, {case}: {error:#}"));

                assert_eq!(
                    held(&variables, key),
                    written(0x87, &payload),
                    "{key}, {case}"
                );
                let operation = UnsafeOperation::SetupModeDeviceDatabaseWrite {
                    variable: key.clone(),
                    setup_mode: SetupModeReading::One,
                };
                assert_eq!(
                    lifted,
                    lifts.then_some(operation).into_iter().collect::<Vec<_>>(),
                    "{key}, {case}: lifted"
                );
            }
        }
    }

    /// sign_and_write_enhanced refuses devdb while SetupMode is 1 unless allowed, after it signs,
    /// as write_signed does: the firmware may not check the signature (UEFI 2.11 §32.6.3).
    /// Without a seed source it fails at the seed, with the flag and without, reading no
    /// SetupMode. It writes devdb when SetupMode is 0 or absent, lifting nothing, or when
    /// allowed, lifting the write.
    #[test]
    fn sign_and_write_enhanced_refuses_devdb_in_setup_mode_unless_allowed() {
        let devdb = key("devdb", DEVDB_VENDOR);
        let freshness =
            Freshness::TimeStamp(signing::tests::TIME.parse().expect("the test TimeStamp"));
        let signer = signing::tests::test_signer();
        let write = |variables: &HeldVariables, unsafe_operations, seed| {
            sign_and_write_enhanced(
                variables,
                &EnhancedSignedWrite {
                    unsafe_operations,
                    ..enhanced_signed_write(&devdb, NV_BS_RT, VALUE, &freshness)
                },
                &signer,
                None,
                &mut signing::tests::FakeSeed(seed),
            )
        };

        let refused = firmware(Some(&[1]));
        let error = write(&refused, UnsafeOperations::Refuse, Some(1))
            .map_err(|error| format!("{error:#}"));
        assert_eq!(error, Err(device_database_refusal(&devdb)), "the refusal");
        assert_eq!(*refused.set.borrow(), [], "writes without the flag");

        for grant in GRANTS {
            let unseeded = firmware(Some(&[1]));

            let error = write(&unseeded, grant, None).map_err(|error| format!("{error:#}"));

            assert_eq!(
                error,
                Err(
                    "cannot seed RSA blinding from EFI_RNG_PROTOCOL: no handle has it: NOT_FOUND"
                        .to_owned()
                ),
                "{grant:?} without a seed source"
            );
            assert_eq!(
                *unseeded.read.borrow(),
                [],
                "{grant:?} without a seed source: reads"
            );
        }

        let expected = signer
            .authentication_3(
                &EnhancedWrite {
                    key: &devdb,
                    attributes: NV_BS_RT_ENHANCED,
                    freshness: &freshness,
                    data: VALUE,
                },
                None,
                &mut rand_chacha::ChaCha20Rng::seed_from_u64(0),
            )
            .expect("sign");
        for (setup_mode, grant, lifts, case) in [
            (
                Some(&[0][..]),
                UnsafeOperations::Refuse,
                false,
                "SetupMode 0",
            ),
            (None, UnsafeOperations::Refuse, false, "no SetupMode"),
            (
                Some(&[1][..]),
                UnsafeOperations::Allow,
                true,
                "SetupMode 1, allowed",
            ),
        ] {
            let variables = firmware(setup_mode);

            let lifted = write(&variables, grant, Some(1))
                .unwrap_or_else(|error| panic!("{case}: {error:#}"));

            assert_eq!(held(&variables, &devdb), written(0x87, &expected), "{case}");
            let operation = UnsafeOperation::SetupModeDeviceDatabaseWrite {
                variable: devdb.clone(),
                setup_mode: SetupModeReading::One,
            };
            assert_eq!(
                lifted,
                lifts.then_some(operation).into_iter().collect::<Vec<_>>(),
                "{case}: lifted"
            );
        }
    }
}
