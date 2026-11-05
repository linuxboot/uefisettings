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

//! Writes of time-based authenticated EFI variables from pre-signed payloads (UEFI 2.11
//! §8.2.6), which `variable write-signed` makes: the payload, an EFI_VARIABLE_AUTHENTICATION_2
//! descriptor and the variable's new data, goes to SetVariable() unchanged, as its signature
//! covers the name, vendor GUID, attributes and time stamp that it was made for. uefisettings
//! checks that the descriptor is complete and refuses, before any write, a payload that would
//! delete the variable and a write that the firmware would make without checking the signature.
//! The backends' VariableData does the I/O: efivarfs on Linux (hii/efivarfs.rs), SetVariable() in
//! the UEFI Shell (hii/variable_services.rs), and SetFirmwareEnvironmentVariableExW on Windows
//! (hii/firmware_environment.rs), whose dwAttributes carries
//! VARIABLE_ATTRIBUTE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS (Microsoft Learn, updated
//! 2024-11-20).

use anyhow::Result;
use thiserror::Error;

use super::globals::EFI_GLOBAL_VARIABLE;
use super::globals::EFI_IMAGE_SECURITY_DATABASE;
use super::RuntimeAccessWithoutBootServiceAccess;
use super::VariableContents;
use super::VariableData;
use crate::hii::package::Guid;
use crate::hii::VariableAttributes;
use crate::hii::VariableKey;

/// The size of EFI_TIME (UEFI 2.11 §8.3.1), the TimeStamp that starts an
/// EFI_VARIABLE_AUTHENTICATION_2.
const EFI_TIME_SIZE: usize = 16;
/// The size of a WIN_CERTIFICATE_UEFI_GUID before its CertData: the dwLength, wRevision and
/// wCertificateType of its Hdr, and its CertType (UEFI 2.11 §32.2.4.1, §32.2.4.3).
const CERTIFICATE_HEADER_SIZE: usize = 24;
/// WIN_CERT_TYPE_EFI_GUID (UEFI 2.11 §32.2.4.1).
const WIN_CERT_TYPE_EFI_GUID: u16 = 0x0EF1;
/// EFI_CERT_TYPE_PKCS7_GUID (UEFI 2.11 §32.2.4.3), the only CertType that an
/// EFI_VARIABLE_AUTHENTICATION_2 takes (§8.2.3).
const EFI_CERT_TYPE_PKCS7_GUID: Guid = Guid {
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
/// The variable of EFI_GLOBAL_VARIABLE that tells whether the firmware writes the Secure Boot
/// Policy Variables without checking their signatures (UEFI 2.11 §3.3).
const SETUP_MODE: &str = "SetupMode";
/// The attributes that a signed write takes.
const SIGNED_WRITE_ATTRIBUTES: VariableAttributes = VariableAttributes::NON_VOLATILE
    .union(VariableAttributes::BOOTSERVICE_ACCESS)
    .union(VariableAttributes::RUNTIME_ACCESS)
    .union(VariableAttributes::APPEND_WRITE)
    .union(VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS);

/// Writes `payload`, an EFI_VARIABLE_AUTHENTICATION_2 descriptor and the new data of the
/// variable `key` (UEFI 2.11 §8.2.6), through `variables` with `attributes` and
/// EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS. Before any write, it refuses other
/// attributes, attributes without access, a payload without a complete descriptor, one without
/// data unless it appends, either of which would delete the variable, and a Secure Boot Policy
/// Variable while SetupMode is 1.
pub(crate) fn write_signed(
    variables: &impl VariableData,
    key: &VariableKey,
    attributes: VariableAttributes,
    payload: &[u8],
) -> Result<()> {
    let attributes = signed_write_attributes(attributes)?;
    let value = auth2_value(payload)?;
    if value.is_empty() && !attributes.contains(VariableAttributes::APPEND_WRITE) {
        return Err(SignedWriteRefusal::Delete(key.clone()).into());
    }
    if is_secure_boot_policy_variable(key) && in_setup_mode(variables)? {
        return Err(SignedWriteRefusal::SetupModePolicyWrite(key.clone()).into());
    }
    variables.set_variable(key, &VariableContents::new(attributes, payload.to_vec())?)
}

/// What write_signed refuses before any write. The messages spell "section", as edk2's
/// terminals but VT-UTF8 show '?' for '§' (edk2-stable202508 TerminalDxe/TerminalConOut.c
/// TerminalConOutOutputString()).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
enum SignedWriteRefusal {
    #[error(
        "{0}: a signed write takes only NON_VOLATILE, BOOTSERVICE_ACCESS, RUNTIME_ACCESS and \
         APPEND_WRITE, and adds TIME_BASED_AUTHENTICATED_WRITE_ACCESS"
    )]
    Attributes(VariableAttributes),
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
        "EFI variable {0} is a Secure Boot policy variable and SetupMode is 1, so the firmware \
         would write it without checking the payload's signature (UEFI 2.11 sections 3.3 and \
         8.2.6)"
    )]
    SetupModePolicyWrite(VariableKey),
    #[error("SetupMode holds {0} bytes, not the 1 of a UINT8 (UEFI 2.11 section 3.3)")]
    SetupModeSize(usize),
    #[error("SetupMode is {0}, neither 0 nor 1 (UEFI 2.11 section 3.3)")]
    SetupModeValue(u8),
    #[error(
        "{0}: without BOOTSERVICE_ACCESS and RUNTIME_ACCESS, a write deletes the variable: \
         \"Setting a data variable with no access attributes causes it to be deleted\" (UEFI 2.11 \
         section 8.2.3), which a signed write does not do"
    )]
    NoAccess(VariableAttributes),
}

/// `attributes` and EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS, unless they hold an
/// attribute that a signed write does not take, runtime access without boot service access, or
/// no access attribute, with which a write deletes the variable (UEFI 2.11 §8.2.3).
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
    Ok(attributes.union(VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS))
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
    // Year, Month, Day, Hour, Minute and Second, then Pad1, Nanosecond, TimeZone, Daylight and
    // Pad2 (UEFI 2.11 §8.3.1)
    let [_, _, _, _, _, _, _, gmt_fields @ ..] = *time_stamp;
    if gmt_fields.iter().any(|&byte| byte != 0) {
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

/// Whether the firmware of `variables` is in Setup Mode, where it writes the Secure Boot Policy
/// Variables without checking their signatures (UEFI 2.11 §8.2.6): SetupMode is 1. Firmware
/// without SetupMode, which a firmware with Secure Boot creates (§3.3), is not.
fn in_setup_mode(variables: &impl VariableData) -> Result<bool> {
    let key = VariableKey {
        name: SETUP_MODE.to_string(),
        guid: EFI_GLOBAL_VARIABLE,
    };
    let Some(setup_mode) = variables.variable_data(&key)? else {
        return Ok(false);
    };
    match setup_mode.data() {
        [0] => Ok(false),
        [1] => Ok(true),
        [value] => Err(SignedWriteRefusal::SetupModeValue(*value).into()),
        data => Err(SignedWriteRefusal::SetupModeSize(data.len()).into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::efi_variables::globals::tests::key;
    use crate::efi_variables::globals::tests::HeldVariables;
    use crate::efi_variables::globals::tests::NV_BS_RT;

    /// A stand-in for the DER of a PKCS #7 SignedData, which uefisettings does not parse.
    const CERT_DATA: &[u8] = b"\x30\x80signed data";
    /// The new data of the variables that the payloads write.
    const VALUE: &[u8] = b"a signature list";
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

            write_signed(&variables, &key, attributes, &payload)
                .unwrap_or_else(|error| panic!("{case}: {error:#}"));

            assert_eq!(
                held(&variables, &key),
                written(set_attributes, &payload),
                "{case}"
            );
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

        let error = write_signed(&variables, &signed, NV_BS_RT, &auth2(&[]))
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

    /// write_signed refuses each Secure Boot Policy Variable (UEFI 2.11 §3.3) while SetupMode is
    /// 1, and writes it when SetupMode is 0 or absent; it writes any other variable whatever
    /// SetupMode is, without reading it.
    #[test]
    fn write_signed_refuses_policy_variables_in_setup_mode() {
        let policy = [
            key("PK", EFI_GLOBAL_VARIABLE),
            key("KEK", EFI_GLOBAL_VARIABLE),
            key("OsRecoveryOrder", EFI_GLOBAL_VARIABLE),
            key("OsRecovery0000", VENDOR),
            key("OsRecovery09AF", EFI_GLOBAL_VARIABLE),
            key("OsRecoveryFFFF", VENDOR),
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

            let error =
                write_signed(&variables, key, attributes, &payload).expect_err(&key.to_string());

            assert_eq!(
                error.to_string(),
                format!(
                    "EFI variable {key} is a Secure Boot policy variable and SetupMode is 1, so \
                     the firmware would write it without checking the payload's signature (UEFI \
                     2.11 sections 3.3 and 8.2.6)"
                ),
                "{key}"
            );
            assert_eq!(*variables.set.borrow(), [], "{key}: writes");
        }
        for (setup_mode, case) in [(Some(&[0][..]), "SetupMode 0"), (None, "no SetupMode")] {
            for key in &policy {
                let variables = firmware(setup_mode);

                write_signed(&variables, key, attributes, &payload)
                    .unwrap_or_else(|error| panic!("{key}, {case}: {error:#}"));

                assert_eq!(
                    held(&variables, key),
                    written(0x67, &payload),
                    "{key}, {case}"
                );
            }
        }
        for key in &others {
            let variables = firmware(Some(&[1]));

            write_signed(&variables, key, attributes, &payload)
                .unwrap_or_else(|error| panic!("{key}: {error:#}"));

            assert_eq!(held(&variables, key), written(0x67, &payload), "{key}");
            assert_eq!(*variables.read.borrow(), [], "{key}: reads");
        }
    }

    /// write_signed refuses a SetupMode other than a UINT8 of 0 or 1 when it writes a Secure Boot
    /// Policy Variable, and writes nothing then.
    #[test]
    fn write_signed_refuses_a_malformed_setup_mode() {
        let db = key("db", EFI_IMAGE_SECURITY_DATABASE);
        for (setup_mode, refusal) in [
            (
                &[1, 0][..],
                "SetupMode holds 2 bytes, not the 1 of a UINT8 (UEFI 2.11 section 3.3)",
            ),
            (
                &[2],
                "SetupMode is 2, neither 0 nor 1 (UEFI 2.11 section 3.3)",
            ),
        ] {
            let variables = firmware(Some(setup_mode));

            let error = write_signed(
                &variables,
                &db,
                NV_BS_RT | VariableAttributes::APPEND_WRITE,
                &auth2(VALUE),
            )
            .expect_err("write with a malformed SetupMode");

            assert_eq!(error.to_string(), refusal, "SetupMode {setup_mode:?}");
            assert_eq!(
                *variables.set.borrow(),
                [],
                "SetupMode {setup_mode:?}: writes"
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
                 BOOTSERVICE_ACCESS, RUNTIME_ACCESS and APPEND_WRITE, and adds \
                 TIME_BASED_AUTHENTICATED_WRITE_ACCESS",
            ),
            (
                VariableAttributes::AUTHENTICATED_WRITE_ACCESS | NV_BS_RT,
                "AUTHENTICATED_WRITE_ACCESS: a signed write takes only NON_VOLATILE, \
                 BOOTSERVICE_ACCESS, RUNTIME_ACCESS and APPEND_WRITE, and adds \
                 TIME_BASED_AUTHENTICATED_WRITE_ACCESS",
            ),
            (
                VariableAttributes::ENHANCED_AUTHENTICATED_ACCESS
                    | VariableAttributes::HARDWARE_ERROR_RECORD,
                "HARDWARE_ERROR_RECORD | ENHANCED_AUTHENTICATED_ACCESS: a signed write takes \
                 only NON_VOLATILE, BOOTSERVICE_ACCESS, RUNTIME_ACCESS and APPEND_WRITE, and adds \
                 TIME_BASED_AUTHENTICATED_WRITE_ACCESS",
            ),
            (
                VariableAttributes::from_bits_retain(0x100) | NV_BS_RT,
                "0x100: a signed write takes only NON_VOLATILE, BOOTSERVICE_ACCESS, \
                 RUNTIME_ACCESS and APPEND_WRITE, and adds TIME_BASED_AUTHENTICATED_WRITE_ACCESS",
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

            let error = write_signed(&variables, &signed, attributes, &auth2(VALUE))
                .expect_err(&attributes.to_string());

            assert_eq!(error.to_string(), refusal, "{attributes}");
            assert_eq!(*variables.set.borrow(), [], "{attributes}: writes");
        }
    }

    /// VariableData whose every read fails, and which hold what is set.
    struct UnreadableVariables(HeldVariables);

    impl VariableData for UnreadableVariables {
        fn variable_data(&self, key: &VariableKey) -> Result<Option<VariableContents>> {
            Err(anyhow::anyhow!("cannot read EFI variable {key}"))
        }

        fn set_variable(&self, key: &VariableKey, contents: &VariableContents) -> Result<()> {
            self.0.set_variable(key, contents)
        }
    }

    /// write_signed refuses a Secure Boot Policy Variable when SetupMode cannot be read, and
    /// writes nothing then.
    #[test]
    fn write_signed_refuses_a_policy_variable_when_setup_mode_is_unreadable() {
        let variables = UnreadableVariables(HeldVariables::default());
        let db = key("db", EFI_IMAGE_SECURITY_DATABASE);

        let error = write_signed(
            &variables,
            &db,
            NV_BS_RT | VariableAttributes::APPEND_WRITE,
            &auth2(VALUE),
        )
        .expect_err("write db with an unreadable SetupMode");

        assert_eq!(
            error.to_string(),
            "cannot read EFI variable SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c",
            "refusal"
        );
        assert_eq!(*variables.0.set.borrow(), [], "writes");
    }
}
