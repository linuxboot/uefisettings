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

//! The metadata that starts the GetVariable() data of an EFI variable with
//! EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS, before its value (UEFI 2.11 §8.2.1): an
//! EFI_VARIABLE_AUTHENTICATION_3, then an EFI_TIME or an EFI_VARIABLE_AUTHENTICATION_3_NONCE as its
//! Type says, then an EFI_VARIABLE_AUTHENTICATION_3_CERT_ID. The hii module skips the metadata to
//! decode the value on every build. And the SetVariable() Data of such a variable (§8.2.5), which
//! `variable write-signed` checks or makes: the EFI_VARIABLE_AUTHENTICATION_3, the EFI_TIME or the
//! EFI_VARIABLE_AUTHENTICATION_3_NONCE, a NewCert when Flags has
//! EFI_VARIABLE_ENHANCED_AUTH_FLAG_UPDATE_CERT, the SigningCert, then the new data.
//! Each structure is aligned to its largest field (UEFI 2.11 §2.3.1), so an
//! EFI_VARIABLE_AUTHENTICATION_3 takes 12 bytes, 2 zero bytes after Type. Between structures,
//! §8.2.5's "||", concatenation, leaves open whether zero bytes pad: uefisettings reads and writes
//! the C layout, in which CERT_ID and each WIN_CERTIFICATE_UEFI_GUID start on a 4-byte boundary
//! (CERTIFICATE_ALIGNMENT) after zero bytes, as edk2-stable202608 lays out its GUID, of a UINT32,
//! two UINT16s and 8 UINT8s (MdePkg/Include/Base.h), and its unpacked WIN_CERTIFICATE_UEFI_GUID
//! (MdePkg/Include/Guid/WinCertificate.h). edk2-stable202608 implements no
//! EFI_VARIABLE_AUTHENTICATION_3 that would settle it.

#[cfg(variable_data)]
use std::str::FromStr;

use thiserror::Error;

#[cfg(variable_data)]
use super::authenticated::TimeStamp;
#[cfg(variable_data)]
use super::authenticated::CERTIFICATE_HEADER_SIZE;
#[cfg(variable_data)]
use super::authenticated::EFI_CERT_TYPE_PKCS7_GUID;
#[cfg(variable_data)]
use super::authenticated::WIN_CERT_REVISION;
#[cfg(variable_data)]
use super::authenticated::WIN_CERT_TYPE_EFI_GUID;
use super::is_gmt_time_stamp;
use super::EFI_TIME_SIZE;
#[cfg(variable_data)]
use crate::hex_digits::hex_bytes;
#[cfg(variable_data)]
use crate::hii::package::Guid;
use crate::hii::VariableAttributes;

/// A UINT32 field of the metadata.
const UINT32_SIZE: usize = std::mem::size_of::<u32>();
/// The offset of EFI_VARIABLE_AUTHENTICATION_3's MetadataSize, after Version, Type and 2 padding
/// bytes.
const METADATA_SIZE_OFFSET: usize = 4;
/// The offset of EFI_VARIABLE_AUTHENTICATION_3's Flags.
const FLAGS_OFFSET: usize = METADATA_SIZE_OFFSET + UINT32_SIZE;
/// EFI_VARIABLE_AUTHENTICATION_3 (UEFI 2.11 §8.2.3), which ends with Flags.
const AUTHENTICATION_3_SIZE: usize = FLAGS_OFFSET + UINT32_SIZE;
/// EFI_VARIABLE_AUTHENTICATION_3's Version, "hardcoded to “0x1”" (UEFI 2.11 §8.2.3).
const AUTHENTICATION_3_VERSION: u8 = 1;
/// EFI_VARIABLE_AUTHENTICATION_3_TIMESTAMP_TYPE (UEFI 2.11 §8.2.3).
const AUTHENTICATION_3_TIMESTAMP_TYPE: u8 = 1;
/// EFI_VARIABLE_AUTHENTICATION_3_NONCE_TYPE (UEFI 2.11 §8.2.3).
const AUTHENTICATION_3_NONCE_TYPE: u8 = 2;
/// EFI_VARIABLE_AUTHENTICATION_3_NONCE before its Nonce: NonceSize (UEFI 2.11 §8.2.3).
const NONCE_HEADER_SIZE: usize = UINT32_SIZE;
/// Where the structure after the Secondary Descriptor starts: on a multiple of this, after zero
/// bytes, in the C layout of the module doc. EFI_VARIABLE_AUTHENTICATION_3_CERT_ID on GetVariable()
/// is aligned to its UINT32 IdSize, and a WIN_CERTIFICATE_UEFI_GUID on SetVariable() to the UINT32
/// dwLength of its Hdr and the UINT32 Data1 of its CertType.
const CERTIFICATE_ALIGNMENT: usize = UINT32_SIZE;
/// EFI_VARIABLE_ENHANCED_AUTH_FLAG_UPDATE_CERT, "the only defined value" of Flags on SetVariable()
/// (UEFI 2.11 §8.2.3): a NewCert precedes the SigningCert.
#[cfg(variable_data)]
const UPDATE_CERT: u32 = 0x0000_0001;
/// The offset of EFI_VARIABLE_AUTHENTICATION_3_CERT_ID's IdSize, after Type and 3 padding bytes.
const ID_SIZE_OFFSET: usize = 4;
/// EFI_VARIABLE_AUTHENTICATION_3_CERT_ID before its Id: Type, 3 padding bytes and IdSize (UEFI
/// 2.11 §8.2.1).
const CERT_ID_HEADER_SIZE: usize = ID_SIZE_OFFSET + UINT32_SIZE;
/// EFI_VARIABLE_AUTHENTICATION_3_CERT_ID_SHA256 (UEFI 2.11 §8.2.1).
const CERT_ID_SHA256: u8 = 1;
/// The Id of a CERT_ID_SHA256: "a SHA-256 digest of the tbsCertificate" (UEFI 2.11 §8.2.1).
const SHA256_DIGEST_SIZE: usize = 32;

/// Why the EFI_VARIABLE_AUTHENTICATION_3 metadata of a variable is refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum MetadataRefusal {
    #[error(
        "it also has EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS, which SetVariable() \
         refuses with it (UEFI 2.11 section 8.2.3)"
    )]
    TimeBasedToo,
    #[error("its {0} bytes of data end inside its metadata")]
    Truncated(usize),
    #[error("EFI_VARIABLE_AUTHENTICATION_3 Version {0}, not 1")]
    Version(u8),
    #[error("EFI_VARIABLE_AUTHENTICATION_3 Type {0}, neither TIMESTAMP (1) nor NONCE (2)")]
    Type(u8),
    #[error("EFI_VARIABLE_AUTHENTICATION_3 Flags {0:#x}: all flags are reserved on GetVariable()")]
    Flags(u32),
    #[error("its TimeStamp has a nonzero Pad1, Nanosecond, TimeZone, Daylight or Pad2")]
    TimeStamp,
    #[error("EFI_VARIABLE_AUTHENTICATION_3_NONCE NonceSize 0")]
    NonceSize,
    #[error(
        "nonzero padding between EFI_VARIABLE_AUTHENTICATION_3_NONCE and \
         EFI_VARIABLE_AUTHENTICATION_3_CERT_ID"
    )]
    NoncePadding,
    #[error("EFI_VARIABLE_AUTHENTICATION_3_CERT_ID Type {0}, not CERT_ID_SHA256 (1)")]
    CertIdType(u8),
    #[error("EFI_VARIABLE_AUTHENTICATION_3_CERT_ID IdSize {0}, not 32")]
    IdSize(u32),
    #[error("MetadataSize {declared}, but its descriptors end at byte {computed}")]
    MetadataSize { declared: u32, computed: usize },
}

impl MetadataRefusal {
    /// `data` ends inside its metadata.
    pub(crate) fn truncated(data: &[u8]) -> Self {
        Self::Truncated(data.len())
    }
}

/// Whether the GetVariable() data of a variable with `attributes` starts with metadata: with
/// EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS. Refuses
/// EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS with it, which SetVariable() refuses
/// (UEFI 2.11 §8.2.3), so the data would start with no metadata that is known.
pub(crate) fn has_metadata(attributes: u32) -> Result<bool, MetadataRefusal> {
    let attributes = VariableAttributes::from_bits_retain(attributes);
    if !attributes.contains(VariableAttributes::ENHANCED_AUTHENTICATED_ACCESS) {
        return Ok(false);
    }
    if attributes.contains(VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS) {
        return Err(MetadataRefusal::TimeBasedToo);
    }
    Ok(true)
}

/// Where the value starts in `data`, the GetVariable() data of a variable with `attributes`:
/// after its metadata (has_metadata), else at 0.
pub(crate) fn metadata_end(attributes: u32, data: &[u8]) -> Result<usize, MetadataRefusal> {
    match has_metadata(attributes)? {
        true => authentication_3_metadata_size(data),
        false => Ok(0),
    }
}

/// The size of the metadata that starts `data`, checked strictly: Version 1, Flags 0, a
/// TimeStamp in GMT or a NonceSize other than 0, CERT_ID_SHA256 with IdSize 32, and a
/// MetadataSize where these descriptors end, as GetVariable() returns no
/// WIN_CERTIFICATE_UEFI_GUID (UEFI 2.11 §8.2.1).
fn authentication_3_metadata_size(data: &[u8]) -> Result<usize, MetadataRefusal> {
    match byte(data, 0)? {
        AUTHENTICATION_3_VERSION => {}
        version => return Err(MetadataRefusal::Version(version)),
    }
    let type_ = byte(data, 1)?;
    let declared = le_u32(data, METADATA_SIZE_OFFSET)?;
    match le_u32(data, FLAGS_OFFSET)? {
        0 => {}
        flags => return Err(MetadataRefusal::Flags(flags)),
    }
    let cert_id = match type_ {
        AUTHENTICATION_3_TIMESTAMP_TYPE => {
            let time_stamp = data
                .get(AUTHENTICATION_3_SIZE..)
                .and_then(<[u8]>::first_chunk::<EFI_TIME_SIZE>)
                .ok_or(MetadataRefusal::truncated(data))?;
            if !is_gmt_time_stamp(time_stamp) {
                return Err(MetadataRefusal::TimeStamp);
            }
            AUTHENTICATION_3_SIZE + EFI_TIME_SIZE
        }
        AUTHENTICATION_3_NONCE_TYPE => {
            let nonce_size = match le_u32(data, AUTHENTICATION_3_SIZE)? {
                0 => return Err(MetadataRefusal::NonceSize),
                nonce_size => nonce_size,
            };
            let nonce_end = usize::try_from(nonce_size)
                .ok()
                .and_then(|size| (AUTHENTICATION_3_SIZE + NONCE_HEADER_SIZE).checked_add(size))
                .ok_or(MetadataRefusal::truncated(data))?;
            let cert_id = nonce_end
                .checked_next_multiple_of(CERTIFICATE_ALIGNMENT)
                .ok_or(MetadataRefusal::truncated(data))?;
            let padding = data
                .get(nonce_end..cert_id)
                .ok_or(MetadataRefusal::truncated(data))?;
            if padding.iter().any(|&byte| byte != 0) {
                return Err(MetadataRefusal::NoncePadding);
            }
            cert_id
        }
        type_ => return Err(MetadataRefusal::Type(type_)),
    };
    match byte(data, cert_id)? {
        CERT_ID_SHA256 => {}
        cert_type => return Err(MetadataRefusal::CertIdType(cert_type)),
    }
    let id_size = cert_id
        .checked_add(ID_SIZE_OFFSET)
        .ok_or(MetadataRefusal::truncated(data))
        .and_then(|at| le_u32(data, at))?;
    if usize::try_from(id_size) != Ok(SHA256_DIGEST_SIZE) {
        return Err(MetadataRefusal::IdSize(id_size));
    }
    let computed = cert_id
        .checked_add(CERT_ID_HEADER_SIZE + SHA256_DIGEST_SIZE)
        .ok_or(MetadataRefusal::truncated(data))?;
    if usize::try_from(declared) != Ok(computed) {
        return Err(MetadataRefusal::MetadataSize { declared, computed });
    }
    if data.len() < computed {
        return Err(MetadataRefusal::truncated(data));
    }
    Ok(computed)
}

/// The little-endian UINT32 at `at` of `data`.
fn le_u32(data: &[u8], at: usize) -> Result<u32, MetadataRefusal> {
    u32_at(data, at).ok_or(MetadataRefusal::truncated(data))
}

/// The little-endian UINT32 at `at` of `data`, if it holds one there.
fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    data.get(at..)
        .and_then(<[u8]>::first_chunk::<UINT32_SIZE>)
        .copied()
        .map(u32::from_le_bytes)
}

/// The byte at `at` of `data`.
fn byte(data: &[u8], at: usize) -> Result<u8, MetadataRefusal> {
    data.get(at)
        .copied()
        .ok_or(MetadataRefusal::truncated(data))
}

/// How the payload of an EFI_VARIABLE_AUTHENTICATION_3 is kept from being replayed: its Type and
/// the Secondary Descriptor after it (UEFI 2.11 §8.2.3, §8.2.5).
#[cfg(variable_data)]
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Freshness {
    /// EFI_VARIABLE_AUTHENTICATION_3_TIMESTAMP_TYPE: an EFI_TIME, which must be later than the
    /// variable's
    TimeStamp(TimeStamp),
    /// EFI_VARIABLE_AUTHENTICATION_3_NONCE_TYPE: `nonce`, which must differ from the variable's,
    /// and `current`, the nonce that the variable holds, which an update or deletion signs after
    /// the data and a create, without one, does not (UEFI 2.11 §8.2.5 step 3c)
    Nonce {
        nonce: Nonce,
        current: Option<Nonce>,
    },
}

#[cfg(variable_data)]
impl Freshness {
    /// The Type of the EFI_VARIABLE_AUTHENTICATION_3.
    fn type_code(&self) -> u8 {
        match self {
            Self::TimeStamp(_) => AUTHENTICATION_3_TIMESTAMP_TYPE,
            Self::Nonce { .. } => AUTHENTICATION_3_NONCE_TYPE,
        }
    }

    /// The Secondary Descriptor: the EFI_TIME, or the EFI_VARIABLE_AUTHENTICATION_3_NONCE, its
    /// NonceSize and Nonce (UEFI 2.11 §8.2.5 step 2).
    pub(crate) fn secondary_descriptor(&self) -> Vec<u8> {
        match self {
            Self::TimeStamp(timestamp) => timestamp.as_bytes().to_vec(),
            Self::Nonce { nonce, .. } => [&nonce.size.to_le_bytes()[..], &nonce.bytes].concat(),
        }
    }

    /// The nonce that UEFI 2.11 §8.2.5 step 3c signs after the data: the current nonce of a
    /// variable of EFI_VARIABLE_AUTHENTICATION_3_NONCE_TYPE that the write updates or deletes.
    pub(crate) fn current_nonce(&self) -> Option<&[u8]> {
        match self {
            Self::TimeStamp(_) | Self::Nonce { current: None, .. } => None,
            Self::Nonce {
                current: Some(current),
                ..
            } => Some(&current.bytes),
        }
    }
}

/// The Nonce of an EFI_VARIABLE_AUTHENTICATION_3_NONCE: 1 byte or more, as many as its UINT32
/// NonceSize counts; all zero, it asks the firmware to make a random one (UEFI 2.11 §8.2.3).
#[cfg(variable_data)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Nonce {
    bytes: Vec<u8>,
    /// The NonceSize of `bytes`.
    size: u32,
}

#[cfg(variable_data)]
impl Nonce {
    /// The nonce of `bytes`, unless they are none, or more than NonceSize counts.
    pub fn new(bytes: Vec<u8>) -> Result<Self, NonceError> {
        let size = u32::try_from(bytes.len()).map_err(|_| NonceError::TooLarge(bytes.len()))?;
        if size == 0 {
            return Err(NonceError::Empty);
        }
        Ok(Self { bytes, size })
    }
}

#[cfg(variable_data)]
impl FromStr for Nonce {
    type Err = NonceError;

    /// Takes two hex digits of either case per byte.
    fn from_str(digits: &str) -> Result<Self, NonceError> {
        let bytes = hex_bytes(digits).ok_or_else(|| NonceError::Digits(digits.to_owned()))?;
        Self::new(bytes)
    }
}

#[cfg(variable_data)]
impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

/// Why a nonce was refused.
#[cfg(variable_data)]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum NonceError {
    #[error(
        "the nonce is empty; the NonceSize of an EFI_VARIABLE_AUTHENTICATION_3_NONCE \"Must not \
         be 0\" (UEFI 2.11 section 8.2.3)"
    )]
    Empty,
    #[error("the nonce holds {0} bytes, more than NonceSize, a UINT32, counts")]
    TooLarge(usize),
    #[error("the nonce {0:?} is not two hex digits per byte")]
    Digits(String),
}

/// The EFI_VARIABLE_AUTHENTICATION_3 metadata of a payload takes more bytes than its UINT32
/// MetadataSize counts.
#[cfg(variable_data)]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "the EFI_VARIABLE_AUTHENTICATION_3 metadata takes more than the {} bytes that MetadataSize, a \
     UINT32, counts",
    u32::MAX
)]
pub(crate) struct MetadataTooLarge;

/// The SetVariable() Data of an EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS write (UEFI 2.11
/// §8.2.5): an EFI_VARIABLE_AUTHENTICATION_3 of `freshness`'s Type, with
/// EFI_VARIABLE_ENHANCED_AUTH_FLAG_UPDATE_CERT if `new_cert` is given and a MetadataSize of all
/// but the data; the Secondary Descriptor; `new_cert`, if given; `signing_cert`; then `data`.
/// Each certificate starts on CERTIFICATE_ALIGNMENT after zero bytes.
#[cfg(variable_data)]
pub(crate) fn authentication_3_payload(
    freshness: &Freshness,
    new_cert: Option<&[u8]>,
    signing_cert: &[u8],
    data: &[u8],
) -> Result<Vec<u8>, MetadataTooLarge> {
    let mut metadata = freshness.secondary_descriptor();
    let flags = match new_cert {
        Some(new_cert) => {
            pad_to_certificate(&mut metadata)?;
            metadata.extend_from_slice(new_cert);
            UPDATE_CERT
        }
        None => 0,
    };
    pad_to_certificate(&mut metadata)?;
    metadata.extend_from_slice(signing_cert);
    let metadata_size = AUTHENTICATION_3_SIZE
        .checked_add(metadata.len())
        .and_then(|size| u32::try_from(size).ok())
        .ok_or(MetadataTooLarge)?;
    Ok([
        &[AUTHENTICATION_3_VERSION, freshness.type_code(), 0, 0][..],
        &metadata_size.to_le_bytes(),
        &flags.to_le_bytes(),
        &metadata,
        data,
    ]
    .concat())
}

/// Zero bytes after `metadata`, what follows the EFI_VARIABLE_AUTHENTICATION_3 of a payload, up to
/// the next payload offset on CERTIFICATE_ALIGNMENT.
#[cfg(variable_data)]
fn pad_to_certificate(metadata: &mut Vec<u8>) -> Result<(), MetadataTooLarge> {
    let padded = AUTHENTICATION_3_SIZE
        .checked_add(metadata.len())
        .and_then(|end| end.checked_next_multiple_of(CERTIFICATE_ALIGNMENT))
        .ok_or(MetadataTooLarge)?;
    metadata.resize(padded - AUTHENTICATION_3_SIZE, 0);
    Ok(())
}

/// What write_signed takes from a pre-signed EFI_VARIABLE_AUTHENTICATION_3 payload.
#[cfg(variable_data)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Authentication3<'a> {
    /// Whether Flags has EFI_VARIABLE_ENHANCED_AUTH_FLAG_UPDATE_CERT, so a NewCert precedes the
    /// SigningCert
    pub(crate) new_cert: bool,
    /// The new data, after MetadataSize bytes
    pub(crate) data: &'a [u8],
}

/// Why a pre-signed EFI_VARIABLE_AUTHENTICATION_3 payload was refused. The messages spell
/// "section", as authenticated.rs's do.
#[cfg(variable_data)]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum Authentication3Refusal {
    #[error(
        "the payload holds {0} bytes, fewer than its EFI_VARIABLE_AUTHENTICATION_3 descriptors \
         need (UEFI 2.11 section 8.2.5)"
    )]
    Truncated(usize),
    #[error(
        "the payload's EFI_VARIABLE_AUTHENTICATION_3 Version is {0}, not 1 (UEFI 2.11 section \
         8.2.3)"
    )]
    Version(u8),
    #[error(
        "the payload's EFI_VARIABLE_AUTHENTICATION_3 holds {0:#06x} in the 2 bytes after Type, \
         which its naturally aligned 12-byte form pads with zeros (UEFI 2.11 section 2.3.1): it \
         looks like the packed 10-byte form, with MetadataSize right after Type, which \
         uefisettings does not take"
    )]
    PackedHeader(u16),
    #[error(
        "the payload's EFI_VARIABLE_AUTHENTICATION_3 Type is {0}, neither TIMESTAMP (1) nor NONCE \
         (2) (UEFI 2.11 section 8.2.3)"
    )]
    Type(u8),
    #[error(
        "the payload's EFI_VARIABLE_AUTHENTICATION_3 Flags is {0:#x}; all bits but \
         EFI_VARIABLE_ENHANCED_AUTH_FLAG_UPDATE_CERT (0x1) are reserved (UEFI 2.11 section 8.2.3)"
    )]
    Flags(u32),
    #[error(
        "the payload's EFI_TIME has a Pad1, Nanosecond, TimeZone, Daylight or Pad2 other than 0 \
         (UEFI 2.11 section 8.2.5)"
    )]
    TimeStampNotGmt,
    #[error("the payload's NonceSize is 0, which \"Must not be 0\" (UEFI 2.11 section 8.2.3)")]
    EmptyNonce,
    #[error(
        "the payload has a byte other than 0 at offset {0}, which pads up to its next \
         WIN_CERTIFICATE_UEFI_GUID"
    )]
    Padding(usize),
    #[error(
        "the payload's WIN_CERTIFICATE_UEFI_GUID at offset {0} is not one of \
         WIN_CERT_TYPE_EFI_GUID and EFI_CERT_TYPE_PKCS7_GUID whose CertData ends within the \
         payload (UEFI 2.11 section 8.2.5)"
    )]
    Certificate(usize),
    #[error(
        "the payload's WIN_CERTIFICATE_UEFI_GUID at offset {at} has wRevision {revision:#06x}, \
         not 0x0200 (UEFI 2.11 section 32.2.4.1)"
    )]
    Revision { at: usize, revision: u16 },
    #[error(
        "the payload's EFI_VARIABLE_AUTHENTICATION_3 MetadataSize is {declared}, but its \
         descriptors and certificates end at {found} (UEFI 2.11 section 8.2.5)"
    )]
    MetadataSize { declared: u32, found: usize },
}

/// The parts of `payload`, a pre-signed EFI_VARIABLE_AUTHENTICATION_3 payload (UEFI 2.11 §8.2.5),
/// after checking its descriptors: Version 1, zero padding after Type, a known Type and Flags, an
/// EFI_TIME in GMT or a NonceSize other than 0, zero padding before each certificate, each a
/// WIN_CERTIFICATE_UEFI_GUID of wRevision 0x0200, WIN_CERT_TYPE_EFI_GUID and
/// EFI_CERT_TYPE_PKCS7_GUID, and a MetadataSize where they end. The firmware verifies the
/// signatures.
#[cfg(variable_data)]
pub(crate) fn authentication_3_value(
    payload: &[u8],
) -> Result<Authentication3<'_>, Authentication3Refusal> {
    let truncated = || Authentication3Refusal::Truncated(payload.len());
    let header = payload
        .first_chunk::<AUTHENTICATION_3_SIZE>()
        .ok_or_else(truncated)?;
    let [version, type_code, p0, p1, ..] = *header;
    if version != AUTHENTICATION_3_VERSION {
        return Err(Authentication3Refusal::Version(version));
    }
    match u16::from_le_bytes([p0, p1]) {
        0 => {}
        padding => return Err(Authentication3Refusal::PackedHeader(padding)),
    }
    let metadata_size = u32_at(payload, METADATA_SIZE_OFFSET).ok_or_else(truncated)?;
    let flags = u32_at(payload, FLAGS_OFFSET).ok_or_else(truncated)?;
    if flags & !UPDATE_CERT != 0 {
        return Err(Authentication3Refusal::Flags(flags));
    }
    let descriptor_end = match type_code {
        AUTHENTICATION_3_TIMESTAMP_TYPE => {
            let time_stamp = payload
                .get(AUTHENTICATION_3_SIZE..)
                .and_then(<[u8]>::first_chunk::<EFI_TIME_SIZE>)
                .ok_or_else(truncated)?;
            if !is_gmt_time_stamp(time_stamp) {
                return Err(Authentication3Refusal::TimeStampNotGmt);
            }
            AUTHENTICATION_3_SIZE + EFI_TIME_SIZE
        }
        AUTHENTICATION_3_NONCE_TYPE => {
            let size = match u32_at(payload, AUTHENTICATION_3_SIZE).ok_or_else(truncated)? {
                0 => return Err(Authentication3Refusal::EmptyNonce),
                size => size,
            };
            usize::try_from(size)
                .ok()
                .and_then(|size| (AUTHENTICATION_3_SIZE + NONCE_HEADER_SIZE).checked_add(size))
                .filter(|&end| end <= payload.len())
                .ok_or_else(truncated)?
        }
        type_code => return Err(Authentication3Refusal::Type(type_code)),
    };
    let mut at = certificate_start(payload, descriptor_end)?;
    let new_cert = flags & UPDATE_CERT != 0;
    if new_cert {
        at = certificate_start(payload, certificate_end(payload, at)?)?;
    }
    let end = certificate_end(payload, at)?;
    if usize::try_from(metadata_size) != Ok(end) {
        return Err(Authentication3Refusal::MetadataSize {
            declared: metadata_size,
            found: end,
        });
    }
    let data = payload.get(end..).ok_or_else(truncated)?;
    Ok(Authentication3 { new_cert, data })
}

/// Where the certificate after `at` of `payload` starts: at the next multiple of
/// CERTIFICATE_ALIGNMENT, after checking that the bytes up to it are 0.
#[cfg(variable_data)]
fn certificate_start(payload: &[u8], at: usize) -> Result<usize, Authentication3Refusal> {
    let truncated = || Authentication3Refusal::Truncated(payload.len());
    let start = at
        .checked_next_multiple_of(CERTIFICATE_ALIGNMENT)
        .ok_or_else(truncated)?;
    let padding = payload.get(at..start).ok_or_else(truncated)?;
    match padding.iter().position(|&byte| byte != 0) {
        Some(offset) => Err(Authentication3Refusal::Padding(at + offset)),
        None => Ok(start),
    }
}

/// The end of the WIN_CERTIFICATE_UEFI_GUID at `at` of `payload`, which must be of
/// WIN_CERT_TYPE_EFI_GUID and EFI_CERT_TYPE_PKCS7_GUID with CertData within `payload` (UEFI 2.11
/// §8.2.5), and of wRevision 0x0200, the current revision (§32.2.4.1), which every
/// EFI_VARIABLE_AUTHENTICATION_3 that uefisettings signs carries; no firmware that would read
/// another is known.
#[cfg(variable_data)]
fn certificate_end(payload: &[u8], at: usize) -> Result<usize, Authentication3Refusal> {
    let refusal = Authentication3Refusal::Certificate(at);
    let header = payload
        .get(at..)
        .and_then(<[u8]>::first_chunk::<CERTIFICATE_HEADER_SIZE>)
        .ok_or_else(|| refusal.clone())?;
    let [l0, l1, l2, l3, r0, r1, t0, t1, cert_type @ ..] = *header;
    let typed = u16::from_le_bytes([t0, t1]) == WIN_CERT_TYPE_EFI_GUID
        && Guid::from(cert_type) == EFI_CERT_TYPE_PKCS7_GUID;
    let end = usize::try_from(u32::from_le_bytes([l0, l1, l2, l3]))
        .ok()
        .filter(|&length| typed && length > CERTIFICATE_HEADER_SIZE)
        .and_then(|length| at.checked_add(length))
        .filter(|&end| end <= payload.len())
        .ok_or(refusal)?;
    match u16::from_le_bytes([r0, r1]) {
        WIN_CERT_REVISION => Ok(end),
        revision => Err(Authentication3Refusal::Revision { at, revision }),
    }
}

/// EFI_VARIABLE_AUTHENTICATION_3 metadata for the tests.
#[cfg(test)]
pub(crate) mod fixture {
    /// EFI_VARIABLE_AUTHENTICATION_3_CERT_ID with a SHA-256 Id (UEFI 2.11 §8.2.1): Type, 3
    /// padding bytes, IdSize and the Id.
    fn cert_id_sha256() -> Vec<u8> {
        [
            &[1, 0, 0, 0][..],
            &32u32.to_le_bytes(),
            &(0..32).collect::<Vec<u8>>(),
        ]
        .concat()
    }

    /// EFI_VARIABLE_AUTHENTICATION_3 ‖ EFI_TIME ‖ EFI_VARIABLE_AUTHENTICATION_3_CERT_ID, the
    /// metadata of a variable with EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS (UEFI 2.11 §8.2.1),
    /// naturally aligned (§2.3.1): 68 bytes.
    pub(crate) fn timestamp_metadata() -> Vec<u8> {
        [
            &[1, 1, 0, 0][..],
            &68u32.to_le_bytes(),
            &0u32.to_le_bytes(),
            &[0xEA, 0x07, 11, 6, 12, 0, 0, 0],
            &[0; 8],
            &cert_id_sha256(),
        ]
        .concat()
    }

    /// EFI_VARIABLE_AUTHENTICATION_3 of MetadataSize `metadata_size` ‖
    /// EFI_VARIABLE_AUTHENTICATION_3_NONCE with `nonce` ‖ `padding` ‖
    /// EFI_VARIABLE_AUTHENTICATION_3_CERT_ID.
    #[cfg(efivar_dumps)]
    pub(crate) fn nonce_metadata_of(nonce: &[u8], padding: &[u8], metadata_size: u32) -> Vec<u8> {
        let nonce_size = u32::try_from(nonce.len()).expect("test nonce fits NonceSize");
        [
            &[1, 2, 0, 0][..],
            &metadata_size.to_le_bytes(),
            &0u32.to_le_bytes(),
            &nonce_size.to_le_bytes(),
            nonce,
            padding,
            &cert_id_sha256(),
        ]
        .concat()
    }

    /// nonce_metadata_of 8 Nonce bytes, which need no padding: 64 bytes.
    #[cfg(efivar_dumps)]
    pub(crate) fn nonce_metadata() -> Vec<u8> {
        nonce_metadata_of(&[0xA5; 8], &[], 64)
    }

    /// A WIN_CERTIFICATE_UEFI_GUID of `cert_data`, written out from UEFI 2.11 §32.2.4.1 and
    /// §32.2.4.3: dwLength of the header and CertData, wRevision 0x0200, wCertificateType
    /// WIN_CERT_TYPE_EFI_GUID, and CertType EFI_CERT_TYPE_PKCS7_GUID,
    /// 4AAFD29D-68DF-49EE-8AA9-347D375665A7, in EFI_GUID byte order.
    #[cfg(variable_data)]
    pub(crate) fn win_certificate_of(cert_data: &[u8]) -> Vec<u8> {
        let length = u32::try_from(24 + cert_data.len()).expect("test dwLength fits a UINT32");
        [
            &length.to_le_bytes()[..],
            &[0x00, 0x02, 0xF1, 0x0E],
            &[
                0x9D, 0xD2, 0xAF, 0x4A, 0xDF, 0x68, 0xEE, 0x49, 0x8A, 0xA9, 0x34, 0x7D, 0x37, 0x56,
                0x65, 0xA7,
            ],
            cert_data,
        ]
        .concat()
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::timestamp_metadata;
    use super::*;

    /// EFI variable Attributes: non-volatile, boot service and runtime access, and enhanced
    /// authenticated access.
    const NV_BS_RT_ENHANCED: u32 = 0x87;

    /// metadata_end takes metadata that ends the data, and refuses data that ends inside it.
    #[test]
    fn metadata_end_takes_metadata_that_ends_the_data() {
        let metadata = timestamp_metadata();

        assert_eq!(
            metadata_end(NV_BS_RT_ENHANCED, &metadata),
            Ok(68),
            "metadata alone"
        );
        assert_eq!(
            metadata_end(NV_BS_RT_ENHANCED, &metadata[..67]),
            Err(MetadataRefusal::Truncated(67)),
            "one byte short"
        );
    }
}

#[cfg(all(test, variable_data))]
mod payload_tests {
    use super::fixture::win_certificate_of;
    use super::*;

    /// The EFI_TIME of 2026-11-07T00:00:00Z: Year 0x07EA, Month 11, Day 7, then zeros (UEFI 2.11
    /// §8.3.1).
    const TIME: [u8; 16] = [0xEA, 0x07, 11, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

    fn timestamp() -> Freshness {
        Freshness::TimeStamp("2026-11-07T00:00:00Z".parse().expect("the test TimeStamp"))
    }

    fn nonce(bytes: &[u8]) -> Nonce {
        Nonce::new(bytes.to_vec()).expect("a test nonce")
    }

    /// A SigningCert of 29 bytes, not a multiple of 4.
    fn signing_cert() -> Vec<u8> {
        win_certificate_of(b"\x30\x80sig")
    }

    /// A NewCert of 30 bytes, not a multiple of 4.
    fn new_cert() -> Vec<u8> {
        win_certificate_of(b"\x30\x80new!")
    }

    /// The payload of a nonce-type write of NonceSize 1 with new_cert() and signing_cert(), then
    /// `data`: the descriptor ends at 17, so 3 zero bytes come before the NewCert at 20, which
    /// ends at 50, and 2 before the SigningCert at 52, which ends at 81.
    fn nonce_payload(data: &[u8]) -> Vec<u8> {
        authentication_3_payload(
            &Freshness::Nonce {
                nonce: nonce(&[0xA5]),
                current: None,
            },
            Some(&new_cert()),
            &signing_cert(),
            data,
        )
        .expect("a nonce payload")
    }

    /// A timestamp-type payload: the 12-byte EFI_VARIABLE_AUTHENTICATION_3 (Version 1, Type 1, 2
    /// zero bytes, MetadataSize, Flags 0), the EFI_TIME at 12, the SigningCert at 28, then the
    /// data at MetadataSize, 57.
    #[test]
    fn timestamp_payload_has_the_section_8_2_5_layout() {
        let payload = authentication_3_payload(&timestamp(), None, &signing_cert(), b"value")
            .expect("a timestamp payload");

        let expected = [
            &[1, 1, 0, 0][..],
            &57u32.to_le_bytes(),
            &0u32.to_le_bytes(),
            &TIME,
            &signing_cert(),
            b"value",
        ]
        .concat();
        assert_eq!(payload, expected, "timestamp payload");
    }

    /// A nonce-type payload with a NewCert: Flags UPDATE_CERT, NonceSize and the Nonce at 12,
    /// and each certificate on a 4-byte boundary after zero bytes, as CERTIFICATE_ALIGNMENT
    /// places them.
    #[test]
    fn nonce_payload_pads_each_certificate_to_4() {
        let expected = [
            &[1, 2, 0, 0][..],
            &81u32.to_le_bytes(),
            &1u32.to_le_bytes(),
            &1u32.to_le_bytes(),
            &[0xA5],
            &[0, 0, 0],
            &new_cert(),
            &[0, 0],
            &signing_cert(),
            b"data",
        ]
        .concat();

        assert_eq!(nonce_payload(b"data"), expected, "nonce payload");
    }

    /// The Secondary Descriptor is the EFI_TIME, or NonceSize and the Nonce; only a nonce-type
    /// write with a current nonce has one for §8.2.5 step 3c, and a timestamp-type write cannot
    /// carry one.
    #[test]
    fn freshness_gives_a_current_nonce_only_to_a_nonce_update() {
        let create = Freshness::Nonce {
            nonce: nonce(&[9; 5]),
            current: None,
        };
        let update = Freshness::Nonce {
            nonce: nonce(&[9; 5]),
            current: Some(nonce(&[7; 3])),
        };
        let cases = [
            ("timestamp", timestamp(), TIME.to_vec(), None),
            (
                "nonce create",
                create,
                vec![5, 0, 0, 0, 9, 9, 9, 9, 9],
                None,
            ),
            (
                "nonce update",
                update,
                vec![5, 0, 0, 0, 9, 9, 9, 9, 9],
                Some(&[7; 3][..]),
            ),
        ];
        for (case, freshness, descriptor, current) in cases {
            assert_eq!(
                (freshness.secondary_descriptor(), freshness.current_nonce()),
                (descriptor, current),
                "{case}"
            );
        }
    }

    /// A nonce is two hex digits of either case per byte, all zero asking the firmware for one,
    /// and never empty, an odd count or a character other than a hex digit.
    #[test]
    fn nonce_is_hex_digits_and_never_empty() {
        let cases: [(&str, Result<Vec<u8>, NonceError>); 5] = [
            ("a5A5", Ok(vec![0xA5, 0xA5])),
            ("0000", Ok(vec![0, 0])),
            ("", Err(NonceError::Empty)),
            ("a5a", Err(NonceError::Digits("a5a".to_owned()))),
            ("zz", Err(NonceError::Digits("zz".to_owned()))),
        ];
        for (digits, want) in cases {
            assert_eq!(
                digits.parse::<Nonce>().map(|nonce| nonce.as_ref().to_vec()),
                want,
                "{digits:?}"
            );
        }
        assert_eq!(
            NonceError::Empty.to_string(),
            "the nonce is empty; the NonceSize of an EFI_VARIABLE_AUTHENTICATION_3_NONCE \"Must \
             not be 0\" (UEFI 2.11 section 8.2.3)",
            "empty"
        );
    }

    /// authentication_3_value takes what authentication_3_payload makes, with and without a
    /// NewCert, and the empty data of a certificate-only update, and gives the data after
    /// MetadataSize.
    #[test]
    fn authentication_3_value_takes_what_authentication_3_payload_makes() {
        let timestamp_payload = authentication_3_payload(&timestamp(), None, &signing_cert(), b"v")
            .expect("a timestamp payload");
        let certificate_only = nonce_payload(b"");
        let cases: [(&str, &[u8], Authentication3<'_>); 3] = [
            (
                "timestamp",
                &timestamp_payload,
                Authentication3 {
                    new_cert: false,
                    data: b"v",
                },
            ),
            (
                "nonce with a NewCert",
                &nonce_payload(b"data"),
                Authentication3 {
                    new_cert: true,
                    data: b"data",
                },
            ),
            (
                "certificate only",
                &certificate_only,
                Authentication3 {
                    new_cert: true,
                    data: b"",
                },
            ),
        ];
        for (case, payload, want) in cases {
            assert_eq!(authentication_3_value(payload), Ok(want), "{case}");
        }
    }

    /// A packed, 10-byte EFI_VARIABLE_AUTHENTICATION_3, MetadataSize right after Type, as
    /// go-efilib decodes it, then the EFI_TIME and the SigningCert: MetadataSize 55 (0x37).
    fn packed_payload() -> Vec<u8> {
        [
            &[1, 1][..],
            &55u32.to_le_bytes(),
            &0u32.to_le_bytes(),
            &TIME,
            &signing_cert(),
        ]
        .concat()
    }

    /// authentication_3_value refuses each broken descriptor field of nonce_payload, a packed
    /// header, and a wRevision other than 0x0200, naming the offset of each certificate.
    #[test]
    fn authentication_3_value_refuses_each_broken_field() {
        let broken = |at: usize, bytes: &[u8]| {
            let mut payload = nonce_payload(b"data");
            payload[at..at + bytes.len()].copy_from_slice(bytes);
            payload
        };
        let length = nonce_payload(b"data").len();
        let cases: [(&str, Vec<u8>, Authentication3Refusal); 17] = [
            (
                "11 bytes",
                nonce_payload(b"")[..11].to_vec(),
                Authentication3Refusal::Truncated(11),
            ),
            (
                "Version 2",
                broken(0, &[2]),
                Authentication3Refusal::Version(2),
            ),
            (
                "packed header",
                packed_payload(),
                Authentication3Refusal::PackedHeader(0x37),
            ),
            ("Type 3", broken(1, &[3]), Authentication3Refusal::Type(3)),
            ("Flags 3", broken(8, &[3]), Authentication3Refusal::Flags(3)),
            (
                "NonceSize 0",
                broken(12, &[0]),
                Authentication3Refusal::EmptyNonce,
            ),
            (
                "NonceSize past the end",
                broken(12, &[0xFF, 0xFF]),
                Authentication3Refusal::Truncated(length),
            ),
            (
                "padding before the NewCert",
                broken(18, &[1]),
                Authentication3Refusal::Padding(18),
            ),
            (
                "padding before the SigningCert",
                broken(51, &[1]),
                Authentication3Refusal::Padding(51),
            ),
            (
                "NewCert wCertificateType",
                broken(26, &[0x02]),
                Authentication3Refusal::Certificate(20),
            ),
            (
                "NewCert CertType",
                broken(28, &[0x9E]),
                Authentication3Refusal::Certificate(20),
            ),
            (
                "NewCert dwLength 24, no CertData",
                broken(20, &[24]),
                Authentication3Refusal::Certificate(20),
            ),
            (
                "SigningCert dwLength past the end",
                broken(52, &[0xFF, 0xFF]),
                Authentication3Refusal::Certificate(52),
            ),
            (
                "NewCert wRevision 0x0100",
                broken(24, &[0x00, 0x01]),
                Authentication3Refusal::Revision {
                    at: 20,
                    revision: 0x0100,
                },
            ),
            (
                "MetadataSize 80",
                broken(4, &[80]),
                Authentication3Refusal::MetadataSize {
                    declared: 80,
                    found: 81,
                },
            ),
            (
                "MetadataSize 82",
                broken(4, &[82]),
                Authentication3Refusal::MetadataSize {
                    declared: 82,
                    found: 81,
                },
            ),
            (
                "TimeZone",
                {
                    let mut payload =
                        authentication_3_payload(&timestamp(), None, &signing_cert(), b"v")
                            .expect("a timestamp payload");
                    payload[12 + 12] = 1;
                    payload
                },
                Authentication3Refusal::TimeStampNotGmt,
            ),
        ];
        for (case, payload, want) in cases {
            assert_eq!(authentication_3_value(&payload), Err(want), "{case}");
        }
        assert_eq!(
            Authentication3Refusal::PackedHeader(0x37).to_string(),
            "the payload's EFI_VARIABLE_AUTHENTICATION_3 holds 0x0037 in the 2 bytes after Type, \
             which its naturally aligned 12-byte form pads with zeros (UEFI 2.11 section 2.3.1): \
             it looks like the packed 10-byte form, with MetadataSize right after Type, which \
             uefisettings does not take",
            "packed header message"
        );
    }
}
