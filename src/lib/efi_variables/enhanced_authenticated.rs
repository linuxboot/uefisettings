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
//! Type says, then an EFI_VARIABLE_AUTHENTICATION_3_CERT_ID. Each structure is aligned to its
//! largest field (UEFI 2.11 §2.3.1), so CERT_ID starts at a 4-byte boundary after the Nonce;
//! uefisettings requires the bytes before it to be zero. The hii module skips the metadata to
//! decode the value on every build.

use thiserror::Error;

use super::is_gmt_time_stamp;
use super::EFI_TIME_SIZE;
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
/// The alignment of EFI_VARIABLE_AUTHENTICATION_3_CERT_ID, that of its UINT32 IdSize.
const CERT_ID_ALIGNMENT: usize = UINT32_SIZE;
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
                .checked_next_multiple_of(CERT_ID_ALIGNMENT)
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
    data.get(at..)
        .and_then(<[u8]>::first_chunk::<UINT32_SIZE>)
        .copied()
        .map(u32::from_le_bytes)
        .ok_or(MetadataRefusal::truncated(data))
}

/// The byte at `at` of `data`.
fn byte(data: &[u8], at: usize) -> Result<u8, MetadataRefusal> {
    data.get(at)
        .copied()
        .ok_or(MetadataRefusal::truncated(data))
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
