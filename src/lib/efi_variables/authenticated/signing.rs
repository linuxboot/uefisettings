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

//! EFI_VARIABLE_AUTHENTICATION_2 descriptors that a caller's RSA key signs (UEFI 2.11 §8.2.6): a
//! PKCS #7 SignedData without signed attributes over the serialization of the write, of SHA-256,
//! SHA-384 or SHA-512. RSA signs only blinded, over a ChaCha20Rng seeded once from the
//! platform's source, and clippy.toml bans rsa's unblinded signing entry points. rsa has no
//! release that fixes RUSTSEC-2023-0071's timing leak; blinding is partial hardening, and
//! uefisettings runs as the advisory's workaround allows: local use on a non-compromised
//! computer. Neither the ChaCha20Rng's state nor the copy of the seed that it takes is zeroized,
//! which rand_chacha 0.3 cannot do, and a key file that fails base64 or DER validation leaves its
//! decoded bytes in freed memory, as pem-rfc7468 0.7 decodes into a plain Vec that der 0.7 drops
//! on the error: accepted residuals.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use cms::cert::CertificateChoices;
use cms::cert::IssuerAndSerialNumber;
use cms::content_info::CmsVersion;
use cms::signed_data::CertificateSet;
use cms::signed_data::EncapsulatedContentInfo;
use cms::signed_data::SignedData;
use cms::signed_data::SignerIdentifier;
use cms::signed_data::SignerInfo;
use cms::signed_data::SignerInfos;
use der::asn1::ObjectIdentifier;
use der::asn1::OctetString;
use der::asn1::SetOfVec;
use der::Any;
use der::DateTime;
use der::Encode;
use der::EncodeValue;
use rand_chacha::ChaCha20Rng;
use rand_core::CryptoRngCore;
use rand_core::SeedableRng;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::pkcs8::EncodePublicKey;
use rsa::signature::RandomizedSigner;
use rsa::signature::SignatureEncoding;
use rsa::traits::PublicKeyParts;
use rsa::RsaPrivateKey;
use sha2::digest::const_oid::AssociatedOid;
use sha2::Sha256;
use sha2::Sha384;
use sha2::Sha512;
use thiserror::Error;
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;
use zeroize::Zeroizing;

use super::CERTIFICATE_HEADER_SIZE;
use super::EFI_CERT_TYPE_PKCS7_GUID;
use super::EFI_TIME_SIZE;
use super::WIN_CERT_TYPE_EFI_GUID;
use crate::hii::VariableAttributes;
use crate::hii::VariableKey;
use crate::secret_file::Secret;

/// id-data, the contentType of the SignedData (UEFI 2.11 §8.2.6 step c; RFC 2315 §14).
const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
/// rsaEncryption, the digestEncryptionAlgorithm of PKCS #1 v1.5 (RFC 8017 Appendix A.1).
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
/// WIN_CERTIFICATE.wRevision (UEFI 2.11 §32.2.4.1).
const WIN_CERT_REVISION: u16 = 0x0200;
/// The RSA key sizes that signing takes.
const KEY_BITS: std::ops::RangeInclusive<usize> = 2048..=4096;
/// The seed of ChaCha20Rng.
const SEED_LEN: usize = 32;
/// The most content bytes of a DER value of a two-byte length (X.690 §8.1.3.5).
const TWO_BYTE_LENGTH_MAX: usize = 0xFFFF;
/// What starts a PEM certificate (RFC 7468 §5.1).
const PEM_CERTIFICATE_LABEL: &[u8] = b"-----BEGIN CERTIFICATE-----";
/// The PEM label of an encrypted PKCS #8 key (pkcs8 0.10's EncryptedPrivateKeyInfo::PEM_LABEL),
/// which signing does not decrypt.
const ENCRYPTED_KEY_LABEL: &str = "ENCRYPTED PRIVATE KEY";

/// The TimeStamp of an EFI_VARIABLE_AUTHENTICATION_2: an EFI_TIME in GMT, its Pad1, Nanosecond,
/// TimeZone, Daylight and Pad2 zero (UEFI 2.11 §8.2.3), or all zero, the value of appends without
/// a reliable time source (§8.2.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeStamp([u8; EFI_TIME_SIZE]);

impl TimeStamp {
    /// Every field 0, Day and Month too (UEFI 2.11 §8.2.6).
    pub const ZERO: Self = Self([0; EFI_TIME_SIZE]);

    /// The UTC second of `time`, "the current time" of a signed write on a platform with a clock
    /// (UEFI 2.11 §8.2.6), from 1970 to 9999.
    pub fn from_system_time(time: SystemTime) -> Result<Self, TimeStampError> {
        let since_epoch = time
            .duration_since(UNIX_EPOCH)
            .map_err(|_| TimeStampError::Clock)?;
        let time = DateTime::from_unix_duration(Duration::from_secs(since_epoch.as_secs()))
            .map_err(|_| TimeStampError::Clock)?;
        Ok(Self::of(
            time.year(),
            [
                time.month(),
                time.day(),
                time.hour(),
                time.minutes(),
                time.seconds(),
            ],
        ))
    }

    /// The EFI_TIME of `year` and its month, day, hour, minute and second, in GMT.
    fn of(year: u16, [month, day, hour, minute, second]: [u8; 5]) -> Self {
        let [y0, y1] = year.to_le_bytes();
        Self([
            y0, y1, month, day, hour, minute, second, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ])
    }
}

/// Why a TimeStamp was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum TimeStampError {
    #[error(
        "{0:?} is not a GMT time such as 2026-11-07T00:00:00Z of years 1900 to 9999 (EFI_TIME, \
         UEFI 2.11 section 8.3.1)"
    )]
    Text(String),
    #[error("the system clock reads no time from 1970 to 9999")]
    Clock,
}

impl FromStr for TimeStamp {
    type Err = TimeStampError;

    /// Takes YYYY-MM-DDTHH:MM:SSZ.
    fn from_str(text: &str) -> Result<Self, TimeStampError> {
        let invalid = || TimeStampError::Text(text.to_owned());
        let &[_, _, _, _, b'-', _, _, b'-', _, _, b'T', _, _, b':', _, _, b':', _, _, b'Z'] =
            text.as_bytes()
        else {
            return Err(invalid());
        };
        let field = |range: std::ops::Range<usize>| {
            text.get(range)
                .filter(|digits| digits.bytes().all(|digit| digit.is_ascii_digit()))
                .and_then(|digits| digits.parse::<u16>().ok())
                .ok_or_else(invalid)
        };
        let year = field(0..4)?;
        let [month, day, hour, minute, second] = [5..7, 8..10, 11..13, 14..16, 17..19]
            .map(field)
            .map(|value| value.and_then(|value| u8::try_from(value).map_err(|_| invalid())));
        let (month, day, hour, minute, second) = (month?, day?, hour?, minute?, second?);
        let valid = (1900..=9999).contains(&year)
            && (1..=days_in_month(year, month)).contains(&day)
            && hour <= 23
            && minute <= 59
            && second <= 59;
        if !valid {
            return Err(invalid());
        }
        Ok(Self::of(year, [month, day, hour, minute, second]))
    }
}

impl fmt::Display for TimeStamp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [y0, y1, month, day, hour, minute, second, ..] = self.0;
        let year = u16::from_le_bytes([y0, y1]);
        write!(
            f,
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z"
        )
    }
}

/// The days of `month` of `year`, 0 for a month outside 1-12.
fn days_in_month(year: u16, month: u8) -> u8 {
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => 0,
    }
}

/// The digest of the SignedData: "Digest algorithms of SHA-256, SHA-384, SHA-512 are accepted"
/// (UEFI 2.11 §8.2.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SignatureDigest {
    #[default]
    Sha256,
    Sha384,
    Sha512,
}

/// One SetVariable() call with EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS, before its
/// descriptor: what the signature covers.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AuthenticatedWrite<'a> {
    pub(crate) key: &'a VariableKey,
    /// The Attributes of the call, TIME_BASED_AUTHENTICATED_WRITE_ACCESS and APPEND_WRITE
    /// included, as edk2 hashes them (edk2-stable202608 AuthService.c VerifyTimeBasedPayload()).
    pub(crate) attributes: VariableAttributes,
    pub(crate) timestamp: TimeStamp,
    pub(crate) data: &'a [u8],
}

/// Why no descriptor was signed.
#[derive(Debug, Error)]
pub(crate) enum SigningRefusal {
    #[error("the signing key is neither a PEM PKCS #8 nor a PEM PKCS #1 RSA private key")]
    KeyFormat,
    #[error("the signing key is encrypted; signing takes an unencrypted one")]
    EncryptedKey,
    #[error("the signing key has {0} bits; signing takes 2048 to 4096")]
    KeySize(usize),
    #[error("the certificate bundle holds no PEM X.509 certificate")]
    NoCertificate,
    #[error("the certificate bundle is not a series of PEM X.509 certificates")]
    CertificateFormat(#[source] der::Error),
    #[error("the first certificate of the bundle does not hold the public key of the signing key")]
    KeyMismatch,
    // spki::Error implements std's Error only with spki's std feature, which nothing turns on.
    #[error("cannot DER-encode the public key of the signing key: {0}")]
    PublicKeyEncoding(rsa::pkcs8::spki::Error),
    #[error("the certificate bundle holds a certificate twice")]
    DuplicateCertificate,
    #[error(
        "EFI variable {0} has a character outside UCS-2, which SetVariable()'s VariableName cannot \
         hold"
    )]
    NameNotUcs2(VariableKey),
    // signature::Error implements std's Error only with signature's std feature, which turns on
    // rand_core's and so getrandom, which builds for no UEFI target.
    #[error("RSA signing failed: {0}")]
    Sign(rsa::signature::Error),
    #[error("cannot encode the SignedData")]
    Encode(#[source] der::Error),
    #[error(
        "the SignedData holds {0} bytes after its tag and length, 64 KiB or more: its length \
         takes 3 bytes, which moves its digest algorithm past the offset 13 where \
         edk2-stable202608 AuthService.c FindHashAlgorithmIndex() reads it, so edk2 refuses the \
         write"
    )]
    TooLarge(usize),
}

/// The signing key, for the digest of the SignedData.
enum DigestKey {
    Sha256(SigningKey<Sha256>),
    Sha384(SigningKey<Sha384>),
    Sha512(SigningKey<Sha512>),
}

impl DigestKey {
    fn new(key: RsaPrivateKey, digest: SignatureDigest) -> Self {
        match digest {
            SignatureDigest::Sha256 => Self::Sha256(SigningKey::new(key)),
            SignatureDigest::Sha384 => Self::Sha384(SigningKey::new(key)),
            SignatureDigest::Sha512 => Self::Sha512(SigningKey::new(key)),
        }
    }

    /// The PKCS #1 v1.5 signature of `message`, blinded over `rng`.
    fn sign(
        &self,
        rng: &mut impl CryptoRngCore,
        message: &[u8],
    ) -> Result<Vec<u8>, SigningRefusal> {
        let signature = match self {
            Self::Sha256(key) => key.try_sign_with_rng(rng, message),
            Self::Sha384(key) => key.try_sign_with_rng(rng, message),
            Self::Sha512(key) => key.try_sign_with_rng(rng, message),
        };
        signature
            .map(|signature| signature.to_vec())
            .map_err(SigningRefusal::Sign)
    }

    /// The digest's object identifier (RFC 5754 §2).
    fn digest_oid(&self) -> ObjectIdentifier {
        match self {
            Self::Sha256(_) => Sha256::OID,
            Self::Sha384(_) => Sha384::OID,
            Self::Sha512(_) => Sha512::OID,
        }
    }
}

/// The signing key and the certificates that go into the SignedData.
pub(crate) struct Signer {
    key: DigestKey,
    /// Of the signer's certificate.
    signer: IssuerAndSerialNumber,
    certificates: CertificateSet,
}

impl Signer {
    /// Takes a PEM RSA private key of 2048 to 4096 bits, PKCS #8 or PKCS #1; a bundle of PEM
    /// X.509 certificates: the signer's, of that key, which SignedData.certificates holds at a
    /// minimum (UEFI 2.11 §8.2.6 step e), then any others for it, such as intermediate CAs; and
    /// the digest of the SignedData.
    pub(crate) fn from_pem(
        key: &Secret,
        certificates: &[u8],
        digest: SignatureDigest,
    ) -> Result<Self, SigningRefusal> {
        // pem-rfc7468 takes one line break after the PEM text, not the blank lines that end
        // some key files.
        let key_text = std::str::from_utf8(key.as_bytes())
            .map_err(|_| SigningRefusal::KeyFormat)?
            .trim_end();
        if matches!(
            der::pem::decode_label(key_text.as_bytes()),
            Ok(ENCRYPTED_KEY_LABEL)
        ) {
            return Err(SigningRefusal::EncryptedKey);
        }
        let key = RsaPrivateKey::from_pkcs8_pem(key_text)
            .or_else(|_| RsaPrivateKey::from_pkcs1_pem(key_text))
            .map_err(|_| SigningRefusal::KeyFormat)?;
        key_size(key.n().bits())?;
        let certificates = pem_certificates(certificates)?;
        let signer = &certificates
            .first()
            .ok_or(SigningRefusal::NoCertificate)?
            .tbs_certificate;
        let public = key
            .to_public_key()
            .to_public_key_der()
            .map_err(SigningRefusal::PublicKeyEncoding)?;
        let certified = signer
            .subject_public_key_info
            .to_der()
            .map_err(SigningRefusal::Encode)?;
        if public.as_bytes() != certified.as_slice() {
            return Err(SigningRefusal::KeyMismatch);
        }
        let signer = IssuerAndSerialNumber {
            issuer: signer.issuer.clone(),
            serial_number: signer.serial_number.clone(),
        };
        let certificates = certificates
            .into_iter()
            .map(CertificateChoices::Certificate)
            .collect::<Vec<_>>();
        // DER sorts a SET OF (X.690 §11.6), so the bundle's order is lost.
        let certificates = match SetOfVec::try_from(certificates) {
            Ok(certificates) => CertificateSet(certificates),
            Err(error) if error.kind() == der::ErrorKind::SetDuplicate => {
                return Err(SigningRefusal::DuplicateCertificate)
            }
            Err(error) => return Err(SigningRefusal::Encode(error)),
        };
        Ok(Self {
            key: DigestKey::new(key, digest),
            signer,
            certificates,
        })
    }

    /// The SetVariable() Data of `write`: its EFI_VARIABLE_AUTHENTICATION_2, signed blinded over
    /// `rng`, then the new data (UEFI 2.11 §8.2.6).
    pub(crate) fn authentication_2(
        &self,
        write: &AuthenticatedWrite<'_>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Vec<u8>, SigningRefusal> {
        let signature = self.key.sign(rng, &digest_input(write)?)?;
        let signed_data = self.signed_data(signature)?;
        let content = signed_data
            .value_len()
            .and_then(usize::try_from)
            .map_err(SigningRefusal::Encode)?;
        if content > TWO_BYTE_LENGTH_MAX {
            return Err(SigningRefusal::TooLarge(content));
        }
        let cert_data = signed_data.to_der().map_err(SigningRefusal::Encode)?;
        let length = CERTIFICATE_HEADER_SIZE
            .checked_add(cert_data.len())
            .and_then(|length| u32::try_from(length).ok())
            .ok_or(SigningRefusal::TooLarge(content))?;
        Ok([
            &write.timestamp.0[..],
            &length.to_le_bytes(),
            &WIN_CERT_REVISION.to_le_bytes(),
            &WIN_CERT_TYPE_EFI_GUID.to_le_bytes(),
            &<[u8; 16]>::from(EFI_CERT_TYPE_PKCS7_GUID),
            &cert_data,
            write.data,
        ]
        .concat())
    }

    /// The SignedData of UEFI 2.11 §8.2.6 steps a-g: version 1, the digest, id-data without
    /// content, the certificates, and one SignerInfo of version 1 by issuer and serial number,
    /// without authenticated or unauthenticated attributes.
    fn signed_data(&self, signature: Vec<u8>) -> Result<SignedData, SigningRefusal> {
        let digest = AlgorithmIdentifierOwned {
            oid: self.key.digest_oid(),
            parameters: None,
        };
        let signer = SignerInfo {
            version: CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(self.signer.clone()),
            digest_alg: digest.clone(),
            signed_attrs: None,
            signature_algorithm: AlgorithmIdentifierOwned {
                oid: RSA_ENCRYPTION,
                parameters: Some(Any::null()),
            },
            signature: OctetString::new(signature).map_err(SigningRefusal::Encode)?,
            unsigned_attrs: None,
        };
        Ok(SignedData {
            version: CmsVersion::V1,
            digest_algorithms: SetOfVec::try_from(vec![digest]).map_err(SigningRefusal::Encode)?,
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: ID_DATA,
                econtent: None,
            },
            certificates: Some(self.certificates.clone()),
            crls: None,
            signer_infos: SignerInfos(
                SetOfVec::try_from(vec![signer]).map_err(SigningRefusal::Encode)?,
            ),
        })
    }
}

/// Refuses an RSA key of `bits` outside KEY_BITS.
fn key_size(bits: usize) -> Result<(), SigningRefusal> {
    if !KEY_BITS.contains(&bits) {
        return Err(SigningRefusal::KeySize(bits));
    }
    Ok(())
}

/// The certificates of the PEM bundle `pem`, in order. x509-cert 0.2.5's load_pem_chain() takes
/// one at least: on text without one, its `input.len() - 1` underflows.
fn pem_certificates(pem: &[u8]) -> Result<Vec<Certificate>, SigningRefusal> {
    if !pem
        .windows(PEM_CERTIFICATE_LABEL.len())
        .any(|window| window == PEM_CERTIFICATE_LABEL)
    {
        return Err(SigningRefusal::NoCertificate);
    }
    Certificate::load_pem_chain(pem).map_err(SigningRefusal::CertificateFormat)
}

/// What UEFI 2.11 §8.2.6 hashes: VariableName without its terminating NUL, VendorGuid,
/// Attributes, TimeStamp, then the new data.
pub(crate) fn digest_input(write: &AuthenticatedWrite<'_>) -> Result<Vec<u8>, SigningRefusal> {
    let name = write
        .key
        .name
        .encode_utf16()
        // A surrogate half belongs to a character outside UCS-2.
        .map(|unit| match unit {
            0xD800..=0xDFFF => Err(SigningRefusal::NameNotUcs2(write.key.clone())),
            unit => Ok(unit.to_le_bytes()),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok([
        name.as_flattened(),
        &<[u8; 16]>::from(write.key.guid),
        &write.attributes.bits().to_le_bytes(),
        &write.timestamp.0,
        write.data,
    ]
    .concat())
}

/// The source that seeds the RNG of RSA blinding once.
pub(crate) trait SeedSource {
    /// The source, as errors name it.
    const NAME: &'static str;

    /// Fills `seed` with random bytes.
    fn fill(&mut self, seed: &mut [u8]) -> Result<()>;
}

/// A ChaCha20Rng seeded from `source`, which signing then draws from alone; a failure names the
/// source.
pub(crate) fn seeded_rng<S: SeedSource>(source: &mut S) -> Result<ChaCha20Rng> {
    let mut seed = Zeroizing::new([0; SEED_LEN]);
    source
        .fill(seed.as_mut_slice())
        .with_context(|| format!("cannot seed RSA blinding from {}", S::NAME))?;
    Ok(ChaCha20Rng::from_seed(*seed))
}

/// The OS source outside the UEFI Shell: getrandom.
#[cfg(not(target_os = "uefi"))]
#[derive(Debug, Default)]
pub(crate) struct OsSeed;

#[cfg(not(target_os = "uefi"))]
impl SeedSource for OsSeed {
    const NAME: &'static str = "the OS random source (getrandom)";

    fn fill(&mut self, seed: &mut [u8]) -> Result<()> {
        // rand_core::Error implements std's Error only with rand_core's std feature.
        rand_core::RngCore::try_fill_bytes(&mut rand_core::OsRng, seed)
            .map_err(|error| anyhow!("{error}"))
    }
}

/// EFI_RNG_PROTOCOL of the first handle that has it (UEFI 2.11 §37.5), in the UEFI Shell.
#[cfg(target_os = "uefi")]
#[derive(Debug, Default)]
pub(crate) struct EfiRngSeed;

#[cfg(target_os = "uefi")]
impl SeedSource for EfiRngSeed {
    const NAME: &'static str = "EFI_RNG_PROTOCOL";

    fn fill(&mut self, seed: &mut [u8]) -> Result<()> {
        use uefi::boot;
        use uefi::proto::rng::Rng;

        let handle = boot::get_handle_for_protocol::<Rng>()
            .map_err(|error| anyhow!("no handle has it: {:?}", error.status()))?;
        let mut rng = boot::open_protocol_exclusive::<Rng>(handle)
            .map_err(|error| anyhow!("OpenProtocol(): {:?}", error.status()))?;
        rng.get_rng(None, seed)
            .map_err(|error| anyhow!("GetRNG(): {:?}", error.status()))
    }
}

/// The seed source of this platform.
#[cfg(target_os = "uefi")]
pub(crate) type PlatformSeed = EfiRngSeed;
/// The seed source of this platform.
#[cfg(not(target_os = "uefi"))]
pub(crate) type PlatformSeed = OsSeed;

#[cfg(test)]
pub(crate) mod tests {
    use std::sync::OnceLock;

    use der::asn1::BitString;
    use der::asn1::UtcTime;
    use der::Decode;
    use der::DecodePem;
    use der::EncodePem;
    use rand_core::CryptoRng;
    use rand_core::RngCore;
    use rsa::pkcs1v15::Signature;
    use rsa::pkcs1v15::VerifyingKey;
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::pkcs8::LineEnding;
    use rsa::signature::Verifier;
    use x509_cert::ext::Extension;
    use x509_cert::name::Name;
    use x509_cert::serial_number::SerialNumber;
    use x509_cert::spki::SubjectPublicKeyInfoOwned;
    use x509_cert::time::Time;
    use x509_cert::time::Validity;
    use x509_cert::TbsCertificate;
    use x509_cert::Version;

    use super::*;
    use crate::efi_variables::globals::EFI_IMAGE_SECURITY_DATABASE;
    use crate::secret_file::read_secret_file;
    use crate::secret_file::MAX_SECRET_LEN;

    /// sha256WithRSAEncryption (RFC 8017 Appendix A.2.4), the certificate's signature.
    const SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");
    /// The digest OIDs where edk2 looks for them (edk2-stable202608 AuthService.c:143-145).
    const EDK2_SHA256_OID: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
    const EDK2_SHA384_OID: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
    const EDK2_SHA512_OID: [u8; 9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];
    /// An extension OID of no meaning, which pads a certificate, under the enterprise number
    /// 32473 "for use in examples" (RFC 5612 §2).
    const PADDING_EXTENSION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.1");
    /// The fixed seed of the test key.
    pub(crate) const KEY_SEED: u64 = 1;
    /// The fixed TimeStamp of the tests.
    pub(crate) const TIME: &str = "2026-11-07T00:00:00Z";
    /// The subject of the test certificates.
    const KEK_NAME: &str = "CN=uefisettings test KEK";
    /// The issuer of a test certificate that a CA issued.
    const CA_NAME: &str = "CN=uefisettings test CA";

    /// key_and_certificate(KEY_SEED), made once: key generation takes seconds in debug builds.
    pub(crate) fn test_pems() -> &'static (Secret, Secret) {
        static PEMS: OnceLock<(Secret, Secret)> = OnceLock::new();
        PEMS.get_or_init(|| key_and_certificate(KEY_SEED))
    }

    /// key_and_certificate(5), another key, made once.
    fn other_pems() -> &'static (Secret, Secret) {
        static PEMS: OnceLock<(Secret, Secret)> = OnceLock::new();
        PEMS.get_or_init(|| key_and_certificate(5))
    }

    pub(crate) fn test_signer() -> Signer {
        let (key, certificate) = test_pems();
        Signer::from_pem(key, certificate.as_bytes(), SignatureDigest::Sha256)
            .expect("signer of the test key")
    }

    fn secret(bytes: &[u8]) -> Secret {
        read_secret_file(bytes, MAX_SECRET_LEN).expect("a secret of the test bytes")
    }

    /// A 2048-bit key from the fixed seed `seed`, and a self-signed certificate of it, as PEM.
    fn key_and_certificate(seed: u64) -> (Secret, Secret) {
        let key = RsaPrivateKey::new(&mut ChaCha20Rng::seed_from_u64(seed), 2048)
            .expect("generate the key");
        let key_pem = key.to_pkcs8_pem(LineEnding::LF).expect("encode the key");
        (
            secret(key_pem.as_bytes()),
            secret(certificate_pem(&key, KEK_NAME).as_bytes()),
        )
    }

    /// A certificate of `key` from `issuer` to KEK_NAME, signed by `key`, as PEM.
    fn certificate_pem(key: &RsaPrivateKey, issuer: &str) -> String {
        let spki = SubjectPublicKeyInfoOwned::from_der(
            key.to_public_key()
                .to_public_key_der()
                .expect("encode the public key")
                .as_bytes(),
        )
        .expect("decode the public key");
        let subject: Name = KEK_NAME.parse().expect("parse the subject");
        let validity = Validity {
            not_before: Time::UtcTime(
                UtcTime::from_unix_duration(Duration::from_secs(1_700_000_000))
                    .expect("start time"),
            ),
            not_after: Time::UtcTime(
                UtcTime::from_unix_duration(Duration::from_secs(1_900_000_000)).expect("end"),
            ),
        };
        let signature_algorithm = AlgorithmIdentifierOwned {
            oid: SHA256_WITH_RSA,
            parameters: Some(Any::null()),
        };
        let tbs = TbsCertificate {
            version: Version::V3,
            serial_number: SerialNumber::new(&[0x01, 0x23]).expect("serial number"),
            signature: signature_algorithm.clone(),
            issuer: issuer.parse().expect("parse the issuer"),
            validity,
            subject,
            subject_public_key_info: spki,
            issuer_unique_id: None,
            subject_unique_id: None,
            extensions: None,
        };
        let tbs_der = tbs.to_der().expect("encode the TBSCertificate");
        let signature = SigningKey::<Sha256>::new(key.clone())
            .try_sign_with_rng(&mut ChaCha20Rng::seed_from_u64(0), &tbs_der)
            .expect("sign the certificate");
        let certificate = Certificate {
            tbs_certificate: tbs,
            signature_algorithm,
            signature: BitString::from_bytes(&signature.to_vec()).expect("signature bits"),
        };
        certificate
            .to_pem(LineEnding::LF)
            .expect("encode the certificate")
    }

    /// The test certificate under serial number 2 with an extension of `padding` bytes, as PEM:
    /// another certificate of the bundle, whose signature no one checks.
    fn padded_certificate_pem(padding: usize) -> String {
        let mut certificate =
            Certificate::from_pem(test_pems().1.as_bytes()).expect("decode the test certificate");
        let tbs = &mut certificate.tbs_certificate;
        tbs.serial_number = SerialNumber::new(&[0x02]).expect("serial number");
        tbs.extensions = Some(vec![Extension {
            extn_id: PADDING_EXTENSION,
            critical: false,
            extn_value: OctetString::new(vec![0; padding]).expect("padding"),
        }]);
        certificate
            .to_pem(LineEnding::LF)
            .expect("encode the other certificate")
    }

    /// A Signer of the test key, SHA-256 and the certificate bundle `bundle`.
    fn bundle_signer(bundle: &[u8]) -> Result<Signer, SigningRefusal> {
        Signer::from_pem(&test_pems().0, bundle, SignatureDigest::Sha256)
    }

    pub(crate) fn db() -> VariableKey {
        VariableKey {
            name: "db".to_owned(),
            guid: EFI_IMAGE_SECURITY_DATABASE,
        }
    }

    /// NON_VOLATILE, BOOTSERVICE_ACCESS, RUNTIME_ACCESS, TIME_BASED_AUTHENTICATED_WRITE_ACCESS
    /// and APPEND_WRITE: 0x67.
    pub(crate) fn append_attributes() -> VariableAttributes {
        VariableAttributes::from_bits_retain(0x67)
    }

    fn write<'a>(key: &'a VariableKey, data: &'a [u8]) -> AuthenticatedWrite<'a> {
        AuthenticatedWrite {
            key,
            attributes: append_attributes(),
            timestamp: TIME.parse().expect("the test TimeStamp"),
            data,
        }
    }

    /// The CertData and the new data of `payload`, after checking its WIN_CERTIFICATE_UEFI_GUID.
    fn split(payload: &[u8]) -> (&[u8], &[u8]) {
        let length = u32::from_le_bytes(payload[16..20].try_into().expect("dwLength"));
        let length = usize::try_from(length).expect("dwLength fits usize");
        assert_eq!(
            payload[20..22],
            WIN_CERT_REVISION.to_le_bytes(),
            "wRevision"
        );
        assert_eq!(
            payload[22..24],
            WIN_CERT_TYPE_EFI_GUID.to_le_bytes(),
            "wCertificateType"
        );
        assert_eq!(
            payload[24..40],
            <[u8; 16]>::from(EFI_CERT_TYPE_PKCS7_GUID),
            "CertType"
        );
        payload[40..].split_at(length - CERTIFICATE_HEADER_SIZE)
    }

    /// Whether `signature`, by the test key over `digest`, verifies over `input`.
    fn verifies(digest: SignatureDigest, input: &[u8], signature: &[u8]) -> bool {
        let key = std::str::from_utf8(test_pems().0.as_bytes()).expect("PEM text");
        let public = RsaPrivateKey::from_pkcs8_pem(key)
            .expect("decode the test key")
            .to_public_key();
        let signature = Signature::try_from(signature).expect("signature bytes");
        match digest {
            SignatureDigest::Sha256 => {
                VerifyingKey::<Sha256>::new(public).verify(input, &signature)
            }
            SignatureDigest::Sha384 => {
                VerifyingKey::<Sha384>::new(public).verify(input, &signature)
            }
            SignatureDigest::Sha512 => {
                VerifyingKey::<Sha512>::new(public).verify(input, &signature)
            }
        }
        .is_ok()
    }

    /// A random source that counts the bytes that it hands out.
    struct CountingRng<R> {
        inner: R,
        drawn: usize,
    }

    impl<R: RngCore> RngCore for CountingRng<R> {
        fn next_u32(&mut self) -> u32 {
            self.drawn += 4;
            self.inner.next_u32()
        }

        fn next_u64(&mut self) -> u64 {
            self.drawn += 8;
            self.inner.next_u64()
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.drawn += dest.len();
            self.inner.fill_bytes(dest)
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.drawn += dest.len();
            self.inner.try_fill_bytes(dest)
        }
    }

    impl<R: CryptoRng> CryptoRng for CountingRng<R> {}

    /// A seed source that fills `bytes`, or fails as a firmware without EFI_RNG_PROTOCOL does.
    pub(crate) struct FakeSeed(pub(crate) Option<u8>);

    impl SeedSource for FakeSeed {
        const NAME: &'static str = "EFI_RNG_PROTOCOL";

        fn fill(&mut self, seed: &mut [u8]) -> Result<()> {
            let byte = self
                .0
                .ok_or_else(|| anyhow!("no handle has it: NOT_FOUND"))?;
            seed.fill(byte);
            Ok(())
        }
    }

    /// TimeStamp takes YYYY-MM-DDTHH:MM:SSZ of years 1900 to 9999 as an EFI_TIME in GMT, and
    /// refuses other text and dates that no calendar has.
    #[test]
    fn time_stamp_takes_gmt_times_of_efi_time() {
        let stamp: TimeStamp = "2026-11-07T01:02:03Z".parse().expect("parse");
        assert_eq!(
            stamp.0,
            [0xEA, 0x07, 11, 7, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            "EFI_TIME of 2026-11-07T01:02:03Z"
        );
        assert_eq!(stamp.to_string(), "2026-11-07T01:02:03Z", "Display");
        for leap_day in ["2024-02-29T00:00:00Z", "2000-02-29T00:00:00Z"] {
            assert!(
                leap_day.parse::<TimeStamp>().is_ok(),
                "{leap_day:?} is taken"
            );
        }
        for bad in [
            "",
            "2026-11-07T01:02:03",
            "2026-11-07 01:02:03Z",
            "2026-11-07T01:02:03+01:00",
            "1899-12-31T23:59:59Z",
            "2023-02-29T00:00:00Z",
            "1900-02-29T00:00:00Z",
            "2100-02-29T00:00:00Z",
            "2026-13-01T00:00:00Z",
            "2026-11-31T00:00:00Z",
            "2026-11-07T24:00:00Z",
            "2026-11-07T00:60:00Z",
            "2026-11-07T00:00:60Z",
            "+026-11-07T00:00:00Z",
        ] {
            assert!(bad.parse::<TimeStamp>().is_err(), "{bad:?} is refused");
        }
    }

    /// A TimeStamp of the system clock is its UTC second, its Nanosecond zero, from 1970 to 9999,
    /// and refuses a clock outside them.
    #[test]
    fn time_stamp_of_the_system_clock_is_its_utc_second() {
        let at = |secs: u64, nanos: u32| UNIX_EPOCH + Duration::new(secs, nanos);
        let stamp = TimeStamp::from_system_time(at(1_794_013_323, 999_999_999)).expect("2026");
        assert_eq!(
            stamp.0,
            [0xEA, 0x07, 11, 7, 1, 2, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0],
            "EFI_TIME of 2026-11-07T01:02:03.999999999Z"
        );
        assert_eq!(
            TimeStamp::from_system_time(at(0, 0)).map(|stamp| stamp.to_string()),
            Ok("1970-01-01T00:00:00Z".to_owned()),
            "the epoch"
        );
        assert_eq!(
            TimeStamp::from_system_time(at(253_402_300_799, 999_999_999))
                .map(|stamp| stamp.to_string()),
            Ok("9999-12-31T23:59:59Z".to_owned()),
            "the last second of 9999"
        );
        assert_eq!(
            TimeStamp::from_system_time(at(253_402_300_800, 0)),
            Err(TimeStampError::Clock),
            "year 10000"
        );
        assert_eq!(
            TimeStamp::from_system_time(UNIX_EPOCH - Duration::from_secs(1)),
            Err(TimeStampError::Clock),
            "before the epoch"
        );
    }

    /// digest_input serializes VariableName as UCS-2 without its NUL, VendorGuid in EFI_GUID
    /// order, Attributes, TimeStamp and the data, and refuses a name outside UCS-2.
    #[test]
    fn digest_input_serializes_the_write() {
        let key = db();
        let input = digest_input(&write(&key, b"data")).expect("serialize");

        assert_eq!(&input[..4], b"d\0b\0", "UCS-2 name without its NUL");
        assert_eq!(
            input[4..20],
            [
                0xcb, 0xb2, 0x19, 0xd7, 0x3a, 0x3d, 0x96, 0x45, 0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67,
                0x65, 0x6f
            ],
            "VendorGuid D719B2CB-3D3A-4596-A3BC-DAD00E67656F in EFI_GUID order"
        );
        assert_eq!(input[20..24], 0x67u32.to_le_bytes(), "Attributes");
        assert_eq!(input[24..26], 2026u16.to_le_bytes(), "TimeStamp.Year");
        assert_eq!(&input[40..], b"data", "data");
        let outside = VariableKey {
            name: "db\u{1F600}".to_owned(),
            ..db()
        };
        assert!(
            matches!(
                digest_input(&write(&outside, b"")),
                Err(SigningRefusal::NameNotUcs2(_))
            ),
            "a name outside UCS-2 is refused"
        );
    }

    /// authentication_2 over `digest` signs a SignedData of version 1 whose digest algorithm is
    /// `oid`, at offset 13 too, where edk2 reads it; with one SignerInfo of version 1, no content
    /// and no signed or unsigned attributes; and whose signature verifies over the serialization
    /// and fails over it with a flipped data byte.
    fn assert_authentication_2_verifies(digest: SignatureDigest, oid: [u8; 9]) {
        let (key_pem, certificate) = test_pems();
        let signer = Signer::from_pem(key_pem, certificate.as_bytes(), digest).expect("signer");
        let key = db();
        let data = b"EFI_SIGNATURE_LIST stand-in";
        let write = write(&key, data);

        let payload = signer
            .authentication_2(&write, &mut ChaCha20Rng::seed_from_u64(2))
            .expect("sign");

        assert_eq!(payload[..16], write.timestamp.0, "{digest:?}: TimeStamp");
        let (cert_data, new_data) = split(&payload);
        assert_eq!(
            new_data, data,
            "{digest:?}: the new data follows the descriptor"
        );
        assert_eq!(cert_data[..2], [0x30, 0x82], "{digest:?}: two-byte length");
        assert_eq!(
            cert_data[11..13],
            [0x06, 0x09],
            "{digest:?}: OID of 9 bytes"
        );
        assert_eq!(
            cert_data[13..22],
            oid,
            "{digest:?}: digest OID at offset 13"
        );
        let signed = SignedData::from_der(cert_data).expect("CertData is a SignedData");
        assert_eq!(
            signed.version,
            CmsVersion::V1,
            "{digest:?}: SignedData.version"
        );
        let algorithms = signed.digest_algorithms.as_slice();
        assert_eq!(algorithms.len(), 1, "{digest:?}: one digest algorithm");
        assert_eq!(
            algorithms[0].oid.as_bytes(),
            oid,
            "{digest:?}: digestAlgorithms"
        );
        assert_eq!(
            signed.encap_content_info.econtent_type, ID_DATA,
            "{digest:?}: contentType"
        );
        assert!(
            signed.encap_content_info.econtent.is_none(),
            "{digest:?}: no content"
        );
        let infos = signed.signer_infos.0.as_slice();
        assert_eq!(infos.len(), 1, "{digest:?}: one SignerInfo");
        assert_eq!(
            infos[0].version,
            CmsVersion::V1,
            "{digest:?}: SignerInfo.version"
        );
        assert_eq!(
            infos[0].digest_alg.oid.as_bytes(),
            oid,
            "{digest:?}: SignerInfo.digestAlgorithm"
        );
        assert!(
            infos[0].signed_attrs.is_none(),
            "{digest:?}: no authenticatedAttributes"
        );
        assert!(
            infos[0].unsigned_attrs.is_none(),
            "{digest:?}: no unauthenticatedAttributes"
        );

        let signature = infos[0].signature.as_bytes();
        let input = digest_input(&write).expect("serialize");
        assert!(
            verifies(digest, &input, signature),
            "{digest:?}: the signature verifies over the serialization"
        );
        let mut flipped = input.clone();
        *flipped.last_mut().expect("a data byte") ^= 1;
        assert!(
            !verifies(digest, &flipped, signature),
            "{digest:?}: a flipped data byte fails"
        );
    }

    #[test]
    fn authentication_2_signs_with_sha256() {
        assert_authentication_2_verifies(SignatureDigest::Sha256, EDK2_SHA256_OID);
    }

    #[test]
    fn authentication_2_signs_with_sha384() {
        assert_authentication_2_verifies(SignatureDigest::Sha384, EDK2_SHA384_OID);
    }

    #[test]
    fn authentication_2_signs_with_sha512() {
        assert_authentication_2_verifies(SignatureDigest::Sha512, EDK2_SHA512_OID);
    }

    /// The SignedData carries every certificate of the bundle, and names the first's issuer, a CA
    /// other than its subject, and serial number in its SignerInfo.
    #[test]
    fn signed_data_carries_every_certificate_of_the_bundle() {
        let key_text = std::str::from_utf8(test_pems().0.as_bytes()).expect("PEM text");
        let test_key = RsaPrivateKey::from_pkcs8_pem(key_text).expect("decode the key");
        let issued = certificate_pem(&test_key, CA_NAME);
        let certificate = issued.as_bytes();
        let other = other_pems().1.as_bytes();
        let signer = bundle_signer(&[certificate, other].concat()).expect("signer");
        let key = db();

        let payload = signer
            .authentication_2(&write(&key, b"data"), &mut ChaCha20Rng::seed_from_u64(8))
            .expect("sign");

        let signed = SignedData::from_der(split(&payload).0).expect("CertData is a SignedData");
        let mut carried = signed
            .certificates
            .expect("SignedData.certificates")
            .0
            .iter()
            .map(|choice| choice.to_der().expect("encode a certificate"))
            .collect::<Vec<_>>();
        carried.sort();
        let first = Certificate::from_pem(certificate).expect("decode the first certificate");
        let second = Certificate::from_pem(other).expect("decode the second certificate");
        let mut bundled = [&first, &second].map(|certificate| {
            CertificateChoices::Certificate(certificate.clone())
                .to_der()
                .expect("encode a certificate")
        });
        bundled.sort();
        assert_eq!(carried, bundled, "both certificates of the bundle");
        let SignerIdentifier::IssuerAndSerialNumber(id) = &signed.signer_infos.0.as_slice()[0].sid
        else {
            panic!("SignerInfo by issuer and serial number");
        };
        assert_eq!(
            id.serial_number, first.tbs_certificate.serial_number,
            "the first certificate's serial number"
        );
        assert_eq!(
            id.issuer, first.tbs_certificate.issuer,
            "the first certificate's issuer"
        );
        assert_ne!(
            id.issuer, first.tbs_certificate.subject,
            "the first certificate's issuer, not its subject"
        );
    }

    /// authentication_2 signs a SignedData of 65535 bytes after its tag and length, its digest
    /// OID at offset 13, and refuses one of 65536, whose OID edk2 would not find there.
    #[test]
    fn authentication_2_refuses_a_signed_data_of_64_kib() {
        let certificate = test_pems().1.as_bytes();
        let key = db();
        let write = write(&key, b"data");
        let sign = |padding: usize| {
            bundle_signer(&[certificate, padded_certificate_pem(padding).as_bytes()].concat())
                .expect("signer")
                .authentication_2(&write, &mut ChaCha20Rng::seed_from_u64(9))
        };
        let length = |payload: &[u8]| {
            let (cert_data, _) = split(payload);
            assert_eq!(cert_data[..2], [0x30, 0x82], "two-byte length");
            assert_eq!(
                cert_data[13..22],
                EDK2_SHA256_OID,
                "digest OID at offset 13"
            );
            usize::from(u16::from_be_bytes([cert_data[2], cert_data[3]]))
        };
        let padding = 1000 + 0xFFFF - length(&sign(1000).expect("sign with 1000 padding bytes"));

        let largest = sign(padding).expect("sign a SignedData of 65535 bytes");
        let refused = sign(padding + 1);

        assert_eq!(
            length(&largest),
            0xFFFF,
            "65535 bytes after the tag and length"
        );
        assert!(
            matches!(refused, Err(SigningRefusal::TooLarge(0x10000))),
            "65536 bytes are refused: {refused:?}"
        );
    }

    /// Signing draws random bytes for blinding, yet PKCS #1 v1.5 gives the same descriptor from
    /// any of them.
    #[test]
    fn signing_draws_random_bytes_for_blinding() {
        let signer = test_signer();
        let key = db();
        let write = write(&key, b"data");
        let mut first = CountingRng {
            inner: ChaCha20Rng::seed_from_u64(3),
            drawn: 0,
        };
        let mut second = CountingRng {
            inner: ChaCha20Rng::seed_from_u64(4),
            drawn: 0,
        };

        let a = signer.authentication_2(&write, &mut first).expect("sign");
        let b = signer.authentication_2(&write, &mut second).expect("sign");

        assert!(first.drawn > 0, "signing drew {} bytes", first.drawn);
        assert!(second.drawn > 0, "signing drew {} bytes", second.drawn);
        assert_eq!(a, b, "the same descriptor from different random bytes");
    }

    /// seeded_rng seeds from its source, and fails naming the source when it has none.
    #[test]
    fn seeded_rng_names_a_missing_source() {
        let mut a = seeded_rng(&mut FakeSeed(Some(7))).expect("seed");
        let mut b = ChaCha20Rng::from_seed([7; SEED_LEN]);
        assert_eq!(a.next_u64(), b.next_u64(), "the RNG starts from the seed");

        let error = seeded_rng(&mut FakeSeed(None)).expect_err("seed without a source");
        assert_eq!(
            format!("{error:#}"),
            "cannot seed RSA blinding from EFI_RNG_PROTOCOL: no handle has it: NOT_FOUND",
            "the refusal names the source"
        );
    }

    /// Signer refuses a certificate of another key, a key of fewer than 2048 bits and text that
    /// is no key.
    #[test]
    fn signer_refuses_keys_that_do_not_fit() {
        let (key, _) = test_pems();
        let (_, other_certificate) = other_pems();
        assert!(
            matches!(
                Signer::from_pem(key, other_certificate.as_bytes(), SignatureDigest::Sha256),
                Err(SigningRefusal::KeyMismatch)
            ),
            "a certificate of another key is refused"
        );

        let small = RsaPrivateKey::new(&mut ChaCha20Rng::seed_from_u64(6), 1024)
            .expect("generate a 1024-bit key")
            .to_pkcs8_pem(LineEnding::LF)
            .expect("encode it");
        assert!(
            matches!(
                Signer::from_pem(
                    &secret(small.as_bytes()),
                    test_pems().1.as_bytes(),
                    SignatureDigest::Sha256
                ),
                Err(SigningRefusal::KeySize(1024))
            ),
            "a 1024-bit key is refused"
        );
        assert!(
            matches!(
                Signer::from_pem(
                    &secret(b"no key"),
                    test_pems().1.as_bytes(),
                    SignatureDigest::Sha256
                ),
                Err(SigningRefusal::KeyFormat)
            ),
            "text that is no key is refused"
        );
    }

    /// key_size takes 2048 to 4096 bits only.
    #[test]
    fn key_size_takes_2048_to_4096_bits() {
        for (bits, taken) in [(2047, false), (2048, true), (4096, true), (4097, false)] {
            let size = key_size(bits);
            assert_eq!(size.is_ok(), taken, "{bits} bits are taken: {taken}");
            assert!(
                taken || matches!(size, Err(SigningRefusal::KeySize(refused)) if refused == bits),
                "{bits} bits are refused by their number"
            );
        }
    }

    /// Signer takes a key file whose PEM text ends in blank lines, and refuses an encrypted key
    /// by its label.
    #[test]
    fn signer_takes_the_pem_text_of_the_key_file() {
        let (key, certificate) = test_pems();
        for end in ["\n", "\n\n", "\r\n \t\n"] {
            assert!(
                Signer::from_pem(
                    &secret(&[key.as_bytes(), end.as_bytes()].concat()),
                    certificate.as_bytes(),
                    SignatureDigest::Sha256
                )
                .is_ok(),
                "a key file that ends in {end:?} is taken"
            );
        }

        let encrypted = format!(
            "-----BEGIN {ENCRYPTED_KEY_LABEL}-----\nAAAA\n-----END {ENCRYPTED_KEY_LABEL}-----\n"
        );
        assert!(
            matches!(
                Signer::from_pem(
                    &secret(encrypted.as_bytes()),
                    certificate.as_bytes(),
                    SignatureDigest::Sha256
                ),
                Err(SigningRefusal::EncryptedKey)
            ),
            "an encrypted key is refused by its label"
        );
    }

    /// Signer takes the signer's certificate first in the bundle, and refuses a bundle of no
    /// certificate, of a broken one or of one twice.
    #[test]
    fn signer_refuses_bundles_that_do_not_fit() {
        let certificate = test_pems().1.as_bytes();
        assert!(
            matches!(
                bundle_signer(&[other_pems().1.as_bytes(), certificate].concat()),
                Err(SigningRefusal::KeyMismatch)
            ),
            "the signer's certificate after another one is refused"
        );
        for empty in [&b"\n"[..], b"  \r\n", b"no certificate"] {
            assert!(
                matches!(bundle_signer(empty), Err(SigningRefusal::NoCertificate)),
                "{empty:?} is refused"
            );
        }
        let broken = String::from_utf8(certificate.to_vec())
            .expect("PEM text")
            .replacen("MII", "MIX", 1);
        assert!(
            matches!(
                bundle_signer(broken.as_bytes()),
                Err(SigningRefusal::CertificateFormat(_))
            ),
            "a broken certificate is refused"
        );
        assert!(
            matches!(
                bundle_signer(&[certificate, certificate].concat()),
                Err(SigningRefusal::DuplicateCertificate)
            ),
            "the signer's certificate twice is refused"
        );
    }
}
