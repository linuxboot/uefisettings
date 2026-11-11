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

//! variable write-signed: writes to an EFI variable a payload that the caller signed, or new data
//! that it signs with the caller's key, and the firmware verifies the signature (UEFI 2.11
//! §8.2.6, and §8.2.5 with EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS).

use std::path::Path;
use std::path::PathBuf;
use std::time::SystemTime;

use anyhow::bail;
use anyhow::Result;
use clap::Args;
use clap::ValueEnum;
use uefisettings::exports::EnhancedVariableWrite;
use uefisettings::exports::Freshness;
use uefisettings::exports::NewAuthority;
use uefisettings::exports::Nonce;
use uefisettings::exports::SignatureDigest;
use uefisettings::exports::SignedVariableWrite;
use uefisettings::exports::TimeStamp;
use uefisettings::exports::UnsafeOperation;
use uefisettings::exports::VariableAttributes;
use uefisettings::exports::VariableBackend;

use crate::platform;
use crate::print_lifted;
use crate::unsafe_long_help;
use crate::UnsafeArgs;
use crate::UNSAFE_ARG;

/// What write-signed refuses without --i-am-fine-to-brick-this-system.
const SETUP_MODE_WRITE: &str = "a write of a Secure Boot policy variable (PK, KEK, \
                                OsRecoveryOrder, any OsRecovery####, any variable of \
                                EFI_IMAGE_SECURITY_DATABASE_GUID such as db, dbx, dbt and dbr) \
                                while SetupMode is 1, when the firmware checks no signature (UEFI \
                                2.11 sections 3.3 and 32.3), or of a device signature database \
                                (any variable of EFI_DEVICE_SECURITY_DATABASE_GUID such as devdb), \
                                which the firmware may then write without checking the signature \
                                (section 32.6.3), either also while SetupMode cannot be read or \
                                holds other than a UINT8 of 0 or 1, which may be 1. The payload \
                                of a Secure Boot policy variable is \
                                still an EFI_VARIABLE_AUTHENTICATION_2; that of a device signature \
                                database may be either descriptor: an \
                                EFI_VARIABLE_AUTHENTICATION_3 with enhanced-authenticated-access, \
                                as section 32.6.3 formats a Setup Mode write, or an \
                                EFI_VARIABLE_AUTHENTICATION_2, which edk2 takes. Writing PK moves \
                                Setup Mode to User Mode, and Audit Mode to Deployed Mode (sections \
                                32.3.1 and 32.3.4). PK may have to be signed with its own key \
                                (section 32.3.1)";

/// The variable, the attributes and the payload file of a signed write.
#[derive(Debug, Args)]
#[command(mut_arg(UNSAFE_ARG, |arg| unsafe_long_help(arg, &[SETUP_MODE_WRITE])))]
pub(super) struct WriteSignedArgs {
    /// The variable, such as db
    name: String,
    /// The vendor GUID of the variable, such as D719B2CB-3D3A-4596-A3BC-DAD00E67656F
    guid: String,
    /// The attributes of the write, which the signature covers, but EFI_VARIABLE_APPEND_WRITE, which --append names, and EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS, which uefisettings adds unless enhanced-authenticated-access names an EFI_VARIABLE_AUTHENTICATION_3 (UEFI 2.11 section 8.2.5)
    #[arg(long, value_enum, value_delimiter = ',', required = true)]
    attributes: Vec<SignedAttributeArg>,
    /// Append the new data to the variable (EFI_VARIABLE_APPEND_WRITE), which the signature covers too
    #[arg(long)]
    append: bool,
    /// The payload: an EFI_VARIABLE_AUTHENTICATION_2 descriptor (UEFI 2.11 section 8.2.6), or with enhanced-authenticated-access an EFI_VARIABLE_AUTHENTICATION_3 and its descriptors (section 8.2.5), and then the new data of the variable, which uefisettings writes unchanged
    #[arg(
        long,
        required_unless_present = "data_file",
        conflicts_with = "data_file"
    )]
    payload_file: Option<PathBuf>,
    /// The new data of the variable, which uefisettings signs with --signing-key-file into an EFI_VARIABLE_AUTHENTICATION_2 (UEFI 2.11 section 8.2.6), or with enhanced-authenticated-access an EFI_VARIABLE_AUTHENTICATION_3 (section 8.2.5), and writes after it
    #[arg(long, requires_all = ["signing_key_file", "signing_certificate_file"])]
    data_file: Option<PathBuf>,
    /// The unencrypted PEM RSA private key, PKCS #8 or PKCS #1 of 2048 to 4096 bits, that signs --data-file; read as a secret of at most 64 KiB
    #[arg(long, requires = "data_file")]
    signing_key_file: Option<PathBuf>,
    /// The PEM X.509 certificates that the signature carries: the one of --signing-key-file's public key, then any others, such as intermediate CAs; DER sorts them (X.690 section 11.6); a file of at most 64 KiB
    #[arg(long, requires = "data_file")]
    signing_certificate_file: Option<PathBuf>,
    /// The digest of the signatures (UEFI 2.11 sections 8.2.6 and 8.2.5)
    #[arg(long, value_enum, default_value_t = DigestArg::Sha256, requires = "data_file")]
    digest: DigestArg,
    /// The TimeStamp to sign, a GMT time such as 2026-11-07T00:00:00Z. In an EFI_VARIABLE_AUTHENTICATION_2, later than the variable's unless --append; by default the current second of the system clock, but in the UEFI Shell, which reads none, --append signs the all-zero TimeStamp of UEFI 2.11 section 8.2.6. With enhanced-authenticated-access, it makes a TIMESTAMP_TYPE EFI_VARIABLE_AUTHENTICATION_3, whose TimeStamp is always later than the variable's (section 8.2.5); that needs this or --nonce
    #[arg(long, requires = "data_file")]
    timestamp: Option<TimeStamp>,
    /// With enhanced-authenticated-access, sign a NONCE_TYPE EFI_VARIABLE_AUTHENTICATION_3 of this nonce, two hex digits per byte, other than the variable's; all zero asks the firmware to make one of that size (UEFI 2.11 section 8.2.5)
    #[arg(long, requires = "data_file", conflicts_with = "timestamp")]
    nonce: Option<Nonce>,
    /// The nonce that the variable holds, two hex digits per byte, which UEFI 2.11 section 8.2.5 signs after the data of an update of a NONCE_TYPE variable (deleting one, which section 8.2.3 defines, write-signed refuses): by default the one that the variable's metadata gives (section 8.2.1); given, it must be that one, and a create takes none
    // clap waives `requires` for an argument that conflicts with a given one, as --nonce with
    // --timestamp, hence the conflict.
    #[arg(long, requires = "nonce", conflicts_with = "timestamp")]
    current_nonce: Option<Nonce>,
    /// With enhanced-authenticated-access, hand the variable to this unencrypted PEM RSA private key, PKCS #8 or PKCS #1 of 2048 to 4096 bits, in a NewCert that it signs over --digest (UEFI 2.11 section 8.2.5); read as a secret of at most 64 KiB
    #[arg(long, requires_all = ["data_file", "new_signing_certificate_file"])]
    new_signing_key_file: Option<PathBuf>,
    /// The PEM X.509 certificates of --new-signing-key-file: the one of its public key, whose tbsCertificate the NewCert signs, then any others; a file of at most 64 KiB
    #[arg(long, requires = "new_signing_key_file")]
    new_signing_certificate_file: Option<PathBuf>,
    #[command(flatten)]
    unsafe_operations: UnsafeArgs,
}

/// An attribute of EFI variables (UEFI 2.11 §8.2.1) that a signed write takes as given.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum SignedAttributeArg {
    NonVolatile,
    BootserviceAccess,
    RuntimeAccess,
    EnhancedAuthenticatedAccess,
}

impl From<SignedAttributeArg> for VariableAttributes {
    fn from(attribute: SignedAttributeArg) -> Self {
        match attribute {
            SignedAttributeArg::NonVolatile => Self::NON_VOLATILE,
            SignedAttributeArg::BootserviceAccess => Self::BOOTSERVICE_ACCESS,
            SignedAttributeArg::RuntimeAccess => Self::RUNTIME_ACCESS,
            SignedAttributeArg::EnhancedAuthenticatedAccess => Self::ENHANCED_AUTHENTICATED_ACCESS,
        }
    }
}

/// A digest that UEFI 2.11 §8.2.6 accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum DigestArg {
    Sha256,
    Sha384,
    Sha512,
}

impl From<DigestArg> for SignatureDigest {
    fn from(digest: DigestArg) -> Self {
        match digest {
            DigestArg::Sha256 => Self::Sha256,
            DigestArg::Sha384 => Self::Sha384,
            DigestArg::Sha512 => Self::Sha512,
        }
    }
}

/// What a signed write of the data file signs it into, as the flags name it, before any file is
/// read.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Signing<'a> {
    /// An EFI_VARIABLE_AUTHENTICATION_2 at this TimeStamp (UEFI 2.11 §8.2.6)
    Authentication2(TimeStamp),
    /// An EFI_VARIABLE_AUTHENTICATION_3 of this Freshness, whose NewCert, if given, hands the
    /// variable to the authority of these key and certificate files (§8.2.5)
    Authentication3 {
        freshness: Freshness,
        new_authority: Option<NewAuthorityFiles<'a>>,
    },
}

/// The key and certificate files of the authority that a NewCert hands a variable to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct NewAuthorityFiles<'a> {
    key: &'a Path,
    certificates: &'a Path,
}

impl WriteSignedArgs {
    /// Writes the payload file, or the data file that the key signs, to the variable, printing
    /// only a warning per unsafe operation that it lifted.
    pub(super) fn run(&self) -> Result<()> {
        print_lifted(&self.write()?)?;
        Ok(())
    }

    /// Writes the payload file, or the data file that the key signs, to the variable; returns the
    /// unsafe operations that it lifted.
    fn write(&self) -> Result<Vec<UnsafeOperation>> {
        let unsafe_operations = self.unsafe_operations.operations();
        let (Some(data_file), Some(key_file), Some(certificate_file)) = (
            &self.data_file,
            &self.signing_key_file,
            &self.signing_certificate_file,
        ) else {
            let Some(payload_file) = &self.payload_file else {
                bail!("write-signed needs --payload-file or --data-file");
            };
            let payload = platform::read_payload(payload_file)?;
            return VariableBackend::write_signed(
                &self.name,
                &self.guid,
                self.attributes(),
                &payload,
                unsafe_operations,
            );
        };
        let signing = self.signing(platform::signing_clock())?;
        let data = platform::read_payload(data_file)?;
        let signing_key = platform::read_secret_file(key_file, "signing key")?;
        let certificates = platform::read_secret_file(certificate_file, "certificate bundle")?;
        let (freshness, new_authority) = match signing {
            Signing::Authentication2(timestamp) => {
                return VariableBackend::sign_and_write(
                    &SignedVariableWrite {
                        name: &self.name,
                        vendor: &self.guid,
                        attributes: self.attributes(),
                        data: &data,
                        timestamp,
                        digest: self.digest.into(),
                        unsafe_operations,
                    },
                    &signing_key,
                    certificates.as_bytes(),
                )
            }
            Signing::Authentication3 {
                freshness,
                new_authority,
            } => (freshness, new_authority),
        };
        let new_authority = new_authority
            .map(|files| -> Result<_> {
                Ok((
                    platform::read_secret_file(files.key, "new signing key")?,
                    platform::read_secret_file(files.certificates, "new certificate bundle")?,
                ))
            })
            .transpose()?;
        VariableBackend::sign_and_write_enhanced(
            &EnhancedVariableWrite {
                name: &self.name,
                vendor: &self.guid,
                attributes: self.attributes(),
                data: &data,
                freshness: &freshness,
                digest: self.digest.into(),
                new_authority: new_authority
                    .as_ref()
                    .map(|(key, certificates)| NewAuthority {
                        key,
                        certificates: certificates.as_bytes(),
                    }),
                unsafe_operations,
            },
            &signing_key,
            certificates.as_bytes(),
        )
    }

    /// What the data file is signed into: with enhanced-authenticated-access, an
    /// EFI_VARIABLE_AUTHENTICATION_3 of --timestamp or of --nonce and --current-nonce, with the
    /// NewCert of --new-signing-key-file and --new-signing-certificate-file if given; else an
    /// EFI_VARIABLE_AUTHENTICATION_2 at signed_time_stamp's TimeStamp, from `clock`. Refuses an
    /// EFI_VARIABLE_AUTHENTICATION_3 of no Type, and the flags of one beside an
    /// EFI_VARIABLE_AUTHENTICATION_2.
    fn signing(&self, clock: Option<SystemTime>) -> Result<Signing<'_>> {
        let new_authority = self
            .new_signing_key_file
            .as_deref()
            .zip(self.new_signing_certificate_file.as_deref())
            .map(|(key, certificates)| NewAuthorityFiles { key, certificates });
        if self
            .attributes
            .contains(&SignedAttributeArg::EnhancedAuthenticatedAccess)
        {
            let freshness = match (self.timestamp, &self.nonce) {
                (Some(timestamp), None) => Freshness::TimeStamp(timestamp),
                (None, Some(nonce)) => Freshness::Nonce {
                    nonce: nonce.clone(),
                    current: self.current_nonce.clone(),
                },
                (None, None) | (Some(_), Some(_)) => bail!(
                    "--attributes enhanced-authenticated-access with --data-file takes one of \
                     --timestamp and --nonce, the Type of its EFI_VARIABLE_AUTHENTICATION_3 (UEFI \
                     2.11 section 8.2.5)"
                ),
            };
            return Ok(Signing::Authentication3 {
                freshness,
                new_authority,
            });
        }
        let enhanced_only = [
            ("--nonce", self.nonce.is_some()),
            ("--current-nonce", self.current_nonce.is_some()),
            ("--new-signing-key-file", new_authority.is_some()),
        ];
        if let Some((flag, _)) = enhanced_only.iter().find(|(_, given)| *given) {
            bail!(
                "{flag} takes --attributes enhanced-authenticated-access, which signs an \
                 EFI_VARIABLE_AUTHENTICATION_3 (UEFI 2.11 section 8.2.5)"
            );
        }
        Ok(Signing::Authentication2(signed_time_stamp(
            self.timestamp,
            self.append,
            clock,
        )?))
    }

    /// The attributes that these name.
    fn attributes(&self) -> VariableAttributes {
        self.attributes
            .iter()
            .copied()
            .map(VariableAttributes::from)
            .chain(self.append.then_some(VariableAttributes::APPEND_WRITE))
            .collect()
    }
}

/// The TimeStamp to sign (UEFI 2.11 §8.2.6): `given`, else the current second of `clock`, the
/// system clock, else, for an append, the all-zero TimeStamp of a platform without a reliable
/// time source.
fn signed_time_stamp(
    given: Option<TimeStamp>,
    append: bool,
    clock: Option<SystemTime>,
) -> Result<TimeStamp> {
    match (given, clock) {
        (Some(timestamp), _) => Ok(timestamp),
        (None, Some(now)) => Ok(TimeStamp::from_system_time(now)?),
        (None, None) if append => Ok(TimeStamp::ZERO),
        (None, None) => bail!(
            "--data-file without --append needs --timestamp here, where uefisettings reads no \
             clock: the firmware takes only a TimeStamp later than the variable's (UEFI 2.11 \
             section 8.2.6)"
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use clap::CommandFactory;
    use clap::Parser;

    use uefisettings::exports::UnsafeOperations;
    use uefisettings::secret_file::MAX_SECRET_LEN;

    use super::*;
    use crate::variable_command::VariableSubcommands;
    use crate::Commands;
    use crate::UefiSettingsToolArgs;
    use crate::UNSAFE_HELP;

    /// The arguments of `uefisettings variable write-signed` and then `args`, or the kind of
    /// error that their parse fails with.
    fn write_signed(args: &[&str]) -> std::result::Result<WriteSignedArgs, clap::error::ErrorKind> {
        let argv = [&["uefisettings", "variable", "write-signed"][..], args].concat();
        let command = UefiSettingsToolArgs::try_parse_from(&argv)
            .map_err(|error| error.kind())?
            .command;
        match command {
            Commands::Variable(variable) => match variable.command {
                VariableSubcommands::WriteSigned(args) => Ok(*args),
                #[cfg(variable_info)]
                parsed @ VariableSubcommands::Info { .. } => {
                    panic!("{argv:?} is no write-signed: {parsed:?}")
                }
                parsed @ (VariableSubcommands::List { .. }
                | VariableSubcommands::Get { .. }
                | VariableSubcommands::Set { .. }
                | VariableSubcommands::Storage { .. }) => {
                    panic!("{argv:?} is no write-signed: {parsed:?}")
                }
            },
            other => panic!("{argv:?} is no variable command: {other:?}"),
        }
    }

    /// write-signed takes the variable, its vendor GUID, the attributes and the payload file,
    /// and APPEND_WRITE only with --append.
    #[test]
    fn write_signed_takes_a_variable_attributes_and_a_payload_file() {
        let db = "D719B2CB-3D3A-4596-A3BC-DAD00E67656F";
        let nv_bs_rt = VariableAttributes::NON_VOLATILE
            | VariableAttributes::BOOTSERVICE_ACCESS
            | VariableAttributes::RUNTIME_ACCESS;
        let cases: [(&[&str], VariableAttributes); 4] = [
            (
                &[
                    "db",
                    db,
                    "--attributes",
                    "non-volatile,bootservice-access,runtime-access",
                    "--append",
                    "--payload-file",
                    "db.auth",
                ],
                nv_bs_rt | VariableAttributes::APPEND_WRITE,
            ),
            (
                &[
                    "db",
                    db,
                    "--payload-file",
                    "db.auth",
                    "--attributes",
                    "non-volatile,bootservice-access",
                    "--attributes",
                    "runtime-access",
                ],
                nv_bs_rt,
            ),
            (
                &[
                    "db",
                    db,
                    "--attributes",
                    "bootservice-access",
                    "--payload-file",
                    "db.auth",
                ],
                VariableAttributes::BOOTSERVICE_ACCESS,
            ),
            (
                &[
                    "db",
                    db,
                    "--attributes",
                    "bootservice-access,enhanced-authenticated-access",
                    "--payload-file",
                    "db.auth",
                ],
                VariableAttributes::BOOTSERVICE_ACCESS
                    | VariableAttributes::ENHANCED_AUTHENTICATED_ACCESS,
            ),
        ];

        for (args, want) in cases {
            let parsed = write_signed(args).unwrap_or_else(|kind| panic!("parse {args:?}: {kind}"));

            assert_eq!(
                (
                    parsed.name.as_str(),
                    parsed.guid.as_str(),
                    parsed.attributes(),
                    parsed.payload_file.as_deref()
                ),
                ("db", db, want, Some(Path::new("db.auth"))),
                "{args:?}"
            );
        }
    }

    /// write-signed signs --data-file with --signing-key-file and --signing-certificate-file at
    /// --timestamp over --digest, SHA-256 by default, takes --i-am-fine-to-brick-this-system, and
    /// refuses a data file next to a payload file, one without its key or certificate, a TimeStamp
    /// that is no GMT time, a digest that UEFI 2.11 §8.2.6 does not accept, and --digest or
    /// --timestamp without a data file.
    #[test]
    fn write_signed_takes_a_data_file_to_sign() {
        use clap::error::ErrorKind::ArgumentConflict;
        use clap::error::ErrorKind::InvalidValue;
        use clap::error::ErrorKind::MissingRequiredArgument;
        use clap::error::ErrorKind::ValueValidation;

        let kek = "8BE4DF61-93CA-11D2-AA0D-00E098032B8C";
        let signed = [
            "KEK",
            kek,
            "--attributes",
            "non-volatile,bootservice-access,runtime-access",
            "--data-file",
            "kek.esl",
            "--signing-key-file",
            "pk.key",
            "--signing-certificate-file",
            "pk.crt",
        ];

        let parsed =
            write_signed(&[&signed[..], &["--timestamp", "2026-11-07T00:00:00Z"]].concat())
                .unwrap_or_else(|kind| panic!("parse a signed write: {kind}"));
        assert_eq!(
            (
                parsed.payload_file.as_deref(),
                parsed.data_file.as_deref(),
                parsed.signing_key_file.as_deref(),
                parsed.signing_certificate_file.as_deref(),
                parsed.timestamp.map(|timestamp| timestamp.to_string()),
                SignatureDigest::from(parsed.digest),
                parsed.unsafe_operations.operations(),
            ),
            (
                None,
                Some(Path::new("kek.esl")),
                Some(Path::new("pk.key")),
                Some(Path::new("pk.crt")),
                Some("2026-11-07T00:00:00Z".to_owned()),
                SignatureDigest::Sha256,
                UnsafeOperations::Refuse,
            ),
            "signed write"
        );
        for args in [
            &signed[..],
            &[
                "db",
                "D719B2CB-3D3A-4596-A3BC-DAD00E67656F",
                "--attributes",
                "non-volatile",
                "--payload-file",
                "db.auth",
            ],
        ] {
            let parsed = write_signed(&[args, &["--i-am-fine-to-brick-this-system"]].concat())
                .unwrap_or_else(|kind| panic!("parse a Setup Mode write of {args:?}: {kind}"));
            assert_eq!(
                parsed.unsafe_operations.operations(),
                UnsafeOperations::Allow,
                "--i-am-fine-to-brick-this-system after {args:?}"
            );
        }
        for (name, digest) in [
            ("sha256", SignatureDigest::Sha256),
            ("sha384", SignatureDigest::Sha384),
            ("sha512", SignatureDigest::Sha512),
        ] {
            let parsed = write_signed(&[&signed[..], &["--digest", name]].concat())
                .unwrap_or_else(|kind| panic!("parse --digest {name}: {kind}"));
            assert_eq!(
                SignatureDigest::from(parsed.digest),
                digest,
                "--digest {name}"
            );
        }

        let payload = [
            "db",
            "D719B2CB-3D3A-4596-A3BC-DAD00E67656F",
            "--attributes",
            "non-volatile",
            "--payload-file",
            "db.auth",
        ];
        let cases: [(Vec<&str>, clap::error::ErrorKind); 7] = [
            (
                [&signed[..], &["--payload-file", "kek.auth"]].concat(),
                ArgumentConflict,
            ),
            (signed[..8].to_vec(), MissingRequiredArgument),
            (
                [&signed[..6], &["--signing-certificate-file", "pk.crt"]].concat(),
                MissingRequiredArgument,
            ),
            (
                [&signed[..], &["--timestamp", "2026-11-07T00:00:00+01:00"]].concat(),
                ValueValidation,
            ),
            ([&signed[..], &["--digest", "sha1"]].concat(), InvalidValue),
            (
                [&payload[..], &["--digest", "sha384"]].concat(),
                MissingRequiredArgument,
            ),
            (
                [&payload[..], &["--timestamp", "2026-11-07T00:00:00Z"]].concat(),
                MissingRequiredArgument,
            ),
        ];
        for (args, want) in cases {
            assert_eq!(write_signed(&args).err(), Some(want), "{args:?}");
        }
    }

    /// The arguments of a write-signed of the data file to sign, with `attributes`; no file
    /// that they name exists.
    fn data_write(attributes: &str) -> Vec<&str> {
        vec![
            "Signed",
            "DE145B29-C3CD-455F-91DE-A76237B67C52",
            "--attributes",
            attributes,
            "--data-file",
            "missing.data",
            "--signing-key-file",
            "missing.key",
            "--signing-certificate-file",
            "missing.crt",
        ]
    }

    /// With enhanced-authenticated-access.
    const ENHANCED: &str = "non-volatile,bootservice-access,enhanced-authenticated-access";
    /// Without it.
    const PLAIN: &str = "non-volatile,bootservice-access";

    /// write-signed maps each of --timestamp, --nonce, --current-nonce, --new-signing-key-file
    /// and --new-signing-certificate-file into its own part of what it signs the data file into,
    /// and an EFI_VARIABLE_AUTHENTICATION_2 into its TimeStamp, given or from the clock.
    #[test]
    fn write_signed_maps_each_signing_flag() {
        let time: TimeStamp = "2026-11-07T00:00:00Z".parse().expect("the test TimeStamp");
        let clock = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_794_013_323);
        let nonce = |digits: &str| digits.parse::<Nonce>().expect("a test nonce");
        let cases: [(&str, &str, &[&str], Signing<'_>); 6] = [
            (
                "--timestamp",
                ENHANCED,
                &["--timestamp", "2026-11-07T00:00:00Z"],
                Signing::Authentication3 {
                    freshness: Freshness::TimeStamp(time),
                    new_authority: None,
                },
            ),
            (
                "--nonce",
                ENHANCED,
                &["--nonce", "a5A5"],
                Signing::Authentication3 {
                    freshness: Freshness::Nonce {
                        nonce: nonce("a5a5"),
                        current: None,
                    },
                    new_authority: None,
                },
            ),
            (
                "--current-nonce",
                ENHANCED,
                &["--nonce", "a5a5", "--current-nonce", "5a5a5a"],
                Signing::Authentication3 {
                    freshness: Freshness::Nonce {
                        nonce: nonce("a5a5"),
                        current: Some(nonce("5a5a5a")),
                    },
                    new_authority: None,
                },
            ),
            (
                "--new-signing-key-file and --new-signing-certificate-file",
                ENHANCED,
                &[
                    "--timestamp",
                    "2026-11-07T00:00:00Z",
                    "--new-signing-key-file",
                    "new.key",
                    "--new-signing-certificate-file",
                    "new.crt",
                ],
                Signing::Authentication3 {
                    freshness: Freshness::TimeStamp(time),
                    new_authority: Some(NewAuthorityFiles {
                        key: Path::new("new.key"),
                        certificates: Path::new("new.crt"),
                    }),
                },
            ),
            (
                "EFI_VARIABLE_AUTHENTICATION_2 at --timestamp",
                PLAIN,
                &["--timestamp", "2026-11-07T00:00:00Z"],
                Signing::Authentication2(time),
            ),
            (
                "EFI_VARIABLE_AUTHENTICATION_2 at the clock's second",
                PLAIN,
                &[],
                Signing::Authentication2("2026-11-07T01:02:03Z".parse().expect("a TimeStamp")),
            ),
        ];

        for (case, attributes, flags, want) in cases {
            let args = [&data_write(attributes)[..], flags].concat();
            let parsed = write_signed(&args).unwrap_or_else(|kind| panic!("parse {case}: {kind}"));

            assert_eq!(
                parsed
                    .signing(Some(clock))
                    .map_err(|error| error.to_string()),
                Ok(want),
                "{case}"
            );
        }
    }

    /// write-signed refuses --nonce beside --timestamp, a nonce that is no hex digits,
    /// --current-nonce beside --timestamp, which a timestamp-type write cannot sign, or without
    /// --nonce, and --new-signing-key-file without its certificate, or either without
    /// --data-file.
    #[test]
    fn write_signed_refuses_enhanced_flags_that_do_not_fit() {
        use clap::error::ErrorKind::ArgumentConflict;
        use clap::error::ErrorKind::MissingRequiredArgument;
        use clap::error::ErrorKind::ValueValidation;

        let payload = [
            "Signed",
            "DE145B29-C3CD-455F-91DE-A76237B67C52",
            "--attributes",
            ENHANCED,
            "--payload-file",
            "signed.auth",
        ];
        let cases: [(&[&str], &[&str], clap::error::ErrorKind); 9] = [
            (
                &data_write(ENHANCED),
                &["--nonce", "a5", "--timestamp", "2026-11-07T00:00:00Z"],
                ArgumentConflict,
            ),
            (&data_write(ENHANCED), &["--nonce", "a5a"], ValueValidation),
            (&data_write(ENHANCED), &["--nonce", ""], ValueValidation),
            (
                &data_write(ENHANCED),
                &[
                    "--timestamp",
                    "2026-11-07T00:00:00Z",
                    "--current-nonce",
                    "a5",
                ],
                ArgumentConflict,
            ),
            (
                &data_write(ENHANCED),
                &["--current-nonce", "a5"],
                MissingRequiredArgument,
            ),
            (
                &data_write(ENHANCED),
                &["--new-signing-key-file", "new.key"],
                MissingRequiredArgument,
            ),
            (
                &data_write(ENHANCED),
                &["--new-signing-certificate-file", "new.crt"],
                MissingRequiredArgument,
            ),
            (&payload, &["--nonce", "a5"], MissingRequiredArgument),
            (
                &payload,
                &[
                    "--new-signing-key-file",
                    "new.key",
                    "--new-signing-certificate-file",
                    "new.crt",
                ],
                MissingRequiredArgument,
            ),
        ];

        for (args, flags, want) in cases {
            let args = [args, flags].concat();
            assert_eq!(write_signed(&args).err(), Some(want), "{args:?}");
        }
    }

    /// write-signed refuses, before it reads any file, an EFI_VARIABLE_AUTHENTICATION_3 of no
    /// Type, and --nonce, --current-nonce or --new-signing-key-file without
    /// enhanced-authenticated-access.
    #[test]
    fn write_signed_refuses_enhanced_flags_without_enhanced_access_before_any_read() {
        let flag_refusal = |flag: &str| {
            format!(
                "{flag} takes --attributes enhanced-authenticated-access, which signs an \
                 EFI_VARIABLE_AUTHENTICATION_3 (UEFI 2.11 section 8.2.5)"
            )
        };
        let cases: [(&str, &[&str], String); 4] = [
            (
                ENHANCED,
                &[],
                "--attributes enhanced-authenticated-access with --data-file takes one of \
                 --timestamp and --nonce, the Type of its EFI_VARIABLE_AUTHENTICATION_3 (UEFI \
                 2.11 section 8.2.5)"
                    .to_owned(),
            ),
            (PLAIN, &["--nonce", "a5"], flag_refusal("--nonce")),
            (
                PLAIN,
                &["--nonce", "a5", "--current-nonce", "5a"],
                flag_refusal("--nonce"),
            ),
            (
                PLAIN,
                &[
                    "--new-signing-key-file",
                    "new.key",
                    "--new-signing-certificate-file",
                    "new.crt",
                ],
                flag_refusal("--new-signing-key-file"),
            ),
        ];

        for (attributes, flags, want) in cases {
            let args = [&data_write(attributes)[..], flags].concat();
            let parsed =
                write_signed(&args).unwrap_or_else(|kind| panic!("parse {args:?}: {kind}"));

            assert_eq!(
                parsed.run().map_err(|error| error.to_string()),
                Err(want),
                "{args:?}"
            );
        }
    }

    /// write-signed needs the variable, its vendor GUID, --attributes and --payload-file, and
    /// takes no attribute that a signed write does not take as given.
    #[test]
    fn write_signed_refuses_missing_arguments_and_other_attributes() {
        use clap::error::ErrorKind::InvalidValue;
        use clap::error::ErrorKind::MissingRequiredArgument;

        let db = "D719B2CB-3D3A-4596-A3BC-DAD00E67656F";
        let cases: [(&[&str], clap::error::ErrorKind); 7] = [
            (
                &["db", "--attributes", "non-volatile", "--payload-file", "p"],
                MissingRequiredArgument,
            ),
            (&["db", db, "--payload-file", "p"], MissingRequiredArgument),
            (
                &["db", db, "--attributes", "non-volatile"],
                MissingRequiredArgument,
            ),
            (
                &[
                    "db",
                    db,
                    "--attributes",
                    "append-write",
                    "--payload-file",
                    "p",
                ],
                InvalidValue,
            ),
            (
                &[
                    "db",
                    db,
                    "--attributes",
                    "time-based-authenticated-write-access",
                    "--payload-file",
                    "p",
                ],
                InvalidValue,
            ),
            (
                &[
                    "db",
                    db,
                    "--attributes",
                    "hardware-error-record",
                    "--payload-file",
                    "p",
                ],
                InvalidValue,
            ),
            (
                &["db", db, "--attributes", "", "--payload-file", "p"],
                InvalidValue,
            ),
        ];

        for (args, want) in cases {
            assert_eq!(write_signed(args).err(), Some(want), "{args:?}");
        }
    }

    /// write-signed refuses a Secure Boot policy variable while SetupMode is 1, and writes it
    /// without a signature check only with --i-am-fine-to-brick-this-system, whose long help
    /// lists the write.
    #[test]
    fn setup_mode_write_is_without_signature_check_only_with_the_flag() {
        let payload = [
            "db",
            "D719B2CB-3D3A-4596-A3BC-DAD00E67656F",
            "--attributes",
            "non-volatile",
            "--payload-file",
            "db.auth",
        ];
        for (flag, unsafe_operations) in [
            (&[][..], UnsafeOperations::Refuse),
            (
                &["--i-am-fine-to-brick-this-system"][..],
                UnsafeOperations::Allow,
            ),
        ] {
            let parsed = write_signed(&[&payload[..], flag].concat())
                .unwrap_or_else(|kind| panic!("parse a write with {flag:?}: {kind}"));
            assert_eq!(
                parsed.unsafe_operations.operations(),
                unsafe_operations,
                "a write with {flag:?}"
            );
        }

        let mut command = UefiSettingsToolArgs::command();
        command.build();
        let long_help = command
            .find_subcommand("variable")
            .and_then(|variable| variable.find_subcommand("write-signed"))
            .and_then(|write_signed| {
                write_signed
                    .get_arguments()
                    .find(|arg| arg.get_long() == Some("i-am-fine-to-brick-this-system"))
            })
            .and_then(|flag| flag.get_long_help())
            .map(ToString::to_string);
        assert_eq!(
            long_help,
            Some(format!(
                "{UNSAFE_HELP}. This command refuses without it: {SETUP_MODE_WRITE}"
            )),
            "write-signed"
        );
    }

    /// Each attribute of write-signed names the one of its spec name.
    #[test]
    fn signed_attributes_are_the_spec_attributes() {
        for attribute in SignedAttributeArg::value_variants() {
            let name = attribute
                .to_possible_value()
                .expect("a possible value")
                .get_name()
                .replace('-', "_")
                .to_ascii_uppercase();

            assert_eq!(
                VariableAttributes::from(*attribute).to_string(),
                name,
                "{attribute:?}"
            );
        }
    }

    /// signed_time_stamp signs --timestamp when given, else the clock's current second, else,
    /// without a clock, the all-zero TimeStamp for an append, and refuses a write that is not.
    #[test]
    fn signed_time_stamp_takes_the_given_then_the_clock_then_zero_for_an_append() {
        let given: TimeStamp = "2026-11-07T00:00:00Z".parse().expect("the given TimeStamp");
        let clock = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_794_013_323);
        let now = Ok("2026-11-07T01:02:03Z".to_owned());
        let cases = [
            (
                Some(given),
                false,
                Some(clock),
                Ok(given.to_string()),
                "given, with a clock",
            ),
            (
                Some(given),
                true,
                None,
                Ok(given.to_string()),
                "given append, without a clock",
            ),
            (
                Some(given),
                false,
                None,
                Ok(given.to_string()),
                "given, without a clock",
            ),
            (None, false, Some(clock), now.clone(), "the clock's second"),
            (
                None,
                true,
                Some(clock),
                now,
                "the clock's second for an append",
            ),
            (
                None,
                true,
                None,
                Ok(TimeStamp::ZERO.to_string()),
                "zero for an append without a clock",
            ),
            (
                None,
                false,
                None,
                Err(
                    "--data-file without --append needs --timestamp here, where uefisettings \
                     reads no clock: the firmware takes only a TimeStamp later than the \
                     variable's (UEFI 2.11 section 8.2.6)"
                        .to_owned(),
                ),
                "no TimeStamp without a clock",
            ),
            (
                None,
                false,
                Some(SystemTime::UNIX_EPOCH - std::time::Duration::from_secs(1)),
                Err("the system clock reads no time from 1970 to 9999".to_owned()),
                "a clock before 1970",
            ),
        ];

        for (given, append, clock, want, case) in cases {
            assert_eq!(
                signed_time_stamp(given, append, clock)
                    .map(|timestamp| timestamp.to_string())
                    .map_err(|error| error.to_string()),
                want,
                "{case}"
            );
        }
    }

    /// The payload is the bytes of its file, and a missing file is an error that names it.
    #[cfg(not(target_os = "uefi"))]
    #[test]
    fn payload_is_the_file_byte_for_byte() {
        let dir = tempfile::tempdir().expect("create a directory");
        let path = dir.path().join("db.auth");
        let payload = (0..=255).collect::<Vec<u8>>();
        std::fs::write(&path, &payload).expect("write the payload file");

        assert_eq!(
            platform::read_payload(&path).map_err(|error| error.to_string()),
            Ok(payload),
            "present"
        );
        let missing = dir.path().join("missing.auth");
        assert_eq!(
            platform::read_payload(&missing).map_err(|error| error.to_string()),
            Err(format!("read the payload {}", missing.display())),
            "missing"
        );
    }

    /// A secret file's errors name what it holds, and one over MAX_SECRET_LEN is refused.
    #[cfg(not(target_os = "uefi"))]
    #[test]
    fn secret_file_errors_name_what_it_holds() {
        let dir = tempfile::tempdir().expect("create a directory");
        let read = |path: &Path| {
            platform::read_secret_file(path, "certificate bundle")
                .map(|secret| secret.as_bytes().len())
                .map_err(|error| error.to_string())
        };
        let full = dir.path().join("full.pem");
        std::fs::write(&full, vec![b'A'; MAX_SECRET_LEN]).expect("write a full file");
        assert_eq!(
            read(&full),
            Ok(MAX_SECRET_LEN),
            "a file of MAX_SECRET_LEN bytes"
        );

        let over = dir.path().join("over.pem");
        std::fs::write(&over, vec![b'A'; MAX_SECRET_LEN + 1]).expect("write a larger file");
        assert_eq!(
            read(&over),
            Err(format!("read the certificate bundle {}", over.display())),
            "a file over MAX_SECRET_LEN bytes"
        );
        let missing = dir.path().join("missing.pem");
        assert_eq!(
            read(&missing),
            Err(format!("open the certificate bundle {}", missing.display())),
            "missing"
        );
    }
}
