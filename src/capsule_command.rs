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

//! The capsule command: capsules for this machine's firmware (UEFI 2.11 §8.5.3).

use std::path::Path;
use std::path::PathBuf;

#[cfg(not(capsule_delivery))]
use anyhow::anyhow;
use anyhow::Result;
use clap::Parser;
use clap::Subcommand;
#[cfg(capsule_delivery)]
use uefisettings::exports::CapsuleBackend;
#[cfg(capsule_delivery)]
use uefisettings::exports::CapsuleCapabilities;

#[cfg(capsule_delivery)]
use crate::platform;
#[cfg(capsule_delivery)]
use crate::print_line;

#[derive(Debug, Parser)]
#[command(next_display_order = None)]
pub(super) struct CapsuleCommand {
    #[command(subcommand)]
    command: CapsuleSubcommands,
}

#[derive(Debug, Subcommand)]
enum CapsuleSubcommands {
    /// Deliver a file to the firmware, unchanged, as the JSON payload of a configuration capsule; it never resets the machine
    #[command(next_display_order = None)]
    Deliver {
        /// The JSON payload, which uefisettings neither parses nor changes
        payload: PathBuf,
        /// The CapsuleId of the capsule, which the result of its processing names
        #[arg(long)]
        capsule_id: u32,
    },
}

impl CapsuleCommand {
    pub(super) fn run(&self) -> Result<()> {
        match &self.command {
            CapsuleSubcommands::Deliver {
                payload,
                capsule_id,
            } => deliver(payload, *capsule_id),
        }
    }
}

/// Delivers the file `payload` as the JSON payload of a capsule whose CapsuleId is `capsule_id`,
/// and prints what that told.
#[cfg(capsule_delivery)]
fn deliver(payload: &Path, capsule_id: u32) -> Result<()> {
    let payload = platform::read_payload(payload)?;
    let delivered = CapsuleBackend::deliver_json(&payload, capsule_id)?;
    print_line(format_args!(
        "{}",
        delivery_report(delivered.capsule_size, delivered.capabilities)
    ))?;
    Ok(())
}

/// Fails: the Windows build delivers no capsules.
#[cfg(not(capsule_delivery))]
fn deliver(_payload: &Path, _capsule_id: u32) -> Result<()> {
    Err(anyhow!(
        "uefisettings cannot deliver capsules on Windows: the Win32 calls that it uses, \
         GetFirmwareEnvironmentVariableExW and SetFirmwareEnvironmentVariableExW, reach EFI \
         variables only; deliver capsules on Linux, or in the UEFI Shell with uefisettings.efi"
    ))
}

/// What deliver prints on stdout about a capsule of `capsule_size` bytes and the `capabilities`
/// that QueryCapsuleCapabilities() told of it: its own JSON object, outside the thrift IDL that
/// the hii commands print, and JSON always, as deliver takes no -j; maximum_capsule_size and
/// reset_type, an EFI_RESET_TYPE, are null where the backend does not see them.
#[cfg(capsule_delivery)]
fn delivery_report(
    capsule_size: usize,
    capabilities: Option<CapsuleCapabilities>,
) -> serde_json::Value {
    serde_json::json!({
        "capsule_size": capsule_size,
        "maximum_capsule_size": capabilities.map(|told| told.maximum_capsule_size),
        "reset_type": capabilities.map(|told| told.reset_type.0),
    })
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    #[cfg(capsule_delivery)]
    use uefisettings::exports::ResetType;

    use super::*;
    use crate::Commands;
    use crate::UefiSettingsToolArgs;

    /// The capsule subcommand that `args`, after `uefisettings capsule`, parse to.
    fn capsule(args: &[&str]) -> Result<CapsuleSubcommands, clap::error::ErrorKind> {
        let argv = [&["uefisettings", "capsule"][..], args].concat();
        match UefiSettingsToolArgs::try_parse_from(&argv)
            .map_err(|error| error.kind())?
            .command
        {
            Commands::Capsule(capsule) => Ok(capsule.command),
            other => panic!("{argv:?} is no capsule command: {other:?}"),
        }
    }

    /// deliver takes a payload file and a CapsuleId, a UINT32, both required.
    #[test]
    fn deliver_takes_a_payload_and_a_capsule_id() {
        for (args, want) in [
            (
                &["deliver", "a.json", "--capsule-id", "7"][..],
                ("a.json", 7),
            ),
            (
                &["deliver", "--capsule-id", "4294967295", "b"],
                ("b", u32::MAX),
            ),
        ] {
            let CapsuleSubcommands::Deliver {
                payload,
                capsule_id,
            } = capsule(args).unwrap_or_else(|error| panic!("parse {args:?}: {error}"));

            assert_eq!(
                (payload.as_path(), capsule_id),
                (Path::new(want.0), want.1),
                "{args:?}"
            );
        }
        for (args, want) in [
            (
                &["deliver", "a.json"][..],
                clap::error::ErrorKind::MissingRequiredArgument,
            ),
            (
                &["deliver", "--capsule-id", "7"],
                clap::error::ErrorKind::MissingRequiredArgument,
            ),
            (
                &["deliver", "a.json", "--capsule-id", "4294967296"],
                clap::error::ErrorKind::ValueValidation,
            ),
            (
                &["deliver", "a.json", "--capsule-id", "-1"],
                clap::error::ErrorKind::UnknownArgument,
            ),
            (
                &["deliver", "a.json", "--capsule-id", "0x7"],
                clap::error::ErrorKind::ValueValidation,
            ),
        ] {
            assert_eq!(capsule(args).err(), Some(want), "{args:?}");
        }
    }

    /// deliver's report names the capsule's size, and the maximum size and reset type of
    /// QueryCapsuleCapabilities() as numbers, or null where the backend does not see them.
    #[cfg(capsule_delivery)]
    #[test]
    fn delivery_report_is_a_json_object_with_nulls_for_what_the_backend_does_not_see() {
        let capabilities = CapsuleCapabilities {
            maximum_capsule_size: 65536,
            reset_type: ResetType::WARM,
        };
        for (report, want) in [
            (
                delivery_report(42, Some(capabilities)),
                serde_json::json!({
                    "capsule_size": 42,
                    "maximum_capsule_size": 65536,
                    "reset_type": 1,
                }),
            ),
            (
                delivery_report(42, None),
                serde_json::json!({
                    "capsule_size": 42,
                    "maximum_capsule_size": null,
                    "reset_type": null,
                }),
            ),
        ] {
            assert_eq!(report, want, "{want}");
        }
    }

    /// deliver refuses on Windows before reading the payload, naming why.
    #[cfg(not(capsule_delivery))]
    #[test]
    fn deliver_refuses_on_windows() {
        let error = deliver(Path::new("missing.json"), 7).expect_err("deliver on Windows");

        assert_eq!(
            error.to_string(),
            "uefisettings cannot deliver capsules on Windows: the Win32 calls that it uses, \
             GetFirmwareEnvironmentVariableExW and SetFirmwareEnvironmentVariableExW, reach EFI \
             variables only; deliver capsules on Linux, or in the UEFI Shell with uefisettings.efi",
            "error"
        );
    }
}
