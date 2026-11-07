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

//! The variable subcommands that write the boot manager's variables (UEFI 2.11 §3.1).

use anyhow::Result;
use clap::Args;
use clap::Subcommand;
use clap::ValueEnum;
use uefisettings::exports::AttributeChange;
use uefisettings::exports::HotKeysFollowing;
use uefisettings::exports::LoadOptionCategory;
use uefisettings::exports::LoadOptionFlag;
use uefisettings::exports::VariableBackend;

use super::print_global_variable;

#[derive(Debug, Subcommand)]
pub(super) enum BootManagerSubcommands {
    /// Set and clear the flags and set the category of a Boot####, Driver#### or SysPrep####,
    /// keeping its other bits and bytes, and the Key#### of a Boot#### following it
    #[command(next_display_order = None)]
    SetAttributes(SetAttributesArgs),
}

impl BootManagerSubcommands {
    pub(super) fn run(&self) -> Result<()> {
        match self {
            Self::SetAttributes(args) => args.run(),
        }
    }
}

/// The load option and the change of its Attributes.
#[derive(Debug, Args)]
pub(super) struct SetAttributesArgs {
    /// The load option, such as Boot0001, of vendor 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
    name: String,
    /// The flags to set, comma-separated
    #[arg(long, value_enum, value_delimiter = ',')]
    set: Vec<FlagArg>,
    /// The flags to clear, comma-separated
    #[arg(long, value_enum, value_delimiter = ',')]
    clear: Vec<FlagArg>,
    /// The category to give it, a value of LOAD_OPTION_CATEGORY: boot options boot, app ones the
    /// boot manager starts only when asked to
    #[arg(long, value_enum)]
    category: Option<CategoryArg>,
}

impl SetAttributesArgs {
    /// Writes the change and prints the load option as get shows it, and a line on stderr for
    /// each Key#### updated.
    fn run(&self) -> Result<()> {
        let set = VariableBackend::set_attributes(&self.name, &self.change())?;
        for note in hot_key_notes(&set.hot_keys) {
            eprintln!("{note}");
        }
        print_global_variable(&set.option)
    }

    fn change(&self) -> AttributeChange {
        AttributeChange {
            set: self.set.iter().copied().map(LoadOptionFlag::from).collect(),
            clear: self
                .clear
                .iter()
                .copied()
                .map(LoadOptionFlag::from)
                .collect(),
            category: self.category.map(LoadOptionCategory::from),
        }
    }
}

/// What set-attributes prints on stderr of the Key#### that followed the load option.
fn hot_key_notes(hot_keys: &HotKeysFollowing) -> Vec<String> {
    match hot_keys {
        HotKeysFollowing::Updated(numbers) => numbers
            .iter()
            .map(|number| {
                format!(
                    "updated Key{number:04X}: its BootOptionCrc is the CRC-32 of the Boot#### \
                     that it starts again (UEFI 2.11 section 3.1.6)"
                )
            })
            .collect(),
        HotKeysFollowing::Unlisted(boot) => vec![format!(
            "warning: EFI variables cannot be listed here, so each Key#### that names {boot} \
             keeps the CRC-32 of its old bytes, and the boot manager now ignores it (UEFI 2.11 \
             section 3.1.6)"
        )],
        _ => Vec::new(),
    }
}

/// A flag of a load option's Attributes (UEFI 2.11 §3.1.3), LOAD_OPTION_ and these names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum FlagArg {
    Active,
    ForceReconnect,
    Hidden,
}

impl From<FlagArg> for LoadOptionFlag {
    fn from(flag: FlagArg) -> Self {
        match flag {
            FlagArg::Active => Self::Active,
            FlagArg::ForceReconnect => Self::ForceReconnect,
            FlagArg::Hidden => Self::Hidden,
        }
    }
}

/// A value of LOAD_OPTION_CATEGORY that UEFI 2.11 §3.1.3 defines, LOAD_OPTION_CATEGORY_ and
/// these names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum CategoryArg {
    Boot,
    App,
}

impl From<CategoryArg> for LoadOptionCategory {
    fn from(category: CategoryArg) -> Self {
        match category {
            CategoryArg::Boot => Self::Boot,
            CategoryArg::App => Self::App,
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::error::ErrorKind;
    use clap::Parser;
    use uefisettings::exports::LoadOptionKind;
    use uefisettings::exports::LoadOptionName;

    use super::*;
    use crate::variable_command::VariableSubcommands;
    use crate::Commands;
    use crate::UefiSettingsToolArgs;

    /// The boot manager subcommand that `args`, after `uefisettings variable`, parse to, or the
    /// kind of error that their parse fails with.
    fn boot_manager(args: &[&str]) -> std::result::Result<BootManagerSubcommands, ErrorKind> {
        let argv = [&["uefisettings", "variable"][..], args].concat();
        let command = UefiSettingsToolArgs::try_parse_from(&argv)
            .map_err(|error| error.kind())?
            .command;
        match command {
            Commands::Variable(variable) => match variable.command {
                VariableSubcommands::BootManager(command) => Ok(command),
                #[cfg(variable_info)]
                parsed @ VariableSubcommands::Info { .. } => {
                    panic!("{argv:?} is no boot manager write: {parsed:?}")
                }
                parsed @ (VariableSubcommands::List { .. }
                | VariableSubcommands::Get { .. }
                | VariableSubcommands::Set { .. }
                | VariableSubcommands::Storage { .. }
                | VariableSubcommands::WriteSigned(_)) => {
                    panic!("{argv:?} is no boot manager write: {parsed:?}")
                }
            },
            other => panic!("{argv:?} is no variable command: {other:?}"),
        }
    }

    /// set-attributes takes the load option, flags to set and to clear, comma-separated or
    /// repeated, and a category, a value: no flag names LOAD_OPTION_CATEGORY_APP's bit.
    #[test]
    fn set_attributes_takes_flags_and_a_category_value() {
        let cases: [(&[&str], AttributeChange); 3] = [
            (
                &[
                    "Boot0001",
                    "--set",
                    "active,hidden",
                    "--clear",
                    "force-reconnect",
                    "--category",
                    "app",
                ],
                AttributeChange {
                    set: vec![LoadOptionFlag::Active, LoadOptionFlag::Hidden],
                    clear: vec![LoadOptionFlag::ForceReconnect],
                    category: Some(LoadOptionCategory::App),
                },
            ),
            (
                &["Boot0001", "--clear", "active", "--clear", "hidden"],
                AttributeChange {
                    clear: vec![LoadOptionFlag::Active, LoadOptionFlag::Hidden],
                    ..AttributeChange::default()
                },
            ),
            (
                &["Boot0001", "--category", "boot"],
                AttributeChange {
                    category: Some(LoadOptionCategory::Boot),
                    ..AttributeChange::default()
                },
            ),
        ];
        for (args, want) in cases {
            let argv = [&["set-attributes"][..], args].concat();
            let parsed = match boot_manager(&argv) {
                Ok(BootManagerSubcommands::SetAttributes(parsed)) => parsed,
                other => panic!("{argv:?} is no set-attributes: {other:?}"),
            };

            assert_eq!(
                (parsed.name.as_str(), parsed.change()),
                ("Boot0001", want),
                "{argv:?}"
            );
        }

        for args in [
            &["set-attributes", "Boot0001", "--set", "app"][..],
            &["set-attributes", "Boot0001", "--clear", "category-app"],
            &["set-attributes", "Boot0001", "--category", "0x300"],
        ] {
            assert_eq!(
                boot_manager(args).map(|_| ()),
                Err(ErrorKind::InvalidValue),
                "{args:?}"
            );
        }
        assert_eq!(
            boot_manager(&["set-attributes"]).map(|_| ()),
            Err(ErrorKind::MissingRequiredArgument),
            "no load option"
        );
    }

    /// The flags and categories that set-attributes and create-load-option take are those that
    /// variable get prints.
    #[test]
    fn flag_and_category_names_are_those_that_get_prints() {
        for flag in FlagArg::value_variants() {
            let name = flag
                .to_possible_value()
                .expect("a possible value")
                .get_name()
                .to_owned();

            assert_eq!(name, LoadOptionFlag::from(*flag).name(), "{flag:?}");
        }
        for category in CategoryArg::value_variants() {
            let name = category
                .to_possible_value()
                .expect("a possible value")
                .get_name()
                .to_owned();

            assert_eq!(
                name,
                LoadOptionCategory::from(*category).name(),
                "{category:?}"
            );
        }
    }

    #[test]
    fn hot_key_notes_name_each_key_updated_or_that_none_could_be() {
        assert_eq!(
            hot_key_notes(&HotKeysFollowing::Updated(vec![1, 0xA])),
            [
                "updated Key0001: its BootOptionCrc is the CRC-32 of the Boot#### that it starts \
                 again (UEFI 2.11 section 3.1.6)",
                "updated Key000A: its BootOptionCrc is the CRC-32 of the Boot#### that it starts \
                 again (UEFI 2.11 section 3.1.6)",
            ],
            "updated"
        );
        assert_eq!(
            hot_key_notes(&HotKeysFollowing::Updated(Vec::new())),
            Vec::<String>::new(),
            "none updated"
        );
        assert_eq!(
            hot_key_notes(&HotKeysFollowing::Unlisted(LoadOptionName {
                kind: LoadOptionKind::Boot,
                number: 1,
            })),
            ["warning: EFI variables cannot be listed here, so each Key#### that names Boot0001 \
              keeps the CRC-32 of its old bytes, and the boot manager now ignores it (UEFI 2.11 \
              section 3.1.6)"],
            "unlisted"
        );
    }
}
