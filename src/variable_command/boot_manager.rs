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

use std::path::PathBuf;

use anyhow::bail;
use anyhow::Result;
use clap::builder::PossibleValue;
use clap::ArgGroup;
use clap::Args;
use clap::Subcommand;
use clap::ValueEnum;
use uefisettings::exports::AttributeChange;
use uefisettings::exports::DevicePathSource;
use uefisettings::exports::HotKeysFollowing;
use uefisettings::exports::InputKey;
use uefisettings::exports::KeyModifier;
use uefisettings::exports::LoadOptionCategory;
use uefisettings::exports::LoadOptionFlag;
use uefisettings::exports::NewHotKey;
use uefisettings::exports::NewLoadOption;
use uefisettings::exports::VariableBackend;

use super::print_global_variable;
use crate::platform;

#[derive(Debug, Subcommand)]
pub(super) enum BootManagerSubcommands {
    /// Set and clear the flags and set the category of a Boot####, Driver#### or SysPrep####,
    /// keeping its other bits and bytes, and the Key#### of a Boot#### following it
    #[command(next_display_order = None)]
    SetAttributes(SetAttributesArgs),
    /// Create a Boot####, Driver#### or SysPrep#### that does not exist, from device paths as
    /// text or files of their bytes
    #[command(next_display_order = None)]
    CreateLoadOption(CreateLoadOptionArgs),
    /// Set ConIn, ConOut or ErrOut to a device path, as text or a file of its bytes, keeping
    /// its attributes
    #[command(next_display_order = None)]
    SetDevicePath(SetDevicePathArgs),
    /// Create a Key#### that does not exist: a hot key that starts a Boot####
    #[command(next_display_order = None)]
    CreateKey(CreateKeyArgs),
}

impl BootManagerSubcommands {
    pub(super) fn run(&self) -> Result<()> {
        match self {
            Self::SetAttributes(args) => args.run(),
            Self::CreateLoadOption(args) => args.run(),
            Self::SetDevicePath(args) => args.run(),
            Self::CreateKey(args) => args.run(),
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

/// The load option to create.
#[derive(Debug, Args)]
#[command(group(ArgGroup::new("device_paths").required(true).args(["device_path", "device_path_file"])))]
pub(super) struct CreateLoadOptionArgs {
    /// The load option, such as Boot0001, of vendor 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
    name: String,
    /// Its Description, UCS-2 text, which boot menus show
    #[arg(long)]
    description: String,
    /// A device path as variable get shows it, such as PciRoot(0x0)/Pci(0x1,0x0), once per device path, the first of which locates the image
    #[arg(long)]
    device_path: Vec<String>,
    /// A file of the bytes of a device path, an EFI_DEVICE_PATH_PROTOCOL ended by an End Entire Device Path node, written as they are, once per device path
    #[arg(long)]
    device_path_file: Vec<PathBuf>,
    /// A file of its OptionalData, the bytes that the boot manager passes to the image, written as they are; none if not given
    #[arg(long)]
    optional_data_file: Option<PathBuf>,
    /// Its flags, comma-separated, or none
    #[arg(long, value_enum, value_delimiter = ',', default_values_t = [NewFlagArg::Flag(FlagArg::Active)])]
    flags: Vec<NewFlagArg>,
    /// Its category: boot options boot, app ones the boot manager starts only when asked to
    #[arg(long, value_enum, default_value_t = CategoryArg::Boot)]
    category: CategoryArg,
}

impl CreateLoadOptionArgs {
    /// Creates the load option and prints it as get shows it, and each warning on stderr.
    fn run(&self) -> Result<()> {
        let optional_data = match &self.optional_data_file {
            Some(path) => platform::read_payload(path)?,
            None => Vec::new(),
        };
        let new = NewLoadOption {
            flags: self.flags()?,
            category: self.category.into(),
            description: self.description.clone(),
            device_paths: device_path_source(&self.device_path, &self.device_path_file)?,
            optional_data,
        };
        let created = VariableBackend::create_load_option(&self.name, &new)?;
        for warning in &created.warnings {
            eprintln!("warning: {warning}");
        }
        print_global_variable(&created.option)
    }

    /// The flags of --flags: none for no flag, alone.
    fn flags(&self) -> Result<Vec<LoadOptionFlag>> {
        match self.flags.as_slice() {
            [NewFlagArg::None] => Ok(Vec::new()),
            flags => flags
                .iter()
                .map(|flag| match flag {
                    NewFlagArg::None => bail!("--flags takes none alone, for no flag"),
                    NewFlagArg::Flag(flag) => Ok(LoadOptionFlag::from(*flag)),
                })
                .collect(),
        }
    }
}

/// The console variable and its device path.
#[derive(Debug, Args)]
#[command(group(ArgGroup::new("path").required(true).args(["device_path", "device_path_file"])))]
pub(super) struct SetDevicePathArgs {
    /// ConIn, ConOut or ErrOut
    name: String,
    /// The device path as variable get shows it, its instances separated by ","
    #[arg(long)]
    device_path: Option<String>,
    /// A file of its bytes, an EFI_DEVICE_PATH_PROTOCOL ended by an End Entire Device Path node, written as they are
    #[arg(long)]
    device_path_file: Option<PathBuf>,
}

impl SetDevicePathArgs {
    /// Writes the device path and prints the variable as get shows it, and each warning on
    /// stderr.
    fn run(&self) -> Result<()> {
        let path = device_path_source(
            self.device_path.as_slice(),
            self.device_path_file.as_slice(),
        )?;
        let set = VariableBackend::set_device_path(&self.name, &path)?;
        for warning in &set.warnings {
            eprintln!("warning: {warning}");
        }
        print_global_variable(&set.console)
    }
}

/// The hot key to create.
#[derive(Debug, Args)]
pub(super) struct CreateKeyArgs {
    /// The hot key, such as Key0001, of vendor 8BE4DF61-93CA-11D2-AA0D-00E098032B8C
    name: String,
    /// The Boot#### that it starts, such as Boot0001
    #[arg(long)]
    boot: String,
    /// The shift states that must be pressed with the keys, comma-separated; the others must not be
    #[arg(long, value_enum, value_delimiter = ',')]
    modifiers: Vec<ModifierArg>,
    /// A key, by the name after SCAN_ of its scan code, such as F2, ESC or PAGE_UP, a character, or ScanCode=0x####,UnicodeChar=0x#### as variable get shows other keys, once per key, in order, at most 3
    #[arg(long)]
    key: Vec<InputKey>,
}

impl CreateKeyArgs {
    /// Creates the hot key and prints it as get shows it, and each warning on stderr.
    fn run(&self) -> Result<()> {
        let new = NewHotKey {
            boot_option: self.boot.clone(),
            modifiers: self
                .modifiers
                .iter()
                .copied()
                .map(KeyModifier::from)
                .collect(),
            keys: self.key.clone(),
        };
        let created = VariableBackend::create_key(&self.name, &new)?;
        for warning in &created.warnings {
            eprintln!("warning: {warning}");
        }
        print_global_variable(&created.key)
    }
}

/// The device paths of `texts`, else of the files `files`, which the argument groups keep
/// apart.
fn device_path_source(texts: &[String], files: &[PathBuf]) -> Result<DevicePathSource> {
    match files.is_empty() {
        true => Ok(DevicePathSource::Texts(texts.to_vec())),
        false => Ok(DevicePathSource::Bytes(
            files
                .iter()
                .map(PathBuf::as_path)
                .map(platform::read_payload)
                .collect::<Result<_>>()?,
        )),
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

/// A shift state of EFI_BOOT_KEY_DATA (UEFI 2.11 §3.1.6), these names and Pressed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum ModifierArg {
    Shift,
    Control,
    Alt,
    Logo,
    Menu,
    SysReq,
}

impl From<ModifierArg> for KeyModifier {
    fn from(modifier: ModifierArg) -> Self {
        match modifier {
            ModifierArg::Shift => Self::Shift,
            ModifierArg::Control => Self::Control,
            ModifierArg::Alt => Self::Alt,
            ModifierArg::Logo => Self::Logo,
            ModifierArg::Menu => Self::Menu,
            ModifierArg::SysReq => Self::SysReq,
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

/// A flag of create-load-option: a FlagArg, or none, for Attributes of the category alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NewFlagArg {
    None,
    Flag(FlagArg),
}

impl ValueEnum for NewFlagArg {
    fn value_variants<'a>() -> &'a [Self] {
        &[
            Self::None,
            Self::Flag(FlagArg::Active),
            Self::Flag(FlagArg::ForceReconnect),
            Self::Flag(FlagArg::Hidden),
        ]
    }

    fn to_possible_value(&self) -> Option<PossibleValue> {
        match self {
            Self::None => Some(PossibleValue::new("none")),
            Self::Flag(flag) => flag.to_possible_value(),
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
        assert_eq!(
            NewFlagArg::value_variants(),
            [
                &[NewFlagArg::None][..],
                &FlagArg::value_variants()
                    .iter()
                    .copied()
                    .map(NewFlagArg::Flag)
                    .collect::<Vec<_>>(),
            ]
            .concat(),
            "create-load-option's flags: none, then each flag"
        );
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

    /// create-load-option takes the load option, a Description, device paths as text or files,
    /// not both, at least one, OptionalData from a file if any, and flags, or none alone, and a
    /// category, active and boot if not given.
    #[test]
    fn create_load_option_takes_device_paths_as_text_or_files() {
        let parse =
            |args: &[&str]| match boot_manager(&[&["create-load-option"][..], args].concat()) {
                Ok(BootManagerSubcommands::CreateLoadOption(parsed)) => Ok(parsed),
                Ok(other) => panic!("{args:?} is no create-load-option: {other:?}"),
                Err(kind) => Err(kind),
            };

        let texts = parse(&[
            "Boot0001",
            "--description",
            "Shell",
            "--device-path",
            "Pci(0x1,0x0)",
            "--device-path",
            "Pci(0x2,0x0)",
        ])
        .expect("parse texts");
        let files = parse(&[
            "Boot0001",
            "--description",
            "Shell",
            "--device-path-file",
            "a.bin",
            "--optional-data-file",
            "o.bin",
            "--flags",
            "hidden,force-reconnect",
            "--category",
            "app",
        ])
        .expect("parse files");

        assert_eq!(
            (
                texts.device_path.as_slice(),
                texts.device_path_file.as_slice(),
                texts.optional_data_file.as_deref(),
                texts.flags().expect("the default flags"),
                texts.category,
            ),
            (
                &["Pci(0x1,0x0)".to_owned(), "Pci(0x2,0x0)".to_owned()][..],
                &[][..],
                None,
                vec![LoadOptionFlag::Active],
                CategoryArg::Boot,
            ),
            "texts, the default flags and category"
        );
        assert_eq!(
            (
                files.device_path.as_slice(),
                files.device_path_file.as_slice(),
                files.optional_data_file.as_deref(),
                files.flags().expect("hidden,force-reconnect"),
                files.category,
            ),
            (
                &[][..],
                &[PathBuf::from("a.bin")][..],
                Some(std::path::Path::new("o.bin")),
                vec![LoadOptionFlag::Hidden, LoadOptionFlag::ForceReconnect],
                CategoryArg::App,
            ),
            "files"
        );

        // no flag: Attributes of the category alone, such as 0x100 of an app
        let app = |flags: &str| {
            parse(&[
                "Boot0001",
                "--description",
                "Shell",
                "--device-path",
                "Pci(0x1,0x0)",
                "--flags",
                flags,
                "--category",
                "app",
            ])
            .unwrap_or_else(|kind| panic!("parse --flags {flags}: {kind}"))
        };
        let none = app("none");
        assert_eq!(
            (none.flags().expect("--flags none"), none.category),
            (vec![], CategoryArg::App),
            "--flags none"
        );
        for flags in ["none,active", "hidden,none", "none,none"] {
            assert_eq!(
                app(flags).flags().map_err(|error| error.to_string()),
                Err("--flags takes none alone, for no flag".to_owned()),
                "--flags {flags}"
            );
        }
        for (args, want) in [
            (
                &["Boot0001", "--description", "Shell"][..],
                ErrorKind::MissingRequiredArgument,
            ),
            (
                &["Boot0001", "--device-path", "Pci(0x1,0x0)"],
                ErrorKind::MissingRequiredArgument,
            ),
            (
                &[
                    "Boot0001",
                    "--description",
                    "Shell",
                    "--device-path",
                    "Pci(0x1,0x0)",
                    "--device-path-file",
                    "a.bin",
                ],
                ErrorKind::ArgumentConflict,
            ),
            (
                &[
                    "Boot0001",
                    "--description",
                    "Shell",
                    "--device-path",
                    "Pci(0x1,0x0)",
                    "--flags",
                    "app",
                ],
                ErrorKind::InvalidValue,
            ),
        ] {
            assert_eq!(parse(args).map(|_| ()), Err(want), "{args:?}");
        }
    }

    /// set-device-path takes the console variable and one device path, as text or a file.
    #[test]
    fn set_device_path_takes_one_device_path() {
        let parse = |args: &[&str]| match boot_manager(&[&["set-device-path"][..], args].concat()) {
            Ok(BootManagerSubcommands::SetDevicePath(parsed)) => Ok(parsed),
            Ok(other) => panic!("{args:?} is no set-device-path: {other:?}"),
            Err(kind) => Err(kind),
        };

        let text = parse(&["ConOut", "--device-path", "Pci(0x1,0x0)"]).expect("parse a text");
        let file = parse(&["ConOut", "--device-path-file", "a.bin"]).expect("parse a file");

        assert_eq!(
            (
                text.name.as_str(),
                text.device_path.as_deref(),
                text.device_path_file
            ),
            ("ConOut", Some("Pci(0x1,0x0)"), None),
            "text"
        );
        assert_eq!(
            (file.device_path, file.device_path_file),
            (None, Some(PathBuf::from("a.bin"))),
            "file"
        );
        for (args, want) in [
            (&["ConOut"][..], ErrorKind::MissingRequiredArgument),
            (
                &[
                    "ConOut",
                    "--device-path",
                    "Pci(0x1,0x0)",
                    "--device-path-file",
                    "a.bin",
                ],
                ErrorKind::ArgumentConflict,
            ),
            (
                &[
                    "ConOut",
                    "--device-path",
                    "Pci(0x1,0x0)",
                    "--device-path",
                    "Pci(0x2,0x0)",
                ],
                ErrorKind::ArgumentConflict,
            ),
        ] {
            assert_eq!(parse(args).map(|_| ()), Err(want), "{args:?}");
        }
    }

    /// create-key takes the hot key, the Boot#### that it starts, shift states, comma-separated,
    /// and keys, by scan code name, character or codes, in order; other names are refused.
    #[test]
    fn create_key_takes_shift_states_and_keys() {
        let parse = |args: &[&str]| match boot_manager(&[&["create-key"][..], args].concat()) {
            Ok(BootManagerSubcommands::CreateKey(parsed)) => Ok(parsed),
            Ok(other) => panic!("{args:?} is no create-key: {other:?}"),
            Err(kind) => Err(kind),
        };

        let parsed = parse(&[
            "Key0001",
            "--boot",
            "Boot0001",
            "--modifiers",
            "control,sys-req",
            "--key",
            "F2",
            "--key",
            "q",
            "--key",
            "ScanCode=0x0099,UnicodeChar=0x0000",
        ])
        .expect("parse create-key");

        assert_eq!(
            (
                parsed.name.as_str(),
                parsed.boot.as_str(),
                parsed.modifiers.as_slice(),
                parsed
                    .key
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
            ),
            (
                "Key0001",
                "Boot0001",
                &[ModifierArg::Control, ModifierArg::SysReq][..],
                vec![
                    "F2".to_owned(),
                    "q".to_owned(),
                    "ScanCode=0x0099,UnicodeChar=0x0000".to_owned(),
                ],
            ),
            "create-key"
        );
        for (args, want) in [
            (
                &["Key0001", "--key", "F2"][..],
                ErrorKind::MissingRequiredArgument,
            ),
            (
                &["Key0001", "--boot", "Boot0001", "--key", "f2"],
                ErrorKind::ValueValidation,
            ),
            (
                &["Key0001", "--boot", "Boot0001", "--modifiers", "ctrl"],
                ErrorKind::InvalidValue,
            ),
        ] {
            assert_eq!(parse(args).map(|_| ()), Err(want), "{args:?}");
        }
    }

    /// The shift states that create-key takes are those that variable get prints.
    #[test]
    fn modifier_names_are_those_that_get_prints() {
        for modifier in ModifierArg::value_variants() {
            let name = modifier
                .to_possible_value()
                .expect("a possible value")
                .get_name()
                .to_owned();

            assert_eq!(name, KeyModifier::from(*modifier).name(), "{modifier:?}");
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
