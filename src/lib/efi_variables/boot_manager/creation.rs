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

//! variable create-load-option: a new Boot####, Driver#### or SysPrep#### (UEFI 2.11 §3.1.3).

use anyhow::Context;
use anyhow::Result;
use thiserror::Error;

use super::boot_option_support;
use super::load_option_data;
use super::written_option;
use super::DevicePathSource;
use super::LoadOptionCategory;
use super::LoadOptionFlag;
use super::BOOT_MANAGER_ATTRIBUTES;
use crate::efi_variables::globals::BootOptionFlags;
use crate::efi_variables::globals::GlobalContents;
use crate::efi_variables::globals::GlobalValue;
use crate::efi_variables::globals::GlobalVariable;
use crate::efi_variables::globals::LoadOptionKind;
use crate::efi_variables::globals::LoadOptionName;
use crate::efi_variables::load_option::LoadOption;
use crate::efi_variables::load_option::LoadOptionAttributes;
use crate::efi_variables::load_option::Ucs2String;
use crate::efi_variables::VariableContents;
use crate::efi_variables::VariableData;

/// The subcommand, which the refusals name
const CREATE_LOAD_OPTION: &str = "create-load-option";

/// A load option to create: its flags and category, its Description, its device paths, the first
/// of which locates the image, and its OptionalData, the bytes that the boot manager passes to
/// the image.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NewLoadOption {
    pub flags: Vec<LoadOptionFlag>,
    pub category: LoadOptionCategory,
    pub description: String,
    pub device_paths: DevicePathSource,
    pub optional_data: Vec<u8>,
}

impl NewLoadOption {
    /// Its EFI_LOAD_OPTION: "When creating a new load option, all undefined attribute bits must
    /// be written as zero" (UEFI 2.11 §3.1.3), so its Attributes hold its flags and category
    /// only.
    fn load_option(&self) -> Result<LoadOption> {
        let attributes = self
            .flags
            .iter()
            .map(|flag| flag.attribute())
            .fold(self.category.attributes(), LoadOptionAttributes::union);
        let description = Ucs2String::try_from(self.description.as_str())
            .context("--description takes UCS-2 text without Null")?;
        Ok(LoadOption {
            attributes,
            description,
            file_paths: self.device_paths.file_path_list()?,
            optional_data: self.optional_data.clone(),
        })
    }
}

/// What variable create-load-option wrote: the load option, as variable get shows it, and why
/// the boot manager may not take it.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadOptionCreated {
    pub option: GlobalVariable,
    pub warnings: Vec<String>,
}

/// Creates the load option `name`, a Boot####, Driver#### or SysPrep#### of EFI_GLOBAL_VARIABLE,
/// with NV+BS+RT, as `new` says; refuses, before any write, another variable, an existing one, a
/// Description other than UCS-2 and device paths that do not read or decode. It warns, and
/// writes still, when BootOptionSupport lacks EFI_BOOT_OPTION_SUPPORT_SYSPREP for a SysPrep####
/// or EFI_BOOT_OPTION_SUPPORT_APP for an app Boot#### (UEFI 2.11 §3.1.4); LOAD_OPTION_CATEGORY "is
/// ignored for variables of the form Driver####, SysPrep####, or OsRecovery####" (§3.1.3).
pub(crate) fn create_load_option(
    variables: &impl VariableData,
    name: &str,
    new: &NewLoadOption,
) -> Result<LoadOptionCreated> {
    let option = written_option(name, CREATE_LOAD_OPTION)?;
    let load_option = new.load_option()?;
    let key = option.key();
    if variables.variable_data(&key)?.is_some() {
        return Err(CreationRefusal::Exists(option).into());
    }
    let support = boot_option_support(variables)?.flags;
    let warnings = [
        (
            option.kind == LoadOptionKind::SysPrep,
            BootOptionFlags::SYSPREP,
            "SysPrep#### load options",
        ),
        (
            option.kind == LoadOptionKind::Boot && new.category == LoadOptionCategory::App,
            BootOptionFlags::APP,
            "load options of LOAD_OPTION_CATEGORY_APP",
        ),
    ]
    .into_iter()
    .filter(|(wanted, flag, _)| *wanted && !support.contains(*flag))
    .map(|(_, flag, what)| unsupported(option, flag, what))
    .collect();

    let bytes = load_option.encode();
    let value = load_option_data(&bytes).with_context(|| format!("EFI variable {key}"))?;
    let contents = VariableContents::new(BOOT_MANAGER_ATTRIBUTES, bytes)
        .with_context(|| format!("EFI variable {key}"))?;
    variables.set_variable(&key, &contents)?;
    Ok(LoadOptionCreated {
        option: GlobalVariable {
            variable: key.to_string(),
            contents: Some(GlobalContents {
                attributes: BOOT_MANAGER_ATTRIBUTES.bits(),
                value: GlobalValue::LoadOptionData(value),
            }),
        },
        warnings,
    })
}

/// The warning that BootOptionSupport lacks `flag`, without which the boot manager supports no
/// `what`.
fn unsupported(option: LoadOptionName, flag: BootOptionFlags, what: &str) -> String {
    let flag = flag.iter_names().map(|(name, _)| name).collect::<String>();
    format!(
        "BootOptionSupport lacks EFI_BOOT_OPTION_SUPPORT_{flag}: the boot manager may ignore \
         {option}, as it supports no {what} (UEFI 2.11 section 3.1.4)"
    )
}

/// What create-load-option refuses before any write, but the names of written_option.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
enum CreationRefusal {
    #[error(
        "{0} exists: create-load-option creates load options; set-attributes changes the \
         Attributes of one, and variable set BootOrder its place in BootOrder"
    )]
    Exists(LoadOptionName),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::efi_variables::boot_manager::read;
    use crate::efi_variables::boot_manager::BootManagerVariable;
    use crate::efi_variables::device_path::tests::bytes;
    use crate::efi_variables::device_path::tests::X64_BOOT0000;
    use crate::efi_variables::device_path::tests::X64_BOOT0001;
    use crate::efi_variables::device_path::tests::X64_BOOT0002;
    use crate::efi_variables::globals::tests::key;
    use crate::efi_variables::globals::tests::HeldVariables;
    use crate::efi_variables::globals::EFI_GLOBAL_VARIABLE;
    use crate::efi_variables::load_option::LoadOption;
    use crate::hii::VariableKey;

    /// The text of the device path of OVMF's x86_64 Boot0002, its UEFI Shell.
    const SHELL: &str =
        "Fv(7CB8BDC9-F8EB-4F34-AAEA-3EE4AF6516A1)/FvFile(7C04A583-9E3E-4F1C-AD65-E05268D0B4D1)";

    /// A load option of `flags`, category `category` and `description`, of the device paths of
    /// `texts` and no OptionalData.
    fn new(
        flags: &[LoadOptionFlag],
        category: LoadOptionCategory,
        description: &str,
        texts: &[&str],
    ) -> NewLoadOption {
        NewLoadOption {
            flags: flags.to_vec(),
            category,
            description: description.to_owned(),
            device_paths: DevicePathSource::Texts(
                texts.iter().map(|text| text.to_string()).collect(),
            ),
            optional_data: Vec::new(),
        }
    }

    fn held(variables: &HeldVariables) -> BTreeMap<VariableKey, VariableContents> {
        variables.variables.borrow().clone()
    }

    /// The load options that OVMF's boot manager wrote, created again from what variable get
    /// shows of them, are the same bytes: Attributes of the flags and category only, the
    /// Description, the FilePathList from text or from bytes, and OptionalData as given.
    #[test]
    fn create_load_option_writes_new_options_byte_for_byte() {
        let boot0001 = LoadOption::decode(&bytes(X64_BOOT0001)).expect("OVMF's Boot0001");
        let cases = [
            (
                "Boot0000",
                new(
                    &[LoadOptionFlag::Active, LoadOptionFlag::Hidden],
                    LoadOptionCategory::App,
                    "UiApp",
                    &["Fv(7CB8BDC9-F8EB-4F34-AAEA-3EE4AF6516A1)/FvFile(462CAA21-7614-4503-836E-8AB6F4662331)"],
                ),
                X64_BOOT0000,
            ),
            (
                "Boot0001",
                NewLoadOption {
                    optional_data: boot0001.optional_data.clone(),
                    ..new(
                        &[LoadOptionFlag::Active],
                        LoadOptionCategory::Boot,
                        "UEFI Misc Device",
                        &["PciRoot(0x0)/Pci(0x1,0x0)"],
                    )
                },
                X64_BOOT0001,
            ),
            (
                "Driver0001",
                NewLoadOption {
                    optional_data: boot0001.optional_data.clone(),
                    device_paths: DevicePathSource::Bytes(vec![boot0001.file_paths.as_ref().to_vec()]),
                    ..new(&[LoadOptionFlag::Active], LoadOptionCategory::Boot, "UEFI Misc Device", &[])
                },
                X64_BOOT0001,
            ),
            (
                "SysPrep0002",
                new(
                    &[LoadOptionFlag::Active],
                    LoadOptionCategory::Boot,
                    "EFI Internal Shell",
                    &[SHELL],
                ),
                X64_BOOT0002,
            ),
        ];
        for (name, new, want) in cases {
            let variables = HeldVariables::default().with(
                "BootOptionSupport",
                EFI_GLOBAL_VARIABLE,
                &0x313_u32.to_le_bytes(),
            );

            let created = create_load_option(&variables, name, &new)
                .unwrap_or_else(|error| panic!("create {name}: {error:#}"));

            let written = variables.variables.borrow()[&key(name, EFI_GLOBAL_VARIABLE)].clone();
            assert_eq!(written.data(), bytes(want), "{name}: bytes");
            assert_eq!(
                written.attributes(),
                BOOT_MANAGER_ATTRIBUTES,
                "{name}: NV+BS+RT"
            );
            assert_eq!(created.warnings, Vec::<String>::new(), "{name}: warnings");
            assert_eq!(
                Some(created.option),
                read(
                    &variables,
                    BootManagerVariable::parse(name).expect("a load option"),
                    None
                )
                .ok(),
                "{name}: what create-load-option prints is what get shows"
            );
        }

        // two device paths, packed in order
        let variables = HeldVariables::default();
        create_load_option(
            &variables,
            "Boot0003",
            &new(
                &[],
                LoadOptionCategory::Boot,
                "two",
                &[SHELL, "PciRoot(0x0)/Pci(0x1,0x0)"],
            ),
        )
        .expect("create Boot0003");
        let boot0003 = LoadOption::decode(
            variables.variables.borrow()[&key("Boot0003", EFI_GLOBAL_VARIABLE)].data(),
        )
        .expect("decode Boot0003");
        let shell = LoadOption::decode(&bytes(X64_BOOT0002)).expect("OVMF's Boot0002");
        assert_eq!(
            boot0003.file_paths.as_ref(),
            [shell.file_paths.as_ref(), boot0001.file_paths.as_ref()].concat(),
            "Boot0003: FilePathList"
        );
        assert_eq!(boot0003.attributes.bits(), 0, "Boot0003: no flag");

        // an app of no flag: Attributes 0x100, else OVMF's Boot0000
        let variables = HeldVariables::default();
        create_load_option(
            &variables,
            "Boot0000",
            &new(
                &[],
                LoadOptionCategory::App,
                "UiApp",
                &["Fv(7CB8BDC9-F8EB-4F34-AAEA-3EE4AF6516A1)/FvFile(462CAA21-7614-4503-836E-8AB6F4662331)"],
            ),
        )
        .expect("create Boot0000");
        let want = [&0x100_u32.to_le_bytes()[..], &bytes(X64_BOOT0000)[4..]].concat();
        assert_eq!(
            variables.variables.borrow()[&key("Boot0000", EFI_GLOBAL_VARIABLE)].data(),
            want,
            "Boot0000: an app of no flag"
        );
    }

    /// An existing load option, a Description other than UCS-2 text without Null, device paths
    /// that do not read or decode, and a name of no Boot####, Driver#### or SysPrep#### are
    /// refused before any write.
    #[test]
    fn create_load_option_refuses_existing_options_and_bad_input_unwritten() {
        let variables = HeldVariables::default()
            .with("Boot0001", EFI_GLOBAL_VARIABLE, &bytes(X64_BOOT0001))
            .with("SysPrep0001", EFI_GLOBAL_VARIABLE, &bytes(X64_BOOT0001));
        let before = held(&variables);
        let shell = new(
            &[LoadOptionFlag::Active],
            LoadOptionCategory::Boot,
            "Shell",
            &[SHELL],
        );
        let path = LoadOption::decode(&bytes(X64_BOOT0002))
            .expect("OVMF's Boot0002")
            .file_paths;
        let cases = [
            (
                "Boot0001",
                shell.clone(),
                "Boot0001 exists: create-load-option creates load options; set-attributes changes \
                 the Attributes of one, and variable set BootOrder its place in BootOrder",
            ),
            (
                "SysPrep0001",
                shell.clone(),
                "SysPrep0001 exists: create-load-option creates load options; set-attributes \
                 changes the Attributes of one, and variable set BootOrder its place in BootOrder",
            ),
            (
                "Boot0002",
                NewLoadOption {
                    description: "Shell \u{1F41A}".to_owned(),
                    ..shell.clone()
                },
                "--description takes UCS-2 text without Null: ",
            ),
            (
                "Boot0002",
                NewLoadOption {
                    description: "Sh\0ell".to_owned(),
                    ..shell.clone()
                },
                "--description takes UCS-2 text without Null: ",
            ),
            (
                "Boot0002",
                new(
                    &[],
                    LoadOptionCategory::Boot,
                    "Shell",
                    &["Fv(7CB8BDC9-F8EB-4F34-AAEA-3EE4AF6516A1"],
                ),
                "--device-path \"Fv(7CB8BDC9-F8EB-4F34-AAEA-3EE4AF6516A1\": ",
            ),
            (
                "Boot0002",
                new(&[], LoadOptionCategory::Boot, "Shell", &["Shell(1)"]),
                "--device-path \"Shell(1)\": ",
            ),
            (
                "Boot0002",
                NewLoadOption {
                    device_paths: DevicePathSource::Bytes(vec![path.as_ref()
                        [..path.as_ref().len() - 4]
                        .to_vec()]),
                    ..shell.clone()
                },
                "--device-path-file #1: ",
            ),
            (
                "Boot0002",
                NewLoadOption {
                    device_paths: DevicePathSource::Bytes(vec![
                        path.as_ref().to_vec(),
                        vec![0x7F, 0xFF, 0x03, 0x00],
                    ]),
                    ..shell.clone()
                },
                "--device-path-file #2: ",
            ),
            (
                "PlatformRecovery0000",
                shell.clone(),
                "create-load-option does not write PlatformRecovery0000: ",
            ),
            (
                "OsRecovery0000",
                shell.clone(),
                "create-load-option does not write OsRecovery0000, a Secure Boot Policy Variable: ",
            ),
            (
                "Key0001",
                shell.clone(),
                "create-load-option takes a Boot####, Driver#### or SysPrep####, not Key0001",
            ),
        ];
        for (name, new, want) in cases {
            let error = create_load_option(&variables, name, &new).expect_err("create refused");

            assert!(format!("{error:#}").starts_with(want), "{name}: {error:#}");
        }
        assert_eq!(held(&variables), before, "the variables");
        assert_eq!(variables.set.into_inner(), [], "keys set");
    }

    /// A SysPrep#### while BootOptionSupport lacks EFI_BOOT_OPTION_SUPPORT_SYSPREP, and an app
    /// Boot#### while it lacks EFI_BOOT_OPTION_SUPPORT_APP, each get a warning, and are written
    /// all the same; an absent BootOptionSupport supports neither. A Driver#### or SysPrep####
    /// gets none for its category, which the boot manager ignores.
    #[test]
    fn create_load_option_warns_of_what_boot_option_support_lacks() {
        let sysprep = "BootOptionSupport lacks EFI_BOOT_OPTION_SUPPORT_SYSPREP: the boot manager \
                       may ignore SysPrep0001, as it supports no SysPrep#### load options (UEFI \
                       2.11 section 3.1.4)";
        let app = |option: &str| {
            format!(
                "BootOptionSupport lacks EFI_BOOT_OPTION_SUPPORT_APP: the boot manager may \
                 ignore {option}, as it supports no load options of LOAD_OPTION_CATEGORY_APP \
                 (UEFI 2.11 section 3.1.4)"
            )
        };
        let cases: [(Option<u32>, &str, LoadOptionCategory, Vec<String>); 7] = [
            (
                None,
                "SysPrep0001",
                LoadOptionCategory::Boot,
                vec![sysprep.to_owned()],
            ),
            (None, "Boot0001", LoadOptionCategory::Boot, vec![]),
            (
                None,
                "Boot0001",
                LoadOptionCategory::App,
                vec![app("Boot0001")],
            ),
            (
                Some(0x301),
                "SysPrep0001",
                LoadOptionCategory::App,
                vec![sysprep.to_owned()],
            ),
            (Some(0x012), "SysPrep0001", LoadOptionCategory::App, vec![]),
            (Some(0x010), "Driver0001", LoadOptionCategory::App, vec![]),
            (
                Some(0x010),
                "Boot0001",
                LoadOptionCategory::App,
                vec![app("Boot0001")],
            ),
        ];
        for (support, name, category, want) in cases {
            let variables = match support {
                Some(support) => HeldVariables::default().with(
                    "BootOptionSupport",
                    EFI_GLOBAL_VARIABLE,
                    &support.to_le_bytes(),
                ),
                None => HeldVariables::default(),
            };

            let created =
                create_load_option(&variables, name, &new(&[], category, "Shell", &[SHELL]))
                    .unwrap_or_else(|error| panic!("create {name}: {error:#}"));

            assert_eq!(created.warnings, want, "{support:?} {name} {category:?}");
            assert_eq!(
                variables.set.into_inner(),
                [key(name, EFI_GLOBAL_VARIABLE)],
                "{support:?} {name} {category:?}: keys set"
            );
        }
    }
}
