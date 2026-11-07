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

//! variable set-device-path: the device path of ConIn, ConOut or ErrOut (UEFI 2.11 §3.3).

use anyhow::Context;
use anyhow::Result;
use thiserror::Error;

use super::console_path;
use super::refuse_authenticated;
use super::value_after_metadata;
use super::BootManagerVariable;
use super::Console;
use super::DevicePathSource;
use super::DevicePathText;
use super::BOOT_MANAGER_ATTRIBUTES;
use crate::efi_variables::device_path;
use crate::efi_variables::globals::GlobalContents;
use crate::efi_variables::globals::GlobalValue;
use crate::efi_variables::globals::GlobalVariable;
use crate::efi_variables::globals::EFI_GLOBAL_VARIABLE;
use crate::efi_variables::VariableContents;
use crate::efi_variables::VariableData;
use crate::hii::VariableKey;

/// What variable set-device-path wrote: the console variable, as variable get shows it, and why
/// the boot manager may not take it.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevicePathSet {
    pub console: GlobalVariable,
    pub warnings: Vec<String>,
}

/// Sets the console variable `name`, ConIn, ConOut or ErrOut, to the one device path of `path`,
/// keeping its attributes, or with NV+BS+RT if it is missing; refuses, before any write, ConInDev,
/// ConOutDev and ErrOutDev, which the firmware sets, any other variable, one that
/// refuse_authenticated refuses, and a path that does not read or decode, or that holds more than
/// one device path. It warns, and writes still, for each
/// instance of the path that the matching *Dev variable lacks: ConIn, ConOut and ErrOut "are
/// always proper subsets" of those (UEFI 2.11 §3.3); but for an instance of a USB Class or USB
/// WWID node, which the firmware matches to the devices of that class or WWID.
pub(crate) fn set_device_path(
    variables: &impl VariableData,
    name: &str,
    path: &DevicePathSource,
) -> Result<DevicePathSet> {
    let (console, devices) = match BootManagerVariable::parse(name) {
        Some(BootManagerVariable::Console(console @ Console::ConIn)) => {
            (console, Console::ConInDev)
        }
        Some(BootManagerVariable::Console(console @ Console::ConOut)) => {
            (console, Console::ConOutDev)
        }
        Some(BootManagerVariable::Console(console @ Console::ErrOut)) => {
            (console, Console::ErrOutDev)
        }
        Some(BootManagerVariable::Console(
            console @ (Console::ConInDev | Console::ConOutDev | Console::ErrOutDev),
        )) => return Err(ConsoleRefusal::Volatile(console.name()).into()),
        Some(BootManagerVariable::LoadOption(_) | BootManagerVariable::HotKey(_)) | None => {
            return Err(ConsoleRefusal::NotConsole(name.to_owned()).into());
        }
    };
    let bytes = path.file_path_list()?.as_ref().to_vec();
    let value = console_path(&bytes)?;
    let key = console_key(console);
    let attributes = variables
        .variable_data(&key)?
        .map_or(BOOT_MANAGER_ATTRIBUTES, |current| current.attributes());
    refuse_authenticated(&key, attributes)?;

    let devices_key = console_key(devices);
    let known = match variables.variable_data(&devices_key)? {
        Some(contents) => value_after_metadata(&contents)
            .map_err(anyhow::Error::from)
            .and_then(|value| device_path::instances(value).map_err(anyhow::Error::from))
            .with_context(|| format!("EFI variable {devices_key} is malformed"))?
            .into_iter()
            .map(<[u8]>::to_vec)
            .collect(),
        None => Vec::new(),
    };
    let mut warnings = Vec::new();
    for instance in device_path::instances(&bytes)? {
        if known.iter().any(|known| known == instance)
            || device_path::holds_usb_short_form(instance)?
        {
            continue;
        }
        warnings.push(format!(
            "{} lacks the instance {} that {} gets: ConIn, ConOut and ErrOut \"are always proper \
             subsets of ConInDev, ConOutDev, and ErrOutDev\" (UEFI 2.11 section 3.3), so the \
             firmware may not use it",
            devices.name(),
            DevicePathText::of(&device_path::ended(instance)),
            console.name()
        ));
    }

    let contents =
        VariableContents::new(attributes, bytes).with_context(|| format!("EFI variable {key}"))?;
    variables.set_variable(&key, &contents)?;
    Ok(DevicePathSet {
        console: GlobalVariable {
            variable: key.to_string(),
            contents: Some(GlobalContents {
                attributes: attributes.bits(),
                value: GlobalValue::DevicePath(value),
            }),
        },
        warnings,
    })
}

fn console_key(console: Console) -> VariableKey {
    VariableKey {
        name: console.name().to_owned(),
        guid: EFI_GLOBAL_VARIABLE,
    }
}

/// A variable that set-device-path refuses before any read. The messages spell "section", as
/// edk2's terminals but VT-UTF8 show '?' for '§'.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
enum ConsoleRefusal {
    #[error("set-device-path takes ConIn, ConOut or ErrOut, not {0}")]
    NotConsole(String),
    #[error(
        "set-device-path does not write {0}: \"These variables are volatile, and are set \
         dynamically on every boot.\" (UEFI 2.11 section 3.3)"
    )]
    Volatile(&'static str),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::efi_variables::boot_manager::AuthenticatedRefusal;
    use crate::efi_variables::device_path::tests::bytes;
    use crate::efi_variables::device_path::tests::node;
    use crate::efi_variables::device_path::tests::X64_CONIN;
    use crate::efi_variables::device_path::tests::X64_CONOUT;
    use crate::efi_variables::enhanced_authenticated::fixture::timestamp_metadata;
    use crate::efi_variables::globals::tests::key;
    use crate::efi_variables::globals::tests::HeldVariables;
    use crate::efi_variables::globals::tests::NV_BS_RT;
    use crate::hii::VariableAttributes;

    /// The text of OVMF's x86_64 ConOut: its two serial ports.
    fn con_out_text() -> String {
        let serial = |n: u8| {
            format!("PciRoot(0x0)/Pci(0x1F,0x0)/Serial(0x{n})/Uart(115200,8,N,1)/VenUtf8()")
        };
        format!("{},/{}", serial(0), serial(1))
    }

    fn held(variables: &HeldVariables) -> BTreeMap<VariableKey, VariableContents> {
        variables.variables.borrow().clone()
    }

    fn texts(texts: &[&str]) -> DevicePathSource {
        DevicePathSource::Texts(texts.iter().map(|text| text.to_string()).collect())
    }

    /// The warning that `devices` lacks the instance of text `instance` that `console` gets.
    fn lacks(devices: &str, instance: &str, console: &str) -> String {
        format!(
            "{devices} lacks the instance {instance} that {console} gets: ConIn, ConOut and ErrOut \
             \"are always proper subsets of ConInDev, ConOutDev, and ErrOutDev\" (UEFI 2.11 \
             section 3.3), so the firmware may not use it"
        )
    }

    /// ConOut set to its own text, or to its own bytes, stays the same bytes and keeps its
    /// attributes; a missing ErrOut is created with NV+BS+RT; each instance that the *Dev
    /// variable lacks gets a warning, and is written all the same.
    #[test]
    fn set_device_path_writes_one_device_path() {
        let con_out = bytes(X64_CONOUT);
        let bs_rt = VariableAttributes::BOOTSERVICE_ACCESS | VariableAttributes::RUNTIME_ACCESS;
        let variables = || {
            HeldVariables::default()
                .with("ConOut", EFI_GLOBAL_VARIABLE, &con_out)
                .with("ConOutDev", EFI_GLOBAL_VARIABLE, &con_out)
        };
        let serial0 = "PciRoot(0x0)/Pci(0x1F,0x0)/Serial(0x0)/Uart(115200,8,N,1)/VenUtf8()";
        let cases = [
            (
                "ConOut",
                texts(&[&con_out_text()]),
                BOOT_MANAGER_ATTRIBUTES,
                con_out.clone(),
                vec![],
            ),
            (
                "ConOut",
                DevicePathSource::Bytes(vec![con_out.clone()]),
                BOOT_MANAGER_ATTRIBUTES,
                con_out.clone(),
                vec![],
            ),
            (
                "ErrOut",
                texts(&[serial0]),
                BOOT_MANAGER_ATTRIBUTES,
                device_path::from_text(serial0).expect("a serial port"),
                vec![lacks("ErrOutDev", serial0, "ErrOut")],
            ),
            (
                "ConOut",
                texts(&[&format!("{serial0},/Pci(0x1,0x0)")]),
                BOOT_MANAGER_ATTRIBUTES,
                device_path::from_text(&format!("{serial0},/Pci(0x1,0x0)")).expect("two instances"),
                vec![lacks("ConOutDev", "Pci(0x1,0x0)", "ConOut")],
            ),
        ];
        for (name, path, attributes, want, warnings) in cases {
            let variables = variables();

            let set = set_device_path(&variables, name, &path)
                .unwrap_or_else(|error| panic!("set {name} to {path:?}: {error:#}"));

            let written = variables.variables.borrow()[&key(name, EFI_GLOBAL_VARIABLE)].clone();
            assert_eq!(
                (written.attributes(), written.data()),
                (attributes, want.as_slice()),
                "{name} {path:?}"
            );
            assert_eq!(set.warnings, warnings, "{name} {path:?}: warnings");
            assert_eq!(
                set.console.contents.map(|contents| contents.attributes),
                Some(attributes.bits()),
                "{name} {path:?}: what set-device-path prints"
            );
        }

        // an existing variable keeps its attributes
        let variables = HeldVariables::default();
        variables.variables.borrow_mut().insert(
            key("ConIn", EFI_GLOBAL_VARIABLE),
            VariableContents::new(bs_rt, con_out.clone()).expect("hold ConIn"),
        );
        set_device_path(&variables, "ConIn", &texts(&[serial0])).expect("set ConIn");
        assert_eq!(
            variables.variables.borrow()[&key("ConIn", EFI_GLOBAL_VARIABLE)].attributes(),
            bs_rt,
            "ConIn's attributes"
        );
    }

    /// OVMF's ConIn, with an instance of a USB WWID node after its parent's nodes, gets a warning
    /// for its serial port 1 only, which ConInDev lacks; not for its instances of a USB Class or
    /// USB WWID node, which the firmware matches to the devices of that class or WWID
    /// (edk2-stable202608 ConPlatform.c MatchUsbShortformDevicePath()).
    #[test]
    fn set_device_path_warns_of_no_usb_short_form() {
        let end_instance: &[u8] = &[0x7F, 0x01, 0x04, 0x00];
        let end_entire: &[u8] = &[0x7F, 0xFF, 0x04, 0x00];
        let con_in = bytes(X64_CONIN);
        // its PS/2 keyboard, serial ports 0 and 1, and USB Class instance
        let instances = device_path::instances(&con_in).expect("OVMF's ConIn");
        let con_in_dev = [instances[0], end_instance, instances[1], end_entire].concat();
        let controller =
            device_path::from_text("PciRoot(0x0)/Pci(0x1D,0x0)").expect("a USB controller");
        let serial: Vec<u16> = "4C530001".encode_utf16().collect();
        let wwid = node(
            0x03,
            0x10,
            &[
                &0_u16.to_le_bytes(),
                &0x0781_u16.to_le_bytes(),
                &0x5581_u16.to_le_bytes(),
                &serial
                    .iter()
                    .copied()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<_>>(),
            ],
        );
        let path = [
            &con_in[..con_in.len() - 4],
            end_instance,
            &controller[..controller.len() - 4],
            &wwid,
            end_entire,
        ]
        .concat();
        let variables = HeldVariables::default().with("ConInDev", EFI_GLOBAL_VARIABLE, &con_in_dev);

        let set = set_device_path(&variables, "ConIn", &DevicePathSource::Bytes(vec![path]))
            .expect("set ConIn");

        assert_eq!(
            set.warnings,
            [lacks(
                "ConInDev",
                "PciRoot(0x0)/Pci(0x1F,0x0)/Serial(0x1)/Uart(115200,8,N,1)/VenUtf8()",
                "ConIn"
            )],
            "warnings"
        );
        assert_eq!(
            variables.set.into_inner(),
            [key("ConIn", EFI_GLOBAL_VARIABLE)],
            "keys set"
        );
    }

    /// ConInDev, ConOutDev and ErrOutDev, which the firmware sets, any variable but ConIn,
    /// ConOut and ErrOut, a path that does not read or decode and bytes of two device paths are
    /// refused before any write.
    #[test]
    fn set_device_path_refuses_dev_variables_and_bad_paths_unwritten() {
        let variables = HeldVariables::default()
            .with("ConOut", EFI_GLOBAL_VARIABLE, &bytes(X64_CONOUT))
            .with("ConOutDev", EFI_GLOBAL_VARIABLE, &bytes(X64_CONOUT));
        let before = held(&variables);
        let con_out = bytes(X64_CONOUT);
        let cases = [
            (
                "ConOutDev",
                texts(&["Pci(0x1,0x0)"]),
                "set-device-path does not write ConOutDev: \"These variables are volatile, and \
                 are set dynamically on every boot.\" (UEFI 2.11 section 3.3)",
            ),
            (
                "ErrOutDev",
                texts(&["Pci(0x1,0x0)"]),
                "set-device-path does not write ErrOutDev: \"These variables are volatile, and \
                 are set dynamically on every boot.\" (UEFI 2.11 section 3.3)",
            ),
            (
                "Boot0001",
                texts(&["Pci(0x1,0x0)"]),
                "set-device-path takes ConIn, ConOut or ErrOut, not Boot0001",
            ),
            (
                "ConOut",
                texts(&["Pci(0x1,0x0"]),
                "--device-path \"Pci(0x1,0x0\": ",
            ),
            (
                "ConOut",
                texts(&["Pci(0x1,0x0),"]),
                "--device-path \"Pci(0x1,0x0),\": ",
            ),
            (
                "ConOut",
                DevicePathSource::Bytes(vec![con_out[..con_out.len() - 4].to_vec()]),
                "--device-path-file #1: ",
            ),
            (
                "ConOut",
                DevicePathSource::Bytes(vec![[&con_out[..], &con_out].concat()]),
                "2 device paths, not the one of a console variable",
            ),
        ];
        for (name, path, want) in cases {
            let error = set_device_path(&variables, name, &path).expect_err("set refused");

            assert!(
                format!("{error:#}").starts_with(want),
                "{name} {path:?}: {error:#}"
            );
        }
        assert_eq!(held(&variables), before, "the variables");
        assert_eq!(variables.set.into_inner(), [], "keys set");
    }

    /// The instances of a ConOutDev with EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS are those of
    /// its value after the metadata (UEFI 2.11 §8.2.1): ConOut's own give no warning, and only
    /// an instance that it lacks does.
    #[test]
    fn set_device_path_takes_the_instances_of_a_dev_variable_after_its_metadata() {
        let serial0 = "PciRoot(0x0)/Pci(0x1F,0x0)/Serial(0x0)/Uart(115200,8,N,1)/VenUtf8()";
        let cases = [
            (con_out_text(), vec![]),
            (
                format!("{serial0},/Pci(0x1,0x0)"),
                vec![lacks("ConOutDev", "Pci(0x1,0x0)", "ConOut")],
            ),
        ];
        for (text, warnings) in cases {
            let variables = HeldVariables::default().with_attributes(
                "ConOutDev",
                EFI_GLOBAL_VARIABLE,
                NV_BS_RT | VariableAttributes::ENHANCED_AUTHENTICATED_ACCESS,
                &[timestamp_metadata(), bytes(X64_CONOUT)].concat(),
            );

            let set = set_device_path(&variables, "ConOut", &texts(&[&text]))
                .unwrap_or_else(|error| panic!("set ConOut to {text}: {error:#}"));

            assert_eq!(set.warnings, warnings, "ConOut {text}: warnings");
        }
    }

    /// A ConOut with EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS or
    /// EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS is refused before any write: only a signed
    /// write sets it (UEFI 2.11 §8.2.3).
    #[test]
    fn set_device_path_refuses_an_authenticated_console_unwritten() {
        let con_out = bytes(X64_CONOUT);
        let cases = [
            (
                NV_BS_RT | VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
                con_out.clone(),
            ),
            (
                NV_BS_RT | VariableAttributes::ENHANCED_AUTHENTICATED_ACCESS,
                [timestamp_metadata(), con_out.clone()].concat(),
            ),
        ];
        for (attributes, data) in cases {
            let variables = HeldVariables::default().with_attributes(
                "ConOut",
                EFI_GLOBAL_VARIABLE,
                attributes,
                &data,
            );
            let before = held(&variables);

            let error = set_device_path(&variables, "ConOut", &texts(&[&con_out_text()]))
                .expect_err("set an authenticated ConOut");

            assert_eq!(
                error.downcast_ref(),
                Some(&AuthenticatedRefusal(key("ConOut", EFI_GLOBAL_VARIABLE))),
                "ConOut of {attributes:?}: {error:#}"
            );
            assert_eq!(held(&variables), before, "the variables, {attributes:?}");
            assert_eq!(variables.set.into_inner(), [], "keys set, {attributes:?}");
        }
    }
}
