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

//! variable create-key: a new Key####, a hot key that starts a Boot#### (UEFI 2.11 §3.1.6).

use anyhow::Context;
use anyhow::Result;
use thiserror::Error;

use super::boot_option_support;
use super::hot_key_variable;
use super::option_number;
use super::value_after_metadata;
use super::BootManagerVariable;
use super::HotKeyListing;
use super::KeyModifier;
use super::BOOT_MANAGER_ATTRIBUTES;
use crate::efi_variables::globals::BootOptionFlags;
use crate::efi_variables::globals::GlobalContents;
use crate::efi_variables::globals::GlobalValue;
use crate::efi_variables::globals::GlobalVariable;
use crate::efi_variables::globals::LoadOptionKind;
use crate::efi_variables::globals::LoadOptionName;
use crate::efi_variables::key_option::InputKey;
use crate::efi_variables::key_option::KeyModifiers;
use crate::efi_variables::key_option::KeyOption;
use crate::efi_variables::VariableContents;
use crate::efi_variables::VariableData;
use crate::hii::VariableKey;

/// A hot key to create: the Boot#### that it starts, such as Boot0001, and the keys that start it,
/// pressed with exactly the shift states `modifiers`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NewHotKey {
    pub boot_option: String,
    pub modifiers: Vec<KeyModifier>,
    pub keys: Vec<InputKey>,
}

/// What variable create-key wrote: the hot key, as variable get shows it, and what it could not
/// check.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HotKeyCreated {
    pub key: GlobalVariable,
    pub warnings: Vec<String>,
}

/// Creates the hot key `name`, a Key#### of EFI_GLOBAL_VARIABLE that does not exist, with
/// NV+BS+RT, as `new` says, its BootOptionCrc the CRC-32 of the Boot####'s value after any
/// EFI_VARIABLE_AUTHENTICATION_3 metadata (UEFI 2.11 §8.2.1). Refuses, before any write, another
/// variable, an existing one, a missing Boot####, one whose metadata metadata_end refuses, more
/// keys than InputKeyCount counts, a BootOptionSupport without EFI_BOOT_OPTION_SUPPORT_KEY or with
/// an EFI_BOOT_OPTION_SUPPORT_COUNT below the keys, an absent one supporting none (§3.1.4), and
/// the shift states and keys of a Key#### of `hot_keys` that the boot manager takes, which it
/// refuses too (edk2-stable202608 EfiBootManagerAddKeyOptionVariable(), BmHotkey.c). Where
/// `hot_keys` are unlisted, it warns that it could not check them.
pub(crate) fn create_key(
    variables: &impl VariableData,
    hot_keys: &HotKeyListing,
    name: &str,
    new: &NewHotKey,
) -> Result<HotKeyCreated> {
    let Some(BootManagerVariable::HotKey(number)) = BootManagerVariable::parse(name) else {
        return Err(HotKeyRefusal::NotHotKey(name.to_owned()).into());
    };
    let boot_option = option_number(&new.boot_option, LoadOptionKind::Boot.prefix())
        .map(|number| LoadOptionName {
            kind: LoadOptionKind::Boot,
            number,
        })
        .ok_or_else(|| HotKeyRefusal::NotBootOption(new.boot_option.clone()))?;
    let key = hot_key_variable(number);
    if variables.variable_data(&key)?.is_some() {
        return Err(HotKeyRefusal::Exists(name.to_owned()).into());
    }
    let boot = variables
        .variable_data(&boot_option.key())?
        .ok_or(HotKeyRefusal::Absent(boot_option))?;
    let load_option = value_after_metadata(&boot)
        .with_context(|| format!("EFI variable {} is malformed", boot_option.key()))?;
    let modifiers = new
        .modifiers
        .iter()
        .map(|modifier| modifier.modifiers())
        .fold(KeyModifiers::empty(), KeyModifiers::union);
    let option = KeyOption::new(modifiers, new.keys.clone(), boot_option.number, load_option)?;

    let support = boot_option_support(variables)?;
    if !support.flags.contains(BootOptionFlags::KEY) {
        return Err(HotKeyRefusal::Unsupported.into());
    }
    if usize::try_from(support.count).is_ok_and(|count| count < option.keys.len()) {
        return Err(HotKeyRefusal::TooManyKeys {
            count: support.count,
            keys: option.keys.len(),
        }
        .into());
    }
    let warnings = match hot_keys {
        HotKeyListing::Listed(numbers) => {
            if let Some(taken) = taken_by(variables, numbers, &option)? {
                return Err(HotKeyRefusal::Taken(taken).into());
            }
            Vec::new()
        }
        HotKeyListing::Unlisted => vec![format!(
            "EFI variables cannot be listed here, so create-key cannot tell whether a Key#### \
             that the boot manager takes holds the same shift states and keys as {name}, which \
             the boot manager would then ignore"
        )],
    };

    let contents = VariableContents::new(BOOT_MANAGER_ATTRIBUTES, option.encode())
        .with_context(|| format!("EFI variable {key}"))?;
    variables.set_variable(&key, &contents)?;
    Ok(HotKeyCreated {
        key: GlobalVariable {
            variable: key.to_string(),
            contents: Some(GlobalContents {
                attributes: BOOT_MANAGER_ATTRIBUTES.bits(),
                value: GlobalValue::HotKey(super::HotKey {
                    revision: option.revision(),
                    modifiers: option.modifiers().bits(),
                    keys: option.keys,
                    boot_option,
                    crc_matches: true,
                }),
            }),
        },
        warnings,
    })
}

/// The Key#### of `numbers` that `variables` hold, that the boot manager takes, as its Boot####
/// exists and BootOptionCrc is its CRC-32, and whose KeyData and keys are those of `option`.
fn taken_by(
    variables: &impl VariableData,
    numbers: &[u16],
    option: &KeyOption,
) -> Result<Option<VariableKey>> {
    for &number in numbers {
        let key = hot_key_variable(number);
        let Some(contents) = variables.variable_data(&key)? else {
            continue;
        };
        let Ok(value) = value_after_metadata(&contents) else {
            continue;
        };
        let Ok(held) = KeyOption::decode(value) else {
            continue;
        };
        if (held.key_data, &held.keys) != (option.key_data, &option.keys) {
            continue;
        }
        let boot = LoadOptionName {
            kind: LoadOptionKind::Boot,
            number: held.boot_option,
        };
        if variables
            .variable_data(&boot.key())?
            .is_some_and(|boot| value_after_metadata(&boot).is_ok_and(|value| held.matches(value)))
        {
            return Ok(Some(key));
        }
    }
    Ok(None)
}

/// What create-key refuses before any write. The messages spell "section", as edk2's terminals
/// but VT-UTF8 show '?' for '§'.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
enum HotKeyRefusal {
    #[error("create-key takes a Key####, not {0}")]
    NotHotKey(String),
    #[error("--boot takes a Boot####, not {0}")]
    NotBootOption(String),
    #[error("{0} exists: create-key creates hot keys")]
    Exists(String),
    #[error("{0} is absent")]
    Absent(LoadOptionName),
    #[error(
        "BootOptionSupport lacks EFI_BOOT_OPTION_SUPPORT_KEY, so the boot manager supports no hot \
         keys (UEFI 2.11 section 3.1.4)"
    )]
    Unsupported,
    #[error(
        "BootOptionSupport's EFI_BOOT_OPTION_SUPPORT_COUNT is {count}, so the boot manager \
         ignores a hot key of {keys} keys (UEFI 2.11 section 3.1.4)"
    )]
    TooManyKeys { count: u32, keys: usize },
    #[error(
        "{} holds these shift states and keys, and the boot manager takes it; it refuses another \
         of the same",
        .0.name
    )]
    Taken(VariableKey),
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::*;
    use crate::efi_variables::device_path::tests::bytes;
    use crate::efi_variables::device_path::tests::X64_BOOT0001;
    use crate::efi_variables::device_path::tests::X64_BOOT0002;
    use crate::efi_variables::enhanced_authenticated::fixture::timestamp_metadata;
    use crate::efi_variables::globals::tests::key;
    use crate::efi_variables::globals::tests::HeldVariables;
    use crate::efi_variables::globals::tests::NV_BS_RT;
    use crate::efi_variables::globals::EFI_GLOBAL_VARIABLE;
    use crate::efi_variables::key_option::boot_option_crc;
    use crate::hii::VariableAttributes;

    /// BootOptionSupport of EFI_BOOT_OPTION_SUPPORT_KEY and an EFI_BOOT_OPTION_SUPPORT_COUNT of
    /// 3, as OVMF's
    const KEY_COUNT_3: u32 = 0x0000_0301;

    fn input_key(text: &str) -> InputKey {
        text.parse().expect("a key")
    }

    fn new(boot_option: &str, modifiers: &[KeyModifier], keys: &[&str]) -> NewHotKey {
        NewHotKey {
            boot_option: boot_option.to_owned(),
            modifiers: modifiers.to_vec(),
            keys: keys.iter().map(|key| input_key(key)).collect(),
        }
    }

    /// Boot0001, Boot0002, and BootOptionSupport of `support`, if any.
    fn variables(support: Option<u32>) -> HeldVariables {
        let variables = HeldVariables::default()
            .with("Boot0001", EFI_GLOBAL_VARIABLE, &bytes(X64_BOOT0001))
            .with("Boot0002", EFI_GLOBAL_VARIABLE, &bytes(X64_BOOT0002));
        match support {
            Some(support) => variables.with(
                "BootOptionSupport",
                EFI_GLOBAL_VARIABLE,
                &support.to_le_bytes(),
            ),
            None => variables,
        }
    }

    fn held(variables: &HeldVariables) -> BTreeMap<VariableKey, VariableContents> {
        variables.variables.borrow().clone()
    }

    /// The EFI_KEY_OPTION of KeyData `key_data`, to Boot#### `boot_option` of BootOptionCrc
    /// `crc`, of `keys`.
    fn key_option(key_data: u32, crc: u32, boot_option: u16, keys: &[(u16, u16)]) -> Vec<u8> {
        let mut bytes = [
            &key_data.to_le_bytes()[..],
            &crc.to_le_bytes(),
            &boot_option.to_le_bytes(),
        ]
        .concat();
        for (scan_code, unicode_char) in keys {
            bytes.extend(scan_code.to_le_bytes());
            bytes.extend(unicode_char.to_le_bytes());
        }
        bytes
    }

    /// A new Key#### holds KeyData of its shift states and InputKeyCount, the CRC-32 of its
    /// Boot#### as held, the Boot####'s number and its keys, with NV+BS+RT; a stale Key#### of
    /// the same keys, which the boot manager ignores, does not stand in its way.
    #[test]
    fn create_key_writes_a_key_that_its_boot_option_starts() {
        let crc = boot_option_crc(&bytes(X64_BOOT0001));
        let variables = variables(Some(KEY_COUNT_3)).with(
            "Key0001",
            EFI_GLOBAL_VARIABLE,
            &key_option(0x4000_0200, crc ^ 1, 1, &[(0x000B, 0)]),
        );

        let created = create_key(
            &variables,
            &HotKeyListing::Listed(vec![1]),
            "Key000A",
            &new("Boot0001", &[KeyModifier::Control], &["F1"]),
        )
        .expect("create Key000A");
        let three = create_key(
            &variables,
            &HotKeyListing::Listed(vec![1, 0xA]),
            "Key000B",
            &new(
                "Boot0001",
                &[KeyModifier::Alt, KeyModifier::SysReq],
                &["p", "r", "ESC"],
            ),
        )
        .expect("create Key000B");

        let held = held(&variables);
        assert_eq!(
            (
                held[&key("Key000A", EFI_GLOBAL_VARIABLE)].attributes(),
                held[&key("Key000A", EFI_GLOBAL_VARIABLE)].data()
            ),
            (
                BOOT_MANAGER_ATTRIBUTES,
                key_option(0x4000_0200, crc, 1, &[(0x000B, 0)]).as_slice()
            ),
            "Key000A"
        );
        assert_eq!(
            held[&key("Key000B", EFI_GLOBAL_VARIABLE)].data(),
            key_option(0xC000_2400, crc, 1, &[(0, 0x70), (0, 0x72), (0x0017, 0)]),
            "Key000B"
        );
        assert_eq!(
            serde_json::to_value(&created.key).expect("serialize"),
            json!({
                "variable": "Key000A-8be4df61-93ca-11d2-aa0d-00e098032b8c",
                "attributes": 7,
                "value": {
                    "revision": 0,
                    "modifiers": ["control"],
                    "keys": ["F1"],
                    "boot_option": "Boot0001",
                    "crc_matches": true,
                },
            }),
            "what create-key prints"
        );
        assert_eq!(
            (created.warnings, three.warnings),
            (Vec::new(), Vec::new()),
            "warnings"
        );
    }

    /// An existing Key####, a missing Boot####, a --boot of no Boot####, a name of no Key####, a
    /// BootOptionSupport without EFI_BOOT_OPTION_SUPPORT_KEY, absent too, or with an
    /// EFI_BOOT_OPTION_SUPPORT_COUNT below the keys, 4 keys, and the shift states and keys of a
    /// Key#### that the boot manager takes, of any Boot####, are refused before any write.
    #[test]
    fn create_key_refuses_unwritten() {
        let f1 = new("Boot0001", &[KeyModifier::Control], &["F1"]);
        let two = new("Boot0001", &[], &["a", "b"]);
        let taken = key_option(
            0x4000_0200,
            boot_option_crc(&bytes(X64_BOOT0002)),
            2,
            &[(0x000B, 0)],
        );
        let cases = [
            (
                Some(KEY_COUNT_3),
                "Key0003",
                f1.clone(),
                "Key0003 exists: create-key creates hot keys",
            ),
            (
                Some(KEY_COUNT_3),
                "Key0004",
                new("Boot1234", &[], &["F1"]),
                "Boot1234 is absent",
            ),
            (
                Some(KEY_COUNT_3),
                "Key0004",
                new("Driver0001", &[], &["F1"]),
                "--boot takes a Boot####, not Driver0001",
            ),
            (
                Some(KEY_COUNT_3),
                "Boot0004",
                f1.clone(),
                "create-key takes a Key####, not Boot0004",
            ),
            (
                None,
                "Key0004",
                f1.clone(),
                "BootOptionSupport lacks EFI_BOOT_OPTION_SUPPORT_KEY, so the boot manager \
                 supports no hot keys (UEFI 2.11 section 3.1.4)",
            ),
            (
                Some(0x0000_0312),
                "Key0004",
                f1.clone(),
                "BootOptionSupport lacks EFI_BOOT_OPTION_SUPPORT_KEY, so the boot manager \
                 supports no hot keys (UEFI 2.11 section 3.1.4)",
            ),
            (
                Some(0x0000_0101),
                "Key0004",
                two.clone(),
                "BootOptionSupport's EFI_BOOT_OPTION_SUPPORT_COUNT is 1, so the boot manager \
                 ignores a hot key of 2 keys (UEFI 2.11 section 3.1.4)",
            ),
            (
                Some(KEY_COUNT_3),
                "Key0004",
                new("Boot0001", &[], &["a", "b", "c", "d"]),
                "a hot key takes 0 to 3 keys, which InputKeyCount counts, not 4",
            ),
            (
                Some(KEY_COUNT_3),
                "Key0004",
                f1.clone(),
                "Key0002 holds these shift states and keys, and the boot manager takes it; it \
                 refuses another of the same",
            ),
        ];
        for (support, name, new, want) in cases {
            let variables = variables(support)
                .with("Key0002", EFI_GLOBAL_VARIABLE, &taken)
                .with("Key0003", EFI_GLOBAL_VARIABLE, &taken[..12]);
            let before = held(&variables);

            let error = create_key(&variables, &HotKeyListing::Listed(vec![2, 3]), name, &new)
                .expect_err("create a refused hot key");

            assert_eq!(error.to_string(), want, "{support:?} {name} {new:?}");
            assert_eq!(held(&variables), before, "{name}: the variables");
            assert_eq!(variables.set.into_inner(), [], "{name}: keys set");
        }
    }

    /// Of a Boot#### with EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS, BootOptionCrc is "the CRC-32
    /// of the entire EFI_LOAD_OPTION" (UEFI 2.11 §3.1.6), its value after the metadata (§8.2.1);
    /// one whose data ends inside its metadata is refused before any write.
    #[test]
    fn create_key_takes_the_crc_of_the_load_option_after_its_metadata() {
        let enhanced = NV_BS_RT | VariableAttributes::ENHANCED_AUTHENTICATED_ACCESS;
        let data = [timestamp_metadata(), bytes(X64_BOOT0001)].concat();
        let crc = boot_option_crc(&bytes(X64_BOOT0001));
        assert_ne!(crc, boot_option_crc(&data), "premise: the CRC-32s differ");
        let f2 = new("Boot0001", &[], &["F2"]);
        let whole = variables(Some(KEY_COUNT_3)).with_attributes(
            "Boot0001",
            EFI_GLOBAL_VARIABLE,
            enhanced,
            &data,
        );
        let truncated = variables(Some(KEY_COUNT_3)).with_attributes(
            "Boot0001",
            EFI_GLOBAL_VARIABLE,
            enhanced,
            &timestamp_metadata()[..10],
        );

        create_key(&whole, &HotKeyListing::Listed(Vec::new()), "Key0001", &f2)
            .expect("create Key0001");
        let error = create_key(
            &truncated,
            &HotKeyListing::Listed(Vec::new()),
            "Key0001",
            &f2,
        )
        .expect_err("create a Key#### of a Boot#### that ends inside its metadata");

        assert_eq!(
            held(&whole)[&key("Key0001", EFI_GLOBAL_VARIABLE)].data(),
            key_option(0x4000_0000, crc, 1, &[(0x000C, 0)]),
            "Key0001"
        );
        assert_eq!(
            format!("{error:#}"),
            "EFI variable Boot0001-8be4df61-93ca-11d2-aa0d-00e098032b8c is malformed: its 10 \
             bytes of data end inside its metadata",
            "a Boot#### that ends inside its metadata"
        );
        assert_eq!(truncated.set.into_inner(), [], "keys set");
    }

    /// A Key#### that the boot manager takes holds the same shift states and keys, as its value
    /// after the metadata tells, or as the CRC-32 of its Boot####'s value after the metadata
    /// tells, of a Key#### or Boot#### with EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS (UEFI 2.11
    /// §8.2.1): create-key refuses the same keys before any write.
    #[test]
    fn create_key_refuses_the_keys_of_a_key_taken_after_metadata() {
        let enhanced = NV_BS_RT | VariableAttributes::ENHANCED_AUTHENTICATED_ACCESS;
        let after_metadata = |value: Vec<u8>| [timestamp_metadata(), value].concat();
        let taken = key_option(
            0x4000_0200,
            boot_option_crc(&bytes(X64_BOOT0002)),
            2,
            &[(0x000B, 0)],
        );
        let cases = [
            (
                "an enhanced Key0002",
                (NV_BS_RT, bytes(X64_BOOT0002)),
                (enhanced, after_metadata(taken.clone())),
            ),
            (
                "an enhanced Boot0002",
                (enhanced, after_metadata(bytes(X64_BOOT0002))),
                (NV_BS_RT, taken.clone()),
            ),
        ];
        for (case, (boot_attributes, boot), (key_attributes, hot_key)) in cases {
            let variables = variables(Some(KEY_COUNT_3))
                .with_attributes("Boot0002", EFI_GLOBAL_VARIABLE, boot_attributes, &boot)
                .with_attributes("Key0002", EFI_GLOBAL_VARIABLE, key_attributes, &hot_key);
            let before = held(&variables);

            let error = create_key(
                &variables,
                &HotKeyListing::Listed(vec![2]),
                "Key0004",
                &new("Boot0001", &[KeyModifier::Control], &["F1"]),
            )
            .expect_err("create the keys of a taken Key0002");

            assert_eq!(
                error.to_string(),
                "Key0002 holds these shift states and keys, and the boot manager takes it; it \
                 refuses another of the same",
                "{case}"
            );
            assert_eq!(held(&variables), before, "{case}: the variables");
            assert_eq!(variables.set.into_inner(), [], "{case}: keys set");
        }
    }

    /// Where the Key#### variables cannot be listed, create-key writes the hot key and warns
    /// that it could not check them.
    #[test]
    fn create_key_warns_where_hot_keys_are_unlisted() {
        let variables = variables(Some(KEY_COUNT_3));

        let created = create_key(
            &variables,
            &HotKeyListing::Unlisted,
            "Key0004",
            &new("Boot0001", &[], &["F1"]),
        )
        .expect("create Key0004");

        assert_eq!(
            created.warnings,
            [
                "EFI variables cannot be listed here, so create-key cannot tell whether a Key#### \
              that the boot manager takes holds the same shift states and keys as Key0004, which \
              the boot manager would then ignore"
            ],
            "warnings"
        );
        assert_eq!(
            variables.set.into_inner(),
            [key("Key0004", EFI_GLOBAL_VARIABLE)],
            "keys set"
        );
    }
}
