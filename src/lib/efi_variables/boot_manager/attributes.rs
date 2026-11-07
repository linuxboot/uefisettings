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

//! variable set-attributes: the flags and category of a Boot####, Driver#### or SysPrep####
//! (UEFI 2.11 §3.1.3), changed in place, and the BootOptionCrc of each Key#### that followed
//! a Boot#### (§3.1.6), updated to follow it still.

use anyhow::Context;
use anyhow::Result;
use thiserror::Error;

use super::load_option_data;
use super::refuse_authenticated;
use super::value_after_metadata;
use super::written_option;
use super::HotKeyListing;
use super::LoadOptionCategory;
use super::LoadOptionFlag;
use super::CATEGORY;
use super::HOT_KEY_PREFIX;
use crate::efi_variables::globals::GlobalContents;
use crate::efi_variables::globals::GlobalValue;
use crate::efi_variables::globals::GlobalVariable;
use crate::efi_variables::globals::LoadOptionKind;
use crate::efi_variables::globals::LoadOptionName;
use crate::efi_variables::globals::EFI_GLOBAL_VARIABLE;
use crate::efi_variables::key_option::boot_option_crc;
use crate::efi_variables::key_option::with_boot_option_crc;
use crate::efi_variables::key_option::KeyOption;
use crate::efi_variables::load_option::LoadOption;
use crate::efi_variables::load_option::LoadOptionAttributes;
use crate::efi_variables::load_option::LoadOptionError;
use crate::efi_variables::VariableContents;
use crate::efi_variables::VariableData;
use crate::hii::VariableKey;

/// The size of Attributes, which starts an EFI_LOAD_OPTION
const ATTRIBUTES_SIZE: usize = 4;
/// The subcommand, which the refusals name
const SET_ATTRIBUTES: &str = "set-attributes";

/// A change of a load option's Attributes: the flags to set and to clear, and the
/// LOAD_OPTION_CATEGORY to give it, a value of that field rather than a bit.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
pub struct AttributeChange {
    pub set: Vec<LoadOptionFlag>,
    pub clear: Vec<LoadOptionFlag>,
    pub category: Option<LoadOptionCategory>,
}

impl AttributeChange {
    /// Refuses a change of nothing, and a flag both to set and to clear.
    fn check(&self) -> Result<(), AttributeRefusal> {
        let both: Vec<&str> = self
            .set
            .iter()
            .filter(|flag| self.clear.contains(flag))
            .map(|flag| flag.name())
            .collect();
        match (both.is_empty(), self.is_empty()) {
            (false, _) => Err(AttributeRefusal::SetAndClear(both.join(","))),
            (true, true) => Err(AttributeRefusal::NoChange),
            (true, false) => Ok(()),
        }
    }

    fn is_empty(&self) -> bool {
        self.set.is_empty() && self.clear.is_empty() && self.category.is_none()
    }

    /// `attributes` changed, every other bit kept: "When updating a load option, all undefined
    /// attribute bits must be preserved" (UEFI 2.11 §3.1.3). A category clears the
    /// LOAD_OPTION_CATEGORY field, then gives it its value.
    fn apply(&self, attributes: LoadOptionAttributes) -> LoadOptionAttributes {
        let bits = |flags: &[LoadOptionFlag]| {
            flags
                .iter()
                .map(|flag| flag.attribute())
                .fold(LoadOptionAttributes::empty(), LoadOptionAttributes::union)
        };
        let flagged = (attributes - bits(&self.clear)) | bits(&self.set);
        match self.category {
            Some(category) => (flagged - CATEGORY) | category.attributes(),
            None => flagged,
        }
    }
}

/// `bytes`, an EFI_LOAD_OPTION, with `change` applied to its Attributes and every other byte as
/// read: decoding and encoding it would turn each surrogate of its Description into U+FFFD.
pub(crate) fn with_attributes(
    bytes: &[u8],
    change: &AttributeChange,
) -> Result<Vec<u8>, LoadOptionError> {
    let attributes = change.apply(LoadOption::decode(bytes)?.attributes);
    let mut changed = bytes.to_vec();
    if let Some(field) = changed.get_mut(..ATTRIBUTES_SIZE) {
        field.copy_from_slice(&attributes.bits().to_le_bytes());
    }
    Ok(changed)
}

/// What variable set-attributes wrote: the load option, as variable get shows it, and what
/// became of the Key#### that followed it.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttributesSet {
    pub option: GlobalVariable,
    pub hot_keys: HotKeysFollowing,
}

/// The Key#### that followed a Boot####: those whose BootOption named it and whose
/// BootOptionCrc was the CRC-32 of its bytes before the change.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HotKeysFollowing {
    /// Those whose BootOptionCrc set-attributes updated, by option number: none for a
    /// Driver#### or SysPrep####, or when the bytes did not change
    Updated(Vec<u16>),
    /// None could be found, as the backend cannot list EFI variables: the boot manager now
    /// ignores each Key#### that followed this Boot####
    Unlisted(LoadOptionName),
}

/// Sets and clears the flags and sets the category of the load option `name` that `variables`
/// hold, as `change` says, every other bit and byte kept, and keeps its attributes; then sets the
/// BootOptionCrc of each Key#### of `hot_keys` that followed a Boot#### to the CRC-32 of its new
/// bytes. Refuses, before any write, a variable other than a Boot####, Driver#### or
/// SysPrep####, an absent one, a change of nothing, and a load option or following Key#### that
/// refuse_authenticated refuses. A Key#### write that fails names the Boot#### as written, the
/// Key#### updated and those left with the CRC-32 of its old bytes.
pub(crate) fn set_attributes(
    variables: &impl VariableData,
    hot_keys: &HotKeyListing,
    name: &str,
    change: &AttributeChange,
) -> Result<AttributesSet> {
    let option = written_option(name, SET_ATTRIBUTES)?;
    change.check()?;
    let key = option.key();
    let current = variables
        .variable_data(&key)?
        .ok_or(AttributeRefusal::Absent(option))?;
    refuse_authenticated(&key, current.attributes())?;
    let malformed = || format!("EFI variable {key} is malformed");
    let bytes = with_attributes(current.data(), change).with_context(malformed)?;
    let value = load_option_data(&bytes).with_context(malformed)?;

    let changed = bytes.as_slice() != current.data();
    let (hot_keys, followers) = match (option.kind, hot_keys, changed) {
        (LoadOptionKind::Boot, HotKeyListing::Listed(numbers), true) => {
            let followers = followers(variables, numbers, option.number, current.data(), &bytes)?;
            let numbers = followers.iter().map(|(number, _)| *number).collect();
            (HotKeysFollowing::Updated(numbers), followers)
        }
        (LoadOptionKind::Boot, HotKeyListing::Unlisted, true) => {
            (HotKeysFollowing::Unlisted(option), Vec::new())
        }
        (LoadOptionKind::Boot, _, false)
        | (LoadOptionKind::Driver | LoadOptionKind::SysPrep, _, _) => {
            (HotKeysFollowing::Updated(Vec::new()), Vec::new())
        }
    };
    if changed {
        let contents = VariableContents::new(current.attributes(), bytes)
            .with_context(|| format!("EFI variable {key}"))?;
        variables.set_variable(&key, &contents)?;
        let numbers: Vec<u16> = followers.iter().map(|(number, _)| *number).collect();
        for (written, (number, contents)) in followers.iter().enumerate() {
            variables
                .set_variable(&hot_key(*number), contents)
                .with_context(|| stale_keys(option, &numbers[..written], &numbers[written..]))?;
        }
    }
    Ok(AttributesSet {
        option: GlobalVariable {
            variable: key.to_string(),
            contents: Some(GlobalContents {
                attributes: current.attributes().bits(),
                value: GlobalValue::LoadOptionData(value),
            }),
        },
        hot_keys,
    })
}

/// The Key#### of `numbers` that `variables` hold that follow the Boot#### `boot_option` of
/// `old` bytes, each with its BootOptionCrc set to that of the `new` bytes; refuses one that
/// refuse_authenticated refuses. A Key#### that is malformed or absent follows none: the boot
/// manager ignores it (edk2-stable202608 BmIsKeyOptionValid(), BmHotkey.c).
fn followers(
    variables: &impl VariableData,
    numbers: &[u16],
    boot_option: u16,
    old: &[u8],
    new: &[u8],
) -> Result<Vec<(u16, VariableContents)>> {
    let (old_crc, new_crc) = (boot_option_crc(old), boot_option_crc(new));
    let mut followers = Vec::new();
    for &number in numbers {
        let key = hot_key(number);
        let Some(contents) = variables.variable_data(&key)? else {
            continue;
        };
        let Ok(value) = value_after_metadata(&contents) else {
            continue;
        };
        let follows = KeyOption::decode(value).is_ok_and(|option| {
            option.boot_option == boot_option && option.boot_option_crc == old_crc
        });
        if follows {
            refuse_authenticated(&key, contents.attributes())?;
            let data = with_boot_option_crc(value, new_crc);
            let contents = VariableContents::new(contents.attributes(), data)
                .with_context(|| format!("EFI variable {key}"))?;
            followers.push((number, contents));
        }
    }
    Ok(followers)
}

/// The Key#### variable `number`.
fn hot_key(number: u16) -> VariableKey {
    VariableKey {
        name: format!("{HOT_KEY_PREFIX}{number:04X}"),
        guid: EFI_GLOBAL_VARIABLE,
    }
}

/// What set-attributes wrote before a Key#### write failed: the Boot#### `option`, the Key####
/// of `updated` that follow it, and those of `stale` that the boot manager now ignores.
fn stale_keys(option: LoadOptionName, updated: &[u16], stale: &[u16]) -> String {
    format!(
        "{option} is written; the BootOptionCrc of {} is updated, but that of {} keeps the \
         CRC-32 of {option}'s old bytes, so the boot manager ignores those keys (UEFI 2.11 \
         section 3.1.6)",
        key_names(updated),
        key_names(stale)
    )
}

/// The Key#### of `numbers`, comma-separated.
fn key_names(numbers: &[u16]) -> String {
    match numbers {
        [] => "no Key####".to_owned(),
        numbers => numbers
            .iter()
            .map(|number| format!("Key{number:04X}"))
            .collect::<Vec<_>>()
            .join(", "),
    }
}

/// A change or variable that set-attributes refuses, before it writes anything, but those of
/// written_option and refuse_authenticated.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
enum AttributeRefusal {
    #[error("{0} is absent")]
    Absent(LoadOptionName),
    #[error("set-attributes cannot both set and clear {0}")]
    SetAndClear(String),
    #[error("set-attributes needs --set, --clear or --category")]
    NoChange,
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use serde_json::json;

    use super::*;
    use crate::efi_variables::boot_manager::AuthenticatedRefusal;
    use crate::efi_variables::device_path::tests::bytes;
    use crate::efi_variables::device_path::tests::X64_BOOT0000;
    use crate::efi_variables::device_path::tests::X64_BOOT0001;
    use crate::efi_variables::device_path::tests::X64_BOOT0002;
    use crate::efi_variables::enhanced_authenticated::fixture::timestamp_metadata;
    use crate::efi_variables::globals::tests::key;
    use crate::efi_variables::globals::tests::HeldVariables;
    use crate::efi_variables::globals::tests::NV_BS_RT;
    use crate::efi_variables::key_option::tests::X64_KEY0000;
    use crate::hii::VariableAttributes;
    use crate::hii::VariableInterface;

    /// HeldVariables whose SetVariable() fails for the variable `.1`.
    struct UnwritableVariable(HeldVariables, VariableKey);

    impl VariableData for UnwritableVariable {
        fn interface(&self) -> VariableInterface {
            self.0.interface()
        }

        fn variable_data(&self, key: &VariableKey) -> Result<Option<VariableContents>> {
            self.0.variable_data(key)
        }

        fn set_variable(&self, key: &VariableKey, contents: &VariableContents) -> Result<()> {
            match *key == self.1 {
                true => Err(anyhow::anyhow!("cannot write EFI variable {key}")),
                false => self.0.set_variable(key, contents),
            }
        }

        fn delete_variable(&self, key: &VariableKey) -> Result<()> {
            self.0.delete_variable(key)
        }
    }

    /// `option` with its Attributes replaced by `attributes`.
    fn with_attributes_bits(option: &str, attributes: u32) -> Vec<u8> {
        let mut option = bytes(option);
        option[..4].copy_from_slice(&attributes.to_le_bytes());
        option
    }

    /// An EFI_KEY_OPTION of one key, F2, to Boot#### `boot_option` with BootOptionCrc `crc`.
    fn key_option(boot_option: u16, crc: u32) -> Vec<u8> {
        [
            &0x4000_0000_u32.to_le_bytes()[..],
            &crc.to_le_bytes(),
            &boot_option.to_le_bytes(),
            &[0x0C, 0, 0, 0],
        ]
        .concat()
    }

    fn change(set: &[LoadOptionFlag], clear: &[LoadOptionFlag]) -> AttributeChange {
        AttributeChange {
            set: set.to_vec(),
            clear: clear.to_vec(),
            category: None,
        }
    }

    fn held(variables: &HeldVariables) -> BTreeMap<VariableKey, VariableContents> {
        variables.variables.borrow().clone()
    }

    fn data(variables: &HeldVariables, name: &str) -> Vec<u8> {
        variables.variables.borrow()[&key(name, EFI_GLOBAL_VARIABLE)]
            .data()
            .to_vec()
    }

    /// Only Attributes change: the undefined bits stay, and so does a Description whose surrogate
    /// a decode and encode would turn into U+FFFD, byte for byte.
    #[test]
    fn set_attributes_changes_only_attributes_and_keeps_undefined_bits() {
        let mut surrogate = with_attributes_bits(X64_BOOT0001, 0x4000_0001);
        // the Description's first CHAR16, "U", becomes a lone high surrogate
        surrogate[6..8].copy_from_slice(&0xD800_u16.to_le_bytes());
        let variables = HeldVariables::default()
            .with("Boot0001", EFI_GLOBAL_VARIABLE, &surrogate)
            .with("Boot0002", EFI_GLOBAL_VARIABLE, &bytes(X64_BOOT0002));

        let set = set_attributes(
            &variables,
            &HotKeyListing::Listed(Vec::new()),
            "Boot0001",
            &change(
                &[LoadOptionFlag::Hidden, LoadOptionFlag::ForceReconnect],
                &[LoadOptionFlag::Active],
            ),
        )
        .expect("set Boot0001's attributes");

        let written = data(&variables, "Boot0001");
        assert_eq!(
            written[..4],
            0x4000_000A_u32.to_le_bytes(),
            "Attributes: hidden and force-reconnect, not active, the undefined bit kept"
        );
        assert_eq!(written[4..], surrogate[4..], "every other byte");
        assert_eq!(
            serde_json::to_value(&set.option).expect("serialize")["value"]["attributes"],
            json!(["force-reconnect", "hidden", "0x40000000"]),
            "what set-attributes prints"
        );
        assert_eq!(
            set.hot_keys,
            HotKeysFollowing::Updated(Vec::new()),
            "hot keys"
        );
        assert_eq!(
            variables.set.into_inner(),
            [key("Boot0001", EFI_GLOBAL_VARIABLE)],
            "keys set"
        );
    }

    /// A category is a value of the LOAD_OPTION_CATEGORY field: giving one clears the field, a
    /// reserved value too, then sets LOAD_OPTION_CATEGORY_BOOT (0) or LOAD_OPTION_CATEGORY_APP
    /// (0x100); the flags and undefined bits stay.
    #[test]
    fn categories_are_values_of_their_field() {
        let cases = [
            (0x0000_0301, LoadOptionCategory::App, 0x0000_0101),
            (0x0000_0301, LoadOptionCategory::Boot, 0x0000_0001),
            (0x8000_1F08, LoadOptionCategory::App, 0x8000_0108),
            (0x0000_0100, LoadOptionCategory::Boot, 0x0000_0000),
            (0x0000_0000, LoadOptionCategory::App, 0x0000_0100),
        ];
        for (before, category, after) in cases {
            let change = AttributeChange {
                category: Some(category),
                ..AttributeChange::default()
            };

            let changed = with_attributes(&with_attributes_bits(X64_BOOT0001, before), &change)
                .expect("change the category");

            assert_eq!(
                changed,
                with_attributes_bits(X64_BOOT0001, after),
                "{before:#010x} to {category:?}"
            );
        }
    }

    /// After a Boot#### changes, each Key#### whose BootOption names it and whose BootOptionCrc
    /// was the CRC-32 of its old bytes gets that of the new ones, every other byte kept; a key
    /// of another Boot####, a stale one, a malformed one and an absent one stay as they were.
    #[test]
    fn hot_keys_that_followed_a_boot_option_follow_it_still() {
        let boot0001 = bytes(X64_BOOT0001);
        let boot0002 = bytes(X64_BOOT0002);
        let follower = key_option(1, boot_option_crc(&boot0001));
        let variables = || {
            HeldVariables::default()
                .with("Boot0001", EFI_GLOBAL_VARIABLE, &boot0001)
                .with("Boot0002", EFI_GLOBAL_VARIABLE, &boot0002)
                .with("Key0001", EFI_GLOBAL_VARIABLE, &follower)
                .with("Key0002", EFI_GLOBAL_VARIABLE, &key_option(1, 0x1234_5678))
                .with(
                    "Key0003",
                    EFI_GLOBAL_VARIABLE,
                    &key_option(2, boot_option_crc(&boot0002)),
                )
                .with("Key0004", EFI_GLOBAL_VARIABLE, &follower[..12])
                .with("Key000A", EFI_GLOBAL_VARIABLE, &follower)
        };
        let listed = HotKeyListing::Listed(vec![1, 2, 3, 4, 5, 0xA]);
        let clear_active = change(&[], &[LoadOptionFlag::Active]);

        let variables_listed = variables();
        let before = held(&variables_listed);
        let set = set_attributes(&variables_listed, &listed, "Boot0001", &clear_active)
            .expect("clear Boot0001's active flag");

        let new_crc = boot_option_crc(&data(&variables_listed, "Boot0001"));
        let mut want = before.clone();
        for name in ["Key0001", "Key000A"] {
            let mut followed = follower.clone();
            followed[4..8].copy_from_slice(&new_crc.to_le_bytes());
            want.insert(
                key(name, EFI_GLOBAL_VARIABLE),
                VariableContents::new(
                    before[&key(name, EFI_GLOBAL_VARIABLE)].attributes(),
                    followed,
                )
                .expect("hold the key"),
            );
        }
        want.insert(
            key("Boot0001", EFI_GLOBAL_VARIABLE),
            variables_listed.variables.borrow()[&key("Boot0001", EFI_GLOBAL_VARIABLE)].clone(),
        );
        assert_ne!(new_crc, boot_option_crc(&boot0001), "the CRC-32 changes");
        assert_eq!(
            set.hot_keys,
            HotKeysFollowing::Updated(vec![1, 0xA]),
            "listed"
        );
        assert_eq!(held(&variables_listed), want, "listed: the variables");
        assert_eq!(
            variables_listed.set.into_inner(),
            [
                key("Boot0001", EFI_GLOBAL_VARIABLE),
                key("Key0001", EFI_GLOBAL_VARIABLE),
                key("Key000A", EFI_GLOBAL_VARIABLE),
            ],
            "listed: keys set"
        );

        let variables_unlisted = variables();
        let set = set_attributes(
            &variables_unlisted,
            &HotKeyListing::Unlisted,
            "Boot0001",
            &clear_active,
        )
        .expect("clear Boot0001's active flag without a listing");
        assert_eq!(
            set.hot_keys,
            HotKeysFollowing::Unlisted(LoadOptionName {
                kind: LoadOptionKind::Boot,
                number: 1,
            }),
            "unlisted"
        );
        assert_eq!(
            variables_unlisted.set.into_inner(),
            [key("Boot0001", EFI_GLOBAL_VARIABLE)],
            "unlisted: keys set"
        );

        // a Driver#### has no hot keys, and an unchanged Boot#### is not written
        let variables_other = variables().with("Driver0001", EFI_GLOBAL_VARIABLE, &boot0001);
        let driver = set_attributes(&variables_other, &listed, "Driver0001", &clear_active)
            .expect("clear Driver0001's active flag");
        let unchanged = set_attributes(
            &variables_other,
            &listed,
            "Boot0001",
            &change(&[LoadOptionFlag::Active], &[]),
        )
        .expect("set Boot0001's active flag again");
        assert_eq!(
            driver.hot_keys,
            HotKeysFollowing::Updated(Vec::new()),
            "Driver0001"
        );
        assert_eq!(
            unchanged.hot_keys,
            HotKeysFollowing::Updated(Vec::new()),
            "unchanged"
        );
        assert_eq!(
            variables_other.set.into_inner(),
            [key("Driver0001", EFI_GLOBAL_VARIABLE)],
            "Driver0001 and unchanged Boot0001: keys set"
        );
    }

    /// The Boot#### and the Key#### that follows it are each written with the attributes that
    /// they held: SetVariable() refuses a rewrite with others (UEFI 2.11 §8.2).
    #[test]
    fn set_attributes_keeps_the_attributes_of_each_variable() {
        let boot0001 = bytes(X64_BOOT0001);
        let bs_rt = VariableAttributes::BOOTSERVICE_ACCESS | VariableAttributes::RUNTIME_ACCESS;
        let nv_bs = VariableAttributes::NON_VOLATILE | VariableAttributes::BOOTSERVICE_ACCESS;
        let variables = HeldVariables::default()
            .with_attributes("Boot0001", EFI_GLOBAL_VARIABLE, bs_rt, &boot0001)
            .with_attributes(
                "Key0001",
                EFI_GLOBAL_VARIABLE,
                nv_bs,
                &key_option(1, boot_option_crc(&boot0001)),
            );

        let set = set_attributes(
            &variables,
            &HotKeyListing::Listed(vec![1]),
            "Boot0001",
            &change(&[], &[LoadOptionFlag::Active]),
        )
        .expect("clear Boot0001's active flag");

        let held = held(&variables);
        assert_eq!(
            [
                held[&key("Boot0001", EFI_GLOBAL_VARIABLE)].attributes(),
                held[&key("Key0001", EFI_GLOBAL_VARIABLE)].attributes(),
            ],
            [bs_rt, nv_bs],
            "Boot0001 and Key0001: their attributes"
        );
        assert_eq!(
            set.option.contents.map(|contents| contents.attributes),
            Some(bs_rt.bits()),
            "what set-attributes prints"
        );
        assert_eq!(set.hot_keys, HotKeysFollowing::Updated(vec![1]), "hot keys");
        assert_eq!(
            variables.set.into_inner(),
            [
                key("Boot0001", EFI_GLOBAL_VARIABLE),
                key("Key0001", EFI_GLOBAL_VARIABLE),
            ],
            "keys set"
        );
    }

    /// A Key#### write that fails after the Boot#### write names the Boot#### as written, the
    /// Key#### updated before it, and it and those after it, left with the old BootOptionCrc.
    #[test]
    fn a_failed_key_write_names_what_was_written_and_the_stale_keys() {
        let boot0001 = bytes(X64_BOOT0001);
        let follower = key_option(1, boot_option_crc(&boot0001));
        let cases = [
            (
                "Key0001",
                "Boot0001 is written; the BootOptionCrc of no Key#### is updated, but that of \
                 Key0001, Key0002, Key000A keeps the CRC-32 of Boot0001's old bytes, so the boot \
                 manager ignores those keys (UEFI 2.11 section 3.1.6): cannot write EFI variable \
                 Key0001-8be4df61-93ca-11d2-aa0d-00e098032b8c",
                vec!["Boot0001"],
            ),
            (
                "Key0002",
                "Boot0001 is written; the BootOptionCrc of Key0001 is updated, but that of \
                 Key0002, Key000A keeps the CRC-32 of Boot0001's old bytes, so the boot manager \
                 ignores those keys (UEFI 2.11 section 3.1.6): cannot write EFI variable \
                 Key0002-8be4df61-93ca-11d2-aa0d-00e098032b8c",
                vec!["Boot0001", "Key0001"],
            ),
            (
                "Key000A",
                "Boot0001 is written; the BootOptionCrc of Key0001, Key0002 is updated, but that \
                 of Key000A keeps the CRC-32 of Boot0001's old bytes, so the boot manager ignores \
                 those keys (UEFI 2.11 section 3.1.6): cannot write EFI variable \
                 Key000A-8be4df61-93ca-11d2-aa0d-00e098032b8c",
                vec!["Boot0001", "Key0001", "Key0002"],
            ),
        ];
        for (failing, want, written) in cases {
            let variables = UnwritableVariable(
                HeldVariables::default()
                    .with("Boot0001", EFI_GLOBAL_VARIABLE, &boot0001)
                    .with("Key0001", EFI_GLOBAL_VARIABLE, &follower)
                    .with("Key0002", EFI_GLOBAL_VARIABLE, &follower)
                    .with("Key000A", EFI_GLOBAL_VARIABLE, &follower),
                key(failing, EFI_GLOBAL_VARIABLE),
            );

            let error = set_attributes(
                &variables,
                &HotKeyListing::Listed(vec![1, 2, 0xA]),
                "Boot0001",
                &change(&[], &[LoadOptionFlag::Active]),
            )
            .expect_err("a Key#### write fails");

            assert_eq!(format!("{error:#}"), want, "{failing}");
            assert_eq!(
                variables.0.set.into_inner(),
                written
                    .iter()
                    .map(|name| key(name, EFI_GLOBAL_VARIABLE))
                    .collect::<Vec<_>>(),
                "{failing}: keys set"
            );
        }
    }

    /// PlatformRecovery####, read-only to the OS, OsRecovery####, a Secure Boot Policy Variable,
    /// any variable but a Boot####, Driver#### or SysPrep####, an absent one, a change of nothing
    /// and one that both sets and clears a flag are refused before any write; a malformed load
    /// option is refused before any write too.
    #[test]
    fn set_attributes_refuses_other_variables_and_changes_unwritten() {
        let variables = HeldVariables::default()
            .with("Boot0001", EFI_GLOBAL_VARIABLE, &bytes(X64_BOOT0001))
            .with("Boot0003", EFI_GLOBAL_VARIABLE, &[1, 0, 0, 0])
            .with(
                "PlatformRecovery0000",
                EFI_GLOBAL_VARIABLE,
                &bytes(X64_BOOT0001),
            )
            .with("OsRecovery0000", EFI_GLOBAL_VARIABLE, &bytes(X64_BOOT0001))
            .with("Key0001", EFI_GLOBAL_VARIABLE, &key_option(1, 0));
        let before = held(&variables);
        let active = change(&[LoadOptionFlag::Active], &[]);
        let cases = [
            (
                "PlatformRecovery0000",
                active.clone(),
                "set-attributes does not write PlatformRecovery0000: \"These variables are only \
                 modified by firmware and are read-only to the OS.\" (UEFI 2.11 section 3.3)",
            ),
            (
                "OsRecovery0000",
                active.clone(),
                "set-attributes does not write OsRecovery0000, a Secure Boot Policy Variable: \
                 \"Secure Boot Policy Variables must be created using the \
                 EFI_VARIABLE_AUTHENTICATION_2 structure.\" (UEFI 2.11 section 3.3); variable \
                 write-signed writes a payload signed so",
            ),
            (
                "Key0001",
                active.clone(),
                "set-attributes takes a Boot####, Driver#### or SysPrep####, not Key0001",
            ),
            (
                "ConOut",
                active.clone(),
                "set-attributes takes a Boot####, Driver#### or SysPrep####, not ConOut",
            ),
            (
                "Boot001",
                active.clone(),
                "set-attributes takes a Boot####, Driver#### or SysPrep####, not Boot001",
            ),
            ("Boot1234", active.clone(), "Boot1234 is absent"),
            (
                "Boot0001",
                AttributeChange::default(),
                "set-attributes needs --set, --clear or --category",
            ),
            (
                "Boot0001",
                change(
                    &[LoadOptionFlag::Active, LoadOptionFlag::Hidden],
                    &[LoadOptionFlag::Hidden, LoadOptionFlag::Active],
                ),
                "set-attributes cannot both set and clear active,hidden",
            ),
        ];
        for (name, change, want) in cases {
            let error = set_attributes(&variables, &HotKeyListing::Listed(vec![1]), name, &change)
                .expect_err("set refused attributes");

            assert_eq!(error.to_string(), want, "{name} {change:?}");
        }
        let malformed = set_attributes(
            &variables,
            &HotKeyListing::Listed(vec![1]),
            "Boot0003",
            &active,
        )
        .expect_err("set the attributes of a malformed load option");

        assert!(
            format!("{malformed:#}").starts_with(
                "EFI variable Boot0003-8be4df61-93ca-11d2-aa0d-00e098032b8c is malformed: "
            ),
            "malformed: {malformed:#}"
        );
        assert_eq!(held(&variables), before, "the variables");
        assert_eq!(variables.set.into_inner(), [], "keys set");
    }

    /// Asserts that clearing LOAD_OPTION_ACTIVE of the Boot0000 that `variables` hold, which
    /// Key0000 may follow, refuses `refused` as only a signed write sets it, and writes nothing.
    fn assert_refused_as_authenticated(variables: &HeldVariables, refused: &str) {
        let before = held(variables);

        let error = set_attributes(
            variables,
            &HotKeyListing::Listed(vec![0]),
            "Boot0000",
            &change(&[], &[LoadOptionFlag::Active]),
        )
        .expect_err("set-attributes refused");

        let refused_key = key(refused, EFI_GLOBAL_VARIABLE);
        assert_eq!(
            error.to_string(),
            format!(
                "EFI variable {refused_key} has ENHANCED_AUTHENTICATED_ACCESS or \
                 TIME_BASED_AUTHENTICATED_WRITE_ACCESS: SetVariable() writes it only with an \
                 EFI_VARIABLE_AUTHENTICATION_3 or EFI_VARIABLE_AUTHENTICATION_2 descriptor (UEFI \
                 2.11 section 8.2.3), as variable write-signed writes it"
            ),
            "{refused} refused"
        );
        assert_eq!(
            error.downcast_ref(),
            Some(&AuthenticatedRefusal(refused_key)),
            "{refused} refused"
        );
        assert_eq!(held(variables), before, "the variables, {refused} refused");
        assert_eq!(*variables.set.borrow(), [], "keys set, {refused} refused");
    }

    /// A Boot#### with EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS, which get decodes after its
    /// metadata, or with EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS is refused before any
    /// write: only an EFI_VARIABLE_AUTHENTICATION_3 or _2 descriptor writes it (UEFI 2.11 §8.2.3).
    #[test]
    fn set_attributes_refuses_an_authenticated_load_option() {
        let cases = [
            (
                NV_BS_RT | VariableAttributes::ENHANCED_AUTHENTICATED_ACCESS,
                [timestamp_metadata(), bytes(X64_BOOT0000)].concat(),
            ),
            (
                NV_BS_RT | VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS,
                bytes(X64_BOOT0000),
            ),
        ];
        for (attributes, data) in cases {
            let variables = HeldVariables::default().with_attributes(
                "Boot0000",
                EFI_GLOBAL_VARIABLE,
                attributes,
                &data,
            );

            assert_refused_as_authenticated(&variables, "Boot0000");
        }
    }

    /// A Key#### with EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS that follows the Boot####, as
    /// its value after the metadata tells (UEFI 2.11 §8.2.1), is refused before any write.
    #[test]
    fn set_attributes_refuses_an_enhanced_key_that_follows() {
        let variables = HeldVariables::default()
            .with("Boot0000", EFI_GLOBAL_VARIABLE, &bytes(X64_BOOT0000))
            .with_attributes(
                "Key0000",
                EFI_GLOBAL_VARIABLE,
                NV_BS_RT | VariableAttributes::ENHANCED_AUTHENTICATED_ACCESS,
                &[timestamp_metadata(), bytes(X64_KEY0000)].concat(),
            );

        assert_refused_as_authenticated(&variables, "Key0000");
    }

    /// A Key#### with EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS that follows the
    /// Boot#### is refused before the Boot#### is written, which would leave it stale (UEFI 2.11
    /// §8.2.3); one that follows another Boot#### is no matter.
    #[test]
    fn set_attributes_refuses_a_time_based_key_that_follows() {
        let time_based = NV_BS_RT | VariableAttributes::TIME_BASED_AUTHENTICATED_WRITE_ACCESS;
        let variables = HeldVariables::default()
            .with("Boot0000", EFI_GLOBAL_VARIABLE, &bytes(X64_BOOT0000))
            .with_attributes(
                "Key0000",
                EFI_GLOBAL_VARIABLE,
                time_based,
                &bytes(X64_KEY0000),
            );

        assert_refused_as_authenticated(&variables, "Key0000");

        let crc = boot_option_crc(&bytes(X64_BOOT0000));
        let variables = HeldVariables::default()
            .with("Boot0000", EFI_GLOBAL_VARIABLE, &bytes(X64_BOOT0000))
            .with_attributes(
                "Key0001",
                EFI_GLOBAL_VARIABLE,
                time_based,
                &key_option(5, crc),
            );
        let set = set_attributes(
            &variables,
            &HotKeyListing::Listed(vec![1]),
            "Boot0000",
            &change(&[], &[LoadOptionFlag::Active]),
        )
        .expect("set the attributes of Boot0000, which a time-based Key0001 does not follow");

        assert_eq!(set.hot_keys, HotKeysFollowing::Updated(Vec::new()), "keys");
        assert_eq!(
            variables.set.into_inner(),
            [key("Boot0000", EFI_GLOBAL_VARIABLE)],
            "variables set"
        );
    }
}
