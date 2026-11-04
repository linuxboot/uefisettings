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

//! The EFI variables of a machine, never their data (UEFI 2.10 §8.2): what the variable commands
//! make of what each backend tells. The backends do the I/O: efivarfs on Linux (hii/efivarfs.rs),
//! the runtime services in the UEFI Shell (hii/variable_services.rs).

#[cfg(any(target_os = "uefi", test))]
use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;

use crate::hii::package::Guid;
use crate::hii::VariableKey;

/// GetNextVariableName() (UEFI 2.10 §8.2.2): the variables that a backend reaches, by name and
/// vendor GUID.
pub(crate) trait VariableNames {
    /// Every variable these reach, in no particular order.
    fn variable_names(&self) -> Result<Vec<VariableKey>>;
}

/// What one GetNextVariableName() call (UEFI 2.10 §8.2.2) did.
#[cfg(any(target_os = "uefi", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NextVariableName {
    /// EFI_SUCCESS: it wrote the next variable's name and vendor GUID over the previous ones
    Found,
    /// EFI_NOT_FOUND: "The next variable was not found", so the listing ends
    End,
    /// EFI_BUFFER_TOO_SMALL: the next name needs a buffer of this many CHAR16
    BufferTooSmall(usize),
}

/// GetNextVariableName(), one call at a time.
#[cfg(any(target_os = "uefi", test))]
pub(crate) trait GetNextVariableName {
    /// Calls GetNextVariableName() with the NUL-terminated `name` and the `vendor` of the
    /// previous variable, or a NUL first on the first call; any other status than those of
    /// NextVariableName is an error.
    fn get_next_variable_name(
        &mut self,
        name: &mut [u16],
        vendor: &mut Guid,
    ) -> Result<NextVariableName>;
}

/// Every variable that `calls` give, from a first call with an empty name to EFI_NOT_FOUND
/// (UEFI 2.10 §8.2.2), each name as VariableKey::from_ucs2 reads it. A variable given twice
/// fails the walk: some firmware gives one variable again and again (Linux v6.17
/// fs/efivarfs/vars.c efivar_init()).
#[cfg(any(target_os = "uefi", test))]
pub(crate) fn walk_variable_names(
    calls: &mut impl GetNextVariableName,
) -> Result<Vec<VariableKey>> {
    // 512 CHAR16 first, as a Toshiba Satellite Pro R50-B-12P does not update VariableNameSize
    // (uefi 0.41 runtime::VariableKeys::new())
    let mut name = vec![0; 512];
    let mut vendor = Guid::from([0; 16]);
    let mut keys = Vec::new();
    let mut given = std::collections::BTreeSet::new();
    loop {
        match calls.get_next_variable_name(&mut name, &mut vendor)? {
            NextVariableName::Found => {}
            NextVariableName::End => return Ok(keys),
            NextVariableName::BufferTooSmall(size) if size > name.len() => {
                name.resize(size, 0);
                continue;
            }
            NextVariableName::BufferTooSmall(size) => {
                return Err(anyhow!(
                    "GetNextVariableName() asked for {size} CHAR16, which its buffer of {} holds",
                    name.len()
                ));
            }
        }
        let units = name
            .iter()
            .position(|&unit| unit == 0)
            .and_then(|end| name.get(..end))
            .context("GetNextVariableName() gave a name without its NUL")?;
        let key = VariableKey::from_ucs2(units, vendor);
        // the units, as from_ucs2 reads distinct surrogates alike
        if !given.insert((units.to_vec(), vendor)) {
            return Err(anyhow!(
                "GetNextVariableName() returned EFI variable {key} twice"
            ));
        }
        keys.push(key);
    }
}

/// The variables that `names` reach, of the vendor `vendor` only if given, sorted by name, then
/// vendor: GetNextVariableName() "cannot be used as a filter" (UEFI 2.10 §8.2.2), so those of
/// other vendors drop out after the listing.
pub(crate) fn list_variables(
    names: &impl VariableNames,
    vendor: Option<Guid>,
) -> Result<Vec<VariableKey>> {
    let mut keys = names.variable_names()?;
    keys.retain(|key| vendor.is_none_or(|vendor| key.guid == vendor));
    keys.sort();
    Ok(keys)
}

/// The vendor GUID `vendor` that a command names, such as 8BE4DF61-93CA-11D2-AA0D-00E098032B8C.
pub(crate) fn parse_vendor(vendor: &str) -> Result<Guid> {
    vendor
        .parse()
        .with_context(|| format!("vendor {vendor} is not a GUID"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// EFI_GLOBAL_VARIABLE, the vendor GUID of the global variables (UEFI 2.10 §3.3).
    const EFI_GLOBAL_VARIABLE: &str = "8BE4DF61-93CA-11D2-AA0D-00E098032B8C";
    /// The formset GUID of EDK2's DriverSample, the vendor GUID of its variables.
    const DRIVER_SAMPLE: &str = "A04A27F4-DF00-4D42-B552-39511302113D";
    /// A vendor GUID of no variable here.
    const UNLISTED: &str = "00000000-0000-0000-0000-000000000001";

    /// VariableNames that reach the variables it holds.
    struct ListedNames(Vec<VariableKey>);

    impl VariableNames for ListedNames {
        fn variable_names(&self) -> Result<Vec<VariableKey>> {
            Ok(self.0.clone())
        }
    }

    /// The GUID `text`.
    fn guid(text: &str) -> Guid {
        text.parse()
            .unwrap_or_else(|error| panic!("parse GUID {text}: {error}"))
    }

    /// The variable `name` of the vendor GUID `vendor`.
    fn key(name: &str, vendor: &str) -> VariableKey {
        VariableKey {
            name: name.to_string(),
            guid: guid(vendor),
        }
    }

    /// What ScriptedNames answers to a call of GetNextVariableName().
    enum Answer {
        /// Writes this name, of these CHAR16, then a NUL, and this vendor
        Name(Vec<u16>, &'static str),
        /// Writes this name, of these CHAR16, filling the buffer without a NUL
        Unterminated(Vec<u16>),
        TooSmall(usize),
        End,
        Fails,
    }

    /// GetNextVariableName() that answers each call with the next of `answers`, and records the
    /// name that each call passes.
    struct ScriptedNames {
        answers: std::collections::VecDeque<Answer>,
        passed: Vec<Vec<u16>>,
    }

    impl ScriptedNames {
        fn new(answers: impl IntoIterator<Item = Answer>) -> Self {
            Self {
                answers: answers.into_iter().collect(),
                passed: Vec::new(),
            }
        }
    }

    impl GetNextVariableName for ScriptedNames {
        fn get_next_variable_name(
            &mut self,
            name: &mut [u16],
            vendor: &mut Guid,
        ) -> Result<NextVariableName> {
            let end = name
                .iter()
                .position(|&unit| unit == 0)
                .expect("a NUL passed");
            self.passed.push(name[..end].to_vec());
            Ok(match self.answers.pop_front().expect("an answer") {
                Answer::Name(units, guid_text) => {
                    name[..units.len()].copy_from_slice(&units);
                    name[units.len()] = 0;
                    *vendor = guid(guid_text);
                    NextVariableName::Found
                }
                Answer::Unterminated(units) => {
                    name.copy_from_slice(&units);
                    NextVariableName::Found
                }
                Answer::TooSmall(size) => NextVariableName::BufferTooSmall(size),
                Answer::End => NextVariableName::End,
                Answer::Fails => return Err(anyhow!("GetNextVariableName(): DEVICE_ERROR")),
            })
        }
    }

    /// The CHAR16 of `text`.
    fn char16(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    /// walk_variable_names passes each name back to get the next until EFI_NOT_FOUND, grows its
    /// buffer to the size that EFI_BUFFER_TOO_SMALL asks for and passes the same name again, and
    /// reads each surrogate code unit as U+FFFD, where two names can read alike.
    #[test]
    fn walk_variable_names_lists_every_variable() {
        let long = "L".repeat(600);
        let mut calls = ScriptedNames::new([
            Answer::Name(char16("Timeout"), EFI_GLOBAL_VARIABLE),
            Answer::TooSmall(601),
            Answer::Name(char16(&long), DRIVER_SAMPLE),
            Answer::Name(vec![0x41, 0xD800, 0x42, 0xDE00], EFI_GLOBAL_VARIABLE),
            // a variable of another name, which reads alike
            Answer::Name(vec![0x41, 0xD801, 0x42, 0xDE00], EFI_GLOBAL_VARIABLE),
            Answer::End,
        ]);

        let keys = walk_variable_names(&mut calls).expect("walk the variables");

        assert_eq!(
            keys,
            [
                key("Timeout", EFI_GLOBAL_VARIABLE),
                key(&long, DRIVER_SAMPLE),
                key("A\u{fffd}B\u{fffd}", EFI_GLOBAL_VARIABLE),
                key("A\u{fffd}B\u{fffd}", EFI_GLOBAL_VARIABLE),
            ],
            "keys"
        );
        assert_eq!(
            calls.passed,
            [
                vec![],
                char16("Timeout"),
                char16("Timeout"),
                char16(&long),
                vec![0x41, 0xD800, 0x42, 0xDE00],
                vec![0x41, 0xD801, 0x42, 0xDE00],
            ],
            "names passed"
        );
    }

    /// walk_variable_names fails where a call fails, asks for no larger buffer, gives a name
    /// without its NUL, or gives a variable again.
    #[test]
    fn walk_variable_names_refuses_what_it_cannot_list() {
        for (answer, refusal) in [
            (
                Answer::Fails,
                "GetNextVariableName(): DEVICE_ERROR".to_string(),
            ),
            (
                Answer::TooSmall(512),
                "GetNextVariableName() asked for 512 CHAR16, which its buffer of 512 holds"
                    .to_string(),
            ),
            (
                Answer::Unterminated(vec![0x41; 512]),
                "GetNextVariableName() gave a name without its NUL".to_string(),
            ),
            (
                Answer::Name(char16("Timeout"), EFI_GLOBAL_VARIABLE),
                "GetNextVariableName() returned EFI variable \
                 Timeout-8be4df61-93ca-11d2-aa0d-00e098032b8c twice"
                    .to_string(),
            ),
        ] {
            let mut calls = ScriptedNames::new([
                Answer::Name(char16("Timeout"), EFI_GLOBAL_VARIABLE),
                answer,
                Answer::End,
            ]);

            let error = walk_variable_names(&mut calls).expect_err("walk to a refusal");

            assert_eq!(error.to_string(), refusal, "{refusal}");
        }
    }

    #[test]
    fn list_variables_sorts_and_keeps_only_the_vendor_asked() {
        let names = ListedNames(vec![
            key("Timeout", EFI_GLOBAL_VARIABLE),
            key("MyIfrNVData", DRIVER_SAMPLE),
            key("BootOrder", EFI_GLOBAL_VARIABLE),
            key("Timeout", DRIVER_SAMPLE),
        ]);
        let cases = [
            (
                "every vendor",
                None,
                vec![
                    key("BootOrder", EFI_GLOBAL_VARIABLE),
                    key("MyIfrNVData", DRIVER_SAMPLE),
                    key("Timeout", EFI_GLOBAL_VARIABLE),
                    key("Timeout", DRIVER_SAMPLE),
                ],
            ),
            (
                "EFI_GLOBAL_VARIABLE",
                Some(EFI_GLOBAL_VARIABLE),
                vec![
                    key("BootOrder", EFI_GLOBAL_VARIABLE),
                    key("Timeout", EFI_GLOBAL_VARIABLE),
                ],
            ),
            ("a vendor of no variable", Some(UNLISTED), vec![]),
        ];

        for (case, vendor, want) in cases {
            let keys = list_variables(&names, vendor.map(guid)).expect("list the variables");

            assert_eq!(keys, want, "{case}");
        }
    }

    #[test]
    fn parse_vendor_takes_either_case_and_names_a_vendor_that_is_no_guid() {
        for vendor in [
            EFI_GLOBAL_VARIABLE.to_string(),
            EFI_GLOBAL_VARIABLE.to_ascii_lowercase(),
        ] {
            assert_eq!(
                parse_vendor(&vendor).expect("parse the vendor").to_string(),
                EFI_GLOBAL_VARIABLE,
                "{vendor}"
            );
        }

        let error = parse_vendor("8BE4DF61-93CA-11D2-AA0D").expect_err("parse a short vendor");

        assert_eq!(
            format!("{error:#}"),
            "vendor 8BE4DF61-93CA-11D2-AA0D is not a GUID: GUID string has wrong length \
             (expected 36 bytes)",
            "short vendor"
        );
    }
}
