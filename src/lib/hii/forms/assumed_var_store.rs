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

//! Bytes of a VarStore that the user states with --assume-var-store, which conditions read in
//! place of those its variable holds: what a setup browser holds where the OS cannot read it,
//! such as a buffer VarStore that only the driver's EFI_HII_CONFIG_ACCESS_PROTOCOL reaches.

use std::cell::RefCell;
use std::fmt;
use std::ops::Range;
use std::rc::Rc;
use std::str::FromStr;

use thiserror::Error;

use super::form_set_list_var_stores;
use super::Creation;
use super::Guid;
use super::IFROpCode;
use super::IFROperation;
use super::ParsedOperation;
use super::VariableStore;
use crate::hex_digits::hex_bytes;
use crate::hii::variables::VariableKey;
use crate::hii::variables::VariableLayout;

/// "8BE4DF61-93CA-11D2-AA0D-00E098032B8C"
const GUID_TEXT_LEN: usize = 36;
/// The bytes of a VarStore's payload: its Size is a UINT16 (UEFI 2.11 §33.3.8.3.89)
const PAYLOAD_LIMIT: usize = 1 << 16;

/// `bytes` that conditions read from byte `offset` of the payload of the VarStore whose variable
/// is `variable`, in place of those the variable holds. It writes nothing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AssumedVarStore {
    /// Named as its efivar file names it: '!' for each '/'
    variable: VariableKey,
    offset: u16,
    bytes: Vec<u8>,
}

/// Why a text is no NAME-GUID[+OFFSET]=HEX.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum AssumedVarStoreError {
    #[error("expected NAME-GUID[+OFFSET]=HEX, got {0:?}")]
    Syntax(String),
    #[error("invalid GUID {0:?}")]
    Guid(String),
    #[error("invalid OFFSET {0:?}: give a decimal number, or a hexadecimal one after 0x")]
    Offset(String),
    #[error("invalid HEX {0:?}: give two hex digits per byte, at least one byte")]
    Bytes(String),
    #[error("{bytes} bytes from byte {offset} pass the 65536 bytes that a VarStore can hold")]
    Size { offset: u16, bytes: usize },
}

/// `variable` named as its efivar file names it: '!' for each '/'.
fn efivar_file_named(variable: VariableKey) -> VariableKey {
    VariableKey {
        name: variable.name.replace('/', "!"),
        ..variable
    }
}

impl AssumedVarStore {
    /// The payload bytes that it states.
    fn range(&self) -> Range<usize> {
        let start = usize::from(self.offset);
        start..start + self.bytes.len()
    }
}

/// NAME-GUID[+OFFSET]=HEX: the name of the efivar file of the VarStore's variable, as the reasons
/// of unreadable values print it, then the first byte stated and the bytes.
impl FromStr for AssumedVarStore {
    type Err = AssumedVarStoreError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let syntax = || AssumedVarStoreError::Syntax(s.to_owned());
        let (key, hex) = s.rsplit_once('=').ok_or_else(syntax)?;
        let (key, offset) = match key.rsplit_once('+') {
            Some((key, offset)) if ends_in_guid(key) => (key, parse_offset(offset)?),
            Some(_) | None => (key, 0),
        };
        let split = key
            .len()
            .checked_sub(GUID_TEXT_LEN + 1)
            .ok_or_else(syntax)?;
        let (Some(name), Some("-"), Some(guid)) = (
            key.get(..split),
            key.get(split..=split),
            key.get(split + 1..),
        ) else {
            return Err(syntax());
        };
        if name.is_empty() {
            return Err(syntax());
        }
        let guid = Guid::from_str(guid).map_err(|_| AssumedVarStoreError::Guid(guid.to_owned()))?;
        let bytes = hex_bytes::<Vec<u8>>(hex)
            .filter(|bytes| !bytes.is_empty())
            .ok_or_else(|| AssumedVarStoreError::Bytes(hex.to_owned()))?;
        if usize::from(offset) + bytes.len() > PAYLOAD_LIMIT {
            return Err(AssumedVarStoreError::Size {
                offset,
                bytes: bytes.len(),
            });
        }
        let variable = VariableKey {
            name: name.to_owned(),
            guid,
        };
        Ok(Self {
            variable: efivar_file_named(variable),
            offset,
            bytes,
        })
    }
}

/// Whether `key` ends in a GUID.
fn ends_in_guid(key: &str) -> bool {
    key.len()
        .checked_sub(GUID_TEXT_LEN)
        .and_then(|start| key.get(start..))
        .is_some_and(|guid| Guid::from_str(guid).is_ok())
}

/// The OFFSET `text`: decimal digits, or hex digits after 0x.
fn parse_offset(text: &str) -> Result<u16, AssumedVarStoreError> {
    let (digits, radix) = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(digits) => (digits, 16),
        None => (text, 10),
    };
    let parsed = match digits.chars().all(|digit| digit.is_digit(radix)) {
        true => u16::from_str_radix(digits, radix).ok(),
        false => None,
    };
    parsed.ok_or_else(|| AssumedVarStoreError::Offset(text.to_owned()))
}

/// NAME-GUID+OFFSET=HEX, as FromStr reads it: the name of its efivar file, then the decimal
/// offset and two lowercase hex digits per byte.
impl fmt::Display for AssumedVarStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}+{}=", self.variable, self.offset)?;
        self.bytes
            .iter()
            .try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

/// Why check_assumed refuses a statement.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
pub(crate) enum AssumedVarStoreRefusal {
    #[error("no FormSet of this HiiDB declares a VarStore {0}")]
    Undeclared(VariableKey),
    #[error(
        "--assume-var-store states bytes {}..{} of VarStore {key} twice",
        .bytes.start,
        .bytes.end
    )]
    Twice {
        key: VariableKey,
        bytes: Range<usize>,
    },
    #[error(
        "bytes {}..{} pass the Size {size} that VarStore {key} declares",
        .bytes.start,
        .bytes.end
    )]
    PastSize {
        key: VariableKey,
        bytes: Range<usize>,
        size: u16,
    },
}

/// The refusals of check_assumed, in the order of the statements.
#[derive(Debug, Clone, Error, PartialEq, Eq)]
#[error("{}", .0.iter().map(ToString::to_string).collect::<Vec<_>>().join("; "))]
pub(crate) struct AssumedVarStoresRefused(Vec<AssumedVarStoreRefusal>);

/// Statements that check_assumed takes: no two of them state one byte.
#[derive(Debug, Clone, Copy)]
pub(crate) struct CheckedVarStores<'a>(&'a [AssumedVarStore]);

impl CheckedVarStores<'static> {
    /// Of no statement.
    pub(crate) const NONE: Self = Self(&[]);
}

#[cfg(test)]
#[cfg(efivar_dumps)]
impl<'a> CheckedVarStores<'a> {
    /// `assumed`, unchecked, for tests of VarStores that no FormSet declares.
    pub(super) fn unchecked(assumed: &'a [AssumedVarStore]) -> Self {
        Self(assumed)
    }
}

/// Refuses each of `assumed` whose VarStore no FormSet of `roots` declares as a VARSTORE or
/// VARSTORE_EFI where edk2 creates it, whose bytes pass the Size of every such declaration, or
/// whose bytes another of them states too.
pub(crate) fn check_assumed<'a, 's>(
    roots: impl IntoIterator<Item = &'a Rc<RefCell<IFROperation>>>,
    assumed: &'s [AssumedVarStore],
) -> Result<CheckedVarStores<'s>, AssumedVarStoresRefused> {
    let declared = declared_sizes(roots);
    let mut refusals = Vec::new();
    for (index, statement) in assumed.iter().enumerate() {
        let size = declared
            .iter()
            .filter(|(key, _)| *key == statement.variable)
            .map(|&(_, size)| size)
            .max();
        match size {
            None => refusals.push(AssumedVarStoreRefusal::Undeclared(
                statement.variable.clone(),
            )),
            Some(size) if statement.range().end > usize::from(size) => {
                refusals.push(AssumedVarStoreRefusal::PastSize {
                    key: statement.variable.clone(),
                    bytes: statement.range(),
                    size,
                });
            }
            Some(_) => {}
        }
        let twice = assumed
            .iter()
            .take(index)
            .filter(|earlier| earlier.variable == statement.variable)
            .filter_map(|earlier| {
                let (earlier, later) = (earlier.range(), statement.range());
                let bytes = earlier.start.max(later.start)..earlier.end.min(later.end);
                (!bytes.is_empty()).then(|| AssumedVarStoreRefusal::Twice {
                    key: statement.variable.clone(),
                    bytes,
                })
            });
        refusals.extend(twice);
    }
    match refusals.is_empty() {
        true => Ok(CheckedVarStores(assumed)),
        false => Err(AssumedVarStoresRefused(refusals)),
    }
}

/// The variable, named as its efivar file names it, and the Size of each VARSTORE and
/// VARSTORE_EFI that a FormSet of `roots` declares where edk2 creates it, as
/// find_corresponding_varstore finds those of its questions.
fn declared_sizes<'a>(
    roots: impl IntoIterator<Item = &'a Rc<RefCell<IFROperation>>>,
) -> Vec<(VariableKey, u16)> {
    let mut declared = Vec::new();
    for root in roots {
        for form_set in &root.borrow().children {
            let form_set = form_set.borrow();
            if form_set.op_code != IFROpCode::FormSet {
                continue;
            }
            form_set_list_var_stores(&form_set, |op, creation, _| {
                if *creation == Creation::Created {
                    declared.extend(declared_size(op));
                }
                None::<()>
            });
        }
    }
    declared
}

/// The variable, named as its efivar file names it, and the Size of the VARSTORE or
/// VARSTORE_EFI `op`; None for another op.
fn declared_size(op: &IFROperation) -> Option<(VariableKey, u16)> {
    let store: &dyn VariableStore = match &op.parsed_data {
        ParsedOperation::VarStore(store) => store,
        ParsedOperation::VarStoreEfi(store) => store,
        ParsedOperation::FormSet(_)
        | ParsedOperation::OneOf(_)
        | ParsedOperation::CheckBox(_)
        | ParsedOperation::OneOfOption(_)
        | ParsedOperation::VarStoreNameValue(_)
        | ParsedOperation::ShortVarStoreEfi(_)
        | ParsedOperation::DefaultStore(_)
        | ParsedOperation::IFRDefault(_)
        | ParsedOperation::Form(_)
        | ParsedOperation::Text(_)
        | ParsedOperation::Subtitle(_)
        | ParsedOperation::Numeric(_)
        | ParsedOperation::QuestionRef1(_)
        | ParsedOperation::EqIdVal(_)
        | ParsedOperation::EqIdId(_)
        | ParsedOperation::EqIdValList(_)
        | ParsedOperation::Get(_)
        | ParsedOperation::Set(_)
        | ParsedOperation::FormMap(_)
        | ParsedOperation::Date(_)
        | ParsedOperation::Time(_)
        | ParsedOperation::OrderedList(_)
        | ParsedOperation::Ref(_)
        | ParsedOperation::String(_)
        | ParsedOperation::Placeholder => return None,
    };
    Some((efivar_file_named(store.variable_key()), store.size()))
}

/// Those of `assumed` that state bytes of `store`, by the name of its efivar file; none of a
/// store whose variable holds the value of one question (VariableLayout::OneValue).
pub(super) fn statements_of<'a>(
    assumed: CheckedVarStores<'a>,
    store: &dyn VariableStore,
) -> StoreStatements<'a> {
    match store.layout() {
        VariableLayout::Offsets => {}
        VariableLayout::OneValue => return StoreStatements::default(),
    }
    let variable = efivar_file_named(store.variable_key());
    StoreStatements(
        assumed
            .0
            .iter()
            .filter(|statement| statement.variable == variable)
            .collect(),
    )
}

/// The statements of one VarStore, of CheckedVarStores.
#[derive(Debug, Default)]
pub(super) struct StoreStatements<'a>(Vec<&'a AssumedVarStore>);

impl StoreStatements<'_> {
    /// The bytes of `range` of the payload that these state, None where none of them does.
    pub(super) fn bytes(&self, range: Range<usize>) -> Vec<Option<u8>> {
        range
            .map(|at| {
                self.0.iter().find_map(|statement| {
                    let index = at.checked_sub(usize::from(statement.offset))?;
                    statement.bytes.get(index).copied()
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::super::ifr_fixtures::*;
    use super::super::storage::VariableStoreKind;
    use super::*;

    /// 11111111-1111-1111-1111-111111111111, as stored
    const MODE_GUID: [u8; 16] = [0x11; 16];
    const KEY: &str = "Mode-11111111-1111-1111-1111-111111111111";

    /// The statement of `text`.
    fn stated(text: &str) -> AssumedVarStore {
        text.parse()
            .unwrap_or_else(|error| panic!("parse {text:?}: {error}"))
    }

    /// FromStr reads NAME-GUID[+OFFSET]=HEX: the name before the last "-GUID" ahead of the
    /// last '=' or of a '+' before it, a GUID of either case, a decimal OFFSET or a hexadecimal
    /// one after 0x, and two hex digits of either case per byte, at least one; the name keeps
    /// '!' and takes '!' for '/', as its efivar file does. Display writes it back with its
    /// offset, the GUID and the digits in lowercase.
    #[test]
    fn assumed_var_store_reads_its_efivar_file_name() {
        let guid = Guid::from_str("11111111-1111-1111-1111-111111111111").expect("parse GUID");
        let taken = [
            (
                format!("{KEY}=00"),
                "Mode",
                0,
                vec![0x00],
                format!("{KEY}+0=00"),
            ),
            (
                format!("{KEY}+3=0aFF"),
                "Mode",
                3,
                vec![0x0A, 0xFF],
                format!("{KEY}+3=0aff"),
            ),
            (
                format!("{KEY}+0x1F=01"),
                "Mode",
                31,
                vec![0x01],
                format!("{KEY}+31=01"),
            ),
            (
                format!("{KEY}+0X10=01"),
                "Mode",
                16,
                vec![0x01],
                format!("{KEY}+16=01"),
            ),
            (
                "Mode-8BE4DF61-93CA-11D2-AA0D-00E098032B8C=01".to_string(),
                "Mode",
                0,
                vec![0x01],
                "Mode-8be4df61-93ca-11d2-aa0d-00e098032b8c+0=01".to_string(),
            ),
            (
                "A-b+c=d-11111111-1111-1111-1111-111111111111=01".to_string(),
                "A-b+c=d",
                0,
                vec![0x01],
                "A-b+c=d-11111111-1111-1111-1111-111111111111+0=01".to_string(),
            ),
            (
                "a!b-11111111-1111-1111-1111-111111111111+2=01".to_string(),
                "a!b",
                2,
                vec![0x01],
                "a!b-11111111-1111-1111-1111-111111111111+2=01".to_string(),
            ),
            (
                "a/b-11111111-1111-1111-1111-111111111111=01".to_string(),
                "a!b",
                0,
                vec![0x01],
                "a!b-11111111-1111-1111-1111-111111111111+0=01".to_string(),
            ),
            (
                format!("{KEY}+65535=00"),
                "Mode",
                65535,
                vec![0x00],
                format!("{KEY}+65535=00"),
            ),
        ];
        for (text, name, offset, bytes, written) in taken {
            let guid = match text.contains("8BE4DF61") {
                true => Guid::from_str("8BE4DF61-93CA-11D2-AA0D-00E098032B8C").expect("parse GUID"),
                false => guid,
            };
            let want = AssumedVarStore {
                variable: VariableKey {
                    name: name.to_string(),
                    guid,
                },
                offset,
                bytes,
            };
            assert_eq!(text.parse::<AssumedVarStore>(), Ok(want.clone()), "{text}");
            assert_eq!(want.to_string(), written, "{text}: Display");
            assert_eq!(
                written.parse::<AssumedVarStore>(),
                Ok(want),
                "{text}: Display read back"
            );
        }

        let refused = [
            (
                KEY.to_string(),
                AssumedVarStoreError::Syntax(KEY.to_string()),
            ),
            (
                format!("{KEY}=0"),
                AssumedVarStoreError::Bytes("0".to_string()),
            ),
            (
                format!("{KEY}="),
                AssumedVarStoreError::Bytes(String::new()),
            ),
            (
                format!("{KEY}=0g"),
                AssumedVarStoreError::Bytes("0g".to_string()),
            ),
            (
                format!("{KEY}+x=00"),
                AssumedVarStoreError::Offset("x".to_string()),
            ),
            (
                format!("{KEY}+=00"),
                AssumedVarStoreError::Offset(String::new()),
            ),
            (
                format!("{KEY}+0x=00"),
                AssumedVarStoreError::Offset("0x".to_string()),
            ),
            (
                format!("{KEY}+-1=00"),
                AssumedVarStoreError::Offset("-1".to_string()),
            ),
            (
                format!("{KEY}+65536=00"),
                AssumedVarStoreError::Offset("65536".to_string()),
            ),
            (
                "-11111111-1111-1111-1111-111111111111=00".to_string(),
                AssumedVarStoreError::Syntax(
                    "-11111111-1111-1111-1111-111111111111=00".to_string(),
                ),
            ),
            (
                "Mode11111111-1111-1111-1111-111111111111=00".to_string(),
                AssumedVarStoreError::Syntax(
                    "Mode11111111-1111-1111-1111-111111111111=00".to_string(),
                ),
            ),
            (
                "Mode-1111111X-2222-3333-4444-555555555555=00".to_string(),
                AssumedVarStoreError::Guid("1111111X-2222-3333-4444-555555555555".to_string()),
            ),
            (
                format!("{KEY}+65535=0000"),
                AssumedVarStoreError::Size {
                    offset: 65535,
                    bytes: 2,
                },
            ),
        ];
        for (text, want) in refused {
            assert_eq!(text.parse::<AssumedVarStore>(), Err(want), "{text}");
        }
    }

    /// FormSets declaring Mode, a 4-byte buffer VarStore, Other, a 2-byte EFI variable one, and
    /// a!b, a 1-byte buffer one, all of MODE_GUID; the second FormSet declares Mode again with 8
    /// bytes.
    fn declaring() -> [Rc<RefCell<IFROperation>>; 2] {
        [
            parse_form_set(&[
                var_store(1, MODE_GUID, "Mode", 4),
                var_store_efi_of(2, MODE_GUID, "Other", NV_BS_RT, 2),
                var_store(3, MODE_GUID, "a!b", 1),
            ]),
            parse_form_set(&[var_store(1, MODE_GUID, "Mode", 8)]),
        ]
    }

    /// check_assumed's refusals of `texts` in `roots`, as they show.
    fn refused(roots: &[Rc<RefCell<IFROperation>>], texts: &[String]) -> Result<(), String> {
        let assumed: Vec<AssumedVarStore> = texts.iter().map(|text| stated(text)).collect();
        check_assumed(roots, &assumed)
            .map(|_| ())
            .map_err(|refused| refused.to_string())
    }

    /// check_assumed takes statements of VarStores that a FormSet declares, within the greatest
    /// Size declared, and refuses, naming each in order, one of an undeclared VarStore, of a
    /// name/value one, of another name or GUID, one past every Size declared, and two whose bytes
    /// overlap, naming the bytes stated twice.
    #[test]
    fn check_assumed_refuses_what_no_var_store_takes() {
        let roots = declaring();
        let mode = |rest: &str| format!("{KEY}{rest}");
        let other = |rest: &str| format!("Other-11111111-1111-1111-1111-111111111111{rest}");
        let taken = [
            vec![],
            vec![mode("=00")],
            vec![mode("+7=00")],
            vec![mode("=0001020304050607")],
            vec![mode("=00"), mode("+1=01")],
            vec![mode("+2=0000"), mode("=0000"), other("=0000")],
            vec![other("+1=00"), mode("+1=00")],
            vec!["a/b-11111111-1111-1111-1111-111111111111=01".to_string()],
            vec!["a!b-11111111-1111-1111-1111-111111111111=01".to_string()],
        ];
        for texts in taken {
            assert_eq!(refused(&roots, &texts), Ok(()), "{texts:?}");
        }

        let refusals = [
            (
                vec!["Undeclared-00000000-0000-0000-0000-000000000001=00".to_string()],
                "no FormSet of this HiiDB declares a VarStore \
                 Undeclared-00000000-0000-0000-0000-000000000001",
            ),
            (
                vec!["Mode-22222222-2222-2222-2222-222222222222=00".to_string()],
                "no FormSet of this HiiDB declares a VarStore \
                 Mode-22222222-2222-2222-2222-222222222222",
            ),
            (
                vec!["MODE-11111111-1111-1111-1111-111111111111=00".to_string()],
                "no FormSet of this HiiDB declares a VarStore \
                 MODE-11111111-1111-1111-1111-111111111111",
            ),
            (
                vec![mode("+8=00")],
                "bytes 8..9 pass the Size 8 that VarStore \
                 Mode-11111111-1111-1111-1111-111111111111 declares",
            ),
            (
                vec![mode("+6=000000")],
                "bytes 6..9 pass the Size 8 that VarStore \
                 Mode-11111111-1111-1111-1111-111111111111 declares",
            ),
            (
                vec![other("+1=0000")],
                "bytes 1..3 pass the Size 2 that VarStore \
                 Other-11111111-1111-1111-1111-111111111111 declares",
            ),
            (
                vec![mode("=00"), mode("=01")],
                "--assume-var-store states bytes 0..1 of VarStore \
                 Mode-11111111-1111-1111-1111-111111111111 twice",
            ),
            (
                vec![mode("+1=000000"), mode("=0000")],
                "--assume-var-store states bytes 1..2 of VarStore \
                 Mode-11111111-1111-1111-1111-111111111111 twice",
            ),
            (
                vec![
                    "a/b-11111111-1111-1111-1111-111111111111=01".to_string(),
                    "a!b-11111111-1111-1111-1111-111111111111=00".to_string(),
                ],
                "--assume-var-store states bytes 0..1 of VarStore \
                 a!b-11111111-1111-1111-1111-111111111111 twice",
            ),
            (
                vec![
                    "Undeclared-00000000-0000-0000-0000-000000000001=00".to_string(),
                    mode("=00"),
                    "Undeclared-33333333-3333-3333-3333-333333333333=00".to_string(),
                    mode("+9=00"),
                    mode("=0101"),
                ],
                "no FormSet of this HiiDB declares a VarStore \
                 Undeclared-00000000-0000-0000-0000-000000000001; no FormSet of this HiiDB \
                 declares a VarStore Undeclared-33333333-3333-3333-3333-333333333333; bytes 9..10 \
                 pass the Size 8 that VarStore Mode-11111111-1111-1111-1111-111111111111 \
                 declares; --assume-var-store states bytes 0..1 of VarStore \
                 Mode-11111111-1111-1111-1111-111111111111 twice",
            ),
        ];
        for (texts, want) in refusals {
            assert_eq!(refused(&roots, &texts), Err(want.to_string()), "{texts:?}");
        }

        let name_value = parse_form_set(&[var_store_name_value(1, MODE_GUID)]);
        assert_eq!(
            refused(&[name_value], &[mode("=00")]),
            Err("no FormSet of this HiiDB declares a VarStore \
                 Mode-11111111-1111-1111-1111-111111111111"
                .to_string()),
            "a name/value VarStore of the GUID"
        );
    }

    /// check_assumed takes a VarStore where edk2 creates it: under a SUPPRESS_IF of the FormSet,
    /// or a DISABLE_IF of it whose constant condition is FALSE; not under one whose condition is
    /// TRUE or not constant.
    #[test]
    fn a_stated_var_store_counts_where_edk2_creates_it() {
        let mode = || var_store(2, MODE_GUID, "Mode", 1);
        let cases = [
            (
                "SUPPRESS_IF TRUE",
                conditional(SUPPRESS_IF, ifr_true(), &[mode()]),
                true,
            ),
            (
                "DISABLE_IF FALSE",
                conditional(DISABLE_IF, ifr_false(), &[mode()]),
                true,
            ),
            (
                "DISABLE_IF TRUE",
                conditional(DISABLE_IF, ifr_true(), &[mode()]),
                false,
            ),
            (
                "DISABLE_IF not constant",
                conditional(DISABLE_IF, eq_id_val_of(1, 0), &[mode()]),
                false,
            ),
        ];
        for (name, declaration, declares) in cases {
            let root = parse_form_set(&[declaration]);
            let checked = refused(&[root], &[format!("{KEY}=00")]).is_ok();
            assert_eq!(checked, declares, "{name}");
        }
    }

    /// A VarStore of NIL_GUID whose variable holds the value of one question.
    struct OneValueStore;

    impl VariableStore for OneValueStore {
        fn name(&self) -> String {
            "Mode".to_string()
        }

        fn guid(&self) -> Guid {
            NIL_GUID
        }

        fn size(&self) -> u16 {
            1
        }

        fn kind(&self) -> VariableStoreKind {
            VariableStoreKind::EfiVariable
        }

        fn is_runtime_accessible(&self) -> bool {
            true
        }

        fn layout(&self) -> VariableLayout {
            VariableLayout::OneValue
        }
    }

    /// StoreStatements::bytes gives each byte of a range from the statement that covers it, and
    /// None for the others; statements_of keeps those of the store, by the name of its efivar
    /// file, and none of a store whose variable holds one value.
    #[test]
    fn stated_bytes_patch_only_the_stated_offsets() {
        let nil = |name: &str, bytes: &str| {
            stated(&format!(
                "{name}-00000000-0000-0000-0000-000000000000={bytes}"
            ))
        };
        let roots = [parse_form_set(&[
            var_store(1, [0; 16], "Mode", 6),
            var_store(2, MODE_GUID, "Mode", 1),
            var_store(3, [0; 16], "Other", 1),
            var_store(4, [0; 16], "a/b", 1),
        ])];

        let assumed = [
            nil("Mode", "0a0b"),
            stated("Mode-00000000-0000-0000-0000-000000000000+5=0c"),
        ];
        let checked = check_assumed(&roots, &assumed).expect("check the statements of Mode");
        let statements = statements_of(checked, &buffer("Mode", 6));
        let cases = [
            (0..2, vec![Some(0x0A), Some(0x0B)]),
            (1..3, vec![Some(0x0B), None]),
            (2..5, vec![None, None, None]),
            (4..7, vec![None, Some(0x0C), None]),
            (
                0..6,
                vec![Some(0x0A), Some(0x0B), None, None, None, Some(0x0C)],
            ),
        ];
        for (range, want) in cases {
            assert_eq!(statements.bytes(range.clone()), want, "{range:?}");
        }

        let assumed = [
            nil("Mode", "01"),
            stated("Mode-11111111-1111-1111-1111-111111111111=02"),
            nil("Other", "03"),
            nil("a/b", "04"),
            stated("Mode-00000000-0000-0000-0000-000000000000+1=05"),
        ];
        let checked = check_assumed(&roots, &assumed).expect("check the statements of each store");
        let stores: [(&str, &dyn VariableStore, Vec<u8>); 5] = [
            ("Mode", &buffer("Mode", 2), vec![0x01, 0x05]),
            (
                "EFI variable Mode",
                &efi_variable("Mode", 2),
                vec![0x01, 0x05],
            ),
            ("a/b", &buffer("a/b", 1), vec![0x04]),
            ("a!b", &buffer("a!b", 1), vec![0x04]),
            ("one value", &OneValueStore, vec![]),
        ];
        for (name, store, want) in stores {
            let got: Vec<u8> = statements_of(checked, store)
                .0
                .iter()
                .flat_map(|statement| statement.bytes.clone())
                .collect();
            assert_eq!(got, want, "{name}");
        }
        assert!(
            statements_of(checked, &buffer("mode", 1)).0.is_empty(),
            "another case of the name"
        );
    }
}
