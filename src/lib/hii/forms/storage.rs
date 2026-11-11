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

//! The VarStores that IFR questions keep their values in, and the reads of those values from
//! the EFI variables behind them.
//!
//! The stores that a FormSet declares (UEFI 2.11 §33.3.8.3.89-§33.3.8.3.91) and the settings
//! that its questions request of each, as a forms browser builds a store's `<ConfigRequest>`
//! (edk2-stable202608 SetupBrowserDxe IfrParse.c InitializeRequestElement), without the bytes or
//! names of PASSWORD questions, which uefisettings never requests.

use std::num::NonZeroUsize;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fmt;
use std::ops::Range;
use std::rc::Rc;

use anyhow::Result;
use binrw::BinRead;
use thiserror::Error;

use super::assumed_var_store::StoreStatements;
use super::bit_field_bits;
use super::conditions::question_expression;
use super::conditions::question_value_expression;
use super::conditions::skips_questions;
use super::conditions::skips_scope;
use super::conditions::ExpressionRefusal;
use super::conditions::QuestionExpression;
use super::conditions::MAX_READ_DEPTH;
use super::defaults::question_scope;
use super::ordered_list::ListRefusal;
use super::question_values::value_question;
use super::question_values::ListedQuestion;
use super::refers_to_bit_field;
use super::storageless::NoVarStore;
use super::storageless::StoragelessRefusal;
use super::string_question::NotUcs2;
use super::time_storage::question_value;
use super::time_storage::TimeStorageUnread;
use super::walk_scopes;
use super::IFROpCode;
use super::IFROperation;
use super::NumericFormatError;
use super::ParsedOperation;
use super::TypeValue;
use super::Walk;
use super::DECLARED_BOOT_SERVICE_ONLY;
use super::EDKII_BIT_FIELD_VALUE_BITS;
use super::EDKII_IFR_NUMERIC_SIZE_BIT;
use super::EFI_IFR_NUMERIC_SIZE;
use crate::hii::config_string::Number;
use crate::hii::config_string::STRING;
use crate::hii::package::Guid;
use crate::hii::strings::ListTexts;
use crate::hii::variables::efivar_attributes;
use crate::hii::variables::EfivarRange;
use crate::hii::variables::EfivarReader;
use crate::hii::variables::EfivarsNotRead;
use crate::hii::variables::EnhancedAuthenticatedVariable;
use crate::hii::variables::VariableInterface;
use crate::hii::variables::VariableKey;
use crate::hii::variables::VariableLayout;
use crate::hii::variables::VariableNotFound;
use crate::hii::variables::VariableReach;
use crate::hii::variables::VariableSizeMismatch;
use crate::hii::variables::EFIVARFS_HEADER_SIZE;
use crate::hii::variables::EFI_VARIABLE_RUNTIME_ACCESS;

/// EFI_QF_DATE_STORAGE, QF_TIME_STORAGE and their _NORMAL values (UEFI 2.11 §33.3.8.3.11,
/// §33.3.8.3.78): only a DATE or TIME with normal storage has a VarStore setting.
const QF_STORAGE: u8 = 0x30;
const QF_STORAGE_NORMAL: u8 = 0x00;
/// sizeof(EFI_HII_DATE), sizeof(EFI_HII_TIME), sizeof(EFI_HII_REF) (UEFI 2.11 §33.3.8.3.51)
const DATE_WIDTH: usize = 4;
const TIME_WIDTH: usize = 3;
const REF_WIDTH: usize = 22;
/// The size of EFI_IFR_QUESTION_HEADER, which every question op's data starts with
const QUESTION_HEADER_SIZE: usize = 11;

pub(super) trait VariableStore {
    fn name(&self) -> String;
    fn guid(&self) -> Guid;
    fn size(&self) -> u16;
    fn kind(&self) -> VariableStoreKind;
    fn is_runtime_accessible(&self) -> bool;

    /// How its variable holds the values of its questions.
    fn layout(&self) -> VariableLayout {
        VariableLayout::Offsets
    }

    /// The attributes that set creates its missing variable with, or None where set refuses a
    /// missing variable: one that holds the values of other questions too would hold bytes that
    /// set invents.
    fn created_attributes(&self) -> Option<u32> {
        None
    }

    /// The variable that holds the values of this VarStore.
    fn variable_key(&self) -> VariableKey {
        VariableKey {
            name: self.name(),
            guid: self.guid(),
        }
    }

    /// Why variables of `reach` Runtime lack the variable of this VARSTORE_EFI, or read none, as
    /// `error`, a VariableNotFound or EfivarsNotRead, says, in the words of their `interface`: the
    /// form declares it without EFI_VARIABLE_RUNTIME_ACCESS. None for other errors, VarStores and
    /// reaches.
    fn explain_unread(
        &self,
        reach: VariableReach,
        interface: VariableInterface,
        error: &anyhow::Error,
    ) -> Option<DeclaredBootServiceOnly> {
        match reach {
            VariableReach::Runtime => {}
            VariableReach::BootServices => return None,
        }
        if self.kind() != VariableStoreKind::EfiVariable || self.is_runtime_accessible() {
            return None;
        }
        let key = self.variable_key();
        match (error.is::<VariableNotFound>(), error.is::<EfivarsNotRead>()) {
            (true, _) => Some(DeclaredBootServiceOnly::Missing { key, interface }),
            (false, true) => Some(DeclaredBootServiceOnly::NotRead { key }),
            (false, false) => None,
        }
    }
}

/// set's error for a missing variable: for variables that reach Runtime, firmware that keeps the
/// variable from the OS, e.g. boot-service-only, leaves no file to rewrite; variables that reach
/// BootServices reach every variable that the firmware has created.
#[derive(Error, Debug)]
#[error("{missing}: {}", .interface.not_found_refusal())]
pub(super) struct VariableNotExported {
    pub(super) missing: VariableNotFound,
    pub(super) interface: VariableInterface,
}

impl VariableNotExported {
    /// Turns the VariableNotFound of FirmwareVariables of `reach` and `interface` for the variable
    /// of `store` into the DeclaredBootServiceOnly of VariableStore::explain_unread, if any, else
    /// into VariableNotExported; other errors pass through unchanged.
    pub(super) fn explain(
        error: anyhow::Error,
        store: &dyn VariableStore,
        reach: VariableReach,
        interface: VariableInterface,
    ) -> anyhow::Error {
        if let Some(declared) = store.explain_unread(reach, interface, &error) {
            return declared.into();
        }
        match error.downcast::<VariableNotFound>() {
            Ok(missing) => Self { missing, interface }.into(),
            Err(error) => error,
        }
    }
}

/// A variable that variables at OS runtime lack or did not read, whose form declares it
/// boot-service-only: set's error and get's reason, in one text.
#[derive(Error, Debug)]
pub(super) enum DeclaredBootServiceOnly {
    /// VariableNotFound
    #[error(
        "EFI variable {key} is not present at OS runtime: {}, and its form declares it {}",
        .interface.absence(),
        DECLARED_BOOT_SERVICE_ONLY
    )]
    Missing {
        key: VariableKey,
        interface: VariableInterface,
    },
    /// EfivarsNotRead
    #[error(
        "{}; the form declares EFI variable {key} {}",
        EfivarsNotRead,
        DECLARED_BOOT_SERVICE_ONLY
    )]
    NotRead { key: VariableKey },
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(super) enum VariableStoreKind {
    Buffer,
    EfiVariable,
}

/// The Name and Guid of a VarStore, which name its variable whatever its kind.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub(super) struct VarStoreVariable {
    pub(super) name: &'static str,
    pub(super) guid: Guid,
}

impl VarStoreVariable {
    pub(super) fn identifies(self, store: &dyn VariableStore) -> bool {
        store.guid() == self.guid && store.name() == self.name
    }
}

#[cfg(test)]
#[cfg(efivar_dumps)]
mod non_efi_varstore_tests {
    use std::cell::RefCell;
    use std::path::Path;
    use std::rc::Rc;

    use super::super::conditions::StateEvaluation;
    use super::super::find_corresponding_varstore;
    use super::super::ifr_fixtures::*;
    use super::super::set::VarStoreWrite;
    use super::super::AnswerOption;
    use super::super::ParsedOperation;
    use super::super::QuestionDescriptor;
    use super::super::QuestionFlags;
    use super::super::QuestionIdentity;
    use super::super::RangeType;
    use super::super::TextInput;
    use super::super::TypeValue;
    use super::super::DUMMY_OPCODE;
    use super::*;
    use crate::efi_variables::enhanced_authenticated::fixture::nonce_metadata;
    use crate::efi_variables::enhanced_authenticated::fixture::nonce_metadata_of;
    use crate::efi_variables::enhanced_authenticated::fixture::timestamp_metadata;
    use crate::hii::variables::tests::EFI_GLOBAL_VARIABLE;
    use crate::hii::variables::EfivarFileName;
    use crate::hii::variables::FirmwareVariables;
    use crate::hii::variables::UnreadVariables;
    use crate::hii::variables::VolatileVariable;

    /// get's and set's text for TestVarStore, which variables that reach Runtime lack, and whose
    /// form declares it boot-service-only.
    const NOT_PRESENT: &str = "EFI variable TestVarStore-00000000-0000-0000-0000-000000000000 is \
        not present at OS runtime: efivarfs does not list it, and its form declares it \
        boot-service-only (no EFI_VARIABLE_RUNTIME_ACCESS)";
    /// NOT_PRESENT for variables through the firmware environment calls.
    const WINDOWS_NOT_PRESENT: &str = "EFI variable \
        TestVarStore-00000000-0000-0000-0000-000000000000 is not present at OS runtime: \
        GetFirmwareEnvironmentVariableExW does not find it, and its form declares it \
        boot-service-only (no EFI_VARIABLE_RUNTIME_ACCESS)";
    /// get's text for TestVarStore without efivars, where its form declares it
    /// boot-service-only.
    const DECLARED_NOT_READ: &str = "EFI variables not read; the form declares EFI variable \
        TestVarStore-00000000-0000-0000-0000-000000000000 boot-service-only \
        (no EFI_VARIABLE_RUNTIME_ACCESS)";

    struct TestVariableStore {
        kind: VariableStoreKind,
    }

    impl VariableStore for TestVariableStore {
        fn name(&self) -> String {
            "TestVarStore".to_string()
        }

        fn guid(&self) -> Guid {
            NIL_GUID
        }

        fn size(&self) -> u16 {
            1
        }

        fn kind(&self) -> VariableStoreKind {
            self.kind
        }

        fn is_runtime_accessible(&self) -> bool {
            self.kind == VariableStoreKind::EfiVariable
        }
    }

    fn efi_varstore(attributes: u32) -> VarStoreEfi {
        VarStoreEfi {
            var_store_id: 1,
            guid: Guid {
                data1: 0,
                data2: 0,
                data3: 0,
                data4: [0; 8],
            },
            attributes,
            size: 1,
            name: "TestVarStore".into(),
        }
    }

    /// read_current_value_bytes of `store` with a fresh EfivarReader of `efivars`.
    fn read(
        store: impl VariableStore + 'static,
        efivars: &Efivars,
    ) -> std::result::Result<Vec<u8>, String> {
        // these tests check reasons, which no value range changes
        read_current_value_bytes(&Ok(Box::new(store)), 0..1, &mut efivars.reader())
            .map(<[u8]>::to_vec)
            .map_err(|reason| reason.to_answer())
    }

    /// get shows a missing variable of a VARSTORE_EFI without EFI_VARIABLE_RUNTIME_ACCESS as not
    /// present at OS runtime, naming the declaration, and that of a VARSTORE_EFI with it as
    /// missing.
    #[test]
    fn missing_variable_of_a_boot_service_only_form_is_not_present_at_os_runtime() {
        let cases = [
            (0x2, format!("<ValueUnavailable: {NOT_PRESENT}>")),
            (0x3, format!("<ValueUnavailable: {NOT_PRESENT}>")),
            (
                0x7,
                "<ValueUnavailable: no EFI variable \
                 TestVarStore-00000000-0000-0000-0000-000000000000>"
                    .to_string(),
            ),
        ];
        for (attributes, want) in cases {
            assert_eq!(
                read(efi_varstore(attributes), &Efivars::new()),
                Err(want),
                "attributes {attributes:#x}"
            );
        }
    }

    /// Without efivars, get names the boot-service-only declaration of a VARSTORE_EFI for
    /// variables that reach Runtime, as those of EfivarSource::Disabled do, also through the
    /// firmware environment calls, and shows another VARSTORE_EFI, or any for variables that reach
    /// BootServices, as not read.
    #[test]
    fn unread_variable_of_a_boot_service_only_form_falls_back_to_the_form() {
        let declared = format!("<ValueUnavailable: {DECLARED_NOT_READ}>");
        let not_read = "<ValueUnavailable: EFI variables not read>".to_string();
        let unread = |reach, interface| {
            EfivarReader::with_variables(Box::new(UnreadVariables { reach, interface }))
        };
        let firmware_environment = || {
            unread(
                VariableReach::Runtime,
                VariableInterface::FirmwareEnvironment,
            )
        };
        let variable_services = || {
            unread(
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            )
        };
        let cases = [
            ("Disabled", disabled_reader(), NV_BS, declared.clone()),
            ("Disabled", disabled_reader(), NV_BS_RT, not_read.clone()),
            (
                "FirmwareEnvironment",
                firmware_environment(),
                NV_BS,
                declared,
            ),
            (
                "FirmwareEnvironment",
                firmware_environment(),
                NV_BS_RT,
                not_read.clone(),
            ),
            (
                "VariableServices",
                variable_services(),
                NV_BS,
                not_read.clone(),
            ),
            ("VariableServices", variable_services(), NV_BS_RT, not_read),
        ];
        for (variables, mut reader, attributes, want) in cases {
            let without = read_current_value_bytes(
                &Ok(Box::new(efi_varstore(attributes))),
                0..1,
                &mut reader,
            )
            .map(<[u8]>::to_vec)
            .map_err(|reason| reason.to_answer());

            assert_eq!(
                without,
                Err(want),
                "{variables} variables, attributes {attributes:#x}"
            );
        }
    }

    /// get reads the variable of a VARSTORE_EFI that variables reaching Runtime hold, through
    /// efivarfs or the firmware environment calls, whatever runtime access the form declares:
    /// firmware may give an NV|BS VarStore's variable runtime access, as firmware whose EDK2 gives
    /// every non-volatile variable runtime access does.
    #[test]
    fn present_variable_of_a_boot_service_only_form_is_read() {
        for interface in [
            VariableInterface::Efivarfs,
            VariableInterface::FirmwareEnvironment,
        ] {
            for declared in [NV_BS, NV_BS_RT] {
                let variables = MemoryVariables::new(VariableReach::Runtime, interface);
                variables.insert(variable_key("TestVarStore"), NV_BS_RT, &[1]);
                let mut reader = EfivarReader::with_variables(Box::new(variables));

                assert_eq!(
                    read_current_value_bytes(
                        &Ok(Box::new(efi_varstore(declared))),
                        0..1,
                        &mut reader
                    )
                    .map(<[u8]>::to_vec)
                    .map_err(|reason| reason.to_answer()),
                    Ok(efivar_file_bytes(NV_BS_RT, &[1])),
                    "{interface:?}, VarStore attributes {declared:#x}, efivar attributes 0x7"
                );
            }
        }
    }

    /// Writes 1 at offset 0 of `store`, as set does, in `variables`.
    fn write_one(store: &VarStoreEfi, variables: &MemoryVariables) -> Result<()> {
        VarStoreWrite::new(store, 0, 1, TypeValue::NumSize8(1), variables.interface())?
            .write(variables)
    }

    /// MemoryVariables holding TestVarStore: NV_BS_RT, then 0.
    fn test_var_store_variables() -> MemoryVariables {
        let variables = MemoryVariables::default();
        variables.insert(variable_key("TestVarStore"), NV_BS_RT, &[0]);
        variables
    }

    /// get shows a missing variable of a boot-service-only form by the text of set's refusal of
    /// it, in the words of the variables' interface.
    #[test]
    fn boot_service_only_text_is_shared_by_get_and_set() {
        for (interface, want) in [
            (VariableInterface::Efivarfs, NOT_PRESENT),
            (VariableInterface::FirmwareEnvironment, WINDOWS_NOT_PRESENT),
        ] {
            let variables = Rc::new(MemoryVariables::new(VariableReach::Runtime, interface));
            let mut reader = EfivarReader::with_variables(Box::new(Rc::clone(&variables)));

            let refusal = write_one(&efi_varstore(NV_BS), &variables)
                .expect_err("write a missing variable")
                .to_string();
            let read =
                read_current_value_bytes(&Ok(Box::new(efi_varstore(NV_BS))), 0..1, &mut reader)
                    .map(<[u8]>::to_vec)
                    .map_err(|reason| reason.to_answer());

            assert_eq!(refusal, want, "{interface:?}: set");
            assert_eq!(
                read,
                Err(format!("<ValueUnavailable: {refusal}>")),
                "{interface:?}: get"
            );
        }
    }

    /// set writes the variable of a boot-service-only form that has
    /// EFI_VARIABLE_RUNTIME_ACCESS, and keeps the variable's attributes.
    #[test]
    fn present_variable_of_a_boot_service_only_form_is_written() {
        for attributes in [0x2, 0x3] {
            let variables = test_var_store_variables();

            assert_eq!(
                write_one(&efi_varstore(attributes), &variables).map_err(|error| error.to_string()),
                Ok(()),
                "write, attributes {attributes:#x}"
            );
            assert_eq!(
                variables.writes_to(&variable_key("TestVarStore")),
                [(0, vec![1])],
                "writes, attributes {attributes:#x}"
            );
            assert_eq!(
                variables.bytes(&variable_key("TestVarStore")),
                Some(efivar_file_bytes(NV_BS_RT, &[1])),
                "variable, attributes {attributes:#x}"
            );
        }
    }

    /// Variables of every reach and interface read and write the variable of an NV|BS VARSTORE_EFI
    /// where it exists, as only choice_for_set refuses a write by the variable's own attributes.
    /// Where it is missing, variables that reach Runtime name the form's declaration, whatever
    /// their interface.
    #[test]
    fn boot_service_only_form_decides_only_for_a_missing_variable() {
        let missing = |text: &str| Err(format!("<ValueUnavailable: {text}>"));
        let get_variable_not_present = "EFI variable \
            TestVarStore-00000000-0000-0000-0000-000000000000 is not present at OS runtime: \
            GetVariable() does not find it, and its form declares it boot-service-only (no \
            EFI_VARIABLE_RUNTIME_ACCESS)";
        let present = |reach, interface| {
            (
                reach,
                interface,
                Some(NV_BS),
                Ok(efivar_file_bytes(NV_BS, &[0])),
                Ok(()),
                vec![(0, vec![1])],
            )
        };
        let cases = [
            present(
                VariableReach::BootServices,
                VariableInterface::VariableServices,
            ),
            present(VariableReach::Runtime, VariableInterface::Efivarfs),
            present(
                VariableReach::Runtime,
                VariableInterface::FirmwareEnvironment,
            ),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
                None,
                missing("no EFI variable TestVarStore-00000000-0000-0000-0000-000000000000"),
                Err(
                    "no EFI variable TestVarStore-00000000-0000-0000-0000-000000000000: the \
                     firmware has not created it, and set creates only the per-question \
                     variables of an EFI_IFR_VARSTORE_EFI before UEFI 2.3.1"
                        .to_string(),
                ),
                vec![],
            ),
            (
                VariableReach::Runtime,
                VariableInterface::Efivarfs,
                None,
                missing(NOT_PRESENT),
                Err(NOT_PRESENT.to_string()),
                vec![],
            ),
            (
                VariableReach::Runtime,
                VariableInterface::FirmwareEnvironment,
                None,
                missing(WINDOWS_NOT_PRESENT),
                Err(WINDOWS_NOT_PRESENT.to_string()),
                vec![],
            ),
            (
                VariableReach::BootServices,
                VariableInterface::Efivarfs,
                None,
                missing("no EFI variable TestVarStore-00000000-0000-0000-0000-000000000000"),
                Err(
                    "no EFI variable TestVarStore-00000000-0000-0000-0000-000000000000: the \
                     firmware has not created it or does not expose it to the OS, so its \
                     questions cannot be set from Linux; change them in the firmware setup, or \
                     ask the board vendor for firmware that exposes it; see \
                     https://github.com/linuxboot/uefisettings/issues/2"
                        .to_string(),
                ),
                vec![],
            ),
            (
                VariableReach::Runtime,
                VariableInterface::VariableServices,
                None,
                missing(get_variable_not_present),
                Err(get_variable_not_present.to_string()),
                vec![],
            ),
        ];

        for (reach, interface, attributes, read_outcome, write_outcome, writes) in cases {
            let variables = Rc::new(MemoryVariables::new(reach, interface));
            if let Some(attributes) = attributes {
                variables.insert(variable_key("TestVarStore"), attributes, &[0]);
            }
            let mut reader = EfivarReader::with_variables(Box::new(Rc::clone(&variables)));
            let case = format!("{reach:?}, {interface:?}, variable attributes {attributes:?}");

            let read =
                read_current_value_bytes(&Ok(Box::new(efi_varstore(NV_BS))), 0..1, &mut reader)
                    .map(<[u8]>::to_vec)
                    .map_err(|reason| reason.to_answer());
            let written =
                write_one(&efi_varstore(NV_BS), &variables).map_err(|error| error.to_string());

            assert_eq!(read, read_outcome, "{case}: read");
            assert_eq!(written, write_outcome, "{case}: write");
            assert_eq!(
                variables.reads(),
                [(variable_key("TestVarStore"), 1)],
                "{case}: reads"
            );
            assert_eq!(
                variables.writes_to(&variable_key("TestVarStore")),
                writes,
                "{case}: writes"
            );
        }
    }

    /// Variables that reach BootServices keep set's check of the attributes that the variable
    /// itself has: a volatile one stays unwritten.
    #[test]
    fn boot_services_refuse_a_volatile_variable() {
        let variables = MemoryVariables::new(
            VariableReach::BootServices,
            VariableInterface::VariableServices,
        );
        variables.insert(variable_key("TestVarStore"), BS_RT, &[0]);

        let error =
            write_one(&efi_varstore(NV_BS_RT), &variables).expect_err("write a volatile variable");

        assert!(
            error.downcast_ref::<VolatileVariable>().is_some(),
            "{error:#} is not VolatileVariable"
        );
        assert_eq!(
            variables.writes_to(&variable_key("TestVarStore")),
            [],
            "writes"
        );
    }

    /// get decodes no value from a variable with EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS whose
    /// data ends inside the metadata it starts with (UEFI 2.10 §8.2.1). The other authenticated
    /// accesses put their descriptors only into writes, so those variables decode as others do.
    #[test]
    fn enhanced_authenticated_variable_without_metadata_is_not_decoded() {
        let store = || efi_variable("Signed", 1);
        let efivars = Efivars::new();
        efivars.write_attributed(&store(), NV_BS_RT | 0x80, &[1]);

        assert_eq!(
            read(store(), &efivars),
            Err(
                "<ValueUnavailable: EFI variable Signed-00000000-0000-0000-0000-000000000000 \
                 has enhanced authenticated access (attributes 0x87), whose metadata \
                 uefisettings refuses: its 1 bytes of data end inside its metadata>"
                    .to_string()
            ),
            "attributes 0x87"
        );
        for attributes in [
            NV_BS_RT,
            NV_BS_RT | 0x08,
            NV_BS_RT | 0x10,
            NV_BS_RT | 0x20,
            NV_BS_RT | 0x40,
        ] {
            let efivars = Efivars::new();
            efivars.write_attributed(&store(), attributes, &[1]);

            assert_eq!(
                read(store(), &efivars),
                Ok(efivar_file_bytes(attributes, &[1])),
                "attributes {attributes:#x}"
            );
        }
    }

    /// `metadata` followed by a value byte.
    fn with_value(metadata: Vec<u8>) -> Vec<u8> {
        [metadata, vec![0x2A]].concat()
    }

    /// `metadata` with the byte at each offset of `bytes` replaced.
    fn changed(mut metadata: Vec<u8>, bytes: &[(usize, u8)]) -> Vec<u8> {
        for &(offset, byte) in bytes {
            metadata[offset] = byte;
        }
        metadata
    }

    /// get decodes the value of a variable with EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS
    /// behind its metadata of either Type, also where its NONCE needs padding before the 4-byte
    /// aligned CERT_ID (UEFI 2.11 §2.3.1), and with the smallest NonceSize, 1 (§8.2.3), for
    /// VarStores shorter and longer than EFI_VARIABLE_AUTHENTICATION_3.
    #[test]
    fn enhanced_authenticated_variable_decodes_behind_its_metadata() {
        for (name, metadata) in [
            ("timestamp", timestamp_metadata()),
            ("nonce", nonce_metadata()),
            (
                "nonce of 5 bytes, padded",
                nonce_metadata_of(&[0xA5; 5], &[0; 3], 64),
            ),
            (
                "nonce of 1 byte, padded",
                nonce_metadata_of(&[0xA5], &[0; 3], 60),
            ),
        ] {
            for size in [1, 16] {
                let store = || efi_variable("Signed", size);
                let efivars = Efivars::new();
                let value: Vec<u8> = (0x40..).take(size).collect();
                efivars.write_attributed(
                    &store(),
                    NV_BS_RT | 0x80,
                    &[&metadata[..], &value].concat(),
                );

                assert_eq!(
                    read(store(), &efivars),
                    Ok(efivar_file_bytes(NV_BS_RT | 0x80, &value)),
                    "{name}, VarStore of {size} bytes"
                );
            }
        }
    }

    /// get refuses the metadata of a variable with EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS,
    /// naming the check it fails, and so decodes no value from it.
    #[test]
    fn enhanced_authenticated_variable_with_bad_metadata_is_not_decoded() {
        // packed, without the padding of natural alignment: the Flags check refuses it, as it
        // reads the Year of EFI_TIME into Flags (0x7ea0000), not a check of the layout
        let packed = [
            &[1, 1][..],
            &63u32.to_le_bytes(),
            &0u32.to_le_bytes(),
            &[0xEA, 0x07, 11, 6, 12, 0, 0, 0],
            &[0; 8],
            &[1],
            &32u32.to_le_bytes(),
            &(0..32).collect::<Vec<u8>>(),
        ]
        .concat();
        let cases = [
            (
                "Version",
                NV_BS_RT | 0x80,
                with_value(changed(timestamp_metadata(), &[(0, 2)])),
                "EFI_VARIABLE_AUTHENTICATION_3 Version 2, not 1",
            ),
            (
                "Type",
                NV_BS_RT | 0x80,
                with_value(changed(timestamp_metadata(), &[(1, 3)])),
                "EFI_VARIABLE_AUTHENTICATION_3 Type 3, neither TIMESTAMP (1) nor NONCE (2)",
            ),
            (
                "Flags",
                NV_BS_RT | 0x80,
                with_value(changed(timestamp_metadata(), &[(8, 1)])),
                "EFI_VARIABLE_AUTHENTICATION_3 Flags 0x1: all flags are reserved on GetVariable()",
            ),
            (
                "Nanosecond",
                NV_BS_RT | 0x80,
                with_value(changed(timestamp_metadata(), &[(20, 1)])),
                "its TimeStamp has a nonzero Pad1, Nanosecond, TimeZone, Daylight or Pad2",
            ),
            (
                "NonceSize",
                NV_BS_RT | 0x80,
                with_value(changed(nonce_metadata(), &[(12, 0)])),
                "EFI_VARIABLE_AUTHENTICATION_3_NONCE NonceSize 0",
            ),
            (
                "nonce of 5 bytes, unpadded",
                NV_BS_RT | 0x80,
                with_value(nonce_metadata_of(&[0xA5; 5], &[], 61)),
                "nonzero padding between EFI_VARIABLE_AUTHENTICATION_3_NONCE and \
                 EFI_VARIABLE_AUTHENTICATION_3_CERT_ID",
            ),
            (
                "CERT_ID Type",
                NV_BS_RT | 0x80,
                with_value(changed(timestamp_metadata(), &[(28, 2)])),
                "EFI_VARIABLE_AUTHENTICATION_3_CERT_ID Type 2, not CERT_ID_SHA256 (1)",
            ),
            (
                "IdSize",
                NV_BS_RT | 0x80,
                with_value(changed(timestamp_metadata(), &[(32, 31)])),
                "EFI_VARIABLE_AUTHENTICATION_3_CERT_ID IdSize 31, not 32",
            ),
            (
                "MetadataSize",
                NV_BS_RT | 0x80,
                with_value(changed(timestamp_metadata(), &[(4, 67)])),
                "MetadataSize 67, but its descriptors end at byte 68",
            ),
            (
                "MetadataSize larger",
                NV_BS_RT | 0x80,
                with_value(changed(timestamp_metadata(), &[(4, 72)])),
                "MetadataSize 72, but its descriptors end at byte 68",
            ),
            (
                "packed",
                NV_BS_RT | 0x80,
                with_value(packed),
                "EFI_VARIABLE_AUTHENTICATION_3 Flags 0x7ea0000: all flags are reserved on \
                 GetVariable()",
            ),
            (
                "truncated",
                NV_BS_RT | 0x80,
                timestamp_metadata()[..60].to_vec(),
                "its 60 bytes of data end inside its metadata",
            ),
            (
                "time-based too",
                NV_BS_RT | 0xA0,
                with_value(timestamp_metadata()),
                "it also has EFI_VARIABLE_TIME_BASED_AUTHENTICATED_WRITE_ACCESS, which \
                 SetVariable() refuses with it (UEFI 2.11 section 8.2.3)",
            ),
        ];
        for (name, attributes, data, reason) in cases {
            let store = || efi_variable("Signed", 1);
            let efivars = Efivars::new();
            efivars.write_attributed(&store(), attributes, &data);

            assert_eq!(
                read(store(), &efivars),
                Err(format!(
                    "<ValueUnavailable: EFI variable Signed-00000000-0000-0000-0000-000000000000 \
                     has enhanced authenticated access (attributes {attributes:#x}), whose \
                     metadata uefisettings refuses: {reason}>"
                )),
                "{name}"
            );
        }
    }

    /// set writes a runtime VarStore in its variable.
    #[test]
    fn runtime_varstore_is_written() {
        for attributes in [0x6, 0x7] {
            let variables = test_var_store_variables();

            write_one(&efi_varstore(attributes), &variables)
                .unwrap_or_else(|error| panic!("write attributes {attributes:#x}: {error:#}"));

            assert_eq!(
                variables.writes_to(&variable_key("TestVarStore")),
                [(0, vec![1])],
                "writes, attributes {attributes:#x}"
            );
        }
    }

    #[test]
    fn volatile_efivar_is_read() {
        let efivars = Efivars::new();
        let store = efi_variable("Volatile", 1);
        efivars.write_attributed(&store, BS_RT, &[1]);

        assert_eq!(
            read(store, &efivars),
            Ok(efivar_file_bytes(BS_RT, &[1])),
            "efivar file with attributes BS_RT"
        );
    }

    #[test]
    fn efi_varstore_runtime_access_does_not_require_nonvolatile_storage() {
        for attributes in [0x6, 0x7] {
            let varstore = efi_varstore(attributes);

            assert_eq!(varstore.kind(), VariableStoreKind::EfiVariable);
            assert!(varstore.is_runtime_accessible());
        }
    }

    #[test]
    fn short_efivar_file_is_a_read_error() {
        let efivars = Efivars::new();
        efivars.write(&efi_variable("Short", 2), &[1]);
        let want = format!(
            "<VStoreError: failed to read efivar file '{}': failed to fill whole buffer>",
            efivars
                .path()
                .join("Short-00000000-0000-0000-0000-000000000000")
                .display()
        );

        for store in [efi_variable("Short", 2), buffer("Short", 2)] {
            let kind = store.kind;
            assert_eq!(read(store, &efivars), Err(want.clone()), "{kind:?}");
        }
    }

    #[test]
    fn efi_varstore_without_efivar_file_is_unavailable() {
        let store = VarStoreEfi {
            var_store_id: 1,
            guid: EFI_GLOBAL_VARIABLE,
            attributes: 0x7,
            size: 1,
            name: "Missing".into(),
        };

        assert_eq!(
            read(store, &Efivars::new()),
            Err(
                "<ValueUnavailable: no EFI variable Missing-8be4df61-93ca-11d2-aa0d-00e098032b8c>"
                    .to_string()
            ),
            "runtime EFI variable without an efivar file"
        );
    }

    #[test]
    fn not_found_read_error_is_not_a_missing_variable() {
        let error = anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::NotFound))
            .context("failed to read bytes");

        assert_eq!(
            ValueUnavailable::from_read_error(VariableStoreKind::Buffer, &error).to_answer(),
            "<VStoreError: failed to read bytes: entity not found>",
            "a NotFound io::Error under a context"
        );
    }

    /// to_answer gives each reason the text that get shows for it.
    #[test]
    fn to_answer_gives_each_reason_the_text_get_shows() {
        let name = variable_key("Setup");
        let cases = [
            (
                ValueUnavailable::NoVarStore("varstore not found because we reached root".into()),
                "<ValueUnavailable: varstore not found because we reached root>",
            ),
            (
                ValueUnavailable::DeclaredBootServiceOnly(DeclaredBootServiceOnly::Missing {
                    key: name.clone(),
                    interface: VariableInterface::Efivarfs,
                }),
                "<ValueUnavailable: EFI variable Setup-00000000-0000-0000-0000-000000000000 is not \
                 present at OS runtime: efivarfs does not list it, and its form declares it \
                 boot-service-only (no EFI_VARIABLE_RUNTIME_ACCESS)>",
            ),
            (
                ValueUnavailable::DeclaredBootServiceOnly(DeclaredBootServiceOnly::Missing {
                    key: name.clone(),
                    interface: VariableInterface::FirmwareEnvironment,
                }),
                "<ValueUnavailable: EFI variable Setup-00000000-0000-0000-0000-000000000000 is not \
                 present at OS runtime: GetFirmwareEnvironmentVariableExW does not find it, and \
                 its form declares it boot-service-only (no EFI_VARIABLE_RUNTIME_ACCESS)>",
            ),
            (
                ValueUnavailable::DeclaredBootServiceOnly(DeclaredBootServiceOnly::NotRead {
                    key: name.clone(),
                }),
                "<ValueUnavailable: EFI variables not read; the form declares EFI variable \
                 Setup-00000000-0000-0000-0000-000000000000 boot-service-only \
                 (no EFI_VARIABLE_RUNTIME_ACCESS)>",
            ),
            (
                ValueUnavailable::NotRead(EfivarsNotRead),
                "<ValueUnavailable: EFI variables not read>",
            ),
            (
                ValueUnavailable::Missing(VariableNotFound(name.clone())),
                "<ValueUnavailable: no EFI variable Setup-00000000-0000-0000-0000-000000000000>",
            ),
            (
                ValueUnavailable::MissingBuffer(VariableNotFound(name)),
                "<ValueUnavailable: no EFI variable Setup-00000000-0000-0000-0000-000000000000; \
                 HII buffer varstore requires EFI_HII_CONFIG_ACCESS_PROTOCOL>",
            ),
            (
                ValueUnavailable::ReadError("failed to read bytes: entity not found".into()),
                "<VStoreError: failed to read bytes: entity not found>",
            ),
            (
                ValueUnavailable::BitField(NumericFormatError::BitFieldWidth(33)),
                "<ValueUnavailable: EDKII bit-field width 33, not 1 to 32>",
            ),
            (
                ValueUnavailable::NotDecoded(IFROpCode::FormSet),
                "<ValueUnavailable: EFI_IFR_FORM_SET value not decoded>",
            ),
            (
                ValueUnavailable::Truncated { offset: 3, len: 8 },
                "<ExtractEFIDataError: failed to fill whole buffer (offset: 3; buflen: 8)>",
            ),
            (
                ValueUnavailable::CheckboxOverByte(256),
                "<ValueUnavailable: CHECKBOX value 256 over a byte>",
            ),
            (
                ValueUnavailable::AmiAccessLevel(Box::new(ValueUnavailable::NotRead(
                    EfivarsNotRead,
                ))),
                "<ValueUnavailable: EFI variables not read; the AMI setup browser keeps its \
                 access level there (0 Administrator, 1 User); \
                 --access-level administrator|user states one>",
            ),
            (
                ValueUnavailable::AmiAccessLevel(Box::new(ValueUnavailable::ReadError(
                    "failed to read bytes: entity not found".into(),
                ))),
                "<VStoreError: failed to read bytes: entity not found; the AMI setup browser \
                 keeps its access level there (0 Administrator, 1 User); \
                 --access-level administrator|user states one>",
            ),
        ];
        for (reason, want) in cases {
            assert_eq!(reason.to_answer(), want, "{reason:?}");
        }
    }

    #[test]
    fn buffer_varstore_with_efivarfs_backing_is_read() {
        let efivars = Efivars::new();
        let store = buffer("Buffer", 1);
        efivars.write(&store, &[1]);

        assert_eq!(
            read(store, &efivars),
            Ok(efivarfs_bytes(&[1])),
            "buffer VarStore with an efivar file"
        );
    }

    #[test]
    fn buffer_varstore_without_efivarfs_backing_names_the_missing_variable() {
        assert_eq!(
            read(buffer("Buffer", 1), &Efivars::new()),
            Err("<ValueUnavailable: no EFI variable \
                 Buffer-00000000-0000-0000-0000-000000000000; \
                 HII buffer varstore requires EFI_HII_CONFIG_ACCESS_PROTOCOL>"
                .to_string()),
            "buffer VarStore without an efivar file"
        );
    }

    #[test]
    fn crafted_varstore_name_stays_in_efivarfs() {
        /// A directory of efivar files: efivarfs, or a copy of it
        const EFIVARS_DIR: &str = "efivars";
        for name in ["../T/ou", "/etc/passwd", "a/b", ".."] {
            let var_store = VarStore {
                guid: NIL_GUID,
                var_store_id: 1,
                size: 1,
                name: name.into(),
            };
            let var_store_efi = VarStoreEfi {
                var_store_id: 1,
                guid: NIL_GUID,
                attributes: 0x7,
                size: 1,
                name: name.into(),
            };
            for file_name in [
                EfivarFileName::from(&var_store.variable_key()),
                EfivarFileName::from(&var_store_efi.variable_key()),
            ] {
                let path = Path::new(EFIVARS_DIR).join(file_name);
                assert_eq!(
                    path.parent(),
                    Some(Path::new(EFIVARS_DIR)),
                    "VarStore name {name:?}"
                );
            }
        }
    }

    /// An op on VarStoreId 0 whose value uefisettings does not decode has no classification.
    #[test]
    fn op_without_a_decoded_value_on_var_store_0_names_its_op_code() {
        let node = Rc::new(RefCell::new(IFROperation {
            op_code: IFROpCode::Unknown(DUMMY_OPCODE),
            length: 0,
            open_scope: false,
            data: Vec::new(),
            parent: None,
            children: Vec::new(),
            parsed_data: ParsedOperation::Placeholder,
            header_past_length: Vec::new(),
        }));

        let error = find_corresponding_varstore(node, 0).err().unwrap();
        assert_eq!(
            error.to_string(),
            "an unknown IFR opcode has VarStoreId 0 and no value that uefisettings decodes"
        );
    }

    #[test]
    fn change_value_allows_buffer_varstore_with_efivarfs_backing() {
        let question = QuestionDescriptor {
            question: "SHA-1 PCR Bank".to_string(),
            help: String::new(),
            value: "Disabled".to_string(),
            input: TextInput::Maximum(RangeType::NumSize8(1)),
            opcode: IFROpCode::OneOf,
            flags: QuestionFlags::empty(),
            defaults: Vec::new(),
            identity: QuestionIdentity {
                question_id: 1,
                form_set: None,
                keywords: Vec::new(),
            },
            possible_options: vec![AnswerOption {
                value: "Enabled".to_string(),
                texts: vec![(Language(b"en-US".to_vec()), "Enabled".to_string())],
                value_type: super::super::EFI_IFR_TYPE_NUM_SIZE_8,
                raw_value: Ok(TypeValue::NumSize8(1)),
                source: ValueSource::Current,
                state: StateEvaluation::selectable(),
            }],
            varstore: Ok(Box::new(TestVariableStore {
                kind: VariableStoreKind::Buffer,
            })),
            location: ValueLocation::Bytes { offset: 0, size: 1 },
            value_state: StateEvaluation::selectable(),
            value_source: ValueSource::Current,
            node: Rc::new(RefCell::new(IFROperation {
                op_code: IFROpCode::OneOf,
                length: 0,
                open_scope: false,
                data: Vec::new(),
                parent: None,
                children: Vec::new(),
                parsed_data: ParsedOperation::Placeholder,
                header_past_length: Vec::new(),
            })),
            driver_held: None,
        };

        let variables = test_var_store_variables();

        change_value(&question, "Enabled", &variables).expect("set the buffer VarStore");

        assert_eq!(
            variables.writes_to(&variable_key("TestVarStore")),
            [(0, vec![1])],
            "writes"
        );
    }
}

impl EfivarRange {
    /// The efivar bytes that hold the value of `store`.
    pub(super) fn of(store: &dyn VariableStore) -> Self {
        Self {
            key: store.variable_key(),
            size: store.size(),
            layout: store.layout(),
        }
    }
}

impl EfivarReader {
    /// Why a read of the efivar of `store` failed, if one did.
    pub(super) fn read_error(&self, store: &dyn VariableStore) -> Option<&anyhow::Error> {
        self.outcomes.get(&EfivarRange::of(store))?.as_ref().err()
    }

    /// What the read of the efivar of `store` gave, if it was read: its bytes, or why it failed.
    pub(super) fn outcome(
        &self,
        store: &dyn VariableStore,
    ) -> Option<std::result::Result<&[u8], &anyhow::Error>> {
        self.outcomes
            .get(&EfivarRange::of(store))
            .map(Result::as_deref)
    }

    /// The attribute word of the efivar of `store`, if a read of it succeeded; None skips set's
    /// check of it before the first write.
    pub(super) fn attributes(&self, store: &dyn VariableStore) -> Option<u32> {
        efivar_attributes(self.outcomes.get(&EfivarRange::of(store))?.as_ref().ok()?)
    }
}

/// Returns the bytes of `varstore`'s efivar file, or why a question on it has no value.
/// The caller decodes the payload bytes `value`.
pub(super) fn read_current_value_bytes<'a>(
    varstore: &Result<Box<dyn VariableStore>>,
    value: std::ops::Range<usize>,
    reader: &'a mut EfivarReader,
) -> std::result::Result<&'a [u8], ValueUnavailable> {
    let reach = reader.reach();
    let store = match varstore {
        Ok(store) => store,
        Err(error) => {
            return Err(
                match error
                    .downcast_ref::<NoVarStore>()
                    .and_then(|NoVarStore(question)| {
                        question.refusal(QuestionExpression::Read, reach)
                    }) {
                    Some(refusal) => ValueUnavailable::Storageless(refusal),
                    None => ValueUnavailable::NoVarStore(error.to_string()),
                },
            )
        }
    };
    if reader
        .withheld_overlap(&store.variable_key(), &value)
        .is_some()
    {
        return Err(ValueUnavailable::PasswordBytes);
    }
    read_stored_bytes(store.as_ref(), value, reader)
}

/// Reads `value` of `store` through `reader`, password bytes too, or returns why it reads none.
pub(super) fn read_stored_bytes<'a>(
    store: &dyn VariableStore,
    value: std::ops::Range<usize>,
    reader: &'a mut EfivarReader,
) -> std::result::Result<&'a [u8], ValueUnavailable> {
    let (reach, interface) = (reader.reach(), reader.interface());
    // A variable that the read finds is read whatever runtime access its VARSTORE_EFI declares:
    // firmware may give an NV|BS VarStore's variable runtime access, as firmware whose EDK2 gives
    // every non-volatile variable runtime access does. The declaration only explains a missing or
    // unread variable.
    reader.read(EfivarRange::of(store), value).map_err(|error| {
        match store.explain_unread(reach, interface, error) {
            Some(declared) => ValueUnavailable::DeclaredBootServiceOnly(declared),
            None => ValueUnavailable::from_read_error(store.kind(), error),
        }
    })
}

/// Why a question has no value. Display gives the reason, to_answer the text shown for the
/// value.
#[derive(Debug, Error)]
pub(super) enum ValueUnavailable {
    /// find_corresponding_varstore's error, its outermost context only
    #[error("{0}")]
    NoVarStore(String),
    /// Why get reads no value of a question without a VarStore
    #[error("{0}")]
    Storageless(StoragelessRefusal),
    /// Why get does not take the value of the question's READ expression
    #[error("{0}")]
    Expression(ExpressionRefusal),
    /// A READ expression that needs, through others, the value that it gives: of question `0`
    #[error(
        "the READ expressions of question {0:#06x} and the questions they refer to need its value"
    )]
    ReadCycle(u16),
    /// A READ expression that takes the value of question `0` through more than
    /// MAX_READ_DEPTH other READ expressions
    #[error(
        "question {0:#06x} is reached through more than {} READ expressions, each retrieving \
         the value of the next",
        MAX_READ_DEPTH
    )]
    ReadDepth(u16),
    /// Why the EFI_IFR_VALUE expression of the question gives no value
    #[error("its EFI_IFR_VALUE expression gives no value: {0}")]
    ValueExpression(String),
    #[error("{0}")]
    DeclaredBootServiceOnly(DeclaredBootServiceOnly),
    #[error("{0}")]
    EnhancedAuthenticated(EnhancedAuthenticatedVariable),
    /// Payload bytes that overlap those of a PASSWORD question, which the reader withholds
    #[error("its bytes hold a password")]
    PasswordBytes,
    #[error("{0}")]
    NotRead(EfivarsNotRead),
    #[error("{0}")]
    Missing(VariableNotFound),
    #[error("{0}")]
    Size(VariableSizeMismatch),
    #[error("{0}; HII buffer varstore requires EFI_HII_CONFIG_ACCESS_PROTOCOL")]
    MissingBuffer(VariableNotFound),
    /// The cause chain of a read error that the EfivarReader keeps, as `{:#}` shows it
    #[error("{0}")]
    ReadError(String),
    #[error("{0}")]
    BitField(NumericFormatError),
    #[error("{} value not decoded", .0.spec_name())]
    NotDecoded(IFROpCode),
    #[error("failed to fill whole buffer (offset: {offset}; buflen: {len})")]
    Truncated {
        offset: usize,
        /// the bytes read_efivar returned, attributes included
        len: usize,
    },
    #[error("CHECKBOX value {0} over a byte")]
    CheckboxOverByte(u64),
    /// The number of a name/value setting in the ExportConfig snapshot, wider than the question
    #[error("its number in the ExportConfig snapshot does not fit in {bits} bits")]
    SnapshotNumber { bits: usize },
    /// A DATE or TIME of EFI Date/Time Storage on a backend without Time Services
    #[error("{0}")]
    TimeStorageUnread(TimeStorageUnread),
    /// The error of the Time Service that reads a DATE or TIME of EFI Date/Time Storage, as
    /// `{:#}` shows it
    #[error("{0}")]
    TimeService(String),
    /// An expression that would give an ORDERED_LIST, a REF or a STRING its value
    #[error("{0}")]
    BufferExpression(BufferExpression),
    /// The CHAR16s of a STRING, one of which no UCS-2 character is
    #[error("{0}")]
    StoredString(NotUcs2),
    /// The setting of a STRING of a VARSTORE_NAME_VALUE in the ExportConfig snapshot, whose
    /// digits are no `<String>` (UEFI 2.11 §35.2.1.2)
    #[error("its setting in the ExportConfig snapshot is no {}", STRING)]
    SnapshotStringDigits,
    /// The setting of a STRING of a VARSTORE_NAME_VALUE in the ExportConfig snapshot, which holds
    /// characters other than NULL past the question's MaxSize
    #[error(
        "its setting in the ExportConfig snapshot holds more than its MaxSize of {max_size} \
         characters"
    )]
    SnapshotStringLength { max_size: usize },
    /// A value of which --assume-var-store states the bytes `stated` of the variable `key` but
    /// not `unstated`, which `reason` keeps from being read
    #[error(
        "{reason}; bytes {} of {key} stated, {} not",
        byte_ranges(.stated),
        byte_ranges(.unstated)
    )]
    PartlyStated {
        reason: Box<ValueUnavailable>,
        key: VariableKey,
        stated: Vec<Range<usize>>,
        unstated: Vec<Range<usize>>,
    },
    /// Why a condition cannot read the `bytes` of the variable `key`, which --assume-var-store
    /// states in place of them; answers keep `reason`, since stated bytes reach only conditions
    #[error("{reason}{}", stating(.key, .bytes))]
    Unstated {
        reason: Box<ValueUnavailable>,
        key: VariableKey,
        bytes: Vec<Range<usize>>,
    },
    /// Why a condition cannot read AMI_ACCESS_LEVEL; answers keep the plain reason, since a stated
    /// level replaces it only in conditions
    #[error(
        "{0}; the AMI setup browser keeps its access level there (0 Administrator, 1 User); \
         --access-level administrator|user states one"
    )]
    AmiAccessLevel(Box<ValueUnavailable>),
}

impl ValueUnavailable {
    /// Why a question on a VarStore of `kind` has no value, its efivar file having failed with
    /// `error`.
    fn from_read_error(kind: VariableStoreKind, error: &anyhow::Error) -> Self {
        if let Some(&not_read) = error.downcast_ref::<EfivarsNotRead>() {
            return Self::NotRead(not_read);
        }
        if let Some(refused) = error.downcast_ref::<EnhancedAuthenticatedVariable>() {
            return Self::EnhancedAuthenticated(refused.clone());
        }
        if let Some(mismatch) = error.downcast_ref::<VariableSizeMismatch>() {
            return Self::Size(mismatch.clone());
        }
        let Some(missing) = error.downcast_ref::<VariableNotFound>() else {
            return Self::ReadError(format!("{error:#}"));
        };
        match kind {
            VariableStoreKind::Buffer => Self::MissingBuffer(missing.clone()),
            VariableStoreKind::EfiVariable => Self::Missing(missing.clone()),
        }
    }

    /// The bytes of a value at `location` that --assume-var-store would state in place of those
    /// its variable cannot give, as this says: those that a PartlyStated value lacks, else the
    /// location's; None where its variable is not why it has no value. PasswordBytes is None:
    /// stating them would put a password on a command line.
    pub(super) fn stateable_bytes(&self, location: ValueLocation) -> Option<Vec<Range<usize>>> {
        match self {
            Self::PartlyStated {
                reason, unstated, ..
            } => reason.stateable_bytes(location).map(|_| unstated.clone()),
            Self::DeclaredBootServiceOnly(_)
            | Self::EnhancedAuthenticated(_)
            | Self::NotRead(_)
            | Self::Missing(_)
            | Self::Size(_)
            | Self::MissingBuffer(_)
            | Self::ReadError(_)
            | Self::Truncated { .. } => Some(vec![location.bytes()]),
            Self::NoVarStore(_)
            | Self::Storageless(_)
            | Self::Expression(_)
            | Self::ReadCycle(_)
            | Self::ReadDepth(_)
            | Self::ValueExpression(_)
            | Self::PasswordBytes
            | Self::BitField(_)
            | Self::NotDecoded(_)
            | Self::CheckboxOverByte(_)
            | Self::SnapshotNumber { .. }
            | Self::TimeStorageUnread(_)
            | Self::TimeService(_)
            | Self::BufferExpression(_)
            | Self::StoredString(_)
            | Self::SnapshotStringDigits
            | Self::SnapshotStringLength { .. }
            | Self::Unstated { .. }
            | Self::AmiAccessLevel(_) => None,
        }
    }

    /// The text that get, list-questions and show-ifr show for the value: the reason, tagged
    /// VStoreError for a read error, ExtractEFIDataError for a short variable, else
    /// ValueUnavailable.
    pub(super) fn to_answer(&self) -> String {
        format!("<{}: {self}>", self.tag())
    }

    /// to_answer's tag: AmiAccessLevel keeps the tag of its reason.
    fn tag(&self) -> &'static str {
        match self {
            Self::ReadError(_) => "VStoreError",
            Self::Truncated { .. } => "ExtractEFIDataError",
            Self::AmiAccessLevel(reason)
            | Self::PartlyStated { reason, .. }
            | Self::Unstated { reason, .. } => reason.tag(),
            Self::NoVarStore(_)
            | Self::Storageless(_)
            | Self::Expression(_)
            | Self::ReadCycle(_)
            | Self::ReadDepth(_)
            | Self::ValueExpression(_)
            | Self::DeclaredBootServiceOnly(_)
            | Self::EnhancedAuthenticated(_)
            | Self::PasswordBytes
            | Self::NotRead(_)
            | Self::Missing(_)
            | Self::Size(_)
            | Self::MissingBuffer(_)
            | Self::BitField(_)
            | Self::NotDecoded(_)
            | Self::CheckboxOverByte(_)
            | Self::SnapshotNumber { .. }
            | Self::TimeStorageUnread(_)
            | Self::TimeService(_)
            | Self::BufferExpression(_)
            | Self::StoredString(_)
            | Self::SnapshotStringDigits
            | Self::SnapshotStringLength { .. } => "ValueUnavailable",
        }
    }
}

/// A question whose value is a buffer, not a number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BufferQuestion {
    OrderedList,
    /// A REF on a VarStore, whose value is an EFI_HII_REF (UEFI 2.11 §33.2.5.4.10)
    CrossReference,
    /// A STRING, whose value is MaxSize CHAR16s (edk2-stable202608
    /// SetupBrowserDxe/IfrParse.c:2225)
    String,
}

impl fmt::Display for BufferQuestion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OrderedList => f.write_str("the buffer of an ORDERED_LIST"),
            Self::CrossReference => f.write_str("the EFI_HII_REF of a cross-reference question"),
            Self::String => f.write_str("the CHAR16s of a STRING"),
        }
    }
}

/// An expression that gives a question its buffer or takes it, which uefisettings does not
/// evaluate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum BufferExpression {
    #[error("its READ expression gives {0}, which uefisettings does not evaluate")]
    Read(BufferQuestion),
    #[error("its WRITE expression takes {0}, which uefisettings does not evaluate")]
    Write(BufferQuestion),
    #[error("its EFI_IFR_VALUE expression gives {0}, which uefisettings does not evaluate")]
    Value(BufferQuestion),
}

/// Where a ONE_OF, NUMERIC, CHECKBOX, DATE, TIME, ORDERED_LIST, REF or STRING keeps its value
/// in the payload of its VarStore.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ValueLocation {
    /// `size` bytes from byte `offset`, little-endian
    Bytes { offset: u16, size: u16 },
    /// `width` bits from bit `offset`: an EDKII bit varstore field, its BitVarOffset and
    /// BitStorageWidth in edk2-stable202608 SetupBrowserDxe/IfrParse.c
    Bits { offset: u16, width: u8 },
}

impl ValueLocation {
    /// The payload bytes that hold the value: for Bits, the StorageWidth bytes of IfrParse.c.
    pub(super) fn bytes(self) -> Range<usize> {
        match self {
            Self::Bytes { offset, size } => {
                usize::from(offset)..usize::from(offset) + usize::from(size)
            }
            Self::Bits { offset, width } => {
                let start = usize::from(offset / 8);
                start..start + usize::from(storage_width(offset, width))
            }
        }
    }

    /// Refuses a bit field that edk2-stable202608 Setup.c GetBitsQuestionValue cannot read: it
    /// copies the StorageWidth bytes into a UINT32 and takes 1 to 32 bits from it.
    pub(super) fn check(self) -> Result<ReadableLocation, NumericFormatError> {
        match self {
            Self::Bytes { .. } => Ok(ReadableLocation(self)),
            Self::Bits { offset, width } => {
                bit_field_bits(width)?;
                if u32::from(storage_width(offset, width)) * u8::BITS > EDKII_BIT_FIELD_VALUE_BITS {
                    return Err(NumericFormatError::BitFieldSpan { offset, width });
                }
                Ok(ReadableLocation(self))
            }
        }
    }
}

/// The StorageWidth of edk2-stable202608 IfrParse.c: the bytes that `width` bits from bit
/// `offset` span.
pub(super) fn storage_width(offset: u16, width: u8) -> u16 {
    (offset % 8 + u16::from(width)).div_ceil(8)
}

/// A ValueLocation that ValueLocation::check accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ReadableLocation(pub(super) ValueLocation);

impl ReadableLocation {
    /// Returns the value that `bytes`, the bytes() of the location, hold: for Bits, as
    /// GetBitsQuestionValue reads it.
    fn read(self, bytes: &[u8]) -> u64 {
        match self.0 {
            ValueLocation::Bytes { .. } => stored_value(bytes),
            ValueLocation::Bits { offset, width } => {
                (stored_value(bytes) >> u32::from(offset % 8)) & ((1 << width) - 1)
            }
        }
    }
}

/// The payload bytes that hold the value of `question`, if it is a ListedQuestion,
/// where edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes places it: an EDKII bit
/// varstore field, whose VarOffset and width count bits, spans the bytes of its bits.
fn value_bytes(question: &IFROperation) -> Option<std::ops::Range<usize>> {
    Some(ListedQuestion::of(question)?.location().bytes())
}

/// Where the value of a question comes from, which get, list-questions and show-ifr tag, or
/// the values that decide its state, which get and list-questions tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ValueSource {
    /// Its variable, its EFI Date/Time Storage, or an expression, now
    Current,
    /// The ExportConfig snapshot that the firmware took before the OS ran (UEFI 2.11
    /// §33.2.11.1), in place of a missing variable
    Snapshot,
}

impl ValueSource {
    /// What get, list-questions and show-ifr show after a value from here.
    pub(crate) fn annotation(self) -> &'static str {
        match self {
            Self::Current => "",
            Self::Snapshot => " <snapshot>",
        }
    }

    /// Snapshot if either is.
    pub(crate) fn or(self, other: Self) -> Self {
        match (self, other) {
            (Self::Current, Self::Current) => Self::Current,
            (Self::Snapshot, Self::Current | Self::Snapshot) | (Self::Current, Self::Snapshot) => {
                Self::Snapshot
            }
        }
    }

    /// Snapshot if questions have taken values from the snapshot of `reader` since it counted
    /// `taken` (EfivarReader::snapshot_values_taken), else Current.
    pub(super) fn since(taken: usize, reader: &EfivarReader) -> Self {
        match reader.snapshot_values_taken() > taken {
            true => Self::Snapshot,
            false => Self::Current,
        }
    }
}

/// The value of a question, where the question keeps it, and where it comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct RetrievedValue {
    pub(super) location: ReadableLocation,
    pub(super) value: u64,
    pub(super) source: ValueSource,
}

/// A VARSTORE_NAME_VALUE of `guid`, whose values only the driver's
/// EFI_HII_CONFIG_ACCESS_PROTOCOL reaches, and the ExportConfig snapshot shows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct NameValueStore {
    pub(super) guid: Guid,
}

// thiserror 1.0.56's derive leaves `guid` unread, which unused_assignments refuses
impl std::fmt::Display for NameValueStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HII name/value varstore requires EFI_HII_CONFIG_ACCESS_PROTOCOL")
    }
}

impl std::error::Error for NameValueStore {}

/// Returns where the question keeps its value and the value, or why it cannot be read: of a
/// DATE or TIME of EFI Date/Time Storage, the fields of the EFI_TIME of that storage, which
/// UEFI 2.11 §33.2.5.6 reads through GetTime() or GetWakeupTime(), also when it has a VarStore
/// too, and never the ExportConfig snapshot, which holds no EFI_TIME; else from the snapshot of
/// `reader`, if any, where the question's variable is missing or its storage is name/value
/// (snapshot_bytes).
pub(super) fn read_question_value(
    question: &IFROperation,
    varstore: &Result<Box<dyn VariableStore>>,
    reader: &mut EfivarReader,
) -> std::result::Result<RetrievedValue, ValueUnavailable> {
    let Some(value_question) = value_question(question) else {
        return Err(ValueUnavailable::NotDecoded(question.op_code));
    };
    // before the read: a field that cannot be read gives its own reason, and dump-efivars keeps
    // no bytes for it
    let location = value_question
        .location()
        .check()
        .map_err(ValueUnavailable::BitField)?;
    if let Some((kind, storage)) = value_question.time_storage() {
        let services = reader
            .time_services()
            .ok_or(ValueUnavailable::TimeStorageUnread(TimeStorageUnread(
                storage,
            )))?;
        let time = storage
            .read(services.as_ref())
            .map_err(|error| ValueUnavailable::TimeService(format!("{error:#}")))?;
        return Ok(RetrievedValue {
            location,
            value: question_value(kind, &time),
            source: ValueSource::Current,
        });
    }
    let (bytes, source) = read_sourced_bytes(question, varstore, reader)?;
    Ok(RetrievedValue {
        location,
        value: location.read(&bytes),
        source,
    })
}

/// read_question_value, with the bytes of `stated`, statements of `varstore`, in place of those
/// its variable holds: a value of EFI Date/Time Storage reads none of them. Where they state only
/// some bytes of the value, the others come from read_sourced_bytes, and if it fails, the value
/// is PartlyStated.
pub(super) fn read_stated_question_value(
    question: &IFROperation,
    varstore: &Result<Box<dyn VariableStore>>,
    stated: &StoreStatements<'_>,
    reader: &mut EfivarReader,
) -> std::result::Result<RetrievedValue, ValueUnavailable> {
    let Some(value_question) = value_question(question) else {
        return Err(ValueUnavailable::NotDecoded(question.op_code));
    };
    let location = value_question
        .location()
        .check()
        .map_err(ValueUnavailable::BitField)?;
    let range = location.0.bytes();
    let patch = stated.bytes(range.clone());
    let (Ok(store), None) = (varstore, value_question.time_storage()) else {
        return read_question_value(question, varstore, reader);
    };
    if patch.iter().all(Option::is_none) {
        return read_question_value(question, varstore, reader);
    }
    let (bytes, source) = match patch.iter().copied().collect::<Option<Vec<u8>>>() {
        Some(bytes) => (bytes, ValueSource::Current),
        None => {
            let (read, source) =
                read_sourced_bytes(question, varstore, reader).map_err(|reason| {
                    let (stated, unstated) = stated_ranges(&patch, range.start);
                    ValueUnavailable::PartlyStated {
                        reason: Box::new(reason),
                        key: store.variable_key(),
                        stated,
                        unstated,
                    }
                })?;
            let bytes = patch
                .iter()
                .zip(read)
                .map(|(stated, read)| stated.unwrap_or(read))
                .collect();
            (bytes, source)
        }
    };
    Ok(RetrievedValue {
        location,
        value: location.read(&bytes),
        source,
    })
}

/// The ranges of payload bytes that `patch`, the stated bytes from byte `start` on, states, and
/// those it does not.
pub(super) fn stated_ranges(
    patch: &[Option<u8>],
    start: usize,
) -> (Vec<Range<usize>>, Vec<Range<usize>>) {
    let mut stated: Vec<Range<usize>> = Vec::new();
    let mut unstated: Vec<Range<usize>> = Vec::new();
    for (at, byte) in (start..).zip(patch) {
        let ranges = match byte {
            Some(_) => &mut stated,
            None => &mut unstated,
        };
        match ranges.last_mut() {
            Some(last) if last.end == at => last.end = at + 1,
            Some(_) | None => ranges.push(at..at + 1),
        }
    }
    (stated, unstated)
}

/// "; " and the --assume-var-store of each of `ranges` of the variable `key`, which states the
/// bytes there; nothing for no range.
fn stating(key: &VariableKey, ranges: &[Range<usize>]) -> String {
    let flags: Vec<String> = ranges
        .iter()
        .map(|range| {
            let unit = match range.len() {
                1 => "byte",
                _ => "bytes",
            };
            format!(
                "--assume-var-store {key}+{}=<HEX of {} {unit}>",
                range.start,
                range.len()
            )
        })
        .collect();
    match flags.as_slice() {
        [flag] => format!("; {flag} states it"),
        [first @ .., last] => format!("; {} and {last} state them", first.join(", ")),
        [] => String::new(),
    }
}

/// `ranges` of payload bytes as A..B, in order, separated by ", ".
pub(super) fn byte_ranges(ranges: &[Range<usize>]) -> String {
    ranges
        .iter()
        .map(|range| format!("{}..{}", range.start, range.end))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Returns the value_bytes of the question and where they come from, or why they cannot be read:
/// from the ExportConfig snapshot of `reader`, if any, where the question's variable is missing
/// or its storage is name/value (snapshot_bytes).
pub(super) fn read_sourced_bytes(
    question: &IFROperation,
    varstore: &Result<Box<dyn VariableStore>>,
    reader: &mut EfivarReader,
) -> std::result::Result<(Vec<u8>, ValueSource), ValueUnavailable> {
    let Some(listed) = ListedQuestion::of(question) else {
        return Err(ValueUnavailable::NotDecoded(question.op_code));
    };
    let unread = match read_question_bytes(question, varstore, reader) {
        Ok(bytes) => return Ok((bytes.to_vec(), ValueSource::Current)),
        Err(unread) => unread,
    };
    let bytes = snapshot_bytes(listed, varstore, reader, unread)?;
    if let Some(snapshot) = reader.snapshot.as_mut() {
        snapshot.count_taken();
    }
    Ok((bytes, ValueSource::Snapshot))
}

/// The bytes of `question`'s value in the ExportConfig snapshot of `reader`, if its variable is
/// missing or its storage is name/value, or `unread`, why the question has no value otherwise, as
/// of a variable of a VarName: the snapshot holds no byte of a PASSWORD question
/// (ConfigSnapshot::parse), so a value over one gives `unread`, PasswordBytes
/// (read_current_value_bytes).
fn snapshot_bytes(
    question: ListedQuestion<'_>,
    varstore: &Result<Box<dyn VariableStore>>,
    reader: &EfivarReader,
    unread: ValueUnavailable,
) -> std::result::Result<Vec<u8>, ValueUnavailable> {
    let Some(snapshot) = &reader.snapshot else {
        return Err(unread);
    };
    let value = question.location().bytes();
    match varstore {
        Ok(store) => {
            // edk2-stable202608 ExportConfig() asks a driver only for the storages that
            // HiiDatabaseDxe/ConfigRouting.c ParseIfrData finds, which skips a VARSTORE_EFI before
            // UEFI 2.3.1 (:2485): no <ConfigResp> holds the variable of a VarName
            match store.layout() {
                VariableLayout::Offsets => {}
                VariableLayout::OneValue => return Err(unread),
            }
            let missing = reader
                .read_error(store.as_ref())
                .is_some_and(|error| error.is::<VariableNotFound>());
            if !missing {
                return Err(unread);
            }
            snapshot.buffer(&store.variable_key(), value).ok_or(unread)
        }
        Err(error) => {
            let Some(NameValueStore { guid }) = error.downcast_ref() else {
                return Err(unread);
            };
            let Some(setting) = snapshot.setting(*guid, question.header().var_store_info) else {
                return Err(unread);
            };
            match question {
                ListedQuestion::String(_) => {
                    let units = setting
                        .string()
                        .ok_or(ValueUnavailable::SnapshotStringDigits)?;
                    string_bytes(&units, value.len())
                }
                ListedQuestion::Value(_)
                | ListedQuestion::OrderedList(_)
                | ListedQuestion::Ref(_) => match setting.number() {
                    Some(number) => number_bytes(&number, value.len()),
                    None => Err(unread),
                },
            }
        }
    }
}

/// The `size` bytes of `number`, least significant first, as EDK2's SetupBrowserDxe
/// BufferToValue takes them, or why they cannot hold it: where it drops the more significant
/// digits, this refuses those that are not zero.
fn number_bytes(number: &Number, size: usize) -> std::result::Result<Vec<u8>, ValueUnavailable> {
    let bytes = number.as_bytes();
    if bytes.iter().skip(size).any(|byte| *byte != 0) {
        return Err(ValueUnavailable::SnapshotNumber {
            bits: size.saturating_mul(8),
        });
    }
    let mut bytes = bytes.to_vec();
    bytes.resize(size, 0);
    Ok(bytes)
}

/// The `size` bytes of the STRING whose CHAR16s are `units`, NULL-padded, as EDK2's
/// SetupBrowserDxe BufferToValue takes them (edk2-stable202608 Setup.c:1557-1579), or why they
/// cannot hold them: where it drops the CHAR16s past MaxSize, `size` / 2, this refuses those that
/// are not NULL.
fn string_bytes(units: &[u16], size: usize) -> std::result::Result<Vec<u8>, ValueUnavailable> {
    let max_size = size / 2;
    if units.iter().skip(max_size).any(|unit| *unit != 0) {
        return Err(ValueUnavailable::SnapshotStringLength { max_size });
    }
    let mut bytes: Vec<u8> = units
        .iter()
        .take(max_size)
        .flat_map(|unit| unit.to_le_bytes())
        .collect();
    bytes.resize(size, 0);
    Ok(bytes)
}

/// Returns the value_bytes of the question, or why its value cannot be read.
fn read_question_bytes<'a>(
    question: &IFROperation,
    varstore: &Result<Box<dyn VariableStore>>,
    reader: &'a mut EfivarReader,
) -> std::result::Result<&'a [u8], ValueUnavailable> {
    let Some(value) = value_bytes(question) else {
        return Err(ValueUnavailable::NotDecoded(question.op_code));
    };
    let bytes = read_current_value_bytes(varstore, value.clone(), reader)?;
    let offset = value.start;
    bytes
        .get(EFIVARFS_HEADER_SIZE..)
        .and_then(|payload| payload.get(value))
        .ok_or(ValueUnavailable::Truncated {
            offset,
            len: bytes.len(),
        })
}

/// The bytes of the location of `question`, a `buffer` on `varstore`, read through `reader`
/// (read_sourced_bytes), and where they come from, or why get takes none: an expression that would
/// give them, or how a question without a VarStore has no value.
pub(super) fn read_buffer(
    question: &Rc<RefCell<IFROperation>>,
    buffer: BufferQuestion,
    varstore: &Result<Box<dyn VariableStore>>,
    reader: &mut EfivarReader,
) -> std::result::Result<(Vec<u8>, ValueSource), ValueUnavailable> {
    // the browser takes EFI_IFR_VALUE first (edk2-stable202608 SetupBrowserDxe/Setup.c
    // GetQuestionValue)
    if question_value_expression(&question.borrow()).is_some() {
        return Err(ValueUnavailable::BufferExpression(BufferExpression::Value(
            buffer,
        )));
    }
    let storageless = varstore
        .as_ref()
        .err()
        .and_then(|error| error.downcast_ref::<NoVarStore>());
    if let Some(NoVarStore(storageless)) = storageless {
        if let Some(refusal) = storageless.refusal(QuestionExpression::Read, reader.reach()) {
            return Err(ValueUnavailable::Storageless(refusal));
        }
    }
    if question_expression(question, QuestionExpression::Read).is_some() {
        return Err(ValueUnavailable::BufferExpression(BufferExpression::Read(
            buffer,
        )));
    }
    read_sourced_bytes(&question.borrow(), varstore, reader)
}

/// The little-endian integer that `bytes`, the value_bytes of a question, store.
pub(super) fn stored_value(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .rev()
        .fold(0, |value, byte| (value << 8) | u64::from(*byte))
}

#[cfg(test)]
#[cfg(efivar_dumps)]
mod efivar_reader_tests {
    use std::collections::BTreeMap;
    use std::rc::Rc;

    use anyhow::anyhow;
    use binrw::io::Cursor;

    use super::super::conditions::ExpressionInputs;
    use super::super::conditions::IncludedStates;
    use super::super::display;
    use super::super::display_answer;
    use super::super::handle_form_set;
    use super::super::ifr_fixtures::*;
    use super::super::list_questions;
    use super::super::CheckedVarStores;
    use super::super::EFI_IFR_NUMERIC_SIZE_2;
    use super::super::EFI_IFR_NUMERIC_SIZE_4;
    use super::super::EFI_IFR_TYPE_NUM_SIZE_16;
    use super::*;
    use crate::hii::variables::DecodedValue;

    const MISSING_BUFFER: &str = "<ValueUnavailable: no EFI variable \
        Missing-00000000-0000-0000-0000-000000000000; \
        HII buffer varstore requires EFI_HII_CONFIG_ACCESS_PROTOCOL>";
    const DECLARED_NOT_READ: &str = "<ValueUnavailable: EFI variables not read; the form \
         declares EFI variable Setup-00000000-0000-0000-0000-000000000000 boot-service-only \
         (no EFI_VARIABLE_RUNTIME_ACCESS)>";
    const NOT_READ: &str = "<ValueUnavailable: EFI variables not read>";

    /// read_question_bytes of `store`, owned.
    fn question_bytes(
        question: &IFROperation,
        store: DeclaredVarStore,
        reader: &mut EfivarReader,
    ) -> std::result::Result<Vec<u8>, String> {
        read_question_bytes(question, &Ok(Box::new(store)), reader)
            .map(<[u8]>::to_vec)
            .map_err(|reason| reason.to_answer())
    }

    #[test]
    fn variable_read_through_two_stores_is_read_once() {
        let (_root, node) = parse_question(&[], CHECKBOX, &checkbox(0, 0x00), &[]);
        let question = node.borrow();
        let efivars = Efivars::new();
        efivars.write(&efi_variable("Setup", 1), &[42]);
        let mut reader = efivars.reader();

        assert_eq!(
            question_bytes(&question, efi_variable("Setup", 1), &mut reader),
            Ok(vec![42]),
            "read_question_bytes"
        );
        efivars.write(&efi_variable("Setup", 1), &[43]);
        let answer = display_answer(
            &node,
            &Ok(Box::new(efi_variable("Setup", 1))),
            &mut ExpressionInputs {
                reader: &mut reader,
                values: &MapValues(BTreeMap::new()),
            },
        );

        assert_eq!(answer, "42", "display_answer after the file changed");
    }

    #[test]
    fn stores_of_one_file_and_size_share_one_read() {
        let (_root, node) = parse_question(&[], CHECKBOX, &checkbox(0, 0x00), &[]);
        let question = node.borrow();
        let efivars = Efivars::new();
        let mut reader = efivars.reader();

        efivars.write(&efi_variable("Setup", 1), &[0]);
        assert_eq!(
            question_bytes(
                &question,
                DeclaredVarStore {
                    runtime_accessible: false,
                    ..efi_variable("Setup", 1)
                },
                &mut reader
            ),
            Ok(vec![0]),
            "boot-service-only store"
        );
        efivars.write(&efi_variable("Setup", 1), &[1]);
        assert_eq!(
            question_bytes(&question, buffer("Setup", 1), &mut reader),
            Ok(vec![0]),
            "buffer after a boot-service-only store"
        );
        efivars.write(&efi_variable("Setup", 1), &[2]);
        assert_eq!(
            question_bytes(&question, efi_variable("Setup", 1), &mut reader),
            Ok(vec![0]),
            "runtime EFI variable after the buffer"
        );
    }

    #[test]
    fn other_files_sizes_and_fresh_reads_read_again() {
        let (_root, node) = parse_question(&[], CHECKBOX, &checkbox(0, 0x00), &[]);
        let question = node.borrow();
        let efivars = Efivars::new();
        efivars.write(&efi_variable("Setup", 2), &[1, 2]);
        efivars.write(&efi_variable("Other", 1), &[3]);
        let mut reader = efivars.reader();

        assert_eq!(
            question_bytes(&question, efi_variable("Setup", 1), &mut reader),
            Ok(vec![1]),
            "first"
        );
        efivars.write(&efi_variable("Setup", 2), &[4, 5]);
        let cases: [(&str, DeclaredVarStore, &[u8]); 3] = [
            ("other name", efi_variable("Other", 1), &[3]),
            ("other size", efi_variable("Setup", 2), &[4]),
            ("first again", efi_variable("Setup", 1), &[1]),
        ];
        for (case, store, want) in cases {
            assert_eq!(
                question_bytes(&question, store, &mut reader),
                Ok(want.to_vec()),
                "{case}"
            );
        }

        assert_eq!(
            question_bytes(&question, efi_variable("Setup", 1), &mut efivars.reader()),
            Ok(vec![4]),
            "fresh EfivarReader"
        );
    }

    #[test]
    fn missing_buffer_variable_is_read_once() {
        let (_root, node) = parse_question(&[], CHECKBOX, &checkbox(0, 0x00), &[]);
        let question = node.borrow();
        let missing = || buffer("Missing", 1);
        let efivars = Efivars::new();
        let mut reader = efivars.reader();

        assert_eq!(
            question_bytes(&question, missing(), &mut reader),
            Err(MISSING_BUFFER.to_string()),
            "first call"
        );
        efivars.write(&missing(), &[0]);
        assert_eq!(
            question_bytes(&question, missing(), &mut reader),
            Err(MISSING_BUFFER.to_string()),
            "call after the file appeared"
        );
        assert_eq!(
            question_bytes(&question, missing(), &mut efivars.reader()),
            Ok(vec![0]),
            "fresh EfivarReader"
        );
    }

    #[test]
    fn missing_file_reason_follows_each_store_kind() {
        const MISSING_EFI_VARIABLE: &str =
            "<ValueUnavailable: no EFI variable Missing-00000000-0000-0000-0000-000000000000>";
        let (_root, node) = parse_question(&[], CHECKBOX, &checkbox(0, 0x00), &[]);
        let question = node.borrow();
        let efivars = Efivars::new();
        let mut reader = efivars.reader();
        let cases = [
            (
                "EFI variable",
                efi_variable("Missing", 1),
                MISSING_EFI_VARIABLE,
            ),
            ("buffer after it", buffer("Missing", 1), MISSING_BUFFER),
            (
                "EFI variable after the buffer",
                efi_variable("Missing", 1),
                MISSING_EFI_VARIABLE,
            ),
        ];

        for (case, store, want) in cases {
            assert_eq!(
                question_bytes(&question, store, &mut reader),
                Err(want.to_string()),
                "{case}"
            );
        }
        assert_eq!(reader.outcomes.len(), 1, "cached outcomes");
    }

    #[test]
    fn disabled_source_leaves_every_value_unread() {
        let (_root, node) = parse_question(&[], CHECKBOX, &checkbox(0, 0x00), &[]);
        let question = node.borrow();
        let mut reader = disabled_reader();
        let cases = [
            ("EFI variable", efi_variable("Setup", 1), NOT_READ),
            ("buffer", buffer("Setup", 1), NOT_READ),
            (
                "boot-service-only EFI variable",
                DeclaredVarStore {
                    runtime_accessible: false,
                    ..efi_variable("Setup", 1)
                },
                DECLARED_NOT_READ,
            ),
        ];

        for (case, store, want) in cases {
            assert_eq!(
                question_bytes(&question, store, &mut reader),
                Err(want.to_string()),
                "{case}"
            );
        }
    }

    #[test]
    fn disabled_source_shows_the_ifr_default() {
        let (root, _node) = parse_question(
            &[var_store_efi(1, "Setup", NV_BS_RT, 1)],
            CHECKBOX,
            &checkbox(0, 0x01),
            &[],
        );

        let listed: Vec<String> = list_questions(
            root,
            &ListTexts::new(&strings(), &[]),
            IncludedStates::empty(),
            CheckedVarStores::NONE,
            &mut disabled_reader(),
        )
        .into_iter()
        .map(|(question, _)| question.value)
        .collect();

        assert_eq!(
            listed,
            [format!("{NOT_READ} <IFR default: 1>")],
            "list_questions without efivars"
        );
    }

    /// The state annotations that list_questions gives, with every state included, to question
    /// 2, to question 1 under a SUPPRESS_IF on question 2 being 1, and to question 3 under a
    /// SUPPRESS_IF TRUE, all on the 2-byte efivar Setup, read through `reader`.
    fn suppressed_states(reader: &mut EfivarReader) -> Vec<String> {
        let root = parse_form_set(&[
            var_store_efi(1, "Setup", NV_BS_RT, 2),
            form(
                1,
                &[
                    checkbox_on(2, 5, 1),
                    conditional(SUPPRESS_IF, eq_id_val_of(2, 1), &[checkbox_op(1, 1)]),
                    conditional(SUPPRESS_IF, ifr_true(), &[checkbox_op(3, 1)]),
                ],
            ),
        ]);
        list_questions(
            root,
            &ListTexts::new(&strings(), &[]),
            IncludedStates::CONDITIONS,
            CheckedVarStores::NONE,
            reader,
        )
        .into_iter()
        .map(|(_, state)| state.annotation())
        .collect()
    }

    #[test]
    fn disabled_source_leaves_value_conditions_undetermined() {
        let efivars = Efivars::new();
        let undetermined = " <selectable or suppressed: EFI_IFR_EQ_ID_VAL of question 0x0002: \
            <ValueUnavailable: EFI variables not read; --assume-var-store \
            Setup-00000000-0000-0000-0000-000000000000+0=<HEX of 1 byte> states it>>";

        efivars.write(&efi_variable("Setup", 2), &[1, 0]);
        assert_eq!(
            suppressed_states(&mut efivars.reader()),
            ["", " <suppressed>", " <suppressed>"],
            "question 2 is 1"
        );
        efivars.write(&efi_variable("Setup", 2), &[0, 0]);
        assert_eq!(
            suppressed_states(&mut efivars.reader()),
            ["", "", " <suppressed>"],
            "question 2 is 0"
        );
        assert_eq!(
            suppressed_states(&mut disabled_reader()),
            ["", undetermined, " <suppressed>"],
            "Disabled"
        );
    }

    #[test]
    fn list_questions_and_display_share_one_read() {
        let first = operation(CHECKBOX, false, &checkbox(0, 0x00));
        let (root, _second) = parse_question(
            &[var_store_efi(1, "Setup", NV_BS_RT, 2), first],
            CHECKBOX,
            &checkbox(1, 0x00),
            &[],
        );
        let show = |reader: &mut EfivarReader| {
            display(
                Rc::clone(&root),
                0,
                &ListTexts::new(&strings(), &[]),
                reader,
            )
            .expect("display the FormSet")
        };
        let efivars = Efivars::new();
        efivars.write(&efi_variable("Setup", 2), &[1, 0]);
        let mut reader = efivars.reader();
        let shown_before = show(&mut efivars.reader());

        let listed: Vec<String> = list_questions(
            Rc::clone(&root),
            &ListTexts::new(&strings(), &[]),
            IncludedStates::empty(),
            CheckedVarStores::NONE,
            &mut reader,
        )
        .into_iter()
        .map(|(question, _)| question.value)
        .collect();
        efivars.write(&efi_variable("Setup", 2), &[0, 1]);
        let shown = show(&mut reader);

        assert_eq!(listed, ["1", "0"], "list_questions");
        assert_eq!(reader.outcomes.len(), 1, "files read by two questions");
        assert_eq!(shown, shown_before, "display after list_questions");
        assert_ne!(
            show(&mut efivars.reader()),
            shown_before,
            "display of the changed file"
        );
    }

    /// A NUMERIC or ONE_OF at VarOffset `offset` whose MinValue, MaxValue and Step take `size`
    /// bytes, as `flags` says.
    fn sized_question(offset: u16, flags: u8, size: usize) -> Vec<u8> {
        [question_header(offset), vec![flags], vec![0; 3 * size]].concat()
    }

    /// Where setup_question puts its question.
    #[derive(Clone, Copy)]
    enum Placement {
        /// In the FormSet, so that its VarOffset counts bytes
        FormSet,
        /// In an EDKII bit varstore GUID op, so that its VarOffset and width count bits
        BitVarStoreGuid,
    }

    /// Parses a FormSet holding the 16-byte VARSTORE_EFI "Setup" and then one question, put
    /// where `placement` says; returns the root and the question.
    fn setup_question(placement: Placement, op_code: u8, data: &[u8]) -> RootAndQuestion {
        let var_store = var_store_efi(1, "Setup", NV_BS_RT, 16);
        match placement {
            Placement::FormSet => parse_question(&[var_store], op_code, data, &[]),
            Placement::BitVarStoreGuid => {
                let bytes = form_set(&[
                    var_store,
                    operation(GUID, true, &BIT_VARSTORE_GUID),
                    operation(op_code, false, data),
                    END.to_vec(), // End of the GUID
                ]);
                let root = handle_form_set(&mut Cursor::new(&bytes)).expect("parse the FormSet");
                let guid = Rc::clone(&root.borrow().children[0].borrow().children[1]);
                let question = Rc::clone(&guid.borrow().children[0]);
                (root, question)
            }
        }
    }

    /// The questions that value_bytes_are_where_the_value_is_stored and
    /// questions_decode_only_their_value_bytes check: name, parsed question, value_bytes.
    fn value_questions() -> Vec<(&'static str, RootAndQuestion, std::ops::Range<usize>)> {
        let in_form_set = |op_code, data: &[u8]| setup_question(Placement::FormSet, op_code, data);
        let bit_field =
            |op_code, data: &[u8]| setup_question(Placement::BitVarStoreGuid, op_code, data);
        vec![
            (
                "CHECKBOX at 3",
                in_form_set(CHECKBOX, &checkbox(3, 0x00)),
                3..4,
            ),
            (
                "UINT8 ONE_OF at 0",
                in_form_set(ONE_OF, &one_of_data()),
                0..1,
            ),
            (
                "UINT16 NUMERIC at 6",
                in_form_set(NUMERIC, &sized_question(6, EFI_IFR_NUMERIC_SIZE_2, 2)),
                6..8,
            ),
            (
                "UINT32 ONE_OF at 5",
                in_form_set(ONE_OF, &uint32_range_question(5, EFI_IFR_NUMERIC_SIZE_4)),
                5..9,
            ),
            (
                "UINT64 NUMERIC at 1",
                // EFI_IFR_NUMERIC_SIZE_8
                in_form_set(NUMERIC, &sized_question(1, 0x03, 8)),
                1..9,
            ),
            (
                "5-bit NUMERIC at bit 13",
                bit_field(NUMERIC, &uint32_range_question(13, 5)),
                1..3,
            ),
            (
                "3-bit ONE_OF at bit 16",
                bit_field(ONE_OF, &uint32_range_question(16, 3)),
                2..3,
            ),
            (
                "bit-field CHECKBOX at bit 15",
                bit_field(CHECKBOX, &checkbox(15, 0x00)),
                1..2,
            ),
            (
                "bit-field CHECKBOX at bit 16",
                bit_field(CHECKBOX, &checkbox(16, 0x00)),
                2..3,
            ),
            ("DATE at 2", in_form_set(DATE, &date_time(2, 0x00)), 2..6),
            ("TIME at 9", in_form_set(TIME, &date_time(9, 0x00)), 9..12),
            (
                "ORDERED_LIST of 3 UINT16 containers at 4",
                parse_question(
                    &[var_store_efi(1, "Setup", NV_BS_RT, 16)],
                    ORDERED_LIST,
                    &ordered_list(4, 3, 0x00),
                    &[one_of_option(5, EFI_IFR_TYPE_NUM_SIZE_16, &[1, 0])],
                ),
                4..10,
            ),
        ]
    }

    #[test]
    fn value_bytes_are_where_the_value_is_stored() {
        for (case, (_root, question), expected) in value_questions() {
            assert_eq!(value_bytes(&question.borrow()), Some(expected), "{case}");
        }
        let (root, _question) = parse_question(&[], CHECKBOX, &checkbox(3, 0x00), &[]);
        let form_set = Rc::clone(&root.borrow().children[0]);
        assert_eq!(value_bytes(&form_set.borrow()), None, "FORM_SET");
    }

    #[test]
    fn ops_without_value_bytes_are_not_decoded() {
        let (root, _question) = parse_question(&[], CHECKBOX, &checkbox(3, 0x00), &[]);
        let form_set = Rc::clone(&root.borrow().children[0]);

        assert_eq!(
            question_bytes(
                &form_set.borrow(),
                efi_variable("FormSet", 4),
                &mut disabled_reader()
            ),
            Err("<ValueUnavailable: EFI_IFR_FORM_SET value not decoded>".to_string()),
            "FORM_SET"
        );
    }

    #[test]
    fn questions_decode_only_their_value_bytes() {
        for (case, (root, _question), value) in value_questions() {
            let show = |outside: u8, inside: u8| {
                let payload: Vec<u8> = (0..16)
                    .map(|offset| match value.contains(&offset) {
                        true => inside,
                        false => outside,
                    })
                    .collect();
                let efivars = Efivars::new();
                efivars.write(&efi_variable("Setup", 16), &payload);
                let mut reader = efivars.reader();
                let root = Rc::clone(&root);
                let listed: Vec<String> = list_questions(
                    Rc::clone(&root),
                    &ListTexts::new(&strings(), &[]),
                    IncludedStates::empty(),
                    CheckedVarStores::NONE,
                    &mut reader,
                )
                .into_iter()
                .map(|(question, _)| question.value)
                .collect();
                let shown = display(root, 0, &ListTexts::new(&strings(), &[]), &mut reader)
                    .expect("display");
                (listed, shown)
            };

            assert_eq!(show(0x00, 0x01), show(0xFF, 0x01), "{case}: other bytes");
            assert_ne!(
                show(0x00, 0xFF).1,
                show(0x00, 0x00).1,
                "{case}: value bytes"
            );
        }
    }

    #[test]
    fn reads_keep_the_bytes_their_question_decodes() {
        let (_root, node) = parse_question(&[], CHECKBOX, &checkbox(3, 0x00), &[]);
        let question = node.borrow();
        let (_root, bit_field_node) =
            parse_question_in_guid(BIT_VARSTORE_GUID, CHECKBOX, &checkbox(15, 0x00), &[]);
        let bit_field = bit_field_node.borrow();
        let (root, _node) = parse_question(&[], CHECKBOX, &checkbox(3, 0x00), &[]);
        let form_set = Rc::clone(&root.borrow().children[0]);
        let mut reader = disabled_reader();
        let hidden = DeclaredVarStore {
            runtime_accessible: false,
            ..efi_variable("Hidden", 4)
        };

        question_bytes(&question, efi_variable("Setup", 4), &mut reader).expect_err("Setup");
        question_bytes(&bit_field, efi_variable("Bits", 4), &mut reader).expect_err("Bits");
        question_bytes(&question, hidden, &mut reader).expect_err("boot-service-only");
        read_question_bytes(&question, &Err(anyhow!("no VarStore 1")), &mut reader)
            .expect_err("no VarStore");
        assert_eq!(
            question_bytes(&form_set.borrow(), efi_variable("FormSet", 4), &mut reader),
            Err("<ValueUnavailable: EFI_IFR_FORM_SET value not decoded>".to_string()),
            "FORM_SET"
        );

        assert_eq!(
            reader.decoded,
            BTreeMap::from([
                (
                    efi_variable("Bits", 4).variable_key(),
                    vec![DecodedValue {
                        size: 4,
                        layout: VariableLayout::Offsets,
                        value: 1..2
                    }]
                ),
                (
                    efi_variable("Hidden", 4).variable_key(),
                    vec![DecodedValue {
                        size: 4,
                        layout: VariableLayout::Offsets,
                        value: 3..4
                    }]
                ),
                (
                    efi_variable("Setup", 4).variable_key(),
                    vec![DecodedValue {
                        size: 4,
                        layout: VariableLayout::Offsets,
                        value: 3..4
                    }]
                ),
            ]),
            "decoded bytes: only of variables read"
        );
    }

    /// A bit field that cannot be read reports why without reading its bytes, so that a short
    /// store reports the field, not the read, and dump-efivars keeps no bytes for it.
    #[test]
    fn unreadable_bit_field_is_refused_before_its_bytes_are_read() {
        // 33 bits from bit 0 span 5 bytes of the 4-byte store
        let (_root, node) = parse_question_in_guid(
            BIT_VARSTORE_GUID,
            NUMERIC,
            &uint32_range_question(0, 33),
            &[],
        );
        let efivars = Efivars::new();
        efivars.write(&efi_variable("Bits", 4), &[0xFF; 4]);
        let mut reader = efivars.reader();

        assert_eq!(
            read_question_value(
                &node.borrow(),
                &Ok(Box::new(efi_variable("Bits", 4))),
                &mut reader
            )
            .map(|_| ())
            .map_err(|reason| reason.to_answer()),
            Err("<ValueUnavailable: EDKII bit-field width 33, not 1 to 32>".to_string()),
            "33-bit field"
        );
        assert_eq!(reader.decoded, BTreeMap::new(), "decoded bytes");
    }
}

#[derive(BinRead, Debug, PartialEq, Clone)]
#[br(little)]
pub struct VarStore {
    pub guid: Guid,
    pub var_store_id: u16,
    pub size: u16,
    pub name: binrw::NullString,
}

#[derive(BinRead, Debug, PartialEq, Clone)]
#[br(little)]
pub struct VarStoreNameValue {
    pub var_store_id: u16,
    pub guid: Guid,
}

impl VariableStore for VarStore {
    fn name(&self) -> String {
        self.name.to_string()
    }
    fn guid(&self) -> Guid {
        self.guid
    }
    fn size(&self) -> u16 {
        self.size
    }
    fn kind(&self) -> VariableStoreKind {
        VariableStoreKind::Buffer
    }
    fn is_runtime_accessible(&self) -> bool {
        false
    }
}

#[derive(BinRead, Debug, PartialEq, Clone)]
#[br(little)]
pub struct VarStoreEfi {
    pub var_store_id: u16,
    pub guid: Guid,
    pub attributes: u32,
    pub size: u16,
    pub name: binrw::NullString,
}
impl VariableStore for VarStoreEfi {
    fn name(&self) -> String {
        self.name.to_string()
    }
    fn guid(&self) -> Guid {
        self.guid
    }
    fn size(&self) -> u16 {
        self.size
    }
    fn kind(&self) -> VariableStoreKind {
        VariableStoreKind::EfiVariable
    }
    /// Whether the form declares EFI_VARIABLE_RUNTIME_ACCESS; the variable's own attributes may
    /// differ.
    fn is_runtime_accessible(&self) -> bool {
        (self.attributes & EFI_VARIABLE_RUNTIME_ACCESS) != 0
    }
}

/// An EFI_IFR_VARSTORE_EFI of the form before UEFI 2.3.1, which ends at Attributes; a Size short
/// of a Name is not read. It names no EFI variable, as each question's VarName names its own
/// (edk2-stable202608 SetupBrowserDxe/IfrParse.c CreateQuestion, Setup.c GetQuestionValue), and
/// as the VarName of a GET or SET still may: "a Name/Value or EFI Variable name ( VarName )"
/// (UEFI 2.11 §33.3.8.3.27 and §33.3.8.3.66 VarStoreInfo).
#[derive(BinRead, Debug, PartialEq, Clone)]
#[br(little)]
pub struct ShortVarStoreEfi {
    pub var_store_id: u16,
    pub guid: Guid,
    pub attributes: u32,
    /// What resolve_short_var_names finds in the strings of its package list
    #[br(default)]
    pub(super) var_names: Rc<VarNames>,
}

/// The EFI variable names of the VarNames of the ops on a ShortVarStoreEfi, by string ID, or the
/// strings that they differ on.
pub(super) type VarNames = BTreeMap<u16, Result<Rc<str>, UnresolvedVarName>>;
impl ShortVarStoreEfi {
    /// Its label in refusals.
    pub(super) const LABEL: &'static str = "EFI_IFR_VARSTORE_EFI before UEFI 2.3.1";

    /// The EFI variable of `size` bytes that VarName `var_name` names, or why it names none.
    pub(super) fn variable(
        &self,
        var_name: u16,
        size: u16,
    ) -> Result<ShortEfiVariable, UnresolvedVarName> {
        Ok(ShortEfiVariable {
            name: self.var_name(var_name)?,
            guid: self.guid,
            attributes: self.attributes,
            size,
        })
    }

    /// The EFI variable that VarName `var_name` names, of no width, or why it names none.
    pub(super) fn variable_key(&self, var_name: u16) -> Result<VariableKey, UnresolvedVarName> {
        Ok(VariableKey {
            name: self.var_name(var_name)?.to_string(),
            guid: self.guid,
        })
    }

    /// The name of the EFI variable that VarName `var_name` names, or why it names none.
    fn var_name(&self, var_name: u16) -> Result<Rc<str>, UnresolvedVarName> {
        self.var_names
            .get(&var_name)
            .cloned()
            .unwrap_or(Err(UnresolvedVarName::NoString(var_name)))
    }

    /// The EFI variables that VarName `var_name` may name where it names none: of each string
    /// that the strings packages differ on, or of UNKNOWN_STRING where none holds it.
    pub(super) fn candidate_variables(&self, var_name: u16) -> Vec<VariableKey> {
        var_name_variables(self.guid, self.var_names.get(&var_name))
    }
}

/// The EFI variables of Guid `guid` that a VarName may name, given the string that its strings
/// packages give it, `string`: of that string, of each string that they differ on, or of
/// UNKNOWN_STRING where none holds it.
pub(super) fn var_name_variables(
    guid: Guid,
    string: Option<&Result<Rc<str>, UnresolvedVarName>>,
) -> Vec<VariableKey> {
    let names = match string {
        Some(Ok(name)) => vec![name.to_string()],
        Some(Err(UnresolvedVarName::Disagreeing { strings, .. })) => {
            strings.iter().map(|(_, string)| string.clone()).collect()
        }
        Some(Err(UnresolvedVarName::NoString(_))) | None => vec![UNKNOWN_STRING.to_owned()],
    };
    names
        .into_iter()
        .map(|name| VariableKey { name, guid })
        .collect()
}

/// The string that edk2-stable202608 SetupBrowserDxe/Setup.c GetToken takes for a string ID that
/// no strings package holds (mUnknownString).
const UNKNOWN_STRING: &str = "!";

/// Why the VarName of an op on a ShortVarStoreEfi names no EFI variable.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(super) enum UnresolvedVarName {
    /// edk2-stable202608 SetupBrowserDxe/Setup.c GetToken takes the unknown string "!" then
    #[error("no string {0:#06x} holds its VarName")]
    NoString(u16),
    /// Strings of the VarName that differ between the strings packages, each with the Language of
    /// its package: GetToken takes the one of the platform language, which uefisettings does not
    /// know
    #[error(
        "the strings packages differ on its VarName {var_name:#06x}: {}",
        .strings
            .iter()
            .map(|(language, string)| format!("{string:?} in {language}"))
            .collect::<Vec<_>>()
            .join(", ")
    )]
    Disagreeing {
        var_name: u16,
        strings: Vec<(String, String)>,
    },
}

/// The EFI variable of one op on a ShortVarStoreEfi, which holds its value alone: of the string of
/// its VarName and the store's Guid, of the `size` bytes of the value (edk2-stable202608
/// SetupBrowserDxe/Setup.c GetQuestionValue, SetQuestionValue).
pub(super) struct ShortEfiVariable {
    name: Rc<str>,
    guid: Guid,
    attributes: u32,
    size: u16,
}

impl VariableStore for ShortEfiVariable {
    fn name(&self) -> String {
        self.name.to_string()
    }
    fn guid(&self) -> Guid {
        self.guid
    }
    fn size(&self) -> u16 {
        self.size
    }
    fn kind(&self) -> VariableStoreKind {
        VariableStoreKind::EfiVariable
    }
    /// Whether the form declares EFI_VARIABLE_RUNTIME_ACCESS; the variable's own attributes may
    /// differ.
    fn is_runtime_accessible(&self) -> bool {
        (self.attributes & EFI_VARIABLE_RUNTIME_ACCESS) != 0
    }
    fn layout(&self) -> VariableLayout {
        VariableLayout::OneValue
    }
    /// The store's Attributes, as edk2-stable202608 SetupBrowserDxe/Setup.c SetQuestionValue
    /// creates the variable through SetVariable(): it holds that question's value alone.
    fn created_attributes(&self) -> Option<u32> {
        Some(self.attributes)
    }
}

/// The attributes that set creates the missing variable of `store` with through variables of
/// `reach` and `interface`, if it creates it: those of VariableStore::created_attributes, through
/// an interface without a VariableInterface::creation_refusal, and at OS runtime only with
/// EFI_VARIABLE_RUNTIME_ACCESS, as "Once ExitBootServices() is performed, only variables that
/// have EFI_VARIABLE_RUNTIME_ACCESS and EFI_VARIABLE_NON_VOLATILE set can be set with
/// SetVariable()" (UEFI 2.11 §8.2.3); check_volatile_write checks EFI_VARIABLE_NON_VOLATILE.
pub(super) fn created_attributes(
    store: &dyn VariableStore,
    reach: VariableReach,
    interface: VariableInterface,
) -> Option<u32> {
    let attributes = store.created_attributes()?;
    if interface.creation_refusal().is_some() {
        return None;
    }
    match reach {
        VariableReach::Runtime if attributes & EFI_VARIABLE_RUNTIME_ACCESS == 0 => None,
        VariableReach::Runtime | VariableReach::BootServices => Some(attributes),
    }
}

/// Why a ShortVarStoreEfi names no EFI variable for an op on it.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("VarStore {var_store_id:#06x} ({}): {reason}", ShortVarStoreEfi::LABEL)]
pub(super) struct ShortEfiRefusal {
    pub(super) var_store_id: u16,
    pub(super) reason: ShortEfiReason,
}

impl ShortEfiRefusal {
    pub(super) fn new(var_store_id: u16, reason: ShortEfiReason) -> Self {
        Self {
            var_store_id,
            reason,
        }
    }
}

/// The reason of a ShortEfiRefusal.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(super) enum ShortEfiReason {
    #[error(transparent)]
    VarName(#[from] UnresolvedVarName),
    #[error(
        "the question is an EDKII bit varstore field, whose VarStoreInfo is a bit offset, not a \
         VarName"
    )]
    BitField,
    #[error(
        "declared after the question, which took its VarStoreInfo for a VarOffset; a question \
         names a previously declared VarStore (UEFI 2.11 §33.3.8.2.2 EFI_IFR_QUESTION_HEADER)"
    )]
    DeclaredAfter,
    /// An op whose value uefisettings does not read, named by its spec name
    #[error("uefisettings reads no {0} on it")]
    NotRead(&'static str),
    /// An ORDERED_LIST without options, to which edk2-stable202608 SetupBrowserDxe/IfrParse.c
    /// gives no StorageWidth (:2466-2493)
    #[error("{}", ListRefusal::NoOptions)]
    NoOptions,
}

/// A store as a FormSet's IFR declares it, with the settings of its questions that a forms
/// browser requests, but those of PASSWORD questions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StoreDeclaration {
    /// Its VarStoreId
    pub(crate) id: u16,
    pub(crate) guid: Guid,
    pub(crate) kind: DeclaredKind,
    /// Whether a PASSWORD question names it: its bytes are never requested, and a RouteConfig()
    /// without them may clear them
    pub(crate) holds_password: bool,
}

/// The kind of a StoreDeclaration, with what a forms browser requests of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DeclaredKind {
    /// EFI_IFR_VARSTORE `name`: `width` bytes at VarOffset `offset` per question, without any
    /// block that overlaps a PASSWORD question's bytes
    Buffer {
        name: String,
        blocks: Vec<(u16, NonZeroUsize)>,
    },
    /// EFI_IFR_VARSTORE_NAME_VALUE: the VarName of each question but a PASSWORD question's
    NameValue { names: Vec<String> },
    /// EFI_IFR_VARSTORE_EFI `name`: the EFI variable of that name and the store's GUID; of an
    /// EFI_IFR_VARSTORE_EFI before UEFI 2.3.1, the EFI variable that a VarName names
    EfiVariable { name: String },
}

/// The stores that `form_set` declares, in IFR order, each with the settings that the questions
/// of its forms request of it, without repeats, as a forms browser adds them to the store's
/// `<ConfigRequest>` (only questions in a form reach InitializeRequestElement): a Buffer store's
/// by VarOffset and width, a Name/Value store's by VarName, its text in `texts`, as
/// edk2-stable202608 SetupBrowserDxe IfrParse.c takes a VarName through GetToken. A PASSWORD
/// question's bytes or name are withheld: no setting that covers them is requested, and its store
/// holds a password. In place of a VARSTORE_EFI before UEFI 2.3.1, each EFI variable that the
/// VarName of one of its questions names (ShortVarStoreEfi::candidate_variables), once, which
/// holds a password if a PASSWORD question names it. It leaves out what IfrParse.c ParseOpCodes
/// skips with a DISABLE_IF outside forms (skips_questions): the VarStore ops there, whose stores
/// it never creates, and the settings of the questions there, but the bytes of a PASSWORD there
/// stay withheld. What ParseOpCodes may skip counts as parsed.
pub(crate) fn store_declarations(
    form_set: &IFROperation,
    texts: &ListTexts<'_>,
) -> Vec<StoreDeclaration> {
    /// A VarStore op: its store, or a VARSTORE_EFI before UEFI 2.3.1, whose questions' VarNames
    /// name the EFI variables
    enum Declared {
        Store(StoreDeclaration),
        ShortEfi(ShortVarStoreEfi),
    }

    /// Where an op is: in a form, and in the scope of a DISABLE_IF that skips_questions names
    #[derive(Clone, Copy)]
    struct Place {
        in_form: bool,
        skipped: bool,
    }

    let mut declared = Vec::new();
    let mut storages = Vec::new();
    let root = Place {
        in_form: false,
        skipped: false,
    };
    walk_scopes(&form_set.children, root, |child, &place| {
        let op = child.borrow();
        if skips_scope(&op) {
            return Walk::Skip;
        }
        match &op.parsed_data {
            _ if place.skipped => storages
                .extend(question_storage(&op).filter(|storage| place.in_form && storage.password)),
            ParsedOperation::VarStore(store) => {
                declared.push(Declared::Store(StoreDeclaration::new(
                    store.var_store_id,
                    store.guid,
                    DeclaredKind::Buffer {
                        name: store.name.to_string(),
                        blocks: Vec::new(),
                    },
                )));
            }
            ParsedOperation::VarStoreNameValue(store) => {
                declared.push(Declared::Store(StoreDeclaration::new(
                    store.var_store_id,
                    store.guid,
                    DeclaredKind::NameValue { names: Vec::new() },
                )));
            }
            ParsedOperation::VarStoreEfi(store) => {
                declared.push(Declared::Store(StoreDeclaration::new(
                    store.var_store_id,
                    store.guid,
                    DeclaredKind::EfiVariable {
                        name: store.name.to_string(),
                    },
                )));
            }
            ParsedOperation::ShortVarStoreEfi(store) => {
                declared.push(Declared::ShortEfi(store.clone()));
            }
            _ if place.in_form => storages.extend(question_storage(&op)),
            _ => {}
        }
        Walk::Enter(Place {
            in_form: place.in_form || matches!(op.op_code, IFROpCode::Form | IFROpCode::FormMap),
            skipped: place.skipped || skips_questions(&op),
        })
    });
    let stores = declared.iter_mut().filter_map(|declared| match declared {
        Declared::Store(declaration) => Some(declaration),
        Declared::ShortEfi(_) => None,
    });
    for declaration in stores {
        let on_store: Vec<&QuestionStorage> = storages
            .iter()
            .filter(|storage| storage.var_store_id == declaration.id)
            .collect();
        let by_name = matches!(declaration.kind, DeclaredKind::NameValue { .. });
        let withheld: Vec<&QuestionStorage> = on_store
            .iter()
            .copied()
            .filter(|storage| storage.password)
            .collect();
        declaration.holds_password = !withheld.is_empty();
        let requested = on_store.into_iter().filter(|storage| {
            !withheld
                .iter()
                .any(|password| password.overlaps(storage, by_name))
        });
        for storage in requested {
            match &mut declaration.kind {
                DeclaredKind::Buffer { blocks, .. } => {
                    if !blocks.contains(&storage.block) {
                        blocks.push(storage.block);
                    }
                }
                DeclaredKind::NameValue { names } => {
                    let name = texts.display(storage.var_store_info).to_owned();
                    if !names.contains(&name) {
                        names.push(name);
                    }
                }
                DeclaredKind::EfiVariable { .. } => {}
            }
        }
    }
    declared
        .into_iter()
        .flat_map(|declared| match declared {
            Declared::Store(declaration) => vec![declaration],
            Declared::ShortEfi(store) => {
                let mut variables: Vec<StoreDeclaration> = Vec::new();
                let on_store = storages
                    .iter()
                    .filter(|storage| storage.var_store_id == store.var_store_id);
                for storage in on_store {
                    for key in store.candidate_variables(storage.var_store_info) {
                        let kind = DeclaredKind::EfiVariable { name: key.name };
                        match variables.iter_mut().find(|variable| variable.kind == kind) {
                            Some(variable) => variable.holds_password |= storage.password,
                            None => variables.push(StoreDeclaration {
                                id: store.var_store_id,
                                guid: key.guid,
                                kind,
                                holds_password: storage.password,
                            }),
                        }
                    }
                }
                variables
            }
        })
        .collect()
}

/// The storage of a question: its VarStoreId and VarStoreInfo, the block it spans in a Buffer
/// store, and whether it is a PASSWORD question's.
struct QuestionStorage {
    var_store_id: u16,
    var_store_info: u16,
    block: (u16, NonZeroUsize),
    password: bool,
}

impl QuestionStorage {
    /// Whether this storage covers any of `other`'s: the same VarName in a Name/Value store,
    /// whose settings go `by_name`, a common byte in a Buffer store.
    fn overlaps(&self, other: &Self, by_name: bool) -> bool {
        match by_name {
            true => self.var_store_info == other.var_store_info,
            false => {
                let (mine, theirs) = (self.span(), other.span());
                mine.start < theirs.end && theirs.start < mine.end
            }
        }
    }

    /// The bytes of its block.
    fn span(&self) -> std::ops::Range<usize> {
        let (offset, width) = self.block;
        let start = usize::from(offset);
        start..start + width.get()
    }
}

impl StoreDeclaration {
    /// A store of `kind`, as its VARSTORE op declares it, before its questions are added.
    fn new(id: u16, guid: Guid, kind: DeclaredKind) -> Self {
        Self {
            id,
            guid,
            kind,
            holds_password: false,
        }
    }
}

/// The storage of the question op `op`, with the StorageWidth of edk2-stable202608
/// SetupBrowserDxe IfrParse.c for its kind; None for an op without storage and a DATE or TIME
/// kept elsewhere. A PASSWORD spans its MaxSize CHAR16s, also with EFI_IFR_FLAG_CALLBACK, whose
/// driver keeps it encoded there and a forms browser requests nothing of (IfrParse.c:684-690).
fn question_storage(op: &IFROperation) -> Option<QuestionStorage> {
    let data = &op.data;
    // Prompt, Help and QuestionId, then VarStoreId and VarStoreInfo (UEFI 2.11 §33.3.8.2.2)
    let &[_, _, _, _, _, _, id_low, id_high, info_low, info_high, ..] =
        data.first_chunk::<QUESTION_HEADER_SIZE>()?;
    let var_store_id = u16::from_le_bytes([id_low, id_high]);
    let var_store_info = u16::from_le_bytes([info_low, info_high]);
    if var_store_id == 0 {
        return None;
    }
    let bit_field = refers_to_bit_field(op);
    let width = match op.op_code {
        IFROpCode::OneOf | IFROpCode::Numeric if bit_field => {
            let bits = after_header(data, 0)? & EDKII_IFR_NUMERIC_SIZE_BIT;
            return bit_field_storage(var_store_id, var_store_info, bits);
        }
        IFROpCode::CheckBox if bit_field => {
            return bit_field_storage(var_store_id, var_store_info, 1);
        }
        IFROpCode::OneOf | IFROpCode::Numeric => {
            1usize << (after_header(data, 0)? & EFI_IFR_NUMERIC_SIZE)
        }
        IFROpCode::CheckBox => 1,
        IFROpCode::String => usize::from(after_header(data, 1)?) * size_of::<u16>(),
        IFROpCode::Password => {
            let max_size = u16::from_le_bytes([after_header(data, 2)?, after_header(data, 3)?]);
            return Some(QuestionStorage {
                var_store_id,
                var_store_info,
                block: (
                    var_store_info,
                    NonZeroUsize::new(usize::from(max_size) * size_of::<u16>())?,
                ),
                password: true,
            });
        }
        IFROpCode::Date if after_header(data, 0)? & QF_STORAGE == QF_STORAGE_NORMAL => DATE_WIDTH,
        IFROpCode::Time if after_header(data, 0)? & QF_STORAGE == QF_STORAGE_NORMAL => TIME_WIDTH,
        IFROpCode::OrderedList => {
            usize::from(after_header(data, 0)?) * ordered_list_element_width(op)?
        }
        IFROpCode::Ref => REF_WIDTH,
        _ => return None,
    };
    Some(QuestionStorage {
        var_store_id,
        var_store_info,
        block: (var_store_info, NonZeroUsize::new(width)?),
        password: false,
    })
}

/// The byte `at` of the fields that follow the question header in `data`, a question op's data.
fn after_header(data: &[u8], at: usize) -> Option<u8> {
    data.get(QUESTION_HEADER_SIZE + at).copied()
}

/// The storage of an EDKII bit varstore field of `bits` bits at bit `bit_offset`: the bytes it
/// spans (IfrParse.c, QuestionReferBitField).
fn bit_field_storage(var_store_id: u16, bit_offset: u16, bits: u8) -> Option<QuestionStorage> {
    let width = (usize::from(bit_offset % 8) + usize::from(bits)).div_ceil(8);
    Some(QuestionStorage {
        var_store_id,
        var_store_info: bit_offset,
        block: (bit_offset / 8, NonZeroUsize::new(width)?),
        password: false,
    })
}

/// The width of an ORDERED_LIST's element: that of its first ONE_OF_OPTION's value type, 1 for
/// another type, as IfrParse.c takes it.
fn ordered_list_element_width(op: &IFROperation) -> Option<usize> {
    question_scope(op).iter().find_map(|option| {
        let ParsedOperation::OneOfOption(parsed) = &option.borrow().parsed_data else {
            return None;
        };
        Some(match parsed.value {
            TypeValue::NumSize16(_) => 2,
            TypeValue::NumSize32(_) => 4,
            TypeValue::NumSize64(_) => 8,
            TypeValue::NumSize8(_)
            | TypeValue::Boolean(_)
            | TypeValue::Time(_)
            | TypeValue::Date(_)
            | TypeValue::StringID(_)
            | TypeValue::Other
            | TypeValue::Undefined
            | TypeValue::Action(_)
            | TypeValue::Ref(_)
            | TypeValue::Unknown(_) => 1,
        })
    })
}

#[cfg(test)]
#[cfg(efivar_dumps)]
mod store_request_tests {
    use super::super::ifr_fixtures::*;
    use super::super::resolve_short_var_names;
    use super::*;
    use crate::hii::strings::Language;
    use crate::hii::strings::StringMap;
    use crate::hii::strings::StringPackage;

    /// EFI_IFR_FLAG_CALLBACK (UEFI 2.11 §33.3.8.2.2)
    const EFI_IFR_FLAG_CALLBACK: u8 = 0x04;

    /// A question header of QuestionId `id` on VarStore `var_store_id` at VarOffset `info`, with
    /// `flags`.
    fn header(id: u16, var_store_id: u16, info: u16, flags: u8) -> Vec<u8> {
        [
            &3u16.to_le_bytes()[..],
            &4u16.to_le_bytes(),
            &id.to_le_bytes(),
            &var_store_id.to_le_bytes(),
            &info.to_le_bytes(),
            &[flags],
        ]
        .concat()
    }

    fn width(bytes: usize) -> NonZeroUsize {
        NonZeroUsize::new(bytes).expect("nonzero")
    }

    fn declarations(body: &[Vec<u8>]) -> Vec<StoreDeclaration> {
        store_declarations(
            &parse_form_set(body).borrow(),
            &ListTexts::new(&strings(), &[]),
        )
    }

    #[test]
    fn store_settings_follow_the_widths_a_forms_browser_requests() {
        let string = operation(
            0x1C,
            false,
            &[header(0x10, 2, 0x10, 0), vec![1, 4, 0]].concat(),
        );
        let date_rtc = operation(
            0x1A,
            false,
            &[header(0x12, 2, 0x30, 0), vec![0x10]].concat(),
        );
        let time = operation(
            0x1B,
            false,
            &[header(0x13, 2, 0x34, 0), vec![0x00]].concat(),
        );
        let uint16 = operation(
            0x07,
            false,
            &[header(0x14, 2, 0x38, 0), vec![0x01], vec![0; 6]].concat(),
        );
        let named = operation(0x06, false, &[header(0x15, 3, 5, 0), vec![0x00]].concat());
        let body = [
            var_store(2, [0x22; 16], "Buffer", 0x40),
            operation(
                0x25,
                false,
                &[&3u16.to_le_bytes()[..], &[0x33; 16]].concat(),
            ),
            var_store_efi(1, "Store", NV_BS_RT, 4),
            form(1, &[string, date_rtc, time, uint16, named]),
            // outside any form: no browser requests it
            checkbox_at(0x16, 7, 2, 0x3F),
        ];

        let stores = declarations(&body);

        assert_eq!(
            stores,
            [
                StoreDeclaration {
                    id: 2,
                    guid: [0x22; 16].into(),
                    kind: DeclaredKind::Buffer {
                        name: "Buffer".into(),
                        blocks: vec![(0x10, width(8)), (0x34, width(3)), (0x38, width(2))],
                    },
                    holds_password: false,
                },
                StoreDeclaration {
                    id: 3,
                    guid: [0x33; 16].into(),
                    kind: DeclaredKind::NameValue {
                        names: vec![ListTexts::new(&strings(), &[]).display(5).to_owned()]
                    },
                    holds_password: false,
                },
                StoreDeclaration {
                    id: 1,
                    guid: [0; 16].into(),
                    kind: DeclaredKind::EfiVariable {
                        name: "Store".into()
                    },
                    holds_password: false,
                },
            ],
            "STRING of 4 CHAR16, TIME, UINT16 NUMERIC, no RTC DATE; the VarName on the \
             Name/Value store; the EFI variable store"
        );
    }

    #[test]
    fn password_bytes_and_names_are_withheld_and_mark_their_store() {
        // a PASSWORD of 20 CHAR16 at bytes 0x10-0x37 of the Buffer store
        let password = password_on(0x11, 4, 2, 0x10);
        let callback_password = operation(
            PASSWORD,
            false,
            &[
                header(0x12, 2, 0x40, EFI_IFR_FLAG_CALLBACK),
                [&1u16.to_le_bytes()[..], &8u16.to_le_bytes()].concat(),
            ]
            .concat(),
        );
        let before = checkbox_at(0x13, 7, 2, 0x0F);
        let inside = checkbox_at(0x14, 7, 2, 0x20);
        let straddling = operation(
            NUMERIC,
            false,
            &[header(0x15, 2, 0x36, 0), vec![0x01], vec![0; 6]].concat(),
        );
        let after = checkbox_at(0x16, 7, 2, 0x38);
        let inside_callback = checkbox_at(0x17, 7, 2, 0x4F);
        let named_password = password_on(0x18, 4, 3, 5);
        let named = operation(0x06, false, &[header(0x19, 3, 5, 0), vec![0x00]].concat());
        let other_name = operation(0x06, false, &[header(0x1A, 3, 6, 0), vec![0x00]].concat());
        let body = [
            var_store(2, [0x22; 16], "Buffer", 0x60),
            operation(
                0x25,
                false,
                &[&3u16.to_le_bytes()[..], &[0x33; 16]].concat(),
            ),
            var_store(4, [0x44; 16], "Other", 1),
            form(
                1,
                &[
                    password,
                    callback_password,
                    before,
                    inside,
                    straddling,
                    after,
                    inside_callback,
                    named_password,
                    named,
                    other_name,
                    checkbox_at(0x1B, 7, 4, 0),
                ],
            ),
        ];

        let stores = declarations(&body);

        assert_eq!(
            stores[0].kind,
            DeclaredKind::Buffer {
                name: "Buffer".into(),
                blocks: vec![(0x0F, width(1)), (0x38, width(1))],
            },
            "only the bytes outside both PASSWORDs, with or without EFI_IFR_FLAG_CALLBACK"
        );
        assert_eq!(
            stores[1].kind,
            DeclaredKind::NameValue {
                names: vec![ListTexts::new(&strings(), &[]).display(6).to_owned()]
            },
            "only the VarName that no PASSWORD names"
        );
        assert_eq!(
            stores
                .iter()
                .map(|store| (store.id, store.holds_password))
                .collect::<Vec<_>>(),
            [(2, true), (3, true), (4, false)],
            "the stores that PASSWORD questions name hold a password, the other not"
        );
    }

    /// edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes skips a DISABLE_IF outside forms
    /// whose condition is TRUE to its END (:1390-1413), with the VarStore ops and questions in
    /// it: no setting of those questions is requested and no store of those VarStore ops
    /// declared, but the bytes of a PASSWORD there stay withheld and mark its store. A DISABLE_IF
    /// whose condition is FALSE or not known leaves its questions requested.
    #[test]
    fn a_true_form_set_disable_if_requests_no_setting_and_declares_no_store_in_it() {
        let body = [
            var_store(2, [0x22; 16], "Buffer", 0x60),
            form(1, &[checkbox_at(0x10, 7, 2, 0x00)]),
            conditional(
                DISABLE_IF,
                ifr_true(),
                &[
                    var_store(3, [0x33; 16], "Hidden", 1),
                    form(
                        2,
                        &[
                            checkbox_at(0x11, 7, 2, 0x01),
                            checkbox_at(0x12, 7, 3, 0),
                            // a PASSWORD of 20 CHAR16 at bytes 0x10-0x37
                            password_on(0x13, 4, 2, 0x10),
                        ],
                    ),
                ],
            ),
            form(3, &[checkbox_at(0x14, 7, 2, 0x20)]),
            conditional(
                DISABLE_IF,
                ifr_false(),
                &[form(4, &[checkbox_at(0x15, 7, 2, 0x02)])],
            ),
            conditional(
                DISABLE_IF,
                eq_id_val_of(0x10, 1),
                &[form(5, &[checkbox_at(0x16, 7, 2, 0x03)])],
            ),
        ];

        assert_eq!(
            declarations(&body),
            [StoreDeclaration {
                id: 2,
                guid: [0x22; 16].into(),
                kind: DeclaredKind::Buffer {
                    name: "Buffer".into(),
                    blocks: vec![(0x00, width(1)), (0x02, width(1)), (0x03, width(1))],
                },
                holds_password: true,
            }],
            "bytes 0x00, 0x02 and 0x03, of the questions outside the TRUE DISABLE_IF; none of \
             its questions, nor its VarStore 3, nor byte 0x20, a byte of the PASSWORD in it"
        );
    }

    /// A VARSTORE_EFI before UEFI 2.3.1 declares, in its place, the EFI variable of its Guid that
    /// the VarName of each of its questions names, once, which holds a password if a PASSWORD
    /// names it, whatever other question names it too; for a VarName that the strings packages
    /// differ on, the variable of each string.
    #[test]
    fn a_short_var_store_declares_the_variable_of_each_var_name() {
        let body = [
            var_store_efi(1, "Store", NV_BS_RT, 4),
            short_var_store_efi(2),
            var_store(3, [0x33; 16], "Buffer", 1),
            form(
                1,
                &[
                    checkbox_at(0x10, 3, 2, 10),
                    password_on(0x11, 3, 2, 11),
                    checkbox_at(0x12, 3, 2, 10),
                    checkbox_at(0x15, 3, 2, 11),
                    checkbox_at(0x13, 3, 2, 12),
                    checkbox_at(0x14, 3, 3, 0),
                ],
            ),
        ];
        let root = parse_form_set(&body);
        let packages =
            [("en-US", "Differs"), ("fr-FR", "Differe")].map(|(language, differs)| StringPackage {
                language: Language(language.as_bytes().to_vec()),
                strings: StringMap::from([
                    (10, Rc::from("Value")),
                    (11, Rc::from("Password")),
                    (12, Rc::from(differs)),
                ]),
            });
        resolve_short_var_names(&[Rc::clone(&root)], &packages);
        let variable = |id, guid: [u8; 16], name: &str, holds_password| StoreDeclaration {
            id,
            guid: guid.into(),
            kind: DeclaredKind::EfiVariable { name: name.into() },
            holds_password,
        };

        let stores = store_declarations(&root.borrow(), &ListTexts::new(&strings(), &[]));

        assert_eq!(
            stores,
            [
                variable(1, [0; 16], "Store", false),
                variable(2, SHORT_VAR_STORE_GUID, "Value", false),
                variable(2, SHORT_VAR_STORE_GUID, "Password", true),
                variable(2, SHORT_VAR_STORE_GUID, "Differs", false),
                variable(2, SHORT_VAR_STORE_GUID, "Differe", false),
                StoreDeclaration {
                    id: 3,
                    guid: [0x33; 16].into(),
                    kind: DeclaredKind::Buffer {
                        name: "Buffer".into(),
                        blocks: vec![(0, width(1))],
                    },
                    holds_password: false,
                },
            ],
            "the VARSTORE_EFI; Value once, Password, which a CHECKBOX names after the PASSWORD, \
             both strings of VarName 12, in IFR order; the VARSTORE after them"
        );
    }
}
