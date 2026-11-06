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

use anyhow::Result;
use binrw::BinRead;
use thiserror::Error;

use super::bit_field_bits;
use super::question_values::value_question;
use super::IFROpCode;
use super::IFROperation;
use super::NumericFormatError;
use super::DECLARED_BOOT_SERVICE_ONLY;
use super::EDKII_BIT_FIELD_VALUE_BITS;
use crate::hii::package::Guid;
use crate::hii::variables::check_decodable;
use crate::hii::variables::efivar_attributes;
use crate::hii::variables::EfivarRange;
use crate::hii::variables::EfivarReader;
use crate::hii::variables::EfivarsNotRead;
use crate::hii::variables::EnhancedAuthenticatedVariable;
use crate::hii::variables::VariableInterface;
use crate::hii::variables::VariableKey;
use crate::hii::variables::VariableNotFound;
use crate::hii::variables::VariableReach;
use crate::hii::variables::WithheldVariable;
use crate::hii::variables::EFIVARFS_HEADER_SIZE;
use crate::hii::variables::EFI_VARIABLE_RUNTIME_ACCESS;

pub(super) trait VariableStore {
    fn name(&self) -> String;
    fn guid(&self) -> Guid;
    fn size(&self) -> u16;
    fn kind(&self) -> VariableStoreKind;
    fn is_runtime_accessible(&self) -> bool;

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
    use super::super::RangeType;
    use super::super::TypeValue;
    use super::super::DUMMY_OPCODE;
    use super::*;
    use crate::hii::efivarfs_format::EfivarFileName;
    use crate::hii::variables::tests::EFI_GLOBAL_VARIABLE;
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
        VarStoreWrite::new(store, 0, TypeValue::NumSize8(1), variables.interface())?
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
                     firmware has not created it, and set never creates variables"
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

    /// get decodes no value from a variable with EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS, whose
    /// data starts with metadata (UEFI 2.10 §8.2.1). The other authenticated accesses put their
    /// descriptors only into writes, so those variables decode as others do.
    #[test]
    fn enhanced_authenticated_variable_is_not_decoded() {
        let store = || efi_variable("Signed", 1);
        let efivars = Efivars::new();
        efivars.write_attributed(&store(), NV_BS_RT | 0x80, &[1]);

        assert_eq!(
            read(store(), &efivars),
            Err(
                "<ValueUnavailable: EFI variable Signed-00000000-0000-0000-0000-000000000000 \
                 has enhanced authenticated access (attributes 0x87): its data starts with \
                 metadata, which uefisettings does not decode>"
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
                "<ValueUnavailable: FormSet value not decoded>",
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

    #[test]
    fn question_without_varstore_is_reported_as_unavailable() {
        let node = Rc::new(RefCell::new(IFROperation {
            op_code: IFROpCode::Unknown(DUMMY_OPCODE),
            length: 0,
            open_scope: false,
            data: Vec::new(),
            parent: None,
            children: Vec::new(),
            parsed_data: ParsedOperation::Placeholder,
        }));

        let error = find_corresponding_varstore(node, 0).err().unwrap();
        assert_eq!(
            error.to_string(),
            "question is callback-driven or temporary and has no varstore"
        );
    }

    #[test]
    fn change_value_allows_buffer_varstore_with_efivarfs_backing() {
        let question = QuestionDescriptor {
            question: "SHA-1 PCR Bank".to_string(),
            help: String::new(),
            value: "Disabled".to_string(),
            max_value: RangeType::NumSize8(1),
            numeric_range: None,
            opcode: IFROpCode::OneOf,
            possible_options: vec![AnswerOption {
                value: "Enabled".to_string(),
                raw_value: TypeValue::NumSize8(1),
                state: StateEvaluation::selectable(),
            }],
            varstore: Ok(Box::new(TestVariableStore {
                kind: VariableStoreKind::Buffer,
            })),
            location: ValueLocation::Bytes { offset: 0, size: 1 },
            value_state: StateEvaluation::selectable(),
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
    fn of(store: &dyn VariableStore) -> Self {
        Self {
            key: store.variable_key(),
            size: store.size(),
        }
    }
}

impl EfivarReader {
    /// Why a read of the efivar of `store` failed, if one did.
    pub(super) fn read_error(&self, store: &dyn VariableStore) -> Option<&anyhow::Error> {
        self.outcomes.get(&EfivarRange::of(store))?.as_ref().err()
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
    let store = match varstore {
        Ok(store) => store,
        Err(error) => return Err(ValueUnavailable::NoVarStore(error.to_string())),
    };
    let reach = reader.reach();
    let interface = reader.interface();

    // A variable that the read finds is read whatever runtime access its VARSTORE_EFI declares:
    // firmware may give an NV|BS VarStore's variable runtime access, as firmware whose EDK2 gives
    // every non-volatile variable runtime access does. The declaration only explains a missing or
    // unread variable.
    let bytes = reader
        .read(EfivarRange::of(store.as_ref()), value)
        .map_err(
            |error| match store.explain_unread(reach, interface, error) {
                Some(declared) => ValueUnavailable::DeclaredBootServiceOnly(declared),
                None => ValueUnavailable::from_read_error(store.kind(), error),
            },
        )?;
    if let Some(attributes) = efivar_attributes(bytes) {
        check_decodable(&store.variable_key(), attributes)
            .map_err(ValueUnavailable::EnhancedAuthenticated)?;
    }
    Ok(bytes)
}

/// Why a question has no value. Display gives the reason, to_answer the text shown for the
/// value.
#[derive(Debug, Error)]
pub(super) enum ValueUnavailable {
    /// find_corresponding_varstore's error, its outermost context only
    #[error("{0}")]
    NoVarStore(String),
    #[error("{0}")]
    DeclaredBootServiceOnly(DeclaredBootServiceOnly),
    #[error("{0}")]
    EnhancedAuthenticated(EnhancedAuthenticatedVariable),
    /// The read of a VarStore that a PASSWORD question names, which the reader withholds
    #[error("VarStore holds a password")]
    PasswordVarStore,
    #[error("{0}")]
    NotRead(EfivarsNotRead),
    #[error("{0}")]
    Missing(VariableNotFound),
    #[error("{0}; HII buffer varstore requires EFI_HII_CONFIG_ACCESS_PROTOCOL")]
    MissingBuffer(VariableNotFound),
    /// The cause chain of a read error that the EfivarReader keeps, as `{:#}` shows it
    #[error("{0}")]
    ReadError(String),
    #[error("{0}")]
    BitField(NumericFormatError),
    #[error("{0:?} value not decoded")]
    NotDecoded(IFROpCode),
    #[error("failed to fill whole buffer (offset: {offset}; buflen: {len})")]
    Truncated {
        offset: usize,
        /// the bytes read_efivar returned, attributes included
        len: usize,
    },
    #[error("CHECKBOX value {0} over a byte")]
    CheckboxOverByte(u64),
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
        if error.downcast_ref::<WithheldVariable>().is_some() {
            return Self::PasswordVarStore;
        }
        let Some(missing) = error.downcast_ref::<VariableNotFound>() else {
            return Self::ReadError(format!("{error:#}"));
        };
        match kind {
            VariableStoreKind::Buffer => Self::MissingBuffer(missing.clone()),
            VariableStoreKind::EfiVariable => Self::Missing(missing.clone()),
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
            Self::AmiAccessLevel(reason) => reason.tag(),
            Self::NoVarStore(_)
            | Self::DeclaredBootServiceOnly(_)
            | Self::EnhancedAuthenticated(_)
            | Self::PasswordVarStore
            | Self::NotRead(_)
            | Self::Missing(_)
            | Self::MissingBuffer(_)
            | Self::BitField(_)
            | Self::NotDecoded(_)
            | Self::CheckboxOverByte(_) => "ValueUnavailable",
        }
    }
}

/// Where a ONE_OF, NUMERIC or CHECKBOX keeps its value in the payload of its VarStore.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ValueLocation {
    /// `size` bytes from byte `offset`, little-endian
    Bytes { offset: u16, size: u8 },
    /// `width` bits from bit `offset`: an EDKII bit varstore field, its BitVarOffset and
    /// BitStorageWidth in edk2-stable202608 SetupBrowserDxe/IfrParse.c
    Bits { offset: u16, width: u8 },
}

impl ValueLocation {
    /// The payload bytes that hold the value: for Bits, the StorageWidth bytes of IfrParse.c.
    fn bytes(self) -> std::ops::Range<usize> {
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
    fn check(self) -> Result<ReadableLocation, NumericFormatError> {
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

/// The payload bytes that hold the value of `question`, if it is a ONE_OF, NUMERIC or CHECKBOX,
/// where edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes places it: an EDKII bit
/// varstore field, whose VarOffset and width count bits, spans the bytes of its bits.
fn value_bytes(question: &IFROperation) -> Option<std::ops::Range<usize>> {
    Some(value_question(question)?.location().bytes())
}

/// Returns where the question keeps its value and the value, or why it cannot be read.
pub(super) fn read_question_value(
    question: &IFROperation,
    varstore: &Result<Box<dyn VariableStore>>,
    reader: &mut EfivarReader,
) -> std::result::Result<(ReadableLocation, u64), ValueUnavailable> {
    let Some(value_question) = value_question(question) else {
        return Err(ValueUnavailable::NotDecoded(question.op_code));
    };
    // before the read: a field that cannot be read gives its own reason, and dump-efivars keeps
    // no bytes for it
    let location = value_question
        .location()
        .check()
        .map_err(ValueUnavailable::BitField)?;
    let bytes = read_question_bytes(question, varstore, reader)?;
    Ok((location, location.read(bytes)))
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

    use super::super::conditions::IncludedStates;
    use super::super::display;
    use super::super::display_answer;
    use super::super::handle_form_set;
    use super::super::ifr_fixtures::*;
    use super::super::list_questions;
    use super::super::EFI_IFR_NUMERIC_SIZE_2;
    use super::super::EFI_IFR_NUMERIC_SIZE_4;
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
            &question,
            &Ok(Box::new(efi_variable("Setup", 1))),
            &mut reader,
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
            &strings(),
            IncludedStates::empty(),
            None,
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
        list_questions(root, &strings(), IncludedStates::all(), None, reader)
            .into_iter()
            .map(|(_, state)| state.annotation())
            .collect()
    }

    #[test]
    fn disabled_source_leaves_value_conditions_undetermined() {
        let efivars = Efivars::new();
        let undetermined = " <selectable or suppressed: EqIdVal of question 0x0002: \
            <ValueUnavailable: EFI variables not read>>";

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
            display(Rc::clone(&root), 0, &strings(), reader).expect("display the FormSet")
        };
        let efivars = Efivars::new();
        efivars.write(&efi_variable("Setup", 2), &[1, 0]);
        let mut reader = efivars.reader();
        let shown_before = show(&mut efivars.reader());

        let listed: Vec<String> = list_questions(
            Rc::clone(&root),
            &strings(),
            IncludedStates::empty(),
            None,
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
            Err("<ValueUnavailable: FormSet value not decoded>".to_string()),
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
                    &strings(),
                    IncludedStates::empty(),
                    None,
                    &mut reader,
                )
                .into_iter()
                .map(|(question, _)| question.value)
                .collect();
                let shown = display(root, 0, &strings(), &mut reader).expect("display");
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
            Err("<ValueUnavailable: FormSet value not decoded>".to_string()),
            "FORM_SET"
        );

        assert_eq!(
            reader.decoded,
            BTreeMap::from([
                (
                    efi_variable("Bits", 4).variable_key(),
                    vec![DecodedValue {
                        size: 4,
                        value: 1..2
                    }]
                ),
                (
                    efi_variable("Hidden", 4).variable_key(),
                    vec![DecodedValue {
                        size: 4,
                        value: 3..4
                    }]
                ),
                (
                    efi_variable("Setup", 4).variable_key(),
                    vec![DecodedValue {
                        size: 4,
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
