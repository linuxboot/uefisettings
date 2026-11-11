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

//! The exports that only the UEFI Shell build has: those that read the HII database of the
//! firmware it runs on and write its variables, through boot services.
//!
//! Every export that reaches this firmware, those here, VariableBackend's, CapsuleBackend's, and
//! get, set, list-questions and show-ifr, which read its Time Services and, from
//! EfivarSource::System, its variables, calls the uefi crate, which
//! panics unless the image has initialized it: uefi::table::set_system_table, then
//! uefi::boot::set_image_handle, as uefisettings.efi's entry point uefi_std_entry does.

use anyhow::anyhow;
use anyhow::Result;
use log::debug;

use super::set_refusal;
use super::staged_question;
use super::text_languages;
use super::CapsuleBackend;
use super::DriverHeldValues;
use super::EfivarSource;
use super::HiiBackend;
use super::IncludedStates;
use super::QuestionList;
use super::SetOptions;
use super::UnsafeOperation;
use super::UnsafeOperations;
use super::VariableBackend;
use super::VolatileWrites;
use crate::capsule_services::RuntimeCapsuleServices;
use crate::efi_variables::CapsuleDelivery;
use crate::efi_variables::UpdateCapsuleDelivery;
use crate::efi_variables::VariableData;
use crate::efi_variables::VariableInfo;
use crate::efi_variables::VariableInfoSource;
use crate::efi_variables::VariableNames;
use crate::efi_variables::VariableStorageInfo;
use crate::efi_variables::VendorTable;
use crate::efi_variables::EFI_JSON_CAPSULE_RESULT_TABLE_GUID;
use crate::efi_variables::EFI_JSON_CONFIG_DATA_TABLE_GUID;
use crate::firmware_width::FirmwareWidth;
use crate::hii::config_access::ConfigAccessDriver;
use crate::hii::config_routing::RoutingProtocol;
use crate::hii::database_protocol::PackageLists;
use crate::hii::export_package_lists;
use crate::hii::form_set_stores::FormSetStore;
use crate::hii::forms::DriverHeldQuestion;
use crate::hii::forms::PasswordQuestions;
use crate::hii::forms::QuestionDescriptor;
use crate::hii::get_keywords_witnessed;
use crate::hii::package;
use crate::hii::question_callbacks::change;
use crate::hii::question_callbacks::retrieve;
use crate::hii::question_callbacks::Call;
use crate::hii::question_callbacks::DriverQuestion;
use crate::hii::question_callbacks::FormSetAccess;
use crate::hii::question_callbacks::IfrValue;
use crate::hii::set_keywords_witnessed;
use crate::hii::time_services::TimeServices;
use crate::hii::FirmwareKeywordHandler;
use crate::hii::FirmwareVariables;
use crate::hii::KeywordGetOptions;
use crate::hii::KeywordValues;
use crate::hii::VariableReach;
use crate::hii::VariableServices;
use crate::hii::WithholdingVariables;
use crate::runtime_time_services::RuntimeTimeServices;
use crate::staged_set::apply::apply_staged_withholding;
use crate::staged_set::apply::Application;
use crate::staged_set::apply::StagedRequestDriver;
use crate::staged_set::StagedRequest;
use crate::uefi_config_table::SystemConfigurationTable;
use crate::unsafe_operations::LiftedOperations;

/// What set and get read and write when no file names them: this firmware's HII database and
/// variables, through boot services.
impl HiiBackend {
    /// This firmware's HiiDB.
    pub(super) fn system_hiidb() -> Result<Vec<u8>> {
        Self::export_hiidb()
    }

    /// This firmware's variables.
    pub(super) fn system_variables() -> Result<impl FirmwareVariables> {
        Ok(VariableServices)
    }

    /// This firmware's Time Services.
    pub(super) fn system_time_services() -> impl TimeServices {
        RuntimeTimeServices
    }
}

/// What the variable commands read: this firmware's variables, through boot services.
impl VariableBackend {
    /// The names of this firmware's variables, from GetNextVariableName().
    pub(super) fn system_variable_names() -> impl VariableNames {
        VariableServices
    }

    /// The attributes and sizes of this firmware's variables, from GetVariable().
    pub(super) fn system_variable_info() -> Result<impl VariableInfoSource> {
        Ok(VariableServices)
    }

    /// What system_variable_data reaches.
    pub(super) const SYSTEM_VARIABLE_REACH: VariableReach = VariableServices::REACH;

    /// The attributes and data of this firmware's variables, from GetVariable().
    pub(super) fn system_variable_data() -> Result<impl VariableData> {
        Ok(VariableServices)
    }

    /// The storage of this firmware's variables, from QueryVariableInfo().
    pub(super) fn system_variable_storage() -> impl VariableStorageInfo {
        VariableServices
    }
}

/// Where the capsule commands deliver: this firmware, through its Capsule Services. What they
/// read: the configuration tables of its System Table.
impl CapsuleBackend {
    /// QueryCapsuleCapabilities(), then UpdateCapsule().
    pub(super) fn system_capsule_delivery() -> impl CapsuleDelivery {
        UpdateCapsuleDelivery(RuntimeCapsuleServices)
    }

    /// The JSON configuration table.
    pub(super) fn system_json_config_data_table() -> Result<Option<impl VendorTable>> {
        SystemConfigurationTable::find(&EFI_JSON_CONFIG_DATA_TABLE_GUID)
    }

    /// The JSON capsule result table.
    pub(super) fn system_json_capsule_result_table() -> Result<Option<impl VendorTable>> {
        SystemConfigurationTable::find(&EFI_JSON_CAPSULE_RESULT_TABLE_GUID)
    }

    /// The width of this firmware, which runs this build natively.
    pub(super) fn system_firmware_width() -> Result<FirmwareWidth> {
        Ok(FirmwareWidth::of_this_build())
    }
}

impl HiiBackend {
    /// The HiiDB of this firmware: every package list that EFI_HII_DATABASE_PROTOCOL exports.
    pub fn export_hiidb() -> Result<Vec<u8>> {
        export_package_lists()
    }

    /// The VariableInfo of the EFI variable `name` of the vendor GUID `vendor`, such as
    /// "8C78A505-BAA0-4C4A-869F-000000000101", whose data it reads only for the metadata of a
    /// variable with EFI_VARIABLE_ENHANCED_AUTHENTICATED_ACCESS: as VariableBackend::info.
    pub fn variable_info(name: &str, vendor: &str) -> Result<VariableInfo> {
        VariableBackend::info(name, vendor)
    }

    /// What GetData() (UEFI 2.11 §35.3.3) of EFI_CONFIG_KEYWORD_HANDLER_PROTOCOL reads of
    /// `requests`, a `<MultiKeywordRequest>` of `<KeywordRequest>`s of an optional PATH, a
    /// KEYWORD, an optional KEYWORDINFO and an optional `<Filter>`, in `namespace`, such as
    /// "x-UEFI-ns", else in a language of the prefix "x-UEFI": for each request, a `<KeywordResp>`
    /// per package list of this firmware's HiiDB whose question of the keyword get would read as
    /// GetData() does and that passes the `<Filter>`, which `options.filter_by` applies, with the
    /// `<KeywordInfoResp>` of KEYWORDINFO from `options.info_source`: the HiiDB's IFR, its texts
    /// in the language that PlatformLang picks, or GetData(). It fails where GetData() changed
    /// the bytes of a PASSWORD question in an EFI variable, which uefisettings never writes back.
    pub fn keyword_get(
        requests: &str,
        namespace: Option<&str>,
        options: KeywordGetOptions,
    ) -> Result<KeywordValues> {
        let lists = package::read_db(&Self::export_hiidb()?)?;
        let platform_lang = EfivarSource::System.platform_lang()?;
        get_keywords_witnessed(
            &lists,
            requests,
            namespace,
            &text_languages(None, platform_lang.as_deref()),
            options,
            VariableServices,
            &FirmwareKeywordHandler,
        )
    }

    /// Writes `keywords`, a `<MultiKeywordResp>`, with one SetData() (UEFI 2.11 §35.3.2) of
    /// EFI_CONFIG_KEYWORD_HANDLER_PROTOCOL, unless set, with `options`, would refuse a keyword's
    /// question or value in this firmware's HiiDB and variables; then returns what GetData() reads
    /// back, which must hold each VALUE written, as a number, and the unsafe operations that it
    /// lifted. It fails where SetData() or that GetData() changed the bytes of a PASSWORD
    /// question in an EFI variable, which uefisettings never writes back.
    pub fn keyword_set(
        keywords: &str,
        options: &KeywordSetOptions,
    ) -> Result<(KeywordValues, Vec<UnsafeOperation>)> {
        let lists = package::read_db(&Self::export_hiidb()?)?;
        set_keywords_witnessed(
            &lists,
            keywords,
            options.include,
            options.unsafe_operations,
            options.volatile,
            VariableServices,
            &FirmwareKeywordHandler,
        )
    }
}

/// The options of HiiBackend::keyword_set.
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct KeywordSetOptions {
    /// The states of the questions and options to select too, as set selects them
    pub include: IncludedStates,
    /// Whether to do the unsafe operations that it meets, which it returns: a write in a HiiDB
    /// that declares a setup password question, never one of a read-only question, which the
    /// Keyword Handler refuses
    pub unsafe_operations: UnsafeOperations,
    /// Whether to write a keyword whose question keeps its value in a volatile variable, as
    /// SetOptions::volatile
    pub volatile: VolatileWrites,
}

/// What get and set do with a question whose driver holds its value: call that driver's
/// Callback() for it, unless --no-efivars keeps get from this firmware's state.
impl HiiBackend {
    pub(super) fn driver_held_values<'a>(
        hiidb: &'a [u8],
        efivars: &EfivarSource,
    ) -> Option<Box<dyn DriverHeldValues + 'a>> {
        match efivars {
            EfivarSource::System => Some(Box::new(DriverCallbacks { hiidb })),
            EfivarSource::Disabled => None,
        }
    }

    /// set calls the driver's Callback()s, as get does.
    pub(super) fn driver_held_setter<'a>(
        hiidb: &'a [u8],
        _options: &SetOptions,
    ) -> Result<Option<Box<dyn DriverHeldValues + 'a>>> {
        Ok(Self::driver_held_values(hiidb, &EfivarSource::System))
    }
}

/// The Callback()s of the drivers of the package lists of `hiidb`, the HiiDB that get and set
/// read.
struct DriverCallbacks<'a> {
    hiidb: &'a [u8],
}

/// What a Callback() sequence reaches: the driver, the stores of the question's FormSet, and the
/// variables without the bytes of PASSWORD questions, which no sequence reads or writes.
struct Reached {
    driver: ConfigAccessDriver,
    stores: Vec<FormSetStore>,
    variables: WithholdingVariables<VariableServices>,
}

impl DriverCallbacks<'_> {
    /// What the sequence for `held` of `list` reaches, after checking that the HII database still
    /// exports `hiidb`, so that the list's index names its handle.
    fn reach(&self, list: &QuestionList<'_>, held: &DriverHeldQuestion) -> Result<Reached> {
        let lists = PackageLists::export()?;
        if lists.hiidb() != self.hiidb {
            return Err(anyhow!(
                "the HII database changed since uefisettings read it; run the command again"
            ));
        }
        let parsed = package::read_db(self.hiidb)?;
        let package_list = parsed
            .get(list.index)
            .ok_or_else(|| no_package_list(list.index))?;
        held.check_disabled_forms(&package_list.disabled_forms)?;
        let variables = PasswordQuestions::of_lists(&parsed).withholding(VariableServices)?;
        let handle = lists
            .handle(list.index)
            .ok_or_else(|| no_package_list(list.index))?;
        let driver = ConfigAccessDriver::of_package_list(handle)?;
        let stores = held
            .stores
            .iter()
            .filter_map(|declaration| FormSetStore::of(declaration, list.device_path).transpose())
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Reached {
            driver,
            stores,
            variables,
        })
    }
}

impl DriverHeldValues for DriverCallbacks<'_> {
    fn store_name(&self) -> &'static str {
        "its driver"
    }

    fn get(
        &self,
        list: &QuestionList<'_>,
        question: &QuestionDescriptor,
        held: &DriverHeldQuestion,
    ) -> Result<String> {
        let reached = match self.reach(list, held) {
            Ok(reached) => reached,
            Err(error) => return Ok(format!("<ValueUnavailable: {error:#}>")),
        };
        let routing = RoutingProtocol::open();
        let access = FormSetAccess {
            stores: reached.stores,
            routing: &routing,
            variables: &reached.variables,
        };
        let retrieval = retrieve(&reached.driver, driver_question(held), access);
        log_calls(&retrieval.calls);
        retrieval.answer(&question.question, |value| shown(question, value))
    }

    /// set reaches the question's driver, its stores and the variables, as `reach` finds them.
    fn check_set(
        &self,
        list: &QuestionList<'_>,
        question: &QuestionDescriptor,
        held: &DriverHeldQuestion,
    ) -> Result<()> {
        self.reach(list, held)
            .map(drop)
            .map_err(|error| set_refusal(&question.question, format!("{error:#}")))
    }

    fn set(
        &self,
        list: &QuestionList<'_>,
        question: &QuestionDescriptor,
        held: &DriverHeldQuestion,
        value: u64,
    ) -> Result<String> {
        let reached = self
            .reach(list, held)
            .map_err(|error| set_refusal(&question.question, format!("{error:#}")))?;
        let routing = RoutingProtocol::open();
        let access = FormSetAccess {
            stores: reached.stores,
            routing: &routing,
            variables: &reached.variables,
        };
        let new_value = IfrValue {
            value_type: held.value_type,
            value,
        };
        let changed = change(&reached.driver, driver_question(held), new_value, access);
        log_calls(&changed.calls);
        changed.annotation(&question.question, |value| shown(question, value))
    }
}

/// The error of a package list `index` that the HII database does not have.
fn no_package_list(index: usize) -> anyhow::Error {
    anyhow!("the HII database has no package list {index}")
}

impl HiiBackend {
    /// apply-staged of `nonce`, which ends the command line of the staged set's Boot####: applies
    /// the staged set of `nonce` through the drivers of this firmware's HII database, records its
    /// outcome and deletes its Boot####, as staged_set::apply::apply_staged_withholding does, writing no byte
    /// of a PASSWORD question; where it cannot tell those bytes, as for a PASSWORD question whose
    /// VarStore it does not find, it writes nothing. Returns what it did, in lines, for
    /// uefisettings.efi to print before it resets.
    pub fn apply_staged(nonce: &str) -> Vec<String> {
        match Self::apply_staged_set(nonce) {
            Ok(application) => application.lines(),
            Err(error) => vec![format!("failed: {error:#}")],
        }
    }

    /// apply_staged_withholding of `nonce` through this firmware's variables, without the bytes of
    /// the PASSWORD questions of its HII database.
    fn apply_staged_set(nonce: &str) -> Result<Application> {
        let lists = package::read_db(&Self::export_hiidb()?)?;
        apply_staged_withholding(&lists, VariableServices, nonce, &StagedCallbacks)
    }
}

/// The drivers of this firmware's HII database, as apply-staged reaches them.
struct StagedCallbacks;

impl StagedRequestDriver for StagedCallbacks {
    /// Sets the question of `request` as set does, in the HII database as exported now, as the
    /// Callback()s of a request before may have changed it.
    fn apply(&self, request: &StagedRequest) -> Result<(String, Vec<UnsafeOperation>)> {
        let hiidb = HiiBackend::export_hiidb()?;
        let parsed = package::read_db(&hiidb)?;
        let mut reader = PasswordQuestions::of_lists(&parsed).reader(Box::new(VariableServices))?;
        let platform_lang = EfivarSource::System.platform_lang()?;
        let (list, question, held, lifted) = staged_question(
            &parsed,
            request,
            &text_languages(None, platform_lang.as_deref()),
            &mut reader,
        )?;
        let set = DriverCallbacks { hiidb: &hiidb }
            .set(&list, &question, &held, request.value)
            .map(|annotation| annotation.trim_start().to_owned());
        LiftedOperations::after(lifted, set)
    }
}

/// The DriverQuestion of `held`.
fn driver_question(held: &DriverHeldQuestion) -> DriverQuestion {
    DriverQuestion {
        question_id: held.question_id,
        initial: IfrValue {
            value_type: held.value_type,
            value: held.initial,
        },
        form_set_has_stores: !held.stores.is_empty(),
        read_expression: held.read_expression,
        write_expression: held.write_expression,
    }
}

/// `value` of `question` as get shows it.
fn shown(question: &QuestionDescriptor, value: IfrValue) -> String {
    question
        .driver_held_text(value.value)
        .unwrap_or_else(|| value.value.to_string())
}

/// Logs each Callback() of a sequence.
fn log_calls(calls: &[Call]) {
    for call in calls {
        debug!(
            "Callback({}) with {:#x}: {}, {}",
            call.action, call.value.value, call.returned.status, call.returned.request
        );
    }
}
