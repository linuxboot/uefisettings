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

//! set on Linux of a question whose value only its driver holds: staged for the next boot, on the
//! mounted EFI system partition that BootCurrent names.

use std::fs;
use std::path::Path;
use std::path::PathBuf;

use anyhow::Context;
use anyhow::Result;
use rand::Rng;

use super::plan_stage;
use super::record_set;
use super::stage_new;
use super::Nonce;
use super::StagePlan;
use super::StagedRequest;
use super::StagedSet;
use crate::efi_variables::globals::secure_boot;
use crate::efi_variables::VariableData;
use crate::esp::linux::LinuxPaths;
use crate::esp::linux::MountedEsp;
use crate::esp::linux::PathDevices;
use crate::exports::set_refusal;
use crate::exports::DriverHeldValues;
use crate::exports::QuestionList;
use crate::exports::SetOptions;
use crate::hii::forms::AccessLevel;
use crate::hii::forms::DriverHeldQuestion;
use crate::hii::forms::IncludedStates;
use crate::hii::forms::PasswordQuestions;
use crate::hii::forms::QuestionDescriptor;
use crate::hii::package::ParsedPackageList;
use crate::hii::EfivarFiles;
use crate::hii::VariableReach;
use crate::hii::WithholdingVariables;
use crate::unsafe_operations::UnsafeOperations;

/// What set does on Linux with a question whose value only its driver holds: stages it for the
/// next boot, the first set with the uefisettings.efi `image`, with the `include` and
/// `access_level` that set selected it with and its grant of `unsafe_operations`, writing no byte
/// of the HiiDB's `passwords`.
pub(crate) struct NextBootStaging {
    pub(crate) image: Option<PathBuf>,
    pub(crate) include: IncludedStates,
    pub(crate) access_level: Option<AccessLevel>,
    pub(crate) unsafe_operations: UnsafeOperations,
    pub(crate) passwords: PasswordQuestions,
}

impl NextBootStaging {
    /// What set stages with `options` in the HiiDB of the package lists `lists`.
    pub(crate) fn of(options: &SetOptions, lists: &[ParsedPackageList]) -> Self {
        Self {
            image: options.staging_image.clone(),
            include: options.include,
            access_level: options.access_level,
            unsafe_operations: options.unsafe_operations,
            passwords: PasswordQuestions::of_lists(lists),
        }
    }

    /// `variables` without the bytes of PASSWORD questions, which staging fails to write over.
    fn withholding<V: VariableData>(&self, variables: V) -> Result<WithholdingVariables<V>> {
        Ok(self
            .passwords
            .withholding_of(variables, VariableReach::Runtime)?)
    }

    /// Stages `request` through `variables` without the bytes of PASSWORD questions, on the ESP
    /// that MountedEsp::locate finds in `paths`, with --image: stage_request.
    fn stage(
        &self,
        variables: impl VariableData,
        paths: &LinuxPaths<impl PathDevices>,
        request: StagedRequest,
        nonce: Nonce,
    ) -> Result<String> {
        stage_request(
            &self.withholding(variables)?,
            paths,
            self.image.as_deref(),
            request,
            nonce,
        )
    }

    /// The request of `value` for the question `question`, whose driver holds it as `held`.
    fn request(&self, question: &str, held: &DriverHeldQuestion, value: u64) -> StagedRequest {
        StagedRequest {
            question: question.to_owned(),
            form_set: held.form_set,
            question_id: held.question_id,
            value_type: held.value_type,
            value,
            include: self.include,
            access_level: self.access_level,
            unsafe_operations: self.unsafe_operations,
        }
    }
}

impl DriverHeldValues for NextBootStaging {
    fn store_name(&self) -> &'static str {
        "staged for the next boot"
    }

    /// get reaches no driver from Linux, and shows the question's refusal instead.
    fn get(
        &self,
        _list: &QuestionList<'_>,
        question: &QuestionDescriptor,
        _held: &DriverHeldQuestion,
    ) -> String {
        question.value.clone()
    }

    /// set finds the ESP, plan_stage allows staging there, and a new set has a readable --image.
    fn check_set(
        &self,
        _list: &QuestionList<'_>,
        question: &QuestionDescriptor,
        _held: &DriverHeldQuestion,
    ) -> Result<()> {
        prepare(
            &self.withholding(EfivarFiles::system())?,
            &LinuxPaths::default(),
            self.image.as_deref(),
            &question.question,
        )
        .map(drop)
    }

    fn set(
        &self,
        _list: &QuestionList<'_>,
        question: &QuestionDescriptor,
        held: &DriverHeldQuestion,
        value: u64,
    ) -> Result<String> {
        self.stage(
            EfivarFiles::system(),
            &LinuxPaths::default(),
            self.request(&question.question, held, value),
            Nonce(rand::thread_rng().gen()),
        )
    }
}

/// How stage_request stages a request, once prepare allowed it.
enum Prepared {
    /// Appended to the pending set
    Append(StagedSet),
    /// In a new set whose Boot#### starts a copy of these image bytes
    New(Vec<u8>),
}

/// The ESP that MountedEsp::locate finds, and how a request of `question` is staged there:
/// appended to the pending set, else in a new set with the bytes of `image`. Refused as set
/// refuses `question`, before anything is staged.
fn prepare(
    variables: &impl VariableData,
    paths: &LinuxPaths<impl PathDevices>,
    image: Option<&Path>,
    question: &str,
) -> Result<(MountedEsp, Prepared)> {
    let esp = MountedEsp::locate(variables, paths)
        .map_err(|error| set_refusal(question, format!("{error:#}")))?;
    let prepared = match plan_stage(variables, &esp)
        .map_err(|error| set_refusal(question, format!("{error:#}")))?
    {
        StagePlan::Append(set) => Prepared::Append(set),
        StagePlan::New => {
            let Some(image) = image else {
                return Err(set_refusal(question, missing_image(variables)?));
            };
            Prepared::New(fs::read(image).with_context(|| format!("read {}", image.display()))?)
        }
    };
    Ok((esp, prepared))
}

/// Stages `request` on the ESP that MountedEsp::locate finds: appended to the pending set, else in
/// a new set of `nonce` whose Boot#### starts a copy of `image`. Returns set's annotation.
fn stage_request(
    variables: &impl VariableData,
    paths: &LinuxPaths<impl PathDevices>,
    image: Option<&Path>,
    request: StagedRequest,
    nonce: Nonce,
) -> Result<String> {
    let (esp, prepared) = prepare(variables, paths, image, &request.question)?;
    let set = match prepared {
        Prepared::Append(mut set) => {
            set.requests.push(request);
            record_set(variables, &set)?;
            set
        }
        Prepared::New(image) => stage_new(variables, &esp, esp.hard_drive, request, &image, nonce)?,
    };
    Ok(format!(
        " <staged for the next boot, as Boot{:04X}: restart to apply>",
        set.boot_option
    ))
}

/// Why a new staged set needs --image: under Secure Boot, signed for db.
fn missing_image(variables: &impl VariableData) -> Result<String> {
    let staged = "its driver holds its value, which only uefisettings.efi reaches before the OS \
                  starts; so set stages it for the next boot, which starts a uefisettings.efi \
                  that set copies to the EFI system partition";
    Ok(match secure_boot(variables)? == Some(1) {
        true => format!(
            "{staged}. Secure Boot is enabled, so name a uefisettings.efi signed for db with \
             --image: the firmware does not start an image whose signature db lacks (UEFI 2.11 \
             §32.4.2)"
        ),
        false => format!("{staged}. Name that uefisettings.efi with --image"),
    })
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;
    use crate::efi_variables::globals::tests::key;
    use crate::efi_variables::globals::EFI_GLOBAL_VARIABLE;
    use crate::efi_variables::load_option::LoadOption;
    use crate::efi_variables::UEFISETTINGS_VENDOR_GUID;
    use crate::esp::linux::tests::booted_from;
    use crate::esp::linux::tests::gpt_512_esp;
    use crate::esp::linux::tests::FakeLinux;
    use crate::hii::forms::ifr_fixtures::form;
    use crate::hii::forms::ifr_fixtures::form_set;
    use crate::hii::forms::ifr_fixtures::parse_form_set;
    use crate::hii::forms::ifr_fixtures::password_on;
    use crate::hii::forms::ifr_fixtures::var_store_efi;
    use crate::hii::forms::ifr_fixtures::var_store_efi_of;
    use crate::hii::forms::ifr_fixtures::NIL_GUID;
    use crate::hii::forms::ifr_fixtures::NV_BS_RT;
    use crate::hii::forms::IfrValueType;
    use crate::hii::package::hiidb_fixtures::form_package_of;
    use crate::hii::package::hiidb_fixtures::package_list_with_guid;
    use crate::hii::package::hiidb_fixtures::password_past_the_walk_hiidb;
    use crate::hii::package::hiidb_fixtures::END_PACKAGE;
    use crate::hii::package::hiidb_fixtures::PAST_THE_WALK_LIST_GUID;
    use crate::hii::package::read_db;
    use crate::hii::package::Guid;
    use crate::hii::VolatileWrites;
    use crate::staged_set::StagedSet;
    use crate::staged_set::StagedState;
    use crate::staged_set::IMAGE_PATH;

    const NONCE: Nonce = Nonce([0x5A; 16]);
    const QUESTION: &str = "Generic Question";

    fn request(value: u64) -> StagedRequest {
        StagedRequest {
            question: QUESTION.to_owned(),
            form_set: "8C78A505-BAA0-4C4A-869F-000000001A09"
                .parse()
                .expect("a GUID"),
            question_id: 0x0201,
            value_type: IfrValueType::NumSize8,
            value,
            include: IncludedStates::empty(),
            access_level: None,
            unsafe_operations: UnsafeOperations::Refuse,
        }
    }

    /// set stages a request of the question and value with the states, access level and grant of
    /// unsafe operations that it selected the question with, and the image that it names.
    #[test]
    fn set_stages_what_it_selected() {
        for grant in [UnsafeOperations::Refuse, UnsafeOperations::Allow] {
            let options = SetOptions {
                include: IncludedStates::GRAYED_OUT,
                access_level: Some(AccessLevel::User),
                unsafe_operations: grant,
                // no request takes it: a driver, not a variable, keeps a staged value
                volatile: VolatileWrites::Allow,
                // no request takes it: a request holds the value, not the text it was picked by
                language: Some("fr-FR".to_owned()),
                staging_image: Some(PathBuf::from("uefisettings.efi")),
            };
            let form_set = "8C78A505-BAA0-4C4A-869F-000000001A09"
                .parse()
                .expect("a GUID");

            let staging = NextBootStaging::of(&options, &[]);
            let held = DriverHeldQuestion::checkbox(form_set, 0x0201);
            let request = staging.request(QUESTION, &held, 1);

            assert_eq!(staging.image, options.staging_image, "the image");
            assert_eq!(
                request,
                StagedRequest {
                    question: QUESTION.to_owned(),
                    form_set,
                    question_id: 0x0201,
                    value_type: IfrValueType::Boolean,
                    value: 1,
                    include: IncludedStates::GRAYED_OUT,
                    access_level: Some(AccessLevel::User),
                    unsafe_operations: grant,
                },
                "{grant:?}"
            );
        }
    }

    #[test]
    fn set_stages_a_new_set_on_the_esp_then_appends_to_it() {
        let (linux, esp) = FakeLinux::with_esp();
        let variables = booted_from(Some(gpt_512_esp()));
        let images = TempDir::new().expect("a temporary directory");
        let image = images.path().join("uefisettings.efi");
        fs::write(&image, b"MZ uefisettings").expect("the image");

        let staged = stage_request(&variables, &linux.paths, Some(&image), request(1), NONCE);

        assert_eq!(
            staged.map_err(|err| format!("{err:#}")),
            Ok(" <staged for the next boot, as Boot0000: restart to apply>".to_owned()),
            "staged"
        );
        assert_eq!(
            fs::read(
                esp.join("EFI")
                    .join("uefisettings")
                    .join("uefisettings.efi")
            )
            .ok(),
            Some(b"MZ uefisettings".to_vec()),
            "the image on the ESP"
        );
        let boot0000 = variables
            .variables
            .borrow()
            .get(&key("Boot0000", EFI_GLOBAL_VARIABLE))
            .map(|contents| LoadOption::decode(contents.data()).expect("Boot0000"))
            .expect("Boot0000");
        assert_eq!(
            boot0000.file_paths.hard_drive(),
            Ok(Some(gpt_512_esp())),
            "Boot0000's Hard Drive node"
        );
        assert_eq!(
            boot0000.file_paths.image_path().map(|nodes| nodes.len()),
            Ok(2),
            "Boot0000's HD()+File"
        );
        let StagedState::Pending(set) = StagedState::read(&variables).expect("the state") else {
            panic!("no pending set");
        };
        assert_eq!(
            (
                set.boot_option,
                set.image.path.as_str(),
                set.requests.as_slice()
            ),
            (0x0000, IMAGE_PATH, [request(1)].as_slice()),
            "the pending set"
        );

        // a second set appends, without --image
        let appended = stage_request(&variables, &linux.paths, None, request(2), Nonce([0; 16]));

        assert_eq!(
            appended.map_err(|err| format!("{err:#}")),
            Ok(" <staged for the next boot, as Boot0000: restart to apply>".to_owned()),
            "appended"
        );
        assert_eq!(
            StagedState::read(&variables).expect("the state"),
            StagedState::Pending(StagedSet {
                requests: vec![request(1), request(2)],
                ..set
            }),
            "the pending set, appended to"
        );
    }

    #[test]
    fn a_new_set_needs_an_image_signed_for_db_under_secure_boot() {
        let (linux, _esp) = FakeLinux::with_esp();
        let staged = "cannot set question \"Generic Question\": its driver holds its value, which \
                      only uefisettings.efi reaches before the OS starts; so set stages it for the \
                      next boot, which starts a uefisettings.efi that set copies to the EFI \
                      system partition";
        for (case, secure_boot, want) in [
            (
                "no SecureBoot",
                None,
                format!("{staged}. Name that uefisettings.efi with --image"),
            ),
            (
                "SecureBoot 0",
                Some(0u8),
                format!("{staged}. Name that uefisettings.efi with --image"),
            ),
            (
                "SecureBoot 1",
                Some(1u8),
                format!(
                    "{staged}. Secure Boot is enabled, so name a uefisettings.efi signed for db \
                     with --image: the firmware does not start an image whose signature db lacks \
                     (UEFI 2.11 §32.4.2)"
                ),
            ),
        ] {
            let variables = booted_from(Some(gpt_512_esp()));
            let variables = match secure_boot {
                Some(value) => variables.with("SecureBoot", EFI_GLOBAL_VARIABLE, &[value]),
                None => variables,
            };

            let got = stage_request(&variables, &linux.paths, None, request(1), NONCE);

            assert_eq!(got.map_err(|err| format!("{err:#}")), Err(want), "{case}");
            assert!(
                !variables
                    .variables
                    .borrow()
                    .contains_key(&key("UefisettingsStagedSet", UEFISETTINGS_VENDOR_GUID)),
                "{case}: no record"
            );
        }
    }

    /// Staging writes through the variables without the bytes of PASSWORD questions: in a HiiDB
    /// whose PASSWORD question keeps its password in BootNext, as its VarStore or as a VarStore
    /// outside any FormSet of its VarStoreId, a new set fails to write BootNext and undoes the
    /// steps before it, so nothing is staged and BootNext is never written.
    #[test]
    fn staging_writes_no_password_byte() {
        let boot_next = var_store_efi_of(1, EFI_GLOBAL_VARIABLE.into(), "BootNext", NV_BS_RT, 40);
        let in_form_set = ParsedPackageList {
            guid: NIL_GUID,
            device_path: None,
            strings: Vec::new(),
            forms: vec![parse_form_set(&[
                boot_next.clone(),
                form(1, &[password_on(0x10, 1, 1, 0)]),
            ])],
            ignored_ifr: Vec::new(),
            outside_ifr: Vec::new(),
            malformed_outside_stores: Vec::new(),
            disabled_forms: Vec::new(),
            first_var_stores: Vec::new(),
        };
        let ifr = [
            boot_next,
            form_set(&[
                var_store_efi(1, "Setup", NV_BS_RT, 40),
                form(1, &[password_on(0x10, 1, 1, 0)]),
            ]),
        ];
        let outside = read_db(&package_list_with_guid(
            [0; 16],
            &[form_package_of(&ifr.concat()), END_PACKAGE.to_vec()].concat(),
        ))
        .expect("read_db")
        .remove(0);
        for (case, list) in [
            ("BootNext the PASSWORD's VarStore", in_form_set),
            ("BootNext a VarStore outside any FormSet of its id", outside),
        ] {
            let (linux, esp) = FakeLinux::with_esp();
            let variables = booted_from(Some(gpt_512_esp()));
            let images = TempDir::new().expect("a temporary directory");
            let image = images.path().join("uefisettings.efi");
            fs::write(&image, b"MZ uefisettings").expect("the image");
            let options = SetOptions {
                staging_image: Some(image),
                ..SetOptions::default()
            };

            let staged = NextBootStaging::of(&options, &[list]).stage(
                &variables,
                &linux.paths,
                request(1),
                NONCE,
            );

            assert_eq!(
                staged.map_err(|err| format!("{err:#}")),
                Err(format!(
                    "EFI variable {} holds a password at bytes 0..40, which set never writes",
                    key("BootNext", EFI_GLOBAL_VARIABLE)
                )),
                "{case}: staged"
            );
            assert!(
                !variables
                    .set
                    .borrow()
                    .contains(&key("BootNext", EFI_GLOBAL_VARIABLE)),
                "{case}: BootNext never written"
            );
            assert_eq!(
                StagedState::read(&variables).expect("the state"),
                StagedState::Idle(None),
                "{case}: nothing staged"
            );
            assert!(
                !variables
                    .variables
                    .borrow()
                    .contains_key(&key("Boot0000", EFI_GLOBAL_VARIABLE)),
                "{case}: no Boot0000"
            );
            assert!(
                !esp.join("EFI")
                    .join("uefisettings")
                    .join("uefisettings.efi")
                    .exists(),
                "{case}: no image on the ESP"
            );
        }
    }

    /// Staging writes through no variable of a HiiDB whose IFR past an op where the walk for
    /// FormSets ends may hold a PASSWORD in any variable (AnyVariablePasswords), as get and set do
    /// not: it refuses, and stages nothing.
    #[test]
    fn staging_refuses_a_hiidb_whose_ifr_past_the_walk_may_hold_a_password() {
        let lists = read_db(&password_past_the_walk_hiidb()).expect("read_db");
        let (linux, esp) = FakeLinux::with_esp();
        let variables = booted_from(Some(gpt_512_esp()));
        let images = TempDir::new().expect("a temporary directory");
        let image = images.path().join("uefisettings.efi");
        fs::write(&image, b"MZ uefisettings").expect("the image");
        let options = SetOptions {
            staging_image: Some(image),
            ..SetOptions::default()
        };

        let staged = NextBootStaging::of(&options, &lists).stage(
            &variables,
            &linux.paths,
            request(1),
            NONCE,
        );

        let want = format!(
            "PASSWORD questions of package list {} may be in the IFR that uefisettings ignores at \
             offset 0 of a form package, which has no op boundary, so in any variable: ",
            Guid::from(PAST_THE_WALK_LIST_GUID)
        );
        let staged = staged.map_err(|err| format!("{err:#}"));
        assert!(
            staged.as_ref().is_err_and(|error| error.starts_with(&want)),
            "staged: {staged:?}"
        );
        assert_eq!(variables.set.borrow().as_slice(), [], "no variable written");
        assert!(
            !esp.join("EFI").join("uefisettings").exists(),
            "no image on the ESP"
        );
    }

    /// Staging reads and writes no variable of a HiiDB with a PASSWORD that its driver may keep
    /// in any variable (AnyVariablePasswords), one of VarStoreId 0, which names no VarStore, or
    /// one that edk2 may route to a VARSTORE_NAME_VALUE, as get and set do not, also with
    /// --i-am-fine-to-brick-this-system: it refuses, and stages nothing. Beside a PASSWORD on a
    /// buffer VarStore it stages.
    #[test]
    fn staging_refuses_a_hiidb_whose_password_a_driver_may_keep_in_any_variable() {
        use crate::hii::forms::ifr_fixtures::form;
        use crate::hii::forms::ifr_fixtures::form_set;
        use crate::hii::forms::ifr_fixtures::password_on;
        use crate::hii::forms::ifr_fixtures::var_store;
        use crate::hii::forms::ifr_fixtures::var_store_name_value;
        use crate::hii::package::hiidb_fixtures::en_strings_package_of;
        use crate::hii::package::hiidb_fixtures::form_package_of;
        use crate::hii::package::hiidb_fixtures::package_list_with_guid;
        use crate::hii::package::hiidb_fixtures::END_PACKAGE;
        use crate::hii::package::read_db;

        for var_store_id in [0, 3, 1] {
            let lists = read_db(&package_list_with_guid(
                [0x55; 16],
                &[
                    form_package_of(&form_set(&[
                        var_store(1, [0x11; 16], "Store", 48),
                        var_store_name_value(3, [0x33; 16]),
                        form(1, &[password_on(3, 1, var_store_id, 4)]),
                    ])),
                    en_strings_package_of(&["Password"]),
                    END_PACKAGE.to_vec(),
                ]
                .concat(),
            ))
            .expect("read_db");
            let (linux, esp) = FakeLinux::with_esp();
            let variables = booted_from(Some(gpt_512_esp()));
            let images = TempDir::new().expect("a temporary directory");
            let image = images.path().join("uefisettings.efi");
            fs::write(&image, b"MZ uefisettings").expect("the image");
            let options = SetOptions {
                staging_image: Some(image),
                unsafe_operations: UnsafeOperations::Allow,
                ..SetOptions::default()
            };
            let request = StagedRequest {
                unsafe_operations: UnsafeOperations::Allow,
                ..request(1)
            };

            let staged = NextBootStaging::of(&options, &lists)
                .stage(&variables, &linux.paths, request, NONCE)
                .map_err(|err| format!("{err:#}"));

            match var_store_id {
                1 => assert!(staged.is_ok(), "VarStoreId 1: staged: {staged:?}"),
                _ => {
                    assert!(
                        staged.as_ref().is_err_and(|error| {
                            error.starts_with("PASSWORD question 0x0003 in FormSet ")
                                && (var_store_id != 0
                                    || error.contains(": VarStoreId 0 names no VarStore, "))
                                && error.ends_with(
                                    "; as a PASSWORD there may keep its password in any \
                                     variable, uefisettings reads and writes no variable of \
                                     this HiiDB",
                                )
                        }),
                        "VarStoreId {var_store_id}: staged: {staged:?}"
                    );
                    assert_eq!(variables.set.borrow().as_slice(), [], "no variable written");
                    assert_eq!(
                        variables.read.borrow().as_slice(),
                        [],
                        "VarStoreId {var_store_id}: no variable read"
                    );
                    assert!(
                        !esp.join("EFI").join("uefisettings").exists(),
                        "no image on the ESP"
                    );
                }
            }
        }
    }

    #[test]
    fn set_refuses_without_the_esp() {
        let linux = FakeLinux::new();
        let variables = booted_from(None);

        let got = stage_request(&variables, &linux.paths, None, request(1), NONCE);

        assert_eq!(
            got.map_err(|err| format!("{err:#}")),
            Err("cannot set question \"Generic Question\": no mounted vfat volume is an EFI system \
                 partition; mount it. Mounted: none"
                .to_owned()),
            "no ESP"
        );
    }
}
