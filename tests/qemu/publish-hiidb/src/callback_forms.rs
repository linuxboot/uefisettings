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

//! The HII package lists that `callback-forms` registers, for the UEFI Shell scenario
//! `shell-callback-forms` of `tests/qemu/scenarios.tsv`: UINT8 ONE_OF questions without a
//! VarStore, with EFI_IFR_FLAG_CALLBACK, whose driver holds their value, which only
//! EFI_HII_CONFIG_ACCESS_PROTOCOL.Callback() reaches (UEFI 2.11 §33.2.5.6). The package list of
//! each form set but the last is registered by a handle of its own, with a vendor device path,
//! so that the HII database keeps that path as the list's device path package and
//! EFI_HII_CONFIG_ROUTING_PROTOCOL routes the form set's stores to the handle's
//! EFI_HII_CONFIG_ACCESS_PROTOCOL (edk2-stable202608 HiiDatabaseDxe Database.c HiiNewPackageList,
//! ConfigRouting.c HiiConfigRoutingExtractConfig).
//! - [`FormSet::Plain`] declares no store; its questions ask for a platform reset in CHANGED, or
//!   reset the platform there, for the scenario `staged-set`.
//! - [`FormSet::Stores`] declares an EFI variable store and a 5-byte Buffer store, kept in the
//!   EFI variable of its name, whose byte 4 ExtractConfig() answers with the count of its
//!   calls, as a driver answers with data that is no setting; its questions' Callback()s keep
//!   the value in a variable of their own, overwrite a store, refuse in CHANGING, fail in
//!   CHANGED, ask for a save or a reconnection, answer RETRIEVE with a reset value or with
//!   EFI_UNSUPPORTED. A driver binding starts on its handle, for the reconnection.
//! - [`FormSet::Unreachable`] declares a Buffer store that its ExtractConfig() never answers.
//! - [`FormSet::Driverless`] is registered by no handle.
//! - [`FormSet::Password`], which `callback-forms-password` registers, declares a Buffer store
//!   with a PASSWORD question; its questions' CHANGED overwrites the store's other setting or
//!   the password.
//! - [`FormSet::DisabledPassword`], which `callback-forms-password` registers too, declares a
//!   Buffer store whose PASSWORD question is in a second form, which a CHECKBOX op shorter than
//!   its minimum disables (UEFI 2.11 §33.2.5.10.1).
//!
//! Every Callback(), ExtractConfig(), RouteConfig() and driver binding Start() prints a line,
//! which `shell/callback-forms.tsv` checks.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::string::ToString;
use alloc::vec::Vec;
use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::AtomicPtr;
use core::sync::atomic::AtomicU8;
use core::sync::atomic::Ordering;

use uefi::boot;
use uefi::boot::OpenProtocolAttributes;
use uefi::boot::OpenProtocolParams;
use uefi::cstr16;
use uefi::guid;
use uefi::println;
use uefi::proto::unsafe_protocol;
use uefi::runtime;
use uefi::runtime::ResetType;
use uefi::runtime::VariableAttributes;
use uefi::runtime::VariableVendor;
use uefi::CStr16;
use uefi::CString16;
use uefi::Guid;
use uefi::Status;
use uefi::StatusExt;
use uefi_raw::protocol::device_path::DevicePathProtocol;
use uefi_raw::protocol::driver::DriverBindingProtocol;
use uefi_raw::protocol::hii::config::BrowserAction;
use uefi_raw::protocol::hii::config::HiiConfigAccessProtocol;
use uefi_raw::protocol::hii::config::HiiConfigRoutingProtocol;
use uefi_raw::protocol::hii::form_browser::BrowserActionRequest;
use uefi_raw::protocol::hii::ifr::IfrTypeValue;
use uefi_raw::Char16;

use crate::driver_handle;
use crate::driver_handle::vendor_device_path;
use crate::hii_package::end;
use crate::hii_package::op;
use crate::hii_package::package;
use crate::hii_package::package_list;
use crate::hii_package::strings_package;
use crate::hii_package::EFI_HII_PACKAGE_FORMS;
use crate::hii_package::EFI_IFR_CHECKBOX_OP;
use crate::hii_package::EFI_IFR_FORM_OP;
use crate::hii_package::EFI_IFR_FORM_SET_OP;
use crate::hii_package::EFI_IFR_NUMERIC_OP;
use crate::hii_package::EFI_IFR_ONE_OF_OP;
use crate::hii_package::EFI_IFR_ONE_OF_OPTION_OP;
use crate::hii_package::EFI_IFR_PASSWORD_OP;
use crate::hii_package::EFI_IFR_VARSTORE_EFI_OP;
use crate::hii_package::EFI_IFR_VARSTORE_OP;
use crate::Failure;
use crate::RawHiiDatabase;

/// The vendor GUID of the stores and of the questions' variables, which the tests own.
const VENDOR: Guid = guid!("de145b29-c3cd-455f-91de-a76237b67c52");
/// The Attributes of every variable here: non-volatile, boot service and runtime access.
const NV_BS_RT: VariableAttributes = VariableAttributes::NON_VOLATILE
    .union(VariableAttributes::BOOTSERVICE_ACCESS)
    .union(VariableAttributes::RUNTIME_ACCESS);

/// The EFI variable store of [`FormSet::Stores`], and its value before any question
/// overwrites it.
const EFI_STORE: &CStr16 = cstr16!("CallbackStore");
const EFI_STORE_INITIAL: [u8; 4] = [0x5A; 4];
const EFI_STORE_ID: u16 = 1;
/// The VarStoreIds of the Buffer stores of [`FormSet::Stores`], [`FormSet::Unreachable`],
/// [`FormSet::Password`] and [`FormSet::DisabledPassword`].
const BUFFER_STORE_ID: u16 = 2;
const UNREACHABLE_STORE_ID: u16 = 3;
const PASSWORD_STORE_ID: u16 = 5;
const DISABLED_PASSWORD_STORE_ID: u16 = 6;

/// A Buffer store that ExtractConfig() and RouteConfig() here serve, kept in the EFI variable of
/// its name.
struct BufferStore {
    name: &'static CStr16,
    /// The device path of the handle whose form set declares it
    path: &'static [u8],
    initial: &'static [u8],
    /// The byte that ExtractConfig() answers with the count of its calls, whatever the variable
    /// holds there
    counted: Option<usize>,
}

/// The Buffer store of [`FormSet::Stores`]: a UINT32 setting at byte 0 and the call count at
/// byte 4.
static CALLBACK_BUFFER: BufferStore = BufferStore {
    name: cstr16!("CallbackBuffer"),
    path: &STORES_PATH,
    initial: &[0xA5, 0xA5, 0xA5, 0xA5, 0],
    counted: Some(4),
};
/// The Buffer store of [`FormSet::Password`]: a password of 2 CHAR16 at byte 0 and a UINT8
/// setting at byte 4.
static PASSWORD_BUFFER: BufferStore = BufferStore {
    name: cstr16!("CallbackPassword"),
    path: &PASSWORD_PATH,
    initial: &[0x11, 0x22, 0x33, 0x44, 0x07],
    counted: None,
};
static BUFFER_STORES: [&BufferStore; 2] = [&CALLBACK_BUFFER, &PASSWORD_BUFFER];

/// The calls of ExtractConfig() of [`CALLBACK_BUFFER`].
static EXTRACTIONS: AtomicU8 = AtomicU8::new(0);
/// The handle of [`FormSet::Stores`], the one controller of the driver binding.
static STORES_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(ptr::null_mut());

/// EFI_IFR_FLAG_CALLBACK and EFI_IFR_FLAG_RESET_REQUIRED (UEFI 2.11 §33.3.8.2.2).
const EFI_IFR_FLAG_CALLBACK: u8 = 0x04;
const EFI_IFR_FLAG_RESET_REQUIRED: u8 = 0x10;
/// EFI_IFR_NUMERIC_SIZE_1 and _4 with EFI_IFR_DISPLAY_UINT_DEC (UEFI 2.11 §33.3.8.3.47).
const UINT8_DECIMAL: u8 = 0x10;
const UINT32_DECIMAL: u8 = 0x12;
/// EFI_IFR_TYPE_NUM_SIZE_8, the Type of a UINT8 EFI_IFR_ONE_OF_OPTION.
const NUM_SIZE_8: u8 = 0x00;

// The strings, from string ID 2, after the language name, then the prompt of each question.
const TITLE: u16 = 2;
const HELP: u16 = 3;
const OFF: u16 = 4;
const ON: u16 = 5;
const TWICE: u16 = 6;
const COMMON_STRINGS: [&str; 6] = [
    "English",
    "uefisettings QEMU callback forms",
    "Questions whose driver holds their value",
    "Off",
    "On",
    "Twice",
];

/// The form sets, each in a package list of its own.
#[derive(Clone, Copy, PartialEq)]
enum FormSet {
    Plain,
    Stores,
    Unreachable,
    Driverless,
    Password,
    DisabledPassword,
}

/// The form sets that `callback-forms` registers, and those of `callback-forms-password`, apart
/// as a PASSWORD question has uefisettings.efi refuse every set without
/// --i-am-fine-to-brick-this-system.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Forms {
    Callbacks,
    Password,
}

impl Forms {
    fn form_sets(self) -> &'static [FormSet] {
        match self {
            Self::Callbacks => &[
                FormSet::Plain,
                FormSet::Stores,
                FormSet::Unreachable,
                FormSet::Driverless,
            ],
            Self::Password => &[FormSet::Password, FormSet::DisabledPassword],
        }
    }
}

impl FormSet {
    /// The GUID of the form set and of its package list.
    const fn guid(self) -> Guid {
        match self {
            Self::Plain => guid!("8c78a505-baa0-4c4a-869f-000000000210"),
            Self::Stores => guid!("8c78a505-baa0-4c4a-869f-000000000211"),
            Self::Unreachable => guid!("8c78a505-baa0-4c4a-869f-000000000202"),
            Self::Driverless => guid!("8c78a505-baa0-4c4a-869f-000000000203"),
            Self::Password => guid!("8c78a505-baa0-4c4a-869f-000000000204"),
            Self::DisabledPassword => guid!("8c78a505-baa0-4c4a-869f-000000001a14"),
        }
    }

    /// The device path of the handle that registers it, and its EFI_HII_CONFIG_ACCESS_PROTOCOL;
    /// None for [`FormSet::Driverless`].
    fn driver(self) -> Option<(&'static [u8], &'static HiiConfigAccessProtocol)> {
        match self {
            Self::Plain => Some((&PLAIN_PATH[..], &PLAIN_ACCESS)),
            Self::Stores => Some((&STORES_PATH[..], &STORES_ACCESS)),
            Self::Unreachable => Some((&UNREACHABLE_PATH[..], &UNREACHABLE_ACCESS)),
            Self::Driverless => None,
            Self::Password => Some((&PASSWORD_PATH[..], &STORES_ACCESS)),
            Self::DisabledPassword => Some((&DISABLED_PASSWORD_PATH[..], &PLAIN_ACCESS)),
        }
    }
}

/// What a question's Callback() does.
#[derive(Clone, Copy, PartialEq)]
enum Behavior {
    /// RETRIEVE reads, and CHANGED writes, the question's own variable
    Own,
    /// As Own, and CHANGED asks for EFI_BROWSER_ACTION_REQUEST_RESET
    OwnAskingReset,
    /// As Own, and CHANGED then resets the platform, so that it never returns
    OwnResetting,
    /// As Own, and CHANGED asks for EFI_BROWSER_ACTION_REQUEST_SUBMIT
    OwnAskingSave,
    /// As Own, and CHANGED asks for EFI_BROWSER_ACTION_REQUEST_RECONNECT
    OwnAskingReconnect,
    /// As Own, but RETRIEVE answers 0, a reset value
    Transient,
    /// As Own, but RETRIEVE returns EFI_UNSUPPORTED
    NoReadBack,
    /// CHANGED overwrites the EFI variable store
    OverwritesEfiStore,
    /// CHANGED overwrites the setting of the Buffer store
    OverwritesBufferStore,
    /// CHANGED overwrites the setting beside the password of the password's Buffer store
    OverwritesPasswordStore,
    /// CHANGED overwrites the password of the password's Buffer store
    OverwritesPassword,
    /// CHANGING returns EFI_ACCESS_DENIED
    RefusedInChanging,
    /// CHANGED returns EFI_DEVICE_ERROR
    FailsInChanged,
}

/// A question without a VarStore: its QuestionId, form set, prompt and Callback().
struct Question {
    id: u16,
    form_set: FormSet,
    prompt: &'static str,
    behavior: Behavior,
}

const QUESTIONS: [Question; 16] = [
    Question {
        id: 0x0101,
        form_set: FormSet::Plain,
        prompt: "Callback value asking for a reset",
        behavior: Behavior::OwnAskingReset,
    },
    Question {
        id: 0x0102,
        form_set: FormSet::Plain,
        prompt: "Callback value resetting the platform",
        behavior: Behavior::OwnResetting,
    },
    Question {
        id: 0x0201,
        form_set: FormSet::Stores,
        prompt: "Callback value beside stores",
        behavior: Behavior::Own,
    },
    Question {
        id: 0x0202,
        form_set: FormSet::Stores,
        prompt: "Callback value overwriting its EFI variable store",
        behavior: Behavior::OverwritesEfiStore,
    },
    Question {
        id: 0x0203,
        form_set: FormSet::Stores,
        prompt: "Callback value overwriting its Buffer store",
        behavior: Behavior::OverwritesBufferStore,
    },
    Question {
        id: 0x0204,
        form_set: FormSet::Stores,
        prompt: "Callback value refused in CHANGING",
        behavior: Behavior::RefusedInChanging,
    },
    Question {
        id: 0x0205,
        form_set: FormSet::Stores,
        prompt: "Callback value failing in CHANGED",
        behavior: Behavior::FailsInChanged,
    },
    Question {
        id: 0x0206,
        form_set: FormSet::Stores,
        prompt: "Callback value asking for a save",
        behavior: Behavior::OwnAskingSave,
    },
    Question {
        id: 0x0207,
        form_set: FormSet::Stores,
        prompt: "Callback value asking for a reconnection",
        behavior: Behavior::OwnAskingReconnect,
    },
    Question {
        id: 0x0208,
        form_set: FormSet::Stores,
        prompt: "Transient callback value",
        behavior: Behavior::Transient,
    },
    Question {
        id: 0x0209,
        form_set: FormSet::Stores,
        prompt: "Callback value without read-back",
        behavior: Behavior::NoReadBack,
    },
    Question {
        id: 0x0301,
        form_set: FormSet::Unreachable,
        prompt: "Callback value beside an unreachable store",
        behavior: Behavior::Own,
    },
    Question {
        id: 0x0401,
        form_set: FormSet::Driverless,
        prompt: "Callback value without a driver",
        behavior: Behavior::Own,
    },
    Question {
        id: 0x0501,
        form_set: FormSet::Password,
        prompt: "Callback value beside a password",
        behavior: Behavior::OverwritesPasswordStore,
    },
    Question {
        id: 0x0502,
        form_set: FormSet::Password,
        prompt: "Callback value over a password",
        behavior: Behavior::OverwritesPassword,
    },
    Question {
        id: 0x0601,
        form_set: FormSet::DisabledPassword,
        prompt: "Callback value beside a disabled password",
        behavior: Behavior::Own,
    },
];

static PLAIN_PATH: [u8; 24] = vendor_device_path(FormSet::Plain.guid());
static STORES_PATH: [u8; 24] = vendor_device_path(FormSet::Stores.guid());
static UNREACHABLE_PATH: [u8; 24] = vendor_device_path(FormSet::Unreachable.guid());
static PASSWORD_PATH: [u8; 24] = vendor_device_path(FormSet::Password.guid());
static DISABLED_PASSWORD_PATH: [u8; 24] = vendor_device_path(FormSet::DisabledPassword.guid());

static PLAIN_ACCESS: HiiConfigAccessProtocol = HiiConfigAccessProtocol {
    extract_config: extract_nothing,
    route_config: route_nothing,
    callback,
};
static STORES_ACCESS: HiiConfigAccessProtocol = HiiConfigAccessProtocol {
    extract_config: extract_buffer_stores,
    route_config: route_buffer_stores,
    callback,
};
static UNREACHABLE_ACCESS: HiiConfigAccessProtocol = HiiConfigAccessProtocol {
    extract_config: extract_nothing,
    route_config: route_nothing,
    callback,
};

/// EFI_HII_CONFIG_ROUTING_PROTOCOL, whose BlockToConfig() and ConfigToBlock() the uefi crate
/// does not wrap.
#[repr(transparent)]
#[unsafe_protocol(HiiConfigRoutingProtocol::GUID)]
struct RawConfigRouting(HiiConfigRoutingProtocol);

/// Gives the stores their initial values if they have none, registers each form set of
/// `forms`, and installs the driver binding of [`FormSet::Stores`]'s handle.
pub(crate) fn register(forms: Forms) -> Result<(), Failure> {
    let vendor = VariableVendor(VENDOR);
    let buffers = BUFFER_STORES
        .iter()
        .map(|store| (store.name, store.initial));
    for (name, initial) in [(EFI_STORE, &EFI_STORE_INITIAL[..])]
        .into_iter()
        .chain(buffers)
    {
        match runtime::get_variable(name, &vendor, &mut [0; 8]) {
            Ok(_) => {}
            Err(error) if error.status() == Status::NOT_FOUND => {
                runtime::set_variable(name, &vendor, NV_BS_RT, initial)
                    .map_err(|error| ("initializing a store", error.status()))?;
            }
            Err(error) => return Err(("reading a store", error.status())),
        }
    }

    let database = boot::get_handle_for_protocol::<RawHiiDatabase>()
        .and_then(boot::open_protocol_exclusive::<RawHiiDatabase>)
        .map_err(|error| ("opening the HII database", error.status()))?;
    for &form_set in forms.form_sets() {
        let handle = match form_set.driver() {
            Some((path, access)) => {
                let handle = driver_handle::install(path, access)?;
                if form_set == FormSet::Stores {
                    STORES_HANDLE.store(handle.as_ptr(), Ordering::Release);
                }
                handle.as_ptr()
            }
            None => ptr::null_mut(),
        };
        let list = package_list(
            form_set.guid(),
            &[strings_package(strings(form_set)), form_package(form_set)],
        );
        let mut hii_handle = ptr::null_mut();
        #[expect(
            unsafe_code,
            reason = "the uefi crate does not wrap NewPackageList(), a function of the protocol"
        )]
        // SAFETY: `database` is the protocol that the firmware installed, which stays open while
        // the call runs; `list` is a whole package list, which the database copies; the driver
        // handle is one installed above, or NULL, which NewPackageList() takes (UEFI 2.11
        // §34.8.2); `hii_handle` is a valid place for the new HII handle.
        let status = unsafe {
            (database.0.new_package_list)(
                &database.0,
                list.as_ptr().cast(),
                handle,
                &mut hii_handle,
            )
        };
        status
            .to_result()
            .map_err(|error| ("registering a callback form set", error.status()))?;
    }

    let image = boot::image_handle().as_ptr();
    let binding = Box::leak(Box::new(DriverBindingProtocol {
        supported,
        start,
        stop,
        version: 0x10,
        image_handle: image,
        driver_binding_handle: image,
    }));
    #[expect(
        unsafe_code,
        reason = "installs a protocol whose interface this resident driver leaks"
    )]
    // SAFETY: the protocol lives as long as this resident boot service driver, which leaks it
    unsafe {
        boot::install_protocol_interface(
            Some(boot::image_handle()),
            &DriverBindingProtocol::GUID,
            ptr::from_mut(binding).cast(),
        )
    }
    .map_err(|error| ("installing EFI_DRIVER_BINDING_PROTOCOL", error.status()))?;
    Ok(())
}

/// The strings package of `form_set`: the common strings, then the prompt of each of its
/// questions and storage settings.
fn strings(form_set: FormSet) -> Vec<&'static str> {
    let prompts = QUESTIONS
        .iter()
        .filter(|question| question.form_set == form_set)
        .map(|question| question.prompt);
    let settings: &[&str] = match form_set {
        FormSet::Stores => &["Buffer setting", "Buffer call count"],
        FormSet::Unreachable => &["Unreachable store setting"],
        FormSet::Password => &["Password", "Password store setting"],
        FormSet::DisabledPassword => &["Disabled password"],
        FormSet::Plain | FormSet::Driverless => &[],
    };
    COMMON_STRINGS
        .into_iter()
        .chain(prompts)
        .chain(settings.iter().copied())
        .collect()
}

/// The form package of `form_set`: the form set, its stores, and one form with its questions,
/// then its storage settings, whose prompts follow those of the questions in [`strings`]; for
/// [`FormSet::DisabledPassword`], its PASSWORD question in a second form, which a CHECKBOX op of
/// 3 bytes, shorter than any CHECKBOX, disables (UEFI 2.11 §33.2.5.10.1).
fn form_package(form_set: FormSet) -> Vec<u8> {
    let form_set_op = [
        &form_set.guid().to_bytes()[..],
        &TITLE.to_le_bytes(),
        &HELP.to_le_bytes(),
        &[1],        // Flags: one ClassGuid
        &[0x22; 16], // ClassGuid
    ]
    .concat();
    let questions: Vec<&Question> = QUESTIONS
        .iter()
        .filter(|question| question.form_set == form_set)
        .collect();
    let mut prompt = u16::try_from(COMMON_STRINGS.len()).expect("a few strings") + 1;
    let mut body = Vec::new();
    for question in &questions {
        let flags = match question.behavior {
            Behavior::OwnAskingReset => EFI_IFR_FLAG_CALLBACK | EFI_IFR_FLAG_RESET_REQUIRED,
            _ => EFI_IFR_FLAG_CALLBACK,
        };
        body.extend(one_of(question.id, prompt, flags));
        prompt += 1;
    }
    let (stores, settings) = match form_set {
        FormSet::Stores => (
            [
                op(
                    EFI_IFR_VARSTORE_EFI_OP,
                    false,
                    &[
                        &EFI_STORE_ID.to_le_bytes()[..],
                        &VENDOR.to_bytes(),
                        &NV_BS_RT.bits().to_le_bytes(),
                        &4u16.to_le_bytes(), // Size
                        b"CallbackStore\0",
                    ]
                    .concat(),
                ),
                buffer_store(BUFFER_STORE_ID, 5, b"CallbackBuffer\0"),
            ]
            .concat(),
            [
                numeric(0x0210, prompt, BUFFER_STORE_ID, 0, UINT32_DECIMAL),
                numeric(0x0211, prompt + 1, BUFFER_STORE_ID, 4, UINT8_DECIMAL),
            ]
            .concat(),
        ),
        FormSet::Unreachable => (
            buffer_store(UNREACHABLE_STORE_ID, 1, b"CallbackUnreachable\0"),
            numeric(0x0310, prompt, UNREACHABLE_STORE_ID, 0, UINT8_DECIMAL),
        ),
        FormSet::Password => (
            buffer_store(PASSWORD_STORE_ID, 5, b"CallbackPassword\0"),
            [
                password(0x0510, prompt, PASSWORD_STORE_ID, 0),
                numeric(0x0511, prompt + 1, PASSWORD_STORE_ID, 4, UINT8_DECIMAL),
            ]
            .concat(),
        ),
        FormSet::DisabledPassword => (
            buffer_store(DISABLED_PASSWORD_STORE_ID, 4, b"CallbackDisabledPassword\0"),
            Vec::new(),
        ),
        FormSet::Plain | FormSet::Driverless => (Vec::new(), Vec::new()),
    };
    let disabled_form = match form_set {
        FormSet::DisabledPassword => [
            op(
                EFI_IFR_FORM_OP,
                true,
                &[2u16.to_le_bytes(), TITLE.to_le_bytes()].concat(),
            ),
            password(0x0610, prompt, DISABLED_PASSWORD_STORE_ID, 0),
            op(EFI_IFR_CHECKBOX_OP, false, &[0x00]),
            end(),
        ]
        .concat(),
        FormSet::Plain
        | FormSet::Stores
        | FormSet::Unreachable
        | FormSet::Driverless
        | FormSet::Password => Vec::new(),
    };
    let form = [1u16.to_le_bytes(), TITLE.to_le_bytes()].concat();
    let body = [
        op(EFI_IFR_FORM_SET_OP, true, &form_set_op),
        stores,
        op(EFI_IFR_FORM_OP, true, &form),
        body,
        settings,
        end(), // of the form
        disabled_form,
        end(), // of the form set
    ]
    .concat();
    package(EFI_HII_PACKAGE_FORMS, &body)
}

/// The Buffer VARSTORE `id` of `size` bytes and NUL-terminated ASCII `name`.
fn buffer_store(id: u16, size: u16, name: &[u8]) -> Vec<u8> {
    op(
        EFI_IFR_VARSTORE_OP,
        false,
        &[
            &VENDOR.to_bytes()[..],
            &id.to_le_bytes(),
            &size.to_le_bytes(),
            name,
        ]
        .concat(),
    )
}

/// EFI_IFR_QUESTION_HEADER: Prompt, Help, QuestionId, VarStoreId, VarStoreInfo and Flags.
fn question_header(id: u16, prompt: u16, var_store: u16, info: u16, flags: u8) -> Vec<u8> {
    [
        &prompt.to_le_bytes()[..],
        &HELP.to_le_bytes(),
        &id.to_le_bytes(),
        &var_store.to_le_bytes(),
        &info.to_le_bytes(),
        &[flags],
    ]
    .concat()
}

/// A UINT8 ONE_OF without a VarStore (VarStoreId 0 and VarStoreInfo 0xFFFF, as VfrCompile
/// emits one), of the options Off, On and Twice.
fn one_of(id: u16, prompt: u16, flags: u8) -> Vec<u8> {
    [
        op(
            EFI_IFR_ONE_OF_OP,
            true,
            &[
                question_header(id, prompt, 0, 0xFFFF, flags),
                // Flags, MinValue, MaxValue, Step
                [UINT8_DECIMAL, 0, 2, 0].to_vec(),
            ]
            .concat(),
        ),
        option(OFF, 0),
        option(ON, 1),
        option(TWICE, 2),
        end(),
    ]
    .concat()
}

/// A NUMERIC at byte `offset` of the Buffer store `var_store`, of the size and display of
/// `flags`, EFI_IFR_NUMERIC_SIZE_1 or _4.
fn numeric(id: u16, prompt: u16, var_store: u16, offset: u16, flags: u8) -> Vec<u8> {
    let range = match flags {
        UINT32_DECIMAL => [
            0u32.to_le_bytes(),
            u32::MAX.to_le_bytes(),
            1u32.to_le_bytes(),
        ]
        .concat(),
        _ => [0, u8::MAX, 1].to_vec(),
    };
    [
        op(
            EFI_IFR_NUMERIC_OP,
            true,
            &[
                question_header(id, prompt, var_store, offset, 0),
                [flags].to_vec(),
                range,
            ]
            .concat(),
        ),
        end(),
    ]
    .concat()
}

/// A PASSWORD of 2 CHAR16 at byte `offset` of the Buffer store `var_store`, without
/// EFI_IFR_FLAG_CALLBACK, which a forms browser writes to the store (UEFI 2.11 §33.3.8.3.54).
fn password(id: u16, prompt: u16, var_store: u16, offset: u16) -> Vec<u8> {
    let data = [
        question_header(id, prompt, var_store, offset, 0),
        [1u16.to_le_bytes(), 2u16.to_le_bytes()].concat(), // MinSize, MaxSize
    ]
    .concat();
    op(EFI_IFR_PASSWORD_OP, false, &data)
}

/// A UINT8 EFI_IFR_ONE_OF_OPTION of `text` and `value`.
fn option(text: u16, value: u8) -> Vec<u8> {
    let data = [&text.to_le_bytes()[..], &[0, NUM_SIZE_8, value]].concat();
    op(EFI_IFR_ONE_OF_OPTION_OP, false, &data)
}

/// The NUL-terminated UCS-2 string at `text`, which a caller passed.
#[expect(unsafe_code, reason = "reads a string that firmware passed")]
fn caller_string(text: *const Char16) -> String {
    // SAFETY: the callers pass a NUL-terminated UCS-2 string that outlives the call
    unsafe { CStr16::from_ptr(text.cast()) }.to_string()
}

impl BufferStore {
    /// Its `<ConfigHdr>` (UEFI 2.11 §35.2.1), in lower case: GUID and NAME as its bytes and
    /// characters in hex, PATH as the bytes of its handle's device path.
    fn header(&self) -> String {
        let guid: String = VENDOR
            .to_bytes()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        let name: String = self
            .name
            .iter()
            .map(|unit| format!("{:04x}", u16::from(*unit)))
            .collect();
        let path: String = self.path.iter().map(|byte| format!("{byte:02x}")).collect();
        format!("guid={guid}&name={name}&path={path}")
    }

    /// The store that `config`, a `<ConfigRequest>` or `<ConfigResp>`, names.
    fn named_by(config: &str) -> Option<&'static Self> {
        BUFFER_STORES.iter().copied().find(|store| {
            let header = store.header();
            config
                .get(..header.len())
                .is_some_and(|start| start.eq_ignore_ascii_case(&header))
                && config
                    .as_bytes()
                    .get(header.len())
                    .is_none_or(|&c| c == b'&')
        })
    }

    /// Its bytes, from its variable.
    fn read(&self) -> Result<Vec<u8>, Status> {
        let mut data = [0; 8];
        match runtime::get_variable(self.name, &VariableVendor(VENDOR), &mut data) {
            Ok((read, _)) if read.len() == self.initial.len() => Ok(read.to_vec()),
            Ok(_) => Err(Status::BAD_BUFFER_SIZE),
            Err(error) => Err(error.status()),
        }
    }
}

/// The firmware's EFI_HII_CONFIG_ROUTING_PROTOCOL, opened GetProtocol while `run` runs.
fn with_routing(run: impl FnOnce(&HiiConfigRoutingProtocol) -> Status) -> Status {
    let Ok(handle) = boot::get_handle_for_protocol::<RawConfigRouting>() else {
        return Status::NOT_FOUND;
    };
    let params = OpenProtocolParams {
        handle,
        agent: boot::image_handle(),
        controller: None,
    };
    #[expect(unsafe_code, reason = "opens a protocol non-exclusively")]
    // SAFETY: the HII database driver installs the protocol and uninstalls it nowhere
    // (edk2-stable202608 HiiDatabaseDxe HiiDatabaseEntry.c)
    let routing = unsafe {
        boot::open_protocol::<RawConfigRouting>(params, OpenProtocolAttributes::GetProtocol)
    };
    match routing.as_ref().ok().and_then(|routing| routing.get()) {
        Some(routing) => run(&routing.0),
        None => Status::NOT_FOUND,
    }
}

/// ExtractConfig() of a form set whose stores it does not answer.
#[expect(unsafe_code, reason = "a protocol function that firmware calls")]
unsafe extern "efiapi" fn extract_nothing(
    _this: *const HiiConfigAccessProtocol,
    request: *const Char16,
    progress: *mut *const Char16,
    _results: *mut *mut Char16,
) -> Status {
    if progress.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: the caller's valid out pointer
    unsafe { *progress = request };
    if !request.is_null() {
        println!(
            "callback-forms: ExtractConfig unanswered {}",
            caller_string(request)
        );
    }
    Status::NOT_FOUND
}

#[expect(unsafe_code, reason = "a protocol function that firmware calls")]
unsafe extern "efiapi" fn route_nothing(
    _this: *const HiiConfigAccessProtocol,
    configuration: *const Char16,
    progress: *mut *const Char16,
) -> Status {
    if configuration.is_null() || progress.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: the caller's valid out pointer
    unsafe { *progress = configuration };
    Status::NOT_FOUND
}

/// ExtractConfig() of a Buffer store of [`BUFFER_STORES`]: the requested settings of its
/// variable, with the call count as its counted byte, through BlockToConfig(). A NULL request,
/// which asks for every store, finds none: the HII database then requests the IFR's settings
/// (edk2-stable202608 ConfigRouting.c HiiConfigRoutingExportConfig).
#[expect(unsafe_code, reason = "a protocol function that firmware calls")]
unsafe extern "efiapi" fn extract_buffer_stores(
    _this: *const HiiConfigAccessProtocol,
    request: *const Char16,
    progress: *mut *const Char16,
    results: *mut *mut Char16,
) -> Status {
    if progress.is_null() || results.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: the caller's valid out pointer
    unsafe { *progress = request };
    if request.is_null() {
        return Status::NOT_FOUND;
    }
    let text = caller_string(request);
    let Some(store) = BufferStore::named_by(&text) else {
        return Status::NOT_FOUND;
    };
    let mut bytes = match store.read() {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    if let Some(counted) = store.counted {
        bytes[counted] = EXTRACTIONS.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    }
    let mut block_progress = ptr::null();
    let status = with_routing(|routing| {
        // SAFETY: the caller's NUL-terminated <ConfigRequest>, the store's bytes, and valid out
        // pointers
        unsafe {
            (routing.block_to_config)(
                routing,
                request,
                bytes.as_ptr(),
                bytes.len(),
                results,
                &mut block_progress,
            )
        }
    });
    if status.is_success() {
        // SAFETY: as above; the end of the caller's string, which BlockToConfig() reached
        unsafe { *progress = request.add(text.encode_utf16().count()) };
    }
    println!("callback-forms: ExtractConfig {text}: {status:?}");
    status
}

/// RouteConfig() of a Buffer store of [`BUFFER_STORES`]: ConfigToBlock() into its variable.
#[expect(unsafe_code, reason = "a protocol function that firmware calls")]
unsafe extern "efiapi" fn route_buffer_stores(
    _this: *const HiiConfigAccessProtocol,
    configuration: *const Char16,
    progress: *mut *const Char16,
) -> Status {
    if configuration.is_null() || progress.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: the caller's valid out pointer
    unsafe { *progress = configuration };
    let text = caller_string(configuration);
    let Some(store) = BufferStore::named_by(&text) else {
        return Status::NOT_FOUND;
    };
    let mut bytes = match store.read() {
        Ok(bytes) => bytes,
        Err(status) => return status,
    };
    let mut size = bytes.len();
    let status = with_routing(|routing| {
        // SAFETY: the caller's NUL-terminated <ConfigResp>, the store's bytes and their size,
        // and the caller's valid out pointer
        unsafe {
            (routing.config_to_block)(
                routing,
                configuration,
                bytes.as_mut_ptr(),
                &mut size,
                progress,
            )
        }
    });
    let status = match status.is_success() {
        true => write_variable(store.name, &bytes),
        false => status,
    };
    println!("callback-forms: RouteConfig {text}: {status:?}");
    status
}

/// Writes `bytes` over those at `offset` of `store`.
fn overwrite(store: &BufferStore, offset: usize, bytes: &[u8]) -> Status {
    match store.read() {
        Ok(mut data) => {
            data[offset..offset + bytes.len()].copy_from_slice(bytes);
            write_variable(store.name, &data)
        }
        Err(status) => status,
    }
}

/// The variable of question `id`, which holds its value.
fn own_variable(id: u16) -> CString16 {
    CString16::try_from(format!("CallbackValue{id:04X}").as_str()).expect("an ASCII name")
}

/// Writes `data` to the variable `name`.
fn write_variable(name: &CStr16, data: &[u8]) -> Status {
    match runtime::set_variable(name, &VariableVendor(VENDOR), NV_BS_RT, data) {
        Ok(()) => Status::SUCCESS,
        Err(error) => error.status(),
    }
}

/// What Callback(`action`) of `question` with `value` returns: its status, ActionRequest and
/// value.
fn respond(
    question: &Question,
    action: BrowserAction,
    value: u8,
) -> (Status, BrowserActionRequest, u8) {
    let vendor = VariableVendor(VENDOR);
    let own = own_variable(question.id);
    let none = BrowserActionRequest::NONE;
    match (action, question.behavior) {
        (BrowserAction::RETRIEVE, Behavior::Transient) => (Status::SUCCESS, none, 0),
        (BrowserAction::RETRIEVE, Behavior::NoReadBack) => (Status::UNSUPPORTED, none, value),
        (BrowserAction::RETRIEVE, _) => {
            let mut data = [0; 1];
            match runtime::get_variable(&own, &vendor, &mut data) {
                Ok(_) => (Status::SUCCESS, none, data[0]),
                Err(error) if error.status() == Status::NOT_FOUND => (Status::SUCCESS, none, 0),
                Err(error) => (error.status(), none, value),
            }
        }
        (BrowserAction::CHANGING, Behavior::RefusedInChanging) => {
            (Status::ACCESS_DENIED, none, value)
        }
        (BrowserAction::CHANGING, _) => (Status::SUCCESS, none, value),
        (BrowserAction::CHANGED, behavior) => {
            let (status, request) = match behavior {
                Behavior::Own | Behavior::Transient | Behavior::NoReadBack => {
                    (write_variable(&own, &[value]), none)
                }
                Behavior::OwnAskingReset => {
                    (write_variable(&own, &[value]), BrowserActionRequest::RESET)
                }
                Behavior::OwnResetting => {
                    let status = write_variable(&own, &[value]);
                    println!(
                        "callback-forms: Callback(CHANGED) question {:#06x} value {value:#x}: \
                         {status:?}, resetting the platform",
                        question.id
                    );
                    runtime::reset(ResetType::COLD, Status::SUCCESS, None)
                }
                Behavior::OwnAskingSave => {
                    (write_variable(&own, &[value]), BrowserActionRequest::SUBMIT)
                }
                Behavior::OwnAskingReconnect => (
                    write_variable(&own, &[value]),
                    BrowserActionRequest::RECONNECT,
                ),
                Behavior::OverwritesEfiStore => {
                    (write_variable(EFI_STORE, &[value, 0xC1, 0xC2, 0xC3]), none)
                }
                Behavior::OverwritesBufferStore => (
                    overwrite(&CALLBACK_BUFFER, 0, &[value, 0xB1, 0xB2, 0xB3]),
                    none,
                ),
                Behavior::OverwritesPasswordStore => {
                    (overwrite(&PASSWORD_BUFFER, 4, &[value]), none)
                }
                Behavior::OverwritesPassword => (
                    overwrite(&PASSWORD_BUFFER, 0, &[value, 0xD1, 0xD2, 0xD3]),
                    none,
                ),
                Behavior::RefusedInChanging => (Status::SUCCESS, none),
                Behavior::FailsInChanged => (Status::DEVICE_ERROR, none),
            };
            (status, request, value)
        }
        _ => (Status::UNSUPPORTED, none, value),
    }
}

/// The name of `action`, as the checks match it.
fn action_name(action: BrowserAction) -> String {
    match action {
        BrowserAction::CHANGING => "CHANGING".to_string(),
        BrowserAction::CHANGED => "CHANGED".to_string(),
        BrowserAction::RETRIEVE => "RETRIEVE".to_string(),
        BrowserAction::FORM_OPEN => "FORM_OPEN".to_string(),
        BrowserAction::FORM_CLOSE => "FORM_CLOSE".to_string(),
        other => format!("{:#x}", other.0),
    }
}

#[expect(unsafe_code, reason = "a protocol function that firmware calls")]
unsafe extern "efiapi" fn callback(
    _this: *const HiiConfigAccessProtocol,
    action: BrowserAction,
    question_id: u16,
    _value_type: u8,
    value: *mut IfrTypeValue,
    action_request: *mut BrowserActionRequest,
) -> Status {
    let Some(question) = QUESTIONS.iter().find(|question| question.id == question_id) else {
        return Status::UNSUPPORTED;
    };
    if value.is_null() || action_request.is_null() {
        return Status::INVALID_PARAMETER;
    }
    // SAFETY: the caller's EFI_IFR_TYPE_VALUE, of a UINT8 question
    let given = unsafe { (*value).u8 };
    let (status, request, returned) = respond(question, action, given);
    // SAFETY: as above, and the caller's ActionRequest
    unsafe {
        (*value).u8 = returned;
        *action_request = request;
    }
    println!(
        "callback-forms: Callback({}) question {question_id:#06x} value {given:#x}: {status:?}, \
         returned {returned:#x}, request {}",
        action_name(action),
        request.0
    );
    status
}

/// Supported() of the driver binding: only the handle of [`FormSet::Stores`].
#[expect(unsafe_code, reason = "a protocol function that firmware calls")]
unsafe extern "efiapi" fn supported(
    _this: *const DriverBindingProtocol,
    controller: uefi_raw::Handle,
    _remaining: *const DevicePathProtocol,
) -> Status {
    match controller == STORES_HANDLE.load(Ordering::Acquire) {
        true => Status::SUCCESS,
        false => Status::UNSUPPORTED,
    }
}

/// Start() of the driver binding, which opens nothing, so that DisconnectController() finds
/// nothing to stop.
#[expect(unsafe_code, reason = "a protocol function that firmware calls")]
unsafe extern "efiapi" fn start(
    _this: *const DriverBindingProtocol,
    _controller: uefi_raw::Handle,
    _remaining: *const DevicePathProtocol,
) -> Status {
    println!("callback-forms: driver binding Start()");
    Status::SUCCESS
}

#[expect(unsafe_code, reason = "a protocol function that firmware calls")]
unsafe extern "efiapi" fn stop(
    _this: *const DriverBindingProtocol,
    _controller: uefi_raw::Handle,
    _children: usize,
    _child_handles: *const uefi_raw::Handle,
) -> Status {
    Status::SUCCESS
}
