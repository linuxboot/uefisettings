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

namespace py3 hardware.uefisettings
namespace cpp2 hardware.uefisettings

enum Backend {
  Unknown = 0,
  Hii = 1,
  Ilo = 2,
  FirmwareAttributes = 3,
}

struct MachineInfo {
  1: set<Backend> backend;
  2: string bios_vendor;
  3: string bios_version;
  4: string bios_release;
  5: string bios_date;
  6: string product_name;
  7: string product_family;
  8: string product_version;
}

// hii - a default that the IFR declares for a question (UEFI 2.11 §33.2.5.8): by an
// EFI_IFR_DEFAULT, by an option flagged DEFAULT or DEFAULT_MFG, or by the Flags of a CHECKBOX.
// edk2's setup browser falls back to another default store and then to a value by type, which
// are not shown.
struct QuestionDefault {
  // the DefaultId of the default store: 0x0000 standard, 0x0001 manufacturing, 0x0002 safe, ...;
  // always set
  1: optional i32 default_id;
  // the DefaultName of the FormSet's EFI_IFR_DEFAULTSTORE of default_id; unset if the FormSet
  // declares none
  2: optional string default_store_name;
  // the value, as the answer shows a current value, or "unknown (<reason>)"; always set
  3: optional string value;
}

struct Question {
  1: string name;
  // answer values:
  // hii - the current value; if unreadable, the reason, followed, only if the IFR of a ONE_OF,
  // NUMERIC or CHECKBOX declares a default, by " <IFR default: v>" or
  // " <IFR default (DefaultId 0x0001): v>", v being "unknown (<reason>)" if undetermined;
  // firmware Callback/ALTCFG defaults may differ. defaults lists every default that the IFR
  // declares.
  // hii answers end with " <s>" if IFR conditions put the question in state s (grayed-out,
  // suppressed or disabled), or with " <s1 or s2: reasons>" if the reasons leave its state
  // undetermined among s1, s2, ... (selectable too).
  // The stored option's state precedes it: " <option s>" or " <option s1 or s2: reasons>".
  // set's hii answer ends with " <volatile: lasts until the next reset or power cycle>" when it
  // wrote a volatile variable (UEFI Shell, --allow-volatile).
  2: string answer;
  // hii - the ONE_OF options that set takes: those that IFR conditions certainly leave
  // selectable or in a state that --include allows.
  3: list<string> options;
  4: string help;
  // hii - the question's Flags (UEFI 2.11 §33.3.8.2.2) that are set, by their names there
  // without the EFI_IFR_FLAG_ prefix, in bit order: READ_ONLY, CALLBACK, RESET_REQUIRED,
  // REST_STYLE, RECONNECT_REQUIRED, OPTIONS_ONLY; reserved bits are left out. Unset if none is.
  // REST_STYLE also when the FormSet's ClassGuids hold EFI_HII_REST_STYLE_FORMSET_GUID, which
  // lets the Flags omit it.
  5: optional list<string> flags;
  // hii - the defaults that the IFR declares for the question, by default_id ascending. Unset if
  // it declares none.
  9: optional list<QuestionDefault> defaults;
}

struct SetResponse {
  // selector values:
  // hii - the selector will be the packagelist (TODO: change to form@packagelist).
  // ilo - the selector will be iloname-endpoint (for example bios or debug).
  // firmware-attributes - the selector will be the class device name (for example thinklmi).
  1: string selector;

  2: Backend backend;
  3: Question question; // this will be the newly modified question
  4: bool modified;
  5: bool is_translated; // is the question/answer in the spellings database
  // firmware-attributes only: what the set observed after the write, as
  // `firmware-attributes set` reports it.
  8: optional FirmwareAttributeSetResult firmware_attribute_set_result;
}

// hii - IFR of a form package, from offset on, that uefisettings ignores in whole or in part,
// and why: get, set and list-questions may miss questions in it.
struct HiiIgnoredIfr {
  1: string package_list;
  2: i64 offset;
  3: string reason;
}

struct SetResponseList {
  1: list<SetResponse> responses;
  // hii - the IFR that uefisettings ignores in the HiiDB, which may hold more questions; unset if
  // there is none
  2: optional list<HiiIgnoredIfr> ignored_ifr;
}

struct GetResponse {
  1: string selector;
  2: Backend backend;
  3: Question question;
  4: bool is_translated; // is the question/answer in the spellings database
}

struct GetResponseList {
  1: list<GetResponse> responses;
  // hii - the IFR that uefisettings ignores in the HiiDB, which may hold more questions; unset if
  // there is none
  2: optional list<HiiIgnoredIfr> ignored_ifr;
}

// The CLI's error object: error_message is for people and may change; kind
// and os_errno are for programs.
struct Error {
  1: string error_message;
  2: optional string kind;
  3: optional i32 os_errno;
  // The error of the password clear that followed a failed password write,
  // or a failed value open or write, of a firmware-attributes set, if the
  // clear failed too.
  4: optional ErrorCause clear_error;
}

// What Error.clear_error holds: the error of the password clear, with no
// clear_error of its own. thrift1 derives Eq, Ord and Hash for a struct
// without rust.ord only if each of its struct-typed fields has rust.ord,
// so this rust.ord keeps them on Error.
struct ErrorCause {
  1: string error_message;
  2: optional string kind;
  3: optional i32 os_errno;
} (rust.ord)

// --- Backend: firmware-attributes ---

struct FirmwareAttributeIntegerBounds {
  1: optional i64 min_value;
  2: optional i64 max_value;
  3: optional i64 scalar_increment;
}

struct FirmwareAttributeStringBounds {
  1: optional i64 min_length;
  2: optional i64 max_length;
  // Absent when the attribute has no possible_values file and when that
  // file lists no value: an empty list is never sent.
  3: optional list<string> possible_values;
}

union FirmwareAttributeKind {
  1: list<string> enumeration;
  2: FirmwareAttributeIntegerBounds integer;
  3: FirmwareAttributeStringBounds string_value;
  4: list<string> ordered_list;
  5: string other;
}

union FirmwareAttributeValue {
  1: string value;
  2: Error read_error;
}

struct FirmwareAttribute {
  1: string device;
  2: string name;
  3: FirmwareAttributeKind kind;
  4: FirmwareAttributeValue current_value;
  5: optional string default_value;
  6: optional string display_name;
  7: optional string display_name_language_code;
  8: optional string not_writable_reason;
  // dell-wmi-sysman only: the raw rules under which the attribute is
  // read-only or suppressed, or firmware forces its value. They are not
  // enforced.
  9: optional string dell_modifier;
  10: optional string dell_value_modifier;
}

struct FirmwareAttributeLoadError {
  1: string device;
  2: optional string name; // absent when the whole device failed (its directory could not be listed)
  3: Error error;
}

struct FirmwareAttributeList {
  1: list<FirmwareAttribute> attributes;
  2: list<FirmwareAttributeLoadError> errors;
}

struct FirmwareAttributeSetResult {
  1: string device;
  2: string name;
  3: string status;
  4: optional string read_back;
  5: optional bool pending_reboot;
  6: optional Error read_back_error;
  7: optional Error clear_error; // the value was written, but clearing current_password failed
}

struct FirmwareAttributeAuthentication {
  1: string device;
  2: string name;
  3: string role;
  4: bool is_enabled;
  5: optional string mechanism;
  6: optional i64 min_password_length;
  7: optional i64 max_password_length;
}

struct FirmwareAttributeAuthenticationList {
  1: list<FirmwareAttributeAuthentication> authentications;
  2: list<FirmwareAttributeLoadError> errors;
}

struct FirmwareAttributePendingReboot {
  1: string device;
  2: optional bool pending_reboot;
  3: optional Error read_error;
}

struct FirmwareAttributePendingRebootList {
  1: list<FirmwareAttributePendingReboot> devices;
}

// --- Backend: ilo ---

struct IloAttributes {
  1: string selector;
  2: map<string, string> attributes;
}

// --- Backend: hii ---

struct HiiShowIfrResponse {
  1: string readable_representation;
}

struct HiiDatabase {
  1: binary db;
}

struct HiiStringsPackage {
  1: string package_list; // note that this isn't unique, multiple packages will be part of the same package list
  2: map<i32, string> string_package;
  // the Language of the package's header (UEFI 2.11 §33.3.6.1): "en-US", for one, or a UEFI
  // configuration language such as "x-UEFI-ns", which holds keywords (§35.3.1)
  3: string language;
}
