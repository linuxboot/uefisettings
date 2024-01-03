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

use std::cell::RefCell;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;
use std::fmt::Display;
use std::fs::File;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::rc::Rc;
use std::rc::Weak;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use binrw::io::Cursor;
use binrw::BinRead;
use binrw::BinReaderExt;
use binrw::BinResult;
use binrw::BinWrite;
use log::debug;
use log::error;
use thiserror::Error;

use crate::chattr::EfivarsImmutabilityGuard;
use crate::file_lock::FileLock;
use crate::hii::efivarfs::EfivarsMountGuard;
use crate::hii::package::Guid;

const DUMMY_OPCODE: u8 = 0xFFu8; // doesn't correspond to any known IFROpCode

// UEFI Spec v2.9 Page 1844
#[derive(BinRead, Debug, PartialEq, Copy, Clone)]
#[br(little)]
pub enum IFROpCode {
    #[br(magic = 0x01u8)]
    Form,
    #[br(magic = 0x02u8)]
    Subtitle,
    #[br(magic = 0x03u8)]
    Text,
    #[br(magic = 0x04u8)]
    Image,
    #[br(magic = 0x05u8)]
    OneOf,
    #[br(magic = 0x06u8)]
    CheckBox,
    #[br(magic = 0x07u8)]
    Numeric,
    #[br(magic = 0x08u8)]
    Password,
    #[br(magic = 0x09u8)]
    OneOfOption,
    #[br(magic = 0x0Au8)]
    SuppressIf,
    #[br(magic = 0x0Bu8)]
    Locked,
    #[br(magic = 0x0Cu8)]
    Action,
    #[br(magic = 0x0Du8)]
    ResetButton,
    #[br(magic = 0x0Eu8)]
    FormSet,
    #[br(magic = 0x0Fu8)]
    Ref,
    #[br(magic = 0x10u8)]
    NoSubmitIf,
    #[br(magic = 0x11u8)]
    InconsistentIf,
    #[br(magic = 0x12u8)]
    EqIdVal,
    #[br(magic = 0x13u8)]
    EqIdId,
    #[br(magic = 0x14u8)]
    EqIdValList,
    #[br(magic = 0x15u8)]
    And,
    #[br(magic = 0x16u8)]
    Or,
    #[br(magic = 0x17u8)]
    Not,
    #[br(magic = 0x18u8)]
    Rule,
    #[br(magic = 0x19u8)]
    GrayOutIf,
    #[br(magic = 0x1Au8)]
    Date,
    #[br(magic = 0x1Bu8)]
    Time,
    #[br(magic = 0x1Cu8)]
    String,
    #[br(magic = 0x1Du8)]
    Refresh,
    #[br(magic = 0x1Eu8)]
    DisableIf,
    #[br(magic = 0x1Fu8)]
    Animation,
    #[br(magic = 0x20u8)]
    ToLower,
    #[br(magic = 0x21u8)]
    ToUpper,
    #[br(magic = 0x22u8)]
    Map,
    #[br(magic = 0x23u8)]
    OrderedList,
    #[br(magic = 0x24u8)]
    VarStore,
    #[br(magic = 0x25u8)]
    VarStoreNameValue,
    #[br(magic = 0x26u8)]
    VarStoreEfi,
    #[br(magic = 0x27u8)]
    VarStoreDevice,
    #[br(magic = 0x28u8)]
    Version,
    #[br(magic = 0x29u8)]
    End,
    #[br(magic = 0x2Au8)]
    Match,
    #[br(magic = 0x2Bu8)]
    Get,
    #[br(magic = 0x2Cu8)]
    Set,
    #[br(magic = 0x2Du8)]
    Read,
    #[br(magic = 0x2Eu8)]
    Write,
    #[br(magic = 0x2Fu8)]
    Equal,
    #[br(magic = 0x30u8)]
    NotEqual,
    #[br(magic = 0x31u8)]
    GreaterThan,
    #[br(magic = 0x32u8)]
    GreaterEqual,
    #[br(magic = 0x33u8)]
    LessThan,
    #[br(magic = 0x34u8)]
    LessEqual,
    #[br(magic = 0x35u8)]
    BitwiseAnd,
    #[br(magic = 0x36u8)]
    BitwiseOr,
    #[br(magic = 0x37u8)]
    BitwiseNot,
    #[br(magic = 0x38u8)]
    ShiftLeft,
    #[br(magic = 0x39u8)]
    ShiftRight,
    #[br(magic = 0x3Au8)]
    Add,
    #[br(magic = 0x3Bu8)]
    Subtract,
    #[br(magic = 0x3Cu8)]
    Multiply,
    #[br(magic = 0x3Du8)]
    Divide,
    #[br(magic = 0x3Eu8)]
    Modulo,
    #[br(magic = 0x3Fu8)]
    RuleRef,
    #[br(magic = 0x40u8)]
    QuestionRef1,
    #[br(magic = 0x41u8)]
    QuestionRef2,
    #[br(magic = 0x42u8)]
    Uint8,
    #[br(magic = 0x43u8)]
    Uint16,
    #[br(magic = 0x44u8)]
    Uint32,
    #[br(magic = 0x45u8)]
    Uint64,
    #[br(magic = 0x46u8)]
    True,
    #[br(magic = 0x47u8)]
    False,
    #[br(magic = 0x48u8)]
    ToUint,
    #[br(magic = 0x49u8)]
    ToString,
    #[br(magic = 0x4Au8)]
    ToBoolean,
    #[br(magic = 0x4Bu8)]
    Mid,
    #[br(magic = 0x4Cu8)]
    Find,
    #[br(magic = 0x4Du8)]
    Token,
    #[br(magic = 0x4Eu8)]
    StringRef1,
    #[br(magic = 0x4Fu8)]
    StringRef2,
    #[br(magic = 0x50u8)]
    Conditional,
    #[br(magic = 0x51u8)]
    QuestionRef3,
    #[br(magic = 0x52u8)]
    Zero,
    #[br(magic = 0x53u8)]
    One,
    #[br(magic = 0x54u8)]
    Ones,
    #[br(magic = 0x55u8)]
    Undefined,
    #[br(magic = 0x56u8)]
    Length,
    #[br(magic = 0x57u8)]
    Dup,
    #[br(magic = 0x58u8)]
    This,
    #[br(magic = 0x59u8)]
    Span,
    #[br(magic = 0x5Au8)]
    Value,
    #[br(magic = 0x5Bu8)]
    Default,
    #[br(magic = 0x5Cu8)]
    DefaultStore,
    #[br(magic = 0x5Du8)]
    FormMap,
    #[br(magic = 0x5Eu8)]
    Catenate,
    #[br(magic = 0x5Fu8)]
    Guid,
    #[br(magic = 0x60u8)]
    Security,
    #[br(magic = 0x61u8)]
    ModalTag,
    #[br(magic = 0x62u8)]
    RefreshId,
    #[br(magic = 0x63u8)]
    WarningIf,
    #[br(magic = 0x64u8)]
    Match2,
    Unknown(u8),
}

/// IFROperation is a node for a tree data structure.
/// In HiiDB the opcodes + data are in a series/list.
/// However, here we will use the open_scope boolean field + the end opcode (which marks end of scope)
/// to generate an HTML like DOM tree.
#[derive(BinRead)]
#[br(little)]
pub struct IFROperation {
    pub op_code: IFROpCode,
    #[br(restore_position, map = |x: u8| x  & 0x7F)]
    // only store the first 7 bits and then move the cursor back to position before this field
    length: u8, // size of the entire header
    #[br(map = |x: u8| x & 0x80 != 0)]
    // read 8 bits, discard all of them except the last one
    pub open_scope: bool,
    #[br(count = length - 2)] // first 3 fields make up 16 bits = 2 bytes
    data: Vec<u8>,

    // the following fields will not be parsed by binrw and when an instance of this struct is created
    // they'll get the default values until we change them
    #[br(default)]
    pub parent: Option<Weak<RefCell<IFROperation>>>,
    #[br(default)]
    pub children: Vec<Rc<RefCell<IFROperation>>>,
    #[br(default)]
    pub parsed_data: ParsedOperation,
}

// Debug is implemented manually because if we derived Debug instead then we'd
// get a stack overflow caused by parent printing child which will try to print it's parent....
impl fmt::Debug for IFROperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IFROperation")
            .field("op_code", &self.op_code)
            .field("open_scope", &self.open_scope)
            .field("length", &self.length)
            .field("children", &self.children)
            .finish()
    }
}

#[derive(Debug)]
pub enum ParsedOperation {
    FormSet(FormSet),
    OneOf(OneOf),
    CheckBox(CheckBox),
    OneOfOption(OneOfOption),
    VarStore(VarStore),
    VarStoreEfi(VarStoreEfi),
    DefaultStore(DefaultStore),
    IFRDefault(IFRDefault),
    Form(Form),
    Text(Text),
    Subtitle(Subtitle),
    Numeric(Numeric),
    QuestionRef1(QuestionRef1),
    EqIdVal(EqIdVal),
    EqIdValList(EqIdValList),
    Placeholder,
}
impl Default for ParsedOperation {
    fn default() -> Self {
        ParsedOperation::Placeholder
    }
}

// Documentation for subsequent structs at:
// UEFI Spec v2.9 Pages 1840 - 1916

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct FormSet {
    pub guid: Guid,
    pub title_string_id: u16,
    pub help_string_id: u16,
    pub flags: u8,
    pub class_guid: Guid,
}

pub trait Question {
    fn question_header(&self) -> QuestionHeader;
}

#[derive(BinRead, Debug, PartialEq, Clone, Copy)]
#[br(little)]
// In the UEFI spec question header's first field is statement header
// however instead of having a separate nested struct I've combined it together
pub struct QuestionHeader {
    // start of statement header
    pub prompt_string_id: u16,
    pub help_string_id: u16,
    // rest of the question header
    pub question_id: u16,
    pub var_store_id: u16,
    pub var_store_info: u16, // an offset except in case of VarStoreNameValue where it'll be a string_id
    pub question_flags: u8,
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct OneOf {
    pub question_header: QuestionHeader,
    pub flags: u8,
    #[br(parse_with = range_parser, args(flags))]
    pub data: Range,
}

impl Question for OneOf {
    fn question_header(&self) -> QuestionHeader {
        self.question_header
    }
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct Numeric {
    pub question_header: QuestionHeader,
    pub flags: u8,
    #[br(parse_with = range_parser, args(flags))]
    pub data: Range,
}

impl Question for Numeric {
    fn question_header(&self) -> QuestionHeader {
        self.question_header
    }
}

// Note: there is nothing called Range in the spec.
// It has weird conditions to parse the data field in Numeric and OneOfOption.

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct Range8 {
    min_value: u8,
    max_value: u8,
    step: u8,
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct Range16 {
    min_value: u16,
    max_value: u16,
    step: u16,
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct Range32 {
    min_value: u32,
    max_value: u32,
    step: u32,
}
#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct Range64 {
    min_value: u64,
    max_value: u64,
    step: u64,
}

pub enum RangeType {
    NumSize8(u8),
    NumSize16(u16),
    NumSize32(u32),
    NumSize64(u64),
}

#[derive(Debug, PartialEq)]
pub enum Range {
    Range8(Range8),
    Range16(Range16),
    Range32(Range32),
    Range64(Range64),
}

fn range_parser<R: Read + Seek>(
    reader: &mut R,
	_endian: binrw::Endian,
    args: (u8,),
) -> BinResult<Range> {
    match args.0 & 0x0Fu8 {
        0x01u8 => {
            let r: Range16 = reader.read_ne()?;
            Ok(Range::Range16(r))
        }
        0x02u8 => {
            let r: Range32 = reader.read_ne()?;
            Ok(Range::Range32(r))
        }
        0x03u8 => {
            let r: Range64 = reader.read_ne()?;
            Ok(Range::Range64(r))
        }

        _ => {
            let r: Range8 = reader.read_ne()?;
            Ok(Range::Range8(r))
        }
    }
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct CheckBox {
    pub question_header: QuestionHeader,
    pub flags: u8,
}

impl Question for CheckBox {
    fn question_header(&self) -> QuestionHeader {
        self.question_header
    }
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct OneOfOption {
    pub option_string_id: u16,
    pub flags: u8,
    value_type: u8,
    #[br(parse_with = type_value_parser, args(value_type))]
    pub value: TypeValue,
}

trait VariableStore {
    fn name(&self) -> String;
    fn guid(&self) -> String;
    fn size(&self) -> u16;

    fn store_filename(&self) -> String {
        format!(
            "/sys/firmware/efi/efivars/{}-{}",
            &self.name(),
            &self.guid().to_ascii_lowercase()
        )
    }

    /// extract raw bytes from UEFI using the /sys virtual filesystem
    fn read_bytes(&self) -> Result<Vec<u8>> {
        // try to read data from varstore
        let mut file = File::open(&self.store_filename())
            .context("failed to open sysfs efivars to get varstore bytes")?;
        let mut buf = vec![0u8; self.size().into()];
        // only read as much as we require
        file.read_exact(&mut buf).context(
            "failed to read bytes from sysfs efivars of size specified by varstore in hiidb",
        )?;
        Ok(buf)
    }

    fn write_at_offset(&self, offset: u16, data: TypeValue) -> Result<()> {
        // Steps:
        // * Read bytes
        // * Seek to 4 + offset
        // * If checks pass, write your answer

        // We have three layers of checks so as to not accidentally corrupt EFI vars.

        // The /run/lock/efibootmgr-remount lock will release automatically on drop.
        // If something errors out, doesn't matter since we are using the flock syscall to lock it.
        // Linux will then release it automatically after the program ends.

        const LOCK_FILE_PATH: &str = "/run/lock/efibootmgr-remount";
        let mut lock = FileLock::new(LOCK_FILE_PATH);
        lock.lock()?;

        let store_filename = self.store_filename();

        let mut file_ro = File::open(&store_filename)
            .context("Failed to open efivarfs file to get varstore bytes")?;

        let mut file_contents = Vec::new();
        file_ro
            .read_to_end(&mut file_contents)
            .context("Failed to read efivarfs file")?;

        let mut cursor = Cursor::new(file_contents);
        cursor.seek(SeekFrom::Start(4 + offset as u64))?;

        match data {
            TypeValue::NumSize8(v) => v.write_options(&mut cursor, binrw::endian::Endian::Little, ())?,
            TypeValue::NumSize16(v) => v.write_options(&mut cursor, binrw::endian::Endian::Little, ())?,
            TypeValue::NumSize32(v) => v.write_options(&mut cursor, binrw::endian::Endian::Little, ())?,
            TypeValue::NumSize64(v) => v.write_options(&mut cursor, binrw::endian::Endian::Little, ())?,
            _ => {}
        }

        let _efifs = EfivarsMountGuard::new().context("Failed to create efivars fs mount guard")?;

        // Needed on kernel 4.6+ to make EFI vars the kernel doesn't know how to
        // validate temporarily writable.
        let _immutability_attribute_guard = EfivarsImmutabilityGuard::new(&store_filename)
            .context("failed to create immutability attribute guard")?;

        // All checks passed, now we can try to write.
        debug!("Writing value to {}", &store_filename);
        File::create(&store_filename)
            .context("Failed to open efivarfs file for writing")?
            .write_all(cursor.get_ref())
            .context("Failed to write to efivarfs file")?;

        Ok(())
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

impl VariableStore for VarStore {
    fn name(&self) -> String {
        self.name.to_string()
    }
    fn guid(&self) -> String {
        self.guid.to_string()
    }
    fn size(&self) -> u16 {
        self.size
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
    fn guid(&self) -> String {
        self.guid.to_string()
    }
    fn size(&self) -> u16 {
        self.size
    }
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct DefaultStore {
    pub name_string_id: u16,
    pub default_id: u16,
}

// IFRDefault is called IFRDefault instead of Default like the opcode because we don't want
// rust to confuse it with std:default:Default trait
#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct IFRDefault {
    pub default_id: u16,
    value_type: u8,
    // The third field is TypeValue and should be parsed with the following code.
    // However the structure of IFRDefault and existence of that field varies depending on
    // what scope the IFRDefault is in, even though the opcode remains the same.

    // Since we are not using TypeValue for IFRDefault right now, we're gonna pretend that field does not exist.

    // #[br(parse_with = type_value_parser, args(value_type))]
    // pub value: TypeValue,
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct Form {
    pub form_id: u16,
    pub title_string_id: u16,
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct Text {
    pub prompt_string_id: u16,
    pub help_string_id: u16,
    pub text_id: u16,
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct Subtitle {
    pub prompt_string_id: u16,
    pub help_string_id: u16,
    pub flags: u8,
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct QuestionRef1 {
    pub question_id: u16,
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct EqIdVal {
    pub question_id: u16,
    pub value: u16,
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct EqIdValList {
    pub question_id: u16,
    pub list_length: u16,
    #[br(count = list_length)]
    pub value_list: Vec<u16>,
}

#[derive(BinRead, Debug, PartialEq, Clone, Copy)]
#[br(little)]
pub struct Time {
    pub hour: u8,
    pub minute: u8,
    pub second: u8,
}

#[derive(BinRead, Debug, PartialEq, Clone, Copy)]
#[br(little)]
pub struct Date {
    pub year: u16,
    pub month: u8,
    pub day: u8,
}

#[derive(BinRead, Debug, PartialEq, Clone, Copy)]
#[br(little)]
pub struct Ref {
    pub question_id: u16,
    pub form_id: u16,
    pub form_set_guid: Guid,
    pub device_path_string_id: u16,
}

#[derive(Debug, PartialEq, Clone, Copy)]
/// Any structs having TypeValue as a field can have value of one of these types
/// depending on the value of the value_type
pub enum TypeValue {
    NumSize8(u8),
    NumSize16(u16),
    NumSize32(u32),
    NumSize64(u64),
    Boolean(bool),
    Time(Time),
    Date(Date),
    StringID(u16),
    Other,
    Undefined,
    Action(u16),
    // Buffer(Vec<u8>),  - spec unclear ; FIXME
    Ref(Ref),
    Unknown(u8),
}

fn type_value_parser<R: Read + Seek>(
    reader: &mut R,
	_endian: binrw::Endian,
    args: (u8,),
) -> BinResult<TypeValue> {
    match args.0 {
        0x00u8 => {
            let r: u8 = reader.read_ne()?;
            Ok(TypeValue::NumSize8(r))
        }
        0x01u8 => {
            let r: u16 = reader.read_ne()?;
            Ok(TypeValue::NumSize16(r))
        }
        0x02u8 => {
            let r: u32 = reader.read_ne()?;
            Ok(TypeValue::NumSize32(r))
        }
        0x03u8 => {
            let r: u64 = reader.read_ne()?;
            Ok(TypeValue::NumSize64(r))
        }
        0x04u8 => {
            let r: u8 = reader.read_ne()?;
            if r != 0 {
                return Ok(TypeValue::Boolean(true));
            }
            Ok(TypeValue::Boolean(false))
        }
        // TODO: handle other types like Date, Time & Ref. We have already made structs for them.
        _ => {
            let r: u8 = reader.read_ne()?;
            Ok(TypeValue::Unknown(r))
        }
    }
}

pub fn handle_form_package(
    package_cursor: &mut Cursor<&Vec<u8>>,
) -> Result<Rc<RefCell<IFROperation>>> {
    // this is the root element so all the values like op_code, length, etc are dummy
    debug!("new forms package");
    let root = Rc::new(RefCell::new(IFROperation {
        op_code: IFROpCode::Unknown(DUMMY_OPCODE),
        length: 0,
        open_scope: false,
        data: Vec::new(),
        parent: None,
        children: Vec::new(),
        parsed_data: ParsedOperation::Placeholder,
    }));

    let mut current_scope = Rc::clone(&root);

    // this loop will terminate when it sees the IFR:End opcode as a child of FormSet
    // if input data is malformed then it will exit on erroring out cause none of the magic bytes match
    loop {
        let node: IFROperation = package_cursor
            .read_ne()
            .context("Failed to parse IFR operation")?;

        let current_node = Rc::new(RefCell::new(node));

        debug!("OpCode is {:?}", current_node.borrow().op_code);

        // end of current scope
        if current_node.borrow().op_code == IFROpCode::End {
            let current_scope_clone = Rc::clone(&current_scope);
            match current_scope_clone.borrow().parent.as_ref() {
                Some(parent_ref) => {
                    match parent_ref.upgrade() {
                        Some(parent_ref_rc) => {
                            // current_scope = current_scope 's parent
                            current_scope = Rc::clone(&parent_ref_rc);
                        }
                        None => {}
                    }

                    debug!(
                        "Inside the IFR:End case. Op Code: {:?}",
                        current_scope.borrow().op_code
                    );
                }
                None => debug!("IFR:End when parent_ref is none"),
            };

            // if its our own dummy opcode we've reached the top again and this form package has been parsed
            if current_scope.borrow().op_code == IFROpCode::Unknown(DUMMY_OPCODE) {
                debug!("Reached root element. Current scope: {:?}", current_scope);
                // NOTE: I'm 99.99 % sure there is only one top level FormSet in a package.
                // Just in case there isn't there could be a chance we're skipping any subsequent FormSets
                // by breaking here.
                // If anyone finds an exception in the future (next to zero chance I know) you will have to
                // remove the break here and find another way of checking bounds to prevent a "trying to read out of bounds" error
                break;
            }
            continue;
        }

        handle_opcode(Rc::clone(&current_node)).context(format!(
            "Failed to parse op_code {:?} properly",
            &current_node.borrow().op_code,
        ))?;

        // add current_node to current_scope's children
        current_scope
            .borrow_mut()
            .children
            .push(Rc::clone(&current_node));

        // set current_node's parent
        current_node.borrow_mut().parent = Some(Rc::downgrade(&current_scope));

        if current_node.borrow().open_scope {
            current_scope = Rc::clone(&current_node);
        }
    }

    Ok(root)
}

fn handle_opcode(node: Rc<RefCell<IFROperation>>) -> Result<()> {
    let mut node = node.borrow_mut();
    let mut data_cursor = Cursor::new(&node.data);

    // debug!("Handling OpCode {:?}", current_node.borrow().op_code);

    match node.op_code {
        IFROpCode::FormSet => {
            let parsed: FormSet = data_cursor
                .read_ne()
                .context("Failed to parse FormSet's data")?;
            debug!("FormSet is {:?}", parsed);
            node.parsed_data = ParsedOperation::FormSet(parsed);
        }

        IFROpCode::OneOf => {
            let parsed: OneOf = data_cursor
                .read_ne()
                .context("Failed to parse OneOf's data")?;
            debug!("OneOf is {:?}", parsed);
            node.parsed_data = ParsedOperation::OneOf(parsed);
        }
        IFROpCode::CheckBox => {
            let parsed: CheckBox = data_cursor
                .read_ne()
                .context("Failed to parse CheckBox's data")?;
            debug!("CheckBox is {:?}", parsed);
            node.parsed_data = ParsedOperation::CheckBox(parsed);
        }
        IFROpCode::OneOfOption => {
            let parsed: OneOfOption = data_cursor
                .read_ne()
                .context("Failed to parse OneOfOption's data")?;
            debug!("OneOfOption is {:?}", parsed);
            node.parsed_data = ParsedOperation::OneOfOption(parsed);
        }
        IFROpCode::VarStore => {
            let parsed: VarStore = data_cursor
                .read_ne()
                .context("Failed to parse VarStore's data")?;

            debug!("VarStore is {:?}", &parsed);

            if log::Level::Debug <= log::max_level() {
                // We HAVE to ignore errors while reading varstores from /sys/firmware/efi/efivars/{name}-{guid}
                // because the file might not exist even if the db says it does.
                // In many cases it will not exist and we'll just use the default value instead.
                // If we are running this in a virtual machine (or sandcastle) then /sys/firmware/efi/efivars won't exist.
                // Or we might not have perms to read it but thats on the caller of the lib to make sure its okay.

                // We're not saving these in the struct because we don't know how many there are - could take up a large amount of memory.
                // For non debug uses we will only call this when we want to know the answer to a question.
                match &parsed.read_bytes() {
                    Ok(b) => {
                        debug!("Varstore bytes are {:?}", b);
                    }
                    Err(why) => {
                        debug!("Failed to read uefi varstore {}", why);
                    }
                }
            }

            node.parsed_data = ParsedOperation::VarStore(parsed);
        }
        IFROpCode::VarStoreEfi => {
            // this is implemented in hiilib and the docs for this are relatively clear
            // so I implemented this but I haven't seen it being used anywhere in the dbdumps I have
            let parsed: VarStoreEfi = data_cursor
                .read_ne()
                .context("Failed to parse VarStoreEfi's data")?;
            debug!("VarStoreEfi is {:?}", parsed);
            node.parsed_data = ParsedOperation::VarStoreEfi(parsed);
        }
        IFROpCode::DefaultStore => {
            let parsed: DefaultStore = data_cursor
                .read_ne()
                .context("Failed to parse DefaultStore's data")?;
            debug!("DefaultStore is {:?}", parsed);
            node.parsed_data = ParsedOperation::DefaultStore(parsed);
        }
        IFROpCode::Default => {
            let parsed: IFRDefault = data_cursor
                .read_ne()
                .context("Failed to parse Default's data")?;
            debug!("Default is {:?}", parsed);
            node.parsed_data = ParsedOperation::IFRDefault(parsed);
        }
        IFROpCode::Form => {
            let parsed: Form = data_cursor
                .read_ne()
                .context("Failed to parse Form's data")?;
            debug!("Form is {:?}", parsed);
            node.parsed_data = ParsedOperation::Form(parsed);
        }
        IFROpCode::Text => {
            let parsed: Text = data_cursor
                .read_ne()
                .context("Failed to parse Text's data")?;
            debug!("Text is {:?}", parsed);
            node.parsed_data = ParsedOperation::Text(parsed);
        }
        IFROpCode::Subtitle => {
            let parsed: Subtitle = data_cursor
                .read_ne()
                .context("Failed to parse Subtitle's data")?;
            debug!("Subtitle is {:?}", parsed);
            node.parsed_data = ParsedOperation::Subtitle(parsed);
        }
        IFROpCode::Numeric => {
            let parsed: Numeric = data_cursor
                .read_ne()
                .context("Failed to parse Numeric's data")?;
            debug!("Numeric is {:?}", parsed);
            node.parsed_data = ParsedOperation::Numeric(parsed);
        }
        IFROpCode::QuestionRef1 => {
            let parsed: QuestionRef1 = data_cursor
                .read_ne()
                .context("Failed to parse QuestionRef1's data")?;
            debug!("QuestionRef1 is {:?}", parsed);
            node.parsed_data = ParsedOperation::QuestionRef1(parsed);
        }
        IFROpCode::EqIdVal => {
            let parsed: EqIdVal = data_cursor
                .read_ne()
                .context("Failed to parse EqIdVal's data")?;
            debug!("EqIdVal is {:?}", parsed);
            node.parsed_data = ParsedOperation::EqIdVal(parsed);
        }
        IFROpCode::EqIdValList => {
            let parsed: EqIdValList = data_cursor
                .read_ne()
                .context("Failed to parse EqIdValList's data")?;
            debug!("EqIdValList is {:?}", parsed);
            node.parsed_data = ParsedOperation::EqIdValList(parsed);
        }
        _ => (),
    }

    Ok(())
}

pub struct QuestionDescriptor {
    pub question: String,
    pub help: String,
    pub value: String,
    max_value: RangeType,
    opcode: IFROpCode,
    pub possible_options: Vec<AnswerOption>,
    header: QuestionHeader,
    varstore: Option<Box<dyn VariableStore>>,
}
impl fmt::Debug for QuestionDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("QuestionObject")
            .field("question", &self.question)
            .field("value", &self.value)
            .field("help", &self.help)
            .field("possible_options", &self.possible_options)
            .finish()
    }
}

#[derive(Debug)]
pub struct AnswerOption {
    pub value: String,
    raw_value: TypeValue,
}

// list_questions returns a list of QuestionDescriptors in a form package
// node should be the form_package node
pub fn list_questions(
    node: Rc<RefCell<IFROperation>>,
    string_packages: &Vec<HashMap<i32, String>>,
) -> Vec<QuestionDescriptor> {
    let mut res = Vec::new();

    let current_node = node.borrow();

    match &current_node.parsed_data {
        ParsedOperation::Numeric(parsed) => {
            let question = find_corresponding_string(
                parsed.question_header().prompt_string_id,
                string_packages,
            );

            let varstore = find_corresponding_varstore(
                Rc::clone(&node),
                parsed.question_header().var_store_id,
            );

            let question_descriptor =
                handle_numeric(varstore, parsed, question, string_packages, &current_node);
            res.push(question_descriptor);
        }
        ParsedOperation::OneOf(parsed) => {
            let question = find_corresponding_string(
                parsed.question_header().prompt_string_id,
                string_packages,
            );

            let varstore = find_corresponding_varstore(
                Rc::clone(&node),
                parsed.question_header().var_store_id,
            );

            let question_descriptor = handle_oneof(
                varstore,
                parsed,
                &node,
                string_packages,
                question,
                &current_node,
            );
            res.push(question_descriptor);
        }
        ParsedOperation::CheckBox(parsed) => {
            let question = find_corresponding_string(
                parsed.question_header().prompt_string_id,
                string_packages,
            );

            let varstore = find_corresponding_varstore(
                Rc::clone(&node),
                parsed.question_header().var_store_id,
            );

            let question_descriptor =
                handle_checkbox(varstore, parsed, question, string_packages, &current_node);
            res.push(question_descriptor);
        }

        _ => {}
    }

    // Now look inside current node's children for more questions
    for child in &node.borrow().children {
        res.extend(list_questions(Rc::clone(child), string_packages));
    }

    res
}

/// find_question accepts the root node, string_packages and possible_question_phrases.
/// possible_question_phrases is a vector of strings which represent variations of the
/// same question. So if a single phrase matches then we assume that we have the answer.
pub fn find_question<T>(
    node: Rc<RefCell<IFROperation>>,
    string_packages: &Vec<HashMap<i32, String>>,
    possible_question_phrases: &HashSet<T>,
) -> Option<QuestionDescriptor>
where
    T: AsRef<str>,
{
    let current_node = node.borrow();

    // Only Numeric, OneOf and CheckBox are questions.
    // If our question is found this match expression will return without caring if we found answer.
    // Otherwise, we will look at children of current_node

    for phrase in possible_question_phrases {
        match &current_node.parsed_data {
            ParsedOperation::Numeric(parsed) => {
                let question = find_corresponding_string(
                    parsed.question_header().prompt_string_id,
                    string_packages,
                );

                if phrase.as_ref().eq_ignore_ascii_case(question.trim()) {
                    let varstore = find_corresponding_varstore(
                        Rc::clone(&node),
                        parsed.question_header().var_store_id,
                    );

                    let res =
                        handle_numeric(varstore, parsed, question, string_packages, &current_node);

                    return Some(res);
                }
            }
            ParsedOperation::OneOf(parsed) => {
                let question = find_corresponding_string(
                    parsed.question_header().prompt_string_id,
                    string_packages,
                );

                if phrase.as_ref().eq_ignore_ascii_case(question.trim()) {
                    let varstore = find_corresponding_varstore(
                        Rc::clone(&node),
                        parsed.question_header().var_store_id,
                    );

                    let res = handle_oneof(
                        varstore,
                        parsed,
                        &node,
                        string_packages,
                        question,
                        &current_node,
                    );

                    return Some(res);
                }
            }
            ParsedOperation::CheckBox(parsed) => {
                let question = find_corresponding_string(
                    parsed.question_header().prompt_string_id,
                    string_packages,
                );

                if phrase.as_ref().eq_ignore_ascii_case(question.trim()) {
                    let varstore = find_corresponding_varstore(
                        Rc::clone(&node),
                        parsed.question_header().var_store_id,
                    );

                    let res =
                        handle_checkbox(varstore, parsed, question, string_packages, &current_node);

                    return Some(res);
                }
            }

            _ => {}
        }
    }

    // Question not found in current_node so look at children
    for child in &node.borrow().children {
        if let Some(res) =
            find_question(Rc::clone(child), string_packages, possible_question_phrases)
        {
            return Some(res);
        }
    }

    None
}

fn handle_checkbox(
    varstore: Result<Box<dyn VariableStore>, anyhow::Error>,
    parsed: &CheckBox,
    question: &str,
    string_packages: &Vec<HashMap<i32, String>>,
    current_node: &std::cell::Ref<IFROperation>,
) -> QuestionDescriptor {
    let mut answer = String::new();
    match &varstore {
        Err(_) => {
            answer.push_str("Unknown");
        }
        Ok(vstore) => match vstore.read_bytes() {
            Err(_) => {
                answer.push_str("Unknown");
            }
            Ok(bytes) => {
                // for a checkbox size should be of type u8
                let answer_raw: Result<u8> =
                    extract_efi_data::<u8>(parsed.question_header().var_store_info, &bytes);
                match answer_raw {
                    Ok(a) => answer.push_str(format!("{a}").as_str()),
                    Err(_) => answer.push_str("Unknown"),
                }
            }
        },
    }
    let res = QuestionDescriptor {
        question: question.to_string(),
        value: answer,
        help: find_corresponding_string(parsed.question_header().help_string_id, string_packages)
            .to_string(),
        possible_options: Vec::new(),
        header: parsed.question_header(),
        varstore: varstore.ok(),
        max_value: RangeType::NumSize8(1),
        opcode: current_node.op_code,
    };
    res
}

fn handle_oneof(
    varstore: Result<Box<dyn VariableStore>, anyhow::Error>,
    parsed: &OneOf,
    node: &Rc<RefCell<IFROperation>>,
    string_packages: &Vec<HashMap<i32, String>>,
    question: &str,
    current_node: &std::cell::Ref<IFROperation>,
) -> QuestionDescriptor {
    let mut answer = String::new();
    let mut chosen_value: u64 = 0;
    let mut varstore_not_found = false;
    match &varstore {
        Err(_) => {
            answer.push_str("Unknown");
            varstore_not_found = true;
        }
        Ok(vstore) => match vstore.read_bytes() {
            Err(_) => {
                answer.push_str("Unknown");
                varstore_not_found = true;
            }
            Ok(bytes) => match &parsed.data {
                Range::Range8(_) => {
                    try_read_answer_as_option::<u8>(
                        &parsed.question_header(),
                        &bytes,
                        &mut chosen_value,
                    );
                }
                Range::Range16(_) => {
                    try_read_answer_as_option::<u16>(
                        &parsed.question_header(),
                        &bytes,
                        &mut chosen_value,
                    );
                }
                Range::Range32(_) => {
                    try_read_answer_as_option::<u32>(
                        &parsed.question_header(),
                        &bytes,
                        &mut chosen_value,
                    );
                }
                Range::Range64(_) => {
                    try_read_answer_as_option::<u64>(
                        &parsed.question_header(),
                        &bytes,
                        &mut chosen_value,
                    );
                }
            },
        },
    }
    let mut possible_options = Vec::new();
    if !varstore_not_found {
        // Some of OneOf's children are OneOfOptions

        let mut found_option = false;
        for child in &node.borrow().children {
            match &child.borrow().parsed_data {
                ParsedOperation::OneOfOption(o) => {
                    let current_value: u64 = match o.value {
                        TypeValue::NumSize8(c) => c as u64,
                        TypeValue::NumSize16(c) => c as u64,
                        TypeValue::NumSize32(c) => c as u64,
                        TypeValue::NumSize64(c) => c as u64,
                        _ => 0,
                    };

                    let opt = AnswerOption {
                        raw_value: o.value.clone(),
                        value: find_corresponding_string(o.option_string_id, string_packages)
                            .to_string(),
                    };

                    if current_value == chosen_value && !found_option {
                        found_option = true;
                        answer.push_str(opt.value.trim());
                        // cannot break here because we want to add all options to possible_options
                    }

                    possible_options.push(opt);
                }
                _ => {}
            }
        }

        if !found_option {
            answer.push_str("Unknown");
        }
    }
    let res = QuestionDescriptor {
        question: question.trim().to_string(),
        value: answer,
        help: find_corresponding_string(parsed.question_header().help_string_id, string_packages)
            .to_string(),
        possible_options,
        header: parsed.question_header(),
        varstore: varstore.ok(),
        max_value: match &parsed.data {
            Range::Range8(r) => RangeType::NumSize8(r.max_value),
            Range::Range16(r) => RangeType::NumSize16(r.max_value),
            Range::Range32(r) => RangeType::NumSize32(r.max_value),
            Range::Range64(r) => RangeType::NumSize64(r.max_value),
        },
        opcode: current_node.op_code,
    };
    res
}

fn handle_numeric(
    varstore: Result<Box<dyn VariableStore>, anyhow::Error>,
    parsed: &Numeric,
    question: &str,
    string_packages: &Vec<HashMap<i32, String>>,
    current_node: &std::cell::Ref<IFROperation>,
) -> QuestionDescriptor {
    let mut answer = String::new();

    match &varstore {
        Err(_) => {
            answer.push_str("Unknown");
        }
        Ok(vstore) => match vstore.read_bytes() {
            Err(_) => {
                answer.push_str("Unknown");
            }
            Ok(bytes) => match &parsed.data {
                Range::Range8(_) => {
                    try_read_answer_as_string::<u8>(&parsed.question_header(), &bytes, &mut answer)
                }
                Range::Range16(_) => {
                    try_read_answer_as_string::<u16>(&parsed.question_header(), &bytes, &mut answer)
                }
                Range::Range32(_) => {
                    try_read_answer_as_string::<u32>(&parsed.question_header(), &bytes, &mut answer)
                }
                Range::Range64(_) => {
                    try_read_answer_as_string::<u64>(&parsed.question_header(), &bytes, &mut answer)
                }
            },
        },
    }
    let res = QuestionDescriptor {
        question: question.to_string(),
        value: answer,
        help: find_corresponding_string(parsed.question_header().help_string_id, string_packages)
            .to_string(),
        possible_options: Vec::new(),
        header: parsed.question_header(),
        varstore: varstore.ok(),
        max_value: match &parsed.data {
            Range::Range8(r) => RangeType::NumSize8(r.max_value),
            Range::Range16(r) => RangeType::NumSize16(r.max_value),
            Range::Range32(r) => RangeType::NumSize32(r.max_value),
            Range::Range64(r) => RangeType::NumSize64(r.max_value),
        },
        opcode: current_node.op_code,
    };
    res
}

// utility function for questions i.e. OneOf, Numeric and Checkbox
fn try_read_answer_as_string<T>(question_header: &QuestionHeader, bytes: &Vec<u8>, ans: &mut String)
where
    T: BinRead + Display,
    for<'a> <T as BinRead>::Args<'a>: Default,
{
    let extracted_data: Result<T> = extract_efi_data(question_header.var_store_info, bytes);
    match extracted_data {
        Ok(a) => ans.push_str(format!("{a}").as_str()),
        Err(_) => ans.push_str("Unknown"),
    }
}

// utility function for OneOfOptions
fn try_read_answer_as_option<T>(
    question_header: &QuestionHeader,
    bytes: &Vec<u8>,
    chosen_value: &mut u64,
) where
    T: BinRead + Display + Into<u64>,
    for<'a> <T as BinRead>::Args<'a>: Default,
{
    let extracted_data: Result<T> = extract_efi_data(question_header.var_store_info, bytes);
    if let Ok(a) = extracted_data {
        *chosen_value = a.into();
    }
}

// display returns a String which is our tree like representation of a Forms package
pub fn display(
    node: Rc<RefCell<IFROperation>>,
    level: usize,
    string_packages: &Vec<HashMap<i32, String>>,
) -> Result<String> {
    let mut result = String::new();
    let extra_spaces = "    ".repeat(level);

    let current_node = node.borrow();

    match &current_node.parsed_data {
        ParsedOperation::Placeholder => {
            if current_node.op_code == IFROpCode::Unknown(DUMMY_OPCODE) {
                result.push_str(format!("{extra_spaces}OpCode: ROOT\n").as_str())
            }
        }
        ParsedOperation::Subtitle(parsed) => result.push_str(
            format!(
                "{extra_spaces}OpCode: {:?} - S: {}\n",
                current_node.op_code,
                find_corresponding_string(parsed.prompt_string_id, string_packages),
            )
            .as_str(),
        ),
        ParsedOperation::FormSet(parsed) => result.push_str(
            format!(
                "{extra_spaces}OpCode: {:?} - {} - GUID {} - ClassGUID {}\n",
                current_node.op_code,
                find_corresponding_string(parsed.title_string_id, string_packages),
                parsed.guid,
                parsed.class_guid,
            )
            .as_str(),
        ),
        ParsedOperation::VarStore(parsed) => result.push_str(
            format!(
                "{extra_spaces}OpCode: {:?} - Name: {}\n",
                current_node.op_code,
                parsed.name.to_string(),
            )
            .as_str(),
        ),
        ParsedOperation::OneOfOption(parsed) => result.push_str(
            format!(
                "{extra_spaces}OpCode: {:?} - S: {}\n{extra_spaces}-ValueType:{}\n{extra_spaces}-Value:{:?}\n",
                current_node.op_code,
                find_corresponding_string(parsed.option_string_id, string_packages),
                parsed.value_type,
                parsed.value
            )
            .as_str(),
        ),

        ParsedOperation::OneOf(parsed) => {
            let mut answer_disp = String::new();

            let varstore =
                find_corresponding_varstore(Rc::clone(&node), parsed.question_header().var_store_id);


            match varstore {
                Err(_) => {
                    answer_disp.push_str("Unknown");
                }
                Ok(vstore) => match vstore.read_bytes() {
                    Err(_) => {
                        answer_disp.push_str("Unknown");
                    },
                    Ok(bytes) => match &parsed.data {
                        Range::Range8(_) => {
                            try_read_answer_as_string::<u8>(&parsed.question_header(), &bytes, &mut answer_disp);
                        }
                        Range::Range16(_) => {
                            try_read_answer_as_string::<u16>(&parsed.question_header(), &bytes, &mut answer_disp);
                        }
                        Range::Range32(_) => {
                            try_read_answer_as_string::<u32>(&parsed.question_header(), &bytes, &mut answer_disp);
                        }
                        Range::Range64(_) => {
                            try_read_answer_as_string::<u64>(&parsed.question_header(), &bytes, &mut answer_disp);
                        }
                    },
                }
            }

            result.push_str(
                format!(
                    "{extra_spaces}OpCode: {:?} - Q: {} - Help: {}\n{extra_spaces}-{:?}\n{extra_spaces}-Answer: {answer_disp}\n",
                    current_node.op_code,
                    find_corresponding_string(
                        parsed.question_header().prompt_string_id,
                        string_packages
                    ),
                    find_corresponding_string(
                        parsed.question_header().help_string_id,
                        string_packages
                    ),
                    parsed.data
                )
                .as_str(),
            );
        }
        ParsedOperation::Numeric(parsed) => {
            let mut answer_disp = String::new();

            let varstore =
                find_corresponding_varstore(Rc::clone(&node), parsed.question_header().var_store_id);
                match varstore {
                    Err(_) => {
                        answer_disp.push_str("Unknown");
                    }
                    Ok(vstore) => match vstore.read_bytes() {
                        Err(_) => {
                            answer_disp.push_str("Unknown");
                        }
                        Ok(bytes) => match &parsed.data {
                            Range::Range8(_) => {
                                try_read_answer_as_string::<u8>(&parsed.question_header(), &bytes, &mut answer_disp);
                            }
                            Range::Range16(_) => {
                                try_read_answer_as_string::<u16>(&parsed.question_header(), &bytes, &mut answer_disp);
                            }
                            Range::Range32(_) => {
                                try_read_answer_as_string::<u32>(&parsed.question_header(), &bytes, &mut answer_disp);
                            }
                            Range::Range64(_) => {
                                try_read_answer_as_string::<u64>(&parsed.question_header(), &bytes, &mut answer_disp);
                            }
                        },
                },
            }

            result.push_str(
                format!(
                    "{extra_spaces}OpCode: {:?} - Q: {} - Help: {}\n{extra_spaces}-{:?}\n{extra_spaces}-Answer: {answer_disp}\n",
                    current_node.op_code,
                    find_corresponding_string(
                        parsed.question_header().prompt_string_id,
                        string_packages
                    ),
                    find_corresponding_string(
                        parsed.question_header().help_string_id,
                        string_packages
                    ),
                    parsed.data
                )
                .as_str(),
            );
        }
        ParsedOperation::CheckBox(parsed) => {
            let mut answer_disp = String::new();

            let varstore =
                find_corresponding_varstore(Rc::clone(&node), parsed.question_header().var_store_id);

                match varstore {
                    Err(_) => {
                        answer_disp.push_str("Unknown");
                    }
                    Ok(vstore) => match vstore.read_bytes() {
                        Err(_) => {
                            answer_disp.push_str("Unknown");
                        },
                        Ok(bytes) => {
                            // for a checkbox size should be of type u8
                            try_read_answer_as_string::<u8>(&parsed.question_header(), &bytes, &mut answer_disp);
                        }
                    }
            }

            result.push_str(
                format!(
                    "{extra_spaces}OpCode: {:?} - Q: - {} - Help: - {}\n{extra_spaces}-Answer: {answer_disp}\n",
                    current_node.op_code,
                    find_corresponding_string(
                        parsed.question_header().prompt_string_id,
                        string_packages
                    ),
                    find_corresponding_string(
                        parsed.question_header().help_string_id,
                        string_packages
                    ),
                )
                .as_str(),
            );
        }

        // TODO: we have already made structs for the most popular opcodes so we should finish the display function for them
        // however display is only for debugging and a visual representation of the forms for humans
        _ => result
            .push_str(format!("{extra_spaces}OpCode: {:?}\n",  current_node.op_code).as_str()),
    }

    for child in &node.borrow().children {
        result.push_str(display(Rc::clone(child), level + 1, string_packages)?.as_str());
    }

    Ok(result)
}

#[derive(Error, Debug)]
pub enum ChangeValueError {
    #[error("provided value did not match any possible option")]
    InvalidOption,
    #[error("provided value exceeded max possible value")]
    ExceededMaxValue,

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub fn change_value(
    question: &QuestionDescriptor,
    new_value: &str,
) -> Result<bool, ChangeValueError> {
    let mut changed = false;
    if let Some(varstore) = &question.varstore {
        if question.opcode == IFROpCode::OneOf {
            for option in &question.possible_options {
                if option.value.eq_ignore_ascii_case(new_value) {
                    varstore.write_at_offset(question.header.var_store_info, option.raw_value)?;
                    changed = true;
                    break;
                }
            }

            if !changed {
                return Err(ChangeValueError::InvalidOption);
            }
        } else {
            match question.max_value {
                RangeType::NumSize8(m) => {
                    let data_to_write = new_value
                        .parse::<u8>()
                        .context("value should fit in a u8")?;
                    if data_to_write > m {
                        return Err(ChangeValueError::ExceededMaxValue);
                    }
                    varstore.write_at_offset(
                        question.header.var_store_info,
                        TypeValue::NumSize8(data_to_write),
                    )?;
                    changed = true;
                }
                RangeType::NumSize16(m) => {
                    let data_to_write = new_value
                        .parse::<u16>()
                        .context("value should fit in a u16")?;
                    if data_to_write > m {
                        return Err(ChangeValueError::ExceededMaxValue);
                    }
                    varstore.write_at_offset(
                        question.header.var_store_info,
                        TypeValue::NumSize16(data_to_write),
                    )?;
                    changed = true;
                }
                RangeType::NumSize32(m) => {
                    let data_to_write = new_value
                        .parse::<u32>()
                        .context("value should fit in a u32")?;
                    if data_to_write > m {
                        return Err(ChangeValueError::ExceededMaxValue);
                    }
                    varstore.write_at_offset(
                        question.header.var_store_info,
                        TypeValue::NumSize32(data_to_write),
                    )?;
                    changed = true;
                }
                RangeType::NumSize64(m) => {
                    let data_to_write = new_value
                        .parse::<u64>()
                        .context("value should fit in a u64")?;
                    if data_to_write > m {
                        return Err(ChangeValueError::ExceededMaxValue);
                    }
                    varstore.write_at_offset(
                        question.header.var_store_info,
                        TypeValue::NumSize64(data_to_write),
                    )?;
                    changed = true;
                }
            }
        }
    }

    Ok(changed)
}

fn find_corresponding_string<'a>(
    string_id: u16,
    string_packages: &'a Vec<HashMap<i32, String>>,
) -> &'a str {
    // TODO: accept language pack parameter later
    // it defaults to the first language pack it can find and the first one is en-US

    for package in string_packages {
        if let Some(s) = package.get(&(string_id as i32)) {
            return s;
        }
    }

    // in lots of language packs most strings are simply not present
    // in some cases strings aren't there at all in any language

    // cannot return an error here because its the firmware not following the spec

    debug!("string id: {string_id} not found");

    ""
}

/// find_corresponding_varstore bubble's up from current node till we find a FormSet.
/// then it looks for varstores which will be FormSet's children
fn find_corresponding_varstore(
    node: Rc<RefCell<IFROperation>>,
    var_store_id: u16,
) -> Result<Box<dyn VariableStore>> {
    let current_node = node.borrow();

    if current_node.op_code == IFROpCode::FormSet {
        // look at its children

        for child in &current_node.children {
            match &child.borrow().parsed_data {
                ParsedOperation::VarStore(v) => {
                    if v.var_store_id == var_store_id {
                        return Ok(Box::new(v.clone()));
                    }
                }
                ParsedOperation::VarStoreEfi(v) => {
                    if v.var_store_id == var_store_id {
                        return Ok(Box::new(v.clone()));
                    }
                }
                _ => {}
            }
        }
        return Err(anyhow!("no varstore with matching id found"));
    }

    match current_node.parent.as_ref() {
        Some(parent_ref) => match parent_ref.upgrade() {
            Some(parent_ref_rc) => {
                find_corresponding_varstore(Rc::clone(&parent_ref_rc), var_store_id)
            }
            None => Err(anyhow!("could not upgrade parent_ref Weak<> to get Rc<>")),
        },
        None => Err(anyhow!("varstore not found because we reached root")),
    }
}

/// extract_efi_data extracts data of type T at given offset from efivar bytes.
/// The <T> type here is used to get the type (and thus size) of our answer.
fn extract_efi_data<T>(offset: u16, bytes: &Vec<u8>) -> Result<T>
where
    T: BinRead,
    for<'a> <T as BinRead>::Args<'a>: Default,
{
    // first 4 bytes are flags provided by the kernel so ignore them
    // values begin after that

    let mut cursor = Cursor::new(&bytes);
    cursor.seek(SeekFrom::Current(4 + offset as i64))?;

    let answer: T = cursor.read_ne()?;

    Ok(answer)
}
