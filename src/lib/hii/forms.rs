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
use std::env::var;
use std::fmt;
use std::fmt::format;
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
use log::debug;
use log::error;
use thiserror::Error;

use crate::chattr::EfivarsImmutabilityGuard;
use crate::file_lock::FileLock;
use crate::hii::efivarfs::EfivarsMountGuard;
use crate::hii::package::Guid;

const DUMMY_OPCODE: u8 = 0xFFu8; // doesn't correspond to any known IFROpCode
const EFIVARFS_HEADER_SIZE: usize = std::mem::size_of::<u32>();
const EFI_VARIABLE_RUNTIME_ACCESS: u32 = 0x00000004;

/// IFR_OPERATION_HEADER_SIZE is the size of EFI_IFR_OP_HEADER, which starts
/// every IFR operation (IFROperation): OpCode (8 bits), Length (7 bits) and
/// Scope (1 bit). UEFI Spec v2.10 §33.3.8.2.1 defines Length as "the number of
/// bytes in the opcode, including this header"; §33.3.8.1 gives it as 2-127
/// bytes, so "opcode" is the whole operation, not the OpCode byte (IFROpCode).
///
/// Example: Length includes the header, so an operation carries
/// `length - IFR_OPERATION_HEADER_SIZE` bytes of data.
const IFR_OPERATION_HEADER_SIZE: u8 = 2;

fn read_efivarfs_bytes<R: Read>(reader: &mut R, payload_size: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0u8; EFIVARFS_HEADER_SIZE + payload_size];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn update_efivarfs_bytes(
    bytes: &mut [u8],
    payload_size: u16,
    offset: u16,
    data: TypeValue,
) -> Result<()> {
    let encoded = match data {
        TypeValue::NumSize8(value) => value.to_le_bytes().to_vec(),
        TypeValue::NumSize16(value) => value.to_le_bytes().to_vec(),
        TypeValue::NumSize32(value) => value.to_le_bytes().to_vec(),
        TypeValue::NumSize64(value) => value.to_le_bytes().to_vec(),
        _ => return Err(anyhow!("unsupported value type for efivarfs write")),
    };
    let payload = bytes
        .get_mut(EFIVARFS_HEADER_SIZE..)
        .context("efivarfs file is missing its attributes header")?;
    if payload.len() < usize::from(payload_size) {
        return Err(anyhow!(
            "efivarfs payload is shorter than the declared varstore: {} < {} bytes",
            payload.len(),
            payload_size
        ));
    }

    let start = usize::from(offset);
    let end = start + encoded.len();
    if end > usize::from(payload_size) {
        return Err(anyhow!(
            "write at offset {} with width {} exceeds varstore size {}",
            offset,
            encoded.len(),
            payload_size
        ));
    }
    payload[start..end].copy_from_slice(&encoded);
    Ok(())
}

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
    //
    // the assert below rejects a length below the header size, because binrw
    // computes `count` further down without a bounds check (debug builds panic
    // on underflow, release builds wrap); no upper bound is needed, as a 7-bit
    // length reserves at most 125 bytes
    #[br(assert(
        length >= IFR_OPERATION_HEADER_SIZE,
        "invalid IFR operation length {}",
        length
    ))]
    length: u8, // size of the entire operation, including the header
    #[br(map = |x: u8| x & 0x80 != 0)]
    // read 8 bits, discard all of them except the last one
    pub open_scope: bool,
    #[br(count = length - IFR_OPERATION_HEADER_SIZE)]
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
    VarStoreNameValue(VarStoreNameValue),
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

struct NumericRange {
    minimum: i128,
    maximum: i128,
    bits: u32,
}

impl NumericRange {
    fn from_ifr(range: &Range, flags: u8) -> Self {
        let (minimum, maximum, bits) = match range {
            Range::Range8(range) => (u64::from(range.min_value), u64::from(range.max_value), 8),
            Range::Range16(range) => (u64::from(range.min_value), u64::from(range.max_value), 16),
            Range::Range32(range) => (u64::from(range.min_value), u64::from(range.max_value), 32),
            Range::Range64(range) => (range.min_value, range.max_value, 64),
        };
        let decode = |value: u64| {
            if flags & 0x30 == 0 {
                i128::from(((value << (64 - bits)) as i64) >> (64 - bits))
            } else {
                i128::from(value)
            }
        };
        Self {
            minimum: decode(minimum),
            maximum: decode(maximum),
            bits,
        }
    }

    fn parse_value(&self, value: &str) -> Result<TypeValue, ChangeValueError> {
        if self.minimum > self.maximum {
            return Err(ChangeValueError::InvalidNumericRange);
        }
        let value = value
            .parse::<i128>()
            .context("value should be a decimal integer")?;
        if value < self.minimum {
            return Err(ChangeValueError::BelowMinValue);
        }
        if value > self.maximum {
            return Err(ChangeValueError::ExceededMaxValue);
        }
        match self.bits {
            8 => Ok(TypeValue::NumSize8(value as u8)),
            16 => Ok(TypeValue::NumSize16(value as u16)),
            32 => Ok(TypeValue::NumSize32(value as u32)),
            64 => Ok(TypeValue::NumSize64(value as u64)),
            _ => Err(ChangeValueError::InvalidNumericRange),
        }
    }
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
    fn kind(&self) -> VariableStoreKind;
    fn is_runtime_accessible(&self) -> bool;

    fn store_filename(&self) -> String {
        format!(
            "/sys/firmware/efi/efivars/{}-{}",
            &self.name(),
            &self.guid().to_ascii_lowercase()
        )
    }

    /// extract raw bytes from UEFI using the /sys virtual filesystem
    fn read_bytes(&self) -> Result<Vec<u8>> {
        if self.kind() == VariableStoreKind::EfiVariable && !self.is_runtime_accessible() {
            return Err(anyhow!(
                "EFI variable is boot-service-only and is not readable from efivarfs"
            ));
        }

        // try to read data from varstore
        let mut file = File::open(&self.store_filename()).context(format!(
            "failed to open sysfs efivars '{}' to get varstore bytes",
            self.store_filename()
        ))?;
        debug!("buffer size: {}", self.size());
        // efivarfs prepends a 4-byte attributes field to the variable payload.
        let buf = read_efivarfs_bytes(&mut file, self.size().into()).context(format!(
            "failed to read bytes from sysfs efivars '{}' of size specified by varstore in hiidb",
            self.store_filename()
        ))?;
        Ok(buf)
    }

    fn write_at_offset(&self, offset: u16, data: TypeValue) -> Result<()> {
        if self.kind() == VariableStoreKind::EfiVariable && !self.is_runtime_accessible() {
            return Err(anyhow!(
                "EFI variable is boot-service-only and cannot be written through efivarfs"
            ));
        }

        self.write_efivarfs_at_offset(offset, data)
    }

    fn write_efivarfs_at_offset(&self, offset: u16, data: TypeValue) -> Result<()> {
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
            .context(format!("Failed to open efivarfs file '{}' to get varstore bytes", store_filename))?;

        let mut file_contents = Vec::new();
        file_ro
            .read_to_end(&mut file_contents)
            .context(format!("Failed to read efivarfs file '{}'", store_filename))?;

        update_efivarfs_bytes(&mut file_contents, self.size(), offset, data)?;

        let _efifs = EfivarsMountGuard::new().context("Failed to create efivars fs mount guard")?;

        // Needed on kernel 4.6+ to make EFI vars the kernel doesn't know how to
        // validate temporarily writable.
        let _immutability_attribute_guard = EfivarsImmutabilityGuard::new(&store_filename)
            .context("failed to create immutability attribute guard")?;

        // All checks passed, now we can try to write.
        debug!("Writing value to {}", &store_filename);
        File::create(&store_filename)
            .context("Failed to open efivarfs file for writing")?
            .write_all(&file_contents)
            .context("Failed to write to efivarfs file")?;

        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum VariableStoreKind {
    Buffer,
    EfiVariable,
}

#[cfg(test)]
mod non_efi_varstore_tests {
    use super::*;

    struct TestVariableStore {
        kind: VariableStoreKind,
    }

    struct FileBackedBufferVarStore {
        path: String,
        size: u16,
    }

    impl VariableStore for TestVariableStore {
        fn name(&self) -> String {
            "TestVarStore".to_string()
        }

        fn guid(&self) -> String {
            "00000000-0000-0000-0000-000000000000".to_string()
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

        fn read_bytes(&self) -> Result<Vec<u8>> {
            Err(anyhow!("simulated efivarfs read failure"))
        }

        fn write_efivarfs_at_offset(&self, _offset: u16, _data: TypeValue) -> Result<()> {
            Ok(())
        }
    }

    impl VariableStore for FileBackedBufferVarStore {
        fn name(&self) -> String {
            "TestBufferVarStore".to_string()
        }

        fn guid(&self) -> String {
            "00000000-0000-0000-0000-000000000000".to_string()
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

        fn store_filename(&self) -> String {
            self.path.clone()
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

    #[test]
    fn boot_service_only_varstore_is_reported_as_unavailable() {
        for attributes in [0x2, 0x3] {
            let varstore: Result<Box<dyn VariableStore>> = Ok(Box::new(efi_varstore(attributes)));

            assert_eq!(
                read_current_value_bytes(&varstore).unwrap_err(),
                "<ValueUnavailable: EFI variable is boot-service-only (no EFI_VARIABLE_RUNTIME_ACCESS)>"
            );
        }
    }

    #[test]
    fn boot_service_only_varstore_read_is_rejected() {
        for attributes in [0x2, 0x3] {
            assert_eq!(
                efi_varstore(attributes).read_bytes().unwrap_err().to_string(),
                "EFI variable is boot-service-only and is not readable from efivarfs"
            );
        }
    }

    #[test]
    fn boot_service_only_varstore_write_is_rejected() {
        for attributes in [0x2, 0x3] {
            assert_eq!(
                efi_varstore(attributes)
                    .write_at_offset(0, TypeValue::NumSize8(1))
                    .unwrap_err()
                    .to_string(),
                "EFI variable is boot-service-only and cannot be written through efivarfs"
            );
        }
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
    fn runtime_varstore_read_failure_remains_an_error() {
        let varstore: Result<Box<dyn VariableStore>> = Ok(Box::new(TestVariableStore {
            kind: VariableStoreKind::EfiVariable,
        }));

        assert_eq!(
            read_current_value_bytes(&varstore).unwrap_err(),
            "<VStoreError: simulated efivarfs read failure>"
        );
    }

    #[test]
    fn buffer_varstore_with_efivarfs_backing_is_read() {
        let bytes = vec![0x07, 0x00, 0x00, 0x00, 0x01];
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(&bytes).unwrap();
        let varstore: Result<Box<dyn VariableStore>> = Ok(Box::new(FileBackedBufferVarStore {
            path: file.path().to_string_lossy().into_owned(),
            size: 1,
        }));

        assert_eq!(read_current_value_bytes(&varstore).unwrap(), bytes);
    }

    #[test]
    fn buffer_varstore_without_efivarfs_backing_is_unavailable() {
        let directory = tempfile::tempdir().unwrap();
        let varstore: Result<Box<dyn VariableStore>> = Ok(Box::new(FileBackedBufferVarStore {
            path: directory
                .path()
                .join("missing-efivarfs-variable")
                .to_string_lossy()
                .into_owned(),
            size: 1,
        }));

        assert_eq!(
            read_current_value_bytes(&varstore).unwrap_err(),
            "<ValueUnavailable: HII buffer varstore requires EFI_HII_CONFIG_ACCESS_PROTOCOL>"
        );
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
            }],
            header: QuestionHeader {
                prompt_string_id: 0,
                help_string_id: 0,
                question_id: 0,
                var_store_id: 1,
                var_store_info: 0,
                question_flags: 0,
            },
            varstore: Some(Box::new(TestVariableStore {
                kind: VariableStoreKind::Buffer,
            })),
        };

        assert!(change_value(&question, "Enabled").unwrap());
    }
}

fn is_not_found(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .map(|io_error| io_error.kind() == std::io::ErrorKind::NotFound)
            .unwrap_or(false)
    })
}

fn read_current_value_bytes(
    varstore: &Result<Box<dyn VariableStore>>,
) -> std::result::Result<Vec<u8>, String> {
    match varstore {
        Err(error) => Err(format!("<ValueUnavailable: {}>", error)),
        Ok(varstore) => {
            if varstore.kind() == VariableStoreKind::EfiVariable
                && !varstore.is_runtime_accessible()
            {
                return Err(
                    "<ValueUnavailable: EFI variable is boot-service-only (no EFI_VARIABLE_RUNTIME_ACCESS)>"
                        .to_string(),
                );
            }

            match varstore.read_bytes() {
                Ok(bytes) => Ok(bytes),
                Err(error)
                    if varstore.kind() == VariableStoreKind::Buffer && is_not_found(&error) =>
                {
                    Err(
                        "<ValueUnavailable: HII buffer varstore requires EFI_HII_CONFIG_ACCESS_PROTOCOL>"
                            .to_string(),
                    )
                }
                Err(error) => Err(format!("<VStoreError: {}>", error)),
            }
        }
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
    fn guid(&self) -> String {
        self.guid.to_string()
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
    fn guid(&self) -> String {
        self.guid.to_string()
    }
    fn size(&self) -> u16 {
        self.size
    }
    fn kind(&self) -> VariableStoreKind {
        VariableStoreKind::EfiVariable
    }
    fn is_runtime_accessible(&self) -> bool {
        (self.attributes & EFI_VARIABLE_RUNTIME_ACCESS) != 0
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
        IFROpCode::VarStoreNameValue => {
            let parsed: VarStoreNameValue = data_cursor
                .read_ne()
                .context("Failed to parse VarStoreNameValue's data")?;
            debug!("VarStoreNameValue is {:?}", parsed);
            node.parsed_data = ParsedOperation::VarStoreNameValue(parsed);
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
    numeric_range: Option<NumericRange>,
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
    match read_current_value_bytes(&varstore) {
        Err(reason) => answer.push_str(&reason),
        Ok(bytes) => {
            // for a checkbox size should be of type u8
            let answer_raw: Result<u8> =
                extract_efi_data::<u8>(parsed.question_header().var_store_info, &bytes);
            match answer_raw {
                Ok(a) => answer.push_str(format!("{a}").as_str()),
                Err(e) => answer.push_str(format!("ExtractEFIDataError: {}", e).as_str()),
            }
        }
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
        numeric_range: None,
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
    let mut chosen_value: u64 = u64::MAX;
    let mut varstore_not_found = false;
    match read_current_value_bytes(&varstore) {
        Err(reason) => {
            answer.push_str(&reason);
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
    }

    if chosen_value == u64::MAX {
        // No answer was provided, so using the default value instead.
        for child in &node.borrow().children {
            match &child.borrow().parsed_data {
                ParsedOperation::IFRDefault(o) => {
                    chosen_value = u64::from(o.default_id);
                }
                _ => {}
            }
        }
    }

    let mut possible_options = Vec::new();
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

                if !varstore_not_found && current_value == chosen_value && !found_option {
                    found_option = true;
                    answer.push_str(opt.value.trim());
                    // cannot break here because we want to add all options to possible_options
                }

                possible_options.push(opt);
            }
            _ => {}
        }
    }
	if answer.is_empty() {
		answer.push_str("Unknown");
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
        numeric_range: None,
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

    match read_current_value_bytes(&varstore) {
        Err(reason) => answer.push_str(&reason),
        Ok(bytes) => match (&parsed.data, parsed.flags & 0x30 == 0) {
            (Range::Range8(_), true) => {
                try_read_answer_as_string::<i8>(&parsed.question_header(), &bytes, &mut answer)
            }
            (Range::Range16(_), true) => {
                try_read_answer_as_string::<i16>(&parsed.question_header(), &bytes, &mut answer)
            }
            (Range::Range32(_), true) => {
                try_read_answer_as_string::<i32>(&parsed.question_header(), &bytes, &mut answer)
            }
            (Range::Range64(_), true) => {
                try_read_answer_as_string::<i64>(&parsed.question_header(), &bytes, &mut answer)
            }
            (Range::Range8(_), false) => {
                try_read_answer_as_string::<u8>(&parsed.question_header(), &bytes, &mut answer)
            }
            (Range::Range16(_), false) => {
                try_read_answer_as_string::<u16>(&parsed.question_header(), &bytes, &mut answer)
            }
            (Range::Range32(_), false) => {
                try_read_answer_as_string::<u32>(&parsed.question_header(), &bytes, &mut answer)
            }
            (Range::Range64(_), false) => {
                try_read_answer_as_string::<u64>(&parsed.question_header(), &bytes, &mut answer)
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
        max_value: match &parsed.data {
            Range::Range8(r) => RangeType::NumSize8(r.max_value),
            Range::Range16(r) => RangeType::NumSize16(r.max_value),
            Range::Range32(r) => RangeType::NumSize32(r.max_value),
            Range::Range64(r) => RangeType::NumSize64(r.max_value),
        },
        numeric_range: Some(NumericRange::from_ifr(&parsed.data, parsed.flags)),
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
    let offset = question_header.var_store_info;
    let extracted_data: Result<T> = extract_efi_data(offset, bytes);
    match extracted_data {
        Ok(a) => ans.push_str(format!("{a}").as_str()),
        Err(e) => ans.push_str(format!("<ExtractEFIDataError: {} (offset: {}; buflen: {})>", e, offset, bytes.len()).as_str())
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
        ParsedOperation::VarStoreNameValue(parsed) => result.push_str(
            format!(
                "{extra_spaces}OpCode: {:?} - Id: {} - Guid: {}\n",
                current_node.op_code, parsed.var_store_id, parsed.guid,
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
                Err(e) => {
                    answer_disp.push_str(format!("<VarStoreError: {}>", e).as_str());
                }
                Ok(vstore) => match vstore.read_bytes() {
                    Err(e) => {
                        answer_disp.push_str(format!("<VStoreError: {}>", e).as_str());
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
                    Err(e) => {
						answer_disp.push_str(format!("<VarStoreError: {}>", e).as_str());
                    }
                    Ok(vstore) => match vstore.read_bytes() {
                        Err(e) => {
							answer_disp.push_str(format!("<VStoreError: {}>", e).as_str());
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
                    Err(e) => {
						answer_disp.push_str(format!("<VarStoreError: {}>", e).as_str());
                    }
                    Ok(vstore) => match vstore.read_bytes() {
                        Err(e) => {
							answer_disp.push_str(format!("<VStoreError: {}>", e).as_str());
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
    #[error("provided value is below the minimum possible value")]
    BelowMinValue,
    #[error("numeric question has an invalid range")]
    InvalidNumericRange,
    #[error("question '{0}' has no supported writable varstore")]
    NoWritableVarStore(String),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub fn change_value(
    question: &QuestionDescriptor,
    new_value: &str,
) -> Result<bool, ChangeValueError> {
    if question.varstore.is_none() {
        return Err(ChangeValueError::NoWritableVarStore(
            question.question.clone(),
        ));
    }

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
        } else if let Some(range) = &question.numeric_range {
            let data = range.parse_value(new_value)?;
            varstore.write_at_offset(question.header.var_store_info, data)?;
            changed = true;
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
    if var_store_id == 0 {
        return Err(anyhow!(
            "question is callback-driven or temporary and has no varstore"
        ));
    }

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
                ParsedOperation::VarStoreNameValue(v) => {
                    if v.var_store_id == var_store_id {
                        return Err(anyhow!(
                            "HII name/value varstore requires EFI_HII_CONFIG_ACCESS_PROTOCOL"
                        ));
                    }
                }
                _ => {}
            }
        }
        return Err(anyhow!(
            "no supported varstore with matching id {:#06x} found",
            var_store_id
        ));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn variable_bytes(payload_size: usize) -> Vec<u8> {
        let mut bytes = 7u32.to_le_bytes().to_vec();
        bytes.extend(vec![0xa5; payload_size]);
        bytes
    }

    #[test]
    fn writes_each_integer_width_at_end_of_varstore() {
        for (data, encoded) in [
            (TypeValue::NumSize8(95), 95u8.to_le_bytes().to_vec()),
            (TypeValue::NumSize16(259), 259u16.to_le_bytes().to_vec()),
            (
                TypeValue::NumSize32(123456),
                123456u32.to_le_bytes().to_vec(),
            ),
            (
                TypeValue::NumSize64(u64::MAX),
                u64::MAX.to_le_bytes().to_vec(),
            ),
        ] {
            let mut bytes = variable_bytes(42);
            let mut expected = bytes.clone();
            let offset = 42 - encoded.len();
            expected[EFIVARFS_HEADER_SIZE + offset..].copy_from_slice(&encoded);
            update_efivarfs_bytes(&mut bytes, 42, offset as u16, data).unwrap();
            assert_eq!(bytes, expected);
        }
    }

    #[test]
    fn trailing_thermal_fields_do_not_overlap() {
        let mut bytes = variable_bytes(42);
        update_efivarfs_bytes(&mut bytes, 42, 38, TypeValue::NumSize16(95)).unwrap();
        update_efivarfs_bytes(&mut bytes, 42, 40, TypeValue::NumSize16(90)).unwrap();
        assert_eq!(extract_efi_data::<u16>(38, &bytes).unwrap(), 95);
        assert_eq!(extract_efi_data::<u16>(40, &bytes).unwrap(), 90);
        assert_eq!(&bytes[..4], &7u32.to_le_bytes());
    }

    #[test]
    fn rejects_writes_past_declared_size_without_changing_bytes() {
        for (size, offset, data) in [
            (42, 42, TypeValue::NumSize8(1)),
            (42, 41, TypeValue::NumSize16(1)),
            (42, 39, TypeValue::NumSize32(1)),
            (42, 35, TypeValue::NumSize64(1)),
            (0, 0, TypeValue::NumSize8(1)),
            (42, u16::MAX, TypeValue::NumSize64(1)),
        ] {
            let mut bytes = variable_bytes(64);
            let original = bytes.clone();
            assert!(update_efivarfs_bytes(&mut bytes, size, offset, data).is_err());
            assert_eq!(bytes, original);
        }
    }

    #[test]
    fn rejects_short_payload_even_when_requested_field_fits() {
        for offset in [0, 40] {
            let mut bytes = variable_bytes(39);
            let original = bytes.clone();
            assert!(
                update_efivarfs_bytes(&mut bytes, 42, offset, TypeValue::NumSize16(1)).is_err()
            );
            assert_eq!(bytes, original);
        }
    }

    #[test]
    fn rejects_incomplete_attributes_header() {
        for length in 0..EFIVARFS_HEADER_SIZE {
            let mut bytes = vec![0xa5; length];
            let original = bytes.clone();
            assert!(update_efivarfs_bytes(&mut bytes, 1, 0, TypeValue::NumSize8(1)).is_err());
            assert_eq!(bytes, original);
        }
    }

    #[test]
    fn preserves_bytes_beyond_declared_varstore() {
        let mut bytes = variable_bytes(50);
        let original = bytes.clone();
        update_efivarfs_bytes(&mut bytes, 42, 40, TypeValue::NumSize16(95)).unwrap();
        assert_eq!(&bytes[46..], &original[46..]);
        assert_eq!(&bytes[..44], &original[..44]);
        assert_eq!(bytes.len(), original.len());
    }

    #[test]
    fn writes_small_and_maximum_sized_varstores() {
        for size in [1, 2, u16::MAX] {
            let mut bytes = variable_bytes(usize::from(size));
            update_efivarfs_bytes(&mut bytes, size, size - 1, TypeValue::NumSize8(95)).unwrap();
            assert_eq!(bytes.len(), EFIVARFS_HEADER_SIZE + usize::from(size));
            assert_eq!(bytes.last(), Some(&95));
        }
    }

    #[test]
    fn rejects_unsupported_value_instead_of_silent_noop() {
        let mut bytes = variable_bytes(42);
        let original = bytes.clone();
        assert!(update_efivarfs_bytes(&mut bytes, 42, 0, TypeValue::Boolean(true)).is_err());
        assert_eq!(bytes, original);
    }

    #[test]
    fn read_efivarfs_bytes_includes_attributes_and_complete_payload() {
        let payload = 95u16.to_le_bytes();
        let mut efivarfs_data = 7u32.to_le_bytes().to_vec();
        efivarfs_data.extend_from_slice(&payload);

        let mut reader = Cursor::new(&efivarfs_data);
        let bytes = read_efivarfs_bytes(&mut reader, payload.len()).unwrap();

        assert_eq!(bytes, efivarfs_data);
        assert_eq!(extract_efi_data::<u16>(0, &bytes).unwrap(), 95);
    }

    /// An IFR operation Length below the header size is rejected as an
    /// invalid length before binrw computes the size of the operation's data
    /// from it.
    #[test]
    fn operation_length_below_header_size_is_an_error() {
        for length in [0, IFR_OPERATION_HEADER_SIZE - 1] {
            let data = vec![0x0E, length]; // FormSet
            let mut cursor = Cursor::new(&data);

            let err = format!("{:#}", handle_form_package(&mut cursor).unwrap_err());

            let want = format!("invalid IFR operation length {} at 0x", length);
            assert!(err.contains(&want), "length {}: {}", length, err);
        }
    }

    /// An IFR operation of Length 0 is an error even when 254 bytes (what a
    /// wrapped `length - IFR_OPERATION_HEADER_SIZE` would read) and an End
    /// operation follow it.
    #[test]
    fn operation_length_zero_before_254_bytes_and_end_is_an_error() {
        let wrapped_count = 0u8.wrapping_sub(IFR_OPERATION_HEADER_SIZE);
        let data = [
            &[0x0E, 0x00][..],                       // FormSet: Length 0
            &vec![0x00; usize::from(wrapped_count)], // 254 bytes
            &[0x29, IFR_OPERATION_HEADER_SIZE],      // End
        ]
        .concat();
        let mut cursor = Cursor::new(&data);

        let err = format!("{:#}", handle_form_package(&mut cursor).unwrap_err());

        let want = "invalid IFR operation length 0 at 0x";
        assert!(err.contains(want), "{}", err);
    }

    /// An IFR operation of exactly the header size, like End, is parsed.
    #[test]
    fn operation_of_header_size_is_parsed() {
        let form_set_data = [
            &[0x11; 16][..],           // Guid
            &[0x01, 0x00, 0x02, 0x00], // FormSetTitle, Help
            &[0x01],                   // Flags: one ClassGuid
            &[0x22; 16],               // ClassGuid
        ]
        .concat();
        let form_set_length =
            IFR_OPERATION_HEADER_SIZE + u8::try_from(form_set_data.len()).unwrap();
        let data = [
            &[0x0E, 0x80 | form_set_length][..], // FormSet: Length, Scope
            &form_set_data,
            &[0x29, IFR_OPERATION_HEADER_SIZE], // End
        ]
        .concat();
        let mut cursor = Cursor::new(&data);

        let root = handle_form_package(&mut cursor).unwrap();

        let root = root.borrow();
        assert_eq!(root.children.len(), 1);
        let form_set = root.children[0].borrow();
        assert_eq!(form_set.op_code, IFROpCode::FormSet);
        assert!(form_set.children.is_empty());
    }

    fn question_without_varstore(opcode: IFROpCode) -> QuestionDescriptor {
        QuestionDescriptor {
            question: "Unsupported question".to_string(),
            help: String::new(),
            value: String::new(),
            max_value: RangeType::NumSize8(1),
            numeric_range: None,
            opcode,
            possible_options: vec![AnswerOption {
                value: "Enabled".to_string(),
                raw_value: TypeValue::NumSize8(1),
            }],
            header: QuestionHeader {
                prompt_string_id: 0,
                help_string_id: 0,
                question_id: 1,
                var_store_id: 0,
                var_store_info: 0,
                question_flags: 0,
            },
            varstore: None,
        }
    }

    #[test]
    fn rejects_numeric_question_without_writable_storage() {
        let question = question_without_varstore(IFROpCode::Numeric);

        assert!(matches!(
            change_value(&question, "1"),
            Err(ChangeValueError::NoWritableVarStore(name))
                if name == "Unsupported question"
        ));
    }

    #[test]
    fn rejects_oneof_question_without_writable_storage() {
        let question = question_without_varstore(IFROpCode::OneOf);

        assert!(matches!(
            change_value(&question, "Enabled"),
            Err(ChangeValueError::NoWritableVarStore(_))
        ));
    }
}

#[cfg(test)]
mod write_validation_tests {
    use super::*;

    type RecordedWrites = Rc<RefCell<Vec<(u16, TypeValue)>>>;

    struct RecordingVarStore {
        bytes: Vec<u8>,
        writes: RecordedWrites,
    }

    impl VariableStore for RecordingVarStore {
        fn name(&self) -> String {
            "NumericTest".to_string()
        }

        fn guid(&self) -> String {
            "00000000-0000-0000-0000-000000000000".to_string()
        }

        fn size(&self) -> u16 {
            42
        }

        fn kind(&self) -> VariableStoreKind {
            VariableStoreKind::Buffer
        }

        fn is_runtime_accessible(&self) -> bool {
            false
        }

        fn read_bytes(&self) -> Result<Vec<u8>> {
            Ok(self.bytes.clone())
        }

        fn write_efivarfs_at_offset(&self, offset: u16, data: TypeValue) -> Result<()> {
            self.writes.borrow_mut().push((offset, data));
            Ok(())
        }
    }

    fn numeric_question(
        bits: u32,
        minimum: u64,
        maximum: u64,
        step: u64,
        display: u8,
        initial: u64,
    ) -> (QuestionDescriptor, RecordedWrites) {
        let (width_code, range) = match bits {
            8 => (
                0,
                Range::Range8(Range8 {
                    min_value: minimum as u8,
                    max_value: maximum as u8,
                    step: step as u8,
                }),
            ),
            16 => (
                1,
                Range::Range16(Range16 {
                    min_value: minimum as u16,
                    max_value: maximum as u16,
                    step: step as u16,
                }),
            ),
            32 => (
                2,
                Range::Range32(Range32 {
                    min_value: minimum as u32,
                    max_value: maximum as u32,
                    step: step as u32,
                }),
            ),
            64 => (
                3,
                Range::Range64(Range64 {
                    min_value: minimum,
                    max_value: maximum,
                    step,
                }),
            ),
            _ => panic!("invalid test width"),
        };
        let parsed = Numeric {
            question_header: QuestionHeader {
                prompt_string_id: 0,
                help_string_id: 0,
                question_id: 1,
                var_store_id: 1,
                var_store_info: 2,
                question_flags: 0,
            },
            flags: width_code | display,
            data: range,
        };
        let node = RefCell::new(IFROperation {
            op_code: IFROpCode::Numeric,
            length: 0,
            open_scope: false,
            data: Vec::new(),
            parent: None,
            children: Vec::new(),
            parsed_data: ParsedOperation::Placeholder,
        });
        let mut bytes = vec![0; EFIVARFS_HEADER_SIZE + 42];
        bytes[..EFIVARFS_HEADER_SIZE].copy_from_slice(&7u32.to_le_bytes());
        let width = (bits / 8) as usize;
        bytes[6..6 + width].copy_from_slice(&initial.to_le_bytes()[..width]);
        let writes = Rc::new(RefCell::new(Vec::new()));
        let store = RecordingVarStore {
            bytes,
            writes: Rc::clone(&writes),
        };
        let question = handle_numeric(
            Ok(Box::new(store)),
            &parsed,
            "Numeric test",
            &Vec::new(),
            &node.borrow(),
        );
        (question, writes)
    }

    fn encoded_value(bits: u32, value: i128) -> TypeValue {
        match bits {
            8 => TypeValue::NumSize8(value as u8),
            16 => TypeValue::NumSize16(value as u16),
            32 => TypeValue::NumSize32(value as u32),
            64 => TypeValue::NumSize64(value as u64),
            _ => panic!("invalid test width"),
        }
    }

    #[test]
    fn rejects_unsigned_out_of_range_values_before_writing() {
        for bits in [8, 16, 32, 64] {
            let (question, writes) = numeric_question(bits, 10, 20, 2, 0x10, 10);
            assert!(matches!(
                change_value(&question, "9"),
                Err(ChangeValueError::BelowMinValue)
            ));
            assert!(matches!(
                change_value(&question, "21"),
                Err(ChangeValueError::ExceededMaxValue)
            ));
            for value in [
                "-1",
                "not-a-number",
                "340282366920938463463374607431768211455",
            ] {
                assert!(change_value(&question, value).is_err());
            }
            assert!(writes.borrow().is_empty());
        }
    }

    #[test]
    fn accepts_unsigned_boundaries_and_does_not_treat_step_as_a_constraint() {
        for bits in [8, 16, 32, 64] {
            for step in [0, 2] {
                for display in [0x10, 0x20] {
                    let (question, writes) = numeric_question(bits, 10, 20, step, display, 10);
                    for value in [10, 11, 20] {
                        assert!(change_value(&question, &value.to_string()).unwrap());
                    }
                    assert_eq!(
                        *writes.borrow(),
                        vec![
                            (2, encoded_value(bits, 10)),
                            (2, encoded_value(bits, 11)),
                            (2, encoded_value(bits, 20)),
                        ]
                    );
                }
            }
        }
    }

    #[test]
    fn validates_signed_bounds_and_encodes_negative_values() {
        for bits in [8, 16, 32, 64] {
            let (question, writes) =
                numeric_question(bits, (-10i64) as u64, 10, 1, 0, (-3i64) as u64);
            assert_eq!(question.value, "-3");
            assert!(matches!(
                change_value(&question, "-11"),
                Err(ChangeValueError::BelowMinValue)
            ));
            assert!(matches!(
                change_value(&question, "11"),
                Err(ChangeValueError::ExceededMaxValue)
            ));
            assert!(writes.borrow().is_empty());
            for value in [-10, 0, 10] {
                assert!(change_value(&question, &value.to_string()).unwrap());
            }
            assert_eq!(
                *writes.borrow(),
                vec![
                    (2, encoded_value(bits, -10)),
                    (2, encoded_value(bits, 0)),
                    (2, encoded_value(bits, 10)),
                ]
            );
        }
    }

    #[test]
    fn supports_full_signed_range_at_each_width() {
        for bits in [8, 16, 32, 64] {
            let minimum = -(1i128 << (bits - 1));
            let maximum = (1i128 << (bits - 1)) - 1;
            let (question, writes) =
                numeric_question(bits, minimum as u64, maximum as u64, 1, 0, 0);
            assert!(change_value(&question, &minimum.to_string()).unwrap());
            assert!(change_value(&question, &maximum.to_string()).unwrap());
            assert!(change_value(&question, &(minimum - 1).to_string()).is_err());
            assert!(change_value(&question, &(maximum + 1).to_string()).is_err());
            assert_eq!(writes.borrow().len(), 2);
        }
    }

    #[test]
    fn supports_unsigned_64_bit_values_above_signed_maximum() {
        let (question, writes) = numeric_question(64, u64::MAX - 2, u64::MAX, 1, 0x10, u64::MAX);
        assert_eq!(question.value, u64::MAX.to_string());
        assert!(change_value(&question, &u64::MAX.to_string()).unwrap());
        assert_eq!(*writes.borrow(), vec![(2, TypeValue::NumSize64(u64::MAX))]);
        assert!(change_value(&question, "18446744073709551616").is_err());
        assert_eq!(writes.borrow().len(), 1);
    }

    #[test]
    fn rejects_invalid_numeric_ranges_without_writing() {
        for bits in [8, 16, 32, 64] {
            let (question, writes) = numeric_question(bits, 20, 10, 1, 0x10, 0);
            assert!(matches!(
                change_value(&question, "15"),
                Err(ChangeValueError::InvalidNumericRange)
            ));
            assert!(writes.borrow().is_empty());
        }
    }
}
