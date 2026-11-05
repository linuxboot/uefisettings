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
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::convert::Infallible;
use std::fmt;
use std::io::Read;
use std::io::Seek;
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
use log::warn;
use thiserror::Error;

use crate::hii::package::Guid;
use crate::hii::variables::check_decodable;
use crate::hii::variables::check_non_volatile;
use crate::hii::variables::check_runtime_writable;
use crate::hii::variables::check_unauthenticated;
use crate::hii::variables::efivar_attributes;
use crate::hii::variables::EfivarRange;
use crate::hii::variables::EfivarReader;
use crate::hii::variables::EfivarsNotRead;
use crate::hii::variables::EnhancedAuthenticatedVariable;
use crate::hii::variables::FirmwareVariables;
use crate::hii::variables::VariableInterface;
use crate::hii::variables::VariableKey;
use crate::hii::variables::VariableNotFound;
use crate::hii::variables::VariableReach;
use crate::hii::variables::WithheldVariable;
use crate::hii::variables::WithholdingVariables;
use crate::hii::variables::EFIVARFS_HEADER_SIZE;
use crate::hii::variables::EFI_VARIABLE_RUNTIME_ACCESS;
use conditions::option_state;
use conditions::question_state;
use conditions::select;
use conditions::skips_scope;
use conditions::ExpressionInputs;
use conditions::QuestionValues;
use conditions::VarStoreValues;
use defaults::option_text;
use defaults::push_default;
use defaults::question_scope;
use defaults::FormSetDefaultIds;

pub use ami_access_level::AccessLevel;
pub use conditions::IncludedStates;
pub use conditions::QuestionState;
pub use conditions::SelectionError;
pub use setup_password::SetupPasswordPolicy;

pub(crate) use ami_access_level::check_access_level;
pub(crate) use conditions::Choice;
pub(crate) use conditions::Selection;
pub(crate) use conditions::StateEvaluation;
pub(crate) use defaults::DefaultId;
pub(crate) use setup_password::PasswordQuestions;

mod ami_access_level;
mod conditions;
mod defaults;
#[cfg(test)]
pub(crate) mod ifr_fixtures;
mod setup_password;

const DUMMY_OPCODE: u8 = 0xFFu8; // doesn't correspond to any known IFROpCode
/// How DeclaredBootServiceOnly names a form's declaration without EFI_VARIABLE_RUNTIME_ACCESS.
const DECLARED_BOOT_SERVICE_ONLY: &str = "boot-service-only (no EFI_VARIABLE_RUNTIME_ACCESS)";
// UEFI 2.10 §33.3.8.3.47
const EFI_IFR_NUMERIC_SIZE: u8 = 0x03;
const EFI_IFR_NUMERIC_SIZE_1: u8 = 0x00;
const EFI_IFR_NUMERIC_SIZE_2: u8 = 0x01;
const EFI_IFR_NUMERIC_SIZE_4: u8 = 0x02;
const EFI_IFR_DISPLAY: u8 = 0x30;
const EFI_IFR_DISPLAY_INT_DEC: u8 = 0x00;
// UEFI 2.10 §33.3.8.3.51
const EFI_IFR_TYPE_NUM_SIZE_8: u8 = 0x00;
const EFI_IFR_TYPE_NUM_SIZE_16: u8 = 0x01;
const EFI_IFR_TYPE_NUM_SIZE_32: u8 = 0x02;
const EFI_IFR_TYPE_NUM_SIZE_64: u8 = 0x03;
const EFI_IFR_TYPE_BOOLEAN: u8 = 0x04;
const EFI_IFR_TYPE_OTHER: u8 = 0x08;
// edk2-stable202608 MdeModulePkg/Include/Guid/MdeModuleHii.h; the GUID is
// 82DDD68B-9163-4187-9B27-20A8FD60A71D, here in its EFI_GUID byte order
const EDKII_IFR_BIT_VARSTORE_GUID: [u8; 16] = [
    0x8B, 0xD6, 0xDD, 0x82, 0x63, 0x91, 0x87, 0x41, 0x9B, 0x27, 0x20, 0xA8, 0xFD, 0x60, 0xA7, 0x1D,
];
const EDKII_IFR_DISPLAY_BIT: u8 = 0xC0;
const EDKII_IFR_DISPLAY_INT_DEC_BIT: u8 = 0x00;
const EDKII_IFR_NUMERIC_SIZE_BIT: u8 = 0x3F;
// edk2-stable202608 BaseTools VfrCompile stores bit-field values as UINT32 (VfrSyntax.g) and
// caps their width at MAX_BIT_WIDTH 32 (VfrUtilityLib.h)
const EDKII_BIT_FIELD_VALUE_BITS: u32 = 32;

/// IFR_OPERATION_HEADER_SIZE is the size of EFI_IFR_OP_HEADER, which starts
/// every IFR operation (IFROperation): OpCode (8 bits), Length (7 bits) and
/// Scope (1 bit). UEFI Spec v2.10 §33.3.8.2.1 defines Length as "the number of
/// bytes in the opcode, including this header"; §33.3.8.1 gives it as 2-127
/// bytes, so "opcode" is the whole operation, not the OpCode byte (IFROpCode).
///
/// Example: Length includes the header, so an operation carries
/// `length - IFR_OPERATION_HEADER_SIZE` bytes of data.
const IFR_OPERATION_HEADER_SIZE: u8 = 2;

// UEFI 2.10 §33.3.8.3, Table 33.11 IFR Opcodes
#[derive(BinRead, Debug, PartialEq, Copy, Clone)]
// binrw tries the variants in order; by default it collects every miss's
// error in a Vec that grows up to 100 entries and is dropped per opcode
#[br(little, return_unexpected_error)]
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
    #[br(count = usize::from(length - IFR_OPERATION_HEADER_SIZE))]
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
// It prints what Debug derived for op_code, open_scope, length and children prints, from a stack
// on the heap, as walk_scopes walks.
impl fmt::Debug for IFROperation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        /// What is left to print after the fields of an op `depth` scopes down.
        enum Pending {
            /// An op of its scope, as RefCell prints it; `first` in the scope or not
            Entry {
                op: Rc<RefCell<IFROperation>>,
                depth: usize,
                first: bool,
            },
            /// The end of the RefCell of an op of its scope
            EntryEnd { depth: usize },
            /// The end of its scope and of the op
            End { depth: usize, empty: bool },
        }

        /// Pushes what is left of `op`, `depth` scopes down, after its fields.
        fn push_scope(pending: &mut Vec<Pending>, op: &IFROperation, depth: usize) {
            pending.push(Pending::End {
                depth,
                empty: op.children.is_empty(),
            });
            pending.extend(op.children.iter().enumerate().rev().map(|(index, child)| {
                Pending::Entry {
                    op: Rc::clone(child),
                    depth,
                    first: index == 0,
                }
            }));
        }

        let mut printer = DebugPrinter {
            pretty: f.alternate(),
            f,
        };
        printer.fields(self, 0)?;
        let mut pending = Vec::new();
        push_scope(&mut pending, self, 0);
        while let Some(next) = pending.pop() {
            match next {
                Pending::Entry { op, depth, first } => {
                    printer.entry(depth, first)?;
                    match op.try_borrow() {
                        Ok(op) => {
                            printer.fields(&op, depth + 1)?;
                            pending.push(Pending::EntryEnd { depth });
                            push_scope(&mut pending, &op, depth + 1);
                        }
                        Err(_) => {
                            printer.f.write_str("<borrowed>")?;
                            printer.entry_end(depth)?;
                        }
                    }
                }
                Pending::EntryEnd { depth } => printer.entry_end(depth)?,
                Pending::End { depth, empty } => printer.end(depth, empty)?,
            }
        }
        Ok(())
    }
}

/// Prints ops as Debug derived for IFROperation's op_code, open_scope, length and children would.
struct DebugPrinter<'a, 'b> {
    f: &'a mut fmt::Formatter<'b>,
    pretty: bool,
}

impl DebugPrinter<'_, '_> {
    /// The indentation of `{:#?}` for an op `depth` scopes down: each scope nests a list, a
    /// RefCell and an op, which indent what they hold by 4 spaces each
    fn indent(depth: usize) -> usize {
        12 * depth
    }

    /// Prints `op` up to its children's opening bracket.
    fn fields(&mut self, op: &IFROperation, depth: usize) -> fmt::Result {
        if !self.pretty {
            return write!(
                self.f,
                "IFROperation {{ op_code: {:?}, open_scope: {:?}, length: {:?}, children: [",
                op.op_code, op.open_scope, op.length
            );
        }
        let indent = Self::indent(depth) + 4;
        self.f.write_str("IFROperation {\n")?;
        let fields: [(&str, &dyn fmt::Debug); 3] = [
            ("op_code", &op.op_code),
            ("open_scope", &op.open_scope),
            ("length", &op.length),
        ];
        for (name, value) in fields {
            write!(self.f, "{:indent$}{name}: ", "")?;
            let value = format!("{value:#?}");
            for (index, line) in value.split('\n').enumerate() {
                if index > 0 {
                    write!(self.f, "\n{:indent$}", "")?;
                }
                self.f.write_str(line)?;
            }
            self.f.write_str(",\n")?;
        }
        write!(self.f, "{:indent$}children: [", "")?;
        if !op.children.is_empty() {
            self.f.write_str("\n")?;
        }
        Ok(())
    }

    /// Prints the start of a RefCell of an op in the scope of an op `depth` scopes down.
    fn entry(&mut self, depth: usize, first: bool) -> fmt::Result {
        match (self.pretty, first) {
            (false, true) => self.f.write_str("RefCell { value: "),
            (false, false) => self.f.write_str(", RefCell { value: "),
            (true, _) => {
                let indent = Self::indent(depth) + 8;
                write!(
                    self.f,
                    "{:indent$}RefCell {{\n{:value_indent$}value: ",
                    "",
                    "",
                    value_indent = indent + 4
                )
            }
        }
    }

    /// Prints the end of a RefCell of an op in the scope of an op `depth` scopes down.
    fn entry_end(&mut self, depth: usize) -> fmt::Result {
        match self.pretty {
            false => self.f.write_str(" }"),
            true => {
                let indent = Self::indent(depth) + 8;
                write!(self.f, ",\n{:indent$}}},\n", "")
            }
        }
    }

    /// Prints the end of the children and of an op `depth` scopes down, `empty` if it has no
    /// children.
    fn end(&mut self, depth: usize, empty: bool) -> fmt::Result {
        let indent = Self::indent(depth);
        match (self.pretty, empty) {
            (false, _) => self.f.write_str("] }"),
            (true, true) => write!(self.f, "],\n{:indent$}}}", ""),
            (true, false) => write!(
                self.f,
                "{:field_indent$}],\n{:indent$}}}",
                "",
                "",
                field_indent = indent + 4
            ),
        }
    }
}

// The ops in its scope are dropped from a stack on the heap, as walk_scopes walks, not by the
// recursive drop glue.
impl Drop for IFROperation {
    fn drop(&mut self) {
        let mut ops = std::mem::take(&mut self.children);
        while let Some(op) = ops.pop() {
            // otherwise the op's last Rc drops its scope
            if let Ok(op) = Rc::try_unwrap(op) {
                ops.append(&mut op.into_inner().children);
            }
        }
    }
}

/// What walk_scopes does after it visits an op.
enum Walk<C> {
    /// Visit the ops in the op's scope, each with this context
    Enter(C),
    /// Leave the ops in the op's scope unvisited
    Skip,
}

/// Visits `ops`, each with `context`, then the ops in the scope of each that `visit` enters, in
/// IFR order. The ops left to visit wait on a stack on the heap, not in recursive calls, so that
/// the thread's stack, e.g. the 128 KiB of UEFI DXE (edk2-stable202608
/// MdeModulePkg/Core/DxeIplPeim/DxeIpl.h STACK_SIZE), does not bound how deep scopes nest.
fn try_walk_scopes<C: Clone, E>(
    ops: &[Rc<RefCell<IFROperation>>],
    context: C,
    mut visit: impl FnMut(&Rc<RefCell<IFROperation>>, &C) -> Result<Walk<C>, E>,
) -> Result<(), E> {
    let mut pending: Vec<_> = ops
        .iter()
        .rev()
        .map(|op| (Rc::clone(op), context.clone()))
        .collect();
    while let Some((op, context)) = pending.pop() {
        match visit(&op, &context)? {
            Walk::Enter(inner) => pending.extend(
                op.borrow()
                    .children
                    .iter()
                    .rev()
                    .map(|child| (Rc::clone(child), inner.clone())),
            ),
            Walk::Skip => {}
        }
    }
    Ok(())
}

/// try_walk_scopes with a `visit` that cannot fail.
fn walk_scopes<C: Clone>(
    ops: &[Rc<RefCell<IFROperation>>],
    context: C,
    mut visit: impl FnMut(&Rc<RefCell<IFROperation>>, &C) -> Walk<C>,
) {
    let Ok(()) = try_walk_scopes(ops, context, |op, context| {
        Ok::<_, Infallible>(visit(op, context))
    });
}

/// The most IFR scopes open at once in a FormSet, its own counted. UEFI 2.11 §33.3.8.2.1 sets no
/// limit and edk2-stable202608 SetupBrowserDxe parses any depth, but its count of the scopes in an
/// unknown op (SetupBrowserDxe/IfrParse.c ParseOpCodes UnknownDepth) and HiiDatabaseDxe's of
/// those in a question (HiiDatabaseDxe/HiiDatabase.h IFR_BLOCK_DATA Scope) are UINT8s, which wrap
/// past 255; show-ifr indents each op by its depth.
pub(crate) const MAX_SCOPE_NESTING: usize = 255;

/// A FormSet whose IFR scopes nest deeper than `limit`, from the op at `offset` of its form
/// package on.
#[derive(Debug, Error, PartialEq, Eq)]
#[error("IFR scopes nest deeper than {limit} at offset {offset} of a form package")]
pub(crate) struct ScopesTooDeep {
    pub(crate) offset: u64,
    pub(crate) limit: usize,
}

#[derive(Debug, Default)]
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
    #[expect(dead_code, reason = "decoded IFR payload; nothing reads it yet")]
    Form(Form),
    #[expect(dead_code, reason = "decoded IFR payload; nothing reads it yet")]
    Text(Text),
    Subtitle(Subtitle),
    Numeric(Numeric),
    QuestionRef1(QuestionRef1),
    EqIdVal(EqIdVal),
    EqIdId(EqIdId),
    EqIdValList(EqIdValList),
    #[default]
    Placeholder,
}

// Documentation for subsequent structs at:
// UEFI 2.10 §33.3.8

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
// In UEFI 2.10 §33.3.8.2.2 question header's first field is statement header
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
#[br(little, import(encoding: ValueEncoding))]
pub struct OneOf {
    pub question_header: QuestionHeader,
    pub flags: u8,
    #[br(parse_with = range_parser, args(flags, encoding))]
    pub data: Range,
    #[br(calc = encoding.numeric_location(question_header.var_store_info, flags, &data))]
    location: ValueLocation,
}

impl Question for OneOf {
    fn question_header(&self) -> QuestionHeader {
        self.question_header
    }
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little, import(encoding: ValueEncoding))]
pub struct Numeric {
    pub question_header: QuestionHeader,
    pub flags: u8,
    #[br(parse_with = range_parser, args(flags, encoding))]
    pub data: Range,
    #[br(calc = encoding.numeric_location(question_header.var_store_info, flags, &data))]
    location: ValueLocation,
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

impl Range {
    /// The size in bytes of the value, and of each of MinValue, MaxValue and Step.
    fn size(&self) -> u8 {
        match self {
            Range::Range8(_) => 1,
            Range::Range16(_) => 2,
            Range::Range32(_) => 4,
            Range::Range64(_) => 8,
        }
    }
}

struct NumericRange {
    minimum: i128,
    maximum: i128,
    format: NumericFormat,
}

impl NumericRange {
    fn from_ifr(range: &Range, flags: u8) -> Self {
        let (minimum, maximum) = match range {
            Range::Range8(range) => (u64::from(range.min_value), u64::from(range.max_value)),
            Range::Range16(range) => (u64::from(range.min_value), u64::from(range.max_value)),
            Range::Range32(range) => (u64::from(range.min_value), u64::from(range.max_value)),
            Range::Range64(range) => (range.min_value, range.max_value),
        };
        let format = NumericFormat::from_ifr(range, flags);
        Self {
            minimum: format.decode(minimum),
            maximum: format.decode(maximum),
            format,
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
        let stored = self
            .format
            .encode(value)
            .ok_or(ChangeValueError::InvalidNumericRange)?;
        match self.format.bits {
            8 => Ok(TypeValue::NumSize8(
                u8::try_from(stored).map_err(|_| ChangeValueError::InvalidNumericRange)?,
            )),
            16 => Ok(TypeValue::NumSize16(
                u16::try_from(stored).map_err(|_| ChangeValueError::InvalidNumericRange)?,
            )),
            32 => Ok(TypeValue::NumSize32(
                u32::try_from(stored).map_err(|_| ChangeValueError::InvalidNumericRange)?,
            )),
            64 => Ok(TypeValue::NumSize64(stored)),
            _ => Err(ChangeValueError::InvalidNumericRange),
        }
    }
}

/// The stored width in bits, 1 to 64, of a NUMERIC or ONE_OF value, and, if
/// EFI_IFR_DISPLAY_INT_DEC signs it, the width of its type.
#[derive(Clone, Copy)]
struct NumericFormat {
    bits: u32,
    signed_type_bits: Option<u32>,
}

/// Why the Flags and VarOffset of a NUMERIC or ONE_OF give no value format.
#[derive(Debug, Error)]
enum NumericFormatError {
    #[error("EDKII bit-field width {0}, not 1 to 32")]
    BitFieldWidth(u8),
    #[error("EDKII bit field of width {width} at bit {offset} spans more than 4 bytes")]
    BitFieldSpan { offset: u16, width: u8 },
}

/// Returns `width`, an EDKII bit varstore field's width, in bits if it is 1 to 32.
fn bit_field_bits(width: u8) -> Result<u32, NumericFormatError> {
    let bits = u32::from(width);
    if !(1..=EDKII_BIT_FIELD_VALUE_BITS).contains(&bits) {
        return Err(NumericFormatError::BitFieldWidth(width));
    }
    Ok(bits)
}

impl NumericFormat {
    /// Returns the format that the Range and EFI_IFR_DISPLAY give (UEFI 2.10 §33.3.8.3.47).
    fn from_ifr(range: &Range, flags: u8) -> Self {
        let bits = u32::from(range.size()) * u8::BITS;
        Self {
            bits,
            signed_type_bits: (flags & EFI_IFR_DISPLAY == EFI_IFR_DISPLAY_INT_DEC).then_some(bits),
        }
    }

    /// Returns the format of the value at `location` of a NUMERIC or ONE_OF with `flags` and
    /// `range`. edk2-stable202608 IfrParse.c types an EDKII bit varstore field's value by its
    /// StorageWidth, the bytes its bits span: UINT8, UINT16, or UINT32 for 3 or 4;
    /// ProcessOptions.c signs an INT_DEC value from that type. So an 8-bit field holding 0xFF
    /// shows -1 at bit 0, in UINT8, and 255 at bit 4, in UINT16.
    fn from_location(location: ReadableLocation, flags: u8, range: &Range) -> Self {
        match location.0 {
            ValueLocation::Bytes { .. } => Self::from_ifr(range, flags),
            ValueLocation::Bits { offset, width } => {
                let storage_bits = u32::from(storage_width(offset, width)) * u8::BITS;
                let signed = flags & EDKII_IFR_DISPLAY_BIT == EDKII_IFR_DISPLAY_INT_DEC_BIT;
                Self {
                    bits: u32::from(width),
                    signed_type_bits: signed.then_some(storage_bits.next_power_of_two()),
                }
            }
        }
    }

    /// Returns the format of the IFR default of an EDKII bit varstore field of `width` bits,
    /// from its Flags.
    fn from_bit_field(width: u8, flags: u8) -> Result<Self, NumericFormatError> {
        let bits = bit_field_bits(width)?;
        // edk2-stable202608 SetupBrowserDxe/Setup.c GetQuestionDefault copies the EFI_IFR_DEFAULT,
        // Type UINT32 here, and DisplayEngineDxe/ProcessOptions.c PrintFormattedNumber signs by
        // that Type; IfrParse.c types the question by the bytes it spans and GetBitsQuestionValue
        // copies no Type, so a byte-aligned 8-bit INT_DEC 0xFF shows 255 as a default and -1 when
        // read after a parse
        let signed = flags & EDKII_IFR_DISPLAY_BIT == EDKII_IFR_DISPLAY_INT_DEC_BIT;
        Ok(Self {
            bits,
            signed_type_bits: signed.then_some(EDKII_BIT_FIELD_VALUE_BITS),
        })
    }

    /// Returns `value` cut to `bits` bits.
    fn cut(self, value: u64) -> u64 {
        let unused = 64 - self.bits;
        value << unused >> unused
    }

    /// Returns the stored bits that decode to `value`, or None if no stored bits do.
    fn encode(self, value: i128) -> Option<u64> {
        let stored = match self.signed_type_bits {
            Some(_) => i64::try_from(value).ok()?.cast_unsigned(),
            None => u64::try_from(value).ok()?,
        };
        let stored = self.cut(stored);
        (self.decode(stored) == value).then_some(stored)
    }

    /// Returns `value` cut to `bits` bits and, if signed, sign-extended from its type width.
    fn decode(self, value: u64) -> i128 {
        let value = self.cut(value);
        match self.signed_type_bits {
            Some(type_bits) => {
                let unused = 64 - type_bits;
                i128::from((value << unused).cast_signed() >> unused)
            }
            None => i128::from(value),
        }
    }
}

/// Returns the format of the question's IFR default, from EDKII bit-field Flags if it has them.
fn numeric_format(
    location: ValueLocation,
    flags: u8,
    range: &Range,
) -> Result<NumericFormat, NumericFormatError> {
    match location {
        ValueLocation::Bits { width, .. } => NumericFormat::from_bit_field(width, flags),
        ValueLocation::Bytes { .. } => Ok(NumericFormat::from_ifr(range, flags)),
    }
}

/// Whether the question is wrapped in the GUID op that marks an EDKII bit varstore field;
/// edk2-stable202608 BaseTools VfrSyntax.g wraps each such question in its own.
fn refers_to_bit_field(question: &IFROperation) -> bool {
    question
        .parent
        .as_ref()
        .and_then(Weak::upgrade)
        .is_some_and(|parent| {
            let parent = parent.borrow();
            parent.op_code == IFROpCode::Guid
                && parent.data.starts_with(&EDKII_IFR_BIT_VARSTORE_GUID)
        })
}

/// How a ONE_OF, NUMERIC or CHECKBOX stores its value, and a NUMERIC or ONE_OF its MinValue,
/// MaxValue and Step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ValueEncoding {
    /// In the size of EFI_IFR_NUMERIC_SIZE in its Flags, a CHECKBOX value in a byte.
    NumericSize,
    /// As UINT32, as edk2-stable202608 VfrSyntax.g stores them for an EDKII bit varstore field,
    /// whose Flags hold its width in bits; the value in that width, a CHECKBOX value in 1 bit.
    EdkiiBitField,
}

impl ValueEncoding {
    fn from_question(question: &IFROperation) -> Self {
        if refers_to_bit_field(question) {
            Self::EdkiiBitField
        } else {
            Self::NumericSize
        }
    }

    /// Where a ONE_OF or NUMERIC with `flags` and `range` keeps its value, VarOffset `offset`.
    fn numeric_location(self, offset: u16, flags: u8, range: &Range) -> ValueLocation {
        match self {
            Self::NumericSize => ValueLocation::Bytes {
                offset,
                size: range.size(),
            },
            Self::EdkiiBitField => ValueLocation::Bits {
                offset,
                width: flags & EDKII_IFR_NUMERIC_SIZE_BIT,
            },
        }
    }

    /// Where a CHECKBOX keeps its value, VarOffset `offset`: in a byte, or in the 1 bit that
    /// edk2-stable202608 IfrParse.c gives a bit-field CHECKBOX.
    fn checkbox_location(self, offset: u16) -> ValueLocation {
        match self {
            Self::NumericSize => ValueLocation::Bytes { offset, size: 1 },
            Self::EdkiiBitField => ValueLocation::Bits { offset, width: 1 },
        }
    }
}

fn range_parser<R: Read + Seek>(
    reader: &mut R,
    _endian: binrw::Endian,
    (flags, encoding): (u8, ValueEncoding),
) -> BinResult<Range> {
    match encoding {
        ValueEncoding::EdkiiBitField => Ok(Range::Range32(reader.read_ne()?)),
        ValueEncoding::NumericSize => match flags & EFI_IFR_NUMERIC_SIZE {
            EFI_IFR_NUMERIC_SIZE_1 => Ok(Range::Range8(reader.read_ne()?)),
            EFI_IFR_NUMERIC_SIZE_2 => Ok(Range::Range16(reader.read_ne()?)),
            EFI_IFR_NUMERIC_SIZE_4 => Ok(Range::Range32(reader.read_ne()?)),
            // EFI_IFR_NUMERIC_SIZE_8, the only value left
            _ => Ok(Range::Range64(reader.read_ne()?)),
        },
    }
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little, import(encoding: ValueEncoding))]
pub struct CheckBox {
    pub question_header: QuestionHeader,
    pub flags: u8,
    #[br(calc = encoding.checkbox_location(question_header.var_store_info))]
    location: ValueLocation,
}

impl Question for CheckBox {
    fn question_header(&self) -> QuestionHeader {
        self.question_header
    }
}

/// A question whose value get reads and set writes.
#[derive(Clone, Copy)]
enum ValueQuestion<'a> {
    OneOf(&'a OneOf),
    Numeric(&'a Numeric),
    CheckBox(&'a CheckBox),
}

impl ValueQuestion<'_> {
    fn header(self) -> QuestionHeader {
        match self {
            ValueQuestion::OneOf(question) => question.question_header(),
            ValueQuestion::Numeric(question) => question.question_header(),
            ValueQuestion::CheckBox(question) => question.question_header(),
        }
    }

    fn location(self) -> ValueLocation {
        match self {
            ValueQuestion::OneOf(question) => question.location,
            ValueQuestion::Numeric(question) => question.location,
            ValueQuestion::CheckBox(question) => question.location,
        }
    }
}

/// Returns `op` as a ONE_OF, NUMERIC or CHECKBOX.
fn value_question(op: &IFROperation) -> Option<ValueQuestion<'_>> {
    match &op.parsed_data {
        ParsedOperation::OneOf(question) => Some(ValueQuestion::OneOf(question)),
        ParsedOperation::Numeric(question) => Some(ValueQuestion::Numeric(question)),
        ParsedOperation::CheckBox(question) => Some(ValueQuestion::CheckBox(question)),
        ParsedOperation::FormSet(_)
        | ParsedOperation::OneOfOption(_)
        | ParsedOperation::VarStore(_)
        | ParsedOperation::VarStoreNameValue(_)
        | ParsedOperation::VarStoreEfi(_)
        | ParsedOperation::DefaultStore(_)
        | ParsedOperation::IFRDefault(_)
        | ParsedOperation::Form(_)
        | ParsedOperation::Text(_)
        | ParsedOperation::Subtitle(_)
        | ParsedOperation::QuestionRef1(_)
        | ParsedOperation::EqIdVal(_)
        | ParsedOperation::EqIdId(_)
        | ParsedOperation::EqIdValList(_)
        | ParsedOperation::Placeholder => None,
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
struct VariableNotExported {
    missing: VariableNotFound,
    interface: VariableInterface,
}

impl VariableNotExported {
    /// Turns the VariableNotFound of FirmwareVariables of `reach` and `interface` for the variable
    /// of `store` into the DeclaredBootServiceOnly of VariableStore::explain_unread, if any, else
    /// into VariableNotExported; other errors pass through unchanged.
    fn explain(
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
enum DeclaredBootServiceOnly {
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
enum VariableStoreKind {
    Buffer,
    EfiVariable,
}

/// The Name and Guid of a VarStore, which name its variable whatever its kind.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct VarStoreVariable {
    name: &'static str,
    guid: Guid,
}

impl VarStoreVariable {
    fn identifies(self, store: &dyn VariableStore) -> bool {
        store.guid() == self.guid && store.name() == self.name
    }
}

#[cfg(test)]
#[cfg(efivar_dumps)]
mod non_efi_varstore_tests {
    use std::path::Path;

    use super::ifr_fixtures::*;
    use super::*;
    use crate::hii::efivarfs_format::EfivarFileName;
    use crate::hii::variables::tests::EFI_GLOBAL_VARIABLE;
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
    fn read_error(&self, store: &dyn VariableStore) -> Option<&anyhow::Error> {
        self.outcomes.get(&EfivarRange::of(store))?.as_ref().err()
    }

    /// The attribute word of the efivar of `store`, if a read of it succeeded; None skips set's
    /// check of it before the first write.
    fn attributes(&self, store: &dyn VariableStore) -> Option<u32> {
        efivar_attributes(self.outcomes.get(&EfivarRange::of(store))?.as_ref().ok()?)
    }
}

/// Returns the bytes of `varstore`'s efivar file, or why a question on it has no value.
/// The caller decodes the payload bytes `value`.
fn read_current_value_bytes<'a>(
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
enum ValueUnavailable {
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
    fn to_answer(&self) -> String {
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
enum ValueLocation {
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
fn storage_width(offset: u16, width: u8) -> u16 {
    (offset % 8 + u16::from(width)).div_ceil(8)
}

/// A ValueLocation that ValueLocation::check accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReadableLocation(ValueLocation);

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
fn read_question_value(
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
fn stored_value(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .rev()
        .fold(0, |value, byte| (value << 8) | u64::from(*byte))
}

#[cfg(test)]
#[cfg(efivar_dumps)]
mod efivar_reader_tests {
    use std::collections::BTreeMap;

    use super::ifr_fixtures::*;
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

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct DefaultStore {
    pub name_string_id: u16,
    pub default_id: DefaultId,
}

// IFRDefault is called IFRDefault instead of Default like the opcode because we don't want
// rust to confuse it with std:default:Default trait
#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct IFRDefault {
    pub default_id: DefaultId,
    value_type: u8,
    #[br(parse_with = default_value_parser, args(value_type))]
    value: IfrDefaultValue,
}

/// The Value of an EFI_IFR_DEFAULT.
#[derive(Debug, PartialEq, Clone, Copy)]
enum IfrDefaultValue {
    Decoded(TypeValue),
    /// Absent from EFI_IFR_DEFAULT_2 (Type EFI_IFR_TYPE_OTHER), whose value is a nested
    /// EFI_IFR_VALUE.
    InValueOp,
    /// Of a Type other than numeric, boolean and EFI_IFR_TYPE_OTHER.
    NotDecoded,
    /// Length leaves no room for a value of Type.
    Missing,
}

fn default_value_parser<R: Read + Seek>(
    reader: &mut R,
    endian: binrw::Endian,
    args: (u8,),
) -> BinResult<IfrDefaultValue> {
    match args.0 {
        EFI_IFR_TYPE_NUM_SIZE_8
        | EFI_IFR_TYPE_NUM_SIZE_16
        | EFI_IFR_TYPE_NUM_SIZE_32
        | EFI_IFR_TYPE_NUM_SIZE_64
        | EFI_IFR_TYPE_BOOLEAN => match type_value_parser(reader, endian, args) {
            Ok(value) => Ok(IfrDefaultValue::Decoded(value)),
            Err(error) if error.is_eof() => Ok(IfrDefaultValue::Missing),
            Err(error) => Err(error),
        },
        EFI_IFR_TYPE_OTHER => Ok(IfrDefaultValue::InValueOp),
        _ => Ok(IfrDefaultValue::NotDecoded),
    }
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
pub struct EqIdId {
    pub question_id_1: u16,
    pub question_id_2: u16,
}

#[derive(BinRead, Debug, PartialEq)]
#[br(little)]
pub struct EqIdValList {
    pub question_id: u16,
    pub list_length: u16,
    #[br(count = usize::from(list_length))]
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
    #[expect(dead_code, reason = "type_value_parser does not decode this type yet")]
    Time(Time),
    #[expect(dead_code, reason = "type_value_parser does not decode this type yet")]
    Date(Date),
    #[expect(dead_code, reason = "type_value_parser does not decode this type yet")]
    StringID(u16),
    #[expect(dead_code, reason = "type_value_parser does not decode this type yet")]
    Other,
    #[expect(dead_code, reason = "type_value_parser does not decode this type yet")]
    Undefined,
    #[expect(dead_code, reason = "type_value_parser does not decode this type yet")]
    Action(u16),
    // Buffer(Vec<u8>),  - spec unclear ; FIXME
    #[expect(dead_code, reason = "type_value_parser does not decode this type yet")]
    Ref(Ref),
    Unknown(u8),
}

impl TypeValue {
    /// Returns a numeric or boolean value as an unsigned integer.
    fn as_u64(self) -> Option<u64> {
        match self {
            TypeValue::NumSize8(v) => Some(v.into()),
            TypeValue::NumSize16(v) => Some(v.into()),
            TypeValue::NumSize32(v) => Some(v.into()),
            TypeValue::NumSize64(v) => Some(v),
            TypeValue::Boolean(v) => Some(v.into()),
            TypeValue::Time(_)
            | TypeValue::Date(_)
            | TypeValue::StringID(_)
            | TypeValue::Other
            | TypeValue::Undefined
            | TypeValue::Action(_)
            | TypeValue::Ref(_)
            | TypeValue::Unknown(_) => None,
        }
    }
}

fn type_value_parser<R: Read + Seek>(
    reader: &mut R,
    _endian: binrw::Endian,
    args: (u8,),
) -> BinResult<TypeValue> {
    match args.0 {
        EFI_IFR_TYPE_NUM_SIZE_8 => {
            let r: u8 = reader.read_ne()?;
            Ok(TypeValue::NumSize8(r))
        }
        EFI_IFR_TYPE_NUM_SIZE_16 => {
            let r: u16 = reader.read_ne()?;
            Ok(TypeValue::NumSize16(r))
        }
        EFI_IFR_TYPE_NUM_SIZE_32 => {
            let r: u32 = reader.read_ne()?;
            Ok(TypeValue::NumSize32(r))
        }
        EFI_IFR_TYPE_NUM_SIZE_64 => {
            let r: u64 = reader.read_ne()?;
            Ok(TypeValue::NumSize64(r))
        }
        EFI_IFR_TYPE_BOOLEAN => {
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

/// Parses a form package into one root per FormSet: the first as handle_form_set parses it,
/// then each FORM_SET op after it that edk2-stable202608 SetupBrowserDxe/Setup.c
/// GetIfrBinaryData reaches when it looks for a FormSet by GUID, walking the package op by op.
/// That walk ends at an op whose Length runs past the package; here it also ends at one below the
/// header size, which that walk loops on (Length 0) or steps into (Length 1), and at a later
/// FormSet whose bytes do not parse. A later FormSet whose scopes nest deeper than
/// MAX_SCOPE_NESTING is skipped to its End, as that walk steps over it.
/// None of them fails the package: edk2 reads past the first FormSet only for such a walk.
pub(super) fn parse_form_sets(
    package_cursor: &mut Cursor<&Vec<u8>>,
    package_list_guid: Guid,
) -> Result<Vec<Rc<RefCell<IFROperation>>>> {
    let mut roots = vec![handle_form_set(package_cursor)?];
    let package_length = u64::try_from(package_cursor.get_ref().len())
        .context("failed to convert form package length into u64")?;
    while package_cursor.position() < package_length {
        let offset = package_cursor.position();
        let op: IFROperation = match package_cursor.read_ne() {
            Ok(op) => op,
            Err(error)
                if error.is_eof()
                    || matches!(error.root_cause(), binrw::Error::AssertFail { .. }) =>
            {
                debug!("ending the FormSet walk at offset {offset}: {error}");
                break;
            }
            Err(error) => return Err(error).context("failed to parse IFR operation"),
        };
        if op.op_code != IFROpCode::FormSet {
            debug!(
                "skipping {:?} outside a FormSet at offset {offset}",
                op.op_code
            );
            continue;
        }
        package_cursor.set_position(offset);
        match handle_form_set(package_cursor) {
            Ok(root) => roots.push(root),
            Err(error) if error.chain().any(|cause| cause.is::<ScopesTooDeep>()) => {
                warn!(
                    "package list {package_list_guid}: ignoring the FormSet at offset {offset} of \
                     a form package: {error:#}"
                );
                package_cursor.set_position(offset);
                if let Err(error) = skip_scope(package_cursor) {
                    debug!("ending the FormSet walk in the FormSet at offset {offset}: {error}");
                    break;
                }
            }
            Err(error) if error.chain().any(|cause| cause.is::<binrw::Error>()) => {
                warn!(
                    "package list {package_list_guid}: ignoring the FormSet at offset {offset} of \
                     a form package and the ops after it: {error:#}"
                );
                break;
            }
            Err(error) => return Err(error),
        }
    }
    Ok(roots)
}

/// Moves `package_cursor` from the op at its position past the End that closes that op's scope,
/// reading the ops in between undecoded, as GetIfrBinaryData's walk steps over them.
fn skip_scope(package_cursor: &mut Cursor<&Vec<u8>>) -> binrw::BinResult<()> {
    let mut depth: usize = 0;
    loop {
        let op: IFROperation = package_cursor.read_ne()?;
        match (&op.op_code, op.open_scope) {
            (IFROpCode::End, _) => depth = depth.saturating_sub(1),
            (_, true) => depth = depth.saturating_add(1),
            (_, false) => {}
        }
        if depth == 0 {
            return Ok(());
        }
    }
}

pub fn handle_form_set(package_cursor: &mut Cursor<&Vec<u8>>) -> Result<Rc<RefCell<IFROperation>>> {
    handle_form_set_within(package_cursor, MAX_SCOPE_NESTING)
}

/// handle_form_set, failing with ScopesTooDeep at an op that opens more than `limit` scopes at
/// once.
fn handle_form_set_within(
    package_cursor: &mut Cursor<&Vec<u8>>,
    limit: usize,
) -> Result<Rc<RefCell<IFROperation>>> {
    // this is the root element so all the values like op_code, length, etc are dummy
    debug!("new FormSet");
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
    // The scopes open inside an op that skips_scope names, its own scope counted: their ops are not
    // decoded, as edk2-stable202608 SetupBrowserDxe/IfrParse.c ParseOpCodes skips them unread
    // (InUnknownScope, UnknownDepth).
    let mut skipped_depth: usize = 0;
    // The scopes open, the FormSet's own and skipped ones counted
    let mut depth: usize = 0;

    // this loop will terminate when it sees the IFR:End opcode as a child of FormSet
    // if input data is malformed then it will exit on erroring out cause none of the magic bytes match
    loop {
        let offset = package_cursor.position();
        let node: IFROperation = package_cursor
            .read_ne()
            .context("failed to parse IFR operation")?;

        let current_node = Rc::new(RefCell::new(node));

        debug!("OpCode is {:?}", current_node.borrow().op_code);

        // end of current scope
        if current_node.borrow().op_code == IFROpCode::End {
            skipped_depth = skipped_depth.saturating_sub(1);
            depth = depth.saturating_sub(1);
            let current_scope_clone = Rc::clone(&current_scope);
            match current_scope_clone.borrow().parent.as_ref() {
                Some(parent_ref) => {
                    if let Some(parent_ref_rc) = parent_ref.upgrade() {
                        // current_scope = current_scope 's parent
                        current_scope = Rc::clone(&parent_ref_rc);
                    }

                    debug!(
                        "Inside the IFR:End case. Op Code: {:?}",
                        current_scope.borrow().op_code
                    );
                }
                None => debug!("IFR:End when parent_ref is none"),
            };

            // back at the root: this FormSet has been parsed. The root is found by
            // identity: an IFR op may have opcode 0xFF, the root's DUMMY_OPCODE, and a scope.
            if Rc::ptr_eq(&current_scope, &root) {
                debug!("Reached root element. Current scope: {:?}", current_scope);
                // parse_form_sets reads the FormSets after this one
                break;
            }
            continue;
        }

        if current_node.borrow().open_scope {
            if depth >= limit {
                return Err(ScopesTooDeep { offset, limit }.into());
            }
            depth += 1;
        }

        // set current_node's parent
        // before handle_opcode: ValueEncoding::from_question reads it
        current_node.borrow_mut().parent = Some(Rc::downgrade(&current_scope));

        if skipped_depth == 0 {
            handle_opcode(Rc::clone(&current_node)).context(format!(
                "failed to parse op_code {:?} properly",
                &current_node.borrow().op_code,
            ))?;
        }

        // add current_node to current_scope's children
        current_scope
            .borrow_mut()
            .children
            .push(Rc::clone(&current_node));

        if current_node.borrow().open_scope {
            if skipped_depth > 0 || skips_scope(&current_node.borrow()) {
                skipped_depth += 1;
            }
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
                .context("failed to parse FormSet's data")?;
            debug!("FormSet is {:?}", parsed);
            node.parsed_data = ParsedOperation::FormSet(parsed);
        }

        IFROpCode::OneOf => {
            let parsed: OneOf = data_cursor
                .read_ne_args((ValueEncoding::from_question(&node),))
                .context("failed to parse OneOf's data")?;
            debug!("OneOf is {:?}", parsed);
            node.parsed_data = ParsedOperation::OneOf(parsed);
        }
        IFROpCode::CheckBox => {
            let parsed: CheckBox = data_cursor
                .read_ne_args((ValueEncoding::from_question(&node),))
                .context("failed to parse CheckBox's data")?;
            debug!("CheckBox is {:?}", parsed);
            node.parsed_data = ParsedOperation::CheckBox(parsed);
        }
        IFROpCode::OneOfOption => {
            let parsed: OneOfOption = data_cursor
                .read_ne()
                .context("failed to parse OneOfOption's data")?;
            debug!("OneOfOption is {:?}", parsed);
            node.parsed_data = ParsedOperation::OneOfOption(parsed);
        }
        IFROpCode::VarStore => {
            let parsed: VarStore = data_cursor
                .read_ne()
                .context("failed to parse VarStore's data")?;

            debug!("VarStore is {:?}", &parsed);

            node.parsed_data = ParsedOperation::VarStore(parsed);
        }
        IFROpCode::VarStoreNameValue => {
            let parsed: VarStoreNameValue = data_cursor
                .read_ne()
                .context("failed to parse VarStoreNameValue's data")?;
            debug!("VarStoreNameValue is {:?}", parsed);
            node.parsed_data = ParsedOperation::VarStoreNameValue(parsed);
        }
        IFROpCode::VarStoreEfi => {
            // this is implemented in hiilib and the docs for this are relatively clear
            // so I implemented this but I haven't seen it being used anywhere in the dbdumps I have
            let parsed: VarStoreEfi = data_cursor
                .read_ne()
                .context("failed to parse VarStoreEfi's data")?;
            debug!("VarStoreEfi is {:?}", parsed);
            node.parsed_data = ParsedOperation::VarStoreEfi(parsed);
        }
        IFROpCode::DefaultStore => {
            let parsed: DefaultStore = data_cursor
                .read_ne()
                .context("failed to parse DefaultStore's data")?;
            debug!("DefaultStore is {:?}", parsed);
            node.parsed_data = ParsedOperation::DefaultStore(parsed);
        }
        IFROpCode::Default => {
            let parsed: IFRDefault = data_cursor
                .read_ne()
                .context("failed to parse Default's data")?;
            debug!("Default is {:?}", parsed);
            node.parsed_data = ParsedOperation::IFRDefault(parsed);
        }
        IFROpCode::Form => {
            let parsed: Form = data_cursor
                .read_ne()
                .context("failed to parse Form's data")?;
            debug!("Form is {:?}", parsed);
            node.parsed_data = ParsedOperation::Form(parsed);
        }
        IFROpCode::Text => {
            let parsed: Text = data_cursor
                .read_ne()
                .context("failed to parse Text's data")?;
            debug!("Text is {:?}", parsed);
            node.parsed_data = ParsedOperation::Text(parsed);
        }
        IFROpCode::Subtitle => {
            let parsed: Subtitle = data_cursor
                .read_ne()
                .context("failed to parse Subtitle's data")?;
            debug!("Subtitle is {:?}", parsed);
            node.parsed_data = ParsedOperation::Subtitle(parsed);
        }
        IFROpCode::Numeric => {
            let parsed: Numeric = data_cursor
                .read_ne_args((ValueEncoding::from_question(&node),))
                .context("failed to parse Numeric's data")?;
            debug!("Numeric is {:?}", parsed);
            node.parsed_data = ParsedOperation::Numeric(parsed);
        }
        IFROpCode::QuestionRef1 => {
            let parsed: QuestionRef1 = data_cursor
                .read_ne()
                .context("failed to parse QuestionRef1's data")?;
            debug!("QuestionRef1 is {:?}", parsed);
            node.parsed_data = ParsedOperation::QuestionRef1(parsed);
        }
        IFROpCode::EqIdVal => {
            let parsed: EqIdVal = data_cursor
                .read_ne()
                .context("failed to parse EqIdVal's data")?;
            debug!("EqIdVal is {:?}", parsed);
            node.parsed_data = ParsedOperation::EqIdVal(parsed);
        }
        IFROpCode::EqIdId => {
            let parsed: EqIdId = data_cursor
                .read_ne()
                .context("failed to parse EqIdId's data")?;
            debug!("EqIdId is {:?}", parsed);
            node.parsed_data = ParsedOperation::EqIdId(parsed);
        }
        IFROpCode::EqIdValList => {
            let parsed: EqIdValList = data_cursor
                .read_ne()
                .context("failed to parse EqIdValList's data")?;
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
    /// The VarStore of the question, or why set cannot write it
    varstore: Result<Box<dyn VariableStore>>,
    /// Where the question keeps its value
    location: ValueLocation,
    /// The state of the option that `value` names: selectable if none does
    pub(crate) value_state: StateEvaluation,
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
    pub(crate) state: StateEvaluation,
}

impl QuestionDescriptor {
    /// The VarStore of the question, or why set cannot write it.
    fn store(&self) -> std::result::Result<&dyn VariableStore, ChangeValueError> {
        self.varstore
            .as_deref()
            .map_err(|reason| ChangeValueError::NoVarStore {
                question: self.question.clone(),
                reason: format!("{reason:#}"),
            })
    }

    /// The option that set writes for one of `texts`.
    pub(crate) fn chosen_option(
        &self,
        texts: &BTreeSet<String>,
        include: IncludedStates,
    ) -> Result<&AnswerOption> {
        // if not a single option matched then error out
        self.select_option(texts, include)?
            .ok_or_else(|| ChangeValueError::InvalidOption.into())
    }

    /// The texts of the options that `include` certainly allows: those that get lists and set
    /// takes.
    pub(crate) fn listed_options(&self, include: IncludedStates) -> Vec<String> {
        self.possible_options
            .iter()
            .filter(|option| option.state.is_allowed(include))
            .map(|option| option.value.clone())
            .collect()
    }

    /// Returns the option that select() picks with `include` among those whose text is one of
    /// `texts` ignoring ASCII case, or, if there are none, among those whose text is one of
    /// `texts` ignoring surrounding whitespace too (get shows the text trimmed), or None if there
    /// are none either. So a text as stored never picks an option that differs from it only by
    /// such whitespace.
    pub(crate) fn select_option(
        &self,
        texts: &BTreeSet<String>,
        include: IncludedStates,
    ) -> std::result::Result<Option<&AnswerOption>, SelectionError> {
        let stored: Vec<&AnswerOption> = self
            .possible_options
            .iter()
            .filter(|option| {
                texts
                    .iter()
                    .any(|text| text.eq_ignore_ascii_case(&option.value))
            })
            .collect();
        let candidates = if stored.is_empty() {
            self.possible_options
                .iter()
                .filter(|option| {
                    texts
                        .iter()
                        .any(|text| text.trim().eq_ignore_ascii_case(option.value.trim()))
                })
                .collect()
        } else {
            stored
        };
        let matches: Vec<(&AnswerOption, StateEvaluation)> = candidates
            .into_iter()
            .map(|option| (option, option.state.clone()))
            .collect();
        let Some(&(first, _)) = matches.first() else {
            return Ok(None);
        };
        let question = self.question.clone();
        match select(matches, include) {
            Selection::Picked(option, _) => Ok(Some(option)),
            Selection::Undetermined {
                likely: (option, _),
                reasons,
                states,
            } => Err(SelectionError::OptionUndetermined {
                question,
                option: option.value.clone(),
                states,
                reasons,
            }),
            Selection::Excluded(states) => Err(SelectionError::OptionExcluded {
                question,
                option: first.value.clone(),
                states,
            }),
            Selection::NotFound => Ok(None),
        }
    }
}

// list_questions returns a list of QuestionDescriptors in a FormSet
// with their states, of the questions in a state that `include` may allow
// node should be the root of a FormSet
// conditions read `access_level`, if stated, for AMI_ACCESS_LEVEL instead of its value
pub fn list_questions(
    node: Rc<RefCell<IFROperation>>,
    string_packages: &[BTreeMap<i32, String>],
    include: IncludedStates,
    access_level: Option<AccessLevel>,
    reader: &mut EfivarReader,
) -> Vec<(QuestionDescriptor, StateEvaluation)> {
    let values = VarStoreValues::new(&node, access_level);
    list_questions_in(
        &node,
        &mut FormSetWalk::new(string_packages, reader, &values, include),
    )
}

/// What walking the ops of a FormSet takes besides them.
struct FormSetWalk<'a, V> {
    /// The string packages of the FormSet's package list
    string_packages: &'a [BTreeMap<i32, String>],
    default_ids: FormSetDefaultIds,
    inputs: ExpressionInputs<'a, V>,
    include: IncludedStates,
}

impl<'a, V> FormSetWalk<'a, V> {
    fn new(
        string_packages: &'a [BTreeMap<i32, String>],
        reader: &'a mut EfivarReader,
        values: &'a V,
        include: IncludedStates,
    ) -> Self {
        Self {
            string_packages,
            default_ids: FormSetDefaultIds::default(),
            inputs: ExpressionInputs { reader, values },
            include,
        }
    }
}

/// Lists questions as list_questions does, with `walk`.
fn list_questions_in(
    node: &Rc<RefCell<IFROperation>>,
    walk: &mut FormSetWalk<'_, impl QuestionValues>,
) -> Vec<(QuestionDescriptor, StateEvaluation)> {
    let mut res = Vec::new();
    walk_scopes(std::slice::from_ref(node), (), |node, ()| {
        if skips_scope(&node.borrow()) {
            return Walk::Skip;
        }
        res.extend(listed_question(node, walk));
        Walk::Enter(())
    });
    res
}

/// Returns the QuestionDescriptor and states of a ONE_OF, NUMERIC or CHECKBOX in a state that
/// `walk.include` may allow.
fn listed_question(
    question: &Rc<RefCell<IFROperation>>,
    walk: &mut FormSetWalk<'_, impl QuestionValues>,
) -> Option<(QuestionDescriptor, StateEvaluation)> {
    let op = question.borrow();
    let value_question = value_question(&op)?;
    let state = question_state(&op, &mut walk.inputs);
    if !state.may_be_allowed(walk.include) {
        return None;
    }
    let descriptor = describe_question(question, &op, value_question, walk);
    Some((descriptor, state))
}

/// find_question accepts the root node, string_packages and possible_question_phrases.
/// possible_question_phrases is a vector of strings which represent variations of the
/// same question. So if a single phrase matches then we assume that we have the answer.
/// Of the matching questions, it selects one as select does, with conditions reading
/// `access_level`, if stated, for AMI_ACCESS_LEVEL instead of its value.
pub fn find_question<T>(
    node: Rc<RefCell<IFROperation>>,
    string_packages: &[BTreeMap<i32, String>],
    possible_question_phrases: &BTreeSet<T>,
    include: IncludedStates,
    access_level: Option<AccessLevel>,
    reader: &mut EfivarReader,
) -> Selection<QuestionDescriptor>
where
    T: AsRef<str>,
{
    let values = VarStoreValues::new(&node, access_level);
    find_question_in(
        &node,
        possible_question_phrases,
        &mut FormSetWalk::new(string_packages, reader, &values, include),
    )
}

/// Finds a question as find_question does, with `walk`.
fn find_question_in<T>(
    node: &Rc<RefCell<IFROperation>>,
    possible_question_phrases: &BTreeSet<T>,
    walk: &mut FormSetWalk<'_, impl QuestionValues>,
) -> Selection<QuestionDescriptor>
where
    T: AsRef<str>,
{
    let questions = questions_named(node, walk.string_packages, possible_question_phrases);
    let ops: Vec<std::cell::Ref<IFROperation>> =
        questions.iter().map(|question| question.borrow()).collect();
    let matches = questions
        .iter()
        .zip(&ops)
        .filter_map(|(question, op)| {
            let value_question = value_question(op)?;
            let state = question_state(op, &mut walk.inputs);
            Some(((question, op, value_question), state))
        })
        .collect();
    select(matches, walk.include)
        .map(|(question, op, value_question)| describe_question(question, op, value_question, walk))
}

/// set's choice of the selection of a FormSet: that of Selection::for_set, unless the
/// match that set would write, or the likely match, has no VarStore, or its efivar is missing,
/// unreadable, e.g. withheld, boot-service-only, volatile or authenticated, which --include
/// cannot make writable: then ChangeValueError::NoVarStore, DeclaredBootServiceOnly,
/// VariableNotExported or the read's error, as `reader` found it, BootServiceOnlyVariable,
/// VolatileVariable or AuthenticatedVariable.
pub(crate) fn choice_for_set(
    selection: Selection<QuestionDescriptor>,
    question: &str,
    reader: &EfivarReader,
) -> Result<Choice<QuestionDescriptor>> {
    let descriptor = match &selection {
        Selection::Picked(descriptor, _)
        | Selection::Undetermined {
            likely: (descriptor, _),
            ..
        } => descriptor,
        Selection::Excluded(_) | Selection::NotFound => return Ok(selection.for_set(question)?),
    };
    let store = descriptor.store()?;
    let reach = reader.reach();
    let interface = reader.interface();
    if let Some(error) = reader.read_error(store) {
        if let Some(declared) = store.explain_unread(reach, interface, error) {
            return Err(declared.into());
        }
        return Err(match error.downcast_ref::<VariableNotFound>() {
            Some(missing) => VariableNotExported {
                missing: missing.clone(),
                interface,
            }
            .into(),
            None => anyhow!("{error:#}"),
        });
    }
    if let Some(attributes) = reader.attributes(store) {
        let key = store.variable_key();
        check_non_volatile(&key, interface, attributes)?;
        check_unauthenticated(&key, attributes)?;
        check_runtime_writable(&key, reach, attributes)?;
    }
    Ok(selection.for_set(question)?)
}

#[cfg(test)]
#[cfg(efivar_dumps)]
mod choice_for_set_tests {
    use super::ifr_fixtures::*;
    use super::*;

    /// The refusal of the efivar Present with the attributes NV_BS through variables that reach
    /// Runtime.
    const PRESENT_BOOT_SERVICE_ONLY: &str = "EFI variable \
        Present-00000000-0000-0000-0000-000000000000 has no EFI_VARIABLE_RUNTIME_ACCESS \
        (attributes 0x3), so the firmware refuses to write it at OS runtime";
    /// The refusal of the efivar Missing, which variables that reach Runtime lack, where its
    /// form declares it boot-service-only.
    const MISSING_NOT_PRESENT: &str = "EFI variable Missing-00000000-0000-0000-0000-000000000000 \
        is not present at OS runtime: efivarfs does not list it, and its form declares it \
        boot-service-only (no EFI_VARIABLE_RUNTIME_ACCESS)";
    /// MISSING_NOT_PRESENT for variables through the firmware environment calls.
    const WINDOWS_MISSING_NOT_PRESENT: &str = "EFI variable \
        Missing-00000000-0000-0000-0000-000000000000 is not present at OS runtime: \
        GetFirmwareEnvironmentVariableExW does not find it, and its form declares it \
        boot-service-only (no EFI_VARIABLE_RUNTIME_ACCESS)";
    /// The VariableNotFound of the efivar Missing.
    const MISSING_NOT_FOUND: &str = "no EFI variable Missing-00000000-0000-0000-0000-000000000000";
    /// Why the EQ_ID_VAL on question 2, on the efivar Missing, is not evaluated.
    const MISSING_INPUT: &str = "EqIdVal of question 0x0002: <ValueUnavailable: no EFI variable \
        Missing-00000000-0000-0000-0000-000000000000>";
    /// Why the EQ_ID_VAL on question 2, on AMI firmware's buffer VarStore SystemAccess without
    /// an efivar, is not evaluated.
    const SYSTEM_ACCESS_INPUT: &str = "EqIdVal of question 0x0002: <ValueUnavailable: no EFI \
        variable SystemAccess-e770bb69-bcb4-4d04-9e97-23ff9456feac; HII buffer varstore requires \
        EFI_HII_CONFIG_ACCESS_PROTOCOL; the AMI setup browser keeps its access level there \
        (0 Administrator, 1 User); \
        --access-level administrator|user states one>";

    /// set's choice for PROMPT in the FormSet `root`, where only the efivar Present, of
    /// 1 byte, exists.
    fn choice_in(root: &Rc<RefCell<IFROperation>>) -> Result<Choice<QuestionDescriptor>> {
        choice_attributed(root, NV_BS_RT)
    }

    /// choice_in, with the attribute word `attributes` in the efivar file of Present.
    fn choice_attributed(
        root: &Rc<RefCell<IFROperation>>,
        attributes: u32,
    ) -> Result<Choice<QuestionDescriptor>> {
        let efivars = Efivars::new();
        efivars.write_attributed(&efi_variable("Present", 1), attributes, &[0]);
        choice_with(root, &efivars)
    }

    /// set's choice for PROMPT in the FormSet `root`, with the efivar files `efivars`.
    fn choice_with(
        root: &Rc<RefCell<IFROperation>>,
        efivars: &Efivars,
    ) -> Result<Choice<QuestionDescriptor>> {
        choice_reading(root, efivars, None)
    }

    /// choice_with, with conditions reading `access_level`, if stated, for SystemAccess instead of
    /// its value.
    fn choice_reading(
        root: &Rc<RefCell<IFROperation>>,
        efivars: &Efivars,
        access_level: Option<AccessLevel>,
    ) -> Result<Choice<QuestionDescriptor>> {
        choice_by(root, efivars.reader(), access_level)
    }

    /// choice_reading, with `reader` instead of a reader of efivar files.
    fn choice_by(
        root: &Rc<RefCell<IFROperation>>,
        mut reader: EfivarReader,
        access_level: Option<AccessLevel>,
    ) -> Result<Choice<QuestionDescriptor>> {
        let values = VarStoreValues::new(root, access_level);
        let selection = find_question_in(
            root,
            &BTreeSet::from([PROMPT]),
            &mut FormSetWalk::new(&strings(), &mut reader, &values, IncludedStates::empty()),
        );
        choice_for_set(selection, PROMPT, &reader)
    }

    /// set's choice for PROMPT in the FormSet of `undetermined_on(own)`.
    fn choice(own: u16) -> Result<Choice<QuestionDescriptor>> {
        choice_in(&undetermined_on(own))
    }

    /// The FormSet of PROMPT, question 1 on VarStore `own` under a SUPPRESS_IF on question 2,
    /// which is on VarStore 2; VarStore 3 is VarStore 1 without runtime access, and only their
    /// efivar exists.
    fn undetermined_on(own: u16) -> Rc<RefCell<IFROperation>> {
        parse_form_set(&[
            var_store_efi(1, "Present", NV_BS_RT, 1),
            var_store_efi(2, "Missing", NV_BS_RT, 1),
            var_store_efi(3, "Present", NV_BS, 1),
            form(
                1,
                &[
                    checkbox_on(2, 5, 2),
                    conditional(SUPPRESS_IF, eq_id_val_of(2, 1), &[checkbox_on(1, 3, own)]),
                ],
            ),
        ])
    }

    /// set's choice for PROMPT, prompting a selectable ONE_OF on VarStore 1, after the
    /// VarStores `var_stores`, whose option Enabled is under a SUPPRESS_IF on question 2 of
    /// VarStore `input`.
    fn picked_choice(var_stores: &[Vec<u8>], input: u16) -> Result<Choice<QuestionDescriptor>> {
        choice_in(&picked_one_of(var_stores, input))
    }

    /// The FormSet of picked_choice.
    fn picked_one_of(var_stores: &[Vec<u8>], input: u16) -> Rc<RefCell<IFROperation>> {
        let (root, _question) = parse_question(
            &[var_stores, &[checkbox_on(2, 5, input)]].concat(),
            ONE_OF,
            &one_of_data(),
            &[
                flagged_option(5, 0x00, 0),
                conditional(
                    SUPPRESS_IF,
                    eq_id_val_of(2, 1),
                    &[flagged_option(6, 0x00, 1)],
                ),
            ],
        );
        root
    }

    #[test]
    fn undetermined_match_on_a_missing_efivar_is_not_exported() {
        let error = choice(2).expect_err("set refuses question 1");
        assert_eq!(
            error
                .downcast_ref::<VariableNotExported>()
                .map(|error| error.missing.to_string())
                .as_deref(),
            Some(MISSING_NOT_FOUND),
            "question 1 on the missing VarStore: {error:#}"
        );
    }

    #[test]
    fn undetermined_match_on_a_present_efivar_is_undetermined() {
        let error = choice(1).expect_err("set refuses question 1");
        assert_eq!(
            error.downcast_ref::<SelectionError>(),
            Some(&SelectionError::Undetermined {
                question: PROMPT.to_string(),
                states: IncludedStates::SUPPRESSED,
                reasons: vec![MISSING_INPUT.to_string()],
            }),
            "question 1 on the present VarStore"
        );
    }

    /// The FormSet of PROMPT, question 1 on VarStore 1, which AMI firmware grays out for a
    /// User session: SystemAccess, question 2, being 1.
    fn grayed_out_for_users() -> Rc<RefCell<IFROperation>> {
        parse_form_set(&[
            var_store_efi(1, "Present", NV_BS_RT, 1),
            var_store(2, SYSTEM_ACCESS_GUID, "SystemAccess", 1),
            form(
                1,
                &[
                    checkbox_on(2, 5, 2),
                    conditional(GRAY_OUT_IF, eq_id_val_of(2, 1), &[checkbox_on(1, 3, 1)]),
                ],
            ),
        ])
    }

    /// set's refusal of a question that AMI firmware grays out for a User session names where
    /// the access level is kept.
    #[test]
    fn undetermined_match_on_the_ami_access_level_names_it() {
        let error = choice_in(&grayed_out_for_users()).expect_err("set refuses question 1");
        assert_eq!(
            error.downcast_ref::<SelectionError>(),
            Some(&SelectionError::Undetermined {
                question: PROMPT.to_string(),
                states: IncludedStates::GRAYED_OUT,
                reasons: vec![SYSTEM_ACCESS_INPUT.to_string()],
            }),
            "question 1 under a GRAY_OUT_IF on the access level: {error:#}"
        );
    }

    /// set chooses a question that AMI firmware grays out for a User session at a stated
    /// Administrator level, and skips it as grayed out at a stated User level.
    #[test]
    fn stated_access_level_decides_the_choice() {
        let root = grayed_out_for_users();
        let efivars = Efivars::new();
        efivars.write(&efi_variable("Present", 1), &[0]);

        let administrator = choice_reading(&root, &efivars, Some(AccessLevel::Administrator));
        assert!(
            matches!(administrator, Ok(Choice::Chosen(..))),
            "Administrator: {administrator:?}"
        );
        let user = choice_reading(&root, &efivars, Some(AccessLevel::User));
        assert!(
            matches!(user, Ok(Choice::Skipped(states)) if states == IncludedStates::GRAYED_OUT),
            "User: {user:?}"
        );
    }

    #[test]
    fn picked_match_on_a_missing_efivar_is_not_exported() {
        let error = picked_choice(&[var_store_efi(1, "Missing", NV_BS_RT, 1)], 1)
            .expect_err("set refuses the ONE_OF");
        assert_eq!(
            error
                .downcast_ref::<VariableNotExported>()
                .map(|error| error.missing.to_string())
                .as_deref(),
            Some(MISSING_NOT_FOUND),
            "the ONE_OF on the missing VarStore: {error:#}"
        );
    }

    #[test]
    fn picked_match_on_a_present_efivar_is_chosen() {
        let choice = picked_choice(&[var_store_efi(1, "Present", NV_BS_RT, 1)], 1);
        assert!(
            matches!(choice, Ok(Choice::Chosen(..))),
            "the ONE_OF on the present VarStore: {choice:?}"
        );
    }

    #[test]
    fn picked_match_with_a_missing_condition_input_is_chosen() {
        let choice = picked_choice(
            &[
                var_store_efi(1, "Present", NV_BS_RT, 1),
                var_store_efi(2, "Missing", NV_BS_RT, 1),
            ],
            2,
        );
        let Ok(Choice::Chosen(descriptor, _)) = choice else {
            panic!("the ONE_OF on the present VarStore: {choice:?}");
        };
        let enabled = BTreeSet::from(["Enabled".to_string()]);
        let selected = |include| {
            descriptor
                .select_option(&enabled, include)
                .map(|option| option.map(|option| option.value.as_str()))
        };

        assert_eq!(
            selected(IncludedStates::empty()),
            Err(SelectionError::OptionUndetermined {
                question: PROMPT.to_string(),
                option: "Enabled".to_string(),
                states: IncludedStates::SUPPRESSED,
                reasons: vec![MISSING_INPUT.to_string()],
            }),
            "Enabled without --include"
        );
        assert_eq!(
            selected(IncludedStates::SUPPRESSED),
            Ok(Some("Enabled")),
            "Enabled with --include suppressed"
        );
    }

    #[test]
    fn match_without_a_varstore_is_refused() {
        let choice = choice_in(&parse_form_set(&[form(1, &[checkbox_on(1, 3, 0)])]));
        assert_eq!(
            choice.map_err(|error| error.to_string()).err().as_deref(),
            Some(
                "cannot set question \"Prompt\": question is callback-driven or temporary and \
                 has no varstore"
            ),
            "question 1 on VarStoreId 0"
        );
    }

    #[test]
    fn match_on_an_unreadable_efivar_is_refused_with_the_read_error() {
        // VARSTORE_EFI's Size is 2
        let root = picked_one_of(&[var_store_efi(1, "Present", NV_BS_RT, 2)], 1);
        let efivars = Efivars::new();
        efivars.write(&efi_variable("Present", 1), &[0]);

        let error = choice_with(&root, &efivars).expect_err("set refuses the ONE_OF");
        assert_eq!(
            format!("{error:#}"),
            format!(
                "failed to read efivar file '{}': failed to fill whole buffer",
                efivars
                    .path()
                    .join("Present-00000000-0000-0000-0000-000000000000")
                    .display()
            ),
            "efivar file of 1 payload byte"
        );
        efivars.write(&efi_variable("Present", 2), &[0, 0]);
        let choice = choice_with(&root, &efivars);
        assert!(
            matches!(choice, Ok(Choice::Chosen(..))),
            "efivar file of 2 payload bytes: {choice:?}"
        );
    }

    #[test]
    fn match_on_a_volatile_efivar_is_refused() {
        // VARSTORE_EFI's Attributes say NV: the efivar file's attribute word decides
        let root = picked_one_of(&[var_store_efi(1, "Present", NV_BS_RT, 1)], 1);

        let volatile = choice_attributed(&root, BS_RT);
        assert_eq!(
            volatile.map_err(|error| error.to_string()).err().as_deref(),
            Some(
                "EFI variable Present-00000000-0000-0000-0000-000000000000 is volatile \
                 (no EFI_VARIABLE_NON_VOLATILE) and cannot be written through efivarfs"
            ),
            "efivar file with attributes BS_RT"
        );
        let non_volatile = choice_attributed(&root, NV_BS_RT);
        assert!(
            matches!(non_volatile, Ok(Choice::Chosen(..))),
            "efivar file with attributes NV_BS_RT: {non_volatile:?}"
        );
    }

    /// set chooses a question on an NV|BS variable from variables that reach BootServices, and
    /// refuses it, having read it, from variables that reach Runtime, through efivarfs or the
    /// firmware environment calls.
    #[test]
    fn match_on_a_boot_service_only_efivar_is_refused_only_for_runtime_variables() {
        let root = picked_one_of(&[var_store_efi(1, "Present", NV_BS, 1)], 1);
        let choose = |reach, interface| {
            let variables = Rc::new(MemoryVariables::new(reach, interface));
            variables.insert(variable_key("Present"), NV_BS, &[0]);
            let reader = EfivarReader::with_variables(Box::new(Rc::clone(&variables)));
            (choice_by(&root, reader, None), variables.reads())
        };

        let (choice, reads) = choose(
            VariableReach::BootServices,
            VariableInterface::VariableServices,
        );
        assert!(
            matches!(choice, Ok(Choice::Chosen(..))),
            "BootServices: {choice:?}"
        );
        assert_eq!(reads, [(variable_key("Present"), 1)], "BootServices: reads");
        for interface in [
            VariableInterface::Efivarfs,
            VariableInterface::FirmwareEnvironment,
        ] {
            let (choice, reads) = choose(VariableReach::Runtime, interface);
            assert_eq!(
                choice.map_err(|error| error.to_string()).err().as_deref(),
                Some(PRESENT_BOOT_SERVICE_ONLY),
                "{interface:?}"
            );
            assert_eq!(
                reads,
                [(variable_key("Present"), 1)],
                "{interface:?}: reads"
            );
        }
    }

    /// set refuses a match whose variable lacks EFI_VARIABLE_RUNTIME_ACCESS and chooses one whose
    /// variable has it, whatever runtime access its VARSTORE_EFI declares, from efivarfs and from
    /// the firmware environment calls; the refusal comes before set tells whether the match is
    /// selectable.
    #[test]
    fn match_is_decided_by_the_runtime_access_of_its_efivar() {
        let firmware_environment = |root: &Rc<RefCell<IFROperation>>, attributes| {
            let variables = MemoryVariables::new(
                VariableReach::Runtime,
                VariableInterface::FirmwareEnvironment,
            );
            variables.insert(variable_key("Present"), attributes, &[0]);
            choice_by(
                root,
                EfivarReader::with_variables(Box::new(variables)),
                None,
            )
        };
        let refusal = |choice: Result<Choice<QuestionDescriptor>>| {
            choice.map_err(|error| error.to_string()).err()
        };

        for declared in [NV_BS, NV_BS_RT] {
            let root = picked_one_of(&[var_store_efi(1, "Present", declared, 1)], 1);
            let cases = [
                (
                    "efivarfs",
                    choice_attributed(&root, NV_BS),
                    choice_attributed(&root, NV_BS_RT),
                ),
                (
                    "Windows",
                    firmware_environment(&root, NV_BS),
                    firmware_environment(&root, NV_BS_RT),
                ),
            ];

            for (variables, boot_service_only, runtime) in cases {
                assert_eq!(
                    refusal(boot_service_only).as_deref(),
                    Some(PRESENT_BOOT_SERVICE_ONLY),
                    "{variables}, VarStore attributes {declared:#x}, efivar attributes 0x3"
                );
                assert!(
                    matches!(runtime, Ok(Choice::Chosen(..))),
                    "{variables}, VarStore attributes {declared:#x}, efivar attributes 0x7: \
                     {runtime:?}"
                );
            }
        }
        for (variables, undetermined) in [
            ("efivarfs", choice_attributed(&undetermined_on(3), NV_BS)),
            ("Windows", firmware_environment(&undetermined_on(3), NV_BS)),
        ] {
            assert_eq!(
                refusal(undetermined).as_deref(),
                Some(PRESENT_BOOT_SERVICE_ONLY),
                "{variables}, undetermined match on VarStore 3, efivar attributes 0x3"
            );
        }
    }

    /// set refuses a match whose variable is missing by its VARSTORE_EFI's boot-service-only
    /// declaration for variables that reach Runtime, in the words of their interface, with the
    /// text that get shows for it, and as VariableNotExported otherwise.
    #[test]
    fn match_on_a_missing_efivar_of_a_boot_service_only_store_is_not_present() {
        let efivarfs = (VariableReach::Runtime, VariableInterface::Efivarfs);
        let firmware_environment = (
            VariableReach::Runtime,
            VariableInterface::FirmwareEnvironment,
        );
        let variable_services = (
            VariableReach::BootServices,
            VariableInterface::VariableServices,
        );
        let cases = [
            (NV_BS, efivarfs, Some(MISSING_NOT_PRESENT)),
            (
                NV_BS,
                firmware_environment,
                Some(WINDOWS_MISSING_NOT_PRESENT),
            ),
            (NV_BS, variable_services, None),
            (NV_BS_RT, efivarfs, None),
            (NV_BS_RT, firmware_environment, None),
        ];

        for (declared, (reach, interface), not_present) in cases {
            let root = picked_one_of(&[var_store_efi(1, "Missing", declared, 1)], 1);
            let store = VarStoreEfi {
                var_store_id: 1,
                guid: NIL_GUID,
                attributes: declared,
                size: 1,
                name: "Missing".into(),
            };
            let mut reader =
                EfivarReader::with_variables(Box::new(MemoryVariables::new(reach, interface)));
            let case = format!("VarStore attributes {declared:#x}, {reach:?}, {interface:?}");

            let read = read_current_value_bytes(&Ok(Box::new(store)), 0..1, &mut reader)
                .map(<[u8]>::to_vec)
                .map_err(|reason| reason.to_answer());
            let error = choice_by(&root, reader, None).expect_err("set refuses the ONE_OF");

            let not_exported = error
                .downcast_ref::<VariableNotExported>()
                .map(|error| error.missing.to_string());
            match not_present {
                Some(text) => {
                    assert_eq!(
                        read,
                        Err(format!("<ValueUnavailable: {error}>")),
                        "{case}: get"
                    );
                    assert_eq!(error.to_string(), text, "{case}");
                    assert_eq!(not_exported, None, "{case}: VariableNotExported");
                }
                None => assert_eq!(
                    not_exported.as_deref(),
                    Some(MISSING_NOT_FOUND),
                    "{case}: {error:#}"
                ),
            }
        }
    }

    /// set's refusal of a match whose variable is missing follows the interface of the variables
    /// that it reads.
    #[test]
    fn match_on_a_missing_variable_is_explained_by_its_interface() {
        let root = picked_one_of(&[var_store_efi(1, "Missing", NV_BS_RT, 1)], 1);
        let cases = [
            (
                VariableReach::Runtime,
                VariableInterface::Efivarfs,
                "does not expose it to the OS",
            ),
            (
                VariableReach::Runtime,
                VariableInterface::FirmwareEnvironment,
                "cannot be set from Windows",
            ),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
                ": the firmware has not created it, and set never creates variables",
            ),
        ];

        for (reach, interface, refusal) in cases {
            let reader =
                EfivarReader::with_variables(Box::new(MemoryVariables::new(reach, interface)));
            let error = choice_by(&root, reader, None).expect_err("set refuses the ONE_OF");

            let text = error.to_string();
            assert!(
                text.starts_with(MISSING_NOT_FOUND) && text.contains(refusal),
                "{interface:?}: {text}"
            );
        }
    }

    /// set decides the runtime access of a match by the reach of its variables, whatever their
    /// interface: it chooses a question on an NV|BS variable from variables that reach
    /// BootServices and refuses it from those that reach Runtime.
    #[test]
    fn runtime_access_is_decided_by_reach_whatever_the_interface() {
        let root = picked_one_of(&[var_store_efi(1, "Present", NV_BS, 1)], 1);
        for interface in [
            VariableInterface::Efivarfs,
            VariableInterface::VariableServices,
            VariableInterface::FirmwareEnvironment,
        ] {
            for (reach, refusal) in [
                (VariableReach::BootServices, None),
                (VariableReach::Runtime, Some(PRESENT_BOOT_SERVICE_ONLY)),
            ] {
                let variables = MemoryVariables::new(reach, interface);
                variables.insert(variable_key("Present"), NV_BS, &[0]);

                let choice = choice_by(
                    &root,
                    EfivarReader::with_variables(Box::new(variables)),
                    None,
                );

                let chosen = matches!(choice, Ok(Choice::Chosen(..)));
                assert_eq!(
                    (chosen, choice.err().map(|error| error.to_string())),
                    (refusal.is_none(), refusal.map(str::to_string)),
                    "{reach:?}, {interface:?}"
                );
            }
        }
    }

    /// get and set explain a missing variable of a boot-service-only VARSTORE_EFI by the reach of
    /// their variables, whatever their interface, in the words of that interface: by the form's
    /// declaration for variables that reach Runtime, and otherwise as VariableNotExported.
    #[test]
    fn missing_variable_is_explained_by_reach_in_the_words_of_its_interface() {
        let root = picked_one_of(&[var_store_efi(1, "Missing", NV_BS, 1)], 1);
        let cases = [
            (
                VariableInterface::Efivarfs,
                "efivarfs does not list it",
                "cannot be set from Linux",
            ),
            (
                VariableInterface::VariableServices,
                "GetVariable() does not find it",
                "set never creates variables",
            ),
            (
                VariableInterface::FirmwareEnvironment,
                "GetFirmwareEnvironmentVariableExW does not find it",
                "cannot be set from Windows",
            ),
        ];

        let crossed = cases.into_iter().flat_map(|case| {
            [VariableReach::Runtime, VariableReach::BootServices].map(|reach| (case, reach))
        });
        for ((interface, absence, not_found_refusal), reach) in crossed {
            let store = VarStoreEfi {
                var_store_id: 1,
                guid: NIL_GUID,
                attributes: NV_BS,
                size: 1,
                name: "Missing".into(),
            };
            let mut reader =
                EfivarReader::with_variables(Box::new(MemoryVariables::new(reach, interface)));
            let case = format!("{reach:?}, {interface:?}");

            let read = read_current_value_bytes(&Ok(Box::new(store)), 0..1, &mut reader)
                .map(<[u8]>::to_vec)
                .map_err(|reason| reason.to_answer());
            let error = choice_by(&root, reader, None).expect_err("set refuses the ONE_OF");

            match reach {
                VariableReach::Runtime => {
                    let not_present = format!(
                        "EFI variable Missing-00000000-0000-0000-0000-000000000000 is not \
                         present at OS runtime: {absence}, and its form declares it \
                         boot-service-only (no EFI_VARIABLE_RUNTIME_ACCESS)"
                    );
                    assert_eq!(
                        read,
                        Err(format!("<ValueUnavailable: {not_present}>")),
                        "{case}: get"
                    );
                    assert_eq!(error.to_string(), not_present, "{case}: set");
                }
                VariableReach::BootServices => {
                    assert_eq!(
                        read,
                        Err(format!("<ValueUnavailable: {MISSING_NOT_FOUND}>")),
                        "{case}: get"
                    );
                    let text = error.to_string();
                    assert!(
                        error.is::<VariableNotExported>()
                            && text.starts_with(MISSING_NOT_FOUND)
                            && text.contains(not_found_refusal),
                        "{case}: set: {text}"
                    );
                }
            }
        }
    }

    /// set refuses a match on a volatile efivar in the words of the interface of its variables,
    /// whatever their reach.
    #[test]
    fn match_on_a_volatile_efivar_is_refused_in_the_words_of_its_interface() {
        let root = picked_one_of(&[var_store_efi(1, "Present", NV_BS_RT, 1)], 1);
        for (interface, refusal) in [
            (
                VariableInterface::Efivarfs,
                " and cannot be written through efivarfs",
            ),
            (
                VariableInterface::VariableServices,
                ", so a write would not outlast a power cycle",
            ),
            (
                VariableInterface::FirmwareEnvironment,
                ", so a write would not outlast a power cycle",
            ),
        ] {
            for reach in [VariableReach::Runtime, VariableReach::BootServices] {
                let variables = MemoryVariables::new(reach, interface);
                variables.insert(variable_key("Present"), BS_RT, &[0]);
                let reader = EfivarReader::with_variables(Box::new(variables));

                let error =
                    choice_by(&root, reader, None).expect_err("set refuses a volatile efivar");

                assert_eq!(
                    error.to_string(),
                    format!(
                        "EFI variable Present-00000000-0000-0000-0000-000000000000 is volatile \
                         (no EFI_VARIABLE_NON_VOLATILE){refusal}"
                    ),
                    "{reach:?}, {interface:?}"
                );
            }
        }
    }

    /// set refuses a match on a variable with any authenticated access before any write: every
    /// write of it needs a signed descriptor (UEFI 2.10 §8.2.3).
    #[test]
    fn match_on_an_authenticated_efivar_is_refused() {
        let root = picked_one_of(&[var_store_efi(1, "Present", NV_BS_RT, 1)], 1);
        for attributes in [NV_BS_RT | 0x10, NV_BS_RT | 0x20, NV_BS_RT | 0x80] {
            let signed = choice_attributed(&root, attributes);

            assert_eq!(
                signed.map_err(|error| error.to_string()).err(),
                Some(format!(
                    "EFI variable Present-00000000-0000-0000-0000-000000000000 has authenticated \
                     access (attributes {attributes:#x}), which uefisettings does not write"
                )),
                "efivar file with attributes {attributes:#x}"
            );
        }
    }

    /// set decides on a match on an NV|BS VARSTORE_EFI whose variable has
    /// EFI_VARIABLE_RUNTIME_ACCESS as on one on a VARSTORE_EFI that declares it.
    #[test]
    fn match_on_a_boot_service_only_store_of_a_runtime_efivar_is_decided_by_its_conditions() {
        let undetermined = choice(3).expect_err("set refuses question 1");
        assert_eq!(
            undetermined.downcast_ref::<SelectionError>(),
            Some(&SelectionError::Undetermined {
                question: PROMPT.to_string(),
                states: IncludedStates::SUPPRESSED,
                reasons: vec![MISSING_INPUT.to_string()],
            }),
            "undetermined: {undetermined:#}"
        );
        let picked = picked_choice(&[var_store_efi(1, "Present", NV_BS, 1)], 1);
        assert!(
            matches!(picked, Ok(Choice::Chosen(..))),
            "picked: {picked:?}"
        );
    }
}

/// Returns the ONE_OF, NUMERIC and CHECKBOX questions under `node`, in IFR order, whose
/// prompt is one of `phrases`, ignoring ASCII case and surrounding whitespace.
fn questions_named<T>(
    node: &Rc<RefCell<IFROperation>>,
    string_packages: &[BTreeMap<i32, String>],
    phrases: &BTreeSet<T>,
) -> Vec<Rc<RefCell<IFROperation>>>
where
    T: AsRef<str>,
{
    let mut found = Vec::new();
    walk_scopes(std::slice::from_ref(node), (), |node, ()| {
        let op = node.borrow();
        if skips_scope(&op) {
            return Walk::Skip;
        }
        let prompt = prompt(&op, string_packages).trim();
        // Only Numeric, OneOf and CheckBox are questions.
        if value_question(&op).is_some()
            && phrases
                .iter()
                .any(|phrase| phrase.as_ref().trim().eq_ignore_ascii_case(prompt))
        {
            found.push(Rc::clone(node));
        }
        Walk::Enter(())
    });
    found
}

/// Returns the prompt of a ONE_OF, NUMERIC or CHECKBOX, empty for other ops.
fn prompt<'a>(op: &IFROperation, string_packages: &'a [BTreeMap<i32, String>]) -> &'a str {
    value_question(op).map_or("", |question| {
        find_corresponding_string(question.header().prompt_string_id, string_packages)
    })
}

/// Returns the QuestionDescriptor of `question`, whose op `op` is `value_question`.
fn describe_question(
    question: &Rc<RefCell<IFROperation>>,
    op: &std::cell::Ref<IFROperation>,
    value_question: ValueQuestion<'_>,
    walk: &mut FormSetWalk<'_, impl QuestionValues>,
) -> QuestionDescriptor {
    let header = value_question.header();
    let prompt = find_corresponding_string(header.prompt_string_id, walk.string_packages);
    let varstore = find_corresponding_varstore(Rc::clone(question), header.var_store_id);
    match value_question {
        ValueQuestion::OneOf(parsed) => handle_oneof(varstore, parsed, prompt, op, walk),
        ValueQuestion::Numeric(parsed) => handle_numeric(varstore, parsed, prompt, op, walk),
        ValueQuestion::CheckBox(parsed) => handle_checkbox(varstore, parsed, prompt, op, walk),
    }
}

/// Returns `value`, a current value or IFR default of a CHECKBOX, as list-questions and get show
/// it: FALSE or TRUE (UEFI 2.10 §33.3.8.3.9) as 0 or 1, any nonzero value as 1, as
/// edk2-stable202608 ProcessOptions.c shows it on.
fn checkbox_text(value: u64) -> String {
    u8::from(value != 0).to_string()
}

/// Returns `value`, a current value or IFR default of a ONE_OF in `format`, as list-questions and
/// get show it: `option`, the text of the option that holds it, else its number.
fn one_of_text(value: u64, format: NumericFormat, option: Option<&str>) -> String {
    match option {
        Some(text) => text.to_string(),
        None => format!("{} (no matching option)", format.decode(value)),
    }
}

fn handle_checkbox(
    varstore: Result<Box<dyn VariableStore>, anyhow::Error>,
    parsed: &CheckBox,
    question: &str,
    current_node: &std::cell::Ref<IFROperation>,
    walk: &mut FormSetWalk<'_, impl QuestionValues>,
) -> QuestionDescriptor {
    let mut answer = String::new();
    let available = match read_question_value(current_node, &varstore, walk.inputs.reader) {
        Err(reason) => {
            answer.push_str(&reason.to_answer());
            false
        }
        Ok((_, value)) => {
            answer.push_str(&checkbox_text(value));
            true
        }
    };
    if !available {
        let default_ids = walk.default_ids.of(current_node, &mut walk.inputs);
        push_default(
            &mut answer,
            current_node,
            default_ids,
            &mut walk.inputs,
            |v, _| Ok::<_, Infallible>(checkbox_text(v)),
        );
    }
    let res = QuestionDescriptor {
        question: question.to_string(),
        value: answer,
        help: find_corresponding_string(
            parsed.question_header().help_string_id,
            walk.string_packages,
        )
        .to_string(),
        possible_options: Vec::new(),
        varstore,
        location: parsed.location,
        max_value: RangeType::NumSize8(1),
        numeric_range: None,
        opcode: current_node.op_code,
        value_state: StateEvaluation::selectable(),
    };
    res
}

fn handle_oneof(
    varstore: Result<Box<dyn VariableStore>, anyhow::Error>,
    parsed: &OneOf,
    question: &str,
    current_node: &std::cell::Ref<IFROperation>,
    walk: &mut FormSetWalk<'_, impl QuestionValues>,
) -> QuestionDescriptor {
    let mut answer = String::new();
    // None, with the reason in `answer`, when the current value cannot be read: any u64,
    // all ones too, can be stored.
    let chosen_value = match read_question_value(current_node, &varstore, walk.inputs.reader) {
        Err(reason) => {
            answer.push_str(&reason.to_answer());
            None
        }
        Ok(stored) => Some(stored),
    };

    if chosen_value.is_none() {
        let default_ids = walk.default_ids.of(current_node, &mut walk.inputs);
        match numeric_format(parsed.location, parsed.flags, &parsed.data) {
            Ok(format) => push_default(
                &mut answer,
                current_node,
                default_ids,
                &mut walk.inputs,
                |v, inputs| {
                    option_text(current_node, format.cut(v), walk.string_packages, inputs)
                        .map(|option| one_of_text(v, format, option.as_deref()))
                },
            ),
            Err(error) => push_default(
                &mut answer,
                current_node,
                default_ids,
                &mut walk.inputs,
                |_, _| Err::<String, _>(error),
            ),
        }
    }

    let mut possible_options = Vec::new();
    // Some of OneOf's children are OneOfOptions

    for op in question_scope(current_node) {
        let op = op.borrow();
        if let ParsedOperation::OneOfOption(o) = &op.parsed_data {
            possible_options.push(AnswerOption {
                raw_value: o.value,
                value: find_corresponding_string(o.option_string_id, walk.string_packages)
                    .to_string(),
                state: option_state(&op, &mut walk.inputs),
            });
        }
    }
    let chosen: Vec<&AnswerOption> = possible_options
        .iter()
        .filter(|opt| chosen_value.is_some_and(|(_, value)| opt.raw_value.as_u64() == Some(value)))
        .collect();
    // the first that may be shown, as edk2-stable202608 SetupBrowserDxe/Setup.c ValueToOption
    // finds it, else the first, which a SUPPRESS_IF hides
    let option = chosen
        .iter()
        .find(|opt| opt.state.may_be_allowed(IncludedStates::empty()))
        .or(chosen.first());
    if let Some((location, value)) = chosen_value {
        let format = NumericFormat::from_location(location, parsed.flags, &parsed.data);
        answer.push_str(&one_of_text(
            value,
            format,
            option.map(|opt| opt.value.trim()),
        ));
    }
    let value_state = option.map_or_else(StateEvaluation::selectable, |opt| opt.state.clone());

    let res = QuestionDescriptor {
        question: question.trim().to_string(),
        value: answer,
        help: find_corresponding_string(
            parsed.question_header().help_string_id,
            walk.string_packages,
        )
        .to_string(),
        possible_options,
        varstore,
        location: parsed.location,
        max_value: match &parsed.data {
            Range::Range8(r) => RangeType::NumSize8(r.max_value),
            Range::Range16(r) => RangeType::NumSize16(r.max_value),
            Range::Range32(r) => RangeType::NumSize32(r.max_value),
            Range::Range64(r) => RangeType::NumSize64(r.max_value),
        },
        numeric_range: None,
        opcode: current_node.op_code,
        value_state,
    };
    res
}

fn handle_numeric(
    varstore: Result<Box<dyn VariableStore>, anyhow::Error>,
    parsed: &Numeric,
    question: &str,
    current_node: &std::cell::Ref<IFROperation>,
    walk: &mut FormSetWalk<'_, impl QuestionValues>,
) -> QuestionDescriptor {
    let mut answer = String::new();

    let available = match read_question_value(current_node, &varstore, walk.inputs.reader) {
        Err(reason) => {
            answer.push_str(&reason.to_answer());
            false
        }
        Ok((location, value)) => {
            let format = NumericFormat::from_location(location, parsed.flags, &parsed.data);
            answer.push_str(&format.decode(value).to_string());
            true
        }
    };
    if !available {
        let default_ids = walk.default_ids.of(current_node, &mut walk.inputs);
        push_default(
            &mut answer,
            current_node,
            default_ids,
            &mut walk.inputs,
            |v, _| {
                numeric_format(parsed.location, parsed.flags, &parsed.data)
                    .map(|format| format.decode(v).to_string())
            },
        );
    }
    let res = QuestionDescriptor {
        question: question.to_string(),
        value: answer,
        help: find_corresponding_string(
            parsed.question_header().help_string_id,
            walk.string_packages,
        )
        .to_string(),
        possible_options: Vec::new(),
        varstore,
        location: parsed.location,
        max_value: match &parsed.data {
            Range::Range8(r) => RangeType::NumSize8(r.max_value),
            Range::Range16(r) => RangeType::NumSize16(r.max_value),
            Range::Range32(r) => RangeType::NumSize32(r.max_value),
            Range::Range64(r) => RangeType::NumSize64(r.max_value),
        },
        // set refuses bit fields, whose Flags from_ifr would misread
        numeric_range: match parsed.location {
            ValueLocation::Bytes { .. } => Some(NumericRange::from_ifr(&parsed.data, parsed.flags)),
            ValueLocation::Bits { .. } => None,
        },
        opcode: current_node.op_code,
        value_state: StateEvaluation::selectable(),
    };
    res
}

#[cfg(test)]
#[cfg(efivar_dumps)]
mod question_value_tests {
    use std::io::SeekFrom;

    use super::ifr_fixtures::*;
    use super::*;

    /// EDKII_IFR_DISPLAY_UINT_DEC_BIT
    const UINT_DEC: u8 = 0x40;

    #[test]
    fn readable_checkbox_shows_no_default() {
        assert_eq!(
            answer(&[], CHECKBOX, &checkbox(0, 0x01), &[], var_store_of(&[0])),
            "0",
            "readable CHECKBOX"
        );
    }

    #[test]
    fn checkbox_past_var_store_shows_bracketed_error_and_default() {
        assert_eq!(
            answer(&[], CHECKBOX, &checkbox(1, 0x01), &[], var_store_of(&[0])),
            "<ExtractEFIDataError: failed to fill whole buffer (offset: 1; buflen: 5)> \
             <IFR default: 1>",
            "CHECKBOX past its VarStore"
        );
    }

    fn one_of_value(data: &[u8], children: &[Vec<u8>], var_store: VarStoreFixture) -> String {
        answer(&[], ONE_OF, data, children, var_store)
    }

    /// A UINT8 ONE_OF of options Disabled (0) and Enabled (1) whose
    /// manufacturing EFI_IFR_DEFAULT (DefaultId 1) has Value 0.
    fn uint8_one_of(offset: u16) -> (Vec<u8>, Vec<Vec<u8>>) {
        let data = [&question_header(offset)[..], &[0x00, 0x00, 0x01, 0x01]].concat();
        let children = vec![
            one_of_option(5, 0x00, &[0]),
            one_of_option(6, 0x00, &[1]),
            ifr_default(0x0001, 0),
        ];
        (data, children)
    }

    #[test]
    fn one_of_storing_all_ones_shows_that_option() {
        let data = [
            &question_header(0)[..],
            &[0x03],                 // Flags: UINT64
            &0u64.to_le_bytes(),     // MinValue
            &u64::MAX.to_le_bytes(), // MaxValue
            &1u64.to_le_bytes(),     // Step
        ]
        .concat();
        let children = [
            one_of_option(5, 0x03, &0u64.to_le_bytes()),
            one_of_option(7, 0x03, &u64::MAX.to_le_bytes()),
            ifr_default(0x0000, 0),
        ];

        let got = one_of_value(&data, &children, var_store_of(&u64::MAX.to_le_bytes()));

        assert_eq!(got, "AllOnes", "ONE_OF storing all ones");
    }

    /// The DefaultId (1 = Enabled) is not a value, and nothing is shown as
    /// the current value when it cannot be read.
    #[test]
    fn one_of_past_var_store_shows_extraction_error() {
        let (data, children) = uint8_one_of(8);
        let declarations = [default_store(0x0000), default_store(0x0001)];
        let var_store = var_store_of(&[1; 8]);

        let got = answer(&declarations, ONE_OF, &data, &children, var_store);

        assert_eq!(
            got,
            "<ExtractEFIDataError: failed to fill whole buffer (offset: 8; buflen: 12)> \
             <IFR default (DefaultId 0x0001): Disabled>",
            "ONE_OF past its VarStore"
        );
    }

    #[test]
    fn one_of_without_var_store_shows_only_the_reason() {
        let (data, children) = uint8_one_of(0);

        let got = one_of_value(&data, &children, unavailable());

        assert_eq!(got, UNAVAILABLE, "ONE_OF without VarStore");
    }

    #[test]
    fn one_of_shows_stored_option() {
        let (data, children) = uint8_one_of(7);

        let got = one_of_value(&data, &children, var_store_of(&[0, 0, 0, 0, 0, 0, 0, 1]));

        assert_eq!(got, "Enabled", "ONE_OF storing option 1");
    }

    /// A ONE_OF answers the option whose value, decoded as defaults are, is the
    /// stored one: a BOOLEAN option TRUE is 1, and an option of another Type
    /// matches nothing, not even an unreadable value.
    #[test]
    fn one_of_matches_options_by_their_decoded_value() {
        let cases = [
            (
                "BOOLEAN options",
                vec![one_of_option(5, 0x04, &[0]), one_of_option(6, 0x04, &[1])],
                var_store_of(&[1]),
                "Enabled",
            ),
            (
                "DATE option before a UINT8 option of 0",
                vec![one_of_option(5, 0x06, &[0]), one_of_option(6, 0x00, &[0])],
                var_store_of(&[0]),
                "Enabled",
            ),
            (
                "DATE option without a current value",
                vec![one_of_option(5, 0x06, &[0])],
                unavailable(),
                UNAVAILABLE,
            ),
        ];
        for (name, children, var_store, want) in cases {
            assert_eq!(
                answer(&[], ONE_OF, &one_of_data(), &children, var_store),
                want,
                "{name}"
            );
        }
    }

    #[test]
    fn one_of_shows_default_only_without_current_value() {
        let children = [
            one_of_option(5, 0x00, &[0]),
            one_of_option(6, 0x00, &[1]),
            ifr_default(0x0000, 1),
        ];

        assert_eq!(
            one_of_default(&[], &children),
            format!("{UNAVAILABLE} <IFR default: Enabled>"),
            "unreadable ONE_OF"
        );
        assert_eq!(
            answer(&[], ONE_OF, &one_of_data(), &children, var_store_of(&[0])),
            "Disabled",
            "readable ONE_OF"
        );
    }

    #[test]
    fn one_of_default_without_option_shows_its_value() {
        let children = [one_of_option(5, 0x00, &[0]), ifr_default(0x0000, 7)];

        assert_eq!(
            one_of_default(&[], &children),
            format!("{UNAVAILABLE} <IFR default: 7 (no matching option)>"),
            "ONE_OF default without option"
        );
    }

    /// A CHECKBOX value shows as its IFR default does: a nonzero byte as 1, as
    /// edk2-stable202608 ProcessOptions.c shows it on.
    #[test]
    fn checkbox_shows_a_nonzero_byte_as_1() {
        for (byte, want) in [(0x00, "0"), (0x01, "1"), (0x02, "1"), (0xFF, "1")] {
            assert_eq!(
                answer(
                    &[],
                    CHECKBOX,
                    &checkbox(0, 0x00),
                    &[],
                    var_store_of(&[byte])
                ),
                want,
                "CHECKBOX byte {byte:#04x}"
            );
        }
    }

    /// A ONE_OF value shows as its IFR default does: a value that no option holds as its
    /// number, signed as the Flags say, and a value whose option has empty text as that text.
    #[test]
    fn one_of_value_shows_as_its_default_does() {
        // Flags: UINT8 INT_DEC; MinValue, MaxValue, Step
        let data = [&question_header(0)[..], &[0x00, 0x00, 0xFF, 0x01]].concat();
        let cases = [
            (
                "no matching option",
                one_of_option(5, 0x00, &[0]),
                "-1 (no matching option)",
            ),
            // string 9 is not in strings()
            ("option without text", one_of_option(9, 0x00, &[0xFF]), ""),
        ];
        for (name, option, want) in cases {
            let children = [option, ifr_default(0x0000, 0xFF)];
            assert_eq!(
                answer(&[], ONE_OF, &data, &children, var_store_of(&[0xFF])),
                want,
                "{name}: current value"
            );
            assert_eq!(
                answer(&[], ONE_OF, &data, &children, unavailable()),
                format!("{UNAVAILABLE} <IFR default: {want}>"),
                "{name}: default"
            );
        }

        // the current value of a bit field is signed by its StorageWidth, its default as UINT32
        let data = uint32_range_question(0, 0x08); // 8-bit INT_DEC
        let children = [
            one_of_option(5, 0x02, &0u32.to_le_bytes()),
            uint32_default(0x0000, 0xFF),
        ];
        for (name, var_store, want) in [
            (
                "current value",
                var_store_of(&[0xFF]),
                "-1 (no matching option)".to_string(),
            ),
            (
                "default",
                unavailable(),
                format!("{UNAVAILABLE} <IFR default: 255 (no matching option)>"),
            ),
        ] {
            assert_eq!(
                answer_in_guid(BIT_VARSTORE_GUID, ONE_OF, &data, &children, var_store),
                want,
                "8-bit field: {name}"
            );
        }
    }

    /// A ONE_OF default is cut to the ONE_OF's width before it is matched to an
    /// option, and a CHECKBOX has only FALSE and TRUE (UEFI 2.10 §33.3.8.3.9).
    #[test]
    fn one_of_and_checkbox_defaults_are_cut_to_question_values() {
        // Type UINT16, Value 0x0101 and 0x0107
        let uint16_default = |value: u16| {
            let data = [&[0x00, 0x00, 0x01][..], &value.to_le_bytes()].concat();
            operation(DEFAULT, false, &data)
        };
        let options = || vec![one_of_option(5, 0x00, &[0]), one_of_option(6, 0x00, &[1])];
        let cases = [
            (
                "UINT16 default of a UINT8 ONE_OF",
                ONE_OF,
                one_of_data(),
                [options(), vec![uint16_default(0x0101)]].concat(),
                " <IFR default: Enabled>",
            ),
            (
                "UINT16 default of a UINT8 ONE_OF without its option",
                ONE_OF,
                one_of_data(),
                [options(), vec![uint16_default(0x0107)]].concat(),
                " <IFR default: 7 (no matching option)>",
            ),
            (
                "ONES default of a UINT8 ONE_OF",
                ONE_OF,
                one_of_data(),
                vec![
                    one_of_option(5, 0x00, &[0]),
                    one_of_option(7, 0x00, &[0xFF]),
                    ifr_default_2(0x0000, ifr_ones()),
                ],
                " <IFR default: AllOnes>",
            ),
            (
                "ONES default of a CHECKBOX",
                CHECKBOX,
                checkbox(0, 0x00),
                vec![ifr_default_2(0x0000, ifr_ones())],
                " <IFR default: 1>",
            ),
            (
                "UINT8 2 default of a CHECKBOX",
                CHECKBOX,
                checkbox(0, 0x00),
                vec![ifr_default(0x0000, 2)],
                " <IFR default: 1>",
            ),
        ];
        for (name, op_code, data, children, suffix) in cases {
            assert_eq!(
                answer(&[], op_code, &data, &children, unavailable()),
                format!("{UNAVAILABLE}{suffix}"),
                "{name}"
            );
        }
    }

    /// Fails every read with an error other than a short read.
    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("simulated read failure"))
        }
    }

    impl Seek for FailingReader {
        fn seek(&mut self, _pos: SeekFrom) -> std::io::Result<u64> {
            Ok(0)
        }
    }

    #[test]
    fn default_value_read_failure_other_than_short_read_is_an_error() {
        let short = default_value_parser(
            &mut Cursor::new(&[0x00][..]),
            binrw::Endian::Little,
            (0x01,),
        );
        let failed = default_value_parser(&mut FailingReader, binrw::Endian::Little, (0x00,));

        assert!(
            matches!(short, Ok(IfrDefaultValue::Missing)),
            "short read: {short:?}"
        );
        assert!(
            matches!(
                &failed,
                Err(binrw::Error::Io(error)) if error.kind() == std::io::ErrorKind::Other
            ),
            "failed read: {failed:?}"
        );
    }

    #[test]
    fn numeric_shows_default_only_without_current_value() {
        let data = uint8_numeric(0x10, 0, 10);
        let children = [ifr_default(0x0000, 5)];

        assert_eq!(
            answer(&[], NUMERIC, &data, &children, unavailable()),
            format!("{UNAVAILABLE} <IFR default: 5>"),
            "unreadable NUMERIC"
        );
        assert_eq!(
            answer(&[], NUMERIC, &data, &children, var_store_of(&[7])),
            "7",
            "readable NUMERIC"
        );
    }

    #[test]
    fn signed_numeric_default_is_signed() {
        let got = answer(
            &[],
            NUMERIC,
            &uint8_numeric(0x00, 0xFB, 5),
            &[ifr_default(0x0000, 0xFF)],
            unavailable(),
        );

        assert_eq!(
            got,
            format!("{UNAVAILABLE} <IFR default: -1>"),
            "signed UINT8 NUMERIC"
        );
    }

    #[test]
    fn signed_uint16_numeric_default_is_signed() {
        let data = [
            &question_header(0)[..],
            &[0x01],                 // Flags: UINT16, EFI_IFR_DISPLAY_INT_DEC
            &(-10i16).to_le_bytes(), // MinValue
            &10i16.to_le_bytes(),    // MaxValue
            &1u16.to_le_bytes(),     // Step
        ]
        .concat();
        // Type UINT16, Value 0xFFFE
        let default = operation(DEFAULT, false, &[0x00, 0x00, 0x01, 0xFE, 0xFF]);

        let got = answer(&[], NUMERIC, &data, &[default], unavailable());

        assert_eq!(
            got,
            format!("{UNAVAILABLE} <IFR default: -2>"),
            "signed UINT16 NUMERIC"
        );
    }

    #[test]
    fn unsigned_numeric_default_is_cut_to_question_size() {
        // Type UINT16, Value 0x01FF
        let default = operation(DEFAULT, false, &[0x00, 0x00, 0x01, 0xFF, 0x01]);

        let got = answer(
            &[],
            NUMERIC,
            &uint8_numeric(0x10, 0, 10),
            &[default],
            unavailable(),
        );

        assert_eq!(
            got,
            format!("{UNAVAILABLE} <IFR default: 255>"),
            "UINT16 default of a UINT8 NUMERIC"
        );
    }

    /// The answer of a NUMERIC with `flags`, Range UINT32 0..=300 and a UINT32
    /// standard default of `default`, in the scope of an EFI_IFR_GUID of `guid`.
    fn numeric_in_guid_answer(guid: [u8; 16], flags: u8, default: u32) -> String {
        answer_in_guid(
            guid,
            NUMERIC,
            &uint32_range_question(0, flags),
            &[uint32_default(0x0000, default)],
            unavailable(),
        )
    }

    /// A bit-field default is cut to the width in EDKII_IFR_NUMERIC_SIZE_BIT, 1 to 32, and
    /// EDKII_IFR_DISPLAY_INT_DEC_BIT signs it as a UINT32.
    #[test]
    fn bit_field_numeric_default_has_edkii_width_and_display() {
        let cases = [
            (
                "12-bit UINT_DEC",
                BIT_VARSTORE_GUID,
                0x4C,
                200,
                " <IFR default: 200>",
            ),
            (
                "8-bit INT_DEC all ones",
                BIT_VARSTORE_GUID,
                0x08,
                0xFF,
                " <IFR default: 255>",
            ),
            (
                "12-bit UINT_DEC all ones",
                BIT_VARSTORE_GUID,
                0x4C,
                0xFFF,
                " <IFR default: 4095>",
            ),
            (
                "12-bit UINT_HEX all ones",
                BIT_VARSTORE_GUID,
                0x8C,
                0xFFF,
                " <IFR default: 4095>",
            ),
            (
                "12-bit INT_DEC all ones",
                BIT_VARSTORE_GUID,
                0x0C,
                0xFFF,
                " <IFR default: 4095>",
            ),
            (
                "12-bit INT_DEC over 2047",
                BIT_VARSTORE_GUID,
                0x0C,
                3000,
                " <IFR default: 3000>",
            ),
            (
                "32-bit INT_DEC all ones",
                BIT_VARSTORE_GUID,
                0x20,
                u32::MAX,
                " <IFR default: -1>",
            ),
            // Flags 0x00: UINT8 INT_DEC
            ("other GUID", OTHER_GUID, 0x00, 0xC8, " <IFR default: -56>"),
        ];
        for (name, guid, flags, default, suffix) in cases {
            assert_eq!(
                numeric_in_guid_answer(guid, flags, default),
                format!("{UNAVAILABLE}{suffix}"),
                "{name}"
            );
        }
    }

    /// show-ifr shows the value in the bits of an EDKII bit varstore field.
    #[test]
    fn show_ifr_answer_of_bit_field_is_its_value() {
        for (guid, want) in [(BIT_VARSTORE_GUID, "1"), (OTHER_GUID, "2")] {
            let (_root, node) = parse_question_in_guid(guid, CHECKBOX, &checkbox(3, 0x00), &[]);
            let question = node.borrow();

            // bit 3, and byte 3
            let VarStoreFixture { store, efivars } = var_store_of(&[0xF8, 0x00, 0x00, 0x02]);

            let got = display_answer(&question, &store, &mut efivars.reader());

            assert_eq!(got, want, "GUID {guid:02X?}");
        }
    }

    /// An unmatched ONE_OF default is the number that its Flags, those of a NUMERIC (UEFI
    /// 2.10 §33.3.8.3.50), display, as for a NUMERIC default.
    #[test]
    fn unmatched_one_of_default_is_displayed_as_its_flags_say() {
        let cases = [
            (
                "12-bit INT_DEC over 2047",
                BIT_VARSTORE_GUID,
                0x0C,
                3000,
                "3000",
            ),
            (
                "12-bit INT_DEC all ones",
                BIT_VARSTORE_GUID,
                0x0C,
                u32::MAX,
                "4095",
            ),
            (
                "32-bit INT_DEC all ones",
                BIT_VARSTORE_GUID,
                0x20,
                u32::MAX,
                "-1",
            ),
            (
                "32-bit UINT_DEC all ones",
                BIT_VARSTORE_GUID,
                0x60,
                u32::MAX,
                "4294967295",
            ),
            // Flags 0x02: UINT32 INT_DEC; 0x12: UINT32 UINT_DEC
            ("UINT32 INT_DEC all ones", OTHER_GUID, 0x02, u32::MAX, "-1"),
            (
                "UINT32 UINT_DEC all ones",
                OTHER_GUID,
                0x12,
                u32::MAX,
                "4294967295",
            ),
        ];
        for (name, guid, flags, default, number) in cases {
            let children = [
                one_of_option(5, 0x02, &0u32.to_le_bytes()),
                uint32_default(0x0000, default),
            ];
            assert_eq!(
                answer_in_guid(
                    guid,
                    ONE_OF,
                    &uint32_range_question(0, flags),
                    &children,
                    unavailable()
                ),
                format!("{UNAVAILABLE} <IFR default: {number} (no matching option)>"),
                "{name}"
            );
        }
    }

    /// A readable EDKII bit varstore field shows the value in its bits, without its default.
    #[test]
    fn readable_bit_field_question_shows_its_value() {
        // bits 4 to 15: 0xC8D; bits 4 and 5: 1
        let store = || var_store_of(&[0xD0, 0xC8, 0x0C, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        let one_of_children = || {
            vec![
                one_of_option(5, 0x02, &0u32.to_le_bytes()),
                one_of_option(6, 0x02, &1u32.to_le_bytes()),
                uint32_default(0x0000, 0),
            ]
        };
        let cases = [
            (
                "12-bit UINT_DEC NUMERIC",
                NUMERIC,
                uint32_range_question(4, 0x4C),
                vec![uint32_default(0x0000, 200)],
                "3213",
            ),
            ("CHECKBOX", CHECKBOX, checkbox(4, 0x01), vec![], "1"),
            (
                "2-bit UINT_DEC ONE_OF",
                ONE_OF,
                uint32_range_question(4, 0x42),
                one_of_children(),
                "Enabled",
            ),
        ];
        for (name, op_code, data, children, want) in cases {
            assert_eq!(
                answer_in_guid(BIT_VARSTORE_GUID, op_code, &data, &children, store()),
                want,
                "{name}"
            );
        }
    }

    /// A bit-field ONE_OF default is cut to the width in its Flags before it is matched to an
    /// option.
    #[test]
    fn bit_field_one_of_default_is_cut_to_its_width() {
        let children = [
            one_of_option(5, 0x02, &0u32.to_le_bytes()),
            one_of_option(6, 0x02, &1u32.to_le_bytes()),
            uint32_default(0x0000, 0b101),
        ];
        assert_eq!(
            answer_in_guid(
                BIT_VARSTORE_GUID,
                ONE_OF,
                &uint32_range_question(4, UINT_DEC | 2),
                &children,
                unavailable()
            ),
            format!("{UNAVAILABLE} <IFR default: Enabled>"),
            "default 0b101 of a 2-bit ONE_OF"
        );
    }

    /// A bit field's value is its width in bits from its bit VarOffset, as edk2-stable202608
    /// Setup.c GetBitsQuestionValue reads it, whatever the other bits of its bytes hold; a
    /// field over the 4 bytes that GetBitsQuestionValue copies into a UINT32 has none.
    #[test]
    fn bit_field_values_are_read_from_their_bits() {
        let payload = [0x6C, 0xBB, 0x15, 0xAF, 0xD7, 0x86];
        // at bits 8, 9 and 15, from Python's int.from_bytes(payload, "little")
        let cases = [
            (1, ["1", "1", "1"]),
            (3, ["3", "5", "3"]),
            (4, ["11", "13", "11"]),
            (12, ["1467", "2781", "3627"]),
            (17, ["71099", "101085", "89643"]),
            (18, ["202171", "232157", "220715"]),
            (19, ["464315", "494301", "482859"]),
            (
                32,
                [
                    "3618575803",
                    "<ValueUnavailable: EDKII bit field of width 32 at bit 9 spans more than 4 \
                     bytes>",
                    "<ValueUnavailable: EDKII bit field of width 32 at bit 15 spans more than 4 \
                     bytes>",
                ],
            ),
        ];
        for (width, wants) in cases {
            for (offset, want) in [8, 9, 15].into_iter().zip(wants) {
                let data = uint32_range_question(offset, UINT_DEC | width);
                assert_eq!(
                    answer_in_guid(
                        BIT_VARSTORE_GUID,
                        NUMERIC,
                        &data,
                        &[],
                        var_store_of(&payload)
                    ),
                    want,
                    "width {width} at bit {offset}"
                );
            }
        }
    }

    /// An INT_DEC bit field is signed from the type that edk2-stable202608 IfrParse.c gives
    /// it by its StorageWidth, as ProcessOptions.c shows it; its UINT32 IFR default is not.
    #[test]
    fn int_dec_bit_field_is_signed_by_its_storage_width() {
        let cases = [
            ("8-bit at bit 0, in UINT8", 0, 8, vec![0xFF], "-1"),
            ("8-bit at bit 4, in UINT16", 4, 8, vec![0xF0, 0x0F], "255"),
            ("16-bit at bit 0, in UINT16", 0, 16, vec![0xFF, 0xFF], "-1"),
            ("4-bit at bit 0, in UINT8", 0, 4, vec![0x0F], "15"),
            (
                "24-bit at bit 0, in UINT32",
                0,
                24,
                vec![0xFF; 3],
                "16777215",
            ),
            ("32-bit at bit 0, in UINT32", 0, 32, vec![0xFF; 4], "-1"),
        ];
        let default = [uint32_default(0x0000, 0xFF)];
        for (name, offset, width, payload, want) in cases {
            // Flags: EDKII_IFR_DISPLAY_INT_DEC_BIT
            let data = uint32_range_question(offset, width);
            assert_eq!(
                answer_in_guid(
                    BIT_VARSTORE_GUID,
                    NUMERIC,
                    &data,
                    &default,
                    var_store_of(&payload)
                ),
                want,
                "{name}"
            );
        }
        assert_eq!(
            answer_in_guid(
                BIT_VARSTORE_GUID,
                NUMERIC,
                &uint32_range_question(0, 8),
                &default,
                unavailable()
            ),
            format!("{UNAVAILABLE} <IFR default: 255>"),
            "8-bit default"
        );
    }

    /// A bit field of width 0 or over 32, which edk2 VfrCompile does not emit, has neither a
    /// value nor a default, and gives its width as the reason before any store error.
    #[test]
    fn bit_field_width_outside_1_to_32_has_no_value() {
        for (width, flags) in [(0, UINT_DEC), (33, UINT_DEC | 33)] {
            let reason = format!("EDKII bit-field width {width}, not 1 to 32");
            assert_eq!(
                answer_in_guid(
                    BIT_VARSTORE_GUID,
                    NUMERIC,
                    &uint32_range_question(0, flags),
                    &[],
                    var_store_of(&[0xFF; 8])
                ),
                format!("<ValueUnavailable: {reason}>"),
                "width {width}"
            );
            assert_eq!(
                numeric_in_guid_answer(BIT_VARSTORE_GUID, flags, 1),
                format!("<ValueUnavailable: {reason}> <IFR default: unknown ({reason})>"),
                "width {width} without a store"
            );
        }
    }

    /// A ONE_OF bit field of width 33 shows its default as unknown for its width, unless the
    /// default itself is unknown, whose reason shows instead.
    #[test]
    fn one_of_bit_field_width_33_default_is_unknown() {
        let reason = "EDKII bit-field width 33, not 1 to 32";
        let cases = [
            (
                "constant DEFAULT",
                uint32_default(0x0000, 1),
                format!("<ValueUnavailable: {reason}> <IFR default: unknown ({reason})>"),
            ),
            (
                "non-constant DEFAULT_2",
                ifr_default_2(0x0000, eq_id_val()),
                format!(
                    "<ValueUnavailable: {reason}> <IFR default: unknown (EFI_IFR_VALUE \
                     expression not evaluated: EqIdVal of question 0x0001: \
                     <ValueUnavailable: {reason}>)>"
                ),
            ),
        ];
        for (name, default, want) in cases {
            assert_eq!(
                answer_in_guid(
                    BIT_VARSTORE_GUID,
                    ONE_OF,
                    &uint32_range_question(0, UINT_DEC | 33),
                    &[default],
                    unavailable()
                ),
                want,
                "{name}"
            );
        }
    }

    /// The Range of the NUMERIC or ONE_OF `question`.
    fn question_range(question: &IFROperation) -> &Range {
        match &question.parsed_data {
            ParsedOperation::Numeric(parsed) => &parsed.data,
            ParsedOperation::OneOf(parsed) => &parsed.data,
            other => panic!("not a NUMERIC or ONE_OF: {other:?}"),
        }
    }

    /// A NUMERIC or ONE_OF at VarOffset 0 with `flags` and the MinValue, MaxValue and Step of
    /// `range`, in its size.
    fn range_question(flags: u8, range: &Range) -> Vec<u8> {
        let values = match range {
            Range::Range8(r) => [r.min_value, r.max_value, r.step]
                .map(u8::to_le_bytes)
                .concat(),
            Range::Range16(r) => [r.min_value, r.max_value, r.step]
                .map(u16::to_le_bytes)
                .concat(),
            Range::Range32(r) => [r.min_value, r.max_value, r.step]
                .map(u32::to_le_bytes)
                .concat(),
            Range::Range64(r) => [r.min_value, r.max_value, r.step]
                .map(u64::to_le_bytes)
                .concat(),
        };
        [question_header(0), vec![flags], values].concat()
    }

    /// An EDKII bit varstore field's Range is UINT32, whatever its width in Flags.
    #[test]
    fn bit_field_range_is_uint32() {
        let want = Range::Range32(Range32 {
            min_value: 0,
            max_value: 300,
            step: 1,
        });
        let cases = [
            ("3-bit UINT_DEC", 0x43),
            ("19-bit UINT_HEX", 0x93),
            ("19-bit INT_DEC", 0x13),
            ("1-bit UINT_DEC", 0x41),
            ("17-bit UINT_DEC", 0x51),
            ("12-bit UINT_DEC", 0x4C),
            ("zero width", 0x40),
            ("33-bit width", 0x61),
        ];
        for op_code in [NUMERIC, ONE_OF] {
            for (name, flags) in cases {
                let data = range_question(flags, &want);
                let (_root, question) =
                    try_parse_question_in_guid(BIT_VARSTORE_GUID, op_code, &data, &[])
                        .unwrap_or_else(|e| panic!("parse {name}, op {op_code:#04x}: {e:#}"));

                assert_eq!(
                    question_range(&question.borrow()),
                    &want,
                    "{name}, op {op_code:#04x}"
                );
            }
        }
    }

    /// A question outside an EDKII bit varstore field's GUID has the Range size of
    /// EFI_IFR_NUMERIC_SIZE, also right after such a field and in another GUID.
    #[test]
    fn non_bit_field_range_has_efi_ifr_numeric_size() {
        let want = Range::Range64(Range64 {
            min_value: 0,
            max_value: 1 << 40,
            step: 1,
        });
        let data = range_question(0x13, &want); // UINT64 UINT_DEC
        let bit_field = [
            operation(GUID, true, &BIT_VARSTORE_GUID),
            operation(NUMERIC, true, &uint32_range_question(0, 0x42)),
            END.to_vec(), // End of the NUMERIC
            END.to_vec(), // End of the GUID
        ]
        .concat();
        let cases = [("alone", vec![]), ("after a bit field", vec![bit_field])];
        for op_code in [NUMERIC, ONE_OF] {
            for (name, declarations) in &cases {
                let (_root, question) = try_parse_question(declarations, op_code, &data, &[])
                    .unwrap_or_else(|e| panic!("parse {name}, op {op_code:#04x}: {e:#}"));

                assert_eq!(
                    question_range(&question.borrow()),
                    &want,
                    "{name}, op {op_code:#04x}"
                );
            }

            let (_root, question) = try_parse_question_in_guid(OTHER_GUID, op_code, &data, &[])
                .unwrap_or_else(|e| panic!("parse other GUID, op {op_code:#04x}: {e:#}"));

            assert_eq!(
                question_range(&question.borrow()),
                &want,
                "other GUID, op {op_code:#04x}"
            );
        }
    }

    /// Reserved Flags bits 2-3 do not change the Range size that EFI_IFR_NUMERIC_SIZE gives.
    #[test]
    fn reserved_flags_bits_do_not_change_range_size() {
        let uint8 = Range::Range8(Range8 {
            min_value: 0,
            max_value: 10,
            step: 1,
        });
        let uint16 = Range::Range16(Range16 {
            min_value: 0,
            max_value: 300,
            step: 1,
        });
        let uint32 = Range::Range32(Range32 {
            min_value: 0,
            max_value: 300,
            step: 1,
        });
        let uint64 = Range::Range64(Range64 {
            min_value: 0,
            max_value: 1 << 40,
            step: 1,
        });
        let cases = [
            ("UINT8", 0x00, &uint8),
            ("UINT8 with reserved bit 2", 0x04, &uint8),
            ("UINT16", 0x01, &uint16),
            ("UINT16 with reserved bit 2", 0x05, &uint16),
            ("UINT32", 0x02, &uint32),
            ("UINT32 with reserved bits 2-3", 0x0E, &uint32),
            ("UINT64", 0x03, &uint64),
            ("UINT64 with reserved bit 2", 0x07, &uint64),
            ("UINT64 with reserved bits 2-3", 0x0F, &uint64),
        ];
        for op_code in [NUMERIC, ONE_OF] {
            for (name, flags, want) in cases {
                let data = range_question(flags, want);
                let (_root, question) = try_parse_question(&[], op_code, &data, &[])
                    .unwrap_or_else(|e| panic!("parse {name}, op {op_code:#04x}: {e:#}"));

                assert_eq!(
                    question_range(&question.borrow()),
                    want,
                    "{name}, op {op_code:#04x}"
                );
            }
        }
    }
}

// display returns a String which is our tree like representation of a FormSet
// TODO: show the default of an unreadable OneOf, Numeric or CheckBox, as list_questions does.
// TODO: show the state that the conditions give each question and option, as list-questions
// does.
pub fn display(
    node: Rc<RefCell<IFROperation>>,
    level: usize,
    string_packages: &[BTreeMap<i32, String>],
    reader: &mut EfivarReader,
) -> Result<String> {
    let mut result = String::new();
    walk_scopes(std::slice::from_ref(&node), level, |node, &level| {
        display_op(node, level, string_packages, reader, &mut result)
    });
    Ok(result)
}

/// Appends the line of `node` that display shows `level` scopes down to `result`, and enters its
/// scope unless edk2 skips it.
fn display_op(
    node: &Rc<RefCell<IFROperation>>,
    level: usize,
    string_packages: &[BTreeMap<i32, String>],
    reader: &mut EfivarReader,
    result: &mut String,
) -> Walk<usize> {
    let extra_spaces = "    ".repeat(level);

    let current_node = node.borrow();
    if let IFROpCode::Unknown(code) = current_node.op_code {
        if skips_scope(&current_node) {
            result.push_str(&format!(
                "{extra_spaces}OpCode: Unknown({code:#04x}) - skipped, as edk2 does\n"
            ));
            return Walk::Skip;
        }
    }

    match &current_node.parsed_data {
        ParsedOperation::Placeholder => {
            // every op that handle_form_set parses has a parent; the root has none
            if current_node.parent.is_none() {
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
                parsed.name,
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
            let varstore =
                find_corresponding_varstore(Rc::clone(node), parsed.question_header().var_store_id);
            let answer_disp = display_answer(&current_node, &varstore, reader);

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
            let varstore =
                find_corresponding_varstore(Rc::clone(node), parsed.question_header().var_store_id);
            let answer_disp = display_answer(&current_node, &varstore, reader);

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
            let varstore =
                find_corresponding_varstore(Rc::clone(node), parsed.question_header().var_store_id);
            let answer_disp = display_answer(&current_node, &varstore, reader);

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

    Walk::Enter(level + 1)
}

/// Returns the answer that show-ifr shows: the question's value, or why it cannot be read.
fn display_answer(
    question: &IFROperation,
    varstore: &Result<Box<dyn VariableStore>>,
    reader: &mut EfivarReader,
) -> String {
    match read_question_value(question, varstore, reader) {
        Err(reason) => reason.to_answer(),
        Ok((_, value)) => value.to_string(),
    }
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
    #[error("setting EDKII bit-field values is not supported")]
    UnsupportedBitField,
    #[error("cannot set question {question:?}: {reason}")]
    NoVarStore { question: String, reason: String },
    #[error(transparent)]
    Selection(#[from] SelectionError),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

/// set's write of a value at VarOffset `offset` of `store`: `encoded`, its little-endian bytes,
/// which fit in the Size of `store`.
struct VarStoreWrite<'a> {
    store: &'a dyn VariableStore,
    offset: u16,
    encoded: Vec<u8>,
}

impl<'a> VarStoreWrite<'a> {
    /// The write of `value` at VarOffset `offset` of `store`, through variables of `interface`:
    /// fails unless `value` is a number that fits in the Size of `store` there.
    fn new(
        store: &'a dyn VariableStore,
        offset: u16,
        value: TypeValue,
        interface: VariableInterface,
    ) -> Result<Self> {
        let encoded = match value {
            TypeValue::NumSize8(value) => value.to_le_bytes().to_vec(),
            TypeValue::NumSize16(value) => value.to_le_bytes().to_vec(),
            TypeValue::NumSize32(value) => value.to_le_bytes().to_vec(),
            TypeValue::NumSize64(value) => value.to_le_bytes().to_vec(),
            TypeValue::Boolean(_)
            | TypeValue::Time(_)
            | TypeValue::Date(_)
            | TypeValue::StringID(_)
            | TypeValue::Other
            | TypeValue::Undefined
            | TypeValue::Action(_)
            | TypeValue::Ref(_)
            | TypeValue::Unknown(_) => {
                return Err(anyhow!("unsupported value type for {}", interface.write()))
            }
        };
        if usize::from(offset) + encoded.len() > usize::from(store.size()) {
            return Err(anyhow!(
                "write at offset {} with width {} exceeds varstore size {}",
                offset,
                encoded.len(),
                store.size()
            ));
        }
        Ok(Self {
            store,
            offset,
            encoded,
        })
    }

    /// Writes the value through `variables`. choice_for_set is the only check of runtime access
    /// before a write: it refuses a variable without EFI_VARIABLE_RUNTIME_ACCESS that the
    /// selection read, and set writes only questions whose variable the selection read. Firmware
    /// refuses such a write if the variable changed since that read (edk2-stable202608
    /// VariableServiceSetVariable, EFI_WRITE_PROTECTED).
    fn write(&self, variables: &dyn FirmwareVariables) -> Result<()> {
        variables
            .write_at(
                &self.store.variable_key(),
                self.store.size(),
                self.offset,
                &self.encoded,
            )
            .map_err(|error| {
                VariableNotExported::explain(
                    error,
                    self.store,
                    variables.reach(),
                    variables.interface(),
                )
            })
    }
}

/// The write that sets `question` to `new_value` through variables of `interface`; for a ONE_OF,
/// to the option of that text that select_option picks without --include.
fn value_write<'a>(
    question: &'a QuestionDescriptor,
    new_value: &str,
    interface: VariableInterface,
) -> Result<VarStoreWrite<'a>, ChangeValueError> {
    // writes take VarOffset in bytes
    let ValueLocation::Bytes { offset, .. } = question.location else {
        return Err(ChangeValueError::UnsupportedBitField);
    };
    let store = question.store()?;
    if question.opcode == IFROpCode::OneOf {
        let option = question
            .select_option(
                &BTreeSet::from([new_value.to_owned()]),
                IncludedStates::empty(),
            )?
            .ok_or(ChangeValueError::InvalidOption)?;
        return option_write(question, option, interface);
    }
    let value = match &question.numeric_range {
        Some(range) => range.parse_value(new_value)?,
        None => match question.max_value {
            RangeType::NumSize8(m) => {
                let data_to_write = new_value
                    .parse::<u8>()
                    .context("value should fit in a u8")?;
                if data_to_write > m {
                    return Err(ChangeValueError::ExceededMaxValue);
                }
                TypeValue::NumSize8(data_to_write)
            }
            RangeType::NumSize16(m) => {
                let data_to_write = new_value
                    .parse::<u16>()
                    .context("value should fit in a u16")?;
                if data_to_write > m {
                    return Err(ChangeValueError::ExceededMaxValue);
                }
                TypeValue::NumSize16(data_to_write)
            }
            RangeType::NumSize32(m) => {
                let data_to_write = new_value
                    .parse::<u32>()
                    .context("value should fit in a u32")?;
                if data_to_write > m {
                    return Err(ChangeValueError::ExceededMaxValue);
                }
                TypeValue::NumSize32(data_to_write)
            }
            RangeType::NumSize64(m) => {
                let data_to_write = new_value
                    .parse::<u64>()
                    .context("value should fit in a u64")?;
                if data_to_write > m {
                    return Err(ChangeValueError::ExceededMaxValue);
                }
                TypeValue::NumSize64(data_to_write)
            }
        },
    };
    Ok(VarStoreWrite::new(store, offset, value, interface)?)
}

/// The write of `option`, one of the possible_options of the ONE_OF `question`, through
/// variables of `interface`.
fn option_write<'a>(
    question: &'a QuestionDescriptor,
    option: &AnswerOption,
    interface: VariableInterface,
) -> Result<VarStoreWrite<'a>, ChangeValueError> {
    // writes take VarOffset in bytes
    let ValueLocation::Bytes { offset, .. } = question.location else {
        return Err(ChangeValueError::UnsupportedBitField);
    };
    Ok(VarStoreWrite::new(
        question.store()?,
        offset,
        option.raw_value,
        interface,
    )?)
}

/// Sets each of the `selected` questions, by the selector of its package list, to `new_value`
/// or to its option of one of `texts` that chosen_option picks with `include`, in `variables`,
/// and returns one option per selected question, in its order; None for a value; fails with
/// SelectionError::NotFound when nothing is selected.
/// It builds every VarStoreWrite before the first write, so that a value that one question
/// refuses leaves every variable unchanged; then it writes each, also after a failed one, and
/// fails unless every write succeeds: with the error of a single write unchanged, else with
/// NotSetEverywhere.
pub(crate) fn set_questions<'a>(
    question: &str,
    selected: &[(&str, &'a QuestionDescriptor)],
    new_value: &str,
    texts: &BTreeSet<String>,
    include: IncludedStates,
    variables: &WithholdingVariables<impl FirmwareVariables>,
) -> Result<Vec<Option<&'a AnswerOption>>> {
    if selected.is_empty() {
        return Err(SelectionError::NotFound {
            question: question.to_owned(),
        }
        .into());
    }
    let writes = selected
        .iter()
        .map(|&(selector, descriptor)| {
            // if the descriptor provides options then set the closest one from texts
            // (example whatever matches from [Enabled, Enable])
            // else try setting the new_value because it might be some arbitrary value like a number
            // (will return error if doesn't match constraints)
            let interface = variables.interface();
            if descriptor.possible_options.is_empty() {
                return Ok((
                    selector,
                    value_write(descriptor, new_value, interface)?,
                    None,
                ));
            }
            let option = descriptor.chosen_option(texts, include)?;
            Ok((
                selector,
                option_write(descriptor, option, interface)?,
                Some(option),
            ))
        })
        .collect::<Result<Vec<_>>>()?;

    if let [(_, write, option)] = writes.as_slice() {
        write.write(variables)?;
        return Ok(vec![*option]);
    }
    let mut written = Vec::new();
    let mut failed = Vec::new();
    for (selector, write, _) in &writes {
        match write.write(variables) {
            Ok(()) => written.push(selector.to_string()),
            Err(error) => failed.push((*selector, error)),
        }
    }
    if !failed.is_empty() {
        return Err(NotSetEverywhere::new(question, failed, written).into());
    }
    Ok(writes.into_iter().map(|(_, _, option)| option).collect())
}

/// set's error when a write fails while set writes several questions: each Failure, and the
/// selectors written.
#[derive(Error, Debug)]
#[error(
    "question {question:?} was not set everywhere: {}",
    outcome(.failures, .written)
)]
struct NotSetEverywhere {
    question: String,
    failures: Vec<Failure>,
    written: Vec<String>,
}

/// A distinct error of NotSetEverywhere, with the selectors whose writes failed with it.
#[derive(Debug)]
struct Failure {
    error: String,
    selectors: Vec<String>,
}

/// The text of NotSetEverywhere after the question: `failures`, then the selectors `written`.
fn outcome(failures: &[Failure], written: &[String]) -> String {
    let failures: Vec<String> = failures
        .iter()
        .map(|Failure { error, selectors }| format!("{error} (in {})", selectors.join(", ")))
        .collect();
    let written = match written {
        [] => "none".to_owned(),
        _ => written.join(", "),
    };
    format!("{}; written in: {written}", failures.join("; "))
}

impl NotSetEverywhere {
    /// The error of `question`, whose writes `failed` by selector, and were `written` by the
    /// others: each error is named once.
    fn new(question: &str, failed: Vec<(&str, anyhow::Error)>, written: Vec<String>) -> Self {
        let mut failures: Vec<Failure> = Vec::new();
        for (selector, error) in failed {
            let error = format!("{error:#}");
            match failures.iter_mut().find(|failure| failure.error == error) {
                Some(failure) => failure.selectors.push(selector.to_owned()),
                None => failures.push(Failure {
                    error,
                    selectors: vec![selector.to_owned()],
                }),
            }
        }
        Self {
            question: question.to_owned(),
            failures,
            written,
        }
    }
}

#[cfg(test)]
#[cfg(efivar_dumps)]
mod set_questions_tests {
    use super::ifr_fixtures::*;
    use super::*;

    const WRITE_ERROR: WriteError = WriteError {
        cause: "write failed",
        context: None,
    };

    /// A CHECKBOX at VarOffset `offset` of `var_store`, as set sees it.
    fn checkbox_at(offset: u16, var_store: VarStoreFixture) -> QuestionDescriptor {
        let (_root, node) = parse_question(&[], CHECKBOX, &checkbox(offset, 0x00), &[]);
        question_descriptor(&node, var_store)
    }

    /// A CHECKBOX on `var_store`, as set sees it.
    fn checkbox_on_store(var_store: VarStoreFixture) -> QuestionDescriptor {
        checkbox_at(0, var_store)
    }

    /// A UINT8 NUMERIC shown unsigned (EFI_IFR_DISPLAY_UINT_DEC) from 0 to `maximum` on
    /// `var_store`, as set sees it.
    fn numeric_on_store(maximum: u8, var_store: VarStoreFixture) -> QuestionDescriptor {
        let (_root, node) = parse_question(&[], NUMERIC, &uint8_numeric(0x10, 0, maximum), &[]);
        question_descriptor(&node, var_store)
    }

    /// A UINT8 ONE_OF with the one option `option` on `var_store`, as set sees it.
    fn one_of_on_store(option: Vec<u8>, var_store: VarStoreFixture) -> QuestionDescriptor {
        let (_root, node) = parse_question(&[], ONE_OF, &one_of_data(), &[option]);
        question_descriptor(&node, var_store)
    }

    /// An EDKII bit varstore field `op_code` with `data` and `children` on `var_store`, as set
    /// sees it.
    fn bit_field_on_store(
        op_code: u8,
        data: &[u8],
        children: &[Vec<u8>],
        var_store: VarStoreFixture,
    ) -> QuestionDescriptor {
        let (_root, node) = parse_question_in_guid(BIT_VARSTORE_GUID, op_code, data, children);
        question_descriptor(&node, var_store)
    }

    /// set_questions of PROMPT to `new_value`, or to an option of the texts `texts`, in
    /// `variables`: the texts of the options written, or the error as the CLI prints it.
    fn set_options(
        variables: &MemoryVariables,
        selected: &[(&str, &QuestionDescriptor)],
        new_value: &str,
        texts: &[&str],
    ) -> std::result::Result<Vec<Option<String>>, String> {
        set_questions(
            PROMPT,
            selected,
            new_value,
            &texts.iter().map(|text| text.to_string()).collect(),
            IncludedStates::empty(),
            &WithholdingVariables::new(variables, BTreeSet::new()),
        )
        .map(|options| {
            options
                .into_iter()
                .map(|option| option.map(|option| option.value.clone()))
                .collect()
        })
        .map_err(|error| format!("{error:#}"))
    }

    /// set_questions of PROMPT to `new_value` in `variables`, its error as the CLI prints it.
    fn set(
        variables: &MemoryVariables,
        selected: &[(&str, &QuestionDescriptor)],
        new_value: &str,
    ) -> std::result::Result<(), String> {
        set_options(variables, selected, new_value, &[]).map(drop)
    }

    /// The writes to the variable `name`.
    fn writes(variables: &MemoryVariables, name: &str) -> Vec<(u16, Vec<u8>)> {
        variables.writes_to(&variable_key(name))
    }

    #[test]
    fn every_match_is_written() {
        let variables = MemoryVariables::default();
        let a = checkbox_on_store(writable_var_store("A", &[0], &variables));
        let b = checkbox_on_store(writable_var_store("B", &[0], &variables));

        assert_eq!(set(&variables, &[("A", &a), ("B", &b)], "1"), Ok(()), "set");
        assert_eq!(writes(&variables, "A"), [(0, vec![1])], "writes of A");
        assert_eq!(writes(&variables, "B"), [(0, vec![1])], "writes of B");
    }

    #[test]
    fn no_match_is_not_found() {
        assert_eq!(
            set(&MemoryVariables::default(), &[], "1"),
            Err("no question \"Prompt\" in the HiiDB".to_string()),
            "no selected question"
        );
    }

    #[test]
    fn the_options_written_follow_the_matches() {
        let variables = MemoryVariables::default();
        let a = one_of_on_store(
            flagged_option(6, 0x00, 1),
            writable_var_store("A", &[0], &variables),
        );
        let b = one_of_on_store(
            flagged_option(5, 0x00, 2),
            writable_var_store("B", &[0], &variables),
        );

        assert_eq!(
            set_options(
                &variables,
                &[("A", &a), ("B", &b)],
                "",
                &["Enabled", "Disabled"]
            ),
            Ok(vec![
                Some("Enabled".to_string()),
                Some("Disabled".to_string())
            ]),
            "A's option Enabled, then B's option Disabled"
        );
        assert_eq!(writes(&variables, "A"), [(0, vec![1])], "writes of A");
        assert_eq!(writes(&variables, "B"), [(0, vec![2])], "writes of B");
    }

    #[test]
    fn a_failed_write_fails_set_after_the_other_writes() {
        let mut variables = MemoryVariables::default();
        let a = checkbox_on_store(failing_var_store("A", WRITE_ERROR, &mut variables));
        let b = checkbox_on_store(writable_var_store("B", &[0], &variables));

        assert_eq!(
            set(&variables, &[("A", &a), ("B", &b)], "1"),
            Err(
                "question \"Prompt\" was not set everywhere: write failed (in A); written in: B"
                    .to_string()
            ),
            "set"
        );
        assert_eq!(
            writes(&variables, "B"),
            [(0, vec![1])],
            "writes of B after A failed"
        );
    }

    #[test]
    fn the_failed_write_of_a_single_match_is_its_error() {
        let mut variables = MemoryVariables::default();
        let a = checkbox_on_store(failing_var_store("A", WRITE_ERROR, &mut variables));

        assert_eq!(
            set(&variables, &[("A", &a)], "1"),
            Err(WRITE_ERROR.cause.to_string()),
            "one match"
        );
    }

    #[test]
    fn a_value_that_one_match_refuses_writes_no_match() {
        let variables = MemoryVariables::default();
        let a = numeric_on_store(200, writable_var_store("A", &[0], &variables));
        let b = numeric_on_store(100, writable_var_store("B", &[0], &variables));

        assert_eq!(
            set(&variables, &[("A", &a), ("B", &b)], "150"),
            Err("provided value exceeded max possible value".to_string()),
            "150, above the maximum of B"
        );
        assert_eq!(writes(&variables, "A"), [], "writes of A");
        assert_eq!(writes(&variables, "B"), [], "writes of B");
    }

    #[test]
    fn a_write_that_the_ifr_of_one_match_refuses_writes_no_match() {
        let variables = MemoryVariables::default();
        let a = checkbox_on_store(writable_var_store("A", &[0], &variables));
        let boolean_option = one_of_on_store(
            one_of_option(6, 0x04, &[1]),
            writable_var_store("Boolean", &[0], &variables),
        );
        let past_the_var_store = checkbox_at(1, writable_var_store("Short", &[0], &variables));
        // 8-bit UINT_DEC fields at bit 0: writes take VarOffset in bytes
        let bit_field_numeric = bit_field_on_store(
            NUMERIC,
            &uint32_range_question(0, 0x48),
            &[],
            writable_var_store("NumericBits", &[0; 4], &variables),
        );
        let bit_field_one_of = bit_field_on_store(
            ONE_OF,
            &uint32_range_question(0, 0x48),
            &[one_of_option(6, 0x02, &1u32.to_le_bytes())],
            writable_var_store("OneOfBits", &[0; 4], &variables),
        );
        let cases = [
            (
                "B's option of Type BOOLEAN",
                &boolean_option,
                "unsupported value type for efivarfs write",
                "Boolean",
            ),
            (
                "B at VarOffset 1 of its 1-byte VarStore",
                &past_the_var_store,
                "write at offset 1 with width 1 exceeds varstore size 1",
                "Short",
            ),
            (
                "B an EDKII bit-field NUMERIC",
                &bit_field_numeric,
                "setting EDKII bit-field values is not supported",
                "NumericBits",
            ),
            (
                "B's option of an EDKII bit-field ONE_OF",
                &bit_field_one_of,
                "setting EDKII bit-field values is not supported",
                "OneOfBits",
            ),
        ];
        for (case, b, error, b_variable) in cases {
            assert_eq!(
                set_options(&variables, &[("A", &a), ("B", b)], "1", &["Enabled"]),
                Err(error.to_string()),
                "{case}"
            );
            assert_eq!(writes(&variables, "A"), [], "writes of A, {case}");
            assert_eq!(writes(&variables, b_variable), [], "writes of B, {case}");
        }
    }

    /// set refuses an option of a type that it does not write in the words of the interface of
    /// its variables, whatever their reach, and writes nothing.
    #[test]
    fn unsupported_option_is_refused_in_the_words_of_its_interface() {
        for (reach, interface, write) in [
            (
                VariableReach::Runtime,
                VariableInterface::Efivarfs,
                "efivarfs write",
            ),
            (
                VariableReach::Runtime,
                VariableInterface::FirmwareEnvironment,
                "SetFirmwareEnvironmentVariableExW write",
            ),
            (
                VariableReach::BootServices,
                VariableInterface::Efivarfs,
                "efivarfs write",
            ),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
                "SetVariable() write",
            ),
        ] {
            let variables = MemoryVariables::new(reach, interface);
            let boolean_option = one_of_on_store(
                one_of_option(6, 0x04, &[1]),
                writable_var_store("Boolean", &[0], &variables),
            );
            let case = format!("{reach:?}, {interface:?}");

            assert_eq!(
                set_options(&variables, &[("B", &boolean_option)], "1", &["Enabled"]),
                Err(format!("unsupported value type for {write}")),
                "{case}"
            );
            assert_eq!(writes(&variables, "Boolean"), [], "{case}: writes");
        }
    }

    #[test]
    fn each_failure_is_named_once() {
        const FIRST: WriteError = WriteError {
            cause: "first failure",
            context: None,
        };
        const SECOND: WriteError = WriteError {
            cause: "second failure",
            context: None,
        };
        const CHAINED: WriteError = WriteError {
            cause: "permission denied",
            context: Some("failed to write"),
        };
        let cases = [
            (
                "one error",
                [WRITE_ERROR, WRITE_ERROR, WRITE_ERROR],
                "write failed (in A, B, C)",
            ),
            (
                "two errors",
                [FIRST, SECOND, FIRST],
                "first failure (in A, C); second failure (in B)",
            ),
            (
                "an error in a context",
                [CHAINED, WRITE_ERROR, CHAINED],
                "failed to write: permission denied (in A, C); write failed (in B)",
            ),
        ];
        for (case, [a_error, b_error, c_error], failures) in cases {
            let mut variables = MemoryVariables::default();
            let [a, b, c] =
                [("A", a_error), ("B", b_error), ("C", c_error)].map(|(name, error)| {
                    checkbox_on_store(failing_var_store(name, error, &mut variables))
                });
            assert_eq!(
                set(&variables, &[("A", &a), ("B", &b), ("C", &c)], "1"),
                Err(format!(
                    "question \"Prompt\" was not set everywhere: {failures}; written in: none"
                )),
                "{case}"
            );
        }
    }
}

fn find_corresponding_string(string_id: u16, string_packages: &[BTreeMap<i32, String>]) -> &str {
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

    let mut node = node;
    loop {
        let parent = {
            let current_node = node.borrow();
            if current_node.op_code == IFROpCode::FormSet {
                return form_set_varstore(&current_node, var_store_id);
            }
            match current_node.parent.as_ref() {
                Some(parent_ref) => match parent_ref.upgrade() {
                    Some(parent_ref_rc) => parent_ref_rc,
                    None => return Err(anyhow!("could not upgrade parent_ref Weak<> to get Rc<>")),
                },
                None => return Err(anyhow!("varstore not found because we reached root")),
            }
        };
        node = parent;
    }
}

/// Returns the varstore of `var_store_id` among the children of `form_set`.
fn form_set_varstore(form_set: &IFROperation, var_store_id: u16) -> Result<Box<dyn VariableStore>> {
    // look at its children

    for child in &form_set.children {
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
    Err(anyhow!(
        "no supported varstore with matching id {:#06x} found",
        var_store_id
    ))
}

#[cfg(test)]
#[cfg(efivar_dumps)]
mod tests {
    use super::ifr_fixtures::*;
    use super::*;
    use crate::hii::efivarfs_format::open_efivar;
    use crate::hii::efivarfs_format::read_efivarfs_bytes;
    use crate::hii::efivarfs_format::EfivarFileName;

    /// find_question_in finds a question by the name that list_questions prints, whose leading
    /// and trailing whitespace the prompt string keeps, and by that name with other surrounding
    /// whitespace or ASCII case.
    #[test]
    fn questions_are_found_by_their_listed_name() {
        let root = parse_form_set(&[form(1, &[checkbox_op(1, 0)])]);
        let values = VarStoreValues::new(&root, None);
        let prompted = |prompt: &str| vec![BTreeMap::from([(3, prompt.to_string())])];
        let find = |prompt: &str, phrase: &str| {
            find_question_in(
                &root,
                &BTreeSet::from([phrase]),
                &mut FormSetWalk::new(
                    &prompted(prompt),
                    &mut Efivars::new().reader(),
                    &values,
                    IncludedStates::empty(),
                ),
            )
            .map(|_| ())
        };
        let listed = list_questions(
            Rc::clone(&root),
            &prompted("  Prompt "),
            IncludedStates::empty(),
            None,
            &mut Efivars::new().reader(),
        );
        let name = &listed[0].0.question;
        assert_eq!(name, "  Prompt ", "listed name");

        let cases = [
            ("  Prompt ", name.as_str()),
            ("  Prompt ", "Prompt"),
            ("  Prompt ", " PROMPT"),
            (" ", ""),
            (" ", " "),
        ];
        for (prompt, phrase) in cases {
            assert_eq!(
                find(prompt, phrase),
                Selection::Picked((), StateEvaluation::selectable()),
                "prompt {prompt:?}, phrase {phrase:?}"
            );
        }
        assert_eq!(
            find("  Prompt ", "Prompt 2"),
            Selection::NotFound,
            "another name"
        );
    }

    /// select_option takes an option by the text that get shows, which is the option's string
    /// trimmed, by that string as stored, and by either with other surrounding whitespace or
    /// ASCII case. When some option's string is the text as stored, ignoring ASCII case, it
    /// takes only such an option.
    #[test]
    fn options_are_selected_by_the_text_that_get_shows() {
        let options = [
            flagged_option(5, 0x00, 0),
            flagged_option(PADDED_ENABLED, 0x00, 1),
        ];
        let (_root, question) = parse_question(&[], ONE_OF, &one_of_data(), &options);
        let shown = question_descriptor(&question, var_store_of(&[1]));
        assert_eq!(shown.value, "Enabled", "the text get shows");
        assert_eq!(
            shown.listed_options(IncludedStates::empty()),
            ["Disabled", "Enabled "],
            "listed options"
        );
        let select = |question: &QuestionDescriptor, text: &str| {
            question
                .select_option(&BTreeSet::from([text.to_string()]), IncludedStates::empty())
                .unwrap_or_else(|error| panic!("select {text:?}: {error}"))
                .map(|option| option.value.clone())
        };

        for text in [shown.value.as_str(), "Enabled ", " enabled"] {
            assert_eq!(
                select(&shown, text).as_deref(),
                Some("Enabled "),
                "{text:?}"
            );
        }
        assert_eq!(select(&shown, "Enable"), None, "another text");

        let enabled = flagged_option(6, 0x00, 2);
        let padded = flagged_option(PADDED_ENABLED, 0x00, 1);
        let orders = [
            ("padded first", [padded.clone(), enabled.clone()]),
            ("padded last", [enabled, padded]),
        ];
        for (order, options) in orders {
            let (_root, question) = parse_question(&[], ONE_OF, &one_of_data(), &options);
            let twins = question_descriptor(&question, var_store_of(&[1]));
            for (text, want) in [
                ("Enabled", "Enabled"),
                ("Enabled ", "Enabled "),
                ("enabled", "Enabled"),
            ] {
                assert_eq!(
                    select(&twins, text).as_deref(),
                    Some(want),
                    "{order}: {text:?}"
                );
            }
        }
    }

    /// set writes each integer width at the end of its VarStore, through FirmwareVariables, which
    /// keep the attributes word and the other bytes.
    #[test]
    fn writes_each_integer_width_at_end_of_varstore() {
        let store = efi_variable("Test", 42);
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
            let variables = MemoryVariables::default();
            variables.insert(store.variable_key(), NV_BS_RT, &[0xa5; 42]);
            let mut expected = variables
                .bytes(&store.variable_key())
                .expect("the bytes of Test");
            let offset = 42 - encoded.len();
            expected[EFIVARFS_HEADER_SIZE + offset..].copy_from_slice(&encoded);
            let write = VarStoreWrite::new(
                &store,
                u16::try_from(offset).expect("offset fits u16"),
                data,
                variables.interface(),
            )
            .unwrap_or_else(|error| panic!("write {data:?} at offset {offset}: {error}"));
            assert_eq!(write.encoded, encoded, "{data:?}");

            write
                .write(&variables)
                .unwrap_or_else(|error| panic!("write {data:?} at offset {offset}: {error:#}"));

            assert_eq!(
                variables.bytes(&store.variable_key()),
                Some(expected),
                "{data:?}"
            );
        }
    }

    /// set refuses a VarStore whose variable is shorter than its Size, also where the value
    /// fits, and writes nothing.
    #[test]
    fn write_of_a_variable_shorter_than_its_var_store_is_refused() {
        let store = efi_variable("Short", 4);
        let variables = MemoryVariables::default();
        variables.insert(store.variable_key(), NV_BS_RT, &[0; 2]);
        let write = VarStoreWrite::new(&store, 0, TypeValue::NumSize8(1), variables.interface())
            .expect("write 1");

        let error = write
            .write(&variables)
            .expect_err("write a variable shorter than its VarStore");

        assert_eq!(
            error.to_string(),
            "efivarfs payload is shorter than the declared varstore: 2 < 4 bytes",
            "refusal"
        );
        assert_eq!(variables.writes_to(&store.variable_key()), [], "writes");
    }

    /// set of a VarStore whose variable is missing explains why it cannot write it.
    #[test]
    fn write_of_a_missing_variable_is_explained_as_not_exported() {
        let store = efi_variable("Setup", 1);
        let write = VarStoreWrite::new(
            &store,
            0,
            TypeValue::NumSize8(1),
            VariableInterface::Efivarfs,
        )
        .expect("write 1");

        let error = write
            .write(&MemoryVariables::default())
            .expect_err("write a missing variable");

        assert!(
            error.downcast_ref::<VariableNotExported>().is_some(),
            "{error:#} is not VariableNotExported"
        );
    }

    #[test]
    fn rejects_writes_past_declared_size() {
        for (size, offset, data, width) in [
            (42, 42, TypeValue::NumSize8(1), 1),
            (42, 41, TypeValue::NumSize16(1), 2),
            (42, 39, TypeValue::NumSize32(1), 4),
            (42, 35, TypeValue::NumSize64(1), 8),
            (0, 0, TypeValue::NumSize8(1), 1),
            (42, u16::MAX, TypeValue::NumSize64(1), 8),
        ] {
            let store = efi_variable("Test", size);
            assert_eq!(
                VarStoreWrite::new(&store, offset, data, VariableInterface::Efivarfs)
                    .map(drop)
                    .map_err(|error| error.to_string()),
                Err(format!(
                    "write at offset {offset} with width {width} exceeds varstore size {size}"
                )),
                "{data:?} at offset {offset} of {size} bytes"
            );
        }
    }

    #[test]
    fn rejects_unsupported_value_instead_of_silent_noop() {
        assert_eq!(
            VarStoreWrite::new(
                &efi_variable("Test", 42),
                0,
                TypeValue::Boolean(true),
                VariableInterface::Efivarfs
            )
            .map(drop)
            .map_err(|error| error.to_string()),
            Err("unsupported value type for efivarfs write".to_string()),
            "BOOLEAN"
        );
    }

    /// set's error for a missing variable follows the interface of its variables: efivarfs as on
    /// Linux, the firmware environment calls as on Windows, GetVariable() as in the UEFI Shell,
    /// whose variables would find any variable the firmware has created.
    #[test]
    fn variable_not_exported_follows_its_interface() {
        let cases = [
            (
                VariableReach::Runtime,
                VariableInterface::Efivarfs,
                "no EFI variable Setup-00000000-0000-0000-0000-000000000000: the firmware has not \
                 created it or does not expose it to the OS, so its questions cannot be set from \
                 Linux; change them in the firmware setup, or ask the board vendor for firmware \
                 that exposes it; see https://github.com/linuxboot/uefisettings/issues/2",
            ),
            (
                VariableReach::Runtime,
                VariableInterface::FirmwareEnvironment,
                "no EFI variable Setup-00000000-0000-0000-0000-000000000000: the firmware has not \
                 created it or does not expose it to the OS, so its questions cannot be set from \
                 Windows; change them in the firmware setup, or ask the board vendor for firmware \
                 that exposes it; see https://github.com/linuxboot/uefisettings/issues/2",
            ),
            (
                VariableReach::BootServices,
                VariableInterface::VariableServices,
                "no EFI variable Setup-00000000-0000-0000-0000-000000000000: the firmware has \
                 not created it, and set never creates variables",
            ),
        ];
        for (reach, interface, want) in cases {
            let variables = MemoryVariables::new(reach, interface);
            let store = efi_variable("Setup", 1);
            let write =
                VarStoreWrite::new(&store, 0, TypeValue::NumSize8(1), interface).expect("write 1");

            let error = write
                .write(&variables)
                .expect_err("write a missing variable");

            assert_eq!(error.to_string(), want, "{interface:?}");
        }
    }

    /// A write of an unsupported value names the write of its variables: efivarfs, or
    /// SetVariable() in the UEFI Shell.
    #[test]
    fn unsupported_value_names_the_write_of_its_interface() {
        for (interface, want) in [
            (
                VariableInterface::Efivarfs,
                "unsupported value type for efivarfs write",
            ),
            (
                VariableInterface::VariableServices,
                "unsupported value type for SetVariable() write",
            ),
        ] {
            assert_eq!(
                VarStoreWrite::new(
                    &efi_variable("Test", 42),
                    0,
                    TypeValue::Boolean(true),
                    interface
                )
                .map(drop)
                .map_err(|error| error.to_string()),
                Err(want.to_string()),
                "{interface:?}"
            );
        }
    }

    #[test]
    fn read_efivarfs_bytes_includes_attributes_and_complete_payload() {
        let payload = 95u16.to_le_bytes();
        let mut efivarfs_data = 7u32.to_le_bytes().to_vec();
        efivarfs_data.extend_from_slice(&payload);

        let mut reader = Cursor::new(&efivarfs_data);
        let bytes = read_efivarfs_bytes(&mut reader, payload.len()).unwrap();

        assert_eq!(bytes, efivarfs_data);
        assert_eq!(stored_value(&bytes[EFIVARFS_HEADER_SIZE..]), 95);
    }

    #[test]
    fn missing_efivar_is_explained_as_not_exported() {
        let key = VariableKey {
            name: "Setup".to_string(),
            guid: Guid {
                data1: 0xec87d643,
                data2: 0xeba4,
                data3: 0x4bb5,
                data4: [0xa1, 0xe5, 0x3f, 0x3e, 0x36, 0xb2, 0x0d, 0xa9],
            },
        };

        let error = VariableNotExported::explain(
            VariableNotFound(key).into(),
            &efi_variable("Setup", 1),
            VariableReach::Runtime,
            VariableInterface::Efivarfs,
        );

        assert!(
            error.downcast_ref::<VariableNotExported>().is_some(),
            "{error:#} is not VariableNotExported"
        );
        assert_eq!(
            format!("{error:#}"),
            "no EFI variable Setup-ec87d643-eba4-4bb5-a1e5-3f3e36b20da9: the firmware has not \
             created it or does not expose it to the OS, so its questions cannot be set from \
             Linux; change them in the firmware setup, or ask the board vendor for firmware that \
             exposes it; see https://github.com/linuxboot/uefisettings/issues/2",
            "message of the missing variable"
        );
    }

    /// The missing variable of a form that declares it boot-service-only is explained by that
    /// declaration, not as not exported.
    #[test]
    fn missing_efivar_of_a_boot_service_only_form_is_explained_by_its_declaration() {
        let store = DeclaredVarStore {
            runtime_accessible: false,
            ..efi_variable("Setup", 1)
        };

        let error = VariableNotExported::explain(
            VariableNotFound(store.variable_key()).into(),
            &store,
            VariableReach::Runtime,
            VariableInterface::Efivarfs,
        );

        assert!(
            error.downcast_ref::<VariableNotExported>().is_none(),
            "{error:#} is VariableNotExported"
        );
        assert_eq!(
            format!("{error:#}"),
            "EFI variable Setup-00000000-0000-0000-0000-000000000000 is not present at OS \
             runtime: efivarfs does not list it, and its form declares it boot-service-only \
             (no EFI_VARIABLE_RUNTIME_ACCESS)",
            "message of the missing variable"
        );
    }

    #[test]
    fn other_efivar_open_failure_is_not_explained_as_not_exported() {
        // ENOTDIR: the directory is a regular file
        let not_a_dir = tempfile::NamedTempFile::new().expect("create a file");
        let name = EfivarFileName::new("Setup", NIL_GUID);

        let open_error = open_efivar(not_a_dir.path(), &name).expect_err("open below a file");
        let expected = format!("{open_error:#}");

        let error = VariableNotExported::explain(
            open_error,
            &efi_variable("Setup", 1),
            VariableReach::Runtime,
            VariableInterface::Efivarfs,
        );

        assert!(
            error.downcast_ref::<VariableNotExported>().is_none(),
            "{error:#} is VariableNotExported"
        );
        assert_eq!(
            format!("{error:#}"),
            expected,
            "message of the open failure below a file"
        );
        assert_eq!(
            error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .map(std::io::Error::kind),
            Some(std::io::ErrorKind::NotADirectory),
            "root cause of the open failure below a file"
        );
    }

    /// An IFR operation Length below the header size is rejected as an
    /// invalid length before binrw computes the size of the operation's data
    /// from it.
    #[test]
    fn operation_length_below_header_size_is_an_error() {
        for length in [0, IFR_OPERATION_HEADER_SIZE - 1] {
            let data = vec![0x0E, length]; // FormSet
            let mut cursor = Cursor::new(&data);

            let err = format!("{:#}", handle_form_set(&mut cursor).unwrap_err());

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

        let err = format!("{:#}", handle_form_set(&mut cursor).unwrap_err());

        let want = "invalid IFR operation length 0 at 0x";
        assert!(err.contains(want), "{}", err);
    }

    /// An End that returns to an IFR op with opcode 0xFF, which is also the root's
    /// DUMMY_OPCODE, does not end the FormSet: the ops after that op's scope are parsed.
    #[test]
    fn end_back_in_an_opcode_0xff_scope_does_not_end_the_form_set() {
        let data = form_set(&[form(
            1,
            &[
                operation(DUMMY_OPCODE, true, &[]),
                form(2, &[]), // its End returns to the opcode 0xFF op
                END.to_vec(), // End of the opcode 0xFF op
                checkbox_op(1, 0),
            ],
        )]);
        let mut cursor = Cursor::new(&data);

        let root = handle_form_set(&mut cursor).expect("parse the FormSet");

        let root = root.borrow();
        assert_eq!(root.children.len(), 1, "FormSets");
        let form_set = root.children[0].borrow();
        assert_eq!(form_set.children.len(), 1, "Forms");
        let form = form_set.children[0].borrow();
        let op_codes: Vec<IFROpCode> = form.children.iter().map(|op| op.borrow().op_code).collect();
        assert_eq!(
            op_codes,
            [IFROpCode::Unknown(DUMMY_OPCODE), IFROpCode::CheckBox],
            "ops of the Form"
        );
        assert_eq!(
            cursor.position(),
            u64::try_from(data.len()).expect("length"),
            "bytes read"
        );
    }

    /// display shows the root as ROOT, and not an IFR op with opcode 0xFF, the root's
    /// DUMMY_OPCODE.
    #[test]
    fn display_shows_only_the_root_as_root() {
        let root = parse_form_set(&[form(1, &[operation(DUMMY_OPCODE, false, &[])])]);

        let shown = display(root, 0, &strings(), &mut disabled_reader()).expect("display");

        let roots: Vec<&str> = shown
            .lines()
            .filter(|line| line.trim() == "OpCode: ROOT")
            .collect();
        assert_eq!(roots, ["OpCode: ROOT"], "ROOT lines of {shown:?}");
    }

    /// display shows an op whose scope edk2 skips on one line, and nothing in that scope.
    #[test]
    fn display_skips_an_unknown_opcode_scope() {
        let skipped_scope = [operation(0x70, true, &[]), checkbox_op(2, 1), END.to_vec()].concat();
        let root = parse_form_set(&[form(1, &[checkbox_op(1, 0), skipped_scope])]);

        let shown = display(root, 0, &strings(), &mut disabled_reader()).expect("display");

        let check_boxes = shown
            .lines()
            .filter(|line| line.trim().starts_with("OpCode: CheckBox "))
            .count();
        assert_eq!(check_boxes, 1, "CheckBox lines of {shown:?}");
        let unknown: Vec<&str> = shown
            .lines()
            .filter(|line| line.trim().starts_with("OpCode: Unknown"))
            .collect();
        assert_eq!(
            unknown,
            ["            OpCode: Unknown(0x70) - skipped, as edk2 does"],
            "Unknown lines of {shown:?}"
        );
    }

    /// The ops in the scope of an opcode above EFI_IFR_MATCH2_OP, nested ones too, are not
    /// decoded, so a malformed one does not fail the FormSet; in a known opcode's scope
    /// it still does.
    #[test]
    fn ops_in_an_unknown_opcode_scope_are_not_decoded() {
        let in_scope = |op_code: u8| {
            let short_checkbox = operation(CHECKBOX, false, &[0x00]); // 1 of its data bytes
            let scope = [
                operation(op_code, true, &[0x00; 16]),
                operation(0x02, true, &[0x05, 0x00, 0x06, 0x00, 0x00]), // Subtitle
                short_checkbox.clone(),
                END.to_vec(), // End of Subtitle
                short_checkbox,
                END.to_vec(), // End of op_code
            ];
            form_set(&[form(
                1,
                &[
                    scope.concat(),
                    operation(op_code, false, &[]),
                    checkbox_op(1, 0),
                ],
            )])
        };

        for op_code in [0x65, 0x70, 0xFF] {
            let data = in_scope(op_code);
            let root = handle_form_set(&mut Cursor::new(&data)).unwrap_or_else(|error| {
                panic!("parse the scope of opcode {op_code:#x}: {error:#}")
            });

            let root = root.borrow();
            let form = Rc::clone(&root.children[0].borrow().children[0]);
            let scope = Rc::clone(&form.borrow().children[0]);
            let subtitle = Rc::clone(&scope.borrow().children[0]);
            let undecoded = [
                ("in the Subtitle", Rc::clone(&subtitle.borrow().children[0])),
                ("after the Subtitle", Rc::clone(&scope.borrow().children[1])),
            ];
            for (place, checkbox) in undecoded {
                assert!(
                    matches!(checkbox.borrow().parsed_data, ParsedOperation::Placeholder),
                    "opcode {op_code:#x}: the CheckBox {place} is not decoded"
                );
            }
            let after = Rc::clone(&form.borrow().children[2]);
            assert!(
                matches!(after.borrow().parsed_data, ParsedOperation::CheckBox(_)),
                "opcode {op_code:#x}: the CheckBox after the scope is decoded"
            );
        }

        let data = in_scope(GUID);
        let error = handle_form_set(&mut Cursor::new(&data)).expect_err("GUID scope");
        assert!(
            format!("{error:#}").contains("failed to parse CheckBox's data"),
            "GUID scope: {error:#}"
        );
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

        let root = handle_form_set(&mut cursor).unwrap();

        let root = root.borrow();
        assert_eq!(root.children.len(), 1);
        let form_set = root.children[0].borrow();
        assert_eq!(form_set.op_code, IFROpCode::FormSet);
        assert!(form_set.children.is_empty());
    }
}

#[cfg(test)]
#[cfg(efivar_dumps)]
mod write_validation_tests {
    use super::ifr_fixtures::*;
    use super::*;

    /// The buffer VarStore NumericTest of 42 bytes, whose efivar file holds `payload`, and
    /// variables that hold it too, for set to write there.
    fn numeric_test_store(payload: &[u8]) -> (VarStoreFixture, MemoryVariables) {
        let store = buffer("NumericTest", 42);
        let variables = MemoryVariables::default();
        variables.insert(store.variable_key(), NV_BS_RT, payload);
        let efivars = Efivars::new();
        efivars.write(&store, payload);
        let fixture = VarStoreFixture {
            store: Ok(Box::new(store)),
            efivars,
        };
        (fixture, variables)
    }

    /// The writes to NumericTest.
    fn writes(variables: &MemoryVariables) -> Vec<(u16, Vec<u8>)> {
        variables.writes_to(&variable_key("NumericTest"))
    }

    fn numeric_question(
        bits: u32,
        minimum: u64,
        maximum: u64,
        step: u64,
        display: u8,
        initial: u64,
    ) -> (QuestionDescriptor, MemoryVariables) {
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
            location: ValueLocation::Bytes {
                offset: 2,
                size: range.size(),
            },
            data: range,
        };
        let node = RefCell::new(IFROperation {
            op_code: IFROpCode::Numeric,
            length: 0,
            open_scope: false,
            data: Vec::new(),
            parent: None,
            children: Vec::new(),
            parsed_data: ParsedOperation::Numeric(parsed),
        });
        let mut payload = vec![0; 42];
        let width = (bits / 8) as usize;
        payload[2..2 + width].copy_from_slice(&initial.to_le_bytes()[..width]);
        let (VarStoreFixture { store, efivars }, variables) = numeric_test_store(&payload);
        let current = node.borrow();
        let ParsedOperation::Numeric(parsed) = &current.parsed_data else {
            panic!("not a NUMERIC: {:?}", current.parsed_data);
        };
        let question = handle_numeric(
            store,
            parsed,
            "Numeric test",
            &current,
            &mut FormSetWalk::new(
                &[],
                &mut efivars.reader(),
                &MapValues(BTreeMap::new()),
                IncludedStates::empty(),
            ),
        );
        (question, variables)
    }

    fn encoded_value(bits: u32, value: i128) -> Vec<u8> {
        let width = usize::try_from(bits / 8).expect("a byte width fits usize");
        value.to_le_bytes()[..width].to_vec()
    }

    #[test]
    fn rejects_unsigned_out_of_range_values_before_writing() {
        for bits in [8, 16, 32, 64] {
            let (question, variables) = numeric_question(bits, 10, 20, 2, 0x10, 10);
            assert!(matches!(
                change_value(&question, "9", &variables),
                Err(ChangeValueError::BelowMinValue)
            ));
            assert!(matches!(
                change_value(&question, "21", &variables),
                Err(ChangeValueError::ExceededMaxValue)
            ));
            for value in [
                "-1",
                "not-a-number",
                "340282366920938463463374607431768211455",
            ] {
                assert!(change_value(&question, value, &variables).is_err());
            }
            assert!(writes(&variables).is_empty());
        }
    }

    #[test]
    fn accepts_unsigned_boundaries_and_does_not_treat_step_as_a_constraint() {
        for bits in [8, 16, 32, 64] {
            for step in [0, 2] {
                for display in [0x10, 0x20] {
                    let (question, variables) = numeric_question(bits, 10, 20, step, display, 10);
                    for value in [10, 11, 20] {
                        let changed = change_value(&question, &value.to_string(), &variables);
                        if let Err(error) = changed {
                            panic!(
                                "set {value} at {bits} bits, step {step}, display {display:#x}: \
                                 {error}"
                            );
                        }
                    }
                    assert_eq!(
                        writes(&variables),
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
            let (question, variables) =
                numeric_question(bits, (-10i64) as u64, 10, 1, 0, (-3i64) as u64);
            assert_eq!(question.value, "-3");
            assert!(matches!(
                change_value(&question, "-11", &variables),
                Err(ChangeValueError::BelowMinValue)
            ));
            assert!(matches!(
                change_value(&question, "11", &variables),
                Err(ChangeValueError::ExceededMaxValue)
            ));
            assert!(writes(&variables).is_empty());
            for value in [-10, 0, 10] {
                change_value(&question, &value.to_string(), &variables)
                    .unwrap_or_else(|error| panic!("set {value} at {bits} bits: {error}"));
            }
            assert_eq!(
                writes(&variables),
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
            let (question, variables) =
                numeric_question(bits, minimum as u64, maximum as u64, 1, 0, 0);
            change_value(&question, &minimum.to_string(), &variables)
                .unwrap_or_else(|error| panic!("set {minimum} at {bits} bits: {error}"));
            change_value(&question, &maximum.to_string(), &variables)
                .unwrap_or_else(|error| panic!("set {maximum} at {bits} bits: {error}"));
            assert!(change_value(&question, &(minimum - 1).to_string(), &variables).is_err());
            assert!(change_value(&question, &(maximum + 1).to_string(), &variables).is_err());
            assert_eq!(writes(&variables).len(), 2);
        }
    }

    #[test]
    fn supports_unsigned_64_bit_values_above_signed_maximum() {
        let (question, variables) = numeric_question(64, u64::MAX - 2, u64::MAX, 1, 0x10, u64::MAX);
        assert_eq!(question.value, u64::MAX.to_string());
        change_value(&question, &u64::MAX.to_string(), &variables).expect("set u64::MAX");
        assert_eq!(
            writes(&variables),
            vec![(2, u64::MAX.to_le_bytes().to_vec())]
        );
        assert!(change_value(&question, "18446744073709551616", &variables).is_err());
        assert_eq!(writes(&variables).len(), 1);
    }

    #[test]
    fn rejects_invalid_numeric_ranges_without_writing() {
        for bits in [8, 16, 32, 64] {
            let (question, variables) = numeric_question(bits, 20, 10, 1, 0x10, 0);
            assert!(matches!(
                change_value(&question, "15", &variables),
                Err(ChangeValueError::InvalidNumericRange)
            ));
            assert!(writes(&variables).is_empty());
        }
    }

    /// set refuses an EDKII bit varstore field, with or without a VarStore, and writes nothing.
    #[test]
    fn bit_field_question_is_not_set() {
        let one_of_children = vec![
            one_of_option(5, 0x02, &0u32.to_le_bytes()),
            one_of_option(6, 0x02, &1u32.to_le_bytes()),
        ];
        let cases = [
            (
                "18-bit NUMERIC",
                NUMERIC,
                uint32_range_question(12, 0x52),
                vec![],
                "5",
                (12, 5u32.to_le_bytes().to_vec()),
            ),
            (
                "CHECKBOX",
                CHECKBOX,
                checkbox(3, 0x00),
                vec![],
                "1",
                (3, vec![1]),
            ),
            (
                "2-bit ONE_OF",
                ONE_OF,
                uint32_range_question(8, 0x42),
                one_of_children,
                "Enabled",
                (8, 1u32.to_le_bytes().to_vec()),
            ),
        ];
        for (name, op_code, data, children, value, write) in cases {
            let set = |guid, var_store, variables: &MemoryVariables| {
                let (_root, node) = parse_question_in_guid(guid, op_code, &data, &children);
                change_value(&question_descriptor(&node, var_store), value, variables)
            };

            let (store, variables) = numeric_test_store(&[0; 42]);
            let changed = set(BIT_VARSTORE_GUID, store, &variables);
            assert!(
                matches!(changed, Err(ChangeValueError::UnsupportedBitField)),
                "{name}, GUID {BIT_VARSTORE_GUID:02X?}: {changed:?}"
            );
            assert!(
                writes(&variables).is_empty(),
                "{name}, GUID {BIT_VARSTORE_GUID:02X?}"
            );

            let changed = set(BIT_VARSTORE_GUID, unavailable(), &variables);
            assert!(
                matches!(changed, Err(ChangeValueError::UnsupportedBitField)),
                "{name}, GUID {BIT_VARSTORE_GUID:02X?} without VarStore: {changed:?}"
            );

            // set writes a ONE_OF's option as change_option does, not as change_value does
            let (_root, node) =
                parse_question_in_guid(BIT_VARSTORE_GUID, op_code, &data, &children);
            let (store, variables) = numeric_test_store(&[0; 42]);
            let question = question_descriptor(&node, store);
            for option in &question.possible_options {
                let changed = change_option(&question, option, &variables);
                assert!(
                    matches!(changed, Err(ChangeValueError::UnsupportedBitField)),
                    "{name}: change_option {:?}: {changed:?}",
                    option.value
                );
            }
            assert!(writes(&variables).is_empty(), "{name}: change_option");

            let question = question_descriptor(&node, unavailable());
            for option in &question.possible_options {
                let changed = change_option(&question, option, &variables);
                assert!(
                    matches!(changed, Err(ChangeValueError::UnsupportedBitField)),
                    "{name}: change_option {:?} without VarStore: {changed:?}",
                    option.value
                );
            }

            let other_guid = OTHER_GUID;
            let (store, variables) = numeric_test_store(&[0; 42]);
            let changed = set(other_guid, store, &variables);
            assert!(
                matches!(changed, Ok(())),
                "{name}, GUID {other_guid:02X?}: {changed:?}"
            );
            assert_eq!(
                writes(&variables),
                [write],
                "{name}, GUID {other_guid:02X?}"
            );
        }
    }

    /// encode inverts decode on every stored value of both 8-bit formats, and refuses the
    /// numbers just outside their ranges, which the `as` casts it replaced wrapped.
    #[test]
    fn encode_inverts_decode_at_8_bits() {
        for signed_type_bits in [None, Some(8)] {
            let format = NumericFormat {
                bits: 8,
                signed_type_bits,
            };
            for stored in 0..=u64::from(u8::MAX) {
                let value = format.decode(stored);
                assert_eq!(
                    format.encode(value),
                    Some(stored),
                    "{signed_type_bits:?}, stored {stored}"
                );
            }
            let outside = match signed_type_bits {
                Some(_) => [-129, 128],
                None => [-1, 256],
            };
            for value in outside {
                assert_eq!(format.encode(value), None, "{signed_type_bits:?}, {value}");
            }
        }
    }

    #[test]
    fn encode_covers_64_bits() {
        let unsigned = NumericFormat {
            bits: 64,
            signed_type_bits: None,
        };
        let signed = NumericFormat {
            bits: 64,
            signed_type_bits: Some(64),
        };
        let cases = [
            (
                "unsigned u64::MAX",
                unsigned,
                i128::from(u64::MAX),
                Some(u64::MAX),
            ),
            ("unsigned -1", unsigned, -1, None),
            (
                "signed i64::MIN",
                signed,
                i128::from(i64::MIN),
                Some(1 << 63),
            ),
            ("signed -1", signed, -1, Some(u64::MAX)),
            ("signed u64::MAX", signed, i128::from(u64::MAX), None),
        ];
        for (name, format, value, want) in cases {
            assert_eq!(format.encode(value), want, "{name}");
        }
    }
}

#[cfg(test)]
#[cfg(efivar_dumps)]
mod nesting_tests {
    use super::conditions::evaluate_condition;
    use super::conditions::Truth;
    use super::ifr_fixtures::*;
    use super::*;

    /// IFR scopes nested in the trees that the walks below run on: a frame per scope would take
    /// far more than SMALL_STACK
    const DEEP: usize = 20_000;
    /// IFR scopes nested in the tree that display runs on: its text grows with the square of the
    /// depth, to 8 MB here, but a frame per scope would still take far more than SMALL_STACK
    const DISPLAY_DEEP: usize = 2_000;

    /// The strings of deep_form_set.
    fn deep_strings() -> Vec<BTreeMap<i32, String>> {
        vec![BTreeMap::from([
            (3, "Deep".to_string()),
            (4, "Help".to_string()),
            (5, "Hidden".to_string()),
        ])]
    }

    /// `op` opening a scope that holds `body`, with its End.
    fn with_scope(mut op: Vec<u8>, body: &[Vec<u8>]) -> Vec<u8> {
        op[1] |= 0x80;
        [op, body.concat(), END.to_vec()].concat()
    }

    /// The CHECKBOX "Deep" on VarStore 1.
    fn deep_checkbox() -> Vec<u8> {
        checkbox_on(1, 3, 1)
    }

    /// The CHECKBOX "Hidden" without a VarStore.
    fn hidden_checkbox() -> Vec<u8> {
        checkbox_on(2, 5, 0)
    }

    /// A FormSet of the VarStore 1 whose Form nests `depth` Subtitle scopes around: deep_checkbox
    /// holding `depth` nested LOCKED scopes; hidden_checkbox in a SUPPRESS_IF of TRUE holding
    /// `nots` nested NOTs; and, if `password`, a PASSWORD on VarStore 1.
    fn deep_form_set(depth: usize, nots: usize, password: bool) -> Vec<u8> {
        let not = operation(NOT, true, &[]);
        let condition = with_scope(operation(TRUE, false, &[]), &[nested(&not, nots, &[])]);
        let mut body = vec![
            with_scope(deep_checkbox(), &[nested(&locked_scope(), depth, &[])]),
            conditional(SUPPRESS_IF, condition, &[hidden_checkbox()]),
        ];
        if password {
            body.push(password_on(3, 3, 1, 0));
        }
        form_set(&[
            var_store(1, [0x22; 16], "Deep", 1),
            form(1, &[nested(&subtitle_scope(3), depth, &body)]),
        ])
    }

    /// The root of deep_form_set, parsed past MAX_SCOPE_NESTING.
    fn parse_deep(depth: usize, nots: usize, password: bool) -> Rc<RefCell<IFROperation>> {
        let ifr = deep_form_set(depth, nots, password);
        handle_form_set_within(&mut Cursor::new(&ifr), usize::MAX).expect("parse the FormSet")
    }

    /// The op of the tree of `root` whose data is that of the op `op`.
    fn op_like(root: &Rc<RefCell<IFROperation>>, op: &[u8]) -> Rc<RefCell<IFROperation>> {
        let data = op.get(2..).expect("an op past its header");
        find_op(root, data).expect("find the op")
    }

    /// The limit counts the scopes open at once, not every scope of a FormSet: MAX_SCOPE_NESTING
    /// + 1 sibling Subtitle scopes, each closed before the next, parse.
    #[test]
    fn scopes_that_close_do_not_count_toward_the_limit() {
        let siblings: Vec<Vec<u8>> = (0..=MAX_SCOPE_NESTING)
            .map(|_| nested(&subtitle_scope(3), 1, &[]))
            .collect();
        let root = handle_form_set(&mut Cursor::new(&form_set(&siblings)))
            .unwrap_or_else(|error| panic!("{} sibling scopes: {error:#}", siblings.len()));
        let form_set = Rc::clone(&root.borrow().children[0]);
        assert_eq!(
            form_set.borrow().children.len(),
            siblings.len(),
            "the sibling Subtitles"
        );
    }

    /// A FormSet nests up to MAX_SCOPE_NESTING scopes at once, its own and unknown ones counted;
    /// handle_form_set fails with ScopesTooDeep at the op that opens one more.
    #[test]
    fn scopes_nest_up_to_the_limit() {
        let unknown = operation(0x70, true, &[]);
        let form_set_op = form_set(&[]).len() - END.len();
        let subtitle_op = subtitle_scope(3).len();
        for in_unknown_scope in [false, true] {
            let outer = 1 + usize::from(in_unknown_scope);
            let ifr = |subtitles: usize| {
                let nested = nested(&subtitle_scope(3), subtitles, &[checkbox_op(1, 0)]);
                let body = match in_unknown_scope {
                    true => [unknown.clone(), nested, END.to_vec()].concat(),
                    false => nested,
                };
                form_set(&[body])
            };
            let case = format!("in an unknown scope: {in_unknown_scope}");

            let root = handle_form_set(&mut Cursor::new(&ifr(MAX_SCOPE_NESTING - outer)))
                .unwrap_or_else(|error| panic!("at the limit, {case}: {error:#}"));
            assert_eq!(
                op_like(&root, &checkbox_op(1, 0)).borrow().op_code,
                IFROpCode::CheckBox,
                "the op in the innermost scope at the limit, {case}"
            );

            let error = handle_form_set(&mut Cursor::new(&ifr(MAX_SCOPE_NESTING - outer + 1)))
                .expect_err("scopes past the limit");
            let past_limit = form_set_op
                + usize::from(in_unknown_scope) * unknown.len()
                + (MAX_SCOPE_NESTING - outer) * subtitle_op;
            assert_eq!(
                error.downcast_ref::<ScopesTooDeep>(),
                Some(&ScopesTooDeep {
                    offset: u64::try_from(past_limit).expect("a u64 offset"),
                    limit: MAX_SCOPE_NESTING,
                }),
                "past the limit, {case}: {error:#}"
            );
        }
    }

    /// The parser, every walk of the tree, Debug and Drop take the same stack however deep IFR
    /// scopes nest: on SMALL_STACK, through DEEP nested scopes (display DISPLAY_DEEP), each finds
    /// what lies at the bottom and nothing that does not.
    #[test]
    fn walks_take_a_stack_that_nesting_does_not_grow() {
        on_small_stack("handle_form_set", || {
            let root = parse_deep(DEEP, DEEP, true);
            let deep = op_like(&root, &deep_checkbox());
            assert_eq!(
                deep.borrow().children.len(),
                1,
                "the Deep CheckBox's LOCKED"
            );
        });

        on_small_stack("PasswordQuestions::of", || {
            for password in [true, false] {
                let declared = PasswordQuestions::of([&parse_deep(DEEP, DEEP, password)])
                    .check_set(VariableReach::BootServices, SetupPasswordPolicy::Refuse)
                    .is_err();
                assert_eq!(declared, password, "declares the PASSWORD at the bottom");
            }
        });

        on_small_stack("VarStoreValues::new", || {
            let root = parse_deep(DEEP, DEEP, false);
            let deep = op_like(&root, &deep_checkbox());
            let values = VarStoreValues::new(&root, None);
            let mut reader = disabled_reader();
            for (id, indexed) in [(1, true), (9, false)] {
                assert_eq!(
                    values.value(&deep.borrow(), id, &mut reader).is_some(),
                    indexed,
                    "question {id} indexed"
                );
            }
        });

        on_small_stack("list_questions", || {
            for (include, want) in [
                (IncludedStates::all(), &["Deep", "Hidden"][..]),
                (IncludedStates::empty(), &["Deep"][..]),
            ] {
                let listed = list_questions(
                    parse_deep(DEEP, DEEP, false),
                    &deep_strings(),
                    include,
                    None,
                    &mut disabled_reader(),
                );
                let names: Vec<String> = listed
                    .into_iter()
                    .map(|(question, _)| question.question)
                    .collect();
                assert_eq!(names, want, "questions listed of {include:?}");
            }
        });

        on_small_stack("find_question", || {
            for (name, want) in [("Deep", true), ("Hidden", false)] {
                let selection = find_question(
                    parse_deep(DEEP, DEEP, false),
                    &deep_strings(),
                    &BTreeSet::from([name]),
                    IncludedStates::empty(),
                    None,
                    &mut disabled_reader(),
                );
                assert_eq!(
                    matches!(selection, Selection::Picked(..)),
                    want,
                    "{name} picked: {selection:?}"
                );
            }
        });

        on_small_stack("question_scope", || {
            let root = parse_deep(DEEP, DEEP, false);
            let deep = op_like(&root, &deep_checkbox());
            let scope = question_scope(&deep.borrow());
            assert_eq!(
                scope.len(),
                DEEP,
                "the LOCKED ops in the Deep CheckBox's scope"
            );
        });

        on_small_stack("find_corresponding_varstore", || {
            let root = parse_deep(DEEP, DEEP, false);
            let deep = op_like(&root, &deep_checkbox());
            assert!(
                find_corresponding_varstore(Rc::clone(&deep), 1).is_ok(),
                "VarStore 1 found from the bottom"
            );
            let missing = find_corresponding_varstore(deep, 2)
                .err()
                .map(|error| error.to_string());
            assert_eq!(
                missing.as_deref(),
                Some("no supported varstore with matching id 0x0002 found"),
                "VarStore 2"
            );
        });

        on_small_stack("evaluate_condition", || {
            for (nots, want) in [(DEEP, true), (DEEP + 1, false)] {
                let root = parse_deep(1, nots, false);
                let hidden = op_like(&root, &hidden_checkbox());
                let suppress_if = hidden
                    .borrow()
                    .parent
                    .as_ref()
                    .and_then(Weak::upgrade)
                    .expect("the SUPPRESS_IF");
                let values = VarStoreValues::new(&root, None);
                let mut reader = disabled_reader();
                let mut inputs = ExpressionInputs {
                    reader: &mut reader,
                    values: &values,
                };
                assert_eq!(
                    evaluate_condition(&suppress_if.borrow(), &mut inputs),
                    Truth::Known(want),
                    "TRUE, then {nots} NOTs"
                );
            }
        });

        on_small_stack("Debug", || {
            let root = parse_deep(DEEP, DEEP, true);
            let printed = format!("{:?}", root.borrow());
            // the root, the FormSet, its VarStore and Form, the Subtitles, the Deep CheckBox and
            // its LOCKEDs, the SUPPRESS_IF, its TRUE and NOTs, Hidden and the PASSWORD
            assert_eq!(
                printed.matches("IFROperation {").count(),
                3 * DEEP + 9,
                "ops printed"
            );
            assert!(
                printed.starts_with(
                    "IFROperation { op_code: Unknown(255), open_scope: false, length: 0, children: \
                     [RefCell { value: IFROperation { op_code: FormSet, open_scope: true"
                ),
                "printed from the root: {}",
                printed.get(..200).unwrap_or(&printed)
            );
        });

        on_small_stack("Drop", || {
            let root = parse_deep(DEEP, DEEP, true);
            let deep = op_like(&root, &deep_checkbox());
            drop(root);
            let deep = deep.borrow();
            assert!(
                deep.parent.as_ref().and_then(Weak::upgrade).is_none(),
                "the Deep CheckBox's ancestors dropped"
            );
            assert_eq!(deep.children.len(), 1, "the Deep CheckBox's LOCKED kept");
        });

        on_small_stack("display", || {
            let root = parse_deep(DISPLAY_DEEP, 1, false);
            let shown = display(root, 0, &deep_strings(), &mut disabled_reader()).expect("display");
            // the root, the FormSet, the Form, then the Subtitles
            let want = format!(
                "{}OpCode: CheckBox - Q: - Deep - Help: - Help",
                "    ".repeat(DISPLAY_DEEP + 3)
            );
            assert!(
                shown.lines().any(|line| line == want),
                "the Deep CheckBox shown"
            );
            let subtitles = shown
                .lines()
                .filter(|line| line.trim_start() == "OpCode: Subtitle - S: Deep")
                .count();
            assert_eq!(subtitles, DISPLAY_DEEP, "the Subtitles shown");
        });
    }

    /// Debug prints what Debug derived for op_code, open_scope, length and children prints, as
    /// `{:?}` and as `{:#?}`, also for an op whose RefCell is borrowed mutably.
    #[test]
    fn debug_prints_as_derived_debug() {
        mod derived {
            use super::*;

            /// IFROperation's printed fields, with Debug derived
            #[derive(Debug)]
            #[expect(dead_code, reason = "Debug, which the test compares, reads them")]
            pub(super) struct IFROperation {
                op_code: IFROpCode,
                open_scope: bool,
                length: u8,
                pub(super) children: Vec<Rc<RefCell<IFROperation>>>,
            }

            /// `op`'s tree, recursively: its ops are few.
            pub(super) fn of(op: &super::IFROperation) -> IFROperation {
                IFROperation {
                    op_code: op.op_code,
                    open_scope: op.open_scope,
                    length: op.length,
                    children: op
                        .children
                        .iter()
                        .map(|child| Rc::new(RefCell::new(of(&child.borrow()))))
                        .collect(),
                }
            }
        }

        let root = parse_form_set(&[
            var_store(1, [0x22; 16], "Deep", 1),
            form(
                1,
                &[
                    nested(&subtitle_scope(3), 2, &[deep_checkbox()]),
                    [operation(0x70, true, &[]), END.to_vec()].concat(),
                ],
            ),
        ]);
        let want = derived::of(&root.borrow());
        assert_eq!(
            format!("{:?}", root.borrow()),
            format!("{want:?}"),
            "{{:?}}"
        );
        assert_eq!(
            format!("{:#?}", root.borrow()),
            format!("{want:#?}"),
            "{{:#?}}"
        );

        let form_set = Rc::clone(&root.borrow().children[0]);
        let form = Rc::clone(&form_set.borrow().children[1]);
        let want_form = Rc::clone(&want.children[0].borrow().children[1]);
        let _mutable = form.borrow_mut();
        let _want_mutable = want_form.borrow_mut();
        assert_eq!(
            format!("{:?}", root.borrow()),
            format!("{want:?}"),
            "{{:?}}, borrowed"
        );
        assert_eq!(
            format!("{:#?}", root.borrow()),
            format!("{want:#?}"),
            "{{:#?}}, borrowed"
        );
    }
}
