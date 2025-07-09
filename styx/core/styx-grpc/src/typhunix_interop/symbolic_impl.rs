// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//! typhunix object trait implementations

use styx_errors::styx_grpc::ApplicationError;
use symbolic::symbol;

use crate::symbolic::data_type::MetaType;
use crate::symbolic::symbol::SymbolType;
use crate::symbolic::{DataType, FileMetadata, Program, ProgramIdentifier};
use crate::typhunix_interop::*;

impl ProgramRef for ProgramIdentifier {
    fn get_program_key(&self) -> ProgKeyType {
        (self.source_id.to_owned(), self.name.to_owned())
    }
}

impl ProgramRef for ConnectMessage {
    fn get_program_key(&self) -> ProgKeyType {
        self.program.as_ref().unwrap().get_program_key()
    }
}

impl ProgramRef for Symbol {
    fn get_program_key(&self) -> ProgKeyType {
        self.pid.as_ref().unwrap().get_program_key()
    }
}

impl ProgramRef for DataType {
    fn get_program_key(&self) -> ProgKeyType {
        self.pid.as_ref().unwrap().get_program_key()
    }
}

impl ProgramRef for Program {
    fn get_program_key(&self) -> ProgKeyType {
        self.pid.as_ref().unwrap().get_program_key()
    }
}

impl std::fmt::Display for Program {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut s = String::new();
        s.push_str(&format!(
            "[{},{}]",
            self.get_program_name(),
            self.get_source_id()
        ));

        if self.metadata.is_some() {
            s.push_str(&format!("meta: [{}], ", self.metadata.as_ref().unwrap()));
        }
        s.push_str(&format!("Arch: [X], Funcs: {}, ", self.functions.len()));
        s.push_str(&format!("segs: {} ... ", self.segments.len()));
        write!(f, "{}", s)
    }
}

impl std::fmt::Display for ProgramIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut s = String::new();
        s.push_str(&format!("({},{})", self.source_id, self.name));
        write!(f, "{}", s)
    }
}

impl std::fmt::Display for FileMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut s = String::new();
        s.push_str(&format!("name: {}, loader: {}", self.name, self.loader));
        write!(f, "{}", s)
    }
}

impl std::fmt::Display for ConnectMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut s = String::new();
        let program = if self.program.is_some() {
            format!("{}", self.program.as_ref().unwrap())
        } else {
            String::new()
        };
        s.push_str("ConnectMessage");
        s.push_str(&program);
        s.push_str(&format!(", DataTypes[{}]", self.data_types.len()));
        s.push_str(&format!(", Symbols[{}]", self.symbols.len()));

        write!(f, "{}", s)
    }
}

impl std::fmt::Display for SymbolType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            SymbolType::SymbolClass => write!(f, "Class"),
            SymbolType::SymbolFunction => write!(f, "Function"),
            SymbolType::SymbolGlobal => write!(f, "Global"),
            SymbolType::SymbolGlobalVar => write!(f, "GlobalVar"),
            SymbolType::SymbolLabel => write!(f, "Label"),
            SymbolType::SymbolLibrary => write!(f, "Library"),
            SymbolType::SymbolLocalVar => write!(f, "LocalVar"),
            SymbolType::SymbolNamespace => write!(f, "Namespace"),
            SymbolType::SymbolParameter => write!(f, "Parameter"),
        }
    }
}

impl std::fmt::Display for DataType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut s = String::new();
        s.push_str(&format!("id: {}, ", self.id));
        s.push_str(&format!("name: {}, ", self.name));
        s.push_str(&format!("size: {}, ", self.size));
        s.push_str(&format!("type: {}, ", self.r#type()));
        s.push_str(&format!("offset: {}", self.offset));
        // if struct, show member count
        if self.r#type() == MetaType::TypeStruct {
            s.push_str(&format!(", #members: {}", self.children.len()));
        }

        let pref = match &self.pid {
            Some(pidval) => format!("{}", pidval),
            _ => "".to_string(),
        };
        s.push_str(&format!("...[pid: {}]", pref));
        write!(f, "{}", s)
    }
}

impl std::fmt::Display for Symbol {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let mut s = String::new();
        s.push_str(&format!("id:{}", self.id));
        s.push_str(&format!(", {}", self.r#type()));
        s.push_str(&format!(", nm:{}", self.name));
        s.push_str(&format!(", ty:{}", self.datatype_name));
        s.push_str(&format!(", adr:{:#010x}", self.address));
        s.push_str(&format!(", sz:{}", self.data_size));
        s.push_str(&format!(", ns:{}", self.namespace));
        let pref = match &self.pid {
            Some(pidval) => format!("{}", pidval),
            _ => "".to_string(),
        };
        s.push_str(&format!("[pid: {}]", pref));
        write!(f, "{}", s)
    }
}

impl std::fmt::Display for MetaType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            MetaType::TypeBasic => write!(f, "Basic"),
            MetaType::TypeStruct => write!(f, "Struct"),
            MetaType::TypeArray => write!(f, "Array"),
            MetaType::TypeUnion => write!(f, "Union"),
            MetaType::TypeEnum => write!(f, "Enum"),
            MetaType::TypeBitfield => write!(f, "BitField"),
        }
    }
}

impl Validator for ConnectMessage {
    /// Check if the ConnectMessage is valid
    fn is_valid(&self) -> bool {
        match self.program.as_ref() {
            Some(p) => p.is_valid(),
            _ => false,
        }
    }
}

impl Validator for Program {
    fn is_valid(&self) -> bool {
        match self.pid.as_ref() {
            Some(p) => p.is_valid(),
            _ => false,
        }
    }
}

impl Validator for Symbol {
    fn is_valid(&self) -> bool {
        self.id > 0
            && !self.namespace.is_empty()
            && !self.name.is_empty()
            && self.address >= 0
            && !(self.r#type() == symbol::SymbolType::SymbolFunction
                && self.function_symbol.is_none())
            && match self.pid.as_ref() {
                Some(p) => p.is_valid(),
                _ => false,
            }
    }
}

impl Validator for Function {
    fn is_valid(&self) -> bool {
        self.symbol.is_some() && self.symbol().function_symbol.is_some()
    }
}

/// Scrub the [ConnectMessage] removing any invalid items:  [Program], [Function],
/// [Symbol], [DataType].
///
/// Return an [ApplicationError] if it's unsalvageable.
pub async fn clean(mut msg: ConnectMessage) -> Result<ConnectMessage, ApplicationError> {
    let Some(ref mut program) = msg.program else {
        return Err(ApplicationError::InvalidRequest("Missing Program".into()));
    };
    let functions = program.functions.to_owned();
    let symbols = msg.symbols.to_owned();
    let data_types = msg.data_types.to_owned();
    program.functions.clear();
    msg.symbols.clear();
    msg.data_types.clear();

    functions.iter().filter(|i| i.is_valid()).for_each(|f| {
        program.functions.push(f.to_owned());
    });
    symbols.iter().filter(|i| i.is_valid()).for_each(|s| {
        msg.symbols.push(s.to_owned());
    });
    data_types.iter().filter(|i| i.is_valid()).for_each(|d| {
        msg.data_types.push(d.to_owned());
    });
    Ok(msg)
}

impl Validator for DataType {
    fn is_valid(&self) -> bool {
        self.id > 0
            && !self.name.is_empty()
            && match self.pid.as_ref() {
                Some(p) => p.is_valid(),
                _ => false,
            }
    }
}

impl Validator for ProgramIdentifier {
    fn is_valid(&self) -> bool {
        !self.source_id.is_empty() && !self.name.is_empty()
    }
}

/// Get a stub Program from a ProgramIdentifier
impl From<Program> for ProgramIdentifier {
    fn from(program: Program) -> Self {
        program.pid.unwrap()
    }
}

/// Extract the pid as new ProgramIdentifer
impl From<ProgramIdentifier> for Program {
    fn from(value: ProgramIdentifier) -> Self {
        Program {
            pid: Some(value),
            ..Default::default()
        }
    }
}

/// Create a new ProgramIdentifier from name and source_id
impl ProgramIdentifier {
    pub fn new(name: &str, source_id: &str) -> Self {
        Self {
            name: name.to_string(),
            source_id: source_id.to_string(),
        }
    }
}

impl HasFunctions for ConnectMessage {
    fn functions(&self) -> Vec<Function> {
        if let Some(ref program) = self.program {
            program.functions.to_vec()
        } else {
            vec![]
        }
    }
}

impl AddrUtils for Symbol {
    fn contains(&self, addr: u32) -> bool {
        addr >= self.addr_start() && addr <= self.addr_end()
    }

    fn addr_start(&self) -> u32 {
        self.address as u32
    }

    fn addr_end(&self) -> u32 {
        match self.r#type() {
            SymbolType::SymbolFunction => self.function_symbol.as_ref().unwrap().last_insn as u32,

            _ => (self.address + self.data_size) as u32,
        }
    }
}

impl SymbolUtils for Symbol {
    fn name(&self) -> String {
        self.name.to_string()
    }
    fn short_display(&self) -> String {
        format!("{:#010x} {}", self.addr_start(), self.name())
    }
}

impl AddrUtils for Function {
    fn contains(&self, addr: u32) -> bool {
        self.symbol().contains(addr)
    }
    fn addr_start(&self) -> u32 {
        self.symbol().addr_start()
    }
    fn addr_end(&self) -> u32 {
        self.symbol().addr_end()
    }
}
impl FuncUtils for Function {
    #[inline(always)]
    fn symbol(&self) -> &Symbol {
        let symbolic = self.symbol.as_ref().unwrap();
        symbolic
    }

    fn parameters(&self) -> Vec<FunctionParameter> {
        self.symbol()
            .function_symbol
            .as_ref()
            .unwrap()
            .parameters
            .to_vec()
    }
}

impl Signature for Function {
    fn signature(&self) -> String {
        let psig = self
            .parameters()
            .iter()
            .map(|p| p.signature())
            .collect::<Vec<String>>()
            .join(", ");
        format!("{}({})", self.symbol().name(), psig)
    }
}

impl Signature for FunctionParameter {
    fn signature(&self) -> String {
        format!("{} {}", self.data_type_name, self.name)
    }
}

/// Create ProgramIdentifier from tuple:
/// `(source_id: &str, name: &str)`
impl From<(&str, &str)> for ProgramIdentifier {
    fn from(value: (&str, &str)) -> Self {
        ProgramIdentifier {
            source_id: value.0.to_string(),
            name: value.1.to_string(),
        }
    }
}

impl Symbol {
    pub fn is_function(&self) -> bool {
        self.function_symbol.is_some()
    }
}
