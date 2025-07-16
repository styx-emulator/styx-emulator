// SPDX-License-Identifier: BSD-2-Clause
//! Abstractions representingf a program variable (struct, int, char, ...)

use crate::{compact_repr, event::AggregateEvent};
use log::warn;
use serde_json::json;
use std::mem::size_of;
use styx_core::grpc::{
    symbolic::{data_type::MetaType, symbol::SymbolType, DataType, Function, Symbol},
    traceapp::{
        ArrayRepr, BasicRepr, CStructMemberRepr, CStructRepr, CVarRepr, Interrupt, MemoryChange,
    },
    typhunix_interop::{AddrUtils, FuncUtils, SymbolUtils},
};
use styx_core::sync::sync::atomic::{AtomicU64, Ordering::SeqCst};
use styx_core::tracebus::{MemReadEvent, MemWriteEvent};
use tracing::trace;
use typhunix_proto::cache::SymbolCache;

/// The maximum number of memory overflow errors to store. We will stop storing,
/// but keep counting in [Variable]
const MAX_OVERFLOWS: usize = usize::MAX;

/// Abstraction for a program variable, composed of a [Symbol], a [DataType],
/// and allocated memory
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Variable {
    /// Symbol definition from decompiler/RE tool, ie Ghidra
    pub symbol: Symbol,
    /// Data type definition from decompiler/RE tool, ie Ghidra
    pub datatype: DataType,
    /// guest memory
    pub mem: Vec<u8>,
    /// statistic for the number of writes to the variable
    pub num_writes: AtomicU64,
    /// statistic for the number of reads to the variable
    pub num_reads: AtomicU64,
    /// Statistic for the number of buffer overflows encountered
    pub overflow_count: usize,
    /// memory overflow errors - stored as JSON
    pub mem_overflow_errors: Vec<serde_json::value::Value>,
}

impl Variable {
    pub fn new(symbol: &Symbol, datatype: &DataType) -> Self {
        Self {
            mem: vec![0; symbol.data_size as usize],
            symbol: symbol.clone(),
            datatype: datatype.clone(),
            num_writes: AtomicU64::new(0),
            num_reads: AtomicU64::new(0),
            mem_overflow_errors: vec![],
            overflow_count: 0,
        }
    }

    /// create a new variable to represent memory reads and writes for
    /// addresses that we do not have a symbol for
    pub fn anonymous(addr: u64, value: &[u8]) -> Self {
        let datatype_name = String::from(match value.len() {
            1 => "char",
            2 => "short",
            _ => "int",
        });

        let symbol = Symbol {
            id: addr,
            name: format!("anon_var_{addr}"),
            address: addr as i64,
            namespace: String::from("Global"),
            r#type: SymbolType::SymbolLabel.into(),
            datatype_name: datatype_name.clone(),
            data_size: value.len() as i64,
            function_symbol: None,
            pid: None,
        };

        let datatype = DataType {
            id: addr,
            name: format!("var_{addr}"),
            size: value.len() as i32,
            r#type: MetaType::TypeBasic.into(),
            alignment: u32::default(),
            base_data_type_name: datatype_name,
            offset: 0,
            bitfld_num_bits: i32::default(),
            bitfld_offset: i32::default(),
            bitfld_base_type: String::default(),
            num_elements: u32::default(),
            array_elem_type_name: String::default(),
            children: Vec::default(),
            enums: Vec::default(),
            pid: None,
        };

        Self {
            mem: vec![0; symbol.data_size as usize],
            symbol,
            datatype,
            num_writes: AtomicU64::new(0),
            num_reads: AtomicU64::new(0),
            mem_overflow_errors: vec![],
            overflow_count: 0,
        }
    }
    #[inline]
    pub fn is_basic(&self) -> bool {
        self.symbol.r#type() == SymbolType::SymbolLabel
            && self.datatype.r#type() == MetaType::TypeBasic
    }
    #[inline]
    pub fn is_struct(&self) -> bool {
        self.symbol.r#type() == SymbolType::SymbolLabel
            && self.datatype.r#type() == MetaType::TypeStruct
    }
    #[inline]
    pub fn is_array(&self) -> bool {
        self.symbol.r#type() == SymbolType::SymbolLabel
            && self.datatype.r#type() == MetaType::TypeArray
    }

    pub fn component_at(&self, addr: u32) -> Option<&DataType> {
        if self.symbol.contains(addr) {
            let start = self.symbol.addr_start();
            let mut iter = self.datatype.children.iter().filter(|dt| {
                addr >= (start + dt.offset as u32)
                    && addr <= (start + dt.offset as u32 + dt.size as u32)
            });
            iter.next()
        } else {
            None
        }
    }

    pub fn to_c_repr(&self) -> (Option<CStructRepr>, Option<BasicRepr>, Option<ArrayRepr>) {
        let mut s_repr: Option<CStructRepr> = None;
        let mut b_repr: Option<BasicRepr> = None;
        let mut a_repr: Option<ArrayRepr> = None;

        if self.is_struct() {
            s_repr = Some(struct_repr(self));
        } else if self.is_basic() {
            b_repr = Some(basic_repr(self));
        } else if self.is_array() {
            a_repr = Some(array_repr(self));
        } else {
            warn!(
                "Not handling {} {}",
                self.symbol.r#type(),
                self.datatype.r#type()
            );
        }

        (s_repr, b_repr, a_repr)
    }

    /// Create a memory write aggregate - [MemoryChange]
    pub fn mem_write_aggregate(
        &self,
        interrupt: Option<Interrupt>,
        insn_num: u64,
        e: &MemWriteEvent,
        oldv: &[u8],
        newv: &[u8],
        function: &Option<Function>,
    ) -> AggregateEvent {
        let is_read = false;
        self.num_writes.fetch_add(1, SeqCst);
        // are we in a function
        let fstr = {
            if let Some(f) = function {
                f.symbol().name()
            } else {
                "".to_string()
            }
        };
        let (s_repr, b_repr, a_repr) = self.to_c_repr();
        let member_var = {
            if self.is_struct() {
                self.component_at(e.address).map(|field| CVarRepr {
                    name: field.name.to_string(),
                    typename: field.base_data_type_name.to_string(),
                    size: field.size as u64,
                })
            } else {
                None
            }
        };

        AggregateEvent::Memory(Box::new(MemoryChange {
            insn_num,
            interrupt,
            pc: e.pc as u64,
            addr: e.address as u64,
            old_value: compact_repr(oldv, 0, oldv.len()),
            new_value: compact_repr(newv, 0, newv.len()),
            function_name: fstr,
            symbol_name: self.symbol.name(),
            member_var,
            struct_repr: s_repr,
            array_repr: a_repr,
            basic_repr: b_repr,
            is_read,
        }))
    }

    /// Create a memory read aggregate - [MemoryChange]
    pub fn mem_read_aggregate(
        &self,
        interrupt: Option<Interrupt>,
        insn_num: u64,
        e: &MemReadEvent,
        newv: &[u8],
        function: &Option<Function>,
    ) -> AggregateEvent {
        let is_read = true;
        self.num_reads.fetch_add(1, SeqCst);
        // are we in a function
        let fstr = {
            if let Some(f) = function {
                f.symbol().name()
            } else {
                "".to_string()
            }
        };
        let (s_repr, b_repr, a_repr) = self.to_c_repr();
        let member_var = {
            if self.is_struct() {
                self.component_at(e.address).map(|field| CVarRepr {
                    name: field.name.to_string(),
                    typename: field.base_data_type_name.to_string(),
                    size: field.size as u64,
                })
            } else {
                None
            }
        };

        AggregateEvent::Memory(Box::new(MemoryChange {
            insn_num,
            interrupt,
            pc: e.pc as u64,
            addr: e.address as u64,
            old_value: String::default(),
            new_value: compact_repr(newv, 0, newv.len()),
            function_name: fstr,
            symbol_name: self.symbol.name(),
            member_var,
            struct_repr: s_repr,
            array_repr: a_repr,
            basic_repr: b_repr,
            is_read,
        }))
    }

    /// The emulator did a memory write of memory which contained by this variable.
    /// Check to see if the memory has changed and return a `MemoryChange` event.
    pub fn mem_write(
        &mut self,
        insn_num: u64,
        e: &MemWriteEvent,
        interrupt: Option<Interrupt>,
        function: Option<Function>,
        changes_only: bool,
    ) -> Option<AggregateEvent> {
        /// Compares the event memory with the variable's memory
        ///
        /// Example: `cmp_vals!(self, type, e)`
        /// - the type must be one of `u8`, `u16`, or `u32`
        /// - e must be an identifier of type [MemWriteEvent]
        ///
        /// Returns: tuple `(old_value, new_value, did_change)`
        macro_rules! cmp_vals {
            ($self: ident, $typ:ty, $e: ident) => {{
                // index inside the variable, make sure we don't exceed its
                // overall size
                let _start = ($e.address - $self.symbol.addr_start()) as usize;
                let _end = (_start + size_of::<$typ>());
                if _end > $self.mem.len() {
                    $self.overflow_error($e);
                    return None;
                }
                // save the old value by cloning the target memory slice
                // into a vector
                let _old_mem_value = (& $self.mem[_start.._end].to_vec()).clone();

                // copy in new value
                let _dst = &mut $self.mem[_start.._end];
                _dst.copy_from_slice( &<$typ>::to_ne_bytes($e.value as $typ));

                let _did_change = _old_mem_value != _dst;
                (_old_mem_value,  $self.mem[_start.._end].to_vec(), _did_change)
            }};
            }

        let (oldv, newv, did_change) = if e.size_bytes == 1 {
            cmp_vals!(self, u8, e)
        } else if e.size_bytes == 2 {
            cmp_vals!(self, u16, e)
        } else if e.size_bytes == 4 {
            cmp_vals!(self, u32, e)
        } else {
            tracing::error!("Unexpected memory write event size: {}", e.size_bytes);
            return None;
        };

        let m = self.mem_write_aggregate(interrupt, insn_num, e, &oldv, &newv, &function);
        if !changes_only || did_change {
            Some(m)
        } else {
            None
        }
    }

    fn overflow_error(&mut self, e: &MemWriteEvent) {
        let end = e.address + e.size_bytes as u32;
        let over_by = end - self.symbol.addr_end();
        let emu_wrt = format!(
            "Emulator write {} b, [{:#010x}..{:#010x}].",
            e.size_bytes, e.address, end,
        );
        let msg = format!(
            "Overflow ({} b), Symbol: ({}) {} {}, size: {}, [{:#010x}..{:#010x}], {}",
            over_by,
            self.datatype.r#type(),
            self.datatype.name,
            self.symbol.name(),
            self.symbol.data_size,
            self.symbol.addr_start(),
            self.symbol.addr_end(),
            emu_wrt
        );
        trace!("{}", msg);
        self.overflow_count += 1;
        if self.mem_overflow_errors.len() < MAX_OVERFLOWS {
            self.mem_overflow_errors.push(json!({
                    "message": msg,
                    "event": serde_json::to_value(e).unwrap(),
                    "memory": serde_json::to_value(&self.mem).unwrap(),
                }
            ));
        }
    }

    pub fn json(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }

    // pretty-print
    pub fn pprint(&self, out_dst: &mut Box<dyn std::io::Write>) -> Result<(), std::io::Error> {
        let summary = format!("- Symbol: {} {}", self.datatype.name, self.symbol.name);
        writeln!(out_dst, "{:120}", &summary)?;
        writeln!(out_dst, "  Symbol:   {}", self.symbol)?;
        writeln!(out_dst, "  DataType: {}", self.datatype)?;

        let mut max_ty_sz = 0;
        let mut max_nm_sz = 0;
        for c in self.datatype.children.iter() {
            if c.base_data_type_name.len() > max_ty_sz {
                max_ty_sz = c.base_data_type_name.len();
            }
            if c.name.len() > max_nm_sz {
                max_nm_sz = c.name.len();
            }
        }
        max_nm_sz += 1;

        for c in self.datatype.children.iter() {
            let vals = compact_repr(
                &self.mem,
                c.offset as usize,
                c.offset as usize + c.size as usize,
            );
            writeln!(
                out_dst,
                "    {:max_ty_sz$} {:max_nm_sz$} {}",
                c.base_data_type_name,
                format!("{}:", c.name),
                vals
            )?;
        }
        Ok(())
    }

    /// Correlate all [symbols](styx_core::grpc::typhunix_interop::symbolic::Symbol) of type
    /// `struct` with their corresponding
    /// [data type](styx_core::grpc::typhunix_interop::symbolic::DataType), create a [Variable].
    ///
    /// Return a vector of all the [variables](Variable)
    pub fn align(cache: &SymbolCache, audit: bool) -> Vec<Variable> {
        let mut results: Vec<Variable> = vec![];
        let sym_dt_pairs = cache.correlate(audit);
        for (symbol, data_type) in sym_dt_pairs.iter() {
            results.push(Variable::new(symbol, data_type));
        }
        results
    }
}

pub fn struct_mbr(dt: &DataType, mem: &[u8]) -> CStructMemberRepr {
    let dt_typename = dt.base_data_type_name.to_string();
    let dt_name = dt.name.to_string();
    let is_ptr = dt_typename.contains('*');
    let cvar = CVarRepr {
        name: dt_name,
        typename: dt_typename.clone(),
        size: dt.size as u64,
    };

    let beg_mbr_mem = dt.offset as usize;
    let end_mbr_mem = beg_mbr_mem + dt.size as usize;
    let mem_slice = &mem[beg_mbr_mem..end_mbr_mem];

    let repr = if is_ptr {
        if dt.size == 4 {
            let val = u32::from_ne_bytes(mem_slice.try_into().unwrap());
            format!("-> {val:#010x}")
        } else {
            compact_repr(mem, beg_mbr_mem, end_mbr_mem)
        }
    } else if dt.size == 1 && dt_typename.eq("byte") {
        let val = mem_slice[0];
        format!("{val:#08b} {val:#01x}")
    } else if dt.size == 2 && dt_typename.eq("byte") {
        let val = u16::from_ne_bytes(mem_slice.try_into().unwrap());
        format!("{val:#01x}")
    } else if dt.size == 4 && (dt_typename.eq("byte") || dt_typename.eq("uint32_t")) {
        let val = u32::from_ne_bytes(mem_slice.try_into().unwrap());
        format!("{val:#01x}")
    } else {
        compact_repr(mem, beg_mbr_mem, end_mbr_mem)
    };

    CStructMemberRepr {
        var: Some(cvar),
        repr_val: repr,
    }
}

pub fn basic_repr(v: &crate::variable::Variable) -> BasicRepr {
    BasicRepr {
        var: Some(CVarRepr {
            name: v.symbol.name.to_string(),
            typename: v.datatype.name.to_string(),
            size: v.symbol.data_size as u64,
        }),
    }
}

pub fn array_repr(v: &crate::variable::Variable) -> ArrayRepr {
    ArrayRepr {
        var: Some(CVarRepr {
            name: "todo()!".into(),
            typename: v.datatype.name.to_string(),
            size: v.symbol.data_size as u64,
        }),
    }
}

pub fn struct_repr(v: &crate::variable::Variable) -> CStructRepr {
    let mut struct_repr = CStructRepr::default();
    let dt_metatype = v.datatype.r#type();
    let sym_name = v.symbol.name.clone();
    let dt_typename = v.datatype.base_data_type_name.clone();

    struct_repr.var = Some(CVarRepr {
        name: sym_name,
        typename: dt_typename,
        size: v.datatype.size as u64,
    });

    if dt_metatype == MetaType::TypeStruct {
        for mbr in v.datatype.children.iter() {
            struct_repr.members.push(struct_mbr(mbr, &v.mem));
        }
    }

    struct_repr
}

impl TryFrom<Variable> for CStructRepr {
    type Error = String;
    fn try_from(value: Variable) -> Result<Self, Self::Error> {
        match value.datatype.r#type() {
            MetaType::TypeStruct | MetaType::TypeUnion => Ok(struct_repr(&value)),
            _ => Err("Must be of type Struct".to_string()),
        }
    }
}
