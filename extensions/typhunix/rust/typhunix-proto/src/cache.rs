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
//! Caches for symbol lookups
use crate::grpc_async_client::{
    data_types_vec, programs_id_vec, programs_vec, symbols_vec, GrpcStatus,
};
use std::collections::HashMap;
use styx_emulator::grpc::typhunix_interop::symbolic::{
    DataType, Function, Program, ProgramFilter, ProgramIdentifier, Symbol,
};
use styx_emulator::grpc::typhunix_interop::{AddrUtils, ConnectMessage};
use styx_emulator::sync::{Arc, Mutex};
use tokio::join;
use tonic::Code;
use tracing::warn;

pub trait FunctionCache: Send + Sync + 'static {
    // Funcations
    fn func_by_start_addr(&self, addr: u32) -> Option<&Function>;
    fn func_by_end_addr(&self, addr: u32) -> Option<&Function>;
    fn funcs_for_addr(&self, addr: u32) -> Option<&Function>;

    // Symbols
    fn symbols(&self) -> Vec<&Symbol>;
    fn symbol_by_addr(&self, id: u32) -> Option<&Symbol>;

    // DataTypes
    fn datatypes(&self) -> Vec<&DataType>;
    fn datatype_by_name(&self, name: &str) -> Option<&DataType>;
}

pub trait DataTypeCache: Send + Sync + 'static {}

pub type SymbolDataTypePair = (Symbol, DataType);

#[derive(Default, Clone)]
pub struct SymbolCache {
    program: Program,
    symbols: Vec<Symbol>,
    datatypes: Vec<DataType>,

    /// Map of {name: DataType}
    map_name_datatype: Arc<Mutex<HashMap<String, usize>>>,
    /// Map of {addr: Symbol}
    map_addr_symbol: Arc<Mutex<HashMap<u32, usize>>>,
    /// Map of {addr_start: Function}
    map_func_start: Arc<Mutex<HashMap<u32, usize>>>,
    /// Map of {addr_end: Function}
    map_func_end: Arc<Mutex<HashMap<u32, usize>>>,
}

impl SymbolCache {
    pub fn info(&self) -> String {
        [
            "Cache Info:".to_string(),
            format!(" - Program:  {}", self.program),
            format!(" - Symbol:   {}", self.symbols.len()),
            format!(" - DataType: {}", self.datatypes.len()),
        ]
        .join("\n")
    }

    /// Correlate the [symbols](Symbol) and [datatypes](DataType) from the cache.
    /// return a vector of tuples (Symbol,DataType) for each correlation.
    ///
    /// - A symbol _correlates_ to a datatype if the symbol's `datatype_name`
    ///   field exactly matches a datatype's `name` field, and the both symbol
    ///   and datatype are considered _valid_. A symbol is valid iff:
    /// - the symbol is not a function and
    /// - `symbol.data_size > 0` and
    /// - `!symbol.datatype_name.is_empty()`
    ///
    /// A datatype is valid if the datatype's name is not empty and the data size
    /// is greater than zero.
    ///
    /// ## audit flag
    ///
    /// Since this function can receive partial and/or imperfect data, the
    /// `audit` flag can be used to display, to `stdout`, additional details
    /// with respect to why the symbol was considered not valid.
    ///
    /// ## Return
    /// A list of the (symbol, datatype) tuples that meet the corrlation
    /// criteria.
    pub fn correlate(&self, audit: bool) -> Vec<SymbolDataTypePair> {
        let mut functions: Vec<Symbol> = vec![];
        let mut sz_lt0: Vec<Symbol> = vec![];
        let mut sz_eq0: Vec<Symbol> = vec![];
        let mut dtnm_empty: Vec<Symbol> = vec![];
        let mut valid: Vec<Symbol> = vec![];
        let mut count = 0;
        for symbol in self.symbols().iter() {
            let symbol = &(*symbol).clone();
            let mut is_func = false;
            let mut data_sz_lt_0 = false;
            let mut data_sz_eq_0 = false;
            let mut dt_nm = false;
            count += 1;
            let reject = {
                if symbol.is_function() {
                    is_func = true;
                } else {
                    if symbol.data_size < 0 {
                        data_sz_lt_0 = true;
                    }
                    if symbol.data_size == 0 {
                        data_sz_eq_0 = true;
                    }
                    if symbol.datatype_name.is_empty() {
                        dt_nm = true;
                    }
                }
                if audit {
                    if is_func {
                        functions.push(symbol.clone().clone());
                    }
                    if data_sz_lt_0 {
                        sz_lt0.push(symbol.clone().clone());
                    }
                    if data_sz_eq_0 {
                        sz_eq0.push(symbol.clone().clone());
                    }
                    if dt_nm {
                        dtnm_empty.push(symbol.clone().clone());
                    }
                }
                is_func || data_sz_eq_0 || data_sz_lt_0 || dt_nm
            };

            if !reject {
                valid.push(symbol.clone().clone());
            }
        }
        if audit {
            println!(
                "AUDIT: Symbol data (pass one, before correlate), total={}",
                count
            );
            println!("AUDIT:   - {:20} {}", "Functions:", functions.len());
            println!("AUDIT:   - {:20} {}", "Size < 0:", sz_lt0.len());
            println!("AUDIT:   - {:20} {}", "Size == 0:", sz_eq0.len());
            println!("AUDIT:   - {:20} {}", "Empty DT nm:", dtnm_empty.len());
            println!("AUDIT:   - {:20} {}", "#good", valid.len());
        }

        let mut good_sym_dt: Vec<SymbolDataTypePair> = vec![];
        let mut bad_sym_dt: Vec<Symbol> = vec![];
        for s in valid.iter() {
            if let Some(dt) = self.datatype_by_name(&s.datatype_name) {
                good_sym_dt.push((s.clone(), dt.clone()));
            } else if audit {
                bad_sym_dt.push(s.clone());
            }
        }
        if audit {
            println!("AUDIT: Correlated Symbol Count: {}", good_sym_dt.len());
            println!("AUDIT: Un-Correlated Symbol Count: {}", bad_sym_dt.len());
            println!("AUDIT:   Symbols with no data type:");
            for s in bad_sym_dt.iter() {
                println!("AUDIT   {}", s);
            }
        }

        good_sym_dt
    }
}

impl FunctionCache for SymbolCache {
    fn func_by_start_addr(&self, addr: u32) -> Option<&Function> {
        if let Some(idx) = self.map_func_start.lock().unwrap().get(&addr) {
            self.program.functions.get(*idx)
        } else {
            None
        }
    }

    fn func_by_end_addr(&self, addr: u32) -> Option<&Function> {
        if let Some(idx) = self.map_func_end.lock().unwrap().get(&addr) {
            self.program.functions.get(*idx)
        } else {
            None
        }
    }

    fn funcs_for_addr(&self, addr: u32) -> Option<&Function> {
        if let Some(f) = self.func_by_start_addr(addr) {
            // addr is first O(1)
            Some(f)
        } else if let Some(f) = self.func_by_end_addr(addr) {
            // addr is last O(1)
            Some(f)
        } else {
            // addr is somehwere between (first..last) exclusive
            // linear search
            let mut iter = self
                .program
                .functions
                .iter()
                .filter(|f| addr >= f.addr_start() && addr <= f.addr_end());
            iter.next()
        }
    }

    fn symbols(&self) -> Vec<&Symbol> {
        self.symbols.iter().collect::<Vec<&Symbol>>()
    }

    fn symbol_by_addr(&self, addr: u32) -> Option<&Symbol> {
        if let Some(idx) = self.map_addr_symbol.lock().unwrap().get(&addr) {
            self.symbols.get(*idx)
        } else {
            None
        }
    }

    fn datatypes(&self) -> Vec<&DataType> {
        self.datatypes.iter().collect::<Vec<&DataType>>()
    }
    fn datatype_by_name(&self, name: &str) -> Option<&DataType> {
        if let Some(idx) = self.map_name_datatype.lock().unwrap().get(name) {
            self.datatypes.get(*idx)
        } else {
            None
        }
    }
}

impl From<&ConnectMessage> for SymbolCache {
    fn from(cmsg: &ConnectMessage) -> Self {
        let cmsg = cmsg.clone();
        if let Some(program) = cmsg.program {
            Self::from((&program, cmsg.symbols, cmsg.data_types))
        } else {
            Self::default()
        }
    }
}

impl From<(&Program, Vec<Symbol>, Vec<DataType>)> for SymbolCache {
    fn from(value: (&Program, Vec<Symbol>, Vec<DataType>)) -> Self {
        let program = value.0;
        let symbols = value.1.to_vec();
        let datatypes = value.2.to_vec();
        let functions = program.functions.to_vec();

        let mut functions_by_first: HashMap<u32, usize> = HashMap::with_capacity(functions.len());
        let mut functions_by_last: HashMap<u32, usize> = HashMap::with_capacity(functions.len());
        let mut symbols_by_addr: HashMap<u32, usize> = HashMap::with_capacity(symbols.len());
        let mut symbols_by_first: HashMap<u32, usize> = HashMap::with_capacity(symbols.len());
        let mut symbols_by_last: HashMap<u32, usize> = HashMap::with_capacity(symbols.len());
        let mut datatypes_by_name: HashMap<String, usize> = HashMap::with_capacity(datatypes.len());

        symbols.iter().enumerate().for_each(|(newidx, s)| {
            // todo: what does it mean to have 2 symbols occupy the
            // same address? For now we are just replacing
            if let Some(oldidx) = symbols_by_addr.insert(s.addr_start(), newidx) {
                fn smsg(s: &Symbol) -> String {
                    format!(
                        "{} [{:#x} .. {:#x}], sz:{}, type:{}",
                        s.name,
                        s.addr_start(),
                        s.addr_end(),
                        s.data_size,
                        s.datatype_name
                    )
                }
                let mut msg = String::from("Overwriting Cache for duplicate symbol, caching NEW");
                msg.push_str(&format!("\n  OLD: {}", smsg(symbols.get(oldidx).unwrap())));
                msg.push_str(&format!("\n  NEW: {}", smsg(symbols.get(newidx).unwrap())));
                warn!("{msg}");
            }
        });
        functions.iter().enumerate().for_each(|(i, f)| {
            functions_by_first.insert(f.addr_start(), i);
            functions_by_last.insert(f.addr_end(), i);
        });

        symbols.iter().enumerate().for_each(|(i, f)| {
            symbols_by_first.insert(f.addr_start(), i);
            symbols_by_last.insert(f.addr_end(), i);
        });

        datatypes.iter().enumerate().for_each(|(i, d)| {
            if let Some(_dup) = datatypes_by_name.insert(d.name.clone(), i) {
                warn!("Caching datatype with duplicate name: {}", d.name);
            }
        });

        Self {
            symbols,
            program: program.to_owned(),
            datatypes,
            map_name_datatype: Arc::new(Mutex::new(datatypes_by_name)),
            map_addr_symbol: Arc::new(Mutex::new(symbols_by_addr)),
            map_func_start: Arc::new(Mutex::new(functions_by_first)),
            map_func_end: Arc::new(Mutex::new(functions_by_last)),
        }
    }
}

fn grpc_wrapped(msg: &str) -> GrpcStatus {
    GrpcStatus::new(tonic::Code::Unknown, msg)
}

/// Create / return a [SymbolCache] for the given program by querying typhunix
/// If the program is not contained by typhunix, return None
/// Connects to the Grpc service using the environment variable `TYPHUNIX_URL`
pub async fn symbol_cache_from_server(
    program_ident: ProgramIdentifier,
) -> Result<Option<SymbolCache>, GrpcStatus> {
    let server_url = std::env::var("TYPHUNIX_URL").map_err(|e| {
        GrpcStatus::new(
            Code::Unknown,
            format!("TYPHUNIX_URL variable not set: {:?}", e),
        )
    })?;

    let pids = programs_id_vec(server_url.clone())
        .await?
        .iter()
        .filter(|pid| program_ident.eq(pid))
        .map(ProgramIdentifier::clone)
        .collect::<Vec<ProgramIdentifier>>();

    if pids.is_empty() {
        Ok(None)
    } else if pids.len() > 1 {
        Err(grpc_wrapped("Too many program idents"))
    } else {
        let pid = pids.first().unwrap().clone();
        let filter = ProgramFilter {
            exact_pids: vec![pid.clone()],
        };

        let (programs, symbols, data_types) = {
            let (r1, r2, r3) = join!(
                programs_vec(server_url.clone(), filter),
                symbols_vec(server_url.clone(), pid.to_owned().into()),
                data_types_vec(server_url.clone(), pid.to_owned().into())
            );
            (r1.unwrap(), r2.unwrap(), r3.unwrap())
        };
        Ok(Some(SymbolCache::from((
            programs.first().unwrap(),
            symbols,
            data_types,
        ))))
    }
}

#[cfg(test)]
mod tests {
    use styx_emulator::grpc::typhunix_interop::HasFunctions;

    use super::*;
    use serde_json::json;

    #[test]
    fn test_function_contains() {
        let symbol_json = json!({
            "address": "0x0000b5f0",
            "data_size": 47,
            "datatype_name": "",
            "function_symbol": {
              "last_insn": "0x0000b61e",
              "parameters": []
            },
            "id": 909,
            "name": "Reset",
            "namespace": "Global",
            "pid": {
              "name": "twitter.bin",
              "source_id": "3524872547775184128"
            },
            "type": 1
        });

        let symbol: Symbol = serde_json::from_value(symbol_json).unwrap();
        let start_addr = symbol.address as u32;
        let addr_end = symbol.addr_end();

        let function: Function = Function {
            symbol: Some(symbol),
            ..Default::default()
        };

        assert!(function.contains(start_addr));
        assert!(function.contains(addr_end));

        assert!(!function.contains(start_addr - 1));
        assert!(!function.contains(addr_end + 1));
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_function_cache() {
        let msg = serde_json::from_str::<ConnectMessage>(include_str!(
            "../../testdata/connect_message.json"
        ))
        .unwrap();
        let functions = msg.functions();
        let n = functions.len();
        assert_eq!(n, 642);
        let cache = SymbolCache::from(&msg);
        // test every function
        for fun in functions.iter() {
            // find by first insn
            assert!(cache.func_by_start_addr(fun.addr_start()).is_some());
            assert_eq!(*cache.func_by_start_addr(fun.addr_start()).unwrap(), *fun);

            // find by addr_end
            assert!(cache.func_by_end_addr(fun.addr_end()).is_some());
            assert_eq!(*cache.func_by_end_addr(fun.addr_end()).unwrap(), *fun);

            // find in the middle - some functions have addr_start == addr_end
            if fun.addr_start() < fun.addr_end() {
                assert!(cache.funcs_for_addr(fun.addr_start() + 1).is_some());
            }
        }
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_correlate() {
        let msg = serde_json::from_str::<ConnectMessage>(include_str!(
            "../../testdata/connect_message.json"
        ))
        .unwrap();

        let cache = SymbolCache::from(&msg);

        let pairs = cache.correlate(true);
        assert_eq!(pairs.len(), 2411);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_symbol_cache() {
        let cache = SymbolCache::from(
            &serde_json::from_str::<ConnectMessage>(include_str!(
                "../../testdata/connect_message.json"
            ))
            .unwrap(),
        );
        assert_eq!(cache.symbols().len(), 6401);
        assert_eq!(cache.datatypes.len(), 329);
    }
}
