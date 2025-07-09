// SPDX-License-Identifier: BSD-2-Clause
//! Consume raw emulation events, maintain guest emulation state, emit artifacts
//!
//! - consumes and processes all "raw" events
//! - tracks (in memory) guest variables, memory, function calls, isrs, etc.
//! - emits "Cooked Events" (aggregates)
//!
//! Raw events are defined by the `styx-trace` crate. "Cooked" events are defined as an enumeration of variants in [`styx_trace_tools::event::AggregateEvent`](crate::event::AggregateEvent).
//!
//! `EmuObserver` is agnostic as to where the (raw) events are being emitted from - in the sense that it doesn't know or care if they are coming from a live emulation or a previousely executed emulation.
//!
//!
//! An emulation observer [EmulationObserver] processes raw [TraceableItem] events,
//! and attempts to emit higer-order emulation [`Event`](crate::event::AggregateEvent) items.
//!
//! It requres items from `Ghidra` / `Typhunix` such as:
//! - [DataType](styx_core::grpc::typhunix_interop::symbolic::DataType) - data types
//! - [Symbol](styx_core::grpc::typhunix_interop::symbolic::Symbol) symbols
//!
//! The _higher-order_ events, items such as are defined in [traceapp](crate) and
//! wrapped in [`Event`](crate::event::AggregateEvent) variants.

use crate::data_recorder::DataRecorder;
use crate::event::AggregateEvent;
use crate::service_err;
use crate::variable::Variable;
use async_stream::stream;
use futures_core::stream::Stream;
use regex::{RegexSet, RegexSetBuilder};
use std::collections::HashMap;
use std::fs::File;
use std::io;
use std::io::Write;
use std::io::{Seek, SeekFrom};
use std::ops::Range;
use std::{
    io::Read,
    sync::{
        atomic::{AtomicU64, Ordering::SeqCst},
        Arc, Mutex, RwLock,
    },
    time::Duration,
    vec,
};

use styx_core::grpc::args::{RawEventLimits, SymbolSearchOptions};
use styx_core::grpc::traceapp::{
    BasicBlock, EndOfEvents, FunctionGate, InstructionExec, Interrupt, Timeout,
};
use styx_core::grpc::typhunix_interop::symbolic::{Function, ProgramIdentifier};
use styx_core::grpc::typhunix_interop::{AddrUtils, Signature};
use tracing::warn;

use styx_core::tracebus::{
    next_event, BaseTraceEvent, BinaryTraceEventType, BlockTraceEvent, IPCTracer, InsnExecEvent,
    InterruptEvent, InterruptType, MemReadEvent, MemWriteEvent, Traceable, TraceableItem,
    TracerReader, TracerReaderOptions, TRACE_EVENT_SIZE,
};
use tonic::{Code, Status};
use tracing::{debug, error, info};
use typhunix_proto::cache::{symbol_cache_from_server, FunctionCache, SymbolCache};

const TIMEOUT_MAX: u64 = 5;

pub struct RawTimeoutManager {
    last_insn: u64,
    max: u64,
    num: u64,
}

impl Default for RawTimeoutManager {
    fn default() -> Self {
        Self {
            last_insn: 0,
            max: TIMEOUT_MAX,
            num: 0,
        }
    }
}

impl RawTimeoutManager {
    pub fn new(max: u64) -> Self {
        Self {
            max,
            ..Default::default()
        }
    }

    /// Process an event timeout
    /// Return AggregateEvent::AggregateEvent::NoMoreEvents if it looks
    /// like there are no more events, otherwise return a
    /// AggregateEvent::RawTimeout
    pub fn timeout(&mut self, last_insn: u64) -> AggregateEvent {
        if last_insn == self.last_insn {
            debug!(
                "timed out reading raw events: {} of {}, last_insn#={} ",
                self.num, self.max, self.last_insn
            );
            self.num += 1;
        } else {
            self.last_insn = last_insn;
            self.num = 0;
        }

        if self.num < self.max {
            warn!("Sending Event::Timeout {} of {}", self.num, self.max);
            AggregateEvent::RawTimeout(Timeout {
                insn_num: self.last_insn,
            })
        } else {
            warn!(
                "Sending Event::NoMoreEvents ({} of {} timeouts)",
                self.num, self.max
            );
            AggregateEvent::NoMoreEvents(EndOfEvents {
                insn_num: self.last_insn,
            })
        }
    }
}

pub struct InterruptStack {
    interrupts: RwLock<Vec<Interrupt>>,
}

impl Default for InterruptStack {
    fn default() -> Self {
        Self::new()
    }
}

impl InterruptStack {
    pub fn new() -> Self {
        Self {
            interrupts: RwLock::new(Vec::new()),
        }
    }

    pub fn in_isr(&self) -> bool {
        self.interrupts.read().unwrap().len() > 0
    }

    /// an Interrupt happened
    pub fn isr(&self, e: InterruptEvent, insn_num: u64) -> Vec<AggregateEvent> {
        if e.interrupt_type == InterruptType::IsrEntry {
            let i = Interrupt {
                insn_num,
                new_pc: e.new_pc as u64,
                old_pc: e.old_pc as u64,
                interrupt_num: e.interrupt_num,
                entered: true,
                ..Default::default()
            };
            self.interrupts.write().unwrap().push(i.to_owned());
            vec![AggregateEvent::Isr(i)]
        } else {
            // exit interrupt
            let mut results: Vec<AggregateEvent> = Vec::with_capacity(1);
            if let Some(i) = self.interrupts.write().unwrap().pop() {
                let this_i = Interrupt {
                    insn_num,
                    new_pc: e.new_pc as u64,
                    old_pc: e.old_pc as u64,
                    interrupt_num: e.interrupt_num,
                    entered: false,
                    stack: i.stack,
                };

                results.push(AggregateEvent::Isr(this_i));
            }
            results
        }
    }
    pub fn push(&self, _: &Function) {}
    pub fn pop(&self, _: &Function) {}
    pub fn current_isr(&self) -> Option<Interrupt> {
        self.interrupts.read().unwrap().last().cloned()
    }
    pub fn func_gate(&self, function_gate: &FunctionGate) {
        if let Some(item) = self.interrupts.write().unwrap().last_mut() {
            item.stack.push(function_gate.clone());
        }
    }
}

pub struct FunctionStack {
    functions: Arc<Mutex<Vec<Function>>>,
}
impl Default for FunctionStack {
    fn default() -> Self {
        Self::new()
    }
}

impl FunctionStack {
    pub fn new() -> Self {
        Self {
            functions: Arc::new(Mutex::new(vec![])),
        }
    }
    /// every function call enter
    pub fn push(&self, function: &Function) {
        self.functions.lock().unwrap().push(function.to_owned());
    }

    // function call exit
    pub fn pop(&self) -> Option<Function> {
        self.functions.lock().unwrap().pop()
    }

    pub fn top(&self) -> Option<Function> {
        self.functions.lock().unwrap().last().cloned()
    }
}
pub struct MemoryTracker {
    pub active: bool,
    pub mem: Vec<u8>,
}
impl MemoryTracker {
    pub fn new(start: u64, end: u64) -> Self {
        let active = end > start && end > 0;
        debug!("MemoryTracker: {}..{} ({})", start, end, active);
        let mem: Vec<u8> = {
            if active {
                debug!(
                    "MemoryTracker: initialize memory {}..{} ({})",
                    start, end, active
                );
                let len = (end - start) as usize;
                vec![0; len]
            } else {
                vec![]
            }
        };
        debug!(
            "MemoryTracker: Ok: {}..{} ({}), len={}",
            start,
            end,
            active,
            mem.len()
        );
        Self { active, mem }
    }

    pub fn dump(&self, path: &str) {
        if self.active {
            match File::create(path) {
                Ok(mut file) => match file.write_all(&self.mem) {
                    Ok(_) => info!("Ok(Memory dumped): {path}"),
                    Err(e) => error!("Err(Memory dumped) {path} {}: ", e),
                },
                Err(e) => error!("Err(Memory dumped) {}", e),
            }
        }
    }

    #[inline]
    pub fn write(&mut self, addr: u32, value: u32, sz: u16) {
        if self.active && sz > 0 {
            let value_bytes = &value.to_le_bytes()[0..sz as usize];
            let from = addr as usize;
            let to = from + sz as usize;
            let mx = self.mem.len() - 1;
            if from > mx || to > mx {
                warn!(
                    "Write out of bounds: mem: Attempt: [{}..{}], Memory: [{},{}]",
                    from, to, 0, mx
                );
            } else {
                // info!("self.mem[{}..{}].copy_from_slice(value_bytes)", from, to);
                self.mem[from..to].copy_from_slice(value_bytes);
                // println!("{}", compact_repr(&self.mem, from as usize, to as usize));
            }
        }
    }
}

/// Process raw discrete events from [Event](styx_core::tracebus), then
/// emit higher-order [AggregateEvent]'s
pub struct EmulationObserver {
    /// Symbol cache for address and symbol lookups
    pub symbol_cache: SymbolCache,
    /// Variables to watch
    // pub variables: Arc<Mutex<HashMap<u32, Variable>>>,
    pub variables: RwLock<Vec<Variable>>,
    /// Interrupt stack
    pub isr_stack: InterruptStack,
    /// Function call stack
    pub fun_stack: FunctionStack,
    /// Flag to indicate the consumer wishes to stop emulation and/or processing
    /// of raw event files
    stop_request: RwLock<bool>,
    /// Persistence manager - this will likely turn into a database at some point
    pub data_recorder: DataRecorder,
    /// The number of instructions that have been executed
    insn_count: AtomicU64,
    /// Limit raw event counts
    _raw_event_limits: RawEventLimits,
    // Trace Event count - used only when processing raw event files
    trace_event_count: AtomicU64,
    // track emulation memory
    pub memory: RwLock<MemoryTracker>,
    /// cache for anonymous variables
    anon_cache: Arc<Mutex<HashMap<u64, Variable>>>,
    /// Symbol match regex
    symbol_search_options: SymbolSearchOptions,
    symbol_match_regex: RegexSet,
}

impl EmulationObserver {
    pub async fn new(
        program_id: ProgramIdentifier,
        raw_event_limits: Option<RawEventLimits>,
        valid_memory_range: Option<Range<u64>>,
        outdir: Option<&str>,
        symbol_search_options: &SymbolSearchOptions,
    ) -> Result<Self, String> {
        let func_cache = symbol_cache_from_server(program_id.clone())
            .await
            .map_err(|e| {
                let mut msg = String::from("Failed to get typhunix function cache. ");
                msg.push_str("Make sure the typhunix service is running. The error was: ");
                format!("{msg} {:?}", e)
            })?;

        let memory = match valid_memory_range {
            Some(mr) => RwLock::new(MemoryTracker::new(mr.start, mr.end)),
            _ => RwLock::new(MemoryTracker::new(0, 0)),
        };
        let symbol_match_regex = symbol_search_options.regex_include().unwrap();

        if let Some(symbol_cache) = func_cache {
            let ptrace_dir = {
                if let Some(dir) = outdir {
                    dir.to_string()
                } else {
                    format!("/tmp/ptrace/{}", std::process::id())
                }
            };
            info!("trace dir: {}", ptrace_dir);
            let symbol_search_options = symbol_search_options.clone();
            Ok(Self {
                fun_stack: FunctionStack::new(),
                isr_stack: InterruptStack::new(),
                symbol_cache,
                insn_count: AtomicU64::new(0),
                trace_event_count: AtomicU64::new(0),
                _raw_event_limits: raw_event_limits.unwrap_or_default(),
                variables: RwLock::new(vec![]),
                stop_request: RwLock::new(false),
                data_recorder: DataRecorder::new(ptrace_dir).unwrap(),
                memory,
                anon_cache: Arc::new(Mutex::new(HashMap::new())),
                symbol_search_options,
                symbol_match_regex,
            })
        } else {
            Err(format!("No data for pid: {}", program_id))
        }
    }

    pub fn variable_count(&self) -> usize {
        self.variables.read().unwrap().len()
    }

    pub fn add_variable(&self, v: &Variable) {
        let mut vars = self.variables.write().unwrap();
        vars.push(Variable::new(&v.symbol, &v.datatype))
    }

    pub fn align_variables(&self, regex_pattern: &str, audit: bool) {
        // https://rust-lang-nursery.github.io/rust-cookbook/text/regex.html
        let rx = RegexSetBuilder::new([regex_pattern])
            .case_insensitive(true)
            .build()
            .unwrap();
        let sym_dt_pairs = self.symbol_cache.correlate(audit);
        for (symbol, data_type) in sym_dt_pairs.iter() {
            if rx.is_match(symbol.name.as_str()) {
                self.add_variable(&Variable::new(symbol, data_type));
            }
        }
    }

    /// Read / process all the records.
    ///
    /// todo: convert this to `tail -f` semantics
    pub fn event_stream_from_raw<'a>(
        &'a self,
        filename: &str,
    ) -> Result<impl Stream<Item = AggregateEvent> + 'a, tonic::Status> {
        let mut raw = RawTraceFile::open(filename, self.trace_event_count.fetch_add(0, SeqCst))
            .map_err(|e| {
                let msg = format!("Failed to open {}: {}", filename, e);
                service_err(&msg)
            })?;
        let mut last_pause_event: AggregateEvent = AggregateEvent::Sentinal;
        let result = stream! {
            while let Some(tr_item) = raw.next_item() {
                self.trace_event_count.fetch_add(1, SeqCst);
                for e in self.process(tr_item) {
                    if e.should_pause() {
                        info!("Pausable event encountered: {}", e);
                        last_pause_event = e.clone();
                        yield e;
                        break;
                    } else {
                        yield e;
                    }
                }
            }
            if last_pause_event != AggregateEvent::Sentinal {
                // then we ran out of raw events...
                let e = AggregateEvent::NoMoreEvents(EndOfEvents { insn_num:  self.insn_count()});
                info!("yielding: {}", e);
                yield e;
            }
        };
        Ok(result)
    }

    /// consume events from a shared ring buffer file (`*.srb`),
    /// yield higher-order events
    ///
    /// the consumption of events is non-blocking, so we should yield an
    /// [AggregateEvent] at least once every `timeout` duration - albeit
    /// the event yielded could be an
    pub fn events_stream_from_srb<'a>(
        &'a self,
        keyfile: &str,
        timeout: Duration,
    ) -> Result<impl Stream<Item = AggregateEvent> + 'a, tonic::Status> {
        let mut tmouts = RawTimeoutManager::default();
        let opts = TracerReaderOptions::new(keyfile);
        let rx = match IPCTracer::get_consumer(opts) {
            Err(err) => {
                return Err(Status::new(Code::Unknown, err.to_string()));
            }
            Ok(v) => Some(v),
        };

        let mut rx = rx.unwrap();
        info!("Waiting for events [{keyfile}], timeout: {:?} ...", timeout);
        let result = stream! {
            loop {
                match next_event!(rx, timeout) {
                    // Event
                    (_, _, Some(event)) => {

                        for e in self.process(event) {
                            if e.should_pause() {
                                info!("Pausable event encountered: {}", e);
                                yield e;
                                break;
                            } else {
                                yield e;
                            }
                        }
                    }

                    // Timeout
                    (_, true, _) => {
                        // yield self.process_raw_timeout()
                        let t = tmouts.timeout(self.insn_count());
                        yield t
                    }

                     // Error
                    (err, false, None) => {
                        yield AggregateEvent::Error(err)
                    }
                }
            }
        };

        Ok(result)
    }

    pub fn stop_processing(&self) {
        log::info!("Request to stop processing");
        *self.stop_request.write().unwrap() = true;
    }

    pub fn should_stop(&self) -> bool {
        *self.stop_request.read().unwrap()
    }

    fn flush_output(&self) {
        io::stdout().flush().unwrap();
    }

    #[inline]
    fn insn_count(&self) -> u64 {
        self.insn_count.fetch_add(0, SeqCst)
    }

    #[inline]
    fn insn_executed(&self, event: &InsnExecEvent) -> (u64, Vec<AggregateEvent>) {
        let count = self.insn_count.fetch_add(1, SeqCst);
        let mut results: Vec<AggregateEvent> = Vec::with_capacity(2);
        results.push(AggregateEvent::Instruction(InstructionExec {
            insn_num: count,
            pc: event.pc as u64,
            insn: event.insn as u64,
        }));

        if self._raw_event_limits.max_insn > 0 && count >= self._raw_event_limits.max_insn {
            results.push(AggregateEvent::InsnLimitReached(count));
        }
        (count, results)
    }

    /// a memory write has occurred
    fn mem_write_event(&self, insn_num: u64, e: &MemWriteEvent) -> Vec<AggregateEvent> {
        let mut results: Vec<AggregateEvent> = vec![];
        let mut vars = self.variables.write().unwrap();
        let isr = self.isr_stack.current_isr();
        let func = self.fun_stack.top();
        let mut symcache_hit = false;

        for v in vars.iter_mut() {
            if v.symbol.contains(e.address) {
                symcache_hit = true;
                if let Some(agg) = v.mem_write(insn_num, e, isr.clone(), func.clone(), true) {
                    results.push(agg);
                }
                break;
            }
        }

        if self.symbol_search_options.anon_writes && !symcache_hit {
            // An address for which we have no symbols
            let id = e.address as u64;
            let mut anon_cache = self.anon_cache.lock().unwrap();
            let value = e.value.to_ne_bytes();
            let v = anon_cache
                .entry(id)
                .or_insert_with(|| Variable::anonymous(id, &value));
            if self.symbol_match_regex.is_match(&v.symbol.name) {
                if let Some(agg) = v.mem_write(insn_num, e, isr, func, true) {
                    results.push(agg);
                }
            }
        }

        results
    }
    fn mem_read_event(&self, insn_num: u64, e: &MemReadEvent) -> Vec<AggregateEvent> {
        let mut results: Vec<AggregateEvent> = vec![];
        let mut vars = self.variables.write().unwrap();
        let value = e.value.to_ne_bytes();
        let isr = self.isr_stack.current_isr();
        let func = self.fun_stack.top();
        let mut symcache_hit = false;

        for v in vars.iter_mut() {
            if v.symbol.contains(e.address) {
                symcache_hit = true;
                let agg = v.mem_read_aggregate(isr.clone(), insn_num, e, &value, &func);
                results.push(agg);
                break;
            }
        }

        if !symcache_hit && self.symbol_search_options.anon_reads {
            // An address for which we have no symbols
            let id = e.address as u64;
            let mut anon_cache = self.anon_cache.lock().unwrap();
            let value = e.value.to_ne_bytes();
            let v = anon_cache
                .entry(id)
                .or_insert_with(|| Variable::anonymous(id, &value));
            let agg = v.mem_read_aggregate(isr, insn_num, e, &value, &func);
            results.push(agg);
        }
        results
    }

    fn block_event(&self, insn_num: u64, e: &BlockTraceEvent) -> Vec<AggregateEvent> {
        let bb = BasicBlock {
            insn_num,
            pc: e.pc as u64,
            size: e.size,
            is_start: false, // todo
            is_end: false,   // todo
        };
        vec![AggregateEvent::Block(bb)]
    }

    /// Inspect raw events, emit higher level events
    pub fn process(&self, event: TraceableItem) -> Vec<AggregateEvent> {
        if self.should_stop() {
            debug!("process: stop has been requested");
            return vec![AggregateEvent::StopRequested];
        }

        match event {
            TraceableItem::InsnExecEvent(e) => {
                let mut results: Vec<AggregateEvent> = vec![];
                let (inum, mut events) = self.insn_executed(&e);
                results.append(&mut events);
                if let Some(func) = self.symbol_cache.func_by_start_addr(e.pc) {
                    self.fun_stack.push(func);
                    self.isr_stack
                        .func_gate(&enter_function(inum, e.pc as u64, func));

                    results.push(AggregateEvent::Function(enter_function(
                        inum,
                        e.pc as u64,
                        func,
                    )));
                    // special case
                    if func.addr_start() == func.addr_end() {
                        self.isr_stack
                            .func_gate(&exit_function(inum, e.pc as u64, func));
                        results.push(AggregateEvent::Function(exit_function(
                            inum,
                            e.pc as u64,
                            func,
                        )));
                        let _ = self.fun_stack.pop();
                    }
                }
                // End of function
                else if let Some(func) = self.symbol_cache.func_by_end_addr(e.pc) {
                    self.isr_stack
                        .func_gate(&exit_function(inum, e.pc as u64, func));
                    results.push(AggregateEvent::Function(exit_function(
                        inum,
                        e.pc as u64,
                        func,
                    )));
                    let _ = self.fun_stack.pop();
                }
                // within a function
                else {
                }

                results
            }

            TraceableItem::InterruptEvent(e) => self.isr_stack.isr(e, self.insn_count()),

            TraceableItem::MemWriteEvent(e) => {
                self.memory
                    .write()
                    .unwrap()
                    .write(e.address, e.value, e.size_bytes);
                if self.symbol_search_options.mem_writes {
                    let results = self.mem_write_event(self.insn_count(), &e);
                    self.flush_output();
                    results
                } else {
                    vec![]
                }
            }

            TraceableItem::ControlEvent(e) => {
                println!("    CtlEvt[{:010}] ", e.event_num);
                vec![]
            }

            TraceableItem::MemReadEvent(e) => {
                if self.symbol_search_options.mem_reads {
                    let results = self.mem_read_event(self.insn_count(), &e);
                    self.flush_output();
                    results
                } else {
                    vec![]
                }
            }
            TraceableItem::BlockTraceEvent(e) => self.block_event(self.insn_count(), &e),
            TraceableItem::InsnFetchEvent(e) => {
                debug!("ignore {}", e.text());
                vec![]
            }
            TraceableItem::RegReadEvent(e) => {
                debug!("ignore {}", e.text());
                vec![]
            }
            TraceableItem::RegWriteEvent(e) => {
                debug!("ignore {}", e.text());
                vec![]
            }

            TraceableItem::BranchEvent(e) => {
                debug!("ignore {}", e.text());
                vec![]
            }
            TraceableItem::Stm32Event(e) => {
                debug!("ignore {}", e.text());
                vec![]
            }
            TraceableItem::Kinetis21Event(e) => {
                debug!("ignore {}", e.text());
                vec![]
            }
            TraceableItem::PowerQuiccEvent(e) => {
                debug!("ignore {}", e.text());
                vec![]
            }
        }
    }
}

/// wait for/return a single /tmp/strace*.srb file
pub async fn wait_for_trace() -> Result<String, String> {
    use glob::glob_with;
    use glob::MatchOptions;

    let options = MatchOptions {
        case_sensitive: false,
        require_literal_separator: false,
        require_literal_leading_dot: false,
    };

    loop {
        let files: Vec<String> = glob_with("/tmp/*.srb", options)
            .unwrap()
            .flatten()
            .map(|e| e.display().to_string())
            .collect();
        if files.len() == 1 {
            return Ok(files[0].to_string());
        }
        if files.len() > 1 {
            return Err("Too many files".to_string());
        }
    }
}

pub fn enter_function(insn_num: u64, pc: u64, func: &Function) -> FunctionGate {
    FunctionGate {
        entered: true,
        function_signature: func.signature(),
        insn_num,
        function_ref: func.id,
        pc,
    }
}

pub fn exit_function(insn_num: u64, pc: u64, func: &Function) -> FunctionGate {
    FunctionGate {
        entered: false,
        function_signature: func.signature(),
        insn_num,
        function_ref: func.id,
        pc,
    }
}

#[cfg(test)]
mod tests {
    use crate::compact_repr;

    use super::*;
    #[test]
    fn test_compact_repr() {
        // compact
        let slice = &[0, 0, 0, 0, 0, 0, 0, 0, 1];
        assert_eq!(compact_repr(slice, 0, 1), "[0]");
        assert_eq!(compact_repr(slice, 0, slice.len()), "[0;8,1]");
        assert_eq!(compact_repr(&vec![0; 256], 0, 256), "[0;256]");
        // slice is unaltered if < len < 8
        assert_eq!(compact_repr(&[0xf, 0xa, 0x1, 0x0], 0, 4), "[f,a,1,0]");
        assert_eq!(compact_repr(&[0, 0, 0, 0], 0, 4), "[0,0,0,0]");
    }

    #[test]
    #[should_panic]
    fn test_compact_repr_panics_oob() {
        // panic! out-of-bounds
        assert_eq!(compact_repr(&[0, 0, 0, 0], 0, 5), "[]");
    }

    #[test]
    #[should_panic]
    fn test_compact_repr_panics_index_overflow() {
        // panic! attempt to subtract with overflow
        assert_eq!(compact_repr(&[0, 0, 0, 0], 5, 4), "[]");
    }

    #[test]
    fn test_to_vec_is_cloned() {
        let mut mem = [0, 1, 2, 3];
        let cp = mem.to_vec();
        assert_eq!(cp[0], mem[0]);
        mem[0] = 1;
        assert_ne!(cp[0], mem[0]);
    }

    #[test]
    fn test_mem() {
        let memsz = 10;

        let (start, end) = (0, memsz);
        let mut m = MemoryTracker::new(start, end);
        assert!(m.active);
        assert_eq!(m.mem.len(), end as usize);
        for b in m.mem.iter() {
            assert_eq!(*b, 0);
        }
        assert_eq!(compact_repr(&m.mem, start as usize, end as usize), "[0;10]");
        m.write(0, 0x1, 2);
        let cr = compact_repr(&m.mem, start as usize, end as usize);
        assert_eq!(cr, "[1,0;9]");
        println!("{}", compact_repr(&m.mem, start as usize, end as usize));
    }
}
#[derive(Debug)]
pub struct RawTraceFile {
    pub filename: String,
    pub filesize: u64,
    pub record_count_remaining: u64,
    file: File,
}

impl RawTraceFile {
    pub fn open(filename: &str, skip_count: u64) -> Result<Self, std::io::Error> {
        let mut file = File::open(filename)?;
        let filesize = std::fs::metadata(filename)?.len();
        let bytes_to_skip = skip_count as usize * TRACE_EVENT_SIZE;
        let bytes_remaining = filesize - bytes_to_skip as u64;
        let recs_remaining = bytes_remaining / TRACE_EVENT_SIZE as u64;
        file.seek(SeekFrom::Start(bytes_to_skip as u64))?;
        Ok(Self {
            filename: filename.to_string(),
            filesize,
            file,
            record_count_remaining: recs_remaining,
        })
    }

    #[inline]
    pub fn next_item(&mut self) -> Option<TraceableItem> {
        let mut buffer: BinaryTraceEventType = [0; TRACE_EVENT_SIZE];
        let sz = match self.file.read(&mut buffer) {
            Ok(sz) => sz,
            Err(e) => {
                error!("read raw trace event {}: {}", self.filename, e);
                0
            }
        };
        if sz == TRACE_EVENT_SIZE {
            self.record_count_remaining -= 1;
            Some(TraceableItem::from(BaseTraceEvent::from(&buffer)))
        } else {
            None
        }
    }
}

pub enum RawEventInputSource {
    Raw(String),
    TraceFile(String, Duration),
}
