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
//! Analyzers - functions that process [AggregateEvents](crate::event::AggregateEvent)
use crate::event::{AggregateEvent, StreamEndReason};
use futures_core::stream::Stream;
use futures_util::stream::StreamExt;
use std::{collections::HashMap, time::Duration};
use styx_core::grpc::traceapp::StartTraceAppSessionResponse;
use tokio::{sync::mpsc::Receiver, time::timeout};
use tokio_util::sync::CancellationToken;
use tracing::{info, trace};

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum OutputFormat {
    /// built-in format
    Builtin,
    /// JSON format
    Json,
    /// Debug text format ({:?})
    Text,
}

pub trait HasAnalysisOptions {
    fn show_fenter(&self) -> bool;
    // (args.flags.show_fenter, args.flags.show_fexit);
    fn show_fexit(&self) -> bool;
    fn output(&self) -> Result<Box<dyn std::io::Write>, std::io::Error>;
    fn output_format(&self) -> OutputFormat;
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum AnalysisType {
    /// Functions
    Functions,
    /// Analyze interrupts and ISRs
    Isr,
    /// Analyze memory writes
    Memory,
    /// Count and summarize events
    Stats,
    /// Trace execution
    Trace,
}

impl AnalysisType {
    pub async fn analyze(
        &self,
        options: &impl HasAnalysisOptions,
        cancel_token: CancellationToken,
        stream: &mut (impl Stream<Item = AggregateEvent> + std::marker::Unpin),
    ) {
        match self {
            AnalysisType::Stats => {
                at_stats(options, cancel_token, stream).await;
            }
            AnalysisType::Functions => {
                at_functions(options, cancel_token, stream).await;
            }
            AnalysisType::Isr => {
                at_isr(options, cancel_token, stream).await;
            }
            AnalysisType::Memory => {
                at_memory(options, cancel_token, stream).await;
            }
            AnalysisType::Trace => {
                at_trace(options, cancel_token, stream).await;
            }
        }
    }
}

macro_rules! check_cancel {
    ($ct: ident, $eoe: ident, $reason: ident) => {
        if $ct.is_cancelled() {
            info!("analyzer cancelled");
            $eoe = true;
            $reason = StreamEndReason::Cancelled;
            true
        } else {
            false
        }
    };
}
macro_rules! check_eoe {
    ($agg_event: ident, $eoe: ident, $reason: ident) => {
        if $agg_event.should_pause() {
            $eoe = true;
            $reason = $agg_event.clone().into();
        }
    };
}

/// trace analyzer
async fn at_trace(
    options: &impl HasAnalysisOptions,
    cancel_token: CancellationToken,
    stream: &mut (impl Stream<Item = AggregateEvent> + std::marker::Unpin),
) {
    let mut out = options.output().unwrap();
    let mut should_stop = false;
    let wait_interval = Duration::from_millis(1000);
    let mut end_reason: StreamEndReason = StreamEndReason::Unknown;

    let (fenter, fexit) = (options.show_fenter(), options.show_fexit());

    while !should_stop {
        if check_cancel!(cancel_token, should_stop, end_reason) {
            break;
        }
        if let Ok(next_result) = tokio::time::timeout(wait_interval, stream.next()).await {
            // Received an either an error or an Aggregate
            if let Some(aggregate_event) = next_result {
                check_eoe!(aggregate_event, should_stop, end_reason);

                match aggregate_event {
                    AggregateEvent::Instruction(insn_event) => {
                        let prefix = format!("{:010} {:#010x}", insn_event.insn_num, insn_event.pc);
                        writeln!(out, "{}    insn:{:#010x}", prefix, insn_event.insn).unwrap();
                    }

                    AggregateEvent::Isr(isr) => {
                        let prefix = format!("{:010} {:#010x}", isr.insn_num, isr.new_pc);
                        let d = if isr.entered {
                            "INTR_ENTER"
                        } else {
                            "INTR_EXIT"
                        };
                        writeln!(out, "{prefix} {d}").unwrap();
                    }

                    AggregateEvent::Function(func_event) => {
                        if func_event.entered && fenter || (!func_event.entered && fexit) {
                            let prefix =
                                format!("{:010} {:#010x}", func_event.insn_num, func_event.pc);
                            writeln!(out, "{prefix} {func_event}").unwrap();
                        }
                    }

                    AggregateEvent::Block(block_event) => {
                        let prefix =
                            format!("{:010} {:#010x}", block_event.insn_num, block_event.pc);
                        writeln!(out, "{} BasicBlock ? [{}]", prefix, block_event.size).unwrap();
                    }

                    AggregateEvent::Memory(mem) => {
                        // Mem written
                        let prefix = format!("{:010} {:#010x}", mem.insn_num, mem.pc);
                        writeln!(out, "{} {}", prefix, mem.list_display()).unwrap();
                    }

                    _ => trace!("Unhandled: {}", aggregate_event),
                }
            } else {
                // end of stream
                should_stop = true;
                end_reason = StreamEndReason::EndOfStream;
            }
        } else {
            // TIMEOUT: Event has not been received
            should_stop = true;
            end_reason = StreamEndReason::NotResponding;
        }
    }

    writeln!(out, "Finished trace: reason: {end_reason}").unwrap();
}

/// functions analyzer
async fn at_functions(
    options: &impl HasAnalysisOptions,
    cancel_token: CancellationToken,
    stream: &mut (impl Stream<Item = AggregateEvent> + std::marker::Unpin),
) {
    let mut out = options.output().unwrap();
    let mut should_stop = false;
    let wait_interval = Duration::from_millis(1000);
    let mut end_reason: StreamEndReason = StreamEndReason::Unknown;
    let (fenter, fexit) = (options.show_fenter(), options.show_fexit());
    while !should_stop {
        if check_cancel!(cancel_token, should_stop, end_reason) {
            break;
        }
        if let Ok(next_result) = tokio::time::timeout(wait_interval, stream.next()).await {
            // Received an either an error or an Aggregate
            if let Some(aggregate_event) = next_result {
                check_eoe!(aggregate_event, should_stop, end_reason);
                #[allow(clippy::single_match)]
                match aggregate_event {
                    AggregateEvent::Function(func_event) => {
                        if (!fenter && !fexit)
                            || (func_event.entered && fenter || (!func_event.entered && fexit))
                        {
                            writeln!(out, "{func_event}").unwrap();
                        }
                    }
                    _ => {}
                }
            } else {
                // end of stream
                should_stop = true;
                end_reason = StreamEndReason::EndOfStream;
            }
        } else {
            // TIMEOUT: Event has not been received
            should_stop = true;
            end_reason = StreamEndReason::NotResponding;
        }
    }

    // finish ...
    writeln!(out, "Finished: reason: {end_reason}").unwrap();
}

/// stats analyzer
/// Displays statistics for [AggregateEvent] received (counting events, summarizing
/// based on event type)
async fn at_stats(
    options: &impl HasAnalysisOptions,
    cancel_token: CancellationToken,
    stream: &mut (impl Stream<Item = AggregateEvent> + std::marker::Unpin),
) {
    let mut out = options.output().unwrap();
    let mut should_stop = false;
    let wait_interval = Duration::from_millis(1000);
    let mut end_reason: StreamEndReason = StreamEndReason::Unknown;

    let mut hm: HashMap<String, usize> = HashMap::new();
    let mut total = 0;

    while !should_stop {
        if check_cancel!(cancel_token, should_stop, end_reason) {
            break;
        }

        if let Ok(next_result) = tokio::time::timeout(wait_interval, stream.next()).await {
            // Received an either an error or an Aggregate
            if let Some(aggregate_event) = next_result {
                check_eoe!(aggregate_event, should_stop, end_reason);

                // body --------------------------------------------------------
                total += 1;
                let repr = format!("{aggregate_event}");
                let fields = repr.split_whitespace().collect::<Vec<&str>>();
                if let Some(s) = fields.first() {
                    let k = s.to_string();
                    total += 1;
                    if !hm.contains_key(&k) {
                        trace!("{k}");
                        hm.insert(k.clone(), 0);
                    }
                    *hm.get_mut(&k).unwrap() += 1;
                }
                // body --------------------------------------------------------

                // if eov {
                //     break;
                // }
            } else {
                // end of stream
                should_stop = true;
                end_reason = StreamEndReason::EndOfStream;
            }
        } else {
            // TIMEOUT: Event has not been received in INTERVAL_MILLIS msb
            should_stop = true;
            end_reason = StreamEndReason::NotResponding;
        }
    }

    writeln!(out, "EOV: {should_stop}, Reason: {end_reason}").unwrap();
    writeln!(out, "Total Events: {total}").unwrap();
    for (k, v) in hm.iter() {
        let label = format!("{k}:");
        writeln!(out, " {label:<20} {v}").unwrap();
    }
}

/// memory analyzer
async fn at_memory(
    options: &impl HasAnalysisOptions,
    cancel_token: CancellationToken,
    stream: &mut (impl Stream<Item = AggregateEvent> + std::marker::Unpin),
) {
    let mut out = options.output().unwrap();
    let mut should_stop = false;
    let wait_interval = Duration::from_millis(1000);
    let mut end_reason: StreamEndReason = StreamEndReason::Unknown;

    while !should_stop {
        if check_cancel!(cancel_token, should_stop, end_reason) {
            break;
        }
        if let Ok(next_result) = tokio::time::timeout(wait_interval, stream.next()).await {
            // Received an either an error or an Aggregate
            if let Some(aggregate_event) = next_result {
                check_eoe!(aggregate_event, should_stop, end_reason);
                #[allow(clippy::single_match)]
                match aggregate_event {
                    AggregateEvent::Memory(mem) => match options.output_format() {
                        OutputFormat::Json => {
                            writeln!(out, "{}", serde_json::to_string(&mem).unwrap()).unwrap()
                        }
                        OutputFormat::Text => writeln!(out, "{mem:?}").unwrap(),
                        OutputFormat::Builtin => {
                            writeln!(out, "{mem}").unwrap();
                        }
                    },
                    _ => {}
                }
            } else {
                // end of stream
                should_stop = true;
                end_reason = StreamEndReason::EndOfStream;
            }
        } else {
            // TIMEOUT: Event has not been received
            should_stop = true;
            end_reason = StreamEndReason::NotResponding;
        }
    }

    // finish ...
    writeln!(out, "Finished: reason: {end_reason}").unwrap();

    // while let Some(aggregate_event) = stream.next().await {
    //     check_pause!(cancel_token, aggregate_event);
    // }
}

/// ISR analyzer
async fn at_isr(
    options: &impl HasAnalysisOptions,
    cancel_token: CancellationToken,
    stream: &mut (impl Stream<Item = AggregateEvent> + std::marker::Unpin),
) {
    let mut out = options.output().unwrap();
    let mut should_stop = false;
    let wait_interval = Duration::from_millis(1000);
    let mut end_reason: StreamEndReason = StreamEndReason::Unknown;

    while !should_stop {
        if check_cancel!(cancel_token, should_stop, end_reason) {
            break;
        }
        if let Ok(next_result) = tokio::time::timeout(wait_interval, stream.next()).await {
            // Received an either an error or an Aggregate
            if let Some(aggregate_event) = next_result {
                check_eoe!(aggregate_event, should_stop, end_reason);
                #[allow(clippy::single_match)]
                match aggregate_event {
                    AggregateEvent::Isr(isr) => {
                        if isr.entered {
                            writeln!(out, "{isr}").unwrap();
                        }
                        let mut level = 0;

                        for fg in isr.stack.iter() {
                            let op = if fg.entered { "E" } else { "X" };

                            let mut padding = String::from("");
                            for _ in 0..level {
                                padding.push(' ');
                            }
                            writeln!(
                                out,
                                "{:010} {}{} {}",
                                fg.insn_num, op, padding, fg.function_signature
                            )
                            .unwrap();
                            if fg.entered {
                                level += 2;
                            } else if level <= 2 {
                                level = 2;
                            } else {
                                level -= 2;
                            }
                        }
                    }
                    _ => {}
                }
            } else {
                // end of stream
                should_stop = true;
                end_reason = StreamEndReason::EndOfStream;
            }
        } else {
            // TIMEOUT: Event has not been received
            should_stop = true;
            end_reason = StreamEndReason::NotResponding;
        }
    }

    // finish ...
    writeln!(out, "Finished: reason: {end_reason}").unwrap();
}

pub struct EventRepeater {
    cancel_token: CancellationToken,
}

impl EventRepeater {
    pub fn new(cancel_token: CancellationToken) -> Self {
        Self { cancel_token }
    }

    pub async fn events<'a>(
        &'a self,
        erx: &'a mut Receiver<StartTraceAppSessionResponse>,
    ) -> Result<impl futures_core::Stream<Item = crate::event::AggregateEvent> + 'a, tonic::Status>
    {
        let mut done = false;
        const INTERVAL_MILLIS: u64 = 1000;
        let wait_interval = tokio::time::Duration::from_millis(INTERVAL_MILLIS);

        let result = async_stream::stream! {

            while !done {
                while let Ok(msg) = timeout(wait_interval, erx.recv()).await {
                    if let Some(mut response) = msg {
                        while let Some(e) = response.memory_writes.pop() {
                            yield AggregateEvent::Memory(Box::new(e));
                        }
                        while let Some(e) = response.instructions.pop() {
                            yield AggregateEvent::Instruction(e)
                        }
                        while let Some(e) = response.basic_blocks.pop() {
                            yield AggregateEvent::Block(e)
                        }
                        while let Some(e) = response.interrupts.pop() {
                            yield AggregateEvent::Isr(e)
                        }
                        while let Some(e) = response.functions.pop() {
                            yield AggregateEvent::Function(e)
                        }

                        if let Some(e) = response.timeout {
                            done = true;
                            yield AggregateEvent::RawTimeout(e)
                        }
                        if let Some(e) = response.insn_limit_reached {
                            done = true;
                            yield AggregateEvent::InsnLimitReached(e.insn_num)
                        }
                        while let Some(e) = response.end_of_events.pop() {
                            done = true;
                            yield AggregateEvent::NoMoreEvents(e);
                        }
                        if self.cancel_token.is_cancelled() {
                            done = true;
                            yield AggregateEvent::Error("Cancellation Request".into())
                        }
                        if done {
                            break;
                        }

                    }
                    else {
                        // end of stream
                        done = true;
                    }
                }
                // timeout receiving a message, check for cancellation
                if self.cancel_token.is_cancelled() {
                    done = true;
                }
            }


        };

        Ok(result)
    }
}
