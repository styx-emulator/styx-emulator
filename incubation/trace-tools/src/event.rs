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
//! _Cooked_ (as opposed to _Raw_ events from [styx_trace](styx_core::tracebus)) event definitions

use std::fmt::Display;

use styx_core::grpc::traceapp::{
    BasicBlock, EndOfEvents, FunctionGate, InstructionExec, Interrupt, MemoryChange, Timeout,
};

/// A set events emitted based on LevelX trace analysis.
///
/// Categories (or potential) categories of events:
///
/// (Potential) Categories of events:
/// - Control: simply used to convey information (some limit reached,
///   no more events, timeouts, etc)
/// - Aggregate: some aggregation or enrichment of an event or set of related
///   events from a Level 1 emulation event. This could be as simple repeating
///   a memory access event, but replacing machine addresses with symbolic names
///   and / or types
#[derive(Debug, Clone, PartialEq)]
pub enum AggregateEvent {
    /// BasicBlock
    Block(BasicBlock),

    // Error
    /// An error occurred
    Error(String),
    /// A function call was entered or exited
    Function(FunctionGate),
    // Control Events
    /// A requested instruction count limit was reached
    InsnLimitReached(u64),
    /// An instruction was executed
    Instruction(InstructionExec),

    // Aggregate / Enriched Events
    /// Interrupt event received
    Isr(Interrupt),
    /// Memory has changed (ie: was written to)
    Memory(Box<MemoryChange>),
    /// There are no more events to process.
    NoMoreEvents(EndOfEvents),
    /// A timeout occurred reading raw (input) events
    RawTimeout(Timeout),
    /// sentinal event to avoid [`Option<Event>`]
    Sentinal,
    /// A stop (processing events) has been reauested
    StopRequested,
}

impl AggregateEvent {
    /// should we stop / pause processing of inbound events?
    pub fn should_pause(&self) -> bool {
        matches!(
            self,
            Self::NoMoreEvents(_)
                | Self::InsnLimitReached(_)
                | Self::RawTimeout(_)
                | Self::StopRequested
                | Self::Error(_)
        )
    }

    /// special case of should_pause - there are no more raw events
    /// at the moment
    pub fn is_no_more(&self) -> bool {
        matches!(self, Self::NoMoreEvents(_))
    }
}

impl std::fmt::Display for AggregateEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            AggregateEvent::Sentinal => "Event::Sentinal".to_string(), // ignore sentinal
            AggregateEvent::Memory(v) => format!("Event::{}", v),
            AggregateEvent::Function(v) => format!("Event::Function {}", v),
            AggregateEvent::Instruction(v) => format!("Event::Instruction {}", v),
            AggregateEvent::Block(v) => format!("Event::Block {}", v),
            AggregateEvent::NoMoreEvents(v) => format!("Event::NoMoreEvents {}", v),
            AggregateEvent::InsnLimitReached(v) => format!("Event::InsnLimitReached {}", v),
            AggregateEvent::StopRequested => "Event::StopRequested".to_string(),
            AggregateEvent::RawTimeout(v) => format!("Event::RawTimeout {}", v),
            AggregateEvent::Isr(v) => format!("Event::Isr {}", v),
            AggregateEvent::Error(v) => format!("Event::Error {}", v),
        };
        write!(f, "{s}")
    }
}

#[derive(Clone, Debug)]
pub enum StreamEndReason {
    Cancelled,
    EndOfEvents,
    EndOfStream,
    ErrorEvent,
    InsnLimitReached,
    NotResponding,
    RawTimeout,
    RxDropped,
    StopRequested,
    Unknown,
}
impl From<AggregateEvent> for StreamEndReason {
    fn from(value: AggregateEvent) -> Self {
        match value {
            AggregateEvent::Sentinal
            | AggregateEvent::Isr(_)
            | AggregateEvent::Memory(_)
            | AggregateEvent::Instruction(_)
            | AggregateEvent::Function(_)
            | AggregateEvent::Block(_) => Self::Unknown,
            AggregateEvent::InsnLimitReached(_) => Self::InsnLimitReached,
            AggregateEvent::NoMoreEvents(_) => Self::EndOfEvents,
            AggregateEvent::RawTimeout(_) => Self::RawTimeout,
            AggregateEvent::StopRequested => Self::StopRequested,
            AggregateEvent::Error(_) => Self::ErrorEvent,
        }
    }
}
impl Display for StreamEndReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                StreamEndReason::Unknown => "Unknown",
                StreamEndReason::RxDropped => "RxDropped",
                StreamEndReason::RawTimeout => "RawTimeout",
                StreamEndReason::InsnLimitReached => "InsnLimitReached",
                StreamEndReason::EndOfEvents => "EndOfEvents",
                StreamEndReason::EndOfStream => "EndOfStream",
                StreamEndReason::Cancelled => "Cancelled",
                StreamEndReason::StopRequested => "StopRequested",
                StreamEndReason::NotResponding => "NotResponding",
                StreamEndReason::ErrorEvent => "ErrorEvent",
            }
        )
    }
}
