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

use styx_core::{event_controller::Exception, prelude::*};

use enum_map::Enum;
use num_enum::{IntoPrimitive, TryFromPrimitive};
use thiserror::Error;

/// Possible interrupts events.
///
/// Variant representation is the event's event number.
///
/// Ordering of [Event]s is determined by priority level, which is inverse to
/// the event number. For example, [Event::Critical] > [Event::MachineCheck].
#[derive(Clone, Copy, PartialEq, Eq, IntoPrimitive, TryFromPrimitive, Enum, Debug)]
#[repr(u8)]
pub enum Event {
    Critical = 0,
    MachineCheck,
    DataStorage,
    InstructionStorage,
    ExternalInput,
    Alignment,
    Program,
    FloatingPointUnavailable,
    SystemCall,
    AuxiliaryProcessorUnavailable,
    ProgrammableInterruptTimer,
    FixedIntervalTimerInterrupt,
    WatchdogTimer,
    DataTLBError,
    InstructionTLBError,
    Debug,
    // events belonging to the external controller
    Uart,
    Ethernet,
}

impl PartialOrd for Event {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for Event {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // reverse because for prio less more higher priority
        self.priority().cmp(&other.priority()).reverse()
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Category {
    Critical,
    Noncritical,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Class {
    Asynchronous,
    MachineCheck,
    Synchronous,
}

const EXTERNAL_EVENT_PRIORITY: u8 = 16;

impl Event {
    pub fn priority(self) -> u8 {
        match self {
            Event::Critical => 5,
            Event::MachineCheck => 1,
            Event::DataStorage => 12,
            Event::InstructionStorage => 8,
            Event::ExternalInput => EXTERNAL_EVENT_PRIORITY,
            Event::Alignment => 14,
            Event::Program => 9,
            Event::FloatingPointUnavailable => 9,
            Event::SystemCall => 9,
            Event::AuxiliaryProcessorUnavailable => 9,
            Event::ProgrammableInterruptTimer => 18,
            Event::FixedIntervalTimerInterrupt => 17,
            Event::WatchdogTimer => 6,
            Event::DataTLBError => 11,
            Event::InstructionTLBError => 7,
            Event::Debug => 2,
            // any other events that get added should be external events which need to have the same priority as ExternalInput
            _ => EXTERNAL_EVENT_PRIORITY,
        }
    }

    pub fn category(self) -> Category {
        match self {
            Event::Critical | Event::MachineCheck | Event::WatchdogTimer | Event::Debug => {
                Category::Critical
            }
            _ => Category::Noncritical,
        }
    }

    pub fn class(self) -> Class {
        match self {
            Event::DataStorage
            | Event::InstructionStorage
            | Event::Alignment
            | Event::Program
            | Event::FloatingPointUnavailable
            | Event::SystemCall
            | Event::AuxiliaryProcessorUnavailable
            | Event::DataTLBError
            | Event::InstructionTLBError
            | Event::Debug => Class::Synchronous,
            Event::Critical
            | Event::ExternalInput
            | Event::FixedIntervalTimerInterrupt
            | Event::ProgrammableInterruptTimer
            | Event::WatchdogTimer
            | Event::Uart
            | Event::Ethernet => Class::Asynchronous,
            Event::MachineCheck => Class::MachineCheck,
        }
    }

    /// Does this event belong to the external event controller?
    pub fn is_external(self) -> bool {
        // `Event::ExternalInput` is a signal on the main interrupt controller, so even though it has external in the name it doesn't belong to the external event controller
        (self.priority() == EXTERNAL_EVENT_PRIORITY) && (self != Event::ExternalInput)
    }

    /// Is this an asynchronous event or system call?
    pub fn async_or_system_call(self) -> bool {
        self.class() == Class::Asynchronous || self == Event::SystemCall
    }

    pub fn from_event_irqn_expect(value: ExceptionNumber) -> Self {
        Self::try_from(value)
            .unwrap_or_else(|_| panic!("invalid irqn for ppc405 interrupt controller: {value}"))
    }

    pub fn event_number(self) -> u8 {
        self.into()
    }

    /// Offset into the exception vector (EVPR).
    pub fn offset(self) -> u64 {
        match self {
            Event::Critical => 0x0100,
            Event::MachineCheck => 0x0200,
            Event::DataStorage => 0x0300,
            Event::InstructionStorage => 0x0400,
            Event::ExternalInput => 0x0500,
            Event::Alignment => 0x0600,
            Event::Program => 0x0700,
            Event::FloatingPointUnavailable => 0x0800,
            Event::SystemCall => 0x0C00,
            Event::AuxiliaryProcessorUnavailable => 0x0F20,
            Event::ProgrammableInterruptTimer => 0x1000,
            Event::FixedIntervalTimerInterrupt => 0x1010,
            Event::WatchdogTimer => 0x1020,
            Event::DataTLBError => 0x1100,
            Event::InstructionTLBError => 0x1200,
            Event::Debug => 0x2000,
            // external interrupts should go to the ExternalInput vector
            _ => 0x0500,
        }
    }
}

#[derive(Error, Debug)]
#[error("could not convert {0} to an event")]
pub struct EventConvert(i32);
impl TryFrom<ExceptionNumber> for Event {
    type Error = EventConvert;

    fn try_from(value: ExceptionNumber) -> Result<Self, Self::Error> {
        Self::try_from(u8::try_from(value).map_err(|_| EventConvert(value))?)
            .map_err(|_| EventConvert(value))
    }
}

impl From<Event> for ExceptionNumber {
    fn from(value: Event) -> Self {
        value.event_number() as i32
    }
}

impl From<Event> for Exception {
    fn from(value: Event) -> Self {
        Exception {
            name: format!("{value:?}").into(),
            number: value.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cmp::Ordering;
    use test_case::test_case;

    use super::*;

    #[test_case(Event::Critical, Event::MachineCheck, Ordering::Less)]
    #[test_case(
        Event::FixedIntervalTimerInterrupt,
        Event::ProgrammableInterruptTimer,
        Ordering::Greater
    )]
    #[test_case(Event::Critical, Event::ProgrammableInterruptTimer, Ordering::Greater)]
    #[test_case(Event::MachineCheck, Event::MachineCheck, Ordering::Equal)]
    #[test_case(
        Event::ProgrammableInterruptTimer,
        Event::ExternalInput,
        Ordering::Less
    )]
    fn test_ordering(a: Event, b: Event, answer: Ordering) {
        assert_eq!(answer, a.cmp(&b));
    }

    #[test_case(Event::SystemCall, 8)]
    #[test_case(Event::Critical, 0)]
    #[test_case(Event::MachineCheck, 1)]
    #[test_case(Event::InstructionStorage, 3)]
    fn test_from_event_irqn(event: Event, irqn: ExceptionNumber) {
        let actual_event = Event::from_event_irqn_expect(irqn);
        assert_eq!(actual_event, event);

        let actual_irqn = ExceptionNumber::from(actual_event);
        assert_eq!(actual_irqn, irqn);
    }

    #[test_case(Event::ExternalInput, false)]
    #[test_case(Event::Uart, true)]
    #[test_case(Event::Debug, false)]
    #[test_case(Event::Ethernet, true)]
    fn test_is_external(event: Event, expected: bool) {
        assert_eq!(event.is_external(), expected);
    }
}
