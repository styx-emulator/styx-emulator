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

use bitfield_struct::bitfield;
use enum_map::EnumMap;
use styx_core::{cpu::arch::ppc32::Ppc32Register, prelude::CpuBackend};
use tracing::{debug, trace};

use super::{Event, Register};

/// Runtime state for an [Event]. Always interfaced through [EventsContainer].
#[derive(PartialEq, Eq, Debug, Clone)]
pub struct EventState {
    /// [Event] that this state is holding for.
    event: Event,
    /// Is this event enabled? Could be always enabled or enabled via a configuration register.
    ///
    /// Note: use [EventState::enabled()] to check if enabled, including if
    /// always enabled (e.g. emu, reset, etc.)
    enabled: bool,
    /// Is this event latched? Latched events will be serviced in the future. An event will stay
    /// latched but not serviced if it is not enabled.
    latched: bool,
}

impl EventState {
    /// Is this event enabled?
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Removes the latch.
    pub fn unlatch(&mut self) {
        self.latched = false;
    }
}

/// Source-of-truth manager for events.
#[derive(Debug)]
pub struct EventsContainer {
    /// A mapping of event types to event states.
    exceptions: EnumMap<Event, EventState>,

    msr: Register,
}

#[derive(Debug)]
pub enum LatchError {
    /// Event is already latched.
    AlreadyLatched,
}
impl EventsContainer {
    pub fn new(cpu: &mut dyn CpuBackend) -> Self {
        let exceptions = EnumMap::from_fn(|event| EventState {
            event,
            enabled: false,
            latched: false,
        });
        Self {
            exceptions,
            msr: Register::new(Ppc32Register::Msr, cpu),
        }
    }

    fn find<P>(&self, mut predicate: P) -> Option<Event>
    where
        P: FnMut(&EventState) -> bool,
    {
        self.exceptions
            .iter()
            .find(|(_, exception)| predicate(exception))
            .map(|(event, _)| event)
    }

    /// Latches event, returning Err if already latched or if pending.
    ///
    /// Does not check mask.
    pub fn latch(&mut self, event: Event) -> Result<(), LatchError> {
        let exception = &mut self.exceptions[event];

        if exception.latched {
            Err(LatchError::AlreadyLatched)
        } else {
            exception.latched = true;
            Ok(())
        }
    }

    /// Returns the highest priority event that is both latched and enabled.
    ///
    /// This method iterates over all events, checking if each event's state is both latched
    /// (`latched` field) and enabled (`enabled` method).
    ///
    /// If no such event is found, an `Option<Event>` with a value of `None` will be returned.
    /// Otherwise, the highest priority matching event will be returned.
    pub fn first_latched_and_enabled(&self) -> Option<Event> {
        self.find(|exception| exception.latched && exception.enabled())
    }

    pub fn event(&mut self, event: Event) -> &mut EventState {
        &mut self.exceptions[event]
    }

    pub fn set_enable(&mut self, event: Event, enabled: bool) {
        let enabled_str = match enabled {
            true => "enabled",
            false => "disabled",
        };
        trace!("{event:?} {enabled_str}");
        self.exceptions[event].enabled = enabled;
    }

    pub fn code_hook(&mut self, cpu: &mut dyn CpuBackend) {
        self.msr = self.msr.clone().update_clone(cpu, |cpu, value| {
            let msr = MachineStateRegisterBitfield::from_bits(value);

            let ee = msr.external_interrupts_enable();
            let pc = cpu.pc().unwrap();
            debug!("set external to {ee} @ 0x{pc:X}");
            self.set_enable(Event::ProgrammableInterruptTimer, ee);
            self.set_enable(Event::FixedIntervalTimerInterrupt, ee);
            self.set_enable(Event::ExternalInput, ee);
            self.set_enable(Event::Uart, ee);

            value
        });
    }
}

#[bitfield(u32)]
struct MachineStateRegisterBitfield {
    /// reserved
    #[bits(4)]
    __: u8,

    data_relocate_enable: bool,
    instruction_relocate_enable: bool,
    /// reserved
    #[bits(2)]
    __: u8,

    #[bits(1)]
    floating_point_exception_mode_one: u8,
    debug_interrupts_enable: bool,
    debug_wait_enable: bool,
    #[bits(1)]
    floating_point_exception_mode_zero: u8,

    machine_check_enable: bool,
    floating_point_available: bool,
    #[bits(1)]
    problem_state: u8,
    external_interrupts_enable: bool,

    /// reserved
    #[bits(1)]
    __: u8,
    critical_interrupts_enable: bool,
    wait_state_enable: bool,
    apu_exception_enable: bool,

    /// reserved
    #[bits(5)]
    __: u8,
    auxiliary_processor_available: bool,
    /// reserved
    #[bits(6)]
    __: u8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    /// Tests that when two events are latched simultaneously the one with the highest precedence (smallest priority) is taken first.
    fn test_event_priority() {
        let exceptions = EnumMap::from_fn(|event| EventState {
            event,
            enabled: false,
            latched: false,
        });

        let mut evt_container = EventsContainer {
            exceptions,
            msr: Register {
                register: Ppc32Register::Msr.into(),
                prev_value: 0,
            },
        };

        evt_container.set_enable(Event::ExternalInput, true);
        evt_container.set_enable(Event::ProgrammableInterruptTimer, true);

        evt_container.latch(Event::ExternalInput).unwrap();
        evt_container
            .latch(Event::ProgrammableInterruptTimer)
            .unwrap();

        let first_evt = evt_container.first_latched_and_enabled();

        assert_eq!(Some(Event::ExternalInput), first_evt);
    }
}
