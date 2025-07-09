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
mod event;
mod exception;
mod external_event_controller;
mod hooks;

use std::sync::Arc;

pub use event::*;
use exception::*;
use external_event_controller::ExternalEventController;
use styx_core::event_controller::{ActivateIRQnError, Exception, OptionalFeatureError};
use styx_core::prelude::*;
use styx_core::{cpu::arch::ppc32::Ppc32Register, event_controller::InterruptExecuted};

use tokio::runtime::Handle;

#[derive(Debug, Clone)]
pub struct Register {
    register: ArchRegister,
    prev_value: u32,
}
impl Register {
    pub fn new(register: impl Into<ArchRegister>, cpu: &mut dyn CpuBackend) -> Self {
        let register = register.into();
        let initial_value = cpu.read_register::<u32>(register).unwrap();

        Self {
            register,
            prev_value: initial_value,
        }
    }

    pub fn update(
        &mut self,
        cpu: &mut dyn CpuBackend,
        on_change: impl FnOnce(&mut dyn CpuBackend, u32) -> u32,
    ) {
        let new_value = cpu.read_register::<u32>(self.register).unwrap();
        if new_value != self.prev_value {
            let hook_modified_new_value = on_change(cpu, new_value);
            cpu.write_register(self.register, hook_modified_new_value)
                .unwrap();
            self.prev_value = hook_modified_new_value;
        }
    }

    pub fn update_clone(
        mut self,
        cpu: &mut dyn CpuBackend,
        on_change: impl FnOnce(&mut dyn CpuBackend, u32) -> u32,
    ) -> Self {
        self.update(cpu, on_change);
        self
    }
}

pub struct CoreEventController {
    exceptions: EventsContainer,
    /// reference to the external interrupt controller that handles events from peripherals
    external_controller: Arc<ExternalEventController>,
    /// holds currently executing interrupt
    interrupt_stack: Vec<ExceptionNumber>,
}

impl CoreEventController {
    pub fn new(cpu: &mut dyn CpuBackend, _runtime_handle: Handle) -> Self {
        let exceptions = EventsContainer::new(cpu);

        Self {
            exceptions,
            external_controller: ExternalEventController::new_arc(),
            interrupt_stack: Vec::with_capacity(8),
        }
    }

    // TODO add this back in
    // /// Handle post-irq things
    // fn post_irq_route_hook(&mut self) {
    //     if let Some(evt) = self.interrupt_stack.pop() {
    //         trace!(target: "interrupts", "{{\"type\": \"interrupts\", \"action\": \"complete\", \"event\": {}}}", evt);

    //         if let Some(peripheral) = self.irq_to_peripheral(evt) {
    //             if let Err(out) = peripheral.post_event_hook(evt) {
    //                 warn!("Error during post-event hook for irq: {}, `{}`", evt, out);
    //             }
    //         }
    //     } else {
    //         warn!("interrupt stack out of sync.");
    //     }
    // }

    fn service_interrupt(
        &mut self,
        cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        event: Event,
    ) -> Result<InterruptExecuted, UnknownError> {
        // at this point we know that the event is latched and enabled

        // section 5.4 details behavior when interrupt is taken

        // the processor will jump to the interrupt handler address which
        // is comprised of the event's offset (static) concatenated with
        // the 16 high-order bits of evpr.
        let evpr = cpu.read_register::<u32>(Ppc32Register::Evpr)?;
        let interrupt_handler_address = evpr + event.offset() as u32;

        let pc = cpu.pc()? as u32;
        // save the current or next pc to save in srr0 or srr2 (for critical interrupts)
        let saved_pc = if event.async_or_system_call() {
            pc
        } else {
            pc - 4
        };
        let msr = cpu.read_register::<u32>(Ppc32Register::Msr)?;

        // save pc and msr to SRRX registers, depending on category
        match event.category() {
            Category::Critical => {
                cpu.write_register(Ppc32Register::SRR2, saved_pc)?;
                cpu.write_register(Ppc32Register::SRR3, msr)?;
            }
            Category::Noncritical => {
                cpu.write_register(Ppc32Register::SRR0, saved_pc)?;
                cpu.write_register(Ppc32Register::SRR1, msr)?;
            }
        };

        // msr is written with 0s,
        // SHORTCOMING: Depending on the event taken, certain bits should be left
        // unchanged instead of cleared. Currently we clear all bits.
        // SHORTCOMING: Events have other registers that are written
        // (e.g. PIT sets PIS bit in TSR). This is currently not done.
        //
        // every interrupts behavior is documented in section 5.x (5.6 - 5.21)
        cpu.write_register(Ppc32Register::Msr, 0u32)?;

        cpu.set_pc(interrupt_handler_address as u64)?;

        self.exceptions.event(event).unlatch();

        self.interrupt_stack.push(event.into());

        log::debug!("event {event:?} executing at 0x{interrupt_handler_address:X} (wrote saved_pc: 0x{saved_pc:X}");

        Ok(InterruptExecuted::Executed)
    }
}
impl EventControllerImpl for CoreEventController {
    fn next(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
        _peripherals: &mut styx_core::event_controller::Peripherals,
    ) -> Result<InterruptExecuted, UnknownError> {
        let next_latched = self.exceptions.first_latched_and_enabled();
        // info!("CEC next: {next_latched:?}");

        if let Some(next_latched) = next_latched {
            // we don't have to check for other interrupts because
            // taken interrupts clear msr and disable them
            log::debug!("executing new interrupt: {next_latched:?}");
            self.service_interrupt(cpu, mmu, next_latched)
        } else {
            // no interrupt latched
            Ok(InterruptExecuted::NotExecuted)
        }
    }

    fn latch(&mut self, event_number: ExceptionNumber) -> Result<(), ActivateIRQnError> {
        let event = Event::try_from(event_number)
            .map_err(|_| ActivateIRQnError::InvalidIRQn(event_number))?;
        log::debug!("latching event {event_number}: {event:?}");

        // if the event is an external event, we pass it to the external controller
        // the return value tells us if we then exit or continue to latch the event
        if event.is_external() && !self.external_controller.handle_event(event) {
            return Ok(());
        }

        let latch_result = self.exceptions.latch(event);
        match latch_result {
            Ok(_) => {
                log::trace!("Latched {event:?}");
            }
            Err(err) => log::trace!("{event:?} couldn't latch because of {err:?} "),
        }

        Ok(())
    }

    fn execute(
        &mut self,
        irq: ExceptionNumber,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
    ) -> Result<InterruptExecuted, ActivateIRQnError> {
        let event = Event::from_event_irqn_expect(irq);
        log::debug!("executing interrupt {event:?}");
        Ok(self.service_interrupt(cpu, mmu, event)?)
    }

    fn finish_interrupt(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
    ) -> Option<ExceptionNumber> {
        self.interrupt_stack.pop()
    }

    fn init(&mut self, cpu: &mut dyn CpuBackend, _mmu: &mut Mmu) -> Result<(), UnknownError> {
        cpu.intr_hook(Box::new(hooks::interrupt_hook))?;
        cpu.add_hook(StyxHook::code(.., hooks::EventsContainerCodeHook))?;

        // invalid instruction hook for return from interrupt workaround.
        // Q: Why is this not a code hook?
        // A: Jumping to 0x99999998 causes an instruction decode error which gets handled before code hooks.
        // So if we don't have an invalid instruction hook, the program will panic.
        cpu.invalid_intr_hook(Box::new(hooks::interrupt_return_hook))?;

        self.external_controller.register_hooks(cpu)?;

        Ok(())
    }

    fn reset(&mut self, _cpu: &mut dyn CpuBackend, mmu: &mut Mmu) -> Result<(), UnknownError> {
        self.external_controller.reset(mmu)?;
        Ok(())
    }

    fn current_exception(&mut self) -> Result<Option<Exception>, OptionalFeatureError> {
        let item = self.interrupt_stack.first();
        Ok(match item {
            Some(exception_number) => Some(
                Event::try_from(*exception_number)
                    .context("could not get Event")?
                    .into(),
            ),
            None => None,
        })
    }
}
