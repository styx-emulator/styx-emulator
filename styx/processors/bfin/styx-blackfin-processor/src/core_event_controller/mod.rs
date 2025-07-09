// SPDX-License-Identifier: BSD-2-Clause
mod event;
mod exception;
mod hooks;
mod system_interrupts;

use event::*;
use exception::*;
use styx_blackfin_sys::bf512 as sys;
use styx_core::prelude::*;
use styx_core::{
    cpu::arch::blackfin::BlackfinRegister,
    event_controller::{ActivateIRQnError, InterruptExecuted, Peripherals},
};
pub use system_interrupts::PeripheralId;
pub use system_interrupts::*;
use tracing::{debug, trace, warn};

const RETI_ADDRESS: u64 = 0xFFFF_FFF0;

/// Blackfin's Core Interrupt Controller (CEC)
pub struct CoreEventController {
    exceptions: EventsContainer,
    system: Arc<Mutex<PeripheralsContainer>>,
    current_exceptions: Mutex<Vec<ExecutingEvent>>,
}

struct ExecutingEvent {
    event: Event,
    reti: u32,
}

impl Default for CoreEventController {
    fn default() -> Self {
        let exceptions = EventsContainer::default();

        let system = Arc::new(Mutex::new(PeripheralsContainer::new()));

        Self {
            exceptions,
            system,
            current_exceptions: Default::default(),
        }
    }
}

impl CoreEventController {
    /// Get the system interrupt controller.
    pub fn get_sic(&self) -> SicHandle {
        SicHandle::new(&self.system)
    }

    fn service_interrupt(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
        event: Event,
    ) -> Result<InterruptExecuted, UnknownError> {
        // at this point we know that the event is latched and enabled

        let event_vector_table_register = event.evt_address();
        let routine_address = mmu.data().read(event_vector_table_register).le().u32()?;

        let reti_pc = RETI_ADDRESS as u32;
        cpu.write_register(BlackfinRegister::RETI, reti_pc)?;
        self.current_exceptions
            .lock()
            .unwrap()
            .push(ExecutingEvent {
                event,
                reti: cpu.pc().unwrap() as u32,
            });
        cpu.set_pc(routine_address as u64)?;

        self.exceptions.set_pending(event);

        trace!("event {event:?} executing at 0x{routine_address:X}");

        Ok(InterruptExecuted::Executed)
    }

    fn return_from_interrupt(&mut self, cpu: &mut dyn CpuBackend) {
        let returned_interrupt = self
            .current_exceptions
            .lock()
            .unwrap()
            .pop()
            .expect("no executing interrupt after reti");
        let reti_pc = returned_interrupt.reti;
        let ret_event = returned_interrupt.event;

        self.exceptions.clear_pending(ret_event);
        debug!("{ret_event:?} returned to 0x{reti_pc:X}");
        cpu.set_pc(reti_pc as u64).unwrap();
    }
}

impl EventControllerImpl for CoreEventController {
    fn next(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
        _peripherals: &mut Peripherals,
    ) -> Result<InterruptExecuted, UnknownError> {
        let next_latched = self.exceptions.first_latched_and_enabled();

        if let Some(next_latched) = next_latched {
            // There is a latched event
            let current_active = self.exceptions.active_interrupt();

            let should_activate_next_latched = if let Some(current_active) = current_active {
                // another interrupt is active
                // true if if the latched interrupt is higher priority than the one currently running
                if next_latched > current_active {
                    debug!("{next_latched:?} activated because > current {current_active:?}");
                    true
                } else {
                    debug!("{next_latched:?} not activated because < current {current_active:?}");
                    false
                }
            } else {
                debug!("executing new interrupt: {next_latched:?}");

                // we're gonna take this interrupt
                true
            };

            if should_activate_next_latched {
                self.service_interrupt(cpu, mmu, next_latched)
            } else {
                Ok(InterruptExecuted::NotExecuted)
            }
        } else {
            Ok(InterruptExecuted::NotExecuted)
        }
    }

    fn latch(&mut self, event: ExceptionNumber) -> Result<(), ActivateIRQnError> {
        let event = Event::from_event_irqn_expect(event)?;
        trace!("latching event {event:?}: {event:?}");

        let latch_result = self.exceptions.latch(event);
        match latch_result {
            Ok(_) => {
                trace!("Latched {event:?}");
            }
            Err(err) => trace!("{event:?} couldn't latch because of {err:?} "),
        }

        Ok(())
    }

    fn execute(
        &mut self,
        _irq: ExceptionNumber,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
    ) -> Result<InterruptExecuted, ActivateIRQnError> {
        unimplemented!()
    }

    fn tick(&mut self, _cpu: &mut dyn CpuBackend, _mmu: &mut Mmu) -> Result<(), UnknownError> {
        warn!("tick not fully implemented for blackfin event controller yet");
        Ok(())
    }

    fn finish_interrupt(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
    ) -> Option<ExceptionNumber> {
        todo!()
    }

    fn init(&mut self, cpu: &mut dyn CpuBackend, _mmu: &mut Mmu) -> Result<(), UnknownError> {
        register_hooks(cpu)?;
        Ok(())
    }
}

fn register_hooks(cpu: &mut dyn CpuBackend) -> Result<(), UnknownError> {
    cpu.intr_hook(Box::new(hooks::interrupt_hook))?;

    // RETI
    cpu.code_hook(RETI_ADDRESS, RETI_ADDRESS, Box::new(hooks::reti_hook))?;

    // CORE INTERRUPT CONTROLLER
    cpu.mem_write_hook(
        sys::IMASK as u64,
        sys::ILAT as u64,
        Box::new(hooks::core_interrupt_registers_hook),
    )?;

    // SYSTEM INTERRUPT CONTROLLER
    // for now only SIC_IMASK0 and SIC_IMASK1
    cpu.mem_write_hook(
        sys::SIC_IMASK0 as u64,
        sys::SIC_IMASK0 as u64,
        Box::new(hooks::system_interrupt_registers_hook),
    )?;
    cpu.mem_write_hook(
        sys::SIC_IMASK1 as u64,
        sys::SIC_IMASK1 as u64,
        Box::new(hooks::system_interrupt_registers_hook),
    )?;
    cpu.mem_write_hook(
        sys::SIC_IWR0 as u64,
        sys::SIC_IWR0 as u64,
        Box::new(hooks::system_interrupt_registers_hook),
    )?;
    cpu.mem_write_hook(
        sys::SIC_IWR1 as u64,
        sys::SIC_IWR1 as u64,
        Box::new(hooks::system_interrupt_registers_hook),
    )?;
    cpu.mem_write_hook(
        sys::SIC_IAR0 as u64,
        sys::SIC_IAR7 as u64,
        Box::new(hooks::system_interrupt_registers_hook),
    )?;

    Ok(())
}
