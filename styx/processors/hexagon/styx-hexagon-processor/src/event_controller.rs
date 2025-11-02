// SPDX-License-Identifier: BSD-2-Clause

use styx_core::{
    cpu::CpuBackend,
    errors::UnknownError,
    event_controller::{ActivateIRQnError, InterruptExecuted, Peripherals},
    memory::Mmu,
    prelude::{
        log::{trace, warn},
        EventControllerImpl, ExceptionNumber,
    },
};

#[derive(Default)]
pub struct HexagonEventController {}

impl EventControllerImpl for HexagonEventController {
    fn next(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        _peripherals: &mut Peripherals,
    ) -> Result<InterruptExecuted, UnknownError> {
        trace!("event controller next unimplemented");
        Ok(InterruptExecuted::NotExecuted)
    }

    fn latch(&mut self, _event: ExceptionNumber) -> Result<(), ActivateIRQnError> {
        todo!()
    }

    fn execute(
        &mut self,
        _irq: ExceptionNumber,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
    ) -> Result<InterruptExecuted, ActivateIRQnError> {
        todo!()
    }

    fn finish_interrupt(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
    ) -> Option<ExceptionNumber> {
        todo!()
    }

    fn init(&mut self, _cpu: &mut dyn CpuBackend, _mmu: &mut Mmu) -> Result<(), UnknownError> {
        trace!("the hexagon event controller has started");
        Ok(())
    }
}
