// SPDX-License-Identifier: BSD-2-Clause
use log::debug;
use styx_errors::UnknownError;

use crate::{cpu::CpuBackend, memory::Mmu};

use super::{
    ActivateIRQnError, EventControllerImpl, ExceptionNumber, InterruptExecuted, Peripherals,
};

#[derive(Default)]
/// A placeholder event controller, does nothing.
pub struct DummyEventController {}

impl EventControllerImpl for DummyEventController {
    fn next(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        _peripherals: &mut Peripherals,
    ) -> Result<InterruptExecuted, UnknownError> {
        debug!("dummy event controller next");

        Ok(InterruptExecuted::NotExecuted)
    }

    fn latch(&mut self, event: ExceptionNumber) -> Result<(), ActivateIRQnError> {
        debug!("dummy event controller latched with {event:?}");
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

    /// todo add cpu, mmu refs
    fn tick(&mut self, _cpu: &mut dyn CpuBackend, _mmu: &mut Mmu) -> Result<(), UnknownError> {
        debug!("dummy event controller tick");
        Ok(())
    }

    fn finish_interrupt(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
    ) -> Option<ExceptionNumber> {
        None
    }

    fn init(&mut self, _cpu: &mut dyn CpuBackend, _mmu: &mut Mmu) -> Result<(), UnknownError> {
        Ok(())
    }
}
