// SPDX-License-Identifier: BSD-2-Clause
use log::debug;
use styx_errors::UnknownError;

use crate::{
    cpu::CpuBackend,
    memory::{MemoryBackend, Mmu},
    processor::Config,
};

use super::{ActivateIRQnError, EventControllerImpl, ExceptionNumber, InterruptExecuted};
use crate::executor::Delta;

#[derive(Default)]
/// A placeholder secondary (per-vCPU) event controller, does nothing.
pub struct DummyEventController {}

impl EventControllerImpl for DummyEventController {
    fn next(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
    ) -> Result<InterruptExecuted, UnknownError> {
        debug!("dummy secondary event controller next");
        Ok(InterruptExecuted::NotExecuted)
    }

    fn latch(&mut self, event: ExceptionNumber) -> Result<(), ActivateIRQnError> {
        debug!("dummy secondary event controller latched with {event:?}");
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

    fn tick(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        _delta: &Delta,
    ) -> Result<(), UnknownError> {
        debug!("dummy secondary event controller tick");
        Ok(())
    }

    fn finish_interrupt(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
    ) -> Option<ExceptionNumber> {
        None
    }

    fn init(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut MemoryBackend,
        _init: &mut Config,
    ) -> Result<(), UnknownError> {
        Ok(())
    }
}
