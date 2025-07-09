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
use as_any::AsAny;
use log::debug;
use static_assertions::assert_obj_safe;
use styx_errors::UnknownError;

use crate::{cpu::CpuBackend, memory::Mmu, processor::BuildingProcessor};

use super::{Delta, EventControllerImpl, ExceptionNumber};

assert_obj_safe!(Peripheral);

/// The common interface for all Styx peripherals.
///
/// Implementing this trait gives peripheral implementations the ability
/// to register hooks with the processor, update state while the processor
/// is running, and to receive callbacks when the target software have
/// completed the ISR.
pub trait Peripheral: AsAny + Send {
    /// called before peripheral is added to the event controller
    fn init(&mut self, _proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        Ok(())
    }

    /// Reset the peripheral's state.
    fn reset(&mut self, _cpu: &mut dyn CpuBackend, _mmu: &mut Mmu) -> Result<(), UnknownError> {
        Ok(())
    }

    /// The name of the peripheral.
    ///
    /// This is used to check for duplicates, so peripheral names should be unique.
    fn name(&self) -> &str;

    /// Return the exception numbers that belong to this peripheral
    fn irqs(&self) -> Vec<ExceptionNumber> {
        vec![]
    }

    /// Called by the event controller when an event that belongs to this peripheral finishes.
    ///
    /// Useful for post-event cleanup, or re-latching an event after the current event finishes.
    fn post_event_hook(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        _event_controller: &mut dyn EventControllerImpl,
        _irqn: ExceptionNumber,
    ) -> Result<(), UnknownError> {
        Ok(())
    }

    /// Called on processor start. Called each time the processor is started after pause.
    fn on_processor_start(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        _event_controller: &mut dyn EventControllerImpl,
    ) -> Result<(), UnknownError> {
        Ok(())
    }

    /// Called on processor stop. Called each time the processor is pause.
    fn on_processor_stop(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        _event_controller: &mut dyn EventControllerImpl,
    ) -> Result<(), UnknownError> {
        Ok(())
    }

    /// Tick the peripheral, ran every so often.
    ///
    /// Useful for checking and handling asynchronous events and acting on the
    /// cpu on behalf of them.
    fn tick(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        _event_controller: &mut dyn EventControllerImpl,
        _delta: &Delta,
    ) -> Result<(), UnknownError> {
        Ok(())
    }
}

#[derive(Default, Debug)]
/// A placeholder peripheral, does nothing.
pub struct DummyPeripheral;

impl Peripheral for DummyPeripheral {
    fn init(&mut self, _proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        debug!("dummy peripheral initialized");
        Ok(())
    }
    fn name(&self) -> &str {
        "DummyPeripheral"
    }

    fn tick(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        _event_controller: &mut dyn EventControllerImpl,
        _delta: &Delta,
    ) -> Result<(), UnknownError> {
        debug!("dummy peripheral tick");
        Ok(())
    }
}
