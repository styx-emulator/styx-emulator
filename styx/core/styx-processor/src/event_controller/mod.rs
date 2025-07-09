// SPDX-License-Identifier: BSD-2-Clause
//! Part of the Processor Core used for managing peripherals and handling interrupts.
mod dummy;
mod peripheral;
mod peripherals;

use std::{any::type_name, borrow::Cow, fmt::Display};

use as_any::AsAny;
pub use dummy::DummyEventController;
pub use peripheral::{DummyPeripheral, Peripheral};
pub use peripherals::Peripherals;

use log::trace;
use static_assertions::assert_obj_safe;
use styx_errors::{
    anyhow::{anyhow, Context},
    UnknownError,
};
use thiserror::Error;

use crate::{cpu::CpuBackend, executor::Delta, memory::Mmu};

pub type ExceptionNumber = i32;

#[derive(Debug)]
pub enum InterruptExecuted {
    Executed,
    NotExecuted,
}

#[derive(thiserror::Error, Debug)]
pub enum ActivateIRQnError {
    #[error("invalid Event `{0:?}` for this controller")]
    InvalidIRQn(ExceptionNumber),
    #[error(transparent)]
    Unknown(#[from] UnknownError),
}

assert_obj_safe!(EventControllerImpl);
pub trait EventControllerImpl: AsAny + Send {
    /// retrieve and execute the highest priority interrupt
    fn next(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
        peripherals: &mut Peripherals,
    ) -> Result<InterruptExecuted, UnknownError>;

    /// queue an interrupt to be executed
    fn latch(&mut self, event: ExceptionNumber) -> Result<(), ActivateIRQnError>;

    /// directly execute an interrupt (useful for things like syscall)
    fn execute(
        &mut self,
        irq: ExceptionNumber,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
    ) -> Result<InterruptExecuted, ActivateIRQnError>;

    fn on_processor_start(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
    ) -> Result<(), UnknownError> {
        Ok(())
    }

    fn on_processor_stop(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
    ) -> Result<(), UnknownError> {
        Ok(())
    }

    /// Update state of the event controller.
    fn tick(&mut self, _cpu: &mut dyn CpuBackend, _mmu: &mut Mmu) -> Result<(), UnknownError> {
        Ok(())
    }

    fn finish_interrupt(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
    ) -> Option<ExceptionNumber>;

    fn init(&mut self, cpu: &mut dyn CpuBackend, mmu: &mut Mmu) -> Result<(), UnknownError>;

    fn reset(&mut self, _cpu: &mut dyn CpuBackend, _mmu: &mut Mmu) -> Result<(), UnknownError> {
        Ok(())
    }

    /// What is the current running exception?
    ///
    /// - `Ok(None)` indicates no exception is running.
    /// - `Err(CurrentExceptionError::Unsupported)` indicates this feature is not available on this
    ///   event controller.
    fn current_exception(&mut self) -> Result<Option<Exception>, OptionalFeatureError> {
        Err(OptionalFeatureError::Unsupported)
    }

    fn available_exceptions(&mut self) -> Result<Cow<'_, [Exception]>, OptionalFeatureError> {
        Err(OptionalFeatureError::Unsupported)
    }
}

#[derive(Error, Debug)]
pub enum OptionalFeatureError {
    #[error(transparent)]
    Other(#[from] UnknownError),
    #[error("feature not supported by this event controller")]
    Unsupported,
}

#[derive(Clone)]
pub struct Exception {
    pub name: Cow<'static, str>,
    pub number: ExceptionNumber,
}

impl Display for Exception {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name)
    }
}

/// The event controller is responsible for owning all of the peripherals
/// attached to a processor and for handling events.
pub struct EventController {
    /// Processor specific event controller implementation
    pub inner: Box<dyn EventControllerImpl>,
    pub peripherals: Peripherals,
}

impl Default for EventController {
    fn default() -> Self {
        Self::new(Box::new(DummyEventController::default()))
    }
}

impl EventController {
    pub fn new(event_controller: Box<dyn EventControllerImpl + Send>) -> Self {
        Self {
            inner: event_controller,
            peripherals: Peripherals::default(),
        }
    }
    pub fn next(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
    ) -> Result<InterruptExecuted, UnknownError> {
        trace!("event controller next");
        self.inner.next(cpu, mmu, &mut self.peripherals)
    }

    pub fn latch(&mut self, event: ExceptionNumber) -> Result<(), ActivateIRQnError> {
        self.inner.latch(event)
    }

    pub fn execute(
        &mut self,
        irq: ExceptionNumber,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
    ) -> Result<InterruptExecuted, ActivateIRQnError> {
        self.inner.execute(irq, cpu, mmu)
    }

    /// Called to indicate the currently executing interrupt is finished, typically called by
    /// instructions like `rfi` (return from interrupt).
    ///
    /// This calls the post_event_hook for the peripheral that triggered the event, if one exists.
    pub fn finish_interrupt(&mut self, cpu: &mut dyn CpuBackend, mmu: &mut Mmu) {
        if let Some(irqn) = self.inner.finish_interrupt(cpu, mmu) {
            if let Ok(p) = self.peripherals.get_peripheral_by_exception(irqn) {
                p.post_event_hook(cpu, mmu, self.inner.as_mut(), irqn)
                    .unwrap();
            }
        }
    }

    pub fn reset(&mut self, cpu: &mut dyn CpuBackend, mmu: &mut Mmu) -> Result<(), UnknownError> {
        self.inner.reset(cpu, mmu)?;
        for peripheral in self.peripherals.peripherals.iter_mut() {
            peripheral.reset(cpu, mmu)?;
        }
        Ok(())
    }

    pub fn on_processor_start(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
    ) -> Result<(), UnknownError> {
        trace!("processor_start event controller");
        // error buffer
        let mut errors = Vec::new();

        // tick impl
        let res = self.inner.on_processor_start(cpu, mmu);
        if let Err(err) = res {
            errors.push(err)
        }

        // tick peripherals
        for peripheral in self.peripherals.peripherals.iter_mut() {
            let result = peripheral.on_processor_start(cpu, mmu, self.inner.as_mut());
            if let Err(err) = result {
                errors.push(err)
            }
        }

        if !errors.is_empty() {
            Err(anyhow!(
                "multiple errors while running processor_start: {errors:?}"
            ))
        } else {
            Ok(())
        }
    }

    pub fn on_processor_stop(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
    ) -> Result<(), UnknownError> {
        trace!("processor_stop event controller");
        // error buffer
        let mut errors = Vec::new();

        // tick impl
        let res = self.inner.on_processor_stop(cpu, mmu);
        if let Err(err) = res {
            errors.push(err)
        }

        // tick peripherals
        for peripheral in self.peripherals.peripherals.iter_mut() {
            let result = peripheral.on_processor_stop(cpu, mmu, self.inner.as_mut());
            if let Err(err) = result {
                errors.push(err)
            }
        }

        if !errors.is_empty() {
            Err(anyhow!(
                "multiple errors while running processor_stop: {errors:?}"
            ))
        } else {
            Ok(())
        }
    }

    // Runs event controller impl tick and all peripheral ticks, collects errors to return later
    pub fn tick(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
        delta: &Delta,
    ) -> Result<(), UnknownError> {
        trace!("ticking event controller");
        // error buffer
        let mut errors = Vec::new();

        // tick impl
        let res = self.inner.tick(cpu, mmu);
        if let Err(err) = res {
            errors.push(err)
        }

        // tick peripherals
        for peripheral in self.peripherals.peripherals.iter_mut() {
            let result = peripheral.tick(cpu, mmu, self.inner.as_mut(), delta);
            if let Err(err) = result {
                errors.push(err)
            }
        }

        if !errors.is_empty() {
            Err(anyhow!("multiple errors while ticking: {errors:?}"))
        } else {
            Ok(())
        }
    }

    pub fn add_peripheral(&mut self, peripheral: Box<dyn Peripheral>) -> Result<(), UnknownError> {
        self.peripherals.insert_peripheral(peripheral)?;
        Ok(())
    }

    pub fn get_impl<T: EventControllerImpl + 'static>(&mut self) -> Result<&mut T, UnknownError> {
        self.inner
            .as_mut()
            .as_any_mut()
            .downcast_mut()
            .with_context(|| {
                format!(
                    "could not downcast event controller impl to {:?}",
                    type_name::<T>()
                )
            })
    }
}
