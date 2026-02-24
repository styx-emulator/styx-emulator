// SPDX-License-Identifier: BSD-2-Clause
//! Part of the Processor Core used for managing peripherals and handling interrupts.
mod dummy;
mod peripheral;
mod peripherals;
mod single_vcpu_ec;

use std::borrow::Cow;
use std::fmt::Display;
use std::{any::type_name, sync::Arc};

use as_any::AsAny;
pub use dummy::DummyEventController;
use log::trace;
pub use peripheral::{DummyPeripheral, Peripheral, PeripheralTickCtx, RaisedIrqs};
pub use peripherals::Peripherals;
pub use single_vcpu_ec::SingleVcpuEventDistributor;
use smallvec::SmallVec;
use static_assertions::assert_obj_safe;
use styx_errors::anyhow::Context;
use styx_errors::UnknownError;
use thiserror::Error;

use crate::core::VcpuId;
use crate::{
    core::VcpuCore,
    cpu::CpuBackend,
    executor::{time::GlobalDelta, Delta},
    memory::{MemoryBackend, Mmu},
    processor::{Config, PerVcpuSlice},
};

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

/// Used in [`EventControllerImpl::current_exception()`] to indicate not implemented.
///
/// [`EventControllerImpl::current_exception()`] is an optional trait method that
/// event controllers can implement to indicate the currently running exception.
/// Because this is not trivial to implement, it is okay to just report
/// `Err(OptionalFeatureError::Unsupported)`.
#[derive(Error, Debug)]
pub enum OptionalFeatureError {
    #[error(transparent)]
    Other(#[from] UnknownError),
    #[error("feature not supported by this event controller")]
    Unsupported,
}

/// Debug/Introspection representation of an Exception.
///
/// Returned by [`EventController::current_exception()`] to show the currently
/// running exception.
///
/// Used by gdbserver to report running exception via a monitor command.
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

assert_obj_safe!(EventControllerImpl);

/// Per-vCPU interrupt controller interface.
///
/// Handles the interrupt lifecycle for a single virtual CPU: queuing, executing,
/// and completing interrupts. Does not own peripherals which are managed by
/// the [`EventDistributor`].
pub trait EventControllerImpl: AsAny + Send {
    /// Retrieve and execute the highest priority interrupt.
    fn next(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
    ) -> Result<InterruptExecuted, UnknownError>;

    /// Queue an interrupt to be executed.
    fn latch(&mut self, event: ExceptionNumber) -> Result<(), ActivateIRQnError>;

    /// Directly execute an interrupt (useful for things like syscall).
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
    fn tick(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        _delta: &Delta,
    ) -> Result<(), UnknownError> {
        Ok(())
    }

    fn finish_interrupt(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
    ) -> Option<ExceptionNumber>;

    fn init(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut MemoryBackend,
        config: &mut Config,
    ) -> Result<(), UnknownError>;

    fn reset(&mut self, _cpu: &mut dyn CpuBackend, _mmu: &mut Mmu) -> Result<(), UnknownError> {
        Ok(())
    }

    /// What is the current running exception?
    ///
    /// Intended for debugging and introspection (e.g. the gdbserver `event info` monitor
    /// command); this is not used to drive interrupt dispatch. For controllers that support
    /// preemption or nested exceptions, implementations should return the top of the active
    /// exception stack.
    ///
    /// - `Ok(None)` indicates no exception is running.
    /// - `Err(OptionalFeatureError::Unsupported)` indicates this feature is not available on this
    ///   event controller.
    fn current_exception(&mut self) -> Result<Option<Exception>, OptionalFeatureError> {
        Err(OptionalFeatureError::Unsupported)
    }
}

assert_obj_safe!(EventDistributorImpl);

/// Processor-level interrupt controller interface.
///
/// Handles processor-wide lifecycle events and routes peripheral interrupts to
/// the appropriate vCPU. Peripheral ownership and dispatch is managed by
/// [`EventDistributor`].
pub trait EventDistributorImpl: AsAny + Send {
    fn on_processor_start(
        &mut self,
        _vcpus: &mut PerVcpuSlice<VcpuCore>,
    ) -> Result<(), UnknownError> {
        Ok(())
    }

    fn on_processor_stop(
        &mut self,
        _vcpus: &mut PerVcpuSlice<VcpuCore>,
    ) -> Result<(), UnknownError> {
        Ok(())
    }

    /// Update state of the event controller.
    ///
    /// Called once per emulation round after all peripherals have been ticked.
    /// `delta` has processor level timekeeping information that peripherals and
    /// the event distributor schedule against.
    ///
    /// `pending_irqs` contains exception numbers returned by peripheral ticks.
    /// The event distributor should route them to the appropriate vCPU's event controller.
    /// The pending irqs are assumed to be handled after this tick.
    fn tick(
        &mut self,
        _delta: &GlobalDelta,
        _pending_irqs: &[ExceptionNumber],
        _vcpus: &mut PerVcpuSlice<VcpuCore>,
    ) -> Result<(), UnknownError> {
        Ok(())
    }

    fn init(
        &mut self,
        _vcpus: &mut PerVcpuSlice<VcpuCore>,
        _memory: &Arc<MemoryBackend>,
        _config: &mut Config,
    ) -> Result<(), UnknownError> {
        Ok(())
    }

    fn reset(&mut self, _mmu: &mut Mmu) -> Result<(), UnknownError> {
        Ok(())
    }
}

/// Wraps a [`EventControllerImpl`] and delegates all per-vCPU interrupt operations to it.
///
/// Does not own peripherals. Peripheral management is the responsibility of [`EventDistributor`].
///
/// The dummy implementation provides a dummy event controller on vcpu 0. Good for tests.
pub struct EventController {
    /// Inner, processor specific implementation of the event controller.
    pub inner: Box<dyn EventControllerImpl>,
    /// Which vcpu does this event controller belong to.
    pub vcpu_index: VcpuId,
}

impl Default for EventController {
    fn default() -> Self {
        Self::new(Box::new(DummyEventController::default()), 0)
    }
}

impl EventController {
    pub fn new(inner: Box<dyn EventControllerImpl>, vcpu_index: VcpuId) -> Self {
        Self { inner, vcpu_index }
    }

    /// Provides a dummy event controller on vcpu 0. Good for tests.
    pub fn dummy() -> Self {
        Self::new(Box::new(DummyEventController::default()), 0)
    }

    pub fn next(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
    ) -> Result<InterruptExecuted, UnknownError> {
        trace!("secondary event controller next");
        self.inner.next(cpu, mmu)
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

    pub fn on_processor_start(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
    ) -> Result<(), UnknownError> {
        trace!("secondary event controller processor_start");
        self.inner.on_processor_start(cpu, mmu)
    }

    pub fn on_processor_stop(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
    ) -> Result<(), UnknownError> {
        trace!("secondary event controller processor_stop");
        self.inner.on_processor_stop(cpu, mmu)
    }

    pub fn tick(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
        delta: &Delta,
    ) -> Result<(), UnknownError> {
        trace!("ticking secondary event controller");
        self.inner.tick(cpu, mmu, delta)
    }

    pub fn reset(&mut self, cpu: &mut dyn CpuBackend, mmu: &mut Mmu) -> Result<(), UnknownError> {
        self.inner.reset(cpu, mmu)
    }

    /// What is the current running exception?
    ///
    /// Intended for debugging and introspection (e.g. the gdbserver `event info` monitor
    /// command); this is not used to drive interrupt dispatch. For controllers that support
    /// preemption or nested exceptions, implementations return the top of the active
    /// exception stack.
    ///
    /// - `Ok(None)` indicates no exception is running.
    /// - `Err(OptionalFeatureError::Unsupported)` indicates this feature is not available on this
    ///   event controller.
    pub fn current_exception(&mut self) -> Result<Option<Exception>, OptionalFeatureError> {
        self.inner.current_exception()
    }

    pub fn get_impl<T: EventControllerImpl + 'static>(&mut self) -> Result<&mut T, UnknownError> {
        self.inner
            .as_mut()
            .as_any_mut()
            .downcast_mut()
            .with_context(|| {
                format!(
                    "could not downcast secondary event controller impl to {:?}",
                    type_name::<T>()
                )
            })
    }
}

/// The event distributor owns all peripherals attached to a processor and handles
/// processor-level lifecycle events.
pub struct EventDistributor {
    /// Processor-level event controller implementation.
    pub inner: Box<dyn EventDistributorImpl>,
    pub peripherals: Peripherals,
}

impl Default for EventDistributor {
    fn default() -> Self {
        Self::new(Box::new(SingleVcpuEventDistributor::default()))
    }
}

impl EventDistributor {
    pub fn new(inner: Box<dyn EventDistributorImpl>) -> Self {
        Self {
            inner,
            peripherals: Peripherals::default(),
        }
    }

    pub fn on_processor_start(
        &mut self,
        vcpus: &mut PerVcpuSlice<VcpuCore>,
    ) -> Result<(), UnknownError> {
        trace!("processor_start event distributor");
        self.inner.on_processor_start(vcpus)?;
        for peripheral in self.peripherals.peripherals.iter_mut() {
            peripheral.on_processor_start(vcpus, self.inner.as_mut())?;
        }
        Ok(())
    }

    pub fn on_processor_stop(
        &mut self,
        vcpus: &mut PerVcpuSlice<VcpuCore>,
    ) -> Result<(), UnknownError> {
        trace!("processor_stop event distributor");
        self.inner.on_processor_stop(vcpus)?;
        for peripheral in self.peripherals.peripherals.iter_mut() {
            peripheral.on_processor_stop(vcpus, self.inner.as_mut())?;
        }
        Ok(())
    }

    pub fn reset(&mut self, mmu: &mut Mmu) -> Result<(), UnknownError> {
        self.inner.reset(mmu)?;
        for peripheral in self.peripherals.peripherals.iter_mut() {
            peripheral.reset(mmu)?;
        }
        Ok(())
    }

    pub fn add_peripheral(&mut self, peripheral: Box<dyn Peripheral>) -> Result<(), UnknownError> {
        self.peripherals.insert_peripheral(peripheral)
    }

    /// Tick all peripherals and route their interrupts.
    ///
    /// Called once per emulation round (after all vCPUs have strided).
    /// Builds a [`PeripheralTickCtx`] (sharing the physical memory backend
    /// from `vcpus.first()`, since all vCPUs share the same `Arc<MemoryBackend>`),
    /// iterates peripherals, collects returned IRQs, then delegates
    /// routing to the inner [`EventDistributorImpl`].
    pub fn tick(
        &mut self,
        delta: &GlobalDelta,
        vcpus: &mut PerVcpuSlice<VcpuCore>,
    ) -> Result<(), UnknownError> {
        // Assume we probably won't get more than 16 peripherals to queue.
        // ExceptionNumber is i32 so 16 i32s reserved on the stack isn't
        // too much.
        //
        // We use SmallVec to avoid a heap allocation in this
        // moderately hot path (tick). It may be worth it to benchmark
        // this code vs Vec vs SmallVec with a smaller buffer.
        let mut pending_irqs = SmallVec::<[ExceptionNumber; 16]>::new();

        let memory: &MemoryBackend = &vcpus.first().mmu.memory;
        let ctx = PeripheralTickCtx::new(delta, memory);
        for peripheral in &mut self.peripherals.peripherals {
            let raised = peripheral.tick(&ctx)?;
            pending_irqs.extend(raised);
        }

        self.inner.tick(delta, &pending_irqs, vcpus)
    }

    pub fn get_impl<T: EventDistributorImpl + 'static>(&mut self) -> Result<&mut T, UnknownError> {
        self.inner
            .as_mut()
            .as_any_mut()
            .downcast_mut()
            .with_context(|| {
                format!(
                    "could not downcast event distributor impl to {:?}",
                    type_name::<T>()
                )
            })
    }
}
