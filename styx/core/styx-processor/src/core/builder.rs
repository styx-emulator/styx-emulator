// SPDX-License-Identifier: BSD-2-Clause

use crate::event_controller::DummyEventController;
use crate::memory::{DummyTlb, TlbImpl};
use crate::processor::BuildingProcessor;
use crate::{
    core::ExceptionBehavior,
    cpu::{CpuBackend, DummyBackend},
    event_controller::EventControllerImpl,
    processor::Config,
};
use styx_cpu_type::Backend;
use styx_errors::UnknownError;
use tokio::runtime::Handle;

use super::ProcessorBundle;

/// Per-vCPU uninitialized components.
pub struct VcpuBundle {
    /// Uninitialized [`CpuBackend`] implementation.
    pub cpu: Box<dyn CpuBackend>,
    /// Processor TLB.
    pub tlb: Box<dyn TlbImpl>,
    /// Uninitialized per-vCPU [`EventControllerImpl`] implementation.
    pub event_controller: Box<dyn EventControllerImpl>,
}

impl Default for VcpuBundle {
    fn default() -> Self {
        Self {
            cpu: Box::new(DummyBackend),
            tlb: Box::new(DummyTlb),
            event_controller: Box::new(DummyEventController::default()),
        }
    }
}

impl VcpuBundle {
    /// Start building a [`VcpuBundle`]. Unset fields default to their dummy
    /// implementations (matching [`VcpuBundle::default()`]).
    pub fn builder() -> VcpuBundleBuilder {
        VcpuBundleBuilder::default()
    }
}

/// Ergonomic builder for a [`VcpuBundle`]. Use to [`Self::build()`] a [`VcpuBundle`].
/// All fields default to their dummy implementations.
///
/// Constructed via [`VcpuBundle::builder()`] or [`super::processor_bundle::ProcessorBundleBuilder::with_vcpu()`].
pub struct VcpuBundleBuilder {
    cpu: Box<dyn CpuBackend>,
    tlb: Box<dyn TlbImpl>,
    event_controller: Box<dyn EventControllerImpl>,
}

impl Default for VcpuBundleBuilder {
    fn default() -> Self {
        Self {
            cpu: Box::new(DummyBackend),
            tlb: Box::new(DummyTlb),
            event_controller: Box::new(DummyEventController::default()),
        }
    }
}

impl VcpuBundleBuilder {
    /// Equivalent to [`Self::default()`].
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the [`CpuBackend`] for this vCPU.
    ///
    /// This boxes the [`CpuBackend`]. Use [`Self::with_cpu_box()`]
    /// if you have an already box'd object.
    pub fn with_cpu(mut self, cpu: impl CpuBackend + 'static) -> Self {
        self.cpu = Box::new(cpu);
        self
    }

    /// See [`Self::with_cpu()`]; accepts an already-boxed backend.
    pub fn with_cpu_box(mut self, cpu: Box<dyn CpuBackend>) -> Self {
        self.cpu = cpu;
        self
    }

    /// Set the [`TlbImpl`] for this vCPU.
    ///
    /// This boxes the [`TlbImpl`]. Use [`Self::with_tlb_box()`]
    /// if you have an already box'd object.
    pub fn with_tlb(mut self, tlb: impl TlbImpl + 'static) -> Self {
        self.tlb = Box::new(tlb);
        self
    }

    /// See [`Self::with_tlb()`]; accepts an already-boxed TLB.
    pub fn with_tlb_box(mut self, tlb: Box<dyn TlbImpl>) -> Self {
        self.tlb = tlb;
        self
    }

    /// Set the per-vCPU [`EventControllerImpl`] (secondary / core-level).
    ///
    /// This boxes the [`EventControllerImpl`]. Use [`Self::with_event_controller_box()`]
    /// if you have an already box'd object.
    pub fn with_event_controller(mut self, ec: impl EventControllerImpl + 'static) -> Self {
        self.event_controller = Box::new(ec);
        self
    }

    /// See [`Self::with_event_controller()`]; accepts an already-boxed impl.
    pub fn with_event_controller_box(mut self, ec: Box<dyn EventControllerImpl>) -> Self {
        self.event_controller = ec;
        self
    }

    /// Build into a [`VcpuBundle`].
    pub fn build(self) -> VcpuBundle {
        VcpuBundle {
            cpu: self.cpu,
            tlb: self.tlb,
            event_controller: self.event_controller,
        }
    }
}

impl From<VcpuBundleBuilder> for VcpuBundle {
    fn from(builder: VcpuBundleBuilder) -> Self {
        builder.build()
    }
}

pub struct BuildProcessorImplArgs<'a> {
    pub runtime: Handle,
    pub backend: Backend,
    pub exception: ExceptionBehavior,
    pub config: &'a Config,
}

/// Provides behavior to build and initialize a processor.
///
/// The job of this is to construct all of pieces needed for a processor. This
/// is contained in the [ProcessorBundle]. After returning the ProcessorBundle
/// the [ProcessorBuilder](crate::processor::ProcessorBuilder) will initialize
/// and construct the final [Processor](crate::processor::Processor).
///
/// This implementation has a lot of freedom in how it constructions the bundle.
/// Refer to documentation of the [ProcessorBundle] fields for more information.
pub trait ProcessorImpl {
    fn build(&self, args: &BuildProcessorImplArgs) -> Result<ProcessorBundle, UnknownError>;
    /// called after the build method, but before the processor is started
    fn init(&self, _proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        Ok(())
    }
}

#[derive(Default, Debug)]
/// A dummy processor builder, does nothing and returns a default [ProcessorBundle].
pub struct DummyProcessorBuilder;
impl ProcessorImpl for DummyProcessorBuilder {
    fn build(&self, _args: &BuildProcessorImplArgs) -> Result<ProcessorBundle, UnknownError> {
        Ok(ProcessorBundle::default())
    }
}

#[derive(Default, Debug)]
/// Used as a placeholder in the processor builder for when a builder hasn't yet been added.
pub struct UnimplementedProcessorImpl;
impl ProcessorImpl for UnimplementedProcessorImpl {
    fn build(&self, _args: &BuildProcessorImplArgs) -> Result<ProcessorBundle, UnknownError> {
        unimplemented!("processor impl ironically is not implemented")
    }
}

impl<F> ProcessorImpl for F
where
    F: Fn(&BuildProcessorImplArgs) -> Result<ProcessorBundle, UnknownError>,
{
    fn build(&self, args: &BuildProcessorImplArgs) -> Result<ProcessorBundle, UnknownError> {
        self(args)
    }
}
