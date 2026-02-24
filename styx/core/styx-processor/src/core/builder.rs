// SPDX-License-Identifier: BSD-2-Clause
use crate::event_controller::{
    DummyEventController, DummyPrimaryEventController, PrimaryEventControllerImpl,
};
use crate::loader::LoaderHints;
use crate::memory::physical::MemoryBackend;
use crate::memory::{DummyTlb, TlbImpl};
use crate::processor::BuildingProcessor;
use crate::{
    core::ExceptionBehavior,
    cpu::{CpuBackend, DummyBackend},
    event_controller::{EventControllerImpl, Peripheral},
    processor::Config,
};
use styx_cpu_type::Backend;
use styx_errors::UnknownError;
use tokio::runtime::Handle;

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

/// Contains the uninitialized parts needed to create a
/// [Processor](crate::processor::Processor).
///
/// The [Default] implementation contains a single dummy vCPU and empty lists
/// for peripherals and loader hints.
pub struct ProcessorBundle {
    /// Physical memory.
    pub memory: MemoryBackend,
    /// Uninitialized processor-level [PrimaryEventControllerImpl] implementation.
    pub primary_event_controller: Box<dyn PrimaryEventControllerImpl>,
    /// Per-vCPU bundles; at least one entry is required.
    pub vcpus: Vec<VCpuBundle>,
    /// List of peripherals that will be added and initialized.
    pub peripherals: Vec<Box<dyn Peripheral>>,
    pub loader_hints: LoaderHints,
}

impl Default for ProcessorBundle {
    fn default() -> Self {
        Self {
            memory: MemoryBackend::default(),
            primary_event_controller: Box::new(DummyPrimaryEventController::default()),
            vcpus: vec![VCpuBundle::default()],
            peripherals: Default::default(),
            loader_hints: Default::default(),
        }
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
