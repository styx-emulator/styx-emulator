// SPDX-License-Identifier: BSD-2-Clause
use styx_cpu_type::Backend;
use styx_errors::UnknownError;
use styx_loader::LoaderHints;
use tokio::runtime::Handle;

use crate::{
    core::ExceptionBehavior,
    cpu::{CpuBackend, DummyBackend},
    event_controller::{DummyEventController, EventControllerImpl, Peripheral},
    memory::Mmu,
    processor::BuildingProcessor,
};

/// Contains the uninitialized parts needed to create a
/// [Processor](crate::processor::Processor).
///
/// The [Default] implementation contains dummy version of the core trinity and
/// empty for everything else.
pub struct ProcessorBundle {
    /// Uninitialized [CpuBackend] implementation.
    pub cpu: Box<dyn CpuBackend>,
    /// Uninitialized [Mmu] implementation.
    pub mmu: Mmu,
    /// Uninitialized [EventControllerImpl] implementation.
    pub event_controller: Box<dyn EventControllerImpl>,
    /// List of peripherals that will be added and initialized.
    pub peripherals: Vec<Box<dyn Peripheral>>,
    pub loader_hints: LoaderHints,
}

impl Default for ProcessorBundle {
    fn default() -> Self {
        Self {
            cpu: Box::new(DummyBackend),
            mmu: Mmu::default(),
            event_controller: Box::new(DummyEventController::default()),
            peripherals: Default::default(),
            loader_hints: Default::default(),
        }
    }
}

pub struct BuildProcessorImplArgs {
    pub runtime: Handle,
    pub backend: Backend,
    pub exception: ExceptionBehavior,
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
        Ok(ProcessorBundle {
            ..Default::default()
        })
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
