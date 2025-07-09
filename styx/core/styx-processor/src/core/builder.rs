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
