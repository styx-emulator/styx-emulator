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
use crate::{
    cpu::{Backend, Hook},
    executor::StyxExecutor,
    loader::Loader,
    plugin::Plugin,
    processor::{Processor, Target},
};
use pyo3::{
    prelude::*,
    types::{PyBytes, PyString},
};
use pyo3_stub_gen::derive::*;
use styx_emulator::{
    cpu::arch::ppc32::Ppc32Variants,
    prelude::anyhow,
    processors::{
        arm::{
            cyclonev::CycloneVBuilder, kinetis21::Kinetis21Builder, stm32f107::Stm32f107Builder,
            stm32f405::Stm32f405Builder,
        },
        bfin::blackfin::BlackfinBuilder,
        ppc::{powerquicci::Mpc8xxBuilder, ppc4xx::PowerPC405Builder},
        superh::superh2a::SuperH2aBuilder,
    },
};

/// A builder for constructing a processor emulator
#[gen_stub_pyclass]
#[pyclass(unsendable, module = "processor")]
pub struct ProcessorBuilder(styx_emulator::prelude::ProcessorBuilder<'static>);

impl ProcessorBuilder {
    fn swapero(
        &mut self,
        f: impl FnOnce(
            styx_emulator::prelude::ProcessorBuilder,
        ) -> styx_emulator::prelude::ProcessorBuilder,
    ) {
        let tmp = std::mem::take(&mut self.0);
        let tmp = f(tmp);
        self.0 = tmp;
    }
}

#[gen_stub_pymethods]
#[pymethods]
impl ProcessorBuilder {
    /// create a new processor builder
    #[allow(clippy::new_without_default)]
    #[new]
    pub fn new() -> Self {
        Self(styx_emulator::prelude::ProcessorBuilder::default())
    }

    /// set the path to the loader's input file
    #[setter]
    pub fn set_target_program(&mut self, pgm: Bound<PyString>) -> PyResult<()> {
        let pgm = pgm.to_str()?.to_string();
        self.swapero(|builder| builder.with_target_program(pgm));
        Ok(())
    }

    /// set the loader's input directly in bytes
    #[setter]
    pub fn set_input_bytes(&mut self, bytes: Bound<PyBytes>) -> PyResult<()> {
        let bytes = bytes.as_bytes().to_vec();
        self.swapero(|builder| builder.with_input_bytes(bytes.into()));
        Ok(())
    }

    /// add a processor plugin to the new processor
    pub fn add_plugin(&mut self, plugin: PyRef<Plugin>) -> PyResult<()> {
        let plugin = plugin
            .0
            .lock()
            .unwrap()
            .take()
            .ok_or(anyhow!("plugin already taken"))
            .map_err(super::convert_machine_err)?;
        self.swapero(|builder| builder.add_plugin_box(plugin));
        Ok(())
    }

    /// set the new processor's executor plugin.
    ///
    /// The StyxExecutor handles how the processor executes instructions and the lifecycle.
    #[setter]
    pub fn set_executor(&mut self, executor: &StyxExecutor) -> PyResult<()> {
        let executor = executor
            .0
            .lock()
            .unwrap()
            .take()
            .ok_or(anyhow!("executor already taken"))
            .map_err(super::convert_machine_err)?;
        self.swapero(|builder| builder.with_executor_box(executor));

        Ok(())
    }

    /// set the new processor's loader
    ///
    /// The loader is invoked by the processor to load the initial state
    #[setter]
    pub fn set_loader(&mut self, loader: PyRef<Loader>) -> PyResult<()> {
        let loader = loader
            .0
            .lock()
            .unwrap()
            .take()
            .ok_or(anyhow!("loader already taken"))
            .map_err(super::convert_machine_err)?;
        self.swapero(|builder| builder.with_loader_box(loader));
        Ok(())
    }

    /// set the inter processor communication (IPC) port
    ///
    /// this port is bound by a GRPC server to communicate with other processors and services
    #[setter]
    pub fn set_ipc_port(&mut self, port: u16) -> PyResult<()> {
        self.swapero(|builder| builder.with_ipc_port(port));
        Ok(())
    }

    /// Add a hook to supported events and trigger custom code
    pub fn add_hook(&mut self, hook: Hook) -> PyResult<()> {
        self.swapero(|builder| builder.add_hook(hook.into()));
        Ok(())
    }

    /// Set the emulation backend this processor should use
    #[setter]
    pub fn set_backend(&mut self, backend: Backend) -> PyResult<()> {
        self.swapero(|builder| builder.with_backend(backend.into()));
        Ok(())
    }

    /// build the new processor and reset the builder
    pub fn build(&mut self, target: Target) -> PyResult<Processor> {
        let builder = std::mem::take(&mut self.0);
        let builder = match target {
            Target::CycloneV => builder.with_builder(CycloneVBuilder::default()),
            Target::Mpc8xx => builder.with_builder(Mpc8xxBuilder::new(
                Ppc32Variants::Mpc860,
                styx_emulator::prelude::ArchEndian::BigEndian,
            )?),
            Target::Ppc4xx => builder.with_builder(PowerPC405Builder::default()),
            Target::Kinetis21 => builder.with_builder(Kinetis21Builder::default()),
            Target::Stm32f107 => builder.with_builder(Stm32f107Builder::default()),
            Target::Stm32f405 => builder.with_builder(Stm32f405Builder::default()),
            Target::Bf512 => builder.with_builder(BlackfinBuilder::default()),
            Target::Raw => {
                todo!("need cannot determine variant, arch, and endian here");
            }
            Target::SuperH2A => builder.with_builder(SuperH2aBuilder),
        };
        let cpu = builder.build_sync()?;

        Ok(Processor(cpu))
    }
}
