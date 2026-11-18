// SPDX-License-Identifier: BSD-2-Clause
use crate::{
    cpu::{ArchEndian, ArchVariant, Backend, Hook},
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
    arch::ArchitectureDef,
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
        RawProcessor,
    },
};

/// A builder for constructing a processor emulator
#[gen_stub_pyclass]
#[pyclass(unsendable, module = "processor")]
pub struct ProcessorBuilder {
    builder: styx_emulator::prelude::ProcessorBuilder<'static>,
    /// architecture variant, only used by [`Target::Raw`]
    variant: Option<styx_emulator::prelude::ArchVariant>,
    /// byte order, only used by [`Target::Raw`]
    endian: Option<styx_emulator::prelude::ArchEndian>,
}

impl ProcessorBuilder {
    fn swapero(
        &mut self,
        f: impl FnOnce(
            styx_emulator::prelude::ProcessorBuilder,
        ) -> styx_emulator::prelude::ProcessorBuilder,
    ) {
        let tmp = std::mem::take(&mut self.builder);
        let tmp = f(tmp);
        self.builder = tmp;
    }
}

#[gen_stub_pymethods]
#[pymethods]
impl ProcessorBuilder {
    /// create a new processor builder
    #[allow(clippy::new_without_default)]
    #[new]
    pub fn new() -> Self {
        Self {
            builder: styx_emulator::prelude::ProcessorBuilder::default(),
            variant: None,
            endian: None,
        }
    }

    /// set the architecture variant of the new processor
    ///
    /// Only [`Target::Raw`] uses this, every other target has a fixed variant.
    #[setter]
    pub fn set_variant(&mut self, variant: ArchVariant) -> PyResult<()> {
        self.variant = Some(variant.into());
        Ok(())
    }

    /// set the byte order of the new processor
    ///
    /// Only [`Target::Raw`] uses this, every other target has a fixed byte order.
    #[setter]
    pub fn set_endian(&mut self, endian: ArchEndian) -> PyResult<()> {
        self.endian = Some(endian.into());
        Ok(())
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
        self.swapero(|builder| builder.with_executor_kind(executor));

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
        let builder = std::mem::take(&mut self.builder);
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
                let variant = self
                    .variant
                    .take()
                    .ok_or(anyhow!("a raw target needs a variant"))
                    .map_err(super::convert_machine_err)?;
                let endian = self
                    .endian
                    .take()
                    .ok_or(anyhow!("a raw target needs an endian"))
                    .map_err(super::convert_machine_err)?;
                let arch = Box::<dyn ArchitectureDef>::from(variant).architecture();
                builder.with_builder(RawProcessor::new(arch, variant, endian))
            }
            Target::SuperH2A => builder.with_builder(SuperH2aBuilder),
        };
        let cpu = builder.build_sync()?;

        Ok(Processor(cpu))
    }
}
