// SPDX-License-Identifier: BSD-2-Clause
//! # Styx-Processors

use styx_core::cpu::arch::hexagon::HexagonVariants;
use styx_core::cpu::{Arch, Backend};
use styx_core::loader::LoaderHints;
use styx_core::memory::{memory_region::MemoryRegion, MemoryPermissions, Mmu};
use styx_core::prelude::log::trace;
use styx_core::prelude::{EventControllerImpl, Peripheral};
use styx_core::{
    core::{
        builder::{BuildProcessorImplArgs, ProcessorImpl},
        ProcessorBundle,
    },
    cpu::{ArchEndian, HexagonPcodeBackend},
    errors::{anyhow, UnknownError},
};

#[derive(serde::Deserialize)]
pub struct HexagonBuilder {
    pub variant: HexagonVariants,
}

#[derive(Default)]
pub struct HexagonEventController {}

impl Default for HexagonBuilder {
    fn default() -> Self {
        Self {
            variant: HexagonVariants::QDSP6V62,
        }
    }
}

impl EventControllerImpl for HexagonEventController {
    fn next(
        &mut self,
        _cpu: &mut dyn styx_core::prelude::CpuBackend,
        _mmu: &mut Mmu,
        _peripherals: &mut styx_core::event_controller::Peripherals,
    ) -> Result<styx_core::event_controller::InterruptExecuted, UnknownError> {
        todo!()
    }

    fn latch(
        &mut self,
        _event: styx_core::prelude::ExceptionNumber,
    ) -> Result<(), styx_core::event_controller::ActivateIRQnError> {
        todo!()
    }

    fn execute(
        &mut self,
        _irq: styx_core::prelude::ExceptionNumber,
        _cpu: &mut dyn styx_core::prelude::CpuBackend,
        _mmu: &mut Mmu,
    ) -> Result<
        styx_core::event_controller::InterruptExecuted,
        styx_core::event_controller::ActivateIRQnError,
    > {
        todo!()
    }

    fn finish_interrupt(
        &mut self,
        _cpu: &mut dyn styx_core::prelude::CpuBackend,
        _mmu: &mut Mmu,
    ) -> Option<styx_core::prelude::ExceptionNumber> {
        todo!()
    }

    fn init(
        &mut self,
        _cpu: &mut dyn styx_core::prelude::CpuBackend,
        _mmu: &mut Mmu,
    ) -> Result<(), UnknownError> {
        trace!("the hexagon event controller has started");
        Ok(())
    }
}

impl ProcessorImpl for HexagonBuilder {
    fn build(&self, args: &BuildProcessorImplArgs) -> Result<ProcessorBundle, UnknownError> {
        let cpu = if let Backend::Pcode = args.backend {
            Box::new(HexagonPcodeBackend::new_engine_config(
                self.variant.clone(),
                ArchEndian::LittleEndian,
                &args.into(),
            ))
        } else {
            return Err(anyhow::anyhow!(
                "hexagon processor only supports pcode backend"
            ));
        };
        let mut mmu = Mmu::default_region_store();
        mmu.memory_map(0, 2u64.pow(32), MemoryPermissions::all())?;

        let cec = Box::new(HexagonEventController::default());

        let peripherals: Vec<Box<dyn Peripheral>> = Vec::new();

        let mut hints = LoaderHints::new();
        hints.insert("arch".to_string().into_boxed_str(), Box::new(Arch::Hexagon));

        Ok(ProcessorBundle {
            cpu,
            mmu,
            event_controller: cec,
            peripherals,
            loader_hints: hints,
        })
    }
}
