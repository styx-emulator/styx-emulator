// SPDX-License-Identifier: BSD-2-Clause
//! # Styx-Processors

use styx_core::{
    core::{
        builder::{BuildProcessorImplArgs, ProcessorImpl},
        ProcessorBundle,
    },
    cpu::{Arch, ArchEndian, PcodeBackend, UnicornBackend},
    loader::LoaderHints,
    memory::Mmu,
    prelude::*,
};
use styx_event_controllers::DummyEventController;
pub mod arm {
    pub use styx_cyclonev_processor as cyclonev;
    pub use styx_kinetis21_processor as kinetis21;
    pub use styx_stm32f107_processor as stm32f107;
    pub use styx_stm32f405_processor as stm32f405;
}

pub mod ppc {
    pub use styx_powerquicci_processor as powerquicci;
    pub use styx_ppc4xx_processor as ppc4xx;
}

pub mod bfin {
    pub use styx_blackfin_processor as blackfin;
}

pub mod superh {
    pub use styx_superh2a_processor as superh2a;
}

/// A processor with no peripherals or event controller, purely instruction emulation.
pub struct RawProcessor {
    arch: Arch,
    arch_variant: ArchVariant,
    endian: ArchEndian,
}

impl RawProcessor {
    pub fn new(arch: Arch, arch_variant: impl Into<ArchVariant>, endian: ArchEndian) -> Self {
        Self {
            arch,
            arch_variant: arch_variant.into(),
            endian,
        }
    }
}

impl ProcessorImpl for RawProcessor {
    fn build(
        &self,
        args: &BuildProcessorImplArgs,
    ) -> Result<styx_core::prelude::ProcessorBundle, styx_core::prelude::UnknownError> {
        let cpu: Box<dyn CpuBackend> = match args.backend {
            Backend::Pcode => Box::new(PcodeBackend::new_engine_config(
                self.arch_variant.clone(),
                self.endian,
                &args.into(),
            )),
            Backend::Unicorn => Box::new(UnicornBackend::new_engine_exception(
                self.arch,
                self.arch_variant.clone(),
                self.endian,
                args.exception,
            )),
        };

        let mut hints = LoaderHints::new();
        hints.insert("arch".to_string().into_boxed_str(), Box::new(self.arch));

        Ok(ProcessorBundle {
            cpu,
            mmu: Mmu::default(),
            event_controller: Box::new(DummyEventController::default()),
            peripherals: vec![],
            loader_hints: hints,
        })
    }
}
