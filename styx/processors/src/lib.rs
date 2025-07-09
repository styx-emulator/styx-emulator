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
