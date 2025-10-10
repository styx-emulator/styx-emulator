// SPDX-License-Identifier: BSD-2-Clause
//! # Styx-Processors

use styx_core::cpu::arch::hexagon::HexagonVariants;
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

impl Default for HexagonBuilder {
    fn default() -> Self {
        Self {
            variant: HexagonVariants::QDSP6V62,
        }
    }
}

impl ProcessorImpl for HexagonBuilder {
    fn build(&self, args: &BuildProcessorImplArgs) -> Result<ProcessorBundle, UnknownError> {
        let cpu = if let backend::pcode = args.backend {
            Box::new(HexagonPcodeBackend::new_engine_config(
                self.variant,
                ArchEndian::LittleEndian,
                &args.into(),
            ))
        } else {
            return Err(anyhow::anyhow!(
                "hexagon processor only supports pcode backend"
            ));
        };
        let mut mmu = Mmu::default_region_store();
        let cec = Box::new(CoreEventController::default());
        let mut peripherals: Vec<Box<dyn Peripheral>> = Vec::new();

        let mut hints = LoaderHints::new();
        hints.insert("arch".to_string().into_boxed_str(), Box::new(Arch::Hexagon));

        Ok(ProcessorBundle {
            cpu: cpu,
            mmu: mmu,
            event_controller: cec,
            peripherals,
            loader_hints: hints,
        })
    }
}
