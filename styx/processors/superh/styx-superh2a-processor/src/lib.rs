// SPDX-License-Identifier: BSD-2-Clause
//! SuperH2a Processor
use styx_core::core::builder::{BuildProcessorImplArgs, ProcessorImpl};
use styx_core::cpu::arch::superh::SuperHVariants;
use styx_core::cpu::arch::ArchEndian;
use styx_core::cpu::PcodeBackend;
use styx_core::prelude::*;

/// Partial Implementation of a SuperH2a processor
///
/// Not implemented:
/// - no event controller
/// - no peripherals get attached
/// - no default memory maps setup besides [`0x0` -> `0xffffffff`]
#[derive(Default)]
pub struct SuperH2aBuilder;
impl SuperH2aBuilder {
    /// Note: This is the bare minimum and needs to be revisited
    fn setup_address_space(&self, mmu: &mut MemoryBackend) -> Result<(), UnknownError> {
        mmu.memory_map(0, u32::MAX as u64, MemoryPermissions::all())?;
        Ok(())
    }
}

impl ProcessorImpl for SuperH2aBuilder {
    fn build(&self, args: &BuildProcessorImplArgs) -> Result<ProcessorBundle, UnknownError> {
        let cpu = if let Backend::Pcode = args.backend {
            PcodeBackend::new_engine_config(
                SuperHVariants::SH2A,
                ArchEndian::BigEndian,
                &args.into(),
            )
        } else {
            return Err(anyhow!("sh2 processor only supports pcode backend"));
        };

        Ok(ProcessorBundle::builder()
            .with_memory(MemoryBackend::new_region_store())
            .modify_memory(|m| self.setup_address_space(m))?
            .with_vcpu(|v| v.with_cpu(cpu))
            .with_arch_hint(Arch::SuperH)
            .build()?)
    }
}
