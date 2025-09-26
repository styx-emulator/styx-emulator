// SPDX-License-Identifier: BSD-2-Clause
mod ghidra;
mod pcode_generator;

pub(crate) use ghidra::{get_pcode, GhidraPcodeGenerator, MmuLoader, RegisterTranslator};
pub(crate) use pcode_generator::GeneratePcodeError;
use styx_processor::cpu::CpuBackend;

use crate::PcodeBackend;

pub(crate) trait HasPcodeGenerator {
    type InnerCpuBackend: CpuBackend;
    fn pcode_generator_mut(&mut self) -> &mut GhidraPcodeGenerator<Self::InnerCpuBackend>;
    fn pcode_generator(&self) -> &GhidraPcodeGenerator<Self::InnerCpuBackend>;
}

impl HasPcodeGenerator for PcodeBackend {
    type InnerCpuBackend = PcodeBackend;
    fn pcode_generator_mut(&mut self) -> &mut GhidraPcodeGenerator<PcodeBackend> {
        &mut self.pcode_generator
    }

    fn pcode_generator(&self) -> &GhidraPcodeGenerator<PcodeBackend> {
        &self.pcode_generator
    }
}
