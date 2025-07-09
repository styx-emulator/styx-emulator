// SPDX-License-Identifier: BSD-2-Clause
mod ghidra;
mod pcode_generator;

pub(crate) use ghidra::{
    GhidraPcodeGenerator, MmuLoader, MmuLoaderDependencies, RegisterTranslator,
};
pub(crate) use pcode_generator::GeneratePcodeError;

use crate::PcodeBackend;

pub(crate) trait HasPcodeGenerator {
    fn pcode_generator(&mut self) -> &mut GhidraPcodeGenerator;
}

impl HasPcodeGenerator for PcodeBackend {
    fn pcode_generator(&mut self) -> &mut GhidraPcodeGenerator {
        &mut self.pcode_generator
    }
}
