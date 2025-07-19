// SPDX-License-Identifier: BSD-2-Clause
use crate::{pcode_gen::GeneratePcodeError, Mmu};
use styx_pcode::pcode::VarnodeData;
use styx_pcode_translator::ContextOption;

use crate::{arch_spec::pc_manager::PcOverflow, PcodeBackend};
use smallvec::{smallvec, SmallVec};

use super::{
    generator_helper::CONTEXT_OPTION_LEN, pc_manager::apply_difference, ArchPcManager,
    GeneratorHelp,
};

mod call_other;
pub mod generic;

/// [GeneratorHelp] for SuperH processors. Does nothing at the moment.
#[derive(Debug, Default, Clone)]
pub struct StandardGeneratorHelper;
impl GeneratorHelp for StandardGeneratorHelper {
    fn pre_fetch(
        &mut self,
        _backend: &mut PcodeBackend,
    ) -> Result<SmallVec<[ContextOption; CONTEXT_OPTION_LEN]>, GeneratePcodeError> {
        Ok(smallvec![])
    }
}

/// Program Counter manager for Blackfin processors.
#[derive(Debug, Default, Clone)]
pub struct StandardPcManager {
    isa_pc: u64,
    internal_pc: u64,
}

impl ArchPcManager for StandardPcManager {
    fn isa_pc(&self) -> u64 {
        self.isa_pc
    }

    fn internal_pc(&self) -> u64 {
        self.internal_pc
    }

    fn set_internal_pc(&mut self, value: u64, _backend: &mut PcodeBackend, _from_branch: bool) {
        // i128 here is used so we don't overflow on cast
        let difference = (value as i128 - self.internal_pc as i128) & (!1);

        apply_difference(&mut self.internal_pc, difference);
        apply_difference(&mut self.isa_pc, difference);
    }

    fn set_isa_pc(&mut self, value: u64, _backend: &mut PcodeBackend) {
        // i128 here is used so we don't overflow on cast
        let difference = (value as i128 - self.isa_pc as i128) & (!1);

        apply_difference(&mut self.internal_pc, difference);
        apply_difference(&mut self.isa_pc, difference);
    }

    fn post_execute(
        &mut self,
        bytes_consumed: u64,
        _backend: &mut PcodeBackend,
        _regs_written: &mut SmallVec<[VarnodeData; 3]>,
        _total_pcodes: usize,
    ) -> Result<(), PcOverflow> {
        self.internal_pc += bytes_consumed;
        self.isa_pc += bytes_consumed;

        Ok(())
    }
}
