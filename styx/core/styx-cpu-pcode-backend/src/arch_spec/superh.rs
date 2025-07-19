// SPDX-License-Identifier: BSD-2-Clause
//! Pcode Arch specs for the SH architecture families
mod call_other;
pub mod register;
pub mod sh1;
pub mod sh2;
pub mod sh2a;
pub mod sh4eb;
pub mod sh4el;

use super::{
    generator_helper::CONTEXT_OPTION_LEN,
    pc_manager::{apply_difference, PcOverflow},
    ArchPcManager, GeneratorHelp,
};
use crate::{pcode_gen::GeneratePcodeError, PcodeBackend, DEFAULT_REG_ALLOCATION};
use smallvec::{smallvec, SmallVec};
use styx_pcode::pcode::VarnodeData;
use styx_pcode_translator::ContextOption;
use styx_processor::memory::Mmu;

/// Program Counter manager for SuperH processors.
///
/// Copied from Blackfin
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
        _regs_written: &mut SmallVec<[VarnodeData; DEFAULT_REG_ALLOCATION]>,
        _total_pcodes: usize,
    ) -> Result<(), PcOverflow> {
        self.internal_pc = self
            .internal_pc
            .checked_add(bytes_consumed)
            .ok_or(PcOverflow)?;
        self.isa_pc = self.isa_pc.checked_add(bytes_consumed).ok_or(PcOverflow)?;
        Ok(())
    }
}

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
