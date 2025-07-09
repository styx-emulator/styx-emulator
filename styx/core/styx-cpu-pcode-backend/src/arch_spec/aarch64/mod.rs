// SPDX-License-Identifier: BSD-2-Clause
use styx_pcode_translator::ContextOption;

use crate::{arch_spec::pc_manager::PcOverflow, PcodeBackend};

use super::{pc_manager::apply_difference, ArchPcManager, GeneratorHelp};

mod call_other;
pub mod generic;

/// [GeneratorHelp] for SuperH processors. Does nothing at the moment.
#[derive(Debug, Default)]
pub struct StandardGeneratorHelper;
impl GeneratorHelp for StandardGeneratorHelper {
    fn pre_fetch(&mut self, _backend: &mut PcodeBackend) -> Box<[ContextOption]> {
        [].into()
    }
}

/// Program Counter manager for Blackfin processors.
#[derive(Debug, Default)]
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

    fn set_internal_pc(&mut self, value: u64, _backend: &mut PcodeBackend) {
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
    ) -> Result<(), PcOverflow> {
        self.internal_pc += bytes_consumed;
        self.isa_pc += bytes_consumed;

        Ok(())
    }
}
