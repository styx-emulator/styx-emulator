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

use smallvec::SmallVec;

use crate::{PcodeBackend, DEFAULT_REG_ALLOCATION};

use super::{
    pc_manager::{apply_difference, PcOverflow},
    ArchPcManager, GeneratorHelper,
};

pub mod call_other;
pub mod ppc4xx;

fn ppc_common<Sla>(spec: &mut super::ArchSpecBuilder<Sla>) {
    spec.set_pc_manager(StandardPpcPcManager::default().into());

    // "Do nothing" generator helper.
    spec.set_generator(GeneratorHelper::default().into());
}

/// [ArchPcManager] for PowerPC Processors.
///
/// Currently holds standard behavior.
///
/// I think *technically* this is incorrect however ppc code cannot read from
/// the pc so not needed.
#[derive(Debug, Default)]
pub struct StandardPpcPcManager {
    isa_pc: u64,
    internal_pc: u64,
}

impl ArchPcManager for StandardPpcPcManager {
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
        _regs_written: &mut SmallVec<[u64; DEFAULT_REG_ALLOCATION]>,
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
