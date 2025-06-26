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
pub mod bf535;
pub mod bf5xx;
mod call_other;
mod register;

use register::AnalogRegister;
use styx_cpu_type::arch::blackfin::BlackfinRegister;
use styx_pcode_translator::sla::{self, BlackfinUserOps};

use crate::PcodeBackend;

use super::{
    pc_manager::{apply_difference, PcOverflow},
    ArchPcManager, ArchSpecBuilder, GeneratorHelper,
};

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
    ) -> Result<(), PcOverflow> {
        self.internal_pc = self
            .internal_pc
            .checked_add(bytes_consumed)
            .ok_or(PcOverflow)?;
        self.isa_pc = self.isa_pc.checked_add(bytes_consumed).ok_or(PcOverflow)?;
        Ok(())
    }
}

fn blackfin_common(spec: &mut ArchSpecBuilder<sla::Blackfin>) {
    spec.set_pc_manager(StandardPcManager::default().into());

    // Standard "do-nothing" generator helper
    spec.set_generator(GeneratorHelper::default());

    spec.register_manager
        .add_handler(BlackfinRegister::A0, AnalogRegister)
        .unwrap();
    spec.register_manager
        .add_handler(BlackfinRegister::A1, AnalogRegister)
        .unwrap();

    spec.call_other_manager
        .add_handler(BlackfinUserOps::Excpt, call_other::ExcptHandler)
        .unwrap();

    spec.call_other_manager
        .add_handler(BlackfinUserOps::Signbits, call_other::SignBitsHandler)
        .unwrap();

    spec.call_other_manager
        .add_handler(BlackfinUserOps::Vectoradd, call_other::VecAddHandler)
        .unwrap();

    spec.call_other_manager
        .add_handler(BlackfinUserOps::Vectorsub, call_other::VecSubHandler)
        .unwrap();

    spec.call_other_manager
        .add_handler(BlackfinUserOps::Move, call_other::MoveHandler)
        .unwrap();

    spec.call_other_manager
        .add_handler(BlackfinUserOps::Min, call_other::MinHandler)
        .unwrap();

    spec.call_other_manager
        .add_handler(BlackfinUserOps::ExtracTz, call_other::ExtractZ)
        .unwrap();
    spec.call_other_manager
        .add_handler(BlackfinUserOps::ExtracTx, call_other::ExtractX)
        .unwrap();

    spec.call_other_manager
        .add_handler(BlackfinUserOps::Raise, call_other::RaiseHandler)
        .unwrap();

    spec.call_other_manager
        .add_handler(BlackfinUserOps::Divq, call_other::DivQHandler)
        .unwrap();

    spec.call_other_manager
        .add_handler(BlackfinUserOps::Divs, call_other::DivSHandler)
        .unwrap();

    spec.call_other_manager
        .add_handler(BlackfinUserOps::Csync, call_other::CSyncHandler)
        .unwrap();

    spec.call_other_manager
        .add_handler(BlackfinUserOps::Ssync, call_other::SSyncHandler)
        .unwrap();

    spec.call_other_manager
        .add_handler(BlackfinUserOps::Deposit, call_other::DepositHandler)
        .unwrap();

    spec.call_other_manager
        .add_handler(BlackfinUserOps::DeposiTx, call_other::DepositXHandler)
        .unwrap();

    spec.call_other_manager
        .add_handler(BlackfinUserOps::Mac, call_other::MacHandler)
        .unwrap();
}
