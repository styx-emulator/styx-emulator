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

use std::str::FromStr;

use crate::{
    arch_spec::{
        arm::{armv7_common, armv7a_common},
        ArchSpecBuilder,
    },
    register_manager::{RegisterCallback, RegisterHandler},
};
use styx_cpu_type::arch::{
    arm::{arm_coproc_registers, SpecialArmRegister},
    backends::{ArchRegister, SpecialArchRegister},
};
use styx_pcode::sla::SlaUserOps;
use styx_pcode_translator::sla::{Arm7Be, Arm7Le, Arm7LeUserOps};

use super::call_other::{
    CoprocMovefromControl, CoprocMovefromPeripheralSystem, CoprocMovetoControl,
    CoprocessorMovefromRt,
};

#[derive(Debug, Default)]
struct CoProcRegisterHandler {
    cbar: u32,
    vbar: u32,
    sctlr: u32,
}

impl RegisterCallback for CoProcRegisterHandler {
    fn read(
        &mut self,
        register: styx_cpu_type::arch::backends::ArchRegister,
        _cpu: &mut crate::PcodeBackend,
    ) -> Result<crate::memory::sized_value::SizedValue, crate::register_manager::RegisterHandleError>
    {
        if let ArchRegister::Special(SpecialArchRegister::Arm(SpecialArmRegister::CoProcessor(r))) =
            register
        {
            match r {
                arm_coproc_registers::CBAR => Ok(self.cbar.into()),
                arm_coproc_registers::VBAR => Ok(self.vbar.into()),
                arm_coproc_registers::SCTLR => Ok(self.sctlr.into()),
                _ => Err(
                    crate::register_manager::RegisterHandleError::CannotHandleRegister(register),
                ),
            }
        } else {
            Err(crate::register_manager::RegisterHandleError::CannotHandleRegister(register))
        }
    }

    fn write(
        &mut self,
        register: styx_cpu_type::arch::backends::ArchRegister,
        value: crate::memory::sized_value::SizedValue,
        _cpu: &mut crate::PcodeBackend,
    ) -> Result<(), crate::register_manager::RegisterHandleError> {
        if let ArchRegister::Special(SpecialArchRegister::Arm(SpecialArmRegister::CoProcessor(r))) =
            register
        {
            match r {
                arm_coproc_registers::CBAR => {
                    self.cbar = value.to_u128().unwrap() as u32;
                    Ok(())
                }
                arm_coproc_registers::VBAR => {
                    self.vbar = value.to_u128().unwrap() as u32;
                    Ok(())
                }
                arm_coproc_registers::SCTLR => {
                    self.sctlr = value.to_u128().unwrap() as u32;
                    Ok(())
                }
                _ => Err(
                    crate::register_manager::RegisterHandleError::CannotHandleRegister(register),
                ),
            }
        } else {
            Err(crate::register_manager::RegisterHandleError::CannotHandleRegister(register))
        }
    }
}

pub fn build<S: SlaUserOps<UserOps: FromStr>>() -> ArchSpecBuilder<S> {
    let mut spec = ArchSpecBuilder::default();

    spec.register_manager
        .add_handler(
            arm_coproc_registers::CBAR,
            RegisterHandler(Box::new(CoProcRegisterHandler::default())),
        )
        .unwrap();
    spec.register_manager
        .add_handler(
            arm_coproc_registers::VBAR,
            RegisterHandler(Box::new(CoProcRegisterHandler::default())),
        )
        .unwrap();
    spec.register_manager
        .add_handler(
            arm_coproc_registers::SCTLR,
            RegisterHandler(Box::new(CoProcRegisterHandler::default())),
        )
        .unwrap();

    spec.set_pc_manager(super::StandardPcManager::default().into());

    spec.set_generator(super::StandardGeneratorHelper::default().into());

    armv7_common(&mut spec);

    armv7a_common(&mut spec);

    spec.call_other_manager
        .add_handler_other_sla(Arm7LeUserOps::CoprocMovefromControl, CoprocMovefromControl)
        .unwrap();
    spec.call_other_manager
        .add_handler_other_sla(Arm7LeUserOps::CoprocMovetoControl, CoprocMovetoControl)
        .unwrap();
    spec.call_other_manager
        .add_handler_other_sla(
            Arm7LeUserOps::CoprocMovefromPeripheralSystem,
            CoprocMovefromPeripheralSystem,
        )
        .unwrap();
    spec.call_other_manager
        .add_handler_other_sla(Arm7LeUserOps::CoprocessorMovefromRt, CoprocessorMovefromRt)
        .unwrap();
    spec
}

pub fn build_le() -> ArchSpecBuilder<Arm7Le> {
    build()
}

pub fn build_be() -> ArchSpecBuilder<Arm7Be> {
    build()
}
