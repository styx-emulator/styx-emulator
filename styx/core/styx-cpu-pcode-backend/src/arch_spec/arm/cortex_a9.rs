// SPDX-License-Identifier: BSD-2-Clause

use std::str::FromStr;

use super::call_other::{
    CoprocMovefromControl, CoprocMovefromPeripheralSystem, CoprocMovetoControl,
    CoprocessorMovefromRt,
};
use crate::memory::sized_value::SizedValue;
use crate::register_manager::{RegisterCallbackCpu, RegisterHandleError};
use crate::{
    arch_spec::{
        arm::{armv7_common, armv7a_common},
        ArchSpecBuilder,
    },
    register_manager::{RegisterCallback, RegisterHandler},
    PcodeBackend,
};
use styx_cpu_type::arch::{
    arm::{arm_coproc_registers, SpecialArmRegister},
    backends::{ArchRegister, SpecialArchRegister},
};
use styx_pcode::sla::SlaUserOps;
use styx_pcode_translator::sla::{Arm7Be, Arm7Le, Arm7LeUserOps};
use styx_processor::cpu::CpuBackend;

#[derive(Debug, Default)]
struct CoProcRegisterHandler {
    cbar: u32,
    vbar: u32,
    sctlr: u32,
}

impl<T: CpuBackend> RegisterCallback<T> for CoProcRegisterHandler {
    fn read(
        &mut self,
        register: ArchRegister,
        _cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<SizedValue, RegisterHandleError> {
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
        register: ArchRegister,
        value: SizedValue,
        _cpu: &mut dyn RegisterCallbackCpu<T>,
    ) -> Result<(), RegisterHandleError> {
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

pub fn build<S: SlaUserOps<UserOps: FromStr>>() -> ArchSpecBuilder<S, PcodeBackend> {
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

pub fn build_le() -> ArchSpecBuilder<Arm7Le, PcodeBackend> {
    build()
}

pub fn build_be() -> ArchSpecBuilder<Arm7Be, PcodeBackend> {
    build()
}
