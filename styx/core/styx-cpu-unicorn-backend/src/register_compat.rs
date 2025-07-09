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
//! Styx to unicorn register compatibility layer
use styx_cpu_type::arch::arm::{CoProcessor, CoProcessorValue, SpecialArmRegisterValues};
use styx_cpu_type::arch::backends::{ArchRegister, BasicArchRegister, SpecialArchRegister};
use styx_cpu_type::arch::RegisterValue;
use styx_errors::anyhow::anyhow;
use styx_errors::UnknownError;

/// Rust version of the type representing an action to perform
/// with an ARM coprocessor
///
/// Sourced from unicorn, the typedef looks like this:
///
/// ```c
/// ARM coprocessor registers, use this with UC_ARM_REG_CP_REG to
// in call to uc_reg_write/read() to access the registers.
/// typedef struct uc_arm_cp_reg {
///     uint32_t cp;   // The coprocessor identifier
///     uint32_t is64; // Is it a 64 bit control register
///     uint32_t sec;  // Security state
///     uint32_t crn;  // Coprocessor register number
///     uint32_t crm;  // Coprocessor register number
///     uint32_t opc1; // Opcode1
///     uint32_t opc2; // Opcode2
///     uint64_t val;  // The value to read/write
/// } uc_arm_cp_reg;
/// ```
#[repr(C)]
#[derive(Debug, PartialEq, Eq, Clone, Default)]
pub struct UcArmCoprocessorRegisterAction {
    /// Coprocessor identifier
    cp: u32,
    /// Is it a 64 bit control register
    is64: u32,
    /// Security state
    sec: u32,
    /// Coprocessor register number 1
    crn: u32,
    /// Coprocessor register number 2
    crm: u32,
    /// Opcode1
    opc1: u32,
    /// Opcode2
    opc2: u32,
    /// Value to read to / write from
    val: u64,
}

impl From<UcArmCoprocessorRegisterAction> for RegisterValue {
    fn from(value: UcArmCoprocessorRegisterAction) -> Self {
        RegisterValue::ArmSpecial(SpecialArmRegisterValues::CoProcessor(CoProcessorValue {
            reg: CoProcessor {
                coproc: value.cp.try_into().unwrap(),
                crn: value.crn.try_into().unwrap(),
                crm: value.crm.try_into().unwrap(),
                opc1: value.opc1,
                opc2: value.opc2,
                secure_state: value.sec != 0,
            },
            value: value.val,
        }))
    }
}

impl From<CoProcessorValue> for UcArmCoprocessorRegisterAction {
    fn from(value: CoProcessorValue) -> Self {
        Self {
            cp: value.reg.coproc as u32,
            is64: false.into(),
            sec: value.reg.secure_state.into(),
            crn: value.reg.crn as u32,
            crm: value.reg.crm as u32,
            opc1: value.reg.opc1,
            opc2: value.reg.opc2,
            val: value.value,
        }
    }
}

impl From<CoProcessor> for UcArmCoprocessorRegisterAction {
    fn from(value: CoProcessor) -> Self {
        Self {
            cp: value.coproc as u32,
            is64: false.into(),
            sec: value.secure_state.into(),
            crn: value.crn as u32,
            crm: value.crm as u32,
            opc1: value.opc1,
            opc2: value.opc2,
            val: 0,
        }
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
mod unicorn_arm_coproc_access_tests {
    use super::*;
    use crate::UnicornBackend;
    use styx_cpu_type::arch::arm::{arm_coproc_registers, ArmVariants};
    use styx_cpu_type::arch::{Arch, ArchEndian};
    use styx_processor::cpu::CpuBackendExt;

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn write_to_coproc_register_not_fail() {
        // can we write to a coprocessor register without exploding
        // - we're not testing the actual write, just that it doesn't explode
        // - unicorn only implements coprocessor writes for a few cpu models
        let mut cpu = UnicornBackend::new_engine(
            Arch::Arm,
            ArmVariants::ArmCortexA9,
            ArchEndian::LittleEndian,
        );

        let reg = arm_coproc_registers::CBAR;

        cpu.write_register(reg, reg.into_value()).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn read_from_coproc_register_not_fail() {
        // can we read to a coprocessor register without exploding
        // - we're not testing the actual read, just that it doesn't explode
        // - unicorn only implements coprocessor writes for a few cpu models
        let mut cpu = UnicornBackend::new_engine(
            Arch::Arm,
            ArmVariants::ArmCortexA9,
            ArchEndian::LittleEndian,
        );

        let _ = cpu
            .read_register::<CoProcessorValue>(arm_coproc_registers::SCTLR)
            .unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn coproc_register_write_read_correct() {
        // can we write to a coprocessor register and read it back
        let mut cpu = UnicornBackend::new_engine(
            Arch::Arm,
            ArmVariants::ArmCortexA9,
            ArchEndian::LittleEndian,
        );

        let reg = arm_coproc_registers::CBAR;

        let val = cpu.read_register::<CoProcessorValue>(reg).unwrap();

        assert_eq!(reg.coproc, val.reg.coproc);
        assert_eq!(reg.crn, val.reg.crn);
        assert_eq!(reg.crm, val.reg.crm);
        assert_eq!(reg.opc1, val.reg.opc1);
        assert_eq!(reg.opc2, val.reg.opc2);
        assert_eq!(reg.secure_state, val.reg.secure_state);

        let val_to_write = reg.with_value(1);

        cpu.write_register(reg, val_to_write).unwrap();

        let val = cpu.read_register::<CoProcessorValue>(reg).unwrap();

        assert_eq!(reg.coproc, val.reg.coproc);
        assert_eq!(reg.crn, val.reg.crn);
        assert_eq!(reg.crm, val.reg.crm);
        assert_eq!(reg.opc1, val.reg.opc1);
        assert_eq!(reg.opc2, val.reg.opc2);
        assert_eq!(reg.secure_state, val.reg.secure_state);
        assert_eq!(val.value, 1);
    }
}

/// Converts from `styx` register impl into Unicorn-known register impl
///
/// Given any register from any architecture supported, convert
/// the global register into a register c-enum value known by
/// unicorn. All those are set as C i32, so we return an i32
#[allow(unreachable_patterns)] // for the moment we only implement arm for `ArchRegister`
pub fn styx_to_unicorn_register(reg: ArchRegister) -> Result<i32, UnknownError> {
    match reg {
        ArchRegister::Basic(BasicArchRegister::Arm(inner)) => {
            Ok(Into::<unicorn_engine::RegisterARM>::into(inner).into())
        }
        ArchRegister::Basic(BasicArchRegister::Ppc32(inner)) => {
            Ok(Into::<unicorn_engine::RegisterPPC>::into(inner).into())
        }
        ArchRegister::Special(SpecialArchRegister::Arm(inner)) => {
            Ok(Into::<unicorn_engine::RegisterARM>::into(inner).into())
        }
        ArchRegister::Special(SpecialArchRegister::Ppc32(inner)) => {
            Ok(Into::<unicorn_engine::RegisterPPC>::into(inner).into())
        }
        // unhandled architecture
        _ => Err(anyhow!("unhandled arch")),
    }
}
