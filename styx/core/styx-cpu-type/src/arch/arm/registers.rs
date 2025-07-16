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
//! Generic top level container for ARM registers.
use derive_more::Display;
use std::num::NonZeroUsize;

use crate::arch::{backends::ArchRegister, CpuRegister, RegisterValue, RegisterValueCompatible};
use crate::macros::*;

#[repr(u32)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CoProc {
    #[default]
    P0 = 0,
    P1,
    P2,
    P3,
    P4,
    P5,
    P6,
    P7,
    P8,
    P9,
    P10,
    P11,
    P12,
    P13,
    P14,
    P15,
}

impl TryFrom<u32> for CoProc {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(CoProc::P0),
            1 => Ok(CoProc::P1),
            2 => Ok(CoProc::P2),
            3 => Ok(CoProc::P3),
            4 => Ok(CoProc::P4),
            5 => Ok(CoProc::P5),
            6 => Ok(CoProc::P6),
            7 => Ok(CoProc::P7),
            8 => Ok(CoProc::P8),
            9 => Ok(CoProc::P9),
            10 => Ok(CoProc::P10),
            11 => Ok(CoProc::P11),
            12 => Ok(CoProc::P12),
            13 => Ok(CoProc::P13),
            14 => Ok(CoProc::P14),
            15 => Ok(CoProc::P15),
            _ => Err(()),
        }
    }
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CoProcReg {
    #[default]
    R0 = 0,
    R1,
    R2,
    R3,
    R4,
    R5,
    R6,
    R7,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
}

impl TryFrom<u32> for CoProcReg {
    type Error = ();

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(CoProcReg::R0),
            1 => Ok(CoProcReg::R1),
            2 => Ok(CoProcReg::R2),
            3 => Ok(CoProcReg::R3),
            4 => Ok(CoProcReg::R4),
            5 => Ok(CoProcReg::R5),
            6 => Ok(CoProcReg::R6),
            7 => Ok(CoProcReg::R7),
            8 => Ok(CoProcReg::R8),
            9 => Ok(CoProcReg::R9),
            10 => Ok(CoProcReg::R10),
            11 => Ok(CoProcReg::R11),
            12 => Ok(CoProcReg::R12),
            13 => Ok(CoProcReg::R13),
            14 => Ok(CoProcReg::R14),
            15 => Ok(CoProcReg::R15),
            _ => Err(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, PartialOrd, Ord, Hash)]
pub struct CoProcessor {
    /// Co-Processor number
    pub coproc: CoProc,
    /// Coprocessor register number 1
    pub crn: CoProcReg,
    /// Coprocessor register number 2
    pub crm: CoProcReg,
    /// Opcode 1
    pub opc1: u32,
    /// Opcode 2
    pub opc2: u32,
    /// security mode
    pub secure_state: bool,
}

impl CoProcessor {
    pub fn into_value(self) -> CoProcessorValue {
        CoProcessorValue {
            reg: self,
            value: 0,
        }
    }

    pub fn with_value(self, val: u64) -> CoProcessorValue {
        CoProcessorValue {
            reg: self,
            value: val,
        }
    }

    pub const fn new() -> Self {
        Self {
            coproc: CoProc::P0,
            crn: CoProcReg::R0,
            crm: CoProcReg::R0,
            opc1: 0,
            opc2: 0,
            secure_state: false,
        }
    }
}

impl From<CoProcessor> for ArchRegister {
    fn from(value: CoProcessor) -> Self {
        SpecialArmRegister::CoProcessor(value).into()
    }
}

impl std::fmt::Display for CoProcessor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Coprocessor Register")
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CoProcessorValue {
    pub reg: CoProcessor,
    pub value: u64,
}

impl CoProcessorValue {
    pub const fn const_default() -> Self {
        Self {
            reg: CoProcessor::new(),
            value: 0,
        }
    }
}

impl std::fmt::Display for CoProcessorValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl RegisterValueCompatible for CoProcessorValue {
    type ReturnValue = CoProcessorValue;

    fn as_inner_value(reg_val: RegisterValue) -> Result<Self::ReturnValue, RegisterValue> {
        Ok(reg_val.into_arm_special().unwrap().into_coproc_value())
    }
}

impl SpecialArmRegisterValues {
    fn into_coproc_value(self) -> CoProcessorValue {
        match self {
            Self::CoProcessor(co_proc_register_value) => co_proc_register_value,
        }
    }
}

pub mod arm_coproc_registers {
    use super::{CoProc, CoProcReg, CoProcessor};

    pub const CBAR: CoProcessor = CoProcessor {
        coproc: CoProc::P15,
        crn: CoProcReg::R15,
        crm: CoProcReg::R0,
        opc1: 4,
        opc2: 0,
        secure_state: false,
    };

    pub const VBAR: CoProcessor = CoProcessor {
        coproc: CoProc::P15,
        crn: CoProcReg::R12,
        crm: CoProcReg::R0,
        opc1: 0,
        opc2: 0,
        secure_state: false,
    };

    pub const SCTLR: CoProcessor = CoProcessor {
        coproc: CoProc::P15,
        crn: CoProcReg::R1,
        crm: CoProcReg::R0,
        opc1: 0,
        opc2: 0,
        secure_state: false,
    };
}

// Implementation notes for backends:
//
//    /// Backends should alias this to R9 under the hood
//    /// (if supported)
//    Sb,
//    /// Backends should alias this to R10 under the hood
//    /// (if supported)
//    Sl,
//    /// Backends should alias this to R11 under the hood
//    /// (if supported)
//    Fp,
//    /// Backends should alias this to R12 under the hood
//    /// (if supported)
//    Ip,
//    /// Backends should alias this to SP under the hood
//    /// (if supported)
//    R13,
//    /// Backends should alias this to LR under the hood
//    /// (if supported)
//    R14,
//    /// Backends should alias this to PC under the hood
//    /// (if supported)
//    R15,
create_basic_register_enums!(
    Arm,
    (Apsr, 32),
    (Cpsr, 32),
    (Fpexc, 32),
    (Fpscr, 32),
    (Fpsid, 32),
    (Mvfr0, 32),
    (Mvfr1, 32),
    (Itstate, 32),
    (Lr, 32),
    (Pc, 32),
    (Sp, 32),
    (Spsr, 32),
    (D0, 64),
    (D1, 64),
    (D2, 64),
    (D3, 64),
    (D4, 64),
    (D5, 64),
    (D6, 64),
    (D7, 64),
    (D8, 64),
    (D9, 64),
    (D10, 64),
    (D11, 64),
    (D12, 64),
    (D13, 64),
    (D14, 64),
    (D15, 64),
    (D16, 64),
    (D17, 64),
    (D18, 64),
    (D19, 64),
    (D20, 64),
    (D21, 64),
    (D22, 64),
    (D23, 64),
    (D24, 64),
    (D25, 64),
    (D26, 64),
    (D27, 64),
    (D28, 64),
    (D29, 64),
    (D30, 64),
    (D31, 64),
    (Q0, 128),
    (Q1, 128),
    (Q2, 128),
    (Q3, 128),
    (Q4, 128),
    (Q5, 128),
    (Q6, 128),
    (Q7, 128),
    (Q8, 128),
    (Q9, 128),
    (Q10, 128),
    (Q11, 128),
    (Q12, 128),
    (Q13, 128),
    (Q14, 128),
    (Q15, 128),
    (R0, 32),
    (R1, 32),
    (R2, 32),
    (R3, 32),
    (R4, 32),
    (R5, 32),
    (R6, 32),
    (R7, 32),
    (R8, 32),
    (R9, 32),
    (R10, 32),
    (R11, 32),
    (R12, 32),
    (S0, 32),
    (S1, 32),
    (S2, 32),
    (S3, 32),
    (S4, 32),
    (S5, 32),
    (S6, 32),
    (S7, 32),
    (S8, 32),
    (S9, 32),
    (S10, 32),
    (S11, 32),
    (S12, 32),
    (S13, 32),
    (S14, 32),
    (S15, 32),
    (S16, 32),
    (S17, 32),
    (S18, 32),
    (S19, 32),
    (S20, 32),
    (S21, 32),
    (S22, 32),
    (S23, 32),
    (S24, 32),
    (S25, 32),
    (S26, 32),
    (S27, 32),
    (S28, 32),
    (S29, 32),
    (S30, 32),
    (S31, 32),
    (Ipsr, 32),
    (Msp, 32),
    (Psp, 32),
    (Control, 32),
    (Iapsr, 32),
    (Eapsr, 32),
    (Xpsr, 32),
    (Epsr, 32),
    (Iepsr, 32),
    (Primask, 32),
    (Basepri, 32),
    (Faultmask, 32),
    (Sb, 32),
    (Sl, 32),
    (Fp, 32),
    (Ip, 32),
    (R13, 32),
    (R14, 32),
    (R15, 32),
);

create_special_register_enums!(Arm, CoProcessor);

#[cfg(test)]
mod tests {
    use super::*;
    use arbitrary_int::{u40, u80};
    use std::str::FromStr;
    use test_case::test_case;

    #[test]
    fn test_regs_from_str() {
        assert_eq!(ArmRegister::Apsr, ArmRegister::from_str("Apsr").unwrap());
        assert_eq!(ArmRegister::Cpsr, ArmRegister::from_str("Cpsr").unwrap());
        assert_eq!(ArmRegister::Sp, ArmRegister::from_str("Sp").unwrap());
        assert_eq!(ArmRegister::Pc, ArmRegister::from_str("Pc").unwrap());
        assert_eq!(ArmRegister::Lr, ArmRegister::from_str("Lr").unwrap());
        assert_eq!(ArmRegister::R0, ArmRegister::from_str("R0").unwrap());
        assert_eq!(ArmRegister::R0, ArmRegister::from_str("r0").unwrap());
        assert_eq!(ArmRegister::Pc, ArmRegister::from_str("pc").unwrap());
    }

    const COPROC_ZERO: CoProcessorValue = CoProcessorValue {
        reg: CoProcessor {
            coproc: CoProc::P0,
            crn: CoProcReg::R0,
            crm: CoProcReg::R0,
            opc1: 0,
            opc2: 0,
            secure_state: false,
        },
        value: 0,
    };

    const COPROC_SET_BITS: CoProcessorValue = CoProcessorValue {
        reg: CoProcessor {
            coproc: CoProc::P10,
            crn: CoProcReg::R10,
            crm: CoProcReg::R10,
            opc1: 10,
            opc2: 10,
            secure_state: true,
        },
        value: 0xdeadbeef,
    };

    #[test_case(COPROC_ZERO, 0u8, std::cmp::Ordering::Greater; "coproc to same u8 eq")]
    #[test_case(COPROC_ZERO, 0u16, std::cmp::Ordering::Greater; "coproc to same u16 eq")]
    #[test_case(COPROC_ZERO, 0u32, std::cmp::Ordering::Greater; "coproc to same u32 eq")]
    #[test_case(COPROC_ZERO, u40::from(0u8), std::cmp::Ordering::Greater; "coproc to same u40 eq")]
    #[test_case(COPROC_ZERO, 0u64, std::cmp::Ordering::Greater; "coproc to same u64 eq")]
    #[test_case(COPROC_ZERO, u80::from(0u8), std::cmp::Ordering::Greater; "coproc to same u80 eq")]
    #[test_case(COPROC_ZERO, 0u128, std::cmp::Ordering::Greater; "coproc to same u128 eq")]
    #[test_case(COPROC_ZERO, COPROC_ZERO, std::cmp::Ordering::Equal; "coproc to same coproc eq")]
    #[test_case(COPROC_ZERO, COPROC_SET_BITS, std::cmp::Ordering::Equal; "coproc to coproc same set_bits eq")]
    #[test_case(COPROC_ZERO, 0u8, std::cmp::Ordering::Greater; "coproc to diff u8 eq")]
    #[test_case(COPROC_ZERO, 0u16, std::cmp::Ordering::Greater; "coproc to diff u16 eq")]
    #[test_case(COPROC_ZERO, 0u32, std::cmp::Ordering::Greater; "coproc to diff u32 eq")]
    #[test_case(COPROC_ZERO, u40::from(0u8), std::cmp::Ordering::Greater; "coproc to diff u40 eq")]
    #[test_case(COPROC_ZERO, 0u64, std::cmp::Ordering::Greater; "coproc to diff u64 eq")]
    #[test_case(COPROC_ZERO, u80::from(0u8), std::cmp::Ordering::Greater; "coproc to diff u80 eq")]
    #[test_case(COPROC_ZERO, 0u128, std::cmp::Ordering::Greater; "coproc to diff u128 eq")]
    #[test_case(COPROC_ZERO, COPROC_ZERO, std::cmp::Ordering::Equal; "coproc to diff coproc eq")]
    #[test_case(COPROC_ZERO, COPROC_SET_BITS, std::cmp::Ordering::Equal; "coproc to coproc diff set_bits eq")]
    #[test_case(COPROC_SET_BITS, 0u8, std::cmp::Ordering::Greater; "coproc set_bits to same u8 eq")]
    #[test_case(COPROC_SET_BITS, 0u16, std::cmp::Ordering::Greater; "coproc set_bits to same u16 eq")]
    #[test_case(COPROC_SET_BITS, 0u32, std::cmp::Ordering::Greater; "coproc set_bits to same u32 eq")]
    #[test_case(COPROC_SET_BITS, u40::from(0u8), std::cmp::Ordering::Greater; "coproc set_bits to same u40 eq")]
    #[test_case(COPROC_SET_BITS, 0u64, std::cmp::Ordering::Greater; "coproc set_bits to same u64 eq")]
    #[test_case(COPROC_SET_BITS, u80::from(0u8), std::cmp::Ordering::Greater; "coproc set_bits to same u80 eq")]
    #[test_case(COPROC_SET_BITS, 0u128, std::cmp::Ordering::Greater; "coproc set_bits to same u128 eq")]
    #[test_case(COPROC_SET_BITS, COPROC_ZERO, std::cmp::Ordering::Equal; "coproc set_bits to same coproc eq")]
    #[test_case(COPROC_SET_BITS, COPROC_SET_BITS, std::cmp::Ordering::Equal; "coproc set_bits to coproc same set_bits eq")]
    #[test_case(COPROC_SET_BITS, 0u8, std::cmp::Ordering::Greater; "coproc set_bits to diff u8 eq")]
    #[test_case(COPROC_SET_BITS, 0u16, std::cmp::Ordering::Greater; "coproc set_bits to diff u16 eq")]
    #[test_case(COPROC_SET_BITS, 0u32, std::cmp::Ordering::Greater; "coproc set_bits to diff u32 eq")]
    #[test_case(COPROC_SET_BITS, u40::from(0u8), std::cmp::Ordering::Greater; "coproc set_bits to diff u40 eq")]
    #[test_case(COPROC_SET_BITS, 0u64, std::cmp::Ordering::Greater; "coproc set_bits to diff u64 eq")]
    #[test_case(COPROC_SET_BITS, u80::from(0u8), std::cmp::Ordering::Greater; "coproc set_bits to diff u80 eq")]
    #[test_case(COPROC_SET_BITS, 0u128, std::cmp::Ordering::Greater; "coproc set_bits to diff u128 eq")]
    #[test_case(COPROC_SET_BITS, COPROC_ZERO, std::cmp::Ordering::Equal; "coproc set_bits to diff coproc eq")]
    #[test_case(COPROC_SET_BITS, COPROC_SET_BITS, std::cmp::Ordering::Equal; "coproc set_bits to coproc diff set_bits eq")]
    fn test_compare_coproc_register_value(
        coproc_reg: impl Into<RegisterValue>,
        reg_value: impl Into<RegisterValue>,
        res: std::cmp::Ordering,
    ) {
        let coproc_reg = coproc_reg.into();
        let other_reg = reg_value.into();

        assert_eq!(res, coproc_reg.cmp(&other_reg));
    }
}
