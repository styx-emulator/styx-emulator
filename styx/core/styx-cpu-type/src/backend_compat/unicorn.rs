// SPDX-License-Identifier: BSD-2-Clause
//! Impls on the styx types to convert to the unicorn backend types
use crate::arch::StyxCpuArchError;
use crate::TargetExitReason;
use unicorn_engine::{uc_error, unicorn_const};

//
// [`TargetExitReason`]
//

impl TryFrom<unicorn_engine::uc_error> for TargetExitReason {
    type Error = String;
    /// attempt to convert the unicorn exit code into a [`TargetExitReason`]
    fn try_from(value: unicorn_engine::uc_error) -> Result<Self, Self::Error> {
        match value {
            uc_error::READ_UNMAPPED => Ok(TargetExitReason::UnmappedMemoryRead),
            uc_error::WRITE_UNMAPPED => Ok(TargetExitReason::UnmappedMemoryWrite),
            uc_error::FETCH_UNMAPPED => Ok(TargetExitReason::UnmappedMemoryFetch),
            uc_error::READ_UNALIGNED => Ok(TargetExitReason::UnalignedMemoryRead),
            uc_error::WRITE_UNALIGNED => Ok(TargetExitReason::UnalignedMemoryWrite),
            uc_error::FETCH_UNALIGNED => Ok(TargetExitReason::UnalignedMemoryFetch),
            uc_error::READ_PROT => Ok(TargetExitReason::ProtectedMemoryRead),
            uc_error::WRITE_PROT => Ok(TargetExitReason::ProtectedMemoryWrite),
            uc_error::FETCH_PROT => Ok(TargetExitReason::ProtectedMemoryFetch),
            uc_error::INSN_INVALID => Ok(TargetExitReason::InstructionDecodeError),
            uc_error::MAP => Ok(TargetExitReason::InvalidMemoryMapping),
            _ => Err(String::from("No applicable code found")),
        }
    }
}

//
// [`Arch`]
//

impl From<unicorn_const::Arch> for crate::arch::Arch {
    fn from(value: unicorn_const::Arch) -> Self {
        match value {
            unicorn_const::Arch::ARM => crate::arch::Arch::Arm,
            unicorn_const::Arch::M68K => crate::arch::Arch::M68k,
            unicorn_const::Arch::MIPS => crate::arch::Arch::Mips64,
            unicorn_const::Arch::PPC => crate::arch::Arch::Ppc32,
            unicorn_const::Arch::RISCV => crate::arch::Arch::Riscv,
            unicorn_const::Arch::SPARC => crate::arch::Arch::Sparc,
            unicorn_const::Arch::TRICORE => crate::arch::Arch::Tricore,
            unicorn_const::Arch::X86 => crate::arch::Arch::X86,
            _ => panic!("Unicorn architecture: {:?} has no styx equivalent", value),
        }
    }
}

impl TryInto<unicorn_const::Arch> for crate::arch::Arch {
    type Error = StyxCpuArchError;

    fn try_into(self) -> Result<unicorn_const::Arch, Self::Error> {
        match self {
            crate::arch::Arch::Arm => Ok(unicorn_const::Arch::ARM),
            crate::arch::Arch::M68k => Ok(unicorn_const::Arch::M68K),
            crate::arch::Arch::Mips64 => Ok(unicorn_const::Arch::MIPS),
            crate::arch::Arch::Mips32 => Ok(unicorn_const::Arch::MIPS),
            crate::arch::Arch::Ppc32 => Ok(unicorn_const::Arch::PPC),
            crate::arch::Arch::Riscv => Ok(unicorn_const::Arch::RISCV),
            crate::arch::Arch::Sparc => Ok(unicorn_const::Arch::SPARC),
            crate::arch::Arch::Tricore => Ok(unicorn_const::Arch::TRICORE),
            crate::arch::Arch::X86 => Ok(unicorn_const::Arch::X86),
            _ => Err(StyxCpuArchError::NotSupported(self)),
        }
    }
}

impl From<crate::arch::ArchEndian> for unicorn_const::Mode {
    fn from(value: crate::arch::ArchEndian) -> Self {
        match value {
            crate::arch::ArchEndian::BigEndian => unicorn_const::Mode::BIG_ENDIAN,
            crate::arch::ArchEndian::LittleEndian => unicorn_const::Mode::LITTLE_ENDIAN,
        }
    }
}

impl From<crate::arch::arm::ArmMetaVariants> for unicorn_engine::ArmCpuModel {
    fn from(value: crate::arch::arm::ArmMetaVariants) -> Self {
        use crate::arch::arm::ArmMetaVariants as STYX_ARM;
        use unicorn_engine::ArmCpuModel as UC_ARM;

        match value {
            STYX_ARM::Arm1026(_) => UC_ARM::UC_CPU_ARM_1026,
            STYX_ARM::Arm1136(_) => UC_ARM::UC_CPU_ARM_1136,
            STYX_ARM::Arm1136r2(_) => UC_ARM::UC_CPU_ARM_1136_R2,
            STYX_ARM::Arm1176(_) => UC_ARM::UC_CPU_ARM_1176,
            STYX_ARM::Arm11Mpcore(_) => UC_ARM::UC_CPU_ARM_11MPCORE,
            STYX_ARM::Arm926(_) => UC_ARM::UC_CPU_ARM_926,
            STYX_ARM::Arm946(_) => UC_ARM::UC_CPU_ARM_946,
            STYX_ARM::ArmCortexA15(_) => UC_ARM::UC_CPU_ARM_CORTEX_A15,
            STYX_ARM::ArmCortexA7(_) => UC_ARM::UC_CPU_ARM_CORTEX_A7,
            STYX_ARM::ArmCortexA8(_) => UC_ARM::UC_CPU_ARM_CORTEX_A9,
            STYX_ARM::ArmCortexA9(_) => UC_ARM::UC_CPU_ARM_CORTEX_A9,
            STYX_ARM::ArmCortexM0(_) => UC_ARM::UC_CPU_ARM_CORTEX_M0,
            STYX_ARM::ArmCortexM3(_) => UC_ARM::UC_CPU_ARM_CORTEX_M3,
            STYX_ARM::ArmCortexM33(_) => UC_ARM::UC_CPU_ARM_CORTEX_M33,
            STYX_ARM::ArmCortexM4(_) => UC_ARM::UC_CPU_ARM_CORTEX_M4,
            STYX_ARM::ArmCortexM7(_) => UC_ARM::UC_CPU_ARM_CORTEX_M7,
            STYX_ARM::ArmCortexR5(_) => UC_ARM::UC_CPU_ARM_CORTEX_R5,
            STYX_ARM::ArmCortexR5F(_) => UC_ARM::UC_CPU_ARM_CORTEX_R5F,
            STYX_ARM::ArmPxa250(_) => UC_ARM::UC_CPU_ARM_PXA250,
            STYX_ARM::ArmPxa255(_) => UC_ARM::UC_CPU_ARM_PXA255,
            STYX_ARM::ArmPxa260(_) => UC_ARM::UC_CPU_ARM_PXA260,
            STYX_ARM::ArmPxa261(_) => UC_ARM::UC_CPU_ARM_PXA261,
            STYX_ARM::ArmPxa262(_) => UC_ARM::UC_CPU_ARM_PXA262,
            STYX_ARM::ArmPxa270(_) => UC_ARM::UC_CPU_ARM_PXA270,
            STYX_ARM::ArmPxa270a0(_) => UC_ARM::UC_CPU_ARM_PXA270A0,
            STYX_ARM::ArmPxa270a1(_) => UC_ARM::UC_CPU_ARM_PXA270A1,
            STYX_ARM::ArmPxa270b0(_) => UC_ARM::UC_CPU_ARM_PXA270B0,
            STYX_ARM::ArmPxa270b1(_) => UC_ARM::UC_CPU_ARM_PXA270B1,
            STYX_ARM::ArmPxa270c0(_) => UC_ARM::UC_CPU_ARM_PXA270C0,
            STYX_ARM::ArmPxa270c5(_) => UC_ARM::UC_CPU_ARM_PXA270C5,
            STYX_ARM::ArmSa1100(_) => UC_ARM::UC_CPU_ARM_SA1100,
            STYX_ARM::ArmSa1110(_) => UC_ARM::UC_CPU_ARM_SA1110,
            STYX_ARM::ArmTi925T(_) => UC_ARM::UC_CPU_ARM_TI925T,
        }
    }
}

impl From<crate::arch::ppc32::Ppc32MetaVariants> for unicorn_engine::PpcCpuModel {
    fn from(value: crate::arch::ppc32::Ppc32MetaVariants) -> Self {
        use crate::arch::ppc32::Ppc32MetaVariants as STYX_PPC;
        use unicorn_engine::PpcCpuModel as UC_PPC;

        match value {
            // all PowerQUICC I models map to the MPC8343E, since
            // we're only using unicorn for insn emulation, which
            // the 855T is a proper subset of 8343E (unicorn doesn't
            // have any model earlier than PowerQUICC II PRO)
            STYX_PPC::Mpc821(_) => UC_PPC::UC_CPU_PPC32_MPC8343E,
            STYX_PPC::Mpc823(_) => UC_PPC::UC_CPU_PPC32_MPC8343E,
            STYX_PPC::Mpc823E(_) => UC_PPC::UC_CPU_PPC32_MPC8343E,
            STYX_PPC::Mpc850(_) => UC_PPC::UC_CPU_PPC32_MPC8343E,
            STYX_PPC::Mpc852T(_) => UC_PPC::UC_CPU_PPC32_MPC8343E,
            STYX_PPC::Mpc853T(_) => UC_PPC::UC_CPU_PPC32_MPC8343E,
            STYX_PPC::Mpc855T(_) => UC_PPC::UC_CPU_PPC32_MPC8343E,
            STYX_PPC::Mpc859T(_) => UC_PPC::UC_CPU_PPC32_MPC8343E,
            STYX_PPC::Mpc857DSL(_) => UC_PPC::UC_CPU_PPC32_MPC8343E,
            STYX_PPC::Mpc859DSL(_) => UC_PPC::UC_CPU_PPC32_MPC8343E,
            STYX_PPC::Mpc860(_) => UC_PPC::UC_CPU_PPC32_MPC8343E,
            STYX_PPC::Mpc862(_) => UC_PPC::UC_CPU_PPC32_MPC8343E,
            STYX_PPC::Mpc866(_) => UC_PPC::UC_CPU_PPC32_MPC8343E,
            STYX_PPC::Mpc870(_) => UC_PPC::UC_CPU_PPC32_MPC8343E,
            STYX_PPC::Mpc875(_) => UC_PPC::UC_CPU_PPC32_MPC8343E,
            STYX_PPC::Mpc880(_) => UC_PPC::UC_CPU_PPC32_MPC8343E,
            STYX_PPC::Mpc885(_) => UC_PPC::UC_CPU_PPC32_MPC8343E,
            STYX_PPC::Ppc401(_) => UC_PPC::UC_CPU_PPC32_401,
            STYX_PPC::Ppc405(_) => UC_PPC::UC_CPU_PPC32_405D2, // guessed the exact model
            STYX_PPC::Ppc440(_) => UC_PPC::UC_CPU_PPC32_440_XILINX, // guessed the exact model
            STYX_PPC::Ppc470(_) => UC_PPC::UC_CPU_PPC32_460EXB, // no 470 models
        }
    }
}

//
// now registers
//

impl From<crate::arch::ppc32::Ppc32Register> for unicorn_engine::RegisterPPC {
    fn from(value: crate::arch::ppc32::Ppc32Register) -> Self {
        use crate::arch::ppc32::Ppc32Register as STYX_PPC;
        use unicorn_engine::RegisterPPC as UC_PPC;

        match value {
            STYX_PPC::Pc => UC_PPC::PC,
            STYX_PPC::Cr => UC_PPC::CR,
            STYX_PPC::Ctr => UC_PPC::CTR,
            STYX_PPC::Fpr0 => UC_PPC::FPR0,
            STYX_PPC::Fpr1 => UC_PPC::FPR1,
            STYX_PPC::Fpr2 => UC_PPC::FPR2,
            STYX_PPC::Fpr3 => UC_PPC::FPR3,
            STYX_PPC::Fpr4 => UC_PPC::FPR4,
            STYX_PPC::Fpr5 => UC_PPC::FPR5,
            STYX_PPC::Fpr6 => UC_PPC::FPR6,
            STYX_PPC::Fpr7 => UC_PPC::FPR7,
            STYX_PPC::Fpr8 => UC_PPC::FPR8,
            STYX_PPC::Fpr9 => UC_PPC::FPR9,
            STYX_PPC::Fpr10 => UC_PPC::FPR10,
            STYX_PPC::Fpr11 => UC_PPC::FPR11,
            STYX_PPC::Fpr12 => UC_PPC::FPR12,
            STYX_PPC::Fpr13 => UC_PPC::FPR13,
            STYX_PPC::Fpr14 => UC_PPC::FPR14,
            STYX_PPC::Fpr15 => UC_PPC::FPR15,
            STYX_PPC::Fpr16 => UC_PPC::FPR16,
            STYX_PPC::Fpr17 => UC_PPC::FPR17,
            STYX_PPC::Fpr18 => UC_PPC::FPR18,
            STYX_PPC::Fpr19 => UC_PPC::FPR19,
            STYX_PPC::Fpr20 => UC_PPC::FPR20,
            STYX_PPC::Fpr21 => UC_PPC::FPR21,
            STYX_PPC::Fpr22 => UC_PPC::FPR22,
            STYX_PPC::Fpr23 => UC_PPC::FPR23,
            STYX_PPC::Fpr24 => UC_PPC::FPR24,
            STYX_PPC::Fpr25 => UC_PPC::FPR25,
            STYX_PPC::Fpr26 => UC_PPC::FPR26,
            STYX_PPC::Fpr27 => UC_PPC::FPR27,
            STYX_PPC::Fpr28 => UC_PPC::FPR28,
            STYX_PPC::Fpr29 => UC_PPC::FPR29,
            STYX_PPC::Fpr30 => UC_PPC::FPR30,
            STYX_PPC::Fpr31 => UC_PPC::FPR31,
            STYX_PPC::R0 => UC_PPC::R0,
            STYX_PPC::R1 => UC_PPC::R1,
            STYX_PPC::R2 => UC_PPC::R2,
            STYX_PPC::R3 => UC_PPC::R3,
            STYX_PPC::R4 => UC_PPC::R4,
            STYX_PPC::R5 => UC_PPC::R5,
            STYX_PPC::R6 => UC_PPC::R6,
            STYX_PPC::R7 => UC_PPC::R7,
            STYX_PPC::R8 => UC_PPC::R8,
            STYX_PPC::R9 => UC_PPC::R9,
            STYX_PPC::R10 => UC_PPC::R10,
            STYX_PPC::R11 => UC_PPC::R11,
            STYX_PPC::R12 => UC_PPC::R12,
            STYX_PPC::R13 => UC_PPC::R13,
            STYX_PPC::R14 => UC_PPC::R14,
            STYX_PPC::R15 => UC_PPC::R15,
            STYX_PPC::R16 => UC_PPC::R16,
            STYX_PPC::R17 => UC_PPC::R17,
            STYX_PPC::R18 => UC_PPC::R18,
            STYX_PPC::R19 => UC_PPC::R19,
            STYX_PPC::R20 => UC_PPC::R20,
            STYX_PPC::R21 => UC_PPC::R21,
            STYX_PPC::R22 => UC_PPC::R22,
            STYX_PPC::R23 => UC_PPC::R23,
            STYX_PPC::R24 => UC_PPC::R24,
            STYX_PPC::R25 => UC_PPC::R25,
            STYX_PPC::R26 => UC_PPC::R26,
            STYX_PPC::R27 => UC_PPC::R27,
            STYX_PPC::R28 => UC_PPC::R28,
            STYX_PPC::R29 => UC_PPC::R29,
            STYX_PPC::R30 => UC_PPC::R30,
            STYX_PPC::R31 => UC_PPC::R31,
            STYX_PPC::Fpscr => UC_PPC::FPSCR,
            STYX_PPC::Lr => UC_PPC::LR,
            STYX_PPC::Msr => UC_PPC::MSR,
            STYX_PPC::Xer => UC_PPC::XER,
            _ => UC_PPC::INVALID,
        }
    }
}

impl From<crate::arch::ppc32::SpecialPpc32Register> for unicorn_engine::RegisterPPC {
    fn from(_value: crate::arch::ppc32::SpecialPpc32Register) -> Self {
        // use crate::arch::ppc32::SpecialPpc32Register as STYX_PPC;
        // use unicorn_engine::RegisterPPC as UC_PPC;

        // match value {
        // };
        unimplemented!()
    }
}

impl From<crate::arch::arm::SpecialArmRegister> for unicorn_engine::RegisterARM {
    fn from(value: crate::arch::arm::SpecialArmRegister) -> Self {
        use crate::arch::arm::SpecialArmRegister as STYX_ARM;
        use unicorn_engine::RegisterARM as UC_ARM;

        match value {
            STYX_ARM::CoProcessor(_) => UC_ARM::CP_REG,
        }
    }
}

impl From<crate::arch::arm::ArmRegister> for unicorn_engine::RegisterARM {
    fn from(value: crate::arch::arm::ArmRegister) -> Self {
        use crate::arch::arm::ArmRegister as STYX_ARM;
        use unicorn_engine::RegisterARM as UC_ARM;

        match value {
            STYX_ARM::Apsr => UC_ARM::APSR,
            STYX_ARM::Basepri => UC_ARM::BASEPRI,
            STYX_ARM::Control => UC_ARM::CONTROL,
            STYX_ARM::Cpsr => UC_ARM::CPSR,
            STYX_ARM::D0 => UC_ARM::D0,
            STYX_ARM::D1 => UC_ARM::D1,
            STYX_ARM::D2 => UC_ARM::D2,
            STYX_ARM::D3 => UC_ARM::D3,
            STYX_ARM::D4 => UC_ARM::D4,
            STYX_ARM::D5 => UC_ARM::D5,
            STYX_ARM::D6 => UC_ARM::D6,
            STYX_ARM::D7 => UC_ARM::D7,
            STYX_ARM::D8 => UC_ARM::D8,
            STYX_ARM::D9 => UC_ARM::D9,
            STYX_ARM::D10 => UC_ARM::D10,
            STYX_ARM::D11 => UC_ARM::D11,
            STYX_ARM::D12 => UC_ARM::D12,
            STYX_ARM::D13 => UC_ARM::D13,
            STYX_ARM::D14 => UC_ARM::D14,
            STYX_ARM::D15 => UC_ARM::D15,
            STYX_ARM::D16 => UC_ARM::D16,
            STYX_ARM::D17 => UC_ARM::D17,
            STYX_ARM::D18 => UC_ARM::D18,
            STYX_ARM::D19 => UC_ARM::D19,
            STYX_ARM::D20 => UC_ARM::D20,
            STYX_ARM::D21 => UC_ARM::D21,
            STYX_ARM::D22 => UC_ARM::D22,
            STYX_ARM::D23 => UC_ARM::D23,
            STYX_ARM::D24 => UC_ARM::D24,
            STYX_ARM::D25 => UC_ARM::D25,
            STYX_ARM::D26 => UC_ARM::D26,
            STYX_ARM::D27 => UC_ARM::D27,
            STYX_ARM::D28 => UC_ARM::D28,
            STYX_ARM::D29 => UC_ARM::D29,
            STYX_ARM::D30 => UC_ARM::D30,
            STYX_ARM::D31 => UC_ARM::D31,
            STYX_ARM::Eapsr => UC_ARM::EAPSR,
            STYX_ARM::Epsr => UC_ARM::EPSR,
            STYX_ARM::Faultmask => UC_ARM::FAULTMASK,
            STYX_ARM::Fp => UC_ARM::FP,
            STYX_ARM::Fpexc => UC_ARM::FPEXC,
            STYX_ARM::Fpscr => UC_ARM::FPSCR,
            STYX_ARM::Fpsid => UC_ARM::FPSID,
            STYX_ARM::Iapsr => UC_ARM::IAPSR,
            STYX_ARM::Iepsr => UC_ARM::IEPSR,
            STYX_ARM::Ip => UC_ARM::IP,
            STYX_ARM::Ipsr => UC_ARM::IPSR,
            STYX_ARM::Itstate => UC_ARM::ITSTATE,
            STYX_ARM::Lr => UC_ARM::LR,
            STYX_ARM::Msp => UC_ARM::MSP,
            STYX_ARM::Mvfr0 => UC_ARM::MVFR0,
            STYX_ARM::Mvfr1 => UC_ARM::MVFR1,
            STYX_ARM::Pc => UC_ARM::PC,
            STYX_ARM::Primask => UC_ARM::PRIMASK,
            STYX_ARM::Psp => UC_ARM::PSP,
            STYX_ARM::Q0 => UC_ARM::Q0,
            STYX_ARM::Q1 => UC_ARM::Q1,
            STYX_ARM::Q2 => UC_ARM::Q2,
            STYX_ARM::Q3 => UC_ARM::Q3,
            STYX_ARM::Q4 => UC_ARM::Q4,
            STYX_ARM::Q5 => UC_ARM::Q5,
            STYX_ARM::Q6 => UC_ARM::Q6,
            STYX_ARM::Q7 => UC_ARM::Q7,
            STYX_ARM::Q8 => UC_ARM::Q8,
            STYX_ARM::Q9 => UC_ARM::Q9,
            STYX_ARM::Q10 => UC_ARM::Q10,
            STYX_ARM::Q11 => UC_ARM::Q11,
            STYX_ARM::Q12 => UC_ARM::Q12,
            STYX_ARM::Q13 => UC_ARM::Q13,
            STYX_ARM::Q14 => UC_ARM::Q14,
            STYX_ARM::Q15 => UC_ARM::Q15,
            STYX_ARM::R0 => UC_ARM::R0,
            STYX_ARM::R1 => UC_ARM::R1,
            STYX_ARM::R2 => UC_ARM::R2,
            STYX_ARM::R3 => UC_ARM::R3,
            STYX_ARM::R4 => UC_ARM::R4,
            STYX_ARM::R5 => UC_ARM::R5,
            STYX_ARM::R6 => UC_ARM::R6,
            STYX_ARM::R7 => UC_ARM::R7,
            STYX_ARM::R8 => UC_ARM::R8,
            STYX_ARM::R9 => UC_ARM::R9,
            STYX_ARM::R10 => UC_ARM::R10,
            STYX_ARM::R11 => UC_ARM::R11,
            STYX_ARM::R12 => UC_ARM::R12,
            STYX_ARM::R13 => UC_ARM::R13,
            STYX_ARM::R14 => UC_ARM::R14,
            STYX_ARM::R15 => UC_ARM::R15,
            STYX_ARM::S0 => UC_ARM::S0,
            STYX_ARM::S1 => UC_ARM::S1,
            STYX_ARM::S2 => UC_ARM::S2,
            STYX_ARM::S3 => UC_ARM::S3,
            STYX_ARM::S4 => UC_ARM::S4,
            STYX_ARM::S5 => UC_ARM::S5,
            STYX_ARM::S6 => UC_ARM::S6,
            STYX_ARM::S7 => UC_ARM::S7,
            STYX_ARM::S8 => UC_ARM::S8,
            STYX_ARM::S9 => UC_ARM::S9,
            STYX_ARM::S10 => UC_ARM::S10,
            STYX_ARM::S11 => UC_ARM::S11,
            STYX_ARM::S12 => UC_ARM::S12,
            STYX_ARM::S13 => UC_ARM::S13,
            STYX_ARM::S14 => UC_ARM::S14,
            STYX_ARM::S15 => UC_ARM::S15,
            STYX_ARM::S16 => UC_ARM::S16,
            STYX_ARM::S17 => UC_ARM::S17,
            STYX_ARM::S18 => UC_ARM::S18,
            STYX_ARM::S19 => UC_ARM::S19,
            STYX_ARM::S20 => UC_ARM::S20,
            STYX_ARM::S21 => UC_ARM::S21,
            STYX_ARM::S22 => UC_ARM::S22,
            STYX_ARM::S23 => UC_ARM::S23,
            STYX_ARM::S24 => UC_ARM::S24,
            STYX_ARM::S25 => UC_ARM::S25,
            STYX_ARM::S26 => UC_ARM::S26,
            STYX_ARM::S27 => UC_ARM::S27,
            STYX_ARM::S28 => UC_ARM::S28,
            STYX_ARM::S29 => UC_ARM::S29,
            STYX_ARM::S30 => UC_ARM::S30,
            STYX_ARM::S31 => UC_ARM::S31,
            STYX_ARM::Sb => UC_ARM::SB,
            STYX_ARM::Sl => UC_ARM::SL,
            STYX_ARM::Sp => UC_ARM::SP,
            STYX_ARM::Spsr => UC_ARM::SPSR,
            STYX_ARM::Xpsr => UC_ARM::XPSR,
        }
    }
}
