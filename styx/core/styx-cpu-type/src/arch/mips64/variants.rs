// SPDX-License-Identifier: BSD-2-Clause
//! Maps the various mips64 architecture variants
use super::gdb_targets::{Mips64CaviumTargetDescription, Mips64CpuTargetDescription};
use crate::arch::Mips64Register;
use crate::arch::{Arch, ArchitectureDef, ArchitectureVariant, CpuRegisterBank};
use derive_more::Display;

const GENERAL_REGISTERS: &[Mips64Register] = &[
    Mips64Register::R0,
    Mips64Register::R1,
    Mips64Register::R2,
    Mips64Register::R3,
    Mips64Register::R4,
    Mips64Register::R5,
    Mips64Register::R6,
    Mips64Register::R7,
    Mips64Register::R8,
    Mips64Register::R9,
    Mips64Register::R10,
    Mips64Register::R11,
    Mips64Register::R12,
    Mips64Register::R13,
    Mips64Register::R14,
    Mips64Register::R15,
    Mips64Register::R16,
    Mips64Register::R17,
    Mips64Register::R18,
    Mips64Register::R19,
    Mips64Register::R20,
    Mips64Register::R21,
    Mips64Register::R22,
    Mips64Register::R23,
    Mips64Register::R24,
    Mips64Register::R25,
    Mips64Register::R26,
    Mips64Register::R27,
    Mips64Register::R28,
    Mips64Register::R29,
    Mips64Register::R30,
    Mips64Register::R31,
    Mips64Register::Hi,
    Mips64Register::Lo,
    Mips64Register::Pc,
];

const CAVIUM_REGISTERS: &[Mips64Register] = &[
    Mips64Register::Pc,
    Mips64Register::R0,
    Mips64Register::R1,
    Mips64Register::R2,
    Mips64Register::R3,
    Mips64Register::R4,
    Mips64Register::R5,
    Mips64Register::R6,
    Mips64Register::R7,
    Mips64Register::R8,
    Mips64Register::R9,
    Mips64Register::R10,
    Mips64Register::R11,
    Mips64Register::R12,
    Mips64Register::R13,
    Mips64Register::R14,
    Mips64Register::R15,
    Mips64Register::R16,
    Mips64Register::R17,
    Mips64Register::R18,
    Mips64Register::R19,
    Mips64Register::R20,
    Mips64Register::R21,
    Mips64Register::R22,
    Mips64Register::R23,
    Mips64Register::R24,
    Mips64Register::R25,
    Mips64Register::R26,
    Mips64Register::R27,
    Mips64Register::R28,
    Mips64Register::R29,
    Mips64Register::R30,
    Mips64Register::R31,
    Mips64Register::Hi,
    Mips64Register::Lo,
    Mips64Register::Pc,
    Mips64Register::Mpl0,
    Mips64Register::Mpl1,
    Mips64Register::Mpl2,
    Mips64Register::P0,
    Mips64Register::P1,
    Mips64Register::P2,
    Mips64Register::CrcIV,
    Mips64Register::CrcPoly,
    Mips64Register::CrcLen,
    Mips64Register::GfmMul,
    Mips64Register::GfmResInp,
    Mips64Register::GfmPoly,
    Mips64Register::HashDat,
    Mips64Register::HashIV,
    Mips64Register::ThreeDESKey,
    Mips64Register::ThreeDESIV,
    Mips64Register::ThreeDESResult,
    Mips64Register::AesKey,
    Mips64Register::AesKeyLen,
    Mips64Register::AesIV,
    Mips64Register::AesResInp,
    Mips64Register::CvmsegLm,
];

#[derive(Default)]
pub struct Mips64GeneralRegisters {}

impl CpuRegisterBank for Mips64GeneralRegisters {
    fn pc(&self) -> crate::arch::CpuRegister {
        Mips64Register::Pc.register()
    }

    fn sp(&self) -> crate::arch::CpuRegister {
        Mips64Register::Sp.register()
    }

    fn registers(&self) -> Vec<crate::arch::CpuRegister> {
        GENERAL_REGISTERS.iter().map(|reg| reg.register()).collect()
    }
}

#[derive(Default)]
pub struct Mips64CaviumRegisters {}

impl CpuRegisterBank for Mips64CaviumRegisters {
    fn pc(&self) -> crate::arch::CpuRegister {
        Mips64Register::Pc.register()
    }

    fn sp(&self) -> crate::arch::CpuRegister {
        Mips64Register::Sp.register()
    }

    fn registers(&self) -> Vec<crate::arch::CpuRegister> {
        CAVIUM_REGISTERS.iter().map(|reg| reg.register()).collect()
    }
}

macro_rules! mips64_arch_impl {
    ($variant_name:ident, $registers_struct:ty, $target_description:ty) => {
        #[derive(Debug, Display, PartialEq, Eq, Clone, Copy)]
        pub struct $variant_name {}

        impl ArchitectureVariant for $variant_name {}

        impl ArchitectureDef for $variant_name {
            fn usize(&self) -> usize {
                64
            }

            fn pc_size(&self) -> usize {
                64
            }

            fn core_register_size(&self) -> usize {
                64
            }

            fn data_word_size(&self) -> usize {
                64
            }

            fn insn_word_size(&self) -> usize {
                32
            }

            fn addr_size(&self) -> usize {
                64
            }

            fn architecture(&self) -> Arch {
                Arch::Mips64
            }

            fn architecture_variant(&self) -> String {
                format!("{}", self)
            }

            fn registers(&self) -> Box<dyn CpuRegisterBank> {
                Box::<$registers_struct>::default()
            }

            fn gdb_target_description(&self) -> crate::arch::GdbTargetDescriptionImpl {
                <$target_description>::default().into()
            }
        }
    };
}

mips64_arch_impl!(
    Mips64R2Generic,
    Mips64GeneralRegisters,
    Mips64CpuTargetDescription
);

mips64_arch_impl!(
    Mips64R4000,
    Mips64GeneralRegisters,
    Mips64CpuTargetDescription
);

mips64_arch_impl!(
    Mips64Vrf5432,
    Mips64GeneralRegisters,
    Mips64CpuTargetDescription
);

mips64_arch_impl!(
    Mips645kc,
    Mips64GeneralRegisters,
    Mips64CpuTargetDescription
);

mips64_arch_impl!(
    Mips645kf,
    Mips64GeneralRegisters,
    Mips64CpuTargetDescription
);

mips64_arch_impl!(
    Mips6420kc,
    Mips64GeneralRegisters,
    Mips64CpuTargetDescription
);

mips64_arch_impl!(
    Mips645kec,
    Mips64GeneralRegisters,
    Mips64CpuTargetDescription
);

mips64_arch_impl!(
    Mips645kef,
    Mips64GeneralRegisters,
    Mips64CpuTargetDescription
);

mips64_arch_impl!(
    Mips64I6400,
    Mips64GeneralRegisters,
    Mips64CpuTargetDescription
);

mips64_arch_impl!(
    Mips64I6500,
    Mips64GeneralRegisters,
    Mips64CpuTargetDescription
);

mips64_arch_impl!(
    Mips64P6600,
    Mips64GeneralRegisters,
    Mips64CpuTargetDescription
);

mips64_arch_impl!(
    Mips64Loongson2e,
    Mips64GeneralRegisters,
    Mips64CpuTargetDescription
);

mips64_arch_impl!(
    Mips64Loongson2f,
    Mips64GeneralRegisters,
    Mips64CpuTargetDescription
);

mips64_arch_impl!(
    Mips64DspR2,
    Mips64GeneralRegisters,
    Mips64CpuTargetDescription
);

mips64_arch_impl!(
    Mips64Cn5520,
    Mips64CaviumRegisters,
    Mips64CaviumTargetDescription
);

mips64_arch_impl!(
    Mips64Cn5530,
    Mips64CaviumRegisters,
    Mips64CaviumTargetDescription
);

mips64_arch_impl!(
    Mips64Cn5534,
    Mips64CaviumRegisters,
    Mips64CaviumTargetDescription
);

mips64_arch_impl!(
    Mips64Cn5640,
    Mips64CaviumRegisters,
    Mips64CaviumTargetDescription
);

mips64_arch_impl!(
    Mips64Cn5645,
    Mips64CaviumRegisters,
    Mips64CaviumTargetDescription
);

mips64_arch_impl!(
    Mips64Cn5650,
    Mips64CaviumRegisters,
    Mips64CaviumTargetDescription
);

mips64_arch_impl!(
    Mips64Cn5740,
    Mips64CaviumRegisters,
    Mips64CaviumTargetDescription
);

mips64_arch_impl!(
    Mips64Cn5745,
    Mips64CaviumRegisters,
    Mips64CaviumTargetDescription
);

mips64_arch_impl!(
    Mips64Cn5750,
    Mips64CaviumRegisters,
    Mips64CaviumTargetDescription
);

mips64_arch_impl!(
    Mips64Cn5830,
    Mips64CaviumRegisters,
    Mips64CaviumTargetDescription
);

mips64_arch_impl!(
    Mips64Cn5840,
    Mips64CaviumRegisters,
    Mips64CaviumTargetDescription
);

mips64_arch_impl!(
    Mips64Cn5850,
    Mips64CaviumRegisters,
    Mips64CaviumTargetDescription
);

mips64_arch_impl!(
    Mips64Cn5860,
    Mips64CaviumRegisters,
    Mips64CaviumTargetDescription
);

mips64_arch_impl!(
    Mips64Cn6320,
    Mips64CaviumRegisters,
    Mips64CaviumTargetDescription
);

mips64_arch_impl!(
    Mips64Cn6330,
    Mips64CaviumRegisters,
    Mips64CaviumTargetDescription
);

mips64_arch_impl!(
    Mips64Cn6350,
    Mips64CaviumRegisters,
    Mips64CaviumTargetDescription
);

mips64_arch_impl!(
    Mips64Cn6860,
    Mips64CaviumRegisters,
    Mips64CaviumTargetDescription
);

mips64_arch_impl!(
    Mips64Cn6870,
    Mips64CaviumRegisters,
    Mips64CaviumTargetDescription
);

mips64_arch_impl!(
    Mips64Cn6880,
    Mips64CaviumRegisters,
    Mips64CaviumTargetDescription
);
