// SPDX-License-Identifier: BSD-2-Clause
//! Maps the various mips64 architecture variants
use super::gdb_targets::{Msp430CpuTargetDescription, Msp430XCpuTargetDescription};
use crate::arch::msp430::Msp430XRegister;
use crate::arch::Msp430Register;
use crate::arch::{Arch, ArchitectureDef, ArchitectureVariant, CpuRegisterBank};
use derive_more::Display;

const GENERAL_REGISTERS: &[Msp430Register] = &[
    Msp430Register::Pc,
    Msp430Register::Sp,
    Msp430Register::Sr,
    Msp430Register::R0,
    Msp430Register::R1,
    Msp430Register::R2,
    Msp430Register::R3,
    Msp430Register::R4,
    Msp430Register::R5,
    Msp430Register::R6,
    Msp430Register::R7,
    Msp430Register::R8,
    Msp430Register::R9,
    Msp430Register::R10,
    Msp430Register::R11,
    Msp430Register::R12,
    Msp430Register::R13,
    Msp430Register::R14,
    Msp430Register::R15,
];

#[derive(Default)]
pub struct Msp430GeneralRegisters {}

impl CpuRegisterBank for Msp430GeneralRegisters {
    fn pc(&self) -> crate::arch::CpuRegister {
        Msp430Register::Pc.register()
    }

    fn sp(&self) -> crate::arch::CpuRegister {
        Msp430Register::Sp.register()
    }

    fn registers(&self) -> Vec<crate::arch::CpuRegister> {
        GENERAL_REGISTERS.iter().map(|reg| reg.register()).collect()
    }
}

macro_rules! msp430_arch_impl {
    ($variant_name:ident, $registers_struct:ty, $target_description:ty) => {
        #[derive(Debug, Display, PartialEq, Eq, Clone)]
        pub struct $variant_name {}

        impl ArchitectureVariant for $variant_name {}

        impl ArchitectureDef for $variant_name {
            fn usize(&self) -> usize {
                16
            }

            fn pc_size(&self) -> usize {
                16
            }

            fn core_register_size(&self) -> usize {
                16
            }

            fn data_word_size(&self) -> usize {
                16
            }

            fn insn_word_size(&self) -> usize {
                16
            }

            fn addr_size(&self) -> usize {
                16
            }

            fn architecture(&self) -> Arch {
                Arch::Msp430
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

macro_rules! msp430_arch_impls (
    ($($variant_name:ident),*) => {
        $(msp430_arch_impl!(
            $variant_name,
            Msp430GeneralRegisters,
            Msp430CpuTargetDescription
        );
    )*
    };
);

msp430_arch_impls!(
    MSP430F112,
    MSP430F157,
    MSP430F168,
    MSP430F167,
    MSP430F1610,
    MSP430F1612,
    MSP430F1611,
    MSP430F1111A,
    MSP430F1122,
    MSP430F122,
    MSP430F1222,
    MSP430F148,
    MSP430F1481,
    MSP430F1491,
    MSP430F156,
    MSP430F169,
    MSP430F1101A,
    MSP430F1471,
    MSP430F1232,
    MSP430F147,
    MSP430F133,
    MSP430F1132,
    MSP430F123,
    MSP430F155,
    MSP430F1121A,
    MSP430F149,
    MSP430F135
);

msp430_arch_impl!(
    Msp430x31x,
    Msp430GeneralRegisters,
    Msp430CpuTargetDescription
);

msp430_arch_impl!(
    Msp430x32x,
    Msp430GeneralRegisters,
    Msp430CpuTargetDescription
);

msp430_arch_impl!(
    Msp430x33x,
    Msp430GeneralRegisters,
    Msp430CpuTargetDescription
);

const GENERAL_REGISTERS_X: &[Msp430XRegister] = &[
    Msp430XRegister::Pc,
    Msp430XRegister::Sp,
    Msp430XRegister::Sr,
    Msp430XRegister::R0,
    Msp430XRegister::R1,
    Msp430XRegister::R2,
    Msp430XRegister::R3,
    Msp430XRegister::R4,
    Msp430XRegister::R5,
    Msp430XRegister::R6,
    Msp430XRegister::R7,
    Msp430XRegister::R8,
    Msp430XRegister::R9,
    Msp430XRegister::R10,
    Msp430XRegister::R11,
    Msp430XRegister::R12,
    Msp430XRegister::R13,
    Msp430XRegister::R14,
    Msp430XRegister::R15,
];
#[derive(Default)]
pub struct Msp430XGeneralRegisters {}

impl CpuRegisterBank for Msp430XGeneralRegisters {
    fn pc(&self) -> crate::arch::CpuRegister {
        Msp430XRegister::Pc.register()
    }

    fn sp(&self) -> crate::arch::CpuRegister {
        Msp430XRegister::Sp.register()
    }

    fn registers(&self) -> Vec<crate::arch::CpuRegister> {
        GENERAL_REGISTERS_X
            .iter()
            .map(|reg| reg.register())
            .collect()
    }
}

macro_rules! msp430x_arch_impl {
    ($variant_name:ident, $registers_struct:ty, $target_description:ty) => {
        #[derive(Debug, Display, PartialEq, Eq, Clone)]
        pub struct $variant_name {}

        impl ArchitectureVariant for $variant_name {}

        impl ArchitectureDef for $variant_name {
            fn usize(&self) -> usize {
                20
            }

            fn pc_size(&self) -> usize {
                20
            }

            fn core_register_size(&self) -> usize {
                20
            }

            fn data_word_size(&self) -> usize {
                20
            }

            fn insn_word_size(&self) -> usize {
                20
            }

            fn addr_size(&self) -> usize {
                20
            }

            fn architecture(&self) -> Arch {
                Arch::Msp430X
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

macro_rules! msp430x_arch_impls (
    ($($variant_name:ident),*) => {
        $(msp430x_arch_impl!(
            $variant_name,
            Msp430XGeneralRegisters,
            Msp430XCpuTargetDescription
        );
    )*
    };
);

msp430x_arch_impls!(Msp430F247x);
