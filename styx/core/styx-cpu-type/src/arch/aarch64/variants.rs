// SPDX-License-Identifier: BSD-2-Clause
use crate::arch::{
    Arch, ArchitectureDef, ArchitectureVariant, CpuRegisterBank, GdbTargetDescriptionImpl,
};
use derive_more::Display;

use super::gdb_targets::{Aarch64CoreDescription, AARCH64_CORE_REGISTER_MAP};
use super::Aarch64Register;

/// A "sane-default" set of default ARM registers.
#[derive(Default)]
pub struct Aarch64CoreRegisters {}

impl CpuRegisterBank for Aarch64CoreRegisters {
    fn pc(&self) -> crate::arch::CpuRegister {
        Aarch64Register::PC.register()
    }

    fn sp(&self) -> crate::arch::CpuRegister {
        Aarch64Register::SP.register()
    }

    fn registers(&self) -> Vec<crate::arch::CpuRegister> {
        AARCH64_CORE_REGISTER_MAP.values().cloned().collect()
    }
}

macro_rules! aarch64_arch_impl {
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
                64
            }

            fn addr_size(&self) -> usize {
                64
            }

            fn architecture(&self) -> Arch {
                Arch::Aarch64
            }

            fn architecture_variant(&self) -> String {
                format!("{}", self)
            }

            fn registers(&self) -> Box<dyn CpuRegisterBank> {
                Box::<$registers_struct>::default()
            }

            fn gdb_target_description(&self) -> GdbTargetDescriptionImpl {
                <$target_description>::default().into()
            }
        }
    };
}

aarch64_arch_impl!(Generic, Aarch64CoreRegisters, Aarch64CoreDescription);
