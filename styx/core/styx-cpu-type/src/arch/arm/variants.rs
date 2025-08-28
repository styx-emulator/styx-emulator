// SPDX-License-Identifier: BSD-2-Clause
use super::gdb_targets::{
    ArmCoreDescription, ArmMProfileDescription, Armv7emDescription, ARM_CORE_REGISTER_MAP,
    ARM_M_PROFILE_REGISTER_MAP,
};
use crate::arch::arm::ArmRegister;
use crate::arch::{
    Arch, ArchitectureDef, ArchitectureVariant, CpuRegisterBank, GdbTargetDescriptionImpl,
};
use derive_more::Display;

/// A "sane-default" set of default ARM registers.
#[derive(Default)]
pub struct ArmCoreRegisters {}

impl CpuRegisterBank for ArmCoreRegisters {
    fn pc(&self) -> crate::arch::CpuRegister {
        ArmRegister::Pc.register()
    }

    fn sp(&self) -> crate::arch::CpuRegister {
        ArmRegister::Sp.register()
    }

    fn registers(&self) -> Vec<crate::arch::CpuRegister> {
        ARM_CORE_REGISTER_MAP.values().cloned().collect()
    }
}

/// A "sane-default" set of default ARM registers.
#[derive(Default)]
pub struct ArmMProfileRegisters {}

impl CpuRegisterBank for ArmMProfileRegisters {
    fn pc(&self) -> crate::arch::CpuRegister {
        ArmRegister::Pc.register()
    }

    fn sp(&self) -> crate::arch::CpuRegister {
        ArmRegister::Sp.register()
    }

    fn registers(&self) -> Vec<crate::arch::CpuRegister> {
        ARM_M_PROFILE_REGISTER_MAP.values().cloned().collect()
    }
}

// TODO: this macro needs to  add support for setting the Usize etc.
// TODO: this is blocked by the trait exposing getter methods for the
/// This macro alleviates the repetitive nature of register bank definitions
/// per architecture variant.
///
/// The first argument is the name to create and implement
/// The second (optional) argument is to struct to use for the
/// [`CpuRegister`](crate::arch::CpuRegister) impl
macro_rules! arm_cortex_arch_impl {
    ($variant_name:ident) => {
        #[derive(Debug, Display, PartialEq, Eq, Clone, Copy)]
        pub struct $variant_name {}

        impl ArchitectureVariant for $variant_name {}

        impl ArchitectureDef for $variant_name {
            fn usize(&self) -> usize {
                32
            }

            fn pc_size(&self) -> usize {
                32
            }

            fn core_register_size(&self) -> usize {
                32
            }

            fn data_word_size(&self) -> usize {
                32
            }

            fn insn_word_size(&self) -> usize {
                32
            }

            fn addr_size(&self) -> usize {
                32
            }

            fn architecture(&self) -> Arch {
                Arch::Arm
            }

            fn registers(&self) -> Box<dyn CpuRegisterBank> {
                Box::new(ArmCoreRegisters {})
            }

            fn gdb_target_description(&self) -> GdbTargetDescriptionImpl {
                ArmCoreDescription::default().into()
            }
        }
    };
    ($variant_name:ident, $registers_struct:ty, $target_description:ty) => {
        #[derive(Debug, Display, PartialEq, Eq, Clone, Copy)]
        pub struct $variant_name {}

        impl ArchitectureVariant for $variant_name {}

        impl ArchitectureDef for $variant_name {
            fn usize(&self) -> usize {
                32
            }

            fn pc_size(&self) -> usize {
                32
            }

            fn core_register_size(&self) -> usize {
                32
            }

            fn data_word_size(&self) -> usize {
                32
            }

            fn insn_word_size(&self) -> usize {
                32
            }

            fn addr_size(&self) -> usize {
                32
            }

            fn architecture(&self) -> Arch {
                Arch::Arm
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

// XXX: this macro invocation is entirely *incorrect* for the non-cortex
// targets, but the general purpose registers are shared so i mean it
// still provides "yes we can perform basic introspection" on these targets
arm_cortex_arch_impl!(Arm926);
arm_cortex_arch_impl!(Arm946);
arm_cortex_arch_impl!(Arm1026);
arm_cortex_arch_impl!(Arm1136);
arm_cortex_arch_impl!(Arm1136r2);
arm_cortex_arch_impl!(Arm1176);
arm_cortex_arch_impl!(Arm11Mpcore);
arm_cortex_arch_impl!(ArmCortexM0, ArmMProfileRegisters, ArmMProfileDescription);
arm_cortex_arch_impl!(ArmCortexM3, ArmMProfileRegisters, ArmMProfileDescription);
arm_cortex_arch_impl!(ArmCortexM4, ArmMProfileRegisters, Armv7emDescription);
arm_cortex_arch_impl!(ArmCortexM7, ArmMProfileRegisters, Armv7emDescription);
arm_cortex_arch_impl!(ArmCortexM33, ArmMProfileRegisters, ArmMProfileDescription);
arm_cortex_arch_impl!(ArmCortexR5);
arm_cortex_arch_impl!(ArmCortexR5F);
arm_cortex_arch_impl!(ArmCortexA7);
arm_cortex_arch_impl!(ArmCortexA8);
arm_cortex_arch_impl!(ArmCortexA9);
arm_cortex_arch_impl!(ArmCortexA15);
arm_cortex_arch_impl!(ArmTi925T);
arm_cortex_arch_impl!(ArmSa1100);
arm_cortex_arch_impl!(ArmSa1110);
arm_cortex_arch_impl!(ArmPxa250);
arm_cortex_arch_impl!(ArmPxa255);
arm_cortex_arch_impl!(ArmPxa260);
arm_cortex_arch_impl!(ArmPxa261);
arm_cortex_arch_impl!(ArmPxa262);
arm_cortex_arch_impl!(ArmPxa270);
arm_cortex_arch_impl!(ArmPxa270a0);
arm_cortex_arch_impl!(ArmPxa270a1);
arm_cortex_arch_impl!(ArmPxa270b0);
arm_cortex_arch_impl!(ArmPxa270b1);
arm_cortex_arch_impl!(ArmPxa270c0);
arm_cortex_arch_impl!(ArmPxa270c5);
