// SPDX-License-Identifier: BSD-2-Clause
use super::{BlackfinRegister, SpecialBlackfinRegister};
use crate::{
    arch::{ArchitectureDef, ArchitectureVariant, CpuRegisterBank, GdbTargetDescriptionImpl},
    Arch,
};
use derive_more::Display;
use strum::IntoEnumIterator;

/// [CpuRegisterBank] that includes all Blackfin registers.
struct BlackfinStandardRegisters;

impl CpuRegisterBank for BlackfinStandardRegisters {
    fn registers(&self) -> Vec<crate::arch::CpuRegister> {
        BlackfinRegister::iter()
            .map(|r| r.register())
            .chain(SpecialBlackfinRegister::iter().map(|r| r.register()))
            .collect()
    }

    fn pc(&self) -> crate::arch::CpuRegister {
        BlackfinRegister::Pc.register()
    }

    fn sp(&self) -> crate::arch::CpuRegister {
        BlackfinRegister::Sp.register()
    }
}

macro_rules! blackfin_arch_impl {
    ($variant_name:ident) => {
        #[derive(Debug, Display, PartialEq, Eq, Clone)]
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
                16
            }

            fn insn_word_size(&self) -> usize {
                16
            }

            fn addr_size(&self) -> usize {
                32
            }

            fn architecture(&self) -> Arch {
                Arch::Blackfin
            }

            fn registers(&self) -> Box<dyn CpuRegisterBank> {
                Box::new(BlackfinStandardRegisters {})
            }

            fn gdb_target_description(&self) -> GdbTargetDescriptionImpl {
                super::gdb_targets::BlackfinDescription::default().into()
            }
        }
    };
}

// this is only "Blackfin", not "Blackfin+", which includes the
// BF7xx series. These are all the chips that are supported by
// the blackfin toolchain last checked, binutils-gdb has pretty
// good support for these chips.
//
// NOTE: this is also not including the BF60x series, for no other
// reason that laziness
blackfin_arch_impl!(Bf504);
blackfin_arch_impl!(Bf504f);
blackfin_arch_impl!(Bf506f);
blackfin_arch_impl!(Bf512);
blackfin_arch_impl!(Bf514);
blackfin_arch_impl!(Bf516);
blackfin_arch_impl!(Bf518);
blackfin_arch_impl!(Bf522);
blackfin_arch_impl!(Bf523);
blackfin_arch_impl!(Bf524);
blackfin_arch_impl!(Bf525);
blackfin_arch_impl!(Bf526);
blackfin_arch_impl!(Bf527);
blackfin_arch_impl!(Bf531);
blackfin_arch_impl!(Bf532);
blackfin_arch_impl!(Bf533);
blackfin_arch_impl!(Bf534);
blackfin_arch_impl!(Bf535);
blackfin_arch_impl!(Bf536);
blackfin_arch_impl!(Bf537);
blackfin_arch_impl!(Bf538);
blackfin_arch_impl!(Bf539);
blackfin_arch_impl!(Bf542);
blackfin_arch_impl!(Bf542m);
blackfin_arch_impl!(Bf544);
blackfin_arch_impl!(Bf544b);
blackfin_arch_impl!(Bf547);
blackfin_arch_impl!(Bf548);
blackfin_arch_impl!(Bf548m);
blackfin_arch_impl!(Bf561);
blackfin_arch_impl!(Bf592a);
