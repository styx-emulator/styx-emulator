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
//! Maps the various Ppc32 architecture variants

use super::gdb_targets::{Mpc8xxTargetDescription, Ppc4xxTargetDescription};
use super::SprRegister;
use crate::arch::ppc32::{Ppc32Register, SpecialPpc32Register};
use crate::arch::{Arch, ArchitectureDef, ArchitectureVariant, CpuRegisterBank};
use derive_more::Display;

/// Pc, Rn, Cr, Lr, Xer, Ctr, and Msr
const GENERAL_REGISTERS: &[Ppc32Register] = &[
    Ppc32Register::Pc,
    Ppc32Register::R0,
    Ppc32Register::R1,
    Ppc32Register::R2,
    Ppc32Register::R3,
    Ppc32Register::R4,
    Ppc32Register::R5,
    Ppc32Register::R6,
    Ppc32Register::R7,
    Ppc32Register::R8,
    Ppc32Register::R9,
    Ppc32Register::R10,
    Ppc32Register::R11,
    Ppc32Register::R12,
    Ppc32Register::R13,
    Ppc32Register::R14,
    Ppc32Register::R15,
    Ppc32Register::R16,
    Ppc32Register::R17,
    Ppc32Register::R18,
    Ppc32Register::R19,
    Ppc32Register::R20,
    Ppc32Register::R21,
    Ppc32Register::R22,
    Ppc32Register::R23,
    Ppc32Register::R24,
    Ppc32Register::R25,
    Ppc32Register::R26,
    Ppc32Register::R27,
    Ppc32Register::R28,
    Ppc32Register::R29,
    Ppc32Register::R30,
    Ppc32Register::R31,
    Ppc32Register::Cr,
    Ppc32Register::Cr0,
    Ppc32Register::Cr1,
    Ppc32Register::Cr2,
    Ppc32Register::Cr3,
    Ppc32Register::Cr4,
    Ppc32Register::Cr5,
    Ppc32Register::Cr6,
    Ppc32Register::Cr7,
    Ppc32Register::Lr,
    Ppc32Register::Xer,
    Ppc32Register::Ctr,
    Ppc32Register::Msr,
];

lazy_static::lazy_static! {
    /// Vec of all SPR registers.
    static ref SPR: Vec<SpecialPpc32Register> = {
        (0..=1023).map(|idx| {
            SpecialPpc32Register::SprRegister(SprRegister::new(idx)
                .expect("spr index not valid"))

        }).collect()
    };
}

/// PPC32 register list not including the floating-point
/// registers. Also contains all special registers.
#[derive(Default)]
pub struct Ppc32GeneralRegisters {}

impl CpuRegisterBank for Ppc32GeneralRegisters {
    fn pc(&self) -> crate::arch::CpuRegister {
        // technically not a real pc but w/e
        Ppc32Register::Pc.register()
    }

    fn sp(&self) -> crate::arch::CpuRegister {
        Ppc32Register::R1.register()
    }

    fn registers(&self) -> Vec<crate::arch::CpuRegister> {
        GENERAL_REGISTERS
            .iter()
            .chain(&[
                Ppc32Register::TblR,
                Ppc32Register::TbuR,
                Ppc32Register::TblW,
                Ppc32Register::TbuW,
                Ppc32Register::Tcr,
                Ppc32Register::Tsr,
                Ppc32Register::Pit,
                Ppc32Register::Dbsr,
                Ppc32Register::Dbcr0,
                Ppc32Register::Dbcr1,
                Ppc32Register::Dac1,
                Ppc32Register::Dac2,
                Ppc32Register::Dvc1,
                Ppc32Register::Dvc2,
                Ppc32Register::Iac1,
                Ppc32Register::Iac2,
                Ppc32Register::Iac3,
                Ppc32Register::Iac4,
                Ppc32Register::Icdbr,
                Ppc32Register::Dccr,
                Ppc32Register::Dcwr,
                Ppc32Register::Iccr,
                Ppc32Register::Sgr,
                Ppc32Register::Sler,
                Ppc32Register::Su0r,
                Ppc32Register::Ccr0,
                Ppc32Register::Sprg0,
                Ppc32Register::Sprg1,
                Ppc32Register::Sprg2,
                Ppc32Register::Sprg3,
                Ppc32Register::Sprg4,
                Ppc32Register::Sprg5,
                Ppc32Register::Sprg6,
                Ppc32Register::Sprg7,
                Ppc32Register::Evpr,
                Ppc32Register::Esr,
                Ppc32Register::Dear,
                Ppc32Register::SRR0,
                Ppc32Register::SRR1,
                Ppc32Register::SRR2,
                Ppc32Register::SRR3,
                Ppc32Register::Pid,
                Ppc32Register::Zpr,
                Ppc32Register::Pvr,
            ])
            .map(|r| r.register())
            .chain(SPR.iter().map(|r| r.register()))
            .collect()
    }
}

/// PPC32 register list that also includes the floating-point
/// registers
#[derive(Default)]
pub struct Ppc32GeneralRegistersWithFloat {}

impl CpuRegisterBank for Ppc32GeneralRegistersWithFloat {
    fn pc(&self) -> crate::arch::CpuRegister {
        // technically not a real pc but w/e
        Ppc32Register::Pc.register()
    }

    fn sp(&self) -> crate::arch::CpuRegister {
        Ppc32Register::R1.register()
    }

    fn registers(&self) -> Vec<crate::arch::CpuRegister> {
        GENERAL_REGISTERS
            .iter()
            .chain(&[
                Ppc32Register::Fpr0,
                Ppc32Register::Fpr1,
                Ppc32Register::Fpr2,
                Ppc32Register::Fpr3,
                Ppc32Register::Fpr4,
                Ppc32Register::Fpr5,
                Ppc32Register::Fpr6,
                Ppc32Register::Fpr7,
                Ppc32Register::Fpr8,
                Ppc32Register::Fpr9,
                Ppc32Register::Fpr10,
                Ppc32Register::Fpr11,
                Ppc32Register::Fpr12,
                Ppc32Register::Fpr13,
                Ppc32Register::Fpr14,
                Ppc32Register::Fpr15,
                Ppc32Register::Fpr16,
                Ppc32Register::Fpr17,
                Ppc32Register::Fpr18,
                Ppc32Register::Fpr19,
                Ppc32Register::Fpr20,
                Ppc32Register::Fpr21,
                Ppc32Register::Fpr22,
                Ppc32Register::Fpr23,
                Ppc32Register::Fpr24,
                Ppc32Register::Fpr25,
                Ppc32Register::Fpr26,
                Ppc32Register::Fpr27,
                Ppc32Register::Fpr28,
                Ppc32Register::Fpr29,
                Ppc32Register::Fpr30,
                Ppc32Register::Fpr31,
                Ppc32Register::Fpscr,
            ])
            .map(|r| r.register())
            .collect()
    }
}

macro_rules! ppc32_arch_impl {
    ($variant_name:ident, $registers_struct:ty, $target_description:ty) => {
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
                32
            }

            fn insn_word_size(&self) -> usize {
                32
            }

            fn addr_size(&self) -> usize {
                32
            }

            fn architecture(&self) -> Arch {
                Arch::Ppc32
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

// PowerPC 4xx
ppc32_arch_impl!(Ppc401, Ppc32GeneralRegisters, Ppc4xxTargetDescription);
ppc32_arch_impl!(Ppc405, Ppc32GeneralRegisters, Ppc4xxTargetDescription);
ppc32_arch_impl!(Ppc440, Ppc32GeneralRegisters, Ppc4xxTargetDescription);
ppc32_arch_impl!(Ppc470, Ppc32GeneralRegisters, Ppc4xxTargetDescription);

// PowerQUICC I
ppc32_arch_impl!(Mpc821, Ppc32GeneralRegisters, Mpc8xxTargetDescription);
ppc32_arch_impl!(Mpc823, Ppc32GeneralRegisters, Mpc8xxTargetDescription);
ppc32_arch_impl!(Mpc823E, Ppc32GeneralRegisters, Mpc8xxTargetDescription);
ppc32_arch_impl!(Mpc850, Ppc32GeneralRegisters, Mpc8xxTargetDescription);
ppc32_arch_impl!(Mpc860, Ppc32GeneralRegisters, Mpc8xxTargetDescription);
ppc32_arch_impl!(Mpc862, Ppc32GeneralRegisters, Mpc8xxTargetDescription);
ppc32_arch_impl!(Mpc866, Ppc32GeneralRegisters, Mpc8xxTargetDescription);
ppc32_arch_impl!(Mpc870, Ppc32GeneralRegisters, Mpc8xxTargetDescription);
ppc32_arch_impl!(Mpc875, Ppc32GeneralRegisters, Mpc8xxTargetDescription);
ppc32_arch_impl!(Mpc880, Ppc32GeneralRegisters, Mpc8xxTargetDescription);
ppc32_arch_impl!(Mpc885, Ppc32GeneralRegisters, Mpc8xxTargetDescription);
ppc32_arch_impl!(Mpc852T, Ppc32GeneralRegisters, Mpc8xxTargetDescription);
ppc32_arch_impl!(Mpc853T, Ppc32GeneralRegisters, Mpc8xxTargetDescription);
ppc32_arch_impl!(Mpc855T, Ppc32GeneralRegisters, Mpc8xxTargetDescription);
ppc32_arch_impl!(Mpc859T, Ppc32GeneralRegisters, Mpc8xxTargetDescription);
ppc32_arch_impl!(Mpc857DSL, Ppc32GeneralRegisters, Mpc8xxTargetDescription);
ppc32_arch_impl!(Mpc859DSL, Ppc32GeneralRegisters, Mpc8xxTargetDescription);

/// Selection of valid family variants usable in the
/// mpx8xx family implementation.
///
/// Convert from a [`Ppc32Variants`](super::Ppc32Variants) into this, note
/// that only the models from the manufacturer actually
/// convert into this enum, so make sure that the model
/// is actually valid.
///
///
/// ```rust
/// # use styx_cpu_type as styx_cpu;
/// use styx_cpu::arch::ppc32::{Ppc32Variants, variants::Mpc8xxVariants};
/// # use styx_cpu::arch::backends::ArchVariant;
///
/// let into: Mpc8xxVariants = Ppc32Variants::Mpc860.try_into().unwrap();
/// assert_eq!(Mpc8xxVariants::Mpc860, into);
/// #
/// # // convert from ArchVariant
/// # let meta: ArchVariant = Ppc32Variants::Mpc860.into();
/// # let meta_into: Mpc8xxVariants = meta.try_into().unwrap();
/// # assert_eq!(Mpc8xxVariants::Mpc860, into);
///
/// // bad conversion
/// assert!(TryInto::<Mpc8xxVariants>::try_into(Ppc32Variants::Mpc821).is_err());
/// # let bad_meta: ArchVariant = Ppc32Variants::Mpc821.into();
/// # assert!(TryInto::<Mpc8xxVariants>::try_into(bad_meta).is_err());
/// ```
#[derive(Debug, Display, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Mpc8xxVariants {
    Mpc850,
    Mpc860,
    Mpc866,
    Mpc875,
    Mpc870,
    Mpc885,
    Mpc880,
    Mpc855T,
    Mpc853T,
    Mpc852T,
    Mpc859T,
    Mpc859DSL,
}

impl TryFrom<super::Ppc32Variants> for Mpc8xxVariants {
    type Error = String;

    fn try_from(value: super::Ppc32Variants) -> Result<Self, Self::Error> {
        match value {
            super::Ppc32Variants::Mpc850 => Ok(Self::Mpc850),
            super::Ppc32Variants::Mpc860 => Ok(Self::Mpc860),
            super::Ppc32Variants::Mpc866 => Ok(Self::Mpc866),
            super::Ppc32Variants::Mpc875 => Ok(Self::Mpc875),
            super::Ppc32Variants::Mpc870 => Ok(Self::Mpc870),
            super::Ppc32Variants::Mpc885 => Ok(Self::Mpc885),
            super::Ppc32Variants::Mpc880 => Ok(Self::Mpc880),
            super::Ppc32Variants::Mpc855T => Ok(Self::Mpc855T),
            super::Ppc32Variants::Mpc853T => Ok(Self::Mpc853T),
            super::Ppc32Variants::Mpc852T => Ok(Self::Mpc852T),
            super::Ppc32Variants::Mpc859T => Ok(Self::Mpc859T),
            super::Ppc32Variants::Mpc859DSL => Ok(Self::Mpc859DSL),
            bad_variant => Err(format!("FamilyIncompatibility: {bad_variant:?}")),
        }
    }
}

impl TryFrom<crate::arch::backends::ArchVariant> for Mpc8xxVariants {
    type Error = String;

    fn try_from(value: crate::arch::backends::ArchVariant) -> Result<Self, Self::Error> {
        match value {
            crate::arch::backends::ArchVariant::Ppc32(ppc_variant) => match ppc_variant {
                super::Ppc32MetaVariants::Mpc850(_) => Ok(Self::Mpc850),
                super::Ppc32MetaVariants::Mpc860(_) => Ok(Self::Mpc860),
                super::Ppc32MetaVariants::Mpc866(_) => Ok(Self::Mpc866),
                super::Ppc32MetaVariants::Mpc875(_) => Ok(Self::Mpc875),
                super::Ppc32MetaVariants::Mpc870(_) => Ok(Self::Mpc870),
                super::Ppc32MetaVariants::Mpc885(_) => Ok(Self::Mpc885),
                super::Ppc32MetaVariants::Mpc880(_) => Ok(Self::Mpc880),
                super::Ppc32MetaVariants::Mpc855T(_) => Ok(Self::Mpc855T),
                super::Ppc32MetaVariants::Mpc853T(_) => Ok(Self::Mpc853T),
                super::Ppc32MetaVariants::Mpc852T(_) => Ok(Self::Mpc852T),
                super::Ppc32MetaVariants::Mpc859T(_) => Ok(Self::Mpc859T),
                super::Ppc32MetaVariants::Mpc859DSL(_) => Ok(Self::Mpc859DSL),
                bad_variant => Err(format!("FamilyIncompatibility: {bad_variant:?}")),
            },
            bad_arch => Err(format!("FamilyIncompatibility: {bad_arch:?}")),
        }
    }
}

/// Selection of valid family variants usable in the
/// mpx8xx family implementation.
///
/// Convert from a [`Ppc32Variants`](super::Ppc32Variants) into this, note
/// that only the models from the manufacturer actually
/// convert into this enum, so make sure that the model
/// is actually valid.
#[derive(Debug, Display, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Ppc4xxVariants {
    Ppc401,
    Ppc405,
    Ppc440,
    Ppc470,
}

impl TryFrom<super::Ppc32Variants> for Ppc4xxVariants {
    type Error = String;

    fn try_from(value: super::Ppc32Variants) -> Result<Self, Self::Error> {
        match value {
            super::Ppc32Variants::Ppc401 => Ok(Self::Ppc401),
            super::Ppc32Variants::Ppc405 => Ok(Self::Ppc405),
            super::Ppc32Variants::Ppc440 => Ok(Self::Ppc440),
            super::Ppc32Variants::Ppc470 => Ok(Self::Ppc470),
            bad_variant => Err(format!("FamilyIncompatibility: {bad_variant:?}")),
        }
    }
}

impl TryFrom<crate::arch::backends::ArchVariant> for Ppc4xxVariants {
    type Error = String;

    fn try_from(value: crate::arch::backends::ArchVariant) -> Result<Self, Self::Error> {
        match value {
            crate::arch::backends::ArchVariant::Ppc32(ppc_variant) => match ppc_variant {
                super::Ppc32MetaVariants::Ppc401(_) => Ok(Self::Ppc401),
                super::Ppc32MetaVariants::Ppc405(_) => Ok(Self::Ppc405),
                super::Ppc32MetaVariants::Ppc440(_) => Ok(Self::Ppc440),
                super::Ppc32MetaVariants::Ppc470(_) => Ok(Self::Ppc470),

                bad_variant => Err(format!("FamilyIncompatibility: {bad_variant:?}")),
            },
            bad_arch => Err(format!("FamilyIncompatibility: {bad_arch:?}")),
        }
    }
}
