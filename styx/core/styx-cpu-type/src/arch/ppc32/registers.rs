// SPDX-License-Identifier: BSD-2-Clause
//! Generic top level container for PPC32 registers
use std::{collections::HashMap, num::NonZeroUsize};
use strum::IntoEnumIterator;

use derive_more::Display;
use num_derive::{FromPrimitive, ToPrimitive};

use crate::arch::{CpuRegister, RegisterValue, RegisterValueCompatible};
use crate::macros::*;

create_basic_register_enums!(
    Ppc32,
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
    (R13, 32),
    (R14, 32),
    (R15, 32),
    (R16, 32),
    (R17, 32),
    (R18, 32),
    (R19, 32),
    (R20, 32),
    (R21, 32),
    (R22, 32),
    (R23, 32),
    (R24, 32),
    (R25, 32),
    (R26, 32),
    (R27, 32),
    (R28, 32),
    (R29, 32),
    (R30, 32),
    (R31, 32),
    (Pc, 32),
    (Msr, 32),
    (Cr0, 32),
    (Cr1, 32),
    (Cr2, 32),
    (Cr3, 32),
    (Cr4, 32),
    (Cr5, 32),
    (Cr6, 32),
    (Cr7, 32),
    (Cr, 32),
    (Lr, 32),
    (Ctr, 32),
    (Xer, 32),
    (TblR, 32),
    (TbuR, 32),
    (TblW, 32),
    (TbuW, 32),
    (Tcr, 32),
    (Tsr, 32),
    (Pit, 32),
    (Dbsr, 32),
    (Dbcr0, 32),
    (Dbcr1, 32),
    (Dac1, 32),
    (Dac2, 32),
    (Dvc1, 32),
    (Dvc2, 32),
    (Iac1, 32),
    (Iac2, 32),
    (Iac3, 32),
    (Iac4, 32),
    (Icdbr, 32),
    (Dccr, 32),
    (Dcwr, 32),
    (Iccr, 32),
    (Sgr, 32),
    (Sler, 32),
    (Su0r, 32),
    (Ccr0, 32),
    (Sprg0, 32),
    (Sprg1, 32),
    (Sprg2, 32),
    (Sprg3, 32),
    (Sprg4, 32),
    (Sprg5, 32),
    (Sprg6, 32),
    (Sprg7, 32),
    (Evpr, 32),
    (Esr, 32),
    (Dear, 32),
    (SRR0, 32),
    (SRR1, 32),
    (SRR2, 32),
    (SRR3, 32),
    (Pid, 32),
    (Zpr, 32),
    (Pvr, 32),
    (Fpr0, 32),
    (Fpr1, 32),
    (Fpr2, 32),
    (Fpr3, 32),
    (Fpr4, 32),
    (Fpr5, 32),
    (Fpr6, 32),
    (Fpr7, 32),
    (Fpr8, 32),
    (Fpr9, 32),
    (Fpr10, 32),
    (Fpr11, 32),
    (Fpr12, 32),
    (Fpr13, 32),
    (Fpr14, 32),
    (Fpr15, 32),
    (Fpr16, 32),
    (Fpr17, 32),
    (Fpr18, 32),
    (Fpr19, 32),
    (Fpr20, 32),
    (Fpr21, 32),
    (Fpr22, 32),
    (Fpr23, 32),
    (Fpr24, 32),
    (Fpr25, 32),
    (Fpr26, 32),
    (Fpr27, 32),
    (Fpr28, 32),
    (Fpr29, 32),
    (Fpr30, 32),
    (Fpr31, 32),
    (Fpscr, 32),
);

lazy_static::lazy_static! {
    /// List of all [Ppc32Register]s convert to string and uppercased.
    /// This is done in a [lazy_static::lazy_static] to avoid recomputing every time [Ppc32Register::register()] is called.
    static ref REGISTER_NAMES: HashMap<Ppc32Register, String> =  {
        Ppc32Register::iter()
            .map(|reg| (reg, reg.to_string().to_uppercase()))
            .collect()
    };
}

create_special_register_enums!(Ppc32, SprRegister);

/// PowerPC SpecialRegister
///
/// 10-bit specifier
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Default)]
pub struct SprRegister(u16);

impl SprRegister {
    pub fn new(index: u16) -> Option<Self> {
        (index <= 0x3ff).then_some(Self(index))
    }

    pub fn index(self) -> u16 {
        self.0
    }
}

impl From<SprRegister> for RegisterValue {
    fn from(spr: SprRegister) -> Self {
        RegisterValue::Ppc32Special(SpecialPpc32RegisterValues::SprRegister(spr.into()))
    }
}

#[derive(
    Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Display, FromPrimitive, ToPrimitive,
)]
pub struct SprRegisterValue(u16);

impl SprRegisterValue {
    pub const fn const_default() -> Self {
        Self(0)
    }
}

impl From<SprRegister> for SprRegisterValue {
    fn from(spr: SprRegister) -> Self {
        Self(spr.0)
    }
}
impl RegisterValueCompatible for SprRegister {
    type ReturnValue = u16;

    fn as_inner_value(reg_val: RegisterValue) -> Result<Self::ReturnValue, RegisterValue> {
        match reg_val.into_ppc32_special() {
            Err(reg_val) => Err(reg_val),
            Ok(ppc_special) => match ppc_special {
                SpecialPpc32RegisterValues::SprRegister(spr) => Ok(spr.0),

                // all other options will always be err
                #[allow(unreachable_patterns)]
                _ => Err(reg_val),
            },
        }
    }
}

impl std::fmt::Display for SprRegister {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "spr(0x{:03x})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_regs_from_str() {
        assert_eq!(Ppc32Register::R0, Ppc32Register::from_str("r0").unwrap());
        assert_eq!(Ppc32Register::R1, Ppc32Register::from_str("r1").unwrap());
        assert_eq!(Ppc32Register::R2, Ppc32Register::from_str("r2").unwrap());
        assert_eq!(Ppc32Register::Pc, Ppc32Register::from_str("Pc").unwrap());
        assert_eq!(Ppc32Register::Pc, Ppc32Register::from_str("pc").unwrap());
        assert_eq!(Ppc32Register::Msr, Ppc32Register::from_str("Msr").unwrap());
        assert_eq!(Ppc32Register::Msr, Ppc32Register::from_str("msr").unwrap());
        assert_eq!(Ppc32Register::Lr, Ppc32Register::from_str("Lr").unwrap());
        assert_eq!(Ppc32Register::Lr, Ppc32Register::from_str("lr").unwrap());
        assert_eq!(Ppc32Register::Ctr, Ppc32Register::from_str("Ctr").unwrap());
        assert_eq!(Ppc32Register::Ctr, Ppc32Register::from_str("ctr").unwrap());
        assert_eq!(
            Ppc32Register::SRR0,
            Ppc32Register::from_str("SRR0").unwrap()
        );
        assert_eq!(
            Ppc32Register::TblR,
            Ppc32Register::from_str("TBLr").unwrap()
        );
    }

    #[test]
    fn test_spr_valid() {
        // 1024 SPR registers (0-1023)
        assert!(SprRegister::new(0).is_some());
        assert!(SprRegister::new(1).is_some());
        assert!(SprRegister::new(0x3ff).is_some());
        assert!(SprRegister::new(0x400).is_none());
        assert!(SprRegister::new(0x1000).is_none());
    }
}
