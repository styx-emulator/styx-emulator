// SPDX-License-Identifier: BSD-2-Clause
pub mod gdb_targets;
mod registers;
pub mod variants;

use crate::arch::ArchitectureDef;
use enum_dispatch::enum_dispatch;

use variants::*;

pub use registers::{BlackfinRegister, SpecialBlackfinRegister};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BlackfinVariants {
    Bf504 = 0,
    Bf504f,
    Bf506f,
    Bf512,
    Bf514,
    Bf516,
    Bf518,
    Bf522,
    Bf523,
    Bf524,
    Bf525,
    Bf526,
    Bf527,
    Bf531,
    Bf532,
    Bf533,
    Bf534,
    Bf535,
    Bf536,
    Bf537,
    Bf538,
    Bf539,
    Bf542,
    Bf542m,
    Bf544,
    Bf544b,
    Bf547,
    Bf548,
    Bf548m,
    Bf561,
    Bf592a,
}

#[enum_dispatch(ArchitectureVariant, ArchitectureDef)]
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum BlackfinMetaVariants {
    Bf504,
    Bf504f,
    Bf506f,
    Bf512,
    Bf514,
    Bf516,
    Bf518,
    Bf522,
    Bf523,
    Bf524,
    Bf525,
    Bf526,
    Bf527,
    Bf531,
    Bf532,
    Bf533,
    Bf534,
    Bf535,
    Bf536,
    Bf537,
    Bf538,
    Bf539,
    Bf542,
    Bf542m,
    Bf544,
    Bf544b,
    Bf547,
    Bf548,
    Bf548m,
    Bf561,
    Bf592a,
}

impl std::fmt::Display for BlackfinMetaVariants {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::fmt::Display for BlackfinVariants {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl From<BlackfinMetaVariants> for crate::arch::backends::ArchVariant {
    fn from(value: BlackfinMetaVariants) -> Self {
        crate::arch::backends::ArchVariant::Blackfin(value)
    }
}

impl From<BlackfinVariants> for BlackfinMetaVariants {
    fn from(value: BlackfinVariants) -> Self {
        match value {
            BlackfinVariants::Bf504 => Bf504 {}.into(),
            BlackfinVariants::Bf504f => Bf504f {}.into(),
            BlackfinVariants::Bf506f => Bf506f {}.into(),
            BlackfinVariants::Bf512 => Bf512 {}.into(),
            BlackfinVariants::Bf514 => Bf514 {}.into(),
            BlackfinVariants::Bf516 => Bf516 {}.into(),
            BlackfinVariants::Bf518 => Bf518 {}.into(),
            BlackfinVariants::Bf522 => Bf522 {}.into(),
            BlackfinVariants::Bf523 => Bf523 {}.into(),
            BlackfinVariants::Bf524 => Bf524 {}.into(),
            BlackfinVariants::Bf525 => Bf525 {}.into(),
            BlackfinVariants::Bf526 => Bf526 {}.into(),
            BlackfinVariants::Bf527 => Bf527 {}.into(),
            BlackfinVariants::Bf531 => Bf531 {}.into(),
            BlackfinVariants::Bf532 => Bf532 {}.into(),
            BlackfinVariants::Bf533 => Bf533 {}.into(),
            BlackfinVariants::Bf534 => Bf534 {}.into(),
            BlackfinVariants::Bf535 => Bf535 {}.into(),
            BlackfinVariants::Bf536 => Bf536 {}.into(),
            BlackfinVariants::Bf537 => Bf537 {}.into(),
            BlackfinVariants::Bf538 => Bf538 {}.into(),
            BlackfinVariants::Bf539 => Bf539 {}.into(),
            BlackfinVariants::Bf542 => Bf542 {}.into(),
            BlackfinVariants::Bf542m => Bf542m {}.into(),
            BlackfinVariants::Bf544 => Bf544 {}.into(),
            BlackfinVariants::Bf544b => Bf544b {}.into(),
            BlackfinVariants::Bf547 => Bf547 {}.into(),
            BlackfinVariants::Bf548 => Bf548 {}.into(),
            BlackfinVariants::Bf548m => Bf548m {}.into(),
            BlackfinVariants::Bf561 => Bf561 {}.into(),
            BlackfinVariants::Bf592a => Bf592a {}.into(),
        }
    }
}

impl From<BlackfinVariants> for crate::arch::backends::ArchVariant {
    fn from(value: BlackfinVariants) -> Self {
        let tmp: BlackfinMetaVariants = value.into();
        tmp.into()
    }
}

impl From<BlackfinMetaVariants> for Box<dyn ArchitectureDef> {
    fn from(value: BlackfinMetaVariants) -> Self {
        let inner = value;
        Box::new(inner)
    }
}
