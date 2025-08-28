// SPDX-License-Identifier: BSD-2-Clause
use derive_more::Display;
use enum_dispatch::enum_dispatch;
use tap::Conv;

pub mod gdb_targets;
mod registers;
pub mod variants;
mod xregisters;

pub use registers::{Msp430Register, SpecialMsp430Register};
pub use xregisters::{Msp430XRegister, SpecialMsp430XRegister};

// for enum dispatch
use variants::*;

use super::ArchitectureDef;

#[enum_dispatch(ArchitectureVariant, ArchitectureDef)]
#[derive(Debug, Display, PartialEq, Eq, Clone, Copy, serde::Deserialize)]
#[serde(from = "Msp430Variants")]
pub enum Msp430MetaVariants {
    Msp430x31x,
}

impl From<Msp430MetaVariants> for crate::arch::backends::ArchVariant {
    fn from(value: Msp430MetaVariants) -> Self {
        crate::arch::backends::ArchVariant::Msp430(value)
    }
}

impl From<Msp430MetaVariants> for Box<dyn ArchitectureDef> {
    fn from(value: Msp430MetaVariants) -> Self {
        let inner = value;
        Box::new(inner)
    }
}

/// The sole purpose of this enum is ergonomics when selecting
/// a cpu model to use
#[derive(Debug, Display, PartialEq, Eq, Clone, Copy, serde::Deserialize)]
pub enum Msp430Variants {
    Msp430x31x,
}

impl From<Msp430Variants> for Msp430MetaVariants {
    fn from(value: Msp430Variants) -> Self {
        match value {
            Msp430Variants::Msp430x31x => Msp430x31x {}.into(),
        }
    }
}

impl From<Msp430Variants> for crate::arch::backends::ArchVariant {
    fn from(value: Msp430Variants) -> Self {
        value.conv::<Msp430MetaVariants>().into()
    }
}
