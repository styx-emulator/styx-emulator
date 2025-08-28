// SPDX-License-Identifier: BSD-2-Clause
//! Implements the high-level CPU Architecture description for ARM 32-bit
//! Variants.
use derive_more::Display;
use enum_dispatch::enum_dispatch;

// get the register code
pub mod gdb_targets;
mod registers;
pub mod variants;

pub use registers::Aarch64Register;
pub use registers::SpecialAarch64Register;

// for enum dispatch
use variants::*;

use super::ArchitectureDef;

#[enum_dispatch(ArchitectureVariant, ArchitectureDef)]
#[derive(Debug, Display, PartialEq, Eq, Clone, Copy, serde::Deserialize)]
#[serde(from = "Aarch64Variants")]
pub enum Aarch64MetaVariants {
    Generic,
}

impl From<Aarch64MetaVariants> for crate::arch::backends::ArchVariant {
    fn from(value: Aarch64MetaVariants) -> Self {
        crate::arch::backends::ArchVariant::Aarch64(value)
    }
}

impl From<Aarch64MetaVariants> for Box<dyn ArchitectureDef> {
    fn from(value: Aarch64MetaVariants) -> Self {
        let inner = value;
        Box::new(inner)
    }
}

/// The sole purpose of this enum is ergonomics when selecting
/// a cpu model to use
#[derive(Debug, Display, PartialEq, Eq, Clone, Copy, serde::Deserialize)]
pub enum Aarch64Variants {
    Generic,
}

impl From<Aarch64Variants> for Aarch64MetaVariants {
    fn from(value: Aarch64Variants) -> Self {
        match value {
            Aarch64Variants::Generic => Generic {}.into(),
        }
    }
}

impl From<Aarch64Variants> for crate::arch::backends::ArchVariant {
    fn from(value: Aarch64Variants) -> Self {
        let tmp: Aarch64MetaVariants = value.into();
        tmp.into()
    }
}
