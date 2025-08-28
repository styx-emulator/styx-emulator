// SPDX-License-Identifier: BSD-2-Clause
//! Implements the high-level CPU Architecture description for ARM 32-bit
//! Variants.
use derive_more::Display;
use enum_dispatch::enum_dispatch;

// get the register code
pub mod gdb_targets;
mod registers;
pub mod variants;
pub use registers::{
    arm_coproc_registers, ArmRegister, CoProc, CoProcessor, CoProcessorValue, SpecialArmRegister,
    SpecialArmRegisterValues,
};

// for enum dispatch
use variants::*;

use super::ArchitectureDef;

#[enum_dispatch(ArchitectureVariant, ArchitectureDef)]
#[derive(Debug, Display, PartialEq, Eq, Clone, Copy, serde::Deserialize)]
#[serde(from = "ArmVariants")]
pub enum ArmMetaVariants {
    Arm1026,
    Arm1136,
    Arm1136r2,
    Arm1176,
    Arm11Mpcore,
    Arm926,
    Arm946,
    ArmCortexA15,
    ArmCortexA7,
    ArmCortexA8,
    ArmCortexA9,
    ArmCortexM0,
    ArmCortexM3,
    ArmCortexM33,
    ArmCortexM4,
    ArmCortexM7,
    ArmCortexR5,
    ArmCortexR5F,
    ArmPxa250,
    ArmPxa255,
    ArmPxa260,
    ArmPxa261,
    ArmPxa262,
    ArmPxa270,
    ArmPxa270a0,
    ArmPxa270a1,
    ArmPxa270b0,
    ArmPxa270b1,
    ArmPxa270c0,
    ArmPxa270c5,
    ArmSa1100,
    ArmSa1110,
    ArmTi925T,
}

impl From<ArmMetaVariants> for crate::arch::backends::ArchVariant {
    fn from(value: ArmMetaVariants) -> Self {
        crate::arch::backends::ArchVariant::Arm(value)
    }
}

impl From<ArmMetaVariants> for Box<dyn ArchitectureDef> {
    fn from(value: ArmMetaVariants) -> Self {
        let inner = value;
        Box::new(inner)
    }
}

/// The sole purpose of this enum is ergonomics when selecting
/// a cpu model to use
#[derive(Debug, Display, PartialEq, Eq, Clone, serde::Deserialize)]
pub enum ArmVariants {
    Arm926 = 0,
    Arm946,
    Arm1026,
    Arm1136r2,
    Arm1136,
    Arm1176,
    Arm11Mpcore,
    ArmCortexM0,
    ArmCortexM3,
    ArmCortexM4,
    ArmCortexM7,
    ArmCortexM33,
    ArmCortexR5,
    ArmCortexR5F,
    ArmCortexA7,
    ArmCortexA8,
    ArmCortexA9,
    ArmCortexA15,
    ArmTi925T,
    ArmSa1100,
    ArmSa1110,
    ArmPxa250,
    ArmPxa255,
    ArmPxa260,
    ArmPxa261,
    ArmPxa262,
    ArmPxa270,
    ArmPxa270a0,
    ArmPxa270a1,
    ArmPxa270b0,
    ArmPxa270b1,
    ArmPxa270c0,
    ArmPxa270c5,
}

impl From<ArmVariants> for ArmMetaVariants {
    fn from(value: ArmVariants) -> Self {
        match value {
            ArmVariants::Arm926 => Arm926 {}.into(),
            ArmVariants::Arm946 => Arm946 {}.into(),
            ArmVariants::Arm1026 => Arm1026 {}.into(),
            ArmVariants::Arm1136r2 => Arm1136r2 {}.into(),
            ArmVariants::Arm1136 => Arm1136 {}.into(),
            ArmVariants::Arm1176 => Arm1176 {}.into(),
            ArmVariants::Arm11Mpcore => Arm11Mpcore {}.into(),
            ArmVariants::ArmCortexM0 => ArmCortexM0 {}.into(),
            ArmVariants::ArmCortexM3 => ArmCortexM3 {}.into(),
            ArmVariants::ArmCortexM4 => ArmCortexM4 {}.into(),
            ArmVariants::ArmCortexM7 => ArmCortexM7 {}.into(),
            ArmVariants::ArmCortexM33 => ArmCortexM33 {}.into(),
            ArmVariants::ArmCortexR5 => ArmCortexR5 {}.into(),
            ArmVariants::ArmCortexR5F => ArmCortexR5F {}.into(),
            ArmVariants::ArmCortexA7 => ArmCortexA7 {}.into(),
            ArmVariants::ArmCortexA8 => ArmCortexA7 {}.into(),
            ArmVariants::ArmCortexA9 => ArmCortexA9 {}.into(),
            ArmVariants::ArmCortexA15 => ArmCortexA15 {}.into(),
            ArmVariants::ArmTi925T => ArmTi925T {}.into(),
            ArmVariants::ArmSa1100 => ArmSa1100 {}.into(),
            ArmVariants::ArmSa1110 => ArmSa1110 {}.into(),
            ArmVariants::ArmPxa250 => ArmPxa250 {}.into(),
            ArmVariants::ArmPxa255 => ArmPxa255 {}.into(),
            ArmVariants::ArmPxa260 => ArmPxa260 {}.into(),
            ArmVariants::ArmPxa261 => ArmPxa261 {}.into(),
            ArmVariants::ArmPxa262 => ArmPxa262 {}.into(),
            ArmVariants::ArmPxa270 => ArmPxa270 {}.into(),
            ArmVariants::ArmPxa270a0 => ArmPxa270a0 {}.into(),
            ArmVariants::ArmPxa270a1 => ArmPxa270a1 {}.into(),
            ArmVariants::ArmPxa270b0 => ArmPxa270b0 {}.into(),
            ArmVariants::ArmPxa270b1 => ArmPxa270b1 {}.into(),
            ArmVariants::ArmPxa270c0 => ArmPxa270c0 {}.into(),
            ArmVariants::ArmPxa270c5 => ArmPxa270c5 {}.into(),
        }
    }
}

impl From<ArmVariants> for crate::arch::backends::ArchVariant {
    fn from(value: ArmVariants) -> Self {
        let tmp: ArmMetaVariants = value.into();
        tmp.into()
    }
}
