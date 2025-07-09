// SPDX-License-Identifier: BSD-2-Clause
use derive_more::Display;
use enum_dispatch::enum_dispatch;

pub mod gdb_targets;
mod registers;
pub mod variants;
pub use registers::{
    Ppc32Register, SpecialPpc32Register, SpecialPpc32RegisterValues, SprRegister, SprRegisterValue,
};

// for enum dispatch
use variants::*;

use super::ArchitectureDef;

#[enum_dispatch(ArchitectureVariant, ArchitectureDef)]
#[derive(Debug, PartialEq, Eq, Clone, Display)]
pub enum Ppc32MetaVariants {
    // PowerQUICC I family
    // https://www.nxp.com/products/processors-and-microcontrollers/legacy-mpu-mcus/powerquicc-processors:POWERQUICC_HOME
    Mpc821,
    Mpc823,
    Mpc823E,
    Mpc850,
    Mpc852T,
    Mpc853T,
    Mpc855T,
    Mpc857DSL,
    Mpc859DSL,
    Mpc859T,
    Mpc860,
    Mpc862,
    Mpc866,
    Mpc870,
    Mpc875,
    Mpc880,
    Mpc885,
    // PowerPC 4xx
    Ppc401,
    Ppc405,
    Ppc440,
    Ppc470,
    // PowerQUICC II family
    // PowerQUICC II PRO family
    // PowerQUICC III family
}

impl From<Ppc32MetaVariants> for crate::arch::backends::ArchVariant {
    fn from(value: Ppc32MetaVariants) -> Self {
        crate::arch::backends::ArchVariant::Ppc32(value)
    }
}

impl From<Ppc32MetaVariants> for Box<dyn ArchitectureDef> {
    fn from(value: Ppc32MetaVariants) -> Self {
        let inner = value;
        Box::new(inner)
    }
}
/// The ergonomic enum implementation, should mirror *exactly*
/// [`Ppc32MetaVariants`]
#[derive(Debug, Display, PartialEq, Eq, Clone)]
pub enum Ppc32Variants {
    // PowerQUICC I family
    // https://www.nxp.com/products/processors-and-microcontrollers/legacy-mpu-mcus/powerquicc-processors:POWERQUICC_HOME
    Mpc850 = 0,
    Mpc860,
    Mpc866,
    Mpc870,
    Mpc875,
    Mpc880,
    Mpc885,
    Mpc852T,
    Mpc853T,
    Mpc855T,
    Mpc859T,
    // PowerQUICC II family
    // PowerQUICC II PRO family
    // PowerQUICC III family
    // OTHER
    Mpc821,
    Mpc823,
    Mpc823E,
    Mpc857DSL,
    Mpc859DSL,
    Mpc862,
    // PowerPC 4xx
    Ppc401,
    Ppc405,
    Ppc440,
    Ppc470,
}

impl From<Ppc32Variants> for Ppc32MetaVariants {
    fn from(value: Ppc32Variants) -> Self {
        match value {
            Ppc32Variants::Ppc401 => Ppc401 {}.into(),
            Ppc32Variants::Ppc405 => Ppc405 {}.into(),
            Ppc32Variants::Ppc440 => Ppc440 {}.into(),
            Ppc32Variants::Ppc470 => Ppc470 {}.into(),
            Ppc32Variants::Mpc821 => Mpc821 {}.into(),
            Ppc32Variants::Mpc823 => Mpc823 {}.into(),
            Ppc32Variants::Mpc823E => Mpc823E {}.into(),
            Ppc32Variants::Mpc850 => Mpc850 {}.into(),
            Ppc32Variants::Mpc852T => Mpc852T {}.into(),
            Ppc32Variants::Mpc853T => Mpc853T {}.into(),
            Ppc32Variants::Mpc855T => Mpc855T {}.into(),
            Ppc32Variants::Mpc857DSL => Mpc857DSL {}.into(),
            Ppc32Variants::Mpc859DSL => Mpc859DSL {}.into(),
            Ppc32Variants::Mpc859T => Mpc859T {}.into(),
            Ppc32Variants::Mpc860 => Mpc860 {}.into(),
            Ppc32Variants::Mpc862 => Mpc862 {}.into(),
            Ppc32Variants::Mpc866 => Mpc866 {}.into(),
            Ppc32Variants::Mpc870 => Mpc870 {}.into(),
            Ppc32Variants::Mpc875 => Mpc875 {}.into(),
            Ppc32Variants::Mpc880 => Mpc880 {}.into(),
            Ppc32Variants::Mpc885 => Mpc885 {}.into(),
        }
    }
}

impl From<Ppc32Variants> for crate::arch::backends::ArchVariant {
    fn from(value: Ppc32Variants) -> Self {
        let tmp: Ppc32MetaVariants = value.into();
        tmp.into()
    }
}
