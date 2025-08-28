// SPDX-License-Identifier: BSD-2-Clause
use derive_more::Display;
use enum_dispatch::enum_dispatch;

pub mod gdb_targets;
mod registers;
pub mod variants;

pub use registers::{Mips32Register, SpecialMips32Register};

use tap::Conv;
// for enum dispatch
use variants::*;

use super::ArchitectureDef;

// Almost complete list: https://techinfodepot.shoutwiki.com/wiki/MIPS32
// GCC defintions for processors at: /gcc/config/mips/mips-cpus.def in gcc source.
//      https://github.com/gcc-mirror/gcc/blob/master/gcc/config/mips/mips-cpus.def
#[enum_dispatch(ArchitectureVariant, ArchitectureDef)]
#[derive(Debug, Display, PartialEq, Eq, Clone, Copy, serde::Deserialize)]
#[serde(from = "Mips32Variants")]
pub enum Mips32MetaVariants {
    // Generic mips32 revision 1 isa
    Mips32r1Generic,

    Mips324kc,
    Mips324km,
    Mips324kp,
    Mips324ksc,

    /* MIPS32 Release 2 processors.  */
    Mips32m4k,
    Mips32m14kc,
    Mips32m14k,
    Mips32m14ke,
    Mips32m14kec,
    Mips324kec,
    Mips324kem,
    Mips324kep,
    Mips324ksd,

    Mips3224kc,
    Mips3224kf2_1,
    Mips3224kf,
    Mips3224kf1_1,
    Mips3224kfx,
    Mips3224kx,

    Mips3224kec,
    Mips3224kef2_1,
    Mips3224kef,
    Mips3224kef1_1,
    Mips3224kefx,
    Mips3224kex,

    Mips3234kc,
    Mips3234kf2_1,
    Mips3234kf,
    Mips3234kf1_1,
    Mips3234kfx,
    Mips3234kx,
    Mips3234kn,

    Mips3274kc,
    Mips3274kf2_1,
    Mips3274kf,
    Mips3274kf1_1,
    Mips3274kfx,
    Mips3274kx,
    Mips3274kf3_2,

    Mips321004kc,
    Mips321004kf2_1,
    Mips321004kf,
    Mips321004kf1_1,

    Mips32interaptiv,

    /* MIPS32 Release 5 processors.  */
    Mips32p5600,
    Mips32m5100,
    Mips32m5101,
}

impl From<Mips32MetaVariants> for crate::arch::backends::ArchVariant {
    fn from(value: Mips32MetaVariants) -> Self {
        crate::arch::backends::ArchVariant::Mips32(value)
    }
}

impl From<Mips32MetaVariants> for Box<dyn ArchitectureDef> {
    fn from(value: Mips32MetaVariants) -> Self {
        let inner = value;
        Box::new(inner)
    }
}

/// The sole purpose of this enum is ergonomics when selecting
/// a cpu model to use
#[derive(Debug, Display, PartialEq, Eq, Clone, Copy, serde::Deserialize)]
pub enum Mips32Variants {
    Mips32r1Generic,
    Mips324kc,
    Mips324km,
    Mips324kp,
    Mips324ksc,

    /* MIPS32 Release 2 processors.  */
    Mips32m4k,
    Mips32m14kc,
    Mips32m14k,
    Mips32m14ke,
    Mips32m14kec,
    Mips324kec,
    Mips324kem,
    Mips324kep,
    Mips324ksd,

    Mips3224kc,
    Mips3224kf2_1,
    Mips3224kf,
    Mips3224kf1_1,
    Mips3224kfx,
    Mips3224kx,

    Mips3224kec,
    Mips3224kef2_1,
    Mips3224kef,
    Mips3224kef1_1,
    Mips3224kefx,
    Mips3224kex,

    Mips3234kc,
    Mips3234kf2_1,
    Mips3234kf,
    Mips3234kf1_1,
    Mips3234kfx,
    Mips3234kx,
    Mips3234kn,

    Mips3274kc,
    Mips3274kf2_1,
    Mips3274kf,
    Mips3274kf1_1,
    Mips3274kfx,
    Mips3274kx,
    Mips3274kf3_2,

    Mips321004kc,
    Mips321004kf2_1,
    Mips321004kf,
    Mips321004kf1_1,

    Mips32interaptiv,

    /* MIPS32 Release 5 processors.  */
    Mips32p5600,
    Mips32m5100,
    Mips32m5101,
}

impl From<Mips32Variants> for Mips32MetaVariants {
    fn from(value: Mips32Variants) -> Self {
        match value {
            Mips32Variants::Mips32r1Generic => Mips32r1Generic {}.into(),
            Mips32Variants::Mips324kc => Mips324kc {}.into(),
            Mips32Variants::Mips324km => Mips324km {}.into(),
            Mips32Variants::Mips324kp => Mips324kp {}.into(),
            Mips32Variants::Mips324ksc => Mips324ksc {}.into(),
            Mips32Variants::Mips32m4k => Mips32m4k {}.into(),
            Mips32Variants::Mips32m14kc => Mips32m14kc {}.into(),
            Mips32Variants::Mips32m14k => Mips32m14k {}.into(),
            Mips32Variants::Mips32m14ke => Mips32m14ke {}.into(),
            Mips32Variants::Mips32m14kec => Mips32m14kec {}.into(),
            Mips32Variants::Mips324kec => Mips324kec {}.into(),
            Mips32Variants::Mips324kem => Mips324kem {}.into(),
            Mips32Variants::Mips324kep => Mips324kep {}.into(),
            Mips32Variants::Mips324ksd => Mips324ksd {}.into(),
            Mips32Variants::Mips3224kc => Mips3224kc {}.into(),
            Mips32Variants::Mips3224kf2_1 => Mips3224kf2_1 {}.into(),
            Mips32Variants::Mips3224kf => Mips3224kf {}.into(),
            Mips32Variants::Mips3224kf1_1 => Mips3224kf1_1 {}.into(),
            Mips32Variants::Mips3224kfx => Mips3224kfx {}.into(),
            Mips32Variants::Mips3224kx => Mips3224kx {}.into(),
            Mips32Variants::Mips3224kec => Mips3224kec {}.into(),
            Mips32Variants::Mips3224kef2_1 => Mips3224kef2_1 {}.into(),
            Mips32Variants::Mips3224kef => Mips3224kef {}.into(),
            Mips32Variants::Mips3224kef1_1 => Mips3224kef1_1 {}.into(),
            Mips32Variants::Mips3224kefx => Mips3224kefx {}.into(),
            Mips32Variants::Mips3224kex => Mips3224kex {}.into(),
            Mips32Variants::Mips3234kc => Mips3234kc {}.into(),
            Mips32Variants::Mips3234kf2_1 => Mips3234kf2_1 {}.into(),
            Mips32Variants::Mips3234kf => Mips3234kf {}.into(),
            Mips32Variants::Mips3234kf1_1 => Mips3234kf1_1 {}.into(),
            Mips32Variants::Mips3234kfx => Mips3234kfx {}.into(),
            Mips32Variants::Mips3234kx => Mips3234kx {}.into(),
            Mips32Variants::Mips3234kn => Mips3234kn {}.into(),
            Mips32Variants::Mips3274kc => Mips3274kc {}.into(),
            Mips32Variants::Mips3274kf2_1 => Mips3274kf2_1 {}.into(),
            Mips32Variants::Mips3274kf => Mips3274kf {}.into(),
            Mips32Variants::Mips3274kf1_1 => Mips3274kf1_1 {}.into(),
            Mips32Variants::Mips3274kfx => Mips3274kfx {}.into(),
            Mips32Variants::Mips3274kx => Mips3274kx {}.into(),
            Mips32Variants::Mips3274kf3_2 => Mips3274kf3_2 {}.into(),
            Mips32Variants::Mips321004kc => Mips321004kc {}.into(),
            Mips32Variants::Mips321004kf2_1 => Mips321004kf2_1 {}.into(),
            Mips32Variants::Mips321004kf => Mips321004kf {}.into(),
            Mips32Variants::Mips321004kf1_1 => Mips321004kf1_1 {}.into(),
            Mips32Variants::Mips32interaptiv => Mips32interaptiv {}.into(),
            Mips32Variants::Mips32p5600 => Mips32p5600 {}.into(),
            Mips32Variants::Mips32m5100 => Mips32m5100 {}.into(),
            Mips32Variants::Mips32m5101 => Mips32m5101 {}.into(),
        }
    }
}

impl From<Mips32Variants> for crate::arch::backends::ArchVariant {
    fn from(value: Mips32Variants) -> Self {
        value.conv::<Mips32MetaVariants>().into()
    }
}
