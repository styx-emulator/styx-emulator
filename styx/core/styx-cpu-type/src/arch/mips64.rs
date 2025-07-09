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
use derive_more::Display;
use enum_dispatch::enum_dispatch;

pub mod gdb_targets;
mod registers;
pub mod variants;

pub use registers::{Mips64Register, SpecialMips64Register};

// for enum dispatch
use variants::*;

use super::ArchitectureDef;

#[enum_dispatch(ArchitectureVariant, ArchitectureDef)]
#[derive(Debug, Display, PartialEq, Eq, Clone)]
pub enum Mips64MetaVariants {
    Mips6420kc,
    Mips645kc,
    Mips645kec,
    Mips645kef,
    Mips645kf,
    // Octeon Plus
    Mips64Cn5520,
    Mips64Cn5530,
    Mips64Cn5534,
    Mips64Cn5640,
    Mips64Cn5645,
    Mips64Cn5650,
    Mips64Cn5740,
    Mips64Cn5745,
    Mips64Cn5750,
    Mips64Cn5830,
    Mips64Cn5840,
    Mips64Cn5850,
    Mips64Cn5860,
    // Octeon II
    Mips64Cn6320,
    Mips64Cn6330,
    Mips64Cn6350,
    Mips64Cn6860,
    Mips64Cn6870,
    Mips64Cn6880,
    Mips64DspR2,
    // MIPS Warrior I-class
    Mips64I6400,
    Mips64I6500,
    // Loongson
    Mips64Loongson2e,
    Mips64Loongson2f,
    // MIPS Warrior P-class
    Mips64P6600,
    // mips64 generic
    Mips64R2Generic,
    // R4000 series
    Mips64R4000,
    // R5000 series
    Mips64Vrf5432,
}

impl From<Mips64MetaVariants> for crate::arch::backends::ArchVariant {
    fn from(value: Mips64MetaVariants) -> Self {
        crate::arch::backends::ArchVariant::Mips64(value)
    }
}

impl From<Mips64MetaVariants> for Box<dyn ArchitectureDef> {
    fn from(value: Mips64MetaVariants) -> Self {
        let inner = value;
        Box::new(inner)
    }
}

/// The sole purpose of this enum is ergonomics when selecting
/// a cpu model to use
#[derive(Debug, Display, PartialEq, Eq, Clone)]
pub enum Mips64Variants {
    Mips6420kc,
    Mips645kc,
    Mips645kec,
    Mips645kef,
    Mips645kf,
    // Octeon Plus
    Mips64Cn5520,
    Mips64Cn5530,
    Mips64Cn5534,
    Mips64Cn5640,
    Mips64Cn5645,
    Mips64Cn5650,
    Mips64Cn5740,
    Mips64Cn5745,
    Mips64Cn5750,
    Mips64Cn5830,
    Mips64Cn5840,
    Mips64Cn5850,
    Mips64Cn5860,
    // Octeon II
    Mips64Cn6320,
    Mips64Cn6330,
    Mips64Cn6350,
    Mips64Cn6860,
    Mips64Cn6870,
    Mips64Cn6880,
    Mips64DspR2,
    // MIPS Warrior I-class
    Mips64I6400,
    Mips64I6500,
    // Loongson
    Mips64Loongson2e,
    Mips64Loongson2f,
    // MIPS Warrior P-class
    Mips64P6600,
    // mips64 generic
    Mips64R2Generic,
    // R4000 series
    Mips64R4000,
    // R5000 series
    Mips64Vrf5432,
}

impl From<Mips64Variants> for Mips64MetaVariants {
    fn from(value: Mips64Variants) -> Self {
        match value {
            Mips64Variants::Mips64R2Generic => Mips64R2Generic {}.into(),
            Mips64Variants::Mips64R4000 => Mips64R4000 {}.into(),
            Mips64Variants::Mips64Vrf5432 => Mips64Vrf5432 {}.into(),
            Mips64Variants::Mips645kc => Mips645kc {}.into(),
            Mips64Variants::Mips645kf => Mips645kf {}.into(),
            Mips64Variants::Mips6420kc => Mips6420kc {}.into(),
            Mips64Variants::Mips645kec => Mips645kec {}.into(),
            Mips64Variants::Mips645kef => Mips645kef {}.into(),
            Mips64Variants::Mips64I6400 => Mips64I6400 {}.into(),
            Mips64Variants::Mips64I6500 => Mips64I6500 {}.into(),
            Mips64Variants::Mips64P6600 => Mips64P6600 {}.into(),
            Mips64Variants::Mips64Loongson2e => Mips64Loongson2e {}.into(),
            Mips64Variants::Mips64Loongson2f => Mips64Loongson2f {}.into(),
            Mips64Variants::Mips64DspR2 => Mips64DspR2 {}.into(),
            Mips64Variants::Mips64Cn5520 => Mips64Cn5520 {}.into(),
            Mips64Variants::Mips64Cn5530 => Mips64Cn5530 {}.into(),
            Mips64Variants::Mips64Cn5534 => Mips64Cn5534 {}.into(),
            Mips64Variants::Mips64Cn5640 => Mips64Cn5640 {}.into(),
            Mips64Variants::Mips64Cn5645 => Mips64Cn5645 {}.into(),
            Mips64Variants::Mips64Cn5650 => Mips64Cn5650 {}.into(),
            Mips64Variants::Mips64Cn5740 => Mips64Cn5740 {}.into(),
            Mips64Variants::Mips64Cn5745 => Mips64Cn5745 {}.into(),
            Mips64Variants::Mips64Cn5750 => Mips64Cn5750 {}.into(),
            Mips64Variants::Mips64Cn5830 => Mips64Cn5830 {}.into(),
            Mips64Variants::Mips64Cn5840 => Mips64Cn5840 {}.into(),
            Mips64Variants::Mips64Cn5850 => Mips64Cn5850 {}.into(),
            Mips64Variants::Mips64Cn5860 => Mips64Cn5860 {}.into(),
            Mips64Variants::Mips64Cn6320 => Mips64Cn6320 {}.into(),
            Mips64Variants::Mips64Cn6330 => Mips64Cn6330 {}.into(),
            Mips64Variants::Mips64Cn6350 => Mips64Cn6350 {}.into(),
            Mips64Variants::Mips64Cn6860 => Mips64Cn6860 {}.into(),
            Mips64Variants::Mips64Cn6870 => Mips64Cn6870 {}.into(),
            Mips64Variants::Mips64Cn6880 => Mips64Cn6880 {}.into(),
        }
    }
}
