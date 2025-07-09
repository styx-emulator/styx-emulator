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
//! Implements the high-level CPU Architecture description for SuperH Variants.
use derive_more::Display;
use enum_dispatch::enum_dispatch;

// get the register code
pub mod gdb_targets;
mod registers;
pub mod variants;
pub use registers::{SpecialSuperHRegister, SuperHRegister};

// for enum dispatch
use variants::*;

use super::ArchitectureDef;

#[enum_dispatch(ArchitectureVariant, ArchitectureDef)]
#[derive(Debug, PartialEq, Eq, Clone, Display)]
pub enum SuperHMetaVariants {
    SH1,
    SH1Dsp,
    SH2,
    SH2A,
    SH2E,
    SH3,
    SH3Dsp,
    SH3E,
    SH4,
    SH4A,
    SH4ALDsp,
    SH4ANoFpu,
    SH4NoFpu,
}

impl From<SuperHMetaVariants> for crate::arch::backends::ArchVariant {
    fn from(value: SuperHMetaVariants) -> Self {
        crate::arch::backends::ArchVariant::SuperH(value)
    }
}

impl From<SuperHMetaVariants> for Box<dyn ArchitectureDef> {
    fn from(value: SuperHMetaVariants) -> Self {
        let inner = value;
        Box::new(inner)
    }
}

/// The ergonomic enum implementation, should mirror *exactly*
/// [`SuperHMetaVariants`]
#[derive(Debug, Display, PartialEq, Eq, Clone)]
pub enum SuperHVariants {
    SH1,
    SH1Dsp,
    SH2,
    SH2A,
    SH2E,
    SH3,
    SH3Dsp,
    SH3E,
    SH4,
    SH4A,
    SH4ALDsp,
    SH4ANoFpu,
    SH4NoFpu,
}

impl From<SuperHVariants> for SuperHMetaVariants {
    fn from(value: SuperHVariants) -> Self {
        match value {
            SuperHVariants::SH1 => SH1 {}.into(),
            SuperHVariants::SH1Dsp => SH1Dsp {}.into(),
            SuperHVariants::SH2 => SH2 {}.into(),
            SuperHVariants::SH2A => SH2A {}.into(),
            SuperHVariants::SH2E => SH2E {}.into(),
            SuperHVariants::SH3 => SH3 {}.into(),
            SuperHVariants::SH3E => SH3E {}.into(),
            SuperHVariants::SH3Dsp => SH3Dsp {}.into(),
            SuperHVariants::SH4 => SH4 {}.into(),
            SuperHVariants::SH4NoFpu => SH4NoFpu {}.into(),
            SuperHVariants::SH4A => SH4A {}.into(),
            SuperHVariants::SH4ANoFpu => SH4ANoFpu {}.into(),
            SuperHVariants::SH4ALDsp => SH4ALDsp {}.into(),
        }
    }
}

impl From<SuperHVariants> for crate::arch::backends::ArchVariant {
    fn from(value: SuperHVariants) -> Self {
        let tmp: SuperHMetaVariants = value.into();
        tmp.into()
    }
}

impl TryFrom<crate::arch::backends::ArchVariant> for SuperHVariants {
    type Error = String;

    fn try_from(value: crate::arch::backends::ArchVariant) -> Result<Self, Self::Error> {
        match value {
            super::backends::ArchVariant::SuperH(superh_variant) => match superh_variant {
                super::SuperHMetaVariants::SH1(_) => Ok(Self::SH1),
                super::SuperHMetaVariants::SH1Dsp(_) => Ok(Self::SH1Dsp),
                super::SuperHMetaVariants::SH2(_) => Ok(Self::SH2),
                super::SuperHMetaVariants::SH2A(_) => Ok(Self::SH2A),
                super::SuperHMetaVariants::SH2E(_) => Ok(Self::SH2E),
                super::SuperHMetaVariants::SH3(_) => Ok(Self::SH3),
                super::SuperHMetaVariants::SH3Dsp(_) => Ok(Self::SH3Dsp),
                super::SuperHMetaVariants::SH3E(_) => Ok(Self::SH3E),
                super::SuperHMetaVariants::SH4(_) => Ok(Self::SH4),
                super::SuperHMetaVariants::SH4A(_) => Ok(Self::SH4A),
                super::SuperHMetaVariants::SH4ALDsp(_) => Ok(Self::SH4ALDsp),
                super::SuperHMetaVariants::SH4ANoFpu(_) => Ok(Self::SH4ANoFpu),
                super::SuperHMetaVariants::SH4NoFpu(_) => Ok(Self::SH4NoFpu),
            },
            bad_arch => Err(format!("FamilyIncompatibility: {bad_arch:?}")),
        }
    }
}
