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
#[derive(Debug, Display, PartialEq, Eq, Clone)]
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
#[derive(Debug, Display, PartialEq, Eq, Clone)]
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
