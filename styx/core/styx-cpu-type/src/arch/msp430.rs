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
mod xregisters;

pub use registers::{Msp430Register, SpecialMsp430Register};
pub use xregisters::{Msp430XRegister, SpecialMsp430XRegister};

// for enum dispatch
use variants::*;

use super::ArchitectureDef;

#[enum_dispatch(ArchitectureVariant, ArchitectureDef)]
#[derive(Debug, Display, PartialEq, Eq, Clone)]
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
#[derive(Debug, Display, PartialEq, Eq, Clone)]
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
