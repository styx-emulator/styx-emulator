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
//! Generic top level container for PPC32 registers
use std::{collections::HashMap, num::NonZeroUsize};
use strum::IntoEnumIterator;

use crate::arch::{CpuRegister, RegisterValue};
use crate::macros::*;

create_basic_register_enums!(
    Msp430X,
    (R0, 20),
    (R1, 20),
    (R2, 20),
    (R3, 20),
    (R4, 20),
    (R5, 20),
    (R6, 20),
    (R7, 20),
    (R8, 20),
    (R9, 20),
    (R10, 20),
    (R11, 20),
    (R12, 20),
    (R13, 20),
    (R14, 20),
    (R15, 20)
);

#[allow(non_upper_case_globals)]
impl Msp430XRegister {
    /// Program Counter
    pub const Pc: Self = Self::R0;
    /// Stack Pointer
    pub const Sp: Self = Self::R1;
    /// Status Register
    pub const Sr: Self = Self::R2;
}

lazy_static::lazy_static! {
    /// List of all [Msp430XRegister]s in uppercase string format
    static ref MSP430X_REGISTER_NAMES: HashMap<Msp430XRegister, String> = {
        Msp430XRegister::iter()
            .map(|reg| (reg, reg.to_string().to_uppercase()))
            .collect()
    };
}

create_special_register_enums!(Msp430X);
