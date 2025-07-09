// SPDX-License-Identifier: BSD-2-Clause
//! Generic top level container for PPC32 registers
use std::{collections::HashMap, num::NonZeroUsize};
use strum::IntoEnumIterator;

use crate::arch::{CpuRegister, RegisterValue};
use crate::macros::*;

create_basic_register_enums!(
    Msp430,
    (R0, 16),
    (R1, 16),
    (R2, 16),
    (R3, 16),
    (R4, 16),
    (R5, 16),
    (R6, 16),
    (R7, 16),
    (R8, 16),
    (R9, 16),
    (R10, 16),
    (R11, 16),
    (R12, 16),
    (R13, 16),
    (R14, 16),
    (R15, 16)
);

#[allow(non_upper_case_globals)]
impl Msp430Register {
    /// Program Counter
    pub const Pc: Self = Self::R0;
    /// Stack Pointer
    pub const Sp: Self = Self::R1;
    /// Status Register
    pub const Sr: Self = Self::R2;
}

lazy_static::lazy_static! {
    /// List of all [Msp430Register]s in uppercase string format
    static ref MSP430_REGISTER_NAMES: HashMap<Msp430Register, String> = {
        Msp430Register::iter()
            .map(|reg| (reg, reg.to_string().to_uppercase()))
            .collect()
    };
}

create_special_register_enums!(Msp430);
