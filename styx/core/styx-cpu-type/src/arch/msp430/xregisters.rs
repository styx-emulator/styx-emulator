// SPDX-License-Identifier: BSD-2-Clause
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
