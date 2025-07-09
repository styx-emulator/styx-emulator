// SPDX-License-Identifier: BSD-2-Clause
//! Generic top level container for Mips32 registers
use std::{collections::HashMap, num::NonZeroUsize};
use strum::IntoEnumIterator;

use crate::arch::{CpuRegister, RegisterValue};
use crate::macros::*;

create_basic_register_enums!(
    Mips32,
    // Basic regs.
    // See Section 4.3 (CPU Registers) of Volume I-A of Mips32 ISA intro (doc: MD00082)
    (R0, 32),
    (R1, 32),
    (R2, 32),
    (R3, 32),
    (R4, 32),
    (R5, 32),
    (R6, 32),
    (R7, 32),
    (R8, 32),
    (R9, 32),
    (R10, 32),
    (R11, 32),
    (R12, 32),
    (R13, 32),
    (R14, 32),
    (R15, 32),
    (R16, 32),
    (R17, 32),
    (R18, 32),
    (R19, 32),
    (R20, 32),
    (R21, 32),
    (R22, 32),
    (R23, 32),
    (R24, 32),
    (R25, 32),
    (R26, 32),
    (R27, 32),
    (R28, 32),
    (R29, 32),
    (R30, 32),
    (R31, 32),
    (Lo, 32),
    (Hi, 32),
    (Pc, 32),
    // These could be 64 or 32 bits wide depending on the implementation.
    // They could also be 32 bits wide and combining to become 64-bits.
    // See section 6.4 of Vol. I-A
    (F0, 64),
    (F1, 64),
    (F2, 64),
    (F3, 64),
    (F4, 64),
    (F5, 64),
    (F6, 64),
    (F7, 64),
    (F8, 64),
    (F9, 64),
    (F10, 64),
    (F11, 64),
    (F12, 64),
    (F13, 64),
    (F14, 64),
    (F15, 64),
    (F16, 64),
    (F17, 64),
    (F18, 64),
    (F19, 64),
    (F20, 64),
    (F21, 64),
    (F22, 64),
    (F23, 64),
    (F24, 64),
    (F25, 64),
    (F26, 64),
    (F27, 64),
    (F28, 64),
    (F29, 64),
    (F30, 64),
    (F31, 64),
    // Fp control regs. See section 6.5 of Vol. I-A
    (FIR, 32),
    (FCSR, 32),
    (FEXR, 32),
    (FCCR, 32),
    // DSP extension registers.
    // See section 3.10 of Volume IV-e of MIPS32 ISA for programmers (doc: MD00374)
    // Note that sometimes MIPS referred to these combined hi[n]/lo[n] pairs as "ac[n]"
    (Hi1, 64),
    (Hi2, 64),
    (Hi3, 64),
    (Lo1, 64),
    (Lo2, 64),
    (Lo3, 64),
    (DSPControl, 64),
);

#[allow(unused)]
#[allow(non_upper_case_globals)]
/// Registers names for the O32 calling convention (most common).
/// Note that the N32 calling convention also exists, which allocates reigsters 8-11 as function
///     args, sacraficing four temporaries. R12 is still referred to as t4, though, so t0-t3 just don't
///     exist.
impl Mips32Register {
    /// Always Zero
    pub const Zero: Self = Self::R0;
    /// Reserved for Assembler
    pub const At: Self = Self::R1;
    /// Value 0: Return value from function call
    pub const V0: Self = Self::R2;
    /// Value 1: Return value from function call
    pub const V1: Self = Self::R3;
    /// Argument 0: Function argument
    pub const A0: Self = Self::R4;
    /// Argument 1: Function argument
    pub const A1: Self = Self::R5;
    /// Argument 2: Function argument
    pub const A2: Self = Self::R6;
    /// Argument 3: Function argument
    pub const A3: Self = Self::R7;
    /// Temporary 0: Clobbered register
    pub const T0: Self = Self::R8;
    /// Temporary 1: Clobbered register
    pub const T1: Self = Self::R9;
    /// Temporary 2: Clobbered register
    pub const T2: Self = Self::R10;
    /// Temporary 3: Clobbered register
    pub const T3: Self = Self::R11;
    /// Temporary 4: Clobbered register
    pub const T4: Self = Self::R12;
    /// Temporary 5: Clobbered register
    pub const T5: Self = Self::R13;
    /// Temporary 6: Clobbered register
    pub const T6: Self = Self::R14;
    /// Temporary 7: Clobbered register
    pub const T7: Self = Self::R15;
    /// Saved 0: Saved register
    pub const S0: Self = Self::R16;
    /// Saved 1: Saved register
    pub const S1: Self = Self::R17;
    /// Saved 2: Saved register
    pub const S2: Self = Self::R18;
    /// Saved 3: Saved register
    pub const S3: Self = Self::R19;
    /// Saved 4: Saved register
    pub const S4: Self = Self::R20;
    /// Saved 5: Saved register
    pub const S5: Self = Self::R21;
    /// Saved 6: Saved register
    pub const S6: Self = Self::R22;
    /// Saved 6: Saved register
    pub const S7: Self = Self::R23;
    /// Temporary 8: Clobbered register
    pub const T8: Self = Self::R24;
    /// Temporary 9: Clobbered register
    pub const T9: Self = Self::R25;
    /// Kernel 0: Reserved by operating system
    pub const K0: Self = Self::R26;
    /// Kernel 1: Reserved by operating system
    pub const K1: Self = Self::R27;
    /// Global Pointer
    pub const Gp: Self = Self::R28;
    /// Stack Pointer
    pub const Sp: Self = Self::R29;
    /// Frame Pointer
    pub const Fp: Self = Self::R30;
    /// Return Address
    pub const Ra: Self = Self::R31;
}

lazy_static::lazy_static! {
    /// List of all [Mips32Register]s in uppercase string format
    static ref MIPS32_REGISTER_NAMES: HashMap<Mips32Register, String> = {
        Mips32Register::iter()
            .map(|reg| (reg, reg.to_string().to_uppercase()))
            .collect()
    };
}

create_special_register_enums!(Mips32);
