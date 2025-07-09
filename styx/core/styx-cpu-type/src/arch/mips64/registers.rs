// SPDX-License-Identifier: BSD-2-Clause
//! Generic top level container for Mips64 registers
use std::{collections::HashMap, num::NonZeroUsize};
use strum::IntoEnumIterator;

use crate::arch::{CpuRegister, RegisterValue};
use crate::macros::*;

// here's some nice docstrings for some individual registers
//
//    /// (cnMIPS) Multiplier 0
//    Mpl0,
//    /// (cnMIPS) Multiplier 1
//    Mpl1,
//    /// (cnMIPS) Multiplier 2
//    Mpl2,
//    /// (cnMIPS) Product 0
//    P0,
//    /// (cnMIPS) Product 1
//    P1,
//    /// (cnMIPS) Product 2
//    P2,
//    /// (cnMIPS) CRC32 IV
//    CrcIV,
//    /// (cnMIPS) CRC32 Polynomial
//    CrcPoly,
//    /// (cnMIPS) CRC32 Length (Number of bytes to add)
//    CrcLen,
//    //
//    // start cnMIPS+Crypto registers (present in the -SSP cpu models)
//    //
//    // cnMIPS Galois Field Multiplier instructions
//    /// (cnMIPS) GFM Multiplier
//    /// (Not Present in non crypto cnMIPS variants `-SP` instead of `-SSP`)
//    GfmMul,
//    /// (cnMIPS) GFM Result/Input
//    /// (Not Present in non crypto cnMIPS variants `-SP` instead of `-SSP`)
//    GfmResInp,
//    /// (cnMIPS) GFM Polynomial
//    /// (Not Present in non crypto cnMIPS variants `-SP` instead of `-SSP`)
//    GfmPoly,
//    /// (cnMIPS) Hash Input Data
//    /// (Not Present in non crypto cnMIPS variants `-SP` instead of `-SSP`)
//    HashDat,
//    /// (cnMIPS) Hash IV
//    /// (Not Present in non crypto cnMIPS variants `-SP` instead of `-SSP`)
//    HashIV,
//    /// (cnMIPS) 3DES Key
//    /// (Not Present in non crypto cnMIPS variants `-SP` instead of `-SSP`)
//    ThreeDESKey,
//    /// (cnMIPS) 3DES IV
//    /// (Not Present in non crypto cnMIPS variants `-SP` instead of `-SSP`)
//    ThreeDESIV,
//    /// (cnMIPS) 3DES Result
//    /// (Not Present in non crypto cnMIPS variants `-SP` instead of `-SSP`)
//    ThreeDESResult,
//    /// (cnMIPS) AES Key
//    /// (Not Present in non crypto cnMIPS variants `-SP` instead of `-SSP`)
//    AesKey,
//    /// (cnMIPS) AES Key Length Indicator
//    /// (Not Present in non crypto cnMIPS variants `-SP` instead of `-SSP`)
//    AesKeyLen,
//    /// (cnMIPS) AES IV
//    /// (Not Present in non crypto cnMIPS variants `-SP` instead of `-SSP`)
//    AesIV,
//    /// (cnMIPS) AES Result/Input
//    /// (Not Present in non crypto cnMIPS variants `-SP` instead of `-SSP`)
//    AesResInp,
//    //
//    // end cnMIPS+Crypto
//    //
//    /// (cnMIPS) Local Scratchpad Memory
//    CvmsegLm,
create_basic_register_enums!(
    Mips64,
    (R0, 64),
    (R1, 64),
    (R2, 64),
    (R3, 64),
    (R4, 64),
    (R5, 64),
    (R6, 64),
    (R7, 64),
    (R8, 64),
    (R9, 64),
    (R10, 64),
    (R11, 64),
    (R12, 64),
    (R13, 64),
    (R14, 64),
    (R15, 64),
    (R16, 64),
    (R17, 64),
    (R18, 64),
    (R19, 64),
    (R20, 64),
    (R21, 64),
    (R22, 64),
    (R23, 64),
    (R24, 64),
    (R25, 64),
    (R26, 64),
    (R27, 64),
    (R28, 64),
    (R29, 64),
    (R30, 64),
    (R31, 64),
    (Lo, 64),
    (Hi, 64),
    (Pc, 64),
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
    (Fir, 64),
    (Fccr, 64),
    (Fexr, 64),
    (Fenr, 64),
    (Fcsr, 64),
    (Ac0, 64),
    (Ac1, 64),
    (Ac2, 64),
    (Ac3, 64),
    (Hi0, 64),
    (Hi1, 64),
    (Hi2, 64),
    (Hi3, 64),
    (Lo0, 64),
    (Lo1, 64),
    (Lo2, 64),
    (Lo3, 64),
    (DSPControl, 64),
    (Mpl0, 64),
    (Mpl1, 64),
    (Mpl2, 64),
    (P0, 64),
    (P1, 64),
    (P2, 64),
    (CrcIV, 64),
    (CrcPoly, 64),
    (CrcLen, 64),
    (GfmMul, 64),
    (GfmResInp, 64),
    (GfmPoly, 64),
    (HashDat, 64),
    (HashIV, 64),
    (ThreeDESKey, 64),
    (ThreeDESIV, 64),
    (ThreeDESResult, 64),
    (AesKey, 64),
    (AesKeyLen, 64),
    (AesIV, 64),
    (AesResInp, 64),
    (CvmsegLm, 64),
);
#[allow(unused)]
#[allow(non_upper_case_globals)]
impl Mips64Register {
    /// Always Zero
    pub const Zero: Self = Self::R0;
    /// Reserved for Assembler
    pub const At: Self = Self::R1;
    /// Value 0: Stores results
    pub const V0: Self = Self::R2;
    /// Value 1: Stores results
    pub const V1: Self = Self::R3;
    /// Argument 0: Stores Arguments
    pub const A0: Self = Self::R4;
    /// Argument 1: Stores Arguments
    pub const A1: Self = Self::R5;
    /// Argument 2: Stores Arguments
    pub const A2: Self = Self::R6;
    /// Argument 3: Stores Arguments
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
    /// List of all [Mips64Register]s in uppercase string format
    static ref MIPS64_REGISTER_NAMES: HashMap<Mips64Register, String> = {
        Mips64Register::iter()
            .map(|reg| (reg, reg.to_string().to_uppercase()))
            .collect()
    };
}

create_special_register_enums!(Mips64);
