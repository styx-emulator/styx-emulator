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
//! Generic top level container for ARM registers.
use crate::{
    arch::{CpuRegister, RegisterValue},
    macros::create_special_register_enums,
};
use std::num::NonZeroUsize;

crate::macros::create_basic_register_enums!(
    Blackfin,
    (Pc, 32),
    (R0, 32),
    (R1, 32),
    (R2, 32),
    (R3, 32),
    (R4, 32),
    (R5, 32),
    (R6, 32),
    (R7, 32),
    (P0, 32),
    (P1, 32),
    (P2, 32),
    (P3, 32),
    (P4, 32),
    (P5, 32),
    (Sp, 32),
    (Fp, 32),
    (I0, 32),
    (I1, 32),
    (I2, 32),
    (I3, 32),
    (L0, 32),
    (L1, 32),
    (L2, 32),
    (L3, 32),
    (B0, 32),
    (B1, 32),
    (B2, 32),
    (B3, 32),
    (M0, 32),
    (M1, 32),
    (M2, 32),
    (M3, 32),
    (A0, 40),
    (A0x, 32),
    (A0w, 32),
    (A1, 40),
    (A1x, 32),
    (A1w, 32),
    (LC0, 32),
    (LC1, 32),
    (LT0, 32),
    (LT1, 32),
    (LB0, 32),
    (LB1, 32),
    (ASTAT, 32),
    (CCflag, 8),
    (AZflag, 8),
    (ANflag, 8),
    (AQflag, 8),
    (RndModflag, 8),
    (AC0flag, 8),
    (AC1flag, 8),
    (AV0flag, 8),
    (AV0Sflag, 8),
    (AV1flag, 8),
    (AV1Sflag, 8),
    (Vflag, 8),
    (VSflag, 8),
    (RETI, 32),
    (RETN, 32),
    (RETX, 32),
    (RETE, 32),
    (RETS, 32),
);

create_special_register_enums!(Blackfin);
