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
use std::num::NonZeroUsize;

use crate::arch::{CpuRegister, RegisterValue};
use crate::macros::*;

// Register List for SuperH systems
//
// Note the "banked" variants of the registers, See
// [this](https://sourceware.org/pipermail/gdb-patches/2004-September/037625.html) patch
// for more information on how GDB decided to implement a banked interface
// for the SH2A. Not that we implement the "Bank" register (Backend defined),
// but it is useful to think about once you start debugging a target in GDB.
// We currently label the banked registers as \<register\>b
//
// Please file an issue to provide feedback on how this architecture is implemented.
//
create_basic_register_enums!(
    SuperH,
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
    (Pc, 32),
    (Pr, 32),
    (Gbr, 32),
    (Vbr, 32),
    (Mach, 32),
    (Macl, 32),
    (Sr, 32),
    (Fpul, 32),
    (Fpscr, 32),
    (Fr0, 32),
    (Fr1, 32),
    (Fr2, 32),
    (Fr3, 32),
    (Fr4, 32),
    (Fr5, 32),
    (Fr6, 32),
    (Fr7, 32),
    (Fr8, 32),
    (Fr9, 32),
    (Fr10, 32),
    (Fr11, 32),
    (Fr12, 32),
    (Fr13, 32),
    (Fr14, 32),
    (Fr15, 32),
    (Ibcr, 32),
    (Ibnr, 32),
    (Tbr, 32),
    (R0b, 32),
    (R1b, 32),
    (R2b, 32),
    (R3b, 32),
    (R4b, 32),
    (R5b, 32),
    (R6b, 32),
    (R7b, 32),
    (R8b, 32),
    (R9b, 32),
    (R10b, 32),
    (R11b, 32),
    (R12b, 32),
    (R13b, 32),
    (R14b, 32),
    (Pcb, 32),
    (Prb, 32),
    (Gbrb, 32),
    (Vbrb, 32),
    (Machb, 32),
    (Maclb, 32),
    (Bank, 32),
    (Dr0, 64),
    (Dr2, 64),
    (Dr4, 64),
    (Dr6, 64),
    (Dr8, 64),
    (Dr10, 64),
    (Dr12, 64),
    (Dr14, 64),
    (Dsr, 32),
    (A0g, 32),
    (A0, 32),
    (A1g, 32),
    (A1, 32),
    (M0, 32),
    (M1, 32),
    (X0, 32),
    (X1, 32),
    (Y0, 32),
    (Y1, 32),
    (Mod, 32),
    (Rs, 32),
    (Re, 32),
    (Ssr, 32),
    (Spc, 32),
    (Ivnb, 32),
    (R0b0, 32),
    (R1b0, 32),
    (R2b0, 32),
    (R3b0, 32),
    (R4b0, 32),
    (R5b0, 32),
    (R6b0, 32),
    (R7b0, 32),
    (R0b1, 32),
    (R1b1, 32),
    (R2b1, 32),
    (R3b1, 32),
    (R4b1, 32),
    (R5b1, 32),
    (R6b1, 32),
    (R7b1, 32),
    (Fv0, 128),
    (Fv4, 128),
    (Fv8, 128),
    (Fv12, 128),
);

create_special_register_enums!(SuperH);

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_regs_from_str() {
        assert_eq!(
            SuperHRegister::Dr0,
            SuperHRegister::from_str("dr0").unwrap()
        );
        assert_eq!(
            SuperHRegister::R0b,
            SuperHRegister::from_str("r0B").unwrap()
        );
        assert_eq!(SuperHRegister::Sr, SuperHRegister::from_str("SR").unwrap());
        assert_eq!(SuperHRegister::Pc, SuperHRegister::from_str("Pc").unwrap());
        assert_eq!(SuperHRegister::Sr, SuperHRegister::from_str("sr").unwrap());
        assert_eq!(SuperHRegister::R0, SuperHRegister::from_str("R0").unwrap());
        assert_eq!(SuperHRegister::R0, SuperHRegister::from_str("r0").unwrap());
        assert_eq!(SuperHRegister::Pc, SuperHRegister::from_str("pc").unwrap());
    }
}
