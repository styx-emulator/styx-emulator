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
use styx_emulator::core::macros::enum_mirror;

/// An architecture at least partially supported by the Sytx emulator
#[enum_mirror(styx_emulator::core::cpu::Arch)]
#[repr(C)]
pub enum StyxArch {
    Aarch64,
    Arm,
    Blackfin,
    Mips32,
    Mips64,
    X86,
    Ppc32,
    Sparc,
    M68k,
    Riscv,
    Tricore,
    Sharc,
    Microblaze,
    Tms320C1x,
    Tms320C2x,
    Tms320C3x,
    Tms320C4x,
    Tms320C8x,
    Tms320C5x,
    Tms320C6x,
    Avr,
    SuperH,
    Pic,
    Arch80xx,
    Arch6502,
    Xtensa,
    Hcsxx,
    V850,
    Z80,
    Msp430,
    Msp430X,
    Hexagon,
}
