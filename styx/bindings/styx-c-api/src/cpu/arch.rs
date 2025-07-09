// SPDX-License-Identifier: BSD-2-Clause
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
}
