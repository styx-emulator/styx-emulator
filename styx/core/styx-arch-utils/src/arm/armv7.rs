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

use styx_cpu::arch::arm::ArmRegister;
use styx_processor::cpu::{CpuBackend, CpuBackendExt};

/// Reset the Current Program Status Register (CPSR).
///
/// See TakeReset() pseudocode in section B1.9.1 of the ARM Architecture Reference Manual, ARMv7-A
/// and ARMv7-R edition.
pub fn reset_cpsr(cpu: &mut dyn CpuBackend) {
    const MODE: u32 = 0x1_0011;
    const MODE_OFFSET: u32 = 0;

    // FIXME: Start in ARM mode for now. This can be Thumb based on SCTLR.TE.
    const T: u32 = 0;
    const T_OFFSET: u32 = 5;

    // Interrupt masks - all interrupts disabled.
    const F: u32 = 1;
    const F_OFFSET: u32 = 6;
    const I: u32 = 1;
    const I_OFFSET: u32 = 7;
    const A: u32 = 1;
    const A_OFFSET: u32 = 8;

    // FIXME: Default to little endian for now. Should be based on SCTLR.EE.
    const E: u32 = 0;
    const E_OFFSET: u32 = 9;

    // If-Then execution state bits for Thumb IT instruction.
    const IT: u32 = 0;
    const IT_OFFSET: u32 = 10;

    // Jazelle bit
    const J: u32 = 0;
    const J_OFFSET: u32 = 24;

    const CPSR: u32 = MODE << MODE_OFFSET
        | T << T_OFFSET
        | F << F_OFFSET
        | I << I_OFFSET
        | A << A_OFFSET
        | E << E_OFFSET
        | IT << IT_OFFSET
        | J << J_OFFSET;
    cpu.write_register(ArmRegister::Cpsr, CPSR).unwrap();
}
