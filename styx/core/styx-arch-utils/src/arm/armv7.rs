// SPDX-License-Identifier: BSD-2-Clause

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
