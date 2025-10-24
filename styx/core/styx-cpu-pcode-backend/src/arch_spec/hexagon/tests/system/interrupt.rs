// SPDX-License-Identifier: BSD-2-Clause
use log::trace;
use styx_cpu_type::{arch::hexagon::HexagonRegister, TargetExitReason};
use styx_processor::{
    cpu::{CpuBackend, CpuBackendExt},
    hooks::{CoreHandle, Hookable, StyxHook},
};

use crate::arch_spec::hexagon::tests::setup_objdump;

#[test]
fn test_trap0() {
    // This is here for reference, but if the TRAP_NUMBER is updated, then the
    // object dump should be updated as well. Unfortunately, Keystone doesn't
    // seem to understand many Hexagon instructions.
    const TRAP_NUMBER: i32 = 0x8;

    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
    0:	00 c1 00 54	5400c100 { 	trap0(#0x8) }
"#,
    );

    let handle_interrupt = |_backend: CoreHandle, irqn: i32| {
        trace!("trap0 handler, irqn was {irqn}");
        assert_eq!(TRAP_NUMBER, irqn);
        Ok(())
    };

    cpu.add_hook(StyxHook::interrupt(handle_interrupt)).unwrap();

    let report = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(
        report.exit_reason,
        TargetExitReason::InstructionCountComplete
    );
}

/// Clear interrupt auto disable (IAD) test
///
/// IAD is cleared based on the mask provided,
/// so we will set IAD, call ciad with a mask, and ensure the registers are cleared appropriately.
///
/// This test is almost the same as the CIAD test. It may change when we implement
/// the interrupt controller.
#[test]
fn test_ciad() {
    // We could mask this here, but it feels better to spell it out.
    const IAD_INITIAL: u32 = 0x11020f74;
    const MASK: u32 = 0x914;
    const RESULT: u32 = 0x11020660;

    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
       0:	60 c0 0a 64	640ac060 { 	ciad(r10) }
"#,
    );

    cpu.write_register(HexagonRegister::Iad, IAD_INITIAL)
        .unwrap();
    cpu.write_register(HexagonRegister::R10, MASK).unwrap();

    let report = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(
        report.exit_reason,
        TargetExitReason::InstructionCountComplete
    );

    let iad = cpu.read_register::<u32>(HexagonRegister::Iad).unwrap();

    assert_eq!(iad, RESULT);
}

/// Cancel pending interrupts
///
/// This clears IPEND based on the provided mask.
/// So we will set IPEND, call cswi with a mask, and ensure the registers are cleared appropriately.
///
/// This test is almost the same as the CIAD test. It may change when we implement
/// the interrupt controller.
#[test]
fn test_cswi() {
    // We could mask this here, but it feels better to spell it out.
    const IPEND_INITIAL: u32 = 0x11020f74;
    const MASK: u32 = 0x914;
    const RESULT: u32 = 0x11020660;

    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
       0:	20 c0 0a 64	640ac020 { 	cswi(r10) }
"#,
    );

    cpu.write_register(HexagonRegister::Ipend, IPEND_INITIAL)
        .unwrap();
    cpu.write_register(HexagonRegister::R10, MASK).unwrap();

    let report = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(
        report.exit_reason,
        TargetExitReason::InstructionCountComplete
    );

    let ipend = cpu.read_register::<u32>(HexagonRegister::Ipend).unwrap();

    assert_eq!(ipend, RESULT);
}
