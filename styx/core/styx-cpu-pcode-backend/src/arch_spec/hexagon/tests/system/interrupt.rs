// SPDX-License-Identifier: BSD-2-Clause
use log::trace;
use styx_processor::{
    cpu::CpuBackend,
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
    cpu.execute(&mut mmu, &mut ev, 1).unwrap();
}
