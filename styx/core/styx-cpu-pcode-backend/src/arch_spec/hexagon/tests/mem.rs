// SPDX-License-Identifier: BSD-2-Clause
use crate::arch_spec::hexagon::tests::*;

#[test]
fn test_mem_signextend_byte() {
    let (mut cpu, mut mmu, mut ev) = setup_asm("{ r0 = memb(r1+r2<<#0); }", None);
    const WRITTEN: u8 = 0xff;
    const ADDR: u32 = 0x100;
    const OFF: u32 = 0x1;

    mmu.write_u8_be_virt_data((ADDR + OFF) as u64, WRITTEN, &mut cpu)
        .unwrap();

    cpu.write_register(HexagonRegister::R1, ADDR).unwrap();
    cpu.write_register(HexagonRegister::R2, OFF).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    // This needs to be sign extended
    let r0_read = cpu.read_register::<u32>(HexagonRegister::R0).unwrap();
    assert_eq!(r0_read, 0xffffffff);
}
