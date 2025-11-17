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

#[test]
fn test_mem_load_halfword() {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
       0:	06 40 82 91	91824006 { 	r6 = memw(r2+#0x0)
       4:	81 c0 24 3c	3c24c081   	memh(r4+#0x2) = #0x1 } 
"#,
    );

    const ADDR2: u32 = 0x10000;
    const ADDR4: u32 = 0x20000;

    mmu.write_u32_le_virt_data(ADDR2 as u64, 0x99887766, &mut cpu)
        .unwrap();
    mmu.write_u32_le_virt_data(ADDR4 as u64, 0xbfbfbfbf, &mut cpu)
        .unwrap();

    cpu.write_register(HexagonRegister::R2, ADDR2).unwrap();
    cpu.write_register(HexagonRegister::R4, ADDR4 - 2).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let dat_read = mmu.read_u32_le_virt_data(ADDR4 as u64, &mut cpu).unwrap();
    let r6_read = cpu.read_register::<u32>(HexagonRegister::R6).unwrap();

    assert_eq!(dat_read, 0xbfbf0001);
    assert_eq!(r6_read, 0x99887766);
}
