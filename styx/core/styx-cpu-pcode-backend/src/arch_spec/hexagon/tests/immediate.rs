// SPDX-License-Identifier: BSD-2-Clause
use crate::arch_spec::hexagon::tests::*;

#[test]
fn test_immediates() {
    const WRITTEN: u32 = 0x29177717;
    // this should be something that is small,
    // to make sure that the previous immext being set doesn't
    // interfere somehow?
    const WRITTEN2: u32 = 12;
    const R0VAL: u32 = 21;
    let (mut cpu, mut mmu, mut ev) = setup_asm(
        &format!(
            "{{ r1 = add(r0, #{WRITTEN}); }}; {{ r2 = add(r1, #{WRITTEN2}) }}; {{ r3 = add(r1, r2); }}; {{ r4 = r2; }};"
        ),
        None,
    );
    cpu.write_register(HexagonRegister::R0, R0VAL).unwrap();

    // We'll have two instructions for each immext, and then the second instruction
    // doesn't have an immediate _extension_ so we're good on that end, total
    // 5 instructions
    let exit = cpu.execute(&mut mmu, &mut ev, 4).unwrap();

    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let r1 = cpu.read_register::<u32>(HexagonRegister::R1).unwrap();
    let r2 = cpu.read_register::<u32>(HexagonRegister::R2).unwrap();
    let r3 = cpu.read_register::<u32>(HexagonRegister::R3).unwrap();
    let r4 = cpu.read_register::<u32>(HexagonRegister::R4).unwrap();

    // I don't think there's any overflow here, but if the
    // test cases are changed we should be careful
    assert_eq!(r1, WRITTEN + R0VAL);
    assert_eq!(r2, WRITTEN2 + r1);
    assert_eq!(r3, r1 + r2);
    assert_eq!(r4, r2);
}

#[test]
fn test_duplex_immext_fiveinsn() {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
       0:	d4 58 43 8e	8e4358d4 { 	r20 |= asl(r3,#0x18)
       4:	00 40 00 7f	7f004000   	nop
       8:	00 40 00 0c	0c004000   	immext(#0xc0000000)
       c:	50 39 0d 28	280d3950   	r21 = ##0xc0000000; 	p0 = cmp.eq(r5,#0x0) }
"#,
    );

    cpu.write_register(HexagonRegister::R3, 0b1011u32).unwrap();
    cpu.write_register(HexagonRegister::R20, 0b0001u32).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let r20 = cpu.read_register::<u32>(HexagonRegister::R20).unwrap();
    let r21 = cpu.read_register::<u32>(HexagonRegister::R21).unwrap();
    let p0 = cpu.read_register::<u8>(HexagonRegister::P0).unwrap();

    assert_eq!(r20, 0b00001011_00000000_00000000_00000001);
    assert_eq!(r21, 0xc0000000);
    assert_eq!(p0, 0xff);
}

#[test]
fn test_immediate_instruction() {
    const WRITTEN: u32 = 0x29177717;
    const R0VAL: u32 = 21;
    let (mut cpu, mut mmu, mut ev) = setup_asm(&format!("{{ r1 = add(r0, #{WRITTEN}); }}"), None);
    cpu.write_register(HexagonRegister::R0, R0VAL).unwrap();

    // We'll have two instructions for immext
    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();

    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let r1 = cpu.read_register::<u32>(HexagonRegister::R1).unwrap();

    assert_eq!(r1, WRITTEN + R0VAL);
}
