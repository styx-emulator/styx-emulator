// SPDX-License-Identifier: BSD-2-Clause
use crate::arch_spec::hexagon::tests::*;
use test_case::test_case;

// TODO: can we add a dual jump that requires sequencing?

#[test_case(0, 0, 5, 5; "both branches true")]
#[test_case(0, 0, 5, 4; "second branch true")]
#[test_case(1, 0, 5, 5; "first branch true")]
#[test_case(0, 1, 4, 5; "neither branch true")]
pub fn test_conditional_simple(r0: u32, r1: u32, r2: u32, r3: u32) {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
       0:	08 73 02 14	14027308 { 	p1 = cmp.eq(r2,r3); if (p1.new) jump:t 0x10
       4:	06 e1 00 14	1400e106   	p0 = cmp.eq(r0,r1); if (p0.new) jump:t 0xc }
       8:	85 c2 00 78	7800c285 { 	r5 = #0x14 }
       c:	05 c5 00 78	7800c505 { 	r5 = #0x28 }
      10:	45 cb 00 78	7800cb45 { 	r5 = #0x5a }
"#,
    );

    cpu.write_register(HexagonRegister::R0, r0).unwrap();
    cpu.write_register(HexagonRegister::R1, r1).unwrap();
    cpu.write_register(HexagonRegister::R2, r2).unwrap();
    cpu.write_register(HexagonRegister::R3, r3).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 2).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let r5 = cpu.read_register::<u32>(HexagonRegister::R5).unwrap();

    // If the first branch is true (r2 == r3), irregardless
    // of whether r0 == r1 or not, the first branch to 0x10 will be taken.
    if r2 == r3 {
        assert_eq!(r5, 90);
    } else if (r2 != r3) && (r0 == r1) {
        assert_eq!(r5, 40);
    } else {
        assert_eq!(r5, 20);
    }
}

#[test_case(32, 19; "conditional jump taken")]
#[test_case(11, 19; "unconditional jump taken")]
pub fn test_conditional_unconditional_simple(r0: u32, r1: u32) {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
       0:	08 71 80 14	14807108 { 	p1 = cmp.gt(r0,r1); if (p1.new) jump:t 0x10
       4:	06 40 00 58	58004006   	jump 0xc
       8:	06 c1 00 f3	f300c106   	r6 = add(r0,r1) }
       c:	05 c5 00 78	7800c505 { 	r5 = #0x28 }
      10:	45 cb 00 78	7800cb45 { 	r5 = #0x5a }
"#,
    );

    cpu.write_register(HexagonRegister::R0, r0).unwrap();
    cpu.write_register(HexagonRegister::R1, r1).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 2).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let r5 = cpu.read_register::<u32>(HexagonRegister::R5).unwrap();
    let r6 = cpu.read_register::<u32>(HexagonRegister::R6).unwrap();

    assert_eq!(r6, r0 + r1);

    // cond branch taken
    if r0 > r1 {
        assert_eq!(r5, 90)
    }
    // direct jump taken
    else {
        assert_eq!(r5, 40)
    }
}
