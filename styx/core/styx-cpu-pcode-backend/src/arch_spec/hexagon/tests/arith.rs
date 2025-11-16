// SPDX-License-Identifier: BSD-2-Clause
//! For arithmetic operations we had to implement

use crate::arch_spec::hexagon::tests::*;
use test_case::test_case;

// TODO: robustize
#[test_case(-392, 392; "negative_392")]
#[test_case(-8820920, 8820920; "negative_8820920")]
#[test_case(8128900, 8128900; "negative_8128900")]
#[test_case(-1, 1; "negative_1")]
#[test_case(-99283, 99283; "negative_99283")]
#[test_case(99283, 99283; "pos_99283")]
#[test_case(883, 883; "pos_883")]
#[test_case(39, 39; "pos_39")]
#[test_case(2, 2; "pos_2")]
pub fn test_abs_helper(inp: i32, out: i32) {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
       0:	80 c0 81 8c	8c81c080 { 	r0 = abs(r1) }
"#,
    );

    cpu.write_register(HexagonRegister::R1, inp as u32).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let r0 = cpu.read_register::<u32>(HexagonRegister::R0).unwrap() as i32;
    assert_eq!(r0, out);
}

// just a small range test
#[test]
pub fn test_abs_range() {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
       0:	80 c0 81 8c	8c81c080 { 	r0 = abs(r1) }
"#,
    );

    for i in -100000i32..100000 {
        cpu.write_register(HexagonRegister::R1, i as u32).unwrap();

        let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
        assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

        let r0 = cpu.read_register::<u32>(HexagonRegister::R0).unwrap() as i32;
        assert_eq!(r0, i.abs());

        cpu.set_pc(0x1000).unwrap();
    }
}

#[test]
pub fn testbit_reg() {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
       0:	00 c0 02 c7	c702c000 { 	p0 = tstbit(r2,r0) }
"#,
    );

    cpu.write_register(HexagonRegister::R2, 65536u32).unwrap();
    cpu.write_register(HexagonRegister::R0, 16u32).unwrap();
    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let p0 = cpu.read_register::<u8>(HexagonRegister::P0).unwrap();
    assert_eq!(p0, 0xff);
}

#[test]
pub fn testbit_reg_f() {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
       0:	00 c0 02 c7	c702c000 { 	p0 = tstbit(r2,r0) }
"#,
    );

    cpu.write_register(HexagonRegister::R2, 0b1_1111_1111_1100_1111u32)
        .unwrap();
    cpu.write_register(HexagonRegister::R0, 5u32).unwrap();
    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let p0 = cpu.read_register::<u8>(HexagonRegister::P0).unwrap();
    assert_eq!(p0, 0x00);
}

#[test]
pub fn testbit_reg_oob() {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
       0:	00 c0 02 c7	c702c000 { 	p0 = tstbit(r2,r0) }
"#,
    );

    cpu.write_register(HexagonRegister::R2, 0u32).unwrap();
    cpu.write_register(HexagonRegister::R0, 0x80du32).unwrap();
    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let p0 = cpu.read_register::<u8>(HexagonRegister::P0).unwrap();
    assert_eq!(p0, 0x00);
}

#[test]
pub fn asl_sub() {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
0:	80 c1 82 cc	cc82c180 { 	r0 -= asl(r2,r1) }
"#,
    );

    cpu.write_register(HexagonRegister::R1, 1u32).unwrap();
    cpu.write_register(HexagonRegister::R2, 4u32).unwrap();
    cpu.write_register(HexagonRegister::R0, 10u32).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let r0 = cpu.read_register::<u32>(HexagonRegister::R0).unwrap();
    assert_eq!(r0, 2u32);
}
