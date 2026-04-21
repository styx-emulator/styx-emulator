// SPDX-License-Identifier: BSD-2-Clause
//! For arithmetic operations we had to implement

use crate::arch_spec::hexagon::tests::*;
use log::info;
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

    let p0 = cpu.read_register::<u8>(HexagonRegister::P0).unwrap() as i32;
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

/// Test togglebit instruction, which was previously broken
///
/// 11.10.2 XTYPE BIT
/// "When using a register to indicate the bit position and the value of the least-significant 7 bits of Rt
/// is out of range, the destination register is unchanged."
///
/// This implies we do not have to test, for exmaple, negative (in 2's complement)
/// register values.
#[test_case(0x1000, 0x5;"toggle_on")]
#[test_case(0x1020, 0x5;"toggle_off")]
pub fn togglebit_r(r0: u32, r1: u32) {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
       0:	82 c1 80 c6	c680c182 { 	r2 = togglebit(r0,r1) }
"#,
    );

    cpu.write_register(HexagonRegister::R1, r1).unwrap();
    cpu.write_register(HexagonRegister::R0, r0).unwrap();
    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let r2 = cpu.read_register::<u32>(HexagonRegister::R2).unwrap();
    assert_eq!(r2, r0 ^ (1 << r1));
}

/// Test clrbit instruction, which was previously broken.
///
/// 11.10.2 XTYPE BIT
/// "When using a register to indicate the bit position and the value of the least-significant 7 bits of Rt
/// is out of range, the destination register is unchanged."
///
/// This implies we do not have to test, for exmaple, negative (in 2's complement)
/// register values.
#[test_case(0x1020, 0x5, 0x1000;"already_set")]
#[test_case(0x1000, 0x5, 0x1000;"not_set")]
pub fn clearbit_r(r0: u32, r1: u32, expected: u32) {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
       0:	42 c1 80 c6	c680c142 { 	r2 = clrbit(r0,r1) }
"#,
    );

    cpu.write_register(HexagonRegister::R1, r1).unwrap();
    cpu.write_register(HexagonRegister::R0, r0).unwrap();
    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let r2 = cpu.read_register::<u32>(HexagonRegister::R2).unwrap();
    assert_eq!(r2, expected);
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

// test 64-bit absolute value
#[test]
pub fn test_abs64_range() {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
        0:	c6 c0 84 80	8084c0c6 { 	r7:6 = abs(r5:4) }
"#,
    );

    const NUMS_TO_TRY: i64 = 1000000i64;

    for i in -10000000000i64..(-10000000000i64 + NUMS_TO_TRY) {
        cpu.write_register(HexagonRegister::D2, i as u64).unwrap();

        let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
        assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

        let r7r6 = cpu.read_register::<u64>(HexagonRegister::D3).unwrap() as i64;
        assert_eq!(r7r6, i.abs());

        cpu.set_pc(0x1000).unwrap();
    }

    for i in (10000000000i64 - NUMS_TO_TRY)..10000000000i64 {
        cpu.write_register(HexagonRegister::D2, i as u64).unwrap();

        let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
        assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

        let r7r6 = cpu.read_register::<u64>(HexagonRegister::D3).unwrap() as i64;
        assert_eq!(r7r6, i.abs());

        cpu.set_pc(0x1000).unwrap();
    }
}

#[test]
pub fn vmux() {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
0:	04 c6 02 d1	d102c604 { 	r5:4 = vmux(p0,r3:2,r7:6) }
"#,
    );

    // R2R3
    cpu.write_register(HexagonRegister::D1, 0x55aabbccddeeff66u64)
        .unwrap();
    // R6R7
    cpu.write_register(HexagonRegister::D3, 0x1122334466778899u64)
        .unwrap();
    // Predicate
    cpu.write_register(HexagonRegister::P0, 0b11010101u32)
        .unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    // R4R5
    let r4r5 = cpu.read_register::<u64>(HexagonRegister::D2).unwrap();
    assert_eq!(r4r5, 0x55aa33cc66ee8866);
}

// just a small range test
#[test_case(0xafab8673, 0xaf78557c, 0xaf785540; "rx_all_ones")]
#[test_case(0xafab8673, 0xaf785558, 0xaf785540; "rx_some_ones")]
pub fn tableidxw(r4: u32, r5: u32, r5_expected: u32) {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
       0:	a5 c9 84 87	8784c9a5 { 	r5 = tableidxw(r4,#0x5,#0x9):raw } 
"#,
    );
    cpu.write_register(HexagonRegister::R4, r4).unwrap();
    cpu.write_register(HexagonRegister::R5, r5).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let r5 = cpu.read_register::<u32>(HexagonRegister::R5).unwrap();
    assert_eq!(r5, r5_expected);
}

/// Some manual test cases in case the "corresponding u64" in the mask_all
/// is computed wrong
#[test_case(0b01011010, 0x00ff00ffff00ff00; "mask_four_bits_set")]
#[test_case(0b11001100, 0xffff0000ffff0000; "mask_some_bits_set")]
pub fn mask(p0: u8, r1_r0_expected: u64) {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
	0:	00 c0 00 86	8600c000 { 	r1:0 = mask(p0) }
"#,
    );

    cpu.write_register(HexagonRegister::P0, p0).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let d0 = cpu.read_register::<u64>(HexagonRegister::D0).unwrap();
    assert_eq!(r1_r0_expected, d0);
}

/// Mask only has 256 possible inputs, so why not test them all?
#[test]
pub fn mask_all() {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
	0:	00 c0 00 86	8600c000 { 	r1:0 = mask(p0) }
"#,
    );

    for i in 0u8..=255 {
        cpu.set_pc(0x1000).unwrap();

        let mut corresp_u64 = 0;
        for j in 0..8 {
            if ((i >> j) & 1) == 1 {
                corresp_u64 |= (0xff << (j * 8));
            }
        }

        info!("iter {i}");
        cpu.write_register(HexagonRegister::P0, i).unwrap();

        let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
        assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

        let d0 = cpu.read_register::<u64>(HexagonRegister::D0).unwrap();
        assert_eq!(corresp_u64, d0);
    }
}

/// Some manual test cases in case the "corresponding u64" in the mask_all
/// is computed wrong
#[test_case(0x00, 0xff; "zero")]
pub fn not(p0: u8, p0_expected: u8) {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
	0:	00 c0 c0 6b	6bc0c000 { 	p0 = not(p0) }
"#,
    );

    cpu.write_register(HexagonRegister::P0, p0).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let p0_result = cpu.read_register::<u8>(HexagonRegister::P0).unwrap();
    assert_eq!(p0_result, p0_expected);
}
