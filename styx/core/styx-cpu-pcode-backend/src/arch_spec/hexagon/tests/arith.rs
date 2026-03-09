// SPDX-License-Identifier: BSD-2-Clause
//! For arithmetic operations we had to implement

use crate::arch_spec::hexagon::tests::*;
use log::info;
use test_case::test_case;

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

/// Test absolute value instruction for a range of different values.
/// More robust than the `test_abs_helper` function.
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
pub fn brev_64() {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
        0:	c6 c0 c4 80	80c4c0c6 { 	r7:6 = brev(r5:4) }
"#,
    );

    const ITERS: u64 = 10000;

    let mut run_check_val = |val: u64| {
        cpu.write_register(HexagonRegister::D2, val).unwrap();

        let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
        assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

        let r7r6 = cpu.read_register::<u64>(HexagonRegister::D3).unwrap();
        trace!("brev want val {val:64b} rev {:64b}", val.reverse_bits());
        assert_eq!(r7r6, val.reverse_bits());

        cpu.set_pc(0x1000).unwrap();
    };

    for val in (u64::MAX - ITERS)..u64::MAX {
        run_check_val(val);
    }

    for val in 0..ITERS {
        run_check_val(val);
    }
}

#[test]
pub fn cl1_32() {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
        0:	c1 c0 00 8c	8c00c0c1 { 	r1 = cl1(r0) }
"#,
    );

    const ITERS: u32 = 10000;

    let mut run_check_val = |val: u32| {
        cpu.write_register(HexagonRegister::R0, val).unwrap();

        let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
        assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

        let r1 = cpu.read_register::<u32>(HexagonRegister::R1).unwrap();
        trace!("brev want val {val:32b} rev {:32b}", val.leading_ones());
        assert_eq!(r1, val.leading_ones());

        cpu.set_pc(0x1000).unwrap();
    };

    for val in (u32::MAX - ITERS)..u32::MAX {
        run_check_val(val);
    }

    for val in 0..ITERS {
        run_check_val(val);
    }
}

#[test]
pub fn cl1_64() {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
        0:	81 c0 42 88	8842c081 { 	r1 = cl1(r3:2) }
"#,
    );

    const ITERS: u64 = 10000;

    let mut run_check_val = |val: u64| {
        cpu.write_register(HexagonRegister::D1, val).unwrap();

        let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
        assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

        let r1 = cpu.read_register::<u32>(HexagonRegister::R1).unwrap();
        trace!("brev want val {val:32b} rev {:32b}", val.leading_ones());
        assert_eq!(r1, val.leading_ones());

        cpu.set_pc(0x1000).unwrap();
    };

    for val in (u64::MAX - ITERS)..u64::MAX {
        run_check_val(val);
    }

    for val in 0..ITERS {
        run_check_val(val);
    }
}

#[test]
pub fn brev_32() {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
        0:	c7 c0 45 8c	8c45c0c7 { 	r7 = brev(r5) }
"#,
    );

    const ITERS: u32 = 10000;

    let mut run_check_val = |val: u32| {
        cpu.write_register(HexagonRegister::R5, val).unwrap();

        let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
        assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

        let r7 = cpu.read_register::<u32>(HexagonRegister::R7).unwrap();
        trace!("brev want val {val:32b} rev {:32b}", val.reverse_bits());
        assert_eq!(r7, val.reverse_bits());

        cpu.set_pc(0x1000).unwrap();
    };

    for val in (u32::MAX - ITERS)..u32::MAX {
        run_check_val(val);
    }

    for val in 0..ITERS {
        run_check_val(val);
    }
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
    cpu.write_register(HexagonRegister::P0, 0b11010101u8)
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

/// These should be sign-extended.
// We want to set the "in" register such that a sign extension occurs
#[test_case(
	r#"
       0:	02 c4 00 80	8000c402 { 	r3:2 = asr(r1:0,#0x4) }
	"#, 0x8000000000000000, HexagonRegister::D1, 0, 0xf800000000000000; "S2_asr_i_p"
)]
#[test_case(
	r#"
       0:	84 c4 00 82	8200c484 { 	r5:4 += asr(r1:0,#0x4) }
	"#, 0x8000000000000000, HexagonRegister::D2, 0, 0xf800000000000000; "S2_asr_i_p_acc"
)]
#[test_case(
	r#"
       0:	04 c4 00 82	8200c404 { 	r5:4 -= asr(r1:0,#0x4) }
	"#, 0x8000000000000000, HexagonRegister::D2, 0xf000000000000000u64, 0xf800000000000000; "S2_asr_i_p_nac"
)]
#[test_case(
	r#"
       0:	04 c4 40 82	8240c404 { 	r5:4 &= asr(r1:0,#0x4) }
	"#, 0x8000000000000000, HexagonRegister::D2, u64::MAX, 0xf800000000000000; "S2_asr_i_p_and"
)]
#[test_case(
	r#"
       0:	84 c4 40 82	8240c484 { 	r5:4 |= asr(r1:0,#0x4) }
	"#, 0x8000000000000000, HexagonRegister::D2, 0, 0xf800000000000000; "S2_asr_i_p_or"
)]
#[test_case(
	r#"
       0:	e2 c4 c0 80	80c0c4e2 { 	r3:2 = asr(r1:0,#0x4):rnd }
	"#, 0x8000000000000010, HexagonRegister::D1, 0, 0xfc00000000000001; "S2_asr_i_p_rnd"
)]
fn arithmetic_shift_right_doubleword(
    objdump: &str,
    in_reg_startval: u64,
    out_reg: HexagonRegister,
    out_reg_startval: u64,
    expected_output: u64,
) {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(objdump);
    cpu.write_register(HexagonRegister::D0, in_reg_startval)
        .unwrap();
    cpu.write_register(out_reg, out_reg_startval).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let out_reg_endval = cpu.read_register::<u64>(out_reg).unwrap();
    assert_eq!(out_reg_endval, expected_output);
}

/// Tests vector arithmetic shift right instructions that were previously broken.
///
/// Other broken instructions include:
///
/// asr_r_vh, but not implemented (in pcode)
/// asrhub_rnd_sat, but not implemented (in pcode)
/// asrhub_sat, but not implemneted (in pcode)
#[test_case(
	r#"
       0:	02 c4 80 80	8080c402 { 	r3:2 = vasrh(r1:0,#0x4) }
	"#, 0x8000800080008000, 0xf800f800f800f800; "S2_asr_i_vh"
)]
#[test_case(
	r#"
       0:	02 c4 20 80	8020c402 { 	r3:2 = vasrh(r1:0,#0x4):raw }
	"#, 0x8010801080108010, 0xfc01fc01fc01fc01; "S5_vasrhrnd"
)]
#[test_case(
	r#"
       0:	02 c4 40 80	8040c402 { 	r3:2 = vasrw(r1:0,#0x4) }
	"#, 0x8000000080000000, 0xf8000000f8000000; "S2_asr_i_vw"
)]
#[test_case(
	r#"
       0:	02 c4 00 c3	c300c402 { 	r3:2 = vasrw(r1:0,r4) }
	"#, 0x8000000080000000, 0xf8000000f8000000; "S2_asr_r_vw"
)]
fn vector_asr_doubleword(objdump: &str, in_reg_val: u64, out_val_expected: u64) {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(objdump);

    cpu.write_register(HexagonRegister::D0, in_reg_val).unwrap();
    cpu.write_register(HexagonRegister::R4, 4u32).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let out_reg_endval = cpu.read_register::<u64>(HexagonRegister::D1).unwrap();
    assert_eq!(out_reg_endval, out_val_expected);
}

#[test_case(
	r#"
       0:	42 d2 c0 88	88c0d242 { 	r2 = vasrw(r1:0,#0x12) }
	"#, 0x8000000080000000, 0xe000e000; "S2_asr_i_svw_trun"
)]
#[test_case(
	r#"
       0:	42 c4 00 c5	c500c442 { 	r2 = vasrw(r1:0,r4) }
	"#, 0x8000000080000000, 0xe000e000; "S2_asr_r_svw_trun"
)]
fn vector_asr_word(objdump: &str, in_reg_val: u64, out_val_expected: u32) {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(objdump);

    cpu.write_register(HexagonRegister::D0, in_reg_val).unwrap();
    cpu.write_register(HexagonRegister::R4, 18u32).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let out_reg_endval = cpu.read_register::<u32>(HexagonRegister::R2).unwrap();
    assert_eq!(out_reg_endval, out_val_expected);
}

#[test_case(
	r#"
       0:	01 c4 00 8c	8c00c401 { 	r1 = asr(r0,#0x4) }
	"#, 0x80000000, HexagonRegister::R1, 0, 0xf8000000; "S2_asr_i_r"
)]
#[test_case(
	r#"
       0:	02 c4 40 8e	8e40c402 { 	r2 &= asr(r0,#0x4) }
	"#, 0x80000000, HexagonRegister::R2, u32::MAX, 0xf8000000; "S2_asr_i_r_and"
)]
#[test_case(
	r#"
       0:	82 c4 40 8e	8e40c482 { 	r2 |= asr(r0,#0x4) }
	"#, 0x80000000, HexagonRegister::R2, 0, 0xf8000000; "S2_asr_i_r_or"
)]
#[test_case(
	r#"
       0:	01 c4 40 8c	8c40c401 { 	r1 = asr(r0,#0x4):rnd }
	"#, 0x80000010, HexagonRegister::R1, 0, 0xfc000001; "S2_asr_i_r_rnd"
)]
#[test_case(
	r#"
       0:	82 c4 00 8e	8e00c482 { 	r2 += asr(r0,#0x4) }
	"#, 0x80000000, HexagonRegister::R2, 0, 0xf8000000; "S2_asr_i_r_acc"
)]
#[test_case(
	r#"
       0:	02 c4 00 8e	8e00c402 { 	r2 -= asr(r0,#0x4) }
	"#, 0x80000000, HexagonRegister::R2, 0xf0000000, 0xf8000000; "S2_asr_i_r_nac"
)]
fn arithmetic_shift_right_word(
    objdump: &str,
    in_reg_startval: u32,
    out_reg: HexagonRegister,
    out_reg_startval: u32,
    expected_output: u32,
) {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(objdump);
    cpu.write_register(HexagonRegister::R0, in_reg_startval)
        .unwrap();
    cpu.write_register(out_reg, out_reg_startval).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let out_reg_endval = cpu.read_register::<u32>(out_reg).unwrap();
    assert_eq!(out_reg_endval, expected_output);
}

// Order of operations test cases require both the operation
// (arithmetic/logical) shift left/right. Then there is an operation,
// which is performed at the wrong time, thereby yielding an unsatisfactory result.

/// The operation enum, describing what operation to do
#[derive(Copy, Clone)]
pub enum OOOperation {
    ArithmeticShiftLeft,
    LogicalShiftLeft,
    ArithmeticShiftRight,
    LogicalShiftRight,
    MulSignExtend,
    MulZeroExtend,
}

/// Post-operation
#[derive(Debug, Copy, Clone)]
pub enum OOPostOperation {
    Add,
    And,
    Or,
    Xor,
    Sub,
    None,
}

#[test_case(
	r#"
       0:	02 c3 80 cc	cc80c302 { 	r2 -= asr(r0,r3) }
	"#, OOOperation::ArithmeticShiftRight, OOPostOperation::Sub; "S2_asr_r_r_nac"
)]
#[test_case(
	r#"
       0:	82 c3 80 cc	cc80c382 { 	r2 -= asl(r0,r3) }
	"#, OOOperation::ArithmeticShiftLeft, OOPostOperation::Sub; "S2_asl_r_r_nac"
)]
#[test_case(
	r#"
       0:	42 c3 80 cc	cc80c342 { 	r2 -= lsr(r0,r3) }
	"#, OOOperation::LogicalShiftRight, OOPostOperation::Sub; "S2_lsr_r_r_nac"
)]
#[test_case(
	r#"
       0:	c2 c3 80 cc	cc80c3c2 { 	r2 -= lsl(r0,r3) }
	"#, OOOperation::LogicalShiftLeft, OOPostOperation::Sub; "S2_lsl_r_r_nac"
)]
#[test_case(
	r#"
       0:	02 c3 40 cc	cc40c302 { 	r2 &= asr(r0,r3) }
	"#, OOOperation::ArithmeticShiftRight, OOPostOperation::And; "S2_asr_r_r_and"
)]
#[test_case(
	r#"
       0:	82 c3 40 cc	cc40c382 { 	r2 &= asl(r0,r3) }
	"#, OOOperation::ArithmeticShiftLeft, OOPostOperation::And; "S2_asl_r_r_and"
)]
#[test_case(
	r#"
       0:	42 c3 40 cc	cc40c342 { 	r2 &= lsr(r0,r3) }
	"#, OOOperation::LogicalShiftRight, OOPostOperation::And; "S2_lsr_r_r_and"
)]
#[test_case(
	r#"
       0:	c2 c3 40 cc	cc40c3c2 { 	r2 &= lsl(r0,r3) }
	"#, OOOperation::LogicalShiftLeft, OOPostOperation::And; "S2_lsl_r_r_and"
)]
#[test_case(
	r#"
       0:	02 c3 00 cc	cc00c302 { 	r2 |= asr(r0,r3) }
	"#, OOOperation::ArithmeticShiftRight, OOPostOperation::Or; "S2_asr_r_r_or"
)]
#[test_case(
	r#"
       0:	82 c3 00 cc	cc00c382 { 	r2 |= asl(r0,r3) }
	"#, OOOperation::ArithmeticShiftLeft, OOPostOperation::Or; "S2_asl_r_r_or"
)]
#[test_case(
	r#"
       0:	42 c3 00 cc	cc00c342 { 	r2 |= lsr(r0,r3) }
	"#, OOOperation::LogicalShiftRight, OOPostOperation::Or; "S2_lsr_r_r_or"
)]
#[test_case(
	r#"
       0:	c2 c3 00 cc	cc00c3c2 { 	r2 |= lsl(r0,r3) }
	"#, OOOperation::LogicalShiftLeft, OOPostOperation::Or; "S2_lsl_r_r_or"
)]
fn order_of_operations_32(objdump: &str, op: OOOperation, post_op: OOPostOperation) {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(objdump);

    for i in 1..1000 {
        order_of_operations_helper(&mut cpu, &mut mmu, &mut ev, op, post_op, 4, 0xea43, i, 5);
        order_of_operations_helper(
            &mut cpu,
            &mut mmu,
            &mut ev,
            op,
            post_op,
            4,
            -2i64 as u64,
            i,
            5,
        );
    }
    for i in (u32::MAX - 1000)..u32::MAX {
        order_of_operations_helper(
            &mut cpu, &mut mmu, &mut ev, op, post_op, 4, 0xea43, i as u64, 5,
        );
        order_of_operations_helper(
            &mut cpu,
            &mut mmu,
            &mut ev,
            op,
            post_op,
            4,
            -2i64 as u64,
            i as u64,
            5,
        );
    }
}

#[test_case(
	r#"
       0:	8a c3 cc cb	cbccc38a { 	r11:10 += asl(r13:12,r3) }
	"#, OOOperation::ArithmeticShiftLeft, OOPostOperation::Add; "S2_asl_r_p_acc"
)]
#[test_case(
	r#"
       0:	4a c3 cc cb	cbccc34a { 	r11:10 += lsr(r13:12,r3) }
	"#, OOOperation::LogicalShiftRight, OOPostOperation::Add; "S2_lsr_r_p_acc"
)]
#[test_case(
	r#"
       0:	ca c3 cc cb	cbccc3ca { 	r11:10 += lsl(r13:12,r3) }
	"#, OOOperation::LogicalShiftLeft, OOPostOperation::Add; "S2_lsl_r_p_acc"
)]
#[test_case(
	r#"
       0:	0a c3 8c cb	cb8cc30a { 	r11:10 -= asr(r13:12,r3) }
	"#, OOOperation::ArithmeticShiftRight, OOPostOperation::Sub; "S2_asr_r_p_nac"
)]
#[test_case(
	r#"
       0:	8a c3 8c cb	cb8cc38a { 	r11:10 -= asl(r13:12,r3) }
	"#, OOOperation::ArithmeticShiftLeft, OOPostOperation::Sub; "S2_asl_r_p_nac"
)]
#[test_case(
	r#"
       0:	4a c3 8c cb	cb8cc34a { 	r11:10 -= lsr(r13:12,r3) }
	"#, OOOperation::LogicalShiftRight, OOPostOperation::Sub; "S2_lsr_r_p_nac"
)]
#[test_case(
	r#"
       0:	ca c3 8c cb	cb8cc3ca { 	r11:10 -= lsl(r13:12,r3) }
	"#, OOOperation::LogicalShiftLeft, OOPostOperation::Sub; "S2_lsl_r_p_nac"
)]
#[test_case(
	r#"
       0:	0a c3 4c cb	cb4cc30a { 	r11:10 &= asr(r13:12,r3) }
	"#, OOOperation::ArithmeticShiftRight, OOPostOperation::And; "S2_asr_r_p_and"
)]
#[test_case(
	r#"
       0:	8a c3 4c cb	cb4cc38a { 	r11:10 &= asl(r13:12,r3) }
	"#, OOOperation::ArithmeticShiftLeft, OOPostOperation::And; "S2_asl_r_p_and"
)]
#[test_case(
	r#"
       0:	4a c3 4c cb	cb4cc34a { 	r11:10 &= lsr(r13:12,r3) }
	"#, OOOperation::LogicalShiftRight, OOPostOperation::And; "S2_lsr_r_p_and"
)]
#[test_case(
	r#"
       0:	ca c3 4c cb	cb4cc3ca { 	r11:10 &= lsl(r13:12,r3) }
	"#, OOOperation::LogicalShiftLeft, OOPostOperation::And; "S2_lsl_r_p_and"
)]
#[test_case(
	r#"
       0:	0a c3 0c cb	cb0cc30a { 	r11:10 |= asr(r13:12,r3) }
	"#, OOOperation::ArithmeticShiftRight, OOPostOperation::Or; "S2_asr_r_p_or"
)]
#[test_case(
	r#"
       0:	8a c3 0c cb	cb0cc38a { 	r11:10 |= asl(r13:12,r3) }
	"#, OOOperation::ArithmeticShiftLeft, OOPostOperation::Or; "S2_asl_r_p_or"
)]
#[test_case(
	r#"
       0:	4a c3 0c cb	cb0cc34a { 	r11:10 |= lsr(r13:12,r3) }
	"#, OOOperation::LogicalShiftRight, OOPostOperation::Or; "S2_lsr_r_p_or"
)]
#[test_case(
	r#"
       0:	ca c3 0c cb	cb0cc3ca { 	r11:10 |= lsl(r13:12,r3) }
	"#, OOOperation::LogicalShiftLeft, OOPostOperation::Or; "S2_lsl_r_p_or"
)]
#[test_case(
	r#"
       0:	0a c3 6c cb	cb6cc30a { 	r11:10 ^= asr(r13:12,r3) }
	"#, OOOperation::ArithmeticShiftRight, OOPostOperation::Xor; "S2_asr_r_p_xor"
)]
#[test_case(
	r#"
       0:	8a c3 6c cb	cb6cc38a { 	r11:10 ^= asl(r13:12,r3) }
	"#, OOOperation::ArithmeticShiftLeft, OOPostOperation::Xor; "S2_asl_r_p_xor"
)]
#[test_case(
	r#"
       0:	4a c3 6c cb	cb6cc34a { 	r11:10 ^= lsr(r13:12,r3) }
	"#, OOOperation::LogicalShiftRight, OOPostOperation::Xor; "S2_lsr_r_p_xor"
)]
#[test_case(
	r#"
       0:	ca c3 6c cb	cb6cc3ca { 	r11:10 ^= lsl(r13:12,r3) }
	"#, OOOperation::LogicalShiftLeft, OOPostOperation::Xor; "S2_lsl_r_p_xor"
)]
fn order_of_operations_64(objdump: &str, op: OOOperation, post_op: OOPostOperation) {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(objdump);

    for i in 1..1000 {
        order_of_operations_helper(&mut cpu, &mut mmu, &mut ev, op, post_op, 8, 0xea43, i, 5);
        order_of_operations_helper(
            &mut cpu,
            &mut mmu,
            &mut ev,
            op,
            post_op,
            8,
            -2i64 as u64,
            i,
            5,
        );
    }
    for i in (u64::MAX - 1000)..u64::MAX {
        order_of_operations_helper(&mut cpu, &mut mmu, &mut ev, op, post_op, 8, 0xea43, i, 5);
        order_of_operations_helper(
            &mut cpu,
            &mut mmu,
            &mut ev,
            op,
            post_op,
            8,
            -2i64 as u64,
            i,
            5,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn order_of_operations_helper(
    cpu: &mut HexagonPcodeBackend,
    mmu: &mut Mmu,
    ev: &mut EventController,
    op: OOOperation,
    post_op: OOPostOperation,
    size: u8,
    dest_start: u64,
    start: u64,
    shift: u32,
) {
    cpu.set_pc(0x1000).unwrap();

    // Overwrite start with a truncated value if 32 bits
    let start = if size == 4 {
        cpu.write_register(HexagonRegister::R0, start as u32)
            .unwrap();
        cpu.write_register(HexagonRegister::R2, dest_start as u32)
            .unwrap();

        // Sign extend it here
        (start as i64) as u64
    } else if size == 8 {
        cpu.write_register(HexagonRegister::D6, start).unwrap();
        cpu.write_register(HexagonRegister::D5, dest_start).unwrap();

        start
    } else {
        unreachable!()
    };

    // Write the shift, which is 32 bits anyway
    cpu.write_register(HexagonRegister::R3, shift).unwrap();

    let exit = cpu.execute(mmu, ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    // Read the result, match with our expectations
    // The only consideration is that
    let shifted = match op {
        // same i
        OOOperation::LogicalShiftLeft | OOOperation::ArithmeticShiftLeft if size == 4 => {
            ((start as u32) << shift) as u64
        }
        OOOperation::LogicalShiftLeft | OOOperation::ArithmeticShiftLeft if size == 8 => {
            start << shift
        }
        OOOperation::ArithmeticShiftRight => ((start as i64) >> shift) as u64,
        OOOperation::LogicalShiftRight => start >> shift,
        _ => unreachable!(),
    };

    let result = match post_op {
        OOPostOperation::Add => shifted.wrapping_add(dest_start),
        OOPostOperation::And => shifted & dest_start,
        OOPostOperation::Or => shifted | dest_start,
        OOPostOperation::Xor => shifted ^ dest_start,
        OOPostOperation::Sub => dest_start.wrapping_sub(shifted),
        _ => unreachable!(),
    };

    if size == 4 {
        // Sign extend to 64 bits
        let output = cpu.read_register::<u32>(HexagonRegister::R2).unwrap();

        println!(
            "start {} shift {} shifted is {} {:x} post_op {:?} dest_start {}, output {}",
            start as i32, shift, shifted as i32, shifted as u32, post_op, dest_start, output
        );
        assert_eq!(output, result as u32);
    } else if size == 8 {
        let output = cpu.read_register::<u64>(HexagonRegister::D5).unwrap();

        println!(
            "start {} shift {} shifted is {} {:x} post_op {:?} dest_start {}, output {}",
            start as i64, shift, shifted as i64, shifted, post_op, dest_start, output
        );

        assert_eq!(output, result);
    } else {
        unreachable!()
    };
}

/// Multiply instructions that sign extend inappropriately when they should zero-extend.
#[test_case(
	r#"
       0:	0a c3 40 e5	e540c30a { 	r11:10 = mpyu(r0,r3) }
	"#, OOOperation::MulZeroExtend, OOPostOperation::None; "M2_dpmpyuu_s0"
)]
#[test_case(
	r#"
       0:	0a c3 40 e7	e740c30a { 	r11:10 += mpyu(r0,r3) }
	"#, OOOperation::MulZeroExtend, OOPostOperation::Add; "M2_dpmpyuu_acc_s0"
)]
#[test_case(
	r#"
       0:	0a c3 60 e7	e760c30a { 	r11:10 -= mpyu(r0,r3) }
	"#, OOOperation::MulZeroExtend, OOPostOperation::Sub; "M2_dpmpyuu_nac_s0"
)]
#[test_case(
	r#"
       0:	0a c3 00 e5	e500c30a { 	r11:10 = mpy(r0,r3) }
	"#, OOOperation::MulSignExtend, OOPostOperation::None; "M2_dpmpyss_s0"
)]
#[test_case(
	r#"
       0:	0a c3 00 e7	e700c30a { 	r11:10 += mpy(r0,r3) }
	"#, OOOperation::MulSignExtend, OOPostOperation::Add; "M2_dpmpyss_acc_s0"
)]
#[test_case(
	r#"
       0:	0a c3 20 e7	e720c30a { 	r11:10 -= mpy(r0,r3) }
	"#, OOOperation::MulSignExtend, OOPostOperation::Sub; "M2_dpmpyss_nac_s0"
)]
fn mpyuuss_sext(objdump: &str, op: OOOperation, post_op: OOPostOperation) {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(objdump);
    let initial_values = [
        0x1u64,
        0x10,
        0x20,
        0x300,
        0xffff,
        0xfea7,
        0xdeadbeef,
        0xffffff87,
        0x78654aff3112,
        0xffffffffffffff89,
    ];
    let mpyu_values = [0xffffff87u32, 6774, 23];

    for initial_value in &initial_values {
        for r0_val in &mpyu_values {
            for r3_val in &mpyu_values {
                cpu.set_pc(0x1000).unwrap();
                cpu.write_register(HexagonRegister::D5, *initial_value)
                    .unwrap();

                cpu.write_register(HexagonRegister::R0, *r0_val).unwrap();
                cpu.write_register(HexagonRegister::R3, *r3_val).unwrap();

                let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
                assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

                let mul = match op {
                    OOOperation::MulSignExtend => {
                        ((*r0_val as i32 as i64).wrapping_mul(*r3_val as i32 as i64)) as u64
                    }
                    OOOperation::MulZeroExtend => (*r0_val as u64).wrapping_mul(*r3_val as u64),
                    _ => unreachable!(),
                };
                let out = match post_op {
                    OOPostOperation::Add => mul.wrapping_add(*initial_value),
                    OOPostOperation::Sub => initial_value.wrapping_sub(mul),
                    OOPostOperation::None => mul,
                    _ => unreachable!(),
                };

                let out_emulated = cpu.read_register::<u64>(HexagonRegister::D5).unwrap();

                info!("initial_value {initial_value:x} r0 {r0_val:x} r3 {r3_val:x} out {mul}",);
                assert_eq!(out, out_emulated)
            }
        }
    }
}

/*
Not implemented yet:

#[test_case(
    r#"
       0:	4a ce 8c e8	e88cce4a { 	r11:10 = cmpyrw(r13:12,r15:14) }
    "#, OOOperation::MulSignExtend, OOPostOperation::None; "M7_dcmpyrw"
)]
#[test_case(
    r#"
       0:	4a ce 8c ea	ea8cce4a { 	r11:10 += cmpyrw(r13:12,r15:14) }
    "#, OOOperation::MulSignExtend, OOPostOperation::Add; "M7_dcmpyrw_acc"
)]
#[test_case(
    r#"
       0:	4a ce cc e8	e8ccce4a { 	r11:10 = cmpyrw(r13:12,r15:14*) }
    "#, OOOperation::MulSignExtend, OOPostOperation::None; "M7_dcmpyrwc"
)]
#[test_case(
    r#"
       0:	4a ce cc ea	eaccce4a { 	r11:10 += cmpyrw(r13:12,r15:14*) }
    "#, OOOperation::MulSignExtend, OOPostOperation::Add; "M7_dcmpyrwc_acc"
)]
#[test_case(
    r#"
       0:	4a ce 6c e8	e86cce4a { 	r11:10 = cmpyiw(r13:12,r15:14) }
    "#, OOOperation::MulSignExtend, OOPostOperation::None; "M7_dcmpyiw"
)]
#[test_case(
    r#"
       0:	4a ce 6c ea	ea6cce4a { 	r11:10 += cmpyiw(r13:12,r15:14) }
    "#, OOOperation::MulSignExtend, OOPostOperation::Add; "M7_dcmpyiw_acc"
)]
#[test_case(
    r#"
       0:	4a ce ec e8	e8ecce4a { 	r11:10 = cmpyiw(r13:12,r15:14*) }
    "#, OOOperation::MulSignExtend, OOPostOperation::None; "M7_dcmpyiwc"
)]
#[test_case(
    r#"
       0:	ca ce 4c ea	ea4cceca { 	r11:10 += cmpyiw(r13:12,r15:14*) }
    "#, OOOperation::MulSignExtend, OOPostOperation::Add; "M7_dcmpyiwc_acc"
)]
pub fn complex_multiply(objdump: &str, op: OOOperation, post_op: OOPostOperation) {}
*/
