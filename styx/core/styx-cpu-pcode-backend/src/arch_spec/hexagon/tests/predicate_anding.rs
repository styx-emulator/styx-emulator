// SPDX-License-Identifier: BSD-2-Clause
use crate::arch_spec::hexagon::tests::*;
use log::info;
use test_case::test_case;

// This is a particularly nasty (and good) test for the sequencer.
#[test_case(6, 5, 7, 2; "r0 gt r1, r2 gt r3, branch taken")]
#[test_case(6, 5, 2, 7; "r0 gt r1, r2 lt r3, branch not taken")]
#[test_case(5, 6, 7, 2; "r0 lt r1, r2 gt r3, branch not taken")]
#[test_case(5, 6, 2, 7; "r0 lt r1, r2 lt r3, branch not taken")]
fn test_reorder_anding(r0: u32, r1: u32, r2: u32, r3: u32) {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
       0:	08 71 80 14	14807108 { 	p1 = cmp.gt(r0,r1); if (p1.new) jump:t 0x10
       4:	06 40 00 58	58004006   	jump 0xc
       8:	01 c3 42 f2	f242c301   	p1 = cmp.gt(r2,r3) }
       c:	05 c5 00 78	7800c505 { 	r5 = #0x28 }
      10:	45 cb 00 78	7800cb45 { 	r5 = #0x5a }
"#,
    );

    // TODO: use the test case thing to create a couple of cases
    // where it doesn't pass and where it does
    cpu.write_register(HexagonRegister::R0, r0).unwrap();
    cpu.write_register(HexagonRegister::R1, r1).unwrap();
    cpu.write_register(HexagonRegister::R2, r2).unwrap();
    cpu.write_register(HexagonRegister::R3, r3).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 2).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let r5 = cpu.read_register::<u32>(HexagonRegister::R5).unwrap();

    if r0 > r1 && r2 > r3 {
        assert_eq!(r5, 0x5a);
    } else {
        assert_eq!(r5, 0x28);
    }
}

#[test_case(2, 3, 639, 993; "r0 lt r1, r2 lt r3, branch not taken")]
#[test_case(3, 2, 993, 993; "r0 gt r1, r2 eq r3, branch not taken")]
#[test_case(3, 2, 39943, 993; "r0 gt r1, r2 gt r3, branch taken")]
#[test_case(1, 2, 9008, 993; "r0 lt r1, r2 gt r3, branch not taken")]
#[test_case(100, 2, 9, 993; "r0 gt r1, r2 lt r3, branch not taken")]
fn test_basic_anding(r0: u32, r1: u32, r2: u32, r3: u32) {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
       0:	01 41 40 f2	f2404101 { 	p1 = cmp.gt(r0,r1)
       4:	01 43 42 f2	f2424301   	p1 = cmp.gt(r2,r3)
       8:	25 e7 06 fb	fb06e725   	if (p1.new) r5 = add(r6,r7) }
"#,
    );

    const R6: u32 = 992;
    const R7: u32 = 329;

    cpu.write_register(HexagonRegister::R0, r0).unwrap();
    cpu.write_register(HexagonRegister::R1, r1).unwrap();
    cpu.write_register(HexagonRegister::R2, r2).unwrap();
    cpu.write_register(HexagonRegister::R3, r3).unwrap();

    cpu.write_register(HexagonRegister::R6, R6).unwrap();
    cpu.write_register(HexagonRegister::R7, R7).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let r5 = cpu.read_register::<u32>(HexagonRegister::R5).unwrap();

    if r0 > r1 && r2 > r3 {
        assert_eq!(r5, R6 + R7)
    } else {
        assert_eq!(r5, 0);
    }
}

#[test_case(2, 3, 639, 993, 0, 99; "r0 lt r1, r2 lt r3, r4 lt r5, branch not taken")]
#[test_case(3, 2, 993, 993, 0, 99; "r0 gt r1, r2 eq r3, r4 lt r5, branch not taken")]
#[test_case(3, 2, 39943, 993, 0, 99; "r0 gt r1, r2 gt r3, r4 lt r5, branch not taken")]
#[test_case(1, 2, 9008, 993, 0, 99; "r0 lt r1, r2 gt r3, r4 lt r5, branch not taken")]
#[test_case(100, 2, 9, 993, 0, 99; "r0 gt r1, r2 lt r3, r4 lt r5, branch not taken")]
#[test_case(2, 3, 639, 993, 109, 0; "r0 lt r1, r2 lt r3, r4 gt r5, branch not taken")]
#[test_case(3, 2, 993, 993, 109, 0; "r0 gt r1, r2 eq r3, r4 gt r5, branch not taken")]
#[test_case(3, 2, 39943, 993, 109, 0; "r0 gt r1, r2 gt r3, r4 gt r5, branch taken")]
#[test_case(1, 2, 9008, 993, 109, 0; "r0 lt r1, r2 gt r3, r4 gt r5, branch not taken")]
#[test_case(100, 2, 9, 993, 109, 0; "r0 gt r1, r2 lt r3, r4 gt r5, branch not taken")]
fn test_three_same_anding(r0: u32, r1: u32, r2: u32, r3: u32, r4: u32, r5: u32) {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
       0:	01 41 40 f2	f2404101 { 	p1 = cmp.gt(r0,r1)
       4:	01 43 42 f2	f2424301   	p1 = cmp.gt(r2,r3)
       8:	28 67 06 fb	fb066728   	if (p1.new) r8 = add(r6,r7)
       c:	01 c5 44 f2	f244c501   	p1 = cmp.gt(r4,r5) }
"#,
    );

    const R6: u32 = 992;
    const R7: u32 = 329;

    cpu.write_register(HexagonRegister::R0, r0).unwrap();
    cpu.write_register(HexagonRegister::R1, r1).unwrap();
    cpu.write_register(HexagonRegister::R2, r2).unwrap();
    cpu.write_register(HexagonRegister::R3, r3).unwrap();
    cpu.write_register(HexagonRegister::R4, r4).unwrap();
    cpu.write_register(HexagonRegister::R5, r5).unwrap();

    cpu.write_register(HexagonRegister::R6, R6).unwrap();
    cpu.write_register(HexagonRegister::R7, R7).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let r8 = cpu.read_register::<u32>(HexagonRegister::R8).unwrap();

    if r0 > r1 && r2 > r3 && r4 > r5 {
        assert_eq!(r8, R6 + R7)
    } else {
        assert_eq!(r8, 0);
    }
}

#[test_case(2, 3, 639, 993, 0, 99; "r0 lt r1, r2 lt r3, r4 lt r5, branch not taken")]
#[test_case(3, 2, 993, 993, 0, 99; "r0 gt r1, r2 eq r3, r4 lt r5, branch not taken")]
#[test_case(3, 2, 39943, 993, 0, 99; "r0 gt r1, r2 gt r3, r4 lt r5, branch not taken")]
#[test_case(1, 2, 9008, 993, 0, 99; "r0 lt r1, r2 gt r3, r4 lt r5, branch not taken")]
#[test_case(100, 2, 9, 993, 0, 99; "r0 gt r1, r2 lt r3, r4 lt r5, branch not taken")]
#[test_case(2, 3, 639, 993, 109, 0; "r0 lt r1, r2 lt r3, r4 gt r5, branch not taken")]
#[test_case(3, 2, 993, 993, 109, 0; "r0 gt r1, r2 eq r3, r4 gt r5, branch not taken")]
#[test_case(3, 2, 39943, 993, 109, 0; "r0 gt r1, r2 gt r3, r4 gt r5, branch taken")]
#[test_case(1, 2, 9008, 993, 109, 0; "r0 lt r1, r2 gt r3, r4 gt r5, branch not taken")]
#[test_case(100, 2, 9, 993, 109, 0; "r0 gt r1, r2 lt r3, r4 gt r5, branch not taken")]
fn test_two_same_anding_one_different(r0: u32, r1: u32, r2: u32, r3: u32, r4: u32, r5: u32) {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
     0:	01 41 40 f2	f2404101 { 	p1 = cmp.gt(r0,r1)
       4:	28 67 06 fb	fb066728   	if (p1.new) r8 = add(r6,r7)
       8:	01 43 42 f2	f2424301   	p1 = cmp.gt(r2,r3)
       c:	02 c5 44 f2	f244c502   	p2 = cmp.gt(r4,r5) }
      10:	49 cb 0a fb	fb0acb49 { 	if (p2) r9 = add(r10,r11) }
"#,
    );

    const R6: u32 = 992;
    const R7: u32 = 329;
    const R10: u32 = 1029;
    const R11: u32 = 811;

    cpu.write_register(HexagonRegister::R0, r0).unwrap();
    cpu.write_register(HexagonRegister::R1, r1).unwrap();
    cpu.write_register(HexagonRegister::R2, r2).unwrap();
    cpu.write_register(HexagonRegister::R3, r3).unwrap();
    cpu.write_register(HexagonRegister::R4, r4).unwrap();
    cpu.write_register(HexagonRegister::R5, r5).unwrap();

    cpu.write_register(HexagonRegister::R6, R6).unwrap();
    cpu.write_register(HexagonRegister::R7, R7).unwrap();
    cpu.write_register(HexagonRegister::R10, R10).unwrap();
    cpu.write_register(HexagonRegister::R11, R11).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 2).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let r8 = cpu.read_register::<u32>(HexagonRegister::R8).unwrap();
    let r9 = cpu.read_register::<u32>(HexagonRegister::R9).unwrap();

    if r0 > r1 && r2 > r3 {
        assert_eq!(r8, R6 + R7)
    } else {
        assert_eq!(r8, 0);
    }

    if r4 > r5 {
        assert_eq!(r9, R10 + R11);
    } else {
        assert_eq!(r9, 0);
    }
}

struct FourInsnTestCaseRegValues {
    r0: u32,
    r1: u32,
    r2: u32,
    r3: u32,
    r4: u32,
    r5: u32,
    r6: u32,
    r7: u32,
    p1: u8,
    p2: u8,
    p3: u8,
}

struct FourInsnTestCase {
    objdumps: Vec<String>,
    verify_fn: Box<dyn Fn(FourInsnTestCaseRegValues)>,
    desc: String,
}

// There is verbosity because of not trusting keystone for reordering things
#[test_case(2, 3, 639, 993, 0, 99, 145, 9982; "r0 lt r1, r2 lt r3, r4 lt r5, r6 lt r7")]
#[test_case(3, 2, 993, 993, 0, 99, 145, 9982; "r0 gt r1, r2 eq r3, r4 lt r5, r6 lt r7")]
#[test_case(3, 2, 39943, 993, 0, 99, 145, 9982; "r0 gt r1, r2 gt r3, r4 lt r5, r6 lt r7")]
#[test_case(1, 2, 9008, 993, 0, 99, 145, 9982; "r0 lt r1, r2 gt r3, r4 lt r5, r6 lt r7")]
#[test_case(100, 2, 9, 993, 0, 99, 145, 9982; "r0 gt r1, r2 lt r3, r4 lt r5, r6 lt r7")]
#[test_case(2, 3, 639, 993, 109, 0, 145, 9982; "r0 lt r1, r2 lt r3, r4 gt r5, r6 lt r7")]
#[test_case(3, 2, 993, 993, 109, 0, 145, 9982; "r0 gt r1, r2 eq r3, r4 gt r5, r6 lt r7")]
#[test_case(3, 2, 39943, 993, 109, 0, 145, 9982; "r0 gt r1, r2 gt r3, r4 gt r5, r6 lt r7")]
#[test_case(1, 2, 9008, 993, 109, 0, 145, 9982; "r0 lt r1, r2 gt r3, r4 gt r5, r6 lt r7")]
#[test_case(100, 2, 9, 993, 109, 0, 145, 9982; "r0 gt r1, r2 lt r3, r4 gt r5, r6 lt r7")]
#[test_case(2, 3, 639, 993, 0, 99, 9982, 145; "r0 lt r1, r2 lt r3, r4 lt r5, r6 gt r7")]
#[test_case(3, 2, 993, 993, 0, 99, 9982, 145; "r0 gt r1, r2 eq r3, r4 lt r5, r6 gt r7")]
#[test_case(3, 2, 39943, 993, 0, 99, 9982, 145; "r0 gt r1, r2 gt r3, r4 lt r5, r6 gt r7")]
#[test_case(1, 2, 9008, 993, 0, 99,9982, 145; "r0 lt r1, r2 gt r3, r4 lt r5, r6 gt r7")]
#[test_case(100, 2, 9, 993, 0, 99, 9982, 145; "r0 gt r1, r2 lt r3, r4 lt r5, r6 gt r7")]
#[test_case(2, 3, 639, 993, 109, 0, 9982, 145; "r0 lt r1, r2 lt r3, r4 gt r5, r6 gt r7")]
#[test_case(3, 2, 993, 993, 109, 0, 9982, 145; "r0 gt r1, r2 eq r3, r4 gt r5, r6 gt r7")]
#[test_case(3, 2, 39943, 993, 109, 0, 9982, 145; "r0 gt r1, r2 gt r3, r4 gt r5, r6 gt r7")]
#[test_case(1, 2, 9008, 993, 109, 0, 9982, 145; "r0 lt r1, r2 gt r3, r4 gt r5, r6 gt r7")]
#[test_case(100, 2, 9, 993, 109, 0, 9982, 145; "r0 gt r1, r2 lt r3, r4 gt r5, r6 gt r7")]
#[allow(clippy::too_many_arguments)]
fn test_four(r0: u32, r1: u32, r2: u32, r3: u32, r4: u32, r5: u32, r6: u32, r7: u32) {
    let tests = [
        FourInsnTestCase {
            objdumps: vec![r#"
       0:	01 47 46 f2	f2464701 { 	p1 = cmp.gt(r6,r7)
       4:	01 43 42 f2	f2424301   	p1 = cmp.gt(r2,r3)
       8:	01 45 44 f2	f2444501   	p1 = cmp.gt(r4,r5)
       c:	01 c1 40 f2	f240c101   	p1 = cmp.gt(r0,r1) }
"#
            .to_string()],
            verify_fn: Box::new(|regs: FourInsnTestCaseRegValues| {
                if regs.r0 > regs.r1 && regs.r2 > regs.r3 && regs.r4 > regs.r5 && regs.r6 > regs.r7 {
                    // NOTE: this should actually be 0xff
                    assert_eq!(regs.p1, 1)
                } else {
                    assert_eq!(regs.p1, 0);
                }
            }),
            desc: "all four instructions have same output predicate".to_string(),
        },
        FourInsnTestCase {
            objdumps: vec![
                r#"
       0:	01 41 40 f2	f2404101 { 	p1 = cmp.gt(r0,r1)
       4:	01 43 42 f2	f2424301   	p1 = cmp.gt(r2,r3)
       8:	02 45 44 f2	f2444502   	p2 = cmp.gt(r4,r5)
       c:	01 c7 46 f2	f246c701   	p1 = cmp.gt(r6,r7) }
"#
                .to_string(),
                r#"
       0:	01 41 40 f2	f2404101 { 	p1 = cmp.gt(r0,r1)
       4:	02 45 44 f2	f2444502   	p2 = cmp.gt(r4,r5)
       8:	01 47 46 f2	f2464701   	p1 = cmp.gt(r6,r7)
       c:	01 c3 42 f2	f242c301   	p1 = cmp.gt(r2,r3) }
"#
                .to_string(),
                r#"
        0:	01 41 40 f2	f2404101 { 	p1 = cmp.gt(r0,r1)
       4:	01 47 46 f2	f2464701   	p1 = cmp.gt(r6,r7)
       8:	01 43 42 f2	f2424301   	p1 = cmp.gt(r2,r3)
       c:	02 c5 44 f2	f244c502   	p2 = cmp.gt(r4,r5) }
"#
                .to_string(),
                r#"
        0:	01 41 40 f2	f2404101 { 	p1 = cmp.gt(r0,r1)
       4:	01 47 46 f2	f2464701   	p1 = cmp.gt(r6,r7)
       8:	01 43 42 f2	f2424301   	p1 = cmp.gt(r2,r3)
       c:	02 c5 44 f2	f244c502   	p2 = cmp.gt(r4,r5) }
"#
                .to_string(),
                r#"
       0:	02 45 44 f2	f2444502 { 	p2 = cmp.gt(r4,r5)
       4:	01 41 40 f2	f2404101   	p1 = cmp.gt(r0,r1)
       8:	01 47 46 f2	f2464701   	p1 = cmp.gt(r6,r7)
       c:	01 c3 42 f2	f242c301   	p1 = cmp.gt(r2,r3) }
"#
                .to_string(),
            ],
            verify_fn: Box::new(|regs: FourInsnTestCaseRegValues| {
                if regs.r0 > regs.r1 && regs.r2 > regs.r3 && regs.r6 > regs.r7 {
                    // NOTE: this should actually be 0xff
                    assert_eq!(regs.p1, 1);
                } else {
                    assert_eq!(regs.p1, 0);
                }

                if regs.r4 > regs.r5 {
                    assert_eq!(regs.p2, 1);
                } else {
                    assert_eq!(regs.p2, 0);
                }
            }),
            desc: "three instructions output to same predicate, one instruction outputs to a different".to_string(),
        },
        // The point is to make sure the ANDed arguments are anded correctly no matter where they are grouped
        // so we can save space by keeping the p2 and p3 sets together. Although, this is then indistinguishable
        // in some sense from the 3 instruction and packet.
        FourInsnTestCase {
            objdumps: vec![
                r#"
       0:	02 45 44 f2	f2444502 { 	p2 = cmp.gt(r4,r5)
       4:	03 41 40 f2	f2404103   	p3 = cmp.gt(r0,r1)
       8:	01 47 46 f2	f2464701   	p1 = cmp.gt(r6,r7)
       c:	01 c3 42 f2	f242c301   	p1 = cmp.gt(r2,r3) }
"#.to_string(),
                r#"
       0:	01 47 46 f2	f2464701 { 	p1 = cmp.gt(r6,r7)
       4:	02 45 44 f2	f2444502   	p2 = cmp.gt(r4,r5)
       8:	03 41 40 f2	f2404103   	p3 = cmp.gt(r0,r1)
       c:	01 c3 42 f2	f242c301   	p1 = cmp.gt(r2,r3) }
"#.to_string(),
                r#"
       0:	01 47 46 f2	f2464701 { 	p1 = cmp.gt(r6,r7)
       4:	02 45 44 f2	f2444502   	p2 = cmp.gt(r4,r5)
       8:	03 41 40 f2	f2404103   	p3 = cmp.gt(r0,r1)
       c:	01 c3 42 f2	f242c301   	p1 = cmp.gt(r2,r3) }
"#.to_string(),
                r#"
        0:	01 47 46 f2	f2464701 { 	p1 = cmp.gt(r6,r7)
       4:	01 43 42 f2	f2424301   	p1 = cmp.gt(r2,r3)
       8:	02 45 44 f2	f2444502   	p2 = cmp.gt(r4,r5)
       c:	03 c1 40 f2	f240c103   	p3 = cmp.gt(r0,r1) }
        "#.to_string(),
            ],
            verify_fn: Box::new(|regs: FourInsnTestCaseRegValues| {
                if regs.r2 > regs.r3 && regs.r6 > regs.r7 {
                    // NOTE: this should actually be 0xff
                    assert_eq!(regs.p1, 1);
                } else {
                    assert_eq!(regs.p1, 0);
                }

                if regs.r4 > regs.r5 {
                    assert_eq!(regs.p2, 1);
                } else {
                    assert_eq!(regs.p2, 0);
                }

                if regs.r0 > regs.r1 {
                    assert_eq!(regs.p3, 1);
                } else {
                    assert_eq!(regs.p3, 0);
                }
            }),
            desc: "two instructions output to p1, one instruction outputs to p2, one instruction outputs to p3".to_string()
        },
        FourInsnTestCase {
            objdumps: vec![
                r#"
       0:	01 47 46 f2	f2464701 { 	p1 = cmp.gt(r6,r7)
       4:	01 43 42 f2	f2424301   	p1 = cmp.gt(r2,r3)
       8:	02 45 44 f2	f2444502   	p2 = cmp.gt(r4,r5)
       c:	02 c1 40 f2	f240c102   	p2 = cmp.gt(r0,r1) }
"#.to_string(),
                r#"
       0:	01 43 42 f2	f2424301 { 	p1 = cmp.gt(r2,r3)
       4:	01 47 46 f2	f2464701   	p1 = cmp.gt(r6,r7)
       8:	02 41 40 f2	f2404102   	p2 = cmp.gt(r0,r1)
       c:	02 c5 44 f2	f244c502   	p2 = cmp.gt(r4,r5) }
"#.to_string(),
                r#"
       0:	02 45 44 f2	f2444502 { 	p2 = cmp.gt(r4,r5)
       4:	02 41 40 f2	f2404102   	p2 = cmp.gt(r0,r1)
       8:	01 47 46 f2	f2464701   	p1 = cmp.gt(r6,r7)
       c:	01 c3 42 f2	f242c301   	p1 = cmp.gt(r2,r3) }
"#.to_string(),
                r#"
       0:	02 41 40 f2	f2404102 { 	p2 = cmp.gt(r0,r1)
       4:	02 45 44 f2	f2444502   	p2 = cmp.gt(r4,r5)
       8:	01 47 46 f2	f2464701   	p1 = cmp.gt(r6,r7)
       c:	01 c3 42 f2	f242c301   	p1 = cmp.gt(r2,r3) }
"#.to_string(),
                r#"
       0:	02 45 44 f2	f2444502 { 	p2 = cmp.gt(r4,r5)
       4:	01 47 46 f2	f2464701   	p1 = cmp.gt(r6,r7)
       8:	02 41 40 f2	f2404102   	p2 = cmp.gt(r0,r1)
       c:	01 c3 42 f2	f242c301   	p1 = cmp.gt(r2,r3) }
"#.to_string(),
                r#"
       0:	02 41 40 f2	f2404102 { 	p2 = cmp.gt(r0,r1)
       4:	01 47 46 f2	f2464701   	p1 = cmp.gt(r6,r7)
       8:	02 45 44 f2	f2444502   	p2 = cmp.gt(r4,r5)
       c:	01 c3 42 f2	f242c301   	p1 = cmp.gt(r2,r3) }
"#.to_string(),
            ],
            verify_fn: Box::new(|regs: FourInsnTestCaseRegValues| {
                if regs.r2 > regs.r3 && regs.r6 > regs.r7 {
                    // NOTE: this should actually be 0xff
                    assert_eq!(regs.p1, 1);
                } else {
                    assert_eq!(regs.p1, 0);
                }

                if regs.r0 > regs.r1 && regs.r4 > regs.r5 {
                    assert_eq!(regs.p2, 1);
                } else {
                    assert_eq!(regs.p2, 0);
                }
            }),
            desc: "two instructions output to p1, two instructions output to p2".to_string()
        },
    ];

    for test in tests {
        for dump in &test.objdumps {
            info!("testing test case {}", test.desc);
            test_four_helper(dump, r0, r1, r2, r3, r4, r5, r6, r7, &test.verify_fn);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn test_four_helper(
    objdump: &str,
    r0: u32,
    r1: u32,
    r2: u32,
    r3: u32,
    r4: u32,
    r5: u32,
    r6: u32,
    r7: u32,
    verify_callback: &impl Fn(FourInsnTestCaseRegValues),
) {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(objdump);

    cpu.write_register(HexagonRegister::R0, r0).unwrap();
    cpu.write_register(HexagonRegister::R1, r1).unwrap();
    cpu.write_register(HexagonRegister::R2, r2).unwrap();
    cpu.write_register(HexagonRegister::R3, r3).unwrap();
    cpu.write_register(HexagonRegister::R4, r4).unwrap();
    cpu.write_register(HexagonRegister::R5, r5).unwrap();
    cpu.write_register(HexagonRegister::R6, r6).unwrap();
    cpu.write_register(HexagonRegister::R7, r7).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    // P0 is never used
    let p1 = cpu.read_register::<u8>(HexagonRegister::P1).unwrap();
    let p2 = cpu.read_register::<u8>(HexagonRegister::P2).unwrap();
    let p3 = cpu.read_register::<u8>(HexagonRegister::P3).unwrap();

    verify_callback(FourInsnTestCaseRegValues {
        r0,
        r1,
        r2,
        r3,
        r4,
        r5,
        r6,
        r7,
        p1,
        p2,
        p3,
    });
}
