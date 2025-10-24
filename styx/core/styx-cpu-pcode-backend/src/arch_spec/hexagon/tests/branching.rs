// SPDX-License-Identifier: BSD-2-Clause
use crate::arch_spec::hexagon::tests::*;
use test_case::test_case;

#[test]
fn test_cond_branching() {
    // need to have a separate test for .new, so
    // that p0 could be in the same packet.
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
       0:	04 40 60 70	70604004 { 	r4 = r0
       4:	00 c0 01 f2	f201c000   	p0 = cmp.eq(r1,r0) }
       8:	42 40 04 b0	b0044042 { 	r2 = add(r4,#0x2)
       c:	08 40 00 5c	5c004008   	if (p0) jump:nt 0x18
      10:	03 31 45 30	30453103   	r5 = r4; 	r3 = add(r0,#1) }
      14:	40 e8 00 78	7800e840 { 	r0 = #0x142 }
      18:	20 f4 01 78	7801f420 { 	r0 = #0x3a1 }
"#,
    );
    cpu.write_register(HexagonRegister::R0, 32u64).unwrap();
    cpu.write_register(HexagonRegister::R1, 32u64).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 3).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let r5 = cpu.read_register::<u32>(HexagonRegister::R5).unwrap();
    let r4 = cpu.read_register::<u32>(HexagonRegister::R4).unwrap();
    let r3 = cpu.read_register::<u32>(HexagonRegister::R3).unwrap();
    let r0 = cpu.read_register::<u32>(HexagonRegister::R0).unwrap();
    let r2 = cpu.read_register::<u32>(HexagonRegister::R2).unwrap();

    // branch taken
    assert_eq!(r0, 929);
    assert_eq!(r4, 32);
    assert_eq!(r5, r4);
    assert_eq!(r3, 33);
    assert_eq!(r2, 34);
}

#[test_case(
    r#"
       0:	0a 40 00 5a	5a00400a { 	call 0x14
       4:	80 c0 00 78	7800c080   	r0 = #0x4 }
       8:	ea c6 00 b0	b000c6ea { 	r10 = add(r0,#0x37) }
       c:	0a e2 13 78	7813e20a { 	r10 = #0x2710 }
      10:	8a ee 13 78	7813ee8a { 	r10 = #0x2774 }
      14:	c0 3f 00 51	51003fc0 { 	r0 = add(r0,#1); 	jumpr r31 }
"#,
    1,
    0x1008;
    "two instructions in one packet"
)]
#[test_case(
    r#"
       0:	0a 40 00 5a	5a00400a { 	call 0x14
       4:	40 28 01 2a	2a012840   	r1 = #0x20; 	r0 = #0x4 }
       8:	ea c6 00 b0	b000c6ea { 	r10 = add(r0,#0x37) }
       c:	0a e2 13 78	7813e20a { 	r10 = #0x2710 }
      10:	8a ee 13 78	7813ee8a { 	r10 = #0x2774 }
      14:	c0 3f 00 51	51003fc0 { 	r0 = add(r0,#1); 	jumpr r31 }
"#,
    1,
    0x1008;
    "three instructions in one packet, one duplex"
)]
#[test_case(
    r#"
       0:	0c 40 00 5a	5a00400c { 	call 0x18
       4:	01 42 00 ed	ed004201   	r1 = mpyi(r0,r2)
       8:	80 c0 00 78	7800c080   	r0 = #0x4 }
       c:	ea c6 00 b0	b000c6ea { 	r10 = add(r0,#0x37) }
      10:	0a e2 13 78	7813e20a { 	r10 = #0x2710 }
      14:	8a ee 13 78	7813ee8a { 	r10 = #0x2774 }
      18:	c0 3f 00 51	51003fc0 { 	r0 = add(r0,#1); 	jumpr r31 }
"#,
    1,
    0x100c;
    "three instructions in one packet"
)]
#[test_case(
    r#"
       0:	80 c0 00 78	7800c080 { 	r0 = #0x4 }
       4:	08 c0 00 5a	5a00c008 { 	call 0x14 }
       8:	ea c6 00 b0	b000c6ea { 	r10 = add(r0,#0x37) }
       c:	0a e2 13 78	7813e20a { 	r10 = #0x2710 }
      10:	8a ee 13 78	7813ee8a { 	r10 = #0x2774 }
      14:	c0 3f 00 51	51003fc0 { 	r0 = add(r0,#1); 	jumpr r31 }
"#,
    2,
    0x1008;
    "one instruction in one packet"
)]
#[test_case(
    r#"
       0:	0c 40 00 5a	5a00400c { 	call 0x18
       4:	ea 42 00 78	780042ea   	r10 = #0x17
       8:	c1 2a 40 28	28402ac1   	r0 = #0x4; 	r1 = #0x2c }
       c:	ea c6 00 b0	b000c6ea { 	r10 = add(r0,#0x37) }
      10:	0a e2 13 78	7813e20a { 	r10 = #0x2710 }
      14:	8a ee 13 78	7813ee8a { 	r10 = #0x2774 }
      18:	c0 3f 00 51	51003fc0 { 	r0 = add(r0,#1); 	jumpr r31 }
"#,
    1,
    0x100c;
    "four instructions in one packet, one duplex"
)]
#[test_case(
    r#"
       0:	0e 40 00 5a	5a00400e { 	call 0x1c
       4:	80 40 00 78	78004080   	r0 = #0x4
       8:	61 6e 34 b0	b0346e61   	r1 = add(r20,#0x373)
       c:	ea c2 00 78	7800c2ea   	r10 = #0x17 }
      10:	ea c6 00 b0	b000c6ea { 	r10 = add(r0,#0x37) }
      14:	0a e2 13 78	7813e20a { 	r10 = #0x2710 }
      18:	8a ee 13 78	7813ee8a { 	r10 = #0x2774 }
      1c:	c0 3f 00 51	51003fc0 { 	r0 = add(r0,#1); 	jumpr r31 }
"#,
    1,
    0x1010;
    "four instructions in one packet"
)]
fn test_call(asm: &str, initial_run: u64, lr_addr: u64) {
    // the link register is set appropriately after the first instruction
    let (mut cpu, mut mmu, mut ev) = setup_objdump(asm);

    // the extra junk instructions are to ensure that only the r10 = add(r0, #0x37) instructino runs
    let report = cpu.execute(&mut mmu, &mut ev, initial_run).unwrap();
    assert_eq!(
        report.exit_reason,
        TargetExitReason::InstructionCountComplete
    );

    // this should have run up to the packet with the "call" instruction.
    // we now wish to verify our link register.
    let lr = cpu.read_register::<u32>(HexagonRegister::Lr).unwrap();
    assert_eq!(lr, lr_addr as u32);

    // now, run the actual function
    let report = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(
        report.exit_reason,
        TargetExitReason::InstructionCountComplete
    );

    // this is the first packet, and immediately after the call ends. at this point,
    // our PC should be set to the link register and point to 0x8, and r0 should be
    // incremented from 4 to 5.
    //
    // NOTE: see `setup_objdump` in `mod.rs` for a reference, but the code
    // specified above is loaded at address 0x1000, so we would expect
    // the PC to be at 0x1008 after the first two instructions
    let r0 = cpu.read_register::<u32>(HexagonRegister::R0).unwrap();
    let pc = cpu.pc().unwrap();

    assert_eq!(r0, 5);
    assert_eq!(pc, lr_addr);

    let report = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(
        report.exit_reason,
        TargetExitReason::InstructionCountComplete
    );

    // now, the first instruction after returning was run, adding
    // 55 to r0 and storing in r10. let's check this.
    let r10 = cpu.read_register::<u32>(HexagonRegister::R10).unwrap();

    // 4 + 1 + 55 = 60
    assert_eq!(r10, 60);
}

#[test]
fn test_basic_branching() {
    const R1: u32 = 47;
    // can't get labels to work for some reason
    // this is a cool test because it's a register transfer jump
    // so the first packet is actually 1 instruction, which adds
    // some lovely edge cases
    //
    // assembler inserts some immexts here, so it's not 1 insnn, hence basic branching
    // single instruction pkt (probably from double pounds)
    let (mut cpu, mut mmu, mut ev) = setup_asm(
        r#"
{ r0 = r1;
  jump 0xc }
junk:
{ r0 = mpyi(r0, ##32) }
lab:
{ r0 = mpyi(r0, ##56) }
{ r2 = add(r0, #2); }
        "#,
        None,
    );
    cpu.write_register(HexagonRegister::R1, R1).unwrap();

    // Check jump
    let initial_isa_pc = get_isa_pc(&mut cpu);

    trace!("starting initial jump");
    // register transfer jump 1 insn and 1 packet
    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let mid_isa_pc = get_isa_pc(&mut cpu);
    // The 12 offset is because we skip over the "junk" packet
    assert_eq!(mid_isa_pc - initial_isa_pc, 12);

    trace!("starting initial multiply");
    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    // We are checking just after the multiply after the "lab" label.
    let end_branch_isa_pc = get_isa_pc(&mut cpu);
    assert_eq!(end_branch_isa_pc - initial_isa_pc, 20);

    // Last addition
    trace!("starting addition");
    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let r0 = cpu.read_register::<u32>(HexagonRegister::R0).unwrap();
    let r2 = cpu.read_register::<u32>(HexagonRegister::R2).unwrap();

    assert_eq!(r0, R1 * 56);
    assert_eq!(r2, r0 + 2);
}

#[test]
fn test_basic_branching_single_insn_pkt() {
    const R1: u32 = 47;
    // similar to basic branching, but ensures that the pkts are standalone with only 1 insn
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
       0:	04 c0 01 17	1701c004 { 	r0 = r1 ; jump 0x8 }
       4:	a0 fd 00 78	7800fda0 { 	r0 = #0x1ed }
       8:	00 c7 00 b0	b000c700 { 	r0 = add(r0,#0x38) }
       c:	42 c0 00 b0	b000c042 { 	r2 = add(r0,#0x2) }
"#,
    );
    cpu.write_register(HexagonRegister::R1, R1).unwrap();

    // Check jump
    let initial_isa_pc = get_isa_pc(&mut cpu);

    trace!("starting initial jump");
    // register transfer jump is 1 insn (and 1 packet)
    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let mid_isa_pc = get_isa_pc(&mut cpu);
    // We expect the PC to be at the first add instruction
    assert_eq!(mid_isa_pc - initial_isa_pc, 8);

    trace!("starting initial add");
    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let end_branch_isa_pc = get_isa_pc(&mut cpu);
    assert_eq!(end_branch_isa_pc - initial_isa_pc, 12);

    // Last addition
    trace!("starting addition");
    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let end_isa_pc = get_isa_pc(&mut cpu);
    assert_eq!(end_isa_pc - initial_isa_pc, 16);

    let r0 = cpu.read_register::<u32>(HexagonRegister::R0).unwrap();
    let r2 = cpu.read_register::<u32>(HexagonRegister::R2).unwrap();

    assert_eq!(r0, R1 + 56);
    assert_eq!(r2, r0 + 2);
}
