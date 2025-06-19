// SPDX-License-Identifier: BSD-2-Clause
use crate::arch_spec::hexagon::tests::*;

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
