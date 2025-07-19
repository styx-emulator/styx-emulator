// SPDX-License-Identifier: BSD-2-Clause
// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
use crate::arch_spec::hexagon::tests::*;

#[test]
fn test_cond_branching() {
    // need to have a separate test for .new, so
    // that p0 could be in the same packet.
    let (mut cpu, mut mmu, mut ev) = setup_asm(
        r#"
{ r4 = r0; p0 = cmp.eq(r1, r0); }
{ r2 = add(r4, #2); r5 = r4; if (p0) jump 0x10; r3 = add(r0, #1) }
{ r0 = #322 }
{ r0 = #929 }
"#,
        None,
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

// TODO: jumpr branch (indirect), conditional branch,
// and a branch that isn't at the end of the packet!
// FIXME: come back to do this
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
    // register transfer jump 1 insn
    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let mid_isa_pc = get_isa_pc(&mut cpu);
    assert_eq!(mid_isa_pc - initial_isa_pc, 12);

    // There's an immext here
    trace!("starting initial multiply");
    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

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

// FIXME: help
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
    // register transfer jump is 1 insn
    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let mid_isa_pc = get_isa_pc(&mut cpu);
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
