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
fn test_duplex_immext() {
    let (mut cpu, mut mmu, mut ev) = setup_asm(
        "{ R4 = mpyi(R0, R1); }; { R2 = #1905856528; R3 = R0; }",
        None,
    );

    cpu.write_register(HexagonRegister::R0, 100u32).unwrap();
    cpu.write_register(HexagonRegister::R1, 470u32).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 4).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let r2 = cpu.read_register::<u32>(HexagonRegister::R2).unwrap();
    let r3 = cpu.read_register::<u32>(HexagonRegister::R3).unwrap();
    let r4 = cpu.read_register::<u32>(HexagonRegister::R4).unwrap();

    assert_eq!(r2, 1905856528u32);
    assert_eq!(r3, 100);
    assert_eq!(r4, 100 * 470);
}

#[test]
fn test_duplex_instructions() {
    // [0x16, 0x30, 0x05, 0x30]
    let (mut cpu, mut mmu, mut ev) =
        setup_asm("{ r5 = r0; r6 = r1 }", Some(vec![0x16, 0x30, 0x05, 0x30]));
    cpu.write_register(HexagonRegister::R1, 0xdeadbeef_u32)
        .unwrap();
    cpu.write_register(HexagonRegister::R0, 0xcafeb0ba_u32)
        .unwrap();

    let initial_isa_pc = get_isa_pc(&mut cpu);

    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let mid_isa_pc = get_isa_pc(&mut cpu);
    assert_eq!(initial_isa_pc, mid_isa_pc);

    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let end_isa_pc = get_isa_pc(&mut cpu);
    let r5 = cpu.read_register::<u32>(HexagonRegister::R5).unwrap();
    let r6 = cpu.read_register::<u32>(HexagonRegister::R6).unwrap();

    assert_eq!(r6, 0xdeadbeef);
    assert_eq!(r5, 0xcafeb0ba);
    assert_eq!(end_isa_pc - initial_isa_pc, 4);
}
