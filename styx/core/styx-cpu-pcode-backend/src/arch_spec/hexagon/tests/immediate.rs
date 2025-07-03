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
fn test_immediates() {
    const WRITTEN: u32 = 0x29177717;
    // this should be something that is small,
    // to make sure that the previous immext being set doesn't
    // interfere somehow?
    const WRITTEN2: u32 = 12;
    const R0VAL: u32 = 21;
    let (mut cpu, mut mmu, mut ev) = setup_asm(
        &format!(
            "{{ r1 = add(r0, #{}); }}; {{ r2 = add(r1, #{}) }}; {{ r3 = add(r1, r2); }}; {{ r4 = r2; }};",
            WRITTEN, WRITTEN2
        ),
        None,
    );
    cpu.write_register(HexagonRegister::R0, R0VAL).unwrap();

    // We'll have two instructions for each immext, and then the second instruction
    // doesn't have an immediate _extension_ so we're good on that end, total
    // 5 instructions
    // TODO: does immext need to be set to 0xffffffff every cycle?
    // it doesn't seem like it..
    let exit = cpu.execute(&mut mmu, &mut ev, 5).unwrap();

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
fn test_immediate_instruction() {
    const WRITTEN: u32 = 0x29177717;
    const R0VAL: u32 = 21;
    let (mut cpu, mut mmu, mut ev) = setup_asm(&format!("{{ r1 = add(r0, #{}); }}", WRITTEN), None);
    cpu.write_register(HexagonRegister::R0, R0VAL).unwrap();

    // TODO: how should the ISA PC respond to immext?

    // We'll have two instructions for immext
    let exit = cpu.execute(&mut mmu, &mut ev, 2).unwrap();

    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let r1 = cpu.read_register::<u32>(HexagonRegister::R1).unwrap();

    assert_eq!(r1, WRITTEN + R0VAL);
}
