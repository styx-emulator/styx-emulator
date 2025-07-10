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
fn test_compound() {
    // More instructions that were taken from the manual
    // Can only do in slot 2 and 3.
    let (mut cpu, mut mmu, mut ev) = setup_asm(
        "{ R2 = add(R0, mpyi(R1, #3)); } { R7 = add(R4, sub(#15, R3)); R10 &= and(R11, R12) }",
        Some(vec![
            0x60, 0xc2, 0x81, 0xdf, 0xe3, 0x67, 0x84, 0xdb, 0x0a, 0xcc, 0x4b, 0xef,
        ]),
    );

    // for add mpyi

    cpu.write_register(HexagonRegister::R0, 12u32).unwrap();
    cpu.write_register(HexagonRegister::R1, 9u32).unwrap();

    // for add sub

    cpu.write_register(HexagonRegister::R4, 200u32).unwrap();
    cpu.write_register(HexagonRegister::R3, 7u32).unwrap();

    // for and, and

    cpu.write_register(HexagonRegister::R10, 8872u32).unwrap();
    cpu.write_register(HexagonRegister::R11, 39939201u32)
        .unwrap();
    cpu.write_register(HexagonRegister::R12, 0xf8f8f8f8u32)
        .unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 3).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let r2 = cpu.read_register::<u32>(HexagonRegister::R2).unwrap();
    let r7 = cpu.read_register::<u32>(HexagonRegister::R7).unwrap();
    let r10 = cpu.read_register::<u32>(HexagonRegister::R10).unwrap();

    assert_eq!(r2, 39);
    assert_eq!(r7, (15 - 7) + 200);
    assert_eq!(r10, (0xf8f8f8f8 & 39939201) & 8872);
}
