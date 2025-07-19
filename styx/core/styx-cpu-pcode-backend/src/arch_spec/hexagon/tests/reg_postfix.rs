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
// postfixes are:
//
// .L least sig 16
// .H most sig 16
//
// .uw[0,1]
// .uh[0,1,2,3] usnigned halfword (upper are for pairs)
// .ub[0,1,2...7]
//
// .w[0,1]
// .h[0,1,2,3]
// .b[0,1,2,3,...7]
//
// .uN bits 0 to N-1 as unsigned
// .sN bits 0 to N-1 as signed
//
// looks like only .H and .L are used

use crate::arch_spec::hexagon::tests::*;

// unfortunately, this is at the moment unimplemented
/*#[test]
fn test_hi_lo_mpyu() {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
0:	42 c1 41 ec	ec41c142 { 	r2 = mpyu(r1.h,r1.l) }
"#,
    );

    cpu.write_register(HexagonRegister::R1, 0x19192021u32)
        .unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let r2 = cpu.read_register::<u32>(HexagonRegister::R2).unwrap();

    assert_eq!(r2, 0x1919 * 0x2021)
}*/

#[test]
fn test_lo_lo_add() {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
0:	02 c3 01 d5	d501c302 { 	r2 = add(r3.l,r1.l) }
"#,
    );

    cpu.write_register(HexagonRegister::R1, 0x19192021u32)
        .unwrap();
    cpu.write_register(HexagonRegister::R3, 0x19198871u32)
        .unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let r2 = cpu.read_register::<u32>(HexagonRegister::R2).unwrap();

    // value is sign extended
    assert_eq!(r2, (((0x2021 + 0x8871) << 16) >> 16) as u32);
}

#[test]
fn test_hi_lo_set() {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
       0:	10 d0 22 72	7222d010 { 	r2.h = #0x1010 }
       4:	32 c3 62 71	7162c332 { 	r2.l = #0x4332 }
"#,
    );

    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);
    let r2 = cpu.read_register::<u32>(HexagonRegister::R2).unwrap();
    assert_eq!(r2, 0x10100000);

    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);
    let r2 = cpu.read_register::<u32>(HexagonRegister::R2).unwrap();
    assert_eq!(r2, 0x10104332);
}
