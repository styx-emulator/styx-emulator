// SPDX-License-Identifier: BSD-2-Clause
use crate::arch_spec::hexagon::tests::*;

#[test]
fn test_duplex_immext() {
    let (mut cpu, mut mmu, mut ev) = setup_asm(
        "{ R4 = mpyi(R0, R1); }; { R2 = #1905856528; R3 = R0; }",
        None,
    );

    cpu.write_register(HexagonRegister::R0, 100u32).unwrap();
    cpu.write_register(HexagonRegister::R1, 470u32).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 2).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let r2 = cpu.read_register::<u32>(HexagonRegister::R2).unwrap();
    let r3 = cpu.read_register::<u32>(HexagonRegister::R3).unwrap();
    let r4 = cpu.read_register::<u32>(HexagonRegister::R4).unwrap();

    assert_eq!(r2, 1905856528u32);
    assert_eq!(r3, 100);
    assert_eq!(r4, 100 * 470);
}

// FIXME: test
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

    let end_isa_pc = get_isa_pc(&mut cpu);
    let r5 = cpu.read_register::<u32>(HexagonRegister::R5).unwrap();
    let r6 = cpu.read_register::<u32>(HexagonRegister::R6).unwrap();

    assert_eq!(r6, 0xdeadbeef);
    assert_eq!(r5, 0xcafeb0ba);
    assert_eq!(end_isa_pc - initial_isa_pc, 4);
}
