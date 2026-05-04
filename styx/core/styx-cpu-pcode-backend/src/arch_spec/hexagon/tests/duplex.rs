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

#[test]
fn test_two_loads() {
    const R5START: u32 = 0x10000;
    const R0START: u32 = 0x20000;
    const VAL: u32 = 0x11987309;
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
       0:	54 00 02 00	00020054 { 	r2 = memw(r0+#0x0); 	r4 = memw(r5+#0x0) }
"#,
    );

    cpu.write_register(HexagonRegister::R0, R0START).unwrap();
    cpu.write_register(HexagonRegister::R5, R5START).unwrap();

    mmu.write_u32_le_phys_data(R0START as u64, VAL).unwrap();
    mmu.write_u32_le_phys_data(R5START as u64, VAL).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let r2 = cpu.read_register::<u32>(HexagonRegister::R2).unwrap();
    let r4 = cpu.read_register::<u32>(HexagonRegister::R4).unwrap();

    assert_eq!(r2, VAL);
    assert_eq!(r4, VAL);
}

/// Tests an instruction that:
/// 1. After the packet executes, sets R16 to R16 + 8
/// 2. Reads 4 bytes from address R16 to R0. Since (1)
///    only causes R16 to be set at the end of the
///    packet, this instruction uses the original value
///    of R16.
///
/// The issue with this packet was that in a duplex, registers are encoded
/// such that R6 is 0b0110, R7 is as 0b0111. You would expect R8 to be 0b1000, but there
/// is a gap skipping R8 to R15 (see table 10-3 in Hexagon manual). So 0b1000 is actually R16,
/// 0b1001 is R17, etc.
///
/// The duplex encoding gap is handled for registers that are _only_ a source reg or destination reg.
/// Calculating the destination register space location for a duplex reg that is _only_ a destination register
/// is also straightforward. See "attach variables" sections in hexagon.slaspec.
///
/// However, computing the destination register space location for a reg that is
/// _both_ a source and dest register (Rx prefixed in encoding) uses the encoding
/// directly. The SLASPEC used to compute the location in the destination register space by doing
/// eg. REG_SPACE_START+(0b1000*4) [4 is the size in bytes of a register],
/// which is wrong and gives us the destination register space location for R8, not R16,
/// so the register R16 would never be written.
///
/// This is now fixed, but this test exists to make sure this works as expected.
///
/// The memory read is there to make this a duplex.
#[test]
fn broken_duplex_add() {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
0:	80 00 88 40	40880080 { 	r16 = add(r16,#0x8); 	r0 = memw(r16+#0x0) }
"#,
    );

    const R16ADDR: u32 = 0x100u32;
    const MAGIC: u32 = 0xaa887652u32;

    cpu.write_register(HexagonRegister::R16, R16ADDR).unwrap();
    mmu.write_u32_le_phys_data(R16ADDR as u64, MAGIC).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let r0 = cpu.read_register::<u32>(HexagonRegister::R0).unwrap();
    let r16 = cpu.read_register::<u32>(HexagonRegister::R16).unwrap();

    assert_eq!(r0, MAGIC);
    assert_eq!(r16, R16ADDR + 8);
}

/// See explanation for `broken_duplex_add`. This tests the same issue again, but for the only
/// other instruction in the SLASPEC with a duplex register that serves as both source and
/// destination.
#[test]
fn broken_duplex_reg_add() {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
0:	80 00 98 58	58980080 { 	r16 = add(r16,r17); 	r0 = memw(r16+#0x0) }
"#,
    );

    const R16ADDR: u32 = 0x100u32;
    const MAGIC: u32 = 0xaa887652u32;

    cpu.write_register(HexagonRegister::R16, R16ADDR).unwrap();
    cpu.write_register(HexagonRegister::R17, 8u32).unwrap();
    mmu.write_u32_le_phys_data(R16ADDR as u64, MAGIC).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let r0 = cpu.read_register::<u32>(HexagonRegister::R0).unwrap();
    let r16 = cpu.read_register::<u32>(HexagonRegister::R16).unwrap();

    assert_eq!(r0, MAGIC);
    assert_eq!(r16, R16ADDR + 8);
}
