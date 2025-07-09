use crate::arch_spec::hexagon::tests::*;
use test_case::test_case;

// need a separate conditional too
#[test_case(
    "{ r2 = memh(r4+#0x8); r3 = #2; p0 = cmp.eq(r3, #2); if (p0) memh(r5+#0x0) = r2.new }",
    None,
    3,
    1,
    0x1020,
    0x1020; "conditional dotnew load halfword branch taken"
)]
#[test_case(
    "{ r2 = memw(r4+#0x8); r3 = #3; p0 = cmp.eq(r3, #2); if (p0) memh(r5+#0x0) = r2.new }",
    None,
    3,
    1,
    0xf0991020,
    0; "conditional dotnew load word branch not taken"
)]
#[test_case(
    "{ r2 = memh(r4+#0x8); memb(r5+#0x0) = r2.new }",
    None,
    1,
    1,
    0x1020,
    0x20; "store halfword, load byte; +0x0"
)]
#[test_case(
    "{ r2 = memh(r4+#0x8); memh(r5+#0x0) = r2.new }",
    None,
    1,
    1,
    0x1020,
    0x1020; "store halfword, load halfword; +0x0"
)]
#[test_case(
    "{ r2 = memw(r4+#0x8); memw(r5+#0x0) = r2.new }",
    None,
    1,
    1,
    0x10202020,
    0x10202020; "store word, load word; +0x0"
)]
#[test_case(
    "{ r2 = memb(r4+#0x8); nop; memb(r5) = r2.new }",
    None,
    2,
    1,
    0x18,
    0x18; "store byte, load byte, with no op; +0x0"
)]
fn test_dotnew_basic_cases(
    insn: &str,
    verify_insn: Option<Vec<u8>>,
    insn_count_1: u64,
    insn_count_2: u64,
    write_value: u32,
    read_value: u32,
) {
    test_dotnew_basic(
        insn,
        verify_insn,
        insn_count_1,
        insn_count_2,
        write_value,
        read_value,
    );
}

#[test]
fn test_store_dotnew_halfword_add() {
    // This gets reordered.
    // the r0 add is first
    // r10 add second
    // store third
    // load fourth
    let (mut cpu, _mmu, _ev) = test_dotnew_basic(
        "{ r2 = memh(r4+#0x8); r0 = add(r0, #40); r10 = add(r10, #30); memh(r5) = r0.new }",
        None,
        3,
        1,
        0x1020,
        40,
    );

    let r10 = cpu.read_register::<u32>(HexagonRegister::R10).unwrap();
    let r0 = cpu.read_register::<u32>(HexagonRegister::R0).unwrap();
    assert_eq!(r10, 30);
    assert_eq!(r0, 40);
}

#[test]
fn test_store_dotnew_halfword_add_immext() {
    // There should be an immext here somewhere, which is the point
    // The immext is moved to the beginning
    let (mut cpu, _mmu, _ev) = test_dotnew_basic(
        "{ r2 = memh(r4+#0x8); r10 = add(r10, #269492265); memh(r5) = r2.new }",
        None,
        3,
        1,
        0x1020,
        0x1020,
    );

    let r10 = cpu.read_register::<u32>(HexagonRegister::R10).unwrap();
    assert_eq!(r10, 269492265);
}

#[test]
fn test_predicate_dotnew() {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
       0:	40 40 00 75	75004040 { 	p0 = cmp.eq(r0,#0x2)
       4:	21 60 00 7e	7e006021   	if (p0.new) r1 = #0x1
       8:	41 e0 80 7e	7e80e041   	if (!p0.new) r1 = #0x2 }
"#,
    );
    cpu.write_register(HexagonRegister::R0, 2u32).unwrap();
    cpu.write_register(HexagonRegister::R1, 1u32).unwrap();

    // We'll have two instructions for each immext, and then the second instruction
    // doesn't have an immediate _extension_ so we're good on that end, total
    // 5 instructions
    // TODO: does immext need to be set to 0xffffffff every cycle?
    // it doesn't seem like it..
    let exit = cpu.execute(&mut mmu, &mut ev, 3).unwrap();

    assert_eq!(exit, TargetExitReason::InstructionCountComplete);

    let r0 = cpu.read_register::<u32>(HexagonRegister::R0).unwrap();
    let r1 = cpu.read_register::<u32>(HexagonRegister::R1).unwrap();

    // I don't think there's any overflow here, but if the
    // test cases are changed we should be careful
    assert_eq!(r0, 2);
    assert_eq!(r1, 1);
}

fn test_dotnew_basic(
    insn: &str,
    verify_insn: Option<Vec<u8>>,
    insn_count_1: u64,
    insn_count_2: u64,
    write_value: u32,
    read_value: u32,
) -> (PcodeBackend, Mmu, EventController) {
    // I copied this from the manual
    let (mut cpu, mut mmu, mut ev) = setup_asm(insn, verify_insn);
    const SRC_MEMLOC: u64 = 20;
    const DST_MEMLOC: u64 = 40;
    cpu.write_register(HexagonRegister::R2, 0xf001u32).unwrap();
    cpu.write_register(HexagonRegister::R4, SRC_MEMLOC as u32)
        .unwrap();
    cpu.write_register(HexagonRegister::R5, DST_MEMLOC as u32)
        .unwrap();

    // byte layout 0x20 0x10
    mmu.write_u32_le_virt_data(SRC_MEMLOC + 8, write_value)
        .unwrap();

    // Load
    let exit = cpu.execute(&mut mmu, &mut ev, insn_count_1).unwrap();
    assert_eq!(exit, TargetExitReason::InstructionCountComplete);

    let r2 = cpu.read_register::<u32>(HexagonRegister::R2).unwrap();
    assert_eq!(r2, write_value);

    // Store
    let exit = cpu.execute(&mut mmu, &mut ev, insn_count_2).unwrap();
    assert_eq!(exit, TargetExitReason::InstructionCountComplete);

    let data = mmu.read_u32_le_virt_data(DST_MEMLOC).unwrap();
    assert_eq!(data, read_value);

    (cpu, mmu, ev)
}
