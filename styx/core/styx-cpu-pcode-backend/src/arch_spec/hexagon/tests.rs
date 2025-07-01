use keystone_engine::Keystone;
use log::trace;
use styx_cpu_type::{
    arch::hexagon::{HexagonRegister, HexagonVariants},
    Arch, ArchEndian, TargetExitReason,
};
use styx_processor::{
    event_controller::EventController,
    memory::{helpers::WriteExt, Mmu},
};
use test_case::test_case;

use crate::{register_manager::RegisterManager, PcodeBackend};
use styx_processor::cpu::{CpuBackend, CpuBackendExt};

fn setup_asm(asm_str: &str, expected_asm: Option<Vec<u8>>) -> (PcodeBackend, Mmu, EventController) {
    styx_util::logging::init_logging();
    // objdump from example ppc program
    // notably load/store operations are omitted because sleigh uses dynamic pointers
    //   to represent memory spaces which change run to run.
    let init_pc = 0x1000u64;

    // Assemble instructions
    // Processor default to thumb so we use that
    let ks = Keystone::new(
        keystone_engine::Arch::HEXAGON,
        keystone_engine::Mode::BIG_ENDIAN,
    )
    .expect("Could not initialize Keystone engine");
    let asm = ks
        .asm(asm_str.to_owned(), init_pc)
        .expect("Could not assemble");
    let code = asm.bytes;

    // Optional param
    if let Some(expected_asm) = expected_asm {
        assert_eq!(code, expected_asm);
    }
    trace!("bytes {:x?} asm {}", code, asm_str);

    // takes the objdump and extracts the binary from it
    //  duplex instruction:
    setup_cpu(init_pc, code)
}

fn setup_cpu(init_pc: u64, code: Vec<u8>) -> (PcodeBackend, Mmu, EventController) {
    let mut cpu = PcodeBackend::new_engine(
        Arch::Hexagon,
        HexagonVariants::QDSP6V66,
        ArchEndian::BigEndian,
    );

    cpu.set_pc(init_pc).unwrap();

    let mut mmu = Mmu::default();
    let ev = EventController::default();
    mmu.code().write(init_pc).bytes(&code).unwrap();

    (cpu, mmu, ev)
}

fn get_isa_pc(cpu: &mut PcodeBackend) -> u32 {
    RegisterManager::read_register(cpu, HexagonRegister::Pc.into())
        .unwrap()
        .to_u64()
        .unwrap() as u32
}

// need a separate conditional too
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

// also need one that does something like R2 = mpyi(R0, add(R1, #1))
// need to test load/stores here

#[test]
fn test_store_dotnew_halfword_add() {
    // This gets reordered.
    // the r0 add is first
    // r10 add second
    // store third
    // load fourth
    let (mut cpu, mmu, ev) = test_dotnew_basic(
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
    let (mut cpu, mmu, ev) = test_dotnew_basic(
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
    styx_util::logging::init_logging();
    let (mut cpu, mut mmu, mut ev) = setup_cpu(
        0x1000,
        styx_util::parse_objdump(
            r#"
       0:	40 40 00 75	75004040 { 	p0 = cmp.eq(r0,#0x2)
       4:	21 60 00 7e	7e006021   	if (p0.new) r1 = #0x1
       8:	41 e0 80 7e	7e80e041   	if (!p0.new) r1 = #0x2 }
"#,
        )
        .unwrap(),
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

#[test]
fn test_hwloop_predicate() {
    styx_util::logging::init_logging();
    // a loop1 should have at min 3 insns in its packet
    // runs 3 times
    let (mut cpu, mut mmu, mut ev) = setup_cpu(
        0x1000,
        styx_util::parse_objdump(
            r#"
       0:	0b c0 00 69	6900c00b { 	loop0(0x4,#0x3) }
       4:	60 c2 80 75	7580c260 { 	p0 = cmp.gtu(r0,#0x13) }
       8:	40 81 80 74	74808140 { 	if (!p0) r0 = add(r0,#0xa)
       c:	00 c0 00 7f	7f00c000   	nop }  :endloop0
       10:	41 f2 00 78	7800f241 { 	r1 = #0x192 }
        "#,
        )
        .unwrap(),
    );

    cpu.write_register(HexagonRegister::R0, 0u32).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 11).unwrap();
    assert_eq!(exit, TargetExitReason::InstructionCountComplete);

    let r0 = cpu.read_register::<u32>(HexagonRegister::R0).unwrap();
    let r1 = cpu.read_register::<u32>(HexagonRegister::R1).unwrap();

    assert_eq!(r0, 20);
    assert_eq!(r1, 402);
}

// similar to the other inner loop one
#[test]
fn test_hwloop_inner() {
    styx_util::logging::init_logging();

    // a loop1 should have at min 3 insns in its packet
    // runs 3 times
    let (mut cpu, mut mmu, mut ev) = setup_cpu(
        0x1000,
        styx_util::parse_objdump(
            r#"
       0:	0b c0 20 69	6920c00b { 	loop1(0x4,#0x3) }
       4:	0b c0 00 69	6900c00b { 	loop0(0x8,#0x3) }
       8:	42 80 02 e0	e0028042 { 	r2 = +mpyi(r2,#0x2)
       c:	01 c0 01 f3	f301c001   	r1 = add(r1,r0) }  :endloop0
      10:	20 40 00 b0	b0004020 { 	r0 = add(r0,#0x1)
      14:	00 80 00 7f	7f008000   	nop
      18:	00 c0 00 7f	7f00c000   	nop }  :endloop1
      1c:	03 f2 00 78	7800f203 { 	r3 = #0x190 }
        "#,
        )
        .unwrap(),
    );

    cpu.write_register(HexagonRegister::R0, 2u32).unwrap();
    cpu.write_register(HexagonRegister::R1, 0u32).unwrap();
    cpu.write_register(HexagonRegister::R2, 3u32).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 32).unwrap();
    assert_eq!(exit, TargetExitReason::InstructionCountComplete);

    let r0 = cpu.read_register::<u32>(HexagonRegister::R0).unwrap();
    let r1 = cpu.read_register::<u32>(HexagonRegister::R1).unwrap();
    let r2 = cpu.read_register::<u32>(HexagonRegister::R2).unwrap();
    let r3 = cpu.read_register::<u32>(HexagonRegister::R3).unwrap();

    assert_eq!(r0, 5);
    assert_eq!(r1, (2 * 3) + (3 * 3) + (4 * 3));
    assert_eq!(r2, 3 * 512);
    assert_eq!(r3, 400);
}

#[test]
fn test_hwloop1() {
    styx_util::logging::init_logging();
    // multiply by 2 to r0, add 1 to r1.

    // a loop1 should have at min 3 insns in its packet
    // runs 3 times
    let (mut cpu, mut mmu, mut ev) = setup_cpu(
        0x1000,
        styx_util::parse_objdump(
            r#"
       0:	0b c0 20 69	6920c00b { 	loop1(0x4,#0x3) }
       4:	40 40 00 e0	e0004040 { 	r0 = +mpyi(r0,#0x2)
       8:	21 80 01 b0	b0018021   	r1 = add(r1,#0x1)
       c:	00 c0 00 7f	7f00c000   	nop }  :endloop1
        "#,
        )
        .unwrap(),
    );

    cpu.write_register(HexagonRegister::R0, 3u32).unwrap();
    cpu.write_register(HexagonRegister::R1, 29u32).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 10).unwrap();
    assert_eq!(exit, TargetExitReason::InstructionCountComplete);

    let r0 = cpu.read_register::<u32>(HexagonRegister::R0).unwrap();
    let r1 = cpu.read_register::<u32>(HexagonRegister::R1).unwrap();

    assert_eq!(r0, 24);
    assert_eq!(r1, 32);
}

#[test]
fn test_hwloop01() {
    styx_util::logging::init_logging();

    let (mut cpu, mut mmu, mut ev) = setup_cpu(
        0x1000,
        styx_util::parse_objdump(
            r#"
       0:	0b c0 20 69	6920c00b { 	loop1(0x4,#0x3) }
       4:	20 c0 00 b0	b000c020 { 	r0 = add(r0,#0x1) }
       8:	0b c0 00 69	6900c00b { 	loop0(0xc,#0x3) }
       c:	42 80 02 e0	e0028042 { 	r2 = +mpyi(r2,#0x2)
      10:	01 80 01 f3	f3018001   	r1 = add(r1,r0)
      14:	00 c0 00 7f	7f00c000   	nop }  :endloop01
      18:	03 f2 00 78	7800f203 { 	r3 = #0x190 }
    "#,
        )
        .unwrap(),
    );

    cpu.write_register(HexagonRegister::R0, 0u32).unwrap();
    cpu.write_register(HexagonRegister::R1, 0u32).unwrap();
    cpu.write_register(HexagonRegister::R2, 1u32).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 35).unwrap();
    assert_eq!(exit, TargetExitReason::InstructionCountComplete);

    let r0 = cpu.read_register::<u32>(HexagonRegister::R0).unwrap();
    let r1 = cpu.read_register::<u32>(HexagonRegister::R1).unwrap();
    let r2 = cpu.read_register::<u32>(HexagonRegister::R2).unwrap();
    let r3 = cpu.read_register::<u32>(HexagonRegister::R3).unwrap();

    assert_eq!(r0, 3);
    assert_eq!(r1, (1 * 3) + (2 * 3) + (3 * 3));
    assert_eq!(r2, 512); // 2 ** 9
    assert_eq!(r3, 400); // 2 ** 9
}

#[test]
fn test_hwloop0() {
    styx_util::logging::init_logging();
    /* copied from the manual
     * The code is:
     * loop0(start,#3);
     * // Loop 3 times
     *start:
     * { R0 = mpyi(R0,R0) } :endloop0
     */
    let (mut cpu, mut mmu, mut ev) = setup_cpu(
        0x1000,
        vec![
            0x0b, 0xc0, 0x00, 0x69, 0x00, 0x80, 0x0, 0xed, 0x0, 0xc0, 0x0, 0x7f,
        ],
    );

    cpu.write_register(HexagonRegister::R0, 7u32).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 7).unwrap();
    assert_eq!(exit, TargetExitReason::InstructionCountComplete);

    let r0 = cpu.read_register::<u32>(HexagonRegister::R0).unwrap();

    assert_eq!(r0, 5764801);
}

#[test]
fn test_duplex_immext() {
    let (mut cpu, mut mmu, mut ev) = setup_asm(
        "{ R4 = mpyi(R0, R1); }; { R2 = #1905856528; R3 = R0; }",
        None,
    );

    cpu.write_register(HexagonRegister::R0, 100u32).unwrap();
    cpu.write_register(HexagonRegister::R1, 470u32).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 4).unwrap();
    assert_eq!(exit, TargetExitReason::InstructionCountComplete);

    let r2 = cpu.read_register::<u32>(HexagonRegister::R2).unwrap();
    let r3 = cpu.read_register::<u32>(HexagonRegister::R3).unwrap();
    let r4 = cpu.read_register::<u32>(HexagonRegister::R4).unwrap();

    assert_eq!(r2, 1905856528u32);
    assert_eq!(r3, 100);
    assert_eq!(r4, 100 * 470);
}

// TODO: can you mix a duplex instruction with some other stuff in a packet?
#[test]
fn test_packet_instructions() {
    // Packet instructions are interesting, as they are reordered to reflect the
    // appropriate slots and such.
    let (mut cpu, mut mmu, mut ev) = setup_asm(
        "{ R1 = add(R0, #32); R2 = mpyi(R3, R4); R3 = add(R5, #10); }; ",
        None,
    );
    let r0 = 71;
    let r5 = 41272;
    let mult_opts = (92, 7);

    // truncate
    let initial_isa_pc = get_isa_pc(&mut cpu);
    trace!("initial isa pc is {}", initial_isa_pc);
    cpu.write_register(HexagonRegister::R0, r0).unwrap();
    cpu.write_register(HexagonRegister::R3, mult_opts.0)
        .unwrap();
    cpu.write_register(HexagonRegister::R4, mult_opts.1)
        .unwrap();
    cpu.write_register(HexagonRegister::R5, r5).unwrap();

    // Packet is 3 insns long, let's get the PC in the middle
    // and ensure it's not moving within a packet.
    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit, TargetExitReason::InstructionCountComplete);

    // truncate
    let mid_isa_pc = get_isa_pc(&mut cpu);
    assert_eq!(mid_isa_pc, initial_isa_pc);

    // let's now finish up. The no op is because styx internally only
    // sets the pc manager's isa pc at the start of the next instruction.
    let exit = cpu.execute(&mut mmu, &mut ev, 2).unwrap();
    assert_eq!(exit, TargetExitReason::InstructionCountComplete);

    let r1 = cpu.read_register::<u32>(HexagonRegister::R1).unwrap();
    let r2 = cpu.read_register::<u32>(HexagonRegister::R2).unwrap();
    let r3 = cpu.read_register::<u32>(HexagonRegister::R3).unwrap();

    // This *should* be the ISA PC
    let end_isa_pc = get_isa_pc(&mut cpu);

    assert_eq!(r1, r0 + 32);
    assert_eq!(r2, mult_opts.0 * mult_opts.1);
    assert_eq!(r3, r5 + 10);

    trace!("initial pc is {}, new pc is {}", initial_isa_pc, end_isa_pc);

    // TODO: test pc increment at end of packet
    assert_eq!(end_isa_pc - initial_isa_pc, 12);
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
    assert_eq!(exit, TargetExitReason::InstructionCountComplete);

    let mid_isa_pc = get_isa_pc(&mut cpu);
    assert_eq!(initial_isa_pc, mid_isa_pc);

    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit, TargetExitReason::InstructionCountComplete);

    let end_isa_pc = get_isa_pc(&mut cpu);
    let r5 = cpu.read_register::<u32>(HexagonRegister::R5).unwrap();
    let r6 = cpu.read_register::<u32>(HexagonRegister::R6).unwrap();

    assert_eq!(r6, 0xdeadbeef);
    assert_eq!(r5, 0xcafeb0ba);
    assert_eq!(end_isa_pc - initial_isa_pc, 4);
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

    assert_eq!(exit, TargetExitReason::InstructionCountComplete);

    let r1 = cpu.read_register::<u32>(HexagonRegister::R1).unwrap();

    assert_eq!(r1, WRITTEN + R0VAL);
}

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

    assert_eq!(exit, TargetExitReason::InstructionCountComplete);

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

// TODO: jumpr branch (indirect), conditional branch,
// and a branch that isn't at the end of the packet!
#[test]
fn test_basic_branching() {
    const R1: u32 = 47;
    // can't get labels to work for some reason
    // this is a cool test because it's a register transfer jump
    // so the first packet is actually 1 instruction, which adds
    // some lovely edge cases
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
    assert_eq!(exit, TargetExitReason::InstructionCountComplete);

    let mid_isa_pc = get_isa_pc(&mut cpu);
    assert_eq!(mid_isa_pc - initial_isa_pc, 12);

    // There's an immext here
    trace!("starting initial multiply");
    let exit = cpu.execute(&mut mmu, &mut ev, 2).unwrap();
    assert_eq!(exit, TargetExitReason::InstructionCountComplete);

    let end_branch_isa_pc = get_isa_pc(&mut cpu);
    assert_eq!(end_branch_isa_pc - initial_isa_pc, 20);

    // Last addition
    trace!("starting addition");
    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit, TargetExitReason::InstructionCountComplete);

    let r0 = cpu.read_register::<u32>(HexagonRegister::R0).unwrap();
    let r2 = cpu.read_register::<u32>(HexagonRegister::R2).unwrap();

    assert_eq!(r0, R1 * 56);
    assert_eq!(r2, r0 + 2);
}

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

    let exit = cpu.execute(&mut mmu, &mut ev, 7).unwrap();
    assert_eq!(exit, TargetExitReason::InstructionCountComplete);

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

// duplex imm test,
// hwloop test, jump test
// .new test, interrupt test??
// later: test function calls

#[test]
fn test_single_instruction() {
    let (mut cpu, mut mmu, mut ev) = setup_asm("{ r5 = r0; }", None);
    const WRITTEN: u32 = 0x29177717;
    cpu.write_register(HexagonRegister::R0, WRITTEN).unwrap();

    let initial_isa_pc = get_isa_pc(&mut cpu);
    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();

    assert_eq!(exit, TargetExitReason::InstructionCountComplete);

    let r5 = cpu.read_register::<u32>(HexagonRegister::R5).unwrap();

    // This *should* be the ISA PC
    let end_isa_pc = get_isa_pc(&mut cpu);

    assert_eq!(r5, WRITTEN);
    assert_eq!(end_isa_pc - initial_isa_pc, 4);
}
