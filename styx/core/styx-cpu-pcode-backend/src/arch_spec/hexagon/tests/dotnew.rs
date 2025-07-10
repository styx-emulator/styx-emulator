use crate::arch_spec::hexagon::tests::*;
use log::info;
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

    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

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
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let r2 = cpu.read_register::<u32>(HexagonRegister::R2).unwrap();
    assert_eq!(r2, write_value);

    // Store
    let exit = cpu.execute(&mut mmu, &mut ev, insn_count_2).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let data = mmu.read_u32_le_virt_data(DST_MEMLOC).unwrap();
    assert_eq!(data, read_value);

    (cpu, mmu, ev)
}

type ExtraCheckHandlerFn = Box<dyn Fn(&mut PcodeBackend, bool)>;

struct DotnewGenericTestCase {
    asm: String,
    insns_to_exec: u64,
    extra_check_handler: ExtraCheckHandlerFn,
    iclass: u8,
    expected_bytes: usize,
    predicate_type: PredicateType,
}

#[derive(Copy, Clone, PartialEq, Debug)]
enum PredicateType {
    NegatedPredicate,
    Predicate,
    None,
}

#[derive(Copy, Clone)]
enum DotnewSizes {
    Byte,
    Halfword,
    Word,
}

#[test]
fn test_all_dotnew_class() {
    styx_util::logging::init_logging();

    let mem_base = 0x100u32;
    let mem_initval = 0x43287761;
    let init_pc = 0x1000;

    let ks = Keystone::new(
        keystone_engine::Arch::HEXAGON,
        keystone_engine::Mode::LITTLE_ENDIAN,
    )
    .expect("Could not initialize Keystone engine");

    let classes = vec![
        DotnewGenericTestCase {
            asm:
                "{ P2 = cmp.eq(R4, #4); } { R0 = memw(R3 + #0x0); if (P2)	mem%0(R3+R2<<#2)=R0.new }"
                    .to_owned(),
            insns_to_exec: 3,
            extra_check_handler: Box::new(|_backend: &mut PcodeBackend, _branch_taken: bool| {})
                as ExtraCheckHandlerFn,
            iclass: 0b0011,
            expected_bytes: 12,
            predicate_type: PredicateType::Predicate,
        },
        DotnewGenericTestCase {
            asm: "{ P2 = cmp.eq(R4, #4);  R0 = memw(R3 + #0x0); if (P2.new)	mem%0(R3+#4)=R0.new }"
                .to_owned(),
            insns_to_exec: 3,
            extra_check_handler: Box::new(|_backend: &mut PcodeBackend, _branch_taken: bool| {}),
            iclass: 0b0100,
            expected_bytes: 12,
            predicate_type: PredicateType::Predicate,
        },
        DotnewGenericTestCase {
            asm:
                "{ P2 = cmp.eq(R4, #4); } { R0 = memw(R3 + #0x0); if (!P2)	mem%0(R10++#4)=R0.new }"
                    .to_owned(),
            insns_to_exec: 3,
            extra_check_handler: Box::new(|backend: &mut PcodeBackend, branch_taken| {
                let r10 = backend.read_register::<u32>(HexagonRegister::R10).unwrap();
                if branch_taken {
                    assert_eq!(0x108, r10);
                } else {
                    assert_eq!(0x104, r10)
                }
            }),
            iclass: 0b1010,
            expected_bytes: 12,
            predicate_type: PredicateType::NegatedPredicate,
        },
        DotnewGenericTestCase {
            asm: "{ P2 = cmp.eq(R4, #4); R0 = memw(R3 + #0x0); if (!P2.new)	mem%0(#0x104)=R0.new }"
                .to_owned(),
            insns_to_exec: 4,
            extra_check_handler: Box::new(|_backend: &mut PcodeBackend, _branch_taken: bool| {}),
            iclass: 0b1010,
            expected_bytes: 16,
            predicate_type: PredicateType::NegatedPredicate,
        },
        DotnewGenericTestCase {
            asm: "{ R0 = memw(R3 + #0x0); mem%0(r5=#0x104)=R0.new }".to_owned(),
            insns_to_exec: 3,
            extra_check_handler: Box::new(|backend: &mut PcodeBackend, _branch_taken: bool| {
                let r5 = backend.read_register::<u32>(HexagonRegister::R5).unwrap();
                assert_eq!(0x104, r5);
            }),
            iclass: 0b1010,
            expected_bytes: 12,
            predicate_type: PredicateType::None,
        },
        DotnewGenericTestCase {
            asm: "{ R0 = memw(R3 + #0x0); mem%0(gp+#4)=R0.new }".to_owned(),
            insns_to_exec: 2,
            extra_check_handler: Box::new(|_backend: &mut PcodeBackend, _branch_taken: bool| {}),
            iclass: 0b0100,
            expected_bytes: 8,
            predicate_type: PredicateType::None,
        },
        DotnewGenericTestCase {
            asm: "{ R0 = memw(R3 + #0x0); mem%0(r3+r2<<#2)=R0.new }".to_owned(),
            insns_to_exec: 2,
            extra_check_handler: Box::new(|_backend: &mut PcodeBackend, _branch_taken: bool| {}),
            iclass: 0b0011,
            expected_bytes: 8,
            predicate_type: PredicateType::None,
        },
    ];

    let sizes = [DotnewSizes::Byte, DotnewSizes::Halfword, DotnewSizes::Word];

    for case in classes {
        for size in sizes {
            let iters = if case.predicate_type != PredicateType::None {
                2
            } else {
                1
            };

            for i in 0..iters {
                // Regular predicate
                let branch_taken_or_no_predicate = i == 0;

                trace!(
                    "iter {}, branch taken or no predicate {}, predicate type {:?}",
                    i,
                    branch_taken_or_no_predicate,
                    case.predicate_type
                );

                let postfix = match size {
                    DotnewSizes::Byte => "b",
                    DotnewSizes::Halfword => "h",
                    DotnewSizes::Word => "w",
                };

                let subst_asm = case.asm.replace("%0", postfix);
                info!("assembling {}", subst_asm);

                let code = ks
                    .asm(subst_asm.clone(), init_pc)
                    .expect("Could not assemble");

                trace!("code is {:?}", code);

                assert_eq!(code.bytes.len(), case.expected_bytes);

                // get last 4 bytes (last insn is dotnew) and make sure iclass matches
                let last_4: [u8; 4] = code.bytes[(case.expected_bytes - 4)..(case.expected_bytes)]
                    .try_into()
                    .expect("Couldn't extract last insn");

                let insn = u32::from_le_bytes(last_4);
                let iclass = (insn >> 28) & 0xf;

                assert_eq!(iclass, case.iclass as u32);

                let (mut cpu, mut mmu, mut ev) = setup_cpu(init_pc, code.bytes);

                cpu.write_register(HexagonRegister::R2, 1u32).unwrap();
                cpu.write_register(HexagonRegister::R3, mem_base).unwrap();

                // This sets it so the negated predicate and predicate both fail
                // on the second iteration
                if (i == 0
                    && case.predicate_type == PredicateType::NegatedPredicate)
                    // To force this to fail
                    || (i == 1
                        && case.predicate_type == PredicateType::Predicate)
                {
                    trace!("branch taken, negated predicate");
                    cpu.write_register(HexagonRegister::R4, 3u32).unwrap();
                } else {
                    cpu.write_register(HexagonRegister::R4, 4u32).unwrap();
                }

                cpu.write_register(HexagonRegister::Gp, mem_base).unwrap();
                // This is for the "indirect with auto increment"
                cpu.write_register(HexagonRegister::R10, mem_base + 4)
                    .unwrap();

                // Write memory
                mmu.write_u32_le_virt_data(mem_base as u64, mem_initval)
                    .unwrap();

                // Run
                let exit = cpu.execute(&mut mmu, &mut ev, case.insns_to_exec).unwrap();
                assert_eq!(TargetExitReason::InstructionCountComplete, exit.exit_reason);

                // Read from memory
                let addr = mem_base + 4;
                let expected_val = if branch_taken_or_no_predicate {
                    trace!("checking memory bc branch taken or no predicate");
                    match size {
                        DotnewSizes::Byte => mem_initval & 0xff,
                        DotnewSizes::Halfword => mem_initval & 0xffff,
                        DotnewSizes::Word => mem_initval,
                    }
                } else {
                    0
                };

                let val = mmu.read_u32_le_virt_data(addr as u64).unwrap();
                assert_eq!(val, expected_val);

                (case.extra_check_handler)(&mut cpu, branch_taken_or_no_predicate);
            }
        }
    }
}
