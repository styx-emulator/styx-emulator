use crate::arch_spec::hexagon::tests::*;

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
      1c:	24 f2 00 78	7800f224 { 	r4 = #0x191 }
      20:	45 f2 00 78	7800f245 { 	r5 = #0x192 }
    "#,
        )
        .unwrap(),
    );

    cpu.write_register(HexagonRegister::R0, 0u32).unwrap();
    cpu.write_register(HexagonRegister::R1, 0u32).unwrap();
    cpu.write_register(HexagonRegister::R2, 1u32).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 37).unwrap();
    assert_eq!(exit, TargetExitReason::InstructionCountComplete);

    let r0 = cpu.read_register::<u32>(HexagonRegister::R0).unwrap();
    let r1 = cpu.read_register::<u32>(HexagonRegister::R1).unwrap();
    let r2 = cpu.read_register::<u32>(HexagonRegister::R2).unwrap();
    let r3 = cpu.read_register::<u32>(HexagonRegister::R3).unwrap();
    let r4 = cpu.read_register::<u32>(HexagonRegister::R4).unwrap();
    let r5 = cpu.read_register::<u32>(HexagonRegister::R5).unwrap();

    assert_eq!(r0, 3);
    assert_eq!(r1, (1 * 3) + (2 * 3) + (3 * 3));
    assert_eq!(r2, 512); // 2 ** 9
    assert_eq!(r3, 0x190); // 2 ** 9
    assert_eq!(r4, 0x191);
    assert_eq!(r5, 0x192);
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
      1c:	03 72 00 78	78007203 { 	r3 = #0x190
      20:	44 d0 14 78	7814d044   	r4 = #0x2882 }
      24:	06 42 00 78	78004206 { 	r6 = #0x10
      28:	47 d0 01 78	7801d047   	r7 = #0x282 }
        "#,
        )
        .unwrap(),
    );

    cpu.write_register(HexagonRegister::R0, 2u32).unwrap();
    cpu.write_register(HexagonRegister::R1, 0u32).unwrap();
    cpu.write_register(HexagonRegister::R2, 3u32).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 35).unwrap();
    assert_eq!(exit, TargetExitReason::InstructionCountComplete);

    // TODO: need to check that the last packet sets context option for hexagonendloop, and
    // that their pcodes are only length 1 each.

    let r0 = cpu.read_register::<u32>(HexagonRegister::R0).unwrap();
    let r1 = cpu.read_register::<u32>(HexagonRegister::R1).unwrap();
    let r2 = cpu.read_register::<u32>(HexagonRegister::R2).unwrap();
    let r3 = cpu.read_register::<u32>(HexagonRegister::R3).unwrap();
    let r4 = cpu.read_register::<u32>(HexagonRegister::R4).unwrap();
    let r6 = cpu.read_register::<u32>(HexagonRegister::R6).unwrap();
    let r7 = cpu.read_register::<u32>(HexagonRegister::R7).unwrap();

    assert_eq!(r0, 5);
    assert_eq!(r1, (2 * 3) + (3 * 3) + (4 * 3));
    assert_eq!(r2, 3 * 512);
    assert_eq!(r3, 400);
    assert_eq!(r4, 0x2882);
    assert_eq!(r6, 0x10);
    assert_eq!(r7, 0x282);
}

#[test]
fn test_hwloop0_iteronce() {
    styx_util::logging::init_logging();
    // multiply by 2 to r0, add 1 to r1.

    // a loop1 should have at min 3 insns in its packet
    // runs 3 times
    let (mut cpu, mut mmu, mut ev) = setup_cpu(
        0x1000,
        styx_util::parse_objdump(
            r#"
       0:	09 c0 20 69	6920c009 { 	loop1(0x4,#0x1) }
       4:	40 40 00 e1	e1004040 { 	r0 += mpyi(r0,#0x2)
       8:	21 80 01 b0	b0018021   	r1 = add(r1,#0x1)
       c:	00 c0 00 7f	7f00c000   	nop }  :endloop1
      10:	62 6e 09 78	78096e62 { 	r2 = #0x1373
      14:	83 d7 07 78	7807d783   	r3 = #0xebc }
        "#,
        )
        .unwrap(),
    );

    cpu.write_register(HexagonRegister::R0, 3u32).unwrap();
    cpu.write_register(HexagonRegister::R1, 29u32).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 6).unwrap();
    assert_eq!(exit, TargetExitReason::InstructionCountComplete);

    let r0 = cpu.read_register::<u32>(HexagonRegister::R0).unwrap();
    let r1 = cpu.read_register::<u32>(HexagonRegister::R1).unwrap();
    let r2 = cpu.read_register::<u32>(HexagonRegister::R2).unwrap();
    let r3 = cpu.read_register::<u32>(HexagonRegister::R3).unwrap();

    assert_eq!(r0, 9);
    assert_eq!(r1, 30);
    assert_eq!(r2, 0x1373);
    assert_eq!(r3, 0xebc);
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
