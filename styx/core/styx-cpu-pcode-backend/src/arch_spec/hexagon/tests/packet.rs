use crate::arch_spec::hexagon::tests::*;

// TODO: can you mix a duplex instruction with some other stuff in a packet?
// (yes, this is tested somewhere here)
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
