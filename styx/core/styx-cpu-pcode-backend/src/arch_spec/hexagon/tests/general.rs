use crate::arch_spec::hexagon::tests::*;

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
