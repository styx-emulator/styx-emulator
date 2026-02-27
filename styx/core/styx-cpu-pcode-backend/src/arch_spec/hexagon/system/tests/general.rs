// SPDX-License-Identifier: BSD-2-Clause
use crate::arch_spec::hexagon::tests::*;
use styx_cpu_type::arch::backends::ArchRegister;
use tap::Conv;

#[test]
fn test_single_instruction() {
    let (mut cpu, mut mmu, mut ev) = setup_asm("{ r5 = r0; }", None);
    const WRITTEN: u32 = 0x29177717;
    cpu.write_register(HexagonRegister::R0, WRITTEN).unwrap();

    let initial_isa_pc = get_isa_pc(&mut cpu);
    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();

    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let r5 = cpu.read_register::<u32>(HexagonRegister::R5).unwrap();

    // This *should* be the ISA PC
    let end_isa_pc = get_isa_pc(&mut cpu);

    assert_eq!(r5, WRITTEN);
    assert_eq!(end_isa_pc - initial_isa_pc, 4);
}

/// Almost the same as the equivalent test for [PcodeBackend].
#[test]
fn test_reg_read_write_wrong_size() {
    let (mut cpu, _mmu, _ev) = setup_cpu();

    let reg = HexagonRegister::R0.conv::<ArchRegister>();
    let res = cpu.write_register(reg, 10u64);
    assert!(res.is_err());
    let res = cpu.write_register(reg, 10u16);
    assert!(res.is_err());
    let res = cpu.read_register::<u64>(reg);
    assert!(res.is_err());
}
