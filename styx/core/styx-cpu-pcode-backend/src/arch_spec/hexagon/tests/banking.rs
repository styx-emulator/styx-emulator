// SPDX-License-Identifier: BSD-2-Clause
use crate::arch_spec::hexagon::tests::*;

// The holy grail of packet semantics
#[test]
pub fn test_swap() {
    let (mut cpu, mut mmu, mut ev) = setup_asm("{ R1 = R2; R2 = R1; }; ", None);

    cpu.write_register(HexagonRegister::R1, 18u32).unwrap();
    cpu.write_register(HexagonRegister::R2, 81u32).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let r1 = cpu.read_register::<u32>(HexagonRegister::R1).unwrap();
    let r2 = cpu.read_register::<u32>(HexagonRegister::R2).unwrap();
    assert_eq!(r1, 81);
    assert_eq!(r2, 18);
}
