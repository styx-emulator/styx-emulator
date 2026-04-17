// SPDX-License-Identifier: BSD-2-Clause

use std::fmt::Debug;
use styx_cpu_type::{
    arch::{hexagon::HexagonRegister, RegisterValueCompatible},
    TargetExitReason,
};
use styx_processor::cpu::{CpuBackend, CpuBackendExt};
use test_case::test_case;

use crate::arch_spec::hexagon::tests::setup_objdump;

#[test_case(
0x778865,
0xaa88bb,
        r#"
	0:	00 c0 2b 65	652bc000 { 	crswap(r11,sgp1) }
	"#,
    HexagonRegister::R11,
    HexagonRegister::Sgp1; "sgp1 transfer"
)]
#[test_case(
0x778865,
0xaa88bb,
        r#"
	0:	00 c0 07 65	6507c000 { 	crswap(r7,sgp0) }
	"#,
    HexagonRegister::R7,
    HexagonRegister::Sgp0; "sgp0 transfer"
)]
pub fn crswap32(
    reg0_orig: u32,
    reg1_orig: u32,
    objdump: &str,

    reg0: HexagonRegister,
    reg1: HexagonRegister,
) {
    crswap(reg0_orig, reg1_orig, objdump, reg0, reg1)
}

#[test_case(
    0xaa8876549900,
    0xba3836279907,
        r#"
    0:	00 c0 8e 6d	6d8ec000 { 	crswap(r15:14,s1:0) }
    "#,
    HexagonRegister::D7,
    HexagonRegister::SGP1SGP0; "sgp 64-bit transfer"
)]
pub fn crswap64(
    reg0_orig: u64,
    reg1_orig: u64,
    objdump: &str,

    reg0: HexagonRegister,
    reg1: HexagonRegister,
) {
    crswap(reg0_orig, reg1_orig, objdump, reg0, reg1)
}

// The generics are here to easily allow for u32 and u64 versions
// to share code.
pub fn crswap<Size: RegisterValueCompatible + Eq + Debug + Copy>(
    reg0_orig: Size,
    reg1_orig: Size,
    objdump: &str,
    reg0: HexagonRegister,
    reg1: HexagonRegister,
) where
    <Size as RegisterValueCompatible>::ReturnValue: PartialEq<Size>,
    <Size as RegisterValueCompatible>::ReturnValue: Debug,
{
    let (mut cpu, mut mmu, mut ev) = setup_objdump(objdump);

    cpu.write_register(reg0, reg0_orig).unwrap();
    cpu.write_register(reg1, reg1_orig).unwrap();

    let report = cpu.execute(&mut mmu, &mut ev, 1).unwrap();

    assert_eq!(
        report.exit_reason,
        TargetExitReason::InstructionCountComplete
    );

    let reg0_read = cpu.read_register::<Size>(reg0).unwrap();
    let reg1_read = cpu.read_register::<Size>(reg1).unwrap();

    assert_eq!(reg0_read, reg1_orig);
    assert_eq!(reg1_read, reg0_orig);
}
