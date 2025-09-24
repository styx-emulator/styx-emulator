// SPDX-License-Identifier: BSD-2-Clause
use crate::arch_spec::hexagon::tests::*;
use log::trace;

#[test]
pub fn array_manipulation() {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(
        r#"
       0:	2a c0 00 78	7800c02a { 	r10 = #0x1 }
       4:	27 c1 02 8c	8c02c127 { 	r7 = lsr(r2,#0x1) }
       8:	08 c0 02 60	6002c008 { 	loop0(0xc,r2) }
       c:	03 c0 01 6a	6a01c003 { 	r3 = lc0 }
      10:	03 42 23 f3	f3234203 { 	r3 = sub(r2,r3)
      14:	06 c7 23 f3	f323c706   	r6 = sub(r7,r3) }
      18:	60 40 43 75	75434060 { 	p0 = cmp.gt(r3,#0x3)
      1c:	04 43 00 3a	3a004304   	r4 = memb(r0+r3<<#0x0)
      20:	02 c6 a1 36	36a1c602   	if (p0.new) memb(r1+r6<<#0x0) = r4.new }
      24:	05 a0 04 74	7404a005 { 	if (p0.new) r5 = add(r4,#0x0)
      28:	00 c5 44 f2	f244c500   	p0 = cmp.gt(r4,r5) }  :endloop0
      2c:	4a c0 00 78	7800c04a { 	r10 = #0x2 }
"#,
    );

    let arr1_memloc = 0x100u64;
    let arr2_memloc = 0x200u64;

    // Set up 8 element array
    let arr = [6u8, 94, 33, 7, 40, 2, 13, 2];
    trace!("array to write is {arr:?}");

    for (i, it) in arr.iter().enumerate() {
        let addr = arr1_memloc + i as u64;
        trace!("writing {it} to memory address 0x{addr:x}");

        mmu.write_u8_le_virt_data(addr, *it, &mut cpu).unwrap();
    }
    cpu.write_register(HexagonRegister::R0, arr1_memloc as u32)
        .unwrap();
    cpu.write_register(HexagonRegister::R1, arr2_memloc as u32)
        .unwrap();
    cpu.write_register(HexagonRegister::R2, arr.len() as u32)
        .unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 8 * 4 + 4).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);

    let mut arr = [0u8; 4];
    // Read out 4 element array
    for (i, item) in arr.iter_mut().enumerate() {
        let addr = arr2_memloc + i as u64;
        let val = mmu.read_u8_le_virt_data(addr, &mut cpu).unwrap();

        trace!("read {val} at memory address 0x{addr:x}");
        *item = val;
    }

    let max = cpu.read_register::<u32>(HexagonRegister::R5).unwrap();
    let check = cpu.read_register::<u32>(HexagonRegister::R10).unwrap();

    trace!("found max was {max}");
    trace!("read array {arr:?}");

    assert_eq!(max, 94);
    assert_eq!(check, 2);
    assert_eq!(arr, [40, 2, 13, 2]);
}
