// SPDX-License-Identifier: BSD-2-Clause
use crate::arch_spec::hexagon::tests::*;
use smallvec::{smallvec, SmallVec};
use test_case::test_case;

#[test_case(
    r#"
        0:	00 62 01 fb	fb016200 { 	if (p0.new) r0 = add(r1,r2)
        4:	00 42 01 f2	f2014200   	p0 = cmp.eq(r1,r2)
        8:	23 65 04 fb	fb046523   	if (p1.new) r3 = add(r4,r5)
        c:	01 c5 04 f2	f204c501   	p1 = cmp.eq(r4,r5) }
    "#,
    smallvec![1, 3, 0, 2]; "two reorders, alternating"
)]
#[test_case(
    r#"
        0:	00 62 01 fb	fb016200 { 	if (p0.new) r0 = add(r1,r2)
        4:	01 45 04 f2	f2044501   	p1 = cmp.eq(r4,r5)
        8:	00 42 01 f2	f2014200   	p0 = cmp.eq(r1,r2)
        c:	23 e5 04 fb	fb04e523   	if (p1.new) r3 = add(r4,r5) }
    "#,
    smallvec![2, 0, 1, 3];
    "only one reorder, immediately after"
)]
#[test_case(
    r#"
       0:	00 62 01 fb	fb016200 { 	if (p0.new) r0 = add(r1,r2)
       4:	23 65 04 fb	fb046523   	if (p1.new) r3 = add(r4,r5)
       8:	01 45 04 f2	f2044501   	p1 = cmp.eq(r4,r5)
       c:	00 c2 01 f2	f201c200   	p0 = cmp.eq(r1,r2) }
    "#,
    smallvec![2, 3, 0, 1]; "two reorders, contiguous"
)]
#[test_case(
    r#"
       0:	00 62 01 fb	fb016200 { 	if (p0.new) r0 = add(r1,r2)
       4:	01 45 04 f2	f2044501   	p1 = cmp.eq(r4,r5)
       8:	23 65 04 fb	fb046523   	if (p1.new) r3 = add(r4,r5)
       c:	00 c2 01 f2	f201c200   	p0 = cmp.eq(r1,r2) }
    "#,
    smallvec![3, 0, 1, 2]; "one reorder, at the end"
)]
#[test_case(
    r#"
       0:	00 62 01 fb	fb016200 { 	if (p0.new) r0 = add(r1,r2)
       4:	03 45 04 f3	f3044503   	r3 = add(r4,r5)
       8:	00 c2 01 f2	f201c200   	p0 = cmp.eq(r1,r2) }
    "#,
    smallvec![2, 0, 1]; "three instructions, one reorder at end"
)]
#[test_case(
    r#"
       0:	00 62 01 fb	fb016200 { 	if (p0.new) r0 = add(r1,r2)
       4:	00 42 01 f2	f2014200   	p0 = cmp.eq(r1,r2)
       8:	03 c5 04 f3	f304c503   	r3 = add(r4,r5) }
    "#,
    smallvec![1, 0, 2]; "three instructions, one reorder at middle"
)]
#[test_case(
    r#"
       0:	00 42 01 f2	f2014200 { 	p0 = cmp.eq(r1,r2)
       4:	00 62 01 fb	fb016200   	if (p0.new) r0 = add(r1,r2)
       8:	03 c5 04 f3	f304c503   	r3 = add(r4,r5) }
    "#,
    smallvec![0, 1, 2]; "three instructions, no reordering"
)]
#[test_case(
    r#"
       0:	01 45 04 f2	f2044501 { 	p1 = cmp.eq(r4,r5)
       4:	00 42 01 f2	f2014200   	p0 = cmp.eq(r1,r2)
       8:	23 65 04 fb	fb046523   	if (p1.new) r3 = add(r4,r5)
       c:	00 e2 01 fb	fb01e200   	if (p0.new) r0 = add(r1,r2) }
    "#,
    smallvec![0, 1, 2, 3]; "four instructions, no reordering"
)]
#[test_case(
    r#"
       0:	01 42 01 f2	f2014201 { 	p1 = cmp.eq(r1,r2)
       4:	20 62 01 fb	fb016220   	if (p1.new) r0 = add(r1,r2)
       8:	01 45 04 f2	f2044501   	p1 = cmp.eq(r4,r5)
       c:	03 c5 04 f3	f304c503   	r3 = add(r4,r5) }
    "#,
    smallvec![2, 0, 1, 3]; "three instructions, reordering sandwich"
)]
pub fn test_simple(objdump: &str, ordering: SmallVec<[usize; 4]>) {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(objdump);

    cpu.write_register(HexagonRegister::R1, 2u32).unwrap();
    cpu.write_register(HexagonRegister::R2, 2u32).unwrap();
    cpu.write_register(HexagonRegister::R4, 7u32).unwrap();
    cpu.write_register(HexagonRegister::R5, 7u32).unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, 1).unwrap();
    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);
    assert_eq!(&Some(ordering), &exit.last_packet_order);

    let r0 = cpu.read_register::<u32>(HexagonRegister::R0).unwrap();
    let r3 = cpu.read_register::<u32>(HexagonRegister::R3).unwrap();

    assert_eq!(r0, 4);
    assert_eq!(r3, 14);
}
