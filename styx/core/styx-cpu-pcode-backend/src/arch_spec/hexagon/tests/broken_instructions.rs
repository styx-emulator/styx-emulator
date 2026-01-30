use crate::arch_spec::hexagon::tests::*;
use log::info;
use styx_processor::{
    cpu::CpuBackendExt,
    hooks::{CoreHandle, Hookable},
};
use test_case::test_case;

use super::setup_objdump;

#[test_case(
	r#"
       0:	03 cc 00 3e	3e00cc03 { 	memb(r0+#0x18) += r3 } 
	"#, 1, 2, 3, 4, 1, 1; "L4_add_memopb_io"
)]
#[test_case(
	r#"
       0:	23 cc 00 3e	3e00cc23 { 	memb(r0+#0x18) -= r3 } 
	"#, 1, 2, 3, 4, 1, 1; "L4_sub_memopb_io"
)]
#[test_case(
	r#"
       0:	43 cc 00 3e	3e00cc43 { 	memb(r0+#0x18) &= r3 } 
	"#, 1, 2, 3, 4, 1, 1; "L4_and_memopb_io"
)]
#[test_case(
	r#"
       0:	63 cc 00 3e	3e00cc63 { 	memb(r0+#0x18) |= r3 } 
	"#, 1, 2, 3, 4, 1, 1; "L4_or_memopb_io"
)]
#[test_case(
	r#"
       0:	0c cc 00 3f	3f00cc0c { 	memb(r0+#0x18) += #0xc } 
	"#, 1, 2, 3, 4, 1, 1; "L4_iadd_memopb_io"
)]
#[test_case(
	r#"
       0:	2c cc 00 3f	3f00cc2c { 	memb(r0+#0x18) -= #0xc } 
	"#, 1, 2, 3, 4, 1, 1; "L4_isub_memopb_io"
)]
#[test_case(
	r#"
       0:	4c cc 00 3f	3f00cc4c { 	memb(r0+#0x18) = clrbit(#0xc) } 
	"#, 1, 2, 3, 4, 1, 1; "L4_iand_memopb_io"
)]
#[test_case(
	r#"
       0:	6c cc 00 3f	3f00cc6c { 	memb(r0+#0x18) = setbit(#0xc) } 
	"#, 1, 2, 3, 4, 1, 1; "L4_ior_memopb_io"
)]
#[test_case(
	r#"
       0:	00 56 15 f2	f2155600 { 	p0 = cmp.eq(r21,r22)
       4:	01 d8 17 f2	f217d801   	p1 = cmp.eq(r23,r24) } 
       8:	1e ec 00 38	3800ec1e { 	if (p0) memb(r0+#0x18) = #-0x2 } 
	"#, 99, 99, 3, 4, 2, 1; "S4_storeirbt_io"
)]
#[test_case(
	r#"
       0:	00 56 15 f2	f2155600 { 	p0 = cmp.eq(r21,r22)
       4:	01 d8 17 f2	f217d801   	p1 = cmp.eq(r23,r24) } 
       8:	1e ec 80 38	3880ec1e { 	if (!p0) memb(r0+#0x18) = #-0x2 } 
	"#, 1, 2, 3, 4, 2, 1; "S4_storeirbf_io"
)]
#[test_case(
	r#"
       0:	00 56 15 f2	f2155600 { 	p0 = cmp.eq(r21,r22)
       4:	01 58 17 f2	f2175801   	p1 = cmp.eq(r23,r24)
       8:	1e ec 00 39	3900ec1e   	if (p0.new) memb(r0+#0x18) = #-0x2 } 
	"#, 99, 99, 3, 4, 1, 1; "S4_storeirbtnew_io"
)]
#[test_case(
	r#"
       0:	00 56 15 f2	f2155600 { 	p0 = cmp.eq(r21,r22)
       4:	01 58 17 f2	f2175801   	p1 = cmp.eq(r23,r24)
       8:	1e ec 80 39	3980ec1e   	if (!p0.new) memb(r0+#0x18) = #-0x2 } 
	"#, 1, 2, 3, 4, 1, 1; "S4_storeirbfnew_io"
)]
#[test_case(
	r#"
       0:	7d ec 00 3c	3c00ec7d { 	memb(r0+#0x18) = #-0x3 } 
	"#, 1, 2, 3, 4, 1, 1; "S4_storeirb_io"
)]
#[test_case(
	r#"
       0:	03 de 20 3e	3e20de03 { 	memh(r0+#0x78) += r3 } 
	"#, 1, 2, 3, 4, 1, 2; "L4_add_memoph_io"
)]
#[test_case(
	r#"
       0:	23 de 20 3e	3e20de23 { 	memh(r0+#0x78) -= r3 } 
	"#, 1, 2, 3, 4, 1, 2; "L4_sub_memoph_io"
)]
#[test_case(
	r#"
       0:	43 de 20 3e	3e20de43 { 	memh(r0+#0x78) &= r3 } 
	"#, 1, 2, 3, 4, 1, 2; "L4_and_memoph_io"
)]
#[test_case(
	r#"
       0:	63 de 20 3e	3e20de63 { 	memh(r0+#0x78) |= r3 } 
	"#, 1, 2, 3, 4, 1, 2; "L4_or_memoph_io"
)]
#[test_case(
	r#"
       0:	0c de 20 3f	3f20de0c { 	memh(r0+#0x78) += #0xc } 
	"#, 1, 2, 3, 4, 1, 2; "L4_iadd_memoph_io"
)]
#[test_case(
	r#"
       0:	2c de 20 3f	3f20de2c { 	memh(r0+#0x78) -= #0xc } 
	"#, 1, 2, 3, 4, 1, 2; "L4_isub_memoph_io"
)]
#[test_case(
	r#"
       0:	4c de 20 3f	3f20de4c { 	memh(r0+#0x78) = clrbit(#0xc) } 
	"#, 1, 2, 3, 4, 1, 2; "L4_iand_memoph_io"
)]
#[test_case(
	r#"
       0:	6c de 20 3f	3f20de6c { 	memh(r0+#0x78) = setbit(#0xc) } 
	"#, 1, 2, 3, 4, 1, 2; "L4_ior_memoph_io"
)]
#[test_case(
	r#"
       0:	00 56 15 f2	f2155600 { 	p0 = cmp.eq(r21,r22)
       4:	01 d8 17 f2	f217d801   	p1 = cmp.eq(r23,r24) } 
       8:	1e fe 20 38	3820fe1e { 	if (p0) memh(r0+#0x78) = #-0x2 } 
	"#, 99, 99, 3, 4, 2, 2; "S4_storeirht_io"
)]
#[test_case(
	r#"
       0:	00 56 15 f2	f2155600 { 	p0 = cmp.eq(r21,r22)
       4:	01 d8 17 f2	f217d801   	p1 = cmp.eq(r23,r24) } 
       8:	1e fe a0 38	38a0fe1e { 	if (!p0) memh(r0+#0x78) = #-0x2 } 
	"#, 1, 2, 3, 4, 2, 2; "S4_storeirhf_io"
)]
#[test_case(
	r#"
       0:	00 56 15 f2	f2155600 { 	p0 = cmp.eq(r21,r22)
       4:	01 58 17 f2	f2175801   	p1 = cmp.eq(r23,r24)
       8:	1e fe 20 39	3920fe1e   	if (p0.new) memh(r0+#0x78) = #-0x2 } 
	"#, 99, 99, 3, 4, 1, 2; "S4_storeirhtnew_io"
)]
#[test_case(
	r#"
       0:	00 56 15 f2	f2155600 { 	p0 = cmp.eq(r21,r22)
       4:	01 58 17 f2	f2175801   	p1 = cmp.eq(r23,r24)
       8:	1e fe a0 39	39a0fe1e   	if (!p0.new) memh(r0+#0x78) = #-0x2 } 
	"#, 1, 2, 3, 4, 1, 2; "S4_storeirhfnew_io"
)]
#[test_case(
	r#"
       0:	7d fe 20 3c	3c20fe7d { 	memh(r0+#0x78) = #-0x3 } 
	"#, 1, 2, 3, 4, 1, 2; "S4_storeirh_io"
)]
fn wrong_size_stores(
    objdump: &str,
    r21: u32,
    r22: u32,
    r23: u32,
    r24: u32,
    num_packets: u64,
    data_size: u32,
) {
    let (mut cpu, mut mmu, mut ev) = setup_objdump(objdump);

    cpu.write_register(HexagonRegister::R0, 0x100u32).unwrap();
    cpu.write_register(HexagonRegister::R21, r21).unwrap();
    cpu.write_register(HexagonRegister::R22, r22).unwrap();
    cpu.write_register(HexagonRegister::R23, r23).unwrap();
    cpu.write_register(HexagonRegister::R24, r24).unwrap();

    cpu.add_hook(styx_processor::hooks::StyxHook::MemoryWrite(
        (0..(u32::MAX as u64)).into(),
        Box::new(
            move |mut proc: CoreHandle, address: u64, size: u32, data: &[u8]| {
                info!("address {address:x} size {size}");
                assert!(size == data_size);
                Ok(())
            },
        ),
    ))
    .unwrap();

    let exit = cpu.execute(&mut mmu, &mut ev, num_packets).unwrap();

    assert_eq!(exit.exit_reason, TargetExitReason::InstructionCountComplete);
}
