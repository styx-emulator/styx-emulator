// SPDX-License-Identifier: BSD-2-Clause
use styx_cpu_pcode_backend::PcodeBackend;
use styx_cpu_type::{arch::ppc32::Ppc32Variants, Arch, ArchEndian, TargetExitReason};
use styx_processor::{
    cpu::{CpuBackend, ExecutionReport},
    event_controller::EventController,
    hooks::{CoreHandle, Hookable, StyxHook},
    memory::{
        helpers::{ReadExt, WriteExt},
        memory_region::MemoryRegion,
        MemoryPermissions, Mmu,
    },
};

/// Tests behavior of the memory read hook on a big endian arch in the pcode backend.
///
/// Ensures hook arguments and read data mutability are ensured.
#[test]
fn test_memory_read_hook_be() {
    let objdump = "
       0:	3c 60 00 00 	lis     r3,0
       4:	60 63 10 00 	ori     r3,r3,4096
       8:	80 83 00 00 	lwz     r4,0(r3)
   ";

    let mut mmu = Mmu::default_region_store();
    let mut ev = EventController::default();
    let mut cpu =
        PcodeBackend::new_engine(Arch::Ppc32, Ppc32Variants::Ppc405, ArchEndian::BigEndian);

    let code_bytes = styx_util::parse_objdump(objdump).unwrap();

    // code region
    mmu.add_memory_region(MemoryRegion::new(0, 0x10000, MemoryPermissions::all()).unwrap())
        .unwrap();

    mmu.write_code(0x0, &code_bytes).unwrap();
    mmu.data().write(0x1000).be().value(0xCAFEBABEu32).unwrap();

    let read_hook = |_core: CoreHandle, addr: u64, size: u32, data: &mut [u8]| {
        assert_eq!(data, &[0xCA, 0xFE, 0xBA, 0xBE]);
        assert_eq!(addr, 0x1000);
        assert_eq!(size, 4);
        assert_eq!(size, data.len() as u32);
        data[0..4].copy_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        Ok(())
    };
    cpu.add_hook(StyxHook::memory_read(0x1000, read_hook))
        .unwrap();

    let res = cpu.execute(&mut mmu, &mut ev, 3).unwrap();

    println!("execution result: {res:?}");

    let assert_addr = mmu.data().read(0x1000).be().u32().unwrap();
    assert_eq!(assert_addr, 0xDEADBEEF);
    assert_eq!(
        res,
        ExecutionReport::new(TargetExitReason::InstructionCountComplete, 3)
    );
}
