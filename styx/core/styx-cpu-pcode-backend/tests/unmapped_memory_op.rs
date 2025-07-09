// SPDX-License-Identifier: BSD-2-Clause
use styx_cpu_pcode_backend::PcodeBackend;
use styx_cpu_type::{arch::ppc32::Ppc32Variants, Arch, ArchEndian, TargetExitReason};
use styx_processor::{
    cpu::{CpuBackend, ExecutionReport},
    event_controller::EventController,
    memory::{memory_region::MemoryRegion, MemoryPermissions, Mmu},
};

#[test]
fn test_unmapped_read() {
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
    mmu.add_memory_region(MemoryRegion::new(0, 0x1000, MemoryPermissions::all()).unwrap())
        .unwrap();
    // no region at 0x1000

    mmu.write_code(0x0, &code_bytes).unwrap();

    let res = cpu.execute(&mut mmu, &mut ev, 3).unwrap();

    println!("execution result: {res:?}");
    assert_eq!(
        res,
        ExecutionReport::new(TargetExitReason::UnmappedMemoryRead, 2)
    );
}

#[test]
fn test_goes_unmapped_read() {
    let objdump = "
       0:	3c 60 00 00 	lis     r3,0
       4:	60 63 10 00 	ori     r3,r3,4094
       8:	80 83 00 00 	lwz     r4,0(r3)
   ";

    let mut mmu = Mmu::default_region_store();
    let mut ev = EventController::default();
    let mut cpu =
        PcodeBackend::new_engine(Arch::Ppc32, Ppc32Variants::Ppc405, ArchEndian::BigEndian);

    let code_bytes = styx_util::parse_objdump(objdump).unwrap();

    // code region
    mmu.add_memory_region(MemoryRegion::new(0, 0x1000, MemoryPermissions::all()).unwrap())
        .unwrap();
    // no region at 0x1000

    mmu.write_code(0x0, &code_bytes).unwrap();

    let res = cpu.execute(&mut mmu, &mut ev, 3).unwrap();

    println!("execution result: {res:?}");
    assert_eq!(
        res,
        ExecutionReport::new(TargetExitReason::UnmappedMemoryRead, 2)
    );
}

#[test]
fn test_unmapped_write() {
    let objdump = "
        0:	3c 60 00 00 	lis     r3,0
        4:	60 63 10 00 	ori     r3,r3,4096
        8:	3c 80 00 00 	lis     r4,0
        c:	60 84 13 37 	ori     r4,r4,4919
        10:	90 83 00 00 	stw     r4,0(r3)
   ";

    let mut mmu = Mmu::default_region_store();
    let mut ev = EventController::default();
    let mut cpu =
        PcodeBackend::new_engine(Arch::Ppc32, Ppc32Variants::Ppc405, ArchEndian::BigEndian);

    let code_bytes = styx_util::parse_objdump(objdump).unwrap();

    // code region
    mmu.add_memory_region(MemoryRegion::new(0, 0x1000, MemoryPermissions::all()).unwrap())
        .unwrap();
    // no region at 0x1000

    mmu.write_code(0x0, &code_bytes).unwrap();

    let res = cpu.execute(&mut mmu, &mut ev, 5).unwrap();

    println!("execution result: {res:?}");
    assert_eq!(
        res,
        ExecutionReport::new(TargetExitReason::UnmappedMemoryWrite, 4)
    );
}

#[test]
fn test_goes_unmapped_write() {
    let objdump = "
        0:	3c 60 00 00 	lis     r3,0
        4:	60 63 10 00 	ori     r3,r3,4094
        8:	3c 80 00 00 	lis     r4,0
        c:	60 84 13 37 	ori     r4,r4,4919
        10:	90 83 00 00 	stw     r4,0(r3)
   ";

    let mut mmu = Mmu::default_region_store();
    let mut ev = EventController::default();
    let mut cpu =
        PcodeBackend::new_engine(Arch::Ppc32, Ppc32Variants::Ppc405, ArchEndian::BigEndian);

    let code_bytes = styx_util::parse_objdump(objdump).unwrap();

    // code region
    mmu.add_memory_region(MemoryRegion::new(0, 0x1000, MemoryPermissions::all()).unwrap())
        .unwrap();
    // no region at 0x1000

    mmu.write_code(0x0, &code_bytes).unwrap();

    let res = cpu.execute(&mut mmu, &mut ev, 5).unwrap();

    println!("execution result: {res:?}");
    assert_eq!(
        res,
        ExecutionReport::new(TargetExitReason::UnmappedMemoryWrite, 4)
    );
}
