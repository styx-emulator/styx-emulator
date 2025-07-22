// SPDX-License-Identifier: BSD-2-Clause
use log::info;
use styx_cpu_pcode_backend::PcodeBackend;
use styx_cpu_type::{
    arch::ppc32::{Ppc32Register, Ppc32Variants},
    Arch, ArchEndian,
};
use styx_errors::UnknownError;
use styx_processor::{
    cpu::{CpuBackend, CpuBackendExt},
    event_controller::EventController,
    memory::{
        helpers::{ReadExt, WriteExt},
        memory_region::MemoryRegion,
        physical::PhysicalMemoryVariant,
        ClosureTlb, MemoryOperation, MemoryPermissions, MemoryType, Mmu, TlbProcessor,
        TlbTranslateResult,
    },
};
use styx_util::logging::init_logging;

/// translate function that just adds 0x1000 to the physical address
fn tlb_translate_plus_0x1000(
    virtual_addr: u64,
    _operation: MemoryOperation,
    _memory_type: MemoryType,
    processor: &mut TlbProcessor,
) -> TlbTranslateResult {
    info!("getting addr 0x{virtual_addr:X}");

    let reg_value = processor
        .cpu
        .read_register::<u32>(Ppc32Register::R1)
        .unwrap();
    info!("got reg value {reg_value}");
    Ok(virtual_addr + 0x1000)
}

/// Test reading from a virtual address while executing at a virtual address.
#[test]
fn test_virtual_read() -> Result<(), UnknownError> {
    init_logging();

    let mut cpu =
        PcodeBackend::new_engine(Arch::Ppc32, Ppc32Variants::Ppc405, ArchEndian::BigEndian);
    let physical_memory = PhysicalMemoryVariant::RegionStore;
    let tlb = ClosureTlb::new(Box::new(tlb_translate_plus_0x1000));
    let mut mmu = Mmu::new(Box::new(tlb), physical_memory, &mut cpu)?;
    let mut ev = EventController::default();

    let objdump = "
       0:	3c 60 00 00 	lis     r3,0
       4:	60 63 10 00 	ori     r3,r3,4096
       8:	80 83 00 00 	lwz     r4,0(r3)
   ";
    let code_bytes = styx_util::parse_objdump(objdump)?;

    mmu.add_memory_region(MemoryRegion::new(0, 0x3000, MemoryPermissions::all())?)
        .unwrap();
    // this is 0x1000 in virtual address space
    mmu.data().write(0x2000).be().value(0xcafebabeu32)?;

    // this is 0x0 in virtual
    mmu.write_code(0x1000, &code_bytes)?;
    cpu.set_pc(0)?;

    cpu.execute(&mut mmu, &mut ev, 3)?;

    let r4 = cpu.read_register::<u32>(Ppc32Register::R4)?;
    assert_eq!(0xcafebabeu32, r4);

    Ok(())
}

/// Test writing to a virtual address while executing at a virtual address.
#[test]
fn test_virtual_write() -> Result<(), UnknownError> {
    init_logging();

    let objdump = "
        0:	3c 60 00 00 	lis     r3,0
        4:	60 63 10 00 	ori     r3,r3,4096
        8:	3c 80 00 00 	lis     r4,0
        c:	60 84 13 37 	ori     r4,r4,4919
        10:	90 83 00 00 	stw     r4,0(r3)
   ";
    let code_bytes = styx_util::parse_objdump(objdump)?;

    let mut cpu =
        PcodeBackend::new_engine(Arch::Ppc32, Ppc32Variants::Ppc405, ArchEndian::BigEndian);
    let physical_memory = PhysicalMemoryVariant::RegionStore;
    let tlb = ClosureTlb::new(Box::new(tlb_translate_plus_0x1000));
    let mut mmu = Mmu::new(Box::new(tlb), physical_memory, &mut cpu)?;
    let mut ev = EventController::default();

    // code region
    mmu.add_memory_region(MemoryRegion::new(0, 0x3000, MemoryPermissions::all())?)?;
    // this is 0x0 in virtual
    mmu.write_code(0x1000, &code_bytes).unwrap();

    cpu.execute(&mut mmu, &mut ev, 5)?;

    let written_value = mmu.data().read(0x2000).be().u32()?;
    assert_eq!(4919, written_value);

    let written_value = mmu.virt_data(&mut cpu).read(0x1000).be().u32()?;
    assert_eq!(4919, written_value);

    Ok(())
}
