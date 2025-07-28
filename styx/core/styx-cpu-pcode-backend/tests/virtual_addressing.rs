// SPDX-License-Identifier: BSD-2-Clause
use log::info;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use styx_cpu_pcode_backend::PcodeBackend;
use styx_cpu_type::{
    arch::ppc32::{Ppc32Register, Ppc32Variants},
    Arch, ArchEndian,
};
use styx_errors::UnknownError;
use styx_processor::{
    cpu::{CpuBackend, CpuBackendExt},
    event_controller::{EventController, ExceptionNumber},
    hooks::{CoreHandle, Hookable, StyxHook},
    memory::{
        helpers::{ReadExt, WriteExt},
        memory_region::MemoryRegion,
        physical::PhysicalMemoryVariant,
        FnTlb, MemoryOperation, MemoryPermissions, MemoryType, Mmu, TlbProcessor,
        TlbTranslateError, TlbTranslateResult,
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

    // make sure reading registers works in here
    let reg_value = processor
        .cpu
        .read_register::<u32>(Ppc32Register::R1)
        .unwrap();
    info!("got reg value {reg_value}");
    Ok(virtual_addr + 0x1000)
}

const LOAD_OBJECT_DUMP: &str = "
       0:	3c 60 00 00 	lis     r3,0
       4:	60 63 20 00 	ori     r3,r3,8192
       8:	80 83 00 00 	lwz     r4,0(r3)
   ";
const STORE_OBJECT_DUMP: &str = "
        0:	3c 60 00 00 	lis     r3,0
        4:	60 63 20 00 	ori     r3,r3,8192
        8:	3c 80 00 00 	lis     r4,0
        c:	60 84 13 37 	ori     r4,r4,4919
        10:	90 83 00 00 	stw     r4,0(r3)
   ";

type TranslateFn = fn(u64, MemoryOperation, MemoryType, &mut TlbProcessor) -> TlbTranslateResult;
/// Test reading from a virtual address while executing at a virtual address.
fn test_proc(
    translate_fn: TranslateFn,
    program_objdump: &str,
) -> Result<(PcodeBackend, Mmu, EventController), UnknownError> {
    init_logging();

    let mut cpu =
        PcodeBackend::new_engine(Arch::Ppc32, Ppc32Variants::Ppc405, ArchEndian::BigEndian);
    let physical_memory = PhysicalMemoryVariant::RegionStore;
    let tlb = FnTlb::new(translate_fn);
    let mut mmu = Mmu::new(Box::new(tlb), physical_memory, &mut cpu)?;
    let ev = EventController::default();

    let code_bytes = styx_util::parse_objdump(program_objdump)?;

    mmu.add_memory_region(MemoryRegion::new(0, 0x4000, MemoryPermissions::all())?)
        .unwrap();

    // this is 0x0 in virtual
    mmu.write_code(0x1000, &code_bytes)?;
    cpu.set_pc(0)?;

    Ok((cpu, mmu, ev))
}

/// Test reading from a virtual address while executing at a virtual address.
#[test]
fn test_virtual_read() -> Result<(), UnknownError> {
    let (mut cpu, mut mmu, mut ev) = test_proc(tlb_translate_plus_0x1000, LOAD_OBJECT_DUMP)?;

    mmu.data().write(0x3000).be().value(0xcafebabeu32)?;
    cpu.execute(&mut mmu, &mut ev, 3)?;

    let r4 = cpu.read_register::<u32>(Ppc32Register::R4)?;
    assert_eq!(0xcafebabeu32, r4);

    Ok(())
}

/// Test writing to a virtual address while executing at a virtual address.
#[test]
fn test_virtual_write() -> Result<(), UnknownError> {
    let (mut cpu, mut mmu, mut ev) = test_proc(tlb_translate_plus_0x1000, STORE_OBJECT_DUMP)?;

    cpu.execute(&mut mmu, &mut ev, 5)?;

    let written_value = mmu.data().read(0x3000).be().u32()?;
    assert_eq!(4919, written_value);

    let written_value = mmu.virt_data(&mut cpu).read(0x2000).be().u32()?;
    assert_eq!(4919, written_value);

    Ok(())
}

fn tlb_translate_exception(
    virtual_addr: u64,
    _operation: MemoryOperation,
    _memory_type: MemoryType,
    processor: &mut TlbProcessor,
) -> TlbTranslateResult {
    info!("getting addr 0x{virtual_addr:X}");

    // make sure reading registers works in here
    let reg_value = processor
        .cpu
        .read_register::<u32>(Ppc32Register::R1)
        .unwrap();
    info!("got reg value {reg_value}");

    Err(TlbTranslateError::Exception(0x1337))
}

/// Test hitting a tlb exception.
#[test]
fn test_virtual_fetch_exception() -> Result<(), UnknownError> {
    let (mut cpu, mut mmu, mut ev) = test_proc(tlb_translate_exception, LOAD_OBJECT_DUMP)?;

    let last_irq: Arc<Mutex<Option<ExceptionNumber>>> = Arc::new(Mutex::new(None));
    {
        let last_irq = last_irq.clone();
        cpu.add_hook(StyxHook::interrupt(move |_cpu: CoreHandle, irqn| {
            *last_irq.lock().unwrap() = Some(irqn);
            Ok(())
        }))?;
    }

    cpu.execute(&mut mmu, &mut ev, 3)?;

    let irq = last_irq.lock().unwrap().unwrap();
    assert_eq!(irq, 0x1337);

    Ok(())
}

fn tlb_translate_exception_over_0x2000(
    virtual_addr: u64,
    _operation: MemoryOperation,
    _memory_type: MemoryType,
    processor: &mut TlbProcessor,
) -> TlbTranslateResult {
    info!("getting addr 0x{virtual_addr:X}");

    // make sure reading registers works in here
    let reg_value = processor
        .cpu
        .read_register::<u32>(Ppc32Register::R1)
        .unwrap();
    info!("got reg value {reg_value}");

    if virtual_addr >= 0x2000 {
        Err(TlbTranslateError::Exception(0x1337))
    } else {
        Ok(virtual_addr + 0x1000)
    }
}

/// Test reading from a virtual address which causes an exception.
///
/// The pc is checked to make sure it did not increment.
#[test]
fn test_virtual_read_exception() -> Result<(), UnknownError> {
    let (mut cpu, mut mmu, mut ev) =
        test_proc(tlb_translate_exception_over_0x2000, LOAD_OBJECT_DUMP)?;

    let last_irq: Arc<Mutex<Option<ExceptionNumber>>> = Arc::new(Mutex::new(None));
    {
        let last_irq = last_irq.clone();
        cpu.add_hook(StyxHook::interrupt(move |_cpu: CoreHandle, irqn| {
            *last_irq.lock().unwrap() = Some(irqn);
            Ok(())
        }))?;
    }

    cpu.execute(&mut mmu, &mut ev, 3)?;

    let irq = last_irq.lock().unwrap().unwrap();
    assert_eq!(irq, 0x1337);

    let pc = cpu.pc()?;
    // exceptions require instruction to re-execute
    assert_eq!(pc, 0x8);

    Ok(())
}

/// Test writing to a virtual address that throws an exception.
///
/// The pc is checked to make sure it did not increment.
#[test]
fn test_virtual_write_exception() -> Result<(), UnknownError> {
    let (mut cpu, mut mmu, mut ev) =
        test_proc(tlb_translate_exception_over_0x2000, STORE_OBJECT_DUMP)?;

    let last_irq: Arc<Mutex<Option<ExceptionNumber>>> = Arc::new(Mutex::new(None));
    {
        let last_irq = last_irq.clone();
        cpu.add_hook(StyxHook::interrupt(move |_cpu: CoreHandle, irqn| {
            *last_irq.lock().unwrap() = Some(irqn);
            Ok(())
        }))?;
    }

    cpu.execute(&mut mmu, &mut ev, 5)?;

    let irq = last_irq.lock().unwrap().unwrap();
    assert_eq!(irq, 0x1337);

    let pc = cpu.pc()?;
    // exceptions require instruction to re-execute
    assert_eq!(pc, 0x10);

    Ok(())
}

/// Test that a code hook triggers on the physical address.
#[test]
fn test_virtual_code_hook() -> Result<(), UnknownError> {
    let (mut cpu, mut mmu, mut ev) = test_proc(tlb_translate_plus_0x1000, LOAD_OBJECT_DUMP)?;

    mmu.data().write(0x3000).be().value(0xcafebabeu32)?;

    let should_trigger = Box::leak(Box::new(AtomicBool::new(false)));
    let should_not_trigger = Box::leak(Box::new(AtomicBool::new(false)));

    // code on physical address should trigger
    cpu.add_hook(StyxHook::code(0x1000, |_proc: CoreHandle| {
        should_trigger.store(true, Ordering::SeqCst);
        Ok(())
    }))?;
    // code on virtual address should not trigger
    cpu.add_hook(StyxHook::code(0x0, |_proc: CoreHandle| {
        should_not_trigger.store(true, Ordering::SeqCst);
        Ok(())
    }))?;

    cpu.execute(&mut mmu, &mut ev, 3)?;

    assert!(should_trigger.load(Ordering::SeqCst));
    assert!(!should_not_trigger.load(Ordering::SeqCst));

    Ok(())
}

/// Test that a memory read hook triggers on the physical address.
#[test]
fn test_virtual_memory_read_hook() -> Result<(), UnknownError> {
    let (mut cpu, mut mmu, mut ev) = test_proc(tlb_translate_plus_0x1000, LOAD_OBJECT_DUMP)?;

    mmu.data().write(0x3000).be().value(0xcafebabeu32)?;

    let should_trigger = Box::leak(Box::new(AtomicBool::new(false)));
    let should_not_trigger = Box::leak(Box::new(AtomicBool::new(false)));

    // code on physical address should trigger
    cpu.add_hook(StyxHook::memory_read(
        0x3000,
        |_proc: CoreHandle, _addr, _size, _data: &mut [u8]| {
            should_trigger.store(true, Ordering::SeqCst);
            Ok(())
        },
    ))?;
    // code on virtual address should not trigger
    cpu.add_hook(StyxHook::memory_read(
        0x2000,
        |_proc: CoreHandle, _addr, _size, _data: &mut [u8]| {
            should_not_trigger.store(true, Ordering::SeqCst);
            Ok(())
        },
    ))?;

    cpu.execute(&mut mmu, &mut ev, 3)?;

    assert!(should_trigger.load(Ordering::SeqCst));
    assert!(!should_not_trigger.load(Ordering::SeqCst));

    Ok(())
}

/// Test that a memory write hook triggers on the physical address.
#[test]
fn test_virtual_memory_write_hook() -> Result<(), UnknownError> {
    let (mut cpu, mut mmu, mut ev) = test_proc(tlb_translate_plus_0x1000, STORE_OBJECT_DUMP)?;

    mmu.data().write(0x3000).be().value(0xcafebabeu32)?;

    let should_trigger = Box::leak(Box::new(AtomicBool::new(false)));
    let should_not_trigger = Box::leak(Box::new(AtomicBool::new(false)));

    // code on physical address should trigger
    cpu.add_hook(StyxHook::memory_write(
        0x3000,
        |_proc: CoreHandle, _addr, _size, _data: &[u8]| {
            should_trigger.store(true, Ordering::SeqCst);
            Ok(())
        },
    ))?;
    // code on virtual address should not trigger
    cpu.add_hook(StyxHook::memory_write(
        0x2000,
        |_proc: CoreHandle, _addr, _size, _data: &[u8]| {
            should_not_trigger.store(true, Ordering::SeqCst);
            Ok(())
        },
    ))?;

    cpu.execute(&mut mmu, &mut ev, 5)?;

    assert!(should_trigger.load(Ordering::SeqCst));
    assert!(!should_not_trigger.load(Ordering::SeqCst));

    Ok(())
}
