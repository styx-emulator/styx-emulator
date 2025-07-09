// SPDX-License-Identifier: BSD-2-Clause

use std::sync::atomic::{AtomicU32, Ordering};

use styx_cpu::{
    arch::arm::{ArmRegister, ArmVariants},
    Arch, ArchEndian, Backend, PcodeBackend, TargetExitReason, UnicornBackend,
};
use styx_errors::UnknownError;
use styx_processor::{
    core::{
        builder::{BuildProcessorImplArgs, ProcessorImpl},
        ExceptionBehavior, ProcessorBundle,
    },
    cpu::{CpuBackend, CpuBackendExt},
    hooks::{CoreHandle, MemFaultData, Resolution, StyxHook},
    memory::{helpers::WriteExt, memory_region::MemoryRegion, MemoryPermissions, Mmu},
    processor::{Processor, ProcessorBuilder},
};

use test_case::test_case;

struct CustomBuilder;

impl ProcessorImpl for CustomBuilder {
    fn build(&self, args: &BuildProcessorImplArgs) -> Result<ProcessorBundle, UnknownError> {
        let cpu: Box<dyn CpuBackend> = match args.backend {
            Backend::Pcode => Box::new(PcodeBackend::new_engine_config(
                ArmVariants::ArmCortexM4,
                ArchEndian::LittleEndian,
                &args.into(),
            )),
            Backend::Unicorn => Box::new(UnicornBackend::new_engine_exception(
                Arch::Arm,
                ArmVariants::ArmCortexM4,
                ArchEndian::LittleEndian,
                args.exception,
            )),
        };
        let mut mmu = Mmu::default_region_store();
        mmu.add_memory_region(MemoryRegion::new(0, 0x1000, MemoryPermissions::all())?)?;

        Ok(ProcessorBundle {
            cpu,
            mmu,
            ..Default::default()
        })
    }
}
fn construct_cpu(
    backend: Backend,
    exception: ExceptionBehavior,
    program_bytes: &[u8],
) -> Result<Processor, UnknownError> {
    styx_util::logging::init_logging();

    let mut proc = ProcessorBuilder::default()
        .with_exception_behavior(exception)
        .with_builder(CustomBuilder)
        .with_backend(backend)
        .build()?;

    // code at 0x100 because unicorn gets fussy if we start at 0
    proc.core.mmu.code().write(0x100).bytes(program_bytes)?;
    proc.core.cpu.set_pc(0x101)?; // 1 bit to set thumb mode
    Ok(proc)
}

#[test_case(Backend::Pcode)]
#[test_case(Backend::Unicorn)]
fn test_target_handle_unmapped(backend: Backend) -> Result<(), UnknownError> {
    // ARM thumb:
    // ldr r0, [r0, #0]
    let program_bytes = [0x00, 0x68];
    let mut proc = construct_cpu(backend, ExceptionBehavior::TargetHandle, &program_bytes)?;
    proc.core.cpu.write_register(ArmRegister::R0, 0x1000u32)?;

    let count: &'static AtomicU32 = Box::leak(Box::new(AtomicU32::new(0)));
    proc.core.cpu.add_hook(StyxHook::unmapped_fault(
        0x1000..=0x2000,
        |core: CoreHandle, _, _, _: MemFaultData| {
            core.mmu.add_memory_region(MemoryRegion::new(
                0x1000,
                0x1000,
                MemoryPermissions::all(),
            )?)?;
            count.fetch_add(1, Ordering::SeqCst);
            Ok(Resolution::Fixed)
        },
    ))?;

    let exit_res = proc.run(1)?.exit_reason;
    assert!(
        matches!(exit_res, TargetExitReason::InstructionCountComplete),
        "ope, actually reason was {exit_res}"
    );

    assert_eq!(count.load(Ordering::SeqCst), 1);

    Ok(())
}

#[test_case(Backend::Pcode)]
#[test_case(Backend::Unicorn)]
fn test_pause_unmapped(backend: Backend) -> Result<(), UnknownError> {
    // ARM thumb:
    // ldr r0, [r0, #0]
    let program_bytes = [0x00, 0x68];
    let mut proc = construct_cpu(backend, ExceptionBehavior::Pause, &program_bytes)?;
    proc.core.cpu.write_register(ArmRegister::R0, 0x1000u32)?;
    let cpu = &mut proc.core.cpu;

    cpu.add_hook(StyxHook::unmapped_fault(
        0x1000..=0x2000,
        |_: CoreHandle, _, _, _: MemFaultData| {
            panic!("should not have triggered handler");
        },
    ))?;

    let exit_res = proc.run(1)?.exit_reason;
    assert!(
        matches!(exit_res, TargetExitReason::UnmappedMemoryRead),
        "ope, actually reason was {exit_res}"
    );

    Ok(())
}

#[test_case(Backend::Pcode)]
#[should_panic]
fn test_panic_unmapped(backend: Backend) {
    // ARM thumb:
    // ldr r0, [r0, #0]
    let program_bytes = [0x00, 0x68];
    let mut proc = construct_cpu(backend, ExceptionBehavior::Panic, &program_bytes).unwrap();
    proc.core
        .cpu
        .write_register(ArmRegister::R0, 0x1000u32)
        .unwrap();
    let cpu = &mut proc.core.cpu;
    cpu.add_hook(StyxHook::unmapped_fault(
        0x1000,
        |_: CoreHandle, _, _, _: MemFaultData| {
            panic!("should not have triggered handler");
        },
    ))
    .unwrap();

    // should panic here
    proc.run(1).unwrap();
}

#[test_case(Backend::Pcode)]
#[test_case(Backend::Unicorn)]
fn test_pause_invalid_instruction(backend: Backend) -> Result<(), UnknownError> {
    // ARM thumb:
    // undefined instruction
    // note that the actual arm undefined instruction 0xde00 will not work because the sla spec
    // paradoxically defines it with a userop.
    let program_bytes = [0xff, 0xff];
    let mut proc = construct_cpu(backend, ExceptionBehavior::Pause, &program_bytes)?;
    let cpu = &mut proc.core.cpu;

    cpu.add_hook(StyxHook::invalid_instruction(|_: CoreHandle| {
        panic!("should not have triggered handler");
    }))?;

    // should panic here
    let exit_res = proc.run(1)?.exit_reason;
    assert!(
        matches!(exit_res, TargetExitReason::InstructionDecodeError),
        "ope, actually reason was {exit_res}"
    );
    Ok(())
}

#[test_case(Backend::Pcode)]
#[should_panic]
fn test_panic_invalid_instruction(backend: Backend) {
    // ARM thumb:
    // undefined instruction
    // note that the actual arm undefined instruction 0xde00 will not work because the sla spec
    // paradoxically defines it with a userop.
    let program_bytes = [0xff, 0xff];
    let mut proc = construct_cpu(backend, ExceptionBehavior::Panic, &program_bytes).unwrap();
    proc.core
        .cpu
        .write_register(ArmRegister::R0, 0x1000u32)
        .unwrap();
    let cpu = &mut proc.core.cpu;

    cpu.add_hook(StyxHook::invalid_instruction(|_: CoreHandle| {
        panic!("should not have triggered handler");
    }))
    .unwrap();

    // should panic here
    proc.run(1).unwrap();
}

#[test_case(Backend::Pcode)]
#[test_case(Backend::Unicorn)]
fn test_pause_unmapped_fetch(backend: Backend) -> Result<(), UnknownError> {
    // ARM thumb:
    // ldr r0, [r0, #0]
    let program_bytes = [0x00, 0x68];
    let mut proc = construct_cpu(backend, ExceptionBehavior::Pause, &program_bytes)?;
    proc.core.cpu.write_register(ArmRegister::R0, 0x1000u32)?;
    let cpu = &mut proc.core.cpu;
    let mmu = &mut proc.core.mmu;

    cpu.set_pc(0xFFE)?;
    // arm thumb nop
    mmu.code().write(0xFFE).le().value(0xbf00u16)?;

    cpu.add_hook(StyxHook::unmapped_fault(
        0x1000,
        |_: CoreHandle, _, _, _: MemFaultData| {
            panic!("should not have triggered handler");
        },
    ))?;

    let exit_res = proc.run(2)?.exit_reason;
    assert!(
        matches!(exit_res, TargetExitReason::UnmappedMemoryFetch),
        "ope, actually reason was {exit_res}"
    );

    Ok(())
}
