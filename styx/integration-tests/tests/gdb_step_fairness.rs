// SPDX-License-Identifier: BSD-2-Clause
//! Test that single-stepping one vCPU must advance every vCPU by exactly
//! one instruction.
use std::sync::atomic::{AtomicU64, Ordering};

use styx_core::arch::ppc32::gdb_targets::Ppc4xxTargetDescription;
use styx_core::arch::ppc32::variants::Ppc405;
use styx_core::arch::RegisterValue;
use styx_core::core::builder::BuildProcessorImplArgs;
use styx_core::core::VcpuBundle;
use styx_core::prelude::*;
use styx_plugins::gdb::{GDBOptions, StepIRQs};

/// ArchitectureDef for the fake CPU to appease GDB.
/// The concrete arch is irrelevant to the test.
const ARCH_DEF: Ppc405 = Ppc405 {};

/// Fake CPU that counts how many instructions it has been asked to execute.
#[derive(Debug)]
struct CountingCpu(&'static AtomicU64);

impl Hookable for CountingCpu {
    fn add_hook(
        &mut self,
        _hook: StyxHook,
    ) -> Result<styx_core::hooks::HookToken, styx_core::hooks::AddHookError> {
        Ok(styx_core::hooks::HookToken::new_integer(0))
    }

    fn delete_hook(
        &mut self,
        _token: styx_core::hooks::HookToken,
    ) -> Result<(), styx_core::hooks::DeleteHookError> {
        Ok(())
    }
}

impl CpuBackend for CountingCpu {
    fn read_register_raw(
        &mut self,
        _reg: ArchRegister,
    ) -> Result<RegisterValue, ReadRegisterError> {
        Ok(RegisterValue::u32(0))
    }

    fn write_register_raw(
        &mut self,
        _reg: ArchRegister,
        _value: RegisterValue,
    ) -> Result<(), WriteRegisterError> {
        Ok(())
    }

    fn architecture(&self) -> &dyn styx_core::arch::ArchitectureDef {
        &ARCH_DEF
    }

    fn endian(&self) -> ArchEndian {
        ArchEndian::LittleEndian
    }

    fn execute(
        &mut self,
        _mmu: &mut Mmu,
        _event_controller: &mut EventController,
        count: u64,
    ) -> Result<styx_core::cpu::ExecutionReport, UnknownError> {
        self.0.fetch_add(count, Ordering::SeqCst);
        Ok(styx_core::cpu::ExecutionReport {
            exit_reason: TargetExitReason::InstructionCountComplete,
            instructions_executed: Some(count),
            last_packet_order: None,
        })
    }

    fn stop(&mut self) {}

    fn context_save(&mut self) -> Result<(), UnknownError> {
        Ok(())
    }

    fn context_restore(&mut self) -> Result<(), UnknownError> {
        Ok(())
    }

    fn pc(&mut self) -> Result<u64, UnknownError> {
        Ok(0)
    }

    fn set_pc(&mut self, _value: u64) -> Result<(), UnknownError> {
        Ok(())
    }
}

/// Single-stepping one thread must advance all vCPUs by exactly one instruction.
#[test]
fn step_advances_all_vcpus_by_one() {
    const NUM_VCPUS: usize = 3;

    // One counter per vCPU.
    //
    // Note: the builder closure requires 'static. That's why we leak instead
    // of hold on the stack.
    let counters: Vec<&'static AtomicU64> = (0..NUM_VCPUS)
        .map(|_| &*Box::leak(Box::new(AtomicU64::new(0))))
        .collect();
    let counters_for_builder = counters.clone();

    let proc = ProcessorBuilder::default().with_builder(move |_: &BuildProcessorImplArgs| {
        let vcpus = counters_for_builder
            .iter()
            .map(|c| VcpuBundle {
                cpu: Box::new(CountingCpu(c)),
                ..Default::default()
            })
            .collect();
        let bundle = ProcessorBundle {
            vcpus,
            ..Default::default()
        };
        Ok(bundle)
    });

    // Large epoch so a single step never crosses an epoch tick boundary.
    let harness = ::styx_integration_tests::gdb_harness::GdbHarness::from_processor_builder_options::<
        Ppc4xxTargetDescription,
    >(
        proc,
        GDBOptions {
            step_irqs: StepIRQs::Disabled,
            cpu_epoch: 1024,
        },
    );

    // One `stepi` on the current thread (thread 1 == vCPU 0).
    harness.step_instruction().unwrap();

    // Every vCPU must have advanced by exactly one instruction: not 0 (frozen /
    // skipped) and not `cpu_epoch` (raced ahead).
    for (i, c) in counters.iter().enumerate() {
        assert_eq!(
            1,
            c.load(Ordering::SeqCst),
            "vCPU {i} did not advance by exactly one instruction"
        );
    }
}
