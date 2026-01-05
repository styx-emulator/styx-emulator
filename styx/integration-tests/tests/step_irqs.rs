// SPDX-License-Identifier: BSD-2-Clause
use std::sync::atomic::{AtomicBool, Ordering};
use styx_core::{
    arch::{
        ppc32::{gdb_targets::Ppc4xxTargetDescription, variants::Ppc405},
        RegisterValue,
    },
    core::builder::BuildProcessorImplArgs,
    prelude::*,
};
use styx_plugins::gdb::StepIRQs;

/// Dummy Event Controller impl that stores if `next()` was called.
struct DidNextEventController(&'static AtomicBool);
impl EventControllerImpl for DidNextEventController {
    fn next(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        _peripherals: &mut styx_core::event_controller::Peripherals,
    ) -> Result<styx_core::event_controller::InterruptExecuted, UnknownError> {
        self.0.store(true, Ordering::SeqCst);
        Ok(styx_core::event_controller::InterruptExecuted::NotExecuted)
    }

    fn latch(
        &mut self,
        _event: ExceptionNumber,
    ) -> Result<(), styx_core::event_controller::ActivateIRQnError> {
        Ok(())
    }

    fn execute(
        &mut self,
        _irq: ExceptionNumber,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
    ) -> Result<
        styx_core::event_controller::InterruptExecuted,
        styx_core::event_controller::ActivateIRQnError,
    > {
        Ok(styx_core::event_controller::InterruptExecuted::NotExecuted)
    }

    fn finish_interrupt(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
    ) -> Option<ExceptionNumber> {
        None
    }

    fn init(&mut self, _cpu: &mut dyn CpuBackend, _mmu: &mut Mmu) -> Result<(), UnknownError> {
        Ok(())
    }
}

/// Dummy CPU implementation, just enough to "execute" instructions under a debugger.
#[derive(Debug)]
struct DummyCpu;
/// ArchitectureDef for DummyCPU, doesn't matter.
const ARCH_DEF: Ppc405 = Ppc405 {};
impl Hookable for DummyCpu {
    fn add_hook(
        &mut self,
        _hook: StyxHook,
    ) -> Result<styx_core::hooks::HookToken, styx_core::hooks::AddHookError> {
        todo!()
    }

    fn delete_hook(
        &mut self,
        _token: styx_core::hooks::HookToken,
    ) -> Result<(), styx_core::hooks::DeleteHookError> {
        todo!()
    }
}
impl CpuBackend for DummyCpu {
    fn read_register_raw(
        &mut self,
        _reg: ArchRegister,
    ) -> Result<styx_core::arch::RegisterValue, ReadRegisterError> {
        Ok(RegisterValue::u32(0))
    }

    fn write_register_raw(
        &mut self,
        _reg: ArchRegister,
        _value: styx_core::arch::RegisterValue,
    ) -> Result<(), WriteRegisterError> {
        todo!()
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
        Ok(styx_core::cpu::ExecutionReport {
            exit_reason: TargetExitReason::InstructionCountComplete,
            instructions_executed: Some(count),
            last_packet_order: None,
        })
    }

    fn stop(&mut self) {
        todo!()
    }

    fn context_save(&mut self) -> Result<(), UnknownError> {
        todo!()
    }

    fn context_restore(&mut self) -> Result<(), UnknownError> {
        todo!()
    }

    fn pc(&mut self) -> Result<u64, UnknownError> {
        Ok(0)
    }

    fn set_pc(&mut self, _value: u64) -> Result<(), UnknownError> {
        todo!()
    }
}

/// Test the [StepIRQs] options in [GDBOption] (activate IRQs on step).
#[test]
fn test_step_irqs() {
    let did_tick: &'static AtomicBool = Box::leak(Box::new(AtomicBool::new(false)));
    let proc = ProcessorBuilder::default().with_builder(move |_: &BuildProcessorImplArgs| {
        let event_controller = DidNextEventController(did_tick);
        let bundle = ProcessorBundle {
            event_controller: Box::new(event_controller),
            cpu: Box::new(DummyCpu),
            ..Default::default()
        };
        Ok(bundle)
    });

    // small cpu epoch to make test fast
    const CPU_EPOCH: u64 = 10;
    let harness = ::styx_integration_tests::gdb_harness::GdbHarness::from_processor_builder_options::<
        Ppc4xxTargetDescription,
    >(
        proc,
        styx_plugins::gdb::GDBOptions {
            step_irqs: StepIRQs::Enabled,
            cpu_epoch: CPU_EPOCH,
        },
    );

    did_tick.store(false, Ordering::SeqCst);
    for i in 0..=CPU_EPOCH * 2 {
        harness.step_instruction().unwrap();
        // tick should trigger on 10 and 20
        // i.e. i % cpu_epoch == 0
        // not triggered on first cycle
        if i != 0 && i % CPU_EPOCH == 0 {
            assert!(did_tick.load(Ordering::SeqCst));
            did_tick.store(false, Ordering::SeqCst);
        } else {
            assert!(!did_tick.load(Ordering::SeqCst));
        }
    }
}
