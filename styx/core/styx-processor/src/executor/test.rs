// SPDX-License-Identifier: BSD-2-Clause
//! Various tests for the executor.
use std::sync::{Arc, Mutex};
use std::time::Duration;
use styx_errors::UnknownError;

use crate::{
    core::ProcessorCore,
    cpu::DummyBackend,
    event_controller::{
        EventController, EventControllerImpl, EventDistributor, EventDistributorImpl,
        PeripheralTickCtx, RaisedIrqs, SingleVcpuEventDistributor,
    },
    executor::{time::*, ConditionalExecutor, DefaultExecutor, Executor, SingleStepExecutor, *},
    memory::{physical::MemoryBackend, Mmu},
    plugins::{Plugin, Plugins},
    processor::{Config, EmulationReport, PerVcpuSlice},
};

use super::Delta;

type SyncTicker = Arc<Mutex<TickCounter>>;

/// Test only helper for [`test_executor_events()`].
#[derive(Default)]
struct TickerManager {
    event_controller: SyncTicker,
    plugin: SyncTicker,
    peripheral: SyncTicker,
}

impl TickerManager {
    fn check(&self, expected_ticks: u32, expected_starts: u32) {
        let ev = self.event_controller.lock().unwrap();
        assert_eq!(
            ev.next_ticked, expected_ticks,
            "event controller next called {} time(s) but expected {} call(s)",
            ev.next_ticked, expected_ticks
        );
        assert_eq!(
            ev.ticked, expected_ticks,
            "event controller tick called {} time(s) but expected {} call(s)",
            ev.ticked, expected_ticks
        );
        assert_eq!(
            ev.stop_ticked, expected_starts,
            "event controller stop called {} time(s) but expected {} call(s)",
            ev.stop_ticked, expected_starts
        );
        assert_eq!(
            ev.start_ticked, expected_starts,
            "event controller start called {} time(s) but expected {} call(s)",
            ev.start_ticked, expected_starts
        );
        let plugin = self.plugin.lock().unwrap();
        assert_eq!(plugin.next_ticked, 0);
        assert_eq!(
            plugin.ticked, expected_ticks,
            "plugin tick called {} time(s) but expected {} call(s)",
            plugin.ticked, expected_ticks
        );
        assert_eq!(
            plugin.stop_ticked, expected_starts,
            "plugin stop called {} time(s) but expected {} call(s)",
            plugin.stop_ticked, expected_starts
        );
        assert_eq!(
            plugin.start_ticked, expected_starts,
            "plugin start called {} time(s) but expected {} call(s)",
            plugin.start_ticked, expected_starts
        );
        let peripheral = self.peripheral.lock().unwrap();
        // peripheral doesn't have next
        assert_eq!(peripheral.next_ticked, 0);
        assert_eq!(
            peripheral.ticked, expected_ticks,
            "peripheral tick called {} time(s) but expected {} call(s)",
            peripheral.ticked, expected_ticks
        );
        assert_eq!(
            peripheral.stop_ticked, expected_starts,
            "peripheral stop called {} time(s) but expected {} call(s)",
            peripheral.stop_ticked, expected_starts
        );
        assert_eq!(
            peripheral.start_ticked, expected_starts,
            "peripheral start called {} time(s) but expected {} call(s)",
            peripheral.start_ticked, expected_starts
        );
    }
}

#[derive(Default, Clone, Copy)]
struct TickCounter {
    // Incremented on `tick` event.
    pub ticked: u32,
    // Incremented on `on_processor_start` event.
    pub start_ticked: u32,
    // Incremented on `on_processor_stop` event.
    pub stop_ticked: u32,
    // Incremented on `next` event in event controller.
    pub next_ticked: u32,
}

impl EventControllerImpl for SyncTicker {
    fn next(
        &mut self,
        _cpu: &mut dyn crate::cpu::CpuBackend,
        _mmu: &mut Mmu,
    ) -> Result<crate::event_controller::InterruptExecuted, styx_errors::UnknownError> {
        self.lock().unwrap().next_ticked += 1;
        Ok(crate::event_controller::InterruptExecuted::NotExecuted)
    }

    fn latch(
        &mut self,
        _event: crate::event_controller::ExceptionNumber,
    ) -> Result<(), crate::event_controller::ActivateIRQnError> {
        todo!()
    }

    fn execute(
        &mut self,
        _irq: crate::event_controller::ExceptionNumber,
        _cpu: &mut dyn crate::cpu::CpuBackend,
        _mmu: &mut Mmu,
    ) -> Result<
        crate::event_controller::InterruptExecuted,
        crate::event_controller::ActivateIRQnError,
    > {
        todo!()
    }

    fn finish_interrupt(
        &mut self,
        _cpu: &mut dyn crate::cpu::CpuBackend,
        _mmu: &mut Mmu,
    ) -> Option<crate::event_controller::ExceptionNumber> {
        None
    }

    fn on_processor_start(
        &mut self,
        _cpu: &mut dyn crate::cpu::CpuBackend,
        _mmu: &mut Mmu,
    ) -> Result<(), styx_errors::UnknownError> {
        self.lock().unwrap().start_ticked += 1;
        Ok(())
    }

    fn on_processor_stop(
        &mut self,
        _cpu: &mut dyn crate::cpu::CpuBackend,
        _mmu: &mut Mmu,
    ) -> Result<(), styx_errors::UnknownError> {
        self.lock().unwrap().stop_ticked += 1;
        Ok(())
    }

    fn tick(
        &mut self,
        _cpu: &mut dyn crate::cpu::CpuBackend,
        _mmu: &mut Mmu,
        _delta: &Delta,
    ) -> Result<(), styx_errors::UnknownError> {
        self.lock().unwrap().ticked += 1;
        Ok(())
    }

    fn init(
        &mut self,
        _cpu: &mut dyn crate::cpu::CpuBackend,
        _mmu: &mut MemoryBackend,
        _config: &mut Config,
    ) -> Result<(), styx_errors::UnknownError> {
        Ok(())
    }
}

impl crate::event_controller::Peripheral for SyncTicker {
    fn name(&self) -> &str {
        "ticker"
    }

    fn on_processor_start(
        &mut self,
        _vcpus: &mut PerVcpuSlice<VcpuCore>,
        _event_controller: &mut dyn EventDistributorImpl,
    ) -> Result<(), UnknownError> {
        self.lock().unwrap().start_ticked += 1;
        Ok(())
    }

    fn on_processor_stop(
        &mut self,
        _vcpus: &mut PerVcpuSlice<VcpuCore>,
        _event_controller: &mut dyn EventDistributorImpl,
    ) -> Result<(), UnknownError> {
        self.lock().unwrap().stop_ticked += 1;
        Ok(())
    }

    fn tick(
        &mut self,
        _ctx: &PeripheralTickCtx<'_>,
    ) -> Result<RaisedIrqs, styx_errors::UnknownError> {
        self.lock().unwrap().ticked += 1;
        Ok(RaisedIrqs::none())
    }
}

impl Plugin for SyncTicker {
    fn name(&self) -> &str {
        "ticker "
    }

    fn on_processor_start(
        &mut self,
        _vcpus: &mut PerVcpuSlice<VcpuCore>,
        _core: &mut ProcessorCore,
    ) -> Result<(), UnknownError> {
        self.lock().unwrap().start_ticked += 1;
        Ok(())
    }

    fn on_processor_stop(
        &mut self,
        _vcpus: &mut PerVcpuSlice<VcpuCore>,
        _core: &mut ProcessorCore,
    ) -> Result<(), UnknownError> {
        self.lock().unwrap().stop_ticked += 1;
        Ok(())
    }

    fn tick(
        &mut self,
        _core: &mut ProcessorCore,
        _delta: &GlobalDelta,
        _vcpus: &mut PerVcpuSlice<VcpuCore>,
    ) -> Result<(), UnknownError> {
        self.lock().unwrap().ticked += 1;
        Ok(())
    }
}

/// Test a [`StrideExecutor`] for correct execution of tick and processor start/stop events.
///
/// The `begin_executor` closure should run the [`StrideExecutor`] so that there are
/// `expected_ticks` tick events and `expected_starts` `on_processor_start` and
/// `on_processor_stop` events run.
///
/// A reasonable `begin_executor` function is [`normal_begin_executor()`].
pub fn test_executor_events(
    executor_kind: ExecutorKind,
    begin_executor: impl FnOnce(ExecutorKind, &mut VcpuCore, &mut ProcessorCore, &mut Plugins),
    expected_ticks: u32,
    expected_starts: u32,
) -> Result<(), UnknownError> {
    let ticker = TickerManager::default();
    let mut primary = EventDistributor::new(Box::new(SingleVcpuEventDistributor::default()));
    primary
        .add_peripheral(Box::new(ticker.peripheral.clone()))
        .expect("failed to add peripheral");

    let mut vcpu = VcpuCore {
        cpu: Box::new(DummyBackend),
        mmu: Mmu::default(),
        event_controller: EventController::new(Box::new(ticker.event_controller.clone()), 0),
        time: VcpuTime::default(),
    };
    let mut core = ProcessorCore {
        memory: Arc::new(MemoryBackend::default()),
        event_controller: primary,
        time: ProcessorTime::default(),
    };
    let mut plugins = Plugins {
        plugins: vec![Box::new(ticker.plugin.clone())],
    };

    begin_executor(executor_kind, &mut vcpu, &mut core, &mut plugins);

    ticker.check(expected_ticks, expected_starts);
    Ok(())
}

/// Reasonable `begin_executor` function for `test_executor_events`.
///
/// This puts the executor into the struct it would be in a processor and run it with a max
/// instruction count of 1000.
pub fn normal_begin_executor(
    executor_kind: ExecutorKind,
    vcpu: &mut VcpuCore,
    core: &mut ProcessorCore,
    plugins: &mut Plugins,
) {
    let mut executor = Executor::new(executor_kind);
    let vcpus = PerVcpuSlice::single_mut(vcpu);
    executor.begin(vcpus, core, plugins, &1000).unwrap();
}

/// Legacy test of [`DefaultExecutor`] event cycle via [`TickerManager`]
///
/// Kept because it also checks processor start/stop
/// counters that the [`crate::executor::test_harness`] harness does not.
#[test]
fn test_default_legacy_events() {
    // This would normally be set via config but we set manually for test
    // to avoid mocking all of BuildingProcessor.
    let executor = DefaultExecutor::with_stride_length(1000);
    test_executor_events(ExecutorKind::stride(executor), normal_begin_executor, 1, 1).unwrap();
}

/// Test the event cycle of the [`ConditionalExecutor`]
#[test]
fn test_conditional() {
    let executor = ConditionalExecutor::new(|| false);
    test_executor_events(ExecutorKind::stride(executor), normal_begin_executor, 1, 1).unwrap();
}

/// Test the event cycle of the [`SingleStepExecutor`]
#[test]
fn test_single_step() {
    let executor = SingleStepExecutor;
    // each instruction is a tick, hence single step
    test_executor_events(
        ExecutorKind::stride(executor),
        normal_begin_executor,
        1000,
        1,
    )
    .unwrap();
}

/// Minimal [`CustomExecutor`] that records the constraints it received.
struct ConstraintCapture {
    captured: Arc<Mutex<Option<ExecutionConstraintConcrete>>>,
}

impl CustomExecutor for ConstraintCapture {
    fn execute(
        &mut self,
        _vcpus: &mut PerVcpuSlice<VcpuCore>,
        _core: &mut ProcessorCore,
        _plugins: &mut Plugins,
        constraints: &ExecutionConstraintConcrete,
    ) -> Result<Vec<EmulationReport>, UnknownError> {
        *self.captured.lock().unwrap() = Some(constraints.clone());
        Ok(vec![])
    }
}

/// Test that a [`CustomExecutor`] receives constraints and lifecycle events fire.
#[test]
fn test_custom_executor_receives_constraints() {
    let captured: Arc<Mutex<Option<ExecutionConstraintConcrete>>> = Arc::new(Mutex::new(None));
    let executor = ConstraintCapture {
        captured: captured.clone(),
    };

    let begin = |kind: ExecutorKind,
                 vcpu: &mut VcpuCore,
                 core: &mut ProcessorCore,
                 plugins: &mut Plugins| {
        let mut executor = Executor::new(kind);
        let vcpus = PerVcpuSlice::single_mut(vcpu);
        executor.begin(vcpus, core, plugins, &500_u64).unwrap();
    };

    // 0 ticks (custom executor doesn't call stride), 1 start/stop pair
    test_executor_events(ExecutorKind::custom(executor), begin, 0, 1).unwrap();

    let constraint = captured.lock().unwrap();
    let constraint = constraint
        .as_ref()
        .expect("CustomExecutor should have received constraints");
    assert_eq!(constraint.inst_count, Some(500));
    assert!(constraint.timeout.is_none());
}

/// Test primary EC that captures every `GlobalDelta` and the `pending_irqs` slice
/// passed to `tick`.
#[derive(Default)]
struct CapturingPrimaryEc {
    deltas: Arc<Mutex<Vec<GlobalDelta>>>,
    received_irqs: Arc<Mutex<Vec<crate::event_controller::ExceptionNumber>>>,
}

impl EventDistributorImpl for CapturingPrimaryEc {
    fn tick(
        &mut self,
        delta: &GlobalDelta,
        pending_irqs: &[crate::event_controller::ExceptionNumber],
        _vcpus: &mut PerVcpuSlice<VcpuCore>,
    ) -> Result<(), UnknownError> {
        self.deltas.lock().unwrap().push(delta.clone());
        self.received_irqs
            .lock()
            .unwrap()
            .extend_from_slice(pending_irqs);
        Ok(())
    }
}

/// Test that IRQs returned from Peripheral::tick() are passed to
/// EventDistributorImpl::tick() as pending_irqs.
#[test]
fn test_peripheral_tick_irq_routing() {
    /// A peripheral that returns IRQ 42 on every tick.
    struct IrqPeripheral;
    impl crate::event_controller::Peripheral for IrqPeripheral {
        fn name(&self) -> &str {
            "irq-peripheral"
        }
        fn tick(
            &mut self,
            _ctx: &PeripheralTickCtx<'_>,
        ) -> Result<RaisedIrqs, styx_errors::UnknownError> {
            Ok(RaisedIrqs::one(42))
        }
    }

    let capturing = CapturingPrimaryEc::default();
    let deltas = capturing.deltas.clone();
    let received = capturing.received_irqs.clone();
    let mut primary = EventDistributor::new(Box::new(capturing));
    primary
        .add_peripheral(Box::new(IrqPeripheral))
        .expect("failed to add peripheral");

    let mut vcpu = VcpuCore {
        cpu: Box::new(DummyBackend),
        mmu: Mmu::default(),
        event_controller: EventController::default(),
        time: VcpuTime::default(),
    };
    let mut core = ProcessorCore {
        memory: Arc::new(MemoryBackend::default()),
        event_controller: primary,
        time: ProcessorTime::default(),
    };
    let mut plugins = Plugins { plugins: vec![] };

    let mut executor = Executor::new(ExecutorKind::stride(DefaultExecutor::with_stride_length(
        1000,
    )));

    let vcpus = PerVcpuSlice::single_mut(&mut vcpu);
    executor
        .begin(vcpus, &mut core, &mut plugins, &1000)
        .unwrap();

    let deltas = deltas.lock().unwrap();
    assert_eq!(deltas.len(), 1, "primary EC should have ticked once");
    assert_eq!(deltas[0].simulated_time, 1000);
    assert!(deltas[0].wall_time > Duration::ZERO);

    let received = received.lock().unwrap();
    assert_eq!(
        received.len(),
        1,
        "EventDistributorImpl::tick() should have received IRQs"
    );
    assert!(
        received[0] == 42,
        "All received IRQs should be 42, got: {:?}",
        *received
    );
}
