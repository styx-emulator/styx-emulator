// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
use std::sync::{Arc, Mutex};

use styx_errors::UnknownError;

use crate::{
    core::ProcessorCore,
    cpu::{CpuBackend, DummyBackend},
    event_controller::{EventController, EventControllerImpl, Peripheral},
    executor::{ConditionalExecutor, DefaultExecutor, Executor, ExecutorImpl, SingleStepExecutor},
    memory::Mmu,
    plugins::{Plugin, Plugins},
};

type SyncTicker = Arc<Mutex<Ticker>>;

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
        assert_eq!(ev.next_ticked, expected_ticks);
        assert_eq!(ev.ticked, expected_ticks);
        assert_eq!(ev.stop_ticked, expected_starts);
        assert_eq!(ev.start_ticked, expected_starts);
        let plugin = self.plugin.lock().unwrap();
        // plugin doesn't have next
        assert_eq!(plugin.next_ticked, 0);
        assert_eq!(plugin.ticked, expected_ticks);
        assert_eq!(plugin.stop_ticked, expected_starts);
        assert_eq!(plugin.start_ticked, expected_starts);
        let peripheral = self.peripheral.lock().unwrap();
        // peripheral doesn't have next
        assert_eq!(peripheral.next_ticked, 0);
        assert_eq!(peripheral.ticked, expected_ticks);
        assert_eq!(peripheral.stop_ticked, expected_starts);
        assert_eq!(peripheral.start_ticked, expected_starts);
    }
}

#[derive(Default, Clone, Copy)]
struct Ticker {
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
        _peripherals: &mut crate::event_controller::Peripherals,
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
        todo!()
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
    ) -> Result<(), styx_errors::UnknownError> {
        self.lock().unwrap().ticked += 1;
        Ok(())
    }

    fn init(
        &mut self,
        _cpu: &mut dyn crate::cpu::CpuBackend,
        _mmu: &mut Mmu,
    ) -> Result<(), styx_errors::UnknownError> {
        Ok(())
    }
}

impl Peripheral for SyncTicker {
    fn name(&self) -> &str {
        "ticker"
    }

    fn on_processor_start(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        _event_controller: &mut dyn EventControllerImpl,
    ) -> Result<(), UnknownError> {
        self.lock().unwrap().start_ticked += 1;
        Ok(())
    }

    fn on_processor_stop(
        &mut self,
        _cpu: &mut dyn CpuBackend,
        _mmu: &mut Mmu,
        _event_controller: &mut dyn EventControllerImpl,
    ) -> Result<(), UnknownError> {
        self.lock().unwrap().stop_ticked += 1;
        Ok(())
    }

    fn tick(
        &mut self,
        _cpu: &mut dyn crate::cpu::CpuBackend,
        _mmu: &mut Mmu,
        _event_controller: &mut dyn EventControllerImpl,
        _delta: &crate::executor::Delta,
    ) -> Result<(), styx_errors::UnknownError> {
        self.lock().unwrap().ticked += 1;
        Ok(())
    }
}

impl Plugin for SyncTicker {
    fn name(&self) -> &str {
        "ticker "
    }

    fn tick(&mut self, _core: &mut ProcessorCore) -> Result<(), styx_errors::UnknownError> {
        self.lock().unwrap().ticked += 1;
        Ok(())
    }

    fn on_processor_start(&mut self, _core: &mut ProcessorCore) -> Result<(), UnknownError> {
        self.lock().unwrap().start_ticked += 1;
        Ok(())
    }

    fn on_processor_stop(&mut self, _core: &mut ProcessorCore) -> Result<(), UnknownError> {
        self.lock().unwrap().stop_ticked += 1;
        Ok(())
    }
}

/// Test an [`ExecutorImpl`] for correct execution of tick and processor start/stop events.
///
/// The `begin_executor` closure should run the [`ExecutorImpl`] so that there are `expected_ticks` tick events
/// and `expected_starts` `on_processor_start` and `on_processor_stop` events run.
///
/// A reasonable `begin_executor` function is [`normal_begin_executor`].
pub fn test_executor_events(
    executor_impl: Box<dyn ExecutorImpl>,
    begin_executor: impl FnOnce(Box<dyn ExecutorImpl>, &mut ProcessorCore, &mut Plugins),
    expected_ticks: u32,
    expected_starts: u32,
) -> Result<(), UnknownError> {
    let ticker = TickerManager::default();
    let mmu = Mmu::default();
    let mut ev = EventController::new(Box::new(ticker.event_controller.clone()));
    ev.add_peripheral(Box::new(ticker.peripheral.clone()))?;
    let cpu = DummyBackend;
    let mut proc = ProcessorCore {
        cpu: Box::new(cpu),
        mmu,
        event_controller: ev,
    };
    let mut plugins = Plugins {
        plugins: vec![Box::new(ticker.plugin.clone())],
    };

    begin_executor(executor_impl, &mut proc, &mut plugins);

    ticker.check(expected_ticks, expected_starts);
    Ok(())
}

/// Reasonable `begin_executor` function for `test_executor_events`.
///
/// This puts the executor into the struct it would be in a processor and run it with a max
/// instruction count of 1000.
pub fn normal_begin_executor(
    executor: Box<dyn ExecutorImpl>,
    proc: &mut ProcessorCore,
    plugins: &mut Plugins,
) {
    let mut executor = Executor::new(executor);
    executor.begin(proc, plugins, 1000).unwrap();
}

/// Test the event cycle of the [`DefaultExecutor`]
#[test]
fn test_default() {
    let executor = DefaultExecutor;
    test_executor_events(Box::new(executor), normal_begin_executor, 1, 1).unwrap();
}

/// Test the event cycle of the [`ConditionalExecutor`]
#[test]
fn test_conditional() {
    let executor = ConditionalExecutor::new(|| false);
    test_executor_events(Box::new(executor), normal_begin_executor, 1, 1).unwrap();
}

/// Test the event cycle of the [`SingleStepExecutor`]
#[test]
fn test_single_step() {
    let executor = SingleStepExecutor;
    // each instruction is a tick, hence single step
    test_executor_events(Box::new(executor), normal_begin_executor, 1000, 1).unwrap();
}
