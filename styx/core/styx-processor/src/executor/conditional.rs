// SPDX-License-Identifier: BSD-2-Clause

use styx_cpu_type::TargetExitReason;
use styx_errors::UnknownError;

use crate::{
    core::ProcessorCore, cpu::ExecutionReport, executor::Delta, plugins::collection::Plugins,
    processor::core_configs::ConfigRequestedStrideLength,
};

use super::ExecutorImpl;

/// Executor that stops when a custom function returns true.
///
/// Otherwise behavior is identical to the [`super::DefaultExecutor`].
///
/// Notably implements [ExecutorImpl].
pub struct ConditionalExecutor {
    should_stop: Box<dyn FnMut() -> bool + Send>,
    stride_length: u64,
}

impl ConditionalExecutor {
    /// Construct [ConditionalExecutor] with custom stop function.
    ///
    /// `should_stop` function is called every stride to determine if the
    /// processor should continue executing.
    pub fn new(should_stop: impl FnMut() -> bool + 'static + Send) -> Self {
        Self {
            should_stop: Box::new(should_stop),
            stride_length: 1000,
        }
    }
}

impl ExecutorImpl for ConditionalExecutor {
    fn get_stride_length(&self) -> u64 {
        self.stride_length
    }

    fn emulate(
        &mut self,
        proc: &mut ProcessorCore,
        insns: u64,
    ) -> Result<ExecutionReport, UnknownError> {
        proc.cpu
            .execute(&mut proc.mmu, &mut proc.event_controller, insns)
    }

    fn post_stride_processing(
        &mut self,
        proc: &mut ProcessorCore,
        plugins: &mut Plugins,
        delta: &Delta,
    ) -> Result<(), UnknownError> {
        let event_controller = &mut proc.event_controller;
        let cpu = &mut proc.cpu;
        let mmu = &mut proc.mmu;

        event_controller.next(cpu.as_mut(), mmu)?;

        event_controller.tick(cpu.as_mut(), mmu, delta)?;

        plugins.tick(proc)?;

        Ok(())
    }

    fn halt_emulation(&mut self, reason: &TargetExitReason, _delta: &Delta) -> bool {
        reason.fatal() || (self.should_stop)()
    }

    fn init(
        &mut self,
        _proc: &mut crate::processor::BuildingProcessor,
    ) -> Result<(), UnknownError> {
        self.stride_length = _proc
            .config
            .get_or_default::<ConfigRequestedStrideLength>()
            .preferred_stride_length;
        Ok(())
    }
}
