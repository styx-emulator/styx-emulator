// SPDX-License-Identifier: BSD-2-Clause
//! Sane default executor for Styx processors
use styx_errors::UnknownError;

use super::ExecutorImpl;
use crate::core::ProcessorCore;
use crate::cpu::ExecutionReport;

#[derive(Default, Debug)]
/// A sane default.
///
/// Executes 1000 instructions per stride, handling events at the end of each stride.
///
/// Notably implements [ExecutorImpl].
pub struct DefaultExecutor;

impl ExecutorImpl for DefaultExecutor {
    fn get_stride_length(&self) -> u64 {
        1000
    }

    fn emulate(
        &mut self,
        proc: &mut ProcessorCore,
        insns: u64,
    ) -> Result<ExecutionReport, UnknownError> {
        proc.cpu
            .execute(&mut proc.mmu, &mut proc.event_controller, insns)
    }
}
