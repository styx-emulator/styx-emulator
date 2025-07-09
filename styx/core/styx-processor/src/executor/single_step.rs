// SPDX-License-Identifier: BSD-2-Clause
use styx_errors::UnknownError;

use crate::{core::ProcessorCore, cpu::ExecutionReport};

use super::ExecutorImpl;

/// Executor that handles events after every instruction.
///
/// Notably implements [ExecutorImpl].
#[derive(Debug)]
pub struct SingleStepExecutor;

impl ExecutorImpl for SingleStepExecutor {
    fn get_stride_length(&self) -> u64 {
        1
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
