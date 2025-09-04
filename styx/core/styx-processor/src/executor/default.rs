// SPDX-License-Identifier: BSD-2-Clause
//! Sane default executor for Styx processors
use styx_errors::UnknownError;

use crate::{
    core::ProcessorCore,
    cpu::ExecutionReport,
    processor::{core_configs::ConfigRequestedStrideLength, BuildingProcessor},
};

use super::ExecutorImpl;

/// A sane default.
///
/// Executes 1000 instructions per stride, handling events at the end of each stride.
///
/// Notably implements [ExecutorImpl].
///
/// Stride length defaults to 0 here but gets initialized to the
/// [`ConfigRequestedStrideLength`].
#[derive(Default, Debug)]
pub struct DefaultExecutor {
    pub(crate) stride_length: u64,
}

impl ExecutorImpl for DefaultExecutor {
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

    /// Called before emulating, initializes stride length here.
    fn init(&mut self, proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        self.stride_length = proc
            .config
            .get_or_default::<ConfigRequestedStrideLength>()
            .preferred_stride_length;
        Ok(())
    }
}
