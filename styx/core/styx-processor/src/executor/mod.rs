// SPDX-License-Identifier: BSD-2-Clause
//! The Executor controls how the core executes and when it halts.
//!
//! The primary point of user control in the executor is by defining an [ExecutorImpl]. The
//! [ExecutorImpl] decides how many instructions to emulate at a time, when to handle events, when
//! to update the state of peripherals, and when to halt emulation.
//!
//! There are some prebuilt [ExecutorImpl] implementations:
//!
//! - [DefaultExecutor] executes the processor as you would expect and is the default in the
//!   processor builder.
//! - [SingleStepExecutor] has a stride length of 1 meaning events and peripherals are
//!   ticked after every instruction.
//! - [ConditionalExecutor] evaluates a custom function each stride to determine if the processor
//!   should halt.
//!
mod conditional;
mod default;
mod execution_constraint;
mod executor_impl;
mod single_step;
#[cfg(test)]
mod test;

pub use conditional::ConditionalExecutor;
pub use default::DefaultExecutor;
pub use execution_constraint::{ExecutionConstraint, ExecutionConstraintConcrete, Forever};
pub use executor_impl::ExecutorImpl;
pub use single_step::SingleStepExecutor;

use log::{debug, trace};
use std::time::Instant;
use styx_cpu_type::TargetExitReason;
use styx_errors::UnknownError;

use crate::{
    core::ProcessorCore,
    plugins::collection::Plugins,
    processor::{EmulationReport, InstructionReport},
};

/// The main control point for Styx emulation.
///
/// Interacts with the inner, processor specific, executor implementation to manage the emulator
/// state.  Control is passed here after the [`Processor::run()`](crate::processor::Processor)
/// function is called.
///
/// The default implementation uses the [DefaultExecutor] which is what you would expect using an
/// executor.
///
/// Styx users are not expected to use [`Executor`] directly. Its behavior is explained in the user
/// facing [`ExecutorImpl`].
pub struct Executor {
    inner: Box<dyn ExecutorImpl>,
}

impl Executor {
    pub(crate) fn new(inner: Box<dyn ExecutorImpl>) -> Self {
        Self { inner }
    }

    /// Start the executor.
    ///
    /// The `conditions` parameter represents the total constraint on emulation, e.g.
    /// how many instructions should we execute in total or how long we should run in
    /// total. This is different from the stride constraint provided by the inner
    /// executor, which defines the size of steps we take to reach the total constraint.
    pub(crate) fn begin(
        &mut self,
        proc: &mut ProcessorCore,
        plugins: &mut Plugins,
        conditions: impl ExecutionConstraint,
    ) -> Result<EmulationReport, UnknownError> {
        let conditions = conditions.concrete();
        debug!("executor emulating with conditions: {conditions:?}");
        let mut stride_constraint = if let Some(i) = conditions.inst_count {
            self.inner.get_stride_length().min(i)
        } else {
            self.inner.get_stride_length()
        };

        self.inner.emulation_setup(proc, plugins)?;

        let target_time = conditions
            .timeout
            .map(|timeout_duration| Instant::now() + timeout_duration);
        let mut remaining_instructions = conditions.inst_count;
        let mut total_instructions = InstructionReport::default();
        let exit_reason = loop {
            if !self.inner.valid_emulation_conditions(proc) {
                break TargetExitReason::HostStopRequest;
            }

            trace!("executor start emulating");
            let emulate_start = Instant::now();
            let report = self.inner.emulate(proc, stride_constraint)?;
            let emulate_time = Instant::now() - emulate_start;

            let instruction_report =
                InstructionReport::from_execution_report(&report, stride_constraint);
            total_instructions += instruction_report;
            let delta = Delta {
                time: emulate_time,
                count: instruction_report.instructions(),
            };

            // check if inner wants to halt
            if self.inner.halt_emulation(&report.exit_reason, &delta) {
                trace!("inner indicated halt emulation");
                break report.exit_reason;
            }

            // post stride processing
            self.inner.post_stride_processing(proc, plugins, &delta)?;

            // timeout check processing
            if target_time
                .map(|timeout| Instant::now() > timeout)
                .unwrap_or(false)
            {
                trace!("executor timeout hit");
                break TargetExitReason::ExecutionTimeoutComplete;
            }

            if let Some(remaining_instr) = &mut remaining_instructions {
                *remaining_instr = remaining_instr.saturating_sub(stride_constraint);
                if *remaining_instr == 0 {
                    trace!("executor instruction count hit");
                    break TargetExitReason::InstructionCountComplete;
                }
                if *remaining_instr < stride_constraint {
                    stride_constraint = *remaining_instr;
                }
            }
        };

        self.inner.emulation_teardown(proc, plugins)?;
        Ok(EmulationReport {
            exit_reason,
            instructions: total_instructions,
        })
    }
}

impl Default for Executor {
    fn default() -> Self {
        Self {
            inner: Box::new(DefaultExecutor),
        }
    }
}

#[derive(Debug, Clone)]
/// Represents a length of emulation.
pub struct Delta {
    /// Elapsed time.
    pub time: std::time::Duration,
    /// Number of instructions executed.
    pub count: u64,
}
