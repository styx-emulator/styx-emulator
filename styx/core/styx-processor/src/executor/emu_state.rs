// SPDX-License-Identifier: BSD-2-Clause
use std::time::{Duration, Instant};

use log::trace;
use styx_cpu_type::TargetExitReason;

use crate::processor::InstructionReport;

use super::ExecutionConstraint;

/// Tracks current emulation progress, per invocation.
///
/// Typical usage will create a new [`EmulationRunState`] when the user starts
/// executing, and will update after every stride.
/// The exit condition returned is checked.
#[derive(Clone, Debug)]
pub struct EmulationRunState {
    pub stride: u64,
    pub target_time: Option<Instant>,
    pub remaining_instructions: Option<u64>,
    pub total_instructions: InstructionReport,
    pub total_wall_time: Duration,
}

impl EmulationRunState {
    pub fn new(stride: u64, conditions: &impl ExecutionConstraint) -> Self {
        let remaining_instructions = conditions.instructions();
        let stride = remaining_instructions
            .map(|r| r.min(stride))
            .unwrap_or(stride);
        EmulationRunState {
            stride,
            target_time: conditions
                .duration()
                .map(|timeout_duration| Instant::now() + timeout_duration),
            remaining_instructions,
            total_instructions: InstructionReport::default(),
            total_wall_time: Duration::ZERO,
        }
    }

    pub fn instructions_ran(&mut self, instructions_ran: u64) -> Option<TargetExitReason> {
        if let Some(remaining_instructions) = &mut self.remaining_instructions {
            *remaining_instructions = remaining_instructions.saturating_sub(instructions_ran);
            self.stride = self.stride.min(*remaining_instructions);
            if *remaining_instructions == 0 {
                trace!("executor instruction count hit");
                return Some(TargetExitReason::InstructionCountComplete);
            }
        }
        None
    }

    pub fn timeout_check(&self) -> Option<TargetExitReason> {
        if self
            .target_time
            .map(|timeout| Instant::now() > timeout)
            .unwrap_or(false)
        {
            trace!("executor timeout hit");
            Some(TargetExitReason::ExecutionTimeoutComplete)
        } else {
            None
        }
    }
}
