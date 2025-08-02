// SPDX-License-Identifier: BSD-2-Clause
use std::ops::{Add, AddAssign};

use styx_cpu_type::TargetExitReason;

use crate::cpu::ExecutionReport;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InstructionReport {
    Exact(u64),
    Approximate(u64),
}

impl InstructionReport {
    /// Approximate number of instructions executed. Upper bound.
    pub fn instructions(&self) -> u64 {
        match self {
            InstructionReport::Exact(instr) => *instr,
            InstructionReport::Approximate(instr) => *instr,
        }
    }

    /// Exact number of instructions executed. None if not available.
    pub fn exact_instructions(&self) -> Option<u64> {
        match self {
            InstructionReport::Exact(instr) => Some(*instr),
            InstructionReport::Approximate(_) => None,
        }
    }

    pub fn from_execution_report(execution_report: &ExecutionReport, stride_length: u64) -> Self {
        Self::from_instructions_executed(&execution_report.instructions_executed, stride_length)
    }

    pub fn from_instructions_executed(
        instructions_executed: &Option<u64>,
        stride_length: u64,
    ) -> Self {
        match instructions_executed {
            Some(instr) => Self::Exact(*instr),
            None => Self::Approximate(stride_length),
        }
    }
}

// Default impl is Exactly 0 instructions.
impl Default for InstructionReport {
    fn default() -> Self {
        Self::Exact(0)
    }
}

// Add will add the total instructs between the left and right hand sides. The output will be Exact
// if both operands are Exact, otherwise the result will be Approximate.
impl Add for InstructionReport {
    type Output = InstructionReport;

    fn add(self, rhs: Self) -> Self::Output {
        match self {
            InstructionReport::Exact(self_exact) => match rhs {
                // If both exact, we get an exact output
                InstructionReport::Exact(rhs_exact) => Self::Exact(self_exact + rhs_exact),
                // If other is approx, we get an approx output
                InstructionReport::Approximate(rhs_approx) => {
                    Self::Approximate(self_exact + rhs_approx)
                }
            },
            // We get an approx output
            InstructionReport::Approximate(self_approx) => {
                Self::Approximate(self_approx + rhs.instructions())
            }
        }
    }
}

impl AddAssign for InstructionReport {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

/// Results of cpu execution. Primarily used as a return from
/// [`Processor::run()`](crate::processor::Processor::run()).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmulationReport {
    /// Exit reason reported by the processor.
    pub exit_reason: TargetExitReason,
    /// The number of executed instructions.
    ///
    /// Indicates the number of instructions executed, if available. InstructionReport::Approximate
    /// is used if the CpuBackend did not report exact instruction counts. The approximate
    /// instruction count will be an upper bound on the amount of executed instructions.
    pub instructions: InstructionReport,
    /// Total wall clock time spent in emulation.
    pub wall_time: std::time::Duration,
}

impl EmulationReport {
    pub fn new(
        exit_reason: TargetExitReason,
        instructions: InstructionReport,
        wall_time: std::time::Duration,
    ) -> Self {
        Self {
            exit_reason,
            instructions,
            wall_time,
        }
    }

    pub fn is_fatal(&self) -> bool {
        self.exit_reason.fatal()
    }

    pub fn is_stop_request(&self) -> bool {
        self.exit_reason.is_stop_request()
    }

    /// Approximate number of instructions executed. Upper bound.
    ///
    /// See the instructions field for more info and exact instruction
    /// count.
    pub fn instructions(&self) -> u64 {
        self.instructions.instructions()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_instruction_report_add() {
        let exact_100 = InstructionReport::Exact(100);
        let exact_1000 = InstructionReport::Exact(1000);
        let approx_1000 = InstructionReport::Approximate(1000);

        assert_eq!(InstructionReport::Exact(1100), exact_100 + exact_1000);
        assert_eq!(
            InstructionReport::Approximate(1100),
            exact_100 + approx_1000
        );
        assert_eq!(
            InstructionReport::Approximate(2000),
            approx_1000 + approx_1000
        );
    }
}
