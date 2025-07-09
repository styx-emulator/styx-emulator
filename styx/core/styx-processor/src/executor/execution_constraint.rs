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
use std::time::Duration;

/// An execution constraint is a combination of an optional instruction count
/// and an optional timeout, which together form an lower bound on the length of
/// an execution.
pub trait ExecutionConstraint {
    /// Optional upper bound on instructions to execute, `None` means no limit.
    fn instructions(&self) -> Option<u64> {
        None
    }

    /// Optional upper bound on time of execute, `None` means no limit.
    fn duration(&self) -> Option<Duration> {
        None
    }

    /// Convert to a [Sized] type of [ExecutionConstraint].
    fn concrete(&self) -> ExecutionConstraintConcrete {
        ExecutionConstraintConcrete {
            timeout: self.duration(),
            inst_count: self.instructions(),
        }
    }

    /// Check if the current execution time and total instructions executed are
    /// above our constraints.
    fn should_stop(&self, total_time: Duration, total_instructions: u64) -> bool {
        if let Some(timeout) = self.duration() {
            if timeout < total_time {
                return true;
            }
        }
        if let Some(insn) = self.instructions() {
            if insn < total_instructions {
                return true;
            }
        }

        false
    }
}

/// [Sized] type of [ExecutionConstraint].
#[derive(Debug)]
pub struct ExecutionConstraintConcrete {
    /// Upper bound on the number of instructions to execute, `None` means no limit.
    pub inst_count: Option<u64>,
    /// Upper bound on the duration of execution, `None` means no limit.
    pub timeout: Option<Duration>,
}

impl ExecutionConstraintConcrete {
    /// Returns an [`ExecutionConstraint`] with both fields set to `None`, i.e. run forever.
    pub fn none() -> Self {
        Self {
            inst_count: None,
            timeout: None,
        }
    }

    /// Traditional constructor where `0` or `Duration::None` means no limit for that timeout.
    pub fn new(inst_count: u64, timeout: Duration) -> Self {
        Self {
            inst_count: (inst_count != 0).then_some(inst_count),
            timeout: (!timeout.is_zero()).then_some(timeout),
        }
    }
}

/// Durations impose a time constraint only.
impl ExecutionConstraint for Duration {
    fn duration(&self) -> Option<Duration> {
        Some(*self)
    }
}

/// u64 imposes an instruction constraint only.
impl ExecutionConstraint for u64 {
    fn instructions(&self) -> Option<u64> {
        Some(*self)
    }
}

/// Allows us to use [ExecutionConstraint::should_stop()].
impl ExecutionConstraint for ExecutionConstraintConcrete {
    fn duration(&self) -> Option<Duration> {
        self.timeout
    }
    fn instructions(&self) -> Option<u64> {
        self.inst_count
    }
}

/// [ExecutionConstraint] with no constraints. Run like the wind, Forest.
#[derive(Default)]
pub struct Forever;
impl ExecutionConstraint for Forever {
    fn duration(&self) -> Option<Duration> {
        None
    }
    fn instructions(&self) -> Option<u64> {
        None
    }
}
