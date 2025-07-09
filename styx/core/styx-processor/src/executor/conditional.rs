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

use styx_cpu_type::TargetExitReason;
use styx_errors::UnknownError;

use crate::{
    core::ProcessorCore, cpu::ExecutionReport, executor::Delta, plugins::collection::Plugins,
};

use super::ExecutorImpl;

/// Executor that stops when a custom function returns true.
///
/// Otherwise behavior is identical to the [`super::DefaultExecutor`].
///
/// Notably implements [ExecutorImpl].
pub struct ConditionalExecutor {
    should_stop: Box<dyn FnMut() -> bool + Send>,
}

impl ConditionalExecutor {
    /// Construct [ConditionalExecutor] with custom stop function.
    ///
    /// `should_stop` function is called every stride to determine if the
    /// processor should continue executing.
    pub fn new(should_stop: impl FnMut() -> bool + 'static + Send) -> Self {
        Self {
            should_stop: Box::new(should_stop),
        }
    }
}

impl ExecutorImpl for ConditionalExecutor {
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
}
