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
use styx_core::cpu::ExecutionReport;
use styx_core::sync::sync::Condvar;
use styx_core::{executor::ExecutorImpl, prelude::*};

/// A processor is either started or paused.
#[derive(PartialEq, Eq, Clone, Copy, Debug, Default)]
pub enum ProcessorState {
    Running,
    #[default]
    Stopped,
}

/// [ExecutorImpl] providing asynchronous start/pause functionality.
///
/// Emulation is blocked until the desired_state is set to be running.
pub struct ServiceExecutor {
    desired_state: Arc<(Mutex<ProcessorState>, Condvar)>,
}

/// Handle to [ServiceExecutor] providing asynchronous start/pause functionality.
///
/// Use [Self::set()] to start and stop the processor.
pub struct ServiceExecutorHandle {
    desired_state: Arc<(Mutex<ProcessorState>, Condvar)>,
}

impl ServiceExecutorHandle {
    pub fn set(&self, desired_state: ProcessorState) {
        let (state, cvar) = &*self.desired_state;
        *state.lock().unwrap() = desired_state;
        cvar.notify_one();
    }
}

impl ServiceExecutor {
    pub fn new() -> (Self, ServiceExecutorHandle) {
        let desired_state = Arc::new((Mutex::new(ProcessorState::default()), Condvar::new()));
        (
            ServiceExecutor {
                desired_state: desired_state.clone(),
            },
            ServiceExecutorHandle { desired_state },
        )
    }

    fn block_until_runnable(&self) {
        let (lock, cvar) = &*self.desired_state;
        let mut state = lock.lock().unwrap();
        while *state != ProcessorState::Running {
            state = cvar.wait(state).unwrap();
        }
    }
}

impl ExecutorImpl for ServiceExecutor {
    fn emulate(
        &mut self,
        proc: &mut ProcessorCore,
        insns: u64,
    ) -> Result<ExecutionReport, UnknownError> {
        self.block_until_runnable();
        proc.cpu
            .execute(&mut proc.mmu, &mut proc.event_controller, insns)
    }
}
