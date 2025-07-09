// SPDX-License-Identifier: BSD-2-Clause
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
