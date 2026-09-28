// SPDX-License-Identifier: BSD-2-Clause
use styx_core::core::VcpuCore;
use styx_core::executor::{default_emulation_setup, StrideExecutor};
use styx_core::plugins::Plugins;
use styx_core::prelude::*;
use styx_core::sync::sync::Condvar;

/// A processor is either started or paused.
#[derive(PartialEq, Eq, Clone, Copy, Debug, Default)]
pub enum ProcessorState {
    Running,
    #[default]
    Stopped,
}

/// [`StrideExecutor`] providing asynchronous start/pause functionality.
///
/// Emulation is blocked until the desired_state is set to be running. Blocking
/// happens once at emulation startup (so the processor waits for the first
/// [`ServiceExecutorHandle::set`] call) and again between strides via the
/// executor's `tick`.
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

impl StrideExecutor for ServiceExecutor {
    fn tick(
        &mut self,
        _delta: &GlobalDelta,
        _vcpus: &mut PerVcpuSlice<VcpuCore>,
    ) -> Result<(), UnknownError> {
        self.block_until_runnable();
        Ok(())
    }

    fn emulation_setup(
        &mut self,
        vcpus: &mut PerVcpuSlice<VcpuCore>,
        core: &mut ProcessorCore,
        plugins: &mut Plugins,
    ) -> Result<(), UnknownError> {
        // Mirror the default [`StrideExecutor::emulation_setup`] so the
        // normal start lifecycle still fires, then block waiting for the
        // service to request a transition to `Running`.
        default_emulation_setup(vcpus, core, plugins)?;
        self.block_until_runnable();
        Ok(())
    }
}
