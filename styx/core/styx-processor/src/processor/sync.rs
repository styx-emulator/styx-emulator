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
//! A [`Processor`] that is [`Sync`] + [`Clone`].
//!
//! Check out [`SyncProcessor`] for detailed docs.
use std::{
    ops::DerefMut,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex,
    },
};

use log::{debug, trace};
use replace_with::{replace_with_or_abort, replace_with_or_abort_and_return};
use static_assertions::assert_impl_all;
use styx_cpu_type::arch::{backends::ArchRegister, RegisterValue};
use styx_errors::UnknownError;

use super::{Processor, ProcessorBuilder};
use crate::{
    core::ProcessorCore,
    cpu::{ReadRegisterError, WriteRegisterError},
    executor::ExecutionConstraint,
    hooks::{AddHookError, DeleteHookError, HookToken, StyxHook},
    memory::{
        helpers::{ReadExt, Readable, Writable},
        MmuOpError,
    },
    plugins::task_queue::*,
    processor::EmulationReport,
};

#[derive(Debug)]
enum InternalProcessorState {
    /// Processor is done running and has not been paused since stopping.
    ///
    /// This is the case where the [`Processor`] stopped before anyone calling
    /// [`SyncProcessor::pause()`] to collect the result.
    DoneRunning((Processor, Result<EmulationReport, UnknownError>)),
    /// Processor is not running.
    ///
    /// This is the initial state of the sync processor when first built and also the state after
    /// [`InternalProcessorState::DoneRunning`] is collected using [`SyncProcessor::pause()`].
    Paused(Processor),
    /// Processor is actively running in a separate thread.
    ///
    /// We get the processor back when the thread completes.
    Running,
}

/// Processor state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessorState {
    /// Processor is not running.
    Paused,
    /// Processor is running.
    Running,
}

impl ProcessorState {
    /// Is the processor running?
    pub fn is_running(&self) -> bool {
        match self {
            ProcessorState::Paused => false,
            ProcessorState::Running => true,
        }
    }
}
impl From<&InternalProcessorState> for ProcessorState {
    fn from(value: &InternalProcessorState) -> Self {
        match value {
            InternalProcessorState::Paused(_) => ProcessorState::Paused,
            InternalProcessorState::DoneRunning(_) => ProcessorState::Paused,
            InternalProcessorState::Running => ProcessorState::Running,
        }
    }
}

/// related to [`SyncProcessor::task_queue_active`]
const ACTIVE: bool = true;
const INACTIVE: bool = false;

#[derive(Debug)]
pub struct ProcessorAlreadyStarted;
#[derive(Debug)]
pub struct ProcessorAlreadyPaused;

assert_impl_all!(SyncProcessor: Send, Sync);

/// A [`Sync`] + [`Clone`] processor, safe and ergonomic to use for all your threading needs! You'd
/// think you were using Python!
///
/// This works by using the [`TaskQueuePlugin`] and tracking processor state in a sync friendly way.
/// The consequence of this is that all accesses while the processor is running occur in the `tick`
/// phase of processor execution.
///
/// The processor is either [ProcessorState::Paused] or [ProcessorState::Running]. In general, all
/// methods can be called in any state and will operate in an expected manner. This is for
/// convenience but also to avoid races, the internal processor state is locked and unobtainable by
/// `SyncProcessor` users. A method that has the processor state as a pre-condition would be
/// impossible to call without racing with a possible other thread.
#[derive(Clone, Debug)]
pub struct SyncProcessor {
    /// Source of truth current state of the processor.
    ///
    /// [Self::start()] and [Self::pause()] handle the switching of states.
    ///
    /// The condvar should be notified when the processor state changes. Currently this is used to
    /// wake users of [`Self::pause()`] but future users can use to block until a certain processor
    /// state is encountered.
    state: Arc<(Mutex<InternalProcessorState>, Condvar)>,
    task_queue_handle: TaskQueueHandle,
    /// Is the task queue actively running. Used to determine where [Self::access()] sends its
    /// tasks.
    ///
    /// In practice, this is a "is_running" bool that has no false positives. A false positive here
    /// will cause [Self::access()] to gives tasks to the task queue while the processor is stopped
    /// which means the task will never be executed, at least until the processor is started again.
    task_queue_active: Arc<AtomicBool>,
    port: u16,
}

// interesting methods
impl SyncProcessor {
    /// Create a [`SyncProcessor`] from a [`ProcessorBuilder`].
    ///
    /// Prefer using [ProcessorBuilder::build_sync()].
    pub(crate) fn from_builder(builder: ProcessorBuilder) -> Result<Self, UnknownError> {
        let (task_queue_plugin, task_queue_handle) = TaskQueuePlugin::new();
        let proc = builder.add_plugin(task_queue_plugin).build()?;
        let port = proc.ipc_port();
        let state = Arc::new((
            Mutex::new(InternalProcessorState::Paused(proc)),
            Condvar::new(),
        ));

        Ok(Self {
            state,
            task_queue_handle,
            task_queue_active: Arc::new(INACTIVE.into()),
            port,
        })
    }

    /// Start the processor in a separate thread.
    ///
    /// This is (mostly) non blocking. There is an internal state lock that should not be heavily
    /// contested but once that is taken, the processor is started and the method returns.
    ///
    /// In the event that the processor is already started, an [`Err`] will be returned. This error
    /// is not fatal but indicates that the given `bounds` were not used.
    pub fn start(&self, bounds: impl ExecutionConstraint) -> Result<(), ProcessorAlreadyStarted> {
        trace!("starting");
        let bounds = bounds.concrete();
        let res =
            replace_with_or_abort_and_return(self.state.0.lock().unwrap().deref_mut(), |state| {
                // can only start processor from paused
                let mut processor = match state {
                    InternalProcessorState::Paused(processor) => processor,
                    InternalProcessorState::Running => {
                        // otherwise, keep processor state the same and report error to user
                        return (Err(ProcessorAlreadyStarted), state);
                    }
                    InternalProcessorState::DoneRunning((processor, _)) => processor,
                };

                let sync_proc = self.clone();
                std::thread::spawn(move || {
                    let proc_run_result = processor.run(bounds);
                    debug!("processor done");
                    // set task_queue_active first so (hopefully) no other users attempt to add to the task
                    // queue after the processor stops
                    sync_proc
                        .task_queue_active
                        .store(INACTIVE, Ordering::Relaxed);
                    replace_with_or_abort(sync_proc.state.0.lock().unwrap().deref_mut(), |state| {
                        let InternalProcessorState::Running = state else {
                            panic!("internal processor state invalid, should be running")
                        };

                        InternalProcessorState::DoneRunning((processor, proc_run_result))
                    });
                    sync_proc.state.1.notify_all();
                });

                (Ok(()), InternalProcessorState::Running)
            });
        self.state.1.notify_all();

        // report the task queue active only after the proc is started
        self.task_queue_active.store(ACTIVE, Ordering::Relaxed);

        res
    }

    /// Stop the processor and wait for it to stop.
    ///
    /// Only one thread/user can pause the processor and get the [`EmulationReport`], others will
    /// continue waiting until it grabs the processor as it's exiting.
    ///
    /// Very blocking.
    pub fn pause(&self) -> Result<EmulationReport, UnknownError> {
        trace!("pausing");
        self.task_queue_handle.add_task(|proc| proc.stop());

        self.wait_for_stop()
    }

    /// Wait for processor to stop.
    ///
    /// Only one thread/user can pause the processor and get the [`EmulationReport`], others will
    /// continue waiting until it grabs the processor as it's exiting.
    ///
    /// Very blocking.
    pub fn wait_for_stop(&self) -> Result<EmulationReport, UnknownError> {
        let (state_lock, state_cond) = &*self.state;
        let mut changed = state_lock.lock().unwrap();
        let res = loop {
            match &mut *changed {
                // ope, someone grabbed the done running before us
                InternalProcessorState::Paused(_) => (),
                InternalProcessorState::Running => (),
                state @ InternalProcessorState::DoneRunning(_) => {
                    break replace_with_or_abort_and_return(state, |state| {
                        let InternalProcessorState::DoneRunning((proc, res)) = state else {
                            panic!();
                        };

                        (res, InternalProcessorState::Paused(proc))
                    })
                }
            }
            changed = state_cond.wait(changed).unwrap();
        };
        self.state.1.notify_all();
        res
    }

    /// Get the current processor state.
    pub fn state(&self) -> ProcessorState {
        (&*self.state.0.lock().unwrap()).into()
    }

    /// Run a function on the processor and get its return.
    ///
    /// This function is blocking but should have low latency.
    ///
    /// Handles the separate case where the processor is running.
    pub fn access<T: Send + 'static>(
        &self,
        task: impl FnOnce(&mut ProcessorCore) -> T + Send + 'static,
    ) -> T {
        if self.task_queue_active.load(Ordering::Relaxed) {
            self.task_queue_handle.add_task(task).join()
        } else {
            match &mut *self.state.0.lock().unwrap() {
                InternalProcessorState::Paused(processor) => task(&mut processor.core),
                InternalProcessorState::DoneRunning((processor, _)) => task(&mut processor.core),
                InternalProcessorState::Running => self.task_queue_handle.add_task(task).join(),
            }
        }
    }
}

// pass through methods
// not interesting
impl SyncProcessor {
    pub fn pc(&self) -> Result<u64, UnknownError> {
        self.access(|proc| proc.pc())
    }

    pub fn set_pc(&self, value: u64) -> Result<(), UnknownError> {
        self.access(move |core| core.set_pc(value))
    }

    pub fn read_register_raw(
        &mut self,
        reg: ArchRegister,
    ) -> Result<RegisterValue, ReadRegisterError> {
        self.access(move |core| core.read_register_raw(reg))
    }
    pub fn write_register_raw(
        &mut self,
        reg: ArchRegister,
        value: RegisterValue,
    ) -> Result<(), WriteRegisterError> {
        self.access(move |core| core.write_register_raw(reg, value))
    }

    pub fn add_hook(&self, hook: StyxHook) -> Result<HookToken, AddHookError> {
        self.access(|proc| proc.cpu.add_hook(hook))
    }

    /// Removes a [`StyxHook`] from the [`Processor`].
    pub fn delete_hook(&self, token: HookToken) -> Result<(), DeleteHookError> {
        self.access(move |proc| proc.cpu.delete_hook(token))
    }

    pub fn ipc_port(&self) -> u16 {
        self.port
    }

    /// Access data memory using the [memory helper api](crate::memory::helpers).
    pub fn data(&self) -> DataMemoryOp {
        DataMemoryOp(self)
    }

    /// Access code memory using the [memory helper api](crate::memory::helpers).
    pub fn code(&self) -> CodeMemoryOp {
        CodeMemoryOp(self)
    }
}

pub struct DataMemoryOp<'a>(&'a SyncProcessor);
impl Readable for DataMemoryOp<'_> {
    type Error = MmuOpError;

    fn read_raw(&mut self, addr: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
        let size = bytes.len();
        let data = self
            .0
            .access(move |core| core.mmu.data().read(addr).vec(size))?;
        bytes.copy_from_slice(&data);
        Ok(())
    }
}
impl Writable for DataMemoryOp<'_> {
    type Error = MmuOpError;

    fn write_raw(&mut self, addr: u64, bytes: &[u8]) -> Result<(), Self::Error> {
        let data = bytes.to_vec();
        self.0
            .access(move |core| core.mmu.data().write_raw(addr, &data))
    }
}

pub struct CodeMemoryOp<'a>(&'a SyncProcessor);
impl Readable for CodeMemoryOp<'_> {
    type Error = MmuOpError;

    fn read_raw(&mut self, addr: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
        let size = bytes.len();
        let data = self
            .0
            .access(move |core| core.mmu.code().read(addr).vec(size))?;
        bytes.copy_from_slice(&data);
        Ok(())
    }
}
impl Writable for CodeMemoryOp<'_> {
    type Error = MmuOpError;

    fn write_raw(&mut self, addr: u64, bytes: &[u8]) -> Result<(), Self::Error> {
        let data = bytes.to_vec();
        self.0
            .access(move |core| core.mmu.code().write_raw(addr, &data))
    }
}

#[cfg(test)]
mod tests {
    use std::{thread::sleep, time::Duration};

    use crate::{
        core::{
            builder::{BuildProcessorImplArgs, ProcessorImpl},
            ProcessorBundle,
        },
        cpu::{CpuBackend, ExecutionReport},
        executor::Forever,
        hooks::Hookable,
    };

    use super::*;

    #[derive(Debug)]
    struct TestCpu(u64);
    impl CpuBackend for TestCpu {
        fn read_register_raw(
            &mut self,
            _reg: styx_cpu_type::arch::backends::ArchRegister,
        ) -> Result<styx_cpu_type::arch::RegisterValue, crate::cpu::ReadRegisterError> {
            todo!()
        }

        fn write_register_raw(
            &mut self,
            _reg: styx_cpu_type::arch::backends::ArchRegister,
            _value: styx_cpu_type::arch::RegisterValue,
        ) -> Result<(), crate::cpu::WriteRegisterError> {
            todo!()
        }

        fn architecture(&self) -> &dyn styx_cpu_type::arch::ArchitectureDef {
            todo!()
        }

        fn endian(&self) -> styx_cpu_type::ArchEndian {
            todo!()
        }

        fn execute(
            &mut self,
            _mmu: &mut crate::memory::Mmu,
            _event_controller: &mut crate::event_controller::EventController,
            count: u64,
        ) -> Result<ExecutionReport, UnknownError> {
            self.0 += count;
            std::thread::sleep(Duration::from_millis(10));
            Ok(ExecutionReport::instructions_complete(count))
        }

        fn stop(&mut self) {
            todo!()
        }

        fn context_save(&mut self) -> Result<(), UnknownError> {
            todo!()
        }

        fn context_restore(&mut self) -> Result<(), UnknownError> {
            todo!()
        }

        fn pc(&mut self) -> Result<u64, UnknownError> {
            Ok(self.0)
        }

        fn set_pc(&mut self, _value: u64) -> Result<(), UnknownError> {
            todo!()
        }
    }
    impl Hookable for TestCpu {
        fn add_hook(
            &mut self,
            _hook: crate::hooks::StyxHook,
        ) -> Result<crate::hooks::HookToken, crate::hooks::AddHookError> {
            todo!()
        }

        fn delete_hook(
            &mut self,
            _token: crate::hooks::HookToken,
        ) -> Result<(), crate::hooks::DeleteHookError> {
            todo!()
        }
    }

    struct ProcImpl;
    impl ProcessorImpl for ProcImpl {
        fn build(
            &self,
            _args: &BuildProcessorImplArgs,
        ) -> Result<crate::core::ProcessorBundle, UnknownError> {
            let bundler = ProcessorBundle {
                cpu: Box::new(TestCpu(0)),
                ..Default::default()
            };
            Ok(bundler)
        }
    }

    #[test]
    fn test_sync() -> Result<(), UnknownError> {
        let builder = ProcessorBuilder::default().with_builder(ProcImpl);

        let sync = builder.build_sync()?;

        sync.start(Forever).unwrap();
        let first_pc = sync.pc()?;
        println!("pc: 0x{first_pc:X}");

        sleep(Duration::from_millis(1000));

        let second_pc = sync.pc()?;
        println!("pc: 0x{second_pc:X}");

        assert!(second_pc > first_pc);

        Ok(())
    }
}
