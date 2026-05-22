// SPDX-License-Identifier: BSD-2-Clause
//! The top-level `Processor` container.
//!
//! The [`Processor`] holds the core execution components [`ProcessorCore`] as well as the
//! [`executor`](crate::executor), async runtime, and plugins.
//!
//! The [`Processor`] acts as an owned value and completely blocking emulation api. The
//! [`SyncProcessor`] is provided for asynchronous applications and allows multiple threads to
//! interact with the processor while it is running.
//!
mod builder;
mod config;
pub use config::*;
use std::fmt::Debug;
use std::sync::Arc;

pub use builder::*;

mod sync;
use styx_errors::anyhow::anyhow;
pub use sync::*;

mod emulation_report;
pub use emulation_report::*;
use static_assertions::assert_impl_all;
use styx_errors::UnknownError;

mod vcpu_container;
pub use vcpu_container::{PerVcpu, PerVcpuSlice};

use crate::core::{ProcMeta, ProcessorCore, VcpuCore, VcpuId};
use crate::executor::{ExecutionConstraint, Executor};
use crate::hooks::{AddHookError, DeleteHookError, HookToken, StyxHook};
use crate::memory::MemoryBackend;
use crate::plugins::collection::PluginsContainer;
use crate::plugins::Plugin;
use crate::runtime::ProcessorRuntime;

// Processor impls Send
assert_impl_all!(Processor: Send);

/// The main computation unit in Styx.
///
/// Utilize the [`ProcessorBuilder`] to get an assembled [`Processor`].
///
/// The [`Processor`] holds the core execution components [`ProcessorCore`] as well as the
/// [`executor`](crate::executor), async runtime, and plugins.
///
/// # Send / Sync
/// Processor impls [`Send`] so you can send it to another thread and run multiple in parallel.
/// Processor is not [`Sync`].
///
/// A [`Sync`] processor wrapper is available: [`SyncProcessor`].
///
pub struct Processor {
    /// Per-vCPU execution state; each entry holds a CPU backend, MMU, and secondary
    /// event controller. Most single-CPU use-cases access [`PerVcpuSlice::first()`] /
    /// [`PerVcpuSlice::first_mut()`].
    pub vcpus: PerVcpu<VcpuCore>,
    /// Processor-level shared state: physical memory and the event distributor.
    pub core: ProcessorCore,
    /// Metadata about the specific [`Processor`]
    #[allow(unused)]
    meta: ProcMeta,
    /// The executor orchestrating the `TargetProgram` on this `Processor`
    executor: Executor,
    /// The async runtime associated with the `Processor`, houses the gRPC
    /// server for the IPC server
    pub runtime: ProcessorRuntime,
    /// The list of plugins attached to this `Processor`
    plugins: PluginsContainer<Box<dyn Plugin>>,
    /// The IPC I/O port used to interact with peripherals connected to the
    /// `TargetProgram`.
    ///
    /// This will not change for the life of the processor.
    port: u16,
}

impl Processor {
    /// Start [`Processor`] instruction execution.
    ///
    /// You can use `bounds` to set the instruction limit or time limit for execution.
    ///
    /// ```
    /// # use styx_processor::executor::Forever;
    /// # use styx_processor::processor::{ProcessorBuilder, Processor};
    /// # use styx_processor::core::builder::DummyProcessorBuilder;
    /// # use std::time::Duration;
    /// // process is owned and must be mutable.
    /// let mut proc: Processor = ProcessorBuilder::default()
    ///     .with_builder(DummyProcessorBuilder)
    ///     .build().unwrap();
    ///
    /// // run for 1000 instructions
    /// proc.run(1000).unwrap();
    ///
    /// // run for 100 milliseconds
    /// proc.run(Duration::from_millis(100)).unwrap();
    ///
    /// // run forever, or until a hook calls stop.
    /// // proc.run(Forever).unwrap();
    ///
    /// ```
    ///
    /// This is a wrapper over the [`Executor`] attached to the [`Processor`],
    /// but this is a convenient porcelain method that allows for any other
    /// top-level logic required before diving in to the execution hot-loop.
    pub fn run(
        &mut self,
        bounds: impl ExecutionConstraint,
    ) -> Result<EmulationReport, UnknownError> {
        if self.vcpus.len() != 1 {
            return Err(anyhow!("run is only compatible with single vcpu emulators. Use run_multi for multi vcpu emulation."));
        }
        self.run_multi(bounds)
            .map(|mut r| r.pop().expect("should have one emulation report"))
    }

    /// Start [`Processor`] execution.
    ///
    /// Compared to [`Processor::run()`], `run_multi()` supports multi-vcpu systems.
    /// These are separated to keep [`Processor::run()`]'s single execution report signature.
    pub fn run_multi(
        &mut self,
        bounds: impl ExecutionConstraint,
    ) -> Result<Vec<EmulationReport>, UnknownError> {
        // pass to executor
        self.executor
            .begin(&mut self.vcpus, &mut self.core, &mut self.plugins, &bounds)
    }

    /// Get resolved ipc port the [`Processor`] will use for I/O
    /// and Peripherals.
    pub fn ipc_port(&self) -> u16 {
        self.port
    }

    /// Save the [`Processor`]'s context to be restored in the future.
    pub fn context_save(&mut self) -> Result<(), UnknownError> {
        for vcpu in self.vcpus.iter_mut() {
            vcpu.context_save()?;
        }
        Ok(())
    }

    /// Restore the [`Processor`]'s context from a saved one.
    pub fn context_restore(&mut self) -> Result<(), UnknownError> {
        for vcpu in self.vcpus.iter_mut() {
            vcpu.context_restore()?;
        }
        Ok(())
    }

    /// Shortcut to `self.core.memory`
    pub fn memory(&self) -> &Arc<MemoryBackend> {
        &self.core.memory
    }
}

/// Error adding a [`StyxHook`] to every vCPU via [`Processor::add_hooks()`].
#[derive(thiserror::Error, Debug)]
pub enum AddHooksError {
    /// Adding the hook to the vCPU with the given [`VcpuId`] failed.
    #[error("failed to add hook to vcpu {vcpu_id}: {error}")]
    AddHook {
        vcpu_id: VcpuId,
        #[source]
        error: AddHookError,
    },
    /// A hook add failed and rolling back the previously added hooks also failed,
    /// leaving the processor in an inconsistent state. This indicates that
    /// something is seriously wrong.
    #[error(
        "failed to remove hooks while rolling back a failed add_hooks on vcpu {vcpu_id}: {error}"
    )]
    RevertingHooks {
        vcpu_id: VcpuId,
        #[source]
        error: DeleteHookError,
    },
}

impl Processor {
    /// Adds a [`StyxHook`] to all vCPUs on the processor.
    ///
    /// `make_hook` is invoked once per vCPU (with that vCPU's [`VcpuId`]) to produce a
    /// fresh hook for it. A factory is required rather than a single [`StyxHook`] because
    /// [`StyxHook`] is not `Clone`.
    ///
    /// On success, returns the [`HookToken`] for each vCPU, indexed by [`VcpuId`].
    ///
    /// Every vCPU is attempted. If any add fails then the hooks that were added are
    /// removed and [`AddHooksError::AddHook`] is returned for the first failure. Another
    /// error, [`AddHooksError::ErrorRemovingHooks`], is returned instead if removing them
    /// fails; this indicates that something is seriously wrong.
    pub fn add_hooks(
        &mut self,
        mut make_hook: impl FnMut(VcpuId) -> StyxHook,
    ) -> Result<PerVcpu<HookToken>, AddHooksError> {
        let results = self
            .vcpus
            .map_mut(|vcpu_id, vcpu| vcpu.cpu.add_hook(make_hook(vcpu_id)));

        if results.iter().any(Result::is_err) {
            // Leave the processor as we found it by removing every hook that was added.
            let mut add_failure = None;
            let mut remove_failure = None;
            for (idx, result) in results.into_iter().enumerate() {
                match result {
                    Ok(token) => {
                        if let Err(error) = self.vcpus[idx].cpu.delete_hook(token) {
                            remove_failure.get_or_insert(error);
                        }
                    }
                    Err(error) => {
                        add_failure.get_or_insert((idx as VcpuId, error));
                    }
                }
            }

            let (vcpu_id, error) = add_failure.expect("checked above that an add failed");
            match remove_failure {
                Some(error) => Err(AddHooksError::RevertingHooks { vcpu_id, error }),
                None => Err(AddHooksError::AddHook { vcpu_id, error }),
            }
        } else {
            Ok(results.map(|result| result.expect("checked above that every add succeeded")))
        }
    }

    /// Removes hooks previously added by [`Processor::add_hooks()`], deleting each token
    /// from the vCPU it was added to (tokens are indexed by [`VcpuId`]).
    pub fn remove_hooks(
        &mut self,
        tokens: &PerVcpuSlice<HookToken>,
    ) -> Result<(), DeleteHookError> {
        for (vcpu_id, &token) in tokens.iter().enumerate() {
            self.vcpus[vcpu_id].cpu.delete_hook(token)?;
        }
        Ok(())
    }
}

impl Debug for Processor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Processor")
            .field("port", &self.port)
            .finish()
    }
}
