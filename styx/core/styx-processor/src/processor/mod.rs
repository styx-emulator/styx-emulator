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

pub use builder::*;

mod sync;
pub use sync::*;

mod emulation_report;
pub use emulation_report::*;

use static_assertions::assert_impl_all;
use styx_errors::UnknownError;

use crate::{
    core::{ProcMeta, ProcessorCore},
    executor::{ExecutionConstraint, Executor},
    hooks::{AddHookError, DeleteHookError, HookToken, Hookable, StyxHook},
    memory::physical::address_space::MemoryImpl,
    plugins::{collection::PluginsContainer, Plugin},
    runtime::ProcessorRuntime,
};

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
    /// Represents the execution core of a [`Processor`], all target execution
    /// occurs in the context of a [`ProcessorCore`]
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
        // pass to executor
        self.executor
            .begin(&mut self.core, &mut self.plugins, bounds)
    }

    /// Get resolved ipc port the [`Processor`] will use for I/O
    /// and Peripherals.
    pub fn ipc_port(&self) -> u16 {
        self.port
    }

    /// Save the [`Processor`]'s context to be restored in the future.
    pub fn context_save(&mut self) -> Result<(), UnknownError> {
        self.core.cpu.context_save()?;
        self.core.mmu.memory.context_save()?;

        Ok(())
    }

    /// Restore the [`Processor`]'s context from a saved one.
    pub fn context_restore(&mut self) -> Result<(), UnknownError> {
        self.core.cpu.context_restore()?;
        self.core.mmu.memory.context_restore()?;

        Ok(())
    }
}

impl Hookable for Processor {
    /// Adds a [`StyxHook`] to be executed when applicable.
    fn add_hook(&mut self, hook: StyxHook) -> Result<HookToken, AddHookError> {
        self.core.cpu.add_hook(hook)
    }

    /// Removes a [`StyxHook`] from the [`Processor`].
    fn delete_hook(&mut self, token: HookToken) -> Result<(), DeleteHookError> {
        self.core.cpu.delete_hook(token)
    }
}

impl Debug for Processor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Processor")
            .field("port", &self.port)
            .finish()
    }
}
