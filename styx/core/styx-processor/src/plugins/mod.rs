// SPDX-License-Identifier: BSD-2-Clause
//! Interface for adding reusable, custom behavior to processors.
//!
//! The plugin interface is a Work in Progress. TODOs are noted where applicable.
//!
//! The primary user facing traits are [`Plugin`] and [`UninitPlugin`]. [`Plugin`] represents a
//! completely initialized plugin and contains runtime behavior including [`Plugin::tick()`].
//! [`UninitPlugin`] defines the way of constructing a [`Plugin`].
//!
//! # Example
//!
//! Below is an example of a custom [`Plugin`] that optionally halts the processor when an unmapped
//! memory fault occurs. The plugin adds the hook in the [`UninitPlugin::init()`] function.
//!
//! ```
//! # use styx_processor::hooks::*;
//! # use styx_processor::plugins::*;
//! # use styx_processor::processor::BuildingProcessor;
//! # use log::error;
//! # use styx_errors::UnknownError;
//! # use styx_processor::executor::DefaultExecutor;
//! # use styx_processor::processor::{ProcessorBuilder, Processor};
//! # use styx_processor::core::builder::DummyProcessorBuilder;
//! /// Hook with optional halting behavior.
//! struct HaltableHook {
//!     halt: bool,
//! }
//! /// UnmappedFaultHook that halts if self.halt is true.
//! impl UnmappedFaultHook for HaltableHook {
//!     fn call(
//!         &mut self,
//!         mut proc: CoreHandle,
//!         address: u64,
//!         size: u32,
//!         fault_data: MemFaultData,
//!     ) -> Result<Resolution, UnknownError> {
//!         error!("unmapped fault hook hit @ 0x{address:X}");
//!         // halt if the user wants this plugin to halt
//!         if self.halt {
//!             proc.stop();
//!         }
//!         Ok(Resolution::NotFixed)
//!     }
//! }
//!
//! /// Our custom plugin that will optionally halt.
//! struct UnmappedMemoryFaultPlugin {
//!     halt: bool
//! }
//! impl UnmappedMemoryFaultPlugin {
//!     pub fn new(halt: bool) -> Self {
//!         Self { halt }
//!     }
//! }
//!
//! impl Plugin for UnmappedMemoryFaultPlugin {
//!     fn name(&self) -> &str {
//!         "UnmappedMemoryFault"
//!     }
//!
//!     // We could also implement tick() here if we wanted runtime behavior
//! }
//!
//! impl UninitPlugin for UnmappedMemoryFaultPlugin {
//!     fn init(
//!         self: Box<Self>,
//!         proc: &mut BuildingProcessor,
//!     ) -> Result<Box<dyn Plugin>, UnknownError> {
//!         // initialize plugin by adding our hook
//!         proc.core.cpu.add_hook(StyxHook::unmapped_fault(
//!             ..,
//!             HaltableHook { halt: self.halt },
//!         ))?;
//!
//!         Ok(self)
//!     }
//! }
//!
//! let proc: Processor = ProcessorBuilder::default()
//!     // add our custom plugin to the processor
//!     .add_plugin(UnmappedMemoryFaultPlugin::new(true))
//!     .with_builder(DummyProcessorBuilder)
//!     .build().unwrap();
//! ```

pub(crate) mod collection;
mod plugin;
pub mod task_queue;

pub use collection::{Plugins, PluginsContainer};
pub use plugin::*;
