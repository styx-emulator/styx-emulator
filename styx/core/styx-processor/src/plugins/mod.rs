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
