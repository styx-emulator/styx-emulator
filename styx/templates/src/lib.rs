// SPDX-License-Identifier: BSD-2-Clause
{% if component_type == "processor" %}//! # {{struct_name}} Processor Implementation
//!
//! This module provides the processor implementation for {{component_name}}.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use styx_core::prelude::*;
//! use {{crate_name}}::{{struct_name_builder}};
//!
//! let processor = ProcessorBuilder::default()
//!     .with_builder({{struct_name_builder}}::default())
//!     .build()
//!     .unwrap();
//! ```

use styx_core::prelude::*;
use styx_core::core::builder::{BuildProcessorImplArgs, ProcessorBundle, ProcessorImpl};
use styx_core::event_controller::DummyEventController;
use thiserror::Error;
use tracing::{debug, info};

#[derive(Debug, Error)]
pub enum {{struct_name}}Error {
    #[error("Loader `{0}` is incompatible with {{struct_name}} implementation")]
    IncompatibleLoader(&'static str),
    #[error("Path is not valid: {0}")]
    InvalidFirmwarePath(String),
    #[error("Expected `{0}` memory regions, loader returned: `{1}`")]
    InvalidMemoryRegionCount(usize, usize),
    #[error("`{0:?}` is not a valid Architecture Variant for the {{struct_name}} implementation")]
    InvalidVariant(ArchVariant),
}

impl From<{{struct_name}}Error> for StyxMachineError {
    fn from(value: {{struct_name}}Error) -> Self {
        Self::TargetSpecific(Box::new(value))
    }
}

#[derive(Debug, Default)]
pub struct {{struct_name_builder}} {
    // Add configuration fields here
}

impl {{struct_name_builder}} {
    pub fn new() -> Self {
        Self::default()
    }
}

impl ProcessorImpl for {{struct_name_builder}} {
    fn build(&self, args: &BuildProcessorImplArgs) -> Result<ProcessorBundle, UnknownError> {
        // TODO: Implement CPU backend selection
        // Example:
        // let cpu: Box<dyn CpuBackend> = match args.backend {
        //     Backend::Pcode => Box::new(PcodeBackend::new_engine_config(
        //         ArmVariants::ArmCortexM4,
        //         ArchEndian::LittleEndian,
        //         &args.into(),
        //     )),
        //     _ => return Err(BackendNotSupported(args.backend).into()),
        // };

        let cpu = Box::new(DummyBackend);
        let mut mmu = Mmu::default_region_store();

        // TODO: Implement event controller
        let event_controller = Box::new(DummyEventController::default());

        // TODO: Add peripherals
        let peripherals: Vec<Box<dyn Peripheral>> = Vec::new();

        let mut loader_hints = LoaderHints::new();
        // TODO: Set loader hints
        // loader_hints.insert("arch".to_string().into_boxed_str(), Box::new(Arch::Arm));

        // TODO: Setup address space
        // setup_address_space(&mut mmu)?;

        Ok(ProcessorBundle {
            cpu,
            mmu,
            event_controller,
            peripherals,
            loader_hints,
        })
    }

    fn init(&self, proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        // TODO: Initialize processor state, registers, hooks, etc.
        debug!("Initializing {{struct_name}} processor");
        Ok(())
    }
}

// TODO: Implement helper functions
// fn setup_address_space(mmu: &mut Mmu) -> Result<(), UnknownError> {
//     // Add memory regions
//     Ok(())
// }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_creation() {
        let builder = {{struct_name_builder}}::new();
        assert!(builder.build(&BuildProcessorImplArgs {
            runtime: tokio::runtime::Handle::current(),
            backend: Backend::Dummy,
            exception: ExceptionBehavior::Continue,
        }).is_ok());
    }
}
{% elsif component_type == "event-controller" %}//! # {{struct_name}} Event Controller
//!
//! This module provides an event controller implementation for {{component_name}}.
//!
//! Event controllers manage interrupt handling and peripheral coordination.

use styx_core::prelude::*;
use styx_core::event_controller::{EventControllerImpl, ExceptionNumber, ActivateIRQnError, InterruptExecuted, Peripherals};
use tracing::{debug, trace};

/// {{struct_name}} event controller implementation
#[derive(Debug, Default)]
pub struct {{struct_name}} {
    // TODO: Add state for interrupt management
    // Example fields:
    // - pending_interrupts: Vec<ExceptionNumber>
    // - active_interrupt: Option<ExceptionNumber>
    // - interrupt_priorities: HashMap<ExceptionNumber, u8>
}

impl {{struct_name}} {
    pub fn new() -> Self {
        Self::default()
    }
}

impl EventControllerImpl for {{struct_name}} {
    fn next(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
        peripherals: &mut Peripherals,
    ) -> Result<InterruptExecuted, UnknownError> {
        // TODO: Implement interrupt retrieval and execution
        // 1. Check for pending interrupts
        // 2. Select highest priority interrupt
        // 3. Execute the interrupt on the CPU
        // 4. Return InterruptExecuted::Executed or InterruptExecuted::NotExecuted

        trace!("{{struct_name}}::next - checking for interrupts");
        Ok(InterruptExecuted::NotExecuted)
    }

    fn latch(&mut self, event: ExceptionNumber) -> Result<(), ActivateIRQnError> {
        // TODO: Queue an interrupt for later execution
        debug!("{{struct_name}}::latch - queuing interrupt {}", event);
        Ok(())
    }

    fn execute(
        &mut self,
        irq: ExceptionNumber,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
    ) -> Result<InterruptExecuted, ActivateIRQnError> {
        // TODO: Directly execute an interrupt
        debug!("{{struct_name}}::execute - executing interrupt {}", irq);
        Ok(InterruptExecuted::Executed)
    }

    fn finish_interrupt(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
    ) -> Option<ExceptionNumber> {
        // TODO: Handle interrupt completion
        // Return the exception number that just finished
        None
    }

    fn init(&mut self, cpu: &mut dyn CpuBackend, mmu: &mut Mmu) -> Result<(), UnknownError> {
        // TODO: Initialize event controller state
        debug!("{{struct_name}}::init - initializing event controller");
        Ok(())
    }

    fn reset(&mut self, cpu: &mut dyn CpuBackend, mmu: &mut Mmu) -> Result<(), UnknownError> {
        // TODO: Reset event controller to initial state
        debug!("{{struct_name}}::reset - resetting event controller");
        Ok(())
    }

    fn tick(&mut self, cpu: &mut dyn CpuBackend, mmu: &mut Mmu) -> Result<(), UnknownError> {
        // TODO: Update event controller state on each tick
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_controller_creation() {
        let controller = {{struct_name}}::new();
        // Add more tests here
    }
}
{% elsif component_type == "peripheral" %}//! # {{struct_name}} Peripheral
//!
//! This module provides a peripheral implementation for {{component_name}}.

use styx_core::prelude::*;
use styx_core::event_controller::Peripheral;
use thiserror::Error;
use tracing::{debug, trace};

#[derive(Debug, Error)]
pub enum {{struct_name}}Error {
    #[error("Invalid register address: {0:#x}")]
    InvalidRegister(u64),
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
}

/// {{struct_name}} peripheral implementation
pub struct {{struct_name}} {
    // TODO: Add peripheral-specific state
    // Example fields:
    // - base_address: u64
    // - irq_number: ExceptionNumber
    // - registers: HashMap<u64, u32>
}

impl {{struct_name}} {
    pub fn new() -> Self {
        Self {
            // TODO: Initialize fields
        }
    }
}

impl Default for {{struct_name}} {
    fn default() -> Self {
        Self::new()
    }
}

impl Peripheral for {{struct_name}} {
    fn init(&mut self, proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        // TODO: Register memory hooks for peripheral registers
        // Example:
        // proc.core.cpu.add_hook(StyxHook::memory_read(
        //     self.base_address,
        //     |handle, addr, size| {
        //         // Handle register read
        //         Ok(())
        //     }
        // ))?;

        debug!("{{struct_name}}::init - initializing peripheral");
        Ok(())
    }

    fn reset(&mut self, cpu: &mut dyn CpuBackend, mmu: &mut Mmu) -> Result<(), UnknownError> {
        // TODO: Reset peripheral to initial state
        debug!("{{struct_name}}::reset - resetting peripheral");
        Ok(())
    }

    fn name(&self) -> &str {
        "{{struct_name}}"
    }

    fn irqs(&self) -> Vec<ExceptionNumber> {
        // TODO: Return the exception numbers this peripheral uses
        vec![]
    }

    fn post_event_hook(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
        event_controller: &mut dyn EventControllerImpl,
        irqn: ExceptionNumber,
    ) -> Result<(), UnknownError> {
        // TODO: Handle post-interrupt cleanup or re-latching
        trace!("{{struct_name}}::post_event_hook - IRQ {} completed", irqn);
        Ok(())
    }

    fn on_processor_start(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
        event_controller: &mut dyn EventControllerImpl,
    ) -> Result<(), UnknownError> {
        // TODO: Handle processor start event
        debug!("{{struct_name}}::on_processor_start");
        Ok(())
    }

    fn on_processor_stop(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
        event_controller: &mut dyn EventControllerImpl,
    ) -> Result<(), UnknownError> {
        // TODO: Handle processor stop event
        debug!("{{struct_name}}::on_processor_stop");
        Ok(())
    }

    fn tick(
        &mut self,
        cpu: &mut dyn CpuBackend,
        mmu: &mut Mmu,
        event_controller: &mut dyn EventControllerImpl,
        delta: &Delta,
    ) -> Result<(), UnknownError> {
        // TODO: Update peripheral state on each tick
        // Use delta.instructions or delta.time_ns for timing
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peripheral_creation() {
        let peripheral = {{struct_name}}::new();
        assert_eq!(peripheral.name(), "{{struct_name}}");
    }
}
{% elsif component_type == "plugin" %}//! # {{struct_name}} Plugin
//!
//! This module provides a plugin implementation for {{component_name}}.
//!
//! ## Usage
//!
//! ```rust,no_run
//! use styx_core::prelude::*;
//! use {{crate_name}}::{{struct_name}};
//!
//! let processor = ProcessorBuilder::default()
//!     .add_plugin({{struct_name}}::new())
//!     .with_builder(DummyProcessorBuilder)
//!     .build()
//!     .unwrap();
//! ```

use styx_core::prelude::*;
use styx_core::plugins::{Plugin, UninitPlugin};
use thiserror::Error;
use tracing::{debug, info, trace};

#[derive(Debug, Error)]
pub enum {{struct_name}}Error {
    #[error("Plugin error: {0}")]
    Generic(String),
}

/// {{struct_name}} plugin implementation
pub struct {{struct_name}} {
    // TODO: Add plugin-specific state and configuration
    enabled: bool,
}

impl {{struct_name}} {
    pub fn new() -> Self {
        Self {
            enabled: true,
        }
    }

    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

impl Default for {{struct_name}} {
    fn default() -> Self {
        Self::new()
    }
}

impl Plugin for {{struct_name}} {
    fn name(&self) -> &str {
        "{{struct_name}}"
    }

    fn on_processor_start(&mut self, core: &mut ProcessorCore) -> Result<(), UnknownError> {
        // TODO: Handle processor start event
        debug!("{{struct_name}}::on_processor_start");
        Ok(())
    }

    fn on_processor_stop(&mut self, core: &mut ProcessorCore) -> Result<(), UnknownError> {
        // TODO: Handle processor stop event
        debug!("{{struct_name}}::on_processor_stop");
        Ok(())
    }

    fn tick(&mut self, core: &mut ProcessorCore) -> Result<(), UnknownError> {
        // TODO: Update plugin state on each tick
        if !self.enabled {
            return Ok(());
        }

        trace!("{{struct_name}}::tick");
        Ok(())
    }

    fn plugins_initialized_hook(
        &mut self,
        proc: &mut BuildingProcessor,
    ) -> Result<(), UnknownError> {
        // TODO: Perform initialization that requires other plugins to be loaded
        info!("{{struct_name}}::plugins_initialized_hook");
        Ok(())
    }
}

impl UninitPlugin for {{struct_name}} {
    fn init(
        self: Box<Self>,
        proc: &mut BuildingProcessor,
    ) -> Result<Box<dyn Plugin>, UnknownError> {
        // TODO: Initialize plugin, add hooks, etc.
        // Example:
        // proc.core.cpu.add_hook(StyxHook::code(
        //     ..,
        //     |handle, addr, size| {
        //         // Hook implementation
        //         Ok(())
        //     }
        // ))?;

        info!("{{struct_name}}::init - initializing plugin");
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plugin_creation() {
        let plugin = {{struct_name}}::new();
        assert_eq!(plugin.name(), "{{struct_name}}");
        assert!(plugin.enabled);
    }

    #[test]
    fn test_plugin_disabled() {
        let plugin = {{struct_name}}::new().with_enabled(false);
        assert!(!plugin.enabled);
    }
}
{% endif %}
