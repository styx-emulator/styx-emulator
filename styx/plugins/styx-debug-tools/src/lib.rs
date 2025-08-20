// SPDX-License-Identifier: BSD-2-Clause
//! Debug Tools Plugins Module
//!
//! Provides some hooks that are useful when things are not working as expected
//! and you need help figuring out where in the emulation stack things are borked.
//!
use styx_core::{
    hooks::{MemFaultData, ProtectionFaultHook, Resolution, UnmappedFaultHook},
    memory::MemoryPermissions,
    prelude::*,
};
use styx_sync::sync::Arc;
use tracing::error;

struct HaltableHook {
    halt: bool,
}

impl HaltableHook {
    fn do_halt(&self, cpu: &mut dyn CpuBackend) {
        if self.halt {
            cpu.stop();
        }
    }
}

impl UnmappedFaultHook for HaltableHook {
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        size: u32,
        fault_data: MemFaultData,
    ) -> Result<Resolution, UnknownError> {
        error!(
            "[Unmapped Mem Fault] PC: `{:#x}` Address: `{:#x}`, size: `{:#x}`, {:?}",
            proc.cpu.pc()?,
            address,
            size,
            fault_data
        );

        // halt if the user wants this plugin to halt
        self.do_halt(proc.cpu);
        Ok(Resolution::NotFixed)
    }
}

impl ProtectionFaultHook for HaltableHook {
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        size: u32,
        perms: MemoryPermissions,
        fault_data: MemFaultData,
    ) -> Result<Resolution, UnknownError> {
        error!(
            "[Unmapped Mem Fault] PC: `{:#x}` Address: `{:#x}`, size: `{:#x}`, Perms: `{}`, {:?}",
            proc.cpu.pc()?,
            address,
            size,
            perms,
            fault_data
        );

        // halt if the user wants this plugin to halt
        self.do_halt(proc.cpu);
        Ok(Resolution::NotFixed)
    }
}

/// Plugin that installs a hook into the emulation runtime that will
/// trigger and log at the `error` level every time an unmapped memory
/// fault occurs.
///
/// The plugin behavior is controllable, depending on the `halt` argument,
/// the plugin will halt the target program execution when the hook is fired
#[derive(Debug, Default, serde::Deserialize)]
pub struct UnmappedMemoryFaultPlugin {
    halt: bool,
}

styx_uconf::register_component_config!(register plugin: id = unmapped_memory_fault, component = UnmappedMemoryFaultPlugin);

impl UnmappedMemoryFaultPlugin {
    pub fn new(halt: bool) -> Self {
        Self { halt }
    }

    pub fn new_arc(halt: bool) -> Arc<Self> {
        Arc::new(Self { halt })
    }
}

impl Plugin for UnmappedMemoryFaultPlugin {
    fn name(&self) -> &str {
        "UnmappedMemoryFault"
    }
}
impl UninitPlugin for UnmappedMemoryFaultPlugin {
    fn init(
        self: Box<Self>,
        proc: &mut BuildingProcessor,
    ) -> Result<Box<dyn Plugin>, UnknownError> {
        // add our hook and call it a day
        proc.core.cpu.add_hook(StyxHook::UnmappedFault(
            (..).into(),
            Box::new(HaltableHook { halt: self.halt }),
        ))?;

        Ok(self)
    }
}

/// Plugin that installs a hook into the emulation runtime that will
/// trigger and log at the `error` level every time an memory protection
/// fault occurs.
///
/// The plugin behavior is controllable, depending on the `halt` argument,
/// the plugin will halt the target program execution when the hook is fired
#[derive(Debug, Default, serde::Deserialize)]
pub struct ProtectedMemoryFaultPlugin {
    halt: bool,
}

styx_uconf::register_component_config!(register plugin: id = protected_memory_fault, component = ProtectedMemoryFaultPlugin);

impl ProtectedMemoryFaultPlugin {
    pub fn new(halt: bool) -> Self {
        Self { halt }
    }

    pub fn new_arc(halt: bool) -> Arc<Self> {
        Arc::new(Self { halt })
    }
}

impl Plugin for ProtectedMemoryFaultPlugin {
    fn name(&self) -> &str {
        "ProtectedMemoryFault"
    }
}

impl UninitPlugin for ProtectedMemoryFaultPlugin {
    fn init(
        self: Box<Self>,
        proc: &mut BuildingProcessor,
    ) -> Result<Box<dyn Plugin>, UnknownError> {
        // add our hook and call it a day
        proc.core.cpu.add_hook(StyxHook::ProtectionFault(
            (..).into(),
            Box::new(HaltableHook { halt: self.halt }),
        ))?;

        Ok(self)
    }
}
