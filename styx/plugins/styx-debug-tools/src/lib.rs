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
#[derive(Debug, Default)]
pub struct UnmappedMemoryFaultPlugin {
    halt: bool,
}

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
#[derive(Debug, Default)]
pub struct ProtectedMemoryFaultPlugin {
    halt: bool,
}

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
        "ProtectecMemoryFault"
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
