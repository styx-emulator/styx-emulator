// SPDX-License-Identifier: BSD-2-Clause
//! Plugin for styx-components utilizing [`styx-trace`]
//!
//! This module provides a [`Plugin`] that registers hooks
//! to contribute to the [`styx-trace`] firehose.
//!
//! On initialization the plugin:
//! - sets up the global [`styx-trace`] provider
//! - registers the desired hooks for the event types
//!     - currently only set via inputs to constructor
//!     - TODO: via command line args
//!     - TODO: via env variables
//!
//! [styx-trace]: styx_core::tracebus
use std::env::{set_var, var};
use styx_core::hooks::StyxHook;
use styx_core::prelude::*;
use styx_core::tracebus::{
    strace, BlockTraceEvent, InsnExecEvent, MemReadEvent, MemWriteEvent, TraceProvider,
    STRACE_ENV_VAR,
};
use tracing::{trace, warn};

/// Plugin that turns on [`styx-trace`] firehose and registers
/// desired events
///
/// Most of the functionality occurs in the installed hooks or private
/// methods. Upon [`Plugin`] initialization, this plugin ensures
/// that the proper environment variables and configuration is setup so
/// that [`styx-trace`] can properly log events over IPC, and that the
/// desired runtime hooks are registered with the backing [`CpuBackend`].
///
/// The runtime overhead (number and diversity of event logged) can be
/// controlled via plugin configuration.
///
/// Currently only the following events can be conditionally enabled/disabled:
/// - PC trace
/// - Memory Writes
/// - Memory Reads
///
/// Interrupt Event logging is currently always enabled at the [`EventController`]
/// level.
///
/// [styx-trace]: styx_core::tracebus
/// [EventController]: styx_core::event_controller::EventController
/// [CpuEngine]: styx_core::cpu::CpuEngine
#[derive(Debug)]
pub struct StyxTracePlugin {
    pub pc_trace: bool,
    pub write_memory: bool,
    pub read_memory: bool,
    pub block_trace: bool,
}

impl std::default::Default for StyxTracePlugin {
    /// Enables all runtime trace events for [`styx-trace`](styx_core::tracebus)
    fn default() -> Self {
        Self {
            pc_trace: true,
            write_memory: true,
            read_memory: true,
            block_trace: true,
        }
    }
}

// builds and emits a basic block trace event
fn block_trace(_proc: CoreHandle, address: u64, size: u32) -> Result<(), UnknownError> {
    let mut evt = BlockTraceEvent::new();

    // set the correct pc
    evt.pc = address as u32;
    evt.size = size;

    // emit the event
    strace!(evt);

    Ok(())
}

/// builds and emits a pc trace event
fn pc_trace(proc: CoreHandle) -> Result<(), UnknownError> {
    let mut evt = InsnExecEvent::new();

    // set the correct pc
    evt.pc = proc.cpu.pc()? as u32;

    // read the instruction
    if let Ok(value) = proc.mmu.code().read(evt.pc).le().u32() {
        // if there is no error loading the insn bytes, then emit an event
        // (if there is an error then the target is about to error bc
        // its attempting to exeucte a bad address)
        //
        // Note that this does not check for decode error, this event
        // can be used to assert that decode errors are properly being
        // found
        evt.insn = value;

        // emit the event
        strace!(evt);
    }
    Ok(())
}

/// builds and emits a memory write event
fn mem_write_trace(
    proc: CoreHandle,
    address: u64,
    size: u32,
    data: &[u8],
) -> Result<(), UnknownError> {
    let mut evt = MemWriteEvent::new();

    evt.pc = proc.cpu.pc()? as u32;
    evt.address = address as u32;

    // need to break it up into multiple events if its an 8 byte operation
    // *courtesy of unicorn*
    if size == 8 {
        // prep second event, second event will take place 4 bytes after
        // the real address
        let mut evt2 = MemWriteEvent::new();
        evt2.pc = evt.pc;
        evt2.address = evt.address + 4;

        // both events have size 4
        evt.size_bytes = 4;
        evt2.size_bytes = 4;

        // the first 4 bytes go to evt, the second 4 bytes go to evt2
        evt.value = u32::from_le_bytes(data[..4].try_into().unwrap());
        evt2.value = u32::from_le_bytes(data[4..8].try_into().unwrap());

        // send the events
        strace!(evt);
        strace!(evt2);
    } else {
        evt.size_bytes = size as u16;
        evt.value = match size {
            0 => 0,
            1 => u8::from_le_bytes(data[..1].try_into().unwrap()) as u32,
            2 => u16::from_le_bytes(data[..2].try_into().unwrap()) as u32,
            4 => u32::from_le_bytes(data[..4].try_into().unwrap()),
            _ => unreachable!(),
        };

        // send the event
        strace!(evt);
    }

    Ok(())
}

/// builds and emits a memory read event
fn mem_read_trace(
    proc: CoreHandle,
    address: u64,
    size: u32,
    data: &mut [u8],
) -> Result<(), UnknownError> {
    let mut evt = MemReadEvent::new();

    evt.pc = proc.cpu.pc()? as u32;
    evt.address = address as u32;

    // need to break it up into multiple events if its an 8 byte operation
    // *courtesy of unicorn*
    if size == 8 {
        // prep second event, second event will take place 4 bytes after
        // the real address
        let mut evt2 = MemReadEvent::new();
        evt2.pc = evt.pc;
        evt2.address = evt.address + 4;

        // both events have size 4
        evt.size_bytes = 4;
        evt2.size_bytes = 4;

        // the first 4 bytes go to evt, the second 4 bytes go to evt2
        evt.value = u32::from_le_bytes(data[..4].try_into().unwrap());
        evt2.value = u32::from_le_bytes(data[4..8].try_into().unwrap());

        // send the events
        strace!(evt);
        strace!(evt2);
    } else {
        evt.size_bytes = size as u16;
        evt.value = match size {
            0 => 0,
            1 => u8::from_le_bytes(data[..1].try_into().unwrap()) as u32,
            2 => u16::from_le_bytes(data[..2].try_into().unwrap()) as u32,
            4 => u32::from_le_bytes(data[..4].try_into().unwrap()),
            _ => unreachable!(),
        };

        // send the event
        strace!(evt);
    }

    Ok(())
}

impl StyxTracePlugin {
    /// Constructs a new [`StyxTracePlugin`], enabling the desired
    /// runtime events if desired based on arguments.
    ///
    /// Note that not all events are runtime-enableable.
    /// TODO: fully define when-and-how all events are enabled/disabled
    pub fn new(pc: bool, mem_read: bool, mem_write: bool, block: bool) -> Self {
        Self {
            pc_trace: pc,
            read_memory: mem_read,
            write_memory: mem_write,
            block_trace: block,
        }
    }

    /// Installs hook in the runtime to emit [`styx-trace`](styx_core::tracebus) events
    fn register_hooks(&self, cpu: &mut dyn CpuBackend) -> Result<(), UnknownError> {
        let mut msg = String::from("Cpu Hooks set: ");

        if self.pc_trace {
            cpu.add_hook(StyxHook::code(.., pc_trace))?;
            msg.push_str("pc_trace, ");
        }

        if self.read_memory {
            cpu.add_hook(StyxHook::memory_read(.., mem_read_trace))?;
            msg.push_str("mem_read, ");
        }

        if self.write_memory {
            cpu.add_hook(StyxHook::memory_write(.., mem_write_trace))?;
            msg.push_str("mem_write, ");
        }

        if self.block_trace {
            cpu.block_hook(Box::new(block_trace))?;

            msg.push_str("block_trace");
        }

        trace!("{}", msg);
        Ok(())
    }

    /// For the moment [`styx-trace`](styx_core::tracebus) is dependent on an env
    /// variable, so we make sure it is set before any emulation
    /// starts, allowing us to create a sink for emulation events.
    fn prepare_env(&self) -> Result<(), UnknownError> {
        match var(STRACE_ENV_VAR) {
            // the env-var was set, so we need to make sure if its
            // not set to "srb" then we warn the user as that is a
            // manual override
            Ok(value) => {
                if value != "srb" {
                    warn!(
                        "`{}` manually set to `{}` while enabling `{}` plugin",
                        STRACE_ENV_VAR,
                        value,
                        self.name()
                    );
                }
            }
            // Variable is not set, so set it to the proper provider
            Err(_) => set_var(STRACE_ENV_VAR, "srb"),
        }

        Ok(())
    }
}
impl Plugin for StyxTracePlugin {
    fn name(&self) -> &str {
        "styx-trace"
    }
}
impl UninitPlugin for StyxTracePlugin {
    fn init(
        self: Box<Self>,
        proc: &mut BuildingProcessor,
    ) -> Result<Box<dyn Plugin>, UnknownError> {
        self.prepare_env()?;
        self.register_hooks(proc.core.cpu.as_mut())?;
        Ok(self)
    }
}

impl From<styx_core::grpc::args::TracePluginArgs> for StyxTracePlugin {
    fn from(value: styx_core::grpc::args::TracePluginArgs) -> Self {
        // Note:  TracePluginArgs.interrupt_event is implicitly true (ie traced)
        Self::new(
            value.insn_event,
            value.read_memory_event,
            value.write_memory_event,
            value.block_event,
        )
    }
}
