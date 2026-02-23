// SPDX-License-Identifier: BSD-2-Clause
//! # Styx Core Prelude
//!
//! This is the top-level crate for all things in the
//! core styx libraries.
//!
//! You can use the prelude to quickly get started:
//!
//! ```rust
//! use styx_core::prelude::*;
//! ```
pub use styx_cpu::arch;
pub use styx_processor::{
    core, event_controller, executor, hooks, memory, plugins, processor, runtime,
};
pub use {
    macrolib, styx_arch_utils as arch_utils, styx_errors as errors, styx_grpc as grpc,
    styx_loader as loader, styx_macros as macros, styx_peripheral_clients as peripheral_clients,
    styx_sync as sync, styx_tracebus as tracebus, styx_util as util,
};

pub mod cpu {
    pub use styx_cpu::*;
    pub use styx_processor::cpu::*;
}

pub mod prelude {
    pub use styx_processor::cpu::{
        CpuBackend, CpuBackendExt, DummyBackend, ReadRegisterError, WriteRegisterError,
    };
    pub use styx_processor::hooks::{AddressRange, CoreHandle, Hookable, MemFaultData, StyxHook};
    pub use styx_processor::memory::helpers::{ReadExt, WriteExt};
    pub use styx_processor::memory::memory_region::MemoryRegion;

    pub use super::core::{ProcessorBundle, ProcessorCore};
    pub use super::cpu::arch::backends::*;
    pub use super::cpu::arch::{u1, u20, u4, u40, u80, TryNewIntError};
    pub use super::cpu::{Arch, ArchEndian, Backend, BackendNotSupported, TargetExitReason};
    pub use super::errors::anyhow::{anyhow, Context};
    pub use super::errors::styx_cpu::*;
    pub use super::errors::styx_grpc::ApplicationError;
    pub use super::errors::styx_loader::StyxLoaderError;
    pub use super::errors::styx_memory::*;
    pub use super::errors::styx_processor::ProcessorBuilderError;
    pub use super::errors::{anyhow, StyxMachineError, UnknownError};
    pub use super::event_controller::{
        EventController, EventControllerImpl, ExceptionNumber, Peripheral,
    };
    pub use super::executor::{
        DefaultExecutor, Delta, ExecutionConstraintConcrete, ExecutorImpl, Forever,
    };
    pub use super::grpc::{self, ToArgVec, Validator};
    pub use super::loader::*;
    pub use super::macros::*;
    pub use super::memory::{
        MemoryBackend, MemoryOperation, MemoryOperationError, MemoryPermissions, MemoryRegionSize,
        MemoryType, Mmu, MmuOpError,
    };
    pub use super::plugins::{Plugin, UninitPlugin};
    pub use super::processor::*;
    pub use super::runtime::ProcessorRuntime;
    pub use super::sync::*;
    pub use super::tracebus::*;
    pub use super::util::*;
}
