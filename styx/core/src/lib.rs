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
pub use macrolib;
pub use styx_arch_utils as arch_utils;
pub use styx_cpu::arch;
pub use styx_errors as errors;
pub use styx_grpc as grpc;
pub use styx_loader as loader;
pub use styx_macros as macros;
pub use styx_peripheral_clients as peripheral_clients;
pub use styx_processor::core;
pub use styx_processor::event_controller;
pub use styx_processor::executor;
pub use styx_processor::hooks;
pub use styx_processor::memory;
pub use styx_processor::plugins;
pub use styx_processor::processor;
pub use styx_processor::runtime;
pub use styx_sync as sync;
pub use styx_tracebus as tracebus;
pub use styx_util as util;

pub mod cpu {
    pub use styx_cpu::*;
    pub use styx_processor::cpu::*;
}

pub mod prelude {
    pub use super::core::{ProcessorBundle, ProcessorCore};
    pub use super::cpu::{
        arch::backends::*,
        arch::{u1, u20, u4, u40, u80, TryNewIntError},
        Arch, ArchEndian, Backend, TargetExitReason,
    };
    pub use super::errors::anyhow::anyhow;
    pub use super::errors::anyhow::Context;
    pub use super::errors::{
        anyhow, styx_cpu::*, styx_grpc::ApplicationError, styx_loader::StyxLoaderError,
        styx_memory::*, styx_processor::ProcessorBuilderError, StyxMachineError, UnknownError,
    };
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
        MemoryOperation, MemoryOperationError, MemoryPermissions, MemoryRegionSize, MemoryType,
        Mmu, MmuOpError,
    };
    pub use super::plugins::{Plugin, UninitPlugin};
    pub use super::processor::*;
    pub use super::runtime::ProcessorRuntime;
    pub use super::sync::*;
    pub use super::tracebus::*;
    pub use super::util::*;
    pub use styx_processor::cpu::{
        CpuBackend, CpuBackendExt, DummyBackend, ReadRegisterError, WriteRegisterError,
    };
    pub use styx_processor::hooks::{AddressRange, CoreHandle, Hookable, MemFaultData, StyxHook};
    pub use styx_processor::memory::helpers::{ReadExt, WriteExt};
    pub use styx_processor::memory::memory_region::MemoryRegion;
}
