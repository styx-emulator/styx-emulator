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
        MemoryOperationError, MemoryPermissions, MemoryRegionSize, Mmu, MmuOpError,
    };
    pub use super::plugins::{Plugin, UninitPlugin};
    pub use super::processor::*;
    pub use super::runtime::ProcessorRuntime;
    pub use super::sync::*;
    pub use super::tracebus::*;
    pub use super::util::*;
    pub use styx_processor::cpu::{
        CpuBackend, CpuBackendExt, ReadRegisterError, WriteRegisterError,
    };
    pub use styx_processor::hooks::{AddressRange, CoreHandle, Hookable, MemFaultData, StyxHook};
    pub use styx_processor::memory::helpers::{ReadExt, WriteExt};
    pub use styx_processor::memory::memory_region::MemoryRegion;
}
