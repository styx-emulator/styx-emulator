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
//! Container for the "core trinity" components and custom builder for the core trinity.
//!
//! The core trinity refers to the cpu, mmu, and event controller in aggregate. They are owned by
//! the [ProcessorCore]. These are separated from the [Processor](super::processor::Processor)
//! because they are used closely during execution. Most calls to the cpu will pass mutable
//! references to the mmu, and event controller. The same is true to most calls to the mmu and event
//! controller taking the other two as mutable references.
//!
use delegate::delegate;
use styx_cpu_type::{
    arch::{backends::ArchRegister, ArchitectureDef, RegisterValue},
    ArchEndian,
};
use styx_errors::UnknownError;

use crate::{
    cpu::{CpuBackend, DummyBackend, ExecutionReport, ReadRegisterError, WriteRegisterError},
    event_controller::{ActivateIRQnError, DummyEventController, EventController, ExceptionNumber},
    hooks::CoreHandle,
    memory::{DummyTlb, Mmu, MmuOpError},
};

pub mod builder;
pub use builder::ProcessorBundle;

mod exceptions;
pub use exceptions::*;

/// Placeholder struct for holding processor metadata.
pub struct ProcMeta {}

/// Core components of an executable processor.
pub struct ProcessorCore {
    pub cpu: Box<dyn CpuBackend>,
    pub mmu: Mmu,
    pub event_controller: EventController,
}

impl ProcessorCore {
    // delegate the common ops to the [`ProcessorCore`]
    delegate! {
        to self.cpu {
            pub fn pc(&mut self) -> Result<u64, UnknownError>;
            pub fn set_pc(&mut self, value: u64) -> Result<(), UnknownError>;
            pub fn stop(&mut self);
            pub fn architecture(&self) -> &dyn ArchitectureDef;
            pub fn endian(&self) -> ArchEndian;
            pub fn read_register_raw(&mut self, reg: ArchRegister) -> Result<RegisterValue, ReadRegisterError>;
            pub fn write_register_raw(
                &mut self,
                reg: ArchRegister,
                value: RegisterValue,
            ) -> Result<(), WriteRegisterError>;
            pub fn execute(
                &mut self,
                mmu: &mut Mmu,
                event_controller: &mut EventController,
                count: u64,
            ) -> Result<ExecutionReport, UnknownError>;
        }

        to self.mmu {
            pub fn write_data(&mut self, addr: u64, bytes: &[u8]) -> Result<(), MmuOpError>;
            pub fn read_data(&mut self, addr: u64, bytes: &mut [u8]) -> Result<(), MmuOpError>;
            pub fn write_code(&mut self, addr: u64, bytes: &[u8]) -> Result<(), MmuOpError>;
            pub fn read_code(&mut self, addr: u64, bytes: &mut [u8]) -> Result<(), MmuOpError>;
            pub fn sudo_write_data(&mut self, addr: u64, bytes: &[u8]) -> Result<(), MmuOpError>;
            pub fn sudo_read_data(&mut self, addr: u64, bytes: &mut [u8]) -> Result<(), MmuOpError>;
            pub fn sudo_write_code(&mut self, addr: u64, bytes: &[u8]) -> Result<(), MmuOpError>;
            pub fn sudo_read_code(&mut self, addr: u64, bytes: &mut [u8]) -> Result<(), MmuOpError>;
        }

        to self.event_controller {
            #[call(latch)]
            pub fn latch_event(&mut self, event: ExceptionNumber) -> Result<(), ActivateIRQnError>;
        }
    }

    /// Create a dummy [`ProcessorCore`]
    pub fn dummy() -> Self {
        Self {
            cpu: Box::new(DummyBackend),
            mmu: Mmu::from_impl(Box::new(DummyTlb)),
            event_controller: EventController::new(Box::new(DummyEventController::default())),
        }
    }

    /// Repackage the [`ProcessorCore`] as a [`CoreHandle`] struct for use within hooks.
    pub fn core_handle(&mut self) -> CoreHandle {
        CoreHandle {
            cpu: self.cpu.as_mut(),
            mmu: &mut self.mmu,
            event_controller: &mut self.event_controller,
        }
    }
}
