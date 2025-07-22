// SPDX-License-Identifier: BSD-2-Clause
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
    memory::{DummyTlb, MemoryOperationError, Mmu},
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
            pub fn write_data(&mut self, addr: u64, bytes: &[u8]) -> Result<(), MemoryOperationError>;
            pub fn read_data(&mut self, addr: u64, bytes: &mut [u8]) -> Result<(), MemoryOperationError>;
            pub fn write_code(&mut self, addr: u64, bytes: &[u8]) -> Result<(), MemoryOperationError>;
            pub fn read_code(&mut self, addr: u64, bytes: &mut [u8]) -> Result<(), MemoryOperationError>;
            pub fn sudo_write_data(&mut self, addr: u64, bytes: &[u8]) -> Result<(), MemoryOperationError>;
            pub fn sudo_read_data(&mut self, addr: u64, bytes: &mut [u8]) -> Result<(), MemoryOperationError>;
            pub fn sudo_write_code(&mut self, addr: u64, bytes: &[u8]) -> Result<(), MemoryOperationError>;
            pub fn sudo_read_code(&mut self, addr: u64, bytes: &mut [u8]) -> Result<(), MemoryOperationError>;
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
