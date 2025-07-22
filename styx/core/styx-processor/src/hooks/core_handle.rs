// SPDX-License-Identifier: BSD-2-Clause
use crate::{
    cpu::{CpuBackend, ExecutionReport, ReadRegisterError, WriteRegisterError},
    event_controller::{ActivateIRQnError, EventController, ExceptionNumber},
    hooks::{AddHookError, DeleteHookError, HookToken, StyxHook},
    memory::{MemoryOperationError, Mmu},
};

use delegate::delegate;
use styx_cpu_type::{
    arch::{backends::ArchRegister, ArchitectureDef, RegisterValue},
    ArchEndian,
};
use styx_errors::UnknownError;

/// Ergonomic reference to the processor trinity for hook users.
pub struct CoreHandle<'a> {
    pub cpu: &'a mut dyn CpuBackend,
    pub mmu: &'a mut Mmu,
    pub event_controller: &'a mut EventController,
}

impl<'a> CoreHandle<'a> {
    /// Create a new [`CoreHandle`]. Useful for [`CpuBackend`] implementors construct and send to
    /// hooks.
    pub fn new(
        cpu: &'a mut dyn CpuBackend,
        mmu: &'a mut Mmu,
        event_controller: &'a mut EventController,
    ) -> Self {
        Self {
            cpu,
            mmu,
            event_controller,
        }
    }

    // delegate the common ops to the [`CoreHandle`]
    delegate! {
        to self.cpu {
            /// See [`CpuBackend::pc()`]
            pub fn pc(&mut self) -> Result<u64, UnknownError>;
            /// See [`CpuBackend::set_pc()`]
            pub fn set_pc(&mut self, value: u64) -> Result<(), UnknownError>;
            /// See [`CpuBackend::stop()`]
            pub fn stop(&mut self);
            /// See [`CpuBackend::architecture()`]
            pub fn architecture(&self) -> &dyn ArchitectureDef;
            /// See [`CpuBackend::endian()`]
            pub fn endian(&self) -> ArchEndian;
            /// See [`CpuBackend::read_register_raw()`]
            pub fn read_register_raw(&mut self, reg: ArchRegister) -> Result<RegisterValue, ReadRegisterError>;
            /// See [`CpuBackend::write_register_raw()`]
            pub fn write_register_raw(
                &mut self,
                reg: ArchRegister,
                value: RegisterValue,
            ) -> Result<(), WriteRegisterError>;
            /// See [`CpuBackend::execute()`]
            pub fn execute(
                &mut self,
                mmu: &mut Mmu,
                event_controller: &mut EventController,
                count: u64,
            ) -> Result<ExecutionReport, UnknownError>;
            /// See [`Hookable::add_hook()`](crate::hooks::Hookable::add_hook())
            pub fn add_hook(&mut self, hook: StyxHook) -> Result<HookToken, AddHookError>;
            /// See [`Hookable::delete_hook()`](crate::hooks::Hookable::delete_hook())
            pub fn delete_hook(&mut self, token: HookToken) -> Result<(), DeleteHookError>;
        }

        to self.mmu {
            /// See [`Mmu::write_data()`]
            pub fn write_data(&mut self, addr: u64, bytes: &[u8]) -> Result<(), MemoryOperationError>;
            /// See [`Mmu::read_data()`]
            pub fn read_data(&mut self, addr: u64, bytes: &mut [u8]) -> Result<(), MemoryOperationError>;
            /// See [`Mmu::write_code()`]
            pub fn write_code(&mut self, addr: u64, bytes: &[u8]) -> Result<(), MemoryOperationError>;
            /// See [`Mmu::read_code()`]
            pub fn read_code(&mut self, addr: u64, bytes: &mut [u8]) -> Result<(), MemoryOperationError>;
            /// See [`Mmu::sudo_write_data()`]
            pub fn sudo_write_data(&mut self, addr: u64, bytes: &[u8]) -> Result<(), MemoryOperationError>;
            /// See [`Mmu::sudo_read_data()`]
            pub fn sudo_read_data(&mut self, addr: u64, bytes: &mut [u8]) -> Result<(), MemoryOperationError>;
            /// See [`Mmu::sudo_write_code()`]
            pub fn sudo_write_code(&mut self, addr: u64, bytes: &[u8]) -> Result<(), MemoryOperationError>;
            /// See [`Mmu::sudo_read_code()`]
            pub fn sudo_read_code(&mut self, addr: u64, bytes: &mut [u8]) -> Result<(), MemoryOperationError>;
            /// See [`Mmu::code()`]
            pub fn code(&mut self) -> crate::memory::CodeMemoryOp;
            /// See [`Mmu::data()`]
            pub fn data(&mut self) -> crate::memory::DataMemoryOp;
            /// See [`Mmu::sudo_code()`]
            pub fn sudo_code(&mut self) -> crate::memory::SudoCodeMemoryOp;
            /// See [`Mmu::sudo_data()`]
            pub fn sudo_data(&mut self) -> crate::memory::SudoDataMemoryOp;
        }

        to self.event_controller {
            /// See [`EventController::latch()`]
            #[call(latch)]
            pub fn latch_event(&mut self, event: ExceptionNumber) -> Result<(), ActivateIRQnError>;
        }
    }
}
