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
use std::fmt::Debug;

use static_assertions::assert_obj_safe;
use styx_cpu_type::{
    arch::{backends::ArchRegister, ArchitectureDef, RegisterValue},
    ArchEndian, TargetExitReason,
};
use styx_errors::UnknownError;
use thiserror::Error;

use crate::{event_controller::EventController, hooks::Hookable, memory::Mmu};

#[derive(Debug, Error)]
pub enum ReadRegisterError {
    #[error(transparent)]
    Other(#[from] UnknownError),
    #[error("register {0} not available on this cpu")]
    RegisterNotAvailable(ArchRegister),
}

#[derive(Debug, Error)]
pub enum WriteRegisterError {
    #[error(transparent)]
    Other(#[from] UnknownError),
    #[error("incorrect requested size {0} for this register {1}")]
    RegisterBadSize(u32, ArchRegister),
    #[error("register {0} not available on this cpu")]
    RegisterNotAvailable(ArchRegister),
}

/// Results of cpu execution. Primarily used as a return from [`CpuBackend::execute()`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionReport {
    /// Exit reason reported by the cpu backend.
    pub exit_reason: TargetExitReason,
    /// The number of executed instructions.
    ///
    /// Indicates the number of instructions executed, if available. A value of None means that the
    /// backend did not report the amount of instructions it executed.
    pub instructions_executed: Option<u64>,
}

impl ExecutionReport {
    pub fn instructions_complete(count: u64) -> Self {
        Self {
            exit_reason: TargetExitReason::InstructionCountComplete,
            instructions_executed: Some(count),
        }
    }

    pub fn new(exit_reason: TargetExitReason, instructions_executed: u64) -> Self {
        Self {
            exit_reason,
            instructions_executed: Some(instructions_executed),
        }
    }

    pub fn unknown_instruction_count(exit_reason: TargetExitReason) -> Self {
        Self {
            exit_reason,
            instructions_executed: None,
        }
    }

    pub fn is_fatal(&self) -> bool {
        self.exit_reason.fatal()
    }

    pub fn is_stop_request(&self) -> bool {
        self.exit_reason.is_stop_request()
    }
}

assert_obj_safe!(CpuBackend);

pub trait CpuBackend: Debug + Hookable + Send {
    /// Reads the value of the desired register from the target cpu.
    ///
    /// This method should error if the register is not available on the target,
    /// and if the value provided is not the correct size for the register.
    ///
    /// This method is "raw" because it takes an [ArchRegister]. The preferred
    /// method of reading a register is using [crate::cpu::CpuBackendExt::read_register()]
    /// which takes an `impl Into<ArchRegister>` providing a more ergonomic api.
    fn read_register_raw(&mut self, reg: ArchRegister) -> Result<RegisterValue, ReadRegisterError>;

    /// Write a value to a register on the target cpu.
    ///
    /// This method should error if the register is not available on the target,
    /// and if the value provided is not the correct size for the register.
    ///
    /// This method is "raw" because it takes an [ArchRegister]. The preferred
    /// method of reading a register is using [crate::cpu::CpuBackendExt::write_register()]
    /// which takes an `impl Into<ArchRegister>` providing a more ergonomic api.
    fn write_register_raw(
        &mut self,
        reg: ArchRegister,
        value: RegisterValue,
    ) -> Result<(), WriteRegisterError>;

    /// Retrieve the underlying [`ArchitectureDef`] metadata struct from the cpu.
    fn architecture(&self) -> &dyn ArchitectureDef;

    /// Retrieve the endianness of the CPU.
    fn endian(&self) -> ArchEndian;

    /// Start Cpu execution, total instruction `count`.
    ///
    /// Setting  `count` to 0 will run indefinitely (or until
    /// the target crashes).
    fn execute(
        &mut self,
        mmu: &mut Mmu,
        event_controller: &mut EventController,
        count: u64,
    ) -> Result<ExecutionReport, UnknownError>;

    /// Pause Cpu execution.
    fn stop(&mut self);

    /// Save the current executing context.
    ///
    /// ### NOTE
    /// Requires the CPU to be stopped.
    /// This will overwrite a previously saved context.
    fn context_save(&mut self) -> Result<(), UnknownError>;

    /// Restore from the previously restored context into the current execution.
    ///
    /// ### NOTE
    /// Requires the CPU to be stopped.
    /// Should return an error if attempting to restore context without saving first
    fn context_restore(&mut self) -> Result<(), UnknownError>;

    /// Get the current value of the current `pc` register.
    ///
    /// ### NOTE
    ///
    /// Reading the value of `PC` before it has been set explicitly by host code, or before the
    /// target is started via [`crate::processor::Processor::run`] is undefined if using the
    /// unicorn backend, (but probably 0).
    fn pc(&mut self) -> Result<u64, UnknownError>;

    /// Set the current value of the current `pc` register.
    fn set_pc(&mut self, value: u64) -> Result<(), UnknownError>;
}
