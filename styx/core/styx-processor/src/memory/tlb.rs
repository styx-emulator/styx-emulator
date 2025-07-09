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
use styx_errors::UnknownError;
use thiserror::Error;

use crate::memory::MemoryOperation;
use crate::{cpu::CpuBackend, event_controller::ExceptionNumber};

#[derive(Error, Debug)]
pub enum TLBError {
    #[error(transparent)]
    Other(#[from] UnknownError),
    /// Indicates a TLB error with an associated exception to synchronously execute.
    #[error("TLB error with exception {0:?}")]
    TlbException(Option<ExceptionNumber>),
}

/// The common interface for TLB implementations.  It defines methods for
/// performing address translations, reading/writing the TLB, updating TLB
/// state, and invalidating TLB entries.
pub trait TlbImpl: Send {
    /// Do any setup
    fn init(&mut self, _cpu: &mut dyn CpuBackend) -> Result<(), UnknownError> {
        Ok(())
    }

    /// Enable translation for data addresses
    fn enable_data_address_translation(&mut self) -> Result<(), UnknownError>;

    /// Disable translation for data addresses
    fn disable_data_address_translation(&mut self) -> Result<(), UnknownError>;

    /// Enable translation for code addresses
    fn enable_code_address_translation(&mut self) -> Result<(), UnknownError>;

    /// Disable translation for code addresses
    fn disable_code_address_translation(&mut self) -> Result<(), UnknownError>;

    /// Translate a virtual code address into a physical address
    fn translate_va_code(&mut self, virt_addr: u64) -> Result<u64, TLBError>;

    /// Translate a virtual data address into a physical address
    fn translate_va_data(
        &mut self,
        virt_addr: u64,
        access_type: MemoryOperation,
    ) -> Result<u64, TLBError>;

    /// Write to the TLB, it is up to the implementation to interpret the idx, data, and flags arguments
    fn tlb_write(&mut self, idx: usize, data: u64, flags: u32) -> Result<(), TLBError>;

    /// Read from the TLB, it is up to the implementation to interpret the idx and flags arguments
    fn tlb_read(&self, idx: usize, flags: u32) -> Result<u64, TLBError>;

    /// Invalidate all tlb entries, implementation specific flags are passed to control behaviour
    fn invalidate_all(&mut self, flags: u32) -> Result<(), UnknownError>;

    /// Invalidate a single tlb entry, based on an index value.
    ///
    /// The implementation decides how to interpret the idx value.
    fn invalidate(&mut self, idx: usize) -> Result<(), UnknownError>;
}

/// TLB implementation that has no address translation.
#[derive(Debug, Default)]
pub struct DummyTlb;
impl TlbImpl for DummyTlb {
    fn translate_va_code(&mut self, virt_addr: u64) -> Result<u64, TLBError> {
        Ok(virt_addr)
    }

    fn translate_va_data(
        &mut self,
        virt_addr: u64,
        _access_type: MemoryOperation,
    ) -> Result<u64, TLBError> {
        Ok(virt_addr)
    }

    fn invalidate_all(&mut self, _flags: u32) -> Result<(), UnknownError> {
        Ok(())
    }

    fn invalidate(&mut self, _idx: usize) -> Result<(), UnknownError> {
        Ok(())
    }

    fn tlb_write(&mut self, _idx: usize, _data: u64, _flags: u32) -> Result<(), TLBError> {
        Ok(())
    }

    fn tlb_read(&self, _idx: usize, _flags: u32) -> Result<u64, TLBError> {
        Ok(0)
    }

    fn enable_data_address_translation(&mut self) -> Result<(), UnknownError> {
        Ok(())
    }

    fn disable_data_address_translation(&mut self) -> Result<(), UnknownError> {
        Ok(())
    }

    fn enable_code_address_translation(&mut self) -> Result<(), UnknownError> {
        Ok(())
    }

    fn disable_code_address_translation(&mut self) -> Result<(), UnknownError> {
        Ok(())
    }
}
