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
use crate::styx_hooks::StyxHookError;
use styx_memory_type::{MemoryOperation, MemoryPermissions};
use thiserror::Error;
use unicorn_engine::uc_error;

#[derive(Error, Debug)]
pub enum StyxMemorySnaphotError {
    #[error("Saved context is empty.")]
    EmptyContext,
}

#[derive(Error, Debug)]
pub enum StyxMemoryError {
    #[error("Region size is declared to be {0}, data provided was size: {1}")]
    DataInvalidSize(u64, u64),
    #[error("Duplicate memory region address: `0x{0:x}` with size: {1}")]
    DuplicateRegion(u64, u64),
    #[error("The memory bank is empty")]
    EmptyMemoryBank,
    #[error("FFI call failed: `{0}`")]
    FFIFailure(String),
    #[error("Hook error")]
    HookError(StyxHookError),
    #[error("Base address `0x{0:x}` is not found")]
    InvalidBase(u64),
    #[error("{op:?} range requested: {request_min:#08X} - {request_max:#08X}, have {limit_min:#08X} - {limit_max:#08X}")]
    InvalidMemoryRange {
        op: MemoryOperation,
        request_min: u64,
        request_max: u64,
        limit_min: u64,
        limit_max: u64,
    },
    #[error("Region at `0x{0:x}` size: `{1}` is not inside valid memory range")]
    InvalidMemoryRegionRange(u64, u64),
    #[error("Region has ({have:?}), need: ({need:?})")]
    InvalidRegionPermissions {
        have: MemoryPermissions,
        need: MemoryPermissions,
    },
    #[error("Range requested: {request_min:#08X} - {request_max:#08X}, but only contiguous for {contiguous_min:#08X} - {contiguous_max:#08X}")]
    NonContiguousRange {
        request_min: u64,
        request_max: u64,
        /// The max of the previous valid region. Also, the largest request_max you can request with
        /// the same request_min.
        previous_max: u64,
        contiguous_min: u64,
        contiguous_max: u64,
    },
    #[error("New Region{{base: 0x{0:x}, size: {1}}} overlaps an existing MemoryRegion")]
    OverlappingRegion(u64, u64),
    #[error("Size `{0}` is too large")]
    SizeTooLarge(u64),
    #[error("Size `{0}` is too small, should be at least `{1}`")]
    SizeTooSmall(u64, u64),
    #[error("Context save/restore error.")]
    SnapshotError(StyxMemorySnaphotError),
    #[error("Memory region base not page (0x1000 byte) aligned")]
    UnalignedMemoryRegionBase,
    #[error("Memory region size not page (0x1000 byte) aligned")]
    UnalignedMemoryRegionSize,
    #[error("Address `0x{0:x}` is unmapped!")]
    UnmappedAddress(u64),
    #[error("Size must be > 0")]
    ZeroSize,
}

impl From<StyxMemorySnaphotError> for StyxMemoryError {
    fn from(value: StyxMemorySnaphotError) -> Self {
        StyxMemoryError::SnapshotError(value)
    }
}

impl From<StyxHookError> for StyxMemoryError {
    fn from(value: StyxHookError) -> Self {
        StyxMemoryError::HookError(value)
    }
}

//
// unicorn compat
//

impl From<uc_error> for StyxMemoryError {
    fn from(value: uc_error) -> Self {
        // need to go back through the api and add other checks as well
        match value {
            uc_error::EXCEPTION => StyxMemoryError::FFIFailure("Generic Exception".into()),
            uc_error::ARG => StyxMemoryError::FFIFailure("Bad Arguments".into()),
            _ => StyxMemoryError::FFIFailure(format!("Unicorn Error: {:?}", value)),
        }
    }
}
