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

use super::Resolution;
// we can replace these with custom  in the future
pub use super::MemFaultData;

use crate::{hooks::CoreHandle, memory::MemoryPermissions};

/// Callback for a memory protection fault hook.
///
/// See [StyxHook::protection_fault()](crate::hooks::StyxHook::protection_fault()) for more
/// information on constructing memory protection fault hooks.
pub trait ProtectionFaultHook: Send {
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        size: u32,
        region_permissions: MemoryPermissions,
        fault_data: MemFaultData,
    ) -> Result<Resolution, UnknownError>;
}

impl<
        T: FnMut(
                CoreHandle,
                u64,
                u32,
                MemoryPermissions,
                MemFaultData,
            ) -> Result<Resolution, UnknownError>
            + Send,
    > ProtectionFaultHook for T
{
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        size: u32,
        region_permissions: MemoryPermissions,
        fault_data: MemFaultData,
    ) -> Result<Resolution, UnknownError> {
        self(proc, address, size, region_permissions, fault_data)
    }
}
