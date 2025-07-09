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

use crate::hooks::{CoreHandle, HookUserData};

/// Callback for a memory read hook.
///
/// See [StyxHook::memory_read()](crate::hooks::StyxHook::memory_read()) for more information on
/// constructing memory read hooks.
pub trait MemoryReadHook: Send {
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        size: u32,
        data: &mut [u8],
    ) -> Result<(), UnknownError>;
}

impl<T: FnMut(CoreHandle, u64, u32, &mut [u8]) -> Result<(), UnknownError> + Send> MemoryReadHook
    for T
{
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        size: u32,
        data: &mut [u8],
    ) -> Result<(), UnknownError> {
        self(proc, address, size, data)
    }
}

pub type MemoryReadHookDataFn = Box<
    dyn FnMut(CoreHandle, u64, u32, &mut [u8], HookUserData) -> Result<(), UnknownError> + Send,
>;

pub struct MemoryReadHookData {
    pub callback: MemoryReadHookDataFn,
    pub data: HookUserData,
}
impl MemoryReadHook for MemoryReadHookData {
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        size: u32,
        data: &mut [u8],
    ) -> Result<(), UnknownError> {
        self.callback.as_mut()(proc, address, size, data, self.data.clone())
    }
}
