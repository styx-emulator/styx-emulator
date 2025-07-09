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
use styx_cpu_type::arch::{backends::ArchRegister, RegisterValue};
use styx_errors::UnknownError;

use crate::hooks::CoreHandle;

/// Callback for a register read hook.
///
/// See [StyxHook::register_read()](crate::hooks::StyxHook::register_read()) for more information on
/// constructing register read hooks.
pub trait RegisterReadHook: Send {
    fn call(
        &mut self,
        proc: CoreHandle,
        register: ArchRegister,
        data: &mut RegisterValue,
    ) -> Result<(), UnknownError>;
}

impl<T: FnMut(CoreHandle, ArchRegister, &mut RegisterValue) -> Result<(), UnknownError> + Send>
    RegisterReadHook for T
{
    fn call(
        &mut self,
        proc: CoreHandle,
        register: ArchRegister,
        data: &mut RegisterValue,
    ) -> Result<(), UnknownError> {
        self(proc, register, data)
    }
}

/// Callback for a register write hook.
///
/// See [StyxHook::register_write()](crate::hooks::StyxHook::register_write()) for more information
/// on constructing register write hooks.
pub trait RegisterWriteHook: Send {
    fn call(
        &mut self,
        proc: CoreHandle,
        register: ArchRegister,
        data: &RegisterValue,
    ) -> Result<(), UnknownError>;
}

impl<T: FnMut(CoreHandle, ArchRegister, &RegisterValue) -> Result<(), UnknownError> + Send>
    RegisterWriteHook for T
{
    fn call(
        &mut self,
        proc: CoreHandle,
        register: ArchRegister,
        data: &RegisterValue,
    ) -> Result<(), UnknownError> {
        self(proc, register, data)
    }
}
