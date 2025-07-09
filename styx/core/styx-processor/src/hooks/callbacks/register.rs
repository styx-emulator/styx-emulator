// SPDX-License-Identifier: BSD-2-Clause
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
