// SPDX-License-Identifier: BSD-2-Clause
use styx_errors::UnknownError;

use crate::hooks::CoreHandle;

/// Callback for a block hook.
///
/// See [StyxHook::block()](crate::hooks::StyxHook::block()) for more information on constructing
/// block hooks.
pub trait BlockHook: Send {
    fn call(&mut self, proc: CoreHandle, address: u64, size: u32) -> Result<(), UnknownError>;
}

impl<T: FnMut(CoreHandle, u64, u32) -> Result<(), UnknownError> + Send> BlockHook for T {
    fn call(&mut self, proc: CoreHandle, address: u64, size: u32) -> Result<(), UnknownError> {
        self(proc, address, size)
    }
}
