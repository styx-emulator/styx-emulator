// SPDX-License-Identifier: BSD-2-Clause
use styx_errors::UnknownError;

use crate::hooks::CoreHandle;

/// Callback for an interrupt hook.
///
/// See [StyxHook::interrupt()](crate::hooks::StyxHook::interrupt()) for more information on
/// constructing interrupt hooks.
pub trait InterruptHook: Send {
    fn call(&mut self, proc: CoreHandle, interrupt: i32) -> Result<(), UnknownError>;
}

impl<T: FnMut(CoreHandle, i32) -> Result<(), UnknownError> + Send> InterruptHook for T {
    fn call(&mut self, proc: CoreHandle, interrupt: i32) -> Result<(), UnknownError> {
        self(proc, interrupt)
    }
}
