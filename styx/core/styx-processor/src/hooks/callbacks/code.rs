// SPDX-License-Identifier: BSD-2-Clause
use styx_errors::UnknownError;

use crate::hooks::CoreHandle;

/// Callback for a code hook.
///
/// See [StyxHook::code()](crate::hooks::StyxHook::code()) for more information on constructing code
/// hooks.
pub trait CodeHook: Send {
    fn call(&mut self, proc: CoreHandle) -> Result<(), UnknownError>;
}

impl<T: FnMut(CoreHandle) -> Result<(), UnknownError> + Send> CodeHook for T {
    fn call(&mut self, proc: CoreHandle) -> Result<(), UnknownError> {
        self(proc)
    }
}
