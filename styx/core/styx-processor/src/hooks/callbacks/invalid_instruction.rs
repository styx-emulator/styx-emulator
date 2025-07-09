// SPDX-License-Identifier: BSD-2-Clause
use styx_errors::UnknownError;

use crate::hooks::CoreHandle;

use super::Resolution;

/// Callback for an invalid instruction hook.
///
/// See [StyxHook::invalid_instruction()](crate::hooks::StyxHook::invalid_instruction()) for more
/// information on constructing invalid instruction hooks.
pub trait InvalidInstructionHook: Send {
    fn call(&mut self, proc: CoreHandle) -> Result<Resolution, UnknownError>;
}

impl<T: FnMut(CoreHandle) -> Result<Resolution, UnknownError> + Send> InvalidInstructionHook for T {
    fn call(&mut self, proc: CoreHandle) -> Result<Resolution, UnknownError> {
        self(proc)
    }
}
