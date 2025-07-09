// SPDX-License-Identifier: BSD-2-Clause
use styx_errors::UnknownError;

use super::Resolution;
// we can replace these with custom  in the future
pub use super::MemFaultData;

use crate::hooks::CoreHandle;

/// Callback for a unmapped memory fault hook.
///
/// See [StyxHook::unmapped_fault()](crate::hooks::StyxHook::unmapped_fault()) for more information
/// on constructing unmapped memory fault hooks.
pub trait UnmappedFaultHook: Send {
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        size: u32,
        fault_data: MemFaultData,
    ) -> Result<Resolution, UnknownError>;
}

impl<T: FnMut(CoreHandle, u64, u32, MemFaultData) -> Result<Resolution, UnknownError> + Send>
    UnmappedFaultHook for T
{
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        size: u32,
        fault_data: MemFaultData,
    ) -> Result<Resolution, UnknownError> {
        self(proc, address, size, fault_data)
    }
}
