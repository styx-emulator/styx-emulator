// SPDX-License-Identifier: BSD-2-Clause
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
