// SPDX-License-Identifier: BSD-2-Clause
use styx_errors::UnknownError;

use crate::hooks::{CoreHandle, HookUserData};

/// Callback for a memory write hook.
///
/// See [StyxHook::memory_write()](crate::hooks::StyxHook::memory_write()) for more information on
/// constructing memory write hooks.
pub trait MemoryWriteHook: Send + Sync {
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        size: u32,
        data: &[u8],
    ) -> Result<(), UnknownError>;
}

impl<T: FnMut(CoreHandle, u64, u32, &[u8]) -> Result<(), UnknownError> + Send + Sync>
    MemoryWriteHook for T
{
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        size: u32,
        data: &[u8],
    ) -> Result<(), UnknownError> {
        self(proc, address, size, data)
    }
}

pub type MemoryWriteHookDataFn = Box<
    dyn FnMut(CoreHandle, u64, u32, &[u8], HookUserData) -> Result<(), UnknownError> + Send + Sync,
>;
pub struct MemoryWriteHookData {
    pub callback: MemoryWriteHookDataFn,
    pub data: HookUserData,
}
impl MemoryWriteHook for MemoryWriteHookData {
    fn call(
        &mut self,
        proc: CoreHandle,
        address: u64,
        size: u32,
        data: &[u8],
    ) -> Result<(), UnknownError> {
        self.callback.as_mut()(proc, address, size, data, self.data.clone())
    }
}
