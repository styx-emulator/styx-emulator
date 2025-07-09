// SPDX-License-Identifier: BSD-2-Clause
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
