use std::sync::{Arc, Mutex};

use styx_core::{
    errors::UnknownError,
    hooks::{CoreHandle, MemoryReadHook, MemoryWriteHook},
};

pub fn peripheral_shared_state_read<T, R>(
    // Inner memory hook function
    mut inner: R,
    state: Arc<Mutex<T>>,
) -> Box<dyn MemoryReadHook>
where
    T: Send + 'static,
    R: FnMut(CoreHandle, u64, u32, &mut [u8], Arc<Mutex<T>>) -> Result<(), UnknownError>
        + Send
        + Sync
        + 'static,
{
    Box::new(
        move |core: CoreHandle<'_>, address: u64, size: u32, value: &mut [u8]| {
            inner(core, address, size, value, state.clone())
        },
    )
}

pub fn peripheral_shared_state_write<T, R>(
    // Inner memory hook function
    mut inner: R,
    state: Arc<Mutex<T>>,
) -> Box<dyn MemoryWriteHook>
where
    T: Send + 'static,
    R: FnMut(CoreHandle, u64, u32, &[u8], Arc<Mutex<T>>) -> Result<(), UnknownError>
        + Send
        + Sync
        + 'static,
{
    Box::new(
        move |core: CoreHandle<'_>, address: u64, size: u32, value: &[u8]| {
            inner(core, address, size, value, state.clone())
        },
    )
}
