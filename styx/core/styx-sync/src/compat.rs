// SPDX-License-Identifier: BSD-2-Clause
//! Houses incompatibilities between loom / `{std | parking_lot}` that
//! need to be implemented.
#![cfg(not(loom))]

/// `loom` wanted to be cool (see: [here](https://docs.rs/loom/latest/loom/#handling-loom-api-differences)),
/// and instead just cause pain
#[derive(Debug)]
pub struct UnsafeCell<T>(std::cell::UnsafeCell<T>);

unsafe impl<T> Send for UnsafeCell<T> where T: Send {}
unsafe impl<T> Sync for UnsafeCell<T> where T: Sync {}

impl<T> UnsafeCell<T> {
    pub fn new(data: T) -> UnsafeCell<T> {
        UnsafeCell(std::cell::UnsafeCell::new(data))
    }

    pub fn with<R>(&self, f: impl FnOnce(*const T) -> R) -> R {
        f(self.0.get())
    }

    pub fn with_mut<R>(&self, f: impl FnOnce(*mut T) -> R) -> R {
        f(self.0.get())
    }
}
