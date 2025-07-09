// SPDX-License-Identifier: BSD-2-Clause
//! Conditionally exports types under [`std`], [`loom`](https://docs.rs/loom/latest/loom/),
//! or [`shuttle`](https://docs.rs/shuttle/latest/shuttle/) depending on compilation flags.
#[cfg(loom)]
pub use loom::{self, alloc, hint, lazy_static, sync, thread};

#[cfg(shuttle)]
pub use shuttle::{self, hint, lazy_static, rand, sync, thread};

#[cfg(not(loom))]
mod compat;

pub mod cell {

    pub use std::cell::{BorrowError, BorrowMutError, OnceCell, Ref, RefCell, RefMut};

    #[cfg(not(loom))]
    pub use std::cell::Cell;

    #[cfg(not(loom))]
    pub use super::compat::UnsafeCell;

    #[cfg(loom)]
    pub use loom::cell::*;
}

#[cfg(not(any(loom, shuttle)))]
pub use std::sync;

#[cfg(not(loom))]
pub use std::alloc;

#[cfg(not(any(loom, shuttle)))]
pub use std::hint;

#[cfg(not(any(loom, shuttle)))]
pub use std::thread;

#[cfg(not(any(loom, shuttle)))]
#[allow(unused_imports)]
#[macro_use]
extern crate lazy_static;

#[cfg(not(any(loom, shuttle)))]
pub use lazy_static::lazy_static;

/// TODO: figure out if we need to replace `once_cell` with
/// a compat layer
pub use once_cell;

pub mod styx_async {
    pub use tokio::sync;
}

// re-export for nicer imports, styx core imports this lib as `sync` so lets remove
// that line of ugly
pub use sync::*;
