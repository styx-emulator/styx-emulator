// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
