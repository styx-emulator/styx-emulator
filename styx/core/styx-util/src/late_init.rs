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
use log::error;
use styx_sync::once_cell::sync::OnceCell;
use styx_sync::sync::{Arc, Mutex};

/// A struct used for creating struct that will have attributes initialized
/// after runtime, dereffable to get access to the underlying struct.
/// This is usable in Send + Sync environments.
///
/// For convenience sake, [`LateInit`] implements the following traits:
/// - [`std::fmt::Display`]
/// - [`std::fmt::Debug`]
/// - [`std::default::Default`]
/// - [`std::ops::Deref`]
/// - [`std::ops::DerefMut`]
/// - [`core::marker::Send`]
/// - [`core::marker::Sync`]
///
/// ```rust
/// use styx_util::LateInit;
///
/// #[derive(Default)]
/// struct Demo {
///     a: i32,
///     pub b: LateInit<u64>,
/// }
///
/// let mut x = Demo::default();
///
/// x.b.init(41).unwrap();
/// assert_eq!(*x.b, 41);
/// // fail to set again
/// assert!(!x.b.init(74).is_ok());
/// ```
pub struct LateInit<T> {
    cell: OnceCell<T>,
    valid: Arc<Mutex<bool>>,
}

impl<T> LateInit<T> {
    /// Initialize the underlying backing store
    pub fn init(&self, value: T) -> Result<(), T> {
        if let Err(value) = self.cell.set(value) {
            error!(
                "LateInit<{}> Value already set",
                core::any::type_name::<T>()
            );
            return Err(value);
        }

        // self valid OK
        *self.valid.lock().unwrap() = true;
        Ok(())
    }

    /// If the [`LateInit`] has been initialized
    pub fn object_valid(&self) -> bool {
        let tmp_valid = *self.valid.lock().unwrap();
        tmp_valid
    }
}

impl<T> Default for LateInit<T> {
    fn default() -> Self {
        LateInit {
            cell: OnceCell::default(),
            valid: Arc::new(Mutex::new(false)),
        }
    }
}

impl<T> std::ops::Deref for LateInit<T> {
    type Target = T;
    fn deref(&self) -> &T {
        self.cell.get().unwrap()
    }
}

impl<T> std::ops::DerefMut for LateInit<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.cell.get_mut().unwrap()
    }
}

impl<T> std::fmt::Debug for LateInit<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LateInit<{}>", core::any::type_name::<T>())
    }
}

impl<T> std::fmt::Display for LateInit<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "LateInit<{}>", core::any::type_name::<T>())
    }
}

unsafe impl<T> Sync for LateInit<T> where T: Sync {}
unsafe impl<T> Send for LateInit<T> where T: Send {}
