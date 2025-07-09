// SPDX-License-Identifier: BSD-2-Clause
use std::ffi::c_void;

/// Created by cpu backends when adding hooks.
///
/// # Internals
///
/// For [HookToken::Pointer] variants, this token is used to reference a specific hook later and
/// should be globally unique from all other [`HookToken`]'s.
///
/// [HookToken::Integer] should also be unique but has no function meaning other being than a unique
/// value associated with a hook.
///
/// Currently, not guaranteed to be globally unique until a pointer is assigned to the inner field.
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum HookToken {
    /// Integer variant for any backend requiring unique hooks.
    Integer(u64),
    /// Pointer variant for unicorn backend, holds callback function pointer.
    Pointer(*mut c_void),
}

impl Default for HookToken {
    fn default() -> Self {
        Self::null_pointer()
    }
}

impl HookToken {
    /// Gets a mut ref to the inner token pointer if it's a pointer token.
    ///
    /// Getting the inner pointer is needed for the unicorn backend as it holds the callback
    /// function pointer. For other backends there is no reason for it to be a pointer. For the
    /// [HookToken::Integer] variant this returns `None`.
    ///
    /// This gives a mutable reference to allow the cpu backend to initialize the tokens as required
    /// if the container must be allocated first
    #[inline]
    pub fn pointer_mut(&mut self) -> Option<&mut *mut c_void> {
        match self {
            HookToken::Pointer(ptr) => Some(ptr),
            HookToken::Integer(_) => None,
        }
    }

    /// Creates a new [`HookToken`] from the provided pointer token.
    pub fn new_pointer(token: *mut c_void) -> Self {
        Self::Pointer(token)
    }

    /// Creates a new [`HookToken`] from the provided pointer token.
    pub fn null_pointer() -> Self {
        Self::Pointer(std::ptr::null_mut())
    }

    /// Creates a new [`HookToken`] from the provided integer token.
    pub fn new_integer(token: u64) -> Self {
        Self::Integer(token)
    }
}

unsafe impl Send for HookToken {}
unsafe impl Sync for HookToken {}
