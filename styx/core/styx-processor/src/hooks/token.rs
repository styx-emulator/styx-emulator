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
