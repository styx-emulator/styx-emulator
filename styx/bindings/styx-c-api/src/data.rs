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
//! TODO: Rename module to abstract datatypes / ADT's instead of `data`
/// a pointer wrapper for resource management
mod opaque_pointer;

pub(crate) use opaque_pointer::{opaque_pointer, OpaquePointer, OpaquePointerType};

/// error handling for C ffi
mod result;
pub(crate) use result::{StyxFFIError, StyxFFIErrorPtr};

/// An array pointer wrapper
mod array_ptr;
pub(crate) use array_ptr::{ArrayPtr, ArrayPtrMut};

/// A cstring pointer wrapper
mod cstr_ptr;
pub(crate) use cstr_ptr::CStrPtr;

/// A boolean wrapper for c-int's
mod c_bool;
pub(crate) use c_bool::CBool;

/// write to a pointer or return an error if the pointer is null
pub(crate) fn try_unit(f: impl FnOnce() -> Result<(), StyxFFIError>) -> StyxFFIErrorPtr {
    match f() {
        Ok(()) => StyxFFIErrorPtr::Ok,
        Err(e) => e.into(),
    }
}

/// lazily write to a pointer or return an error if the pointer is null
pub(crate) fn try_out<T>(
    out: *mut T,
    value: impl FnOnce() -> Result<T, StyxFFIError>,
) -> StyxFFIErrorPtr {
    std::ptr::NonNull::new(out)
        .map(|ptr| {
            let value = value()?;
            unsafe {
                std::ptr::write(ptr.as_ptr(), value);
            }
            StyxFFIErrorPtr::Ok
        })
        .unwrap_or_else(|| StyxFFIError::null_output().into())
}
