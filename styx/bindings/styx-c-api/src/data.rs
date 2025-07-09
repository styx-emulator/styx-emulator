// SPDX-License-Identifier: BSD-2-Clause
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
