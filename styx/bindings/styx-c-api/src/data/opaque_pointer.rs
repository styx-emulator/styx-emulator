// SPDX-License-Identifier: BSD-2-Clause
use std::{alloc::Layout, marker::PhantomData, ptr::NonNull};

mod macros;
pub(crate) use macros::*;

use super::StyxFFIError;

/// A "safe" pointer type for managing styx resources across the FFI boundary
///
/// This type should not be used directly in API's, instead used the [crate::data::opaque_pointer]
/// macro to create a wrapper type for this object
#[repr(transparent)]
pub struct OpaquePointer<T>(*mut (), PhantomData<T>);

impl<T> Clone for OpaquePointer<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for OpaquePointer<T> {}

/// A marker trait for the inner type of a pointer type
pub trait OpaquePointerType {
    type To;
}

impl<T> OpaquePointer<T>
where
    T: OpaquePointerType,
{
    /// cast the inner type to the actual pointer target type
    fn as_ptr(&self) -> *mut T::To {
        self.0 as *mut T::To
    }

    pub(crate) unsafe fn new_uninit() -> Result<Self, StyxFFIError> {
        unsafe {
            let layout = Layout::new::<T::To>();
            let ptr = std::alloc::alloc(layout) as *mut ();
            if ptr.is_null() {
                Err(StyxFFIError::allocation_error())
            } else {
                Ok(Self(ptr, PhantomData))
            }
        }
    }

    pub(crate) fn new(inner: T::To) -> Result<Self, StyxFFIError> {
        // safety: we definitely move into the pointer
        unsafe {
            let out = Self::new_uninit()?;
            std::ptr::write(out.as_ptr(), inner);
            Ok(out)
        }
    }

    /// create a opaque pointer based on some owned data,
    ///
    /// # Safety
    ///
    /// this pointer is bound to the lifetime of the inner value so this value should not be
    /// returned past that point!
    ///
    pub(crate) unsafe fn from_mut(inner: &mut T::To) -> Self {
        Self(inner as *mut T::To as *mut (), PhantomData)
    }

    /// free an allocated styx pointer and set the inner pointer to null
    ///
    /// # Example
    /// ```c
    /// StyxOpaquePointer ptr = StyxOpaquePointer_new();
    /// assert(ptr); // it's not null!
    /// StyxOpaquePointer_free(&ptr);
    /// assert(ptr == NULL); // we've free'd our resource and it is now null
    /// ```
    pub fn free(ptr: *mut Self) {
        let Some(outer) = (unsafe { ptr.as_mut() }) else {
            return;
        };
        if let Some(inner) = NonNull::new(outer.as_ptr()) {
            unsafe {
                Self::free_impl(inner.as_ptr());
                std::ptr::write(ptr, OpaquePointer(std::ptr::null_mut(), PhantomData));
            }
        }
    }

    /// Actually free a pointer to a resource
    ///
    /// # Safety
    /// This can have issues if the pointer is not initialized
    unsafe fn free_impl(t: *mut T::To) {
        unsafe {
            let layout = Layout::new::<T::To>();
            std::ptr::drop_in_place(t);
            std::alloc::dealloc(t as *mut u8, layout);
        }
    }

    /// Free a pointer created temporarily and not passed into styx
    pub fn free_owned(self) {
        unsafe {
            let ptr = self.as_ptr();
            Self::free_impl(ptr);
        }
    }

    /// get the underlying value as a reference or supply an FFI error
    pub(crate) fn as_ref(&self) -> Result<&T::To, StyxFFIError> {
        unsafe { self.as_ptr().as_ref() }.ok_or_else(StyxFFIError::null_input)
    }

    /// get the underlying value as a mutable reference or supply an FFI error
    pub(crate) fn as_mut(&mut self) -> Result<&mut T::To, StyxFFIError> {
        unsafe { self.as_ptr().as_mut() }.ok_or_else(StyxFFIError::null_input)
    }

    pub(crate) fn take(self) -> Result<T::To, StyxFFIError> {
        let out = unsafe { std::ptr::read(self.0 as *const T::To) };

        let layout = Layout::new::<T::To>();
        unsafe {
            std::alloc::dealloc(self.0 as *mut u8, layout);
        }
        Ok(out)
    }
}
