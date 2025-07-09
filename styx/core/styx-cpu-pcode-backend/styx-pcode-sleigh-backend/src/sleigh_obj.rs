// SPDX-License-Identifier: BSD-2-Clause
use std::pin::Pin;

use cxx::{memory::UniquePtrTarget, UniquePtr};

/// Generic object providing helper functions for an owned C++/libsla/Sleigh object.
pub struct SleighObj<T: UniquePtrTarget> {
    ptr: cxx::UniquePtr<T>,
}

impl<T: UniquePtrTarget> SleighObj<T> {
    /// Create from a [UniquePtr]. Returns [None] if null.
    pub fn from_unique_ptr(ptr: UniquePtr<T>) -> Option<Self> {
        if ptr.is_null() {
            return None;
        }
        Some(Self { ptr })
    }

    /// This is dangerous as the returned pointer could become invalid if self is freed.
    pub fn as_raw(&self) -> *mut T {
        self.as_ref() as *const _ as *mut _
    }

    /// Get pinned mutable reference to underlying cpp object.
    pub fn as_mut(&mut self) -> std::pin::Pin<&mut T> {
        self.ptr.as_mut().expect("SleighObj pointer is null")
    }

    /// Upcast derived cpp class to reference to parent.
    pub fn upcast_ref<P: UniquePtrTarget>(&self) -> &P
    where
        SleighObj<T>: DeriveParent<P>,
    {
        unsafe { &*(self.as_ref() as *const T as *const P) }
    }

    /// Upcast derived cpp class to pinned mutable reference to parent.
    pub fn upcast_mut<P: UniquePtrTarget>(&mut self) -> Pin<&mut P>
    where
        SleighObj<T>: DeriveParent<P>,
    {
        unsafe { Pin::new_unchecked(&mut *(self.as_raw() as *mut P)) }
    }

    /// Upcast derived cpp class to pointer to parent.
    ///
    /// This is dangerous as the returned pointer could become invalid if self is freed.
    pub fn upcast_raw<P: UniquePtrTarget>(&self) -> *mut P
    where
        SleighObj<T>: DeriveParent<P>,
    {
        self.as_raw() as *mut P
    }
}

impl<T: cxx::memory::UniquePtrTarget> AsRef<T> for SleighObj<T> {
    fn as_ref(&self) -> &T {
        self.ptr.as_ref().expect("SleighObj pointer is null")
    }
}

/// Implement on a `SleighObject<T>` to indicate `T` is a cpp subclass of `P`.
///
/// This trait is only useful if P is a cpp ffi type. More specifically, it should implement
/// [UniquePtrTarget].
///
/// # Safety
///
/// By implementing this unsafe trait you are promising the implementer type is a derived subclass
/// of `P`. The implementer pointer type must be able to be casted to pointer type of `P`.
///
pub unsafe trait DeriveParent<P: UniquePtrTarget> {}
