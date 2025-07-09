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
use super::StyxFFIError;

#[repr(transparent)]
pub struct ArrayPtr<T>(*const T);

impl<T> ArrayPtr<T> {
    pub(crate) fn null() -> Self {
        Self(std::ptr::null())
    }

    pub(crate) fn new(ptr: *const T) -> Self {
        Self(ptr)
    }

    fn non_null(&self) -> Result<*const T, StyxFFIError> {
        if self.0.is_null() {
            return Err(StyxFFIError::null_array());
        }
        Ok(self.0)
    }

    pub(crate) fn as_slice(
        &self,
        size: impl TryInto<usize, Error: std::error::Error + 'static>,
    ) -> Result<&[T], StyxFFIError> {
        let data = self.non_null()?;
        let len = size
            .try_into()
            .map_err(|e| StyxFFIError::invalid_array_length(Box::new(e)))?;
        Ok(unsafe { std::slice::from_raw_parts(data, len) })
    }
}

impl<T> From<&'_ [T]> for ArrayPtr<T> {
    fn from(value: &'_ [T]) -> Self {
        Self(value.as_ptr())
    }
}

impl<T> From<&'_ mut [T]> for ArrayPtr<T> {
    fn from(value: &'_ mut [T]) -> Self {
        Self(value.as_ptr())
    }
}

#[repr(transparent)]
pub struct ArrayPtrMut<T>(*mut T);
impl<T> From<ArrayPtrMut<T>> for ArrayPtr<T> {
    fn from(value: ArrayPtrMut<T>) -> Self {
        Self(value.0)
    }
}

impl<T> ArrayPtrMut<T> {
    fn non_null(&self) -> Result<*mut T, StyxFFIError> {
        if self.0.is_null() {
            return Err(StyxFFIError::null_array());
        }
        Ok(self.0)
    }

    // todo: should this be allowed? mutability
    //pub(crate) fn as_slice(
    //    &self,
    //    size: impl TryInto<usize, Error: std::error::Error + 'static>,
    //) -> Result<&[T], StyxFFIError> {
    //    let data = self.non_null()?;
    //    let len = size
    //        .try_into()
    //        .map_err(|e| StyxFFIError::invalid_array_length(Box::new(e)))?;
    //    Ok(unsafe { std::slice::from_raw_parts(data, len) })
    //}

    pub(crate) fn as_slice_mut(
        &mut self,
        size: impl TryInto<usize, Error: std::error::Error + 'static>,
    ) -> Result<&'_ mut [T], StyxFFIError> {
        let data = self.non_null()?;
        let len = size
            .try_into()
            .map_err(|e| StyxFFIError::invalid_array_length(Box::new(e)))?;
        Ok(unsafe { std::slice::from_raw_parts_mut(data, len) })
    }
}

impl<T> From<&'_ mut [T]> for ArrayPtrMut<T> {
    fn from(value: &'_ mut [T]) -> Self {
        Self(value.as_mut_ptr())
    }
}
