// SPDX-License-Identifier: BSD-2-Clause
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
