// SPDX-License-Identifier: BSD-2-Clause
use std::ffi::c_char;

use super::StyxFFIError;

#[allow(non_camel_case_types)]
#[repr(transparent)]
pub(crate) struct CStrPtr(*const c_char);

impl CStrPtr {
    pub(crate) fn as_str(
        &self,
        len: impl TryInto<usize, Error: std::error::Error + 'static>,
    ) -> Result<&str, StyxFFIError> {
        if self.0.is_null() {
            return Err(StyxFFIError::null_string());
        }

        let len = len
            .try_into()
            .map_err(|e| StyxFFIError::invalid_string_length(Box::new(e)))?;

        let slice = unsafe { std::slice::from_raw_parts(self.0.cast(), len) };
        let out = std::str::from_utf8(slice).map_err(StyxFFIError::invalid_string)?;
        Ok(out)
    }
}
