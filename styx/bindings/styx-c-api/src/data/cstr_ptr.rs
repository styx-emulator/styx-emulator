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
