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
use thiserror::Error;
use unicorn_engine::uc_error;

/// ffi [uc_error] wrapper, guaranteed to be an error variant i.e. will never be [uc_error::OK].
#[derive(Debug, Error)]
#[error("unicorn error of type `{0:?}`")]
pub struct UcErr(uc_error);

impl UcErr {
    pub fn from_unicorn(error: uc_error) -> Result<(), UcErr> {
        match error {
            uc_error::OK => Ok(()),
            other => Err(UcErr(other)),
        }
    }

    pub fn from_unicorn_trn<T>(error: uc_error, value: T) -> Result<T, UcErr> {
        match error {
            uc_error::OK => Ok(value),
            other => Err(UcErr(other)),
        }
    }

    pub fn from_unicorn_result<T>(error: Result<T, uc_error>) -> Result<T, UcErr> {
        if let Err(error_from_uc) = error {
            debug_assert_ne!(
                error_from_uc,
                uc_error::OK,
                "error variant of uc_error result is OK"
            );
        }
        error.map_err(UcErr)
    }
}
