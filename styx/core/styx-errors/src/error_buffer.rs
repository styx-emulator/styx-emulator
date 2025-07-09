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
use std::fmt::Display;

use thiserror::Error;

use crate::UnknownError;

/// Holds a growing list of errors to be handled at a later time.
///
/// Intended use is in a loop of fallible operations that should run all
/// operations and report failures after processing.
#[derive(Default, Debug, Error)]
pub struct ErrorBuffer {
    errors: Vec<UnknownError>,
}
impl Display for ErrorBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.errors)
    }
}
impl From<Vec<UnknownError>> for ErrorBuffer {
    fn from(value: Vec<UnknownError>) -> Self {
        Self { errors: value }
    }
}

impl ErrorBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, item: impl Into<UnknownError>) {
        self.errors.push(item.into());
    }

    /// Returns [Ok] if empty, returns [Err(self)] if non-empty.
    pub fn result(self) -> Result<(), ErrorBuffer> {
        if self.errors.is_empty() {
            Ok(())
        } else {
            Err(self)
        }
    }
}
