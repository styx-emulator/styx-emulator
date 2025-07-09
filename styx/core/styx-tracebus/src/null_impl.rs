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
//! Null trace provider - a [TraceProvider] that does does not store events

use crate::{mkpath, TraceError, TraceProvider, Traceable};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct NullTracer {
    key: String,
}

impl Default for NullTracer {
    fn default() -> Self {
        // this is not strictly necessary, however, it allows us to assert
        // that the path does not exist in tests.
        Self {
            key: mkpath(None, "null"),
        }
    }
}

impl NullTracer {}

impl TraceProvider for NullTracer {
    fn trace<T>(&self, _: &T) -> Result<bool, TraceError>
    where
        T: for<'de> Deserialize<'de> + Serialize + Traceable,
    {
        Ok(true)
    }

    fn teardown(&self) -> Result<(), TraceError> {
        Ok(())
    }

    fn key(&self) -> String {
        self.key.to_string()
    }
}
