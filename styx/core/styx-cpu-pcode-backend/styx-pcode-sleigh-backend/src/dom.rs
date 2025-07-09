// SPDX-License-Identifier: BSD-2-Clause
use std::path::Path;

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
use styx_sleigh_bindings::ffi;

use crate::sleigh_obj::SleighObj;

pub struct DocumentStorage {
    pub obj: SleighObj<ffi::DocumentStorage>,
}

impl DocumentStorage {
    /// Create a new document storage from raw spec string.
    ///
    /// Returns `None` if parsing failed.
    pub fn new(spec_str: &str) -> Result<Self, cxx::Exception> {
        cxx::let_cxx_string!(spec = spec_str);

        let doc_ptr = ffi::newDocumentStorage(&spec)?;

        // Should never fail to create here unless somehow newDocumentStorage returned a nullptr.
        let obj =
            SleighObj::from_unique_ptr(doc_ptr).expect("Could not create DocumentStorage object.");

        Ok(Self { obj })
    }

    /// Creates a spec with the given path wrapped in <sleigh></sleigh>.
    ///
    /// Returns `None` if parsing failed.
    pub fn with_path(spec_file: impl AsRef<Path>) -> Result<Self, cxx::Exception> {
        let path: &Path = spec_file.as_ref();
        let spec_str = format!("<sleigh>{}</sleigh>", path.to_string_lossy());

        Self::new(&spec_str)
    }
}
