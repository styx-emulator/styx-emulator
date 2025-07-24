// SPDX-License-Identifier: BSD-2-Clause
use std::path::Path;
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
