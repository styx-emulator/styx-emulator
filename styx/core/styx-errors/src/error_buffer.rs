// SPDX-License-Identifier: BSD-2-Clause
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
