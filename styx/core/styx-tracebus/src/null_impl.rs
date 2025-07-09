// SPDX-License-Identifier: BSD-2-Clause
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
