// SPDX-License-Identifier: BSD-2-Clause
//! Sane default executor for Styx processors
use styx_errors::UnknownError;

use crate::processor::{core_configs::ConfigRequestedStrideLength, BuildingProcessor};

use super::StrideExecutor;

/// A sane default.
///
/// Notably implements [StrideExecutor].
///
/// Users of Styx should use the [`DefaultExecutor::default()`] implementation
/// and define stride length with [`ConfigRequestedStrideLength`].
/// Tests inside `styx-processor` should use [`DefaultExecutor::with_stride_length()`].
#[derive(Default, Debug)]
pub struct DefaultExecutor {
    stride_length: Option<u64>,
}

impl StrideExecutor for DefaultExecutor {
    fn get_stride_length(&self) -> u64 {
        // we use expect here because init not being called is a core bug.
        self.stride_length.expect(
            "DefaultExecutor stride length not set. This indicates that `init` was not called.",
        )
    }

    /// Called before emulating, initializes stride length here.
    fn init(&mut self, proc: &mut BuildingProcessor) -> Result<(), UnknownError> {
        self.stride_length = Some(
            proc.config
                .get_or_default::<ConfigRequestedStrideLength>()
                .preferred_stride_length,
        );
        Ok(())
    }
}

impl DefaultExecutor {
    /// styx-processor only initialization for when `init` is not called.
    #[allow(dead_code)]
    pub(crate) fn with_stride_length(stride: u64) -> Self {
        Self {
            stride_length: Some(stride),
        }
    }
}
