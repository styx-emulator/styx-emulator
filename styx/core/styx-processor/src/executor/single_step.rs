// SPDX-License-Identifier: BSD-2-Clause

use super::StrideExecutor;

/// Executor that handles events after every instruction.
///
/// Notably implements [StrideExecutor].
#[derive(Debug)]
pub struct SingleStepExecutor;

impl StrideExecutor for SingleStepExecutor {
    fn get_stride_length(&self) -> u64 {
        1
    }
}
