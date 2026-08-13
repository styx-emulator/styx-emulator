// SPDX-License-Identifier: BSD-2-Clause
use log::info;
use styx_cpu_type::TargetExitReason;

use super::Delta;

/// Callback that decides whether the stride loop should halt after a stride.
///
/// Returns `true` to halt emulation, `false` to continue. Produced by
/// [`StrideExecutor::halt_emulation()`](super::StrideExecutor::halt_emulation) once per vCPU,
/// so the closure may hold per-vCPU mutable state.
pub type HaltFn = Box<dyn FnMut(&TargetExitReason, &Delta) -> bool + Send>;

/// Built-in halt policy: stop on fatal exits or host-requested stops.
///
/// Used when a [`StrideExecutor`](super::StrideExecutor) does not supply its own [`HaltFn`].
pub fn default_halter() -> HaltFn {
    Box::new(|reason: &TargetExitReason, _delta: &Delta| {
        if reason.fatal() || reason.is_stop_request() {
            info!("Executor exit reason: {reason:?}");
            true
        } else {
            false
        }
    })
}
