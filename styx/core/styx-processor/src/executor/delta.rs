// SPDX-License-Identifier: BSD-2-Clause
/// Reports metrics after *some* execution.
///
/// Target execution is broken up into stides of emulation.
/// The stride length is determined by [`ConfigRequestedStrideLength`] but real
/// execution will have varying stride lengths if vCPUs exit early or pause (i.e.
/// via GDB breakpoint).
#[derive(Debug, Clone, Default)]
pub struct Delta {
    /// Elapsed wall clock time since last tick.
    ///
    /// This is the real-world duration of the stride, not a processor-specific or simulated time.
    pub time: std::time::Duration,
    /// Number of instructions executed.
    pub count: u64,
}
