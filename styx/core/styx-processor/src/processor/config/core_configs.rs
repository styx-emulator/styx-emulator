// SPDX-License-Identifier: BSD-2-Clause
//! Built-in [`ProcessorConfig`](super::ProcessorConfig) types populated by the processor
//! builder.
//!
//! These configs carry architecture metadata and execution preferences
//! that subsystems (executors, peripherals, plugins) can query at
//! runtime without depending on each other directly.

use styx_cpu_type::{arch::backends::ArchVariant, ArchEndian, Backend};
use styx_macros::ProcessorConfig;

/// Architecture and endianness of the processor being emulated.
#[derive(Debug, Clone, Copy, ProcessorConfig)]
pub struct ConfigProcInfo {
    /// The target architecture variant.
    pub arch_variant: ArchVariant,
    /// Byte ordering of the target.
    pub endian: ArchEndian,
}

/// The CPU execution [`Backend`] selected for this processor.
#[derive(Debug, Clone, Copy, ProcessorConfig)]
pub struct ConfigBackend(pub Backend);

/// Preferred number of instructions to execute per tick.
///
/// [`ExecutorImpl`](crate::executor::ExecutorImpl) implementations use
/// this as a hint when scheduling execution strides. The actual stride
/// may differ for example in the gdb executor where the condition of
/// 1 or more watchpoints will change the stride length to 1.
#[derive(Debug, Clone, Copy, ProcessorConfig)]
pub struct ConfigRequestedStrideLength {
    pub preferred_stride_length: u64,
}

impl Default for ConfigRequestedStrideLength {
    fn default() -> Self {
        Self {
            preferred_stride_length: 1000,
        }
    }
}
