// SPDX-License-Identifier: BSD-2-Clause
//! Part of the Processor Core used for managing memory.
//!
//! The [processor core](crate::core) contains the [`Mmu`]. The [`Mmu`] supports traditional mmu
//! behaviors using the [`TlbImpl`] however it also supports no-translation behavior with the
//! [`DummyTlb`].
use bitflags::bitflags;
use derive_more::Display;

pub mod helpers;
pub mod memory_region;
mod mmu;
mod mmu_sized_rw;
pub mod physical;
mod tlb;

pub use memory_region::{MemoryRegionData, MemoryRegionSize};
pub use mmu::{CodeMemoryOp, DataMemoryOp, Mmu, MmuOpError, SudoCodeMemoryOp, SudoDataMemoryOp};
pub use physical::{AddRegionError, FromConfigError, MemoryOperationError, UnmappedMemoryError};
pub use tlb::{DummyTlb, TLBError, TlbImpl};

/// Enum that is used to be explicit in error handling
/// of current memory operations
#[derive(Debug, Display, PartialEq, Eq, Clone, Copy)]
pub enum MemoryOperation {
    Read,
    Write,
}

bitflags! {
    #[repr(C)]
    #[derive(Default, Debug, PartialEq, Eq, PartialOrd, Ord, Copy, Clone)]
    pub struct MemoryPermissions : u32 {
        const READ = 1;
        const WRITE = 2;
        const EXEC = 4;
        const RW = Self::READ.bits() | Self::WRITE.bits();
        const RX = Self::READ.bits() | Self::EXEC.bits();
        const WX = Self::WRITE.bits() | Self::EXEC.bits();
    }
}

impl std::fmt::Display for MemoryPermissions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}{}{}",
            if self.contains(Self::READ) { "R" } else { "-" },
            if self.contains(Self::WRITE) { "W" } else { "-" },
            if self.contains(Self::EXEC) { "X" } else { "-" }
        )
    }
}
