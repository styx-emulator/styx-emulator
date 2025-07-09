// SPDX-License-Identifier: BSD-2-Clause
mod blob;
mod harvard;
mod region;

pub use blob::FlatMemory;
use enum_dispatch::enum_dispatch;
pub use harvard::HarvardStore;
pub use region::RegionStore;
use styx_errors::{anyhow::anyhow, UnknownError};

use crate::memory::memory_region::MemoryRegion;

use super::{AddRegionError, FromConfigError, MemoryOperationError, MemoryRegionDescriptor, Space};

pub trait FromYaml {
    /// Create a new address space from a set of memory region descriptors
    fn from_config(config: Vec<MemoryRegionDescriptor>) -> Result<Self, FromConfigError>
    where
        Self: Sized;
}

/// A physical memory implementation needs to implement functions for reading and writing
/// memory, with a logical split between code and data memory.
///
/// Unchecked read and write functions have default implementations which just
/// call the respective normal read/write functions.  If needed, the implementation
/// of these functions should ignore permission checks.
///
/// Reading or writing out of bounds should always cause an appropriate error.
#[enum_dispatch]
pub trait MemoryImpl {
    /// Returns the minimum address represented in this space
    fn min_address(&self, _space: Option<Space>) -> u64 {
        0
    }

    /// Returns the maximum address represented in this space
    fn max_address(&self, _space: Option<Space>) -> u64 {
        u64::MAX
    }

    /// Add a new region to the address space
    fn add_region(&mut self, _region: MemoryRegion) -> Result<(), AddRegionError> {
        Err(AddRegionError::UnsupportedAddressSpaceOperation)
    }

    /// Reads a contiguous array of code bytes to the buffer `data` starting from `addr`.
    fn read_code(&self, addr: u64, bytes: &mut [u8]) -> Result<(), MemoryOperationError> {
        self.unchecked_read_code(addr, bytes)
    }

    /// Reads a contiguous array of data bytes to the buffer `data` starting from `addr`.
    fn read_data(&self, addr: u64, bytes: &mut [u8]) -> Result<(), MemoryOperationError> {
        self.unchecked_read_data(addr, bytes)
    }

    /// Writes a contiguous array of bytes from the buffer `data` into code memory, starting at `addr`.
    fn write_code(&mut self, addr: u64, bytes: &[u8]) -> Result<(), MemoryOperationError> {
        self.unchecked_write_code(addr, bytes)
    }

    /// Writes a contiguous array of bytes from the buffer `data` into data memory, starting at `addr`.
    fn write_data(&mut self, addr: u64, bytes: &[u8]) -> Result<(), MemoryOperationError> {
        self.unchecked_write_data(addr, bytes)
    }

    /// Reads a contiguous array of code bytes to the buffer `data` starting from `addr`.
    ///
    /// Ignores memory permissions imposed by the physical memory backend.
    fn unchecked_read_code(&self, addr: u64, bytes: &mut [u8]) -> Result<(), MemoryOperationError>;

    /// Reads a contiguous array of data bytes to the buffer `data` starting from `addr`.
    ///
    /// Ignores memory permissions imposed by the physical memory backend.
    fn unchecked_read_data(&self, addr: u64, bytes: &mut [u8]) -> Result<(), MemoryOperationError>;

    /// Writes a contiguous array of bytes from the buffer `data` into code memory, starting at `addr`.
    ///
    /// Ignores memory permissions imposed by the physical memory backend.
    fn unchecked_write_code(&mut self, addr: u64, bytes: &[u8])
        -> Result<(), MemoryOperationError>;

    /// Writes a contiguous array of bytes from the buffer `data` into data memory, starting at `addr`.
    ///
    /// Ignores memory permissions imposed by the physical memory backend.
    fn unchecked_write_data(&mut self, addr: u64, bytes: &[u8])
        -> Result<(), MemoryOperationError>;

    /// Save the current memory state
    ///
    /// Holding multiple saved states is not supported.  Saving memory state will overwrite any previously saved state.
    fn context_save(&mut self) -> Result<(), UnknownError> {
        Err(anyhow!(
            "memory implementation doesn't support save/restore"
        ))
    }

    /// Restore a previously saved memory state
    ///
    /// This will error if no saved state exists.
    fn context_restore(&mut self) -> Result<(), UnknownError> {
        Err(anyhow!(
            "memory implementation doesn't support save/restore"
        ))
    }
}
