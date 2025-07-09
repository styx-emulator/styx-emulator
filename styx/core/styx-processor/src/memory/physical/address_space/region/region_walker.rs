// SPDX-License-Identifier: BSD-2-Clause
use crate::memory::{memory_region::MemoryRegion, MemoryOperationError};

/// small enum used to keep track of state during region walk search
#[derive(PartialEq, Eq, PartialOrd, Ord, Default, Clone, Copy)]
pub enum SearchState {
    #[default]
    Start,
    /// Base found with last_address
    BaseFound(u64),
    Done,
}

/// Trait for implementing a struct to walk regions of an address range.
pub trait RegionWalker {
    fn single_walk(
        &mut self,
        region: &MemoryRegion,
        start: u64,
        size: u64,
    ) -> Result<(), MemoryOperationError>;
}

/// [RegionWalker] for reading a section of memory.
pub struct MemoryReadRegionWalker<'a> {
    data: &'a mut [u8],
    data_idx: usize,
}
impl<'a> MemoryReadRegionWalker<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data, data_idx: 0 }
    }
}
impl RegionWalker for MemoryReadRegionWalker<'_> {
    fn single_walk(
        &mut self,
        region: &MemoryRegion,
        start: u64,
        size: u64,
    ) -> Result<(), MemoryOperationError> {
        let read_data = region.read_data(start, size)?;
        self.data[self.data_idx..self.data_idx + read_data.len()].copy_from_slice(&read_data);
        self.data_idx += read_data.len();

        Ok(())
    }
}

/// [RegionWalker] for writing a section of memory.
pub struct MemoryWriteRegionWalker<'a> {
    /// Data to write to memory.
    data: &'a [u8],
    /// Current index into [Self::data].
    data_idx: usize,
}
impl<'a> MemoryWriteRegionWalker<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, data_idx: 0 }
    }
}
impl RegionWalker for MemoryWriteRegionWalker<'_> {
    fn single_walk(
        &mut self,
        region: &MemoryRegion,
        start: u64,
        size: u64,
    ) -> Result<(), MemoryOperationError> {
        let size = size as usize;
        let to_write = &self.data[self.data_idx..self.data_idx + size];
        region.write_data(start, to_write)?;
        self.data_idx += size;

        Ok(())
    }
}

pub struct UncheckedMemoryReadRegionWalker<'a> {
    data: &'a mut [u8],
    data_idx: usize,
}
impl<'a> UncheckedMemoryReadRegionWalker<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data, data_idx: 0 }
    }
}
impl RegionWalker for UncheckedMemoryReadRegionWalker<'_> {
    fn single_walk(
        &mut self,
        region: &MemoryRegion,
        start: u64,
        size: u64,
    ) -> Result<(), MemoryOperationError> {
        let read_data = unsafe { region.read_data_unchecked(start, size) }?;
        self.data[self.data_idx..self.data_idx + read_data.len()].copy_from_slice(&read_data);
        self.data_idx += read_data.len();

        Ok(())
    }
}

/// [RegionWalker] for writing a section of memory.
pub struct UncheckedMemoryWriteRegionWalker<'a> {
    /// Data to write to memory.
    data: &'a [u8],
    /// Current index into [Self::data].
    data_idx: usize,
}
impl<'a> UncheckedMemoryWriteRegionWalker<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, data_idx: 0 }
    }
}
impl RegionWalker for UncheckedMemoryWriteRegionWalker<'_> {
    fn single_walk(
        &mut self,
        region: &MemoryRegion,
        start: u64,
        size: u64,
    ) -> Result<(), MemoryOperationError> {
        let size = size as usize;
        let to_write = &self.data[self.data_idx..self.data_idx + size];
        unsafe { region.write_data_unchecked(start, to_write) }?;
        self.data_idx += size;

        Ok(())
    }
}
