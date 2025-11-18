// SPDX-License-Identifier: BSD-2-Clause
use crate::memory::{
    memory_region::MemoryRegion, physical::AtomicMemoryOperationError, MemoryOperationError,
};

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
///
/// An implementer of `RegionWalker` aims to perform an operation on a contiguous range of memory.
/// The `RegionWalker`'s user will call [`RegionWalker::single_walk()`] on 1+ segments of memory
/// within the contiguous range, until the whole range has been accessed.
pub trait RegionWalker {
    /// Error from walking regions AND doing the operation (reading, writing, etc).
    type Error;

    /// Perform an operation on a single segment of the whole range.
    ///
    /// `region` is the current [`MemoryRegion`] we are accessing.
    /// `start` and `size` are the address and size of the current segment.
    /// The `start` and `size` are guaranteed to be valid in the `region`.
    fn single_walk(
        &mut self,
        region: &MemoryRegion,
        start: u64,
        size: u64,
    ) -> Result<(), Self::Error>;
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
    type Error = MemoryOperationError;

    fn single_walk(
        &mut self,
        region: &MemoryRegion,
        start: u64,
        size: u64,
    ) -> Result<(), Self::Error> {
        region.read_data(
            start,
            &mut self.data[self.data_idx..self.data_idx + size as usize],
        )?;

        self.data_idx += size as usize;

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
    type Error = MemoryOperationError;

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
    type Error = MemoryOperationError;

    fn single_walk(
        &mut self,
        region: &MemoryRegion,
        start: u64,
        size: u64,
    ) -> Result<(), MemoryOperationError> {
        let read_data = region.read_data_unchecked_vec(start, size)?;
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
    type Error = MemoryOperationError;

    fn single_walk(
        &mut self,
        region: &MemoryRegion,
        start: u64,
        size: u64,
    ) -> Result<(), MemoryOperationError> {
        let size = size as usize;
        let to_write = &self.data[self.data_idx..self.data_idx + size];
        region.write_data_unchecked(start, to_write)?;
        self.data_idx += size;

        Ok(())
    }
}

pub struct AtomicMemoryReadRegionWalker<'a> {
    data: &'a mut [u8],
}
impl<'a> AtomicMemoryReadRegionWalker<'a> {
    pub fn new(data: &'a mut [u8]) -> Self {
        Self { data }
    }
}
impl RegionWalker for AtomicMemoryReadRegionWalker<'_> {
    type Error = AtomicMemoryOperationError;
    fn single_walk(
        &mut self,
        region: &MemoryRegion,
        start: u64,
        size: u64,
    ) -> Result<(), AtomicMemoryOperationError> {
        if size < self.data.len() as u64 {
            return Err(AtomicMemoryOperationError::StradlesRegions {
                address: start,
                size: size as usize,
            });
        }
        // this will always be true
        assert!(size == self.data.len() as u64);
        region.read_atomic(start, self.data)
    }
}
pub struct AtomicMemoryWriteRegionWalker<'a> {
    data: &'a [u8],
}
impl<'a> AtomicMemoryWriteRegionWalker<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data }
    }
}
impl RegionWalker for AtomicMemoryWriteRegionWalker<'_> {
    type Error = AtomicMemoryOperationError;
    fn single_walk(
        &mut self,
        region: &MemoryRegion,
        start: u64,
        size: u64,
    ) -> Result<(), AtomicMemoryOperationError> {
        if size < self.data.len() as u64 {
            return Err(AtomicMemoryOperationError::StradlesRegions {
                address: start,
                size: size as usize,
            });
        }
        // this will always be true
        assert!(size == self.data.len() as u64);
        region.write_atomic(start, self.data)
    }
}
