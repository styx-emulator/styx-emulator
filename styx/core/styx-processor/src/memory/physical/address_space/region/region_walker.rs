// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
