// SPDX-License-Identifier: BSD-2-Clause
//! TODO: add some kind of dirty page tracking thing so we can reasonably support saving/restoring memory.
use crate::memory::{
    memory_region::MemoryRegionView, physical::UnmappedMemoryError, FromConfigError,
    MemoryOperationError, MemoryPermissions, MemoryRegionData, MemoryRegionSize,
};

use super::{FromYaml, MemoryImpl};

impl MemoryRegionSize for FlatMemory {
    fn base(&self) -> u64 {
        self.base
    }

    fn size(&self) -> u64 {
        self.end - self.base
    }
}

impl MemoryRegionData for FlatMemory {
    fn data(&self) -> &[u8] {
        &self.bytes
    }

    fn data_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }
}

impl<'a> From<&'a mut FlatMemory> for MemoryRegionView<'a> {
    fn from(value: &'a mut FlatMemory) -> Self {
        MemoryRegionView {
            base: value.base,
            perms: MemoryPermissions::all(),
            data: &mut value.bytes,
        }
    }
}

/// A single flat address space defined by a base address and a size.
///
/// No memory permissions, everything is RWX
pub struct FlatMemory {
    base: u64,
    end: u64,
    bytes: Box<[u8]>,
}

impl Default for FlatMemory {
    fn default() -> Self {
        // additional offset of 0x1001 is to make the 'page' 4k aligned so that unicorn doesn't complain
        let end = (u32::MAX as u64) + 0x1001;
        Self {
            base: 0,
            end,
            bytes: vec![0; end as usize].into(),
        }
    }
}

impl FromYaml for FlatMemory {
    fn from_config(
        config: Vec<crate::memory::physical::MemoryRegionDescriptor>,
    ) -> Result<FlatMemory, FromConfigError> {
        let region = &config[0];

        Ok(Self {
            base: region.base,
            bytes: vec![0; region.size as usize].into_boxed_slice(),
            end: region.base + region.size,
        })
    }
}

impl MemoryImpl for FlatMemory {
    fn min_address(&self, _space: Option<crate::memory::physical::Space>) -> u64 {
        self.base
    }

    fn max_address(&self, _space: Option<crate::memory::physical::Space>) -> u64 {
        self.end
    }

    fn write_data(&mut self, addr: u64, bytes: &[u8]) -> Result<(), MemoryOperationError> {
        // no distinction between code and data here
        self.write_code(addr, bytes)
    }

    fn unchecked_read_code(&self, addr: u64, bytes: &mut [u8]) -> Result<(), MemoryOperationError> {
        // check for out of bounds
        if addr < self.base || addr >= self.end {
            return Err(MemoryOperationError::UnmappedMemory(
                UnmappedMemoryError::UnmappedStart(addr),
            ));
        }

        // convert address into array index
        let addr = (addr - self.base) as usize;

        bytes.copy_from_slice(&self.bytes[addr..(addr + bytes.len())]);
        Ok(())
    }

    fn unchecked_read_data(&self, addr: u64, bytes: &mut [u8]) -> Result<(), MemoryOperationError> {
        // no distinction between code and data here
        self.unchecked_read_code(addr, bytes)
    }

    fn unchecked_write_code(
        &mut self,
        addr: u64,
        bytes: &[u8],
    ) -> Result<(), MemoryOperationError> {
        // check for out of bounds
        if addr < self.base || addr >= self.end {
            return Err(MemoryOperationError::UnmappedMemory(
                UnmappedMemoryError::UnmappedStart(addr),
            ));
        }

        // convert address into array index
        let addr = (addr - self.base) as usize;

        let self_slice = &mut self.bytes[addr..(addr + bytes.len())];
        self_slice.copy_from_slice(bytes);
        Ok(())
    }

    fn unchecked_write_data(
        &mut self,
        addr: u64,
        bytes: &[u8],
    ) -> Result<(), MemoryOperationError> {
        // no distinction between code and data here
        self.unchecked_write_code(addr, bytes)
    }
}
