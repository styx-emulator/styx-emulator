// SPDX-License-Identifier: BSD-2-Clause
//! TODO: add some kind of dirty page tracking thing so we can reasonably support saving/restoring memory.
use crate::memory::{
    physical::{MemoryRegionDescriptor, Space, UnmappedMemoryError},
    FromConfigError, MemoryOperationError,
};

use super::{FromYaml, MemoryImpl};

/// A single flat memory space for each code and data.
///
/// Each region is defined by a base address and an offset.
///
/// No memory permissions, everything is RWX.
pub struct HarvardStore {
    code_base: u64,
    data_base: u64,
    code_mem: Box<[u8]>,
    data_mem: Box<[u8]>,
    code_end: u64,
    data_end: u64,
}

impl FromYaml for HarvardStore {
    fn from_config(
        config: Vec<crate::memory::physical::MemoryRegionDescriptor>,
    ) -> Result<Self, FromConfigError> {
        let mut code_region_opt: Option<&MemoryRegionDescriptor> = None;
        let mut data_region_opt: Option<&MemoryRegionDescriptor> = None;
        for r in &config {
            if r.space == Space::Code {
                code_region_opt = Some(r);
            } else if r.space == Space::Data {
                data_region_opt = Some(r);
            }
        }

        if code_region_opt.is_none() {
            return Err(FromConfigError::YamlContentsError);
        }
        if data_region_opt.is_none() {
            return Err(FromConfigError::YamlContentsError);
        }

        let code_region = code_region_opt.unwrap();
        let data_region = data_region_opt.unwrap();

        Ok(Self {
            code_base: code_region.base,
            data_base: data_region.base,
            code_mem: vec![0; code_region.size as usize].into_boxed_slice(),
            data_mem: vec![0; data_region.size as usize].into_boxed_slice(),
            code_end: code_region.base + code_region.size,
            data_end: data_region.base + data_region.size,
        })
    }
}

impl Default for HarvardStore {
    /// The memory layout of the ATTiny10.
    ///
    /// 1024 byte code memory, 32 byte data memory
    fn default() -> Self {
        Self {
            code_base: 0,
            data_base: 0,
            code_mem: vec![0; 1024].into_boxed_slice(),
            data_mem: vec![0; 32].into_boxed_slice(),
            code_end: 1024,
            data_end: 32,
        }
    }
}

impl MemoryImpl for HarvardStore {
    fn min_address(&self, space: Option<Space>) -> u64 {
        if let Some(s) = space {
            match s {
                Space::Code => self.code_base,
                Space::Data => self.data_base,
            }
        } else {
            0
        }
    }

    fn max_address(&self, space: Option<Space>) -> u64 {
        if let Some(s) = space {
            match s {
                Space::Code => self.code_end,
                Space::Data => self.data_end,
            }
        } else {
            0
        }
    }

    fn unchecked_read_code(&self, addr: u64, bytes: &mut [u8]) -> Result<(), MemoryOperationError> {
        // check for out of bounds
        if addr < self.code_base || addr >= self.code_end {
            return Err(MemoryOperationError::UnmappedMemory(
                UnmappedMemoryError::UnmappedStart(addr),
            ));
        }

        // adjust address for base offset
        let addr = (addr - self.code_base) as usize;

        bytes.copy_from_slice(&self.code_mem[addr..(addr + bytes.len())]);
        Ok(())
    }

    fn unchecked_read_data(&self, addr: u64, bytes: &mut [u8]) -> Result<(), MemoryOperationError> {
        // check for out of bounds
        if addr < self.data_base || addr >= self.data_end {
            return Err(MemoryOperationError::UnmappedMemory(
                UnmappedMemoryError::UnmappedStart(addr),
            ));
        }

        // adjust address for base offset
        let addr = (addr - self.data_base) as usize;

        bytes.copy_from_slice(&self.data_mem[addr..(addr + bytes.len())]);
        Ok(())
    }

    fn unchecked_write_code(
        &mut self,
        addr: u64,
        bytes: &[u8],
    ) -> Result<(), MemoryOperationError> {
        // check for out of bounds
        if addr < self.code_base || addr >= self.code_end {
            return Err(MemoryOperationError::UnmappedMemory(
                UnmappedMemoryError::UnmappedStart(addr),
            ));
        }

        // adjust address for base offset
        let addr = (addr - self.code_base) as usize;

        let self_slice = &mut self.code_mem[addr..(addr + bytes.len())];
        self_slice.copy_from_slice(bytes);
        Ok(())
    }

    fn unchecked_write_data(
        &mut self,
        addr: u64,
        bytes: &[u8],
    ) -> Result<(), MemoryOperationError> {
        // check for out of bounds
        if addr < self.data_base || addr >= self.data_end {
            return Err(MemoryOperationError::UnmappedMemory(
                UnmappedMemoryError::UnmappedStart(addr),
            ));
        }

        // adjust address for base offset
        let addr = (addr - self.data_base) as usize;

        let self_slice = &mut self.data_mem[addr..(addr + bytes.len())];
        self_slice.copy_from_slice(bytes);
        Ok(())
    }
}
