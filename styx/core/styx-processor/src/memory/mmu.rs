// SPDX-License-Identifier: BSD-2-Clause
use super::{
    helpers::{Readable, Writable},
    memory_region::{MemoryRegion, MemoryRegionView},
    physical::{MemoryBackend, PhysicalMemoryVariant},
    tlb::DummyTlb,
    AddRegionError, MemoryOperation, MemoryOperationError, MemoryPermissions, TLBError, TlbImpl,
};
use crate::memory::physical::address_space::MemoryImpl;
use crate::{cpu::CpuBackend, event_controller::ExceptionNumber};
use std::ops::Range;
use styx_errors::UnknownError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MmuOpError {
    #[error(transparent)]
    Other(#[from] UnknownError),
    #[error("encountered physical memory error")]
    PhysicalMemoryError(#[from] MemoryOperationError),
    #[error("tlb exception")]
    TlbException(Option<ExceptionNumber>),
}

impl From<TLBError> for MmuOpError {
    fn from(value: TLBError) -> Self {
        match value {
            TLBError::TlbException(exception) => Self::TlbException(exception),
            TLBError::Other(error) => Self::Other(error),
        }
    }
}

/// The MMU owns the processor specific TLB implementation and the physical memory backend. It is
/// the single point where all memory transactions flow through.
///
/// Default implementation for testing purposes uses [`PhysicalMemoryVariant::FlatMemory`] and
/// [`DummyTlb`].
///
/// For a processor ready default use [`Mmu::default_region_store()`].
///
/// Access physical memory using [`Mmu::memory()`].
pub struct Mmu {
    pub(crate) tlb: Box<dyn TlbImpl>,
    pub(crate) memory: MemoryBackend,
}

impl Default for Mmu {
    fn default() -> Self {
        // OKAY to subvert ::new() because DummyTlb has noop init.
        Mmu {
            tlb: Box::new(DummyTlb),
            memory: MemoryBackend::new(PhysicalMemoryVariant::FlatMemory),
        }
    }
}

impl Mmu {
    /// Takes uninitialized tlb and creates mmu and inits `tlb`.
    pub fn new(
        mut tlb: Box<dyn TlbImpl>,
        memory: PhysicalMemoryVariant,
        cpu: &mut dyn CpuBackend,
    ) -> Result<Self, UnknownError> {
        tlb.init(cpu)?;
        Ok(Self {
            tlb,
            memory: MemoryBackend::new(memory),
        })
    }

    /// Constructs the [`Mmu`] with the default physical memory backend.
    pub fn from_impl(tlb: Box<dyn TlbImpl>) -> Self {
        Self {
            tlb,
            memory: MemoryBackend::default(),
        }
    }

    /// Constructs the [`Mmu`] with a [`DummyTlb`] and a [`PhysicalMemoryVariant::RegionStore`].
    pub fn default_region_store() -> Self {
        // OKAY to subvert ::new() because DummyTlb has noop init.
        Mmu {
            tlb: Box::new(DummyTlb),
            memory: MemoryBackend::new(PhysicalMemoryVariant::RegionStore),
        }
    }

    /// Returns a mutable reference to the physical memory backend.  Useful
    /// if you want to read/write memory without involving the Tlb.
    pub fn memory(&mut self) -> &mut MemoryBackend {
        &mut self.memory
    }

    /// Returns the range made up of the min and max addresses supported
    /// by the physical memory backend.
    pub fn valid_memory_range(&self) -> Range<u64> {
        self.memory.min_address(None)..self.memory.max_address(None)
    }

    /// Create a new memory region on the backend.
    ///
    /// Notes: Not all backends support adding regions.
    pub fn memory_map(
        &mut self,
        base: u64,
        size: u64,
        perms: MemoryPermissions,
    ) -> Result<(), AddRegionError> {
        self.add_memory_region(MemoryRegion::new(base, size, perms)?)
    }

    /// Adds a pre-populated MemoryRegion to emulator memory map.
    pub fn add_memory_region(&mut self, region: MemoryRegion) -> Result<(), AddRegionError> {
        self.memory.add_region(region)
    }

    /// Returns an iterator over the regions contained in the underlying physical memory backend.
    ///
    /// Notes: The return type is an `Option` because iterating over memory regions is not always
    /// a definable operation.
    pub fn regions(&mut self) -> Option<impl Iterator<Item = MemoryRegionView>> {
        let rtn: Option<Box<dyn Iterator<Item = MemoryRegionView>>> = match self.memory() {
            MemoryBackend::HarvardFlatMemory(_) => None,
            MemoryBackend::FlatMemory(flat_memory) => Some(Box::new(
                [flat_memory].into_iter().map(MemoryRegionView::from),
            )),
            MemoryBackend::RegionStore(region_store) => Some(Box::new(
                region_store.regions.iter_mut().map(MemoryRegionView::from),
            )),
        };
        rtn
    }

    /// Write an array of bytes to data memory, the address will be interpreted as a virtual address.
    pub fn write_data(&mut self, addr: u64, bytes: &[u8]) -> Result<(), MmuOpError> {
        let phys_addr = self.tlb.translate_va_data(addr, MemoryOperation::Write)?;
        self.memory.write_data(phys_addr, bytes).map_err(Into::into) // map phys memory error to mmu memory error
    }

    /// Read an array of bytes from data memory, the address will be interpreted as a virtual address.
    pub fn read_data(&mut self, addr: u64, bytes: &mut [u8]) -> Result<(), MmuOpError> {
        let phys_addr = self.tlb.translate_va_data(addr, MemoryOperation::Read)?;
        self.memory.read_data(phys_addr, bytes).map_err(Into::into) // map phys memory error to mmu memory error
    }

    /// Write an array of bytes to code memory, the address will be interpreted as a virtual address.
    pub fn write_code(&mut self, addr: u64, bytes: &[u8]) -> Result<(), MmuOpError> {
        let phys_addr = self.tlb.translate_va_code(addr)?;
        self.memory.write_code(phys_addr, bytes).map_err(Into::into) // map phys memory error to mmu memory error
    }

    /// Read an array of bytes from code memory, the address will be interpreted as a virtual address.
    pub fn read_code(&mut self, addr: u64, bytes: &mut [u8]) -> Result<(), MmuOpError> {
        let phys_addr = self.tlb.translate_va_code(addr)?;
        self.memory.read_code(phys_addr, bytes).map_err(Into::into) // map phys memory error to mmu memory error
    }

    /// Write to data without checking permissions
    pub fn sudo_write_data(&mut self, addr: u64, bytes: &[u8]) -> Result<(), MmuOpError> {
        let phys_addr = self.tlb.translate_va_data(addr, MemoryOperation::Write)?;
        self.memory
            .unchecked_write_data(phys_addr, bytes)
            .map_err(Into::into) // map phys memory error to mmu memory error
    }

    /// Read from data without checking permissions
    pub fn sudo_read_data(&mut self, addr: u64, bytes: &mut [u8]) -> Result<(), MmuOpError> {
        let phys_addr = self.tlb.translate_va_data(addr, MemoryOperation::Read)?;
        self.memory
            .unchecked_read_data(phys_addr, bytes)
            .map_err(Into::into) // map phys memory error to mmu memory error
    }

    /// Write to code without checking permissions
    pub fn sudo_write_code(&mut self, addr: u64, bytes: &[u8]) -> Result<(), MmuOpError> {
        let phys_addr = self.tlb.translate_va_code(addr)?;
        self.memory
            .unchecked_write_code(phys_addr, bytes)
            .map_err(Into::into) // map phys memory error to mmu memory error
    }

    /// Read from code without checking permissions
    pub fn sudo_read_code(&mut self, addr: u64, bytes: &mut [u8]) -> Result<(), MmuOpError> {
        let phys_addr = self.tlb.translate_va_code(addr)?;
        self.memory
            .unchecked_read_code(phys_addr, bytes)
            .map_err(Into::into) // map phys memory error to mmu memory error
    }

    /// Access data memory using the [memory helper api](crate::memory::helpers).
    pub fn data(&mut self) -> DataMemoryOp {
        DataMemoryOp(self)
    }

    /// Access code memory using the [memory helper api](crate::memory::helpers).
    pub fn code(&mut self) -> CodeMemoryOp {
        CodeMemoryOp(self)
    }

    /// Access data memory without permission checks using the [memory helper api](crate::memory::helpers).
    pub fn sudo_data(&mut self) -> SudoDataMemoryOp {
        SudoDataMemoryOp(self)
    }

    /// Access code memory without permission checks using the [memory helper api](crate::memory::helpers).
    pub fn sudo_code(&mut self) -> SudoCodeMemoryOp {
        SudoCodeMemoryOp(self)
    }
}

pub struct DataMemoryOp<'a>(&'a mut Mmu);
impl Readable for DataMemoryOp<'_> {
    type Error = MmuOpError;

    fn read_raw(&mut self, addr: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
        let phys_addr = self.0.tlb.translate_va_data(addr, MemoryOperation::Read)?;
        self.0
            .memory
            .read_data(phys_addr, bytes)
            .map_err(Into::into) // map phys memory error to mmu memory error
    }
}
impl Writable for DataMemoryOp<'_> {
    type Error = MmuOpError;

    fn write_raw(&mut self, addr: u64, bytes: &[u8]) -> Result<(), Self::Error> {
        let phys_addr = self.0.tlb.translate_va_data(addr, MemoryOperation::Write)?;
        self.0
            .memory
            .write_data(phys_addr, bytes)
            .map_err(Into::into) // map phys memory error to mmu memory error
    }
}

pub struct CodeMemoryOp<'a>(&'a mut Mmu);
impl Readable for CodeMemoryOp<'_> {
    type Error = MmuOpError;

    fn read_raw(&mut self, addr: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
        let phys_addr = self.0.tlb.translate_va_code(addr)?;
        self.0
            .memory
            .read_code(phys_addr, bytes)
            .map_err(Into::into) // map phys memory error to mmu memory error
    }
}
impl Writable for CodeMemoryOp<'_> {
    type Error = MmuOpError;

    fn write_raw(&mut self, addr: u64, bytes: &[u8]) -> Result<(), Self::Error> {
        let phys_addr = self.0.tlb.translate_va_code(addr)?;
        self.0
            .memory
            .write_code(phys_addr, bytes)
            .map_err(Into::into) // map phys memory error to mmu memory error
    }
}

pub struct SudoDataMemoryOp<'a>(&'a mut Mmu);
impl Readable for SudoDataMemoryOp<'_> {
    type Error = MmuOpError;

    fn read_raw(&mut self, addr: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
        let phys_addr = self.0.tlb.translate_va_data(addr, MemoryOperation::Read)?;
        self.0
            .memory
            .unchecked_read_data(phys_addr, bytes)
            .map_err(Into::into) // map phys memory error to mmu memory error
    }
}
impl Writable for SudoDataMemoryOp<'_> {
    type Error = MmuOpError;

    fn write_raw(&mut self, addr: u64, bytes: &[u8]) -> Result<(), Self::Error> {
        let phys_addr = self.0.tlb.translate_va_data(addr, MemoryOperation::Write)?;
        self.0
            .memory
            .unchecked_write_data(phys_addr, bytes)
            .map_err(Into::into) // map phys memory error to mmu memory error
    }
}

pub struct SudoCodeMemoryOp<'a>(&'a mut Mmu);
impl Readable for SudoCodeMemoryOp<'_> {
    type Error = MmuOpError;

    fn read_raw(&mut self, addr: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
        let phys_addr = self.0.tlb.translate_va_code(addr)?;
        self.0
            .memory
            .unchecked_read_code(phys_addr, bytes)
            .map_err(Into::into) // map phys memory error to mmu memory error
    }
}
impl Writable for SudoCodeMemoryOp<'_> {
    type Error = MmuOpError;

    fn write_raw(&mut self, addr: u64, bytes: &[u8]) -> Result<(), Self::Error> {
        let phys_addr = self.0.tlb.translate_va_code(addr)?;
        self.0
            .memory
            .unchecked_write_code(phys_addr, bytes)
            .map_err(Into::into) // map phys memory error to mmu memory error
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::helpers::*;

    #[test]
    fn test_simple() {
        let mut mmu = Mmu::default();
        mmu.write_u32_le_virt_data(0x100, 0xdeadbeef).unwrap();
        let data = mmu.data().read(0x100).le().u32().unwrap();
        assert_eq!(data, 0xdeadbeef)
    }

    #[test]
    fn test_big_endian() {
        let mut mmu = Mmu::default();
        mmu.write_u32_be_virt_data(0x100, 0xdeadbeef).unwrap();
        let data = mmu.data().read(0x100).be().u32().unwrap();
        assert_eq!(data, 0xdeadbeef)
    }

    // todo add tests for virtual addressing once we make a TLB
}
