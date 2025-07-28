// SPDX-License-Identifier: BSD-2-Clause
use super::{
    helpers::{Readable, Writable},
    memory_region::{MemoryRegion, MemoryRegionView},
    physical::{MemoryBackend, PhysicalMemoryVariant},
    tlb::DummyTlb,
    AddRegionError, MemoryOperation, MemoryOperationError, MemoryPermissions, TlbImpl,
    TlbTranslateError,
};
use crate::{
    cpu::CpuBackend,
    event_controller::ExceptionNumber,
    memory::{physical::address_space::MemoryImpl, tlb::TlbProcessor, TlbTranslateResult},
};
use std::ops::Range;
use styx_errors::UnknownError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MmuOpError {
    #[error(transparent)]
    Other(#[from] UnknownError),
    #[error("encountered physical memory error")]
    PhysicalMemoryError(#[from] MemoryOperationError),
    #[error("TLB exception irq: {0:?}")]
    TlbException(ExceptionNumber),
}

impl From<TlbTranslateError> for MmuOpError {
    fn from(value: TlbTranslateError) -> Self {
        match value {
            TlbTranslateError::Exception(exception) => Self::TlbException(exception),
            TlbTranslateError::Other(error) => Self::Other(error),
        }
    }
}

/// A memory operation is either on Code or Data. Allows representing Harvard memory architectures.
pub enum MemoryType {
    Data,
    Code,
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
    pub tlb: Box<dyn TlbImpl>,
    pub memory: MemoryBackend,
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

    pub fn translate_va(
        &mut self,
        virtual_addr: u64,
        access_type: MemoryOperation,
        memory_type: MemoryType,
        cpu: &mut dyn CpuBackend,
    ) -> TlbTranslateResult {
        let mut processor = TlbProcessor::new(&mut self.memory, cpu);
        self.tlb
            .translate_va(virtual_addr, access_type, memory_type, &mut processor)
    }

    // PHYSICAL METHODS

    /// Write an array of bytes to data memory, the address will be interpreted as a physical address.
    pub fn write_data(&mut self, phys_addr: u64, bytes: &[u8]) -> Result<(), MemoryOperationError> {
        self.memory.write_data(phys_addr, bytes)
    }

    /// Read an array of bytes from data memory, the address will be interpreted as a physical address.
    pub fn read_data(
        &mut self,
        phys_addr: u64,
        bytes: &mut [u8],
    ) -> Result<(), MemoryOperationError> {
        self.memory.read_data(phys_addr, bytes)
    }

    /// Write an array of bytes to code memory, the address will be interpreted as a physical address.
    pub fn write_code(&mut self, phys_addr: u64, bytes: &[u8]) -> Result<(), MemoryOperationError> {
        self.memory.write_code(phys_addr, bytes)
    }

    /// Read an array of bytes from code memory, the address will be interpreted as a physical address.
    pub fn read_code(
        &mut self,
        phys_addr: u64,
        bytes: &mut [u8],
    ) -> Result<(), MemoryOperationError> {
        self.memory.read_code(phys_addr, bytes)
    }

    // VIRTUAL METHODS

    /// Write an array of bytes to data memory, the address will be interpreted as a virtual address.
    pub fn virt_write_data(
        &mut self,
        addr: u64,
        bytes: &[u8],
        cpu: &mut dyn CpuBackend,
    ) -> Result<(), MmuOpError> {
        let phys_addr = self.translate_va(addr, MemoryOperation::Write, MemoryType::Data, cpu)?;
        self.memory.write_data(phys_addr, bytes).map_err(Into::into)
    }

    /// Read an array of bytes from data memory, the address will be interpreted as a virtual
    /// address.
    pub fn virt_read_data(
        &mut self,
        addr: u64,
        bytes: &mut [u8],
        cpu: &mut dyn CpuBackend,
    ) -> Result<(), MmuOpError> {
        let phys_addr = self.translate_va(addr, MemoryOperation::Read, MemoryType::Data, cpu)?;
        self.memory.read_data(phys_addr, bytes).map_err(Into::into)
    }

    /// Write an array of bytes to code memory, the address will be interpreted as a virtual address.
    pub fn virt_write_code(
        &mut self,
        addr: u64,
        bytes: &[u8],
        cpu: &mut dyn CpuBackend,
    ) -> Result<(), MmuOpError> {
        let phys_addr = self.translate_va(addr, MemoryOperation::Write, MemoryType::Code, cpu)?;
        self.memory.write_code(phys_addr, bytes).map_err(Into::into)
    }

    /// Read an array of bytes from code memory, the address will be interpreted as a virtual address.
    pub fn virt_read_code(
        &mut self,
        addr: u64,
        bytes: &mut [u8],
        cpu: &mut dyn CpuBackend,
    ) -> Result<(), MmuOpError> {
        let phys_addr = self.translate_va(addr, MemoryOperation::Read, MemoryType::Code, cpu)?;
        self.memory.read_code(phys_addr, bytes).map_err(Into::into)
    }

    // SUDO METHODS

    /// Write to data without checking permissions
    pub fn sudo_write_data(
        &mut self,
        phys_addr: u64,
        bytes: &[u8],
    ) -> Result<(), MemoryOperationError> {
        self.memory.unchecked_write_data(phys_addr, bytes)
    }

    /// Read from data without checking permissions
    pub fn sudo_read_data(
        &mut self,
        phys_addr: u64,
        bytes: &mut [u8],
    ) -> Result<(), MemoryOperationError> {
        self.memory.unchecked_read_data(phys_addr, bytes)
    }

    /// Write to code without checking permissions
    pub fn sudo_write_code(
        &mut self,
        phys_addr: u64,
        bytes: &[u8],
    ) -> Result<(), MemoryOperationError> {
        self.memory.unchecked_write_code(phys_addr, bytes)
    }

    /// Read from code without checking permissions
    pub fn sudo_read_code(
        &mut self,
        phys_addr: u64,
        bytes: &mut [u8],
    ) -> Result<(), MemoryOperationError> {
        self.memory.unchecked_read_code(phys_addr, bytes)
    }

    /// Access data memory using the [memory helper api](crate::memory::helpers).
    ///
    /// Addresses given are physical addresses.
    ///
    /// ```
    /// # use styx_processor::{cpu::DummyBackend, memory::Mmu};
    /// # use styx_errors::UnknownError;
    /// // traits for ergonomic memory apis
    /// use styx_processor::memory::helpers::{ReadExt, WriteExt};
    ///
    /// # fn main() -> Result<(), UnknownError> {
    /// // using a new mmu here for testing, you would use a proper processor
    /// let mut mmu = Mmu::default();
    ///
    /// // write a 32 bit, little endian value to virtual address 0x1000
    /// // infer type
    /// mmu.data().write(0x1000).le().value(0x1337u32)?;
    /// // same thing but with a concrete type, if you prefer
    /// mmu.data().write(0x1000).le().u32(0x1337)?;
    ///
    /// // read back the 32 bit value, ensuring same endianess
    /// let value = mmu.data().read(0x1000).le().u32()?;
    /// // again, inferred type api available
    /// let value_2: u32 = mmu.data().read(0x1000).le().value()?;
    /// assert_eq!(value, 0x1337);
    /// assert_eq!(value_2, 0x1337);
    ///
    /// let mut bytes = [0u8; 8];
    /// // you can also do a traditional byte array read, this time 8 bytes starting at 0x1000
    /// mmu.data().read(0x1000).bytes(&mut bytes)?;
    /// assert_eq!(&bytes, &[0x37, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn data(&mut self) -> DataMemoryOp {
        DataMemoryOp(self)
    }

    /// Access code memory using the [memory helper api](crate::memory::helpers).
    ///
    /// Addresses given are physical addresses.
    ///
    /// ```
    /// # use styx_processor::{cpu::DummyBackend, memory::Mmu};
    /// # use styx_errors::UnknownError;
    /// // traits for ergonomic memory apis
    /// use styx_processor::memory::helpers::{ReadExt, WriteExt};
    ///
    /// # fn main() -> Result<(), UnknownError> {
    /// // using a new mmu here for testing, you would use a proper processor
    /// let mut mmu = Mmu::default();
    ///
    /// // write a 32 bit, little endian value to virtual address 0x1000
    /// // infer type
    /// mmu.code().write(0x1000).le().value(0x1337u32)?;
    /// // same thing but with a concrete type, if you prefer
    /// mmu.code().write(0x1000).le().u32(0x1337)?;
    ///
    /// // read back the 32 bit value, ensuring same endianess
    /// let value = mmu.code().read(0x1000).le().u32()?;
    /// // again, inferred type api available
    /// let value_2: u32 = mmu.code().read(0x1000).le().value()?;
    /// assert_eq!(value, 0x1337);
    /// assert_eq!(value_2, 0x1337);
    ///
    /// let mut bytes = [0u8; 8];
    /// // you can also do a traditional byte array read, this time 8 bytes starting at 0x1000
    /// mmu.code().read(0x1000).bytes(&mut bytes)?;
    /// assert_eq!(&bytes, &[0x37, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn code(&mut self) -> CodeMemoryOp {
        CodeMemoryOp(self)
    }

    /// Access virtual code memory using the [memory helper api](crate::memory::helpers).
    ///
    /// ```
    /// # use styx_processor::{cpu::DummyBackend, memory::Mmu};
    /// # use styx_errors::UnknownError;
    /// // traits for ergonomic memory apis
    /// use styx_processor::memory::helpers::{ReadExt, WriteExt};
    ///
    /// # fn main() -> Result<(), UnknownError> {
    /// // using dummy backend here for testing, you would use a proper processor
    /// let mut cpu = DummyBackend::default();
    /// let mut mmu = Mmu::default();
    ///
    /// // write a 32 bit, little endian value to virtual address 0x1000
    /// // infer type
    /// mmu.virt_code(&mut cpu).write(0x1000).le().value(0x1337u32)?;
    /// // same thing but with a concrete type, if you prefer
    /// mmu.virt_code(&mut cpu).write(0x1000).le().u32(0x1337)?;
    ///
    /// // read back the 32 bit value, ensuring same endianess
    /// let value = mmu.virt_code(&mut cpu).read(0x1000).le().u32()?;
    /// // again, inferred type api available
    /// let value_2: u32 = mmu.virt_code(&mut cpu).read(0x1000).le().value()?;
    /// assert_eq!(value, 0x1337);
    /// assert_eq!(value_2, 0x1337);
    ///
    /// let mut bytes = [0u8; 8];
    /// // you can also do a traditional byte array read, this time 8 bytes starting at 0x1000
    /// mmu.virt_code(&mut cpu).read(0x1000).bytes(&mut bytes)?;
    /// assert_eq!(&bytes, &[0x37, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn virt_code<'a>(&'a mut self, cpu: &'a mut dyn CpuBackend) -> VirtualCodeMemoryOp<'a> {
        VirtualCodeMemoryOp { cpu, mmu: self }
    }

    /// Access virtual data memory using the [memory helper api](crate::memory::helpers).
    ///
    /// ```
    /// # use styx_processor::{cpu::DummyBackend, memory::Mmu};
    /// # use styx_errors::UnknownError;
    /// // traits for ergonomic memory apis
    /// use styx_processor::memory::helpers::{ReadExt, WriteExt};
    ///
    /// # fn main() -> Result<(), UnknownError> {
    /// // using dummy backend here for testing, you would use a proper processor
    /// let mut cpu = DummyBackend::default();
    /// let mut mmu = Mmu::default();
    ///
    /// // write a 32 bit, little endian value to virtual address 0x1000
    /// // infer type
    /// mmu.virt_data(&mut cpu).write(0x1000).le().value(0x1337u32)?;
    /// // same thing but with a concrete type, if you prefer
    /// mmu.virt_data(&mut cpu).write(0x1000).le().u32(0x1337)?;
    ///
    /// // read back the 32 bit value, ensuring same endianess
    /// let value = mmu.virt_data(&mut cpu).read(0x1000).le().u32()?;
    /// // again, inferred type api available
    /// let value_2: u32 = mmu.virt_data(&mut cpu).read(0x1000).le().value()?;
    /// assert_eq!(value, 0x1337);
    /// assert_eq!(value_2, 0x1337);
    ///
    /// let mut bytes = [0u8; 8];
    /// // you can also do a traditional byte array read, this time 8 bytes starting at 0x1000
    /// mmu.virt_data(&mut cpu).read(0x1000).bytes(&mut bytes)?;
    /// assert_eq!(&bytes, &[0x37, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn virt_data<'a>(&'a mut self, cpu: &'a mut dyn CpuBackend) -> VirtualDataMemoryOp<'a> {
        VirtualDataMemoryOp { cpu, mmu: self }
    }

    /// Access data memory without permission checks using the [memory helper api](crate::memory::helpers).
    ///
    /// Addresses given are physical addresses.
    ///
    /// ```
    /// # use styx_processor::{cpu::DummyBackend, memory::Mmu};
    /// # use styx_errors::UnknownError;
    /// // traits for ergonomic memory apis
    /// use styx_processor::memory::helpers::{ReadExt, WriteExt};
    ///
    /// # fn main() -> Result<(), UnknownError> {
    /// // using a new mmu here for testing, you would use a proper processor
    /// let mut mmu = Mmu::default();
    ///
    /// // write a 32 bit, little endian value to virtual address 0x1000
    /// // infer type
    /// mmu.sudo_data().write(0x1000).le().value(0x1337u32)?;
    /// // same thing but with a concrete type, if you prefer
    /// mmu.sudo_data().write(0x1000).le().u32(0x1337)?;
    ///
    /// // read back the 32 bit value, ensuring same endianess
    /// let value = mmu.sudo_data().read(0x1000).le().u32()?;
    /// // again, inferred type api available
    /// let value_2: u32 = mmu.sudo_data().read(0x1000).le().value()?;
    /// assert_eq!(value, 0x1337);
    /// assert_eq!(value_2, 0x1337);
    ///
    /// let mut bytes = [0u8; 8];
    /// // you can also do a traditional byte array read, this time 8 bytes starting at 0x1000
    /// mmu.sudo_data().read(0x1000).bytes(&mut bytes)?;
    /// assert_eq!(&bytes, &[0x37, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn sudo_data(&mut self) -> SudoDataMemoryOp {
        SudoDataMemoryOp(self)
    }

    /// Access code memory without permission checks using the [memory helper api](crate::memory::helpers).
    ///
    /// Addresses given are physical addresses.
    ///
    /// ```
    /// # use styx_processor::{cpu::DummyBackend, memory::Mmu};
    /// # use styx_errors::UnknownError;
    /// // traits for ergonomic memory apis
    /// use styx_processor::memory::helpers::{ReadExt, WriteExt};
    ///
    /// # fn main() -> Result<(), UnknownError> {
    /// // using a new mmu here for testing, you would use a proper processor
    /// let mut mmu = Mmu::default();
    ///
    /// // write a 32 bit, little endian value to virtual address 0x1000
    /// // infer type
    /// mmu.sudo_code().write(0x1000).le().value(0x1337u32)?;
    /// // same thing but with a concrete type, if you prefer
    /// mmu.sudo_code().write(0x1000).le().u32(0x1337)?;
    ///
    /// // read back the 32 bit value, ensuring same endianess
    /// let value = mmu.sudo_code().read(0x1000).le().u32()?;
    /// // again, inferred type api available
    /// let value_2: u32 = mmu.sudo_code().read(0x1000).le().value()?;
    /// assert_eq!(value, 0x1337);
    /// assert_eq!(value_2, 0x1337);
    ///
    /// let mut bytes = [0u8; 8];
    /// // you can also do a traditional byte array read, this time 8 bytes starting at 0x1000
    /// mmu.sudo_code().read(0x1000).bytes(&mut bytes)?;
    /// assert_eq!(&bytes, &[0x37, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    /// # Ok(())
    /// # }
    /// ```
    pub fn sudo_code(&mut self) -> SudoCodeMemoryOp {
        SudoCodeMemoryOp(self)
    }
}

pub struct DataMemoryOp<'a>(&'a mut Mmu);
impl Readable for DataMemoryOp<'_> {
    type Error = MmuOpError;

    fn read_raw(&mut self, phys_addr: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.0
            .memory
            .read_data(phys_addr, bytes)
            .map_err(Into::into) // map phys memory error to mmu memory error
    }
}
impl Writable for DataMemoryOp<'_> {
    type Error = MmuOpError;

    fn write_raw(&mut self, phys_addr: u64, bytes: &[u8]) -> Result<(), Self::Error> {
        self.0
            .memory
            .write_data(phys_addr, bytes)
            .map_err(Into::into) // map phys memory error to mmu memory error
    }
}

pub struct CodeMemoryOp<'a>(&'a mut Mmu);
impl Readable for CodeMemoryOp<'_> {
    type Error = MmuOpError;

    fn read_raw(&mut self, phys_addr: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.0
            .memory
            .read_code(phys_addr, bytes)
            .map_err(Into::into) // map phys memory error to mmu memory error
    }
}
impl Writable for CodeMemoryOp<'_> {
    type Error = MmuOpError;

    fn write_raw(&mut self, phys_addr: u64, bytes: &[u8]) -> Result<(), Self::Error> {
        self.0
            .memory
            .write_code(phys_addr, bytes)
            .map_err(Into::into) // map phys memory error to mmu memory error
    }
}

pub struct VirtualCodeMemoryOp<'a> {
    mmu: &'a mut Mmu,
    cpu: &'a mut dyn CpuBackend,
}
impl Readable for VirtualCodeMemoryOp<'_> {
    type Error = MmuOpError;

    fn read_raw(&mut self, virtual_addr: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
        let phys_addr = self.mmu.translate_va(
            virtual_addr,
            MemoryOperation::Read,
            MemoryType::Code,
            self.cpu,
        )?;

        self.mmu
            .memory
            .read_code(phys_addr, bytes)
            .map_err(Into::into) // map phys memory error to mmu memory error
    }
}
impl Writable for VirtualCodeMemoryOp<'_> {
    type Error = MmuOpError;

    fn write_raw(&mut self, virtual_addr: u64, bytes: &[u8]) -> Result<(), Self::Error> {
        let phys_addr = self.mmu.translate_va(
            virtual_addr,
            MemoryOperation::Write,
            MemoryType::Code,
            self.cpu,
        )?;

        self.mmu
            .memory
            .write_code(phys_addr, bytes)
            .map_err(Into::into) // map phys memory error to mmu memory error
    }
}

pub struct VirtualDataMemoryOp<'a> {
    mmu: &'a mut Mmu,
    cpu: &'a mut dyn CpuBackend,
}
impl Readable for VirtualDataMemoryOp<'_> {
    type Error = MmuOpError;

    fn read_raw(&mut self, virtual_addr: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
        let phys_addr = self.mmu.translate_va(
            virtual_addr,
            MemoryOperation::Read,
            MemoryType::Data,
            self.cpu,
        )?;

        self.mmu
            .memory
            .read_data(phys_addr, bytes)
            .map_err(Into::into) // map phys memory error to mmu memory error
    }
}
impl Writable for VirtualDataMemoryOp<'_> {
    type Error = MmuOpError;

    fn write_raw(&mut self, virtual_addr: u64, bytes: &[u8]) -> Result<(), Self::Error> {
        let phys_addr = self.mmu.translate_va(
            virtual_addr,
            MemoryOperation::Write,
            MemoryType::Data,
            self.cpu,
        )?;

        self.mmu
            .memory
            .write_data(phys_addr, bytes)
            .map_err(Into::into) // map phys memory error to mmu memory error
    }
}

pub struct SudoDataMemoryOp<'a>(&'a mut Mmu);
impl Readable for SudoDataMemoryOp<'_> {
    type Error = MmuOpError;

    fn read_raw(&mut self, phys_addr: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.0
            .memory
            .unchecked_read_data(phys_addr, bytes)
            .map_err(Into::into) // map phys memory error to mmu memory error
    }
}
impl Writable for SudoDataMemoryOp<'_> {
    type Error = MmuOpError;

    fn write_raw(&mut self, phys_addr: u64, bytes: &[u8]) -> Result<(), Self::Error> {
        self.0
            .memory
            .unchecked_write_data(phys_addr, bytes)
            .map_err(Into::into) // map phys memory error to mmu memory error
    }
}

pub struct SudoCodeMemoryOp<'a>(&'a mut Mmu);
impl Readable for SudoCodeMemoryOp<'_> {
    type Error = MmuOpError;

    fn read_raw(&mut self, phys_addr: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.0
            .memory
            .unchecked_read_code(phys_addr, bytes)
            .map_err(Into::into) // map phys memory error to mmu memory error
    }
}
impl Writable for SudoCodeMemoryOp<'_> {
    type Error = MmuOpError;

    fn write_raw(&mut self, phys_addr: u64, bytes: &[u8]) -> Result<(), Self::Error> {
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
        mmu.write_u32_le_phys_data(0x100, 0xdeadbeef).unwrap();
        let data = mmu.data().read(0x100).le().u32().unwrap();
        assert_eq!(data, 0xdeadbeef)
    }

    #[test]
    fn test_big_endian() {
        let mut mmu = Mmu::default();
        mmu.write_u32_be_phys_data(0x100, 0xdeadbeef).unwrap();
        let data = mmu.data().read(0x100).be().u32().unwrap();
        assert_eq!(data, 0xdeadbeef)
    }

    // todo add tests for virtual addressing once we make a TLB
}
