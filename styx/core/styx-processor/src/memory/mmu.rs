// SPDX-License-Identifier: BSD-2-Clause
use super::{
    helpers::{Readable, Writable},
    memory_region::{HasRegions, MemoryRegion},
    physical::{MemoryBackend, PhysicalMemoryVariant},
    CompareExchangeError, CompareExchangeResult, DummyTlb, MemoryArchitecture, MemoryOperation,
    MemoryOperationError, TlbImpl, TlbTranslateError,
};
use crate::{
    cpu::CpuBackend,
    event_controller::ExceptionNumber,
    memory::{tlb::TlbProcessor, TlbTranslateResult},
};
use itertools::Itertools;
use std::{fmt::Debug, ops::Range, sync::Arc};
use styx_errors::{anyhow::anyhow, UnknownError};
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

/// Per-cpu MMU allows access to virtual and physical memory.
///
/// The MMU has two components: the processor specific TLB implementation and
/// a reference to the physical memory backend.
/// It is the single point where all memory transactions should flow through.
/// The Mmu has full mutable access to the [`TlbImpl`] but an **immutable** reference
/// to the [`MemoryBackend`].
/// [`MemoryBackend`] has interior mutability and allows for synchronous mutation
/// of memory with other vCPUs.
///
/// Currently, [`MemoryRegion`]s require `&mut MemoryBackend` and so can only be configured
/// at `Mmu` construction time and cannot be modified after construction.
///
/// In the future it may be possible to add regions at emulation time via an Append Only Vec.
///
/// Default implementation for testing purposes uses [`PhysicalMemoryVariant::FlatMemory`] and
/// [`DummyTlb`]. For a test ready default use [`Mmu::default_flat()`].
///
/// The recommended way of construction in a [`crate::core::ProcessorImpl`]
/// is to create separate [`MemoryBackend`] and [`DummyTlb`]
/// and then pass them to the [`crate::core::ProcessorBundle`].
///
/// In tests, [`Mmu::default_flat()`] or [`Mmu::with_regions()`] should suffice.
pub struct Mmu {
    /// [`TlbImpl`] instance for this cpu.
    pub tlb: Box<dyn TlbImpl>,
    /// Shared physical memory backend.
    ///
    /// At the moment this is `pub` and so technically users are free to clone.
    /// If we ever want to collect all the `Arc<MemoryBackend>` from each CPU
    /// to get a `&mut MemoryBackend` then we will have to provide helper methods to access this.
    pub memory: Arc<MemoryBackend>,
}

impl Default for Mmu {
    fn default() -> Self {
        Self::default_flat()
    }
}

// Constructors
impl Mmu {
    /// Construct a Mmu with a set of regions and default TLB.
    ///
    /// This is useful for testing or processor that do not have a custom TLB.
    pub fn with_regions(regions: impl IntoIterator<Item = MemoryRegion>) -> Self {
        Self::with_regions_tlb(regions, DummyTlb::new())
    }

    /// Construct a Mmu with a set of regions and custom TLB.
    ///
    /// [`DummyTlb`] is the default TLB and an Mmu can be created with
    /// regions and the [`DummyTlb`] using [`Mmu::with_regions()`]. Otherwise,
    /// use this method to attach a custom, processor specific [`TlbImpl`]
    /// implementation.
    pub fn with_regions_tlb(
        regions: impl IntoIterator<Item = MemoryRegion>,
        tlb: Box<dyn TlbImpl>,
    ) -> Self {
        let mut memory = MemoryBackend::new(PhysicalMemoryVariant::RegionStore);
        for region in regions.into_iter() {
            memory.add_memory_region(region).unwrap();
        }

        Self {
            tlb,
            memory: Arc::new(memory),
        }
    }

    /// Create a new Mmu with dummy tlb and flat memory.
    ///
    /// This is good for testing or proof of concept processors.
    /// This is not recommended for production processors since there are no memory regions
    /// with a flat memory structure.
    ///
    /// ## Why Use Memory Regions
    /// Memory regions are necessary for processors because they define the available
    /// memory on the processor explicitly.
    /// Having out of bounds or restricted permission memory regions could fail on common errors
    /// like null pointer dereference, code execution in
    /// uninitialized memory (if impossible on target processor).
    ///
    /// With memory regions, an invalid read/write/execute faults the processor and stops
    /// execution allowing the user to debug the issue.
    /// With no regions, the processor will continue executing as if nothing happened,
    /// most likely causing issues down the road and masking the root cause.
    /// Uninitialized null bytes may act like a sled, hiding that invalid address
    /// that was jumped to.
    pub fn default_flat() -> Self {
        Self {
            tlb: DummyTlb::new(),
            memory: Arc::new(MemoryBackend::new(PhysicalMemoryVariant::FlatMemory)),
        }
    }
}

impl Mmu {
    /// Returns the range made up of the min and max addresses supported
    /// by the physical memory backend.
    pub fn valid_memory_range(&self) -> MemoryArchitecture<Range<u64>> {
        self.memory
            .min_address()
            .with(self.memory.max_address(), |a, b| a..b)
    }

    /// Translates a virtual address to a physical address.
    pub fn translate_va(
        &mut self,
        virtual_addr: u64,
        access_type: MemoryOperation,
        memory_type: MemoryType,
        cpu: &mut dyn CpuBackend,
    ) -> TlbTranslateResult {
        let mut processor = TlbProcessor::new(&self.memory, cpu);
        self.tlb
            .translate_va(virtual_addr, access_type, memory_type, &mut processor)
    }

    // PHYSICAL METHODS

    /// Write an array of bytes to data memory, the address will be interpreted as a physical address.
    pub fn write_data(&self, phys_addr: u64, bytes: &[u8]) -> Result<(), MemoryOperationError> {
        self.memory.write_data(phys_addr, bytes)
    }

    /// Read an array of bytes from data memory, the address will be interpreted as a physical address.
    pub fn read_data(&self, phys_addr: u64, bytes: &mut [u8]) -> Result<(), MemoryOperationError> {
        self.memory.read_data(phys_addr, bytes)
    }

    /// Write an array of bytes to code memory, the address will be interpreted as a physical address.
    pub fn write_code(&self, phys_addr: u64, bytes: &[u8]) -> Result<(), MemoryOperationError> {
        self.memory.write_code(phys_addr, bytes)
    }

    /// Read an array of bytes from code memory, the address will be interpreted as a physical address.
    pub fn read_code(&self, phys_addr: u64, bytes: &mut [u8]) -> Result<(), MemoryOperationError> {
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
        &self,
        phys_addr: u64,
        bytes: &[u8],
    ) -> Result<(), MemoryOperationError> {
        self.memory.unchecked_write_data(phys_addr, bytes)
    }

    /// Read from data without checking permissions
    pub fn sudo_read_data(
        &self,
        phys_addr: u64,
        bytes: &mut [u8],
    ) -> Result<(), MemoryOperationError> {
        self.memory.unchecked_read_data(phys_addr, bytes)
    }

    /// Write to code without checking permissions
    pub fn sudo_write_code(
        &self,
        phys_addr: u64,
        bytes: &[u8],
    ) -> Result<(), MemoryOperationError> {
        self.memory.unchecked_write_code(phys_addr, bytes)
    }

    /// Read from code without checking permissions
    pub fn sudo_read_code(
        &self,
        phys_addr: u64,
        bytes: &mut [u8],
    ) -> Result<(), MemoryOperationError> {
        self.memory.unchecked_read_code(phys_addr, bytes)
    }

    // ATOMIC

    pub fn compare_exchange_code(
        &self,
        physical_address: u64,
        old: &[u8],
        new: &[u8],
    ) -> Result<CompareExchangeResult, CompareExchangeError> {
        self.memory
            .compare_exchange_code(physical_address, old, new)
    }

    pub fn compare_exchange_data(
        &self,
        physical_address: u64,
        old: &[u8],
        new: &[u8],
    ) -> Result<CompareExchangeResult, CompareExchangeError> {
        self.memory
            .compare_exchange_data(physical_address, old, new)
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
    /// // read back the 32 bit value, ensuring same endianness
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
    /// // read back the 32 bit value, ensuring same endianness
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
    /// // read back the 32 bit value, ensuring same endianness
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
    /// // read back the 32 bit value, ensuring same endianness
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
    /// // read back the 32 bit value, ensuring same endianness
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
    /// // read back the 32 bit value, ensuring same endianness
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

// context save/restore
impl Mmu {
    /// Save the [`Mmu`]'s context to be restored in the future.
    pub fn context_save(&mut self) -> Result<(), UnknownError> {
        Err(anyhow!(
            "memory implementation doesn't support save/restore"
        ))
    }
    /// Restore the [`Mmu`]'s context from a saved one.
    pub fn context_restore(&mut self) -> Result<(), UnknownError> {
        Err(anyhow!(
            "memory implementation doesn't support save/restore"
        ))
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

impl HasRegions for Mmu {
    fn regions(&self) -> impl Iterator<Item = &MemoryRegion> {
        // collect to vec so that the iters are the same type
        match &*self.memory {
            MemoryBackend::Harvard { code, data } => code
                .regions
                .iter()
                .chain(data.regions.iter())
                .collect_vec()
                .into_iter(),
            MemoryBackend::VonNeumann { memory } => memory.regions.iter().collect_vec().into_iter(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::memory::{helpers::*, Mmu};

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

    /// Simple test of compare exchange in the unmodified and modified case with size=2.
    #[test]
    fn test_compare_exchange() {
        let mut mmu = Mmu::default();

        mmu.write_data(0x1100, &[0x12, 0x34]).unwrap();
        let result = mmu
            .compare_exchange_data(0x1100, &[0x99, 0x99], &[0x13, 0x37])
            .unwrap();
        assert!(!result.success());
        // data didn't change because compare exchange failed
        assert_eq!(
            mmu.data().read(0x1100).vec(2).unwrap().as_slice(),
            &[0x12, 0x34]
        );

        let result = mmu
            .compare_exchange_data(0x1100, &[0x12, 0x34], &[0x13, 0x37])
            .unwrap();
        assert!(result.success());
        // compare and swap changed data
        assert_eq!(
            mmu.data().read(0x1100).vec(2).unwrap().as_slice(),
            &[0x13, 0x37]
        );
    }

    // todo add tests for virtual addressing once we make a TLB
}
