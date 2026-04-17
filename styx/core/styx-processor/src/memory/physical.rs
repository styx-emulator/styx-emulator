// SPDX-License-Identifier: BSD-2-Clause

use serde::Deserialize;
use styx_errors::anyhow::anyhow;
use thiserror::Error;

use super::{
    atomic_word::CompareExchangeResult, region::RegionStore, MemoryArchitecture, MemoryPermissions,
};
use crate::memory::memory_region::MemoryRegion;

use styx_errors::UnknownError;

#[derive(Error, Debug)]
pub enum MemoryOperationError {
    #[error("Region has ({have:?}), need: ({need:?})")]
    InvalidRegionPermissions {
        have: MemoryPermissions,
        need: MemoryPermissions,
    },
    #[error("buffer goes outside the memory bounds of this store")]
    UnmappedMemory(#[from] UnmappedMemoryError),
}

#[derive(Error, Debug)]
pub enum AtomicMemoryOperationError {
    #[error("Cannot provide atomic operations to memory that spans multiple regions")]
    StradlesRegions { address: u64, size: usize },
    #[error(
        "Cannot provide atomic operation of {bytes} bytes (max {max_size} bytes) at 0x{address:X}"
    )]
    TooLarge {
        address: u64,
        bytes: usize,
        max_size: usize,
    },
    #[error("Atomic memory operations cannot be guaranteed with this backend")]
    NotSupported,
    #[error("Atomic memory access failed due to non-atomic reason")]
    NonAtomic(#[from] MemoryOperationError),
}

#[derive(Error, Debug)]
pub enum CompareExchangeError {
    #[error(transparent)]
    Atomic(#[from] AtomicMemoryOperationError),
    #[error("mismatched sizes")]
    MismatchedSizes(usize, usize),
}

#[derive(Error, Debug)]
pub enum UnmappedMemoryError {
    #[error("starting address and 0x{0:X} bytes mapped")]
    /// Operation starts in mapped memory for `n` bytes but not the full range.
    GoesUnmapped(u64),
    #[error("starting address 0x{0:X} is unmapped")]
    /// Operation starts in unmapped memory at address `n`.
    UnmappedStart(u64),
}

#[derive(Error, Debug)]
pub enum FromConfigError {
    #[error("error adding region from yaml description")]
    AddRegion(#[from] AddRegionError),
    #[error("bad yaml description")]
    YamlContentsError,
}

#[derive(Error, Debug)]
pub enum AddRegionError {
    #[error("Region size is declared to be {0}, data provided was size: {1}")]
    DataInvalidSize(u64, u64),
    #[error("New Region{{base: 0x{0:x}, size: {1}}} overlaps an existing MemoryRegion")]
    OverlappingRegion(u64, u64),
    #[error("Size `{0}` is too large")]
    SizeTooLarge(usize),
    #[error("Size `{0}` is too small, should be at least `{1}`")]
    SizeTooSmall(u64, u64),
    #[error("operation not supported by this address space")]
    UnsupportedAddressSpaceOperation,
    #[error("Size must be > 0")]
    ZeroSize,
}

/// Defines all of the valid address spaces
#[derive(Deserialize, Debug, PartialEq)]
pub enum Space {
    Code,
    Data,
}

/// This enumeration specifies the memory permissions for an allocated memory region.
/// Note, we need the permissions to be deserializable, so we couldn't just use
/// [`MemoryPermissions`] in this context.
#[derive(Deserialize, PartialEq, Debug)]
enum MemoryPermissionsDesc {
    All,
    Execute,
    None,
    Read,
    ReadExecute,
    ReadWrite,
    Write,
    WriteExecute,
}

/// Convert from our deserialized enumeration to the official memory permissions.
impl From<MemoryPermissionsDesc> for MemoryPermissions {
    fn from(value: MemoryPermissionsDesc) -> Self {
        match value {
            MemoryPermissionsDesc::None => MemoryPermissions::empty(),
            MemoryPermissionsDesc::Read => MemoryPermissions::READ,
            MemoryPermissionsDesc::Write => MemoryPermissions::WRITE,
            MemoryPermissionsDesc::Execute => MemoryPermissions::EXEC,
            MemoryPermissionsDesc::ReadWrite => MemoryPermissions::RW,
            MemoryPermissionsDesc::ReadExecute => MemoryPermissions::RX,
            MemoryPermissionsDesc::WriteExecute => MemoryPermissions::WX,
            MemoryPermissionsDesc::All => MemoryPermissions::all(),
        }
    }
}

#[derive(Deserialize, PartialEq, Debug)]
/// A struct that describes a memory region.
pub struct MemoryRegionDescriptor {
    /// The space that this region belongs to
    space: Space,
    /// Base address for the mapped memory region.
    base: u64,
    /// Size of the requested region.
    size: u64,
    /// Permissions to be applied to the memory region.
    perms: MemoryPermissionsDesc,
}

/// Defines all of the currently available, physical memory backends.
pub enum PhysicalMemoryVariant {
    /// Flat array based memory, everything RWX
    FlatMemory,
    /// Physically separate code and data memory, code is RX, data is RW
    HarvardFlatMemory,
    /// Separate Code + Data, flat array based memory, RW for data, RX for code
    RegionStore,
}

/// Processor's physical memory.
///
/// Typically the [`MemoryBackend`] will be accessed via the [`crate::memory::Mmu`].
/// Creation of the [`MemoryBackend`] happens in the [`crate::core::ProcessorImpl`].
///
/// Memory operations on the [`MemoryBackend`] do not use tlb and operate on physical memory.
/// All documentation here relates to the processor's **physical memory** and any
/// reference to **memory regions** and **memory permissions** are referring
/// to the processor's physical memory configuration. Virtual Memory, Mmu, and
/// TLB related logic is contained in the [`crate::memory::TlbImpl`].
///
/// The [`MemoryBackend`] has three configurations (correlating to [`PhysicalMemoryVariant`]):
///
/// 1. Harvard Flat Memory
/// 2. VonNeumann Flat Memory
/// 3. VonNeumann Region store
///
/// Flat memory variants do not have regions or memory permissions.
/// Any `u64` address is valid and uses a giant allocated array to represent memory.
/// The hosts memory manager ensures that this will not actually allocate `2^64` bytes
/// of memory until it has been accessed.
/// For this reason, avoid zeroing large sections of memory when using the Flat Memory.
///
/// Harvard configuration splits code and data memory while VonNeumann has a unified
/// memory space.
/// Read/write operations have `_code` and `_data` variants which will be identical
/// in a VonNeumann configuration.
/// [`MemoryBackend`]
///
/// ## Concurrency
/// The [`MemoryBackend`] is designed for concurrent memory reads and
/// writes. Concurrent reads and writes to memory are enabled by using host
/// [`std::sync::atomic`] reads and writes. Because Atomic operations are
/// immutable (only requiring `&`), we can modify memory from multiple vCPUs,
/// threads, etc all without requiring a lock on memory, which would cause a
/// major performance hit.
///
/// While the memory itself can be modified using atomics, adding and removing regions
/// is still a mutable operation.
/// For that resion memory region addition and removal require `&mut` and so should
/// be added during construction and cannot be added at emulation time.
/// Theorehically, this could change in the future by adding a thread safe storage for
/// memory regions.
pub enum MemoryBackend {
    Harvard {
        code: RegionStore,
        data: RegionStore,
    },
    VonNeumann {
        memory: RegionStore,
    },
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self::new(PhysicalMemoryVariant::FlatMemory)
    }
}

impl MemoryBackend {
    pub fn new(variant: PhysicalMemoryVariant) -> Self {
        match variant {
            PhysicalMemoryVariant::HarvardFlatMemory => Self::Harvard {
                code: RegionStore::flat(),
                data: RegionStore::flat(),
            },
            PhysicalMemoryVariant::FlatMemory => Self::VonNeumann {
                memory: RegionStore::flat(),
            },
            PhysicalMemoryVariant::RegionStore => Self::VonNeumann {
                memory: RegionStore::empty(),
            },
        }
    }

    /// Equivalent to [`MemoryBackend::new(PhysicalMemoryVariant::RegionStore)`]
    pub fn new_region_store() -> Self {
        Self::new(PhysicalMemoryVariant::RegionStore)
    }

    /// Equivalent to [`MemoryBackend::new(PhysicalMemoryVariant::FlatMemory)`]
    pub fn new_flat() -> Self {
        Self::new(PhysicalMemoryVariant::FlatMemory)
    }

    /// Access data memory using the [memory helper api](crate::memory::helpers).
    pub fn data(&self) -> Data {
        Data(self)
    }

    /// Access code memory using the [memory helper api](crate::memory::helpers).
    pub fn code(&self) -> Code {
        Code(self)
    }

    fn code_storage(&self) -> &RegionStore {
        match self {
            MemoryBackend::Harvard { code, data: _ } => code,
            MemoryBackend::VonNeumann { memory } => memory,
        }
    }

    fn data_storage(&self) -> &RegionStore {
        match self {
            MemoryBackend::Harvard { code: _, data } => data,
            MemoryBackend::VonNeumann { memory } => memory,
        }
    }

    /// Returns the minimum address represented in this space
    pub fn min_address(&self) -> MemoryArchitecture<u64> {
        match self {
            MemoryBackend::Harvard { code, data } => MemoryArchitecture::Harvard {
                code: code.min_address(),
                data: data.min_address(),
            },
            MemoryBackend::VonNeumann { memory } => {
                MemoryArchitecture::VonNeuman(memory.min_address())
            }
        }
    }

    /// Returns the maximum address represented in this space
    pub fn max_address(&self) -> MemoryArchitecture<u64> {
        match self {
            MemoryBackend::Harvard { code, data } => MemoryArchitecture::Harvard {
                code: code.max_address(),
                data: data.max_address(),
            },
            MemoryBackend::VonNeumann { memory } => {
                MemoryArchitecture::VonNeuman(memory.max_address())
            }
        }
    }

    /// Add a new physical memory region with optional [`Space`].
    ///
    /// The `space` can be specified as `Some(Space)` so add to that space if Harvard type
    /// or just add the region if VonNeuman. `None` will add the region to both [`Space::Code`]
    /// [`Space::Data`] if Harvard.
    pub fn add_region(
        &mut self,
        region: MemoryRegion,
        space: Option<Space>,
    ) -> Result<(), AddRegionError> {
        match self {
            MemoryBackend::Harvard { code, data } => match space {
                Some(Space::Code) => code.add_region(region),
                Some(Space::Data) => data.add_region(region),
                None => {
                    code.add_region(region.clone())?;
                    data.add_region(region)?;
                    Ok(())
                }
            },
            MemoryBackend::VonNeumann { memory } => memory.add_region(region),
        }
    }

    /// Add a new physical memory region.
    ///
    /// Adds a region to the physical memory, adding to both code and data space if
    /// Harvard configuration.
    pub fn add_memory_region(&mut self, region: MemoryRegion) -> Result<(), AddRegionError> {
        self.add_region(region, None)
    }

    /// Create a new memory region on the backend.
    ///
    /// Adds a region to the physical memory, adding to both code and data space if
    /// Harvard configuration.
    pub fn memory_map(
        &mut self,
        base: u64,
        size: u64,
        perms: MemoryPermissions,
    ) -> Result<(), AddRegionError> {
        self.add_region(MemoryRegion::new(base, size, perms)?, None)
    }

    /// Reads a contiguous array of code bytes to the buffer `data` starting from `addr`.
    ///
    /// This operation MAY be atomic.
    pub fn read_code(&self, addr: u64, bytes: &mut [u8]) -> Result<(), MemoryOperationError> {
        self.code_storage().read_memory(addr, bytes)
    }

    /// Reads a contiguous array of data bytes to the buffer `data` starting from `addr`.
    ///
    /// This operation MAY be atomic.
    pub fn read_data(&self, addr: u64, bytes: &mut [u8]) -> Result<(), MemoryOperationError> {
        self.data_storage().read_memory(addr, bytes)
    }

    /// Writes a contiguous array of bytes from the buffer `data` into code memory, starting at `addr`.
    ///
    /// This operation MAY be atomic.
    pub fn write_code(&self, addr: u64, bytes: &[u8]) -> Result<(), MemoryOperationError> {
        self.code_storage().write_memory(addr, bytes)
    }

    /// Writes a contiguous array of bytes from the buffer `data` into data memory, starting at `addr`.
    ///
    /// This operation MAY be atomic.
    pub fn write_data(&self, addr: u64, bytes: &[u8]) -> Result<(), MemoryOperationError> {
        self.data_storage().write_memory(addr, bytes)
    }

    /// Reads a contiguous array of code bytes to the buffer `data` starting from `addr`.
    ///
    /// This operation MUST be atomic or return `Err`.
    pub fn read_code_atomic(
        &self,
        addr: u64,
        bytes: &mut [u8],
    ) -> Result<(), AtomicMemoryOperationError> {
        self.code_storage().read_memory_atomic(addr, bytes)
    }

    /// Reads a contiguous array of data bytes to the buffer `data` starting from `addr`.
    ///
    /// This operation MUST be atomic or return `Err`.
    pub fn read_data_atomic(
        &self,
        addr: u64,
        bytes: &mut [u8],
    ) -> Result<(), AtomicMemoryOperationError> {
        self.data_storage().read_memory_atomic(addr, bytes)
    }

    /// Writes a contiguous array of bytes from the buffer `data` into code memory, starting at `addr`.
    ///
    /// This operation MUST be atomic or return `Err`.
    pub fn write_code_atomic(
        &self,
        addr: u64,
        bytes: &[u8],
    ) -> Result<(), AtomicMemoryOperationError> {
        self.code_storage().write_memory_atomic(addr, bytes)
    }

    /// Writes a contiguous array of bytes from the buffer `data` into data memory, starting at `addr`.
    ///
    /// This operation MUST be atomic or return `Err`.
    pub fn write_data_atomic(
        &self,
        addr: u64,
        bytes: &[u8],
    ) -> Result<(), AtomicMemoryOperationError> {
        self.data_storage().write_memory_atomic(addr, bytes)
    }

    // at minimum we need compare and swap on an arbitrary 8 byte.

    /// Compare exchange operation on a segment in code memory.
    ///
    /// The `current` and `new` slices must be the same size and be
    /// < 8 bytes, otherwise this will return `Err()`.
    pub fn compare_exchange_code(
        &self,
        address: u64,
        current: &[u8],
        new: &[u8],
    ) -> Result<CompareExchangeResult, CompareExchangeError> {
        self.code_storage().compare_exchange(address, current, new)
    }

    /// Compare exchange operation on a segment in data memory.
    ///
    /// The `current` and `new` slices must be the same size and be
    /// < 8 bytes, otherwise this will return `Err()`.
    pub fn compare_exchange_data(
        &self,
        address: u64,
        current: &[u8],
        new: &[u8],
    ) -> Result<CompareExchangeResult, CompareExchangeError> {
        self.data_storage().compare_exchange(address, current, new)
    }

    /// Reads a contiguous array of code bytes to the buffer `data` starting from `addr`.
    ///
    /// Ignores memory permissions imposed by the physical memory backend.
    pub fn unchecked_read_code(
        &self,
        addr: u64,
        bytes: &mut [u8],
    ) -> Result<(), MemoryOperationError> {
        self.code_storage().sudo_read_memory(addr, bytes)
    }

    /// Reads a contiguous array of data bytes to the buffer `data` starting from `addr`.
    ///
    /// Ignores memory permissions imposed by the physical memory backend.
    pub fn unchecked_read_data(
        &self,
        addr: u64,
        bytes: &mut [u8],
    ) -> Result<(), MemoryOperationError> {
        self.data_storage().sudo_read_memory(addr, bytes)
    }

    /// Writes a contiguous array of bytes from the buffer `data` into code memory, starting at `addr`.
    ///
    /// Ignores memory permissions imposed by the physical memory backend.
    pub fn unchecked_write_code(
        &self,
        addr: u64,
        bytes: &[u8],
    ) -> Result<(), MemoryOperationError> {
        self.code_storage().sudo_write_memory(addr, bytes)
    }

    /// Writes a contiguous array of bytes from the buffer `data` into data memory, starting at `addr`.
    ///
    /// Ignores memory permissions imposed by the physical memory backend.
    pub fn unchecked_write_data(
        &self,
        addr: u64,
        bytes: &[u8],
    ) -> Result<(), MemoryOperationError> {
        self.data_storage().sudo_write_memory(addr, bytes)
    }

    /// Save the current memory state
    ///
    /// Holding multiple saved states is not supported. Saving memory state will overwrite any previously saved state.
    pub fn context_save(&mut self) -> Result<(), UnknownError> {
        Err(anyhow!(
            "memory implementation doesn't support save/restore"
        ))
    }

    /// Restore a previously saved memory state
    ///
    /// This will error if no saved state exists.
    pub fn context_restore(&mut self) -> Result<(), UnknownError> {
        Err(anyhow!(
            "memory implementation doesn't support save/restore"
        ))
    }
}

pub struct Data<'a>(&'a MemoryBackend);
impl super::helpers::Readable for Data<'_> {
    type Error = MemoryOperationError;

    fn read_raw(&mut self, addr: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.0.read_data(addr, bytes)
    }
}
impl super::helpers::Writable for Data<'_> {
    type Error = MemoryOperationError;

    fn write_raw(&mut self, addr: u64, bytes: &[u8]) -> Result<(), Self::Error> {
        self.0.write_data(addr, bytes)
    }
}

pub struct Code<'a>(&'a MemoryBackend);
impl super::helpers::Readable for Code<'_> {
    type Error = MemoryOperationError;

    fn read_raw(&mut self, addr: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.0.read_code(addr, bytes)
    }
}
impl super::helpers::Writable for Code<'_> {
    type Error = MemoryOperationError;

    fn write_raw(&mut self, addr: u64, bytes: &[u8]) -> Result<(), Self::Error> {
        self.0.write_code(addr, bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_simple() {
        let memory = MemoryBackend::default();

        let expected_data = [0x13u8, 0x37];
        memory.write_data(0x100, &expected_data).unwrap();
        let mut read_data = [0u8; 2];
        memory.read_data(0x100, &mut read_data).unwrap();
        assert_eq!(expected_data, read_data)
    }

    #[test]
    fn test_simple_unified() {
        let memory = MemoryBackend::default();

        let expected_data = [0x13u8, 0x37, 0xde, 0xad];
        memory.write_data(0x100, &expected_data).unwrap();
        let mut read_data = [0u8; 4];
        memory.read_data(0x100, &mut read_data).unwrap();
        assert_eq!(expected_data, read_data);
        let mut read_data = [0u8; 4];
        memory.read_code(0x100, &mut read_data).unwrap();
        assert_eq!(expected_data, read_data);
    }

    #[test]
    fn test_simple_separate() {
        let memory = MemoryBackend::new(PhysicalMemoryVariant::HarvardFlatMemory);

        let expected_data = [0x13u8, 0x37, 0xde, 0xad];
        memory.write_data(0, &expected_data).unwrap();

        let mut read_code = [0_u8; 4];
        memory.read_code(0, &mut read_code).unwrap();

        let mut read_data = [0_u8; 4];
        memory.read_data(0, &mut read_data).unwrap();

        assert_eq!(expected_data, read_data);
        assert_ne!(expected_data, read_code);
    }
}
