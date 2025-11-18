// SPDX-License-Identifier: BSD-2-Clause

use serde::Deserialize;
use styx_errors::anyhow::anyhow;
use thiserror::Error;

use super::{
    atomic_word::CompareAndSwapResult, region::RegionStore, MemoryArchitecture, MemoryPermissions,
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

/// Physical memory storage.
///
/// Memory operations on the memory backend bypass the tlb and operate on physical memory.
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

    /// Access data memory using the [memory helper api](crate::memory::helpers).
    pub fn data(&mut self) -> Data {
        Data(self)
    }

    /// Access code memory using the [memory helper api](crate::memory::helpers).
    pub fn code(&mut self) -> Code {
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

    /// Add a new region to the address space.
    ///
    /// The `space` can be specified as `Some(Space)` so add to that space if Harvard type
    /// or just add the region if VonNeuman. `None` will add the region to both [`Space::Code`]
    /// [`Space::Data`] if Hardvard.
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

    /// Performs an atomic arbitrary memory operations.
    pub fn compare_and_swap_code(
        &self,
        _addr: u64,
        _current: &[u8],
        _new: &[u8],
    ) -> Result<CompareAndSwapResult, AtomicMemoryOperationError> {
        todo!()
    }

    pub fn compare_and_swap_data(
        &self,
        _addr: u64,
        _current: &[u8],
        _new: &[u8],
    ) -> Result<CompareAndSwapResult, AtomicMemoryOperationError> {
        todo!()
    }

    // possible here atomic_add, atomic_inc, etc

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

pub struct Data<'a>(&'a mut MemoryBackend);
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

pub struct Code<'a>(&'a mut MemoryBackend);
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
