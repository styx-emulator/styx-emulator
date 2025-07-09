// SPDX-License-Identifier: BSD-2-Clause
pub(crate) mod address_space;

use std::borrow::Cow;

use address_space::{FlatMemory, HarvardStore, MemoryImpl, RegionStore};
use enum_dispatch::enum_dispatch;
use serde::Deserialize;
use thiserror::Error;

use super::MemoryPermissions;
use crate::memory::memory_region::MemoryRegion;
use crate::memory::physical::address_space::FromYaml;

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
    SizeTooLarge(u64),
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

/// This enumeration is specifies the memory permissions for an allocated memory region.
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
#[enum_dispatch(MemoryImpl)]
pub enum MemoryBackend {
    FlatMemory(FlatMemory),
    HarvardFlatMemory(HarvardStore),
    RegionStore(RegionStore),
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self::FlatMemory(FlatMemory::default())
    }
}

impl MemoryBackend {
    pub fn new(variant: PhysicalMemoryVariant) -> Self {
        match variant {
            PhysicalMemoryVariant::HarvardFlatMemory => {
                Self::HarvardFlatMemory(HarvardStore::default())
            }
            PhysicalMemoryVariant::FlatMemory => Self::FlatMemory(FlatMemory::default()),
            PhysicalMemoryVariant::RegionStore => Self::RegionStore(RegionStore::new()),
        }
    }

    pub fn new_from_yaml(variant: PhysicalMemoryVariant, deserializable: Cow<[u8]>) -> Self {
        let config: Vec<MemoryRegionDescriptor> =
            serde_yaml::from_slice(&deserializable[..]).expect("failed to parse yaml");

        match variant {
            PhysicalMemoryVariant::HarvardFlatMemory => {
                Self::HarvardFlatMemory(HarvardStore::from_config(config).unwrap())
            }
            PhysicalMemoryVariant::FlatMemory => {
                Self::FlatMemory(FlatMemory::from_config(config).unwrap())
            }
            PhysicalMemoryVariant::RegionStore => {
                Self::RegionStore(RegionStore::from_config(config).unwrap())
            }
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
        let mut memory = MemoryBackend::default();

        let expected_data = [0x13u8, 0x37];
        memory.write_data(0x100, &expected_data).unwrap();
        let mut read_data = [0u8; 2];
        memory.read_data(0x100, &mut read_data).unwrap();
        assert_eq!(expected_data, read_data)
    }

    #[test]
    fn test_simple_unified() {
        let mut memory = MemoryBackend::default();

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
        let mut memory = MemoryBackend::new(PhysicalMemoryVariant::HarvardFlatMemory);

        let expected_data = [0x13u8, 0x37, 0xde, 0xad];
        memory.write_data(0, &expected_data).unwrap();

        let mut read_code = [0_u8; 4];
        memory.read_code(0, &mut read_code).unwrap();

        let mut read_data = [0_u8; 4];
        memory.read_data(0, &mut read_data).unwrap();

        assert_eq!(expected_data, read_data);
        assert_ne!(expected_data, read_code);
    }

    #[test]
    fn test_yaml_config() {
        let config = "- !MemoryRegion
    space: !Code
    base: 8
    size: 4
    perms: !All
- !MemoryRegion
    space: !Data
    base: 0x0
    size: 32
    perms: !All"
            .as_bytes();

        let mut memory = MemoryBackend::new_from_yaml(
            PhysicalMemoryVariant::HarvardFlatMemory,
            std::borrow::Cow::Borrowed(config),
        );

        let expected_data = [0x13u8, 0x37, 0xde, 0xad];
        memory.write_code(8, &expected_data).unwrap();

        let mut read_code = [0_u8; 4];
        memory.read_code(8, &mut read_code).unwrap();

        assert_eq!(expected_data, read_code);
    }
}
