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
use super::{
    blob_store::BlobStore, const_memory::ConstMemory, hash_store::HashStore,
    sized_value::SizedValue,
};
use enum_dispatch::enum_dispatch;
use styx_pcode::pcode::{SpaceId, SpaceInfo};
use styx_processor::memory::MmuOpError;
use thiserror::Error;

use crate::ArchEndian;

/// Space memory access specific errors, superset of [MmuOpError].
///
/// Passes underlying [MmuOpError] or indicates that requested size does not fit in an
/// integer.
#[derive(Error, Debug)]
pub enum SpaceError {
    #[error(transparent)]
    MemoryError(#[from] MmuOpError),
    #[error("given size is too large to fit in a u64 value (max {0} bytes)")]
    SizeTooLarge(usize),
}

/// Single address space with backing data store.
#[derive(Debug)]
pub struct Space {
    /// Metadata about space.
    pub info: SpaceInfo,
    /// Backing memory store.
    pub memory: SpaceMemory,
}

impl Space {
    /// Create a space from a [SpaceInfo] and backing [SpaceMemory].
    pub fn from_parts(info: SpaceInfo, memory: SpaceMemory) -> Self {
        Self { info, memory }
    }

    /// Create a new Const [Space].
    ///
    /// This creates a Space with a word_size of 1, size of 8, the specified endianess, and a
    /// [ConstMemory] backing.
    pub fn new_const(endian: ArchEndian) -> Self {
        Self {
            info: SpaceInfo {
                word_size: 1,    // Const space is never pointed in to those this won't matter.
                address_size: 8, // This is always true
                endian,
                id: SpaceId::from(0), // Must be unique checked when added to space manager
            },
            memory: ConstMemory::new(endian).into(),
        }
    }

    /// Get <=16 bytes from any offset, corrected for endianess.
    pub fn get_value(&self, offset: u64, size: u8) -> Result<SizedValue, SpaceError> {
        let mut buf = [0u8; SizedValue::SIZE_BYTES];
        let buf_ref = &mut buf[0..size as usize];
        self.memory.get_chunk(offset, buf_ref)?;

        let value = match self.info.endian {
            ArchEndian::LittleEndian => SizedValue::from_le_bytes(buf_ref),
            ArchEndian::BigEndian => SizedValue::from_be_bytes(buf_ref),
        };
        Ok(value)
    }
    /// Set <=8 bytes to any offset, corrected for endianess.
    pub fn set_value(&mut self, offset: u64, value: SizedValue) -> Result<(), SpaceError> {
        let mut bytes_buf = [0u8; SizedValue::SIZE_BYTES];
        let bytes = match self.info.endian {
            ArchEndian::LittleEndian => value.to_le_bytes(&mut bytes_buf),
            ArchEndian::BigEndian => value.to_be_bytes(&mut bytes_buf),
        };

        self.memory.set_chunk(offset, bytes).map_err(Into::into)
    }

    /// Get bytes from any offset.
    pub fn get_chunk(&self, offset: u64, buf: &mut [u8]) -> Result<(), MmuOpError> {
        self.memory.get_chunk(offset, buf)
    }
    /// Set bytes to any offset.
    #[allow(dead_code)] // TODO: why is this popping?
    pub fn set_chunk(&mut self, offset: u64, buf: &[u8]) -> Result<(), MmuOpError> {
        self.memory.set_chunk(offset, buf)
    }
}

/// Trait for usable space memory backing.
#[enum_dispatch]
pub trait IsSpaceMemory {
    /// Get bytes from any offset.
    fn get_chunk(&self, offset: u64, buf: &mut [u8]) -> Result<(), MmuOpError>;
    /// Set bytes to any offset.
    fn set_chunk(&mut self, offset: u64, buf: &[u8]) -> Result<(), MmuOpError>;
}

/// Usable memory backings for spaces.
#[derive(Debug)]
#[enum_dispatch(IsSpaceMemory)]
pub enum SpaceMemory {
    BlobStore(BlobStore),
    ByteHashStore(HashStore<1>),
    Const(ConstMemory),
}

#[cfg(test)]
mod tests {
    use styx_cpu_type::ArchEndian;
    use styx_pcode::pcode::SpaceId;

    use crate::memory::{blob_store::BlobStore, sized_value::SizedValue, space::SpaceInfo};

    use super::Space;

    #[test]
    fn test_const_space() {
        // Little endian
        let le_const_space = Space::new_const(ArchEndian::LittleEndian);
        let val = le_const_space.get_value(1337, 8).unwrap();
        assert_eq!(val.to_u128().unwrap(), 1337);
        let val = le_const_space.get_value(1337, 4).unwrap();
        assert_eq!(val.to_u128().unwrap(), 1337);
        let val = le_const_space.get_value(1337, 2).unwrap();
        assert_eq!(val.to_u128().unwrap(), 1337);

        // Big endian
        let be_const_space = Space::new_const(ArchEndian::BigEndian);
        let val = be_const_space.get_value(1337, 8).unwrap();
        assert_eq!(val.to_u128().unwrap(), 1337);
        let val = be_const_space.get_value(1337, 4).unwrap();
        assert_eq!(val.to_u128().unwrap(), 1337);
        let val = be_const_space.get_value(1337, 2).unwrap();
        assert_eq!(val.to_u128().unwrap(), 1337);
    }

    #[test]
    fn test_space_get_little_endian() {
        let blob_store = BlobStore::new(10).unwrap();
        let mut space = Space::from_parts(
            SpaceInfo {
                word_size: 4,
                address_size: 4,
                endian: ArchEndian::LittleEndian,
                id: SpaceId::from(1),
            },
            blob_store.into(),
        );

        space.set_chunk(0, &[0x12, 0x34]).unwrap();
        let value = space.get_value(0, 2).unwrap();
        assert_eq!(value.to_u128().unwrap(), 0x3412);
        let value = space.get_value(0, 4).unwrap();
        assert_eq!(value.to_u128().unwrap(), 0x3412);
    }

    #[test]
    fn test_space_get_big_endian() {
        let blob_store = BlobStore::new(10).unwrap();
        let mut space = Space::from_parts(
            SpaceInfo {
                word_size: 4,
                address_size: 4,
                endian: ArchEndian::BigEndian,
                id: SpaceId::from(1),
            },
            blob_store.into(),
        );

        space.set_chunk(0, &[0x12, 0x34]).unwrap();
        let value = space.get_value(0, 2).unwrap();
        assert_eq!(value.to_u128().unwrap(), 0x1234);
        let value = space.get_value(0, 4).unwrap();
        assert_eq!(value.to_u128().unwrap(), 0x12340000);
    }

    #[test]
    fn test_space_set_little_endian() {
        let blob_store = BlobStore::new(10).unwrap();
        let mut space = Space::from_parts(
            SpaceInfo {
                word_size: 4,
                address_size: 4,
                endian: ArchEndian::LittleEndian,
                id: SpaceId::from(1),
            },
            blob_store.into(),
        );

        space
            .set_value(0, SizedValue::from_u128(0x1234, 2))
            .unwrap();

        let mut buf = [0; 2];
        space.get_chunk(0, &mut buf).unwrap();
        assert_eq!(buf, [0x34, 0x12]);

        let mut buf = [0; 4];
        space.get_chunk(0, &mut buf).unwrap();
        assert_eq!(buf, [0x34, 0x12, 0x00, 0x00]);
    }

    #[test]
    fn test_space_set_big_endian() {
        let blob_store = BlobStore::new(10).unwrap();
        let mut space = Space::from_parts(
            SpaceInfo {
                word_size: 4,
                address_size: 4,
                endian: ArchEndian::BigEndian,
                id: SpaceId::from(1),
            },
            blob_store.into(),
        );

        space
            .set_value(0, SizedValue::from_u128(0x1234, 2))
            .unwrap();

        let mut buf = [0; 2];
        space.get_chunk(0, &mut buf).unwrap();
        assert_eq!(buf, [0x12, 0x34]);

        space
            .set_value(0, SizedValue::from_u128(0x1234, 4))
            .unwrap();
        let mut buf = [0; 4];
        space.get_chunk(0, &mut buf).unwrap();
        assert_eq!(buf, [0x00, 0x00, 0x12, 0x34]);
    }
}
