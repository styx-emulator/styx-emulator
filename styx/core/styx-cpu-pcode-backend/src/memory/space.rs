// SPDX-License-Identifier: BSD-2-Clause
use super::{
    blob_store::BlobStore, const_memory::ConstMemory, hash_store::HashStore,
    sized_value::SizedValue,
};
use enum_dispatch::enum_dispatch;
use log::{info, trace};
use std::{ops::Range, sync::Arc};
use styx_cpu_type::arch::RegisterValue;
use styx_pcode::pcode::{SpaceId, SpaceInfo, SpaceName, VarnodeData};
use styx_processor::{cpu::GlobalRegisterStore, memory::MmuOpError};
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

    /// Global register store. Only used in a register store.
    global_register_store: Option<Arc<Box<dyn GlobalRegisterStore>>>,
    global_register_range: Option<Range<u64>>,
}

impl Space {
    /// Create a space from a [SpaceInfo] and backing [SpaceMemory].
    pub fn from_parts(info: SpaceInfo, memory: SpaceMemory) -> Self {
        Self {
            info,
            memory,
            global_register_store: None,
            global_register_range: None,
        }
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
            global_register_store: None,
            global_register_range: None,
        }
    }

    /// Get <=16 bytes from any offset, corrected for endianess.
    pub fn get_value(&self, offset: u64, size: u8) -> Result<SizedValue, SpaceError> {
        // Fast path, try to do a global register read. Ignored if not a Register varnode space.
        if let Some(szval) = self.read_global_register(offset, size, self.info.endian) {
            return Ok(szval);
        }

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
        // Fast path, try to do a global register write. Ignored if not a Register varnode space.
        if let Some(()) = self.write_global_register(offset, value, self.info.endian) {
            return Ok(());
        }

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

    pub fn write_global_register(
        &mut self,
        offset: u64,
        data: SizedValue,
        endian: ArchEndian,
    ) -> Option<()> {
        if let Some(global_register_range) = self.global_register_range.as_ref() {
            if global_register_range.contains(&offset) {
                info!("set_value_mmu {offset:x?} {data:x?}");
                // Check if this is a global register.
                let store = self.global_register_store.as_ref().unwrap();
                store
                    .write_register_raw(
                        offset as usize - global_register_range.start as usize,
                        RegisterValue::try_from(data).unwrap(),
                        endian,
                    )
                    .expect("Couldn't write global register");

                return Some(());
            }
        }

        None
    }

    pub fn read_global_register(
        &self,
        offset: u64,
        size: u8,
        endian: ArchEndian,
    ) -> Option<SizedValue> {
        if let Some(global_register_range) = self.global_register_range.as_ref() {
            if global_register_range.contains(&offset) {
                trace!("get_value_mmu {offset:x?}");
                // Check if this is a global register.
                let store = self.global_register_store.as_ref().unwrap();

                return Some(
                    SizedValue::try_from(
                        store
                            .read_register_raw(
                                offset as usize - global_register_range.start as usize,
                                size as usize,
                                endian,
                            )
                            .expect("Couldn't write global register"),
                    )
                    .expect("couldn't convert RegisterValue to SizedValue"),
                );
            }
        }

        None
    }

    /// Only used for a register store.
    pub fn setup_global_register_store(
        &mut self,
        register_store: Arc<Box<dyn GlobalRegisterStore>>,
        global_register_range: Range<u64>,
    ) {
        self.global_register_store = Some(register_store);
        self.global_register_range = Some(global_register_range);
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
