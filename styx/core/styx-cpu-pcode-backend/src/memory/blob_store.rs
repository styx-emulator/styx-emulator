// SPDX-License-Identifier: BSD-2-Clause
use super::space::IsSpaceMemory;
use std::fmt::Debug;
use styx_processor::memory::{MemoryOperationError, MmuOpError, UnmappedMemoryError};

/// Simple [IsSpaceMemory] implementation that uses a single block of contiguous memory.
///
/// Note that [BlobStore] cannot be resized and does not have a base offset.
///
/// In the future [BlobStore] could have auto resize and a base offset, making it almost as useful
/// as [super::hash_store::HashStore] but reaping the speed benefits of directly memory access.
pub struct BlobStore {
    data: Box<[u8]>,
}

impl BlobStore {
    /// Create a new [BlobStore] with a certain size.
    pub fn new(size: usize) -> Option<Self> {
        Some(Self {
            data: vec![0; size].into(),
        })
    }

    fn make_invalid_memory_range(&self, request_min: u64) -> MmuOpError {
        MmuOpError::PhysicalMemoryError(MemoryOperationError::UnmappedMemory(
            UnmappedMemoryError::UnmappedStart(request_min),
        ))
    }
}

/// Less verbose debug format, shows the struct name and size.
impl Debug for BlobStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("BlobStore(size: {})", self.data.len()))
    }
}

impl IsSpaceMemory for BlobStore {
    fn get_chunk(&self, offset: u64, buf: &mut [u8]) -> Result<(), MmuOpError> {
        let offset_usize = offset as usize;

        let data_chunk = self
            .data
            .get(offset_usize..offset_usize + buf.len())
            .ok_or(self.make_invalid_memory_range(offset))?;

        buf.copy_from_slice(data_chunk);
        Ok(())
    }

    fn set_chunk(&mut self, offset: u64, buf: &[u8]) -> Result<(), MmuOpError> {
        let offset_usize = offset as usize;

        let result = self.data.get_mut(offset_usize..offset_usize + buf.len());
        if let Some(data_chunk) = result {
            data_chunk.copy_from_slice(buf);
            Ok(())
        } else {
            Err(self.make_invalid_memory_range(offset))
        }
    }
}

#[cfg(test)]
mod tests {

    use super::BlobStore;
    use crate::memory::space::IsSpaceMemory;

    #[test]
    fn test_blob_store_oob() {
        let mut store = BlobStore::new(0x1000).unwrap();

        let set_value = [0xDE, 0xAD, 0xFA, 0xCE];
        let rtn = store.set_chunk(0x2000, &set_value);
        assert!(rtn.is_err());

        let set_value = [0xDE, 0xAD, 0xFA, 0xCE];
        let rtn = store.set_chunk(0x1000, &set_value);
        assert!(rtn.is_err());

        let set_value = [0xDE, 0xAD, 0xFA, 0xCE];
        let rtn = store.set_chunk(0xFFD, &set_value);
        assert!(rtn.is_err());

        let set_value = [0xDE, 0xAD, 0xFA, 0xCE];
        let rtn = store.set_chunk(0xFFC, &set_value);
        assert!(rtn.is_ok());
    }

    #[test]
    fn test_blob_store_chunks() {
        let mut store = BlobStore::new(0x1000).unwrap();

        let set_value = [0xDE, 0xAD, 0xFA, 0xCE];
        store.set_chunk(0x501, &set_value).unwrap();

        let mut get_value = [0u8; 4];
        store.get_chunk(0x501, &mut get_value).unwrap();

        assert_eq!(set_value, get_value);
    }
}
