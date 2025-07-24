// SPDX-License-Identifier: BSD-2-Clause
use styx_processor::memory::MmuOpError;
use thiserror::Error;

use super::space::IsSpaceMemory;

/// Storage that operates with aligned read/writes.
///
/// Data stores that would benefit from having a "preferred word size" can implement this trait for
/// an arbitrary alignment. [IsSpaceMemory] is implemented for all [SimpleStore] implementations so
/// [SimpleStore] implementers get this for free.
pub trait SimpleStore<const ALIGNMENT: u64> {
    /// Writes a word at an aligned offset.
    ///
    /// # Panics
    ///
    /// Panics if offset is not aligned with `ALIGNMENT`.
    fn insert(&mut self, offset: u64, value: u64) -> Result<(), SimpleStoreMemoryErr>;
    /// Retrieves a word at an aligned offset.
    ///
    /// # Panics
    ///
    /// Panics if offset is not aligned with `ALIGNMENT`.
    fn find(&self, offset: u64) -> Result<u64, SimpleStoreMemoryErr>;

    /// Panics if offset is not aligned, otherwise does nothing.
    fn aligned(offset: u64) {
        if offset % ALIGNMENT != 0 {
            panic!("offset {offset} is not aligned with {ALIGNMENT}");
        }
    }
}

#[derive(Error, Debug)]
pub enum SimpleStoreMemoryErr {
    #[error(transparent)]
    MemoryErr(#[from] MmuOpError),
}

// Currently only alignment sizes of 1 are implemented. This is an easy implementation but is
// slow (each byte is a memory operation). Ideally [SimpleStore] alignment would match the processor
// architecture meaning most emulated memory operations would be a single memory operation.
impl<T: SimpleStore<1>> IsSpaceMemory for T {
    fn get_chunk(&self, offset: u64, buf: &mut [u8]) -> Result<(), MmuOpError> {
        for (idx, byte) in buf.iter_mut().enumerate() {
            let result = self.find(offset + idx as u64);
            let value = match result {
                Ok(value) => Ok(value),
                Err(err) => match err {
                    SimpleStoreMemoryErr::MemoryErr(err) => Err(err),
                },
            }?;

            *byte = value as u8;
        }
        Ok(())
    }

    fn set_chunk(&mut self, offset: u64, buf: &[u8]) -> Result<(), MmuOpError> {
        for (idx, byte) in buf.iter().enumerate() {
            let result = self.insert(offset + idx as u64, *byte as u64);
            match result {
                Ok(value) => Ok(value),
                Err(err) => match err {
                    SimpleStoreMemoryErr::MemoryErr(err) => Err(err),
                },
            }?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::memory::{hash_store::HashStore, space::IsSpaceMemory};

    #[test]
    fn test_hash_one() {
        let mut store: HashStore<1> = HashStore::new();

        let mut buf = [0u8; 4];
        store.get_chunk(0x1338, &mut buf).unwrap();
        assert_eq!(buf, [0, 0, 0, 0]);

        store.set_chunk(0x1338, &[0xDE, 0xAD, 0xFA, 0xCE]).unwrap();
        store.get_chunk(0x1338, &mut buf).unwrap();
        assert_eq!(buf, [0xDE, 0xAD, 0xFA, 0xCE]);
    }
}
