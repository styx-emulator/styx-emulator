// SPDX-License-Identifier: BSD-2-Clause
use std::collections::HashMap;

use super::simple_store::{SimpleStore, SimpleStoreMemoryErr};

/// [SimpleStore] implemented using a HashMap backend.
///
/// The backing store is a HashMap of addresses->value mappings where each entry holds `alignment`
/// bytes.
#[derive(Debug, Default)]
pub struct HashStore<const ALIGNMENT: u64> {
    backing: HashMap<u64, u64>,
}

impl<const ALIGNMENT: u64> HashStore<ALIGNMENT> {
    /// Create a new [HashStore] with a preferred alignment.
    ///
    /// For example, with an alignment of 4 each hash entry
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a mask of the bottom `alignment` bytes being 0xFF.
    fn mask(&self) -> u64 {
        let mut start = 0xFF;
        for _ in 1..ALIGNMENT {
            start <<= 8;
            start |= 0xFF;
        }
        start
    }
}

impl<const ALIGNMENT: u64> SimpleStore<ALIGNMENT> for HashStore<ALIGNMENT> {
    fn insert(&mut self, offset: u64, value: u64) -> Result<(), SimpleStoreMemoryErr> {
        Self::aligned(offset);

        self.backing.insert(offset, value & self.mask());
        Ok(())
    }

    fn find(&self, offset: u64) -> Result<u64, SimpleStoreMemoryErr> {
        Self::aligned(offset);

        Ok(*self.backing.get(&offset).unwrap_or(&0))
    }
}

#[cfg(test)]
mod tests {
    use crate::memory::simple_store::SimpleStore;

    use super::HashStore;

    #[test]
    fn test_get_mask() {
        let store: HashStore<4> = HashStore::new();
        assert_eq!(store.mask(), 0xFFFFFFFF);

        let store: HashStore<8> = HashStore::new();
        assert_eq!(store.mask(), 0xFFFFFFFFFFFFFFFF);

        let store: HashStore<2> = HashStore::new();
        assert_eq!(store.mask(), 0xFFFF);

        let store: HashStore<1> = HashStore::new();
        assert_eq!(store.mask(), 0xFF);
    }

    #[test]
    fn test_hash_store_simple() {
        let mut store: HashStore<4> = HashStore::new();

        let value = store.find(0x1338).unwrap();
        assert_eq!(value, 0);

        store.insert(0x1338, 0xDEADFACE).unwrap();
        let value = store.find(0x1338).unwrap();
        assert_eq!(value, 0xDEADFACE);

        store.insert(0x1330, 0xCAFEDEADFACE).unwrap();
        let value = store.find(0x1330).unwrap();
        assert_eq!(value, 0xDEADFACE);
    }
}
