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
