// SPDX-License-Identifier: BSD-2-Clause
use styx_processor::memory::MmuOpError;
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
