// SPDX-License-Identifier: BSD-2-Clause
//! Byte-addressable atomic value used to build *mostly* atomic target memory.
//!
//! This is an internal Styx mechanism and shouldn't be used by library users.
//! See the [`AtomicWord`] and its associated methods.
//! See [`crate::memory`] for how this fits into Styx's memory as a whole.
//!
use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

type Word = AtomicU64;
type NonAtomicWord = u64;

/// Small buffer that supports memory-like read/write/update operations via host atomic operations.
///
/// The core of this api is being able to do the following.
///
/// ```ignore
/// # use styx_processor::memory::atomic_word::AtomicWord;
/// # let atomic_word = AtomicWord::default();
/// let bytes = 0x1337u16.to_le_bytes();
/// // Writing two bytes to the 4th byte in this word
/// // This operation is atomic and can be done with a immutable ref
/// &atomic_word.write(4, &bytes)?;
/// ```
///
/// The goal of this structure is to provide a memory-like API that supports atomic operations.
/// Memory API is reading/writing via `u8` slices and a endian-agnostic byte index (memory address).
/// Because we are constricted to using host atomic instructions, the size of this buffer is limited
/// to the largest atomic word size (probably [`AtomicU64`]).
///
/// Guarantees:
///  - The underlying representation should be `[u8; Self::WORD_SIZE_BYTES]`
///  - Indices into the data store are interpreted the same, independent of host architecture
///
/// All operations are atomic.
///
#[derive(Default, Debug)]
#[repr(transparent)]
pub(in crate::memory) struct AtomicWord(Word);

#[derive(Error, Debug, PartialEq, Eq)]
#[error("Access of atomic at idx={idx} and size={size} does not fit in the atomic word.")]
pub(in crate::memory) struct AlignmentError {
    /// Index into the word.
    idx: usize,
    /// Size of access.
    size: usize,
}

impl AtomicWord {
    pub(in crate::memory) const WORD_SIZE_BYTES: usize = std::mem::size_of::<Self>();

    /// Check that the given `idx` and `size` will fit into the word.
    const fn check(idx: usize, size: usize) -> Result<(), AlignmentError> {
        if idx + size > Self::WORD_SIZE_BYTES {
            Err(AlignmentError { idx, size })
        } else {
            Ok(())
        }
    }

    /// Read some bytes from the word atomically from index idx.
    ///
    /// The entire buffer must fit in to underlying data store, starting with index idx.
    pub(in crate::memory) fn read(
        &self,
        idx: usize,
        bytes: &mut [u8],
    ) -> Result<(), AlignmentError> {
        let size = bytes.len();
        Self::check(idx, size)?;

        // we know it's in the bounds now :+1:

        let value = self.0.load(Ordering::Relaxed);
        read_from_word(idx, bytes, value);
        Ok(())
    }

    /// Write a buffer into the buffer, starting at idx.
    ///
    /// The entire buffer must fit in to underlying data store.
    pub(in crate::memory) fn write(&self, idx: usize, bytes: &[u8]) -> Result<(), AlignmentError> {
        let size = bytes.len();
        Self::check(idx, size)?;

        // we know it's in the bounds now :+1:

        let mut bytes_to_write = [0u8; AtomicWord::WORD_SIZE_BYTES];
        bytes_to_write[idx..(idx + size)].copy_from_slice(bytes);

        self.0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |prev| {
                Some(write_to_word(idx, size, bytes_to_write, prev))
            })
            .unwrap(); // only Errs if we return None, which we aren't

        Ok(())
    }

    /// Updates the value, akin to [`AtomicU64::fetch_update()`].
    ///
    /// This is not needed but is a convenience method.
    ///
    /// Not sure if we will need this in the long term.
    #[allow(unused)]
    pub(in crate::memory) fn update(
        &self,
        idx: usize,
        size: usize,
        mut update_fn: impl FnMut(&mut [u8]),
    ) -> Result<(), AlignmentError> {
        Self::check(idx, size)?;

        // we know it's in the bounds now :+1:

        self.0
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |original_value| {
                let mut given_bytes = [0u8; AtomicWord::WORD_SIZE_BYTES];
                let given_bytes_slice = &mut given_bytes[idx..(idx + size)];
                read_from_word(idx, given_bytes_slice, original_value);

                update_fn(given_bytes_slice);

                Some(write_to_word(idx, size, given_bytes, original_value))
            })
            .unwrap(); // only Errs if we return None, which we aren't

        Ok(())
    }

    /// Updates the value in the word if `current` is the current bytes in the word, akin to [`AtomicU64::compare_exchange()`].
    #[allow(unused)]
    pub(in crate::memory) fn compare_and_swap(
        &self,
        idx: usize,
        current: &[u8],
        new: &[u8],
    ) -> Result<CompareAndSwapResult, AlignmentError> {
        // This will use AtomicU64 compare and swap with read_from_word and write_to_word
        todo!()
    }

    /// Convert to in-memory representation.
    ///
    /// ## Synchronization
    /// Any unsynchronized reads combined with writes (via [`Self::write()`]) are undefined behavior.
    /// As per Rust's atomic memory model.
    #[cfg(test)]
    pub(in crate::memory) fn as_slice(&self) -> &[u8; std::mem::size_of::<Self>()] {
        // SAFETY: Resulting Array is same size as Self and
        // Self has AT LEAST 1 byte alignment as required by [u8].
        unsafe { &*(self as *const Self as *const [u8; std::mem::size_of::<Self>()]) }
    }
}

pub enum CompareAndSwapResult {
    /// The swap succeeded.
    #[allow(unused)]
    Success,
    /// The swap was not performed.
    #[allow(unused)]
    Failure,
}

/// Copy a idx and size from an Atomic.
///
/// - idx and size MUST HAVE BEEN CHECKED FIRST.
fn read_from_word(idx: usize, read_bytes: &mut [u8], loaded_value: NonAtomicWord) {
    let size = read_bytes.len();
    debug_assert!(AtomicWord::check(idx, size).is_ok());
    let value_bytes = loaded_value.to_ne_bytes();
    read_bytes.copy_from_slice(&value_bytes[idx..(idx + size)]);
}

/// Helper to apply a write to a loaded value.
///
/// The idx and size defines the memory operation bounds.
/// Only the bytes starting at idx and extending to idx+size will be overwritten by the write_bytes.
///
/// Returned is the load_value after applying the write.
fn write_to_word(
    idx: usize,
    size: usize,
    write_bytes: [u8; AtomicWord::WORD_SIZE_BYTES],
    load_value: NonAtomicWord,
) -> NonAtomicWord {
    // To do this operation we create a u64 from the write_bytes buffer
    // and create a mask that we use to clear the modified bytes
    // of the load value.
    let u64_to_write = u64::from_ne_bytes(write_bytes);
    let mut mask_bytes = [0u8; AtomicWord::WORD_SIZE_BYTES];
    mask_bytes[idx..(idx + size)].fill(0xff);
    let mask = NonAtomicWord::from_ne_bytes(mask_bytes);
    (load_value & !mask) | u64_to_write
}

impl Clone for AtomicWord {
    fn clone(&self) -> Self {
        // naive, loads value of self and copies to new atomic
        Self(Word::new(self.0.load(Ordering::Relaxed)))
    }
}

impl From<u64> for AtomicWord {
    fn from(value: u64) -> Self {
        Self(Word::new(value))
    }
}

impl From<[u8; AtomicWord::WORD_SIZE_BYTES]> for AtomicWord {
    fn from(value: [u8; AtomicWord::WORD_SIZE_BYTES]) -> Self {
        AtomicWord::from(u64::from_ne_bytes(value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use test_case::test_case;

    #[test_case(0, 0, true)]
    #[test_case(0, 8, true)]
    #[test_case(1, 8, false)]
    #[test_case(2, 2, true)]
    #[test_case(4, 4, true)]
    #[test_case(0, 4, true)]
    #[test_case(6, 4, false)]
    fn test_check(idx: usize, size: usize, expected: bool) {
        let result = AtomicWord::check(idx, size);
        assert!(result.is_ok() == expected);
    }

    #[test_case(0, 0)]
    #[test_case(0, 8)]
    #[test_case(2, 2)]
    #[test_case(4, 4)]
    #[test_case(0, 4)]
    #[test_case(1, 1)]
    #[test_case(0, 1)]
    #[test_case(6, 2)]
    fn test_read_write_update(idx: usize, size: usize) {
        // temporary buffer to hold the user's bytes
        let mut user_bytes_buf = [0u8; 8];
        // the bytes that the "user" is writing
        let user_bytes = &mut user_bytes_buf[0..size];
        // initialize with some data
        (0..size).for_each(|i| {
            user_bytes[i] = 0x11 * (i + 1) as u8;
        });

        // makes sure all user bytes are nonzero
        assert!(user_bytes.iter().all(|b| *b > 0));

        test_update(idx, user_bytes);
        test_read_write(idx, user_bytes);
        test_byte_repr(idx, user_bytes);
    }

    fn test_update(idx: usize, user_bytes: &[u8]) {
        let atomic_word = AtomicWord::default();
        atomic_word.write(idx, user_bytes).unwrap();
        // test update function
        atomic_word
            .update(idx, user_bytes.len(), |original_bytes| {
                // The given previous bytes should match what we wrote
                assert_eq!(original_bytes, user_bytes);
                original_bytes.iter_mut().for_each(|b| *b += 1);
            })
            .unwrap();

        let modified_bytes = user_bytes.iter().map(|b| b + 1).collect::<Vec<_>>();

        // read the bytes into here
        let mut read_bytes_buf = [0u8; 8];
        let read_bytes = &mut read_bytes_buf[0..user_bytes.len()];
        atomic_word.read(idx, read_bytes).unwrap();
        // make sure the read bytes are the same as the written bytes
        assert_eq!(modified_bytes, read_bytes);
    }

    fn test_read_write(idx: usize, user_bytes: &[u8]) {
        // write user's bytes to the word
        let atomic_word = AtomicWord::default();
        atomic_word.write(idx, user_bytes).unwrap();

        // read the bytes into here
        let mut read_bytes_buf = [0u8; 8];
        let read_bytes = &mut read_bytes_buf[0..user_bytes.len()];
        atomic_word.read(idx, read_bytes).unwrap();
        // make sure the read bytes are the same as the written bytes
        assert_eq!(user_bytes, read_bytes);
    }

    fn test_byte_repr(idx: usize, user_bytes: &[u8]) {
        let atomic_word = AtomicWord::default();
        atomic_word.write(idx, user_bytes).unwrap();

        // next, we will verify that the underlying data is the same as a [u8]
        // with respect to the idx we are using
        // let raw_data_ptr = &atomic_word as *const AtomicWord as *mut AtomicWord as *mut u8;
        // let raw_data_size = std::mem::size_of::<AtomicWord>();
        // let raw_bytes = unsafe { std::slice::from_raw_parts(raw_data_ptr, raw_data_size) };
        let raw_bytes = atomic_word.as_slice();

        for i in 0..user_bytes.len() {
            assert_eq!(raw_bytes[idx + i], user_bytes[i])
        }
    }
}
