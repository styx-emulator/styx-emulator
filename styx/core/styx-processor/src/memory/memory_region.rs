// SPDX-License-Identifier: BSD-2-Clause
use std::alloc::{alloc_zeroed, Layout};
use std::fmt::Debug;
use std::num::NonZeroUsize;
use std::ops::Range;

use crate::memory::{AddRegionError, MemoryOperation, MemoryOperationError, MemoryPermissions};

use itertools::Itertools;
use styx_errors::anyhow::{anyhow, Context};
use styx_errors::UnknownError;
use styx_sync::sync::Arc;

use getset::CopyGetters;
use tap::Conv;
use thiserror::Error;
use zstd::{decode_all, encode_all};

use super::atomic_word::AtomicWord;
use super::physical::{AtomicMemoryOperationError, CompareExchangeError};
use super::{CompareExchangeResult, UnmappedMemoryError};

#[derive(Debug, Error)]
#[error("region not 0x{expected_alignment:X} aligned (base: 0x{base:X}, size: 0x{size:X})")]
pub struct AlignmentError {
    expected_alignment: u64,
    base: u64,
    size: u64,
}
/// Represents a base address + size span of memory.
///
/// ## Examples
///
/// ```
/// use styx_processor::memory::MemoryRegionSize;
///
/// // defined region_foo with base=0x4000 and size=0x1000
/// let region_foo = (0x4000_u64, 0x1000_u64);
///
/// // address in region
/// assert!(region_foo.contains(0x4100));
/// assert!(!region_foo.contains(0x5000));
///
/// // region in region
/// assert!(region_foo.contains_region((0x4000, 0x1000)));
/// assert!(region_foo.contains_region((0x4100, 0x200)));
///
/// // alignment
/// assert!(region_foo.aligned(0x1000));
/// assert!(!region_foo.aligned(0x8000));
/// ```
pub trait MemoryRegionSize {
    /// Base address of this region.
    fn base(&self) -> u64;
    /// Extent of this region.
    fn size(&self) -> u64;

    /// Non inclusive final address of this region
    fn end(&self) -> u64 {
        self.base() + self.size()
    }

    fn range(&self) -> Range<u64> {
        self.base()..self.end()
    }
    /// Does `address` fall into this region.
    fn contains(&self, address: u64) -> bool {
        self.range().contains(&address)
    }

    /// Is this region `alignment` aligned.
    fn aligned(&self, alignment: u64) -> bool {
        self.base() % alignment == 0 && self.size() % alignment == 0
    }

    /// Is this region `alignment` aligned.
    fn expect_aligned(&self, alignment: u64) -> Result<(), AlignmentError> {
        self.aligned(alignment)
            .then_some(())
            .ok_or_else(|| AlignmentError {
                expected_alignment: alignment,
                base: self.base(),
                size: self.size(),
            })
    }

    /// Is `other` fully contained in this region.
    fn contains_region(&self, other: impl MemoryRegionSize) -> bool {
        let base = other.base();
        let size = other.size();
        if !self.contains(base) {
            return false;
        }

        // size cannot be zero
        if size == 0 {
            return true;
        }

        // minus 1 because requested bytes are inclusive.
        // note that this being unchecked required size be > 0
        let request_max = base + size - 1;
        // base + size must be <= self.end
        // this allows reads at the last byte address size 1 to succeed,
        // and not letting things run past the end
        if request_max > self.end() {
            return false;
        }

        true
    }
}

impl MemoryRegionSize for MemoryRegion {
    fn base(&self) -> u64 {
        self.base
    }

    fn size(&self) -> u64 {
        self.size
    }
}

impl MemoryRegionSize for (u64, u64) {
    fn base(&self) -> u64 {
        self.0
    }

    fn size(&self) -> u64 {
        self.1
    }
}

pub trait MemoryRegionPerms {
    fn perms(&self) -> MemoryPermissions;
}

pub trait MemoryRegionRawData {
    fn data(&self) -> *mut u8;
}

impl MemoryRegionSize for &MemoryRegion {
    fn base(&self) -> u64 {
        self.base
    }

    fn size(&self) -> u64 {
        self.size
    }
}

impl MemoryRegionPerms for &MemoryRegion {
    fn perms(&self) -> MemoryPermissions {
        self.perms
    }
}

pub struct RegionDataHelper<'a>(&'a MemoryRegion);

impl<'a> crate::memory::helpers::Readable for RegionDataHelper<'a> {
    type Error = MemoryOperationError;

    fn read_raw(&mut self, addr: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
        self.0.read_data(addr, bytes)
    }
}

impl<'a> crate::memory::helpers::Writable for RegionDataHelper<'a> {
    type Error = MemoryOperationError;

    fn write_raw(&mut self, addr: u64, bytes: &[u8]) -> Result<(), Self::Error> {
        self.0.write_data(addr, bytes)
    }
}

#[repr(transparent)]
pub(in crate::memory) struct RegionData(pub(in crate::memory) Vec<AtomicWord>);

impl RegionData {
    pub fn empty(size: usize) -> Result<Self, AddRegionError> {
        let size_words = size.div_ceil(AtomicWord::WORD_SIZE_BYTES);

        let Ok(layout) = Layout::array::<AtomicWord>(size_words) else {
            return Err(AddRegionError::SizeTooLarge(size));
        };

        if layout.size() == 0 {
            return Ok(RegionData(Vec::with_capacity(0)));
        }
        assert!(layout.size() > 0);
        // # SAFETY
        // - Size is >0, checked at start of function and assert above.
        let buffer_ptr = unsafe { alloc_zeroed(layout) };

        // Allocating large, empty regions using `vec![AtomicWord; size]` triggers a copy to all
        // bytes in the region. This is slow and reserves the full size of the buffer.
        // In the case of a flat memory space, this could be on the order of 2^32 bytes.
        //
        // Using `vec![0u8; size]` was good because this gets optimized to a `alloc_zeroed`/calloc
        // with no writes. From my understanding, this is not possible with user defined types.
        //
        // So we create our own vec with an `alloc_zeroed` buffer.
        // # SAFETY
        // ## `Vec::from_raw_parts()`
        // - `T` is not a ZST so it is alloced from global allocator.
        // - `Layout` is used to ensure the ptr has same alignment as `T` and size
        //   is size of `T` times the `capacity`.
        // - length is <= capacity
        // - The first `length` values are properly initialized values of T because AtomicWord
        //   has the same bit validity of u64, and 0 is obviously a valid bit representation of u64.
        // - The allocated size is not too big, that would be caught by `Layout` creation.
        let bytes_vec = unsafe {
            Vec::<AtomicWord>::from_raw_parts(buffer_ptr as *mut AtomicWord, size_words, size_words)
        };

        Ok(RegionData(bytes_vec))
    }

    pub fn with_data(data: Vec<u8>) -> Result<Self, AddRegionError> {
        let chunks = data.into_iter().chunks(AtomicWord::WORD_SIZE_BYTES);
        let atomic_data = chunks.into_iter().map(|chunk| {
            let mut extra_bytes = [0u8; AtomicWord::WORD_SIZE_BYTES];
            for (i, byte) in chunk.into_iter().enumerate() {
                let cur_byte = extra_bytes.get_mut(i).expect("chunk unexpected >=8 bytes");
                *cur_byte = byte;
            }

            AtomicWord::from(extra_bytes)
        });
        Ok(RegionData(atomic_data.collect()))
    }
}

/// Memory Region, base underlying struct for all memory.
/// All memory units are composed of `n` MemoryRegion's.
///
/// Comparison's between [`MemoryRegion`]'s do not compare data,
/// only the addresses and sizes. When comparing regions it is
/// assumed that the regions do *NOT** overlap
///
/// ## No Permissions Optimization
/// If the memory region is created with no permissions (`perms.is_empty() == true`), the data store
/// will not be allocated. The region is still created but there is no underlying storage.
///
/// ## Data Storage Safety
/// The underlying data storage is a contiguous storage of atomics.
/// Previously, this was wrapped in an [`std::cell::UnsafeCell`], however I don't think this is needed anymore.
/// Atomics are already assumed to be interiorly mutable, i.e. data can mutate despite having a immutable ref.
/// This is the only concept you are opting in to with an [`std::cell::UnsafeCell`] so it is redundant.
///
/// Accessing the data via Rust atomic operations is completely safe, however certain Cpu Backends
/// (Unicorn) need contiguous buffers to operate on memory, which introduces the concept of FFI safety.
/// This is touched on in the documentation of [`MemoryRegion::as_raw_parts()`], but the basic rule is that
/// the memory data storage can be modified freely by FFI as long as a "happens before" relationship is
/// established between the FFI accesses and Rust/Styx accesses.
/// The easiest way to do this is ensure that all access to MemoryRegion are in a single thread.
///
/// See the Rust docs on the [memory model for atomic accesses] for more information.
///
/// [memory model for atomic accesses]: https://doc.rust-lang.org/std/sync/atomic/#memory-model-for-atomic-accesses
///
#[repr(C)]
#[derive(CopyGetters, Clone)]
pub struct MemoryRegion {
    /// Base address of the region.
    #[getset(get_copy = "pub")]
    base: u64,
    /// Size of region, in bytes.
    #[getset(get_copy = "pub")]
    size: u64,
    #[getset(get_copy = "pub")]
    perms: MemoryPermissions,
    /// Zero sized if the permissions are empty.
    pub(in crate::memory) data: Arc<RegionData>,
    /// The actual size of the data being stored, in bytes.
    ///
    /// This is used to skip context save/restore if it is zero.
    /// Use `size` to get the size of the region.
    effective_size: usize,
    aliased: bool,
    saved_context: Option<Vec<u8>>,
}

impl std::fmt::Display for MemoryRegion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MemoryRegion{{base: {:#x}, size: {:#x}, perms: {}}}",
            self.base, self.size, self.perms,
        )
    }
}

impl PartialEq for MemoryRegion {
    fn eq(&self, other: &Self) -> bool {
        self.base == other.base && self.size == other.size
    }
}

impl PartialOrd for MemoryRegion {
    fn gt(&self, other: &Self) -> bool {
        self.base > other.base
    }

    fn lt(&self, other: &Self) -> bool {
        self.base < other.base
    }

    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        if self < other {
            Some(std::cmp::Ordering::Less)
        } else if self > other {
            Some(std::cmp::Ordering::Greater)
        } else if self == other {
            Some(std::cmp::Ordering::Equal)
        } else {
            None
        }
    }
}

impl MemoryRegion {
    /// Create a new memory region, initializing all memory to 0.
    pub fn new(base: u64, size: u64, perms: MemoryPermissions) -> Result<Self, AddRegionError> {
        // make sure that the region size > 0
        if size == 0 {
            Err(AddRegionError::ZeroSize)
        } else {
            let effective_size = if perms.is_empty() { 0 } else { size as usize };

            let data = Arc::new(RegionData::empty(effective_size)?);

            Ok(MemoryRegion {
                base,
                size,
                perms,
                data,
                effective_size,
                aliased: false,
                saved_context: None,
            })
        }
    }

    /// Create a new memory region with existing data.
    pub fn new_with_data(
        base: u64,
        size: u64,
        perms: MemoryPermissions,
        data: Vec<u8>,
    ) -> Result<Self, AddRegionError> {
        // make sure that the region size > 0
        if size == 0 {
            return Err(AddRegionError::ZeroSize);
        }

        // make sure that the vec provided is the correct size
        if data.len() as u64 != size {
            Err(AddRegionError::DataInvalidSize(size, data.len() as u64))
        } else {
            let data = RegionData::with_data(data)?;
            Ok(MemoryRegion {
                base,
                size,
                perms,
                data: Arc::new(data),
                effective_size: size as usize,
                aliased: false,
                saved_context: None,
            })
        }
    }

    /// Returns a new [`MemoryRegion`] aliased to the current region.
    pub fn new_alias(&self, base_address: u64) -> Self {
        Self {
            base: base_address,
            size: self.size,
            perms: self.perms,
            data: self.data.clone(),
            effective_size: self.effective_size,
            aliased: true,
            saved_context: None,
        }
    }

    /// Modifies the `base_address` of the [`MemoryRegion`]
    #[inline]
    pub fn rebase(&mut self, base_address: u64) -> Result<(), MemoryOperationError> {
        self.base = base_address;

        Ok(())
    }

    /// Checks if the [`MemoryRegion`] has the desired permissions
    #[inline]
    fn permissions_check(&self, has: MemoryPermissions) -> Result<(), MemoryOperationError> {
        if self.perms & has != has {
            Err(MemoryOperationError::InvalidRegionPermissions {
                have: self.perms,
                need: has,
            })
        } else {
            Ok(())
        }
    }

    /// Returns the first address of the region.
    #[inline]
    pub fn start(&self) -> u64 {
        self.base
    }

    /// Returns the last (inclusive) address of base + size
    #[inline]
    pub fn end(&self) -> u64 {
        self.base + (self.size - 1)
    }

    /// writes a vector of data to the provided address
    pub fn write_data(&self, base: u64, data: &[u8]) -> Result<(), MemoryOperationError> {
        self.permissions_check(MemoryPermissions::WRITE)?;

        // # Safety
        // We just checked the permissions, size is checked in `write_data_unchecked`
        self.write_data_unchecked(base, data)
    }

    /// reads the specified `size` from the provided `base` address
    pub fn read_data_vec(&self, base: u64, size: u64) -> Result<Vec<u8>, MemoryOperationError> {
        self.permissions_check(MemoryPermissions::READ)?;

        // We just checked the permissions
        self.read_data_unchecked_vec(base, size)
    }

    /// reads the specified `size` from the provided `base` address
    pub fn read_data(&self, base: u64, data: &mut [u8]) -> Result<(), MemoryOperationError> {
        self.permissions_check(MemoryPermissions::READ)?;

        // We just checked the permissions
        self.read_data_unchecked(base, data)
    }

    /// Read and write the region using the memory api.
    pub fn data(&self) -> RegionDataHelper {
        RegionDataHelper(self)
    }

    /// Get the region's data as a pointer and size, probably for ffi.
    ///
    /// This returns `None` if the underlying data store is empty, which happens
    /// when the regions has no permissions.
    /// See the documentation for [`MemoryRegion`] under "no permissions optimization".
    ///
    /// ## Safety
    /// The underlying data storage in Rust land is a contiguous block of Atomics.
    ///
    /// Rust's Atomic Memory Model says that conflicting, non-synchronized operations
    /// are Undefined Behavior.
    /// Writing to this pointer without atomic operations without synchronization is undefined behavior.
    /// Because of this, by using this poiniter in FFI, you should ensure that there is a "happens-before"
    /// relationship between operations.
    /// The simplest of which is to run the FFI code in the same thread as any memory accesses, i.e. do no multithreading.
    ///
    /// It is unwise to ever cast this to a slice of u8, or any non-atomic data store, even `UnsafeCell<[u8]>`.
    /// The underlying data store is an array of atomics and the memory should be considered volatile.
    /// For example, if cast as a &[u8], the compiler will assume the data will not change and generate
    /// incorrect code. See [this blog post] for more information.
    ///
    /// [this blog post]: https://leon.schuermann.io/blog/2024-08-07_rust-mutex-atomics-unsafecell_spooky-action-at-a-distance.html
    ///
    pub fn as_raw_parts(&self) -> Option<(*const u8, NonZeroUsize)> {
        if self.data.0.is_empty() {
            None
        } else {
            let vec = &self.data.0;
            let ptr = vec.as_ptr();
            let size = NonZeroUsize::new(self.size as usize)
                .expect("unexpected memory region with size=0 has non empty data vector");
            Some((ptr as *const u8, size))
        }
    }

    /// # Permissions
    /// This method is only intended to be called from emulated peripherals,
    /// never from emulator guest code. The unsafety here is that guest code
    /// could access memory that should be disallowed, and the system would
    /// not generate a fault as it should.
    ///
    /// ## Proper use
    /// In that vein, peripherals and emulator code using this method should
    /// only use this to write to memory mapped registers etc. And must
    /// ensure that when operations like DMA transfers are occurring that
    /// the respective manual is followed so that styx properly checks
    /// permissions when required (eg. if a DMA transfer cannot write to
    /// a page it doesn't have permissions for -- don't let it).
    pub fn write_data_unchecked(&self, base: u64, data: &[u8]) -> Result<(), MemoryOperationError> {
        self.address_range_valid(base, data.len() as u64, MemoryOperation::Write)?;

        // the start index into our underlying Vec<u8>
        let byte_idx: usize = (base - self.base) as usize;

        let left_byte_idx = byte_idx;
        let (left, middle, right) = align_access::<{ AtomicWord::WORD_SIZE_BYTES }>(byte_idx, data);

        if !left.is_empty() {
            let left_idx = byte_idx / AtomicWord::WORD_SIZE_BYTES;
            self.data.0[left_idx]
                .write(left_byte_idx % AtomicWord::WORD_SIZE_BYTES, left)
                .unwrap();
        }

        if !middle.is_empty() {
            let middle_byte_idx = byte_idx + left.len();
            // middle is word aligned
            debug_assert!(middle_byte_idx % AtomicWord::WORD_SIZE_BYTES == 0);
            let middle_idx = middle_byte_idx / AtomicWord::WORD_SIZE_BYTES;
            for (i, word_bytes) in middle.iter().enumerate() {
                self.data.0[middle_idx + i].write(0, word_bytes).unwrap();
            }
        }

        if !right.is_empty() {
            let right_byte_idx = byte_idx + left.len() + middle.as_flattened().len();
            // right is word aligned
            debug_assert!(right_byte_idx % AtomicWord::WORD_SIZE_BYTES == 0);
            let right_idx = right_byte_idx / AtomicWord::WORD_SIZE_BYTES;
            self.data.0[right_idx].write(0, right).unwrap();
        }
        Ok(())
    }

    /// Write that is guaranteed atomic, or will error if cannot be atomic.
    ///
    /// Currently, the requirements to have an atomic operation are:
    /// - Must fit inside a word.
    pub fn write_atomic(&self, base: u64, data: &[u8]) -> Result<(), AtomicMemoryOperationError> {
        self.address_range_valid(base, data.len() as u64, MemoryOperation::Write)?;

        // the start index into our underlying Vec<u8>
        let byte_idx: usize = (base - self.base) as usize;

        match align_access::<{ AtomicWord::WORD_SIZE_BYTES }>(byte_idx, data) {
            // ONLY left or ONLY right
            // this fits in an word so we are good
            (bytes, [], []) | ([], [], bytes) => {
                let word_idx = byte_idx / AtomicWord::WORD_SIZE_BYTES;
                // this will be 0 for !right.is_empty()
                let inside_word_idx = byte_idx % AtomicWord::WORD_SIZE_BYTES;
                self.data.0[word_idx].write(inside_word_idx, bytes).unwrap();
                Ok(())
            }
            // ONLY middle and ONLY one item
            // this will fit in an word
            ([], [bytes], []) => {
                let word_idx = byte_idx / AtomicWord::WORD_SIZE_BYTES;
                self.data.0[word_idx].write(0, bytes).unwrap();
                Ok(())
            }
            // any more WILL NOT fit in an word
            _ => Err(AtomicMemoryOperationError::TooLarge {
                address: base,
                bytes: data.len(),
                max_size: AtomicWord::WORD_SIZE_BYTES,
            }),
        }
    }

    /// Write that is guaranteed atomic, or will error if cannot be atomic.
    ///
    /// Currently, the requirements to have an atomic operation are:
    /// - Must fit inside a word.
    pub fn read_atomic(
        &self,
        base: u64,
        data: &mut [u8],
    ) -> Result<(), AtomicMemoryOperationError> {
        self.address_range_valid(base, data.len() as u64, MemoryOperation::Read)?;

        // the start index into our underlying Vec<u8>
        let byte_idx: usize = (base - self.base) as usize;

        match align_access_mut::<{ AtomicWord::WORD_SIZE_BYTES }>(byte_idx, data) {
            // ONLY left or ONLY right
            // this fits in an word so we are good
            (bytes, [], []) | ([], [], bytes) => {
                let word_idx = byte_idx / AtomicWord::WORD_SIZE_BYTES;
                // this will be 0 for !right.is_empty()
                let inside_word_idx = byte_idx % AtomicWord::WORD_SIZE_BYTES;
                self.data.0[word_idx].read(inside_word_idx, bytes).unwrap();
                Ok(())
            }
            // ONLY middle and ONLY one item
            // this will fit in an word
            ([], [bytes], []) => {
                let word_idx = byte_idx / AtomicWord::WORD_SIZE_BYTES;
                self.data.0[word_idx].read(0, bytes).unwrap();
                Ok(())
            }
            // any more WILL NOT fit in an word
            _ => Err(AtomicMemoryOperationError::TooLarge {
                address: base,
                bytes: data.len(),
                max_size: AtomicWord::WORD_SIZE_BYTES,
            }),
        }
    }

    /// Perform a Compare Exchange operation on `address`, writing `new` if the current value of those bytes is `new`.
    pub fn compare_exchange(
        &self,
        address: u64,
        current: &[u8],
        new: &[u8],
    ) -> Result<CompareExchangeResult, CompareExchangeError> {
        if current.len() != new.len() {
            return Err(CompareExchangeError::MismatchedSizes(
                current.len(),
                new.len(),
            ));
        }
        let op_size = current.len();
        self.address_range_valid(address, op_size as u64, MemoryOperation::Read)
            .map_err(|e| e.conv::<AtomicMemoryOperationError>())?;

        // the start index into our underlying Vec<u8>
        let byte_idx: usize = (address - self.base) as usize;

        let word_idx;
        let inside_word_idx;
        match align_access::<{ AtomicWord::WORD_SIZE_BYTES }>(byte_idx, current) {
            // ONLY left or ONLY right
            // this fits in an word so we are good
            (_, [], []) | ([], [], _) => {
                word_idx = byte_idx / AtomicWord::WORD_SIZE_BYTES;
                // this will be 0 for !right.is_empty()
                inside_word_idx = byte_idx % AtomicWord::WORD_SIZE_BYTES;
            }
            // ONLY middle and ONLY one item
            // this will fit in an word and is word aligned
            ([], [_], []) => {
                word_idx = byte_idx / AtomicWord::WORD_SIZE_BYTES;
                inside_word_idx = 0;
            }
            // any more WILL NOT fit in an word
            _ => {
                return Err(AtomicMemoryOperationError::TooLarge {
                    address,
                    bytes: current.len(),
                    max_size: AtomicWord::WORD_SIZE_BYTES,
                }
                .into())
            }
        }

        // we've checked size and alginement of our compare and swap, this should never Err
        Ok(self.data.0[word_idx]
            .compare_exchange(inside_word_idx, current, new)
            .expect("bug in memory region compare and swap"))
    }

    /// # Safety
    /// This method is only intended to be called from emulated peripherals,
    /// never from emulator guest code. The unsafety here is that guest code
    /// could access memory that should be disallowed, and the system would
    /// not generate a fault as it should.
    ///
    /// ## Proper use
    /// In that vein, peripherals and emulator code using this method should
    /// only use this to write to memory mapped registers etc. And must
    /// ensure that when operations like DMA transfers are occurring that
    /// the respective manual is followed so that styx properly checks
    /// permissions when required (eg. if a DMA transfer cannot write to
    /// a page it doesn't have permissions for -- don't let it).
    pub fn read_data_unchecked(
        &self,
        base: u64,
        data: &mut [u8],
    ) -> Result<(), MemoryOperationError> {
        self.address_range_valid(base, data.len() as u64, MemoryOperation::Read)?;

        // the start index into our underlying Vec<u8>
        let byte_idx: usize = (base - self.base) as usize;

        let left_byte_idx = byte_idx;
        let (left, middle, right) =
            align_access_mut::<{ AtomicWord::WORD_SIZE_BYTES }>(byte_idx, data);

        if !left.is_empty() {
            let left_idx = byte_idx / AtomicWord::WORD_SIZE_BYTES;
            self.data.0[left_idx]
                .read(left_byte_idx % AtomicWord::WORD_SIZE_BYTES, left)
                .unwrap();
        }

        if !middle.is_empty() {
            let middle_byte_idx = byte_idx + left.len();
            // middle is word aligned
            debug_assert!(middle_byte_idx % AtomicWord::WORD_SIZE_BYTES == 0);
            let middle_idx = middle_byte_idx / AtomicWord::WORD_SIZE_BYTES;
            for (i, word_bytes) in middle.iter_mut().enumerate() {
                self.data.0[middle_idx + i].read(0, word_bytes).unwrap();
            }
        }

        if !right.is_empty() {
            let right_byte_idx = byte_idx + left.len() + middle.as_flattened().len();
            // right is word aligned
            debug_assert!(right_byte_idx % AtomicWord::WORD_SIZE_BYTES == 0);
            let right_idx = right_byte_idx / AtomicWord::WORD_SIZE_BYTES;
            self.data.0[right_idx].read(0, right).unwrap();
        }
        Ok(())
    }

    pub fn read_data_unchecked_vec(
        &self,
        base: u64,
        size: u64,
    ) -> Result<Vec<u8>, MemoryOperationError> {
        let mut buffer = vec![0u8; size as usize];
        self.read_data_unchecked(base, buffer.as_mut_slice())?;
        Ok(buffer)
    }

    /// Validate that the requested range is within the current memory
    /// region.
    fn address_range_valid(
        &self,
        base: u64,
        size: u64,
        _op: MemoryOperation,
    ) -> Result<(), MemoryOperationError> {
        // size cannot be zero
        if size == 0 {
            return Ok(());
        }

        // minus 1 because requested bytes are inclusive.
        // note that this being unchecked required size be > 0
        let request_max = base + (size - 1);

        if base < self.base || base > self.end() {
            return Err(MemoryOperationError::UnmappedMemory(
                UnmappedMemoryError::UnmappedStart(base),
            ));
        }

        // base + size must be <= self.end
        // this allows reads at the last byte address size 1 to succeed,
        // and not letting things run past the end
        if request_max > self.end() {
            return Err(MemoryOperationError::UnmappedMemory(
                UnmappedMemoryError::GoesUnmapped(self.end() - base),
            ));
        }

        Ok(())
    }

    /// Reads contents of the [`MemoryRegion`] and saves it
    ///
    /// # Safety
    /// This will overwrite an previously saved context; the caller MUST
    /// PAUSE the CPU to stop execution before calling.
    pub unsafe fn context_save(&mut self) -> Result<(), UnknownError> {
        if self.effective_size > 0 {
            self.saved_context = Some(
                encode_all(
                    self.read_data_unchecked_vec(self.base, self.size)
                        .with_context(|| "could not read data while saving")?
                        .as_slice(),
                    0,
                )
                .unwrap(),
            );
        }
        Ok(())
    }

    /// Overwrites contents of the [`MemoryRegion`] with the saved_context
    /// Returns an error if saved_context is empty.
    ///
    /// # Safety
    /// This will overwrite the entire region; the caller MUST PAUSE the CPU to stop execution
    /// before calling.
    pub unsafe fn context_restore(&mut self) -> Result<(), UnknownError> {
        if self.effective_size > 0 {
            match &self.saved_context {
                Some(contents) => {
                    let data = decode_all(contents.as_slice())
                        .with_context(|| "could not decode saved data")?;
                    self.write_data_unchecked(self.base, data.as_slice())
                        .with_context(|| "could not write data while restoring")?;
                }
                None => Err(anyhow!("no saved context to restore from"))?,
            }
        }
        Ok(())
    }
}

/// Crates a list of full, word aligned bytes, along with the remainder at the beginning and end.
///
/// The left and right slices are guaranteed to be `< ALIGN`.
/// The middle and right bytes are guaranteed to be aligned on `ALIGN`.
///
/// `start_offset` is the byte address into the `Vec` of Words. I.e. 0 and 8 are Word aligned.
fn align_access<const ALIGN: usize>(
    offset_byte: usize,
    buffer: &[u8],
) -> (&[u8], &[[u8; ALIGN]], &[u8]) {
    let start_into_word = offset_byte % ALIGN;
    // modulo ALIGN here otherwise an already aligned buffer
    // would be 8-0 = 8, when in reality we are already aligned, should be 0.
    let bytes_until_aligned = (ALIGN - start_into_word) % ALIGN;

    let split_idx = bytes_until_aligned.min(buffer.len());
    // won't panic since we know that buffer has >=offset len
    let (left, rest) = buffer.split_at(split_idx);
    let (middle, right) = rest.as_chunks();
    (left, middle, right)
}

/// See [`align_access()`].
fn align_access_mut<const ALIGN: usize>(
    offset_byte: usize,
    buffer: &mut [u8],
) -> (&mut [u8], &mut [[u8; ALIGN]], &mut [u8]) {
    let start_into_word = offset_byte % ALIGN;
    let bytes_until_aligned = (ALIGN - start_into_word) % ALIGN;

    let split_idx = bytes_until_aligned.min(buffer.len());
    // won't panic since we know that buffer has >=offset len
    let (left, rest) = buffer.split_at_mut(split_idx);
    let (middle, right) = rest.as_chunks_mut();
    (left, middle, right)
}

impl Debug for &MemoryRegion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MemoryRegion(start: 0x{:X}, size: 0x{:X}, end: 0x{:X}, perms: {})",
            self.base,
            self.size,
            self.base + self.size,
            self.perms
        )
    }
}

#[derive(Clone, Copy, Default)]
pub struct MemoryRegionFormat {
    /// Show a bool if the region is all zero.
    pub is_zeroed: bool,
    /// Display all the data in this region.
    pub show_data: bool,
}

struct MemoryRegionWithFormat<'a> {
    region: &'a MemoryRegion,
    format: MemoryRegionFormat,
}

impl<'a> Debug for MemoryRegionWithFormat<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let region = self.region;
        write!(
            f,
            "MemoryRegion(start: 0x{:X}, size: 0x{:X}, end: 0x{:X}, perms: {}",
            region.base,
            region.size,
            region.base + region.size,
            region.perms
        )?;
        if self.format.is_zeroed || self.format.show_data {
            let data = self
                .region
                .read_data_vec(self.region.base, self.region.size)
                .unwrap();

            if self.format.is_zeroed {
                let is_empty = data.iter().all(|a| *a == 0);
                write!(f, ", is_empty: {is_empty}")?;
            }
            if self.format.show_data {
                write!(f, ", data: {data:X?}")?;
            }
        }
        write!(f, ")")?;
        Ok(())
    }
}

/// Trait for anything that has a list of [`MemoryRegion`]s.
pub trait HasRegions {
    /// Iterate over the [`MemoryRegion`]s that this has.
    fn regions(&self) -> impl Iterator<Item = &MemoryRegion>;

    /// Format the list of regions using the default [`MemoryRegionFormat`].
    fn format_regions(&self) -> MemoryRegionsWithFormat<Self> {
        self.with_format(MemoryRegionFormat::default())
    }

    /// Format the list of regions using a [`MemoryRegionFormat`].
    fn with_format(&self, format: MemoryRegionFormat) -> MemoryRegionsWithFormat<Self> {
        MemoryRegionsWithFormat {
            regions: self,
            format,
        }
    }
}

pub struct MemoryRegionsWithFormat<'a, T: ?Sized> {
    regions: &'a T,
    format: MemoryRegionFormat,
}

impl<'a, T: HasRegions> Debug for MemoryRegionsWithFormat<'a, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let regions = self.regions.regions();
        for region in regions {
            let format = MemoryRegionWithFormat {
                region,
                format: self.format,
            };
            write!(f, "{format:?}")?;
        }
        Ok(())
    }
}

impl<'a, T> MemoryRegionsWithFormat<'a, T> {
    pub fn with_format(self, format: MemoryRegionFormat) -> Self {
        Self {
            regions: self.regions,
            format,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::memory::helpers::{ReadExt, WriteExt};
    use crate::memory::MemoryOperation;
    use crate::memory::MemoryPermissions as Perms;

    use test_case::test_case;

    #[test_case(0, 8, (0, 8, 0))]
    #[test_case(4, 4, (4, 0, 0))]
    #[test_case(4, 8, (4, 0, 4))]
    #[test_case(4, 12, (4, 8, 0))]
    #[test_case(4, 16, (4, 8, 4))]
    #[test_case(4, 18, (4, 8, 6))]
    #[test_case(8, 34, (0, 32, 2))]
    // important test: crosses align
    // boundary but is not large enough
    // for a full word.
    #[test_case(6, 6, (2, 0, 4))]
    #[test_case(0, 0, (0, 0, 0))]
    #[test_case(4, 0, (0, 0, 0))]
    fn test_align(start_offset: usize, size: usize, expected_sizes: (usize, usize, usize)) {
        println!("running with start_idx={start_offset},size={size}");
        let buffer = (start_offset..(start_offset + size))
            .map(|a| a as u8)
            .collect_vec();
        let mut buffer_2_electric_boogaloo = buffer.clone();
        let (left, middle, right) = align_access::<8>(start_offset, buffer.as_slice());
        let (left_mut, middle_mut, right_mut) =
            align_access_mut::<8>(start_offset, buffer_2_electric_boogaloo.as_mut_slice());

        assert_eq!(left, left_mut);
        assert_eq!(middle, middle_mut);
        assert_eq!(right, right_mut);

        assert_eq!(left.len(), expected_sizes.0);
        assert_eq!(middle.as_flattened().len(), expected_sizes.1,);
        assert_eq!(right.len(), expected_sizes.2);

        assert_eq!(left, &buffer[..expected_sizes.0]);
        assert_eq!(
            middle.as_flattened(),
            &buffer[expected_sizes.0..(expected_sizes.0 + expected_sizes.1)]
        );
        assert_eq!(
            right,
            &buffer[(expected_sizes.0 + expected_sizes.1)
                ..(expected_sizes.0 + expected_sizes.1 + expected_sizes.2)]
        );

        let region = MemoryRegion::new(0x0, 0x1024, MemoryPermissions::all()).unwrap();
        let bytes = (1..size as u8 + 1).collect_vec();
        region
            .data()
            .write(start_offset)
            .bytes(bytes.as_slice())
            .unwrap();
        let read_bytes = region.data().read(start_offset).vec(size).unwrap();
        assert_eq!(bytes, read_bytes);
    }

    #[test_case(0x0, 0x0, true)]
    #[test_case(0x0, 0x4, true)]
    #[test_case(0x0, 0x8, true)]
    #[test_case(0x10, 0x8, true)]
    #[test_case(0x12, 0x8, false)]
    #[test_case(0x10, 0xA, false)]
    #[test_case(0x2, 0x2, true)]
    #[test_case(0x2, 0x4, true)]
    fn test_atomic_read_write(start_offset: u64, size: u64, success: bool) {
        let buffer = (start_offset..(start_offset + size))
            .map(|a| a as u8)
            .collect_vec();
        let region = MemoryRegion::new(0x0, 0x1000, MemoryPermissions::all()).unwrap();
        let result = region.write_atomic(start_offset, buffer.as_slice());
        assert!(result.is_ok() == success);

        let mut read_buffer = vec![0u8; buffer.len()];
        let result = region.read_atomic(start_offset, &mut read_buffer);
        assert_eq!(result.is_ok(), success);

        let expected_buffer = if success {
            buffer.as_slice()
        } else {
            &vec![0u8; buffer.len()]
        };
        assert_eq!(expected_buffer, read_buffer);
    }

    #[test_case(0x0, 0x1; "base too small")]
    #[test_case(0x1100, 0x1; "starts after region")]
    #[test_case(0xFFE, 0x2; "overlap bottom")]
    #[test_case(0x10FF, 0x2; "overlap top")]
    #[test_case(0x1000, 0x101; "larger than region")]
    fn test_valid_address_range_err(base: u64, size: u64) {
        let region = MemoryRegion::new(0x1000, 0x100, Perms::all()).unwrap();

        let result = region.address_range_valid(base, size, MemoryOperation::Read);

        assert!(result.is_err());
    }

    #[test_case(0x1000, 0x0; "size is zero")]
    fn test_memory_range_creation_range_err(start: u64, size: u64) {
        let perms = Perms::all();
        assert!(matches!(
            MemoryRegion::new(start, size, perms),
            Err(AddRegionError::ZeroSize)
        ));
    }

    #[test_case(1)]
    #[test_case(2)]
    #[test_case(4)]
    #[test_case(8)]
    #[test_case(9)]
    #[test_case(12)]
    #[test_case(200)]
    fn test_memory_range_creation_valid(size: u8) {
        let data = (1..size + 1).collect_vec();
        // end is after beginning
        let perms = Perms::all();
        assert!(MemoryRegion::new(0, size as u64, perms).is_ok());

        // vector is correct size
        let data_region = MemoryRegion::new_with_data(0, size as u64, perms, data.clone()).unwrap();

        let read_data = data_region.read_data_vec(0, size as u64).unwrap();
        assert_eq!(read_data, data);
    }

    #[test_case(0x100; "vec too small")]
    #[test_case(0x1000; "vec too big")]
    #[test_case(0; "vec empty")]
    fn test_memory_range_creation_size(vec_size: usize) {
        let data = vec![0; vec_size];
        let result = MemoryRegion::new_with_data(0x100, 0x1ff, Perms::all(), data);

        // test vec not being the correct size
        assert!(matches!(result, Err(AddRegionError::DataInvalidSize(_, _))));
    }

    #[test]
    fn test_read_memory_bad_perms() {
        // make initial region
        let region = MemoryRegion::new(0x1000, 0x1100, Perms::WRITE).unwrap();

        // attempt a read
        let result = region.read_data_vec(0x1000, 32);

        // test cannot read from write only
        assert!(matches!(
            result,
            Err(MemoryOperationError::InvalidRegionPermissions {
                have: Perms::WRITE,
                need: Perms::READ
            })
        ));
    }

    #[test]
    fn test_write_memory_bad_perms() {
        // make initial region
        let region = MemoryRegion::new(0x1000, 0x1100, Perms::READ).unwrap();

        // attempt a write
        let result = region.write_data(0x1000, &[1, 2, 3, 4]);

        // test cannot write to read only
        assert!(matches!(
            result,
            Err(MemoryOperationError::InvalidRegionPermissions {
                have: Perms::READ,
                need: Perms::WRITE
            })
        ));
    }

    #[test]
    fn test_read_data_memory_bad_perms() {
        // make initial region
        let region = MemoryRegion::new(0x1000, 0x1100, Perms::WRITE).unwrap();

        // attempt a write
        let result = region.read_data_vec(0x1000, 0x4);

        // test cannot read from write only
        assert!(matches!(
            result,
            Err(MemoryOperationError::InvalidRegionPermissions {
                have: Perms::WRITE,
                need: Perms::READ
            })
        ));
    }

    #[test]
    fn test_write_data_memory_bad_perms() {
        // make initial region
        let region = MemoryRegion::new(0x1000, 0x1100, Perms::READ).unwrap();

        // attempt a write
        let result = region.write_data(0x1000, &[0, 1, 2]);

        // test cannot write to read only
        assert!(matches!(
            result,
            Err(MemoryOperationError::InvalidRegionPermissions {
                have: Perms::READ,
                need: Perms::WRITE
            })
        ));
    }

    #[test_case(0x1000, &[0], Perms::READ; "(R) Write valid vec to valid beginning")]
    #[test_case(0x1000, &[0], Perms::WRITE; "(W) Write valid vec to valid beginning")]
    #[test_case(0x1010, &[0], Perms::READ; "(R) Write valid vec to valid middle")]
    #[test_case(0x1010, &[0], Perms::WRITE; "(W) Write valid vec to valid middle")]
    #[test_case(0x10FF, &[0], Perms::READ; "(R) Write valid vec to top byte")]
    #[test_case(0x10FF, &[0], Perms::WRITE; "(W) Write valid vec to top byte")]
    fn test_write_data_memory_unchecked_valid(base: u64, data: &[u8], perms: MemoryPermissions) {
        // make initial region
        let region = MemoryRegion::new(0x1000, 0x100, perms).unwrap();

        // assert write ok
        assert!(region.write_data_unchecked(base, data).is_ok());
    }

    #[test_case(0x1000, &[0], Perms::WRITE; "(W) Write valid vec to valid beginning")]
    #[test_case(0x1010, &[0], Perms::WRITE; "(W) Write valid vec to valid middle")]
    #[test_case(0x10FF, &[0], Perms::WRITE; "(W) Write valid vec to top byte")]
    fn test_write_data_memory_valid(base: u64, data: &[u8], perms: MemoryPermissions) {
        // make initial region
        let region = MemoryRegion::new(0x1000, 0x100, perms).unwrap();

        // assert write ok
        assert!(region.write_data(base, data).is_ok());
    }

    #[test_case(0x100, &[0], Perms::READ; "(R) Write below memory map")]
    #[test_case(0x100, &[0], Perms::WRITE; "(W) Write below memory map")]
    #[test_case(0x10000, &[0], Perms::READ; "(R) Write above memory map")]
    #[test_case(0x10000, &[0], Perms::WRITE; "(W) Write above memory map")]
    #[test_case(0x10FF, &[0, 1], Perms::READ; "(R) Write overlap high end")]
    #[test_case(0x10FF, &[0, 1], Perms::WRITE; "(W) Write overlap high end")]
    #[test_case(0xFFF, &[0, 1], Perms::READ; "(R) Write overlap low end")]
    #[test_case(0xFFF, &[0, 1], Perms::WRITE; "(W) Write overlap low end")]
    fn test_write_data_memory_unchecked_err(start: u64, data: &[u8], perms: MemoryPermissions) {
        // make initial region
        let region = MemoryRegion::new(0x1000, 0x100, perms).unwrap();

        // attempt to write
        let result = region.write_data_unchecked(start, data);
        assert!(matches!(
            result,
            Err(MemoryOperationError::UnmappedMemory(_))
        ));
    }

    #[test_case(0x100, &[0], Perms::WRITE; "(W) Write below memory map")]
    #[test_case(0x10000, &[0], Perms::WRITE; "(W) Write above memory map")]
    #[test_case(0x10FF, &[0, 1], Perms::WRITE; "(W) Write overlap high end")]
    #[test_case(0xFFF, &[0, 1], Perms::WRITE; "(W) Write overlap low end")]
    fn test_write_data_memory_err(start: u64, data: &[u8], perms: MemoryPermissions) {
        // make initial region
        let region = MemoryRegion::new(0x1000, 0x100, perms).unwrap();

        // attempt to write
        let result = region.write_data(start, data);
        assert!(matches!(
            result,
            Err(MemoryOperationError::UnmappedMemory(_))
        ));
    }

    #[test_case(0x100, 8, Perms::READ; "(R) Read below memory map")]
    #[test_case(0x100, 8, Perms::WRITE; "(W) Read below memory map")]
    #[test_case(0x10000, 8, Perms::READ; "(R) Read above memory map")]
    #[test_case(0x10000, 8, Perms::WRITE; "(W) Read above memory map")]
    #[test_case(0x10FE, 8, Perms::READ; "(R) Read overlap high end")]
    #[test_case(0x10FE, 8, Perms::WRITE; "(W) Read overlap high end")]
    #[test_case(0x10FE, 3, Perms::READ; "(R) Read overlap high 1 byte")]
    #[test_case(0x10FE, 3, Perms::WRITE; "(W) Read overlap high 1 byte")]
    #[test_case(0xFFE, 3, Perms::READ; "(R) Read overlap bottom end")]
    #[test_case(0xFFE, 3, Perms::WRITE; "(W) Read overlap bottom end")]
    fn test_read_data_memory_unchecked_err(base: u64, size: u64, perms: MemoryPermissions) {
        // make initial region
        let region = MemoryRegion::new(0x1000, 0x100, perms).unwrap();

        // attempt to read
        let result = region.read_data_unchecked_vec(base, size);

        assert!(matches!(
            result,
            Err(MemoryOperationError::UnmappedMemory(_))
        ));
    }

    #[test_case(0x100, 8, Perms::READ; "(R) Read below memory map")]
    #[test_case(0x10000, 8, Perms::READ; "(R) Read above memory map")]
    #[test_case(0x10FE, 8, Perms::READ; "(R) Read overlap high end")]
    #[test_case(0x10FE, 3, Perms::READ; "(R) Read overlap high 1 byte")]
    #[test_case(0xFFE, 3, Perms::READ; "(R) Read overlap bottom end")]
    fn test_read_data_memory_err(base: u64, size: u64, perms: MemoryPermissions) {
        // make initial region
        let region = MemoryRegion::new(0x1000, 0x100, perms).unwrap();

        // attempt to read
        let result = region.read_data_vec(base, size);

        assert!(matches!(
            result,
            Err(MemoryOperationError::UnmappedMemory(_))
        ));
    }

    #[test_case(0x1000, 8, Perms::READ; "(R) Read from beginning")]
    #[test_case(0x1000, 8, Perms::WRITE; "(W) Read from beginning")]
    #[test_case(0x1008, 8, Perms::READ; "(R) Read from middle")]
    #[test_case(0x1008, 8, Perms::WRITE; "(W) Read from middle")]
    #[test_case(0x10FF, 1, Perms::READ; "(R) Read top byte")]
    #[test_case(0x10FF, 1, Perms::WRITE; "(W) Read top byte")]
    fn test_read_data_memory_unchecked_valid(base: u64, size: u64, perms: MemoryPermissions) {
        // make initial region
        let mut data = Vec::new();
        for i in 0x1000..0x1100 {
            data.push((i % 0xff) as u8);
        }
        let validation = data.clone();
        let region = MemoryRegion::new_with_data(0x1000, 0x100, perms, data).unwrap();

        // assert read ok
        if let Ok(value) = region.read_data_unchecked_vec(base, size) {
            // assert value correct
            let start_idx = base as usize - 0x1000;
            assert_eq!(validation[start_idx..start_idx + size as usize], value)
        } else {
            panic!("Read size {size} @  {base:#08X} failed!");
        }
    }

    #[test_case(0x1000, 8, Perms::READ; "(R) Read from beginning")]
    #[test_case(0x1008, 8, Perms::READ; "(R) Read from middle")]
    #[test_case(0x10FF, 1, Perms::READ; "(R) Read top byte")]
    fn test_read_data_memory_valid(base: u64, size: u64, perms: MemoryPermissions) {
        // make initial region
        let mut data = Vec::new();
        for i in 0x1000..0x1100 {
            data.push((i % 0xff) as u8);
        }
        let validation = data.clone();
        let region = MemoryRegion::new_with_data(0x1000, 0x100, perms, data).unwrap();

        // assert read ok
        if let Ok(value) = region.read_data_vec(base, size) {
            // assert value correct
            let start_idx = base as usize - 0x1000;
            assert_eq!(validation[start_idx..start_idx + size as usize], value)
        } else {
            panic!("Read size {size} @  {base:#08X} failed!");
        }
    }

    /// The `as_raw_parts()` method should give the raw parts of the underlying slice.
    #[test]
    fn test_as_raw_parts() {
        // Using a size greater than 1 word but not on word boundraries
        let expected_data = (0..0x4B).collect_vec();
        let region = MemoryRegion::new_with_data(
            0x1000,
            expected_data.len() as u64,
            MemoryPermissions::all(),
            expected_data.clone(),
        )
        .unwrap();

        let actual_read = region
            .read_data_vec(0x1000, expected_data.len() as u64)
            .unwrap();
        // sanity check
        assert_eq!(actual_read, expected_data);

        let (ptr, size) = region.as_raw_parts().unwrap();
        let slice = unsafe { std::slice::from_raw_parts(ptr, size.get()) };
        assert_eq!(slice, &expected_data);
    }
}
