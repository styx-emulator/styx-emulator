// SPDX-License-Identifier: BSD-2-Clause
use std::ops::Range;

use crate::memory::{AddRegionError, MemoryOperation, MemoryOperationError, MemoryPermissions};

use styx_errors::anyhow::{anyhow, Context};
use styx_errors::UnknownError;
use styx_sync::cell::UnsafeCell;
use styx_sync::sync::Arc;

use getset::CopyGetters;
use thiserror::Error;
use zstd::{decode_all, encode_all};

use super::UnmappedMemoryError;

#[derive(Debug, Error)]
#[error("region not 0x{expected_alignment:X} aligned (base: 0x{base:X}, size: 0x{size:X})")]
pub struct AlignmentError {
    expected_alignment: u64,
    base: u64,
    size: u64,
}
/// Represents a base address + size span of memory.
///
/// # Examples
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

pub trait MemoryRegionData: MemoryRegionSize {
    fn data(&self) -> &[u8];
    fn data_mut(&mut self) -> &mut [u8];
}
impl MemoryRegionData for MemoryRegion {
    fn data(&self) -> &[u8] {
        unsafe { (*self.data.with_mut(|a| a)).as_mut_slice() }
    }

    fn data_mut(&mut self) -> &mut [u8] {
        unsafe { (*self.data.with_mut(|a| a)).as_mut_slice() }
    }
}

impl<T: MemoryRegionData> crate::memory::helpers::Readable for &T {
    type Error = UnknownError;

    fn read_raw(&mut self, addr: u64, bytes: &mut [u8]) -> Result<(), Self::Error> {
        let size = bytes.len();
        if !self.contains_region((addr, size as u64)) {
            return Err(anyhow!("not in region"));
        }

        let base_index = (addr - self.base()) as usize;
        bytes.copy_from_slice(&self.data()[base_index..(base_index + size)]);
        Ok(())
    }
}
impl<T: MemoryRegionData> crate::memory::helpers::Writable for &mut T {
    type Error = UnknownError;

    fn write_raw(&mut self, addr: u64, bytes: &[u8]) -> Result<(), Self::Error> {
        let size = bytes.len();
        if !self.contains_region((addr, size as u64)) {
            return Err(anyhow!("not in region"));
        }

        let base_index = (addr - self.base()) as usize;
        let self_slice = &mut self.data_mut()[base_index..(base_index + size)];

        self_slice.copy_from_slice(bytes);
        Ok(())
    }
}

pub struct MemoryRegionView<'a> {
    pub base: u64,
    pub perms: MemoryPermissions,
    pub data: &'a mut [u8],
}
impl MemoryRegionSize for MemoryRegionView<'_> {
    fn base(&self) -> u64 {
        self.base
    }

    fn size(&self) -> u64 {
        self.data.len() as u64
    }
}
impl<'a> From<&'a mut MemoryRegion> for MemoryRegionView<'a> {
    fn from(value: &'a mut MemoryRegion) -> Self {
        let ptr = unsafe { (*value.data.with_mut(|a| a)).as_mut_slice() };
        MemoryRegionView {
            base: value.base,
            perms: value.perms,
            data: ptr,
        }
    }
}
impl MemoryRegionData for MemoryRegionView<'_> {
    fn data(&self) -> &[u8] {
        self.data
    }

    fn data_mut(&mut self) -> &mut [u8] {
        self.data
    }
}

/// Memory Region, base underlying struct for all memory.
/// All memory units are composed of `n` MemoryRegion's.
///
/// Comparison's between [`MemoryRegion`]'s do not compare data,
/// only the addresses and sizes. When comparing regions it is
/// assumed that the regions do *NOT** overlap
#[repr(C)]
#[derive(CopyGetters, Debug, Clone)]
pub struct MemoryRegion {
    #[getset(get_copy = "pub")]
    base: u64,
    #[getset(get_copy = "pub")]
    size: u64,
    #[getset(get_copy = "pub")]
    perms: MemoryPermissions,
    data: Arc<UnsafeCell<Vec<u8>>>,
    // the actual size of the data being stored
    effective_size: u64,
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
    /// Create a new memory region, initializing all memory to 0
    /// and creating a buffer that can be used elsewhere
    /// if perms are empty, create an empty vector
    pub fn new(base: u64, size: u64, perms: MemoryPermissions) -> Result<Self, AddRegionError> {
        // make sure that the region size > 0
        if size == 0 {
            Err(AddRegionError::ZeroSize)
        } else {
            let data;
            let effective_size;
            if perms.is_empty() {
                data = Arc::new(UnsafeCell::new(Vec::with_capacity(0)));
                effective_size = 0;
            } else {
                data = Arc::new(UnsafeCell::new(vec![0; size as usize]));
                effective_size = size;
            }

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

    /// Create a new memory region with already created memory
    /// data.
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
            Ok(MemoryRegion {
                base,
                size,
                perms,
                data: Arc::new(UnsafeCell::new(data)),
                effective_size: size,
                aliased: false,
                saved_context: None,
            })
        }
    }

    /// Returns a new [`MemoryRegion`] aliased to the current
    /// region.
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
    ///
    /// # Safety
    /// Should not be invoked while [`MemoryRegion`] is in use,
    /// safe usage can only occur while configuring and setting
    /// up initial memory states
    #[inline]
    pub unsafe fn rebase(&mut self, base_address: u64) -> Result<(), MemoryOperationError> {
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

    /// Gets an underlying reference to the data inside the
    /// memory region, and the size of the buffer.
    ///
    ///
    /// # Returns
    ///
    /// Tuple of a pointer to the data buffer, and the size
    /// of the buffer. Any alignment requirements must be
    /// managed by the caller
    ///
    /// # Safety
    /// This is only intended to be passed to styx internal
    /// structs such as `CpuEngine`, `CoreEventController` etc.
    /// as this exposes a raw pointer to the underlying data
    /// buffer. This is janky / sketchy to enable mildly
    /// realistic behavior (read: wildly unsafe) behavior.
    ///
    /// This implementation should be revisited as it will
    /// probably result in misuse errors in the future.
    pub unsafe fn data_into_parts(&self) -> (*mut u8, usize) {
        let inner_data: &mut Vec<u8> = unsafe { &mut *self.data.with_mut(|ptr| ptr) };

        // return a pointer to the data, and the size
        (inner_data.as_mut_ptr(), inner_data.len())
    }

    /// writes a vector of data to the provided address
    pub fn write_data(&self, base: u64, data: &[u8]) -> Result<(), MemoryOperationError> {
        self.permissions_check(MemoryPermissions::WRITE)?;

        // # Safety
        // We just checked the permissions, size is checked in `write_data_unchecked`
        unsafe { self.write_data_unchecked(base, data) }
    }

    /// reads the specified `size` from the provided `base` address
    pub fn read_data(&self, base: u64, size: u64) -> Result<Vec<u8>, MemoryOperationError> {
        self.permissions_check(MemoryPermissions::READ)?;

        // # Safety
        // We just checked the permissions
        unsafe { self.read_data_unchecked(base, size) }
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
    /// ensure that when operations like DMA transfers are occuring that
    /// the respective manual is followed so that styx properly checks
    /// permissions when required (eg. if a DMA transfer cannot write to
    /// a page it doesn't have permissions for -- don't let it).
    pub unsafe fn write_data_unchecked(
        &self,
        base: u64,
        data: &[u8],
    ) -> Result<(), MemoryOperationError> {
        self.address_range_valid(base, data.len() as u64, MemoryOperation::Write)?;

        // the start index into our underlying Vec<u8>
        let base_index: usize = (base - self.base) as usize;

        // # Safety
        // The unsafe part about this is that we are accessing
        // data inside of an [`UnsafeCell`], which is intentional.
        unsafe {
            (&mut *self.data.with_mut(|ptr| ptr))[base_index..base_index + data.len()]
                .copy_from_slice(data);
        }

        Ok(())
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
    /// ensure that when operations like DMA transfers are occuring that
    /// the respective manual is followed so that styx properly checks
    /// permissions when required (eg. if a DMA transfer cannot write to
    /// a page it doesn't have permissions for -- don't let it).
    pub unsafe fn read_data_unchecked(
        &self,
        base: u64,
        size: u64,
    ) -> Result<Vec<u8>, MemoryOperationError> {
        self.address_range_valid(base, size, MemoryOperation::Read)?;

        // the start index into our underlying Vec<u8>
        let base_index: usize = (base - self.base) as usize;

        // # Safety
        // The unsafe part about this is that we are accessing
        // data inside of an [`UnsafeCell`], which is intentional.
        unsafe {
            Ok(
                (&mut *self.data.with_mut(|ptr| ptr))[base_index..base_index + size as usize]
                    .to_vec(),
            )
        }
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
        unsafe {
            if self.effective_size > 0 {
                self.saved_context = Some(
                    encode_all(
                        self.read_data_unchecked(self.base, self.size)
                            .with_context(|| "could not read data while saving")?
                            .as_slice(),
                        0,
                    )
                    .unwrap(),
                );
            }
            Ok(())
        }
    }

    /// Overwrites contents of the [`MemoryRegion`] with the saved_context
    /// Returns an error if saved_context is empty.
    ///
    /// # Safety
    /// This will overwrite the entire region; the caller MUST PAUSE the CPU to stop execution
    /// before calling.
    pub unsafe fn context_restore(&mut self) -> Result<(), UnknownError> {
        unsafe {
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
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::memory::MemoryOperation;
    use crate::memory::MemoryPermissions as Perms;

    use test_case::test_case;

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

    #[test]
    fn test_memory_range_creation_valid() {
        // end is after beginning
        let perms = Perms::all();
        assert!(MemoryRegion::new(0x1000, 0x1000, perms).is_ok());

        // vector is correct size
        assert!(MemoryRegion::new_with_data(0x1000, 0x1000, perms, vec![0; 0x1000],).is_ok());
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
    fn test_region_with_no_perms() {
        let region = MemoryRegion::new(0x1000, 0x100, Perms::empty()).unwrap();

        let (_, size) = unsafe { region.data_into_parts() };

        assert_eq!(size, 0);
    }

    #[test]
    fn test_read_memory_bad_perms() {
        // make initial region
        let region = MemoryRegion::new(0x1000, 0x1100, Perms::WRITE).unwrap();

        // attempt a read
        let result = region.read_data(0x1000, 32);

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
        let result = region.read_data(0x1000, 0x4);

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
        // make intial region
        let region = MemoryRegion::new(0x1000, 0x100, perms).unwrap();

        unsafe {
            // assert write ok
            assert!(region.write_data_unchecked(base, data).is_ok());
        }
    }

    #[test_case(0x1000, &[0], Perms::WRITE; "(W) Write valid vec to valid beginning")]
    #[test_case(0x1010, &[0], Perms::WRITE; "(W) Write valid vec to valid middle")]
    #[test_case(0x10FF, &[0], Perms::WRITE; "(W) Write valid vec to top byte")]
    fn test_write_data_memory_valid(base: u64, data: &[u8], perms: MemoryPermissions) {
        // make intial region
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

        unsafe {
            // attempt to write
            let result = region.write_data_unchecked(start, data);
            assert!(matches!(
                result,
                Err(MemoryOperationError::UnmappedMemory(_))
            ));
        }
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

        unsafe {
            // attempt to read
            let result = region.read_data_unchecked(base, size);

            assert!(matches!(
                result,
                Err(MemoryOperationError::UnmappedMemory(_))
            ));
        }
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
        let result = region.read_data(base, size);

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

        unsafe {
            // assert read ok
            if let Ok(value) = region.read_data_unchecked(base, size) {
                // assert value correct
                let start_idx = base as usize - 0x1000;
                assert_eq!(validation[start_idx..start_idx + size as usize], value)
            } else {
                panic!("Read size {size} @  {base:#08X} failed!");
            }
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
        if let Ok(value) = region.read_data(base, size) {
            // assert value correct
            let start_idx = base as usize - 0x1000;
            assert_eq!(validation[start_idx..start_idx + size as usize], value)
        } else {
            panic!("Read size {size} @  {base:#08X} failed!");
        }
    }
}
