// SPDX-License-Identifier: BSD-2-Clause
use std::cmp::{max, min};

use crate::memory::{
    memory_region::MemoryRegion, AddRegionError, MemoryOperationError, UnmappedMemoryError,
};

use super::{FromYaml, MemoryImpl};

mod region_walker;

use log::{debug, trace};
use region_walker::{
    MemoryReadRegionWalker, MemoryWriteRegionWalker, RegionWalker, SearchState,
    UncheckedMemoryReadRegionWalker, UncheckedMemoryWriteRegionWalker,
};
use styx_errors::UnknownError;

/// A region based memory implementation, memory is represented by zero or more
/// unique, non-overlapping memory regions.
///
/// Each region has it's own set of permissions and regions are not necessarily contiguous.
pub struct RegionStore {
    pub(in crate::memory) regions: Vec<MemoryRegion>,
    /// Minimum address in the store, inclusive.
    min_address: u64,
    /// Maximum address in the store, inclusive.
    max_address: u64,
}

impl Default for RegionStore {
    fn default() -> Self {
        Self {
            regions: Vec::new(),
            min_address: u64::MAX,
            max_address: u64::MIN,
        }
    }
}

impl FromYaml for RegionStore {
    fn from_config(
        config: Vec<crate::memory::physical::MemoryRegionDescriptor>,
    ) -> Result<Self, crate::memory::FromConfigError>
    where
        Self: Sized,
    {
        let mut mem = RegionStore::default();

        for region in config {
            mem.add_region(MemoryRegion::new(
                region.base,
                region.size,
                region.perms.into(),
            )?)?;
        }

        Ok(mem)
    }
}

impl RegionStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn check_overlap(&self, base: u64, size: u64) -> bool {
        // ignore anything that would overflow
        if base.checked_add(size).is_none() {
            return false;
        }

        for region in self.regions.iter() {
            // do an intersection of the two memory region ranges and check if empty
            if !(max(base, region.base())..min(base + size, region.base() + region.size()))
                .is_empty()
            {
                return true;
            }
        }

        false
    }

    /// Reads a contiguous array of bytes to the buffer `data`.
    ///
    /// This function handles the traversing of internal memory regions. If an errors occurs when
    /// reading from a region, the function will return early. Because of this the read may
    /// partially complete before erroring. This could be changed in the future.
    fn read_memory(&self, base: u64, data: &mut [u8]) -> Result<(), MemoryOperationError> {
        let size = data.len() as u64;
        if size != 0 {
            let mut walker = MemoryReadRegionWalker::new(data);
            self.walk_regions(&mut walker, base, size)?;
        } // do nothing if there is no data to write

        Ok(())
    }

    /// Writes a contiguous array of bytes to memory.
    ///
    /// This function handles the traversing of internal memory regions. If an errors occurs when
    /// writing to a region, the function will return early. Because of this the write may partially
    /// complete before erroring. This could be changed in the future.
    fn write_memory(&self, base: u64, data: &[u8]) -> Result<(), MemoryOperationError> {
        let size = data.len() as u64;

        if size != 0 {
            let mut walker = MemoryWriteRegionWalker::new(data);
            self.walk_regions(&mut walker, base, size)?;
        } // do nothing if there is no data to write

        Ok(())
    }

    /// Reads a contiguous array of bytes to the buffer `data`, without checking permissions.
    ///
    /// This function handles the traversing of internal memory regions. If an errors occurs when
    /// reading from a region, the function will return early. Because of this the read may
    /// partially complete before erroring. This could be changed in the future.
    fn sudo_read_memory(&self, base: u64, data: &mut [u8]) -> Result<(), MemoryOperationError> {
        let size = data.len() as u64;
        if size != 0 {
            let mut walker = UncheckedMemoryReadRegionWalker::new(data);
            self.walk_regions(&mut walker, base, size)?;
        } // do nothing if there is no data to write

        Ok(())
    }

    /// Writes a contiguous array of bytes to memory, without checking permissions.
    ///
    /// This function handles the traversing of internal memory regions. If an errors occurs when
    /// writing to a region, the function will return early. Because of this the write may partially
    /// complete before erroring. This could be changed in the future.
    fn sudo_write_memory(&self, base: u64, data: &[u8]) -> Result<(), MemoryOperationError> {
        let size = data.len() as u64;

        if size != 0 {
            let mut walker = UncheckedMemoryWriteRegionWalker::new(data);
            self.walk_regions(&mut walker, base, size)?;
        } // do nothing if there is no data to write

        Ok(())
    }

    /// Walks the regions while passing region information to a [RegionWalker].
    ///
    /// Because of the way [RegionStore] is laid out, it is difficult to read/write a contiguous
    /// range of memory or even validate that the range is contained in the bank. This is will walk
    /// the bank's regions starting from `base` and continuing until `base + size`. If the range
    /// spans multiple [MemoryRegion]s then the `walker` will be called with a `region`, `start`,
    /// and `size`.
    fn walk_regions<RW: RegionWalker>(
        &self,
        walker: &mut RW,
        base: u64,
        size: u64,
    ) -> Result<(), MemoryOperationError> {
        // make sure the range is eligible in the first place
        let in_min = base;
        // inclusive
        let in_max = base.saturating_add(size - 1);
        trace!(
            "in_min: 0x{in_min:X}, in_max: 0x{in_max:X} (size: 0x{size:X}), min: 0x{:X}, max: 0x{:X}",
            self.min_address,
            self.max_address
        );
        if in_min < self.min_address || in_min > self.max_address {
            trace!("operation in_min < self.min_address || in_min > self.max_address");
            return Err(MemoryOperationError::UnmappedMemory(
                UnmappedMemoryError::UnmappedStart(base),
            ));
        } else if in_max > self.max_address {
            trace!("operation in_max > self.max_address");
            return Err(MemoryOperationError::UnmappedMemory(
                UnmappedMemoryError::GoesUnmapped(1 + self.max_address - base),
            ));
        }

        // if a range is not enclosed within a single region, we
        // need to check for overlaps, so we need to record the last
        // address inside the desired range that we have found in our
        // memory bank.
        let mut state = SearchState::default();
        let mut my_base;
        let mut my_size;

        // Assumptions we can make based on our previous checks:
        // - in_min >= min_address
        // - in_max <= max_address
        // - each region will have a base starting after the previous region
        //     (self.regions is sorted smallest address to largest address)
        //
        // This `O|regions.len()|` check is looking for an invalidation of the
        // assumption the inner `MemoryRegion`'s contain the requested range
        for region in self.regions.iter() {
            trace!("searching region {region}");
            let region_min = region.base();
            let region_max = region.end();

            match state {
                // look for the region that contains `in_min`
                SearchState::Start => {
                    // `in_min` does not start in this region
                    if in_min < region_min || in_min > region_max {
                        trace!("`in_min` does not start in this region");
                        continue;
                    } else {
                        trace!("`in_min` starts in this region");
                        // min is in this region, now we have two possible states:
                        // - min and max fit inside this region
                        // - min is in the region, and max is not in the region
                        if in_max <= region_max {
                            trace!("min and max fit inside this region");
                            state = SearchState::Done;

                            my_base = base;
                            my_size = 1 + (in_max - in_min);
                        } else {
                            trace!("in_max is not in this region, set the marker and set state to `BaseFound`");
                            // in_max is not in this region, set the marker and
                            // set state to `BaseFound`
                            state = SearchState::BaseFound(region_max);

                            my_base = base;
                            my_size = 1 + region_max - base;
                        }
                    }
                }
                // we have found the start in a previous region, and now
                // we need to ensure that this region picks up *immediately*
                // after the previous region
                SearchState::BaseFound(prev_address) => {
                    // if prev_address +1 is not this regions' base then
                    // we immediately fail
                    if prev_address + 1 != region_min {
                        return Err(MemoryOperationError::UnmappedMemory(
                            UnmappedMemoryError::GoesUnmapped(1 + prev_address - base),
                        ));
                    } // can now assume these regions are fully contiguous

                    // if `in_max` is in this region then we're done
                    if in_max >= region_min || in_max <= region_max {
                        state = SearchState::Done;
                        my_base = region_min;
                        my_size = 1 + in_max - region_min;
                    } else {
                        // `in_max` is not in this region, keep looking
                        state = SearchState::BaseFound(region_max);
                        my_base = region_min;
                        my_size = 1 + region_max - region_min;
                    }
                }
                // we're done, do nothing
                SearchState::Done => {
                    break;
                }
            }

            walker.single_walk(region, my_base, my_size)?;
        }

        // we've now walked all regions. if we're not SearchState::Done then the memory operation is
        // not fully mapped.
        match state {
            // base of operation was not found
            SearchState::Start => Err(MemoryOperationError::UnmappedMemory(
                UnmappedMemoryError::UnmappedStart(in_min),
            )),
            // base of operation was found but whole range is not mapped.
            // BaseFound variant contains the last address that was found valid
            SearchState::BaseFound(last_address) => Err(MemoryOperationError::UnmappedMemory(
                UnmappedMemoryError::GoesUnmapped(1 + last_address - in_min),
            )),
            SearchState::Done => Ok(()),
        }
    }
}

impl MemoryImpl for RegionStore {
    fn context_save(&mut self) -> Result<(), UnknownError> {
        for region in self.regions.iter_mut() {
            // safety: unsafe because we are ignoring memory permissions
            unsafe { region.context_save()? };
        }
        Ok(())
    }

    fn context_restore(&mut self) -> Result<(), UnknownError> {
        for region in self.regions.iter_mut() {
            // safety: unsafe because we are ignoring memory permissions
            unsafe { region.context_restore()? };
        }
        Ok(())
    }

    fn min_address(&self, _space: Option<crate::memory::physical::Space>) -> u64 {
        self.min_address
    }

    fn max_address(&self, _space: Option<crate::memory::physical::Space>) -> u64 {
        self.max_address
    }

    fn add_region(&mut self, region: MemoryRegion) -> Result<(), AddRegionError> {
        debug!(
            "adding region with base: 0x{:X} size: 0x{:X}",
            region.base(),
            region.size()
        );
        let base = region.base();
        let size = region.size();

        // check for overlap
        if !self.regions.is_empty() && self.check_overlap(base, size) {
            return Err(AddRegionError::OverlappingRegion(base, size));
        }

        self.regions.push(region);
        self.regions.sort_by(|a, b| a.partial_cmp(b).unwrap());

        // TODO: maybe merge adjacent regions to speed up reads/writes

        if base < self.min_address {
            self.min_address = base;
        }

        if base + (size - 1) > self.max_address {
            self.max_address = base + (size - 1);
        }

        Ok(())
    }

    fn read_code(
        &self,
        addr: u64,
        bytes: &mut [u8],
    ) -> Result<(), crate::memory::MemoryOperationError> {
        self.read_memory(addr, bytes)
    }

    fn read_data(
        &self,
        addr: u64,
        bytes: &mut [u8],
    ) -> Result<(), crate::memory::MemoryOperationError> {
        self.read_memory(addr, bytes)
    }

    fn write_code(
        &mut self,
        addr: u64,
        bytes: &[u8],
    ) -> Result<(), crate::memory::MemoryOperationError> {
        self.write_memory(addr, bytes)
    }

    fn write_data(
        &mut self,
        addr: u64,
        bytes: &[u8],
    ) -> Result<(), crate::memory::MemoryOperationError> {
        self.write_memory(addr, bytes)
    }

    fn unchecked_read_code(
        &self,
        addr: u64,
        bytes: &mut [u8],
    ) -> Result<(), crate::memory::MemoryOperationError> {
        self.sudo_read_memory(addr, bytes)
    }

    fn unchecked_read_data(
        &self,
        addr: u64,
        bytes: &mut [u8],
    ) -> Result<(), crate::memory::MemoryOperationError> {
        self.sudo_read_memory(addr, bytes)
    }

    fn unchecked_write_code(
        &mut self,
        addr: u64,
        bytes: &[u8],
    ) -> Result<(), crate::memory::MemoryOperationError> {
        self.sudo_write_memory(addr, bytes)
    }

    fn unchecked_write_data(
        &mut self,
        addr: u64,
        bytes: &[u8],
    ) -> Result<(), crate::memory::MemoryOperationError> {
        self.sudo_write_memory(addr, bytes)
    }
}

#[cfg(test)]
mod tests {
    use log::info;
    use styx_util::logging::init_logging;

    use crate::memory::MemoryPermissions;

    use super::*;

    /// Check mapping memory at u64::MAX.
    #[test]
    fn test_memory_u64_max() {
        init_logging();
        let mut store = RegionStore::new();
        let region = MemoryRegion::new(u64::MAX, 1, MemoryPermissions::all()).unwrap();
        store.add_region(region).unwrap();

        store.write_memory(u64::MAX, &[0x12]).unwrap();
        let mut buf = [0u8];
        store.read_memory(u64::MAX, &mut buf).unwrap();
        assert_eq!(buf[0], 0x12);
    }

    /// Check mapping memory at 0.
    #[test]
    fn test_memory_at_0() {
        init_logging();
        let mut store = RegionStore::new();
        let region = MemoryRegion::new(0, 1, MemoryPermissions::all()).unwrap();
        store.add_region(region).unwrap();

        store.write_memory(0, &[0x12]).unwrap();
        let mut buf = [0u8];
        store.read_memory(0, &mut buf).unwrap();
        assert_eq!(buf[0], 0x12);
    }

    /// Checks invalid memory operation when the region is in the RegionStore min/max but does not
    /// start in a valid region.
    #[test]
    fn test_memory_op_in_range_not_in_region() {
        let mut store = RegionStore::new();
        let region = MemoryRegion::new(0x0, 0x10000, MemoryPermissions::all()).unwrap();
        store.add_region(region).unwrap();
        let region = MemoryRegion::new(0xFFFFF000, 0x1000, MemoryPermissions::all()).unwrap();
        store.add_region(region).unwrap();

        // store range is now 0x0..=0xFFFFFFFF
        // but 0xFFF00000 is NOT mapped

        let res = store.write_memory(0xFFF00000, &vec![0u8; 0x100000]);
        assert!(res.is_err());
        assert!(matches!(
            res,
            Err(MemoryOperationError::UnmappedMemory(
                UnmappedMemoryError::UnmappedStart(0xFFF00000)
            ))
        ));
    }

    /// Checks invalid memory operation when the region is in the RegionStore min/max and
    /// starts in a valid region but goes out of bounds.
    #[test]
    fn test_memory_op_in_range_starts_in_region_go_unmapped() {
        let mut store = RegionStore::new();
        let region = MemoryRegion::new(0x0, 0x10000, MemoryPermissions::all()).unwrap();
        store.add_region(region).unwrap();
        let region = MemoryRegion::new(0xFFFFF000, 0x1000, MemoryPermissions::all()).unwrap();
        store.add_region(region).unwrap();

        let res = store.write_memory(0xFFF0, &[0u8; 0x20]);
        assert!(res.is_err());
        assert!(matches!(
            res,
            Err(MemoryOperationError::UnmappedMemory(
                UnmappedMemoryError::GoesUnmapped(0x10)
            ))
        ));
    }

    /// Checks invalid memory operation when the operation starts in a valid region but goes out of
    /// bounds with no other regions.
    ///
    /// Different than the test above, this test hits the else if in the start of the walking.
    #[test]
    fn test_memory_op_in_range_starts_in_region_go_unmapped_at_0() {
        init_logging();
        let mut store = RegionStore::new();
        let region = MemoryRegion::new(0x0, 0x10, MemoryPermissions::all()).unwrap();
        store.add_region(region).unwrap();

        let res = store.write_memory(0x0, &[0u8; 0x20]);
        assert!(res.is_err());
        assert!(matches!(
            res,
            Err(MemoryOperationError::UnmappedMemory(
                UnmappedMemoryError::GoesUnmapped(0x10)
            ))
        ));
    }

    /// Checks that an operation starting on the bounds of unmapped memory is UnmappedStart and not
    /// GoesUnmapped(0).
    #[test]
    fn test_memory_op_start_unmapped_0() {
        styx_util::logging::init_logging();
        let mut store = RegionStore::new();
        let region = MemoryRegion::new(0x0, 0x1000, MemoryPermissions::all()).unwrap();
        store.add_region(region).unwrap();

        // test where store maximum should catch
        let res = store.write_memory(0x1000, &[0u8; 0x20]);
        info!("{res:?}");
        assert!(res.is_err());
        assert!(matches!(
            res,
            Err(MemoryOperationError::UnmappedMemory(
                UnmappedMemoryError::UnmappedStart(0x1000)
            ))
        ));

        // test where region maximum should catch
        let region = MemoryRegion::new(0xFFFFF000, 0x1000, MemoryPermissions::all()).unwrap();
        store.add_region(region).unwrap();
        let res = store.write_memory(0x1000, &[0u8; 0x20]);
        info!("{res:?}");
        assert!(res.is_err());
        assert!(matches!(
            res,
            Err(MemoryOperationError::UnmappedMemory(
                UnmappedMemoryError::UnmappedStart(0x1000)
            ))
        ));
    }

    /// Checks that an operation on the bounds of touching regions is Okay.
    #[test]
    fn test_memory_adjacent() {
        styx_util::logging::init_logging();
        let mut store = RegionStore::new();
        let region = MemoryRegion::new(0x0, 0x1000, MemoryPermissions::all()).unwrap();
        store.add_region(region).unwrap();
        let region = MemoryRegion::new(0x1000, 0x1000, MemoryPermissions::all()).unwrap();
        store.add_region(region).unwrap();

        let res = store.write_memory(0x1000, &[0u8; 0x20]);
        info!("{res:?}");
        assert!(res.is_ok());
    }
}
