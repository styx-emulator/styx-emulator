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
use getset::CopyGetters;
use num_traits::PrimInt;
use styx_errors::styx_memory::{StyxMemoryError, StyxMemorySnaphotError};
pub use styx_memory_type::{MemoryOperation, MemoryPermissions};
use styx_sync::cell::UnsafeCell;
use styx_sync::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, RwLock,
};
use zstd::{decode_all, encode_all};

/// Container struct representing multiple [`MemoryRegion`]'s.
/// Keeps a running tally of the min and max address while adding
/// new [`MemoryRegion`]'s to the [`MemoryBank`] for faster queries
#[derive(Debug)]
pub struct MemoryBank {
    /// Inner collection of [`MemoryRegion`]'s inside the
    /// given [`MemoryBank`], the inner vec is sorted smallest
    /// address to largest
    regions: Arc<RwLock<Vec<MemoryRegion>>>,
    /// Minimum address mapped into the [`MemoryBank`], this
    /// is updated every time a [`MemoryRegion`] is added to
    /// the bank and will reflect the smallest address in any
    /// region, note that the reset state is [`u64::MAX`]
    min_address: AtomicU64,
    /// Maximum address mapped into the [`MemoryBank`], this
    /// is updated every time a [`MemoryRegion`] is added to
    /// the bank and will reflect the largest address in any
    /// region, note that the reset state is [`u64::MIN`]
    max_address: AtomicU64,
}

impl Default for MemoryBank {
    fn default() -> Self {
        Self {
            regions: Arc::new(RwLock::new(Vec::new())),
            min_address: u64::MAX.into(),
            max_address: u64::MIN.into(),
        }
    }
}

unsafe impl Send for MemoryBank {}
unsafe impl Sync for MemoryBank {}

impl MemoryBank {
    /// Get's the current minimum address represented in the
    /// [`MemoryBank`], if there are no [`MemoryRegion`]'s in the
    /// [`MemoryBank`] then this methods returns an error
    ///
    /// ```rust
    /// use styx_memory::{MemoryBank, MemoryRegion, MemoryPermissions as Perms};
    /// use styx_errors::styx_memory::StyxMemoryError;
    /// let region = MemoryRegion::new_with_data(0x4000, 0x1000, Perms::all(), vec![0; 0x1000]).unwrap();
    ///
    /// let bank = MemoryBank::default();
    /// assert!(matches!(bank.min_address().unwrap_err(), StyxMemoryError::EmptyMemoryBank));
    ///
    /// bank.add_region(region).unwrap();
    /// assert_eq!(0x4000, bank.min_address().unwrap());
    /// ```
    pub fn min_address(&self) -> Result<u64, StyxMemoryError> {
        if !self.regions.read().unwrap().is_empty() {
            Ok(self.min_address.load(Ordering::Acquire))
        } else {
            Err(StyxMemoryError::EmptyMemoryBank)
        }
    }

    /// Removes and returns a [`MemoryRegion`] if there is a region
    /// that begins at the specified address.
    pub fn pop_region(&self, base_address: u64) -> Result<MemoryRegion, StyxMemoryError> {
        let mut regions = self.regions.write().unwrap();

        // find regions with the base address
        let mut found = vec![];
        for (idx, r) in regions.iter().enumerate() {
            if r.base == base_address {
                found.push(idx);
            }
        }

        // something is wrong
        if found.len() != 1 {
            return Err(StyxMemoryError::InvalidBase(base_address));
        }

        Ok(regions.remove(found[0]))
    }

    /// Calls context_save on each memory region in the bank
    pub fn context_save(&self) -> Result<(), StyxMemoryError> {
        for region in self.regions.write().unwrap().iter_mut() {
            region.context_save()?;
        }
        Ok(())
    }

    /// Calls context_restore on each memory region in the bank
    pub fn context_restore(&self) -> Result<(), StyxMemoryError> {
        for region in self.regions.write().unwrap().iter_mut() {
            unsafe { region.context_restore()? };
        }
        Ok(())
    }

    /// Get's the current maximum address represented in the
    /// [`MemoryBank`], if there are no [`MemoryRegion`]'s in the
    /// [`MemoryBank`] then this methods returns an error
    ///
    /// ```rust
    /// use styx_memory::{MemoryBank, MemoryRegion, MemoryPermissions as Perms};
    /// use styx_errors::styx_memory::StyxMemoryError;
    /// let region = MemoryRegion::new_with_data(0x4000, 0x1000, Perms::all(), vec![0; 0x1000]).unwrap();
    ///
    /// let bank = MemoryBank::default();
    /// assert!(matches!(bank.max_address().unwrap_err(), StyxMemoryError::EmptyMemoryBank));
    ///
    /// bank.add_region(region).unwrap();
    /// assert_eq!(0x4fff, bank.max_address().unwrap());
    /// ```
    pub fn max_address(&self) -> Result<u64, StyxMemoryError> {
        if !self.regions.read().unwrap().is_empty() {
            Ok(self.max_address.load(Ordering::Acquire))
        } else {
            Err(StyxMemoryError::EmptyMemoryBank)
        }
    }

    /// Attempts to add a new [`MemoryRegion`] into the container type.
    ///
    /// This method will check if the new region overlaps any previous
    /// region before adding it into the collection
    ///
    /// ```rust
    /// use styx_memory::{MemoryBank, MemoryRegion, MemoryPermissions as Perms};
    /// let region = MemoryRegion::new_with_data(0x4000, 0x1000, Perms::all(), vec![0; 0x1000]).unwrap();
    ///
    /// let bank = MemoryBank::default();
    /// bank.add_region(region).unwrap();
    ///
    /// # assert_eq!(true, bank.contains_address(0x4000));
    /// ```
    pub fn add_region(&self, region: MemoryRegion) -> Result<(), StyxMemoryError> {
        // only check for overlap if there are regions in the bank
        if !self.regions.read().unwrap().is_empty()
            && self.check_overlap(region.base(), region.size())
        {
            Err(StyxMemoryError::OverlappingRegion(
                region.base(),
                region.size(),
            ))
        } else {
            let mut regions = self.regions.write().unwrap();

            // update min address
            if region.base() < self.min_address.load(Ordering::Acquire) {
                self.min_address.store(region.base(), Ordering::Release);
            }

            let max_address = region.end();
            if max_address > self.max_address.load(Ordering::Acquire) {
                self.max_address.store(max_address, Ordering::Release);
            }

            regions.push(region);

            regions.sort_by(|a, b| a.partial_cmp(b).unwrap());

            Ok(())
        }
    }

    /// If the range is contained in a single region, return the
    /// [`MemoryPermissions`] that govern this memory region
    ///
    /// ```rust
    /// use styx_memory::{MemoryBank, MemoryRegion, MemoryPermissions as Perms};
    /// let region = MemoryRegion::new_with_data(0x4000, 0x1000, Perms::WRITE, vec![0; 0x1000]).unwrap();
    /// let region2 = MemoryRegion::new(0x5000, 0x1000, Perms::RW).unwrap();
    ///
    /// let bank = MemoryBank::default();
    /// bank.add_region(region).unwrap();
    /// bank.add_region(region2).unwrap();
    ///
    /// assert_eq!(None, bank.containing_region_perms(0x1000, 1)); // below all memory
    /// assert_eq!(None, bank.containing_region_perms(0x4fff, 2)); // accross 2 regions
    /// assert_eq!(None, bank.containing_region_perms(0x6000, 1)); // above all memory
    /// assert!(bank.containing_region_perms(0x4000, 0x100).is_some()); // in first range
    /// assert!(bank.containing_region_perms(0x5510, 0x100).is_some()); // in 2nd range
    /// assert_eq!(Perms::WRITE, bank.containing_region_perms(0x4000, 0x100).unwrap());
    /// assert_eq!(Perms::RW, bank.containing_region_perms(0x5510, 0x100).unwrap());
    /// ```
    pub fn containing_region_perms(&self, base: u64, size: u64) -> Option<MemoryPermissions> {
        // if we contain the region, then return the permissions
        //
        // # Safety
        // The only use of the aliased region is read-only
        unsafe { self.containing_region(base, size) }.map(|region| region.perms())
    }

    /// If the range is contained in a single region, return a new [`MemoryRegion`]
    /// that is aliased to the same region
    ///
    /// # Safety
    ///
    /// Writing to this region is not synchronized or serialized in anyway.
    /// You can seriously corrupt the runtime state of the target program
    /// by modifying the data of the new region in any manner.
    ///
    /// ```rust
    /// use styx_memory::{MemoryBank, MemoryRegion, MemoryPermissions as Perms};
    /// let region = MemoryRegion::new_with_data(0x4000, 0x1000, Perms::all(), vec![0; 0x1000]).unwrap();
    /// let region2 = MemoryRegion::new(0x5000, 0x1000, Perms::all()).unwrap();
    /// # let region1_alias = unsafe { region.new_alias(0x4000) };
    /// # let region2_alias = unsafe { region.new_alias(0x5000) };
    ///
    /// let bank = MemoryBank::default();
    /// bank.add_region(region).unwrap();
    /// bank.add_region(region2).unwrap();
    ///
    /// unsafe {
    ///     assert_eq!(None, bank.containing_region(0x1000, 1)); // below all memory
    ///     assert_eq!(None, bank.containing_region(0x4fff, 2)); // accross 2 regions
    ///     assert_eq!(None, bank.containing_region(0x6000, 1)); // above all memory
    ///     assert!(bank.containing_region(0x4000, 0x100).is_some()); // in first range
    ///     assert!(bank.containing_region(0x5510, 0x100).is_some()); // in 2nd range
    ///     # assert_eq!(region1_alias, bank.containing_region(0x4000, 0x100).unwrap());
    ///     # assert_eq!(region2_alias, bank.containing_region(0x5510, 0x100).unwrap());
    /// }
    /// ```
    pub unsafe fn containing_region(&self, base: u64, size: u64) -> Option<MemoryRegion> {
        let min_address = match self.min_address() {
            Ok(addr) => addr,
            Err(_) => return None,
        };

        let max_address = match self.max_address() {
            Ok(addr) => addr,
            Err(_) => return None,
        };

        // make sure the range is eligible in the first place
        let in_min = base;
        let in_max = base.saturating_add(size) - 1;
        if in_min < min_address || in_max > max_address {
            return None;
        }

        // Assumptions we can make based on our previous checks:
        // - in_min >= min_address
        // - in_max <= max_address
        // - each region will have a base starting after the previous region
        //     (self.regions is sorted smallest address to largest address)
        //
        // This `O|regions.len()|` check is looking for an invalidation of the
        // assumption a single `MemoryRegion` contains the requested range
        for region in self.regions.read().unwrap().iter() {
            let region_min = region.base;
            let region_max = region.end();

            // look for the region that contains `in_min`
            if in_min < region_min || in_min > region_max {
                // `in_min` does not start in this region
                continue;
            } else {
                // min is in this region, now we have two possible states:
                // - min and max fit inside this region
                // - min is in the region, and max is not in the region
                if in_max <= region_max {
                    return Some(region.new_alias(region.base()));
                } else {
                    // in_max is not in this region,
                    // so we're done, and return None bc no single region
                    // can fit the requested range
                    return None;
                }
            }
        }

        // no region contained our base address
        None
    }

    /// Checks if the [`MemoryBank`] contains the entirety
    /// of the provided range, this requested range can include
    /// or overlap multiple underlying continugous [`MemoryRegion`]'s.
    ///
    /// ```rust
    /// use styx_memory::{MemoryBank, MemoryRegion, MemoryPermissions as Perms};
    /// let region = MemoryRegion::new_with_data(0x4000, 0x1000, Perms::all(), vec![0; 0x1000]).unwrap();
    ///
    /// let bank = MemoryBank::default();
    /// bank.add_region(region).unwrap();
    ///
    /// assert_eq!(true, bank.contains_range(0x4001, 3));
    /// assert_eq!(true, bank.contains_range(0x4000, 0x1000));
    /// assert_eq!(false, bank.contains_range(0x3000, 0x1800));
    /// assert_eq!(false, bank.contains_range(0x3fff, 0x2));
    /// assert_eq!(false, bank.contains_range(0x4ff0, 0x11));
    /// assert_eq!(true, bank.contains_range(0x4ff0, 0x10));
    /// ```
    pub fn contains_range(&self, base: u64, size: u64) -> bool {
        // TODO replace this with region walker
        let min_address = match self.min_address() {
            Ok(addr) => addr,
            Err(_) => return false,
        };

        let max_address = match self.max_address() {
            Ok(addr) => addr,
            Err(_) => return false,
        };

        // make sure the range is eligible in the first place
        let in_min = base;
        let in_max = base.saturating_add(size) - 1;
        if in_min < min_address || in_max > max_address {
            return false;
        }

        // if a range is not enclosed within a single region, we
        // need to check for overlaps, so we need to record the last
        // address inside the desired range that we have found in our
        // memory bank.
        let mut state = SearchState::default();

        // Assumptions we can make based on our previous checks:
        // - in_min >= min_address
        // - in_max <= max_address
        // - each region will have a base starting after the previous region
        //     (self.regions is sorted smallest address to largest address)
        //
        // This `O|regions.len()|` check is looking for an invalidation of the
        // assumption the inner `MemoryRegion`'s contain the requested range
        for region in self.regions.read().unwrap().iter() {
            let region_min = region.base;
            let region_max = region.end();

            match state {
                // look for the region that contains `in_min`
                SearchState::Start => {
                    // `in_min` does not start in this region
                    if in_min < region_min || in_min > region_max {
                        continue;
                    } else {
                        // min is in this region, now we have two possible states:
                        // - min and max fit inside this region
                        // - min is in the region, and max is not in the region
                        if in_max <= region_max {
                            state = SearchState::Done;
                        } else {
                            // in_max is not in this region, set the marker and
                            // set state to `BaseFound`
                            state = SearchState::BaseFound(region_max);
                        }
                    }
                }
                // we have found the start in a previous region, and now
                // we need to ensure that this region picks up *immediately*
                // after the previous region
                SearchState::BaseFound(prev) => {
                    // if last_address +1 is not this regions' base then
                    // we immediately fail
                    if prev + 1 != region_min {
                        return false;
                    } // can now assume these regions are fully contiguous

                    // if `in_max` is in this region then we're done
                    if in_max >= region_min || in_max <= region_max {
                        state = SearchState::Done;
                    } else {
                        // `in_max` is not in this region, keep looking
                        state = SearchState::BaseFound(region_max);
                    }
                }
                // we're done, do nothing
                SearchState::Done => {}
            }

            if state == SearchState::Done {
                break;
            }
        }

        true
    }

    /// Checks if the requested address is contained within
    /// this [`MemoryBank`], under the hood this just calls
    /// [`Self::check_overlap`] with a size of 1
    ///
    /// ```rust
    /// use styx_memory::{MemoryBank, MemoryRegion, MemoryPermissions as Perms};
    /// let region = MemoryRegion::new_with_data(0x4000, 0x1000, Perms::all(), vec![0; 0x1000]).unwrap();
    ///
    /// let bank = MemoryBank::default();
    /// bank.add_region(region).unwrap();
    ///
    /// assert_eq!(true, bank.contains_address(0x4000));
    /// ```
    pub fn contains_address(&self, address: u64) -> bool {
        self.check_overlap(address, 1)
    }

    /// Checks if the [`MemoryBank`] contains an exact copy
    /// of the [`MemoryRegion`], note that only the base address
    /// and the size are checked
    ///
    /// ```rust
    /// use styx_memory::{MemoryBank, MemoryRegion, MemoryPermissions as Perms};
    /// let region = MemoryRegion::new_with_data(0x4000, 0x1000, Perms::all(), vec![0; 0x1000]).unwrap();
    ///
    /// let bank = MemoryBank::default();
    /// bank.add_region(region).unwrap();
    ///
    /// let new_region = MemoryRegion::new(0x4000, 0x1000, Perms::all()).unwrap();
    /// assert_eq!(true, bank.contains_region(&new_region));
    /// ```
    pub fn contains_region(&self, region: &MemoryRegion) -> bool {
        let regions = self.regions.read().unwrap();

        for r in regions.iter() {
            if r.base() == region.base() && r.size() == region.size() {
                return true;
            }
        }

        false
    }

    /// Checks if any [`MemoryRegion`] inside the [`MemoryBank`]
    /// contains memory that overlaps part of the requested range
    ///
    /// ```rust
    /// use styx_memory::{MemoryBank, MemoryRegion, MemoryPermissions as Perms};
    /// let region = MemoryRegion::new_with_data(0x4000, 0x1000, Perms::all(), vec![0; 0x1000]).unwrap();
    ///
    /// let bank = MemoryBank::default();
    /// bank.add_region(region).unwrap();
    ///
    /// assert_eq!(true, bank.check_overlap(0x3fff, 2));
    /// assert_eq!(true, bank.check_overlap(0x4fff, 1));
    /// assert_eq!(true, bank.check_overlap(0x4000, 0x1001));
    /// assert_eq!(true, bank.check_overlap(0x4000, 0x1000));
    /// assert_eq!(true, bank.check_overlap(0x4800, 0x1000));
    /// assert_eq!(false, bank.check_overlap(0x5000, 100));
    /// assert_eq!(false, bank.check_overlap(0x3fff, 1));
    /// ```
    pub fn check_overlap(&self, base: u64, size: u64) -> bool {
        let regions = self.regions.read().unwrap();

        // ignore anything that would overflow
        if base.checked_add(size).is_none() {
            return false;
        }

        for region in regions.iter() {
            let region_base = region.base();
            let region_max = region.end();
            let in_base = base;
            let in_max = base.saturating_add(size) - 1;

            // there are only a few possible cases we ned to check
            // for memory region overlap:
            // - starts "beneath" the region and goes into the region
            // - starts in the region and goes anywhere
            let beneath_to_inside = in_base < region_base && in_max >= region_base;
            let inside_to_above = in_base >= region_base && in_base <= region_max;

            if beneath_to_inside || inside_to_above {
                return true;
            }
        }

        false
    }

    pub fn valid_memory(&self) -> Result<MemoryRange, StyxMemoryError> {
        let regions = self.regions.read().unwrap();

        if regions.is_empty() {
            Err(StyxMemoryError::EmptyMemoryBank)
        } else {
            Ok(MemoryRange::new(
                self.min_address.load(Ordering::Acquire),
                self.max_address.load(Ordering::Acquire),
            ))
        }
    }

    /// Reads a contiguous array of bytes to the buffer `data`.
    ///
    /// This function handles the traversing of internal memory regions. If an errors occurs when
    /// reading from a region, the function will return early. Because of this the read may
    /// partially complete before erroring. This could be changed in the future.
    ///
    /// ```rust
    /// use styx_memory::{MemoryBank, MemoryRegion, MemoryPermissions as Perms};
    /// let region_one = MemoryRegion::new_with_data(0x4000, 0x1000, Perms::all(), vec![0; 0x1000]).unwrap();
    /// let region_two = MemoryRegion::new_with_data(0x5000, 0x1000, Perms::all(), vec![0x41; 0x1000]).unwrap();
    ///
    /// let bank = MemoryBank::default();
    /// bank.add_region(region_one).unwrap();
    /// bank.add_region(region_two).unwrap();
    ///
    /// let mut buf = [0u8; 8];
    /// // Read over region bounds.
    /// bank.read_memory(0x4FFC, &mut buf);
    ///
    /// assert_eq!(&buf, &[0, 0, 0, 0, 0x41, 0x41, 0x41, 0x41]);
    /// ```
    pub fn read_memory(&self, base: u64, data: &mut [u8]) -> Result<(), StyxMemoryError> {
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
    ///
    ///
    /// ```rust
    /// use styx_memory::{MemoryBank, MemoryRegion, MemoryPermissions as Perms};
    /// let region_one = MemoryRegion::new_with_data(0x4000, 0x1000, Perms::all(), vec![0; 0x1000]).unwrap();
    /// let region_two = MemoryRegion::new_with_data(0x5000, 0x1000, Perms::all(), vec![0x41; 0x1000]).unwrap();
    ///
    /// let bank = MemoryBank::default();
    /// bank.add_region(region_one).unwrap();
    /// bank.add_region(region_two).unwrap();
    ///
    /// let data = 0x4141DEADBEEF4141_u64.to_be_bytes();
    /// // Write over region bounds.
    /// bank.write_memory(0x4FFC, &data);
    /// let mut buf = [0u8; 8];
    /// bank.read_memory(0x4FFC, &mut buf);
    ///
    /// assert_eq!(&buf, &[0x41, 0x41, 0xDE, 0xAD, 0xBE, 0xEF, 0x41, 0x41]);
    /// ```
    pub fn write_memory(&self, base: u64, data: &[u8]) -> Result<(), StyxMemoryError> {
        let size = data.len() as u64;

        if size != 0 {
            let mut walker = MemoryWriteRegionWalker::new(data);
            self.walk_regions(&mut walker, base, size)?;
        } // do nothing if there is no data to write

        Ok(())
    }

    /// Walks the regions while passing region information to a [RegionWalker].
    ///
    /// Because of the way [MemoryBank] is laid out, it is difficult to read/write a contiguous
    /// range of memory or even validate that the range is contained in the bank. This is will walk
    /// the bank's regions starting from `base` and continuing until `base + size`. If the range
    /// spans multiple [MemoryRegion]s then the `walker` will be called with a `region`, `start`,
    /// and `size`.
    fn walk_regions<RW: RegionWalker>(
        &self,
        walker: &mut RW,
        base: u64,
        size: u64,
    ) -> Result<(), StyxMemoryError> {
        let min_address = match self.min_address() {
            Ok(addr) => addr,
            Err(_) => return Err(StyxMemoryError::EmptyMemoryBank),
        };

        let max_address = match self.max_address() {
            Ok(addr) => addr,
            Err(_) => return Err(StyxMemoryError::EmptyMemoryBank),
        };

        // make sure the range is eligible in the first place
        let in_min = base;
        let in_max = base.saturating_add(size) - 1;
        if in_min < min_address || in_max > max_address {
            return Err(StyxMemoryError::InvalidMemoryRange {
                op: MemoryOperation::Read,
                request_min: in_min,
                request_max: in_max,
                limit_min: min_address,
                limit_max: max_address,
            });
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
        for region in self.regions.read().unwrap().iter() {
            let region_min = region.base;
            let region_max = region.end();

            match state {
                // look for the region that contains `in_min`
                SearchState::Start => {
                    // `in_min` does not start in this region
                    if in_min < region_min || in_min > region_max {
                        continue;
                    } else {
                        // min is in this region, now we have two possible states:
                        // - min and max fit inside this region
                        // - min is in the region, and max is not in the region
                        if in_max <= region_max {
                            state = SearchState::Done;

                            my_base = base;
                            my_size = 1 + in_max - in_min;
                        } else {
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
                        return Err(StyxMemoryError::NonContiguousRange {
                            request_min: in_min,
                            request_max: in_max,
                            previous_max: prev_address,
                            contiguous_min: min_address,
                            contiguous_max: region_min,
                        });
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

        Ok(())
    }

    pub fn regions<'a>(
        self: &'a Arc<Self>,
    ) -> styx_sync::sync::RwLockReadGuard<'a, Vec<MemoryRegion>> {
        self.regions.read().unwrap()
    }
}

/// small enum used to keep track of state during region walk search
#[derive(PartialEq, Eq, PartialOrd, Ord, Default, Clone, Copy)]
enum SearchState {
    #[default]
    Start,
    /// Base found with last_address
    BaseFound(u64),
    Done,
}

/// Trait for implementing a struct to walk regions of an address range.
///
/// See [MemoryBank]s walk_regions for more information.
trait RegionWalker {
    fn single_walk(
        &mut self,
        region: &MemoryRegion,
        start: u64,
        size: u64,
    ) -> Result<(), StyxMemoryError>;
}

/// [RegionWalker] for reading a section of memory.
struct MemoryReadRegionWalker<'a> {
    data: &'a mut [u8],
    data_idx: usize,
}
impl<'a> MemoryReadRegionWalker<'a> {
    fn new(data: &'a mut [u8]) -> Self {
        Self { data, data_idx: 0 }
    }
}
impl RegionWalker for MemoryReadRegionWalker<'_> {
    fn single_walk(
        &mut self,
        region: &MemoryRegion,
        start: u64,
        size: u64,
    ) -> Result<(), StyxMemoryError> {
        let read_data = region.read_data(start, size)?;
        self.data[self.data_idx..self.data_idx + read_data.len()].copy_from_slice(&read_data);
        self.data_idx += read_data.len();

        Ok(())
    }
}

/// [RegionWalker] for writing a section of memory.
struct MemoryWriteRegionWalker<'a> {
    /// Data to write to memory.
    data: &'a [u8],
    /// Current index into [Self::data].
    data_idx: usize,
}
impl<'a> MemoryWriteRegionWalker<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, data_idx: 0 }
    }
}
impl RegionWalker for MemoryWriteRegionWalker<'_> {
    fn single_walk(
        &mut self,
        region: &MemoryRegion,
        start: u64,
        size: u64,
    ) -> Result<(), StyxMemoryError> {
        let size = size as usize;
        let to_write = &self.data[self.data_idx..self.data_idx + size];
        region.write_data(start, to_write)?;
        self.data_idx += size;

        Ok(())
    }
}

/// Represents a region of memory, inclusive
///
/// ```rust
/// use styx_memory::{MemoryBank, MemoryRegion, MemoryPermissions as Perms};
/// use styx_memory::MemoryRange;
/// let region = MemoryRegion::new_with_data(0x4000, 0x1000, Perms::all(), vec![0; 0x1000]).unwrap();
///
/// // add region to the bank
/// let bank = MemoryBank::default();
/// bank.add_region(region).unwrap();
///
/// // manually create range to test against
/// let mem_range = MemoryRange::new(0x4000, 0x4fff);
///
/// assert_eq!(mem_range, bank.valid_memory().unwrap());
/// assert_eq!(mem_range.start(), 0x4000);
/// assert_eq!(mem_range.end(), 0x4fff);
/// assert_eq!(mem_range.size(), 0x1000);
/// ```
#[derive(Debug, Default, PartialEq)]
pub struct MemoryRange(u64, u64);

impl MemoryRange {
    /// Constructs a new [`MemoryRange`] from the
    /// provided (start, end) tuple
    pub fn new(start: u64, end: u64) -> Self {
        assert!(
            end > start,
            "End address must be greater than start address"
        );
        Self(start, end)
    }

    /// Gets the first element of the tuple to return the start
    /// address in the [`MemoryRange`]
    ///
    /// ```rust
    /// use styx_memory::MemoryRange;
    ///
    /// let mem_range = MemoryRange::new(0x4000, 0x4fff);
    /// assert_eq!(mem_range.start(), 0x4000);
    /// ```
    pub fn start(&self) -> u64 {
        self.0
    }

    /// Gets the second element of the tuple to return the ending
    /// address in the [`MemoryRange`]
    ///
    /// ```rust
    /// use styx_memory::MemoryRange;
    ///
    /// let mem_range = MemoryRange::new(0x4000, 0x4fff);
    /// assert_eq!(mem_range.end(), 0x4fff);
    /// ```
    pub fn end(&self) -> u64 {
        self.1
    }

    /// Gets the size of the [`MemoryRegion`]
    ///
    /// ```rust
    /// use styx_memory::MemoryRange;
    ///
    /// let mem_range = MemoryRange::new(0x4000, 0x4fff);
    /// assert_eq!(mem_range.size(), 0x1000);
    /// ```
    pub fn size(&self) -> u64 {
        // plus 1 because we are address inclusive on the range
        1 + self.1 - self.0
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
    callbacks: Vec<MemoryCallback>,
    saved_context: Option<Vec<u8>>,
    aliased: bool,
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
    /// Reads contents of the [`MemoryRegion`] and saves it
    fn context_save(&mut self) -> Result<(), StyxMemoryError> {
        self.saved_context =
            Some(encode_all(self.read_data(self.base, self.size).unwrap().as_slice(), 0).unwrap());
        Ok(())
    }

    /// Overwrites contents of the [`MemoryRegion`] with the saved_context
    /// Returns an error if saved_context is empty.
    ///
    /// # Safety
    /// This will overwrite the entire region; the caller MUST PAUSE the CPU to stop execution
    /// before calling.
    unsafe fn context_restore(&mut self) -> Result<(), StyxMemoryError> {
        match &self.saved_context {
            Some(contents) => {
                let data = decode_all(contents.as_slice()).unwrap();
                unsafe { self.write_data_unchecked(self.base, data.as_slice()) }
            }
            None => Err(StyxMemorySnaphotError::EmptyContext)?,
        }
    }

    /// Checks if the [`MemoryRegion`] is aliased
    pub fn is_aliased(&self) -> bool {
        self.aliased
    }

    /// Returns a new [`MemoryRegion`] aliased to the current
    /// region. Note that calbackks are **not** clone'd, only
    /// the reference to memory, contexts are not transferred
    /// to the new alias
    pub fn new_alias(&self, base_address: u64) -> Self {
        Self {
            base: base_address,
            size: self.size,
            perms: self.perms,
            data: self.data.clone(),
            callbacks: Vec::new(),
            saved_context: None,
            aliased: true,
        }
    }

    /// Aligns the size of data to be a multiple of `alignment`,
    /// returning the number of bytes added to the end of the region.
    /// Any bytes added are `fill`
    ///
    /// `alignment` must not be 0
    ///
    /// # Safety
    /// Performing a size align operation should only occur before this
    /// [`MemoryRegion`] is actually being used, otherwise unknown things
    /// could happen
    ///
    /// ```rust
    /// use styx_memory::{MemoryRegion, MemoryPermissions};
    ///
    /// let mut region = MemoryRegion::new(0x1000, 0x10, MemoryPermissions::all()).unwrap();
    ///
    /// let bytes_added = unsafe {
    ///      region.align_size(0x100, 0xFF).unwrap()
    /// };
    ///
    /// let added_data = region.read_data(0x1010, 0xF0).unwrap();
    ///
    /// assert_eq!(0xF0u64, bytes_added, "Did not add correct # of bytes");
    /// assert_eq!(0x100, region.size(), "Did not resize correctly");
    /// assert_eq!(vec![0xFF; 0xF0], added_data, "Did not fill correctly");
    /// ```
    pub unsafe fn align_size(&mut self, alignment: u64, fill: u8) -> Result<u64, StyxMemoryError> {
        // an alignment of 0 is not a thing
        if alignment == 0 {
            return Err(StyxMemoryError::ZeroSize);
        }
        let usize_alignment =
            usize::try_from(alignment).map_err(|_| StyxMemoryError::SizeTooLarge(alignment))?;

        // get the amount we need to increase the length by to meet
        // the alignment requirements
        //
        // # Safety
        // Performing simple gette of the data vec
        let inner_data: &mut Vec<u8> = unsafe { &mut *self.data.with_mut(|ptr| ptr) };
        let data_len = inner_data.len();

        // figure out how much the vec needs to be modified
        let size_increase = if data_len > usize_alignment {
            // alignment is smaller than data
            data_len % usize_alignment
        } else {
            // alignment is larger or equal to data len
            usize_alignment - data_len
        };

        // check if we actually need to modify the region
        if size_increase > 0 {
            // need to increase the size of len by `size_increase`
            inner_data.extend(vec![fill; size_increase]);
            self.size = self.size.saturating_add(size_increase as u64);
        }

        Ok(size_increase as u64)
    }

    /// Increases the size of the region, setting all new contents to
    /// `fill`, returns the number of bytes added to the region, `size`
    /// must not be smaller than the current size
    ///
    /// # Safety
    /// Performing a resizing operation while the [`MemoryRegion`] is
    /// in use is unsafe. This method should only be used to perform
    /// modifications while the region is being prepared for use
    ///
    /// ```rust
    /// use styx_memory::{MemoryRegion, MemoryPermissions};
    ///
    /// let mut region = MemoryRegion::new(0x1000, 0x10, MemoryPermissions::all()).unwrap();
    ///
    /// let bytes_added = unsafe {
    ///      region.expand_size(0x100, 0xFF).unwrap()
    /// };
    ///
    /// let added_data = region.read_data(0x1010, 0xF0).unwrap();
    ///
    /// assert_eq!(0xF0u64, bytes_added, "Did not add correct # of bytes");
    /// assert_eq!(0x100, region.size(), "Did not resize correctly");
    /// assert_eq!(vec![0xFF; 0xF0], added_data, "Did not fill correctly");
    ///
    /// ```
    pub unsafe fn expand_size(&mut self, size: u64, fill: u8) -> Result<u64, StyxMemoryError> {
        match size.cmp(&self.size) {
            // nothing to do
            std::cmp::Ordering::Equal => Ok(0),
            // we cannot shrink
            std::cmp::Ordering::Less => Err(StyxMemoryError::SizeTooSmall(size, self.size)),
            // need to increase
            std::cmp::Ordering::Greater => {
                // get the size to increase by
                let size_increase = size - self.size;
                let inner_data: &mut Vec<u8> = unsafe { &mut *self.data.with_mut(|ptr| ptr) };

                // perform the increase
                inner_data.extend(vec![fill; size_increase as usize]);
                self.size += size_increase;

                // return the size increased by
                Ok(size_increase)
            }
        }
    }

    /// Modifies the `base_address` of the [`MemoryRegion`]
    ///
    /// # Safety
    /// Should not be invoked while [`MemoryRegion`] is in use,
    /// safe usage can only occur while configuring and setting
    /// up initial memory states
    ///
    /// ```rust
    /// use styx_memory::{MemoryRegion, MemoryPermissions};
    ///
    /// let mut region = MemoryRegion::new(0x1000, 0x10, MemoryPermissions::all()).unwrap();
    ///
    /// unsafe {
    ///     region.rebase(0x2000).unwrap();
    /// }
    ///
    /// assert_eq!(0x2000, region.base());
    /// ```
    #[inline]
    pub unsafe fn rebase(&mut self, base_address: u64) -> Result<(), StyxMemoryError> {
        self.base = base_address;

        Ok(())
    }

    /// Checks if the [`MemoryRegion`] has the desired permissions
    #[inline]
    fn permissions_check(&self, has: MemoryPermissions) -> Result<(), StyxMemoryError> {
        if self.perms & has != has {
            Err(StyxMemoryError::InvalidRegionPermissions {
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
        (self.base + self.size) - 1
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

    /// Create a new memory region with already created memory
    /// data.
    pub fn new_with_data(
        base: u64,
        size: u64,
        perms: MemoryPermissions,
        data: Vec<u8>,
    ) -> Result<Self, StyxMemoryError> {
        // make sure that the region size > 0
        if size == 0 {
            return Err(StyxMemoryError::ZeroSize);
        }

        // make sure that the vec provided is the correct size
        if data.len() as u64 != size {
            Err(StyxMemoryError::DataInvalidSize(size, data.len() as u64))
        } else {
            Ok(MemoryRegion {
                base,
                size,
                perms,
                data: Arc::new(UnsafeCell::new(data)),
                callbacks: Vec::new(),
                saved_context: None,
                aliased: false,
            })
        }
    }

    /// Create a new memory region, initializing all memory to 0
    /// and creating a buffer that can be used elsewhere
    /// if perms are empty, create an empty vector
    pub fn new(base: u64, size: u64, perms: MemoryPermissions) -> Result<Self, StyxMemoryError> {
        // make sure that the region size > 0
        if size == 0 {
            Err(StyxMemoryError::ZeroSize)
        } else {
            Ok(MemoryRegion {
                base,
                size,
                perms,
                data: if perms.is_empty() {
                    Arc::new(UnsafeCell::new(Vec::with_capacity(0)))
                } else {
                    Arc::new(UnsafeCell::new(vec![0; size as usize]))
                },
                callbacks: Vec::new(),
                saved_context: None,
                aliased: false,
            })
        }
    }

    /// writes a vector of data to the provided address
    pub fn write_data(&self, base: u64, data: &[u8]) -> Result<(), StyxMemoryError> {
        self.permissions_check(MemoryPermissions::WRITE)?;

        // # Safety
        // We just checked the permissions, size is checked in `write_data_unchecked`
        unsafe { self.write_data_unchecked(base, data) }
    }

    /// writes primitive type to bytes at provided address in little
    /// endian form
    pub fn write<T: PrimInt>(&self, base: u64, data: T) -> Result<(), StyxMemoryError> {
        self.permissions_check(MemoryPermissions::WRITE)?;

        // # Safety
        // Converts from a primitive to the bytes of the primitive, and gets
        // the correct type size bound to deconstruct it.
        let value = unsafe {
            // rUsT iS sAfE
            core::slice::from_raw_parts(&data as *const T as *const u8, core::mem::size_of::<T>())
        };

        // # Safety
        // We just checked the permissions, size is checked in `write_data_unchecked`
        unsafe { self.write_data_unchecked(base, value) }
    }

    /// reads primitive type to bytes at provided address in little
    /// endian form
    pub fn read<T: PrimInt>(&self, base: u64) -> Result<T, StyxMemoryError> {
        self.permissions_check(MemoryPermissions::READ)?;

        // # Safety
        // We just checked the permissions
        unsafe { self.read_unchecked(base) }
    }

    /// reads the specified `size` from the provided `base` address
    pub fn read_data(&self, base: u64, size: u64) -> Result<Vec<u8>, StyxMemoryError> {
        self.permissions_check(MemoryPermissions::READ)?;

        // # Safety
        // We just checked the permissions
        unsafe { self.read_data_unchecked(base, size) }
    }

    /// Performs a write to the internal region data without checking
    /// for permissions however the bounds are still checked.
    ///
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
    pub unsafe fn write_unchecked<T: PrimInt>(
        &self,
        base: u64,
        data: T,
    ) -> Result<(), StyxMemoryError> {
        let size = core::mem::size_of::<T>();

        // # Safety
        // Converts from a primitive to the bytes of the primitive, and gets
        // the correct type size bound to deconstruct it.
        let value = unsafe {
            // rUsT iS sAfE
            core::slice::from_raw_parts(&data as *const T as *const u8, size)
        };

        // # Safety
        // We just checked the permissions
        unsafe { self.write_data_unchecked(base, value) }
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
    ) -> Result<(), StyxMemoryError> {
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
    pub unsafe fn read_unchecked<T: PrimInt>(&self, base: u64) -> Result<T, StyxMemoryError> {
        let size = core::mem::size_of::<T>();
        self.address_range_valid(base, size as u64, MemoryOperation::Read)?;

        let mut tmp: [u8; 64] = [0; 64];
        let base_idx = (base - self.base) as usize;
        let end_idx = base_idx + size;

        unsafe {
            let data = &mut *self.data.with_mut(|ptr| ptr);
            // copy the data into the stack buffer
            tmp[0..size].copy_from_slice(&data[base_idx..end_idx]);

            // return a copy of these bytes
            Ok(core::ptr::read_unaligned(tmp.as_ptr() as *const T))
        }
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
    ) -> Result<Vec<u8>, StyxMemoryError> {
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

    /// Validate that the requested ranges is within the current memory
    /// region.
    pub(crate) fn address_range_valid(
        &self,
        base: u64,
        size: u64,
        op: MemoryOperation,
    ) -> Result<(), StyxMemoryError> {
        // size cannot be zero
        if size == 0 {
            return Err(StyxMemoryError::ZeroSize);
        }

        // minus 1 because requested bytes are inclusive.
        // note that this being unchecked required size be > 0
        let request_max = base + size - 1;

        if base < self.base {
            return Err(StyxMemoryError::InvalidMemoryRange {
                op,
                request_min: base,

                request_max,
                limit_min: self.base,
                limit_max: self.end(),
            });
        }

        // base + size must be <= self.end
        // this allows reads at the last byte address size 1 to succeed,
        // and not letting things run past the end
        if request_max > self.end() {
            return Err(StyxMemoryError::InvalidMemoryRange {
                op,
                request_min: base,
                request_max,
                limit_min: self.base,
                limit_max: self.end(),
            });
        }

        Ok(())
    }
}

/// Stub idea, at some point we're going to need to register
/// callbacks for R/W events on MMR's as they happen,
/// this is a possible implementation.
pub struct CallbackError {}

pub type MemoryCallback = fn() -> Result<(), CallbackError>;

#[cfg(test)]
mod tests {
    use super::*;
    use styx_memory_type::MemoryPermissions as Perms;
    use test_case::test_case;

    #[test_case(0x0, 0x1; "base too small")]
    #[test_case(0x1000, 0x0; "size is zero")]
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
            Err(StyxMemoryError::ZeroSize)
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
        assert!(matches!(
            result,
            Err(StyxMemoryError::DataInvalidSize(_, _))
        ));
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
        let result = region.read::<u64>(0x1000);

        // test cannot read from write only
        assert!(matches!(
            result,
            Err(StyxMemoryError::InvalidRegionPermissions {
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
        let result = region.write::<u64>(0x1000, 5);

        // test cannot write to read only
        assert!(matches!(
            result,
            Err(StyxMemoryError::InvalidRegionPermissions {
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
            Err(StyxMemoryError::InvalidRegionPermissions {
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
            Err(StyxMemoryError::InvalidRegionPermissions {
                have: Perms::READ,
                need: Perms::WRITE
            })
        ));
    }

    #[test]
    fn test_write_empty() {
        // make bank initial region at 0
        let bank = MemoryBank::default();
        bank.add_region(MemoryRegion::new(0x0000, 0x10, Perms::all()).unwrap())
            .unwrap();

        // attempt a zero-length write and read
        bank.write_memory(0x00, &[]).unwrap();
        bank.read_memory(0x00, &mut []).unwrap();

        // Make sure memory is still zero
        let mut buf = [0xAA; 0x10];
        bank.read_memory(0x00, &mut buf).unwrap();

        assert_eq!(&[0x00; 0x10], &buf);
    }

    #[test_case(0x100, 0, Perms::READ; "(R) Write below memory map")]
    #[test_case(0x100, 0, Perms::WRITE; "(W) Write below memory map")]
    #[test_case(0x10000, 0, Perms::READ; "(R) Write above memory map")]
    #[test_case(0x10000, 0, Perms::WRITE; "(W) Write above memory map")]
    #[test_case(0x10FE, 0, Perms::READ; "(R) Write overlap high end")]
    #[test_case(0x10FE, 0, Perms::WRITE; "(W) Write overlap high end")]
    #[test_case(0x10F9, 0, Perms::READ; "(R) Write overlap high 1 byte")]
    #[test_case(0x10F9, 0, Perms::WRITE; "(W) Write overlap high 1 byte")]
    #[test_case(0xFFE, 0, Perms::READ; "(R) Write overlap low end")]
    #[test_case(0xFFE, 0, Perms::WRITE; "(W) Write overlap low end")]
    fn test_write_memory_unchecked_err(start: u64, data: u64, perms: MemoryPermissions) {
        // make initial region
        let region = MemoryRegion::new(0x1000, 0x100, perms).unwrap();

        // attempt to write
        let result = unsafe { region.write_unchecked::<u64>(start, data) };

        assert!(matches!(
            result,
            Err(StyxMemoryError::InvalidMemoryRange { .. })
        ));
    }

    #[test_case(0x100, 0, Perms::WRITE; "(W) Write below memory map")]
    #[test_case(0x10000, 0, Perms::WRITE; "(W) Write above memory map")]
    #[test_case(0x10FE, 0, Perms::WRITE; "(W) Write overlap high end")]
    #[test_case(0x10F9, 0, Perms::WRITE; "(W) Write overlap high 1 byte")]
    #[test_case(0xFFE, 0, Perms::WRITE; "(W) Write overlap low end")]
    fn test_write_memory_err(start: u64, data: u64, perms: MemoryPermissions) {
        // make initial region
        let region = MemoryRegion::new(0x1000, 0x100, perms).unwrap();

        // attempt to write
        let result = region.write::<u64>(start, data);

        assert!(matches!(
            result,
            Err(StyxMemoryError::InvalidMemoryRange { .. })
        ));
    }

    #[test_case(0x1000, 0, Perms::READ; "(R) Write valid to bottom")]
    #[test_case(0x1000, 0, Perms::WRITE; "(W) Write valid to bottom")]
    #[test_case(0x1008, 0, Perms::READ; "(R) Write valid to middle")]
    #[test_case(0x1008, 0, Perms::WRITE; "(W) Write valid to middle")]
    #[test_case(0x10F8, 0, Perms::READ; "(R) Write valid to top")]
    #[test_case(0x10F8, 0, Perms::WRITE; "(W) Write valid to top")]
    fn test_write_unchecked_valid(start: u64, data: u64, perms: MemoryPermissions) {
        // make initial region
        let region = MemoryRegion::new(0x1000, 0x100, perms).unwrap();

        unsafe {
            // assert write succeeded
            assert!(region.write_unchecked::<u64>(start, data).is_ok());
        }
    }

    #[test_case(0x1000, 0, Perms::WRITE; "(W) Write valid to bottom")]
    #[test_case(0x1008, 0, Perms::WRITE; "(W) Write valid to middle")]
    #[test_case(0x10F8, 0, Perms::WRITE; "(W) Write valid to top")]
    fn test_write_valid(start: u64, data: u64, perms: MemoryPermissions) {
        // make initial region
        let region = MemoryRegion::new(0x1000, 0x100, perms).unwrap();

        // assert write succeeded
        assert!(region.write::<u64>(start, data).is_ok());
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
                Err(StyxMemoryError::InvalidMemoryRange { .. })
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
            Err(StyxMemoryError::InvalidMemoryRange { .. })
        ));
    }

    #[test_case(0x100, Perms::READ; "(R) Read below memory map")]
    #[test_case(0x100, Perms::WRITE; "(W) Read below memory map")]
    #[test_case(0x10000, Perms::READ; "(R) Read above memory map")]
    #[test_case(0x10000, Perms::WRITE; "(W) Read above memory map")]
    #[test_case(0x10FE, Perms::READ; "(R) Read overlap high end")]
    #[test_case(0x10FE, Perms::WRITE; "(W) Read overlap high end")]
    #[test_case(0x10F9, Perms::READ; "(R) Read overlap high 1 byte")]
    #[test_case(0x10F9, Perms::WRITE; "(W) Read overlap high 1 byte")]
    #[test_case(0xFFE, Perms::READ; "(R) Read overlap low end")]
    #[test_case(0xFFE, Perms::WRITE; "(W) Read overlap low end")]
    fn test_read_memory_unchecked_err(base: u64, perms: MemoryPermissions) {
        // make initial region
        let region = MemoryRegion::new(0x1000, 0x100, perms).unwrap();

        unsafe {
            // attempt to read
            let result = region.read_unchecked::<u64>(base);

            // assert proper fail
            assert!(matches!(
                result,
                Err(StyxMemoryError::InvalidMemoryRange { .. })
            ));
        }
    }

    #[test_case(0x100, Perms::READ; "(R) Read below memory map")]
    #[test_case(0x10000, Perms::READ; "(R) Read above memory map")]
    #[test_case(0x10FE, Perms::READ; "(R) Read overlap high end")]
    #[test_case(0x10F9, Perms::READ; "(R) Read overlap high 1 byte")]
    #[test_case(0xFFE, Perms::READ; "(R) Read overlap low end")]
    fn test_read_memory_err(base: u64, perms: MemoryPermissions) {
        // make initial region
        let region = MemoryRegion::new(0x1000, 0x100, perms).unwrap();

        // attempt to read
        let result = region.read::<u64>(base);

        // assert proper fail
        assert!(matches!(
            result,
            Err(StyxMemoryError::InvalidMemoryRange { .. })
        ));
    }

    #[test_case(0x1000, Perms::READ; "(R) Read valid from bottom")]
    #[test_case(0x1000, Perms::WRITE; "(W) Read valid from bottom")]
    #[test_case(0x1008, Perms::READ; "(R) Read valid from middle")]
    #[test_case(0x1008, Perms::WRITE; "(W) Read valid from middle")]
    #[test_case(0x10F8, Perms::READ; "(R) Read valid from top")]
    #[test_case(0x10F8, Perms::WRITE; "(W) Read valid from top")]
    fn test_read_memory_unchecked_valid(base: u64, perms: MemoryPermissions) {
        // make initial region
        let mut data = Vec::new();
        for i in 0x1000..0x1100 {
            data.push((i % 0xff) as u8);
        }
        let verification = data.clone();
        let region = MemoryRegion::new_with_data(0x1000, 0x100, perms, data).unwrap();

        unsafe {
            // assert read ok
            if let Ok(value) = region.read_unchecked::<u8>(base) {
                // assert content correct
                let verified_idx: usize = (base as usize) - 0x1000;
                assert_eq!(
                    value, verification[verified_idx],
                    "Wanted: {:#08X}, Got: {:#08X}",
                    verification[verified_idx], value
                );
            } else {
                panic!("read of (valid) address {base:#08X} failed");
            }
        }
    }

    #[test_case(0x1000, Perms::READ; "(R) Read valid from bottom")]
    #[test_case(0x1008, Perms::READ; "(R) Read valid from middle")]
    #[test_case(0x10F8, Perms::READ; "(R) Read valid from top")]
    fn test_read_memory_valid(base: u64, perms: MemoryPermissions) {
        // make initial region
        let mut data = Vec::new();
        for i in 0x1000..0x1100 {
            data.push((i % 0xff) as u8);
        }
        let verification = data.clone();
        let region = MemoryRegion::new_with_data(0x1000, 0x100, perms, data).unwrap();

        // assert read ok
        if let Ok(value) = region.read::<u8>(base) {
            // assert content correct
            let verified_idx: usize = (base as usize) - 0x1000;
            assert_eq!(
                value, verification[verified_idx],
                "Wanted: {:#08X}, Got: {:#08X}",
                verification[verified_idx], value
            );
        } else {
            panic!("read of (valid) address {base:#08X} failed");
        }
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
                Err(StyxMemoryError::InvalidMemoryRange { .. })
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
            Err(StyxMemoryError::InvalidMemoryRange { .. })
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

    #[test_case(0x1000, 2, vec![0xDE, 0xEA]; "Single region, two bytes")]
    #[test_case(0x1004, 4, vec![0xCA, 0xFE, 0xBA, 0xBE]; "Single region, four bytes")]
    #[test_case(0x1000, 6, vec![0xDE, 0xEA, 0xBE, 0xEF, 0xCA, 0xFE]; "Two regions, six bytes")]
    #[test_case(0x1002, 4, vec![0xBE, 0xEF, 0xCA, 0xFE]; "Two regions, four bytes")]
    fn test_bank_read_data(base: u64, size: usize, expected: Vec<u8>) {
        let bank = MemoryBank::default();
        let region1 = MemoryRegion::new_with_data(
            0x1000,
            4,
            MemoryPermissions::all(),
            vec![0xDE, 0xEA, 0xBE, 0xEF],
        )
        .unwrap();
        bank.add_region(region1).unwrap();

        let region2 = MemoryRegion::new_with_data(
            0x1004,
            4,
            MemoryPermissions::all(),
            vec![0xCA, 0xFE, 0xBA, 0xBE],
        )
        .unwrap();
        bank.add_region(region2).unwrap();

        let mut data = vec![0u8; size];
        bank.read_memory(base, &mut data).unwrap();

        assert_eq!(data, expected);
    }

    #[test_case(0x1000, vec![0xDE, 0xEA]; "Single region, two bytes")]
    #[test_case(0x1000, vec![0xDE, 0xEA, 0xBE, 0xEF]; "Single region, four bytes")]
    #[test_case(0x1000, vec![0xDE, 0xEA, 0xBE, 0xEF, 0xCA, 0xFE]; "Two regions, six bytes")]
    #[test_case(0x1002, vec![0xBE, 0xEF, 0xCA, 0xFE]; "Two regions, four bytes")]
    fn test_bank_write_data(base: u64, data: Vec<u8>) {
        let bank = MemoryBank::default();
        let region1 = MemoryRegion::new_with_data(
            0x1000,
            4,
            MemoryPermissions::all(),
            vec![0xDE, 0xEA, 0xBE, 0xEF],
        )
        .unwrap();
        bank.add_region(region1).unwrap();

        let region2 = MemoryRegion::new_with_data(
            0x1004,
            4,
            MemoryPermissions::all(),
            vec![0xCA, 0xFE, 0xBA, 0xBE],
        )
        .unwrap();
        bank.add_region(region2).unwrap();

        bank.write_memory(base, &data).unwrap();
        let mut read_data = vec![0u8; data.len()];
        bank.read_memory(base, &mut read_data).unwrap();

        assert_eq!(read_data, data);
    }

    #[test]
    #[cfg_attr(miri, ignore)] // uses zstd ffi
    fn test_memory_range_context_save_restore() {
        const BASE: u64 = 0x1000;
        const PERMS: MemoryPermissions = Perms::READ;
        let data = Vec::from_iter(0..255);

        let bank = MemoryBank::default();
        let region =
            MemoryRegion::new_with_data(BASE, data.len() as u64, PERMS, data.clone()).unwrap();
        bank.add_region(region).unwrap();

        bank.context_save().unwrap();
        bank.context_restore().unwrap();

        let mut read_data = vec![0u8; data.len()];
        bank.read_memory(BASE, &mut read_data).unwrap();

        assert_eq!(read_data, data);
    }
}
