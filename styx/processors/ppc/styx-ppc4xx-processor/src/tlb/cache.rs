// SPDX-License-Identifier: BSD-2-Clause
use std::{cmp::Ordering, ops::Range};

/// Functions for a Tlb cache with 32 bit addresses
pub trait TlbCache32 {
    const SIZE: usize;

    fn new(start_index: usize) -> Self;
    /// Search for a matching page
    fn search(&self, virt_addr: u32) -> Option<usize>;
    /// Replace a page in the cache, implementation decides which one to replace
    ///
    /// This function returns the index of the entry being replaced
    fn replace(&mut self, start_addr: u32, end_addr: u32) -> usize;
    /// Replace a page with a matching Tlb index
    fn replace_index(&mut self, tlb_idx: usize, start_addr: u32, end_addr: u32);
}

/// An unsorted Tlb cache with round robin replacement
///
/// Best if used for small hardware managed caches (like <16 elements)
pub struct UnsortedRoundRobinTlbCache<const N: usize> {
    pub pages: [PageID; N],
    next_idx_to_replace: usize,
}

impl<const N: usize> TlbCache32 for UnsortedRoundRobinTlbCache<N> {
    const SIZE: usize = N;

    fn new(start_index: usize) -> Self {
        let mut v: Vec<PageID> = Vec::with_capacity(N);

        for i in 0..N {
            v.push(PageID::new(start_index + i));
        }

        Self {
            pages: v.try_into().unwrap(),
            next_idx_to_replace: 0,
        }
    }

    fn search(&self, virt_addr: u32) -> Option<usize> {
        (0..N).find(|&i| unsafe {
            self.pages
                .get_unchecked(i)
                .address_range
                .contains(&virt_addr)
        })
    }

    fn replace(&mut self, start_addr: u32, end_addr: u32) -> usize {
        self.pages[self.next_idx_to_replace].address_range = start_addr..end_addr;

        let ret = self.pages[self.next_idx_to_replace].id;

        self.next_idx_to_replace = (self.next_idx_to_replace + 1) % N;

        ret
    }

    fn replace_index(&mut self, tlb_idx: usize, start_addr: u32, end_addr: u32) {
        for i in 0..N {
            // Safety: this will never go out of bounds, array is size N and 0 <= i < N
            if unsafe { self.pages.get_unchecked(i).id == tlb_idx } {
                self.pages[i].address_range = start_addr..end_addr;
                break;
            }
        }
    }
}

/// A Tlb Cache of size N, where contents are sorted by page base address for fast searching
pub struct SortedTlbCache<const N: usize> {
    pub pages: [PageID; N],
}

impl<const N: usize> TlbCache32 for SortedTlbCache<N> {
    const SIZE: usize = N;

    fn new(start_index: usize) -> Self {
        let mut v: Vec<PageID> = Vec::with_capacity(N);

        for i in 0..N {
            v.push(PageID::new(start_index + i));
        }

        Self {
            pages: v.try_into().unwrap(),
        }
    }

    fn search(&self, virt_addr: u32) -> Option<usize> {
        let mut tlb_idx = 0_usize;
        if self
            .pages
            .binary_search_by(|e| {
                if e.address_range.start > virt_addr {
                    Ordering::Greater
                } else if e.address_range.end <= virt_addr {
                    Ordering::Less
                } else {
                    tlb_idx = e.id;
                    Ordering::Equal
                }
            })
            .is_ok()
        {
            Some(tlb_idx)
        } else {
            None
        }
    }

    fn replace(&mut self, _start_addr: u32, _end_addr: u32) -> usize {
        // this function should not be used for this cache type
        unreachable!()
    }

    fn replace_index(&mut self, tlb_idx: usize, start_addr: u32, end_addr: u32) {
        for i in 0..N {
            // Safety: this will never go out of bounds, array is size N and 0 <= i < N
            if unsafe { self.pages.get_unchecked(i).id == tlb_idx } {
                self.pages[i].address_range = start_addr..end_addr;
                break;
            }
        }

        self.pages.sort_unstable();
    }
}

#[derive(Debug)]
/// An identifier for a virtual page
pub struct PageID {
    /// the virtual addresses that this page covers
    pub address_range: Range<u32>,
    /// the index in the TLB where this page is described
    pub id: usize,
}

impl Eq for PageID {}

impl PartialEq for PageID {
    fn eq(&self, other: &Self) -> bool {
        self.address_range.start == other.address_range.start
    }
}

impl Ord for PageID {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.address_range.start.cmp(&other.address_range.start)
    }
}

impl PartialOrd for PageID {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PageID {
    fn new(tlb_idx: usize) -> Self {
        Self {
            address_range: u32::MAX..u32::MAX,
            id: tlb_idx,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_page_id() {
        // tests ordering and equality for the PageID struct
        let id1 = PageID {
            address_range: 0..20,
            id: 0,
        };
        let id2 = PageID {
            address_range: 40..60,
            id: 1,
        };
        let id3 = PageID {
            address_range: 40..80,
            id: 2,
        };

        assert!(id1 < id2);
        assert!(id1 < id3);
        assert_eq!(id2, id3);
    }
}
