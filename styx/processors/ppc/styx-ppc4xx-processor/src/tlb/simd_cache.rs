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
//! SIMD based implementations of Tlb caches to provide faster searching/translation of virtual addresses.
//!
//! Requires avx2 and bmi1 (bit manipulation instruction set 1.0) features
//!
//! The search procedure for each of the following structs are basically identical but with some differences in sizes.
//!
//! The problem:
//!
//! Given a set of non-overlapping, half-open address ranges and an address `x`, tell me which address range `x`
//! belongs to (and do it quickly).
//!
//! The solution:
//!
//! 1. split each address range into low and high components and store in separate vectors, defined as low and high.
//!
//! 2. create a third vector, the query vector, as a vector of the same size as low and high but each entry is `x`
//!
//!     Ex:
//!
//!     address ranges: [0,10), [10,20), [20,30), [30,40)
//!     address query = 25
//!
//!     low   = [ 0, 10, 20, 30]
//!     high  = [10, 20, 30, 40]
//!     query = [25, 25, 25, 25]
//!
//! 3. Do the operation query < high to find all of the high bounds that satisfy the query
//!
//!     lt_high = query < high = [0, 0, 1, 1]
//!
//! 4. Do the operation query >= low to find all of the low bounds that satisfy the query
//!
//!     ge_low = query >= low = [1, 1, 1, 0]
//!
//! 5. Do the operation lt_high & ge_low to find the address range that contains the query
//!
//!     lt_high & ge_low = [0, 0, 1, 1] & [1, 1, 1, 0] = [0, 0, 1, 0]
//!
//!     therefore, 25 belongs to address range [20, 30)
//!
//! Usind SIMD intrinsics we can do this for up to 8 elements at a time, assuming 32 bit addresses (256 bit vector, 8*32 = 256)
//!
//! Notes:
//! 1. There is no greater than or equal to operation in AVX2 so instead we do
//!
//!     `!(low > query) <==> (query >= low)`
//!
//!     which is actually implemented as `(low > query) ^ vec[1]` because 'not' also doesn't exist
//!
//! 2. To tell which address range an address belongs to we convert the resulting vector of 1s and 0s into a bit
//!     mask and then use the trailing zero count intrinsic to quickly determine which index is a 1
//!
use crate::tlb::cache::TlbCache32;

use std::arch::x86_64;

#[repr(C, align(16))]
/// A 4 element Tlb cache with round robin replacement
pub struct FastTlbCache4 {
    low_bounds: [u32; 4],
    high_bounds: [u32; 4],
    tlb_ids: [usize; 4],
    replacement_idx: usize,
}

impl TlbCache32 for FastTlbCache4 {
    const SIZE: usize = 4;

    fn new(start_index: usize) -> Self {
        let mut cache = Self {
            low_bounds: [u32::MAX; Self::SIZE],
            high_bounds: [u32::MAX; Self::SIZE],
            tlb_ids: [0; Self::SIZE],
            replacement_idx: 0,
        };

        for i in 0..Self::SIZE {
            cache.tlb_ids[i] = start_index + i;
        }

        cache
    }

    fn search(&self, virt_addr: u32) -> Option<usize> {
        // Safety: if self.tlb_lookup returns Some(i), then 0 <= i < 4
        unsafe { self.tlb_lookup(virt_addr) }
            .map(|idx| unsafe { *(self.tlb_ids.get_unchecked(idx)) })
    }

    fn replace(&mut self, start_addr: u32, end_addr: u32) -> usize {
        self.low_bounds[self.replacement_idx] = start_addr;
        self.high_bounds[self.replacement_idx] = end_addr;
        let ret = self.tlb_ids[self.replacement_idx];

        self.replacement_idx = (self.replacement_idx + 1) % Self::SIZE;

        ret
    }

    fn replace_index(&mut self, tlb_idx: usize, start_addr: u32, end_addr: u32) {
        for i in 0..Self::SIZE {
            // Safety: array of length SIZE, 0 <= i < SIZE
            if unsafe { *(self.tlb_ids.get_unchecked(i)) } == tlb_idx {
                self.low_bounds[i] = start_addr;
                self.high_bounds[i] = end_addr;
            }
        }
    }
}

impl FastTlbCache4 {
    #[target_feature(enable = "avx2")]
    #[target_feature(enable = "bmi1")]
    unsafe fn tlb_lookup(&self, v_addr: u32) -> Option<usize> {
        let low_vec = x86_64::_mm_load_si128(self.low_bounds.as_ptr() as *const x86_64::__m128i);
        let high_vec = x86_64::_mm_load_si128(self.high_bounds.as_ptr() as *const x86_64::__m128i);
        let query_vec = x86_64::_mm_set1_epi32(std::mem::transmute::<u32, i32>(v_addr));

        let lt_high = x86_64::_mm_cmplt_epi32(query_vec, high_vec);
        let ge_low = x86_64::_mm_xor_si128(
            x86_64::_mm_cmpgt_epi32(low_vec, query_vec),
            x86_64::_mm_set1_epi32(-1),
        );

        let in_bounds = x86_64::_mm_and_si128(lt_high, ge_low);

        let mask = x86_64::_mm_movemask_ps(x86_64::_mm_castsi128_ps(in_bounds));
        if mask > 0 {
            Some(x86_64::_tzcnt_u32(core::mem::transmute::<i32, u32>(mask)) as usize & 0b11)
        } else {
            None
        }
    }
}

#[repr(C, align(32))]
/// An 8 element Tlb cache with round robin replacement
pub struct FastTlbCache8 {
    low_bounds: [u32; 8],
    high_bounds: [u32; 8],
    tlb_ids: [usize; 8],
    replacement_idx: usize,
}

impl TlbCache32 for FastTlbCache8 {
    const SIZE: usize = 8;

    fn new(start_index: usize) -> Self {
        let mut cache = Self {
            low_bounds: [u32::MAX; Self::SIZE],
            high_bounds: [u32::MAX; Self::SIZE],
            tlb_ids: [0; Self::SIZE],
            replacement_idx: 0,
        };

        for i in 0..Self::SIZE {
            cache.tlb_ids[i] = start_index + i;
        }

        cache
    }

    fn search(&self, virt_addr: u32) -> Option<usize> {
        // Safety: if self.tlb_lookup returns Some(i),0 <= i < Self::SIZE
        unsafe { self.tlb_lookup(virt_addr) }
            .map(|idx| unsafe { *(self.tlb_ids.get_unchecked(idx)) })
    }

    fn replace(&mut self, start_addr: u32, end_addr: u32) -> usize {
        self.low_bounds[self.replacement_idx] = start_addr;
        self.high_bounds[self.replacement_idx] = end_addr;
        let ret = self.tlb_ids[self.replacement_idx];

        self.replacement_idx = (self.replacement_idx + 1) % Self::SIZE;

        ret
    }

    fn replace_index(&mut self, tlb_idx: usize, start_addr: u32, end_addr: u32) {
        for i in 0..Self::SIZE {
            // Safety: array of size Self::SIZE, 0 <= i < Self::SIZE
            if unsafe { *(self.tlb_ids.get_unchecked(i)) } == tlb_idx {
                self.low_bounds[i] = start_addr;
                self.high_bounds[i] = end_addr;
            }
        }
    }
}

impl FastTlbCache8 {
    #[target_feature(enable = "avx2")]
    #[target_feature(enable = "bmi1")]
    unsafe fn tlb_lookup(&self, v_addr: u32) -> Option<usize> {
        let low_vec = x86_64::_mm256_load_si256(self.low_bounds.as_ptr() as *const x86_64::__m256i);
        let high_vec =
            x86_64::_mm256_load_si256(self.high_bounds.as_ptr() as *const x86_64::__m256i);
        let query = x86_64::_mm256_set1_epi32(std::mem::transmute::<u32, i32>(v_addr));

        let lt_high = x86_64::_mm256_cmpgt_epi32(high_vec, query);
        let ge_low = x86_64::_mm256_xor_si256(
            x86_64::_mm256_cmpgt_epi32(low_vec, query),
            x86_64::_mm256_set1_epi32(-1),
        );

        let in_bounds = x86_64::_mm256_and_si256(lt_high, ge_low);

        let mask = x86_64::_mm256_movemask_ps(x86_64::_mm256_castsi256_ps(in_bounds));
        if mask > 0 {
            Some(x86_64::_tzcnt_u32(core::mem::transmute::<i32, u32>(mask)) as usize & 0b111)
        } else {
            None
        }
    }
}

#[repr(C, align(32))]
/// A 64 element Tlb cache with no hardware replacement, unsorted
pub struct FastTlbCache64 {
    low_bounds: [u32; 64],
    high_bounds: [u32; 64],
    tlb_ids: [usize; 64],
}

impl TlbCache32 for FastTlbCache64 {
    const SIZE: usize = 64;

    fn new(start_index: usize) -> Self {
        let mut cache = Self {
            low_bounds: [u32::MAX; Self::SIZE],
            high_bounds: [u32::MAX; Self::SIZE],
            tlb_ids: [0; Self::SIZE],
        };

        for i in 0..Self::SIZE {
            cache.tlb_ids[i] = start_index + i;
        }

        cache
    }

    /// Binary searches down to 8 elements and then does a SIMD search for the remaining elements
    fn search(&self, virt_addr: u32) -> Option<usize> {
        // Safety: if self.tlb_lookup returns Some(i),0 <= i < Self::SIZE
        unsafe { self.lookup(virt_addr) }.map(|idx| unsafe { *(self.tlb_ids.get_unchecked(idx)) })
    }

    fn replace(&mut self, _start_addr: u32, _end_addr: u32) -> usize {
        unimplemented!()
    }

    fn replace_index(&mut self, tlb_idx: usize, start_addr: u32, end_addr: u32) {
        for i in 0..Self::SIZE {
            // Safety: array of size Self::SIZE, 0 <= i < Self::SIZE
            if unsafe { *(self.tlb_ids.get_unchecked(i)) } == tlb_idx {
                self.low_bounds[i] = start_addr;
                self.high_bounds[i] = end_addr;
            }
        }
    }
}

impl FastTlbCache64 {
    #[target_feature(enable = "avx2")]
    #[target_feature(enable = "bmi1")]
    unsafe fn lookup(&self, v_addr: u32) -> Option<usize> {
        // chunk our 64 entry array into 8 pieces and search each sequentially
        for i in 0..8 {
            let low_vec = x86_64::_mm256_load_si256(
                self.low_bounds[(8 * i)..(8 * (i + 1))].as_ptr() as *const x86_64::__m256i,
            );
            let high_vec = x86_64::_mm256_load_si256(
                self.high_bounds[(8 * i)..(8 * (i + 1))].as_ptr() as *const x86_64::__m256i,
            );
            let query = x86_64::_mm256_set1_epi32(std::mem::transmute::<u32, i32>(v_addr));

            let lt_high = x86_64::_mm256_cmpgt_epi32(high_vec, query);
            let ge_low = x86_64::_mm256_xor_si256(
                x86_64::_mm256_cmpgt_epi32(low_vec, query),
                x86_64::_mm256_set1_epi32(-1),
            );

            let in_bounds = x86_64::_mm256_and_si256(lt_high, ge_low);

            let x = x86_64::_mm256_movemask_ps(x86_64::_mm256_castsi256_ps(in_bounds));
            if x != 0 {
                return Some(
                    (8 * i) + x86_64::_tzcnt_u32(core::mem::transmute::<i32, u32>(x)) as usize,
                );
            }
        }

        None
    }
}
