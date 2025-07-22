// SPDX-License-Identifier: BSD-2-Clause
//! Tlb Architecture:
//!
//! - 64 entry unified TLB, managed by software
//! - 4 entry shadow instruction TLB, managed by hardware (round robin replacement)
//! - 4 entry shadow data TLB, managed by hardware (round robin replacement)
//!
//! TLB Interrupts:
//!  - Data storage interrupt
//!    - triggered when data address translation is enabled but access to virtual address is not permitted
//!  - Instruction storage interrupt
//!    - triggered when instruction address translation is enabled but access to virtual address is not permitted
//!  - Data TLB miss interrupt
//!    - triggered when translation active and address not present in UTLB
//!  - Instruction TLB miss interrupt
//!    - triggered when translation active and address not present in UTLB
//!  - Program interrupt
//!    - triggered when "TIE_cpuMmuEn" is 0 and any TLB related instruction is executed, in this state they
//!      are treated as illegal instructions
//!
//! For instruction accesses:
//! 1. Cpu generates a virtual address and fetches from memory.
//! 2. If instruction address translation is disabled, address is treated as physical.
//! 3. Lookup in shadow ITLB.
//! 4. If Tlb hit, return translation.
//! 5. If Tlb miss, lookup in unified TLB.
//! 6. If Tlb miss, generate Tlb miss exception.
//! 7. If Tlb hit, return translation.
//!
//!
//! A virtual address can be represented as an offset + a
//! base (the virtual page number). The size of the page
//! determines how many "free" bits exist in the address.
//! Which determines how many bits get masked off when
//! computing a physical address.
//!
//! Example:
//!     A page size of 1KB leave the 22 most significant
//!     bits as the page number and the 10 least
//!     significant bits as the offset into the page.
//!
//! MSR[IR, DR] enables/disables address translation for instructions and data
//! - all interrupts clear these bits
//! - default to disabled
//!
//! page sizes (1KB, 4KB, 16KB, 64KB, 256KB, 1MB, 4MB, 16MB)
//!
//! Zone fields are currently not supported, afaik nothing really uses them and it would just be a waste of time to implement right now.
mod cache;
mod record;
mod simd_cache;

use cache::{SortedTlbCache, TlbCache32, UnsortedRoundRobinTlbCache};
use record::TlbRecord;
use styx_core::errors::UnknownError;

use styx_core::memory::{
    MemoryOperation, TlbImpl, TlbProcessor, TlbTranslateError, TlbTranslateResult,
};
use styx_core::prelude::log::warn;
use styx_core::prelude::*;

#[cfg(target_feature = "avx2")]
#[cfg(target_feature = "bmi1")]
use simd_cache::{FastTlbCache4, FastTlbCache64, FastTlbCache8};

const UNIFIED_TLB_CAPACITY: usize = 64;
const INSTRUCTION_TLB_CAPACITY: usize = 4;
const DATA_TLB_CAPACITY: usize = 8;

const TOTAL_TLB_CAPACITY: usize =
    UNIFIED_TLB_CAPACITY + INSTRUCTION_TLB_CAPACITY + DATA_TLB_CAPACITY;

// used to clear the valid bit in tlb record tags
const TLBHI_V_MASK: u32 = !(1 << 25);

// flags for reading/writing to the tlb
const PPC405_TLB_HI: u32 = 0;
const PPC405_TLB_LO: u32 = 1;

// flags for invalidating different cache layers
const PPC405_TLB_L1: u32 = 0b1;
const PPC405_TLB_L2: u32 = 0b10;

pub struct Ppc405Tlb {
    /// is address translation for code enabled
    inst_relocate_enabled: bool,
    /// is address translation for data enabled
    data_relocate_enabled: bool,
    /// the current value of the pid register
    current_pid: u8,
    /// holds the actual tlb data for each of the caches
    tlb_data: [TlbRecord; TOTAL_TLB_CAPACITY],

    /// various arrays for searching in each cache
    #[cfg(not(target_feature = "avx2"))]
    #[cfg(not(target_feature = "bmi1"))]
    unified_tlb: SortedTlbCache<64>,
    #[cfg(not(target_feature = "avx2"))]
    #[cfg(not(target_feature = "bmi1"))]
    instruction_tlb: UnsortedRoundRobinTlbCache<4>,
    #[cfg(not(target_feature = "avx2"))]
    #[cfg(not(target_feature = "bmi1"))]
    data_tlb: UnsortedRoundRobinTlbCache<8>,

    #[cfg(target_feature = "avx2")]
    #[cfg(target_feature = "bmi1")]
    unified_tlb: FastTlbCache64,
    #[cfg(target_feature = "avx2")]
    #[cfg(target_feature = "bmi1")]
    instruction_tlb: FastTlbCache4,
    #[cfg(target_feature = "avx2")]
    #[cfg(target_feature = "bmi1")]
    data_tlb: FastTlbCache8,
}

impl Ppc405Tlb {
    pub fn new() -> Self {
        #[cfg(target_feature = "avx2")]
        #[cfg(target_feature = "bmi1")]
        {
            Self {
                inst_relocate_enabled: false,
                data_relocate_enabled: false,
                current_pid: 0,
                tlb_data: [TlbRecord::default(); TOTAL_TLB_CAPACITY],
                unified_tlb: FastTlbCache64::new(0),
                instruction_tlb: FastTlbCache4::new(64),
                data_tlb: FastTlbCache8::new(68),
            }
        }

        #[cfg(not(target_feature = "avx2"))]
        #[cfg(not(target_feature = "bmi1"))]
        {
            Self {
                // translation disabled on reset
                inst_relocate_enabled: false,
                data_relocate_enabled: false,
                current_pid: 0,

                tlb_data: [TlbRecord::default(); TOTAL_TLB_CAPACITY],

                unified_tlb: SortedTlbCache::new(0),
                instruction_tlb: UnsortedRoundRobinTlbCache::new(64),
                data_tlb: UnsortedRoundRobinTlbCache::new(68),
            }
        }
    }

    /// search the instruction tlb for a matching entry
    fn instruction_tlb_lookup(&mut self, v_addr: u64) -> Option<&TlbRecord> {
        let v_addr_32 = v_addr as u32;

        // search instruction tlb
        if let Some(idx) = self.instruction_tlb.search(v_addr_32) {
            return Some(&self.tlb_data[idx]);
        }

        // we didn't find it in the itlb, check the utlb next
        if let Some(idx) = self.unified_tlb.search(v_addr_32) {
            let replacement = self.tlb_data[idx];

            let tlb_data_idx = self.instruction_tlb.replace(
                replacement.virtual_page_start as u32,
                replacement.virtual_page_end as u32,
            );

            self.tlb_data[tlb_data_idx] = replacement;

            return Some(&self.tlb_data[tlb_data_idx]);
        }

        // if we get here this is a ITLB miss
        None
    }

    /// search the data tlb for a matching entry
    fn data_tlb_lookup(&mut self, v_addr: u64) -> Option<&TlbRecord> {
        let v_addr_32 = v_addr as u32;

        // search data tlb
        if let Some(idx) = self.data_tlb.search(v_addr_32) {
            return Some(&self.tlb_data[idx]);
        }

        // we didn't find it in the dtlb, check the utlb next
        if let Some(idx) = self.unified_tlb.search(v_addr_32) {
            let replacement = self.tlb_data[idx];

            let tlb_data_idx = self.data_tlb.replace(
                replacement.virtual_page_start as u32,
                replacement.virtual_page_end as u32,
            );

            self.tlb_data[tlb_data_idx] = replacement;

            return Some(&self.tlb_data[tlb_data_idx]);
        }

        // if we get here this is a DTLB miss
        None
    }

    /// Implements the behaviour of the 'tlbwe' instruction for the high portion
    pub fn tlbwe_high(&mut self, idx: usize, data: u32) -> Result<(), TlbTranslateError> {
        debug_assert!(idx < UNIFIED_TLB_CAPACITY);

        let record = &mut self.tlb_data[idx];

        record.write_high(data, self.current_pid);

        self.unified_tlb.replace_index(
            idx,
            record.virtual_page_start as u32,
            record.virtual_page_end as u32,
        );

        Ok(())
    }

    /// Implements the behaviour of the 'tlbwe' instruction for the low portion
    pub fn tlbwe_low(&mut self, idx: usize, data: u32) -> Result<(), TlbTranslateError> {
        debug_assert!(idx < UNIFIED_TLB_CAPACITY);

        self.tlb_data[idx].write_low(data);
        // modifying the low (data) portion of the record doesn't affect
        // our internal ordering for the high (tag) part of the record
        Ok(())
    }

    /// TODO: look at expected behavior for out of bounds
    /// Returns the tag portion of the tlb record at the specified index
    pub fn tlbre_high(&self, idx: usize) -> Result<u32, UnknownError> {
        debug_assert!(idx < UNIFIED_TLB_CAPACITY);
        Ok(self.tlb_data[idx].raw_hi)
    }

    /// Returns the data portion of the tlb record at the specified index
    pub fn tlbre_low(&self, idx: usize) -> Result<u32, UnknownError> {
        debug_assert!(idx < UNIFIED_TLB_CAPACITY);
        Ok(self.tlb_data[idx].raw_lo)
    }

    /// Invalidate the contents of the shadow TLBs (ITLB, DTLB)
    ///
    /// This should occur any time one of the following conditions is met:
    /// 1. isync instruction
    /// 2. processor context switch (all interrupts as well as return from interrupts)
    /// 3. sc instruction
    pub fn invalidate_shadow_tlb(&mut self) {
        let mut i = UNIFIED_TLB_CAPACITY;

        while i < TOTAL_TLB_CAPACITY {
            self.tlb_data[i].valid = false;
            i += 1;
        }
    }
}

use crate::core_event_controller::Event;

impl TlbImpl for Ppc405Tlb {
    fn init(&mut self, _cpu: &mut dyn CpuBackend) -> Result<(), UnknownError> {
        // TODO: set a MSR hook to catch when MSR[IR, DR] get set/unset
        // TODO: set a PID register hook to update the current pid

        Ok(())
    }

    fn invalidate_all(&mut self, flags: u32) -> Result<(), UnknownError> {
        if flags & PPC405_TLB_L2 != 0 {
            for record in &mut self.tlb_data {
                record.valid = false;
                // clear v bit in raw value
                record.raw_hi &= TLBHI_V_MASK;
            }
        }

        if flags & PPC405_TLB_L1 != 0 {
            self.invalidate_shadow_tlb();
        }
        Ok(())
    }

    fn invalidate(&mut self, idx: usize) -> Result<(), UnknownError> {
        self.tlb_data[idx].valid = false;
        self.tlb_data[idx].raw_hi &= TLBHI_V_MASK;
        Ok(())
    }

    fn translate_va(
        &mut self,
        v_address: u64,
        access_type: MemoryOperation,
        memory_type: MemoryType,
        _processor: &mut TlbProcessor,
    ) -> TlbTranslateResult {
        match memory_type {
            MemoryType::Data => {
                if self.data_relocate_enabled {
                    let current_pid = self.current_pid;
                    if let Some(record) = self.data_tlb_lookup(v_address) {
                        if (record.pid != 0 && record.pid != current_pid)
                            || (access_type == MemoryOperation::Write && !record.write_enabled)
                        {
                            Err(TlbTranslateError::Exception(Event::DataStorage.into()))
                        } else {
                            Ok(record.translate_v_addr(v_address))
                        }
                    } else {
                        Err(TlbTranslateError::Exception(Event::DataTLBError.into()))
                    }
                } else {
                    Ok(v_address)
                }
            }
            MemoryType::Code => {
                if self.inst_relocate_enabled {
                    let current_pid = self.current_pid;
                    if let Some(record) = self.instruction_tlb_lookup(v_address) {
                        if (record.pid == 0 || record.pid == current_pid) && record.exec_enabled {
                            Ok(record.translate_v_addr(v_address))
                        } else {
                            Err(TlbTranslateError::Exception(
                                Event::InstructionStorage.into(),
                            ))
                        }
                    } else {
                        Err(TlbTranslateError::Exception(
                            Event::InstructionTLBError.into(),
                        ))
                    }
                } else {
                    Ok(v_address)
                }
            }
        }
    }

    fn tlb_write(&mut self, idx: usize, data: u64, flags: u32) -> Result<(), TlbTranslateError> {
        match flags {
            PPC405_TLB_HI => self.tlbwe_high(idx, data as u32),
            PPC405_TLB_LO => self.tlbwe_low(idx, data as u32),
            _ => {
                warn!("invalid tlb write flags: {flags}");
                Ok(())
            }
        }
    }

    fn tlb_read(&self, idx: usize, flags: u32) -> Result<u64, TlbTranslateError> {
        match flags {
            PPC405_TLB_HI => Ok(self.tlbre_high(idx).unwrap() as u64),
            PPC405_TLB_LO => Ok(self.tlbre_low(idx).unwrap() as u64),
            _ => {
                warn!("invalid tlb read flags: {flags}");
                Ok(0)
            }
        }
    }

    fn enable_data_address_translation(&mut self) -> Result<(), UnknownError> {
        self.data_relocate_enabled = true;
        Ok(())
    }

    fn disable_data_address_translation(&mut self) -> Result<(), UnknownError> {
        self.data_relocate_enabled = false;
        Ok(())
    }

    fn enable_code_address_translation(&mut self) -> Result<(), UnknownError> {
        self.inst_relocate_enabled = true;
        Ok(())
    }

    fn disable_code_address_translation(&mut self) -> Result<(), UnknownError> {
        self.inst_relocate_enabled = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KB: u64 = 1024;

    const EPN_MASK: u32 = 0b11_1111_1111_1111_1111_1111;
    const RPN_MASK: u32 = 0b11_1111_1111_1111_1111_1111;

    /// helper function to generate a valid tlb tag
    fn util_generate_tag(vpn: u64, size: u8) -> u32 {
        ((vpn >> 10) as u32 & EPN_MASK) | ((size as u32 & 0b111) << 22) | !TLBHI_V_MASK
    }

    /// helper function to generate a tlb data record
    fn util_generate_data(rpn: u64, exec: bool, write: bool) -> u32 {
        let mut temp = (rpn >> 10) as u32 & RPN_MASK;

        if exec {
            temp |= 1 << 22;
        }

        if write {
            temp |= 1 << 23;
        }

        temp
    }

    #[test]
    fn test_tlb_record_format() {
        let mut record = TlbRecord::default();

        record.write_high(util_generate_tag(0xfffffc00, 0b010), 1);
        record.write_low(util_generate_data(0xABC00, false, true));

        // check high fields
        assert!(record.valid);
        assert_eq!(record.virtual_page_start, 0xfffffc00);
        //0b10101111111111111111111111
        assert_eq!(record.virtual_page_end, 0xfffffc00 + (16 * KB));

        // check low fields
        assert_eq!(record.physical_page_base, 0xABC00);
        assert!(!record.exec_enabled);
        assert!(record.write_enabled);
    }

    #[test]
    /// tests that the tlbwe implementations do what is expected
    fn test_tlb_read_write() {
        let mut tlb = Ppc405Tlb::new();

        let high1 = util_generate_tag(0, 0b001);
        let high2 = util_generate_tag(8 * KB, 0);

        let low1 = util_generate_data(0x800, true, false);
        let low2 = util_generate_data(0, false, true);

        tlb.current_pid = 20;
        tlb.tlbwe_high(0, high1).unwrap();
        tlb.tlbwe_low(0, low1).unwrap();

        tlb.current_pid = 255;
        tlb.tlbwe_high(1, high2).unwrap();
        tlb.tlbwe_low(1, low2).unwrap();

        let entry = &tlb.tlb_data[0];
        assert_eq!(entry.pid, 20);
        assert_eq!(entry.raw_hi, high1);
        assert_eq!(entry.valid, true);
        assert_eq!(entry.virtual_page_start, 0);
        assert_eq!(entry.virtual_page_end, 4 * KB);
        assert_eq!(entry.raw_lo, low1);
        assert_eq!(entry.physical_page_base, 0x800);
        assert_eq!(entry.physical_page_mask, 0xFFF);

        let entry = &tlb.tlb_data[1];
        assert_eq!(entry.pid, 255);
        assert_eq!(entry.raw_hi, high2);
        assert_eq!(entry.valid, true);
        assert_eq!(entry.virtual_page_start, 8 * KB);
        assert_eq!(entry.virtual_page_end, 9 * KB);
        assert_eq!(entry.raw_lo, low2);
        assert_eq!(entry.physical_page_base, 0);
        assert_eq!(entry.physical_page_mask, 0x3FF);
    }

    #[test]
    fn test_searching() {
        let mut tlb = Ppc405Tlb::new();

        tlb.current_pid = 0;
        tlb.tlbwe_high(0, util_generate_tag(0, 0)).unwrap();

        tlb.current_pid = 1;
        tlb.tlbwe_high(1, util_generate_tag(KB, 0)).unwrap();

        tlb.current_pid = 2;
        tlb.tlbwe_high(2, util_generate_tag(3 * KB, 0)).unwrap();

        assert!(tlb.instruction_tlb_lookup(4 * KB).is_none());
        assert!(tlb.instruction_tlb_lookup(4 * KB + 1).is_none());
        assert!(tlb.instruction_tlb_lookup(2 * KB).is_none());
        assert!(tlb.instruction_tlb_lookup(2 * KB + 512).is_none());

        assert_eq!(tlb.instruction_tlb_lookup(0).unwrap().pid, 0);
        assert_eq!(tlb.instruction_tlb_lookup(KB / 2).unwrap().pid, 0);
        assert_eq!(tlb.instruction_tlb_lookup(KB + KB / 2).unwrap().pid, 1);
        assert_eq!(tlb.instruction_tlb_lookup(3 * KB + KB / 2).unwrap().pid, 2);
    }

    #[test]
    /// tests that the different cache layers get exercised properly
    fn test_shadow_tlbs() {
        let mut tlb = Ppc405Tlb::new();

        tlb.current_pid = 0;
        tlb.tlbwe_high(0, util_generate_tag(0, 0)).unwrap();

        tlb.current_pid = 1;
        tlb.tlbwe_high(1, util_generate_tag(KB, 0)).unwrap();

        tlb.current_pid = 2;
        tlb.tlbwe_high(2, util_generate_tag(3 * KB, 0)).unwrap();

        for id in &tlb.instruction_tlb.pages {
            assert!(id.address_range.is_empty());
        }

        // do an ITLB lookup
        let result = tlb.instruction_tlb_lookup(0).unwrap();
        assert_eq!(result.pid, 0);
        assert_eq!(result.virtual_page_start, 0);
        assert_eq!(result.virtual_page_end, KB);

        // assert that this result was filled into the shadow tlb
        assert_eq!(tlb.instruction_tlb.pages[0].address_range.start, 0);
        assert_eq!(tlb.instruction_tlb.pages[0].address_range.end, KB as u32);
        // check that the rest of the shadow tlb is empty
        for id in &tlb.instruction_tlb.pages[1..] {
            assert!(id.address_range.is_empty());
        }

        // do a DTLB lookup
        let result = tlb.data_tlb_lookup(0).unwrap();
        assert_eq!(result.pid, 0);
        assert_eq!(result.virtual_page_start, 0);
        assert_eq!(result.virtual_page_end, KB);

        // assert that instruction tlb is untouched
        assert_eq!(tlb.instruction_tlb.pages[0].address_range.start, 0);
        assert_eq!(tlb.instruction_tlb.pages[0].address_range.end, KB as u32);
        for id in &tlb.instruction_tlb.pages[1..] {
            assert!(id.address_range.is_empty());
        }
        // assert that data tlb was filled
        assert_eq!(tlb.data_tlb.pages[0].address_range.start, 0);
        assert_eq!(tlb.data_tlb.pages[0].address_range.end, KB as u32);
        for id in &tlb.data_tlb.pages[1..] {
            assert!(id.address_range.is_empty());
        }
    }

    #[test]
    /// Tests the round robin shadow tlb replacement
    fn test_shadow_tlb_replacement() {
        let mut tlb = Ppc405Tlb::new();

        tlb.current_pid = 0;
        tlb.tlbwe_high(0, util_generate_tag(0, 0)).unwrap();
        tlb.current_pid = 1;
        tlb.tlbwe_high(1, util_generate_tag(KB, 0)).unwrap();
        tlb.current_pid = 2;
        tlb.tlbwe_high(2, util_generate_tag(2 * KB, 0)).unwrap();
        tlb.current_pid = 3;
        tlb.tlbwe_high(3, util_generate_tag(3 * KB, 0)).unwrap();
        tlb.current_pid = 4;
        tlb.tlbwe_high(4, util_generate_tag(4 * KB, 0)).unwrap();

        tlb.instruction_tlb_lookup(0).unwrap();
        assert_eq!(tlb.instruction_tlb.pages[0].address_range.start, 0);
        assert_eq!(tlb.instruction_tlb.pages[0].address_range.end, KB as u32);
        for id in &tlb.instruction_tlb.pages[1..] {
            assert!(id.address_range.is_empty());
        }

        tlb.instruction_tlb_lookup(KB).unwrap();
        assert_eq!(tlb.instruction_tlb.pages[1].address_range.start, KB as u32);
        assert_eq!(
            tlb.instruction_tlb.pages[1].address_range.end,
            2 * KB as u32
        );
        for id in &tlb.instruction_tlb.pages[2..] {
            assert!(id.address_range.is_empty());
        }

        tlb.instruction_tlb_lookup(2 * KB).unwrap();
        assert_eq!(
            tlb.instruction_tlb.pages[2].address_range.start,
            2 * KB as u32
        );
        assert_eq!(
            tlb.instruction_tlb.pages[2].address_range.end,
            3 * KB as u32
        );
        for id in &tlb.instruction_tlb.pages[3..] {
            assert!(id.address_range.is_empty());
        }

        tlb.instruction_tlb_lookup(3 * KB).unwrap();
        assert_eq!(
            tlb.instruction_tlb.pages[3].address_range.start,
            3 * KB as u32
        );
        assert_eq!(
            tlb.instruction_tlb.pages[3].address_range.end,
            4 * KB as u32
        );

        tlb.instruction_tlb_lookup(4 * KB).unwrap();
        assert_eq!(
            tlb.instruction_tlb.pages[0].address_range.start,
            4 * KB as u32
        );
        assert_eq!(
            tlb.instruction_tlb.pages[0].address_range.end,
            5 * KB as u32
        );
    }

    #[test]
    /// tests that addresses get translated properly
    fn test_address_translation() {
        let mut record1 = TlbRecord::default();
        // virtual page start 0x8000_0000 with size 1K
        record1.write_high(util_generate_tag(0x8000_0000, 0b000), 0);
        // physical page start 0x10_0000
        record1.write_low(util_generate_data(0x10_0000, true, true));

        // valid addresses are [0x8000_0000, 0x8000_0400)
        // should get mapped to [0x10_0000, 0x10_0400)

        assert_eq!(record1.translate_v_addr(0x8000_0000), 0x10_0000);
        assert_eq!(record1.translate_v_addr(0x8000_0050), 0x10_0050);
        assert_eq!(record1.translate_v_addr(0x8000_00FF), 0x10_00FF);

        let mut record2 = TlbRecord::default();

        // virtual page [0xA000_0000, 0xA100_0000)
        record2.write_high(util_generate_tag(0xA000_0000, 0b111), 0);
        // physical page [0x4000_0000, 0x4100_0000)
        record2.write_low(util_generate_data(0x4000_0000, true, true));

        assert_eq!(record2.translate_v_addr(0xA000_0000), 0x4000_0000);
        assert_eq!(record2.translate_v_addr(0xA000_5000), 0x4000_5000);
        assert_eq!(record2.translate_v_addr(0xA010_0000), 0x4010_0000);
        assert_eq!(record2.translate_v_addr(0xA0FF_FFFF), 0x40FF_FFFF);
    }
}
