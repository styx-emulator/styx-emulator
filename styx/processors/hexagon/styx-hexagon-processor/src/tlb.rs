// SPDX-License-Identifier: BSD-2-Clause
use arbitrary_int::*;
use bitbybit::bitfield;
use std::collections::BTreeMap;
use styx_core::{
    errors::UnknownError,
    memory::{
        MemoryOperation, MemoryType, TlbImpl, TlbProcessor, TlbTranslateError, TlbTranslateResult,
    },
    prelude::log::{error, info, trace},
};

// See https://github.com/quic/qemu/blob/hex-next/target/hexagon/cpu.h.
const MAX_TLB_ENTRIES: usize = 1024;

#[bitfield(u64, debug)]
struct Pte {
    // Physical page descriptor
    #[bits(0..=23, rw)]
    ppd: u24,
    #[bits(24..=27, rw)]
    c: u4,
    #[bit(28, rw)]
    u: bool,
    #[bit(29, rw)]
    r: bool,
    #[bit(30, rw)]
    w: bool,
    #[bit(31, rw)]
    x: bool,
    #[bits(32..=51, rw)]
    vpn: u20,
    #[bits(52..=58, rw)]
    asid: u7,
    #[bit(59, rw)]
    atr0: bool,
    #[bit(60, rw)]
    atr1: bool,
    #[bit(61, rw)]
    pa35: bool,
    #[bit(62, rw)]
    g: bool,
    #[bit(63, rw)]
    v: bool,
}

pub struct HexagonTlb {
    entries: [Pte; MAX_TLB_ENTRIES],
    // mapping of u64 entry to u64 entry
    cache: BTreeMap<u64, u64>,
    enable_code_translation: bool,
    enable_data_translation: bool,
}

impl HexagonTlb {
    pub fn new() -> Self {
        Self {
            enable_code_translation: false,
            enable_data_translation: false,
            entries: [Pte::new_with_raw_value(0); MAX_TLB_ENTRIES],
            cache: BTreeMap::new(),
        }
    }
}

impl TlbImpl for HexagonTlb {
    fn enable_data_address_translation(&mut self) -> Result<(), UnknownError> {
        self.enable_data_translation = true;
        Ok(())
    }

    fn disable_data_address_translation(&mut self) -> Result<(), UnknownError> {
        self.enable_data_translation = false;
        Ok(())
    }

    fn enable_code_address_translation(&mut self) -> Result<(), UnknownError> {
        self.enable_code_translation = true;
        Ok(())
    }

    fn disable_code_address_translation(&mut self) -> Result<(), UnknownError> {
        self.enable_code_translation = false;
        Ok(())
    }

    fn translate_va(
        &mut self,
        virt_addr: u64,
        access_type: MemoryOperation,
        memory_type: MemoryType,
        processor: &mut TlbProcessor,
    ) -> TlbTranslateResult {
        let page_number_mask = !((1 << PAGE_SIZE_BITS) - 1);
        let vpn_page_masked = virt_addr & page_number_mask;
        if !self.enable_code_translation && !self.enable_data_translation {
            // Physical memory mode
            Ok(virt_addr)
        } else if let Some(&ppn_addr) = self.cache.get(&vpn_page_masked) {
            let va_off_mask = (1 << PAGE_SIZE_BITS) - 1;
            let p_addr = ppn_addr + (virt_addr & va_off_mask);
            trace!("fast path: translated {virt_addr:x} to {p_addr:x}");
            Ok(p_addr)
        } else {
            let virt_addr = virt_addr as u32;
            // 4k page
            let vpn = virt_addr >> 16;
            let offset = virt_addr & 0xffff;

            for ent in &self.entries {
                if !ent.v() {
                    continue;
                }

                let ppd = u64::from((ent.ppd() >> 5)).overflowing_shl(16).0;
                let ent_vpn = u32::from(ent.vpn()) >> 4;

                let page_type = Self::get_entry_page_type(ent);

                let va_vpn = (virt_addr as u64) & !PAGE_MASK[page_type];
                let va_offset = virt_addr as u64 & PAGE_MASK[page_type];

                let ent_vpn = u64::from(ent.vpn()) << PAGE_SIZE_BITS;

                trace!("ent vpn {ent_vpn:x} real vpn {va_vpn:x} va_offset {va_offset:x}",);
                if va_vpn == ent_vpn {
                    let ppd_mask = u64::from(ent.ppd() >> 1)
                        .overflowing_shl(PAGE_SIZE_BITS as u32)
                        .0
                        & !PAGE_MASK[page_type];
                    let pa = ppd_mask + va_offset;

                    // TODO: invalidate the cache
                    self.cache.insert(vpn_page_masked, pa & page_number_mask);

                    trace!("va {virt_addr:x} ppd_mask {ppd_mask:x} pa {pa:x}");
                    return Ok(pa);
                }
            }

            error!("couldn't translate {virt_addr:x}");
            // lol what
            Err(TlbTranslateError::Other(UnknownError::msg("tlb failed")))
        }
    }

    fn tlb_write(&mut self, idx: usize, data: u64, flags: u32) -> Result<(), TlbTranslateError> {
        let pte = Pte::new_with_raw_value(data);
        self.entries[idx] = pte;
        info!(
            "tlb inserted at {idx} was {pte:x?} PA 0x{:x} VA 0x{:x}",
            (pte.ppd() >> 1).overflowing_shl(12).0,
            pte.vpn().overflowing_shl(12).0
        );
        Ok(())
    }

    fn tlb_read(&self, idx: usize, flags: u32) -> Result<u64, TlbTranslateError> {
        todo!()
    }

    /// This is only used for ASID in our implementation
    fn invalidate_all(&mut self, flags: u32) -> Result<(), UnknownError> {
        todo!()
    }

    fn invalidate(&mut self, idx: usize) -> Result<(), UnknownError> {
        todo!()
    }
}
