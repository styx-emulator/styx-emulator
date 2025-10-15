// SPDX-License-Identifier: BSD-2-Clause
use arbitrary_int::*;
use bitbybit::bitfield;
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
    #[bit(27, rw)]
    pte_hsv39: bool,
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
    enable_code_translation: bool,
    enable_data_translation: bool,
}

const PAGE_SIZE_BITS: u64 = 12;
// From https://github.com/quic/qemu/blob/3921c6eed6bd7c670eff633fe829e18607125969/hw/hexagon/hexagon_tlb.c
const PAGE_MASK: [u64; 13] = [
    0x0fff,
    0x3fff,
    0xffff,
    0x3ffff,
    0xfffff,
    0x3fffff,
    0xffffff,
    0x3ffffff,
    0xfffffff,
    0x3fffffff,
    0xffffffff,
    0x3ffffffff,
    0xfffffffff,
];

impl HexagonTlb {
    pub fn new() -> Self {
        Self {
            enable_code_translation: false,
            enable_data_translation: false,
            entries: [Pte::new_with_raw_value(0); MAX_TLB_ENTRIES],
        }
    }

    // https://github.com/quic/qemu/blob/3921c6eed6bd7c670eff633fe829e18607125969/hw/hexagon/hexagon_tlb.c#L100
    fn get_entry_page_type(ent: &Pte) -> usize {
        ent.ppd().trailing_zeros() as usize // + (ent.pte_hsv39() as usize * 4)
    }

    // https://github.com/quic/qemu/blob/3921c6eed6bd7c670eff633fe829e18607125969/hw/hexagon/hexagon_tlb.c#L100
    fn get_entry_page_num_bits(ent: &Pte) -> u64 {
        PAGE_SIZE_BITS + (2 * Self::get_entry_page_type(ent) as u64)
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
        if !self.enable_code_translation && !self.enable_data_translation {
            Ok(virt_addr)
        } else {
            let virt_addr = virt_addr as u32;

            for ent in &self.entries {
                if !ent.v() {
                    continue;
                }

                // It appears that tlb entries have varying page sizes that are encoded

                let page_type = Self::get_entry_page_type(ent);
                let vpn_shift = PAGE_SIZE_BITS;

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

                    trace!("va {virt_addr:x} ppd_mask {ppd_mask:x} pa {pa:x}");
                    return Ok(pa);
                }
            }

            error!("couldn't translate {virt_addr:x}");
            //
            Err(TlbTranslateError::Other(UnknownError::msg("tlb failed")))
        }
    }

    fn tlb_write(&mut self, idx: usize, data: u64, flags: u32) -> Result<(), TlbTranslateError> {
        let pte = Pte::new_with_raw_value(data);
        self.entries[idx] = pte;
        info!(
            "tlb {data:x} inserted at {idx} was {pte:x?} PA 0x{:x} VA 0x{:x} page size bits {:?}",
            (pte.ppd() >> 1).overflowing_shl(12).0,
            pte.vpn().overflowing_shl(12).0,
            Self::get_entry_page_num_bits(&pte)
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
