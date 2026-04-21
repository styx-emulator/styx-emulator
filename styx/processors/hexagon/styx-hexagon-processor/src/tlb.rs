// SPDX-License-Identifier: BSD-2-Clause
use arbitrary_int::*;
use bitbybit::bitfield;
use std::collections::BTreeMap;
use styx_core::{
    arch::hexagon::{register_fields::Ssr, HexagonRegister},
    cpu::{CpuBackendExt, HexagonInterruptCause, HexagonInterruptType},
    errors::UnknownError,
    memory::{
        MemoryOperation, MemoryType, TlbImpl, TlbProcessor, TlbTranslateError, TlbTranslateResult,
    },
    prelude::{
        log::{error, info, trace},
        Context,
    },
};

use crate::exception::{ssr_set_cause, update_badva};

// See https://github.com/quic/qemu/blob/hex-next/target/hexagon/cpu.h.
pub const MAX_TLB_ENTRIES: usize = 1024;

#[bitfield(u32, debug)]
pub struct TLBProbeField {
    #[bits(0..=19, rw)]
    vpn: u20,
    #[bits(20..=26, rw)]
    asid: u7,
}

/// Page table entries
#[bitfield(u64, debug)]
pub struct Pte {
    /// Physical page descriptor
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

    /// Hexagon TLB translation.
    ///
    /// The crux of the logic for this function is implemented in
    /// https://github.com/quic/qemu/blob/bcain/tlb_obj/hw/hexagon/hexagon_tlb.c.
    ///
    /// It is worth noting that the default address translation algorithm for QUIC's QEMU fork,
    /// located at https://github.com/quic/qemu/blob/hex-next/target/hexagon/hex_mmu.c, does not
    /// align with the page table entries that are inserted and are present in tested Hexagon
    /// firmware.
    ///
    /// Address translation in Hexagon, as such, works as follows.
    ///
    /// At least in testing, it appears that the page size is 4K,
    /// which translates to having the lowest 12 bits indicate the offset. However,
    /// when translating an address in Hexagon, the page translation algorithm looks at
    /// the number of trailing zeroes to determine the actual page number + offset
    /// masks.
    ///
    /// To make this more clear, let's look at an example.
    ///
    /// Some ground rules: there are three page table entries, all valid, all
    /// with the correct permissions. The parts of the page table entry we care about are the
    /// PPD (physical page descriptor) and the VPN (the virtual page number).
    ///
    /// - Entry 0: VPN is 0x89104, PPD is 0x112202
    /// - Entry 1: VPN is 0x1d25c, PPD is 0x022308
    /// - Entry 2: VPN is 0x1d21c, PPD is 0x03a490
    ///
    /// First, we receive a virtual address. For the sake of example, let's say this
    /// is 0x1d23c210. The way we match the VA to PA is by iterating through the page table
    /// entries, finding a mask based on the number of trailing zeroes in the PPD, and then
    /// matching the input VA to the VPN based on this mask.
    ///
    /// **Iteration 0:** PPD is 0x112202. This has exactly 1 trailing zero, which means
    /// in our mask table, this corresponds to mask 0x3fff, which is 14 bits for the offset.
    /// Our mask for the "page number" is the inverse of this, 0xffffc000. There is a chance that
    /// some of the bits in the actual VPN entry may get cleared by this, which is intentional.
    ///
    /// The idea with the VPN is we shift left by 12, yielding 0x89104000, then mask with
    /// 0xffffc000, yielding the same. Now, we do the same mask for the VA, yielding
    /// 0x1d23c000 (itself).  Now, comparing the two masked values, they don't match, and
    /// we move on.
    ///
    /// **Iteration 1**: PPD is 0x022308. There are *three* trailing zeroes, so we choose mask
    /// 0xffff. Now, we wish to mask the (shifted left) VPN and VA with the inverse, which is 0xffff0000.
    /// The VA masked is 0x1d230000. The VPN shfited left is 0x1d25c000, and masked it is 0x1d250000.
    /// We see that 0x1d230000 != 0x1d250000, so this isn't a match. Onwards.
    ///
    /// **Iteration 3:** PPD is 0x03a490. As before, we have *three* trailing zeroes, so our mask is
    /// 0x3ffff and our inverse is 0xfffc0000. Now, the VPN shifted is 0x1d21c000, with the mask, it's 0x
    /// 0x1d200000. Our VA masked is 0x1d20000 as well. It's a match!
    ///
    /// Now we can go ahead and translate our PA. We obtain our offset with the original mask:
    /// 0x1d23c210 & 0x3ffff = 0x3c210.
    ///
    /// To get the "base" from our PPD, we must shift right by one and then shift left by 12
    /// (0x03a490 >> 1) << 12 = 0x1d248000. Finally, we add our offset to this base:
    /// 0x1d248000 + 0x3c210 = 0x1d284210.
    ///
    /// And that's our PA.
    ///
    /// TODO: figure out the 34 and 36-bit masks
    /// TODO: permissions checks, ASID checks
    fn translate_va(
        &mut self,
        virt_addr: u64,
        access_type: MemoryOperation,
        memory_type: MemoryType,
        processor: &mut TlbProcessor,
    ) -> TlbTranslateResult {
        let page_number_mask = !((1 << PAGE_SIZE_BITS) - 1);
        let vpn_page_masked = virt_addr & page_number_mask;
        let ssr = Ssr::new_with_raw_value(
            processor
                .cpu
                .read_register::<u32>(HexagonRegister::Ssr)
                .with_context(|| {
                    "couldn't read SSR register for ASID during address translation"
                })?,
        );

        if !self.enable_translation {
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
                if !ent.v() || (ent.asid() != ssr.asid() && !ent.g()) {
                    trace!("skipping {ent:x?}");
                    continue;
                }

                // Permission checking doesn't happen in monitor mode.
                // NOTE: not clear if permission checking happens in guest mode.
                // Need to relearn some stuff about hypervisors.
                //
                // See hexagon_cpu_mmu_index function in QEMU (cpu.c)
                // See hex_tlb_entry_get_perm in QEMU (hexagon_tlb.c/hexagon_mmu.c)
                if !ssr.monitor_mode() {
                    if matches!(memory_type, MemoryType::Code) && !ent.x() {
                        continue;
                    }

                    match access_type {
                        MemoryOperation::Read if !ent.r() => {
                            continue;
                        }
                        MemoryOperation::Write if !ent.w() => {
                            continue;
                        }
                        _ => {}
                    }
                }

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

            error!(
                "couldn't translate {virt_addr:x} at pc {:x?}",
                processor.cpu.pc()
            );

            let err = if matches!(memory_type, MemoryType::Code)
                && matches!(access_type, MemoryOperation::Read)
            {
                update_badva(processor, virt_addr)?;

                if (virt_addr as u64 & page_number_mask) == 0 {
                    ssr_set_cause(processor, HexagonInterruptCause::TlbmissxCauseNextpage)?;
                } else if access_type == MemoryOperation::Write {
                    ssr_set_cause(processor, HexagonInterruptCause::TlbmissxCauseNormal)?;
                }

                Err(TlbTranslateError::Exception(
                    HexagonInterruptType::TlbMissX as i32,
                ))
            } else if matches!(memory_type, MemoryType::Data) {
                update_badva(processor, virt_addr)?;

                if access_type == MemoryOperation::Read {
                    ssr_set_cause(processor, HexagonInterruptCause::TlbmissrwCauseRead)?;
                } else if access_type == MemoryOperation::Write {
                    ssr_set_cause(processor, HexagonInterruptCause::TlbmissrwCauseWrite)?;
                }

                Err(TlbTranslateError::Exception(
                    HexagonInterruptType::TlbMissRw as i32,
                ))
            } else {
                Err(TlbTranslateError::Other(UnknownError::msg(
                    "couldn't translate tlb and not a page fault",
                )))
            };

            err
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
        if idx >= MAX_TLB_ENTRIES {
            Err(TlbTranslateError::Other(UnknownError::msg(format!(
                "specified tlb entry at index {idx} doesn't exist, cannot read"
            ))))
        } else {
            Ok(self.entries[idx].raw_value())
        }
    }

    /// This is only used for ASID in our implementation
    fn invalidate_all(&mut self, flags: u32) -> Result<(), UnknownError> {
        todo!()
    }

    fn invalidate(&mut self, idx: usize) -> Result<(), UnknownError> {
        if idx >= MAX_TLB_ENTRIES {
            Err(UnknownError::msg(format!(
                "specified tlb entry at index {idx} doesn't exist, cannot invalidate"
            )))
        } else {
            self.entries[idx].set_v(false);
            Ok(())
        }
    }

    fn tlb_search(&self, input: u64, flags: u32) -> Option<u64> {
        // Match based on TLBProbeField
        if flags == 0 {
            let probe_field = TLBProbeField::new_with_raw_value(input as u32);

            trace!(
                "tlb search with asid {:x} vpn {:x}",
                probe_field.asid(),
                probe_field.vpn()
            );

            // match on VPN and ASID
            for (i, ent) in self.entries.iter().enumerate() {
                trace!(
                    "probe_field vpn {:x} entry vpn {:x}",
                    probe_field.vpn(),
                    ent.vpn()
                );
                if ent.asid() == probe_field.asid() && ent.v() {
                    let ent_vpn_shifted = ent.vpn().as_u64() << PAGE_SIZE_BITS;
                    let probe_field_vpn_shifted = probe_field.vpn().as_u64() << PAGE_SIZE_BITS;

                    let page_type = Self::get_entry_page_type(ent);
                    let page_mask = PAGE_MASK[page_type];

                    let probe_field_vpn_page_masked = probe_field_vpn_shifted & !page_mask;
                    trace!("probe_field_vpn_page_masked {probe_field_vpn_page_masked:x} ent_vpn_shfited {ent_vpn_shifted:x}");

                    if probe_field_vpn_page_masked == ent_vpn_shifted {
                        trace!("tlb search got entry {:x?}", ent);
                        return Some(i as u64);
                    }
                }
            }
        } else if flags == 1 {
            // TLB match, input is a TLB entry
            let input_entry = Pte::new_with_raw_value(input);
            let valid = input_entry.v();
            if !valid {
                return None;
            }

            for (i, entry) in self.entries.iter().enumerate() {
                if !entry.v() {
                    continue;
                }

                let page_type = Self::get_entry_page_type(entry);
                let page_mask = PAGE_MASK[page_type];

                let input_va = (u64::from(input_entry.vpn()) << PAGE_SIZE_BITS) & !page_mask;
                let va = (u64::from(entry.vpn()) << PAGE_SIZE_BITS) & !page_mask;

                let sz = 1 << Self::get_entry_page_num_bits(entry);
                let input_sz = 1 << Self::get_entry_page_num_bits(&input_entry);

                if (input_va < va && va < (input_va + input_sz))
                    || (va < input_va && input_va < (va + sz))
                {
                    if input_entry.asid() == entry.asid() {
                        return Some(i as u64);
                    }
                }
            }
        }

        return None;
    }
}
