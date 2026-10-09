// SPDX-License-Identifier: BSD-2-Clause
use arbitrary_int::*;
use bitbybit::bitfield;
use std::collections::BTreeMap;
use styx_core::{
    arch::hexagon::{register_fields::Ssr, HexagonRegister},
    cpu::{CpuBackendExt, HexagonInterruptCause, HexagonInterruptType},
    errors::{anyhow::anyhow, UnknownError},
    memory::{
        MemoryOperation, MemoryType, TlbImpl, TlbProcessor, TlbTranslateError, TlbTranslateResult,
    },
    prelude::{
        log::{debug, error, info, trace},
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

#[derive(Hash, Ord, Eq, PartialEq, PartialOrd)]
pub struct HexagonTlbCacheEntry {
    vpn_page_masked: u64,
    asid: u7,
}

pub struct HexagonTlb {
    entries: [Pte; MAX_TLB_ENTRIES],
    // mapping of u64 entry to u64 entry
    cache: BTreeMap<HexagonTlbCacheEntry, u64>,
    enable_translation: bool,
}

pub const PAGE_SIZE_BITS: u64 = 12;
// From https://github.com/quic/qemu/blob/3921c6eed6bd7c670eff633fe829e18607125969/hw/hexagon/hexagon_tlb.c
const PAGE_MASK: [u64; 13] = [
    // 12 bits
    0x0fff,
    // 14 bits
    0x3fff,
    // 16 bits
    0xffff,
    // 18 bits
    0x3ffff,
    // 20 bits
    0xfffff,
    // 22 bits
    0x3fffff,
    // 24 bits
    0xffffff,
    // 26 bits
    0x3ffffff,
    // 28 bits
    0xfffffff,
    // 30 bits
    0x3fffffff,
    // 32 bits
    0xffffffff,
    // 34 bits
    0x3ffffffff,
    // 36 bits
    0xfffffffff,
];

impl Pte {
    /// Invalidate the entry and delete entry from cache.
    pub fn invalidate(&mut self, cache: &mut BTreeMap<HexagonTlbCacheEntry, u64>) {
        self.set_v(false);

        // Entry in cache is stored as (VPN << 12)
        let virt_shifted = self.vpn().as_u64() << 12;
        cache.remove(&HexagonTlbCacheEntry {
            vpn_page_masked: virt_shifted,
            asid: self.asid(),
        });
    }
}

/// N.B. It appears that Hexagon uses the words MMU and TLB interchangeably,
/// as the the TLB-related instructions (tlbw, tlbr, etc.) store the page tables,
/// translate, and presumably cache as well.
///
/// Sources: 11.9.2 "TLB read/write/probe operations" and QEMU sources.
impl HexagonTlb {
    pub fn new() -> Self {
        Self {
            enable_translation: false,
            entries: [Pte::new_with_raw_value(0); MAX_TLB_ENTRIES],
            cache: BTreeMap::new(),
        }
    }

    // https://github.com/quic/qemu/blob/3921c6eed6bd7c670eff633fe829e18607125969/hw/hexagon/hexagon_tlb.c#L100
    fn get_entry_page_type(ent: &Pte) -> usize {
        trace!("PPD trailing zeroes is {}", ent.ppd().trailing_zeros());
        ent.ppd().trailing_zeros() as usize // + (ent.pte_hsv39() as usize * 4)
    }

    // https://github.com/quic/qemu/blob/3921c6eed6bd7c670eff633fe829e18607125969/hw/hexagon/hexagon_tlb.c#L100
    fn get_entry_page_num_bits(ent: &Pte) -> u64 {
        PAGE_SIZE_BITS + (2 * Self::get_entry_page_type(ent) as u64)
    }
}

impl TlbImpl for HexagonTlb {
    /// This seems to be a von Neumann architecture and not Harvard architecture,
    /// so enabling data translation will also enable code address translation.
    fn enable_data_address_translation(&mut self) -> Result<(), UnknownError> {
        self.enable_translation = true;
        Ok(())
    }

    /// This seems to be a von Neumann architecture and not Harvard architecture,
    /// so disabling data translation will also disable code address translation.
    fn disable_data_address_translation(&mut self) -> Result<(), UnknownError> {
        self.enable_translation = false;
        Ok(())
    }

    /// This seems to be a von Neumann architecture and not Harvard architecture,
    /// so enabling code translation will also enable data address translation.
    fn enable_code_address_translation(&mut self) -> Result<(), UnknownError> {
        self.enable_translation = true;
        Ok(())
    }

    /// This seems to be a von Neumann architecture and not Harvard architecture,
    /// so disabling code translation will also disable cata address translation.
    fn disable_code_address_translation(&mut self) -> Result<(), UnknownError> {
        self.enable_translation = false;
        Ok(())
    }

    /// Hexagon TLB translation.
    ///
    /// The crux of the logic for this function is implemented in
    /// <https://github.com/quic/qemu/blob/bcain/tlb_obj/hw/hexagon/hexagon_tlb.c>.
    ///
    /// It is worth noting that the default address translation algorithm for QUIC's QEMU fork,
    /// located at <https://github.com/quic/qemu/blob/hex-next/target/hexagon/hex_mmu.c>, does not
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
    /// - Entry 0: VPN is `0x89104`, PPD is `0x112202`
    /// - Entry 1: VPN is `0x1d25c`, PPD is `0x022308`
    /// - Entry 2: VPN is `0x1d21c`, PPD is `0x03a490`
    ///
    /// First, we receive a virtual address. For the sake of example, let's say this
    /// is `0x1d23c210`. The way we match the VA to PA is by iterating through the page table
    /// entries, finding a mask based on the number of trailing zeroes in the PPD, and then
    /// matching the input VA to the VPN based on this mask.
    ///
    /// **Iteration 0:** PPD is `0x112202`. This has exactly 1 trailing zero, which means
    /// in our mask table, this corresponds to mask `0x3fff`, which is 14 bits for the offset.
    /// Our mask for the "page number" is the inverse of this, `0xffffc000`. There is a chance that
    /// some of the bits in the actual VPN entry may get cleared by this, which is intentional.
    ///
    /// The idea with the VPN is we shift left by 12, yielding `0x89104000`, then mask with
    /// `0xffffc000`, yielding the same. Now, we do the same mask for the VA, yielding
    /// `0x1d23c000` (itself).  Now, comparing the two masked values, they don't match, and
    /// we move on.
    ///
    /// **Iteration 1**: PPD is `0x022308`. There are *three* trailing zeroes, so we choose mask
    /// 0xffff. Now, we wish to mask the (shifted left) VPN and VA with the inverse, which is `0xffff0000`.
    /// The VA masked is `0x1d230000`. The VPN shfited left is `0x1d25c000`, and masked it is `0x1d250000`.
    /// We see that `0x1d230000` != `0x1d250000`, so this isn't a match. Onwards.
    ///
    /// **Iteration 3:** PPD is `0x03a490`. As before, we have *three* trailing zeroes, so our mask is
    /// `0x3ffff` and our inverse is `0xfffc0000`. Now, the VPN shifted is `0x1d21c000`, with the mask, it's 0x
    /// `0x1d200000`. Our VA masked is `0x1d20000` as well. It's a match!
    ///
    /// Now we can go ahead and translate our PA. We obtain our offset with the original mask:
    /// `0x1d23c210 & 0x3ffff = 0x3c210`.
    ///
    /// To get the "base" from our PPD, we must shift right by one and then shift left by 12
    /// `(0x03a490 >> 1) << 12 = 0x1d248000`. Finally, we add our offset to this base:
    /// `0x1d248000 + 0x3c210 = 0x1d284210`.
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
        } else if let Some(&ppn_addr) = self.cache.get(&HexagonTlbCacheEntry {
            vpn_page_masked,
            asid: ssr.asid(),
        }) {
            let va_off_mask = (1 << PAGE_SIZE_BITS) - 1;
            let p_addr = ppn_addr + (virt_addr & va_off_mask);
            trace!("fast path: translated {virt_addr:x} to {p_addr:x}");
            Ok(p_addr)
        } else {
            let virt_addr = virt_addr as u32;

            for ent in &self.entries {
                trace!("pte {ent:x?}");
                if !ent.v() || (ent.asid() != ssr.asid() && !ent.g()) {
                    trace!("skipping pte");
                    continue;
                }

                debug!("pte {ent:x?}");
                let page_type = Self::get_entry_page_type(ent);
                let page_mask = PAGE_MASK[page_type];
                trace!("page_mask is {page_mask:x}");

                let va_vpn = (virt_addr as u64) & !page_mask;
                let va_offset = virt_addr as u64 & page_mask;

                let ent_vpn = (u64::from(ent.vpn()) << PAGE_SIZE_BITS) & !page_mask;

                debug!("ent vpn {ent_vpn:x} real vpn {va_vpn:x} va_offset {va_offset:x} page_mask {page_mask:x}",);
                if va_vpn == ent_vpn {
                    trace!(
                        "ssr {:?} ssr raw {:x} usermode? {} x {} w {} r {} memory_type {:?}",
                        ssr,
                        ssr.raw_value(),
                        ssr.user_mode(),
                        ent.x(),
                        ent.w(),
                        ent.r(),
                        memory_type
                    );

                    // Do permissions checking here. We do permissions checking _after_ a match
                    // because in case there is a violation, we are supposed to do a page fault.
                    // See hexagon_tlb_fill in target/hexagon/cpu.c.
                    //
                    // Permission checking doesn't happen in monitor mode.
                    // NOTE: not clear if permission checking happens in guest mode.
                    // Need to relearn some stuff about hypervisors.
                    //
                    // See hexagon_cpu_mmu_index function in QEMU (cpu.c)
                    // See hex_tlb_entry_get_perm in QEMU (hexagon_tlb.c/hexagon_mmu.c)
                    if !ssr.monitor_mode() {
                        let mut cause = None;

                        if matches!(memory_type, MemoryType::Code) {
                            if ssr.user_mode() && !ent.u() {
                                cause = Some(HexagonInterruptCause::FetchNoUpage);
                            } else if !ent.x() {
                                cause = Some(HexagonInterruptCause::FetchNoXpage);
                            }
                        } else {
                            match access_type {
                                MemoryOperation::Read if ssr.user_mode() && !ent.u() => {
                                    cause = Some(HexagonInterruptCause::PrivNoUread);
                                }
                                MemoryOperation::Read if !ent.r() => {
                                    cause = Some(HexagonInterruptCause::PrivNoRead);
                                }
                                MemoryOperation::Write if ssr.user_mode() && !ent.u() => {
                                    cause = Some(HexagonInterruptCause::PrivNoUwrite);
                                }
                                MemoryOperation::Write if !ent.w() => {
                                    cause = Some(HexagonInterruptCause::PrivNoWrite);
                                }
                                _ => {}
                            }
                        }

                        if let Some(cause) = cause {
                            trace!("tlb permissions error cause {cause:?}");

                            update_badva(processor, virt_addr)?;
                            ssr_set_cause(processor, cause)?;
                            return Err(TlbTranslateError::Exception(
                                HexagonInterruptType::Precise as i32,
                            ));
                        }
                    }

                    let ppd_unmask = u64::from(ent.ppd() >> 1)
                        .overflowing_shl(PAGE_SIZE_BITS as u32)
                        .0;
                    let ppd_mask = ppd_unmask & !page_mask;
                    let pa = ppd_mask + va_offset;

                    // If there were already an entry in the cache, this overwrites it.
                    // In other cases (eg. removing an entry from the TLB), the cache is
                    // also invalidated.
                    self.cache.insert(
                        HexagonTlbCacheEntry {
                            vpn_page_masked,
                            asid: ssr.asid(),
                        },
                        pa & page_number_mask,
                    );

                    debug!("va {virt_addr:x} ppd_unmask {ppd_unmask:x} ppd_mask {ppd_mask:x} pa {pa:x}");
                    return Ok(pa);
                }
            }

            let err = if matches!(memory_type, MemoryType::Code)
                && matches!(access_type, MemoryOperation::Read)
            {
                error!("couldn't translate {virt_addr:x} (pc/code)",);

                update_badva(processor, virt_addr)?;

                // See hex_tlb_entry_get_perm
                if (virt_addr as u64 & page_number_mask) == 0 {
                    ssr_set_cause(processor, HexagonInterruptCause::TlbmissxCauseNextpage)?;
                } else {
                    ssr_set_cause(processor, HexagonInterruptCause::TlbmissxCauseNormal)?;
                }

                Err(TlbTranslateError::Exception(
                    HexagonInterruptType::TlbMissX as i32,
                ))
            } else if matches!(memory_type, MemoryType::Data) {
                error!(
                    "couldn't translate {virt_addr:x} at pc {:x?}",
                    processor.cpu.pc()
                );

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

    fn tlb_write(&mut self, idx: usize, data: u64, _flags: u32) -> Result<(), TlbTranslateError> {
        // In QUIC QEMU branch hex-next, function hexagon_tlb_write in hw/hexagon/hexagon_tlb.c,
        // nothing is done if the TLB index is out of bounds (eg. no error). In our case, we will return an error.
        if idx > MAX_TLB_ENTRIES {
            return Err(TlbTranslateError::Other(anyhow!(
                "TLB write to index {idx:x} is out of bounds"
            )));
        }

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

    fn tlb_read(&self, idx: usize, _flags: u32) -> Result<u64, TlbTranslateError> {
        // In QUIC QEMU branch hex-next, function hexagon_tlb_write in hw/hexagon/hexagon_tlb.c,
        // nothing is done if the TLB index is out of bounds (eg. no error). In our case, we will return an error.
        if idx >= MAX_TLB_ENTRIES {
            Err(TlbTranslateError::Other(UnknownError::msg(format!(
                "specified tlb entry at index {idx} doesn't exist, cannot read"
            ))))
        } else {
            Ok(self.entries[idx].raw_value())
        }
    }

    /// This is only used for ASID in our implementation
    /// 11.9.2 "TLB read/write/probe operations"
    ///
    /// The TLBINVASID instruction "invalidates all TLB entries with the Global bit not
    /// set and with the ASID matching the `Rs[26:20]` operand." What is passed is a 32-bit
    /// flags value where **the lower 7 bits are the ASID.**
    ///
    /// NOTE: Any bits above the 7th bit will be ignored.
    fn invalidate_all(&mut self, flags: u32) -> Result<(), UnknownError> {
        let probe_field = TLBProbeField::new_with_raw_value(flags);

        trace!("tlbinvasid invalidate for asid {:x}", probe_field.asid());
        for ent in self.entries.iter_mut() {
            if ent.asid() == probe_field.asid() && !ent.g() {
                // Set the valid bit to false and invalidate in cache.
                ent.invalidate(&mut self.cache);
            }
        }
        Ok(())
    }

    fn invalidate(&mut self, idx: usize) -> Result<(), UnknownError> {
        // In QUIC QEMU branch hex-next, function hexagon_tlb_write in hw/hexagon/hexagon_tlb.c,
        // nothing is done if the TLB index is out of bounds (eg. no error). In our case, we will return an error.
        if idx >= MAX_TLB_ENTRIES {
            Err(UnknownError::msg(format!(
                "specified tlb entry at index {idx} doesn't exist, cannot invalidate"
            )))
        } else {
            // Cache is passed to invalidate the entry in the cache as well.
            self.entries[idx].invalidate(&mut self.cache);
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
                        trace!("tlb search got entry {ent:x?}");
                        return Some(i as u64);
                    }
                }
            }
            None
        } else if flags == 1 {
            // TLB match, input is a TLB entry
            let input_entry = Pte::new_with_raw_value(input);
            let mut overlapping_entry = None;

            // In the Hexagon manual, 11.9.2 SYSTEM MONITOR "TLB read/write/probe operations,"
            // the documentation states that "In the overlap check, the global bit of the incoming
            // Rss entry is forced to zero and the valid bit is forced to 1." As such, we don't
            // check the valid bit or global bit.
            trace!("tlb_search on input entry {input_entry:x?}");

            for (i, entry) in self.entries.iter().enumerate() {
                trace!("checking against entry {entry:x?}");
                if !entry.v() || entry.asid() != input_entry.asid() {
                    continue;
                }

                let page_type = Self::get_entry_page_type(entry);
                let page_mask = PAGE_MASK[page_type];

                let input_va = (u64::from(input_entry.vpn()) << PAGE_SIZE_BITS) & !page_mask;
                let va = (u64::from(entry.vpn()) << PAGE_SIZE_BITS) & !page_mask;

                let sz = 1 << Self::get_entry_page_num_bits(entry);
                let input_sz = 1 << Self::get_entry_page_num_bits(&input_entry);

                trace!("input_va {input_va:x} input_sz {input_sz:x} va {va:x} sz {sz:x}");
                // Now actually check for overlaps.
                //
                // Case 1:
                //                           |VA............ |
                //   |INPUT_VA...+INPUT_SZ|                           false (input_va + input_sz < va)
                //   |INPUT_VA................+INPUT_SZ|              true
                //                           |INPUT_VA...+INPUT_SZ|   true  (== case)
                // Case 2:
                //   |VA............ |
                //                      |INPUT_VA...+INPUT_SZ|        false ((va+sz) < input_va)
                //          |INPUT_VA................+INPUT_SZ|       true
                //   |INPUT_VA...+INPUT_SZ|                           true  (== case)
                //
                // Note that input_va <= va and va <= input_va catches all cases to either side of the OR.
                //
                // With (input_va + input_sz > va) and (va + sz > input_va), we don't check if these are equal
                // because then we'd be checking outside of the entry range.
                //
                // For example, imagine va = 0x100, sz = 0x100, and input_va = 0x200.
                // Then va + sz = 0x200. The check (va + sz > input_va) sees if the input entry (input_va)
                // _starts inside_ of the range [va...end]. For the range of the checked entry to be size sz,
                // the values must be [va...va+sz-1]. Checking [va...va+sz] (inclusive) would mean checking
                // a range of 0x201, resulting in a false overlap.
                //
                // The actual range for the checked entry is 0x100 to 0x1ff inclusive, so that's what we
                // check by not including "equal to."
                if (input_va <= va && (input_va + input_sz) > va)
                    || (va <= input_va && (va + sz) > input_va)
                {
                    match overlapping_entry {
                        // In the Hexagon manual, 11.9.2 SYSTEM MONITOR "TLB read/write/probe operations,"
                        // the documentation states: "If multiple entries overlap, the value
                        // 0xffff_ffff is returned."
                        Some(_) => return Some(u32::MAX as u64),
                        None => overlapping_entry = Some(i as u64),
                    }
                }
            }

            overlapping_entry
        } else {
            unreachable!("Invalid flags 0x{flags:x} value passed to hexagon TLB search!")
        }
    }
}
