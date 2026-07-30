// SPDX-License-Identifier: BSD-2-Clause

use derive_more::FromStr;
use log::{info, trace, warn};
use std::cmp::min;
use styx_errors::anyhow::Context;
use styx_pcode::{pcode::VarnodeData, sla::SlaUserOps};
use styx_pcode_translator::sla::HexagonUserOps;
use styx_processor::{cpu::CpuBackend, event_controller::EventController, memory::Mmu};

use crate::{
    arch_spec::{ArchSpecBuilder, HexagonPcodeBackend},
    call_other::{CallOtherCallback, CallOtherCpu, CallOtherHandleError},
    PCodeStateChange,
};

const FLAGS_NONE: u32 = 0;

#[derive(Debug)]
pub struct TlbGenericStub {
    from: &'static str,
}

impl<T: CpuBackend> CallOtherCallback<T> for TlbGenericStub {
    fn handle(
        &mut self,
        backend: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        warn!("tlb stub called for {} at {:x?}", self.from, backend.pc());
        unimplemented!();
    }
}

/// FIXME: multicore (per-core tlb?)
#[derive(Debug)]
pub struct TlbWrite {}
impl<T: CpuBackend> CallOtherCallback<T> for TlbWrite {
    fn handle(
        &mut self,
        cpu: &mut dyn CallOtherCpu<T>,
        mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        // tlbw, input 0 is PTE and input 1 is index
        let pte_vn = &inputs[0];
        let index_vn = &inputs[1];

        // 11.9.2 TLB read/write/probe operations

        let pte = cpu.read(pte_vn).with_context(|| "couldn't read tlb pte")?;
        let index = cpu
            .read(index_vn)
            .with_context(|| "couldn't read tlb index")?;

        trace!("hexagon tlb write request with index {index} and pte {pte:x?}");

        assert!(pte_vn.size == 8 && index_vn.size == 4);

        mmu.tlb
            .tlb_write(
                index
                    .to_u64()
                    .with_context(|| "couldn't convert index to u64")? as usize,
                pte.to_u64()
                    .with_context(|| "couldn't convert pte to u64")?,
                0,
            )
            .with_context(|| "couldn't write to tlb")?;
        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug)]
pub struct TlbRead {}
impl<T: CpuBackend> CallOtherCallback<T> for TlbRead {
    fn handle(
        &mut self,
        cpu: &mut dyn CallOtherCpu<T>,
        mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        // 11.9.2 TLB read/write/probe operations
        // tlbr, input 0 is index

        let index_vn = &inputs[0];
        let output_vn = output.with_context(|| "couldn't read output varnode in tlbr")?;
        assert!(index_vn.size == 4);

        let index = cpu
            .read(index_vn)
            .with_context(|| "couldn't read tlb index")?;

        trace!("hexagon tlb read request with index {index}");

        let pte = mmu
            .tlb
            .tlb_read(
                index
                    .to_u64()
                    .with_context(|| "couldn't convert index to u64")? as usize,
                FLAGS_NONE,
            )
            .with_context(|| format!("couldn't read from tlb {:x?}", cpu.pc()))?;

        // write the entry to the vn
        cpu.write(output_vn, pte.into())
            .with_context(|| "couldn't write PTE to output varnode in tlbr")?;

        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug)]
pub struct TlbInvAsid {}
impl<T: CpuBackend> CallOtherCallback<T> for TlbInvAsid {
    fn handle(
        &mut self,
        cpu: &mut dyn CallOtherCpu<T>,
        mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        // 11.9.2 TLB read/write/probe operations
        // tlbinvasid, read bits 20 to 26 (zero-indexed)
        // of Rs (varnode 0)

        let probe_vn = &inputs[0];
        assert!(probe_vn.size == 4);

        let tlb_probe_field =
            cpu.read(probe_vn)
                .with_context(|| "couldn't read tlb asid vn")?
                .to_u64()
                .with_context(|| "couldn't convert asid vn to u64")? as u32;

        // we must pass in the bits as unshifted
        mmu.tlb
            .invalidate_all(tlb_probe_field)
            .with_context(|| "couldn't read from tlb")?;

        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug)]
pub struct TlbProbe {}
impl<T: CpuBackend> CallOtherCallback<T> for TlbProbe {
    fn handle(
        &mut self,
        cpu: &mut dyn CallOtherCpu<T>,
        mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        let probe_vn = &inputs[0];
        assert!(probe_vn.size == 4);

        let tlb_probe_field =
            cpu.read(probe_vn)
                .with_context(|| "couldn't read tlb asid vn")?
                .to_u64()
                .with_context(|| "couldn't convert asid vn to u64")? as u32;

        info!("hexagon tlb probe {tlb_probe_field}");

        // we must pass in the bits as unshifted
        let stored_ent = mmu
            .tlb
            .tlb_search(tlb_probe_field as u64, 0)
            .unwrap_or(0x8000_0000);

        let output = output.with_context(|| "tlbp hexagon should have an output")?;

        cpu.write(output, stored_ent.into())
            .with_context(|| "couldn't store tlb probe result in output varnode")?;

        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug)]
pub struct TlbLockUnlock {}
impl<T: CpuBackend> CallOtherCallback<T> for TlbLockUnlock {
    fn handle(
        &mut self,
        _cpu: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug)]
pub struct TlbMatch {}
impl<T: CpuBackend> CallOtherCallback<T> for TlbMatch {
    fn handle(
        &mut self,
        cpu: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        // cpu

        let rss = cpu
            .read(&inputs[0])
            .with_context(|| "couldn't read Rss")?
            .to_u64()
            .with_context(|| "couldn't turn Rss to u64")?;

        // Fine to keep as u64 since we mask with a u64 later.
        let rt = cpu.read(&inputs[1]).with_context(|| "couldn't read Rt")?;
        assert_eq!(rt.size(), 4);
        let rt = rt.to_u64().with_context(|| "couldn't turn Rt to u64")?;

        let output_unwrap = output.with_context(|| "no output for tlbmatch")?;

        let tlblo = rss & 0xffffffff;
        let tlbhi = (rss >> 32) & 0xffffffff;

        let size = min(6, (!(tlblo.reverse_bits())).leading_ones());
        let mask = 0x07ffffff & (0xffffffff << (2 * size));

        // The top bit is set (valid bit??)
        let tlbhi_topbit = ((tlbhi >> 31) & 1) == 1;

        let pd: u32 = if tlbhi_topbit && ((tlbhi & mask) == (rt & mask)) {
            0xff
        } else {
            0x0
        };

        cpu.write(output_unwrap, pd.into())
            .with_context(|| "failed to set Pd register for tlbmatch")?;

        Ok(PCodeStateChange::Fallthrough)
    }
}

#[derive(Debug)]
pub struct CtlbwTlboc {
    write: bool,
}
impl<T: CpuBackend> CallOtherCallback<T> for CtlbwTlboc {
    fn handle(
        &mut self,
        cpu: &mut dyn CallOtherCpu<T>,
        mmu: &mut Mmu,
        _ev: &mut EventController,
        inputs: &[VarnodeData],
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        let rss = cpu
            .read(&inputs[0])
            .with_context(|| "couldn't read rss varnode")?
            .to_u64()
            .with_context(|| "couldn't turn rss to u64")?;

        let rd = output.with_context(|| "couldn't unwrap Rd output for ctlbw")?;

        let rd_val = if let Some(idx) = mmu.tlb.tlb_search(rss, 1) {
            idx as u32
        } else {
            // Logic for Ctlbw and Tlboc are largely the same. This is the only thing that is
            // different.
            if self.write {
                let rt = cpu
                    .read(&inputs[1])
                    .with_context(|| "couldn't read rss varnode")?
                    .to_u64()
                    .with_context(|| "couldn't turn rss to u64")? as u32;

                mmu.tlb
                    .tlb_write(rt as usize, rss, 0)
                    .with_context(|| "couldn't write to tlb")?;
            }
            0x8000_0000
        };

        cpu.write(rd, rd_val.into())
            .with_context(|| "couldn't write Rd for ctlbw")?;

        Ok(PCodeStateChange::Fallthrough)
    }
}

pub fn add_tlb_callothers<S: SlaUserOps<UserOps: FromStr>>(
    spec: &mut ArchSpecBuilder<S, HexagonPcodeBackend>,
) {
    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Tlbw, TlbWrite {})
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Tlbmatch, TlbMatch {})
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Ctlbw, CtlbwTlboc { write: true })
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Tlboc, CtlbwTlboc { write: false })
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Tlbr, TlbRead {})
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Tlbp, TlbProbe {})
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Tlbinvasid, TlbInvAsid {})
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Tlblock, TlbLockUnlock {})
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Tlbunlock, TlbLockUnlock {})
        .unwrap();
}
