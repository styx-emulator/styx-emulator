// SPDX-License-Identifier: BSD-2-Clause
use arbitrary_int::*;
use derive_more::FromStr;
use log::{debug, trace};
use styx_errors::{
    anyhow::{self, Context},
    UnknownError,
};
use styx_pcode::{
    pcode::{AddressSpaceName, SpaceName, VarnodeData},
    sla::SlaUserOps,
};
use styx_pcode_translator::sla::HexagonUserOps;
use styx_processor::{
    cpu::{CpuBackend, CpuBackendExt},
    event_controller::EventController,
    memory::Mmu,
};

use crate::{
    arch_spec::{ArchSpecBuilder, HexagonPcodeBackend},
    call_other::{CallOtherCallback, CallOtherCpu, CallOtherHandleError},
    PCodeStateChange,
};
use bitbybit::bitfield;

const FLAGS_NONE: u32 = 0;

#[bitfield(u32, Debug)]
pub struct TLBProbeField {
    #[bits(0..=19, rw)]
    vpn: u20,
    #[bits(20..=26, rw)]
    asid: u7,
}

#[derive(Debug)]
pub struct TlbGenericStub {
    from: &'static str,
}

impl<T: CpuBackend> CallOtherCallback<T> for TlbGenericStub {
    fn handle(
        &mut self,
        _backend: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        debug!("tlb stub called for {}", self.from);
        Ok(PCodeStateChange::Fallthrough)
    }
}

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
            .with_context(|| "couldn't read from tlb")?;

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
        output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        // 11.9.2 TLB read/write/probe operations
        // tlbinvasid, read bits 20 to 26 (zero-indexed)
        // of Rs (varnode 0)

        let asid_vn = &inputs[0];
        assert!(asid_vn.size == 4);

        let query = TLBProbeField::new_with_raw_value(
            cpu.read(asid_vn)
                .with_context(|| "couldn't read tlb asid vn")?
                .to_u64()
                .with_context(|| "couldn't convert asid vn to u64")? as u32,
        );

        trace!("hexagon tlb asid {}", query.asid());

        // we must pass in the bits as unshifted
        mmu.tlb
            .invalidate_all(u8::from(query.asid()) as u32)
            .with_context(|| "couldn't read from tlb")?;

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
        .add_handler_other_sla(
            HexagonUserOps::Tlbmatch,
            TlbGenericStub { from: "tlbmatch" },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Ctlbw, TlbGenericStub { from: "ctlbw" })
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Tlboc, TlbGenericStub { from: "tlboc" })
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Tlbr, TlbRead {})
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Tlbp, TlbGenericStub { from: "tlbp" })
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Tlbinvasid, TlbInvAsid {})
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Tlblock, TlbGenericStub { from: "tlblock" })
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Tlbunlock,
            TlbGenericStub { from: "tlbunlock" },
        )
        .unwrap();
}
