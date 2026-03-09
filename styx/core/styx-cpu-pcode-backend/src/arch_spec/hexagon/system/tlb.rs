// SPDX-License-Identifier: BSD-2-Clause
use derive_more::FromStr;
use log::{debug, trace};
use styx_errors::anyhow::Context;
use styx_pcode::{pcode::VarnodeData, sla::SlaUserOps};
use styx_pcode_translator::sla::HexagonUserOps;
use styx_processor::{cpu::CpuBackend, event_controller::EventController, memory::Mmu};

use crate::{
    arch_spec::{ArchSpecBuilder, HexagonPcodeBackend},
    call_other::{CallOtherCallback, CallOtherCpu, CallOtherHandleError},
    PCodeStateChange,
};

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
        .add_handler_other_sla(HexagonUserOps::Tlbr, TlbGenericStub { from: "tlbr" })
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Tlbp, TlbGenericStub { from: "tlbp" })
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Tlbinvasid,
            TlbGenericStub { from: "tlbinvasid" },
        )
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
