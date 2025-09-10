// SPDX-License-Identifier: BSD-2-Clause
use derive_more::FromStr;
use log::debug;
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
    from: String,
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

pub fn add_tlb_callothers<S: SlaUserOps<UserOps: FromStr>>(
    spec: &mut ArchSpecBuilder<S, HexagonPcodeBackend>,
) {
    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Tlbw,
            TlbGenericStub {
                from: "tlbw".to_owned(),
            },
        )
        .unwrap();
    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Tlbmatch,
            TlbGenericStub {
                from: "tlbmatch".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Ctlbw,
            TlbGenericStub {
                from: "ctlbw".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Tlboc,
            TlbGenericStub {
                from: "tlboc".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Tlbr,
            TlbGenericStub {
                from: "tlbr".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Tlbp,
            TlbGenericStub {
                from: "tlbp".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Tlbinvasid,
            TlbGenericStub {
                from: "tlbinvasid".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Tlblock,
            TlbGenericStub {
                from: "tlblock".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Tlbunlock,
            TlbGenericStub {
                from: "tlbunlock".to_owned(),
            },
        )
        .unwrap();
}
