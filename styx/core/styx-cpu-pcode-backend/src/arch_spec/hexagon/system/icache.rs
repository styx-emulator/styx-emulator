// SPDX-License-Identifier: BSD-2-Clause
use derive_more::FromStr;
use log::debug;
use styx_pcode::pcode::VarnodeData;
use styx_pcode::sla::SlaUserOps;
use styx_pcode_translator::sla::HexagonUserOps;
use styx_processor::cpu::CpuBackend;
use styx_processor::event_controller::EventController;
use styx_processor::memory::Mmu;

use crate::arch_spec::{ArchSpecBuilder, HexagonPcodeBackend};
use crate::call_other::{CallOtherCallback, CallOtherCpu, CallOtherHandleError};
use crate::PCodeStateChange;

// Instruction cache

#[derive(Debug)]
pub struct IcacheGenericStub {
    from: &'static str,
}

impl<T: CpuBackend> CallOtherCallback<T> for IcacheGenericStub {
    fn handle(
        &mut self,
        _backend: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        debug!("icache stub called for {}", self.from);
        Ok(PCodeStateChange::Fallthrough)
    }
}

pub fn add_icache_callothers<S: SlaUserOps<UserOps: FromStr>>(
    spec: &mut ArchSpecBuilder<S, HexagonPcodeBackend>,
) {
    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Ictagr, IcacheGenericStub { from: "ictagr" })
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Ictagw, IcacheGenericStub { from: "ictagw" })
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Icdatar,
            IcacheGenericStub { from: "icdatar" },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Icdataw,
            IcacheGenericStub { from: "icdataw" },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Icinva, IcacheGenericStub { from: "icinva" })
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Icinvidx,
            IcacheGenericStub { from: "icinvidx" },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Ickill, IcacheGenericStub { from: "ickill" })
        .unwrap();
}
