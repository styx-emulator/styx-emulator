// SPDX-License-Identifier: BSD-2-Clause
use derive_more::FromStr;
use styx_pcode::{pcode::VarnodeData, sla::SlaUserOps};
use styx_pcode_translator::sla::HexagonUserOps;
use styx_processor::{cpu::CpuBackend, event_controller::EventController, memory::Mmu};

use crate::{
    arch_spec::{ArchSpecBuilder, HexagonPcodeBackend},
    call_other::{CallOtherCallback, CallOtherCpu, CallOtherHandleError},
    PCodeStateChange,
};

#[derive(Debug)]
pub struct InterruptGenericStub {
    from: &'static str,
}

impl<T: CpuBackend> CallOtherCallback<T> for InterruptGenericStub {
    fn handle(
        &mut self,
        _backend: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        unimplemented!("interrupt related stub called for {}", self.from);
    }
}

pub fn add_interrupt_callothers<S: SlaUserOps<UserOps: FromStr>>(
    spec: &mut ArchSpecBuilder<S, HexagonPcodeBackend>,
) {
    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Trap0,
            InterruptGenericStub { from: "trap0" },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Trap1,
            InterruptGenericStub { from: "trap1" },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Rte, InterruptGenericStub { from: "rte" })
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Swi, InterruptGenericStub { from: "swi" })
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Cswi, InterruptGenericStub { from: "cswi" })
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Ciad, InterruptGenericStub { from: "ciad" })
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Siad, InterruptGenericStub { from: "siad" })
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Iassignr,
            InterruptGenericStub { from: "iassignr" },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Iassignw,
            InterruptGenericStub { from: "iassignw" },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::Nmi, InterruptGenericStub { from: "nmi" })
        .unwrap();
}
