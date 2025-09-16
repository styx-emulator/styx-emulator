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
pub struct L2GenericStub {
    from: &'static str,
}

impl<T: CpuBackend> CallOtherCallback<T> for L2GenericStub {
    fn handle(
        &mut self,
        _backend: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        debug!("l2 stub called for {}", self.from);
        Ok(PCodeStateChange::Fallthrough)
    }
}

pub fn add_l2_callothers<S: SlaUserOps<UserOps: FromStr>>(
    spec: &mut ArchSpecBuilder<S, HexagonPcodeBackend>,
) {
    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::L2kill, L2GenericStub { from: "l2kill" })
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::L2tagw, L2GenericStub { from: "l2tagw" })
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::L2tagr, L2GenericStub { from: "l2tagr" })
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::L2cleaninvidx,
            L2GenericStub {
                from: "l2cleaninvidx",
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::L2cleanidx,
            L2GenericStub { from: "l2cleanidx" },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::L2invidx, L2GenericStub { from: "l2invidx" })
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::L2fetch, L2GenericStub { from: "l2fetch" })
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::L2locka, L2GenericStub { from: "l2locka" })
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::L2unlocka,
            L2GenericStub { from: "l2unlocka" },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::L2gunlock,
            L2GenericStub { from: "l2gunlock" },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(HexagonUserOps::L2gclean, L2GenericStub { from: "l2gclean" })
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::L2gcleaninv,
            L2GenericStub {
                from: "l2gcleaninv",
            },
        )
        .unwrap();
}
