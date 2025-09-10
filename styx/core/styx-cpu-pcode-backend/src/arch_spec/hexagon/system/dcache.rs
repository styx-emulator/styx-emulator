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

// Data cache

#[derive(Debug)]
pub struct DcacheGenericStub {
    from: String,
}

impl<T: CpuBackend> CallOtherCallback<T> for DcacheGenericStub {
    fn handle(
        &mut self,
        _backend: &mut dyn CallOtherCpu<T>,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        debug!("dcache stub called for {}", self.from);
        Ok(PCodeStateChange::Fallthrough)
    }
}

pub fn add_dcache_callothers<S: SlaUserOps<UserOps: FromStr>>(
    spec: &mut ArchSpecBuilder<S, HexagonPcodeBackend>,
) {
    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Dctagr,
            DcacheGenericStub {
                from: "dctagr".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Dctagw,
            DcacheGenericStub {
                from: "dctagw".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Dcfetch,
            DcacheGenericStub {
                from: "dcfetch".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Dckill,
            DcacheGenericStub {
                from: "dckill".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Dczeroa,
            DcacheGenericStub {
                from: "dczeroa".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Dccleana,
            DcacheGenericStub {
                from: "dccleana".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Dccleanidx,
            DcacheGenericStub {
                from: "dccleanidx".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Dccleaninva,
            DcacheGenericStub {
                from: "dccleaninva".to_owned(),
            },
        )
        .unwrap();
    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Dccleaninvidx,
            DcacheGenericStub {
                from: "dccleaninvidx".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Dcinva,
            DcacheGenericStub {
                from: "dcinva".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Dcinvidx,
            DcacheGenericStub {
                from: "dcinvidx".to_owned(),
            },
        )
        .unwrap();
}
