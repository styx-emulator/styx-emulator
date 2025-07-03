// BSD 2-Clause License
//
// Copyright (c) 2024, Styx Emulator Project
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
use derive_more::FromStr;
use log::debug;
use styx_pcode::{pcode::VarnodeData, sla::SlaUserOps};
use styx_pcode_translator::sla::HexagonUserOps;
use styx_processor::{event_controller::EventController, memory::Mmu};

use crate::{
    arch_spec::ArchSpecBuilder,
    call_other::{CallOtherCallback, CallOtherHandleError},
    PCodeStateChange, PcodeBackend,
};

// Data cache

#[derive(Debug)]
pub struct InterruptGenericStub {
    from: String,
}

impl CallOtherCallback for InterruptGenericStub {
    fn handle(
        &mut self,
        _backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        debug!("interrupt related stub called for {}", self.from);
        Ok(PCodeStateChange::Fallthrough)
    }
}

pub fn add_interrupt_callothers<S: SlaUserOps<UserOps: FromStr>>(spec: &mut ArchSpecBuilder<S>) {
    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Trap0,
            InterruptGenericStub {
                from: "trap0".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Trap1,
            InterruptGenericStub {
                from: "trap1".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Rte,
            InterruptGenericStub {
                from: "rte".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Swi,
            InterruptGenericStub {
                from: "swi".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Cswi,
            InterruptGenericStub {
                from: "cswi".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Ciad,
            InterruptGenericStub {
                from: "ciad".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Siad,
            InterruptGenericStub {
                from: "siad".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Iassignr,
            InterruptGenericStub {
                from: "iassignr".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Iassignw,
            InterruptGenericStub {
                from: "iassignw".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Nmi,
            InterruptGenericStub {
                from: "nmi".to_owned(),
            },
        )
        .unwrap();
}
