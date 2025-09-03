// SPDX-License-Identifier: BSD-2-Clause
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
use styx_processor::{cpu::CpuBackend, event_controller::EventController, memory::Mmu};

use crate::{
    arch_spec::{ArchSpecBuilder, HexagonPcodeBackend},
    call_other::{CallOtherCallback, CallOtherCpu, CallOtherHandleError},
    PCodeStateChange, PcodeBackend,
};

#[derive(Debug)]
pub struct L2GenericStub {
    from: String,
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
        .add_handler_other_sla(
            HexagonUserOps::L2kill,
            L2GenericStub {
                from: "l2kill".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::L2tagw,
            L2GenericStub {
                from: "l2tagw".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::L2tagr,
            L2GenericStub {
                from: "l2tagr".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::L2cleaninvidx,
            L2GenericStub {
                from: "l2cleaninvidx".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::L2cleanidx,
            L2GenericStub {
                from: "l2cleanidx".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::L2invidx,
            L2GenericStub {
                from: "l2invidx".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::L2fetch,
            L2GenericStub {
                from: "l2fetch".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::L2locka,
            L2GenericStub {
                from: "l2locka".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::L2unlocka,
            L2GenericStub {
                from: "l2unlocka".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::L2gunlock,
            L2GenericStub {
                from: "l2gunlock".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::L2gclean,
            L2GenericStub {
                from: "l2gclean".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::L2gcleaninv,
            L2GenericStub {
                from: "l2gcleaninv".to_owned(),
            },
        )
        .unwrap();
}
