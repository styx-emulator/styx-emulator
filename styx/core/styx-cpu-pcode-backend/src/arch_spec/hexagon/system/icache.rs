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
use styx_processor::{event_controller::EventController, memory::Mmu};

use crate::{
    arch_spec::ArchSpecBuilder,
    call_other::{CallOtherCallback, CallOtherHandleError},
    PCodeStateChange, PcodeBackend,
};

// Instruction cache

#[derive(Debug)]
pub struct IcacheGenericStub {
    from: String,
}

impl CallOtherCallback for IcacheGenericStub {
    fn handle(
        &mut self,
        _backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
        _ev: &mut EventController,
        _inputs: &[VarnodeData],
        _output: Option<&VarnodeData>,
    ) -> Result<PCodeStateChange, CallOtherHandleError> {
        debug!("icache stub called for {}", self.from);
        Ok(PCodeStateChange::Fallthrough)
    }
}

pub fn add_icache_callothers<S: SlaUserOps<UserOps: FromStr>>(spec: &mut ArchSpecBuilder<S>) {
    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Ictagr,
            IcacheGenericStub {
                from: "ictagr".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Ictagw,
            IcacheGenericStub {
                from: "ictagw".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Icdatar,
            IcacheGenericStub {
                from: "icdatar".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Icdataw,
            IcacheGenericStub {
                from: "icdataw".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Icinva,
            IcacheGenericStub {
                from: "icinva".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Icinvidx,
            IcacheGenericStub {
                from: "icinvidx".to_owned(),
            },
        )
        .unwrap();

    spec.call_other_manager
        .add_handler_other_sla(
            HexagonUserOps::Ickill,
            IcacheGenericStub {
                from: "ickill".to_owned(),
            },
        )
        .unwrap();
}
