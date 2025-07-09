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
use styx_pcode_translator::sla::{Aarch64, Aarch64UserOps};

use crate::arch_spec::{
    aarch64::call_other::{
        NeonAddvCallother, NeonBifCallother, NeonBitCallother, NeonBslCallother,
        NeonCmtestCallother, NeonCntCallother, NeonFcmeqCallother, NeonFcmgeCallother,
        NeonFcmgtCallother, NeonFcmleCallother, NeonFcmltCallother, NeonFminnmCallother,
        NeonRev64Callother,
    },
    ArchSpecBuilder,
};

pub fn build() -> ArchSpecBuilder<Aarch64> {
    let mut spec = ArchSpecBuilder::default();

    spec.set_pc_manager(super::StandardPcManager::default().into());

    spec.set_generator(super::StandardGeneratorHelper.into());

    spec.call_other_manager
        .add_handler(Aarch64UserOps::NeonAddv, NeonAddvCallother)
        .unwrap();
    spec.call_other_manager
        .add_handler(Aarch64UserOps::NeonCnt, NeonCntCallother)
        .unwrap();
    spec.call_other_manager
        .add_handler(Aarch64UserOps::NeonBif, NeonBifCallother)
        .unwrap();
    spec.call_other_manager
        .add_handler(Aarch64UserOps::NeonBit, NeonBitCallother)
        .unwrap();
    spec.call_other_manager
        .add_handler(Aarch64UserOps::NeonBsl, NeonBslCallother)
        .unwrap();
    spec.call_other_manager
        .add_handler(Aarch64UserOps::NeonRev64, NeonRev64Callother)
        .unwrap();
    spec.call_other_manager
        .add_handler(Aarch64UserOps::NeonCmtst, NeonCmtestCallother)
        .unwrap();
    spec.call_other_manager
        .add_handler(Aarch64UserOps::NeonFcmeq, NeonFcmeqCallother)
        .unwrap();
    spec.call_other_manager
        .add_handler(Aarch64UserOps::NeonFcmle, NeonFcmleCallother)
        .unwrap();
    spec.call_other_manager
        .add_handler(Aarch64UserOps::NeonFcmlt, NeonFcmltCallother)
        .unwrap();
    spec.call_other_manager
        .add_handler(Aarch64UserOps::NeonFcmge, NeonFcmgeCallother)
        .unwrap();
    spec.call_other_manager
        .add_handler(Aarch64UserOps::NeonFcmgt, NeonFcmgtCallother)
        .unwrap();
    spec.call_other_manager
        .add_handler(Aarch64UserOps::NeonFminnm, NeonFminnmCallother)
        .unwrap();

    spec
}
