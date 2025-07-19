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
use log::trace;
use smallvec::SmallVec;
use styx_processor::memory::Mmu;

use crate::{
    arch_spec::{generator_helper::CONTEXT_OPTION_LEN, GeneratorHelp},
    pcode_gen::GeneratePcodeError,
    PcodeBackend,
};
use styx_pcode_translator::ContextOption;

#[derive(Debug, Clone)]
pub struct HexagonGeneratorHelper {
    ctx_opts: Option<Result<SmallVec<[ContextOption; CONTEXT_OPTION_LEN]>, GeneratePcodeError>>,
}

impl Default for HexagonGeneratorHelper {
    fn default() -> Self {
        Self { ctx_opts: None }
    }
}

impl HexagonGeneratorHelper {
    pub fn update_context(
        &mut self,
        opts: Result<SmallVec<[ContextOption; CONTEXT_OPTION_LEN]>, GeneratePcodeError>,
    ) {
        self.ctx_opts = Some(opts);
    }
}

impl GeneratorHelp for HexagonGeneratorHelper {
    fn pre_fetch(
        &mut self,
        _backend: &mut PcodeBackend,
        _mmu: &mut Mmu,
    ) -> Result<SmallVec<[ContextOption; CONTEXT_OPTION_LEN]>, GeneratePcodeError> {
        trace!("generator helper called");
        self.ctx_opts.take().unwrap()
    }
}
