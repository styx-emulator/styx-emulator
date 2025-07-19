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
use std::sync::{Arc, Mutex};

use crate::{arch_spec::ArchPcManager, PcodeBackend};

use super::HexagonExecutionHelper;

#[derive(Default, Debug, Clone)]
pub struct HexagonPcManager {
    helper: Option<Arc<Mutex<Box<dyn HexagonExecutionHelper>>>>,
}

impl HexagonPcManager {
    pub fn set_helper(&mut self, helper: Arc<Mutex<Box<dyn HexagonExecutionHelper>>>) {
        self.helper = Some(helper);
    }
}

impl ArchPcManager for HexagonPcManager {
    fn isa_pc(&self) -> u64 {
        let helper = self.helper.as_ref().unwrap().lock().unwrap();
        helper.isa_pc()
    }

    fn set_isa_pc(&mut self, value: u64, backend: &mut PcodeBackend) {
        let mut helper = self.helper.as_mut().unwrap().lock().unwrap();
        helper.set_isa_pc(value, backend)
    }

    fn internal_pc(&self) -> u64 {
        let helper = self.helper.as_ref().unwrap().lock().unwrap();
        helper.internal_pc()
    }

    fn set_internal_pc(&mut self, value: u64, backend: &mut PcodeBackend, _from_branch: bool) {
        let mut helper = self.helper.as_mut().unwrap().lock().unwrap();
        helper.set_internal_pc(value, backend)
    }
}
