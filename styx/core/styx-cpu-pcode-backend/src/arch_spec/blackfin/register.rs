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
use styx_cpu_type::arch::backends::ArchRegister;
use styx_errors::anyhow::Context;

use crate::{
    memory::sized_value::SizedValue,
    pcode_gen::RegisterTranslator,
    register_manager::{RegisterCallback, RegisterHandleError},
    PcodeBackend,
};

/// Handler for A0 and A1 to explicitly convert size from sla specs 8 bytes to styx's expected 5
/// bytes.
#[derive(Debug)]
pub(super) struct AnalogRegister;
impl RegisterCallback for AnalogRegister {
    fn read(
        &mut self,
        register: ArchRegister,
        cpu: &mut PcodeBackend,
    ) -> Result<SizedValue, RegisterHandleError> {
        let varnode = cpu.pcode_generator.get_register_expect(&register)?;

        let read_value = cpu
            .space_manager
            .read(varnode)
            .with_context(|| format!("failed to read {register:?} from {varnode:?}"))?;

        // analog registers are actually 40 bytes
        let read_value = read_value.resize(5);

        Ok(read_value)
    }

    fn write(
        &mut self,
        register: ArchRegister,
        value: SizedValue,
        cpu: &mut PcodeBackend,
    ) -> Result<(), RegisterHandleError> {
        let varnode = cpu.pcode_generator.get_register_expect(&register)?.clone();

        // sla spec size is 8 bytes
        // size 5 -> 8 loses no data
        let value = value.resize(8);

        cpu.space_manager
            .write(&varnode, value)
            .with_context(|| format!("failed to write {register:?} at {varnode:?}"))?;
        Ok(())
    }
}
