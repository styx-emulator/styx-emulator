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
use crate::{cpu::ExecutionReport, hooks::HookToken};
use log::debug;
use styx_cpu_type::arch::RegisterValue;
use styx_errors::UnknownError;

use crate::{
    event_controller::EventController,
    hooks::{AddHookError, DeleteHookError, Hookable, StyxHook},
    memory::Mmu,
};

use super::CpuBackend;

/// [CpuBackend] and [Hookable] for testing purposes.
///
/// The only implemented functionality here is [CpuBackend::execute()]. All
/// other functions will panic unimplemented.
#[derive(Default, Debug)]
pub struct DummyBackend;

impl CpuBackend for DummyBackend {
    fn read_register_raw(
        &mut self,
        _reg: styx_cpu_type::arch::backends::ArchRegister,
    ) -> Result<RegisterValue, super::backend::ReadRegisterError> {
        unimplemented!()
    }

    fn write_register_raw(
        &mut self,
        _reg: styx_cpu_type::arch::backends::ArchRegister,
        _value: RegisterValue,
    ) -> Result<(), super::backend::WriteRegisterError> {
        unimplemented!()
    }

    fn architecture(&self) -> &dyn styx_cpu_type::arch::ArchitectureDef {
        unimplemented!()
    }

    fn endian(&self) -> styx_cpu_type::ArchEndian {
        unimplemented!()
    }

    fn execute(
        &mut self,
        _mmu: &mut Mmu,
        _event_controller: &mut EventController,
        num_instructions: u64,
    ) -> Result<ExecutionReport, UnknownError> {
        debug!("dummy backend emulating {num_instructions} instructions");

        Ok(ExecutionReport::instructions_complete(num_instructions))
    }

    fn pc(&mut self) -> Result<u64, UnknownError> {
        unimplemented!()
    }

    fn set_pc(&mut self, _value: u64) -> Result<(), UnknownError> {
        unimplemented!()
    }

    fn stop(&mut self) {
        unimplemented!()
    }

    fn context_save(&mut self) -> Result<(), UnknownError> {
        unimplemented!()
    }

    fn context_restore(&mut self) -> Result<(), UnknownError> {
        unimplemented!()
    }
}

impl Hookable for DummyBackend {
    fn add_hook(&mut self, _hook: StyxHook) -> Result<HookToken, AddHookError> {
        Ok(HookToken::new_integer(0))
    }

    fn delete_hook(&mut self, _token: HookToken) -> Result<(), DeleteHookError> {
        Ok(())
    }
}
