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
//! Machine definition for the Ppc4xx family.
use styx_emulator::core::core::builder::BuildProcessorImplArgs;
use styx_emulator::cpu::ExecutionReport;
use styx_emulator::prelude::*;

/// Custom Cpu backend for emulation.
#[derive(Debug)]
struct CustomBackend {}

impl Hookable for CustomBackend {
    fn add_hook(
        &mut self,
        _hook: StyxHook,
    ) -> Result<styx_emulator::hooks::HookToken, styx_emulator::hooks::AddHookError> {
        todo!()
    }

    fn delete_hook(
        &mut self,
        _token: styx_emulator::hooks::HookToken,
    ) -> Result<(), styx_emulator::hooks::DeleteHookError> {
        todo!()
    }
}

impl CpuBackend for CustomBackend {
    fn read_register_raw(
        &mut self,
        _reg: ArchRegister,
    ) -> Result<styx_emulator::cpu::arch::RegisterValue, ReadRegisterError> {
        todo!()
    }

    fn write_register_raw(
        &mut self,
        _reg: ArchRegister,
        _value: styx_emulator::cpu::arch::RegisterValue,
    ) -> Result<(), WriteRegisterError> {
        todo!()
    }

    fn architecture(&self) -> &dyn styx_emulator::cpu::arch::ArchitectureDef {
        todo!()
    }

    fn endian(&self) -> ArchEndian {
        todo!()
    }

    fn execute(
        &mut self,
        _mmu: &mut Mmu,
        _event_controller: &mut EventController,
        count: u64,
    ) -> Result<ExecutionReport, UnknownError> {
        println!("executing {count} instructions");
        Ok(ExecutionReport::instructions_complete(count))
    }

    fn stop(&mut self) {
        todo!()
    }

    fn context_save(&mut self) -> Result<(), UnknownError> {
        todo!()
    }

    fn context_restore(&mut self) -> Result<(), UnknownError> {
        todo!()
    }

    fn pc(&mut self) -> Result<u64, UnknownError> {
        todo!()
    }

    fn set_pc(&mut self, _value: u64) -> Result<(), UnknownError> {
        todo!()
    }
}

fn main() -> Result<(), UnknownError> {
    let proc_builder =
        ProcessorBuilder::default().with_builder(|_args: &BuildProcessorImplArgs| {
            let cpu = Box::new(CustomBackend {});

            Ok(ProcessorBundle {
                cpu,
                ..Default::default()
            })
        });

    let mut proc = proc_builder.build()?;

    proc.run(5000)?;

    Ok(())
}
