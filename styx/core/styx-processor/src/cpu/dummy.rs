// SPDX-License-Identifier: BSD-2-Clause
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
