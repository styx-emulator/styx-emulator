// SPDX-License-Identifier: BSD-2-Clause
//! Scripted CPU backend for driving executors down exit paths on demand.

use styx_errors::UnknownError;

use crate::event_controller::EventController;
use crate::memory::Mmu;

#[derive(Debug, Clone)]
pub struct ScriptedParams {
    /// During this round, return the `exit_reason`.
    pub exit_on_round: u32,
    /// If Some, the exited round will report n completed instructions.
    pub partial_count: Option<u64>,
    /// ExitReason to give on exit round.
    pub exit_reason: styx_cpu_type::TargetExitReason,
}

/// A [`crate::cpu::CpuBackend`] wrapper that returns a configurable exit reason on a chosen round.
/// For all other rounds it behaves like [`DummyBackend`](crate::cpu::DummyBackend) (`InstructionCountComplete`).
///
/// Only `execute`, `stop`, `context_save`/`context_restore`, `pc`/`set_pc`, and `endian`
/// are exercised by the harness. `read_register_raw`, `write_register_raw`, `architecture`,
/// and `Hookable::add_hook` / `Hookable::delete_hook` panic via `unimplemented!()`.
/// A panic from any of these means the executor loop started calling a code path
/// the harness did not anticipate, not that this helper itself is buggy.
#[derive(Debug)]
pub struct ScriptedBackend {
    /// Current round we are on.
    pub round: u32,
    pub params: ScriptedParams,
}

impl ScriptedBackend {
    pub fn new(params: ScriptedParams) -> Self {
        Self { round: 0, params }
    }
}

impl crate::hooks::Hookable for ScriptedBackend {
    fn add_hook(
        &mut self,
        _hook: crate::hooks::StyxHook,
    ) -> Result<crate::hooks::HookToken, crate::hooks::AddHookError> {
        unimplemented!()
    }

    fn delete_hook(
        &mut self,
        _token: crate::hooks::HookToken,
    ) -> Result<(), crate::hooks::DeleteHookError> {
        unimplemented!()
    }
}

impl crate::cpu::CpuBackend for ScriptedBackend {
    fn read_register_raw(
        &mut self,
        _reg: styx_cpu_type::arch::backends::ArchRegister,
    ) -> Result<styx_cpu_type::arch::RegisterValue, crate::cpu::ReadRegisterError> {
        unimplemented!()
    }

    fn write_register_raw(
        &mut self,
        _reg: styx_cpu_type::arch::backends::ArchRegister,
        _value: styx_cpu_type::arch::RegisterValue,
    ) -> Result<(), crate::cpu::WriteRegisterError> {
        unimplemented!()
    }

    fn architecture(&self) -> &dyn styx_cpu_type::arch::ArchitectureDef {
        unimplemented!()
    }

    fn endian(&self) -> styx_cpu_type::ArchEndian {
        styx_cpu_type::ArchEndian::LittleEndian
    }

    fn execute(
        &mut self,
        _mmu: &mut Mmu,
        _event_controller: &mut EventController,
        count: u64,
    ) -> Result<crate::cpu::ExecutionReport, UnknownError> {
        self.round += 1;
        if self.round == self.params.exit_on_round {
            Ok(crate::cpu::ExecutionReport::new(
                self.params.exit_reason.clone(),
                self.params.partial_count.unwrap_or(count),
            ))
        } else {
            Ok(crate::cpu::ExecutionReport::instructions_complete(count))
        }
    }

    fn stop(&mut self) {}

    fn context_save(&mut self) -> Result<(), UnknownError> {
        Ok(())
    }

    fn context_restore(&mut self) -> Result<(), UnknownError> {
        Ok(())
    }

    fn pc(&mut self) -> Result<u64, UnknownError> {
        Ok(0)
    }

    fn set_pc(&mut self, _value: u64) -> Result<(), UnknownError> {
        Ok(())
    }
}
