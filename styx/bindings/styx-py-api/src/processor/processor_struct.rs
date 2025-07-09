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
use std::ops::Deref;
use std::time::Duration;
use styx_emulator::hooks::StyxHook;

use pyo3::{prelude::*, pyclass, types::PyBytes, Bound};
use pyo3_stub_gen::derive::*;
use styx_emulator::core::cpu::arch::{u40, u80};
use styx_emulator::prelude::{
    anyhow, u20, CpuBackendExt, ExecutionConstraintConcrete, ReadExt, ReadRegisterError,
    WriteRegisterError,
};

use crate::processor::EmulationReport;

#[gen_stub_pyclass]
#[pyclass(module = "processor")]
pub struct Processor(pub styx_emulator::prelude::SyncProcessor);

impl Deref for Processor {
    type Target = styx_emulator::prelude::SyncProcessor;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[gen_stub_pymethods]
#[pymethods]
impl Processor {
    /// read the processor's current state
    #[getter]
    pub fn processor_state(&self) -> PyResult<super::ProcessorState> {
        let state = self.0.state();
        Ok(super::ProcessorState::from(state))
    }

    /// temporarily stop the internal executor
    pub fn pause(&self, py: Python) -> PyResult<()> {
        // need to release gil to let python hooks run while stopping
        py.allow_threads(|| self.0.pause())
            .map_err(super::convert_machine_err)?;
        Ok(())
    }

    /// wait for processor to exit
    pub fn wait_for_stop(&self, py: Python) -> PyResult<EmulationReport> {
        // need to release gil to let python hooks run while stopping
        let report = py
            .allow_threads(|| self.0.wait_for_stop())
            .map_err(super::convert_machine_err)?;
        Ok(EmulationReport(report))
    }

    /// start the processor (nonblocking)
    ///
    /// Optionally supply inst or timeout to only execute for a set amount of instructions or time.
    #[pyo3(signature = (inst=None, timeout=None))]
    pub fn start(&self, inst: Option<u64>, timeout: Option<Duration>) -> PyResult<()> {
        let run_args = ExecutionConstraintConcrete {
            inst_count: inst,
            timeout,
        };

        // it's okay, start() can't hurt you; it doesn't block anymore
        self.0.start(run_args).unwrap();

        Ok(())
    }

    /// write a value to the register
    pub fn write_registers(&self, reg: crate::cpu::Register, value: u128) -> PyResult<()> {
        let reg: styx_emulator::prelude::ArchRegister = reg.into();

        let result = match reg.register_value_enum() {
            styx_emulator::core::cpu::arch::RegisterValue::u8(_) => {
                let value: u8 = value.try_into()?;
                self.0
                    .access(move |core| core.cpu.write_register(reg, value))
            }
            styx_emulator::core::cpu::arch::RegisterValue::u16(_) => {
                let value: u16 = value.try_into()?;
                self.0
                    .access(move |core| core.cpu.write_register(reg, value))
            }
            styx_emulator::core::cpu::arch::RegisterValue::u20(_) => {
                let value: u32 = value.try_into()?;
                let value: u20 = u20::try_new(value).unwrap();
                self.0
                    .access(move |core| core.cpu.write_register(reg, value))
            }
            styx_emulator::core::cpu::arch::RegisterValue::u32(_) => {
                let value: u32 = value.try_into()?;
                self.0
                    .access(move |core| core.cpu.write_register(reg, value))
            }
            styx_emulator::core::cpu::arch::RegisterValue::u40(_) => {
                let value: u64 = value.try_into()?;
                let value: u40 = u40::try_new(value).unwrap();
                self.0
                    .access(move |core| core.cpu.write_register(reg, value))
            }
            styx_emulator::core::cpu::arch::RegisterValue::u64(_) => {
                let value: u64 = value.try_into()?;
                self.0
                    .access(move |core| core.cpu.write_register(reg, value))
            }
            styx_emulator::core::cpu::arch::RegisterValue::u80(_) => {
                let value: u80 = u80::try_new(value).unwrap();
                self.0
                    .access(move |core| core.cpu.write_register(reg, value))
            }
            styx_emulator::core::cpu::arch::RegisterValue::u128(_) => {
                let value: u128 = value;
                self.0
                    .access(move |core| core.cpu.write_register(reg, value))
            }
            styx_emulator::core::cpu::arch::RegisterValue::ArmSpecial(_) => {
                Err(WriteRegisterError::Other(anyhow!(
                    "ARM special registers not implemented yet for python bindings",
                )))
            }
            styx_emulator::core::cpu::arch::RegisterValue::Ppc32Special(_) => {
                Err(WriteRegisterError::Other(anyhow!(
                    "PPC32 special registers not implemented yet for python bindings",
                )))
            }
        };
        result.map_err(super::convert_machine_err)?;
        Ok(())
    }

    /// read the value of a register, currently only integer support
    pub fn read_register(&self, reg: crate::cpu::Register) -> PyResult<u128> {
        let reg: styx_emulator::prelude::ArchRegister = reg.into();

        let result = self.0.access(move |core| {
            let proc = &mut core.cpu;
            match reg.register_value_enum() {
                styx_emulator::core::cpu::arch::RegisterValue::u8(_) => {
                    proc.read_register::<u8>(reg).map(u128::from)
                }
                styx_emulator::core::cpu::arch::RegisterValue::u16(_) => {
                    proc.read_register::<u16>(reg).map(u128::from)
                }
                styx_emulator::core::cpu::arch::RegisterValue::u20(_) => {
                    proc.read_register::<u20>(reg).map(u128::from)
                }
                styx_emulator::core::cpu::arch::RegisterValue::u32(_) => {
                    proc.read_register::<u32>(reg).map(u128::from)
                }
                styx_emulator::core::cpu::arch::RegisterValue::u40(_) => {
                    proc.read_register::<u40>(reg).map(u128::from)
                }
                styx_emulator::core::cpu::arch::RegisterValue::u64(_) => {
                    proc.read_register::<u64>(reg).map(u128::from)
                }
                styx_emulator::core::cpu::arch::RegisterValue::u80(_) => {
                    proc.read_register::<u80>(reg).map(u128::from)
                }
                styx_emulator::core::cpu::arch::RegisterValue::u128(_) => {
                    proc.read_register::<u128>(reg)
                }
                styx_emulator::core::cpu::arch::RegisterValue::ArmSpecial(_) => {
                    Err(ReadRegisterError::Other(anyhow!(
                        "ARM special registers not implemented yet for python bindings"
                    )))
                }
                styx_emulator::core::cpu::arch::RegisterValue::Ppc32Special(_) => {
                    Err(ReadRegisterError::Other(anyhow!(
                        "PPC32 special registers not implemented yet for python bindings"
                    )))
                }
            }
        });

        let value = result.map_err(super::convert_machine_err)?;
        Ok(value)
    }

    /// write the memory staring att [addr], writing all of the bytes in bytes
    pub fn write_code(&self, addr: u64, bytes: Bound<PyBytes>) -> PyResult<()> {
        let bytes = bytes.as_bytes().to_vec();
        self.0
            .access(move |core| core.mmu.write_code(addr, &bytes))
            .map_err(super::convert_machine_err)?;
        Ok(())
    }
    /// write the memory staring att [addr], writing all of the bytes in bytes
    pub fn write_data(&self, addr: u64, bytes: Bound<PyBytes>) -> PyResult<()> {
        let bytes = bytes.as_bytes().to_vec();
        self.0
            .access(move |core| core.mmu.write_data(addr, &bytes))
            .map_err(super::convert_machine_err)?;
        Ok(())
    }

    /// read the memory starting at [base], ending at [base] + [size]
    pub fn read_code<'py>(
        &self,
        py: Python<'py>,
        base: u64,
        size: usize,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let memory = self
            .0
            .access(move |core| core.mmu.code().read(base).vec(size))
            .map_err(super::convert_machine_err)?;
        Ok(PyBytes::new(py, memory.as_slice()))
    }

    /// read the memory starting at [base], ending at [base] + [size]
    pub fn read_data<'py>(
        &self,
        py: Python<'py>,
        base: u64,
        size: usize,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let memory = self
            .0
            .access(move |core| core.mmu.data().read(base).vec(size))
            .map_err(super::convert_machine_err)?;
        Ok(PyBytes::new(py, memory.as_slice()))
    }

    /// get the current program counter
    #[getter]
    pub fn pc(&self) -> PyResult<u64> {
        let pc = self.0.pc().map_err(super::convert_machine_err)?;
        Ok(pc)
    }

    /// set the value of the program counter for the processor
    #[setter]
    pub fn set_pc(&self, pc: u64) -> PyResult<()> {
        self.0.set_pc(pc).map_err(super::convert_machine_err)?;
        Ok(())
    }

    /// get the Inter Process Communication (IPC) port for this processor
    #[getter]
    pub fn ipc_port(&self) -> Option<u16> {
        Some(self.0.ipc_port())
    }

    pub fn add_hook(&self, hook: crate::cpu::Hook) -> PyResult<crate::cpu::HookToken> {
        let hook: StyxHook = hook.into();
        let token = self.0.add_hook(hook).map_err(super::convert_machine_err)?;
        Ok(crate::cpu::HookToken(token))
    }

    pub fn delete_hook(&self, token: crate::cpu::HookToken) -> PyResult<()> {
        self.0
            .delete_hook(token.0)
            .map_err(super::convert_machine_err)?;
        Ok(())
    }
}
