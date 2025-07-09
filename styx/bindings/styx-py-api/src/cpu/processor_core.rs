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
use std::{sync::Mutex, time::Duration};

use super::Register;
use pyo3::{
    exceptions::PyAssertionError,
    pyclass, pymethods,
    types::{PyBytes, PyBytesMethods, PyString, PyStringMethods},
    Bound, PyErr, PyRef, PyResult, Python,
};
use pyo3_stub_gen::derive::*;
use styx_emulator::{
    core::cpu::arch::{u40, u80},
    prelude::{u20, CpuBackendExt, StyxCpuBackendError, StyxMemoryError},
};

fn backend_err(err: impl ToString) -> PyErr {
    PyAssertionError::new_err(err.to_string())
}

#[gen_stub_pyclass]
#[pyclass(module = "cpu")]
#[derive(Clone)]
pub struct HookToken(pub styx_emulator::hooks::HookToken);

#[gen_stub_pyclass]
#[pyclass(module = "cpu")]
pub struct ProcessorCore(Mutex<styx_emulator::prelude::CoreHandle<'static>>);

impl ProcessorCore {
    pub fn new(inner: styx_emulator::prelude::CoreHandle<'static>) -> Self {
        Self(Mutex::new(inner))
    }
}

#[gen_stub_pymethods]
#[pymethods]
impl ProcessorCore {
    #[getter]
    pub fn pc(me: PyRef<Self>) -> PyResult<u64> {
        me.0.lock().unwrap().pc().map_err(backend_err)
    }

    pub fn read_code<'py>(
        me: PyRef<Self>,
        py: Python<'py>,
        address: u64,
        nbytes: u32,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let mut buf = vec![0; nbytes as usize];
        me.0.lock()
            .unwrap()
            .read_code(address, &mut buf)
            .map_err(backend_err)?;
        Ok(PyBytes::new(py, buf.as_slice()))
    }

    pub fn write_code(me: PyRef<Self>, address: u64, value: Bound<PyBytes>) -> PyResult<()> {
        let bytes = value.as_bytes();
        me.0.lock()
            .unwrap()
            .write_code(address, bytes)
            .map_err(backend_err)?;
        Ok(())
    }

    pub fn read_data<'py>(
        me: PyRef<Self>,
        py: Python<'py>,
        address: u64,
        nbytes: u32,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let mut buf = vec![0; nbytes as usize];
        me.0.lock()
            .unwrap()
            .read_data(address, &mut buf)
            .map_err(backend_err)?;
        Ok(PyBytes::new(py, buf.as_slice()))
    }

    pub fn write_data(me: PyRef<Self>, address: u64, value: Bound<PyBytes>) -> PyResult<()> {
        let bytes = value.as_bytes();
        me.0.lock()
            .unwrap()
            .write_data(address, bytes)
            .map_err(backend_err)?;
        Ok(())
    }

    pub fn read_register(me: PyRef<Self>, register: Bound<PyString>) -> PyResult<Option<u128>> {
        let reg_name = register.to_cow()?;
        let registers = me.0.lock().unwrap().architecture().registers().registers();
        let register = registers
            .iter()
            .find(|reg| reg.name().eq_ignore_ascii_case(&reg_name));
        let Some(register) = register else {
            return Ok(None);
        };

        Ok(Some(read_register_value(
            &mut me.0.lock().unwrap(),
            register,
        )))
    }

    pub fn write_register(
        me: PyRef<Self>,
        register_: Bound<PyString>,
        value: u128,
    ) -> PyResult<()> {
        let reg_name = register_.to_cow()?;
        let registers = me.0.lock().unwrap().architecture().registers().registers();
        let register = registers
            .iter()
            .find(|reg| reg.name().eq_ignore_ascii_case(&reg_name));
        let Some(register) = register else {
            return Err(PyAssertionError::new_err("register does not exist"));
        };
        write_register_value(&mut me.0.lock().unwrap(), register, value);
        Ok(())
    }

    pub fn add_hook(&mut self, hook: crate::cpu::Hook) -> PyResult<HookToken> {
        let token = self
            .0
            .lock()
            .unwrap()
            .cpu
            .add_hook(hook.into())
            .map_err(backend_err)?;
        Ok(HookToken(token))
    }

    pub fn delete_hook(me: PyRef<Self>, token: HookToken) -> PyResult<()> {
        me.0.lock()
            .unwrap()
            .cpu
            .delete_hook(token.0)
            .map_err(backend_err)?;
        Ok(())
    }

    pub fn stop(&self) -> PyResult<()> {
        self.0.lock().unwrap().stop();
        Ok(())
    }
}

pub fn read_register_value(
    cpu: &mut styx_emulator::core::hooks::CoreHandle,
    register: &styx_emulator::core::cpu::arch::CpuRegister,
) -> u128 {
    match register.register_value_enum() {
        styx_emulator::core::cpu::arch::RegisterValue::u8(_) => {
            let value = cpu
                .cpu
                .read_register::<u8>(register.variant())
                .expect("we already checked that this register existed");
            u128::from(value)
        }
        styx_emulator::core::cpu::arch::RegisterValue::u16(_) => {
            let value = cpu
                .cpu
                .read_register::<u16>(register.variant())
                .expect("we already checked that this register existed");
            u128::from(value)
        }
        styx_emulator::core::cpu::arch::RegisterValue::u20(_) => {
            let value = cpu
                .cpu
                .read_register::<u20>(register.variant())
                .expect("we already checked that this register existed");
            u128::from(value)
        }
        styx_emulator::core::cpu::arch::RegisterValue::u32(_) => {
            let value = cpu
                .cpu
                .read_register::<u32>(register.variant())
                .expect("we already checked that this register existed");
            u128::from(value)
        }
        styx_emulator::core::cpu::arch::RegisterValue::u40(_) => {
            let value = cpu
                .cpu
                .read_register::<u40>(register.variant())
                .expect("we already checked that this register existed");
            u128::from(value)
        }
        styx_emulator::core::cpu::arch::RegisterValue::u64(_) => {
            let value = cpu
                .cpu
                .read_register::<u64>(register.variant())
                .expect("we already checked that this register existed");
            u128::from(value)
        }
        styx_emulator::core::cpu::arch::RegisterValue::u80(_) => {
            let value = cpu
                .cpu
                .read_register::<u80>(register.variant())
                .expect("we already checked that this register existed");
            u128::from(value)
        }
        styx_emulator::core::cpu::arch::RegisterValue::u128(_) => cpu
            .cpu
            .read_register::<u128>(register.variant())
            .expect("we already checked that this register existed"),
        styx_emulator::core::cpu::arch::RegisterValue::ArmSpecial(_) => {
            unimplemented!("ARM special registers are not supported yet for python bindings")
        }
        styx_emulator::core::cpu::arch::RegisterValue::Ppc32Special(_) => {
            unimplemented!("PPC32 special registers are not supported yet for python bindings")
        }
    }
}

pub fn write_register_value(
    cpu: &mut styx_emulator::core::hooks::CoreHandle,
    register: &styx_emulator::core::cpu::arch::CpuRegister,
    value: u128,
) {
    let cpu = &mut cpu.cpu;
    match register.register_value_enum() {
        styx_emulator::core::cpu::arch::RegisterValue::u8(_) => {
            let value: u8 = value.try_into().unwrap();
            cpu.write_register(register.variant(), value).unwrap();
        }
        styx_emulator::core::cpu::arch::RegisterValue::u16(_) => {
            let value: u16 = value.try_into().unwrap();
            cpu.write_register(register.variant(), value).unwrap();
        }
        styx_emulator::core::cpu::arch::RegisterValue::u20(_) => {
            let value: u32 = value.try_into().unwrap();
            let value: u20 = u20::try_new(value).unwrap();
            cpu.write_register(register.variant(), value).unwrap();
        }
        styx_emulator::core::cpu::arch::RegisterValue::u32(_) => {
            let value: u32 = value.try_into().unwrap();
            cpu.write_register(register.variant(), value).unwrap();
        }
        styx_emulator::core::cpu::arch::RegisterValue::u40(_) => {
            let value: u64 = value.try_into().unwrap();
            let value: u40 = u40::try_new(value).unwrap();
            cpu.write_register(register.variant(), value).unwrap();
        }
        styx_emulator::core::cpu::arch::RegisterValue::u64(_) => {
            let value: u64 = value.try_into().unwrap();
            cpu.write_register(register.variant(), value).unwrap();
        }
        styx_emulator::core::cpu::arch::RegisterValue::u80(_) => {
            let value: u80 = u80::try_new(value).unwrap();
            cpu.write_register(register.variant(), value).unwrap();
        }
        styx_emulator::core::cpu::arch::RegisterValue::u128(_) => {
            let value: u128 = value;
            cpu.write_register(register.variant(), value).unwrap();
        }
        styx_emulator::core::cpu::arch::RegisterValue::ArmSpecial(_) => {
            unimplemented!("ARM special registers are not supported yet for python bindings")
        }
        styx_emulator::core::cpu::arch::RegisterValue::Ppc32Special(_) => {
            unimplemented!("PPC32 special registers are not supported yet for python bindings")
        }
    }
}
