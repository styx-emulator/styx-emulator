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
use pyo3::{
    prelude::*,
    types::{PyBytes, PyString},
};
use pyo3_stub_gen::derive::*;

use crate::util::module_system::ModuleSystem;

#[gen_stub_pyclass]
#[pyclass(module = "peripherals")]
pub struct UartClient(styx_emulator::peripheral_clients::uart::UartClient);

#[gen_stub_pymethods]
#[pymethods]
impl UartClient {
    #[new]
    #[pyo3(signature=(addr, uart_port=None))]
    pub fn new(addr: Bound<PyString>, uart_port: Option<u16>) -> PyResult<Self> {
        let addr = addr.to_str()?.to_string();
        Ok(Self(
            styx_emulator::peripheral_clients::uart::UartClient::new(addr, uart_port),
        ))
    }

    pub fn recv_nonblocking<'py>(
        me: PyRef<'py, Self>,
        py: Python<'py>,
        len: usize,
    ) -> Option<Bound<'py, PyBytes>> {
        me.0.recv_nonblocking(len)
            .map(|bytes| PyBytes::new(py, bytes.as_slice()))
    }

    pub fn send(mut me: PyRefMut<Self>, bytes: Bound<PyBytes>) {
        me.0.send(bytes.as_bytes().to_vec());
    }
}

pub(crate) fn register(m: &mut ModuleSystem) -> PyResult<()> {
    m.register("peripherals", |m| {
        m.add_class::<UartClient>()?;
        Ok(())
    })?;
    Ok(())
}
