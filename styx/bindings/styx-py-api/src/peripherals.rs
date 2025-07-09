// SPDX-License-Identifier: BSD-2-Clause
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
