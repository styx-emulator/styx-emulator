// SPDX-License-Identifier: BSD-2-Clause
use pyo3::prelude::*;
use pyo3_stub_gen::derive::{gen_stub_pyclass, gen_stub_pyclass_enum};

use styx_emulator::hooks as styx;

#[gen_stub_pyclass]
#[pyclass(eq, module = "cpu")]
#[derive(PartialEq, Eq)]
pub struct MemFaultData {
    operation: MemFaultDataType,
    data: Option<Vec<u8>>,
}

#[pymethods]
impl MemFaultData {
    #[getter]
    fn operation(&self) -> PyResult<MemFaultDataType> {
        Ok(self.operation)
    }

    #[getter]
    fn data(&self) -> PyResult<Option<&[u8]>> {
        Ok(self.data.as_deref())
    }
}

#[gen_stub_pyclass_enum]
#[pyclass(eq, module = "cpu")]
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum MemFaultDataType {
    Read,
    Write,
}

impl From<styx::MemFaultData<'_>> for MemFaultData {
    fn from(value: styx::MemFaultData) -> Self {
        match value {
            styx::MemFaultData::Read => Self {
                operation: MemFaultDataType::Read,
                data: None,
            },
            styx::MemFaultData::Write { data } => Self {
                operation: MemFaultDataType::Write,
                data: Some(data.to_vec()),
            },
        }
    }
}
