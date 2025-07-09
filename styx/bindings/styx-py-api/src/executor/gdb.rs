// SPDX-License-Identifier: BSD-2-Clause
use std::sync::Arc;

use pyo3::{pyclass, pymethods};

use super::Executor;

#[pyclass(extends=Executor, module = "executor")]
pub struct GdbExecutor;

#[pyclass(eq, module = "executor")]
#[derive(PartialEq)]
pub enum GdbTarget {
    Arm,
    Blackfin,
    Ppc32,
}

#[pymethods]
impl GdbExecutor {
    #[new]
    pub fn new(params: GdbPluginParams) -> (Self, Executor) {
        let params = params.0.clone();

        (Self, Executor(inner))
    }
}

#[pyclass(subclass, frozen, module = "executor")]
pub struct GdbPluginParams(styx_emulator::prelude::gdb::GdbPluginParams);

#[pyclass(extends=GdbPluginParams, module = "executor")]
pub struct TcpGdbPluginParams;
