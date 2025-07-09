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
use styx_emulator::sync::Mutex;

use pyo3::{pyclass, pymethods, types::PyModuleMethods, PyResult};
use pyo3_stub_gen::derive::*;

use crate::util::module_system::ModuleSystem;

#[gen_stub_pyclass]
#[pyclass(subclass, module = "executor")]
pub struct StyxExecutor(pub Mutex<Option<Box<dyn styx_emulator::core::executor::ExecutorImpl>>>);

#[gen_stub_pyclass]
#[pyclass(extends=StyxExecutor, module = "executor")]
pub struct DefaultExecutor;

#[gen_stub_pymethods]
#[pymethods]
impl DefaultExecutor {
    #[new]
    pub fn new() -> (DefaultExecutor, StyxExecutor) {
        (
            Self,
            StyxExecutor(Mutex::new(Some(Box::new(
                styx_emulator::core::executor::DefaultExecutor,
            )))),
        )
    }
}

//mod gdb;

pub(crate) fn register(m: &mut ModuleSystem) -> PyResult<()> {
    m.register("executor", |m| {
        m.add_class::<StyxExecutor>()?;
        m.add_class::<DefaultExecutor>()?;

        Ok(())
    })?;

    Ok(())
}
