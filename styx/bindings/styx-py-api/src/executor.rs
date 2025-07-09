// SPDX-License-Identifier: BSD-2-Clause
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
