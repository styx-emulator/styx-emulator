// SPDX-License-Identifier: BSD-2-Clause
use styx_emulator::sync::Mutex;

use pyo3::{prelude::*, pyclass, pymethods};
use pyo3_stub_gen::derive::*;

use crate::util::module_system::ModuleSystem;

#[gen_stub_pyclass]
#[pyclass(subclass, module = "plugin")]
pub struct Plugin(pub Mutex<Option<Box<dyn styx_emulator::core::plugins::UninitPlugin>>>);

#[gen_stub_pyclass]
#[pyclass(extends=Plugin, module="plugin")]
pub struct ProcessorTracingPlugin;

#[gen_stub_pymethods]
#[pymethods]
impl ProcessorTracingPlugin {
    #[new]
    pub fn new() -> (ProcessorTracingPlugin, Plugin) {
        let b: Box<dyn styx_emulator::core::plugins::UninitPlugin> =
            Box::new(styx_emulator::plugins::tracing_plugins::ProcessorTracingPlugin);
        let inner = Mutex::new(Some(b));
        (Self, Plugin(inner))
    }
}
pub(crate) fn register(m: &mut ModuleSystem) -> PyResult<()> {
    m.register("plugin", |m| {
        m.add_class::<Plugin>()?;
        m.add_class::<ProcessorTracingPlugin>()?;
        Ok(())
    })?;

    Ok(())
}
