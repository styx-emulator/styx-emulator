// SPDX-License-Identifier: BSD-2-Clause
mod builder;
pub use builder::ProcessorBuilder;

mod processor_struct;
pub use processor_struct::Processor;

mod processor_state;
pub use processor_state::ProcessorState;

mod emulation_report;
pub use emulation_report::EmulationReport;

mod target_exit_reason;
pub use target_exit_reason::TargetExitReason;

mod target;
pub use target::Target;

use crate::util::module_system::ModuleSystem;
use pyo3::{exceptions::PyAssertionError, types::PyModuleMethods, PyErr, PyResult};

use std::fmt::Debug;

fn convert_machine_err(e: impl Debug) -> PyErr {
    PyAssertionError::new_err(format!("{e:?}"))
}

pub(crate) fn register(m: &mut ModuleSystem) -> PyResult<()> {
    m.register("processor", |m| {
        m.add_class::<builder::ProcessorBuilder>()?;
        m.add_class::<processor_struct::Processor>()?;
        m.add_class::<target::Target>()?;
        m.add_class::<processor_state::ProcessorState>()?;
        Ok(())
    })?;

    Ok(())
}
