// SPDX-License-Identifier: BSD-2-Clause
use pyo3::prelude::*;
use pyo3_stub_gen::derive::*;
use styx_emulator::prelude as styx;

use crate::processor::TargetExitReason;

#[gen_stub_pyclass]
#[pyclass(module = "processor")]
pub struct EmulationReport(pub(crate) styx::EmulationReport);

#[gen_stub_pymethods]
#[pymethods]
impl EmulationReport {
    #[getter]
    pub fn instructions(&self) -> u64 {
        self.0.instructions()
    }

    #[getter]
    pub fn exit_reason(&self) -> TargetExitReason {
        self.0.exit_reason.clone().into()
    }

    #[getter]
    pub fn is_fatal(&self) -> bool {
        self.0.is_fatal()
    }

    #[getter]
    pub fn is_stop_request(&self) -> bool {
        self.0.is_stop_request()
    }

    /// Total wall clock time spent in emulation, in seconds.
    #[getter]
    pub fn wall_time(&self) -> f64 {
        self.0.wall_time.as_secs_f64()
    }
}
