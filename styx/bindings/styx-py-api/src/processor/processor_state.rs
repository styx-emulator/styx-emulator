// SPDX-License-Identifier: BSD-2-Clause

// TODO this is needed for angr but is not implemented yet

use pyo3::prelude::*;
use pyo3_stub_gen::derive::*;
use styx_emulator::prelude::enum_mirror;

#[enum_mirror(styx_emulator::prelude::ProcessorState)]
#[gen_stub_pyclass_enum]
#[pyclass(eq, module = "processor")]
#[derive(Eq, PartialEq, Debug)]
pub enum ProcessorState {
    Paused,
    Running,
}
