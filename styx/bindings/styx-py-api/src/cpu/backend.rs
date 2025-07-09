// SPDX-License-Identifier: BSD-2-Clause
use pyo3::pyclass;
use pyo3_stub_gen::derive::*;
use styx_emulator::core::macros::enum_mirror;

/// All of the supported emulator backends
#[enum_mirror(styx_emulator::core::cpu::Backend)]
#[gen_stub_pyclass_enum]
#[pyclass(eq, module = "cpu")]
#[derive(PartialEq, Debug, Clone)]
pub enum Backend {
    /// A backend which uses PCode to emulate the system
    Pcode,
    /// A backend that uses Unicorn to emulate the system
    Unicorn,
}
