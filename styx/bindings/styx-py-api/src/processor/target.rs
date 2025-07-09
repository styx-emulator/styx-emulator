// SPDX-License-Identifier: BSD-2-Clause
use pyo3::prelude::*;
use pyo3_stub_gen::derive::*;

/// A CPU that Styx supports emulation for.
#[gen_stub_pyclass_enum]
#[pyclass(eq, module = "processor")]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Target {
    Bf512,
    CycloneV,
    Kinetis21,
    Mpc8xx,
    Ppc4xx,
    Raw,
    Stm32f107,
    Stm32f405,
    SuperH2A,
}
