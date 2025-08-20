// SPDX-License-Identifier: BSD-2-Clause
use pyo3::pyclass;
use pyo3_stub_gen::derive::*;
use styx_emulator::prelude::Backend as StyxBackend;

/// All of the supported emulator backends
#[gen_stub_pyclass_enum]
#[pyclass(eq, module = "cpu")]
#[derive(PartialEq, Debug, Clone)]
pub enum Backend {
    /// A backend which uses PCode to emulate the system
    Pcode,
    #[cfg(feature = "unicorn-backend")]
    /// A backend that uses Unicorn to emulate the system
    Unicorn,
}

impl From<Backend> for StyxBackend {
    fn from(value: Backend) -> Self {
        match value {
            Backend::Pcode => StyxBackend::Pcode,
            #[cfg(feature = "unicorn-backend")]
            Backend::Unicorn => StyxBackend::Unicorn,
        }
    }
}
