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
use std::sync::Mutex;

use pyo3::{prelude::PyModuleMethods, pyclass, pymethods, PyResult};
use pyo3_stub_gen::derive::*;

use crate::util::module_system::ModuleSystem;

#[gen_stub_pyclass]
#[pyclass(subclass, unsendable, module = "loader")]
pub struct Loader(pub Mutex<Option<Box<dyn styx_emulator::prelude::Loader + 'static>>>);

impl Loader {
    pub fn new(loader: impl styx_emulator::prelude::Loader + 'static) -> Self {
        let b: Box<dyn styx_emulator::prelude::Loader> = Box::new(loader);
        let inner = Mutex::new(Some(b));
        Self(inner)
    }
}

#[gen_stub_pyclass]
#[pyclass(extends=Loader, module="loader")]
pub struct BlackfinLDRLoader;

#[gen_stub_pymethods]
#[pymethods]
impl BlackfinLDRLoader {
    #[new]
    pub fn new() -> (BlackfinLDRLoader, Loader) {
        let inner = styx_emulator::prelude::BlackfinLDRLoader;
        (Self, Loader::new(inner))
    }
}

#[gen_stub_pyclass]
#[pyclass(extends=Loader, module="loader")]
pub struct ElfLoader;

#[gen_stub_pymethods]
#[pymethods]
impl ElfLoader {
    #[new]
    pub fn new() -> (ElfLoader, Loader) {
        let inner = styx_emulator::prelude::ElfLoader::default();
        (Self, Loader::new(inner))
    }
}

#[gen_stub_pyclass]
#[pyclass(extends=Loader, module="loader")]
pub struct RawLoader;

#[gen_stub_pymethods]
#[pymethods]
impl RawLoader {
    #[new]
    pub fn new() -> (RawLoader, Loader) {
        let inner = styx_emulator::prelude::RawLoader;
        (Self, Loader::new(inner))
    }
}

pub(crate) fn register(m: &mut ModuleSystem) -> PyResult<()> {
    m.register("loader", |m| {
        m.add_class::<Loader>()?;
        m.add_class::<BlackfinLDRLoader>()?;
        m.add_class::<ElfLoader>()?;
        m.add_class::<RawLoader>()?;
        Ok(())
    })?;

    Ok(())
}
