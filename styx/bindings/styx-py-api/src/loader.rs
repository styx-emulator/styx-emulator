// SPDX-License-Identifier: BSD-2-Clause
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
