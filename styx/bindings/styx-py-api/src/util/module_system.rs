// SPDX-License-Identifier: BSD-2-Clause
use std::collections::BTreeMap;

use pyo3::{
    exceptions::PyAssertionError,
    types::{PyAnyMethods, PyModule, PyModuleMethods, PyStringMethods},
    Bound, PyAny, PyResult, Python,
};

struct Node<'py> {
    module: Bound<'py, PyModule>,
    children: BTreeMap<String, Node<'py>>,
}

pub(crate) struct ModuleSystem<'py> {
    root: Node<'py>,
}

impl<'py> ModuleSystem<'py> {
    pub(crate) fn new(root: Bound<'py, PyModule>) -> Self {
        Self {
            root: Node {
                module: root,
                children: Default::default(),
            },
        }
    }

    pub fn register(
        &mut self,
        path: impl AsRef<str>,
        f: impl FnOnce(&Bound<'py, PyModule>) -> PyResult<()>,
    ) -> PyResult<()> {
        let path = path.as_ref();
        let parts = path
            .split(".")
            .map(|part: &str| {
                part.chars()
                    .next()
                    .filter(|c| c.is_ascii_alphabetic() || *c == '_')
                    .ok_or_else(|| PyAssertionError::new_err("invalid module name"))?;
                part.chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
                    .then_some(())
                    .ok_or_else(|| PyAssertionError::new_err("invalid module name"))?;
                Ok(part)
            })
            .collect::<PyResult<Vec<_>>>()?;

        fn get_or_add_child<'me, 'py: 'me>(
            py: Python<'py>,
            node: &'me mut Node<'py>,
            name: &str,
        ) -> PyResult<&'me mut Node<'py>> {
            use std::collections::btree_map::Entry;
            Ok(match node.children.entry(name.to_string()) {
                Entry::Vacant(entry) => {
                    let submodule: Bound<'py, PyModule> = PyModule::new(py, name)?;
                    node.module.add_submodule(&submodule)?;
                    entry.insert(Node {
                        module: submodule,
                        children: Default::default(),
                    })
                }
                Entry::Occupied(entry) => entry.into_mut(),
            })
        }

        let py = self.root.module.py();
        let mut node = &mut self.root;
        for part in parts {
            node = get_or_add_child(py, node, part)?;
        }
        f(&node.module)?;
        Ok(())
    }

    pub(crate) fn update_sys_modules(&self) -> PyResult<()> {
        let py = self.root.module.py();

        let modules = py.import("sys")?.getattr("modules")?;

        let name = self.root.module.name()?;
        let (a, b) = name
            .to_str()?
            .split_once(".")
            .expect("root module name is {name}.{name}");
        assert_eq!(a, b, "names should be the same!");
        let mut path = a.to_string();

        fn register<'py>(
            path: &mut String,
            module: &Node<'py>,
            modules: &Bound<'py, PyAny>,
        ) -> PyResult<()> {
            path.push('.');
            for (name, child) in module.children.iter() {
                path.push_str(name.as_str());

                modules.set_item(&*path, &child.module)?;
                register(path, child, modules)?;

                path.drain(path.len() - name.len()..);
            }
            path.pop().unwrap();
            Ok(())
        }
        register(&mut path, &self.root, &modules)?;

        Ok(())
    }
}
