// SPDX-License-Identifier: BSD-2-Clause
use pyo3::prelude::*;
use pyo3_stub_gen::StubInfo;
use std::fmt::Write;
use std::fs;
use std::io::Write as IoWrite;
use util::module_system::ModuleSystem;

mod util;

/// CPU based API's including the CPU Backend API, CPU hooks, and memory management apis
pub mod cpu;

/// All of Styx' supported executors
pub mod executor;

/// All of Styx' supported target loaders
pub mod loader;

/// All of Styx' support processor plugins
pub mod plugin;

/// All Processor related API's include the processor builder and c2 API
pub mod processor;

/// ANGR integrations
// pub mod angr;

/// Peripheral bindings
pub mod peripherals;

/// A Python module implemented in Rust.
#[pymodule]
fn styx_emulator(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let mut module_system = ModuleSystem::new(m.clone());
    cpu::register(&mut module_system)?;
    executor::register(&mut module_system)?;
    loader::register(&mut module_system)?;
    plugin::register(&mut module_system)?;
    processor::register(&mut module_system)?;
    // angr::register(&mut module_system)?;
    peripherals::register(&mut module_system)?;
    module_system.update_sys_modules()?;
    Ok(())
}

// Define a function to gather stub information.
pub fn stub_info() -> pyo3_stub_gen::Result<StubInfo> {
    let manifest_dir: &::std::path::Path = env!("CARGO_MANIFEST_DIR").as_ref();
    let mut stub_info = StubInfo::from_pyproject_toml(manifest_dir.join("pyproject.toml"))?;
    // otherwise our root module is named incorrectly
    if let Some(root_module) = stub_info.modules.remove("styx-py-api") {
        stub_info.modules.insert("__init__".to_owned(), root_module);
    }

    Ok(stub_info)
}

pub trait BetterGenerate {
    /// [StubInfo::generate()] modified to be formatted to pass pre-commitm lints.
    fn custom_generate(&self) -> pyo3_stub_gen::Result<()>;
}

impl BetterGenerate for StubInfo {
    fn custom_generate(&self) -> pyo3_stub_gen::Result<()> {
        let python_root = &self.python_root;

        for (name, module) in self.modules.iter() {
            let path = name.replace(".", "/");
            let dest = if module.submodules.is_empty() {
                python_root.join(format!("{path}.pyi"))
            } else {
                python_root.join(path).join("__init__.pyi")
            };

            let dir = dest.parent().expect("Cannot get parent directory");
            if !dir.exists() {
                fs::create_dir_all(dir)?;
            }

            let mut f = fs::File::create(&dest)?;
            // changes here, removes whitespace in comment blank lines and removes trailing newlines (down to single newline)
            let module_str = module.to_string();
            let trimmed_module_str = module_str
                .lines()
                .map(|line| line.trim_end_matches(" "))
                .fold(String::new(), |mut agg, line| {
                    let _ = writeln!(agg, "{line}");
                    agg
                });
            let trimmed_module_str = trimmed_module_str.trim_end();

            writeln!(f, "{}", trimmed_module_str)?;
            log::info!(
                "Generate stub file of a module `{name}` at {dest}",
                dest = dest.display()
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::path::{Path, PathBuf};

    use crate::BetterGenerate;

    /// Checks that the in tree type stubs are correct.
    ///
    /// This is done by generating fresh type stubs in a temporary directory and
    /// checking if any of the files differ.
    #[test]
    fn test_check_stubs_are_up_to_date() {
        let mut stub_info = crate::stub_info().unwrap();
        // temp dir for newly generated stubs to check against
        // this will not be cleaned up if the test fails
        let mut fresh_stub_dir = temp_dir::TempDir::new().unwrap();

        // hacky way to generate stubs in new directory
        stub_info.python_root = fresh_stub_dir.path().to_owned();
        stub_info.custom_generate().unwrap();

        // directory of type stubs in tree
        let tree_stub_dir = [
            &std::env::var("CARGO_MANIFEST_DIR").unwrap(),
            "python",
            "styx_emulator",
        ]
        .iter()
        .collect::<PathBuf>();

        let folder_diff =
            folder_compare::FolderCompare::new(fresh_stub_dir.path(), &tree_stub_dir, &Vec::new())
                .unwrap();

        /// remove prefix from slice of paths
        fn strip_prefix<'a>(path: &Path, files: &'a [PathBuf]) -> Vec<&'a Path> {
            files
                .iter()
                .map(|a| a.strip_prefix(path).unwrap())
                .collect::<Vec<_>>()
        }

        let fix_text =
            "use `cargo run --bin stub_gen` in `styx/bindings/styx-py-api` to update these files";

        // debug logging to help debug
        println!("Changed files: {:?}", folder_diff.changed_files);
        println!("New files: {:?}", folder_diff.new_files);
        println!("Unchanged files: {:?}", folder_diff.unchanged_files);

        // if anything was changed, removed, or added, we ensure the temp dir
        // will not be cleaned up
        if !folder_diff.changed_files.is_empty() || !folder_diff.new_files.is_empty() {
            // disable tmp dir cleanup
            fresh_stub_dir = fresh_stub_dir.dont_delete_on_drop();
        }

        // check if any files were removed in fresh generation
        let rev_folder_diff =
            folder_compare::FolderCompare::new(&tree_stub_dir, fresh_stub_dir.path(), &Vec::new())
                .unwrap();

        // assert things are not different
        if !folder_diff.changed_files.is_empty() {
            let b = strip_prefix(fresh_stub_dir.path(), &folder_diff.changed_files);
            panic!("the following generated pyi files were changed from the git tree:\n{b:?}\n{fix_text}")
        }
        if !folder_diff.new_files.is_empty() {
            let b = strip_prefix(fresh_stub_dir.path(), &folder_diff.new_files);
            panic!("the following generated pyi files were missing from the git tree:\n{b:?}\n{fix_text}")
        }

        // aren't generated and that's okay
        let ignore = ["__init__.py", "py.typed"];
        let filtered_new_files = rev_folder_diff
            .new_files
            .into_iter()
            .filter(|file| !ignore.contains(&file.file_name().unwrap().to_str().unwrap()))
            .collect::<Vec<_>>();
        if !filtered_new_files.is_empty() {
            let b = strip_prefix(&tree_stub_dir, &filtered_new_files);
            panic!("the following generated pyi files were removed from the git tree:\n{b:?}\n{fix_text}")
        }
    }
}
