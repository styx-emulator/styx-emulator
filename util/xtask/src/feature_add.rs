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
//! Infrastructure to add the specified features to cargo files.
use crate::commands::FeatureAddModes;
use globwalk::{FileType, GlobWalkerBuilder};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use styx_sync::sync::{Arc, Mutex};
use styx_util::resolve_path;
use toml_edit::{value, Array, DocumentMut, Item, Table, Value};
use tracing::{debug, info};

const CARGO_FILE: &str = "Cargo.toml";

/// When we say "workspace", we really only mean these subdirectories.
const WORKSPACE_DIRS: [&str; 4] = ["examples", "extensions", "incubation", "styx"];

/// Takes a full path to a root directory and returns a vector containing the `PathBuf` paths to
/// all cargo files within that root.
fn find_cargo_files(root: String) -> Vec<PathBuf> {
    debug!(
        "Starting search for cargo files at root directory '{:?}'",
        root
    );
    let entries: Vec<_> =
        GlobWalkerBuilder::from_patterns(root.clone(), &["**/Cargo.toml".to_string()])
            .file_type(FileType::FILE)
            .build()
            .unwrap_or_else(|_| panic!("Path contains no `{}` files: [{:?}]", CARGO_FILE, root))
            .filter_map(|e| e.ok())
            .map(|i| i.into_path())
            .collect();
    entries
}

/// Takes a full path to a target cargo file and returns a vector of `PathBuf` paths to all cargo
/// files in the branch (target cargo file and ancestors).
fn find_branch_cargo_files(child_file: String) -> Vec<PathBuf> {
    let mut cargo_files: Vec<PathBuf> = Vec::new();

    // Append the child cargo file itself to our list of files to edit.
    let mut target = PathBuf::from(child_file);
    if !target.exists() {
        panic!("Cargo file does not exist: {:?}", target);
    }
    cargo_files.push(target.clone());

    // Find parent cargo files. Remove the child cargo file and its directory from the search
    // space.
    debug!("Constructing cargo file branch to target file {:?}", target);
    target.pop();
    target.pop();
    for path in target.ancestors() {
        if path.file_name().is_none() {
            break;
        }
        let mut cargo_path = path.to_path_buf();
        cargo_path.push(CARGO_FILE);
        if cargo_path.exists() {
            cargo_files.push(cargo_path);
        }
    }
    cargo_files
}

/// Adds the specified `features` to the toml_edit `Table`.
///
/// A feature string that includes a dash, comma, or colon (without any spaces), is split: the
/// first string is the feature name and the subsequent strings are values to be added to the
/// feature's value array.
fn add_features_to_table(table: &mut Table, features: &Vec<String>) {
    for feature in features {
        let mut feature_strings: Vec<&str> = feature.split(&['-', ',', ':']).collect();
        let feature = feature_strings.remove(0);
        match table.get_mut(feature) {
            None => {
                table.insert(feature, value(Array::from_iter(feature_strings)));
            }
            Some(Item::Value(Value::Array(arr))) => {
                arr.extend(feature_strings);
            }
            Some(_) => {
                panic!("Malformed features table");
            }
        }
    }
}

/// Represents the features to be added and the corresponding target cargo files.
pub struct FeatureAdd {
    /// Cargo files to be modified.
    cargo_files: Arc<Mutex<Vec<PathBuf>>>,
    /// Features to be added to the cargo files.
    features: Vec<String>,
}

impl FeatureAdd {
    pub fn new(mode: FeatureAddModes, files: Vec<String>, features: Vec<String>) -> Self {
        let mut resolved_mode = mode;
        assert!(
            !features.is_empty(),
            "At least one feature must be specified."
        );
        if !files.is_empty() {
            resolved_mode = FeatureAddModes::Branches;
        }
        let mut cargo_files: Vec<PathBuf> = Vec::new();
        match resolved_mode {
            FeatureAddModes::Workspace => {
                cargo_files.push(PathBuf::from(resolve_path(CARGO_FILE)));
                for dir in WORKSPACE_DIRS {
                    let root = resolve_path(dir);
                    cargo_files.extend(find_cargo_files(root));
                }
            }
            FeatureAddModes::Styx => {
                let root = resolve_path("styx");
                cargo_files.extend(find_cargo_files(root));
            }
            FeatureAddModes::Branches => {
                for file in files {
                    let mut target = PathBuf::from(&file);
                    if !file.ends_with(CARGO_FILE) {
                        target.push(CARGO_FILE);
                    }
                    let full_path = match target.canonicalize() {
                        Ok(buf) => buf.as_path().display().to_string(),
                        Err(_) => panic!("Failed to find path: {target:?}"),
                    };
                    cargo_files.extend(find_branch_cargo_files(full_path));
                }
            }
        }
        debug!("cargo files: {:#?}", cargo_files);

        Self {
            cargo_files: Arc::new(Mutex::new(cargo_files)),
            features,
        }
    }

    /// Modifies the target cargo files with the desired features.
    pub fn add_features(&self) -> Result<(), std::io::Error> {
        for cargo_file in self.cargo_files.lock().unwrap().iter() {
            debug!("Adding features to: {:#?}", cargo_file);
            let contents = fs::read_to_string(cargo_file).expect("missing `Cargo.toml` file");
            let mut doc = contents.parse::<DocumentMut>().expect("invalid doc");
            // A `features` section is not allowed for a virtual manifest. A virtual manifest is a
            // Cargo.toml file that only describes a workspace, and does not include a package.
            if doc.get_mut("workspace").is_some() && doc.get_mut("package").is_none() {
                info!("Skipping virtual manifest {:?}", cargo_file);
                continue;
            }
            match doc.get_mut("features") {
                Some(features_section) => {
                    // A features section exists in the cargo file, so we just add our features to the
                    // table.
                    match features_section {
                        Item::Table(feature_table) => {
                            add_features_to_table(feature_table, &self.features);
                        }
                        _ => {
                            panic!("features section is not a table");
                        }
                    }
                }
                None => {
                    // There is no features section in the cargo file, so we must create one.
                    let mut feature_table = Table::default();
                    add_features_to_table(&mut feature_table, &self.features);
                    doc.insert("features", Item::Table(feature_table));
                }
            }
            let mut output_file = fs::File::create(cargo_file)?;
            output_file.write_all(doc.to_string().as_bytes())?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Seek};
    use std::path::Path;
    use temp_dir::TempDir;
    use tempfile::NamedTempFile;
    use test_case::test_case;

    const CARGO_FILE_CONTENTS: &str = r#"
[package]
name = "xtask"
edition.workspace = true
rust-version.workspace = true
version.workspace = true

[lints]
workspace = true

# See more keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html

[dependencies]
styx-util = { workspace = true }
styx-sync = { workspace = true }
anyhow = { workspace = true }
globwalk = { workspace = true }
rayon = { workspace = true }
clap = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
strum_macros = { workspace = true }
toml_edit = { workspace = true }
styx-workspace-hack = { version = "0.1", path = "../../styx/workspace-hack" }

[dev-dependencies]
ctor = "0.2.8"
tempdir = { workspace = true }
"#;

    const CARGO_FILE_CONTENTS_MODIFIED: &str = r#"
[package]
name = "xtask"
edition.workspace = true
rust-version.workspace = true
version.workspace = true

[lints]
workspace = true

# See more keys and their definitions at https://doc.rust-lang.org/cargo/reference/manifest.html

[dependencies]
styx-util = { workspace = true }
styx-sync = { workspace = true }
anyhow = { workspace = true }
globwalk = { workspace = true }
rayon = { workspace = true }
clap = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
strum_macros = { workspace = true }
toml_edit = { workspace = true }
styx-workspace-hack = { version = "0.1", path = "../../styx/workspace-hack" }

[dev-dependencies]
ctor = "0.2.8"
tempdir = { workspace = true }

[features]
foo = []
bar = []
baz = []
"#;

    /// Creates a new cargo file in the specified directory.
    fn create_cargo_file(
        dir: &Path,
        created_files: Option<&mut Vec<PathBuf>>,
    ) -> Result<(), std::io::Error> {
        let mut cargo_file = dir.to_path_buf();

        // make the Cargo file in the directory
        cargo_file.push(CARGO_FILE);
        fs::File::create(&cargo_file)?;

        if let Some(files) = created_files {
            files.push(cargo_file);
        }

        Ok(())
    }

    fn create_sub_dir(dir: &mut PathBuf, sub_dir: &str) -> Result<(), std::io::Error> {
        dir.push(sub_dir);
        fs::create_dir(dir)?;
        Ok(())
    }

    struct TestFiles {
        /// Full test path:
        /// - For general tests, this will point at the top-level crate.
        /// - For branch tests, this will point to a cargo file several crates deep.
        pub target: String,
        /// List of paths to all cargo files to be discovered in the test.
        /// - For general tests, this will include all cargo files created.
        /// - For branch tests, this will only include the desired branch of cargo files.
        pub master_list: Vec<PathBuf>,
    }

    impl Drop for TestFiles {
        fn drop(&mut self) {
            // Remove all created files.
            for file in &self.master_list {
                if file.exists() {
                    fs::remove_file(file).unwrap_or_else(|_| {
                        panic!("Failed to remove test file: {:?}", file);
                    });
                }
            }

            // Remove the root directory.
            let root_dir = PathBuf::from(&self.target);
            if root_dir.exists() {
                fs::remove_dir_all(root_dir.clone()).unwrap_or_else(|_| {
                    panic!("Failed to remove test directory: {:?}", root_dir);
                });
            }
        }
    }

    impl TestFiles {
        fn new(branch: bool) -> Self {
            let mut master_list: Vec<PathBuf> = Vec::new();

            // Create test directory.
            let mut root_dir = TempDir::new().unwrap();
            let mut tmp_dir = root_dir.path().to_path_buf();
            info!("Created test directory: {:?}", root_dir.path());

            // we manually remove everything when done
            root_dir = root_dir.dont_delete_on_drop();

            // Create top-level cargo file.
            create_cargo_file(&tmp_dir, Some(&mut master_list)).unwrap();

            // Create top-level subdirectory with a cargo file.
            create_sub_dir(&mut tmp_dir, "foo").unwrap();
            create_cargo_file(&tmp_dir, Some(&mut master_list)).unwrap();

            // Create next subdirectory with a cargo file.
            create_sub_dir(&mut tmp_dir, "bar").unwrap();
            create_cargo_file(&tmp_dir, Some(&mut master_list)).unwrap();

            // Create next subdirectory with a cargo file.
            create_sub_dir(&mut tmp_dir, "baz").unwrap();
            create_cargo_file(&tmp_dir, Some(&mut master_list)).unwrap();

            // Create alternate top-level subdirectory structure.
            // We do not add these cargo files to the master list if we are testing for a branch
            // (parent-child only) of cargo files.
            let mut tmp_dir = root_dir.path().to_path_buf();
            create_sub_dir(&mut tmp_dir, "herp").unwrap();
            create_cargo_file(&tmp_dir, (!branch).then_some(&mut master_list)).unwrap();
            create_sub_dir(&mut tmp_dir, "derp").unwrap();
            create_cargo_file(&tmp_dir, (!branch).then_some(&mut master_list)).unwrap();
            create_sub_dir(&mut tmp_dir, "yee").unwrap();
            create_cargo_file(&tmp_dir, (!branch).then_some(&mut master_list)).unwrap();
            create_sub_dir(&mut tmp_dir, "haw").unwrap();
            create_cargo_file(&tmp_dir, (!branch).then_some(&mut master_list)).unwrap();

            master_list.sort();

            let target: PathBuf = match branch {
                true => master_list.last().unwrap().to_owned(),
                false => root_dir.path().to_path_buf(),
            };
            let target: String = match target.canonicalize() {
                Ok(buf) => buf.into_os_string().into_string().unwrap(),
                Err(_) => panic!("Failed to find path: {target:?}"),
            };
            Self {
                target,
                master_list,
            }
        }
    }

    #[test_case(false; "find all cargo files")]
    #[test_case(true; "find all cargo files in branch")]
    fn test_finding_cargo_files(branch: bool) {
        let test_files = TestFiles::new(branch);

        let mut found_files: Vec<PathBuf>;
        if branch {
            found_files = find_branch_cargo_files(test_files.target.clone());
        } else {
            found_files = find_cargo_files(test_files.target.clone());
        }
        found_files.sort();
        assert_eq!(test_files.master_list, found_files);
    }

    #[test]
    fn test_add_features_file() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(CARGO_FILE_CONTENTS.as_bytes()).unwrap();
        let feature_add = FeatureAdd {
            cargo_files: Arc::new(Mutex::new(vec![file.path().into()])),
            features: ["foo", "bar", "baz"]
                .iter()
                .map(|s| s.to_string())
                .collect(),
        };
        assert!(feature_add.add_features().is_ok());

        let mut result = String::new();
        assert!(file.rewind().is_ok());
        assert!(file.read_to_string(&mut result).is_ok());
        assert_eq!(result.trim(), CARGO_FILE_CONTENTS_MODIFIED.trim());
    }
}
