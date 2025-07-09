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
//! Infrastructure to verify the validity and the presence of necessary
//! software licenses.
//!
//! The format of every source file (like this one) should have a license at
//! the very beginning of it using *single line* comments, and should directly
//! copy the content from the `LICENSE` file in the root directory of the
//! repository
//!
//! # Limitations
//! - empty files are currently allowed
//! - limited to certain source file types
//!
use globwalk::GlobWalkerBuilder;
use rayon::prelude::*;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use styx_sync::lazy_static;
use styx_sync::sync::{Arc, Mutex};
use styx_util::styx_root_pathbuf;
use tracing::{debug, error};

lazy_static! {
    static ref EXT_COMMENT_MAP: HashMap<&'static str, &'static str> =
        HashMap::from_iter(vec![("py", "#"), ("rs", "//"), ("dfy", "//")]);
    static ref STYX_ROOT_PATH: PathBuf = styx_root_pathbuf();
    /// Paths under the `styx-emulator` to skip
    static ref PATH_GLOBS: Vec<&'static str> = vec![
        // ignore our test dirs
        "!util/xtask/test-data/",
        // ignore python venv dir
        "!venv/",
        // ignore target dir since thats binary artifacts
        "!target/",
        // ignore data dir (for now)
        "!/data/",
        // node modules
        "!**/node_modules/",
        // direnv data
        "!.direnv/**",
    ];
}

fn contains_license_content(
    file_content: String,
    license_content: &str,
    comment_form: &str,
) -> bool {
    let file_prefix = format!("{comment_form} ");

    // make sure every line in the license is there
    for (license_line, file_line) in license_content.lines().zip(file_content.lines()) {
        // make sure its not the empty line (ending line)
        if license_line.is_empty() {
            continue;
        }

        // the proper form of file_line is as follows:
        // <comment_form> + " " + LICENSE content
        // we just need to see if it is different or not

        // first check if the prefix is correct
        if !file_line.starts_with(&file_prefix) {
            return false;
        }

        // then check if the rest of the line is correct
        if !file_line.get(file_prefix.len()..).unwrap().eq(license_line) {
            return false;
        }
    }

    // no errors, we're good go
    true
}

fn prepend_license(
    file_path: &Path,
    license_content: &str,
    comment_form: &str,
) -> Result<(), std::io::Error> {
    // create formatted license content
    let formatted_license: String = license_content
        .lines()
        // add comment form to each line, if the line is empty, just add the comment form
        .map(|l| {
            if !l.is_empty() {
                format!("{comment_form} {l}")
            } else {
                comment_form.to_string()
            }
        })
        .collect::<Vec<String>>()
        .join("\n");

    // get file content
    let file_content = std::fs::read_to_string(file_path)?;

    // append file content to license content
    let new_file_content = [formatted_license, file_content].join("\n");

    // writeback new file content
    std::fs::write(file_path, new_file_content)
}

struct LicenseChecker {
    root_path: PathBuf,
    bad_paths: Arc<Mutex<Vec<PathBuf>>>,
    license_data: String,
}

impl LicenseChecker {
    fn new(root_path: PathBuf) -> Self {
        debug!("Using root dir: {root_path:?}");

        Self {
            root_path,
            bad_paths: Arc::new(Mutex::new(Vec::new())),
            license_data: String::default(),
        }
    }

    fn set_license_data(&mut self, data: String) {
        self.license_data = data;
    }

    fn check_files(&mut self, check_only: bool, files: Vec<String>) -> Result<(), std::io::Error> {
        // if no files were provided, then we default to using
        // global path globs
        let mut path_globs = if files.is_empty() {
            // the extensions we care about by default
            EXT_COMMENT_MAP
                .keys()
                .map(|e| format!("*.{e}"))
                .collect::<Vec<String>>()
        } else {
            files
        };

        // add the ignore lists
        path_globs.extend(
            PATH_GLOBS
                .iter()
                .map(|&p| p.to_owned())
                .collect::<Vec<String>>(),
        );

        // find and parse .licenseignore files
        let ignore_globs: Vec<String> =
            GlobWalkerBuilder::from_patterns(&self.root_path, &["**/.licenseignore".to_string()])
                .build()?
                // no file access errors
                .filter_map(|e| e.ok())
                // filter out empty .licenseignore files
                .filter(|e| {
                    fs::metadata(e.path())
                        .expect(".licenseignore file should be always valid with metadata")
                        .len()
                        > 0
                })
                .flat_map(|f| {
                    // parse .licenseignore file
                    debug!("parsing {}", f.path().display());
                    let dir = f
                        .path()
                        .parent()
                        .expect("all .licenseignore files should exist in a directory...??")
                        .strip_prefix(&self.root_path)
                        .expect("child must be below parent");
                    let content = fs::read_to_string(f.path())
                        .expect("all empty .licenseignore files should have been filtered out");

                    // qualify all relative .licenseignore paths into absolute
                    // slightly verbose but this syntax makes Rust happy
                    content
                        .lines()
                        .filter(|line| !line.trim().is_empty())
                        .map(|line| {
                            let path = dir.join(line);
                            format!("!{}", path.display())
                        })
                        .collect::<Vec<String>>()
                })
                .collect();

        // add ignore globs to the path globs
        path_globs.extend(ignore_globs);

        debug!("Using path globs: {:?}", path_globs);

        // every file in this collection will have an extension that
        // we care about and are tracking in `EXT_COMMENT_MAP`
        let files_to_search: Vec<_> =
            GlobWalkerBuilder::from_patterns(&self.root_path, &path_globs)
                .build()?
                // no file access errors
                .filter_map(|e| {
                    let file = e.ok();
                    if let Some(ref f) = file {
                        debug!("Collecting file: {f:?}");
                    }
                    file
                })
                // make sure the file has an extension
                .filter(|e| e.path().extension().is_some())
                .collect();

        files_to_search.par_iter().for_each(|source_file| {
            // attempt to get the comment format
            let maybe_comment_form = EXT_COMMENT_MAP.get(
                &source_file
                    .path()
                    .extension()
                    .expect("We already have a valid ext")
                    .to_str()
                    .expect("Ext should have str conversion"),
            );

            // if the extension of the file is one we actually care about,
            // do the thing, else do nothing
            if let Some(&comment_form) = maybe_comment_form {
                // get the content of the source
                if let Ok(file_contents) = std::fs::read_to_string(source_file.path()) {
                    // check if the license content is present in the source file
                    if !contains_license_content(file_contents, &self.license_data, comment_form) {
                        // add to bad paths
                        self.bad_paths
                            .lock()
                            .unwrap()
                            .push(source_file.clone().into_path());
                        if check_only {
                            // done
                            debug!(
                                "Path `{:?}` is missing license, but cannot modify file",
                                source_file.path()
                            );
                        } else {
                            // prepend license
                            if let Err(e) = prepend_license(
                                source_file.path(),
                                &self.license_data,
                                comment_form,
                            ) {
                                error!("Error prepending license: {e}");
                            }
                        }
                    }
                }
            }
        });

        // check if we have any bad paths
        let bad_paths = self.bad_paths.lock().unwrap();
        if bad_paths.len() > 0 {
            for path in bad_paths.iter() {
                eprintln!("Missing License: {}", path.as_os_str().to_str().unwrap());
            }
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Files missing License",
            ));
        }

        Ok(())
    }
}

fn get_license_data() -> Result<String, std::io::Error> {
    let mut license_path = styx_root_pathbuf();
    license_path.push("LICENSE");
    debug!("License path: {:?}", license_path);

    // make sure `LICENSE` is in the top level of the repository
    if !license_path.exists() {
        error!("No LICENSE file present");
        return Err(std::io::Error::new(std::io::ErrorKind::NotFound, "LICENSE"));
    }

    // return the LICENSE content
    std::fs::read_to_string(license_path)
}

pub fn check_licenses(check_only: bool, files: Vec<String>) -> Result<(), std::io::Error> {
    let root_dir = styx_root_pathbuf();
    debug!("root dir: {:?}", root_dir);
    let mut checker = LicenseChecker::new(root_dir.clone());

    // init the LICENSE data
    checker.set_license_data(get_license_data()?);

    // Call + return check function
    checker.check_files(check_only, files)
}

#[cfg(test)]
mod tests {

    use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

    use super::*;

    fn test_data_root() -> PathBuf {
        let mut dir = styx_root_pathbuf();
        dir.push("util");
        dir.push("xtask");
        dir.push("test-data");
        dir.push("license");
        dir
    }

    #[ctor::ctor]
    fn init() {
        // tests run in a multithreaded context, must set tracing once only
        tracing_subscriber::registry()
            .with(fmt::layer())
            .with(EnvFilter::from_default_env())
            .init();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_valid_for_known_extensions() {
        let mut test_dir = test_data_root();
        test_dir.push("valid");
        let mut checker = LicenseChecker::new(test_dir);

        // init the LICENSE data
        checker.set_license_data(get_license_data().expect("BAD LICENSE"));

        // Call + return check function
        let res = checker.check_files(true, Vec::new());
        assert!(res.is_ok(), "Files failed LICENSE checks {:?}", res);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_valid_nested_paths_for_known_extensions() {
        let mut test_dir = test_data_root();
        test_dir.push("nested");
        let mut checker = LicenseChecker::new(test_dir);

        // init the LICENSE data
        checker.set_license_data(get_license_data().expect("BAD LICENSE"));

        // Call + return check function
        let res = checker.check_files(true, Vec::new());
        assert!(res.is_ok(), "Files failed LICENSE checks {:?}", res);
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_invalid_for_known_extensions() {
        let mut test_dir = test_data_root();
        debug!("Test dir: {:?}", test_dir);
        test_dir.push("invalid");
        let mut checker = LicenseChecker::new(test_dir);

        // init the LICENSE data
        checker.set_license_data(get_license_data().expect("BAD LICENSE"));

        // Call + return check function
        let res = checker.check_files(true, Vec::new());
        assert!(res.is_err(), "No files failed LICENSE checks");
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_invalid_but_ignore() {
        let mut test_dir = test_data_root();
        debug!("Test dir: {:?}", test_dir);
        test_dir.push("invalid_but_ignore");
        let mut checker = LicenseChecker::new(test_dir);

        // init the LICENSE data
        checker.set_license_data(get_license_data().expect("BAD LICENSE"));

        // Call + return check function
        let res = checker.check_files(true, Vec::new());
        assert!(
            res.is_ok(),
            "Files failed license checks, but should have been ignored"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_invalid_nested_but_ignore() {
        let mut test_dir = test_data_root();
        debug!("Test dir: {:?}", test_dir);
        test_dir.push("invalid_but_ignore_nested");
        let mut checker = LicenseChecker::new(test_dir);

        // init the LICENSE data
        checker.set_license_data(get_license_data().expect("BAD LICENSE"));

        // Call + return check function
        let res = checker.check_files(true, Vec::new());
        assert!(
            res.is_ok(),
            "Files in the nested directory should have been ignored, but got checked and failed"
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_invalid_outer_but_ignore() {
        let mut test_dir = test_data_root();
        debug!("Test dir: {:?}", test_dir);
        test_dir.push("invalid_but_ignore_outer");
        let mut checker = LicenseChecker::new(test_dir);

        // init the LICENSE data
        checker.set_license_data(get_license_data().expect("BAD LICENSE"));

        // Call + return check function
        let res = checker.check_files(true, Vec::new());
        assert!(
            res.is_ok(),
            "Files in the outer directory should have been ignored, but got checked and failed"
        );
    }

    #[test]
    fn test_modify_file_in_place() {
        let to_prepend = "PREPENDME";
        let data = "IAMDATA";

        let temp_file = styx_util::bytes_to_tmp_file(data.as_bytes());

        prepend_license(temp_file.path(), to_prepend, "//").expect("Failed to prepend data");

        let all_data = std::fs::read_to_string(temp_file.path()).expect("Failed to read temp file");

        let correct_data = format!("// {to_prepend}\n{data}");
        assert_eq!(correct_data, all_data, "Did not modify file correctly");
    }
}
