// SPDX-License-Identifier: BSD-2-Clause
use anyhow::{bail, Context};
use convert_case::{Case, Casing};
use std::{fs, path::Path};
use styx_sync::lazy_static;

lazy_static! {
    static ref RFC_DIR: String = styx_util::resolve_path("docs/source/rfcs");
    static ref TEST_FIRST: String = styx_util::resolve_path("util/xtask/test-data/rfc/test-first");
    static ref TEST_ONE: String = styx_util::resolve_path("util/xtask/test-data/rfc/test-one");
    static ref TEST_VERY_LONG: String =
        styx_util::resolve_path("util/xtask/test-data/rfc/test-very-long");
}

/// Generate a new RFC Template file for the
/// documentation site
pub fn execute(name: String) -> anyhow::Result<()> {
    generate_adr(RFC_DIR.as_str(), name)
}

/// Given a path to a directory, emit a new template file
/// with the provided name
/// - in kebab
/// - they are restructured text files (.rst)
fn generate_adr(base: &str, name: String) -> anyhow::Result<()> {
    // calculate dir path
    let root = Path::new(base);

    // make directory if it does not exist
    if !root.exists() {
        fs::create_dir_all(root).with_context(|| format!("Failed to make dirs for {root:?}"))?;
    }

    // make sure the root is a directory and not a file
    // canonicalize to resolve symlink
    if !root.canonicalize()?.is_dir() {
        bail!("{:?} is not a directory", root);
    }

    // get the next number
    let number = next_file_number(root);
    // form the new file name
    let file_name = format!("{}-{}.rst", number, name.to_case(Case::Kebab));
    tracing::info!("Please add {file_name} to ./docs/source/rfcs.rst");

    // generate the new content
    let content = content_template(name, number);

    // write the file
    fs::write(root.join(file_name), content).with_context(|| "failed to write new RFC template")
}

fn next_file_number(path: &Path) -> u32 {
    assert!(path.is_dir());
    // list directory
    let mut files: Vec<String> = fs::read_dir(path)
        .expect("failed to read RFC dir")
        // ignore read errors
        .filter_map(|p| p.ok())
        .map(|p| p.file_name().into_string().unwrap())
        .collect();

    // sort
    files.sort();

    //
    // Now we actually parse out the names
    //

    // split each name for the first kebab `{}-`
    files.iter().filter_map(|name|
          name.split('-').next()
    )
    // turn into Option<u32>
    .filter_map(|maybe_number_str|{
        maybe_number_str.parse::<u32>().ok()
    })
    // get the max, if there are none then we need to return `1`,
    // so the max is currently "0"
    .max().unwrap_or(0)
    // return max + 1
     + 1
}

fn content_template(name: String, number: u32) -> String {
    let camel_case_name = name.to_case(Case::Snake);
    let title_name = name.to_case(Case::Title);
    let titled_line = format!("{number}. {title_name}");
    let title_under: String = vec!['#'; titled_line.len()].into_iter().collect();
    let section_under: String = vec!['='; title_name.len()].into_iter().collect();

    format!(
        r#"
.. _{camel_case_name}_rfc:

{titled_line}
{title_under}

{title_name}
{section_under}

Status: Draft

Summary
=======

Motivation
==========

Details
=======

Drawbacks/Alternatives
======================

Future Work
===========
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(miri, ignore)]
    fn generate_first() {
        let requested_name = "hello name".to_owned();
        let correct_name = "1-hello-name.rst".to_owned();
        let root_dir = TEST_FIRST.as_str();
        let dir_root = Path::new(root_dir);
        let file_path = dir_root.join(correct_name);
        let correct_content = content_template(requested_name.clone(), 1);

        // ensure the file does not exist
        assert!(!file_path.exists());
        // run
        assert!(generate_adr(root_dir, requested_name).is_ok());
        // ensure the file exists
        assert!(file_path.exists());
        // ensure the content is correct
        assert_eq!(
            std::fs::read_to_string(file_path.clone()).unwrap(),
            correct_content
        );
        // remove file
        std::fs::remove_file(file_path).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn generate_one() {
        let requested_name = "hello name".to_owned();
        let correct_name = "2-hello-name.rst".to_owned();
        let root_dir = TEST_ONE.as_str();
        let dir_root = Path::new(root_dir);
        let file_path = dir_root.join(correct_name);
        let correct_content = content_template(requested_name.clone(), 2);

        // ensure the file does not exist
        assert!(!file_path.exists());
        // run
        assert!(generate_adr(root_dir, requested_name).is_ok());
        // ensure the file exists
        assert!(file_path.exists());
        // ensure the content is correct
        assert_eq!(
            std::fs::read_to_string(file_path.clone()).unwrap(),
            correct_content
        );
        // remove file
        std::fs::remove_file(file_path).unwrap();
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn generate_very_long() {
        let requested_name = "this is a not really long name".to_owned();
        let correct_name = "2-this-is-a-not-really-long-name.rst".to_owned();
        let root_dir = TEST_VERY_LONG.as_str();
        let dir_root = Path::new(root_dir);
        let file_path = dir_root.join(correct_name);
        let correct_content = content_template(requested_name.clone(), 2);

        // ensure the file does not exist
        assert!(!file_path.exists());
        // run
        assert!(generate_adr(root_dir, requested_name).is_ok());
        // ensure the file exists
        assert!(file_path.exists());
        // ensure the content is correct
        assert_eq!(
            std::fs::read_to_string(file_path.clone()).unwrap(),
            correct_content
        );
        // remove file
        std::fs::remove_file(file_path).unwrap();
    }
}
