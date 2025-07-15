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
use anyhow::{bail, Context};
use serde_json::Value as JsonValue;
use std::{
    fs::{self, File},
    io::{BufWriter, Write},
};
use styx_sync::lazy_static;
use toml_edit::{DocumentMut, Formatted, Value as TomlValue};

lazy_static! {
    static ref RUST_VERSION_TEST_PATH: String =
        styx_util::resolve_path("util/xtask/test-data/rust-version/rust-version");
    static ref RUST_VERSION_PATH: String = styx_util::resolve_path(".rust-version");
    static ref RUST_TOOLCHAIN_TEST_PATH: String =
        styx_util::resolve_path("util/xtask/test-data/rust-version/rust-toolchain.toml");
    static ref RUST_TOOLCHAIN_PATH: String = styx_util::resolve_path("rust-toolchain.toml");
    static ref DEVCONTAINER_PATH: String = styx_util::resolve_path(".devcontainer.json");
    static ref DEVCONTAINER_TEST_PATH: String =
        styx_util::resolve_path("util/xtask/test-data/devcontainer.json");
}

/// Path to the `.rust-version` file to use,
/// when running in tests it points to
/// `util/xtask/test-data/rust-version/rust-version`
fn rust_version_path() -> String {
    #[cfg(test)]
    {
        RUST_VERSION_TEST_PATH.to_string()
    }
    #[cfg(not(test))]
    {
        RUST_VERSION_PATH.to_string()
    }
}

/// Path to the `rust-toolchain.toml` file to use
/// when running in testsw it points to
/// `util/xtask/test-data/rust-version/rust-toolchain.toml`
fn rust_toolchain_path() -> String {
    #[cfg(test)]
    {
        RUST_TOOLCHAIN_TEST_PATH.to_string()
    }
    #[cfg(not(test))]
    {
        RUST_TOOLCHAIN_PATH.to_string()
    }
}

fn devcontainer_path() -> String {
    #[cfg(test)]
    {
        DEVCONTAINER_TEST_PATH.to_string()
    }
    #[cfg(not(test))]
    {
        DEVCONTAINER_PATH.to_string()
    }
}

/// Entrypoint for rust-version `xtask`
///
/// The high level goal of this is to update the rust version
/// used across the codebase in a single action.
///
/// While rust can do this for rusts' sake in the `rust-toolchain.toml`,
/// all of CI etc needs to react and build containers etc as well.
///
/// As of this writing we only need to update 2 locations:
/// - `rust-toolchain.toml`
/// - `.rust-version` -- all containers / ci etc source from here
pub fn update(target: String, check: bool) -> anyhow::Result<()> {
    let mut changed_files = false;

    // ensure the `rust-toolchain.toml` is up to date
    if update_rust_toolchain_toml(&target, check, rust_toolchain_path())? {
        changed_files = true;
    }

    // ensure the `.rust-vesion` file is up to date
    if update_rust_version(&target, check, rust_version_path())? {
        changed_files = true;
    }

    // ensure the `devcontainer.json`
    if update_devcontainer_json(&target, check, devcontainer_path())? {
        changed_files = true;
    }

    // return error message if anything was/would have
    // been updated
    if changed_files {
        let suffix = if check { "would have " } else { "" };
        bail!(
            "Updating rust-version to {}, {}changed files",
            target,
            suffix,
        )
    } else {
        Ok(())
    }
}

fn update_rust_toolchain_toml(
    target: &str,
    check: bool,
    file_path: String,
) -> anyhow::Result<bool> {
    let contents = fs::read_to_string(file_path.as_str())
        .with_context(|| format!("failed to read file at {file_path}"))?;

    let mut doc = contents
        .parse::<DocumentMut>()
        .with_context(|| "rust-toolchain.toml is invalid toml".to_string())?;

    let mut modified = false;

    let channel = doc["toolchain"]["channel"]
        .as_value_mut()
        .with_context(|| "rust-toolchain.toml does not have a channel listed".to_string())?;

    // now compare the channel against our new target
    match channel {
        TomlValue::String(formatted_string_value) => {
            let string_value = formatted_string_value.value();
            // check if the target is different than the
            // version listed in the channel
            if string_value.trim() != target {
                // content is out of date, propagate that
                // content needs to be updated
                modified = true;

                // if not checking, then we need to update
                // the content of the toml value
                if !check {
                    let mut new_value = Formatted::<String>::new(target.to_owned());
                    new_value
                        .decor_mut()
                        .clone_from(formatted_string_value.decor());

                    // commit the changes
                    *channel = TomlValue::String(new_value);

                    // write the contents back to file
                    fs::write(file_path.as_str(), doc.to_string())?;
                }
            }
        }
        _ => bail!("toolchain toml is formatted incorrectly"),
    }

    // return edit or not
    Ok(modified)
}

/// Writes the `target` to the devcontainer["build"]["args"]["RUST_VERSION"] json object
fn update_devcontainer_json(target: &str, check: bool, file_path: String) -> anyhow::Result<bool> {
    // read the file at `path` into json
    let contents = std::fs::read_to_string(&file_path)?;
    let mut value: JsonValue = serde_json::from_str(&contents)?;

    // get the current value
    let version = value["build"]["args"]["RUST_VERSION"]
        .as_str()
        .expect("devcontainer json is missing ['build']['args']['RUST_VERSION']");

    // are the targets and the real versions different
    if version.ne(target) {
        // if we're supposed to write changes do it
        if !check {
            std::fs::remove_file(&file_path)?;
            // set the `RUST_VERSION` to the new target
            value["build"]["args"]["RUST_VERSION"] = JsonValue::String(target.to_owned());

            // write the object
            let file = File::create(&file_path)?;
            let mut writer = BufWriter::new(file);
            serde_json::to_writer_pretty(&mut writer, &value)?;
            writer.flush()?;
        }
        Ok(true)
    } else {
        Ok(false)
    }
}

/// Updates the `.rust-version` file
///
/// Since the file simply holds the version tag eg:
///
/// ```text
/// 1.82.0
/// ```
///
/// If the stripped version of the file and the `target` are
/// not the same, then it will be changed
fn update_rust_version(target: &str, check: bool, file_path: String) -> anyhow::Result<bool> {
    let contents = fs::read_to_string(file_path.as_str())?;

    // the contents are not the same
    if target.ne(contents.trim()) {
        // we are not checking, we are "doing"
        if !check {
            // write `.rust-version`
            fs::write(file_path.as_str(), format!("{target}\n"))?;
        }

        Ok(true)
    }
    // the contents are the same
    else {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Update this variable after updating rust
    static LIVE_RUST_VERSION: &str = "1.88.0"; // update me

    // This test will fail when we update the rust version,
    // that means its working :smile:
    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_ci_fails_after_rust_update_toolchain() {
        // assert that we always return `false`,
        // meaning that no files would be updated
        assert!(
            !update_rust_toolchain_toml(LIVE_RUST_VERSION, true, RUST_TOOLCHAIN_PATH.to_string())
                .unwrap(),
            "Update this tests' version of rust to assert!",
        );
    }

    // This test will fail when we update the rust version,
    // that means its working :smile:
    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_ci_fails_after_rust_update_version() {
        // assert that we always return `false`,
        // meaning that no files would be updated
        assert!(
            !update_rust_version(LIVE_RUST_VERSION, true, RUST_VERSION_PATH.to_string()).unwrap(),
            "Update this tests' version of rust to assert!",
        );
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_update_toolchain_same() {
        // the test file  has the version `1.55.5`
        let rust_version = "1.55.5";

        // should return `false`, would not change
        assert!(!update_rust_toolchain_toml(rust_version, true, rust_toolchain_path(),).unwrap());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_update_toolchain_diff_patch() {
        // the test file  has the version `1.55.5`
        let rust_version = "1.55.888";

        // should return `true`, would change
        assert!(update_rust_toolchain_toml(rust_version, true, rust_toolchain_path(),).unwrap());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_update_toolchain_diff_minor() {
        // the test file  has the version `1.55.5`
        let rust_version = "1.57777777.5";

        // should return `true`, would change
        assert!(update_rust_toolchain_toml(rust_version, true, rust_toolchain_path(),).unwrap());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_update_toolchain_diff_major() {
        // the test file  has the version `1.55.5`
        let rust_version = "8.55.5";

        // should return `true`, would change
        assert!(update_rust_toolchain_toml(rust_version, true, rust_toolchain_path(),).unwrap());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_update_rust_version_same() {
        // the test file  has the version `1.55.5`
        let rust_version = "1.55.5";

        // should return `false`, would not change
        assert!(!update_rust_version(rust_version, true, rust_version_path(),).unwrap());
    }

    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_update_rust_version_different_patch() {
        // the test file  has the version `1.55.5`
        let rust_version = "1.55.6";

        // should return `true`, would change
        assert!(update_rust_version(rust_version, true, rust_version_path(),).unwrap());
    }
    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_update_rust_version_different_minor() {
        // the test file  has the version `1.55.5`
        let rust_version = "1.56.5";

        // should return `true`, would change
        assert!(update_rust_version(rust_version, true, rust_version_path(),).unwrap());
    }
    #[test]
    #[cfg_attr(miri, ignore)]
    fn test_update_rust_version_different_major() {
        // the test file  has the version `1.55.5`
        let rust_version = "2.55.5";

        // should return `true`, would change
        assert!(update_rust_version(rust_version, true, rust_version_path(),).unwrap());
    }
}
