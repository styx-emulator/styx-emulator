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
use std::fs;
use std::process::Command;
use styx_util::resolve_path;
use toml_edit::{DocumentMut, Formatted, Value as TomlValue};

const TAG_PROMPT: &str = r#"
## Make a new git tag once this commit is merged into main:

git tag -F CHANGELOG.md v{version} origin/main

~alternatively~

only put the new changelog contents in the tag message:

echo "$(git show HEAD -- ./CHANGELOG.md | grep '^+' | grep -v '^+++' | sed 's/^+//')" > tag-msg
git tag -F tag-msg v{version} origin/main

finally, remember to push your tag

git push origin v{version}
"#;
const COMMIT_PROMPT: &str = r#"
## Please commit all changes to files made during this step:

(from the root of styx-emulator):
git add ./CHANGELOG.md ./Cargo.toml ./Cargo.lock ./styx/bindings/Cargo.toml ./styx/bindings/Cargo.lock
git commit -m "chore(release): prepare for release v{version}"
"#;
const TAG_IGNORE_PATTERN: &str = ".*-foss-.*";
const BASE_FILE_CONTENTS_COMMAND: &str =
    "git diff {path} | grep '^+' | grep -v '^+++' | sed 's/^+//'";

pub fn execute(version: String) -> anyhow::Result<()> {
    // strip the leading `v` if it exists, we'll add it where we need it later
    let version = if version.starts_with("v") {
        let (_, keep) = version.split_at(1);
        keep.to_owned()
    } else {
        version
    };
    let changelog_path = resolve_path("./CHANGELOG.md").to_string();
    let root_cargo_toml_path = resolve_path("./Cargo.toml").to_string();
    let bindings_cargo_toml_path = resolve_path("./styx/bindings/Cargo.toml").to_string();

    // generate changelog
    let final_cliff_cmd = format!(
        "git cliff -t v{version} -u --ignore-tags '{TAG_IGNORE_PATTERN}' -p {changelog_path}",
    );
    // execute GIT_CLIFF_COMMAND here with the args
    _ = shell_command(&final_cliff_cmd, false)?;

    // get changelog contents
    println!("Updating changelog...");
    let changelog_update = changed_git_contents(changelog_path)?;

    // update versions in cargo tomls:
    // - root cargo.toml
    println!("Updating root Cargo.toml..");
    _ = update_cargo_toml_version(&root_cargo_toml_path, &version)?;
    // - bindings cargo.coml
    println!("Updating bindings Cargo.toml..");
    _ = update_cargo_toml_version(&bindings_cargo_toml_path, &version)?;

    // cargo update --workspace so the cargo.lock gets updated with the new styx version
    // - root cargo toml
    println!("Updating root Cargo.lock...");
    // allow failure since we just need the lock file update
    _ = shell_command(
        &format!("cargo clean && cargo update --workspace --manifest-path {root_cargo_toml_path}"),
        true,
    )?;
    // - bindings cargo toml
    println!("Updating bindings Cargo.lock...");
    // allow failure since we just need the lock file update
    _ = shell_command(
        &format!(
            "cargo clean && cargo update --workspace --manifest-path {bindings_cargo_toml_path}"
        ),
        true,
    )?;

    // print the changelog contents
    println!("\n**NEW CHANGELOG CONTENTS**");
    println!("==========================\n");
    println!("{changelog_update}");
    // print a "commit the changes" message
    println!("{}", COMMIT_PROMPT.replace("{version}", &version));
    // print the tag prompt
    println!("{}", TAG_PROMPT.replace("{version}", &version));
    Ok(())
}

fn shell_command(cmd: &str, allow_failure: bool) -> anyhow::Result<String> {
    let output = Command::new("sh")
        .arg("-c")
        .arg(cmd)
        .output()
        .with_context(|| format!("failed to execute `{cmd}`"))?;

    // if we dont allow failures, err on fail
    if !allow_failure && !output.status.success() {
        return Err(anyhow::anyhow!(format!(
            "command `{cmd}` failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    Ok(String::from_utf8_lossy(&output.stdout).into())
}

fn update_cargo_toml_version(path: &str, new_version: &str) -> anyhow::Result<bool> {
    let contents =
        fs::read_to_string(path).with_context(|| format!("failed to read file at {path}"))?;

    let mut doc = contents
        .parse::<DocumentMut>()
        .with_context(|| format!("{path} is invalid toml"))?;

    let version_value = doc["workspace"]["package"]["version"]
        .as_value_mut()
        .with_context(|| format!("{path} does not have workspace.package.version"))?;

    let mut modified = false; // have we modified a file

    // check that the version is a string and then
    // perform the update logic (and check if different etc.)
    match version_value {
        TomlValue::String(formatted_version_string) => {
            let version_string = formatted_version_string.value();

            // if the string value is different than what is already there,
            // then update
            if version_string != new_version {
                let mut new_value = Formatted::<String>::new(new_version.to_owned());
                new_value
                    .decor_mut()
                    .clone_from(formatted_version_string.decor());

                // commit the changes
                *version_value = TomlValue::String(new_value);

                // write contents back to file
                fs::write(path, doc.to_string())?;

                // modified a file
                modified = true;
            }
        }
        _ => bail!("{path} is formatted incorrectly (workspace.package.version is not string)"),
    }

    Ok(modified)
}

/// use [`BASE_FILE_CONTENTS_COMMAND`] with the path to the changelog to get the new changes
fn changed_git_contents(path: String) -> anyhow::Result<String> {
    // run git diff on the path
    let output = shell_command(&BASE_FILE_CONTENTS_COMMAND.replace("{path}", &path), false)?;

    Ok(output)
}
