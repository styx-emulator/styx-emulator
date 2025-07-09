// SPDX-License-Identifier: BSD-2-Clause
use std::process::Command;

use crate::commands::HakariStages;

/// Executes the provided hakari stage, returns the exit status code
/// of the command.
pub fn execute(stage: HakariStages, dry_run: bool, verify: bool) -> anyhow::Result<i32> {
    if verify {
        hakari_verify_check()?;
    }

    match stage {
        HakariStages::Update => execute_check(dry_run),
    }
}

const HAKARI_VERIFY_FAIL_MSG: &str = r#"
    This error message means that the following command has failed:

    cargo hakari verify

    This means that the cargo-haraki workspace hack installation is borked.
    If this configuration was not intentionally changed please file an
    issue and let the maintainers know. If you did intentionally change
    this configuration, you did not do it correctly.
"#;

const HAKARI_GENERATE_FAIL_MSG: &str = r#"
    This error message means that the following command has failed:

    cargo hakari generate --diff

    This means that the cargo hakari installation needs to be modified,
    this should *only* happen when packages/dependencies are added and
    Cargo.toml/Cargo.locks are changing.

    To update the installation please run the following commands and
    then commit the changes:

    cargo xtask hakari --verify

    Follow any further prompts from cargo-hakari as necessary
"#;

const HAKARI_MANAGE_FAIL_MSG: &str = r#"
    This error message means that the following command has failed:

    cargo hakari manage-deps --dry-run

    This means that the cargo hakari installation needs to be modified,
    this should *only* happen when packages/dependencies are added and
    Cargo.toml/Cargo.locks are changing.

    To update the installation please run the following commands and
    then commit the changes:

    cargo xtask hakari
"#;

/// Executes the `hakari generate` command and then the `hakari manage-deps`
/// Returns the exit status code of the command.
fn execute_check(dry_run: bool) -> anyhow::Result<i32> {
    let mut args = vec!["hakari", "generate", "--color", "always"];
    if dry_run {
        args.push("--diff");
    }

    // execute cargo hakari "generate"
    let status = Command::new("cargo").args(args).status()?;
    let status_code = status.code().unwrap();

    if !status.success() {
        eprintln!("{}", HAKARI_GENERATE_FAIL_MSG);
        tracing::error!(
            "cargo hakari generate failed with error code: {}",
            status_code
        );
        return Err(anyhow::anyhow!("cargo hakari generate failed"));
    }

    // now execute hakari manage-deps
    let mut args = vec!["hakari", "manage-deps", "--color", "always"];
    if dry_run {
        args.push("--dry-run");
    }

    // execute cargo hakari "manage-deps"
    let status = Command::new("cargo").args(args).status()?;
    let status_code = status.code().unwrap();

    if !status.success() {
        eprintln!("{}", HAKARI_MANAGE_FAIL_MSG);
        tracing::error!(
            "cargo hakari manage-deps failed with error code: {}",
            status_code
        );
        return Err(anyhow::anyhow!("cargo hakari manage-deps failed"));
    }

    Ok(status_code)
}

/// Executes the `hakari verify` command to ensure the lockfile is up-to-date
/// and the hakari configuration is valid
fn hakari_verify_check() -> anyhow::Result<i32> {
    // execute cargo hakari "verify"
    let status = Command::new("cargo")
        .args(["hakari", "verify", "--color", "always"])
        .status()?;
    let status_code = status.code().unwrap();

    if !status.success() {
        eprintln!("{}", HAKARI_VERIFY_FAIL_MSG);
        tracing::error!(
            "cargo hakari verify failed with error code: {}",
            status_code
        );
        Err(anyhow::anyhow!("cargo hakari verify failed"))
    } else {
        Ok(status_code)
    }
}
