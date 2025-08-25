// SPDX-License-Identifier: BSD-2-Clause
//! See <https://github.com/matklad/cargo-xtask/>.
//!
//! This binary defines various auxiliary build commands, which are not possible with just
//! `cargo`. Any extra CI-scripting task functionality should be added as a module of this
//! crate.
//!
//! This binary is integrated into the `cargo` command line by using an alias in `.cargo/config`.
mod adr;
mod alphabetize;
mod commands;
mod feature_add;
mod hakari;
mod license;
mod release;
mod rust_version;

use clap::Parser;
use commands::Commands;
use tracing::error;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Arguments {
    /// Subcommand to execute
    #[command(subcommand)]
    command: Option<Commands>,

    /// Verbose logging
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> anyhow::Result<()> {
    let args = Arguments::parse();

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    // execute the command that was provided
    if let Some(command) = args.command {
        match command {
            Commands::License { check_only, files } => license::check_licenses(check_only, files)?,
            Commands::LicenseUpdate {
                check_only,
                old_license,
                new_license,
            } => license::update_licenses(check_only, &old_license, &new_license)?,
            Commands::Hakari {
                stage,
                dry_run,
                verify,
            } => {
                let _ = hakari::execute(stage, dry_run, verify).map_err(|err| {
                    error!("cargo hakari exited with error: {}", err);
                    err
                })?;
            }
            Commands::FeatureAdd {
                mode,
                files,
                features,
            } => {
                let feature_adder = feature_add::FeatureAdd::new(mode, files, features);
                feature_adder.add_features()?;
            }
            Commands::RustVersionUpdate { target, check } => {
                rust_version::update(target, check)?;
            }
            Commands::Adr { name } => {
                adr::execute(name)?;
            }
            Commands::Release { version } => {
                release::execute(version)?;
            }
            Commands::Alphabetize {} => {
                alphabetize::execute()?;
            }
        };

        Ok(())
    } else {
        error!("No xtask provided");
        std::process::exit(1);
    }
}
