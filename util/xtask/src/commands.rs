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
use clap::Subcommand;
use strum_macros::Display;

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Generate a template file for a new ADR
    Adr {
        /// Name for the new ADR template
        #[arg(long)]
        name: String,
    },
    /// Alphabetize the enums of the code base. Performs modifications
    Alphabetize {},
    /// Add features to a DAG of crates at a time
    FeatureAdd {
        /// Mode of operation.
        #[arg(short, long)]
        #[arg(default_value_t = FeatureAddModes::Workspace, required_unless_present = "files")]
        mode: FeatureAddModes,
        /// List of `Cargo.toml` files to modify along with their parent crates.
        /// Note this will override the `mode` option to `branches`.
        #[arg(long, value_name = "FILE", value_delimiter = ' ', num_args=0..)]
        #[arg(conflicts_with = "mode")]
        files: Vec<String>,
        /// List of features to add.
        /// A feature string that includes a dash, comma, or colon (without any spaces), is split: the
        /// first string is the feature name and the subsequent strings are values to be added to
        /// the feature's value array.
        #[arg(long, value_name = "FEATURE", value_delimiter = ' ', num_args=0.., required = true)]
        features: Vec<String>,
    },
    /// Updates the workspace-hack configuration
    Hakari {
        /// Runs + wraps cargo-hakari stages for managing dependencies
        /// and updating the lockfile. Add `--dry-run` to avoid modifying
        /// files or making changes to anything. Add `--verify` to ensure
        /// the configuration is not borked.
        #[arg(short, long, default_value_t = HakariStages::default())]
        stage: HakariStages,
        /// Dry Run
        #[arg(long, default_value_t = false)]
        dry_run: bool,
        /// Enable verification if things are broke
        #[arg(long, default_value_t = false)]
        verify: bool,
    },
    /// Checks that the LICENSE file is present and modifies files recursively
    /// within the working directory to prepend applicable license content.
    License {
        /// Check only instead of modifying in place
        ///
        /// Returns non-zero if it would normally modify a file
        #[arg(short, long)]
        check_only: bool,

        /// List of files to operate on, optional, space delimited
        #[arg(short, long, value_name = "FILE", value_delimiter = ' ', num_args=0..)]
        files: Vec<String>,
    },
    /// Performs the necessary actions to prepare for a new release
    Release {
        /// The version of the next release
        #[arg(long)]
        version: String,
    },
    /// Generate a template file for a new RFC
    Rfc {
        /// Name for the new RFC template
        #[arg(long)]
        name: String,
    },
    /// Used for updating the version of rust in the codebase
    RustVersionUpdate {
        /// Target rust version to use
        #[arg(long)]
        target: String,
        /// Check and do not modify any files,
        /// Returns nonzero if any files would be updated
        #[arg(long)]
        #[arg(default_value_t = false)]
        check: bool,
    },
}

/// List of possible hakari stages to execute,
///
/// Note that all stages will begin with `hakari verify` to ensure
/// the lockfile is up-to-date.
///
/// Commands:
/// - `Update` - Wraps `hakari generate` and `hakari manage-deps`
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug, clap::ValueEnum, Default, Display)]
pub enum HakariStages {
    #[default]
    #[strum(to_string = "update")]
    Update,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Debug, clap::ValueEnum, Display)]
pub enum FeatureAddModes {
    /// Add the feature to all crates in the workspace.
    #[strum(to_string = "workspace")]
    Workspace,
    /// Add the feature to all styx crates.
    #[strum(to_string = "styx")]
    Styx,
    /// Add the feature to all the specified `Cargo.toml` files and their parent crates.
    #[strum(to_string = "branches")]
    Branches,
}
