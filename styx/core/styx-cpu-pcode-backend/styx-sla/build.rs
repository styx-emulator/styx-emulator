// SPDX-License-Identifier: BSD-2-Clause

//! Build script for `styx-sla`: turns the checked-in SLEIGH processor
//! definitions into compiled `.sla` artifacts plus generated Rust bindings.
//!
//! Pipeline (see [`main`]):
//! 1. Copy the `processors/` tree (Ghidra + custom slaspecs) into `OUT_DIR`,
//!    then apply the unified-diff patches from `patches/` onto that copy.
//! 2. For every arch feature enabled at build time (see [`SPECS`] and the
//!    `arch_*` cargo features), compile each `.slaspec` into a `.sla` with
//!    Ghidra's SLEIGH compiler ([`process`]).
//! 3. Load each `.sla` to extract its user-ops and emit Rust into
//!    `$OUT_DIR/sla_artifacts.rs`: a `SlaSpec`/`SlaUserOps` impl per spec plus a
//!    `<Spec>UserOps` enum. `src/lib.rs` `include!`s that file.
//!
//! ## Concurrency
//! Compiling a slaspec goes through Ghidra's C++ SLEIGH compiler, which
//! relies on process-global lexer/parser state and therefore cannot be run
//! concurrently within a single process (threads would corrupt each other).
//! To use more than one core we instead spawn one *child process* per
//! spec by re-executing this same build-script binary in "worker" mode. Each
//! worker compiles exactly one spec and writes the generated rust snippet
//! to a file which the parent then concatenates them.
//!
use heck::ToUpperCamelCase;
use std::{
    collections::VecDeque,
    env,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    thread::JoinHandle,
};
use styx_pcode_sleigh_backend::Sleigh;

#[derive(Clone, Copy)]
enum ArchFeature {
    Arm,
    AArch64,
    Blackfin,
    M32R,
    Mips32,
    Mips64,
    Msp430,
    PowerPc,
    SuperH,
    Hexagon,
}

impl ArchFeature {
    /// CARGO_FEATURE_ARCH_{arm,bfin,etc}
    const fn feature_name(self) -> &'static str {
        match self {
            ArchFeature::Arm => "arm",
            ArchFeature::AArch64 => "aarch64",
            ArchFeature::Blackfin => "bfin",
            ArchFeature::SuperH => "superh",
            ArchFeature::PowerPc => "ppc",
            ArchFeature::M32R => "m32r",
            ArchFeature::Mips32 => "mips32",
            ArchFeature::Mips64 => "mips64",
            ArchFeature::Msp430 => "msp430",
            ArchFeature::Hexagon => "hexagon",
        }
    }

    fn env_feature_flag(self) -> String {
        format!("CARGO_FEATURE_ARCH_{}", self.feature_name().to_uppercase())
    }
}

/// List of slaspecs to build, organized by arch for feature guarding.
///
/// Each Value is the list of slas to compile when the feature Key is enabled
/// for compilation. The path is relative to the `processors` dir in this crate
/// and should be the path to the slaspec without the  `.slaspec` suffix.
const SPECS: &[(ArchFeature, &[&str])] = &[
    (
        ArchFeature::Arm,
        &[
            "ghidra/ARM/data/languages/ARM7_le",
            "ghidra/ARM/data/languages/ARM4_be",
            "ghidra/ARM/data/languages/ARM5_be",
            "ghidra/ARM/data/languages/ARM6_be",
            "ghidra/ARM/data/languages/ARM7_be",
            "ghidra/ARM/data/languages/ARM8_be",
        ],
    ),
    (
        ArchFeature::AArch64,
        &["ghidra/AARCH64/data/languages/AARCH64"],
    ),
    (ArchFeature::Blackfin, &["custom/bfin/blackfin"]),
    (
        ArchFeature::SuperH,
        &[
            "ghidra/SuperH/data/languages/sh-1",
            "ghidra/SuperH/data/languages/sh-2",
            "ghidra/SuperH/data/languages/sh-2a",
            "ghidra/SuperH4/data/languages/SuperH4_be",
            "ghidra/SuperH4/data/languages/SuperH4_le",
        ],
    ),
    (
        ArchFeature::PowerPc,
        &["ghidra/PowerPC/data/languages/ppc_32_4xx_be"],
    ),
    (ArchFeature::M32R, &["custom/m32r/m32r"]),
    (
        ArchFeature::Mips32,
        &[
            "ghidra/MIPS/data/languages/mips32le",
            "ghidra/MIPS/data/languages/mips32be",
        ],
    ),
    (
        ArchFeature::Mips64,
        &[
            "ghidra/MIPS/data/languages/mips64le",
            "ghidra/MIPS/data/languages/mips64be",
        ],
    ),
    (
        ArchFeature::Msp430,
        &[
            "ghidra/TI_MSP430/data/languages/TI_MSP430X",
            "ghidra/TI_MSP430/data/languages/TI_MSP430",
        ],
    ),
    (ArchFeature::Hexagon, &["custom/hexagon/hexagon"]),
];

/// Slaspec paths are relative to the `processors` directory in this crate and
/// omit the slapsec file extension.
fn path_from_spec_rel(spec_path: &str) -> PathBuf {
    PathBuf::from(env::var_os("OUT_DIR").expect("no OUT_DIR"))
        .join(PathBuf::from(format!("./processors/{spec_path}.slaspec")))
}

/// Takes a single slaspec path, compiles it, and returns the generated rust code.
fn process(job: JobInputs) {
    let spec_file = path_from_spec_rel(&job.spec_path);
    let spec_file = &spec_file;
    let spec_dir = spec_file.parent().unwrap();
    // e.g. ARMv7le
    let spec_name = spec_file.file_stem().unwrap().to_string_lossy();
    let out_dir = spec_dir;
    let sla_file = out_dir.join(format!("{spec_name}.sla"));

    // compile the slaspec into sla
    styx_pcode_sleigh_backend::compile(spec_file, &sla_file).unwrap();

    let rust_name = spec_name.to_upper_camel_case();

    let sleigh = Sleigh::with_context_no_load_image(&sla_file);
    let user_ops = sleigh.get_user_ops();
    // user ops with no duplicate names
    let mut deduped_user_ops = Vec::new();

    // Gets list of user ops with non-conflicting names
    // If any user op names case-insensitive conflict then we append `Idx[idx]` to ensure the names are unique.
    for orig_op in user_ops.iter() {
        let mut new_op = orig_op.clone();
        if user_ops
            .iter()
            .filter(|op| orig_op.name.to_upper_camel_case() == op.name.to_upper_camel_case())
            .count()
            > 1
        {
            new_op.name = format!("{}Idx{}", orig_op.name, orig_op.index);
        }
        deduped_user_ops.push(new_op);
    }

    // FromStr derive throws a warning if the enum is empty so let's only add it if there are user
    // ops.
    let from_str = if user_ops.is_empty() { "" } else { ", FromStr" };
    let mut user_op_str = String::new();
    user_op_str.push_str(&format!(
        "#[derive(Debug, Clone, Copy, PartialEq, Eq, Display{from_str})]"
    ));
    user_op_str.push_str(&format!("pub enum {rust_name}UserOps {{"));
    let mut user_op_impl_str = String::new();
    user_op_impl_str.push_str(&format!("impl UserOps for {rust_name}UserOps {{"));
    user_op_impl_str.push_str("fn index(self) -> u64 {");
    user_op_impl_str.push_str("match self {");
    for op in deduped_user_ops {
        let op_name = op.name.to_upper_camel_case();
        let idx = op.index;
        user_op_str.push_str(&format!("{op_name},"));

        user_op_impl_str.push_str(&format!("Self::{op_name} => {idx}u64,"));
    }
    user_op_str.push('}');

    user_op_impl_str.push_str("} } }");

    let outfile = sla_file.to_string_lossy();
    let rust_string = format! {r#"
        pub struct {rust_name};
        impl SlaSpec for {rust_name} {{
            fn spec() -> &'static [u8] {{
                include_bytes!("{outfile}")
            }}

            fn name() -> &'static str {{
                "{spec_name}"
            }}
        }}

        impl SlaUserOps for {rust_name} {{
            type UserOps = {rust_name}UserOps;
        }}
        "#};

    let out_rust_string = format! {r#"
        {rust_string}
        {user_op_str}
        {user_op_impl_str}
        "#};

    let out_path = &job.output_path;
    std::fs::write(out_path, out_rust_string)
        .unwrap_or_else(|e| panic!("failed to write worker output {out_path:?}: {e}"));
}

/// Represents the inputs to one worker slaspec conversion.
struct JobInputs {
    /// Slaspec path relative to the crate's `processors/` directory, without the
    /// `.slaspec` extension (e.g. `ghidra/ARM/data/languages/ARM7_le`).
    ///
    /// Resolve it to an absolute path with [`path_from_spec_rel`] when the file
    /// is needed.
    spec_path: String,
    /// Path to the file to output generated rust to.
    output_path: PathBuf,
}

impl JobInputs {
    fn try_from_env() -> Option<Self> {
        match (env::var(WORKER_SPEC_ENV), env::var(WORKER_OUT_ENV)) {
            (Ok(spec_path), Ok(output_str)) => {
                let output_path = PathBuf::from(output_str);
                Some(Self {
                    spec_path,
                    output_path,
                })
            }
            // We should never have just one or the other.
            (Ok(_), Err(_)) => {
                panic!("worker env `{WORKER_SPEC_ENV}` present but `{WORKER_OUT_ENV}` missing")
            }
            (Err(_), Ok(_)) => {
                panic!("worker env `{WORKER_OUT_ENV}` present but `{WORKER_SPEC_ENV}` missing")
            }
            // Not a worker.
            (Err(_), Err(_)) => None,
        }
    }
}

/// Env var used to re-invoke this build script binary in "worker" mode. When
/// set, its value is the single slaspec path to compile (see [`worker_main`]).
const WORKER_SPEC_ENV: &str = "STYX_SLA_WORKER_SPEC";
/// Env var giving the worker the absolute path it should write generated rust to.
const WORKER_OUT_ENV: &str = "STYX_SLA_WORKER_OUT";

/// Run one slaspec compilation by re-executing this build-script binary in
/// worker mode (see file-level docs). Any failure is recorded in `errors`
/// rather than panicking, so the caller can join every worker before reporting.
fn run_worker(self_exe: &Path, job: &JobInputs, errors: &Mutex<Vec<String>>) {
    let status = std::process::Command::new(self_exe)
        .env(WORKER_SPEC_ENV, &job.spec_path)
        .env(WORKER_OUT_ENV, &job.output_path)
        .status();
    let spec = &job.spec_path;
    match status {
        Ok(status) if status.success() => {}
        Ok(status) => errors
            .lock()
            .unwrap()
            .push(format!("worker for `{spec}` failed: {status}")),
        Err(e) => errors
            .lock()
            .unwrap()
            .push(format!("failed to spawn worker for `{spec}`: {e}")),
    }
}

fn main() {
    // Check if this process is a worker (see file level documentation).
    if let Some(job) = JobInputs::try_from_env() {
        // Worker entry point: compile a single spec and write the generated rust to the
        // path given in [`WORKER_OUT_ENV`]. Runs in a dedicated child process so that
        // the non-reentrant C++ SLEIGH compiler can run in parallel across specs.
        process(job);
        return;
    }

    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());

    // out_dir is sometimes not empty
    let processors_dir = out_dir.join("processors");
    // errors if didn't already exist, that's okay
    let _ = std::fs::remove_dir_all(&processors_dir);

    println!("Output Directory:\n{}", out_dir.to_string_lossy());
    copy_dir::copy_dir("./processors", out_dir.join("processors")).unwrap();

    // apply patches
    apply_file_patches_in_place("./patches", &processors_dir, false, false).unwrap();

    // Collect the list of enabled specs (in declaration order for deterministic
    // output).
    let mut enabled_specs: Vec<&str> = Vec::new();
    for (arch_feature, specs) in SPECS {
        let env_feature = arch_feature.env_feature_flag();
        if env::var(&env_feature).is_ok() {
            println!("{env_feature} enabled");
            enabled_specs.extend(*specs);
        } else {
            println!("{env_feature} disabled");
        }
    }

    let self_exe = env::current_exe().expect("could not resolve build script path");
    let gen_dir = out_dir.join("gen");
    let _ = std::fs::remove_dir_all(&gen_dir);
    std::fs::create_dir_all(&gen_dir).unwrap();

    // Bound concurrency using Cargo's jobserver.
    //
    // SAFETY: Recommended to be called early, which we do.
    let client = unsafe { jobserver::Client::from_env() }.expect("no jobserver configured");

    // Build the per-spec output paths up front and turn every enabled spec into
    // a queued job.
    let jobs: Arc<Mutex<VecDeque<JobInputs>>> = Arc::new(Mutex::new(
        enabled_specs
            .iter()
            .enumerate()
            .map(|(idx, spec)| JobInputs {
                spec_path: spec.to_string(),
                output_path: gen_dir.join(format!("{idx}.rs")),
            })
            .collect(),
    ));

    // Collect worker failures instead of panicking inside a thread, so every
    // worker is joined and all failures are reported cleanly afterwards.
    let errors: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    // Join handles for worker threads spawned by the jobserver helper thread.
    let handles: Arc<Mutex<Vec<JoinHandle<()>>>> = Arc::new(Mutex::new(Vec::new()));
    let self_exe = Arc::new(self_exe);

    // A build script is itself a "make thread" that already holds one implicit
    // jobserver token, so it may always run *one* unit of work without asking
    // the jobserver for anything.
    //
    // Instead we split the work two ways:
    //   * The helper thread requests extra tokens from the jobserver; each
    //     granted token dispatches one job onto its own worker thread.
    //   * The main thread, using our implicit token, drains the same queue
    //     sequentially.
    let helper = client
        .into_helper_thread({
            let jobs = jobs.clone();
            let errors = errors.clone();
            let handles = handles.clone();
            let self_exe = self_exe.clone();

            // Run on token aquisition.
            move |token| match token {
                Ok(acquired) => {
                    // Grab a job.
                    let job = jobs.lock().unwrap().pop_front();
                    if let Some(job) = job {
                        let errors = errors.clone();
                        let self_exe = self_exe.clone();
                        let handle = std::thread::spawn(move || {
                            run_worker(&self_exe, &job, &errors);
                            // Move token into thread and drop when done.
                            drop(acquired);
                        });
                        handles.lock().unwrap().push(handle);
                    }
                    // Ope, didn't need that token, no more jobs.
                }
                Err(e) => errors
                    .lock()
                    .unwrap()
                    .push(format!("jobserver token error: {e}")),
            }
        })
        .expect("failed to spawn jobserver helper thread");

    // Ask for a token per job.
    for _ in 0..enabled_specs.len() {
        helper.request_token();
    }

    // Drain the queue on the main thread using our implicit token.
    loop {
        // Note for future devs, this looks like it could be rewritten as a
        // `while let Some(job) = jobs.lock().unwrap().pop_front() {}`,
        // however, this will hold the lock while inide the loop body,
        // which is not what we want here.
        let job = jobs.lock().unwrap().pop_front();
        match job {
            Some(job) => run_worker(&self_exe, &job, &errors),
            // All jobs taken.
            None => break,
        }
    }

    // Join all threads.
    drop(helper);
    loop {
        let handle = handles.lock().unwrap().pop();
        match handle {
            Some(handle) => handle.join().unwrap(),
            None => break,
        }
    }

    let errors = Arc::try_unwrap(errors).unwrap().into_inner().unwrap();
    assert!(
        errors.is_empty(),
        "sla worker(s) failed:\n{}",
        errors.join("\n")
    );

    // Assemble the final artifacts file.
    let generated_code_file = std::fs::File::create(out_dir.join("sla_artifacts.rs")).unwrap();
    let mut generated_code = BufWriter::new(generated_code_file);
    for (idx, spec) in enabled_specs.iter().enumerate() {
        let snippet_path = gen_dir.join(format!("{idx}.rs"));
        let snippet = std::fs::read(&snippet_path)
            .unwrap_or_else(|e| panic!("missing worker output for `{spec}`: {e}"));
        generated_code.write_all(&snippet).unwrap();
    }
    generated_code.flush().unwrap();

    println!("cargo::rerun-if-changed=processors/");
    println!("cargo::rerun-if-changed=patches/");
}

// The following patch functions were taken from AndrejOrsula/built_different licensed under the MIT license
// The License is included:
// MIT License
//
// Copyright (c) 2024 Andrej Orsula
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

pub fn apply_file_patches_in_place(
    patch_dir: impl AsRef<std::path::Path>,
    target_dir: impl AsRef<std::path::Path>,
    copy_original: bool,
    rerun_if_patch_changed: bool,
) -> Result<(), std::io::Error> {
    let patch_dir = patch_dir.as_ref();
    let target_dir = target_dir.as_ref();
    // Iterate over all patch files
    walkdir::WalkDir::new(patch_dir)
        .into_iter()
        .filter(|entry| {
            entry
                .as_ref()
                .map(|entry| {
                    let is_file = entry.file_type().is_file();
                    // we are going to check if the file ends in patch, otherwise error
                    if is_file {
                        let path = entry.path();
                        let path_str = path.as_os_str().to_string_lossy();
                        let ends_with_patch = path
                            .extension()
                            .unwrap_or_default()
                            .to_str()
                            .unwrap_or_default()
                            .ends_with("patch");
                        if !ends_with_patch {
                            panic!("file `{path_str}` does not end with `.patch`. all files in patch directory must end with .patch");
                        }
                    }
                    is_file
                })
                .unwrap_or(false)
        })
        .map(|entry| entry.unwrap().path().to_path_buf())
        .try_for_each(|patch| {
            // Get relative path of the patched file
            let patched_file_relative = patch
                .canonicalize()
                .unwrap()
                .strip_prefix(patch_dir.canonicalize().unwrap().as_os_str())
                .unwrap()
                .with_file_name(
                    patch
                        .file_name()
                        .unwrap()
                        .to_str()
                        .unwrap()
                        .strip_suffix(".patch")
                        .unwrap(),
                );

            // Get the path to the target file
            let target_file = target_dir.join(patched_file_relative);

            // Determine the path to the original file (either the target file or a copy of it)
            let original_file = if copy_original {
                // If requested, create a copy of the target file and treat it as the original file
                let original_file = target_file.with_extension(
                    target_file
                        .extension()
                        .unwrap_or_default()
                        .to_str()
                        .unwrap_or_default()
                        .to_owned()
                        + ".original",
                );
                if !original_file.is_file() {
                    std::fs::copy(&target_file, &original_file).unwrap();
                }
                original_file
            } else {
                // Otherwise, use the target file as the original file
                target_file.clone()
            };

            // Apply the patch
            apply_file_patch(&patch, original_file, &target_file, rerun_if_patch_changed)
        })
}

fn read_to_str_normalised<P: AsRef<Path>>(path: P) -> std::io::Result<String> {
    // Failsafe normalise line ends -> LR due to Diffy issue.
    // Reference: https://github.com/bmwill/diffy/issues/20
    std::fs::read_to_string(path).map(|s| s.replace("\r\n", "\n"))
}

pub fn apply_file_patch(
    patch_path: impl AsRef<std::path::Path>,
    original_path: impl AsRef<std::path::Path>,
    target_path: impl AsRef<std::path::Path>,
    rerun_if_patch_changed: bool,
) -> Result<(), std::io::Error> {
    let patch_path = patch_path.as_ref();
    let target_path = target_path.as_ref();

    // Inform cargo to rerun this build script if the patch file changes
    if rerun_if_patch_changed {
        println!("cargo:rerun-if-changed={}", patch_path.display());
    }

    // Parse the patch
    let patch_string = read_to_str_normalised(patch_path)?;
    let patch = diffy::Patch::from_str(&patch_string).map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("failed to parse patch: {err}"),
        )
    })?;

    // Read the original file
    let content = read_to_str_normalised(original_path)?;

    // Apply the patch
    let patched_content = diffy::apply(&content, &patch).map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("failed to apply patch: {err}"),
        )
    })?;

    // If the target file already exists and the patched content is the same as the target content, skip
    if target_path.is_file() {
        let target_content = std::fs::read_to_string(target_path)?;
        if patched_content == target_content {
            return Ok(());
        }
    }

    // Make sure the parent directory exists
    if let Some(parent) = target_path.parent() {
        if !parent.try_exists()? {
            std::fs::create_dir_all(parent).unwrap();
        }
    }

    // Write the patched content to the target path
    std::fs::write(target_path, patched_content)?;

    Ok(())
}
