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
use heck::ToUpperCamelCase;
use std::{
    env,
    fs::File,
    io::{BufWriter, Write},
    path::PathBuf,
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
];

/// Takes a single slaspec source and writes the generated rust code to `generated_code`.
fn process(spec_path: &str, generated_code: &mut BufWriter<File>) {
    let global_out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let spec_file = global_out_dir.join(PathBuf::from(format!("./processors/{spec_path}.slaspec")));

    let spec_dir = spec_file.parent().unwrap();
    // e.g. ARMv7le
    let spec_name = spec_file.file_stem().unwrap().to_string_lossy();
    let out_dir = spec_dir;
    let sla_file = out_dir.join(format!("{spec_name}.sla"));

    // compile the slaspec into sla
    styx_pcode_sleigh_backend::compile(&spec_file, &sla_file).unwrap();

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

    generated_code
        .write_all(out_rust_string.as_bytes())
        .unwrap();
}

fn main() {
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());

    // out_dir is sometimes not empty
    let processors_dir = out_dir.join("processors");
    // errors if didn't already exist, that's okay
    let _ = std::fs::remove_dir_all(&processors_dir);

    println!("Output Directory:\n{}", out_dir.to_string_lossy());
    copy_dir::copy_dir("./processors", out_dir.join("processors")).unwrap();

    let generated_code_file = std::fs::File::create(out_dir.join("sla_artifacts.rs")).unwrap();
    let mut generated_code = BufWriter::new(generated_code_file);

    // apply patches
    apply_file_patches_in_place("./patches", &processors_dir, false, false).unwrap();

    for (arch_feature, specs) in SPECS {
        let env_feature = arch_feature.env_feature_flag();
        let env = env::var(&env_feature);
        if env.is_ok() {
            println!("{env_feature} enabled");
            for spec in *specs {
                process(spec, &mut generated_code);
            }
        } else {
            println!("{env_feature} disabled");
        }
    }
    generated_code.flush().unwrap();

    println!("cargo::rerun-if-changed=processors/");
    println!("cargo::rerun-if-changed=patches/");
    println!("cargo::rerun-if-changed=src/lib.rs");
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
    let patch_string = std::fs::read_to_string(patch_path)?;
    let patch = diffy::Patch::from_str(&patch_string).map_err(|err| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("failed to parse patch: {err}"),
        )
    })?;

    // Read the original file
    let content = std::fs::read_to_string(original_path)?;

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
