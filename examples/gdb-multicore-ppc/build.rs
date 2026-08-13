// SPDX-License-Identifier: BSD-2-Clause
//! Assembles the example firmware located in `firmware/firmware.S`.
//!
//! We:
//!   1. assemble it for `powerpc-unknown-linux-gnu` with clang's integrated
//!      assembler,
//!      then
//!   2. extract the raw `.text` bytes from the resulting object with `goblin`.
//!
//! Because clang has a ppc assembler already we don't need the powerpc toolchain
//! installed. We could link to an ELF with proper program headers but I think that
//! would require the powerpc toolchain so using clang and manually extracting
//! the .text to a raw firmware blob seemed easier.
//!
//! Paths are exported to the crate via environment variables:
//!   - `FIRMWARE_TEXT_BIN`: raw `.text` bytes for the firmware.
//!   - `FIRMWARE_OBJ_FILE`: the full object (with symbols). The gdb `nexti`
//!     tests load it as a symbol file (`add-symbol-file`) so the gdb client has
//!     the function-boundary symbols it needs to unwind the call stack.

use std::path::{Path, PathBuf};

/// Assemble `source` and return the path to the produced object file.
fn assemble(source: &str) -> PathBuf {
    println!("cargo:rerun-if-changed={source}");

    let objects = cc::Build::new()
        .file(source)
        .target("powerpc-unknown-linux-gnu")
        .compiler("clang")
        // This isn't going to be linked to the crate, so disable cargo metadata.
        .cargo_metadata(false)
        .compile_intermediates();

    let object = objects
        .first()
        .unwrap_or_else(|| panic!("cc produced no object file for {source}"));
    assert!(
        Path::new(object).exists(),
        "expected object file {} to exist",
        object.display()
    );
    object.clone()
}

/// Extract the raw `.text` section bytes from `object` and write them to
/// `$OUT_DIR/{out_name}`, returning that path.
fn extract_text(object: &Path, out_name: &str) -> PathBuf {
    let bytes = std::fs::read(object)
        .unwrap_or_else(|e| panic!("could not read object {}: {e}", object.display()));
    let elf = goblin::elf::Elf::parse(&bytes)
        .unwrap_or_else(|e| panic!("could not parse {} as ELF: {e}", object.display()));

    let text = elf
        .section_headers
        .iter()
        .find(|sh| elf.shdr_strtab.get_at(sh.sh_name) == Some(".text"))
        .unwrap_or_else(|| panic!("no .text section in {}", object.display()));
    let start = text.sh_offset as usize;
    let end = start + text.sh_size as usize;

    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR not set");
    let out_path = Path::new(&out_dir).join(out_name);
    std::fs::write(&out_path, &bytes[start..end])
        .unwrap_or_else(|e| panic!("could not write {}: {e}", out_path.display()));
    out_path
}

fn main() {
    let obj = assemble("firmware/firmware.S");
    let text = extract_text(&obj, "firmware.text.bin");

    println!("cargo:rustc-env=FIRMWARE_TEXT_BIN={}", text.display());
    // The full object (with symbols) is loaded by the gdb nexti tests as a
    // symbol file via `add-symbol-file`.
    println!("cargo:rustc-env=FIRMWARE_OBJ_FILE={}", obj.display());
}
