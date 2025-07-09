// SPDX-License-Identifier: BSD-2-Clause
use std::env;
use std::path::PathBuf;

fn main() {
    println!("cargo::rerun-if-changed=common.h");

    let bindings = bindgen::Builder::default()
        .clang_arg("-Iinclude/")
        .header("common.h")
        .blocklist_function("divq")
        // generating struct defs for these types emits the following error:
        // `packed type cannot transitively contain a `#[repr(align)]` type`
        .opaque_type("^(ADI_DMA_DESCRIPTOR_.*)$")
        .derive_default(true)
        // Invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());

    // bf512 bindings written to OUT_DIR/bf512.rs
    bindings
        .write_to_file(out_path.join("bf512.rs"))
        .expect("Couldn't write bindings!");
}
