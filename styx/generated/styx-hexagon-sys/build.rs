// SPDX-License-Identifier: BSD-2-Clause
use std::env;
use std::fs;
use std::path::PathBuf;

// See https://rust-lang.github.io/rust-bindgen/tutorial-3.html
fn main() {
    let clade_header_path = fs::canonicalize(
        env::var("CLADE_HEADERS").expect("need to specify clade header path in CLADE_HEADERS"),
    )
    .expect("clade header path may not exist - cannot canonicalize")
    .display()
    .to_string();

    let clade_lib_path = fs::canonicalize(
        env::var("CLADE_LIBS")
            .expect("need to specify path to clade shared libraries in CLADE_LIBS"),
    )
    .expect("clade shared library path may not exist - cannot canonicalize")
    .display()
    .to_string();

    println!("cargo:rustc-link-search={}", clade_lib_path);
    println!("cargo:rustc-link-lib=clade");
    println!("cargo:rustc-link-lib=clade2");

    let bindings = bindgen::Builder::default()
        .header("common.h")
        .derive_default(true)
        .clang_arg(&format!("-I{}", clade_header_path))
        .wrap_static_fns(true)
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .layout_tests(false)
        .generate()
        .expect("Couldn't generate clade bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("clade.rs"))
        .expect("Couldn't write clade bindings to file");
}
