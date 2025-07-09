// SPDX-License-Identifier: BSD-2-Clause
fn main() {
    let crate_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let config = cbindgen::Config::from_file("cbindgen.toml")
        .expect("cbindgen.toml was not found in the root of the styx-c-api crate");
    cbindgen::generate_with_config(&crate_dir, config)
        .unwrap()
        .write_to_file("inc/styx_emulator.h");
}
