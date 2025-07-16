// SPDX-License-Identifier: BSD-2-Clause
extern crate compiletest_rs as compiletest;

use std::path::PathBuf;

fn run_mode(mode: &'static str) {
    let mut config = compiletest::Config {
        mode: mode.parse().expect("Invalid mode"),
        src_base: PathBuf::from(format!("tests/{mode}")),
        ..Default::default()
    };

    config.link_deps(); // Populate config.target_rustcflags with dependencies on the path
    config.clean_rmeta(); // If your tests import the parent crate, this helps with E0464

    compiletest::run_tests(&config);
}

/// IGNORED: Running this tests causes all crate artifacts to become stale for
/// an "unknown reason". The effect of including this test in the project is
/// that testsuite runs require a full rebuild.
#[test]
#[ignore]
fn compile_test() {
    run_mode("compile-fail");
}
