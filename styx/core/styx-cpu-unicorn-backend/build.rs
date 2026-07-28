// SPDX-License-Identifier: BSD-2-Clause
//! Building unicorn on current Linux distributions fail without linking against libatomic.
//! This file exists to add libatomic when linking.

fn main() {
    // MacOS does not need libatomic, will fail to compile if included on MacOS
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "linux" {
        println!("cargo:rustc-link-lib=atomic");
    }
}
