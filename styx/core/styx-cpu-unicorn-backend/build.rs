// SPDX-License-Identifier: BSD-2-Clause
//! Building unicorn on current Linux distributions fail without linking against libatomic.
//! This file exists to add libatomic when linking.

fn main() {
    println!("cargo:rustc-link-lib=atomic");
}
