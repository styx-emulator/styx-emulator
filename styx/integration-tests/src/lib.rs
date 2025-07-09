// SPDX-License-Identifier: BSD-2-Clause
// mod runner;

use std::ffi::OsStr;
use std::path::Path;
use std::path::PathBuf;

pub mod gdb_core_integration_test_suite;
pub mod gdb_harness;
mod runner;
pub mod uart_integration;

pub use runner::run_test;
pub use runner::ProcessorIntegrationTest;

/// Return true if the path exists, false otherwise
#[inline]
pub fn path_exists<S: AsRef<OsStr> + ?Sized>(path: &S) -> bool {
    Path::new(path).exists()
}

/// Return the size of the file.
/// **Panics** on `io` Error (does not exist, insufficient privs)
#[inline]
pub fn file_size<P: AsRef<Path>>(path: P) -> u64 {
    std::fs::metadata(path).unwrap().len()
}

/// Relative path to `blink_flash.bin` under test binaries
/// see [test_bins_pathbuf](fn@styx_core::util::test_bins_pathbuf)
pub const TEST_BIN_BLINK_FLASH: &str = "arm/stm32f107/bin/blink_flash/blink_flash.bin";

pub struct TestBins {}
impl TestBins {
    /// Return absolution path to `blink_flash.bin`
    pub fn gpio_blink_bin() -> String {
        let mut pb = styx_core::util::test_bins_pathbuf();
        pb.push::<PathBuf>(TEST_BIN_BLINK_FLASH.into());
        pb.as_path().display().to_string()
    }
}
