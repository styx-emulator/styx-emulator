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
