//! Hexagon Test Data
//!
//! Test data is built in the build script (`build.rs`) using docker and included at compile time
//! into this crate.
//!
//! Test completion for assembly tests are signaled by a trap0 with a status of 1. r6 will hold 94
//! and r0 will be 0 if failed, 1 if success. It is recommended to initialize r0 with a nonzero
//! value to avoid false passes.
//!
//! The C tests return an int ro report status but have not investigated how this translates to
//! baremetal.

#[cfg(feature = "binutils-tests")]
pub mod binutils_tests {
    //! Unit tests taken from binutils-gdb simulator.
    #[cfg(not(feature = "disable-hexagon-tests"))] // hack for when using `--all-features`
    use super::TestData;

    #[cfg(not(feature = "disable-hexagon-tests"))] // hack for when using `--all-features`
    include!(concat!(env!("OUT_DIR"), "/generated_binutils_binaries.rs"));
}

#[allow(dead_code)] // for now we only use this in binutils-tests
pub struct TestData {
    bytes: &'static [u8],
}

impl TestData {
    pub const fn new(data: &'static [u8]) -> Self {
        Self { bytes: data }
    }

    pub fn bytes(&self) -> &[u8] {
        self.bytes
    }

    // maybe methods here to get a tempfile, etc.
}
