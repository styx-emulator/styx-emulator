//! Blackfin Test Data
//!
//! Test data is built in the build script (`build.rs`) using docker and included at compile time
//! into this crate.

#[cfg(feature = "binutils-tests")]
pub mod binutils_tests {
    //! Unit tests taken from binutils-gdb simulator.
    #[cfg(not(feature = "disable-blackfin-tests"))] // hack for when using `--all-features`
    use super::TestData;

    #[cfg(not(feature = "disable-blackfin-tests"))] // hack for when using `--all-features`
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
