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
//! Provides miscellaneous styx utility functions and abstractions.

pub mod gdb_xml;
mod late_init;
pub mod logging;
pub mod traits;
pub mod unsafe_lib;

// To avoid circular dependencies, don't use other styx crates
use convert_case::{Boundary, Case, Casing};
pub use late_init::LateInit;
use std::env;
use std::ffi::OsStr;
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Gets the least significant bit of `n`
///
/// ```rust
/// # use num_traits::PrimInt;
/// # use styx_util::get_lsb;
/// assert_eq!(get_lsb(50u32), 0);
/// assert_eq!(get_lsb(51u32), 1);
/// assert_eq!(get_lsb(0x4000000009u64), 1);
/// ```
pub fn get_lsb<N: num_traits::PrimInt>(n: N) -> N {
    n & N::one()
}

/// Gets the most significant bit of `n`
///
/// ```rust
/// # use num_traits::PrimInt;
/// # use styx_util::get_msb;
/// assert_eq!(get_msb(0x80000050u32), 1);
/// assert_eq!(get_msb(0x51000000u32), 0);
/// assert_eq!(get_msb(0x8000004000000009u64), 1);
/// ```
pub fn get_msb<N: num_traits::PrimInt>(n: N) -> N {
    let shift = std::mem::size_of::<N>() * 8 - 1;
    (n >> shift) & N::one()
}

/// Return a tuple (low16, low16) from u32 value
///
/// ```rust
/// # use styx_util::high_low_u32;
/// assert_eq!(high_low_u32(0xdeadbeef), (0xdead, 0xbeef));
/// assert_eq!(high_low_u32(std::u32::MIN), (std::u16::MIN, std::u16::MIN));
#[inline(always)]
pub fn high_low_u32(n: u32) -> (u16, u16) {
    ((n >> 16) as u16, n as u16)
}

/// Get inclusive bit range m..=n
///
/// ```rust
/// assert_eq!(styx_util::bit_range(0x30000, 16..=19), 0x3);
/// assert_eq!(styx_util::bit_range(0x1, 0..=1), 1);
/// assert_eq!(styx_util::bit_range(0b0101, 0..=2), 0b101);
/// assert_eq!(styx_util::bit_range(0xff00_ff00u32, 0..=15), 0xff00);
/// ```
pub fn bit_range<T: num_traits::PrimInt>(x: T, r: core::ops::RangeInclusive<usize>) -> T {
    fn get_bits<T: num_traits::PrimInt>(n: T, idx: usize, nbits: usize) -> T {
        (n >> idx) & (((T::one()) << nbits) - T::one())
    }
    get_bits(x, *r.start(), (*r.end() - *r.start()) + 1)
}

/// Return snake case version of the string
///
/// ```rust
/// use styx_util::camel_to_snake;
/// assert_eq!(camel_to_snake("SoThisBecomes"),"so_this_becomes" );
/// assert_eq!(camel_to_snake("ArmCortexM4"), "arm_cortex_m4".to_string());
/// assert_eq!(camel_to_snake("ArmV4"), "arm_v4".to_string());
/// ```
pub fn camel_to_snake(nm: &str) -> String {
    nm.from_case(Case::Camel)
        .without_boundaries(&[Boundary::UPPER_DIGIT])
        .to_case(Case::Snake)
}

/// Use this to resovlve any path relative to the root of the styx monorepo.
///
/// Resolve the `relative_path` from styx root. Returns a cannonical absolute
/// path as a `String`, which is not guaranteed to exist.
///
/// Use this to resolve any path from the root of the monorepo.
///
/// # Example
///
/// ```rust
/// let docs_dir = styx_util::resolve_path("docs");
/// let docs_path = std::path::Path::new(&docs_dir);
/// assert!(docs_path.exists());
/// assert!(docs_path.is_dir());
/// assert!(docs_path.is_absolute());
///```
/// # Panics
/// - panics if `relative_path` is not a relative path
///
/// # See Also
/// - [styx_root_pathbuf](fn@styx_root_pathbuf) is the basis for determining the
///   root path
/// - [test_bins_pathbuf](fn@test_bins_pathbuf) can be used for test binaries
///   in the [TEST_BINARY_RELATIVE_PATH] directory.
#[inline]
pub fn resolve_path<P: AsRef<OsStr> + ?Sized + std::fmt::Debug>(relative_path: &P) -> String {
    let mut pb = styx_root_pathbuf();
    let rp: PathBuf = relative_path.into();
    assert!(rp.is_relative());
    pb.push(rp.as_path());

    match pb.canonicalize() {
        Ok(buf) => buf.as_path().display().to_string(),
        Err(_) => panic!("Failed to find path: {relative_path:?}"),
    }
}

/// Get a PathBuf of the canonical, absolute path, to the root directory
/// for the cargo workspace (styx-emulator monorepo)
///
/// `CARGO_MANIFEST_DIR` is set by cargo, and is "the path to the manifest",
/// which is this crate's `Cargo.toml`, if the path of [`styx-util`] is
/// changed, this function will need to be updated.
#[inline]
pub fn styx_root_pathbuf() -> PathBuf {
    let output = std::process::Command::new(env!("CARGO"))
        .arg("locate-project")
        .arg("--workspace")
        .arg("--message-format=plain")
        .output()
        .unwrap()
        .stdout;
    let cargo_path = Path::new(std::str::from_utf8(&output).unwrap().trim());
    cargo_path.parent().unwrap().to_path_buf()
}

/// Directory, relative to the root for styx test binaries
///
/// See also:
/// - [styx_root_pathbuf](fn@styx_root_pathbuf)
/// - [test_bins_pathbuf](fn@test_bins_pathbuf)
pub const TEST_BINARY_RELATIVE_PATH: &str = "data/test-binaries";

/// Get a PathBuf of the canonical, absolute path, to the root directory
/// for the cargo workspace (styx-emulator).
///
/// Uses [TEST_BINARY_RELATIVE_PATH] to determine the relative path from root
/// which is resolved by [styx_root_pathbuf](fn@styx_root_pathbuf)
pub fn test_bins_pathbuf() -> PathBuf {
    let mut path_buf = styx_root_pathbuf();
    path_buf.push(PathBuf::from(TEST_BINARY_RELATIVE_PATH));
    path_buf.canonicalize().unwrap()
}

/// Resolve the `relative_path` and return a cannonical absolute path. the
/// `relative_path` should be relative to the test binaries folder at
/// `<ROOT>/<TEST_BINS>/<relative path>` where
/// - `<ROOT>` is resolved by [styx_root_pathbuf](fn@styx_root_pathbuf) and
/// - `<TEST_BINS>` is resolved by [test_bins_pathbuf](fn@test_bins_pathbuf),
///
/// # Example
///
/// ```rust
/// let blink_flash_str = styx_util::resolve_test_bin("arm/stm32f107/bin/blink_flash/blink_flash.bin");
/// let blink_flash_path = std::path::Path::new(&blink_flash_str);
/// assert!(blink_flash_path.exists());
/// assert!(blink_flash_path.is_file());
/// assert!(blink_flash_path.is_absolute());
///```
///
/// # Pancs
/// - panics if `relative_path` is not a relative path
pub fn resolve_test_bin<P: AsRef<OsStr> + ?Sized>(relative_path: &P) -> String {
    let mut pb = test_bins_pathbuf();
    let rp: PathBuf = relative_path.into();
    assert!(rp.is_relative());
    pb.push(rp.as_path());
    let val = pb.canonicalize().unwrap().as_path().display().to_string();
    val
}

/// Given an array of bytes, writes the contents to a tmp file
/// and returns the handle to it. The file will be automatically
/// deleted when the object goes out of scope.
pub fn bytes_to_tmp_file(data: &[u8]) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(data).unwrap();

    file
}

/// Parses an `objdump -d` output and returns an iterator over the code bytes.
///
/// This is useful for tests with a binary that but want to include the
/// disassembly to help future developers understand what code is being
/// executed. This is also helpful for test iteration as when developing with a
/// compiled a binary you can simply paste in the objdump output instead of
/// pasting and formatting raw bytes.
///
/// ```
/// use styx_util::parse_objdump;
///
/// let objdump = r#"
///     10c:    7c 3f 0b 78     mr      r31,r1
///     110:    3d 20 00 00     lis     r9,0
///     114:    39 40 00 00     li      r10,0
///     11c:    39 20 00 00     li      r9,0
///     124:    48 00 00 28     b       14c <main+0x4c>
///     128:    3d 20 00 00     lis     r9,0
///     134:    7d 4a 4a 14     add     r10,r10,r9
///     138:    3d 20 00 00     lis     r9,0
///     144:    39 29 00 01     addi    r9,r9,1
///     150:    2c 09 27 0f     cmpwi   r9,9999
///     154:    40 81 ff d4     ble     128 <main+0x28>
///     158:    3d 20 00 00     lis     r9,0
///     160:    7d 2f 4b 78     mr      r15,r9
///     164:    60 00 00 00     nop
///     168:    60 00 00 00     nop
///     16c:    4b ff ff fc     b       168 <main+0x68>
///     "#;
///
/// let mut bytes = parse_objdump(objdump).unwrap();
/// assert_eq!(bytes[0], 0x7c);
/// assert_eq!(bytes[1], 0x3f);
/// assert_eq!(bytes[2], 0x0b);
/// assert_eq!(bytes[3], 0x78);
/// ```
pub fn parse_objdump(objdump: &str) -> Result<Vec<u8>, InvalidObjdumpFormat> {
    objdump
        .lines()
        .flat_map(|line| {
            line.split_whitespace()
                .enumerate()
                .filter_map(|(idx, col_str)| (1..=4).contains(&idx).then_some(col_str))
        })
        .map(|byte_str| u8::from_str_radix(byte_str, 16).map_err(|_| InvalidObjdumpFormat))
        .collect()
}
#[derive(Error, Debug)]
#[error("could not parse objump format")]
pub struct InvalidObjdumpFormat;

pub mod dtutil;

/// A [`todo!`] alternative that does not prevent subsequent semantic evaluation.
#[inline(always)]
#[track_caller]
pub fn todo<T>(message: &'static str) -> T {
    todo!("{}", message)
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_high_low_u32() {
        assert_eq!(high_low_u32(u32::MAX), (u16::MAX, u16::MAX));
        assert_eq!(high_low_u32(u32::MIN), (u16::MIN, u16::MIN));
        assert_eq!(high_low_u32(0x10001), (0x1, 0x1));
        assert_eq!(high_low_u32(0xdeadbeef), (0xdead, 0xbeef));
    }

    #[test]
    fn test_camel_to_snake() {
        assert_eq!(camel_to_snake("SoThisBecomes"), "so_this_becomes");
        assert_eq!(camel_to_snake("ArmCortexM4"), "arm_cortex_m4".to_string());
        assert_eq!(camel_to_snake("ArmV4"), "arm_v4".to_string());
    }

    #[test]
    #[cfg_attr(miri, ignore)] // uses a syscall
    fn test_styx_root() {
        let root = styx_root_pathbuf();
        assert!(root.is_dir());
        assert!(root.is_absolute());
        assert!(root.exists());
    }

    #[test]
    #[cfg_attr(miri, ignore)] // uses a syscall
    fn test_test_bins_pathbuf() {
        let datapath = test_bins_pathbuf();
        println!("{:?}", datapath);
        assert!(datapath.is_dir());
        assert!(datapath.is_absolute());
        assert!(datapath.exists());
    }

    #[test]
    #[cfg_attr(miri, ignore)] // uses a syscall
    fn test_resolve_path() {
        let path_string =
            resolve_path("data/test-binaries/arm/stm32f107/bin/blink_flash/blink_flash.bin");
        assert!(Path::new(&path_string).exists());
    }

    #[test]
    #[cfg_attr(miri, ignore)] // uses a syscall
    fn test_resolve_path_is_canonical() {
        let filename = "CONTRIBUTING.md";
        let contrib_str = resolve_path(&format!("./{filename}"));
        let path = Path::new(&contrib_str);
        assert!(path.exists());
        assert!(path.is_file());
        assert!(path.is_absolute());
        assert_eq!(path.file_name().unwrap(), filename);

        assert_eq!(
            path.display().to_string(),
            format!(
                "{}/{filename}",
                styx_root_pathbuf().as_path().to_string_lossy(),
            )
        );

        log::debug!("{}", path.display());
    }

    #[test]
    #[should_panic]
    fn test_todo() {
        struct Foo {
            _a: u32,
        }
        let _foo = Foo {
            _a: super::todo("value not implemented"),
        };

        // this is still evaluated by check/clippy
        let _bar = Foo { _a: 24 };
    }
}
