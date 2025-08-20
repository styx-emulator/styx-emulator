// SPDX-License-Identifier: BSD-2-Clause
// import all the modules
mod blackfin;
mod elf;
mod parameterized;
mod raw;

// re-export under styx-loader::loaders::*;
pub use blackfin::BlackfinLDRLoader;
pub use elf::{ElfLoader, ElfLoaderConfig};
pub use parameterized::*;
pub use raw::RawLoader;
