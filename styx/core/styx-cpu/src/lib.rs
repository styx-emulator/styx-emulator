// SPDX-License-Identifier: BSD-2-Clause
//! # styx-cpu
//! Exposed from this crate is the [`Arch`] and enum and the architecture
//! variants/families that are exposed by [`ArchitectureVariant`](arch::ArchitectureVariant).
//!
//! - [`Arch`] (architecture selection)
//! - [`ArchEndian`] (endianness selection)
//! - [`ArchVariant`](arch::backends::ArchVariant) (Architecture sub-family / variant selection)
//!     - Note that each architecture has their own `<ArchName>Variants` struct to import
//!         - eg. arm -> [`styx_cpu::arch::arm::ArmVariants`](crate::arch::arm::ArmVariants)
//! - [`Backend`] (backend executor selection)
//!
//! See the docs of [`arch`] to get a better picture of how things work
//! when referring to specifics of different architectures and the
//! architectural details of them.
//!
//! By combining the details of the above list you are able to create an operable
//! "description" of how you want an instruction emulation to behave, and get an
//! equivalent pre-made [`ArchitectureDef`](arch::ArchitectureDef) that is
//! representative of your target processor / cpu core.
#![allow(rustdoc::private_intra_doc_links)] // for the above link to `arch::backends::ArchVariant`

pub use styx_cpu_pcode_backend::{PcodeBackend, PcodeBackendConfiguration};
#[cfg(feature = "unicorn-backend")]
pub use styx_cpu_unicorn_backend::UnicornBackend;

// re-export all pub interfaces + enums
#[doc(inline)]
pub use styx_cpu_type::arch;
pub use styx_cpu_type::*;
