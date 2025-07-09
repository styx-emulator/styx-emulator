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
pub use styx_cpu_unicorn_backend::UnicornBackend;

// re-export all pub interfaces + enums
#[doc(inline)]
pub use styx_cpu_type::arch;
pub use styx_cpu_type::*;
