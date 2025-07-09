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
//! # Styx
//!
//! This is the frontend crate for the *`styx`* composable emulation
//! framework.
//!
//! You can quickly get started by importing the prelude:
//! ```rust
//! use styx_emulator::prelude::*;
//! ```
//!
//! The lib frontend internally is importing:
//! ```ignore
//! pub use core::arch;
//! pub use core::cpu;
//! pub use core::errors;
//! pub use core::grpc;
//! pub use core::loader;
//! pub use core::peripheral_clients;
//! pub use core::sync::sync;
//! pub use styx_core as core;
//! pub use styx_devices as devices;
//! pub use styx_event_controllers as event_controllers;
//! pub use styx_integration_tests as integration_tests;
//! pub use styx_peripherals as peripherals;
//! pub use styx_plugins as plugins;
//! pub use styx_processors as processors;
//!
//! pub mod prelude {
//!     pub use super::core::prelude::*;
//!     pub use super::integration_tests::*;
//!     pub use super::peripherals::*;
//!     pub use super::plugins::*;
//! }
//! ```
pub use core::arch;
pub use core::cpu;
pub use core::errors;
pub use core::grpc;
pub use core::hooks;
pub use core::loader;
pub use core::peripheral_clients;
pub use core::processor;
pub use core::sync::sync;
pub use core::tracebus;
pub use styx_core as core;
pub use styx_devices as devices;
pub use styx_event_controllers as event_controllers;
pub use styx_integration_tests as integration_tests;
pub use styx_peripherals as peripherals;
pub use styx_plugins as plugins;
pub use styx_processors as processors;

pub mod prelude {
    pub use super::core::prelude::*;
    pub use super::integration_tests::*;
    pub use super::peripherals::*;
    pub use super::plugins::*;
}
