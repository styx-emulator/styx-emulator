// SPDX-License-Identifier: BSD-2-Clause
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
pub use core::sync::sync;
pub use core::{arch, cpu, errors, grpc, hooks, loader, peripheral_clients, processor, tracebus};

pub use {
    styx_core as core, styx_devices as devices, styx_event_controllers as event_controllers,
    styx_integration_tests as integration_tests, styx_peripherals as peripherals,
    styx_plugins as plugins, styx_processors as processors,
};

pub mod prelude {
    pub use super::core::prelude::*;
    pub use super::integration_tests::*;
    pub use super::peripherals::*;
    pub use super::plugins::*;
}
