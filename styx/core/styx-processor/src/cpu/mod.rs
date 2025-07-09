// SPDX-License-Identifier: BSD-2-Clause
//! Part of the Processor Core used for instruction emulation.
//!
//! Each hook has a way to query resources on the processor
//!
//! The [`CpuBackend`] exposes the ability to create full system
//! emulators from the instruction emulators housed in this crate. The
//! [`CpuBackend`] trait exposes everything necessary to create a proper
//! emulator based on memory mapped register hooks, and exposes the
//! ability to add many more types of hooks as desired (see [`crate::hooks`]).
//!
//! If you want to add a new backend to the system see how it was done for
//! the unicorn backend at `styx/styx-cpu-unicorn-backend`.
//!
//! # Instruction Emulation Backends
//!
//! The `Styx` emulation model revolves around the execution of a [`CpuBackend`],
//!  and the implemented engine abstractions that reside in [`CpuBackend`].
//!
//! Under the hood [`CpuBackend`] uses monomorphization / static dispatch to
//! wrap and route calls to the underlying instruction emulation backend.
mod backend;
mod backend_ext;
mod dummy;

pub use backend::*;
pub use backend_ext::CpuBackendExt;
pub use dummy::DummyBackend;
