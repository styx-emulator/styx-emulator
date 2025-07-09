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
