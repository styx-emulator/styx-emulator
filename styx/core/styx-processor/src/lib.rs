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
//! Welcome to the guts of the operation!
//!
//! All engine responsibility at the [Processor](processor::Processor) level and below is
//! implemented in this crate.
//!
//! Get started by constructing a [Processor](processor::Processor) with the
//! [ProcessorBuilder](processor::ProcessorBuilder).
//!
//! The [Processor](processor::Processor) represents a full system emulated in Styx. It contains the
//! [core] components for execution, [plugins] to add custom defined behavior, an [executor] to
//! control execution behavior, and an async [runtime]. A Processor is owned and emulation requires
//! a mutable reference.
//!
//! The emulation core consists of a [CpuBackend](cpu::CpuBackend) for instruction emulation, a
//! [Mmu](memory::Mmu) for memory, and an [EventController](event_controller::EventController) for
//! holding peripherals and processing interrupts.
//!
//! # Processor Lifecycle
//!
//! 1. `building` - [`processor::ProcessorBuilder`]
//!   - Define target processor (e.g. Kinetis21, includes cpu, arch, variant, meta variant, and
//!     endianess), hooks, plugins, executor.
//! 2. `paused`
//!   - A built processor from [`processor::ProcessorBuilder::build()`].
//!   - Also return state after `running`
//! 3. `running` - [`executor::Executor::begin()`]
//!   1. `emulate` - [`cpu::CpuBackend::execute()`]
//!   2. `post stride processing` - [`executor::ExecutorImpl::post_stride_processing()`]
//!      - 1. `interrupt` - [`event_controller::EventControllerImpl::next()`]
//!      - 2. `tick`
//!      - [`event_controller::Peripheral::tick()`]
//!      - [`plugins::Plugin::tick()`]
//!   3. `valid_emulation_conditions` - [`executor::ExecutorImpl::valid_emulation_conditions()`]
//!
pub mod core;
pub mod cpu;
pub mod event_controller;
pub mod executor;
pub mod hooks;
pub mod memory;
pub mod plugins;
pub mod processor;
pub mod runtime;
