// SPDX-License-Identifier: BSD-2-Clause
//! [`GdbExecutor`] and [`TargetImpl`](target_impl::TargetImpl)
//! for styx emulators.
//!
//! # Overview
//!
//! The `GdbExecutor` leverages the
//! [`gdbstub`](https://docs.rs/gdbstub/0.6.6/gdbstub/) crate to enable debugging
//! for styx emulators.
//!
//! Implementation is largely driven by:
//! - gdbstub trait implementation ([`TargetImpl`](target_impl::TargetImpl))
//! - cpu/architecture metadata from [`ArchitectureDef`](styx_core::cpu::arch::ArchitectureDef) exposed by the [`Processor`](styx_core::processor::Processor)
//!   trait.
//!
//! ## Loading and using `GdbExecutor`
//!
//! - See [Loading and using `GdbExecutor`](plugin::GdbExecutor)
//!
//! ## Implementation Details
//!
//! As the [gdbstub docs](https://docs.rs/gdbstub/0.6.6/gdbstub/) explain, three
//! items are needed for integration with `gdbstub`:
//!
//! **Connection**
//! - A way to communicate with a GDB client using gdbstub's
//!   [Connection trait](https://docs.rs/gdbstub/0.6.6/gdbstub/conn/trait.ConnectionExt.html)
//! - This is mostly provided by gdbstub, but [the event_loop](event_loop) module
//!   has a [`WaitForConnection`](event_loop::WaitForConnection) trait
//!   that supports [`TCP`](event_loop::TcpParameters) and
//!   [`unix domain sockets`](event_loop::UdsParameters).
//!
//! **Target trait**
//! - Describes how to control and modify the emulator's execution state during a
//!   GDB debugging session, and serves as the primary bridge between gdbstub’s
//!   generic GDB protocol implementation and a styx emulator.
//! - This is implemented specifically for all [`styx_core::cpu`] targets and
//!   more generally in the [`target_impl`] module. Most of this module (gdb)
//!   is concerned with defining [`target_impl::TargetImpl`] and implementing
//!   [`gdbstub::Target`](https://docs.rs/gdbstub/0.6.6/gdbstub/target/trait.Target.html)
//!   traits.
//!
//! **Event Loop**
//! - The call flow and I/O between the emulated target and the gdb client.
//! - [`EmuGdbEventLoop`](event_loop::EmuGdbEventLoop) provides a blocking event
//!   loop by implementing
//!   [gdbstub's BlockingEventLoop](https://docs.rs/gdbstub/0.6.6/gdbstub/stub/run_blocking/trait.BlockingEventLoop.html)
//!   trait.
//!
#![allow(rustdoc::private_intra_doc_links)]
pub(crate) mod breakpoint_manager;
pub(crate) mod event_loop;
pub(crate) mod mem_watch;
pub(crate) mod monitor;
pub(crate) mod plugin;
pub(crate) mod target_impl;
use styx_core::cpu::arch::GdbArchIdSupportTrait;

pub use event_loop::GdbPluginParams;
pub use plugin::GdbExecutor;
