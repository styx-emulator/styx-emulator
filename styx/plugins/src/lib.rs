// SPDX-License-Identifier: BSD-2-Clause
//! Plugin Collection for Styx
//!
//! The exposed plugins create the necessary executors, profilers,
//! tracers, and observability extensions that should together
//! fulfill most needs.
//!
//! - For backend tracing, see [`tracing_plugins`]
//! - For target tracing, see
//!     - [`styx-trace`](styx_trace)
//!     - [`StyxTracePlugin`](styx_trace::StyxTracePlugin)
//! - For help debugging or jump-starting a new emulation:
//!     - [`debug_tools`]
pub use styx_debug_tools as debug_tools;
pub use styx_fuzzer as fuzzer;
pub use styx_gdbserver as gdb;
pub use styx_trace_plugin as styx_trace;
pub use tracing_plugins;
pub mod testing_utils;
