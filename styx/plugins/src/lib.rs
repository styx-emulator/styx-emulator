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
pub use {
    styx_debug_tools as debug_tools, styx_fuzzer as fuzzer, styx_gdbserver as gdb,
    styx_trace_plugin as styx_trace, tracing_plugins,
};
pub mod testing_utils;
