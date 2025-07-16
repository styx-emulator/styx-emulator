// SPDX-License-Identifier: BSD-2-Clause
#![feature(try_trait_v2)]
#![allow(non_snake_case)]

/// data structures & structured data for c-interop
pub mod data;
pub(crate) use data::{try_out, try_unit};

/// CPU based API's including the CPU Backend API, CPU hooks, and memory management apis
pub mod cpu;

/// All of Styx' supported executors
pub mod executor;

/// All of Styx' supported target loaders
pub mod loader;

/// All of Styx' support processor plugins
pub mod plugin;

/// All Processor related API's include the processor builder and c2 API
pub mod processor;

/// All support CPU targets
pub mod target;

mod util {
    use crate::data::{CStrPtr, StyxFFIErrorPtr};

    /// Initialize styx logging, this only has effect if you also add the StyxPlugin_StyxTracePlugin
    #[unsafe(no_mangle)]
    pub extern "C" fn Styx_init_logging(level_len: u32, level: CStrPtr) -> StyxFFIErrorPtr {
        let level = level.as_str(level_len)?;
        println!("log level: {level:?}");
        // TODO: Audit that the environment access only happens in single-threaded code.
        unsafe { std::env::set_var("RUST_LOG", level) };
        StyxFFIErrorPtr::Ok
    }
}
