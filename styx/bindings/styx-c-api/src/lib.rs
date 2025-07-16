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
