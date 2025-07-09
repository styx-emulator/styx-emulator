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
//! Provides an importable daemon service to control
//! emulator's and their tracing

use clap::Parser;
use emulation_registry_service::svc::{EmulationInstanceRegistry, TraceRegistry};
use std::error::Error;
use styx_core::sync::sync::Arc;
use tracing::info;

/// Run a daemon that initiates emulators that emit
/// `styx-trace` events
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value_t = 10101)]
    port: u16,

    /// If set, display idl / styx-core enumeration mappings and exit
    #[arg(short, long, default_value_t = false)]
    meta: bool,
}

#[tokio::main]
#[allow(dead_code)]
pub(crate) async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    if args.meta {
        let response = styx_trace_tools::identity::identity_mapping_response();
        println!("{}", serde_json::to_string_pretty(&response).unwrap());
        std::process::exit(0);
    }

    styx_core::util::logging::ServiceLog::new("emuregsvc-svc").create();
    let reg = EmulationInstanceRegistry::new();
    let address = format!("0.0.0.0:{}", args.port);
    let server = TraceRegistry::new(Arc::new(reg));
    let sa = address.parse()?;
    info!("Starting service at: {}", sa);
    tonic::transport::Server::builder()
        .add_service(server)
        .serve(sa)
        .await?;
    Ok(())
}
