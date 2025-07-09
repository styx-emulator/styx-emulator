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
//! `gRPC` service for for trace execution analysis

use clap::Parser;
use std::collections::HashMap;
use styx_core::grpc::traceapp::trace_app_session_service_server::*;
use styx_core::sync::sync::{Arc, Mutex};
use styx_trace_tools::trace_sessions::session_mgr::SessionManager;
use tonic::transport;
use traceapp_service::svc::TraceAppSessionImpl;
use tracing::{error, info};

#[derive(Debug, Parser, Clone)]
#[command(author, version, about, long_about = None)]
pub(crate) struct Args {
    /// Port
    #[arg(short, long, default_value_t = 54321)]
    port: i32,

    /// listen/bind address
    #[arg(short, long, default_value_t = String::from("0.0.0.0")  )]
    bind_addr: String,
}

/// Starts the [TraceAppSessionServiceServer] GRPC service
/// - Constructs/owns the session manager and sessions
/// - Starts the session reaper task
async fn run_service(args: Args, reap: bool) -> Result<(), Box<dyn std::error::Error>> {
    let socket_addr = format!("{}:{}", args.bind_addr, args.port).parse()?;
    let sm = Arc::new(SessionManager::new(Arc::new(Mutex::new(HashMap::new()))));
    let smrefs = (sm.clone(), sm.clone());
    if reap {
        tokio::spawn(async move { smrefs.0.reaper_task().await });
    }
    info!("Started session reaper, running service");
    Ok(transport::Server::builder()
        .add_service(TraceAppSessionServiceServer::new(
            TraceAppSessionImpl::new(smrefs.1).await?,
        ))
        .serve(socket_addr)
        .await?)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    styx_core::util::logging::ServiceLog::new("traceapp-svc").create();
    // parse args
    let args = Args::parse();
    let reap = false;
    // delegate to run_service()
    if let Err(e) = run_service(args, reap).await {
        error!("{:?}", e);
        std::process::exit(1);
    }
    std::process::exit(0);
}
