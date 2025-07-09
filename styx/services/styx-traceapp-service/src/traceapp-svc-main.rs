// SPDX-License-Identifier: BSD-2-Clause
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
