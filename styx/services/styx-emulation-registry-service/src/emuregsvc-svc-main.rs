// SPDX-License-Identifier: BSD-2-Clause
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
