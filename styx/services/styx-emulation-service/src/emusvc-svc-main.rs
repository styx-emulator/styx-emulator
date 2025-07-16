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
//! Executable which launches a [SingleEmulationServiceServer] based on the input.
//!
//! The server implements [SingleEmulationService](styx_core::grpc::emulation::single_emulation_service_server::SingleEmulationService)

const IPC_HOST_ADDR: &str = "127.0.0.1";

use clap::Parser;
use emulation_service::emulation_args::{CliEmulationArgs, SingleEmulationServiceExecutor};
use emulation_service::processor_factory::ProcessorFactory;
use styx_core::errors::styx_grpc::ApplicationError;
use styx_core::grpc::args::HasEmulationArgs;
use styx_core::grpc::emulation::single_emulation_service_server::SingleEmulationServiceServer;
use styx_core::tracebus::STRACE_ENV_VAR;
use tokio::net::TcpListener;
use tracing::{error, info};

/// Create and start a
/// [SingleEmulationService](styx_core::grpc::emulation::single_emulation_service_server::SingleEmulationService)
/// gRPC service on a random tcp port. The emulation is initialized but not running
/// and can be started/stopped with the `SingleEmulationService` API.
fn create_emulator_service<T: HasEmulationArgs + std::fmt::Debug>(
    args: &T,
    start: bool,
) -> Result<(), ApplicationError> {
    info!(
        "initialize_emulator: single_emulation_service_args: {:?}",
        args
    );

    let processor_instance = ProcessorFactory::create_processor(args)?;

    println!(
        "SingleEmulationServiceServer metadata: {}",
        processor_instance.metadata_json(false)
    );

    let tcp_listener = std::net::TcpListener::bind("0.0.0.0:0")?;
    tcp_listener.set_nonblocking(true)?;

    let addr = tcp_listener.local_addr()?.to_string();
    let port = tcp_listener.local_addr()?.port();
    if start {
        processor_instance.start_processor();
    }
    // Communicate to the caller / executor the host, port, and styx trace path
    SingleEmulationServiceExecutor::broadcast_service_meta(
        IPC_HOST_ADDR,
        port,
        &processor_instance.trace_path(),
    );

    let rt = tokio::runtime::Runtime::new().unwrap();

    processor_instance.set_port(port);
    rt.block_on(async {
        info!("{addr}");
        tonic::transport::Server::builder()
            .add_service(SingleEmulationServiceServer::new(processor_instance))
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(
                TcpListener::from_std(tcp_listener).expect("Failed to use std::net::TcpListener"),
            ))
            .await
    })?;

    Ok(())
}

fn main() {
    styx_core::util::logging::ServiceLog::new("emusvc")
        .with_timestamp(true)
        .create();
    let args = CliEmulationArgs::parse();
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe { std::env::set_var(STRACE_ENV_VAR, "srb") };
    info!("Input as yaml:");
    info!("{}---", serde_yaml::to_string(&args).unwrap());

    if args.dry_run {
        info!("Dry run, not executing");
        std::process::exit(0);
    }

    if let Err(e) = create_emulator_service(&args, args.start) {
        let message = format!("Failed to create or initialize emulator: {e}");
        eprintln!("{message} (exit 1)");
        error!("{message} (exit 1)");
        std::process::exit(1);
    }
    info!("exit(0)");
    std::process::exit(0);
}
