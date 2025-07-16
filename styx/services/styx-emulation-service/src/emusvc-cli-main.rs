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
use clap::{Args, Parser, Subcommand};
use std::error::Error;
use std::fmt::Debug;
use styx_core::grpc::{
    emulation::{
        single_emulation_service_client::SingleEmulationServiceClient, StartSingleEmulationRequest,
    },
    utils::Empty,
};
use styx_core::util::{logging::init_logging, traits::HasUrl};
use tonic::Request;

#[derive(Debug, Subcommand)]
enum Command {
    /// Drop the emulation
    Drop,
    /// Get Info
    Info,
    /// Start the emulation
    Start,
    /// Stop the emulation
    Stop,
}

#[derive(Debug, Args)]
struct URLArgs {
    // hostname or ip address
    #[arg(long, global=true, default_value_t = String::from("127.0.0.1"))]
    host: String,
    /// inet port
    #[arg(short, long, global = true, default_value_t = 10101)]
    port: u16,
}

#[derive(Debug, Parser)]
struct ClientArgs {
    #[clap(flatten)]
    url_opts: URLArgs,

    #[clap(subcommand)]
    command: Command,
}

impl HasUrl for URLArgs {
    fn url(&self) -> String {
        format!("http://{}:{}", self.host, self.port)
    }
}

fn display_response<T>(response: T)
where
    T: Debug,
{
    println!("===============================================================");
    println!("{response:?}");
    println!("===============================================================");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    init_logging();

    let args = ClientArgs::parse();
    let url = args.url_opts.url();
    match args.command {
        Command::Start => {
            display_response(
                SingleEmulationServiceClient::connect(url)
                    .await?
                    .start(Request::new(StartSingleEmulationRequest::default()))
                    .await?
                    .into_inner(),
            );
        }
        Command::Stop => {
            display_response(
                SingleEmulationServiceClient::connect(url)
                    .await?
                    .stop(Request::new(Empty::default()))
                    .await?
                    .into_inner(),
            );
        }
        Command::Drop => {
            display_response(
                SingleEmulationServiceClient::connect(url)
                    .await?
                    .drop(Request::new(Empty::default()))
                    .await?
                    .into_inner(),
            );
        }
        Command::Info => {
            display_response(
                SingleEmulationServiceClient::connect(url)
                    .await?
                    .info(Request::new(Empty::default()))
                    .await?
                    .into_inner(),
            );
        }
    }

    Ok(())
}
