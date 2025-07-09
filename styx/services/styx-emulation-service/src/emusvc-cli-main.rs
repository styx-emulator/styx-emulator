// SPDX-License-Identifier: BSD-2-Clause
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
    println!("{:?}", response);
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
