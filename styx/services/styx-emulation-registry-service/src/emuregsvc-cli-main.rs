// SPDX-License-Identifier: BSD-2-Clause
//! Client program for the trace execution service

use clap::{Args, Parser, Subcommand};
use std::error::Error;
use std::fmt::Debug;
use styx_core::grpc::{
    args::HasEmulationArgs,
    emulation_registry::{
        emulation_registry_service_client::EmulationRegistryServiceClient,
        StartTraceExecutionRequest,
    },
    utils::{Empty, EmuMetadataList, Token},
};
use styx_core::util::{logging::init_logging, traits::HasUrl};
use tonic::Request;

#[derive(Debug, Subcommand)]
enum Command {
    /// Drop the emulation
    Drop(TokenArg),
    /// Create/initialize a new emulation
    Init(BaseEmuArgs),
    /// List running emulations
    List,
    /// Start the emulation
    Start(TokenArg),
    /// Stop the emulation
    Stop(TokenArg),
}

/// Run a styx emulation
#[styx_macros_args::styx_app_args]
pub struct BaseEmuArgs {}

#[derive(Debug, Args)]
struct URLArgs {
    #[arg(long, global=true, default_value_t = String::from("127.0.0.1"))]
    host: String,
    /// port
    #[arg(short, long, global = true, default_value_t = 10101)]
    port: u16,
}

#[derive(Debug, Args)]
struct TokenArg {
    /// token
    #[arg(short, long, required = true)]
    token_id: u64,
}

#[derive(Debug, Parser)]
struct ClientArgs {
    #[clap(flatten)]
    global_opts: URLArgs,

    #[clap(subcommand)]
    command: Command,
}

impl HasUrl for URLArgs {
    fn url(&self) -> String {
        format!("http://{}:{}", self.host, self.port)
    }
}

async fn list(dst: &str) -> Result<EmuMetadataList, Box<dyn Error>> {
    let mut cli = EmulationRegistryServiceClient::connect(dst.to_owned()).await?;
    let r = cli.list(Request::new(Empty::default())).await?.into_inner();
    Ok(r)
}

async fn display_response<T>(response: &T)
where
    T: Debug,
{
    println!("------------------------------\n{:?}\n--", response);
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    init_logging();
    let args = ClientArgs::parse();

    let url = args.global_opts.url();
    match args.command {
        Command::List => {
            list(&url).await?.meta_data.iter().for_each(|item| {
                let token = match item.token {
                    Some(t) => t.inner_token.to_string(),
                    _ => " ".to_string(),
                };
                println!(
                    "{}: {:?} {} [{}] [pid: {}]",
                    token,
                    item.state(),
                    item.url,
                    item.trace_file_path,
                    item.process_id
                );
            });
        }

        Command::Init(args) => {
            display_response(
                &EmulationRegistryServiceClient::connect(url)
                    .await?
                    .initialize(StartTraceExecutionRequest {
                        args: Some(args.as_emulation_args()),
                    })
                    .await?
                    .into_inner(),
            )
            .await;
        }
        Command::Start(token) => {
            display_response(
                &EmulationRegistryServiceClient::connect(url)
                    .await?
                    .start(Request::new(Token {
                        inner_token: token.token_id,
                    }))
                    .await?
                    .into_inner(),
            )
            .await;
        }
        Command::Stop(token) => {
            display_response(
                &EmulationRegistryServiceClient::connect(url)
                    .await?
                    .stop(Request::new(Token {
                        inner_token: token.token_id,
                    }))
                    .await?
                    .into_inner(),
            )
            .await;
        }
        Command::Drop(token) => {
            display_response(
                &EmulationRegistryServiceClient::connect(url)
                    .await?
                    .drop(Request::new(Token {
                        inner_token: token.token_id,
                    }))
                    .await?
                    .into_inner(),
            )
            .await;
        }
    }
    Ok(())
}
