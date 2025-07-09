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
//! typhunix client program

use clap::Parser;
use futures::join;
use styx_emulator::grpc::typhunix_interop::json_util;
use tracing::debug;
use typhunix_client_bin::*;
use typhunix_config::AppConfig;

/// sim demo program
#[derive(clap::Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// List programs, symbols, datatypes
    #[arg(short, long, default_value_t = true)]
    list: bool,

    /// Dump symbols, datatypes to json files
    #[arg(short, long, default_value_t = false)]
    dump: bool,

    /// Load from json files and register_new
    #[arg(short, long, default_value_t = false)]
    import: bool,

    /// subscribe to updates
    #[arg(short, long, default_value_t = false)]
    subscribe: bool,

    /// unsubscribe to updates
    #[arg(short, long, default_value_t = false)]
    unsubscribe: bool,

    /// subscription ID (for unsubscribe)
    #[arg(long)]
    cli_uuid: Option<String>,

    /// drain the subscriber queue for the given sub_uuid
    #[arg(long, default_value_t = false)]
    drain: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let endpoint = &AppConfig::server_uri();
    debug!("endpoint: {}", endpoint);
    let args = Args::parse();
    if args.import {
        import(endpoint).await?;
    } else if args.subscribe {
        let (status, cli_uuid) = subscribe_all(endpoint).await.unwrap();
        println!("Subscribed: {:?}", (status, cli_uuid));
        println!("    use the id for unsubscribe ^^^^^^^^^^^");
    } else if args.unsubscribe {
        match args.cli_uuid {
            Some(x) => {
                let result = unsubscribe(endpoint, x).await.unwrap();
                println!("Unsubscribe: {:?}", result);
            }
            _ => println!("Need a --cli_uuid to unsubscribe"),
        }
    } else if args.drain {
        match args.cli_uuid {
            Some(x) => {
                let (syms, dts) = check_for_updates(endpoint, x).await.unwrap();
                if !syms.is_empty() {
                    println!("{} Symbol changes [consumed]", syms.len());
                    syms.iter().for_each(|s| {
                        println!("    => {:}", s.name);
                    });
                }
                if !dts.is_empty() {
                    println!("{} DataType changes [consumed]", dts.len());
                    dts.iter().for_each(|s| {
                        println!("    => {:}", s.name);
                    });
                }
            }
            _ => println!("Need a --cli_uuid to drain"),
        }
    } else if args.list {
        debug!("list programs ...");
        list_all(endpoint, args.dump).await?;
    }

    Ok(())
}

async fn import(endpoint: &str) -> Result<(), Box<dyn std::error::Error>> {
    for sym_file in glob::glob_with(
        &format!("{}/*/symbols*.json", AppConfig::config_dir()),
        glob::MatchOptions::new(),
    )
    .unwrap()
    .flatten()
    .map(|e| e.display().to_string())
    .collect::<Vec<String>>()
    .iter()
    {
        let dt_file = sym_file.replace("symbols_", "data_types_");
        let (symbols, data_types) = {
            let (s, d) = join!(
                json_util::symbols_from_file(sym_file),
                json_util::data_types_from_file(&dt_file)
            );
            (s.unwrap(), d.unwrap())
        };

        println!(
            "Loaded {} Symbols, {} data types",
            symbols.len(),
            data_types.len()
        );
        println!("Register: {}", endpoint);
        register_new(endpoint, symbols, data_types).await?;
    }
    Ok(())
}
