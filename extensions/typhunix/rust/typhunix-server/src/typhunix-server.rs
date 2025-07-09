// SPDX-License-Identifier: BSD-2-Clause
//! Typhunix grpc server

use std::error::Error;

use clap::Parser;
use tracing::info;
use typhunix_server_bin::*;

/// Args for typhunix server
#[derive(clap::Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Load `~/.typhunix/cm-*.json` from config dir to seed the server
    /// with programs.
    #[arg(short, long, default_value_t = false)]
    import: bool,

    /// run on this tcp port
    #[arg(short, long, default_value_t = DEFAULT_TYPHUNIX_PORT)]
    port: u16,
}

#[tokio::main]
// main
async fn main() -> Result<(), Box<dyn Error>> {
    styx_emulator::core::util::logging::ServiceLog::new("typhunix").create();
    info!("Starting typhunix");
    let args = Args::parse();
    if let Err(e) = start(Some(args.port), args.import).await {
        eprintln!("{e}");
        std::process::exit(1);
    }
    std::process::exit(0);
}
