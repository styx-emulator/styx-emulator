// SPDX-License-Identifier: BSD-2-Clause

use clap::Parser;
use devices::pixel5::Pixel5;
use devices::s22::S22;
use devices::tester::Tester;
use devices::{HexagonDevice, HexagonTarget};
use runner::{HexagonBinaryType, HexagonDebuggerInfo};
use styx_emulator::prelude::log::info;
use styx_emulator::prelude::logging::init_logging;
use styx_emulator::prelude::styx_async::sync::broadcast;
use styx_emulator::prelude::*;

mod devices;
mod runner;

mod tester;

const CHANNEL_SIZE: usize = 1024;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct HexagonTesterArgs {
    #[arg(required = true)]
    file_name: String,

    // default_value_t doesn't work here
    #[arg(short, long, default_value = "s22")]
    target: HexagonTarget,

    #[arg(short, long, default_value_t = 9999)]
    gdb_remote_port: u16,

    #[arg(short, long, default_value_t = false)]
    debug: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    init_logging();

    let args = HexagonTesterArgs::parse();

    let device: Box<dyn HexagonDevice> = match args.target {
        HexagonTarget::S22 => Box::new(S22::default()),
        HexagonTarget::Pixel5 => Box::new(Pixel5::default()),
        HexagonTarget::Tester => Box::new(Tester::default()),
    };

    // Semihosting channel
    let (tx, mut rx) = broadcast::channel(CHANNEL_SIZE);

    let mut proc = runner::setup_load_hexagon(
        HexagonBinaryType::FilePath(args.file_name),
        if args.debug {
            Some(HexagonDebuggerInfo {
                gdb_remote_port: args.gdb_remote_port,
            })
        } else {
            None
        },
        device.as_ref(),
        Arc::new(tx),
    )?;

    // Start thread that gets TX output and prints it
    thread::spawn(move || {
        while let Ok(chr) = rx.blocking_recv() {
            print!("{}", chr as char);
        }
    });

    info!("Starting emulator");
    proc.run(Forever)?;

    Ok(())
}
