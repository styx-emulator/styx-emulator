// SPDX-License-Identifier: BSD-2-Clause

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use styx_emulator::{
    errors::UnknownError,
    prelude::{logging::init_logging, Forever},
};
use styx_uconf::components::Context;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Lists available components.
    List,
    /// Runs a configuration file.
    Run(RunOptions),
}

#[derive(Args)]
struct RunOptions {
    /// File to run
    #[arg(default_value = "styx.yaml")]
    processors_yaml: PathBuf,
}

fn main() -> Result<(), UnknownError> {
    init_logging();
    let cli = Cli::parse();
    match cli.command {
        Some(c) => match c {
            Commands::List => {
                let mapper = styx_uconf::ProcessorComponentsStore::new();
                fn print_list(items: impl Iterator<Item = impl AsRef<str>>) {
                    for item in items {
                        println!("- {}", item.as_ref())
                    }
                }
                println!("processors:");
                print_list(mapper.builders.list());
                println!("executors:");
                print_list(mapper.executors.list());
                println!("plugins:");
                print_list(mapper.plugins.list());
            }
            Commands::Run(run_options) => {
                let yaml =
                    std::fs::read_to_string(&run_options.processors_yaml).with_context(|| {
                        format!(
                            "could not read processors yaml file {:?}",
                            &run_options.processors_yaml
                        )
                    })?;

                let builders = styx_uconf::realize_unified(yaml)
                    .with_context(|| "could not realize processors")?;
                let processors = builders
                    .into_iter()
                    .map(|b| b.build())
                    .collect::<Result<Vec<_>, _>>()
                    .with_context(|| "could not build processors")?;

                let mut threads = Vec::new();
                for mut processor in processors.into_iter() {
                    let handle = std::thread::spawn(move || {
                        processor
                            .run(Forever)
                            .with_context(|| "error during processor execution")
                            .unwrap();
                    });
                    threads.push(handle);
                }

                for handle in threads.into_iter() {
                    handle.join().unwrap();
                }
            }
        },
        None => todo!(),
    }

    Ok(())
}
