// SPDX-License-Identifier: BSD-2-Clause
//! Machine definition for the Ppc4xx family.
use clap::Parser;
use styx_emulator::arch::ppc32::gdb_targets::Ppc4xxTargetDescription;
use styx_emulator::core::util::logging::init_logging;
use styx_emulator::plugins::gdb::{GdbExecutor, GdbPluginParams};
use styx_emulator::plugins::tracing_plugins::*;
use styx_emulator::prelude::*;
use styx_emulator::processors::ppc::ppc4xx::PowerPC405Builder;

/// PowerPc 4xx emulation, controlled via gdb remote on `:9999`
///
/// Level of trace logging is determined by the command line arguments
/// provided. `--firmware-path` is mandatory. As with most all rust
/// applications, `RUST_LOG` also plays into the tracing verbosity.
#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct TargetArgs {
    /// Path to the target firmware `.bin`, required.
    #[arg(short, long)]
    firmware_path: String,

    /// Enable json trace logging, extremely verbose, bad practice
    /// to use this instead of `styx-trace`
    #[arg(short, long, default_value_t = false)]
    json_trace: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // parse our simple cli args
    let args = TargetArgs::parse();

    // build the arguments to the gdb server plugin
    let gdb_params = GdbPluginParams::tcp("0.0.0.0", 9999, true);

    // example yaml file to load a `TargetProgram`
    let loader_yaml = format!(
        r#"
        - !FileRaw
            base: 0xfff00000
            file: {}
            # Permissions for the allocated memory. Valid permissions are ReadOnly,
            # WriteOnly, ExecuteOnly, ReadWrite, ReadExecute and AllowAll.
            perms: !AllowAll
        - !RegisterImmediate
            # Register to be loaded with a value.
            register: pc
            # Immediate value to load into the register.
            value: 0xfffffffc
"#,
        args.firmware_path
    );

    // build the processor
    let mut proc_builder = ProcessorBuilder::default()
        .with_builder(PowerPC405Builder::default())
        .with_executor(GdbExecutor::<Ppc4xxTargetDescription>::new(gdb_params)?)
        .with_loader(ParameterizedLoader::default()) // takes an input yaml
        .with_input_bytes(loader_yaml.as_bytes().into());

    // It is bad practice to use these instead of `styx-trace`
    //
    // This is only to help first-timers build trust in emulation
    if args.json_trace {
        proc_builder = proc_builder
            .add_plugin(ProcessorTracingPlugin)
            .add_plugin(JsonMemoryReadPlugin)
            .add_plugin(JsonMemoryWritePlugin)
            .add_plugin(JsonPcTracePlugin)
            .add_plugin(JsonInterruptPlugin);
    } else {
        // utility function to enable logging, in production setups
        // it is better to utilize `ProcessorTracingPlugin`.
        //
        // Note that only 1 log handler can be present or you will runtime panic.
        // this is a side-effect of rust core language infrastructure
        init_logging();
    }

    // actually "build" the processor now that all the options
    // are initialized
    let mut proc = proc_builder.build()?;

    // start `TargetProgram` execution
    proc.run(Forever)?;

    Ok(())
}
