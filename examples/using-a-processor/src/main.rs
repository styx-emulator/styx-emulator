// SPDX-License-Identifier: BSD-2-Clause
//! This binary is an example use of [`styx-emulator`] to emulate
//! a Kinetis K21 (ARMv7) chip.
//!
//! This machine will initialize the memory state,
//! setup peripherals, and run a pre-packaged basic firmware.
#![allow(dead_code)] // for this example, linters will complain due to the cfg's

use std::env;
#[cfg(not(feature = "trace"))]
use styx_emulator::core::util::logging::init_logging;
use styx_emulator::loader::RawLoader;
#[cfg(feature = "trace")]
use styx_emulator::plugins::tracing_plugins::{
    JsonMemoryReadPlugin, JsonMemoryWritePlugin, JsonPcTracePlugin, ProcessorTracingPlugin,
};
use styx_emulator::prelude::*;
use styx_emulator::processors::arm::kinetis21::Kinetis21Builder;
use tracing::info;

/// Sets the environment log level to `info` by force, if it is not already
/// set to something reasonable to view output from the example emulation
fn set_env_log_info() {
    env::set_var(
        "RUST_LOG",
        match env::var("RUST_LOG") {
            Ok(v) => v,
            Err(_) => "debug".to_string(),
        },
    );
}

/// Get the path to the firmware. Use env::var("FIRMWARE_PATH") if its set, use
/// the const FW_PATH if not.
fn get_firmware_path() -> String {
    match env::var("FIRMWARE_PATH") {
        Ok(v) => v,
        Err(_) => styx_emulator::core::util::resolve_test_bin(
            "arm/kinetis_21/bin/freertos_hello/freertos_hello_debug.bin",
        ),
    }
}

fn main() -> Result<(), UnknownError> {
    // its an example, force info log level so people see stuff
    // if its not set in the environment
    set_env_log_info();

    // Set up logging.
    // NOTE: Logging acts as a tracing subscriber. The tracing plugins below also act as a tracing
    // sink. Since there can only be one tracing sink at a time, logging and the tracing plugins
    // cannot both be used simultaneously.
    #[cfg(not(feature = "trace"))]
    init_logging();

    info!("Building processor.");

    // create a builder for the processor, this is a pretty bog
    // standard builder-pattern that is common among rust projects
    // due to the simple data-ownership
    let builder = ProcessorBuilder::default()
        .with_builder(Kinetis21Builder::default())
        .with_loader(RawLoader)
        .with_target_program(get_firmware_path());

    // Note that it is bad practice to use the JSON console logging plugins,
    // for production setups you should make a `styx-trace` consumer and
    // work off that that data as it will not slow down the emulation
    #[cfg(feature = "trace")]
    let builder = builder
        .add_plugin(ProcessorTracingPlugin)
        .add_plugin(JsonPcTracePlugin)
        .add_plugin(JsonMemoryReadPlugin)
        .add_plugin(JsonMemoryWritePlugin);

    // "Build" the processor using the builder-pattern.
    // All it does is consume all the inputs to create a final
    // processor you can interact with and execute code with
    let mut proc = builder.build()?;

    // start the execution of the input `TargetProgram`
    proc.run(Forever)?;

    Ok(())
}
