// SPDX-License-Identifier: BSD-2-Clause
//! This binary is an example use of [`styx-emulator`] to emulate
//! an ARMv7 chip.
//!
//! This machine will initialize the memory state,
//! setup peripherals, and run a pre-packaged basic firmware. In
//! practice this chip is used in power lines, PLC's, printers
//! and alarm systems. This does not emulate any of those, simply
//! a toy operating system that toggles a gpio
//!
//! The `gpio` peripheral is provided by the
//! [Gpio](styx_emulator::processors::arm::stm32f107::example_gpio::Gpio)
//! example in the [styx_machines](crate) crate.
use std::env;
use styx_emulator::arch::arm::ArmRegister;
use styx_emulator::plugins::tracing_plugins::ProcessorTracingPlugin;
use styx_emulator::prelude::*;
use styx_emulator::processors::arm::stm32f107::Stm32f107Builder;
use tracing::{error, info};

/// Sets the environment log level to `info` by force, if it is not already
/// set to something reasonable to view output from the example emulation
fn set_env_log_info() {
    // TODO: Audit that the environment access only happens in single-threaded code.
    unsafe {
        env::set_var(
            "RUST_LOG",
            match env::var("RUST_LOG") {
                Ok(v) => v,
                Err(_) => "info".to_string(),
            },
        )
    };
}

/// path to demo firmware
const FW_PATH: &str = "../../data/test-binaries/arm/stm32f107/bin/blink_flash/blink_flash.bin";

/// Get the path to the firmware. Use env::var("FIRMWARE_PATH") if its set, use
/// the const FW_PATH if not.
fn get_firmware_path() -> String {
    match env::var("FIRMWARE_PATH") {
        Ok(v) => v,
        Err(_) => FW_PATH.to_string(),
    }
}

fn log_signal(proc: CoreHandle) -> Result<(), UnknownError> {
    //0x6954
    error!(
        "signal: {}",
        proc.cpu.read_register::<u32>(ArmRegister::R3).unwrap()
    );
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // its an example, force info log level so people see stuff
    // if its not set in the environment
    set_env_log_info();

    info!("Starting emulator");

    let mut proc = ProcessorBuilder::default()
        .with_builder(Stm32f107Builder)
        .with_target_program(get_firmware_path())
        .with_backend(Backend::Unicorn)
        // setup logging
        .add_plugin(ProcessorTracingPlugin)
        // TODO this address is not correct, unsure where in blink flash it should be pointing to
        .add_hook(StyxHook::code(0x690C..=0x690D, log_signal))
        .build()?;

    println!("initial PC=0x{:x}", proc.core.pc().unwrap());
    proc.run(Forever)?;

    Ok(())
}
