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
use styx_emulator::core::core::ExceptionBehavior;
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
        .with_builder(Stm32f107Builder {
            exception_behavior: ExceptionBehavior::Panic,
        })
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
