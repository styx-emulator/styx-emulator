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
//! Example emulation of the STM32F405 processor running a UART echo binary.
//!
//! TODO: this examples runs but does not echo back correctly.
//! The addresses for hooks may also be incorrect.
use std::env;
use styx_emulator::core::util::logging::init_logging;
use styx_emulator::loader::RawLoader;
use styx_emulator::prelude::*;
use styx_emulator::processors::arm::stm32f405::Stm32f405Builder;
use tracing::info;

/// Sets the environment log level to `info` by force, if it is not already
/// set to something reasonable to view output from the example emulation
fn set_env_log_info() {
    env::set_var(
        "RUST_LOG",
        match env::var("RUST_LOG") {
            Ok(v) => v,
            Err(_) => "info".to_string(),
        },
    );
}

/// path to demo firmware
const FW_PATH: &str = "arm/stm32f405/demos/uart_echo/build/uart_demo.bin";

/// Get the path to the firmware. Use env::var("FIRMWARE_PATH") if its set, use
/// the const FW_PATH if not.
fn get_firmware_path() -> String {
    match env::var("FIRMWARE_PATH") {
        Ok(v) => v,
        Err(_) => styx_emulator::core::util::resolve_test_bin(FW_PATH),
    }
}

fn cpu_start(proc: CoreHandle) -> Result<(), UnknownError> {
    println!("CPU started, pc = :[ {:#x}]", proc.cpu.pc().unwrap());
    Ok(())
}

fn send_byte(proc: CoreHandle) -> Result<(), UnknownError> {
    println!(
        "send_byte() function called, pc = :[ {:#x}]",
        proc.cpu.pc().unwrap()
    );
    Ok(())
}

fn recv_byte(proc: CoreHandle) -> Result<(), UnknownError> {
    println!(
        "LL_USART_ReceiveData8() function called, pc = :[ {:#x}]",
        proc.cpu.pc().unwrap()
    );
    Ok(())
}

fn irq_handler(proc: CoreHandle) -> Result<(), UnknownError> {
    println!(
        "UART4_IRQHandler() function called, pc = :[ {:#x}]",
        proc.cpu.pc().unwrap()
    );
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // its an example, force info log level so people see stuff
    // if its not set in the environment
    set_env_log_info();

    // setup logging
    init_logging();

    info!("Starting emulator");

    let mut proc = ProcessorBuilder::default()
        .with_builder(Stm32f405Builder::default())
        .with_loader(RawLoader)
        .with_target_program(get_firmware_path())
        .with_backend(Backend::Unicorn)
        .with_ipc_port(16000)
        /* CPU START HOOK
        struct construction of code hook */
        .add_hook(StyxHook::Code(
            (0x0000_03D0..=0x0000_03D1).into(),
            Box::new(cpu_start),
        ))
        /* LL_USART_ReceiveData8()
        convenience method construction */
        .add_hook(StyxHook::code(0x0000_0322..=0x0000_0323, recv_byte))
        /* send_byte('G')
        convenience hook on single address */
        .add_hook(StyxHook::code(0x0000_03A0, send_byte))
        /* UART4_IRQHandler() */
        .add_hook(StyxHook::code(0x0000_0444, irq_handler))
        .build()?;

    println!("initial PC: 0x{:x}", proc.core.cpu.pc().unwrap());
    let exit = proc.run(Forever);
    println!("{:?}", exit);

    Ok(())
}
