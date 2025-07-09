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
use std::any::Any;
use std::net::TcpStream;
use std::thread;
use std::{env, time::Duration};
use styx_emulator::core::executor::Delta;
use styx_emulator::core::util::logging::init_logging;
use styx_emulator::cpu::arch::arm::ArmRegister;
use styx_emulator::loader::RawLoader;
use styx_emulator::peripheral_clients::uart::UartClient;
use styx_emulator::plugins::fuzzer::{FuzzerExecutor, StyxFuzzerConfig};
use styx_emulator::plugins::styx_trace::StyxTracePlugin;
use styx_emulator::prelude::*;
use styx_emulator::processors::arm::kinetis21::Kinetis21Builder;
use styx_emulator::sync::Arc;
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
const FW_PATH: &str =
    "../../data/test-binaries/arm/kinetis_21/bin/fuzz_example/fuzz_example_debug.bin";

/// Get the path to the firmware. Use env::var("FIRMWARE_PATH") if its set, use
/// the const FW_PATH if not.
fn get_firmware_path() -> String {
    match env::var("FIRMWARE_PATH") {
        Ok(v) => v,
        Err(_) => FW_PATH.to_string(),
    }
}

fn pre_fuzzing_setup(proc: &mut ProcessorCore) {
    let stop_emulation = |proc: CoreHandle| -> Result<(), UnknownError> {
        proc.cpu.stop();
        Ok(())
    };

    let handle = proc
        .cpu
        .code_hook(0xb58, 0xb58 + 1, Box::new(stop_emulation))
        .unwrap();

    let sock_addr = String::from("127.0.0.1:16000");

    let uart_client_handle = thread::spawn(move || {
        // give a couple of seconds to make sure emulator gets setup
        thread::sleep(Duration::from_secs(2));

        println!("waiting for {} ...", sock_addr);
        loop {
            match TcpStream::connect(&sock_addr) {
                Ok(_) => break,
                Err(_) => continue,
            }
        }
        let mut addr = String::from("http://");
        addr.push_str(&sock_addr);
        let mut client = UartClient::new(addr, Some(5));
        println!("client created");
        let data = client.recv(7, Some(Duration::from_secs(1)));

        println!("recv: {:?}", data);
        println!("client sending test data");
        client.send("0000\n".as_bytes().to_vec());
    });

    loop {
        let execution_report = proc
            .cpu
            .execute(&mut proc.mmu, &mut proc.event_controller, 1000)
            .unwrap();
        // something is broken or the host requested a stop
        if execution_report.exit_reason.fatal() {
            panic!(
                "emulation failed to reach fuzzer start address: {:?}",
                execution_report
            );
        }
        if execution_report.exit_reason.is_stop_request() {
            println!("Reached end of fuzz-case seed test");
            break;
        }
        proc.event_controller
            .tick(
                proc.cpu.as_mut(),
                &mut proc.mmu,
                &Delta {
                    time: Duration::from_nanos(1000),
                    count: 1000,
                },
            )
            .unwrap();
        proc.event_controller
            .next(proc.cpu.as_mut(), &mut proc.mmu)
            .unwrap();
    }

    proc.cpu.delete_hook(handle).unwrap();
    uart_client_handle.join().unwrap();
}

fn context_save(proc: &mut ProcessorCore) -> Arc<dyn Any + Send> {
    Arc::new(SavedContext {
        sp: proc.cpu.read_register::<u32>(ArmRegister::Sp).unwrap(),
        lr: proc.cpu.read_register::<u32>(ArmRegister::Lr).unwrap(),
        pc: proc.cpu.pc().unwrap() | 0x1,
    })
}

fn context_restore(proc: &mut ProcessorCore, data: Arc<dyn Any + Send>) {
    let data = data.downcast_ref::<SavedContext>().unwrap();
    proc.cpu.write_register(ArmRegister::Sp, data.sp).unwrap();
    proc.cpu.write_register(ArmRegister::Lr, data.lr).unwrap();
    proc.cpu.set_pc(data.pc).unwrap();
}

const INPUT_BUFFER_ADDR: u64 = 0x1fff011c;
const MAX_INPUT_LEN: usize = 5;

fn insert_input(proc: &mut ProcessorCore, data: &[u8]) -> bool {
    if data.len() < MAX_INPUT_LEN {
        proc.mmu.write_data(INPUT_BUFFER_ADDR, data).unwrap();
    } else {
        proc.mmu
            .write_data(INPUT_BUFFER_ADDR, &data[..MAX_INPUT_LEN])
            .unwrap();
    }
    true
}

struct SavedContext {
    sp: u32,
    lr: u32,
    pc: u64,
}

const COVERAGE_MAP_SIZE: usize = 1024;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // its an example, force info log level so people see stuff
    // if its not set in the environment
    set_env_log_info();

    // setup logging
    init_logging();

    info!("Starting emulator");

    let mut proc = ProcessorBuilder::default()
        .with_builder(Kinetis21Builder::default())
        .with_backend(Backend::Unicorn)
        .with_executor(FuzzerExecutor::new(
            COVERAGE_MAP_SIZE,
            StyxFuzzerConfig {
                timeout: Duration::from_secs(1),
                branches_filepath: String::from("./branches.txt"),
                exits: vec![0xba2],
                max_input_len: MAX_INPUT_LEN,
                input_hook: Box::new(insert_input),
                setup: Box::new(pre_fuzzing_setup),
                context_restore: Box::new(context_restore),
                context_save: Box::new(context_save),
                ..Default::default()
            },
        ))
        .with_ipc_port(16000)
        .add_plugin(StyxTracePlugin::new(false, false, false, true))
        .with_loader(RawLoader)
        .with_target_program(get_firmware_path())
        .build()?;

    proc.run(Forever)?;

    Ok(())
}
