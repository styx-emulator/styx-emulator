// SPDX-License-Identifier: BSD-2-Clause
use std::thread::spawn;
use styx_emulator::core::core::ExceptionBehavior;
use styx_emulator::core::util::logging::init_logging;
use styx_emulator::peripheral_clients::uart::UartClient;
use styx_emulator::plugins::styx_trace::StyxTracePlugin;
use styx_emulator::prelude::*;
use styx_emulator::processors::arm::stm32f107::Stm32f107Builder;

fn set_env_log(level: &'static str) {
    use std::env;
    env::set_var(
        "RUST_LOG",
        match env::var("RUST_LOG") {
            Ok(v) => v,
            Err(_) => level.to_string(),
        },
    );
}

fn main() {
    set_env_log("info");
    init_logging();

    const PRIMARY_PORT: u16 = 12345;
    const SECONDARY_PORT: u16 = 12346;

    let mut primary = ProcessorBuilder::default()
        .with_builder(Stm32f107Builder {
            exception_behavior: ExceptionBehavior::Panic,
        })
        .with_backend(Backend::Unicorn)
        .with_target_program("test.bin".to_owned())
        .with_ipc_port(PRIMARY_PORT)
        .add_plugin(StyxTracePlugin::default())
        .build()
        .unwrap();

    let mut secondary = ProcessorBuilder::default()
        .with_builder(Stm32f107Builder {
            exception_behavior: ExceptionBehavior::Panic,
        })
        .with_backend(Backend::Unicorn)
        .with_target_program("int.bin".to_owned())
        .with_ipc_port(SECONDARY_PORT)
        .add_plugin(StyxTracePlugin::default())
        .build()
        .unwrap();

    // start the emulators
    // the UART clients cannot connect until the emulators are running
    spawn(move || {
        primary.run(Forever).unwrap();
    });
    spawn(move || {
        secondary.run(Forever).unwrap();
    });

    //wait_for_tcp(PRIMARY_PORT);
    //wait_for_tcp(SECONDARY_PORT);
    std::thread::sleep(std::time::Duration::from_secs(5));

    // the uart controller on the first CPU
    let primary_uart = UartClient::new(format!("127.0.0.1:{PRIMARY_PORT}"), Some(5));
    // the uart controller on the second CPU
    let secondary_uart = UartClient::new(format!("127.0.0.1:{SECONDARY_PORT}"), Some(5));

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(3)
        .enable_all()
        .build()
        .unwrap();

    // primary --> secondary
    // secondary <-> primary
    let (primary_tx, primary_rx) = tokio::sync::mpsc::channel::<u8>(10);
    let (secondary_tx, secondary_rx) = tokio::sync::mpsc::channel::<u8>(10);

    PrimaryFromSecondary::spawn(
        &runtime,
        PrimaryFromSecondary {
            primary_uart,
            secondary_tx,
            primary_rx,
        },
    );

    SecondaryFromPrimary::spawn(
        &runtime,
        SecondaryFromPrimary {
            secondary_uart,
            primary_tx,
            secondary_rx,
        },
    );

    loop {
        std::thread::sleep(std::time::Duration::from_secs(1));
    }
}

struct SecondaryFromPrimary {
    secondary_uart: UartClient,
    primary_tx: tokio::sync::mpsc::Sender<u8>,
    secondary_rx: tokio::sync::mpsc::Receiver<u8>,
}

impl SecondaryFromPrimary {
    fn spawn(
        runtime: &tokio::runtime::Runtime,
        SecondaryFromPrimary {
            mut secondary_uart,
            primary_tx,
            mut secondary_rx,
        }: SecondaryFromPrimary,
    ) {
        runtime.spawn(async move {
            loop {
                // messages received from the secondary CPU should be forwarded to the primary CPU.
                while let Some(data) = secondary_uart.recv_nonblocking(1) {
                    primary_tx
                        .try_send(data[0])
                        .expect("(primary -> secondary) queue is full!");
                }

                // Messages from the primary CPU should be forwarded to the secondary CPU
                loop {
                    match secondary_rx.try_recv() {
                        // TODO: this should probably be a non-blocking send, or not... IDK
                        Ok(v) => secondary_uart.send(vec![v]),
                        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => return,
                    };
                }
            }
        });
    }
}

struct PrimaryFromSecondary {
    primary_uart: UartClient,
    secondary_tx: tokio::sync::mpsc::Sender<u8>,
    primary_rx: tokio::sync::mpsc::Receiver<u8>,
}

impl PrimaryFromSecondary {
    fn spawn(
        runtime: &tokio::runtime::Runtime,
        PrimaryFromSecondary {
            mut primary_uart,
            secondary_tx,
            mut primary_rx,
        }: PrimaryFromSecondary,
    ) {
        runtime.spawn(async move {
            loop {
                // Forward messages from the primary CPU to the secondary CPU
                while let Some(data) = primary_uart.recv_nonblocking(1) {
                    secondary_tx
                        .try_send(data[0])
                        .expect("(primary -> secondary) queue is full!");
                }

                // Messages from the secondary CPU are sent to the primary CPU
                loop {
                    match primary_rx.try_recv() {
                        // TODO: this should probably be a non-blocking send, or not... IDK
                        Ok(v) => primary_uart.send(vec![v]),
                        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => return,
                    };
                }
            }
        });
    }
}
