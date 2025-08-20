// SPDX-License-Identifier: BSD-2-Clause
#![cfg(feature = "unicorn-backend")]
use std::net::TcpStream;

use styx_core::{peripheral_clients::uart::UartClient, prelude::*};
use styx_kinetis21_processor::Kinetis21Builder;

const FREERTOS_HELLO_PATH: &str = "arm/kinetis_21/bin/freertos_hello/freertos_hello_debug.bin";

#[cfg_attr(miri, ignore)]
#[cfg_attr(asan, ignore)]
#[test]
fn test_freertos_hello() {
    let mut processor = ProcessorBuilder::default()
        .with_loader(RawLoader)
        .with_target_program(resolve_test_bin(FREERTOS_HELLO_PATH))
        .with_backend(Backend::Unicorn)
        .with_builder(Kinetis21Builder::default())
        .build()
        .unwrap();

    let ipc_port = processor.ipc_port();
    println!("Trying to connect...");

    loop {
        match TcpStream::connect(format!("127.0.0.1:{ipc_port}")) {
            Ok(_) => break,
            Err(_) => continue,
        }
    }

    let uart_client = Arc::new(UartClient::new(
        format!("http://127.0.0.1:{ipc_port}"),
        Some(5),
    ));
    println!("Connected!");

    std::thread::spawn(move || {
        processor.run(Forever).unwrap();
    });

    // wait for hello world uart message
    let data = uart_client.recv(14, None);

    // check that we got the correct message
    assert_eq!(&data, "Hello world.\r\n".as_bytes());

    // cleanup processor
    println!("Aborting");
}
