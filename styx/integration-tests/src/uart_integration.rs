// SPDX-License-Identifier: BSD-2-Clause

use rand::Rng;
use std::net::TcpStream;
use styx_core::{peripheral_clients::uart::UartClient, prelude::*};

/// create a `Vec<u8>` with random bytes of some size
fn generate_random_vec(length: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    (0..length).map(|_| rng.r#gen()).collect()
}

/// Given a series of inputs, generate a test suite to exercise
/// uart functionality for a provided styx processor
///
/// Inputs:
/// - `T`: the concrete processor type to test
/// - `builder`: a function that returns ProcessorBuilder<'static>
///   - the processor builder needs to have the target program, endianness, backend, and architecture defined
/// - `port`: the uart port to connect to
///
/// The target program that the processor is running should do exactly two things.
/// 1. First the target program should send the following message "Hello world.\r\n", including the null byte.
/// 2. Then, the target program should become an echo server, sending back exactly what was received over UART.
///
/// See `data/test-binaries/arm/kinetis_21/twrk21f120m-sdk/boards/twrk21f120m/demo_apps/uart_test/uart_test.c`
///     for an example test program.
///
/// The test itself first builds the processor and a Uart client, making sure that the client is able to connect
/// to the processor.  Next, it waits for the "Hello world.\r\n" message to be sent from the target.  Finally
/// the test generates `Vec<u8>` of several sizes with random data, sends the data and compares the echo against
/// the original to make sure that the message was echoed back exactly.
///
/// Beware:
/// The messages that are sent and echoed by the target program are randomly generated.
pub fn uart_test(builder: ProcessorBuilder, port: u16) {
    let mut proc = builder.with_ipc_port(IPCPort::any()).build().unwrap();

    let ipc_port: u16 = proc.ipc_port();

    // run the processor in a separate thread
    std::thread::spawn(move || {
        proc.run(Forever).unwrap();
    });

    println!("Trying to connect...");
    loop {
        match TcpStream::connect(format!("127.0.0.1:{ipc_port}")) {
            Ok(_) => break,
            Err(_) => continue,
        }
    }

    let mut uart_client = UartClient::new(format!("http://127.0.0.1:{ipc_port}"), Some(port));

    println!("Connected!");

    // wait for hello world uart message
    let data = uart_client.recv(15, None);

    // check that we got the correct message "Hello world.\r\n\x00"
    let hello_message: Vec<u8> = vec![
        72, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 46, 13, 10, 0,
    ];
    assert_eq!(&data, &hello_message, "failed to receive hello message");
    println!("Hello message received.");

    // added a special case that came up as a bug
    let expected: Vec<u8> = vec![1, 2, 3, 4, 0, 6, 7, 8];
    println!("sending: {expected:x?}");
    uart_client.send(expected.clone());
    let recv = uart_client.recv(8, None);
    assert_eq!(&expected, &recv);

    let sizes: Vec<usize> = vec![1, 16, 32, 64, 1024];

    for s in sizes {
        // send data and check for response
        let expected_data: Vec<u8> = generate_random_vec(s);
        println!("sending: {expected_data:x?}");
        uart_client.send(expected_data.clone());
        let data = uart_client.recv(s, None);
        assert_eq!(
            &expected_data, &data,
            "failed to receive random expected data with size {s}"
        );
        println!("Send/Recv of {s:?} bytes succeeded");
    }
}
