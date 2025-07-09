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
        match TcpStream::connect(format!("127.0.0.1:{}", ipc_port)) {
            Ok(_) => break,
            Err(_) => continue,
        }
    }

    let uart_client = Arc::new(UartClient::new(
        format!("http://127.0.0.1:{}", ipc_port),
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
