// SPDX-License-Identifier: BSD-2-Clause
//! User-interactive program to interact with the STM32F405 example emulation
use clap::Parser;
use std::fmt::Write as BufWrite;
use std::io::Write;
use std::net::TcpStream;
use std::time::Duration;
use std::{io, thread};
use styx_emulator::peripheral_clients::uart::UartClient;

#[derive(Debug, Parser)]
#[command(name="emulator", version, about, long_about = None)]
struct Socket {
    /// Port to connect to
    port: u16,

    /// Host to connect to
    host: String,
}

impl Default for Socket {
    fn default() -> Self {
        Self {
            port: 16000,
            host: "localhost".to_string(),
        }
    }
}

impl Socket {
    fn to_socket_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl std::fmt::Display for Socket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "http://{}:{}", self.host, self.port)
    }
}

fn ascii_from_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|&c| c as char).collect()
}

fn bytes_string(bytes: &[u8]) -> String {
    bytes.iter().fold(String::new(), |mut string, b| {
        let _ = write!(string, "{b:02X}");
        string
    })
}

fn main() {
    let socket = Socket::default();
    println!("waiting for {} ...", socket.to_socket_addr());
    loop {
        thread::sleep(Duration::from_millis(100));
        match TcpStream::connect(socket.to_socket_addr()) {
            Ok(_) => break,
            Err(_) => continue,
        }
    }
    let uart_port = 4; // the test binary uses UART4
    let mut client = UartClient::new(socket.to_string(), Some(uart_port));
    println!("client created\n----------");

    loop {
        // read in a user byte
        io::stdout()
            .write_all("Type a single character to send to the STM32F405: ".as_bytes())
            .expect("error printing to stdout");
        io::stdout().flush().expect("error flushing stdout");

        let input = &mut String::new();
        let result = io::stdin().read_line(input);
        match result {
            Ok(size) => {
                if size != 2 {
                    println!("invalid number of bytes\n");
                    break;
                }
            }
            Err(_) => {
                println!("error reading input\n");
                break;
            }
        }

        let input_byte = input.as_bytes();
        // send the data to the processor
        println!("Sending {:#x}...", input_byte[0]);
        client.send(vec![input_byte[0]]);

        // await the 6 byte response
        let response = client.recv(6, Some(Duration::from_millis(5000)));
        if !response.is_empty() {
            print!(
                "STM32F405 responded with: [ {}]. \
            In ASCII: {}",
                bytes_string(&response),
                ascii_from_bytes(&response)
            );
        } else {
            break;
        }

        input.clear();
    }

    println!("Closing program...");
}
