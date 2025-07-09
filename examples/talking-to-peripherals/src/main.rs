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
use chrono::prelude::*;
use clap::Parser;
use core::panic;
use std::net::TcpStream;
use std::thread;
use std::time::Duration;
use styx_core::peripheral_clients::i2c::{I2CClient, I2CDevice};

#[derive(Debug, Parser)]
#[command(name="emulator", version, about, long_about = None)]
struct ClientArgs {
    /// Port to connect to
    #[arg(short, long, default_value_t = 16000)]
    port: u16,

    /// Host to connect to
    #[arg(long, default_value_t = String::from("0.0.0.0"))]
    host: String,
}

impl ClientArgs {
    fn to_socket_addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

impl std::fmt::Display for ClientArgs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "http://{}:{}", self.host, self.port)
    }
}

/// RTC peripheral,
/// <https://www.analog.com/media/en/technical-documentation/data-sheets/DS3231.pdf>
pub struct RTC {
    reg_pointer: u8,
    state: DeviceState,
}

// ro
const RTC_SECONDS_REG: u8 = 0x0;
const RTC_MINUTES_REG: u8 = 0x1;
const RTC_HOURS_REG: u8 = 0x2;
const RTC_DAY_OF_WEEK_REG: u8 = 0x3;
const RTC_DATE_REG: u8 = 0x4;
const RTC_MONTH_REG: u8 = 0x5;
const RTC_YEAR_REG: u8 = 0x6;

// converts a 2 digit number into BCD format (4 bits per digit)
fn u8_to_bcd(val: u8) -> u8 {
    let tens = val / 10;
    let ones = val - (tens * 10);

    (tens << 4) | ones
}

impl RTC {
    pub fn new() -> Self {
        Self {
            reg_pointer: 0x0,
            state: DeviceState::Address,
        }
    }
}

impl Default for RTC {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, PartialEq, Debug, Default)]
enum DeviceState {
    #[default]
    Address,
    Read,
    Write,
    WriteIdx,
}

impl I2CDevice for RTC {
    fn get_address(&self) -> u32 {
        0x68
    }

    fn get_name(&self) -> &str {
        "RTC"
    }

    fn read_data(&mut self) -> u8 {
        if self.state == DeviceState::Read {
            println!("[{}] sending data.", self.get_name());
            let time = chrono::offset::Local::now();
            // return the correct time/calendar field depending on current reg pointer
            let val = match self.reg_pointer {
                RTC_SECONDS_REG => u8_to_bcd(time.second() as u8),
                RTC_MINUTES_REG => u8_to_bcd(time.minute() as u8),
                RTC_HOURS_REG => u8_to_bcd(time.hour() as u8),
                RTC_DAY_OF_WEEK_REG => time.weekday() as u8 + 1,
                RTC_DATE_REG => time.day() as u8,
                RTC_MONTH_REG => time.month() as u8,
                RTC_YEAR_REG => time.year() as u8,
                _ => panic!("unsupported address"),
            };

            // pointer is incremented after a read
            self.reg_pointer += 1;
            val
        } else {
            panic!("RTC tried reading in bad state: {:?}", self.state);
        }
    }

    fn write_data(&mut self, data: u8) -> bool {
        if self.state == DeviceState::Address {
            if self.get_address() == (data >> 1) as u32 {
                println!("[{}] matched address.", self.get_name());
                if data & 1 > 0 {
                    println!("\tentering read mode");
                    self.state = DeviceState::Read;
                } else {
                    println!("\tentering write mode");
                    self.state = DeviceState::WriteIdx;
                }
                return true;
            }
            return false;
        }
        if self.state == DeviceState::WriteIdx {
            println!("[{}] set register pointer", self.get_name());
            self.reg_pointer = data;
            self.state = DeviceState::Write;
            return true;
        }
        if self.state == DeviceState::Write {
            // todo or maybe not, actually write data

            self.reg_pointer = (self.reg_pointer + 1) % 0x13;
            return true;
        }
        false
    }

    fn process_ack(&mut self) {}

    fn process_start(&mut self) {
        self.state = DeviceState::Address;
    }

    fn process_stop(&mut self) {
        self.state = DeviceState::Address;
    }
}

#[derive(Default, Debug, PartialEq)]
enum TC74Command {
    RTemp,
    #[default]
    RwConfig,
}

/// temp sensor
/// <https://cdn-shop.adafruit.com/product-files/4375/4375_TC74A0-5.0VAT-Microchip-datasheet.pdf>
#[derive(Default)]
struct TC74 {
    config: u8,
    state: DeviceState,
    command: TC74Command,
}

impl I2CDevice for TC74 {
    fn get_address(&self) -> u32 {
        0x4D
    }

    fn get_name(&self) -> &str {
        "TC74"
    }

    fn read_data(&mut self) -> u8 {
        if self.state == DeviceState::Read {
            println!("[{}] sending data.", self.get_name());
            if self.command == TC74Command::RTemp {
                // 70 degrees F
                21
            } else {
                self.config
            }
        } else {
            panic!("TC74 tried to read while in bad state: {:?}", self.state);
        }
    }

    fn write_data(&mut self, data: u8) -> bool {
        match self.state {
            DeviceState::Address => {
                if self.get_address() as u8 == data >> 1 {
                    println!("[{}] matched address, sending ACK.", self.get_name());
                    if data & 1 > 0 {
                        println!("\tentering read mode");
                        self.state = DeviceState::Read;
                    } else {
                        println!("\tentering write mode");
                        self.state = DeviceState::WriteIdx;
                    }
                    return true;
                }
                false
            }
            DeviceState::WriteIdx => {
                match data {
                    0 => self.command = TC74Command::RTemp,
                    1 => self.command = TC74Command::RwConfig,
                    _ => {
                        panic!("TC74 device got bad command: {data}");
                    }
                };
                println!("[{}] received command: {:?}", self.get_name(), self.command);
                self.state = DeviceState::Write;
                true
            }
            DeviceState::Write => {
                if self.command == TC74Command::RwConfig {
                    self.config = data;
                }
                true
            }
            DeviceState::Read => {
                panic!("TC74 tried to write while in read mode.");
            }
        }
    }

    fn process_ack(&mut self) {}

    fn process_start(&mut self) {
        self.state = DeviceState::Address;
    }

    fn process_stop(&mut self) {
        self.state = DeviceState::Address;
    }
}

/// Wait for the emulator's IPC port to be up, then connect each device.
fn main() {
    let args = ClientArgs::parse();

    println!("waiting for {} ...", args.to_socket_addr());
    loop {
        thread::sleep(Duration::from_millis(100));
        match TcpStream::connect(args.to_socket_addr()) {
            Ok(_) => break,
            Err(_) => continue,
        }
    }

    // builds both the RTC and temp sensor devices
    let device_rtc = RTC::new();
    let device_temp = TC74::default();

    println!("starting client");
    let client = I2CClient::new(args.to_string());

    // connect both devices to the bus
    client.start_client(device_rtc, args.to_string(), Some(0));
    client.start_client(device_temp, args.to_string(), Some(0));

    loop {
        thread::sleep(Duration::from_secs(1));
    }
}
