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
use log::debug;
use styx_grpc::io::i2c;
use styx_grpc::io::i2c::i2c_packet::Contents;
use styx_grpc::io::i2c::i2c_port_client::I2cPortClient;
use styx_grpc::io::i2c::signal::Sig;
use styx_grpc::io::i2c::{I2cPacket, I2cRegistration};
use tokio::net::ToSocketAddrs;
use tokio::runtime::Runtime;
use tokio_stream::StreamExt;
use tonic::codegen::StdError;
use tonic::transport::Channel;

/// Defines required methods for an I2C device
pub trait I2CDevice {
    /// i2c address of device
    fn get_address(&self) -> u32;
    /// name of device
    fn get_name(&self) -> &str;

    /// called when I2C bus requests data from this device
    fn read_data(&mut self) -> u8;
    /// called when I2C bus writes data to this device
    fn write_data(&mut self, data: u8) -> bool;

    /// device specific handler for the ACK signal
    fn process_ack(&mut self);
    /// device specific handler for the START signal
    fn process_start(&mut self);
    /// device specific handler for the STOP signal
    fn process_stop(&mut self);
}

/// Slave state machine transitions:
///     Any -> DevAddr
///     DevAddr -> Read
///     DevAddr -> Write
///
/// - A start or stop signal on the bus resets the device to the address state.
/// - The first data packet on the bus after a start signal puts the device into Read/Write mode
#[derive(Debug, PartialEq)]
pub enum SlaveState {
    /// waiting to be addressed
    DevAddr,
    /// reading data from device
    Read,
    /// writing data to device
    Write,
}

/// Const definition of an ACK, is long
const SIG_ACK: i2c::Signal = i2c::Signal {
    sig: Some(i2c::signal::Sig::Ack(i2c::Ack {})),
};

pub struct I2CClient {
    _inner: I2cPortClient<Channel>,
    runtime: Runtime,
}

impl I2CClient {
    pub fn new<T>(address: T) -> Self
    where
        T: ToSocketAddrs,
        T: TryInto<tonic::transport::Endpoint>,
        T::Error: Into<StdError>,
        T: Clone + Send + 'static + std::fmt::Display,
    {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();

        let inner = runtime.block_on(async {
            I2cPortClient::connect(address.clone())
                .await
                .unwrap_or_else(|_| panic!("Could not connect to: {}", address))
        });

        Self {
            _inner: inner,
            runtime,
        }
    }

    /// Start an I2C client for a device.
    ///
    /// The client has three states: waiting to be addressed, receiving data from master, and sending data to master
    ///
    /// We start by registering the device on the I2C bus, which returns a receiver for the data stream.  Then, we move into
    /// an eval loop which handles processing signals and data from the bus.
    ///
    /// - A Start or Stop signal on the bus resets the client to the waiting to be addresses state.
    /// - The first data packet after a start signal indicates the address of the slave device that the master is trying to communicate with.
    ///     If we match that address, we send an Ack signal on the bus and then switch into either read or write mode depending on the state
    ///     of the LSB in the address data packet.
    /// - If we got put into read mode, we initiate the transfer by sending the first data packet and then waiting for an Ack signal before sending
    ///     the next byte.
    /// - If we got put into write mode, we wait for the master to send the next data packet, and then send an Ack after performing the write to
    ///     indicate we are ready for more data.
    /// - Once the master is done reading from the device or writing to the device, it will send a stop signal which resets our state.
    ///
    /// Error Conditions:
    /// - Attempting to register multiple devices with the same address on the bus will result in an error from the `register_client` method.
    ///     On a real I2C interface, duplicate slave addresses will cause unpredicatable behaviour and arbitration errors so we don't allow this.
    pub fn start_client<D, T>(&self, mut device: D, address: T, bus: Option<u32>)
    where
        T: ToSocketAddrs,
        T: TryInto<tonic::transport::Endpoint>,
        T::Error: Into<StdError>,
        T: Clone + Send + 'static + std::fmt::Display,
        D: I2CDevice + Send + 'static,
    {
        let bus = bus.unwrap_or(0);
        let own_address = device.get_address();
        let device_name = device.get_name().to_string();
        let dev_str = device_name.clone();

        self.runtime.spawn(async move {
            let mut inner: I2cPortClient<Channel> = I2cPortClient::connect(address).await.unwrap();

            // tracks the internal interface state
            let mut interface_state = SlaveState::DevAddr;

            // register the device on the I2C bus
            let mut resp = inner
                .register_client(I2cRegistration {
                    bus,
                    dev_address: own_address,
                    device_name,
                })
                .await
                .unwrap()
                .into_inner();

            while let Some(recv) = resp.next().await {
                if let Err(e) = recv {
                    debug!("Server disconnected or other error occured: {:?}", e);
                    break;
                }

                let i2c_packet = recv.unwrap();
                debug!("[{}] Received packet on the bus: {:?}", dev_str, i2c_packet);

                // unpack the message from the bus and react accordingly
                match i2c_packet.contents.unwrap() {
                    Contents::Data(d) => {
                        let data = d.data as u8;

                        if device.write_data(data) {
                            // write was successful, send ACK
                            inner
                                .broadcast(I2cPacket {
                                    bus,
                                    contents: Some(i2c::i2c_packet::Contents::Sig(SIG_ACK)),
                                })
                                .await
                                .unwrap();
                            // if we were waiting for an address byte, then advance state
                            if interface_state == SlaveState::DevAddr {
                                // determine read/write control based on the lsb bit of the message
                                if data & 0x1 > 0 {
                                    interface_state = SlaveState::Read;
                                    // send the first requested byte
                                    let read = device.read_data();
                                    inner
                                        .broadcast(I2cPacket {
                                            bus,
                                            contents: Some(i2c::i2c_packet::Contents::Data(
                                                i2c::Data { data: read as u32 },
                                            )),
                                        })
                                        .await
                                        .unwrap();
                                } else {
                                    interface_state = SlaveState::Write;
                                }
                            }
                        }
                    }
                    Contents::Sig(s) => {
                        match s.sig.unwrap() {
                            Sig::Ack(_) => {
                                device.process_ack();

                                // if we got an ACK while in read mode then we can send the next byte
                                if interface_state == SlaveState::Read {
                                    let read = device.read_data();
                                    inner
                                        .broadcast(I2cPacket {
                                            bus,
                                            contents: Some(i2c::i2c_packet::Contents::Data(
                                                i2c::Data { data: read as u32 },
                                            )),
                                        })
                                        .await
                                        .unwrap();
                                }
                            }
                            Sig::Start(_) => {
                                device.process_start();
                                interface_state = SlaveState::DevAddr;
                            }
                            Sig::Stop(_) => {
                                device.process_stop();
                                interface_state = SlaveState::DevAddr;
                            }
                        }
                    }
                }
            }
        });
    }
}
