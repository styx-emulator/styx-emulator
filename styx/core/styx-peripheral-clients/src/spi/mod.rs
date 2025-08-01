// SPDX-License-Identifier: BSD-2-Clause
use std::borrow::Cow;
use std::sync::Mutex;

use log::{debug, error};
use styx_grpc::io::spi::spi_port_client::SpiPortClient;
use styx_grpc::io::spi::{self, MasterChipSelectPacket, MasterPacket};
use styx_sync::sync::atomic::AtomicBool;
use styx_sync::sync::Arc;
use tokio::net::ToSocketAddrs;
use tokio_stream::StreamExt;
use tonic::{codegen::StdError, transport::Channel};

/// defines the required methods for a SPI device
pub trait SPIDevice {
    /// returns the name of the device
    fn get_name(&self) -> Cow<'static, str>;
    /// Called by the SPI client to write data to the device.
    fn write_data(&mut self, data: u8);
    /// Called in a loop by the SPI client to read data from the device when chip select is enabled.
    ///
    /// This should be non blocking, otherwise `write_data` and `set_cs` callbacks will lag.
    fn read_data(&mut self) -> Option<u8>;
    /// Called to set chip select status.
    fn set_cs(&mut self, _cs: bool) {}
}

pub struct SPISimpleClient<T> {
    runtime: tokio::runtime::Runtime,
    address: T,
    spi_port: u32,
    chip_select_id: u32,
    _inner: SpiPortClient<Channel>,
}

enum DeviceComs {
    Data(u8),
    ChipSelect(bool),
}
impl<T> SPISimpleClient<T> {
    pub fn new(address: T, spi_port: u32) -> Self
    where
        T: ToSocketAddrs,
        T: TryInto<tonic::transport::Endpoint>,
        T::Error: Into<StdError>,
        T: Clone + Send + 'static + std::fmt::Display,
    {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(3)
            .build()
            .unwrap();

        let _inner = runtime.block_on(async {
            SpiPortClient::connect(address.clone())
                .await
                .unwrap_or_else(|_| panic!("Could not connect to: {address}"))
        });

        debug!("Client Connected.");

        Self {
            runtime,
            address,
            spi_port,
            chip_select_id: 0,
            _inner,
        }
    }

    pub fn connect_device<D: SPIDevice + Send + 'static>(&self, mut device: D)
    where
        T: ToSocketAddrs,
        T: TryInto<tonic::transport::Endpoint>,
        T::Error: Into<StdError>,
        T: Clone + Send + 'static + std::fmt::Display,
    {
        let (to_cpu_tx, mut to_cpu_rx) = tokio::sync::mpsc::channel(32);
        let (to_dev_tx, mut to_dev_rx) = tokio::sync::mpsc::channel(32);

        let port = self.spi_port;
        let address = self.address.clone();
        let address_ = address.clone();
        let device_name = device.get_name().to_string();
        let device_name_ = device_name.clone();

        let chip_select: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
        let chip_select_ = chip_select.clone();
        let good_id = self.chip_select_id;

        #[derive(Debug)]
        enum Packet {
            Data(MasterPacket),
            CSel(MasterChipSelectPacket),
        }

        // Subscribe to port mosi and csel and process.
        self.runtime.spawn(async move {
            let mut inner = SpiPortClient::connect(address).await.unwrap();
            let mosi_resp = inner
                .master_subscribe(spi::PortRequest {
                    port,
                    device_name: device_name.clone(),
                })
                .await
                .unwrap()
                .into_inner();
            let csel_resp = inner
                .master_chip_select_subscribe(spi::PortRequest {
                    port,
                    device_name: device_name.clone(),
                })
                .await
                .unwrap()
                .into_inner();

            let mut merged = mosi_resp
                .map(|res| res.map(Packet::Data))
                .merge(csel_resp.map(|res| res.map(Packet::CSel)));

            while let Some(recv) = merged.next().await {
                if let Err(e) = recv {
                    error!("Server disconnected or other error occured: {e:?}");
                    break;
                }

                // packet is not an error, so we can unwrap
                let packet = recv.unwrap();
                debug!("[{device_name}] received: {packet:?}");

                match packet {
                    Packet::CSel(c) => {
                        if c.chip_select_id != good_id {
                            continue;
                        }
                        debug!("received chip select {}", c.chip_select);
                        chip_select.store(c.chip_select, std::sync::atomic::Ordering::Release);
                        to_dev_tx
                            .send(DeviceComs::ChipSelect(c.chip_select))
                            .await
                            .unwrap();
                    }
                    Packet::Data(d) => {
                        if d.chip_select_id != good_id {
                            continue;
                        }

                        for byte in d.data {
                            // will wait for space to send
                            to_dev_tx.send(DeviceComs::Data(byte)).await.unwrap();
                        }
                    }
                }
            }
            error!("stream disconnected");
        });

        // This thread receives data from a device and sends it to the processor
        self.runtime.spawn(async move {
            let mut inner = SpiPortClient::connect(address_).await.unwrap();
            loop {
                // recv call blocks thread
                if let Some(data) = to_cpu_rx.recv().await {
                    let packet = spi::MasterPacket {
                        port,
                        chip_select_id: good_id,
                        data: vec![data],
                    };
                    debug!("[{device_name_}] sending: {packet:?}");
                    if let Err(e) = inner.master_receive(packet).await {
                        error!("to master receive socket disconnected: {e}");
                        break;
                    }
                } else {
                    error!("[to_cpu_rx] channel disconnected");
                    break;
                }
            }
        });

        // this thread handles reading/writing data from/to the device
        self.runtime.spawn(async move {
            loop {
                // get data from the server to process, if any is available
                if let Ok(packet) = to_dev_rx.try_recv() {
                    match packet {
                        DeviceComs::Data(byte) => device.write_data(byte),
                        DeviceComs::ChipSelect(cs) => device.set_cs(cs),
                    }
                }

                // If we aren't selected, then keep processing data that we've received but don't send anything new
                if !chip_select_.load(std::sync::atomic::Ordering::Acquire) {
                    continue;
                }

                // send
                if let Some(d) = device.read_data() {
                    // will wait for space to send
                    if let Err(e) = to_cpu_tx.send(d).await {
                        error!("[to_cpu_tx] channel disconnected: {e}");
                        break;
                    }
                }
            }
        });
    }
}

impl<T: SPIDevice> SPIDevice for Arc<Mutex<T>> {
    fn get_name(&self) -> Cow<'static, str> {
        self.lock().unwrap().get_name()
    }

    fn write_data(&mut self, data: u8) {
        self.lock().unwrap().write_data(data)
    }

    fn read_data(&mut self) -> Option<u8> {
        self.lock().unwrap().read_data()
    }

    fn set_cs(&mut self, cs: bool) {
        self.lock().unwrap().set_cs(cs)
    }
}
