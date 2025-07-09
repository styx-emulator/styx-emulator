// SPDX-License-Identifier: BSD-2-Clause
use log::{debug, error};
use styx_grpc::io::spi;
use styx_grpc::io::spi::spi_port_client::SpiPortClient;
use styx_sync::sync::atomic::AtomicBool;
use styx_sync::sync::Arc;
use tokio::net::ToSocketAddrs;
use tokio_stream::StreamExt;
use tonic::{codegen::StdError, transport::Channel};

/// defines the required methods for a SPI device
pub trait SPIDevice {
    /// returns the name of the device
    fn get_name(&self) -> &str;
    /// called by the SPI client to write data to the device
    fn write_data(&mut self, data: u8);
    /// called by the SPI client to read data from the device
    fn read_data(&mut self) -> Option<u8>;
}

pub struct SPIClient<T> {
    runtime: tokio::runtime::Runtime,
    address: T,
    port: u32,
    _inner: SpiPortClient<Channel>,
}

impl<T> SPIClient<T> {
    pub fn new(address: T, port: u32) -> Self
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
                .unwrap_or_else(|_| panic!("Could not connect to: {}", address))
        });

        debug!("Client Connected.");

        Self {
            runtime,
            address,
            port,
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
        let (to_cpu_tx, to_cpu_rx) = std::sync::mpsc::channel();
        let (to_dev_tx, to_dev_rx) = std::sync::mpsc::channel();

        let port = self.port;
        let address = self.address.clone();
        let address_ = address.clone();
        let device_name = device.get_name().to_string();
        let device_name_ = device_name.clone();

        let chip_select: Arc<AtomicBool> = Arc::new(AtomicBool::new(false));
        let chip_select_ = chip_select.clone();

        // We connect to the server and subscribe to messages on the port
        self.runtime.spawn(async move {
            let mut inner = SpiPortClient::connect(address).await.unwrap();
            let mut resp = inner
                .subscribe(spi::PortRequest {
                    port,
                    device_name: device_name.clone(),
                })
                .await
                .unwrap()
                .into_inner();

            while let Some(recv) = resp.next().await {
                if let Err(e) = recv {
                    error!("Server disconnected or other error occured: {:?}", e);
                    break;
                }

                // packet is not an error, so we can unwrap
                let packet = recv.unwrap();
                debug!("[{}] received: {:?}", device_name, packet);

                match packet.contents.unwrap() {
                    spi::packet::Contents::ChipSelect(s) => {
                        chip_select.store(s.state, std::sync::atomic::Ordering::Release)
                    }
                    spi::packet::Contents::Data(d) => {
                        // if we aren't selected, don't put anything new into the channel
                        if !chip_select.load(std::sync::atomic::Ordering::Acquire) {
                            continue;
                        }
                        for byte in d.data {
                            to_dev_tx.send(byte).unwrap();
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
                if let Ok(data) = to_cpu_rx.recv() {
                    let packet = spi::Packet {
                        port,
                        contents: Some(spi::packet::Contents::Data(spi::Data { data: vec![data] })),
                    };
                    println!("[{device_name_}] sending: {packet:?}");
                    inner.receive(packet).await.unwrap();
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
                    device.write_data(packet);
                }

                // If we aren't selected, then keep processing data that we've received but don't send anything new
                if !chip_select_.load(std::sync::atomic::Ordering::Acquire) {
                    continue;
                }

                // send
                if let Some(d) = device.read_data() {
                    to_cpu_tx.send(d).unwrap();
                }
            }
        });
    }
}
