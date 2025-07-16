// SPDX-License-Identifier: BSD-2-Clause
use std::io::Write;

use styx_grpc::io::ethernet::ethernet_port_client::EthernetPortClient;
use styx_grpc::io::ethernet::EthernetPacket;
use styx_grpc::io::ethernet::SubscribeRequest;
use tokio::net::ToSocketAddrs;
use tokio_stream::StreamExt;
use tonic::codegen::StdError;

use std::fs;

const PCAP_FILE_HEADER: [u8; 24] = [
    0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
];
const PCAP_PACK_HEADER: [u8; 8] = [0x3a, 0x87, 0x9a, 0x67, 0x07, 0xb7, 0x0e, 0x00];

/// A basic ethernet client that only receives data, and just writes it to a file, creates a valid pcap file with proper file headers and headers for each ethernet frame.  The file path passed to the constructor will get overwritten if it already exists.
#[derive(Debug)]
pub struct SimpleEthernetClient<T> {
    /// inner async runtime
    runtime: tokio::runtime::Runtime,

    /// address of grpc endpoint
    addr: T,

    /// file to write data
    filepath: String,
}

impl<T> SimpleEthernetClient<T> {
    /// Creates a new Ethernet Client
    pub fn new(addr: T, file_path: Option<String>) -> Self
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

        Self {
            runtime,
            addr,
            filepath: file_path.unwrap_or(String::from("data.pcap")),
        }
    }

    pub fn start_client(self)
    where
        T: ToSocketAddrs,
        T: TryInto<tonic::transport::Endpoint>,
        T::Error: Into<StdError>,
        T: Clone + Send + 'static + std::fmt::Display,
    {
        self.runtime.block_on(async move {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(self.filepath)
                .unwrap();

            // write pcap header
            file.write_all(&PCAP_FILE_HEADER).unwrap();

            let mut inner = EthernetPortClient::connect(self.addr).await.unwrap();

            let mut resp = inner
                .subscribe(SubscribeRequest {})
                .await
                .unwrap()
                .into_inner();

            while let Some(recv) = resp.next().await {
                if let Err(e) = recv {
                    println!("Server disconnected or other error occured: {e:?}");
                    break;
                }
                println!("Got packet, writing to file.");

                let msg: EthernetPacket = recv.unwrap();

                // write pcap record header
                file.write_all(&PCAP_PACK_HEADER).unwrap();

                // write captured and original length fields
                let len = ((msg.frame.len() + 4) as u32).to_le_bytes();
                file.write_all(&len).unwrap();
                file.write_all(&len).unwrap();

                // write frame contents and crc
                file.write_all(&msg.frame).unwrap();
                file.write_all(&msg.crc.to_le_bytes()).unwrap();
            }
        });
    }
}
