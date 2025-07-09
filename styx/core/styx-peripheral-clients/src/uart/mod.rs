// SPDX-License-Identifier: BSD-2-Clause
use log::debug;
use std::time::Duration;
use styx_errors::anyhow::{anyhow, Context};
use styx_errors::UnknownError;
use styx_grpc::io::uart::bytes_message::Data::{RxData, TxData};
use styx_grpc::io::uart::uart_port_client::UartPortClient;
use styx_grpc::io::uart::{BytesMessage, PortRequest, SubscribeRequest};
use styx_sync::sync::{Arc, Mutex};
use tokio::net::ToSocketAddrs;
use tokio_stream::StreamExt;
use tonic::codegen::StdError;
use tonic::transport::Channel;
/// Sync container over a vec of bytes
#[derive(Debug, Default)]
struct DataBytes {
    data: Mutex<Vec<u8>>,
}

impl DataBytes {
    /// Extend the vec of bytes in inner with new data vec
    fn push(&self, data: Vec<u8>) {
        let mut inner = self.data.lock().unwrap();
        inner.extend_from_slice(&data);
    }

    /// returns up to the first n elements from the vec,
    fn take(&self, n: usize) -> Vec<u8> {
        let mut inner = self.data.lock().unwrap();
        let l = inner.len();

        // if we try to take more elements than exist, just return eveything we have
        if l < n {
            inner.drain(..l).collect()
        } else {
            inner.drain(..n).collect()
        }
    }

    #[inline]
    fn len(&self) -> usize {
        self.data.lock().unwrap().len()
    }
}

/// A blocking client that communicates via a wrapped
/// async client and a private async runtime
#[derive(Debug)]
pub struct UartClient {
    /// async uart client that we wrap
    inner: UartPortClient<Channel>,

    /// inner async runtime
    runtime: tokio::runtime::Runtime,

    /// which uart device to target, defaults to 0
    uart_port: u16,

    /// Thread safe container around rx'd bytes from UARTx
    uart_data: Arc<DataBytes>,
}

async fn uart_monitor<T>(
    address: T,
    uart_port: String,

    out_data: Arc<DataBytes>,
) -> Result<(), UnknownError>
where
    T: ToSocketAddrs,
    T: TryInto<tonic::transport::Endpoint>,
    T::Error: Into<StdError>,
    T: Clone + Send + 'static,
{
    // we make a new inner here
    let mut inner = UartPortClient::connect(address).await.unwrap();

    let mut resp = inner
        .subscribe(SubscribeRequest {
            direction: styx_grpc::io::uart::TX_DIRECTION,
            port: Some(PortRequest {
                port: uart_port.clone(),
            }),
        })
        .await
        .with_context(|| format!("could not subscribe to uart port {uart_port}"))?
        .into_inner();

    while let Some(recv) = resp.next().await {
        if let Err(e) = recv {
            println!("Server disconnected or other error occured: {:?}", e);
            break;
        }

        // add the message to the shared data buffer
        let msg: BytesMessage = recv.unwrap();
        match msg.data.unwrap() {
            TxData(d) => out_data.push(d.data),
            RxData(_) => return Err(anyhow!("got rx data on tx direction")),
        }
    }
    Ok(())
}

impl UartClient {
    /// Spawn background thread that will stream in the messages from Uart
    fn create_uart_monitor<T>(
        &self,
        address: T,
        uart_port: String,
        out_data: Arc<DataBytes>,
        handle: tokio::runtime::Handle,
    ) where
        T: ToSocketAddrs,
        T: TryInto<tonic::transport::Endpoint>,
        T::Error: Into<StdError>,
        T: Clone + Send + 'static,
    {
        handle.spawn(async move {
            let err = uart_monitor(address, uart_port, out_data).await;
            debug!("uart mointor exited with {err:?}");
        });
    }

    /// Creates a new UART Client, uart port defaults to 0 if not specified.
    pub fn new<T>(addr: T, uart_port: Option<u16>) -> UartClient
    where
        T: ToSocketAddrs,
        T: TryInto<tonic::transport::Endpoint>,
        T::Error: Into<StdError>,
        T: Clone + Send + 'static + std::fmt::Display,
    {
        let uart_port = uart_port.unwrap_or(0);

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();

        // create
        let inner = runtime.block_on(async {
            UartPortClient::connect(addr.clone())
                .await
                .unwrap_or_else(|_| panic!("Could not connect to: {}", addr))
        });

        // start background receiver thread
        let uart_data = Arc::new(DataBytes::default());
        let handle = runtime.handle().clone();

        // create new struct
        let client = UartClient {
            inner,
            runtime,
            uart_port,
            uart_data: uart_data.clone(),
        };

        client.create_uart_monitor(
            addr.clone(),
            uart_port.to_string(),
            uart_data,
            handle.clone(),
        );

        client
    }

    /// async recv function, waits until length is satisfied before returning data
    pub async fn recv_async(&self, length: usize) -> Vec<u8> {
        loop {
            if self.uart_data.len() >= length {
                return self.uart_data.take(length);
            }
        }
    }

    // returns immediately if there isn't enough data to fill the request
    pub fn recv_nonblocking(&self, length: usize) -> Option<Vec<u8>> {
        if self.uart_data.len() >= length {
            Some(self.uart_data.take(length))
        } else {
            None
        }
    }

    /// waits until there is enough data or until timeout is reached
    /// if no timeout is specified, this will block until 'length' amount of data
    //      has been collected
    pub fn recv(&self, length: usize, timeout: Option<Duration>) -> Vec<u8> {
        // if no timeout is specified, just loop until we've collected enough data
        if timeout.is_none() {
            loop {
                if self.uart_data.len() >= length {
                    return self.uart_data.take(length);
                }
            }
        } else {
            let now = std::time::Instant::now();
            let wait_duration = timeout.unwrap();

            // busy wait until either the timeout is met or we have enough data
            while now.elapsed() < wait_duration && self.uart_data.len() < length {}
            self.uart_data.take(length)
        }
    }

    /// send message, blocking
    pub fn send(&mut self, data: Vec<u8>) {
        let request = BytesMessage {
            port: self.uart_port.to_string(),
            data: Some(RxData(styx_grpc::io::uart::RxData { data })),
        };

        // block the thread on sending the message
        self.runtime.block_on(async {
            let _ = self.inner.receive(request).await.unwrap();
        });
    }

    /// send message async
    pub async fn send_async(&mut self, data: Vec<u8>) {
        let request = BytesMessage {
            port: self.uart_port.to_string(),
            data: Some(RxData(styx_grpc::io::uart::RxData { data })),
        };
        self.inner.receive(request).await.unwrap();
    }

    /// returns a copy of the currently held data
    pub fn peek(&self) -> Vec<u8> {
        self.uart_data.data.lock().unwrap().clone()
    }
}
