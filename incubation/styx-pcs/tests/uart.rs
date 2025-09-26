use std::{net::Incoming, pin::Pin, time::Duration};

use styx_core::{
    grpc::io::uart::{
        self,
        bytes_message::Data,
        uart_port_server::{UartPort, UartPortServer},
        BytesMessage, SubscribeDirection, TxData,
    },
    prelude::*,
    util::logging::init_logging,
};
use styx_pcs::{start_pcs, PcsConfig};
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio_stream::Stream;
use tonic::{async_trait, service::RoutesBuilder, transport::Server};

/// Test Uart sender that sends a test message;
#[derive(Clone)]
struct UartSend {
    recv: mpsc::Sender<u8>,
}

impl UartSend {
    fn into_server(self) -> UartPortServer<UartSend> {
        UartPortServer::new(self)
    }
}

const MESSAGE: &str = "TURN IT UP THROW IT DOWN";
#[async_trait]
impl UartPort for UartSend {
    type SubscribeStream =
        Pin<Box<dyn Stream<Item = Result<uart::BytesMessage, tonic::Status>> + Send + 'static>>;

    // copies data into an internal shared buffer for inspection later
    async fn receive(
        &self,
        request: tonic::Request<uart::BytesMessage>,
    ) -> tonic::Result<tonic::Response<uart::Ack>> {
        let (_, _, bytes_message) = request.into_parts();
        let port_string = bytes_message.port;

        log::info!(
            "<gRPC> UART interface {} received data: {:?}",
            &port_string,
            &bytes_message.data,
        );

        if let Some(uart::bytes_message::Data::RxData(rx_data)) = bytes_message.data {
            for byte in rx_data.data {
                self.recv.send(byte).await.unwrap();
            }
        }
        Ok(tonic::Response::new(uart::Ack {}))
    }

    async fn subscribe(
        &self,
        request: tonic::Request<uart::SubscribeRequest>,
    ) -> Result<tonic::Response<Self::SubscribeStream>, tonic::Status> {
        let (_, _, subscribe_request) = request.into_parts();
        let port_string = subscribe_request.port.unwrap().port;
        let direction: SubscribeDirection = subscribe_request.direction.into();

        log::info!(
            "<gRPC> UART port {} {:?} is being subscribed to",
            &port_string,
            direction
        );

        match direction {
            SubscribeDirection::Tx => {
                log::info!("connected: sending message");
                // message to send over
                let message_stream = tokio_stream::iter(MESSAGE.bytes().map(|b| {
                    Ok(BytesMessage {
                        port: "test".to_owned(),
                        data: Some(Data::TxData(TxData { data: vec![b] })),
                    })
                }));
                Ok(tonic::Response::new(
                    Box::pin(message_stream) as Self::SubscribeStream
                ))
            }
            SubscribeDirection::Rx => {
                // messages coming into this device
                // not needed for this test
                todo!()
            }
            SubscribeDirection::Both => {
                // messages coming into and out of this device
                // not needed for this test
                todo!()
            }
        }
    }
}

/// Test Uart sender that sends a test message;
struct UartEcho {
    send: broadcast::Sender<u8>,
}

impl UartEcho {
    fn new() -> Self {
        let (send, _) = broadcast::channel(100);
        UartEcho { send }
    }
    fn into_server(self) -> UartPortServer<Self> {
        UartPortServer::new(self)
    }
}

#[async_trait]
impl UartPort for UartEcho {
    type SubscribeStream =
        Pin<Box<dyn Stream<Item = Result<uart::BytesMessage, tonic::Status>> + Send + 'static>>;

    // copies data into an internal shared buffer for inspection later
    async fn receive(
        &self,
        request: tonic::Request<uart::BytesMessage>,
    ) -> tonic::Result<tonic::Response<uart::Ack>> {
        let (_, _, bytes_message) = request.into_parts();
        let port_string = bytes_message.port;

        log::info!(
            "<gRPC> UART interface {} received data: {:?}",
            &port_string,
            &bytes_message.data,
        );

        if let Some(uart::bytes_message::Data::RxData(rx_data)) = bytes_message.data {
            for data in rx_data.data {
                // errors if no receivers (ok) so we ignore error
                let _ = self.send.send(data);
            }
        }
        Ok(tonic::Response::new(uart::Ack {}))
    }

    async fn subscribe(
        &self,
        request: tonic::Request<uart::SubscribeRequest>,
    ) -> Result<tonic::Response<Self::SubscribeStream>, tonic::Status> {
        let (_, _, subscribe_request) = request.into_parts();
        let port_string = subscribe_request.port.unwrap().port;
        let direction: SubscribeDirection = subscribe_request.direction.into();

        log::info!(
            "<gRPC> UART port {} {:?} is being subscribed to",
            &port_string,
            direction
        );

        match direction {
            SubscribeDirection::Tx => {
                let stream = tokio_stream::wrappers::BroadcastStream::new(self.send.subscribe());
                let message_stream = async_stream::stream! {

                    for await message_byte in stream {
                        let message_byte = message_byte.unwrap();
                        yield Ok(BytesMessage {
                            port: "test".to_owned(),
                            data: Some(Data::TxData(TxData { data: vec![message_byte] }))
                        });
                    }

                };

                Ok(tonic::Response::new(
                    Box::pin(message_stream) as Self::SubscribeStream
                ))
            }
            SubscribeDirection::Rx => {
                // messages coming into this device
                // not needed for this test
                todo!()
            }
            SubscribeDirection::Both => {
                // messages coming into and out of this device
                // not needed for this test
                todo!()
            }
        }
    }
}

#[test]
fn test_uart() {
    init_logging();
    let mut routes_send = RoutesBuilder::default();
    let (uart_send, mut uart_recv) = mpsc::channel(100);
    let uart_sender = UartSend { recv: uart_send };
    routes_send.add_service(uart_sender.into_server());
    // create tokio runtime
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_time()
        .enable_io()
        .build()
        .unwrap();

    let tcp_send = runtime
        .block_on(tokio::net::TcpListener::bind("0.0.0.0:0"))
        .unwrap();
    let port_send = tcp_send.local_addr().unwrap().port();

    let mut routes_echo = RoutesBuilder::default();
    let uart_echo = UartEcho::new();
    routes_echo.add_service(uart_echo.into_server());
    let tcp_echo = runtime
        .block_on(tokio::net::TcpListener::bind("0.0.0.0:0"))
        .unwrap();
    let port_echo = tcp_echo.local_addr().unwrap().port();

    let yaml = format!(
        r#"
        devices:
            - !Remote
              id: sender
              endpoint: http://127.0.0.1:{port_send}
            - !Remote
              id: echo
              endpoint: http://127.0.0.1:{port_echo}
        connections:
            - id: uart
              config:
                  direction: Both
                  from:
                      id: sender
                      port: "1"
                  to:
                      id: echo
                      port: "1"
    "#
    );

    log::info!("spawning uart send");
    runtime.spawn(async {
        log::info!("send serving on port_send");
        Server::builder()
            .add_routes(routes_send.routes())
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(tcp_send))
            .await
            .unwrap();
        log::info!("send done");
    });

    runtime.spawn(async {
        Server::builder()
            .add_routes(routes_echo.routes())
            .serve_with_incoming(tokio_stream::wrappers::TcpListenerStream::new(tcp_echo))
            .await
            .unwrap()
    });
    let config = serde_yaml::from_str::<PcsConfig>(&yaml).unwrap();
    start_pcs(config, runtime.handle()).unwrap();

    runtime.block_on(async {
        let mut buf = String::new();
        while let Some(recv_byte) = uart_recv.recv().await {
            buf.push(recv_byte.into());
            if buf == MESSAGE {
                println!("yay!");
                break;
            }
        }
    });
}
