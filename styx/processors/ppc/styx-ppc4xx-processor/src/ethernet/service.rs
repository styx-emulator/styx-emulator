// SPDX-License-Identifier: BSD-2-Clause
use std::pin::Pin;
use styx_core::grpc::io::ethernet::Empty;
use styx_core::prelude::*;

use styx_core::grpc::io::ethernet::{
    ethernet_port_server::EthernetPort, EthernetPacket, SubscribeRequest,
};
use tokio::sync::broadcast;
use tokio_stream::Stream;
use tonic::async_trait;

pub struct EthernetControllerService {
    pub tx: broadcast::Sender<EthernetPacket>,
    pub rx: broadcast::Sender<EthernetPacket>,
}

#[async_trait]
impl EthernetPort for EthernetControllerService {
    type SubscribeStream =
        Pin<Box<dyn Stream<Item = Result<EthernetPacket, tonic::Status>> + Send + 'static>>;

    async fn receive(
        &self,
        request: tonic::Request<EthernetPacket>,
    ) -> tonic::Result<tonic::Response<Empty>> {
        let (_, _, packet) = request.into_parts();

        log::debug!("<gRPC> Ethernet interface received data: {:?}", packet);
        self.rx.send(packet).unwrap();

        Ok(tonic::Response::new(Empty {}))
    }

    async fn subscribe(
        &self,
        request: tonic::Request<SubscribeRequest>,
    ) -> Result<tonic::Response<Self::SubscribeStream>, tonic::Status> {
        let (_, _, _) = request.into_parts();

        log::trace!("<gRPC> Ethernet port is being subscribed to",);

        // unclear if this is rx or tx but I'll guess tx
        let mut stream = self.tx.subscribe();
        let output = async_stream::try_stream! {
            while let Ok(data) = stream.recv().await {
                yield data
            }
        };

        // the final pinned stream that will service
        // the requested subscription
        Ok(tonic::Response::new(
            Box::pin(output) as Self::SubscribeStream
        ))
    }
}
