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
