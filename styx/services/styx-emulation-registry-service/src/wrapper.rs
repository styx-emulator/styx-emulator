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
//! Wrapper for [EmulationRegistryServiceClient]

use styx_core::grpc::{
    emulation_registry::{
        emulation_registry_service_client::EmulationRegistryServiceClient,
        StartTraceExecutionRequest, StartTraceExecutionResponse,
    },
    utils::{Empty, EmuMetadata, ResponseStatus, Token},
};
use styx_core::util::traits::HasUrl;
use tonic::{Request, Status};
use tracing::debug;

fn grpc_wrapped(msg: &str) -> tonic::Status {
    tonic::Status::new(tonic::Code::Unknown, msg)
}

pub struct EmulationRegistryServiceWrapper {
    url: String,
}

impl HasUrl for EmulationRegistryServiceWrapper {
    fn url(&self) -> String {
        self.url.clone()
    }
}

impl EmulationRegistryServiceWrapper {
    pub fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
        }
    }

    pub async fn initialize(
        &self,
        request: &StartTraceExecutionRequest,
    ) -> Result<StartTraceExecutionResponse, Status> {
        debug!("connect {}, initialize", self.url());
        Ok(EmulationRegistryServiceClient::connect(self.url())
            .await
            .map_err(|e| grpc_wrapped(&e.to_string()))?
            .initialize(Request::new(request.clone()))
            .await?
            .into_inner())
    }

    pub async fn start(&self, token: Token) -> Result<ResponseStatus, Status> {
        Ok(EmulationRegistryServiceClient::connect(self.url())
            .await
            .map_err(|e| grpc_wrapped(&e.to_string()))?
            .start(Request::new(token))
            .await?
            .into_inner())
    }

    pub async fn stop(&self, token: &Token) -> Result<ResponseStatus, Status> {
        Ok(EmulationRegistryServiceClient::connect(self.url())
            .await
            .map_err(|e| grpc_wrapped(&e.to_string()))?
            .stop(Request::new(*token))
            .await?
            .into_inner())
    }

    pub async fn drop(&self, token: &Token) -> Result<ResponseStatus, Status> {
        debug!("traceapp_service: drop token {}", token);
        Ok(EmulationRegistryServiceClient::connect(self.url())
            .await
            .map_err(|e| grpc_wrapped(&e.to_string()))?
            .drop(Request::new(*token))
            .await?
            .into_inner())
    }

    pub async fn list(&self) -> Result<Vec<EmuMetadata>, Status> {
        Ok(EmulationRegistryServiceClient::connect(self.url())
            .await
            .map_err(|e| grpc_wrapped(&e.to_string()))?
            .list(Empty::default())
            .await?
            .into_inner()
            .meta_data
            .into_iter()
            .collect::<Vec<EmuMetadata>>())
    }
}
