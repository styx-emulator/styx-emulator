// SPDX-License-Identifier: BSD-2-Clause
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
