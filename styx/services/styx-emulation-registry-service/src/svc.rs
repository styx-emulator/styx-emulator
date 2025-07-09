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
//! Provides an importable daemon service to control
//! emulator's and their tracing

use async_trait::async_trait;
use emulation_service::emulation_args::{
    CliEmulationArgs, ServiceMetadata, SingleEmulationServiceExecutor,
};
use std::collections::HashMap;
use std::fmt::Display;
use styx_core::errors::styx_grpc::ApplicationError;
use styx_core::grpc::{
    args::HasEmulationArgs,
    emulation::{
        single_emulation_service_client::SingleEmulationServiceClient, StartSingleEmulationRequest,
    },
    emulation_registry::{
        emulation_registry_service_server::*, IdentityMappingResponse, StartTraceExecutionRequest,
        StartTraceExecutionResponse,
    },
    utils::{
        Empty, EmuMetadata, EmuMetadataList, EmulationState, HashableToken, ProcessorInfo,
        ResponseStatus, Token,
    },
    ToArgVec, Validator,
};
use styx_core::sync::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex,
};
use styx_core::util::traits::HasUrl;
use tonic::Status;
use tonic::{Request, Response};
use tracing::{debug, info, warn};

#[derive(Debug)]
pub struct EmulatorMetadata {
    pub token: HashableToken,
    pub service_meta: ServiceMetadata,
    pub metadata: EmuMetadata,
    pub processor_info: ProcessorInfo,
}
impl HasUrl for EmulatorMetadata {
    fn url(&self) -> String {
        self.metadata.url.to_owned()
    }
}
impl EmulatorMetadata {
    pub fn set_state(&mut self, value: EmulationState) {
        self.metadata.set_state(value)
    }

    pub fn get_state(&self) -> EmulationState {
        self.metadata.state()
    }
}

impl From<&EmulatorMetadata> for EmuMetadata {
    fn from(value: &EmulatorMetadata) -> Self {
        value.metadata.to_owned()
    }
}

impl Display for EmulatorMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let token = if let Some(ref token) = self.metadata.token {
            token.inner_token.to_string()
        } else {
            "?".to_string()
        };

        write!(
            f,
            "file: {}, url: {}, pid:{}, token:{}, ",
            self.metadata.trace_file_path, self.metadata.url, self.metadata.process_id, token,
        )
    }
}

#[derive(Debug)]
pub struct EmulationInstanceRegistry {
    /// Single service instances being managed
    service_instances: Arc<Mutex<HashMap<HashableToken, EmulatorMetadata>>>,
    /// next token # to issue
    next_token: AtomicU64,
}

impl Default for EmulationInstanceRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl EmulationInstanceRegistry {
    pub fn new() -> Self {
        Self {
            service_instances: Arc::new(Mutex::new(HashMap::new())),
            next_token: 0.into(),
        }
    }

    /// gets the current token and prepares the next token
    fn next_token(&self) -> HashableToken {
        HashableToken::from(Token {
            inner_token: self
                .next_token
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |x| Some(x + 1))
                .unwrap(),
        })
    }

    /// Checks if the token is valid
    pub fn contains_token(&self, token: HashableToken) -> bool {
        self.service_instances.lock().unwrap().contains_key(&token)
    }

    /// get the service url for the given token
    pub fn url(&self, token: HashableToken) -> Option<String> {
        self.service_instances
            .lock()
            .unwrap()
            .get(&token)
            .map(|si| si.url())
    }

    pub fn state(&self, token: HashableToken) -> Option<EmulationState> {
        self.service_instances
            .lock()
            .unwrap()
            .get(&token)
            .map(|si| si.metadata.state())
    }

    pub fn set_state(&self, token: HashableToken, value: EmulationState) {
        if let Some(ref mut si) = self.service_instances.lock().unwrap().get_mut(&token) {
            si.set_state(value)
        }
    }

    pub fn get_state(&self, token: HashableToken) -> EmulationState {
        if let Some(si) = self.service_instances.lock().unwrap().get(&token) {
            si.get_state()
        } else {
            EmulationState::Unknown
        }
    }

    pub async fn stop_emulation(&self, token: HashableToken) -> bool {
        info!("Stop emulation: token: {}", token);
        if let Some(url) = self.url(token) {
            info!("stopping {:?}", url);
            info!(
                "{:?}",
                SingleEmulationServiceClient::connect(url)
                    .await
                    .unwrap()
                    .stop(Request::new(Empty::default()))
                    .await
                    .unwrap()
                    .into_inner()
            );
            return true;
        }
        false
    }

    pub async fn drop_emulation(&self, token: HashableToken) -> bool {
        if self.contains_token(token) {
            info!("registry service drop_emulation: token: {}", token);
            let data = self.service_instances.lock().unwrap().remove_entry(&token);
            if let Some((_, mut data)) = data {
                info!("Dropping {:?}", data.metadata);
                info!(
                    "Tearing down single emulation instance with process id {}",
                    data.service_meta.process_id()
                );

                if let Err(e) = data.service_meta.kill_child() {
                    warn!("error killing child process {:?}", e);
                    return false;
                }
                true
            } else {
                warn!("drop_emulation: token: {} [No MetaData]", token);
                false
            }
        } else {
            warn!("drop_emulation: token: {} [No such token]", token);
            false
        }
    }

    pub async fn launch<T: HasEmulationArgs + serde::ser::Serialize + ToArgVec>(
        &self,
        args: T,
    ) -> Result<EmuMetadata, std::io::Error> {
        info!(
            "Launching serviceable emulator: yaml:\n{}\n",
            serde_yaml::to_string(&args).unwrap()
        );

        let svc_exec = SingleEmulationServiceExecutor::from_pbuf_emulation_args(args)?;
        let service_meta: ServiceMetadata = svc_exec.exec()?;
        let token = self.next_token();
        let process_id = service_meta.child.id();
        let processor_info = SingleEmulationServiceClient::connect(service_meta.url())
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::ConnectionRefused, e.to_string()))?
            .info(Request::new(Empty::default()))
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?
            .into_inner();

        let metadata = EmuMetadata {
            token: Some(Token {
                inner_token: token.token(),
            }),
            trace_file_path: service_meta.trace_path.clone(),
            process_id,
            port: service_meta.port as u32,
            url: service_meta.url(),
            state: EmulationState::Initialized.into(),
            processor_info: Some(processor_info.clone()),
        };

        self.service_instances.lock().unwrap().insert(
            token,
            EmulatorMetadata {
                token,
                service_meta,
                metadata: metadata.clone(),
                processor_info,
            },
        );

        // return the metadata
        Ok(metadata)
    }
}

/// gRPC service with a handle to the internal tracing daemon
#[derive(Debug)]
pub struct TraceRegistry {
    state: Arc<EmulationInstanceRegistry>,
}

impl TraceRegistry {
    pub fn new(state: Arc<EmulationInstanceRegistry>) -> EmulationRegistryServiceServer<Self> {
        EmulationRegistryServiceServer::new(Self { state })
    }
}

#[async_trait]
impl EmulationRegistryService for TraceRegistry {
    /// Initialialize
    /// - launch a new `SingleEmulationService` to host the emulation
    async fn initialize(
        &self,
        request: Request<StartTraceExecutionRequest>,
    ) -> tonic::Result<Response<StartTraceExecutionResponse>> {
        info!(
            "EmulationRegistryService::initialize: {:?}",
            request.get_ref()
        );
        let request = request.into_inner();
        if !request.is_valid() {
            return Err(
                ApplicationError::InvalidRequest("StartTraceExecutionRequest".into()).into(),
            );
        }
        let args: CliEmulationArgs = request.args()?.into();
        let metadata: EmuMetadata = self.state.launch(args).await?;
        info!("EmulationRegistryService::initialize OK");
        tonic::Result::Ok(Response::new(StartTraceExecutionResponse {
            token: metadata.token,
            emu_metadata: Some(metadata),
        }))
    }

    /// Start the emulation
    async fn start(&self, request: Request<Token>) -> tonic::Result<Response<ResponseStatus>> {
        info!("EmulationRegistryService::start({:?}", request);
        let token = HashableToken::from(request.into_inner());
        if !self.state.contains_token(token) {
            Ok(Response::new(ResponseStatus {
                state: EmulationState::Unknown.into(),
                message: "token does not exist".to_string(),
                result: styx_core::grpc::utils::response_status::Result::Err.into(),
            }))
        } else if let Some(url) = self.state.url(token) {
            debug!("url: {}, ", url);
            let nrequest = StartSingleEmulationRequest::default();
            self.state.set_state(token, EmulationState::Starting);
            let mut cli = SingleEmulationServiceClient::connect(url).await.unwrap();
            let resp = cli
                .start(Request::new(nrequest))
                .await
                .map_err(|e| {
                    tonic::Status::new(tonic::Code::Unknown, format!("connect failed: {}", e))
                })?
                .into_inner();
            debug!("Got response {:?}", resp);
            self.state.set_state(token, EmulationState::Running);
            debug!("Emulator: state: EmulationState::Running");
            Ok(Response::new(ResponseStatus {
                state: EmulationState::Running.into(),
                result: styx_core::grpc::utils::response_status::Result::Ok.into(),
                ..Default::default()
            }))
        } else {
            Ok(Response::new(ResponseStatus {
                state: self.state.get_state(token).into(),
                result: styx_core::grpc::utils::response_status::Result::Err.into(),
                message: "Could not get service url".to_string(),
            }))
        }
    }

    async fn stop(&self, request: Request<Token>) -> tonic::Result<Response<ResponseStatus>> {
        info!("stop request={:?}", request.get_ref());
        let token = HashableToken::from(request.into_inner());
        if !self.state.contains_token(token) {
            Ok(Response::new(ResponseStatus {
                state: EmulationState::Unknown.into(),
                message: "token does not exist".to_string(),
                result: styx_core::grpc::utils::response_status::Result::Err.into(),
            }))
        } else if !self.state.stop_emulation(token).await {
            tonic::Result::Err(tonic::Status::not_found("Bad token"))
        } else {
            self.state.set_state(token, EmulationState::Stopped);
            Ok(Response::new(ResponseStatus {
                state: EmulationState::Stopped.into(),
                result: styx_core::grpc::utils::response_status::Result::Ok.into(),
                ..Default::default()
            }))
        }
    }

    async fn drop(&self, request: Request<Token>) -> tonic::Result<Response<ResponseStatus>> {
        info!("stop request={:?}", request.get_ref());
        let token = HashableToken::from(request.into_inner());
        if !self.state.contains_token(token) {
            Ok(Response::new(ResponseStatus {
                state: EmulationState::Unknown.into(),
                message: "token does not exist".to_string(),
                result: styx_core::grpc::utils::response_status::Result::Err.into(),
            }))
        } else {
            if let Some(state) = self.state.state(token) {
                if state == EmulationState::Running {
                    let _ = self.state.stop_emulation(token).await;
                }
                self.state.set_state(token, EmulationState::Stopped)
            }
            if self.state.drop_emulation(token).await {
                Ok(Response::new(ResponseStatus {
                    state: EmulationState::Dropped.into(),
                    result: styx_core::grpc::utils::response_status::Result::Ok.into(),
                    message: "dropped".into(),
                }))
            } else {
                Ok(Response::new(ResponseStatus {
                    state: self.state.get_state(token).into(),
                    message: "failed to drop emulation".to_string(),
                    result: styx_core::grpc::utils::response_status::Result::Err.into(),
                }))
            }
        }
    }

    /// get a list of emulations
    async fn list(&self, _: Request<Empty>) -> tonic::Result<Response<EmuMetadataList>> {
        let mut list = EmuMetadataList::default();
        for (_, metadata) in self.state.service_instances.lock().unwrap().iter() {
            list.meta_data.push(metadata.into());
        }
        Ok(Response::new(list))
    }

    // rpc GetIdentityMapping(utils.Empty) returns (IdentityMappingResponse){}
    async fn get_identity_mapping(
        &self,
        _: Request<Empty>,
    ) -> Result<Response<IdentityMappingResponse>, Status> {
        Ok(Response::new(
            styx_trace_tools::identity::identity_mapping_response(),
        ))
    }
}
