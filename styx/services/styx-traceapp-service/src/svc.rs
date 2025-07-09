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
//! `gRPC` service for for trace execution analysis

use emulation_registry_service::wrapper::EmulationRegistryServiceWrapper;
use std::{error::Error, time::Duration};
use styx_core::errors::styx_grpc::{env_or_error, ApplicationError};
use styx_core::grpc::{
    args::{trace_app_session_args::TraceMode, EmulationArgs, TraceAppSessionArgs},
    emulation_registry::StartTraceExecutionRequest,
    traceapp::{
        trace_app_session_service_server::*, AppSession, InitializeTraceRequest, ListResponse,
        SessionInfo, StartTraceAppSessionResponse, VariableSnapshot, VariableSnapshotRequest,
        VariableSnapshots,
    },
    typhunix_interop::symbolic::ProgramIdentifier,
    utils::{Empty, EmuMetadata, EmulationState, ResponseStatus, Token},
    workspace::{TraceSession, TraceSessionState},
};
use styx_core::sync::sync::Arc;
use styx_dbmodel::api::prelude::*;
use styx_trace_tools::{
    send_state_change, service_err,
    svcutil::re_write_request,
    trace_sessions::{
        oob_pri_queue::{OOBRequest, OOBRequestQueue},
        session::Session,
        session_mgr::{SessionManager, TraceSessionSync},
    },
};
use thiserror::Error;
use tokio::{
    sync::mpsc::{self, Sender},
    time::Instant,
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Response, Status};
use tracing::{debug, error, info, trace, warn};

/// incubating: dump data when the session is stopped/disconnected
const SNAPSHOT: bool = false;

#[derive(Error, Debug)]
pub enum ServiceError {
    #[error("Must set environment variable {0}")]
    UnsetEnvironmentVariable(&'static str),
}

pub struct TraceAppSessionImpl {
    /// session manager
    pub sm: Arc<SessionManager>,

    /// wrapper for EmulationRegistryService
    trace_execution_svc: EmulationRegistryServiceWrapper,

    /// Database connection
    cnx: DatabaseConnection,
}

impl TraceAppSessionImpl {
    pub async fn new(sm: Arc<SessionManager>) -> Result<Self, Box<dyn Error>> {
        Ok(TraceAppSessionImpl {
            sm,
            trace_execution_svc: EmulationRegistryServiceWrapper::new(
                &std::env::var("TRACE_EXECUTION_URL").map_err(|_| {
                    Box::new(ServiceError::UnsetEnvironmentVariable(
                        "TRACE_EXECUTION_URL",
                    ))
                })?,
            ),
            cnx: styx_dbmodel::default_connection().await?,
        })
    }

    pub async fn initialize_emulator(
        &self,
        session_id: &str,
        tx: Sender<Result<StartTraceAppSessionResponse, tonic::Status>>,
        args: &EmulationArgs,
    ) -> Result<EmuMetadata, tonic::Status> {
        let response = self
            .trace_execution_svc
            .initialize(&StartTraceExecutionRequest {
                args: Some(args.clone()),
            })
            .await?;
        let emu_metadata = response.emu_metadata()?;
        send_state_change!(tx, &session_id, TraceSessionState::Initialized);
        Ok(emu_metadata)
    }

    pub async fn start_emulator(
        &self,
        tx: Sender<Result<StartTraceAppSessionResponse, tonic::Status>>,
        session_id: &str,
        token: Token,
        emu_metadata: &EmuMetadata,
    ) -> Result<EmuMetadata, tonic::Status> {
        let mut emu_metadata = emu_metadata.clone();
        let start_resp = self.trace_execution_svc.start(token).await?;
        emu_metadata.state = start_resp.state;
        send_state_change!(tx, session_id, TraceSessionState::Running);
        Ok(emu_metadata)
    }

    /// Create a new [Session]
    pub async fn create_session(
        &self,
        request: &InitializeTraceRequest,
        tx: Sender<Result<StartTraceAppSessionResponse, tonic::Status>>,
    ) -> Result<String, tonic::Status> {
        let mut args = request.args()?;
        let pid_arg = args.pid_args()?;
        let pid = ProgramIdentifier::new(&pid_arg.name, &pid_arg.source_id);
        let raw_event_limits = args.limits;
        let session_id = SessionManager::new_id();
        let metadata = match args.mode() {
            TraceMode::Emulated => {
                let tm = self
                    .initialize_emulator(
                        &session_id,
                        tx.clone(),
                        &request.clone().emulation_args()?,
                    )
                    .await?;
                args.trace_filepath.clone_from(&tm.trace_file_path);
                Some(tm)
            }

            _ => None,
        };

        let session = Session::new(
            &session_id,
            args.mode(),
            &args.symbol_options,
            &raw_event_limits,
            pid.clone(),
            metadata.clone(),
            Arc::new(OOBRequestQueue::default()),
        )
        .await?;

        self.sm
            .inbound_oob_requests
            .init(&session.id(), session.oob_request_queue());
        self.sm
            .checkin(session, "TraceMode::Emulated session created");

        let sync = TraceSessionSync::new(
            &args,
            &TraceSession {
                id: 0,
                session_id: session_id.to_string(),
                state: "Initialized".into(),
                ts_state: TraceSessionState::Initialized.into(),
                timestamp: Some(std::time::SystemTime::now().into()),
                metadata,
            },
        );
        sync.upsert().await?;

        Ok(session_id.to_string())
    }

    pub async fn hydrate_from_session(
        &self,
        session_id: &str,
    ) -> Result<(TraceAppSessionArgs, TraceSession), Status> {
        let Some((args, trace_session)) =
            DbQuery::find_trace_session_by_session_id(&self.cnx, session_id)
                .await
                .map_err(|e| service_err(&e.to_string()))?
        else {
            return Err(ApplicationError::InvalidRequest("session_id".into()).into());
        };
        let Some(args) = DbQuery::find_all_trace_app_session_args_by_id(&self.cnx, args.id)
            .await
            .map_err(|e| service_err(&e.to_string()))?
        else {
            return Err(ApplicationError::InvalidRequest("db find by id failed".into()).into());
        };

        Ok((args, trace_session))
    }
}

#[tonic::async_trait]
impl TraceAppSessionService for TraceAppSessionImpl {
    type StartStream = ReceiverStream<Result<StartTraceAppSessionResponse, tonic::Status>>;
    type InitializeStream = ReceiverStream<Result<StartTraceAppSessionResponse, tonic::Status>>;

    /// Initialize the trace session analysis
    async fn initialize(
        &self,
        req: tonic::Request<InitializeTraceRequest>,
    ) -> Result<tonic::Response<Self::InitializeStream>, tonic::Status> {
        debug!("TraceAppSessionService::initialize oreq: {:?}", req);
        let nreq = re_write_request(
            req.get_ref(),
            &env_or_error("WORKSPACE_URL")?,
            &env_or_error("TYPHUNIX_URL")?,
        )
        .await?;

        let nreq = tonic::Request::new(nreq);
        debug!("TraceAppSessionService::initialize new req: {:?}", nreq);
        let (tx, rx) = mpsc::channel(8);
        let _session_id = self.create_session(nreq.get_ref(), tx.clone()).await?;
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    /// Start the trace session analysis
    async fn start(
        &self,
        request: tonic::Request<InitializeTraceRequest>,
    ) -> Result<tonic::Response<Self::StartStream>, tonic::Status> {
        debug!(
            "{}: {}",
            "TraceAppService::start",
            serde_json::to_string(request.get_ref()).unwrap_or("{}".to_string())
        );
        let (tx, rx) = mpsc::channel(8);
        self.sm.debug_session_lists().await;
        let session_id = self
            .sm
            .session_id_or_err(&request.get_ref().args()?.session_id)?;

        let (args, mut trace_session) = self.hydrate_from_session(&session_id).await?;

        let request = InitializeTraceRequest {
            args: Some(args.clone()),
        };

        if args.mode() == TraceMode::Emulated {
            let session = self.sm.checkout(&session_id);
            let Some(ref metadata) = trace_session.metadata else {
                return Err(ApplicationError::MissingData("metadata".into()).into());
            };
            let Some(token) = metadata.clone().token else {
                return Err(ApplicationError::MissingData("token".into()).into());
            };
            trace_session.metadata = Some(
                self.start_emulator(tx.clone(), &session_id, token, metadata)
                    .await?,
            );
            self.sm
                .checkin(session, "TraceMode::Emulated session started");
        }

        trace_session.state = "Running".into();
        trace_session.ts_state = TraceSessionState::Running.into();
        let sync = TraceSessionSync::new(&args, &trace_session);
        sync.upsert().await?;
        let sm = self.sm.clone();

        // Run the request
        tokio::spawn(async move {
            debug!("spawned thread, request: {:?}", &request);
            let session = sm.checkout(&request.args()?.session_id);
            session.set_last_active_time();
            sm.add_running(&session.id());
            let result = session.run_request(tx, request).await;
            session.set_last_active_time();
            sm.checkin(session, "start complete");
            result
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn stop(
        &self,
        request: tonic::Request<AppSession>,
    ) -> Result<tonic::Response<ResponseStatus>, tonic::Status> {
        #[rustfmt::skip]
        debug!("{}: {}","TraceAppService::stop",
            serde_json::to_string(request.get_ref()).unwrap_or("{}".to_string())
        );
        let session_id = &request.get_ref().session_id();
        let (args, mut trace_session) = self.hydrate_from_session(session_id).await?;
        if self.sm.is_running(session_id)
            && self
                .sm
                .inbound_oob_requests
                .insert(&request.get_ref().session_id(), OOBRequest::Stop)
        {
            self.sm
                .set_state(&request.get_ref().session_id(), EmulationState::Stopping);
            // allow 10 second timeout waiting for stop
            let timeout_milliseconds = 10_000;
            let start_epoch = Instant::now();
            while self.sm.is_running(&request.get_ref().session_id) {
                info!("Waiting for stop ... {}", &request.get_ref().session_id());
                if start_epoch.elapsed().as_millis() > timeout_milliseconds {
                    warn!("timed out waiting for emulator to stop");
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }

        if SNAPSHOT {
            // dump artifacts from emulation
            self.sm
                .set_state(&request.get_ref().session_id(), EmulationState::Finalizing);
            let session = self.sm.checkout(&request.get_ref().session_id());
            self.sm.add_running(&session.id());
            session.snapshot().await;
            self.sm.checkin(session, "artifacts dumped");
        }

        let mode = self.sm.mode_or_err(&request.get_ref().session_id())?;
        if mode == TraceMode::Emulated {
            // Send stop to trace_execution service
            debug!("Call trace_execution_svc to stop the emulator...");
            let stop_resp = self
                .trace_execution_svc
                .stop(&self.sm.token_or_err(&request.get_ref().session_id())?)
                .await?;
            let state = stop_resp.state();
            self.sm.set_state(&request.get_ref().session_id(), state);
            trace_session.state = "Stopped".into();
            trace_session.ts_state = TraceSessionState::Stopped.into();
            let sync = TraceSessionSync::new(&args, &trace_session);
            sync.upsert().await?;

            Ok(stop_resp.into())
        } else {
            self.sm.set_state(
                &request.get_ref().session_id(),
                styx_core::grpc::utils::EmulationState::Stopped,
            );
            trace_session.state = "Stopped".into();
            trace_session.ts_state = TraceSessionState::Stopped.into();
            let sync = TraceSessionSync::new(&args, &trace_session);
            sync.upsert().await?;
            Ok(ResponseStatus::ok_resp(
                "",
                styx_core::grpc::utils::EmulationState::Stopped,
            ))
        }
    }

    async fn disconnect(
        &self,
        request: tonic::Request<AppSession>,
    ) -> Result<tonic::Response<ResponseStatus>, tonic::Status> {
        #[rustfmt::skip]
        debug!("{}: {}","TraceAppService::disconnect",
            serde_json::to_string(request.get_ref()).unwrap_or("{}".to_string())
        );
        self.sm.debug_session_lists().await;

        let (args, trace_session) = self
            .hydrate_from_session(&request.get_ref().session_id())
            .await?;

        let sync = TraceSessionSync::new(&args, &trace_session);
        sync.update_state("Dropping", TraceSessionState::Dropping)
            .await?;

        let session_id = self.sm.session_id_or_err(&request.get_ref().session_id())?;
        let mode = self.sm.mode_or_err(&request.get_ref().session_id())?;
        let drop_response = {
            if mode == TraceMode::Emulated {
                let token = self.sm.token_or_err(&request.get_ref().session_id())?;
                let drop_resp = self.trace_execution_svc.drop(&token).await?;
                let state = drop_resp.state();
                self.sm.set_state(&request.get_ref().session_id(), state);
                drop_resp
            } else {
                ResponseStatus::ok("", EmulationState::Dropped)
            }
        };
        if let Some(s) = self.sm.idle_sessions().lock().unwrap().remove(&session_id) {
            info!("Dropped session {}", s.id());
        }

        self.sm
            .inbound_oob_requests
            .remove(&request.get_ref().session_id());
        self.sm.debug_session_lists().await;

        Ok(Response::new(drop_response))
    }

    async fn list_session_info(
        &self,
        request: tonic::Request<Empty>,
    ) -> Result<tonic::Response<ListResponse>, tonic::Status> {
        #[rustfmt::skip]
        trace!("{}: {}","TraceAppService::list_session_info",
            serde_json::to_string(request.get_ref()).unwrap_or("{}".to_string())
        );

        let mut data = self
            .sm
            .idle_sessions()
            .lock()
            .unwrap()
            .values()
            .map(|s| s.into())
            .collect::<Vec<SessionInfo>>();

        let running = self
            .sm
            .running_sessions()
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect::<Vec<SessionInfo>>();
        data.extend(running);

        Ok(Response::new(ListResponse { data }))
    }

    async fn get_variable_snapshots(
        &self,
        request: tonic::Request<VariableSnapshotRequest>,
    ) -> Result<tonic::Response<VariableSnapshots>, tonic::Status> {
        info!("{:?}", request.get_ref());

        let is_running = self.sm.is_running(&request.get_ref().session_id);
        let msg = format!(
            "{} is_running: {}",
            &request.get_ref().session_id,
            is_running
        );
        let vs = VariableSnapshots {
            snapshots: vec![VariableSnapshot {
                array_repr: None,
                basic_repr: None,
                struct_repr: None,
                message: msg,
            }],
        };

        Ok(Response::new(vs))
    }
}
