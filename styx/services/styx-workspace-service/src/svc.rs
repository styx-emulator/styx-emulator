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

//! Implementation of `GRPC` workspace service [WorkspaceSvc]

use std::collections::HashMap;
use styx_core::errors::styx_grpc::ApplicationError;
use styx_core::grpc::workspace::{
    DeleteWsProgramResponse, GetWorkspaceRequest, GetWorkspaceResponse, GetWsProgamsResponse,
    GetWsProgramsRequest, Workspace,
};
use styx_core::grpc::{
    args::TraceAppSessionArgs,
    symbolic::{Program, ProgramFilter},
    typhunix_interop::ProgramRef,
    workspace::{
        workspace_svc_server::{WorkspaceSvc, WorkspaceSvcServer},
        DbId, GetJoinedTraceSessionsRequest, JoinedTraceSession, TraceSession, TraceSessionRequest,
        TraceSessionResponse, UpsertWsProgramRequest, UpsertWsProgramResponse,
    },
};
use styx_core::grpc::{
    utils::{service_response, ServiceResponse},
    workspace::{TraceAppSessRequest, TraceAppSessResponse},
};
use styx_dbmigration::{Migrator, MigratorTrait};
use styx_dbmodel::model::prelude::WorkspaceEntity;
use styx_dbmodel::{api::prelude::*, default_connection};
use tokio::{
    join,
    sync::mpsc::{self, Sender},
};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{transport::Server, Code};
use tonic::{Request, Response, Status};
use tracing::debug;

#[derive(Default)]
pub struct ServerImpl {
    cnx: DatabaseConnection,
}

impl ServerImpl {
    pub fn new(cnx: DatabaseConnection) -> Self {
        Self { cnx }
    }
}

#[tonic::async_trait]
impl WorkspaceSvc for ServerImpl {
    type GetTraceAppSessStreamingStream = ReceiverStream<Result<TraceAppSessionArgs, Status>>;
    type GetJoinedTraceSessionsStream = ReceiverStream<Result<JoinedTraceSession, Status>>;

    /// Create a
    async fn upsert_trace_app_sess(
        &self,
        request: Request<TraceAppSessRequest>,
    ) -> Result<Response<TraceAppSessResponse>, Status> {
        let request = request.into_inner();
        let msgs = request.trace_app_sessions();
        let mut response = TraceAppSessResponse {
            with_msg: request.with_msg,
            ..Default::default()
        };

        for msg in msgs {
            match DbApi::upsert_trace_app_session(&self.cnx, msg, request.with_msg).await {
                Ok(item) => {
                    response.dbids.push(item.0);
                    response.responses.push(ServiceResponse {
                        result: service_response::Result::Ok.into(),
                        ..Default::default()
                    });
                    if request.with_msg {
                        response.trace_app_session_args.push(item.1.unwrap());
                    }
                }
                Err(dberr) => {
                    response.dbids.push(DbId::default());
                    response.responses.push(ServiceResponse {
                        result: service_response::Result::Err.into(),
                        message: format!("{dberr}"),
                    });
                }
            }
        }

        Ok(Response::new(response))
    }
    async fn upsert_trace_session(
        &self,
        request: Request<TraceSessionRequest>,
    ) -> Result<Response<TraceSessionResponse>, Status> {
        let args = request.get_ref().clone().args;
        let session = request.get_ref().clone().session.unwrap();
        let trace_session = DbApi::upsert_trace(&self.cnx, &args, &session)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?;
        Ok(Response::new(TraceSessionResponse {
            args,
            session: Some(trace_session),
        }))
    }

    async fn del_trace_app_sess(
        &self,
        request: Request<TraceAppSessRequest>,
    ) -> Result<Response<TraceAppSessResponse>, Status> {
        let mut response = TraceAppSessResponse {
            ..Default::default()
        };

        for id in request.into_inner().dbids.iter() {
            let id = id.id;
            match DbApi::delete_trace_app_session_args(&self.cnx, id).await {
                Ok(dr) => {
                    if dr.rows_affected == 0 {
                        response.dbids.push(DbId { id });
                        response.responses.push(ServiceResponse {
                            result: service_response::Result::Err.into(),
                            ..Default::default()
                        });
                    } else {
                        response.dbids.push(DbId { id });
                        response.responses.push(ServiceResponse {
                            result: service_response::Result::Ok.into(),
                            ..Default::default()
                        });
                    }
                }
                Err(dberr) => {
                    response.dbids.push(DbId::default());
                    response.responses.push(ServiceResponse {
                        result: service_response::Result::Err.into(),
                        message: format!("{dberr}"),
                    });
                }
            }
        }

        Ok(Response::new(TraceAppSessResponse::default()))
    }

    async fn get_trace_app_sess(
        &self,
        _request: Request<TraceAppSessRequest>,
    ) -> Result<Response<TraceAppSessResponse>, Status> {
        let args = DbQuery::find_all_trace_app_session_args(&self.cnx)
            .await
            .map_err(|e| Status::new(Code::Internal, e.to_string()))?
            .iter()
            .map(|rslt| rslt.0.clone())
            .collect::<Vec<TraceAppSessionArgs>>();

        Ok(Response::new(TraceAppSessResponse {
            trace_app_session_args: args,
            ..Default::default()
        }))
    }

    async fn get_trace_app_sess_streaming(
        &self,
        _request: Request<TraceAppSessRequest>,
    ) -> Result<Response<Self::GetTraceAppSessStreamingStream>, Status> {
        let channel_max_buffered_msgs = 100; // todo: understand this better
        let (tx, rx) = mpsc::channel(channel_max_buffered_msgs);

        tokio::spawn(async move {
            let dburl = "postgres://postgres:styx@localhost/styxdb";
            let cnx = Database::connect(dburl).await.unwrap();
            for msg in DbQuery::find_all_trace_app_session_args(&cnx)
                .await
                .unwrap()
                .iter()
            {
                tx.send(Ok(msg.0.clone())).await.unwrap();
            }
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn get_joined_trace_sessions(
        &self,
        request: Request<GetJoinedTraceSessionsRequest>,
    ) -> Result<Response<Self::GetJoinedTraceSessionsStream>, Status> {
        let channel_max_buffered_msgs = 100; // todo: understand this better
        let (tx, rx) = mpsc::channel(channel_max_buffered_msgs);
        let request = request.get_ref().clone();
        tokio::spawn(async move {
            send_joined(request.clone(), tx.clone()).await;
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }

    // Get ws programs
    async fn get_ws_programs(
        &self,
        request: Request<GetWsProgramsRequest>,
    ) -> Result<Response<GetWsProgamsResponse>, Status> {
        debug!("service: get_ws_programs: {:?}", request.get_ref());
        let (dbid, with_data) = {
            let request = request.get_ref();
            (
                if request.ws_program_db_id == 0 {
                    None
                } else {
                    Some(request.ws_program_db_id)
                },
                request.with_data,
            )
        };
        let programs = {
            if with_data {
                DbQuery::get_ws_programs(dbid, &self.cnx)
                    .await
                    .map_err(|e| {
                        ApplicationError::DbQueryError("query get_ws_programs", e.to_string())
                    })?
            } else {
                DbQuery::get_partial_ws_programs(dbid, &self.cnx)
                    .await
                    .map_err(|e| {
                        ApplicationError::DbQueryError("query get_ws_programs", e.to_string())
                    })?
            }
        };

        Ok(Response::new(GetWsProgamsResponse {
            with_data,
            programs,
        }))
    }

    // delete ws programs
    async fn delete_ws_program(
        &self,
        request: Request<DbId>,
    ) -> Result<Response<DeleteWsProgramResponse>, Status> {
        let id = request.into_inner().id;
        let rows_affected = DbApi::delete_ws_program(&self.cnx, id)
            .await
            .map_err(|e| ApplicationError::DbQueryError("Delete failed", e.to_string()))?;

        Ok(Response::new(DeleteWsProgramResponse {
            status: (rows_affected == 1),
            ..Default::default()
        }))
    }

    // Create a new WsProgram
    async fn upsert_ws_program(
        &self,
        request: Request<UpsertWsProgramRequest>,
    ) -> Result<Response<UpsertWsProgramResponse>, Status> {
        let Some(program) = request.into_inner().program else {
            return Err(ApplicationError::MissingData("program".into()).into());
        };
        let mut program = program.clone();
        let wsid = if program.workspace_id.is_some() {
            program.workspace_id.unwrap().id
        } else {
            default_workspace_id(&self.cnx).await?
        };
        program.workspace_id = Some(DbId { id: wsid });

        let ws_program_id: Option<DbId> = DbApi::upsert_program(&self.cnx, program)
            .await
            .map_err(|e| ApplicationError::DbQueryError("upsert program", e.to_string()))?;
        Ok(Response::new(UpsertWsProgramResponse { ws_program_id }))
    }

    // Insert or update Workspace
    async fn upsert_workspace(
        &self,
        request: Request<Workspace>,
    ) -> Result<Response<DbId>, Status> {
        Ok(Response::new(
            DbApi::upsert_workspace(&self.cnx, request.into_inner())
                .await
                .map_err(|e| ApplicationError::DbQueryError("upsert workspace", e.to_string()))?,
        ))
    }

    // Get ws workspaces
    async fn get_workspaces(
        &self,
        request: Request<GetWorkspaceRequest>,
    ) -> Result<Response<GetWorkspaceResponse>, Status> {
        let id = request.into_inner().dbid.map(|id| id.id);
        Ok(Response::new(GetWorkspaceResponse {
            workspaces: DbQuery::get_workspaces(id, &self.cnx).await.map_err(|e| {
                ApplicationError::DbQueryError("query get_ws_programs", e.to_string())
            })?,
        }))
    }
}

pub async fn start(dburl: String, port: u16) -> Result<(), Status> {
    let addr = format!("0.0.0.0:{port}")
        .parse()
        .map_err(|e| Status::new(Code::Unavailable, format!("{e}")))?;

    // establish database connection
    let cnx = Database::connect(dburl)
        .await
        .map_err(|e| Status::new(Code::Unavailable, format!("{e}")))?;

    Migrator::up(&cnx, None)
        .await
        .map_err(|e| Status::new(Code::Unavailable, format!("{e}")))?;
    debug!("database schema up to data");
    let svc = ServerImpl { cnx };
    Server::builder()
        .add_service(WorkspaceSvcServer::new(svc))
        .serve(addr)
        .await
        .map_err(|e| Status::new(Code::Unavailable, format!("{e}")))?;
    Ok(())
}

pub async fn send_joined(
    _: GetJoinedTraceSessionsRequest,
    tx: Sender<Result<JoinedTraceSession, tonic::Status>>,
) {
    let cnx = default_connection().await.unwrap();
    let (programs, result) = {
        let (fut1, fut2) = join!(get_programs(), find_all_trace_app_session_args(&cnx));
        (fut1.unwrap(), fut2.unwrap())
    };

    for (args, session) in result.iter() {
        let p = args.get_pid().clone().unwrap().source_id;
        let msg = JoinedTraceSession {
            args: Some(args.clone()),
            session: session.clone(),
            program: programs.get(&p).cloned(),
        };

        tx.send(Ok(msg)).await.unwrap();
    }
}

pub async fn get_programs() -> Result<HashMap<String, Program>, ApplicationError> {
    let url = styx_core::errors::styx_grpc::env_or_error("TYPHUNIX_URL")?;
    let mut programs: HashMap<String, Program> = HashMap::new();
    for p in typhunix_proto::grpc_async_client::AsyncClient::connect(url)
        .await
        .map_err(|e| ApplicationError::GrpcConnectError("typhunix", e.to_string()))?
        .get_programs_vec(ProgramFilter::default())
        .await
        .map_err(|e| ApplicationError::GrpcConnectError("typhunix", e.to_string()))?
        .iter()
    {
        programs.insert(p.get_source_id(), p.to_owned());
    }

    Ok(programs)
}

pub async fn find_all_trace_app_session_args(
    db: &DbConn,
) -> Result<Vec<(TraceAppSessionArgs, Option<TraceSession>)>, ApplicationError> {
    let args = DbQuery::find_all_trace_app_session_args(db)
        .await
        .map_err(|e| {
            ApplicationError::DbQueryError("find_all_trace_app_session_args", e.to_string())
        })?;
    Ok(args)
}

pub async fn default_workspace_id(cnx: &DatabaseConnection) -> Result<i32, ApplicationError> {
    match WorkspaceEntity::find_by_id(1)
        .one(cnx)
        .await
        .map_err(|e| ApplicationError::GrpcConnectError("typhunix", e.to_string()))?
    {
        Some(v) => Ok(v.id),
        None => Err(ApplicationError::InvalidRequest(
            "No workspace provided, no default workspace found".to_string(),
        )),
    }
}
