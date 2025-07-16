// SPDX-License-Identifier: BSD-2-Clause

//! Wrapper for [WorkspaceSvcClient]

use std::error::Error;
use styx_core::grpc::args::TraceAppSessionArgs;
use styx_core::grpc::db::DbId;
use styx_core::grpc::workspace::workspace_svc_client::WorkspaceSvcClient;
use styx_core::grpc::workspace::{
    GetWorkspaceRequest, GetWsProgramsRequest, TraceAppSessRequest, TraceAppSessResponse,
    TraceSession, TraceSessionRequest, TraceSessionResponse, UpsertWsProgramRequest,
    UpsertWsProgramResponse, Workspace, WsProgram,
};
use styx_dbmodel::DBIdType;
use tonic::transport::Endpoint;
pub type StdError = Box<dyn std::error::Error + Send + Sync + 'static>;

/// tonic does not publicize its error Kind, so we match this string to
/// detect a transport error
const TRANSPORT_ERROR: &str = "transport error";

/// test the connection, return a tuple
/// - bool: can the service be connected to?
/// - optional message: error or info
pub async fn test_connection(url: &str, verbose_msg: bool) -> (bool, Option<String>) {
    match Endpoint::from_shared(url.to_string()) {
        Ok(addr) => match WorkspaceSvcClient::connect(addr).await {
            Ok(_cnx) => (true, None),
            Err(err) => {
                let err_msg = err.to_string();
                let verbose = if let Some(src) = err.source() {
                    if verbose_msg {
                        format!(": source: {src:?}")
                    } else {
                        "".to_string()
                    }
                } else {
                    "".to_string()
                };

                match err_msg.to_string().as_str() {
                    TRANSPORT_ERROR => (
                        false,
                        Some("(transport error) waiting for service".to_string()),
                    ),
                    _ => (false, Some(format!("{err_msg}{verbose}"))),
                }
            }
        },
        Err(e) => (false, Some(format!("Bad url[{url}]: {e}"))),
    }
}

pub async fn upsert_trace_app_session(
    url: &str,
    msgs: Vec<TraceAppSessionArgs>,
) -> Result<TraceAppSessResponse, Box<dyn std::error::Error>> {
    Ok(
        WorkspaceSvcClient::connect(Endpoint::from_shared(url.to_string())?)
            .await?
            .upsert_trace_app_sess(tonic::Request::new(TraceAppSessRequest {
                trace_app_session_args: msgs,
                with_msg: true,
                ..Default::default()
            }))
            .await?
            .into_inner(),
    )
}

pub async fn upsert_ws_program(
    url: &str,
    wsp: &WsProgram,
) -> Result<UpsertWsProgramResponse, Box<dyn std::error::Error>> {
    Ok(
        WorkspaceSvcClient::connect(Endpoint::from_shared(url.to_string())?)
            .await?
            .upsert_ws_program(tonic::Request::new(UpsertWsProgramRequest {
                program: Some(wsp.clone()),
            }))
            .await?
            .into_inner(),
    )
}

pub async fn upsert_workspace(
    url: &str,
    workspace: &Workspace,
) -> Result<DbId, Box<dyn std::error::Error>> {
    Ok(
        WorkspaceSvcClient::connect(Endpoint::from_shared(url.to_string())?)
            .await?
            .upsert_workspace(tonic::Request::new(workspace.clone()))
            .await?
            .into_inner(),
    )
}

pub async fn get_workspaces(
    dbid: Option<DbId>,
    url: &str,
) -> Result<Vec<Workspace>, Box<dyn std::error::Error>> {
    Ok(
        WorkspaceSvcClient::connect(Endpoint::from_shared(url.to_string())?)
            .await?
            .get_workspaces(tonic::Request::new(GetWorkspaceRequest { dbid }))
            .await?
            .into_inner()
            .workspaces,
    )
}

pub async fn upsert_trace_session(
    url: &str,
    msg: &TraceAppSessionArgs,
    session: &TraceSession,
) -> Result<TraceSessionResponse, Box<dyn std::error::Error>> {
    let addr = Endpoint::from_shared(url.to_string())?;
    let mut client = WorkspaceSvcClient::connect(addr).await?;
    let request = tonic::Request::new(TraceSessionRequest {
        args: Some(msg.clone()),
        session: Some(session.clone()),
    });

    Ok(client.upsert_trace_session(request).await?.into_inner())
}

pub async fn update_state(
    url: &str,
    session: &TraceSession,
) -> Result<TraceSessionResponse, Box<dyn std::error::Error>> {
    let addr = Endpoint::from_shared(url.to_string())?;
    let mut client = WorkspaceSvcClient::connect(addr).await?;
    let request = tonic::Request::new(TraceSessionRequest {
        args: None,
        session: Some(session.clone()),
    });

    Ok(client.upsert_trace_session(request).await?.into_inner())
}

pub async fn get_all_trace_app_sess(
    url: &str,
) -> Result<TraceAppSessResponse, Box<dyn std::error::Error>> {
    let addr = Endpoint::from_shared(url.to_string())?;
    let mut client = WorkspaceSvcClient::connect(addr).await?;
    let request = tonic::Request::new(TraceAppSessRequest {
        ..Default::default()
    });
    Ok(client.get_trace_app_sess(request).await?.into_inner())
}

pub async fn get_ws_programs(
    url: &str,
    ws_program_db_id: DBIdType,
    with_data: bool,
) -> Result<Vec<WsProgram>, Box<dyn std::error::Error>> {
    Ok(
        WorkspaceSvcClient::connect(Endpoint::from_shared(url.to_string())?)
            .await?
            .get_ws_programs(tonic::Request::new(GetWsProgramsRequest {
                with_data,
                ws_program_db_id,
            }))
            .await?
            .into_inner()
            .programs,
    )
}
