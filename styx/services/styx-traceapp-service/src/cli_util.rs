// SPDX-License-Identifier: BSD-2-Clause
//! Convenience functions for communicating with to the trace app session service

use styx_core::grpc::traceapp::trace_app_session_service_client::TraceAppSessionServiceClient;
use styx_core::grpc::traceapp::{
    AppSession, InitializeTraceRequest, SessionInfo, StartTraceAppSessionResponse,
    VariableSnapshotRequest,
};
use styx_core::grpc::utils::Empty;
use tokio::sync::mpsc;
use tokio::time::{timeout, Instant};
use tokio_util::sync::CancellationToken;
use tonic::transport::Channel;
use tracing::{error, info, warn};

use styx_trace_tools::event::StreamEndReason;

pub async fn match_one_session(url: &str, session_id: &str) -> Result<SessionInfo, String> {
    let sessions = starts_with(url, session_id)
        .await
        .map_err(|e| e.to_string())?;

    if sessions.is_empty() {
        Err("No session by that ID".into())
    } else if sessions.len() > 1 {
        Err(format!(
            "too many sessions: {}",
            sessions
                .iter()
                .map(|si| { si.session_id.clone() })
                .collect::<Vec<String>>()
                .join(", ")
        ))
    } else {
        Ok(sessions[0].clone())
    }
}

fn new_buffer() -> StartTraceAppSessionResponse {
    StartTraceAppSessionResponse {
        session_id: "".into(),
        memory_writes: vec![],
        end_of_events: vec![],
        interrupts: vec![],
        instructions: vec![],
        functions: vec![],
        basic_blocks: vec![],
        timeout: None,
        insn_limit_reached: None,
        state_change: None,
        cum_session_stats: None,
    }
}

pub async fn start(
    url: &str,
    request: &InitializeTraceRequest,
    buffer_interval: u128,
    ctrl_channel: mpsc::Sender<String>,
    response_channel: mpsc::Sender<StartTraceAppSessionResponse>,
    cancel_token: CancellationToken,
) -> Result<StreamEndReason, tonic::Status> {
    const INTERVAL_MILLIS: u64 = 1000;
    let mut end_reason: StreamEndReason = StreamEndReason::Unknown;
    let mut cli = connect(url.to_string()).await.map_err(|e| {
        let msg = format!("Failed connecting to {}: {:?}", url, e);
        error!("{msg}");
        tonic::Status::new(tonic::Code::Unknown, msg)
    })?;
    let trace_app_args = request.clone();
    let mut need_session_id = true;
    let wait_interval = tokio::time::Duration::from_millis(INTERVAL_MILLIS);
    let mut eov = false;
    let mut buffer = new_buffer();
    let mut last_send = Instant::now();
    let mut stream = cli.start(trace_app_args.clone()).await?.into_inner();

    while !eov {
        while let Ok(msg) = timeout(wait_interval, stream.message()).await {
            // Check cancel token
            if cancel_token.is_cancelled() {
                info!("traceapp_client: event processing loop cancelled");
                eov = true;
                end_reason = StreamEndReason::Cancelled;
            }

            if let Some(response) = msg? {
                if need_session_id {
                    let session_id = response.session_id();
                    buffer.session_id.clone_from(&session_id);
                    if ctrl_channel.send(buffer.session_id()).await.is_err() {
                        warn!("tx.send error (receiver dropped)");
                        eov = true;
                        end_reason = StreamEndReason::Unknown;
                    }
                    need_session_id = false;
                }

                buffer.instructions.extend(response.instructions);
                buffer.interrupts.extend(response.interrupts);
                buffer.memory_writes.extend(response.memory_writes);
                buffer.functions.extend(response.functions);

                if response.timeout.is_some() {
                    end_reason = StreamEndReason::RawTimeout;
                    buffer.timeout.clone_from(&response.timeout);
                    eov = true;
                }
                if response.insn_limit_reached.is_some() {
                    end_reason = StreamEndReason::InsnLimitReached;
                    buffer
                        .insn_limit_reached
                        .clone_from(&response.insn_limit_reached);
                    eov = true;
                }
                if !eov && !response.end_of_events.is_empty() {
                    buffer.end_of_events.extend(response.end_of_events);
                    end_reason = StreamEndReason::EndOfEvents;
                    eov = true;
                }

                if buffer_interval == 0
                    || last_send.elapsed().as_millis() > buffer_interval
                        && buffer.total_event_count() > 0
                {
                    if response_channel.send(buffer).await.is_err() {
                        println!("etx.send error (receiver dropped)");
                        eov = true;
                        end_reason = StreamEndReason::Unknown;
                    }
                    buffer = new_buffer();
                    last_send = Instant::now();
                }
                if eov {
                    break;
                }
            } else {
                // end of stream
                eov = true;
                end_reason = StreamEndReason::EndOfStream;
                break;
            }
        }
        // Event has not been received in INTERVAL_MILLIS ms
        if cancel_token.is_cancelled() {
            eov = true;
            end_reason = StreamEndReason::Cancelled;
        }
    }

    if buffer.total_event_count() > 0 && response_channel.send(buffer).await.is_err() {
        println!("etx.send error (receiver dropped)");
    }

    Ok(end_reason)
}

pub async fn initialize(
    url: &str,
    request: &InitializeTraceRequest,
    response_channel: mpsc::Sender<StartTraceAppSessionResponse>,
    cancel_token: CancellationToken,
) -> Result<StreamEndReason, tonic::Status> {
    const INTERVAL_MILLIS: u64 = 1000;
    let mut end_reason: StreamEndReason = StreamEndReason::Unknown;
    let mut cli = connect(url.to_string()).await.map_err(|e| {
        let msg = format!("Failed connecting to {}: {:?}", url, e);
        error!("{msg}");
        tonic::Status::new(tonic::Code::Unknown, msg)
    })?;
    let trace_app_args = request.clone();
    let wait_interval = tokio::time::Duration::from_millis(INTERVAL_MILLIS);
    let mut eov = false;
    let mut stream = cli.initialize(trace_app_args.clone()).await?.into_inner();

    while !eov {
        while let Ok(msg) = timeout(wait_interval, stream.message()).await {
            // Check cancel token
            if cancel_token.is_cancelled() {
                info!("traceapp_client: event processing loop cancelled");
                eov = true;
                end_reason = StreamEndReason::Cancelled;
            }

            if let Some(response) = msg? {
                if response_channel.send(response).await.is_err() {
                    eprintln!("etx.send error (receiver dropped)");
                    eov = true;
                    end_reason = StreamEndReason::Unknown;
                }
            } else {
                // end of stream
                eov = true;
                end_reason = StreamEndReason::EndOfStream;
                break;
            }
        }
        // Event has not been received in INTERVAL_MILLIS ms
        if cancel_token.is_cancelled() {
            eov = true;
            end_reason = StreamEndReason::Cancelled;
        }
    }
    Ok(end_reason)
}

pub async fn connect<D>(dst: D) -> Result<TraceAppSessionServiceClient<Channel>, tonic::Status>
where
    D: TryInto<tonic::transport::Endpoint>,
    D::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
{
    let cli = TraceAppSessionServiceClient::connect(dst)
        .await
        .map_err(|transport_error| {
            tonic::Status::new(
                tonic::Code::Unknown,
                format!("Failed to connect: {}", transport_error),
            )
        })?;
    Ok(cli)
}

pub async fn stop(url: &str, session_info: &SessionInfo) -> Result<(), tonic::Status> {
    let mut cli = connect(url.to_string()).await?;
    let x = cli
        .stop(AppSession::new(&session_info.session_id).clone())
        .await?
        .into_inner();
    println!("{:?}", x);
    Ok(())
}

pub async fn disconnect(url: &str, session_info: &SessionInfo) -> Result<(), tonic::Status> {
    let mut cli = connect(url.to_string().clone()).await?;
    let x = cli
        .disconnect(AppSession::new(&session_info.session_id).clone())
        .await?
        .into_inner();
    println!("{:?}", x);
    if let Err(e) = std::fs::remove_file(session_info.trace_file_path()?) {
        warn!("could not remove tracefile: {}", e);
    }

    Ok(())
}

pub async fn get_variable_snapshots(
    url: &str,
    session_info: &SessionInfo,
) -> Result<(), tonic::Status> {
    let mut cli = connect(url.to_string().clone()).await?;
    let x = cli
        .get_variable_snapshots(VariableSnapshotRequest {
            session_id: session_info.session_id.to_string(),
            address: 0xdeadbeef,
            name: "SomeVar".to_string(),
        })
        .await?
        .into_inner();
    println!("{:?}", x);

    Ok(())
}

pub async fn starts_with(args: &str, pattern: &str) -> Result<Vec<SessionInfo>, tonic::Status> {
    let sessions = sessions(args).await?;
    Ok(sessions
        .iter()
        .filter(|p| p.session_id.starts_with(pattern))
        .cloned()
        .collect())
}

pub async fn sessions(url: &str) -> Result<Vec<SessionInfo>, tonic::Status> {
    Ok(connect(url.to_string().clone())
        .await?
        .list_session_info(Empty::default())
        .await?
        .into_inner()
        .data
        .into_iter()
        .collect())
}

pub async fn list(long_list: bool, url: &str) -> Result<(), tonic::Status> {
    let sessions = sessions(url).await?;
    for session in sessions.iter() {
        if let Some(ref md) = session.metadata {
            if long_list {
                println!("Session: {} {}", session.session_id, md.state());
                println!("  pid:  {}, {}", md.process_id, md.url);
                println!("  path: {}", md.trace_file_path);
            } else {
                print!("{:8.8}-* {:10.10} ", session.session_id, md.state());
                print!("{:5.5} {} ", md.process_id, md.url);
                println!("{}", md.trace_file_path);
            }
        }
    }
    Ok(())
}
