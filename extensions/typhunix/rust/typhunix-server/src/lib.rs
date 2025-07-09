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
//! Typhunix Server lib

use std::net::SocketAddr;
use std::time::Duration;
use styx_emulator::grpc::typhunix_interop::symbolic_impl::clean;
use styx_emulator::grpc::typhunix_interop::{
    json_util, typhunix_client::TyphunixClient, typhunix_server::TyphunixServer, ConnectMessage,
    PingRequest,
};
use styx_emulator::sync::{Arc, Mutex};
use thiserror::Error;
use tokio::task::JoinSet;
use tonic::transport;
use tracing::{info, warn};
use typhunix_config::AppConfig;
use typhunix_proto::symboldb::Wildcards;

pub mod async_server_impl;

pub const SERVICE_READY_MSG: &str = "running";
pub const SERVICE_PORT: u16 = 50051;
pub const SERVICE_HOST: &str = "localhost";

/// Prints message on stderr - this is required for testcontainers - a
/// message to wait for to indicate the service is ready.
fn service_ready() {
    eprintln!("{SERVICE_READY_MSG}");
}

#[derive(Debug, Error)]
pub enum StartServerError {
    #[error("Failed to parse typhunix bind address: `{0}`")]
    BadBindAddress(String),
    #[error("Failed to start typhunix: `{0}`")]
    StartFailed(String),
}

/// Default `TCP` port for the typhunix grpc server
pub const DEFAULT_TYPHUNIX_PORT: u16 = 50051;

/// Import cached typhunix [ConnectMessage] files
pub async fn import_config_cache() -> Vec<ConnectMessage> {
    let mut tasks = Vec::new();
    for cfile in glob::glob_with(
        &format!("{}/cm-*.json", AppConfig::config_dir()),
        glob::MatchOptions::new(),
    )
    .unwrap()
    .flatten()
    .map(|e| e.display().to_string())
    .collect::<Vec<String>>()
    .iter()
    {
        let cfile = cfile.clone();
        info!("Importing cache file {cfile}");
        tasks.push(tokio::spawn(async move {
            json_util::connect_msg_from_file(cfile).await.unwrap()
        }));
    }

    let mut result: Vec<ConnectMessage> = vec![];
    for t in tasks {
        match t.await {
            Ok(c) => match clean(c).await {
                Ok(v) => result.push(v.clone()),
                Err(e) => warn!("{e}"),
            },
            Err(err) => warn!("{err}"),
        }
    }
    result
}

/// Run TyphunixServer on `port`. If `import_cache` is true, import cached `json`
/// [ConnectMessage] files from the `typhunix cache`. If port is not specified,
/// [DEFAULT_TYPHUNIX_PORT] is used.
pub async fn start(port: Option<u16>, import_cache: bool) -> Result<(), StartServerError> {
    let mut cmsgs: Vec<ConnectMessage> = vec![];
    if import_cache {
        cmsgs = import_config_cache().await;
    }
    let port = if let Some(port) = port {
        port
    } else {
        DEFAULT_TYPHUNIX_PORT
    };

    let addr: SocketAddr = format!("0.0.0.0:{port}")
        .parse::<SocketAddr>()
        .map_err(|e| StartServerError::BadBindAddress(e.to_string()))?;

    let dstatesrvr = async_server_impl::TyphunixImpl::new(true, &cmsgs).await;
    log::info!("Server listening on {}", addr);
    log::info!("Wildcard enabled:   {}", dstatesrvr.get_wildcard());
    service_ready();

    transport::Server::builder()
        .add_service(TyphunixServer::new(dstatesrvr))
        .serve(addr)
        .await
        .map_err(|e| StartServerError::StartFailed(e.to_string()))?;
    Ok(())
}

/// An instance of the `typhunix` service running on a port
pub struct TyphunixInstance {
    endpoint: String,
    verify: bool,
    max_verify_tries: u32,
    verify_interval_duration: Duration,
}

impl Default for TyphunixInstance {
    fn default() -> Self {
        const MAX_VERIFY_TRIES: u32 = 10;
        const WAIT_INTERVAL: Duration = Duration::from_millis(125);
        Self {
            endpoint: AppConfig::server_uri(),
            verify: true,
            max_verify_tries: MAX_VERIFY_TRIES,
            verify_interval_duration: WAIT_INTERVAL,
        }
    }
}
impl TyphunixInstance {
    /// Starts typhunix and adds to resource list to cleanup on exit.
    /// Use the provided [JoinSet] to spawn the task.If `verify` is true,
    /// verify it's up and running.
    pub async fn start_joinset_verified(
        &self,
        joinset: Arc<Mutex<JoinSet<Result<(), StartServerError>>>>,
    ) -> bool {
        // Start typhunix and wait for it to come up
        joinset
            .lock()
            .unwrap()
            .spawn(async move { crate::start(None, true).await });
        if self.verify {
            self.verify_started().await
        } else {
            true
        }
    }

    /// verify with a ping that the server is running
    /// try [self.max_verify_tries] times
    #[inline]
    async fn verify_started(&self) -> bool {
        let mut ping_ok = false;
        let mut mx_tries = self.max_verify_tries;
        while mx_tries > 0 && !ping_ok {
            if let Ok(mut cli) = TyphunixClient::connect(self.endpoint.to_string()).await {
                if (cli.ping(tonic::Request::new(PingRequest::default())).await).is_ok() {
                    ping_ok = true;
                }
            }
            tokio::time::sleep(self.verify_interval_duration).await;
            mx_tries -= 1;
        }
        ping_ok
    }
}
