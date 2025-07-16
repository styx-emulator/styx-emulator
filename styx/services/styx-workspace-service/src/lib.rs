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

//! Implementation of `GRPC` workspace service
//! [WorkspaceSvc](styx_core::grpc::workspace::workspace_svc_server::WorkspaceSvc)

use styx_core::grpc::workspace::workspace_svc_server::WorkspaceSvcServer;
use styx_dbmigration::{Migrator, MigratorTrait};
use styx_dbmodel::api::prelude::*;
use tonic::{transport::Server, Code, Status};
use tracing::debug;

pub const SERVICE_READY_MSG: &str = "running";
pub const SERVICE_PORT: u16 = 55555;
pub const SERVICE_HOST: &str = "localhost";

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
    let svc = svc::ServerImpl::new(cnx);
    Server::builder()
        .add_service(WorkspaceSvcServer::new(svc))
        .serve(addr)
        .await
        .map_err(|e| Status::new(Code::Unavailable, format!("{e}")))?;
    Ok(())
}

pub mod cli_util;
pub mod svc;
