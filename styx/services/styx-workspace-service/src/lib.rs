// SPDX-License-Identifier: BSD-2-Clause

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
    let addr = format!("0.0.0.0:{}", port)
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
