// SPDX-License-Identifier: BSD-2-Clause

use std::time::Duration;
use styx_dbmigration::{Migrator, MigratorTrait};
use styx_dbmodel::api::prelude::*;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use workspace_service::{cli_util as ws_svc_cli, SERVICE_READY_MSG};

/// Prints message on stderr - this is required for testcontainers - a
/// message to wait for to indicate the service is ready.
fn service_ready() {
    eprintln!("{SERVICE_READY_MSG}");
}
use tokio::task::JoinSet;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    styx_core::util::logging::ServiceLog::new("workspace-svc").create();
    let (dburl, port, svc_url) = {
        let database_url = std::env::var("DATABASE_URL").expect("DATABASE_URL required");
        let port = std::env::var("WORKSPACE_URL_PORT")
            .unwrap_or(workspace_service::SERVICE_PORT.to_string());
        let url = std::env::var("WORKSPACE_URL").unwrap_or(format!(
            "http://{}:{}",
            workspace_service::SERVICE_HOST,
            port
        ));
        let port = port.parse::<u16>().expect("WORKSPACE_URL_PORT: bad port");

        (database_url, port, url)
    };
    info!("DATABASE_URL={dburl}");
    // establish database connection
    let cnx = Database::connect(&dburl).await?;
    Migrator::up(&cnx, None).await?;
    debug!("database schema up to data");
    let mut tasks = JoinSet::new();
    tasks.spawn(workspace_service::start(dburl, port));
    let maxtries = 5;
    for i in 0..maxtries {
        sleep(Duration::from_millis(250)).await;
        let (ok, msg) = ws_svc_cli::test_connection(&svc_url, i == (maxtries - 1)).await;
        if ok {
            service_ready();
            break;
        } else {
            let msg = msg.unwrap();
            eprintln!("{}", msg);
            warn!("{}", msg);
        }
    }

    // we block here until the service completes
    if let Some(Ok(Err(e))) = tasks.join_next().await {
        error!("Workspace service failed: {e}");
        std::process::exit(1);
    }

    Ok(())
}
