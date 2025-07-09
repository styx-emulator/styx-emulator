// SPDX-License-Identifier: BSD-2-Clause
#[allow(unused_imports)]
use log::{debug, info};
use std::env::var;
use std::error::Error;
use styx_core::grpc::workspace::Workspace;
use workspace_service::cli_util as ws_svc_cli;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    styx_core::util::logging::init_logging();
    upsert_default(&var("WORKSPACE_URL")?).await?;
    Ok(())
}

async fn upsert_default(url: &str) -> Result<(), Box<dyn Error>> {
    let workspace = Workspace {
        id: 0,
        name: "Default".into(),
        ws_programs: vec![],
        created_timestamp: Some(std::time::SystemTime::now().into()),
    };

    let id = ws_svc_cli::upsert_workspace(url, &workspace).await?;
    info!("upsert_workspace response:  {:?}", id);
    Ok(())
}
