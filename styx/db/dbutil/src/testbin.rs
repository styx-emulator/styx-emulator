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
