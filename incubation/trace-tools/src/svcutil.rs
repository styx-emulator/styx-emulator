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

//! Service utils that span multiple services

use styx_core::errors::styx_grpc::ApplicationError;
use styx_core::grpc::{
    args::ProgramIdentifierArgs, traceapp::InitializeTraceRequest, typhunix_interop::ConnectMessage,
};
use styx_dbmodel::model::prelude::*;
use tracing::error;
use workspace_service::cli_util as ws_svc_cli;

/// Give the [InitializeTraceRequest], check to see if it has a [WsProgram]
/// id. If it does, then try to match the [WsProgram] config to a known
/// [Target](styx_core::grpc::args::Target) - return an error (for now) if there is no match.
///
/// If there is a [Target](styx_core::grpc::args::Target) match, then update the
/// inbound [InitializeTraceRequest] message based on the [WsProgram]:
/// - Save the bin program from bytes
/// - Update the target
pub async fn re_write_request(
    input_request: &InitializeTraceRequest,
    ws_svc_url: &str,
    ty_svc_url: &str,
) -> Result<InitializeTraceRequest, ApplicationError> {
    let request = tonic::Request::new(input_request.clone()).into_inner();
    let mut new_args = request.args()?.clone();

    if new_args.ws_program_id > 0 {
        let mut ws_programs = ws_svc_cli::get_ws_programs(ws_svc_url, new_args.ws_program_id, true)
            .await
            .map_err(|e| {
                ApplicationError::ConnectToServiceError(ws_svc_url.to_string(), e.to_string())
            })?;

        if ws_programs.len() != 1 {
            error!(
                "Expected to fetch 1 wsProgram, but found {} for id={}",
                ws_programs.len(),
                new_args.ws_program_id
            );
            return Err(ApplicationError::InvalidRequest(
                "cannot get ws_program".into(),
            ));
        }

        let (ws_program, cmsg, wsp_pid) = {
            let wsp = ws_programs.pop().unwrap();
            let wsp_pid = wsp.sym_program.clone().unwrap().pid.clone();
            // wsp.sym_program.unwrap(), wsp.symbols, wsp.data_types);
            (
                wsp.clone(),
                ConnectMessage {
                    program: wsp.sym_program.clone(),
                    symbols: wsp.symbols.clone(),
                    data_types: wsp.data_types.clone(),
                },
                wsp_pid.unwrap(),
            )
        };

        new_args.pid = Some(ProgramIdentifierArgs {
            source_id: wsp_pid.source_id.to_string(),
            name: wsp_pid.name.to_string(),
        });

        let Some(config) = ws_program.config else {
            return Err(ApplicationError::MissingData("Config".to_string()));
        };

        let Some(target) =
            super::identity::supported_config::SupportedConfigs::default().target_for(&config)
        else {
            return Err(ApplicationError::ConfigNotSupported(format!(
                "{:?}",
                &config
            )));
        };

        new_args.emulation_args = Some({
            let bin_program_path = format!(
                "/tmp/styx-{}-{}",
                uuid::Uuid::new_v4(),
                ws_program.file.clone().unwrap().path,
            );
            {
                use std::fs::File;
                use std::io::prelude::*;
                File::create_new(&bin_program_path)?.write_all(&ws_program.data)?;
            }
            let mut emu_args = new_args.emulation_args.clone().unwrap();
            if new_args.mode() == TraceMode::Emulated {
                emu_args.firmware_path = bin_program_path.to_string();
            }
            emu_args.target = target.into();
            emu_args
        });

        typhunix_client_bin::register_connect_msg(ty_svc_url, &cmsg)
            .await
            .map_err(|e| {
                ApplicationError::ConnectToServiceError(ty_svc_url.to_string(), e.to_string())
            })?;

        let saved = ws_svc_cli::upsert_trace_app_session(ws_svc_url, [new_args].to_vec())
            .await
            .map_err(|e| ApplicationError::DbQueryError("error saving request", e.to_string()))?
            .trace_app_session_args
            .first()
            .cloned();

        if let Some(trace_app_session_args) = saved {
            return Ok(InitializeTraceRequest::new(trace_app_session_args));
        } else {
            return Err(ApplicationError::DbQueryError(
                "error saving request",
                "fetch result".to_string(),
            ));
        };
    }

    Ok(request)
}
