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
//! Client-side utilities for typhunix grpc services
use futures::join;
use std::error::Error;
use styx_emulator::grpc::typhunix_interop::{
    json_util,
    symbolic::{DataType, Program, ProgramFilter, ProgramIdentifier, Symbol},
    typhunix_client::TyphunixClient,
    ConnectMessage,
};
use tonic::Request;
use tracing::debug;
use typhunix_proto::grpc_async_client::{data_types_vec, programs_vec, symbols_vec};

/// types
pub type ProgramWithData = Vec<(Program, Vec<Symbol>, Vec<DataType>)>;

/// Get a wilcard program with setting as provided, defaults elsewhere
pub fn get_wildcard_program(client_uuid: Option<String>, updates_only: Option<bool>) -> Program {
    let client_uuid = client_uuid.unwrap_or_default();
    let updates_only = updates_only.unwrap_or_default();
    let any_pid = Some(ProgramIdentifier {
        source_id: "*".to_string(),
        name: "*".to_string(),
    });
    Program {
        pid: any_pid,
        client_uuid,
        updates_only,
        ..Default::default()
    }
}

/// Get updated symbols and data types
pub async fn check_for_updates(
    cstr: &str,
    cli_uuid: String,
) -> Result<(Vec<Symbol>, Vec<DataType>), Box<dyn Error>> {
    let program = get_wildcard_program(Some(cli_uuid), Some(true));
    let (symbols, data_types) = {
        let (r1, r2) = join!(
            symbols_vec(String::from(cstr), program.to_owned()),
            data_types_vec(String::from(cstr), program)
        );
        (r1.unwrap(), r2.unwrap())
    };
    Ok((symbols, data_types))
}

/// subscribe to all updates
pub async fn subscribe_all(cstr: &str) -> Result<(bool, String), Box<dyn Error>> {
    let response = TyphunixClient::connect(cstr.to_owned())
        .await?
        .subscribe(Request::new(get_wildcard_program(None, None)))
        .await?
        .into_inner();
    Ok((response.success, response.uuid))
}

/// unsubscribe for updates
pub async fn unsubscribe(cstr: &str, cli_uuid: String) -> Result<(bool, String), Box<dyn Error>> {
    let response = TyphunixClient::connect(cstr.to_owned())
        .await?
        .un_subscribe(Request::new(get_wildcard_program(Some(cli_uuid), None)))
        .await?
        .into_inner();
    Ok((response.success, response.uuid))
}

/// Get a list of all programs, with symbols and datatypes for each program
pub async fn list_programs(cstr: &str, dump: bool) -> Result<ProgramWithData, Box<dyn Error>> {
    let programs = programs_vec(cstr.to_owned(), ProgramFilter::default()).await?;
    debug!("programs count: {}", programs.len());

    let mut alldata: ProgramWithData = Vec::new();
    for program in programs {
        let (symbols, data_types) = {
            let (r1, r2) = join!(
                symbols_vec(String::from(cstr), program.to_owned()),
                data_types_vec(String::from(cstr), program.to_owned()),
            );
            (r1.unwrap(), r2.unwrap())
        };

        if dump {
            let pid = program.pid.to_owned().unwrap();
            let suffix = &format!("{}_{}.json", pid.source_id, pid.name,);
            let _ = join!(
                json_util::dump_to_file(&symbols, format!("symbols_{}", suffix)),
                json_util::dump_to_file(&data_types, format!("data_types_{}", suffix))
            );
        }
        alldata.push((program, symbols, data_types));
    }
    Ok(alldata)
}

/// Print all programs with symbol and data type counts to stdout
/// if dump==true, write symbols and data types to json files
pub async fn list_all(cstr: &str, dump: bool) -> Result<(), Box<dyn Error>> {
    let data = list_programs(cstr, dump).await?;
    data.iter().for_each(|(p, s, d)| {
        let arch = if let Some(ref arch) = p.architecture {
            format!("{:?}", arch)
        } else {
            "Architecture: None".to_string()
        };

        print!("{}, ", p.pid.as_ref().unwrap());
        print!("Symbol count: {}, ", s.len());
        println!("DataType count: {}", d.len());
        println!("    {}", arch);
        if let Some(ref md) = p.metadata {
            println!("    Loader: {}", md.loader);
        }
        println!();
    });
    println!("-------------------------------------------------------------");
    Ok(())
}

/// Register the program with the provided symbols and data types
pub async fn register_new(
    cstr: &str,
    symbols: Vec<Symbol>,
    data_types: Vec<DataType>,
) -> Result<(), Box<dyn Error>> {
    let response = TyphunixClient::connect(cstr.to_owned())
        .await?
        .register_new(Request::new(ConnectMessage {
            program: Some(Program {
                pid: symbols.first().unwrap().pid.clone(),
                ..Default::default()
            }),
            data_types,
            symbols,
        }))
        .await?
        .into_inner();
    println!("RegisterNew -> success: {}", response.success);
    Ok(())
}

/// Register the [ConnectMessage]
pub async fn register_connect_msg(cstr: &str, cmsg: &ConnectMessage) -> Result<(), Box<dyn Error>> {
    let _ = TyphunixClient::connect(cstr.to_owned())
        .await?
        .register_new(Request::new(cmsg.clone()))
        .await?;
    Ok(())
}
