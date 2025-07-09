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
//! Client tool for connecting to
//! [TraceAppSessionService](styx_core::grpc::traceapp::trace_app_session_service_server::TraceAppSessionService).

use clap::{Args, Parser, Subcommand};
use serde_json::{json, Value};
use std::fs::File;
use std::io::BufReader;
use std::time::Duration;
use std::{error::Error, path::Path};
use styx_core::grpc::{
    args::{
        EmulationArgs, ProgramIdentifierArgs, RawEventLimits, SymbolSearchOptions,
        TraceAppSessionArgs,
    },
    traceapp::{
        InitializeTraceRequest, StartTraceAppSessionResponse, StartTraceAppSessionResponseSummary,
    },
};
use styx_trace_tools::{event::StreamEndReason, util::ghidra_program_id_from_env};
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;
use traceapp_service::cli_util::*;

pub fn input() -> Value {
    json!(
    {
        "args": {
          "id": 2,
          "mode": 0,
          "session_id": "",
          "resume": false,
          "pid": {
            "name": "k21-1.bin",
            "source_id": "3524872547775184128"
          },
          "trace_filepath": "/tmp/sample2.raw",
          "raw_trace_args": {
            "trace_directory": "/tmp",
            "trace_wait_file": false
          },
          "emulation_args": {
            "id": 2,
            "target": 0,
            "firmware_path": "/firmware/k21-1.bin",
            "trace_plugin_args": {
              "insn_event": true,
              "write_memory_event": true,
              "read_memory_event": false,
              "interrupt_event": true,
              "block_event": false
            },

            "ipc_port": 0
          },
          "limits": {
            "id": 2,
            "max_insn": 1000000,
            "max_mem_read_events": 0,
            "max_mem_write_events": 0
          },
          "symbol_options": {
            "regex_include": ".",
            "regex_exclude": ""
          }
        }
      })
}
/// traceapp is a cli for controlling the traceapp-svc gRPC service
#[derive(Debug, Subcommand, Clone)]
enum Command {
    /// Drop a session
    Drop(SessionArg),
    // Disconnect(String),
    // List,
    GetVariable(SessionArg),
    /// Start a session
    Initialize,
    /// List sessions
    List(ListArgs),
    /// Start a session
    Start(StartArgs),
    /// Stop a session
    Stop(SessionArg),
}

#[derive(Debug, Args, Clone)]
struct SessionArg {
    /// session id
    #[arg(required(true))]
    session_id: String,
}

#[derive(Debug, Args, Clone)]
struct ListArgs {
    /// Long (verbose) session list
    #[arg(short('l'), default_value("false"))]
    long_list: bool,
}

/// Start a new emulation
#[styx_macros_args::styx_app_args]
struct StartArgs {
    /// Duration in seconds to run the emulator
    #[arg(long, default_value("0"))]
    emu_duration: u64,

    /// max_insn
    #[arg(long, default_value("0"))]
    max_insn: u64,

    /// Buffer interval in milli-seconds
    #[arg(long, default_value("5000"))]
    buffer_interval: u128,

    #[arg(long, default_value("false"))]
    drop_when_done: bool,
}

#[derive(Debug, Parser, Clone)]
pub struct AppArgs {
    #[clap(subcommand)]
    command: Command,

    /// Regex pattern to match symbol name
    #[arg(global(true), short('r'), long, default_value_t=String::from("."))]
    regex: String,

    /// Regex pattern to match symbol name
    #[arg(global(true), long, default_value_t=String::from("http://localhost:54321"))]
    url: String,
}

impl AppArgs {
    pub fn url(&self) -> String {
        self.url.clone()
    }
    pub fn regex(&self) -> String {
        self.regex.clone()
    }
}

pub fn make_traceapp_request(
    emulation_args: &EmulationArgs,
    app_args: &AppArgs,
    max_insn: u64,
) -> InitializeTraceRequest {
    // fixme: pid should be a parameter
    let pid = ghidra_program_id_from_env();

    if pid.is_none() {
        eprintln!("Set / export GHIDRA_SOURCE_PROJECT_ID");
        std::process::exit(1);
    }
    let pid = pid.unwrap();
    let raw_event_limits = RawEventLimits {
        id: i32::default(),
        max_insn,
        max_mem_read_events: 0,
        max_mem_write_events: 0,
    };

    let regex_include = &app_args.regex.clone();
    InitializeTraceRequest::new(TraceAppSessionArgs::new_emulated(
        Some(ProgramIdentifierArgs::new(&pid.name, &pid.source_id)),
        Some(emulation_args.clone()),
        Some(raw_event_limits),
        Some(SymbolSearchOptions {
            regex_include: regex_include.clone(),
            regex_exclude: "".to_string(),
            mem_reads: bool::default(),
            mem_writes: true,
            anon_reads: bool::default(),
            anon_writes: bool::default(),
        }),
    ))
}

fn summarize_responses(
    responses: &[StartTraceAppSessionResponse],
    emu_duration: u64,
    buffer_interval: u128,
    reason: &StreamEndReason,
) -> String {
    let mut max_insn = 0;
    let mut nfenter = 0;
    let mut nfexit = 0;
    let mut nintr = 0;
    let mut nmems = 0;
    let mut neoe = 0;
    let mut ninst = 0;

    for response in responses.iter() {
        // let temp = response.clone();
        // let ss = StartTraceAppSessionResponseSummary::from(temp);
        // println!("{:?}", ss);

        if let Some(ref timeout) = response.timeout {
            if timeout.insn_num > max_insn {
                max_insn = timeout.insn_num;
            }
        }
        if let Some(ref insn_limit_reached) = response.insn_limit_reached {
            if insn_limit_reached.insn_num > max_insn {
                max_insn = insn_limit_reached.insn_num;
            }
        }
        for memchg in response.memory_writes.iter() {
            if memchg.insn_num > max_insn {
                max_insn = memchg.insn_num;
            }
            nmems += 1;
        }
        for eoe in response.end_of_events.iter() {
            if eoe.insn_num > max_insn {
                max_insn = eoe.insn_num;
            }
            neoe += 1;
        }
        for intr in response.interrupts.iter() {
            if intr.insn_num > max_insn {
                max_insn = intr.insn_num;
            }
            nintr += 1;
        }
        for inst in response.instructions.iter() {
            if inst.insn_num > max_insn {
                max_insn = inst.insn_num;
            }
            ninst += 1;
        }
        for f in response.functions.iter() {
            if f.insn_num > max_insn {
                max_insn = f.insn_num;
            }
            if f.entered {
                nfenter += 1;
            } else {
                nfexit += 1;
            }
        }
    }

    let mut summary_str = format!(
        "StopReason: {:?}, dur(s):{}, buf(ms):{}, responses: {}",
        reason,
        emu_duration,
        buffer_interval,
        responses.len(),
    );

    summary_str.push_str(&format!("\n  max_insn: {}", max_insn));
    summary_str.push_str(&format!("\n  nfenter:  {}", nfenter));
    summary_str.push_str(&format!("\n  nfexit:   {}", nfexit));
    summary_str.push_str(&format!("\n  nintr:    {}", nintr));
    summary_str.push_str(&format!("\n  nmems:    {}", nmems));
    summary_str.push_str(&format!("\n  neoe:     {}", neoe));
    summary_str.push_str(&format!("\n  ninst:    {}", ninst));

    summary_str
}

/// Deserialize request from the file path
#[inline]
pub async fn request_from_file<P: AsRef<Path>>(
    path: P,
) -> Result<InitializeTraceRequest, Box<dyn Error>> {
    Ok(serde_json::from_reader(BufReader::new(File::open(path)?))?)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    styx_core::util::logging::init_logging();
    let args = AppArgs::parse();
    let url = args.url();

    match args.command {
        Command::Initialize => {
            let request = request_from_file("").await?;
            println!("{:?}", request);
            let (etx, mut erx) = mpsc::channel(100);
            // let eargs: EmulationArgs = request.args()?.get_emulation_args().unwrap();
            let cancel_token = CancellationToken::new();

            println!("=> Initializing ...");
            let url_c = url.clone();
            let ct = cancel_token.clone();
            let fut =
                tokio::spawn(async move { initialize(&url_c.clone(), &request, etx, ct).await });
            while !fut.is_finished() {
                tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
                while let Some(stuff) = erx.recv().await {
                    let json = serde_json::to_string(&stuff)?;
                    println!("{json}");
                }
            }

            std::process::exit(1);
        }
        Command::Start(ref start_args) => {
            let emu_duration = start_args.emu_duration;
            let buffer_interval = start_args.buffer_interval;
            let drop_when_done = start_args.drop_when_done;
            let (tx, mut rx) = mpsc::channel(100);
            let (etx, mut erx) = mpsc::channel(100);
            let eargs: EmulationArgs = start_args.clone().into();
            let request = make_traceapp_request(&eargs, &args.clone(), start_args.max_insn);
            let cancel_token = CancellationToken::new();

            println!("=> Starting ...");
            let url_c = url.clone();
            let ct = cancel_token.clone();
            let fut = tokio::spawn(async move {
                start(&url_c.clone(), &request, buffer_interval, tx, etx, ct).await
            });

            let mut sid: Option<String> = None;

            while sid.is_none() {
                if let Ok(Some(session_id)) = timeout(Duration::from_secs(1), rx.recv()).await {
                    println!("SESSION_ID={}", session_id);
                    sid = Some(session_id.clone());
                }
                if fut.is_finished() || cancel_token.is_cancelled() {
                    break;
                }
            }

            if let Some(session_id) = sid {
                let stopper_fut = if emu_duration > 0 {
                    let running = match_one_session(&url.clone(), &session_id).await?;
                    let url_c = url.clone();
                    Some(tokio::spawn(async move {
                        println!(
                            "  => Scheduled stop {} in {} seconds...",
                            running.session_id, emu_duration
                        );
                        sleep(Duration::from_secs(emu_duration)).await;
                        println!("=> Stopping {} ...", &running.session_id);
                        stop(&url_c, &running).await
                    }))
                } else {
                    None
                };

                let mut all_responses: Vec<StartTraceAppSessionResponse> = vec![];
                // process the stream of responses...
                while let Some(stuff) = erx.recv().await {
                    all_responses.push(stuff.clone());
                    let s = StartTraceAppSessionResponseSummary::from(stuff);
                    println!("Received: {}", s.json());
                }

                let result_string = match fut.await? {
                    Ok(ref result) => {
                        let summary = summarize_responses(
                            &all_responses,
                            emu_duration,
                            buffer_interval,
                            result,
                        );
                        println!("SUMMARY: {summary}");
                        format!("Start task result OK: {:?}", result)
                    }
                    Err(e) => {
                        format!("Start task result FAIL: {:?}", e)
                    }
                };
                if let Some(fut) = stopper_fut {
                    match fut.await? {
                        Ok(stop_task) => println!("stop_task: {:?}", stop_task),
                        Err(e) => println!("stop_task: {:?}", e),
                    }
                }

                if drop_when_done {
                    println!("=> Dropping ...");
                    let session = match_one_session(&url.clone(), &session_id).await?;
                    disconnect(&url.clone(), &session).await?;
                    println!("{}", result_string);
                }
            } else {
                eprintln!("No session_id: failed to start");
                if fut.is_finished() {
                    let result_string = match fut.await? {
                        Ok(result) => {
                            format!("Start task result OK: {:?}", result)
                        }
                        Err(e) => {
                            format!("Start task result FAIL: {:?}", e)
                        }
                    };
                    println!("{result_string}")
                }
                std::process::exit(1);
            }
        }

        Command::List(ref list_args) => {
            list(list_args.long_list, &url.clone()).await?;
        }
        Command::Stop(SessionArg { session_id }) => {
            let session = match_one_session(&url.clone(), &session_id).await?;
            stop(&url.clone(), &session).await?;
        }
        Command::Drop(SessionArg { session_id }) => {
            let session = match_one_session(&url.clone(), &session_id).await?;
            disconnect(&url.clone(), &session).await?;
        }

        Command::GetVariable(SessionArg { session_id }) => {
            let session = match_one_session(&url.clone(), &session_id).await?;
            get_variable_snapshots(&url.clone(), &session).await?;
        }
    }

    Ok(())
}
