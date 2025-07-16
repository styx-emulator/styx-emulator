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
//! strace - a command-line tool for reading and generating trace events

use clap::{value_parser, Arg, ArgAction, Command};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
    time::{Duration, Instant},
};
use styx_core::tracebus::*;
use styx_trace_tools::util::io::{writable, OutputFormat, ReturnType};

/// timeout value waiting for events before the API says there are no more events
const DEFAULT_READ_TIMEOUT: u64 = 500;

const ARG_NUM_EVENTS: &str = "num_events";
const ARG_KEY: &str = "key";
const ARG_OUTPUT_TYPE: &str = "output_type";
const ARG_OUTPUT_FILE: &str = "file_out";
const ARG_STOP_ON_TIMEOUT: &str = "stop_on_timeout";
const ARG_TIMEOUT: &str = "timeout";
const CMD_READ: &str = "read";
const CMD_GENERATE: &str = "generate";

const DEFAULT_BUFFER_KEY: &str = "/tmp/strace.srb";

/// Arguments and options for this tool
#[derive(Debug, Default, Serialize, Deserialize)]
struct CArgs {
    /// the commmand (generate/read)
    cmd: String,
    /// the buffer key
    key: String,
    /// number of events
    num_events: usize,
    /// format of output
    output_format: String,
    /// flag to indicate stop on timeout
    stop_on_timeout: bool,
    /// read timeout
    read_timeout: Duration,
    /// output file
    outfile: Option<String>,
}

impl CArgs {
    pub fn parse_args() -> CArgs {
        let arg_num_events = Arg::new(ARG_NUM_EVENTS)
            .short('n')
            .value_parser(value_parser!(usize))
            .long(ARG_NUM_EVENTS)
            .help("Number of events to generate")
            .action(ArgAction::Set)
            .default_missing_value("1")
            .global(true)
            .default_value("1");
        let arg_outfile = Arg::new(ARG_OUTPUT_FILE)
            .short('f')
            .global(true)
            .long(ARG_OUTPUT_FILE)
            .action(ArgAction::Set);
        let arg_output_type = Arg::new(ARG_OUTPUT_TYPE)
            .short('o')
            .global(true)
            .long(ARG_OUTPUT_TYPE)
            .value_parser(["jsonl", "text", "raw"])
            .default_value("jsonl");

        let arg_key = Arg::new(ARG_KEY)
            .global(true)
            .default_value(DEFAULT_BUFFER_KEY)
            .short('k')
            .long(ARG_KEY)
            .action(ArgAction::Set)
            .num_args(1)
            .help("Key to buffer file (full path filename)");

        let arg_timeout = Arg::new(ARG_TIMEOUT)
            .short('t')
            .value_parser(value_parser!(u64))
            .long(ARG_TIMEOUT)
            .help("Read timeout (ms). Zero will block.")
            .action(ArgAction::Set)
            .default_missing_value("500")
            .default_value("500");

        let arg_stop_on_timeout = Arg::new(ARG_STOP_ON_TIMEOUT)
            .short('s')
            .required(false)
            .action(ArgAction::SetTrue)
            .help("stop reading on first timeout");

        let matches = Command::new("strace")
            .about("styx trace utility")
            .version("1.0")
            .subcommand_required(true)
            .arg_required_else_help(true)
            .subcommand_required(false)
            // All commands have these args
            .arg(&arg_output_type)
            .arg(&arg_key)
            .arg(&arg_num_events)
            .arg(&arg_outfile)
            // SUB COMMANDS
            .subcommand(
                Command::new(CMD_GENERATE)
                    .short_flag('G')
                    .long_flag(CMD_GENERATE)
                    .about("Generate TraceEvents")
                    .arg(&arg_key)
                    .arg(&arg_num_events),
            )
            // read subcommand
            .subcommand(
                Command::new(CMD_READ)
                    .short_flag('R')
                    .long_flag(CMD_READ)
                    .about("Read/display events")
                    .arg(&arg_stop_on_timeout)
                    .arg(&arg_timeout),
            )
            .get_matches();

        let mut stop_on_timeout = false;
        let mut read_timeout = Duration::from_millis(DEFAULT_READ_TIMEOUT);

        let cmd = match matches.subcommand() {
            Some(("generate", _)) => {
                // match sub-cmd specific options with match {...}
                CMD_GENERATE.to_string()
            }
            Some(("read", m)) => {
                // match sub-cmd specific options
                // if m.contains_id(ARG_STOP_ON_TIMEOUT) {
                stop_on_timeout = m.get_flag(ARG_STOP_ON_TIMEOUT);
                let read_timeout_val = *m.get_one::<u64>(ARG_TIMEOUT).unwrap();
                read_timeout = Duration::from_millis(read_timeout_val);
                CMD_READ.to_string()
            }
            _ => CMD_READ.to_string(),
        };

        let num_events = *matches.get_one::<usize>(ARG_NUM_EVENTS).unwrap();
        let outfile = matches.get_one::<String>(ARG_OUTPUT_FILE);
        let output_format = matches
            .get_one::<String>(ARG_OUTPUT_TYPE)
            .unwrap()
            .to_string();
        let key = matches.get_one::<String>(ARG_KEY).unwrap().to_string();
        CArgs {
            cmd,
            key,
            num_events,
            output_format,
            stop_on_timeout,
            read_timeout,
            outfile: outfile.cloned(),
        }
    }

    #[inline]
    pub fn block_msg(&self) -> String {
        if self.read_timeout.as_nanos() == 0 {
            " [will block]".to_string()
        } else {
            "".to_string()
        }
    }
}

/// Generate a handfull of TraceEvents
fn generate_events() {
    strace!(ControlEvent::new());
    strace!(InsnExecEvent::new());
    strace!(InsnFetchEvent::new());
    strace!(MemReadEvent::new());
    strace!(MemWriteEvent::new());
    strace!(RegReadEvent::new());
    strace!(RegWriteEvent::new());
    strace!(BranchEvent::new());
    strace!(InterruptEvent::new());
}

/// main
fn main() {
    // setup logging
    pretty_env_logger::init();
    let cargs = CArgs::parse_args();
    tracing::debug!("ARGS: {:?}", cargs);

    let ofmt = OutputFormat::from(cargs.output_format.to_owned());
    let keyfile = &cargs.key;
    let bstr = cargs.block_msg();
    let mut write_to_file: bool = false;
    let mut out_writer = match cargs.outfile {
        Some(x) => {
            write_to_file = true;
            let path = Path::new(&x);
            Box::new(File::create(path).unwrap()) as Box<dyn Write>
        }
        None => Box::new(std::io::stdout()) as Box<dyn Write>,
    };

    if ofmt == OutputFormat::RAW && !write_to_file {
        eprintln!("output file is required when format is raw");
        std::process::exit(1);
    }

    let mut num_timeouts = 0;
    let mut num_events = 0;
    let start_epoch = Instant::now();

    if cargs.cmd == CMD_GENERATE {
        generate_events();
    } else if keyfile.ends_with(".raw") {
        fn read_events(filename: &str, out_format: &OutputFormat, out_writer: &mut Box<dyn Write>) {
            //  [u8; 24] {
            let mut f = File::open(filename).expect("no file found");
            let metadata = std::fs::metadata(filename).expect("unable to read metadata");
            let mut buffer: [u8; 24] = [0; 24];
            // let mut buffer = vec![0; metadata.len() as usize];
            let nrecs = metadata.len() / 24;
            for _ in 0..nrecs {
                let sz = f.read(&mut buffer).expect("Read failed");
                debug_assert_eq!(sz, TRACE_EVENT_SIZE);
                let out_str = match out_format {
                    OutputFormat::JSONL => format!(
                        "{}\n",
                        TraceableItem::from(BaseTraceEvent::from(&buffer)).json()
                    ),
                    _ => format!(
                        "{}\n",
                        TraceableItem::from(BaseTraceEvent::from(&buffer)).text()
                    ),
                };
                out_writer.write_all(out_str.as_bytes()).unwrap();
            }
        }
        read_events(keyfile, &ofmt, &mut out_writer);

        std::process::exit(0);
    } else {
        let mut rx = receiver!(keyfile.as_str());
        eprintln!(
            "Waiting for events [{keyfile}], timeout: {:?} {bstr}...",
            cargs.read_timeout
        );

        loop {
            match next_event!(rx, cargs.read_timeout) {
                (_, _, Some(event)) => {
                    match writable(event, ofmt) {
                        ReturnType::Binary(ref data) => {
                            out_writer.write_all(data).unwrap();
                        }
                        ReturnType::Json(ref s) | ReturnType::Text(ref s) => {
                            let s = format!("{s}\n");
                            out_writer.write_all(s.as_bytes()).unwrap();
                        }
                    }

                    num_events += 1;
                    num_timeouts = 0;
                }
                (_, true, _) => {
                    num_timeouts += 1;
                    if cargs.stop_on_timeout {
                        break;
                    }
                }
                (err, false, None) => {
                    eprintln!("Error: {err}");
                    break;
                }
            }
        }
    }

    let dur = start_epoch.elapsed();
    let rate = num_events as f64 / dur.as_secs_f64();
    let mut stats = String::from("Stats: ");
    stats.push_str(&format!("events: {num_events}, "));
    stats.push_str(&format!("timeouts: {num_timeouts}, "));
    stats.push_str(&format!("time: {:.2} secs, ", dur.as_secs_f64()));
    stats.push_str(&format!("rate: {} events/sec", rate as u64));
    eprintln!("{stats}");
}
