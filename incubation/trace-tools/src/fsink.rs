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
//! fsink - drain live traces to a file. Watch `/tmp` for `*.srb` files, open
//! consume events, store as a raw file.

use clap::Parser;
use futures::stream::StreamExt;
use ipmpsc::{Receiver, SharedRingBuffer};
use signal_hook::consts::signal::*;
use signal_hook_tokio::Signals;
use std::collections::HashSet;
use std::fs::File;
use std::time::Duration;
use std::{
    io::{Error, Write},
    path::Path,
};
use styx_core::sync::sync::atomic::{AtomicBool, Ordering};
use styx_core::tracebus::{BaseTraceEvent, TraceError, Traceable};
use styx_core::util::logging::init_logging;
use tokio::task::JoinSet;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

#[derive(Debug)]
pub enum SinkDoneReason {
    Cancelled,
    Error,
    MaxTimeouts,
    Stopped,
    Unknown,
}

#[derive(Debug)]
pub struct SinkResult {
    pub reason: SinkDoneReason,
    pub srbfile: String,
    pub num_events: usize,
}
impl SinkResult {
    fn new(srbfile: &str) -> Self {
        Self {
            reason: SinkDoneReason::Unknown,
            num_events: 0,
            srbfile: srbfile.to_string(),
        }
    }
}

/// catch signals, cancel running tasks using the [CancellationToken]
async fn handle_signals(mut signals: Signals, token: CancellationToken) {
    loop {
        if let Some(signal) = signals.next().await {
            let sig_str = match signal {
                SIGHUP => "SIGHUP",
                SIGTERM => "SIGTERM",
                SIGINT => "SIGINT",
                SIGQUIT => "SIGQUIT",
                _ => unreachable!(),
            };
            println!("\nfsink: {sig_str}");
            token.cancel();
        }
        if token.is_cancelled() {
            break;
        }
    }
}

/// read all the events from the srb file, store in a corresponding *.raw file
async fn sink(
    file: &str,
    timeout: Duration,
    max_consecutive_timeouts: usize,
    cancel_token: CancellationToken,
) -> Result<SinkResult, TraceError> {
    let mut reader = EventSink::new(
        file,
        file.replace(".srb", ".raw"),
        timeout,
        max_consecutive_timeouts,
        cancel_token,
    )?;
    println!("fsink: start consuming {file}");
    reader.consume()
}

/// wait for/return a single /tmp/strace*.srb file
async fn next_file(exclude: HashSet<String>) -> Result<Option<String>, String> {
    use glob::glob_with;
    use glob::MatchOptions;
    let options = MatchOptions::new();

    let srb_files: Vec<String> = glob_with("/tmp/strace*.srb", options)
        .unwrap()
        .flatten()
        .map(|e| e.display().to_string())
        .filter(|f| {
            let ip = exclude.contains(f);
            let rawfile = f.replace(".srb", ".raw");
            let path = Path::new(&rawfile);
            !ip && !path.exists()
        })
        .collect();
    Ok(if srb_files.is_empty() {
        None
    } else {
        Some(srb_files[0].clone())
    })
}

pub struct EventSink {
    timeout: Duration,
    max_consecutive_timeouts: usize,
    rx: Box<Receiver>,
    srbfile: String,
    stop_flag: AtomicBool,
    cancel_token: CancellationToken,
}

impl EventSink {
    pub fn new(
        key: &str,
        outfile: String,
        timeout: Duration,
        max_consecutive_timeouts: usize,
        cancel_token: CancellationToken,
    ) -> Result<Self, Error> {
        let rx = Receiver::new(SharedRingBuffer::open(key).unwrap());
        Ok(EventSink {
            rx: Box::new(rx),
            timeout,
            max_consecutive_timeouts,
            srbfile: outfile,
            stop_flag: AtomicBool::new(false),
            cancel_token,
        })
    }

    pub fn stop(&mut self) {
        self.stop_flag.store(true, Ordering::Relaxed);
    }

    pub fn consume(&mut self) -> Result<SinkResult, TraceError> {
        let mut consecutive_timeout_count = 0;
        let mut outfp = File::create(Path::new(&self.srbfile))?;
        let mut result = SinkResult::new(&self.srbfile.clone());

        loop {
            if self.stop_flag.load(Ordering::Relaxed) {
                result.reason = SinkDoneReason::Stopped;
                break;
            }

            if self.cancel_token.is_cancelled() {
                result.reason = SinkDoneReason::Cancelled;
                break;
            }

            match self
                .rx
                .zero_copy_context()
                .recv_timeout::<BaseTraceEvent>(self.timeout)
            {
                Err(e) => {
                    result.reason = SinkDoneReason::Stopped;
                    return Err(TraceError::ReadFailed(format!("{}: {}", self.srbfile, e)));
                }

                Ok(Some(v)) => {
                    result.num_events += 1;
                    consecutive_timeout_count = 0;
                    outfp.write_all(v.binary())?;
                }

                Ok(None) => {
                    // timeout
                    consecutive_timeout_count += 1;
                    if self.max_consecutive_timeouts != 0
                        && consecutive_timeout_count >= self.max_consecutive_timeouts
                    {
                        result.reason = SinkDoneReason::MaxTimeouts;
                        break;
                    } else {
                        continue;
                    }
                }
            };
        }
        Ok(result)
    }
}
/// Args for typhunix server
#[derive(clap::Parser, Debug)]
#[command(version, about, long_about = None)]
struct SinkAppArgs {
    /// path to an SRB file
    #[arg(short, long, default_value = None)]
    file: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = SinkAppArgs::parse();

    init_logging();
    let signals = Signals::new([SIGHUP, SIGTERM, SIGINT, SIGQUIT])?;
    let sig_handle = signals.handle();
    let cancel_token = CancellationToken::new();
    let signals_task = tokio::spawn(handle_signals(signals, cancel_token.clone()));

    let read_timeout = Duration::from_millis(500);
    let max_consecutive_timeouts = 4;

    let mut sink_tasks = JoinSet::new();
    let mut in_progress: HashSet<String> = HashSet::new();

    if let Some(file) = args.file {
        let ct = cancel_token.clone();
        let rawfile = file.replace(".srb", ".raw");
        let path = Path::new(&rawfile);
        if path.exists() {
            println!("fsink: raw file already exists: {rawfile}");
        } else {
            in_progress.insert(file.clone());
            sink_tasks.spawn(async move {
                sink(&file, read_timeout, max_consecutive_timeouts, ct).await
            });
            // we block here
            if let Some(Ok(sink_result)) = sink_tasks.join_next().await {
                match sink_result {
                    Ok(sr) => println!(
                        "fsink: complete: {}: events: {}, ({:?})",
                        sr.srbfile, sr.num_events, sr.reason
                    ),
                    Err(e) => println!("fsink: error: {e}"),
                }
            }
        }
    } else {
        while !cancel_token.is_cancelled() {
            let cancel_token = cancel_token.clone();
            if let Some(ref srbfile) =
                next_file(in_progress.iter().cloned().collect::<HashSet<String>>())
                    .await
                    .unwrap_or_else(|e| {
                        println!("fsink: error getting more files: {e}");
                        std::process::exit(1);
                    })
            {
                let srbfile = srbfile.clone();
                let ct = cancel_token.clone();
                if !in_progress.contains(&srbfile) {
                    in_progress.insert(srbfile.clone());
                    sink_tasks.spawn(async move {
                        sink(&srbfile, read_timeout, max_consecutive_timeouts, ct).await
                    });
                }
            }
            reap_tasks(&mut sink_tasks).await;
        }
    }

    // Terminate the signal stream.
    sig_handle.close();
    let ct = cancel_token.clone();
    if !ct.is_cancelled() {
        ct.cancel();
    }

    signals_task.await?;
    Ok(())
}

pub async fn reap_tasks(taskset: &mut JoinSet<Result<SinkResult, TraceError>>) {
    loop {
        if taskset.is_empty() {
            break;
        }

        match timeout(Duration::from_millis(100), taskset.join_next()).await {
            Ok(result) => match result {
                Some(task_join_result) => match task_join_result {
                    Ok(sink_result) => match sink_result {
                        Ok(sr) => println!(
                            "fsink: complete: {}: events: {}, ({:?})",
                            sr.srbfile, sr.num_events, sr.reason
                        ),
                        Err(e) => println!("fsink: error: {e}"),
                    },
                    Err(e) => println!("{e:?}"),
                },
                None => break, // race condition its OK tho
            },

            // timeout - no tasks have completed
            Err(_) => break,
        }
    }
}
