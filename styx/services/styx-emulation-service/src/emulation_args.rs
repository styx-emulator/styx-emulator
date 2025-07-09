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
//! Module to [spawn](fn@std::process::Command::spawn) a
//! [SingleEmulationService](styx_core::grpc::emulation::single_emulation_service_server::SingleEmulationService),
//! with help from [SingleEmulationServiceExecutor].

use std::fmt::Display;
use std::fs::File;
use std::io::{BufRead, BufReader, Error, ErrorKind};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use styx_core::grpc::args::HasEmulationArgs;
use styx_core::grpc::ToArgVec;
use styx_core::util::traits::HasUrl;
use tracing::{debug, error, info, warn};

/// Full path to the binary program that runs the emulation service for a single
/// emulator instance.
pub const SINGLE_EMULATION_SERVICE_BINARY: &str = "emusvc-svc";

/// Run styx emulation as a service
#[styx_macros_args::styx_app_args]
pub struct CliEmulationArgs {
    /// Start the emulator
    #[arg(short('S'), long, default_value_t = false)]
    pub start: bool,

    /// Display args, but do not execute
    #[arg(short, long, default_value_t = false)]
    pub dry_run: bool,

    /// emulation level
    #[arg(default_value_t = styx_core::grpc::args::EmulationLevel::Machine)]
    #[clap(value_enum)]
    pub emu_level: styx_core::grpc::args::EmulationLevel,
}

/// When the [SINGLE_EMULATION_SERVICE_BINARY] is launched, we need to know
/// what the trace path is, which port was randomly selected, the host its running
/// on and the [Child] process. The host and port are used to connect over `GRPC`
/// and call `RPC` methods.
#[derive(Debug)]
pub struct ServiceMetadata {
    pub trace_path: String,
    pub port: u16,
    pub host: String,
    pub child: Child,
}
impl Display for ServiceMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{}, {}, pid:{}",
            self.host,
            self.port,
            self.trace_path,
            self.child.id()
        )
    }
}
impl ServiceMetadata {
    pub fn process_id(&self) -> u32 {
        self.child.id()
    }
    pub fn port(&self) -> u16 {
        self.port
    }
    pub fn host(&self) -> String {
        self.host.to_string()
    }
    pub fn trace_path(&self) -> String {
        self.trace_path.to_string()
    }

    pub fn wait_child(&mut self) -> std::io::Result<std::process::ExitStatus> {
        self.child.wait()
    }

    pub fn kill_child(&mut self) -> std::io::Result<()> {
        debug!("kill_child: {:?}, pid: {}", self.child, self.child.id());
        if let Err(e) = self.child.kill() {
            warn!("Failed to kill child process: {}", e);
        } else {
            info!("child process killled")
        }
        self.child.wait()?;
        Ok(())
    }
}

impl HasUrl for ServiceMetadata {
    fn url(&self) -> String {
        format!("http://{}:{}", self.host, self.port)
    }
}

/// Component used to launch the [SINGLE_EMULATION_SERVICE_BINARY]
pub struct SingleEmulationServiceExecutor {
    command: String,
    args: Vec<String>,
}

impl Display for SingleEmulationServiceExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: args: {:?}", self.command, self.args)
    }
}
/// error message for when we are unable to determine the [ServiceMetadata].
const META_ERROR: &str = r#"Cannot determine launch host, port, trace path
    for spawned emulation service. This is done by reading/parsing stderr
    from the launched process."#;

impl SingleEmulationServiceExecutor {
    /// Construct with arguments that get parsed by [CliEmulationArgs] when
    /// launching the [SINGLE_EMULATION_SERVICE_BINARY]
    pub fn new(args: Vec<String>) -> Self {
        Self {
            command: SINGLE_EMULATION_SERVICE_BINARY.into(),
            args,
        }
    }

    /// Construct with arguments that get parsed by [CliEmulationArgs] when
    /// launching the [SINGLE_EMULATION_SERVICE_BINARY]
    pub fn from_pbuf_emulation_args<T: HasEmulationArgs + ToArgVec>(
        args: T,
    ) -> Result<Self, std::io::Error> {
        let arg_vec = args.arg_vec();
        debug!("SingleEmulationServiceExecutor: args vector: {:?}", arg_vec);
        Ok(Self::new(arg_vec))
    }

    /// Spawn the [SINGLE_EMULATION_SERVICE_BINARY] using [Command] and
    /// [spawn](fn@std::process::Command::spawn).
    ///
    /// The caller needs to track [ServiceMetadata]. This is currenly
    /// done by reading / parsing the `stderr` of the
    /// [SINGLE_EMULATION_SERVICE_BINARY].
    ///
    /// # Returns
    /// [ServiceMetadata] or an error if unable to spawn or unable to
    /// determine the requred metadata for [ServiceMetadata].
    pub fn exec(&self) -> Result<ServiceMetadata, std::io::Error> {
        let command_string = format!("cmd: [{} {}]", self.command, self.args.join(" "));
        info!("SingleEmulationServiceExecutor: Spawning emulator process");
        info!("{}", command_string);
        for (i, arg) in self.args.iter().enumerate() {
            info!("  arg[{}]: {}", i, arg);
        }
        let mut child = Command::new(&self.command)
            .args(&self.args)
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                let msg = format!("Failed to launch {}: {}", self.command, e);
                error!("{}", msg);
                Error::new(ErrorKind::Other, msg)
            })?;

        debug!("Child spawned, capture service info...");
        let stderr = child.stderr.take().unwrap();
        let mut br = BufReader::new(stderr);

        for _ in 0..1000 {
            let mut line = String::new();
            let _ = br.read_line(&mut line)?;
            if let Some((host, port, trace_path)) = Self::parse_info(&line) {
                let meta = ServiceMetadata {
                    trace_path,
                    port,
                    host,
                    child,
                };
                info!("Created emulator: {:?}", meta);
                return Ok(meta);
            }
        }
        Err(Error::new(
            ErrorKind::Other,
            format!("{} {}", META_ERROR, command_string),
        ))
    }

    /// The [SINGLE_EMULATION_SERVICE_BINARY] should call
    /// [SingleEmulationServiceExecutor::broadcast_service_meta]. This function
    /// gets repeatedly called to parse the information.
    ///
    /// # Returns
    /// an Optional 3-tuple, None if the information is not found, else:
    ///   - host: String,
    ///   - port: u16,
    ///   - path: String
    fn parse_info(line: &str) -> Option<(String, u16, String)> {
        // Example: SERVICE_INFO_LINE,127.0.0.1,3232,/tmp/strace..."
        let mut line = line.to_string();
        while line.ends_with('\n') {
            line.pop();
        }
        debug!("emulator output: stderr: {}", line);
        if line.starts_with("SERVICE_INFO_LINE") {
            let parts = line.split(',').collect::<Vec<&str>>();
            if parts.len() >= 4 {
                let host = parts.get(1).unwrap().to_string();
                let port = parts.get(2).unwrap().parse::<u16>().unwrap();
                let path = parts.get(3).unwrap().to_string();
                return Some((host, port, path));
            }
        }

        None
    }

    /// called by [SINGLE_EMULATION_SERVICE_BINARY] to send service metadata
    /// over stderr to be parsed by [SingleEmulationServiceExecutor].
    /// # Parameters
    /// - host is the hostname or ip address that the service is addressable by (example: 127.0.0.1)
    /// - port is the port number
    /// - trace_path is the fullpath to the styx trace file
    pub fn broadcast_service_meta(host: &str, port: u16, trace_path: &str) {
        eprintln!("SERVICE_INFO_LINE,{},{},{}", host, port, trace_path);
    }
}

/// Deserialize the yaml
#[inline]
pub async fn yaml_from_file<P: AsRef<Path>>(
    path: P,
) -> Result<CliEmulationArgs, Box<dyn std::error::Error>> {
    Ok(serde_yaml::from_reader(BufReader::new(File::open(path)?))?)
}

// /// Deserialize the yaml
// #[inline]
// pub async fn yaml_from_file(path: &str) -> Result<CliEmulationArgs, Box<dyn std::error::Error>> {
//     Ok(serde_yaml::from_reader(BufReader::new(File::open(path)?))?)
// }
