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
//! ptrace - command-line trace execution for styx emulators

use clap::{Args, Parser, Subcommand};
use emulation_service::emulation_args::{
    yaml_from_file, CliEmulationArgs, ServiceMetadata, SingleEmulationServiceExecutor,
};
use futures_util::{pin_mut, stream::StreamExt};
use signal_hook::consts::signal::*;
use signal_hook_tokio::Signals;
use std::{error::Error, time::Duration};
use styx_emulator::core::sync::lazy_static;
use styx_emulator::core::util::traits::*;
use styx_emulator::errors::styx_grpc::ApplicationError;
use styx_emulator::grpc::args::{
    EmulationArgs, HasTarget, ProgramIdentifierArgs, RawEventLimits, RawEventLimitsValueParser,
    SymbolSearchOptions, TraceAppSessionArgs, TracePluginArgs,
};
use styx_emulator::grpc::typhunix_interop::symbolic::ProgramIdentifier;
use styx_emulator::grpc::typhunix_interop::ProgramRef;
use styx_emulator::grpc::utils::Empty;
use styx_emulator::grpc::{
    emulation::{
        single_emulation_service_client::SingleEmulationServiceClient, StartSingleEmulationRequest,
    },
    traceapp::InitializeTraceRequest,
};
use styx_emulator::sync::{
    atomic::{AtomicBool, Ordering::AcqRel, Ordering::Acquire, Ordering::Release},
    Arc, Mutex,
};
use styx_trace_tools::{
    analyzers::{AnalysisType, EventRepeater, HasAnalysisOptions, OutputFormat},
    emu_observer::*,
    post_analysis::post_analysis,
    util::{ghidra_program_id_from_env, output_dst, OutDst},
    ConditionVar,
};
use tokio::{
    sync::mpsc::{self},
    task::JoinSet,
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;
use tonic::Request;
use traceapp_service::cli_util::match_one_session;
use tracing::{debug, info};
use typhunix_server_bin::{StartServerError, TyphunixInstance};

#[derive(Debug, Default)]
pub struct StaticResources {
    pub pids: Arc<Mutex<Vec<ServiceMetadata>>>,
    pub typhunix_tasks: Arc<Mutex<JoinSet<Result<(), StartServerError>>>>,
    pub cancel_token: CancellationToken,
    pub was_killed: AtomicBool,
    pub cleaned: AtomicBool,
    pub signal_handler_executing: AtomicBool,
    pub ok_to_exit: ConditionVar,
}

lazy_static! {
    static ref RESOURCES: StaticResources = StaticResources::default();
}

/// Global resources that need release on exit
impl StaticResources {
    /// Cleanup resources allocated/acquired by ptrace
    /// this method is idempotent, using `cleaned` as a mutex
    fn cleanup(&self, caller: &str) {
        debug!(
            "cleanup: [caller: {caller}]: cancel token: {:?}, was_killed: {}, signal_handler_executing={}",
            self.cancel_token,
            self.was_killed(),
            self.signal_handler_executing.load(Acquire)
        );

        if !self.signal_handler_executing.load(Acquire) && !self.cleaned.load(Acquire) {
            let (cndmtx, cvar) = &*self.ok_to_exit.get_pair();
            // let (lock, cvar) = &*self.ok_to_exit.pair2;
            let mut started = cndmtx.lock().unwrap();
            *started = true;

            debug!("cleanup: [caller: {caller}]: start");
            self.cleaned.store(true, Release);
            let mut mtx = self.pids.lock().unwrap();
            let mut item = mtx.pop();
            while let Some(mut smeta) = item {
                debug!("cleanup: [caller: {caller}]: killing {smeta}");
                let _ = smeta.kill_child();
                let _ = smeta.wait_child();
                item = mtx.pop();
            }
            debug!("cleanup: [caller: {caller}]: done cleaning");
            cvar.notify_one();
        }

        loop {
            let (v, t, e) = self.ok_to_exit.wait_timeout(Duration::from_secs(1));
            if t {
                debug!("cleanup: [caller: {caller}]: waiting for cleanup to complete...");
            }
            if e || v {
                break;
            }
        }
        debug!("cleanup: [caller: {caller}]: exits function");
    }

    fn cancel_token(&self) -> CancellationToken {
        self.cancel_token.clone()
    }
    pub fn was_killed(&self) -> bool {
        self.was_killed.load(Acquire)
    }
    pub fn set_killed(&self) {
        self.was_killed.store(true, Release);
    }

    pub async fn start_typhunix(&self) -> bool {
        TyphunixInstance::default()
            .start_joinset_verified(self.typhunix_tasks.clone())
            .await
    }
}

pub fn app_exit() {}
/// Trace execution tool for styx
#[derive(Debug, Subcommand, Clone)]
enum Command {
    /// Emulate a target using full web stack
    Emulate(CliEmulationArgs),
    /// Emulate a target using just typhunix
    EmulateMin(CliEmulationArgs),
    /// Gather emulation args from the YAML file
    FromYAML(FromYamlArgs),
    /// Start an emulation target (no analysis)
    Launch(CliEmulationArgs),
    /// post trace analysis
    Post(PostArgs),
    /// Trace a raw file
    Raw(InputFileArg),
    /// Trace an SRB file
    Srb(InputFileArg),
}

#[derive(Debug, Parser, Clone)]
pub struct AppArgs {
    /// sub command
    #[clap(subcommand)]
    command: Command,

    /// Regex pattern to match symbol names
    #[arg(short('r'), global(true), long, default_value_t=String::from("."))]
    regex: String,

    /// Optional args
    #[clap(flatten)]
    options: OptionalArgs,

    /// file path to output file. stdout if not specified
    #[arg(short('o'), global(true), long, required(false))]
    outpath: Option<String>,

    // Output format
    #[arg(long, global(true), default_value_t = OutputFormat::Builtin)]
    #[clap(value_enum)]
    output_format: OutputFormat,

    /// Options to (prematurely) stop emulation
    #[arg(long, global(true), allow_hyphen_values(true), value_parser=RawEventLimitsValueParser{})]
    pub raw_event_limits: Option<RawEventLimits>,

    /// Stop emulation after max_insn instructions
    #[arg(long, global(true), default_value_t = 0)]
    max_insn: u64,

    // Analyzer
    #[arg(short('a'),global(true), long, default_value_t = AnalysisType::Stats)]
    #[clap(value_enum)]
    analysis_type: AnalysisType,
}

impl AppArgs {
    /// Return the output destination based on the arguments: either a file or
    /// stdout.
    ///
    /// # Example:
    /// ```no_run
    /// fn example(args: &AnalysisArgs) {
    ///     let mut out = args.output().unwrap();
    ///     writeln!(out, "{}", serde_json::to_string(&mem).unwrap()).unwrap();
    /// }
    /// ```
    pub fn output(&self) -> Result<Box<dyn std::io::Write>, std::io::Error> {
        Ok(if let Some(ref outpath) = self.outpath {
            output_dst(OutDst::File(outpath))?
        } else {
            output_dst(OutDst::StdOut)?
        })
    }

    pub fn raw_event_limits(&self) -> RawEventLimits {
        if self.max_insn > 0 {
            RawEventLimits {
                max_insn: self.max_insn,
                ..Default::default()
            }
        } else {
            self.clone().raw_event_limits.unwrap_or_default()
        }
    }

    pub fn regex(&self) -> String {
        self.regex.clone()
    }
}

impl HasAnalysisOptions for AppArgs {
    fn show_fenter(&self) -> bool {
        self.options.show_fenter
    }

    fn show_fexit(&self) -> bool {
        self.options.show_fexit
    }

    fn output(&self) -> Result<Box<dyn std::io::Write>, std::io::Error> {
        self.output()
    }

    fn output_format(&self) -> OutputFormat {
        self.output_format.clone()
    }
}
#[derive(Debug, Args, Clone)]
struct InputFileArg {
    /// file path to input file
    #[arg(short('f'), long)]
    inpath: String,
}

#[derive(Debug, Args, Clone)]
struct PostArgs {
    /// Directory containing ptrace artifacts
    #[arg(short('d'), long)]
    directory_path: String,
}

#[derive(Debug, Args, Clone)]
struct FromYamlArgs {
    /// Use YAML as emulation args
    #[arg(short('y'), global(true), long, required(false))]
    yaml_file: Option<String>,
}

#[derive(Debug, Args, Clone)]
struct OptionalArgs {
    /// Instruction limit - stop after this many have been executed.
    #[arg(short('I'), long, global(true))]
    insn_limit: Option<u64>,
    /// display function enter
    #[arg(long("fenter"), global(true), default_value_t = false)]
    show_fenter: bool,
    /// display function exit
    #[arg(long("fexit"), global(true), default_value_t = false)]
    show_fexit: bool,
}

async fn get_program_identifier() -> Result<ProgramIdentifier, ApplicationError> {
    let pid = ghidra_program_id_from_env();
    if pid.is_none() {
        Err(ApplicationError::InvalidArgs(
            "No program identifier provided".into(),
        ))
    } else {
        let pid = pid.unwrap();
        let program = pid.get_program_name();
        let source_id = pid.get_source_id();
        Ok(ProgramIdentifier::new(&program, &source_id))
    }
}

async fn handle_signals(mut signals: Signals, cancel_token: CancellationToken, _args: AppArgs) {
    loop {
        if let Some(signal) = signals.next().await {
            if RESOURCES
                .signal_handler_executing
                .compare_exchange(false, true, AcqRel, Acquire)
                .is_ok()
            {
                RESOURCES.set_killed();
                let siginfo = match signal {
                    SIGHUP => format!("SIGHUP: {signal}"),
                    SIGTERM => format!("SIGTERM: {signal}"),
                    SIGINT => format!("SIGINT: {signal}"),
                    SIGQUIT => format!("SIGQUIT: {signal}"),
                    _ => format!("UNKNOWN-SIGNAL: {signal}"),
                };
                debug!("ptrace caught signal {siginfo}, cancel threads ...");
                cancel_token.cancel();
                debug!("ptrace: cancel_token.cancel(), token:{:?})", cancel_token);
                debug!("ptrace: wait 2 seconds");
                sleep(Duration::from_millis(2000)).await;
                break;
            }
        }

        if cancel_token.is_cancelled() {
            break;
        }
    }
    RESOURCES.signal_handler_executing.store(false, Release);
    RESOURCES.cleanup("handle_signals");
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    styx_emulator::core::util::logging::init_logging();
    let app_args = AppArgs::parse();
    let raw_event_limit_args = app_args.clone().raw_event_limits();
    let signals = Signals::new([SIGHUP, SIGTERM, SIGINT, SIGQUIT])?;
    let sig_handle = signals.handle();
    let cancel_token = RESOURCES.cancel_token();
    let signals_task = tokio::spawn(handle_signals(
        signals,
        cancel_token.clone(),
        app_args.clone(),
    ));

    match app_args.command {
        Command::FromYAML(ref args) => {
            if let Some(ref yaml_file) = args.yaml_file {
                let cli_emu_args = yaml_from_file(yaml_file).await?;
                match emulate_min(
                    &app_args.clone(),
                    &cli_emu_args,
                    &raw_event_limit_args,
                    cancel_token.clone(),
                )
                .await
                {
                    Err(e) => {
                        eprintln!("emulate min error: {e}");
                    }
                    _ => {
                        eprintln!("emulate min error: OK");
                    }
                }
            }
        }

        Command::EmulateMin(ref emu_args) => {
            match emulate_min(
                &app_args.clone(),
                emu_args,
                &raw_event_limit_args,
                cancel_token.clone(),
            )
            .await
            {
                Err(e) => {
                    eprintln!("emulate min error: {e}");
                }
                _ => {
                    eprintln!("emulate min error: OK");
                }
            }
        }

        Command::Launch(ref emu_args) => {
            match launch(
                &app_args.clone(),
                emu_args,
                &raw_event_limit_args,
                cancel_token.clone(),
            )
            .await
            {
                Err(e) => {
                    eprintln!("launch: error: {e}");
                }
                _ => {
                    eprintln!("launch: OK");
                }
            }
        }

        Command::Emulate(ref emu_args) => {
            match emulate_full(
                &app_args.clone(),
                emu_args,
                &raw_event_limit_args,
                cancel_token.clone(),
            )
            .await
            {
                Err(e) => {
                    eprintln!("launch: error: {e}");
                }
                _ => {
                    eprintln!("launch: OK");
                }
            }
        }

        Command::Raw(ref raw_args) => {
            let cancel_token = cancel_token.clone();

            match analyze_from_file(
                EventFileType::Raw,
                raw_args,
                &app_args.clone(),
                &raw_event_limit_args,
                cancel_token,
            )
            .await
            {
                Err(e) => {
                    eprintln!("analyze_from_file: error {e}")
                }
                _ => {
                    eprintln!("analyze_from_file: OK")
                }
            }
        }

        Command::Srb(ref infile) => {
            // from ring buffer
            let ct = cancel_token.clone();
            if let Err(e) = analyze_from_file(
                EventFileType::Srb,
                infile,
                &app_args,
                &raw_event_limit_args,
                ct,
            )
            .await
            {
                eprintln!("analyze_from_file error: {e}")
            }
        }

        Command::Post(ref post_args) => {
            post_analysis(&post_args.directory_path).await.unwrap();
        }
    }
    debug!("main: command is complete");
    if !cancel_token.is_cancelled() {
        cancel_token.cancel();
    }
    debug!("main: call cleanup...");
    RESOURCES.cleanup("main");
    debug!("main: close sig_handle...");
    sig_handle.close();
    debug!("main: wait on signals_task ...");
    signals_task.await?;
    Ok(())
}

enum EventFileType {
    Raw,
    Srb,
}

/// Analyze events in a RAW event file
async fn analyze_from_file(
    file_type: EventFileType,
    raw_args: &InputFileArg,
    args: &AppArgs,
    _: &RawEventLimits,
    cancel_token: CancellationToken,
) -> Result<(), Box<dyn Error>> {
    RESOURCES.start_typhunix().await;
    let observer = make_observer(&args.regex(), &args.raw_event_limits()).await?;
    match file_type {
        EventFileType::Raw => {
            let s = observer.event_stream_from_raw(&raw_args.inpath).unwrap();
            pin_mut!(s);
            args.analysis_type
                .analyze(&args.clone(), cancel_token.clone(), &mut s)
                .await;
        }
        EventFileType::Srb => {
            let s = observer
                .events_stream_from_srb(&raw_args.inpath, Duration::from_millis(100))
                .unwrap();
            pin_mut!(s);
            args.analysis_type
                .analyze(&args.clone(), cancel_token.clone(), &mut s)
                .await;
        }
    }

    debug!("finalize_observer...");
    finalize_observer(&observer);
    debug!("finalize_observer OK");
    // post(&observer.data_recorder.directory_root_path).await?;
    Ok(())
}

fn finalize_observer(o: &EmulationObserver) {
    info!("finalize_observer: dump variables ...");
    let dump_vars = true;
    let dump_overflows = true;
    let dump_callstack = true;
    let dump_memory = false;
    o.data_recorder
        .finalize(o, dump_vars, dump_overflows, dump_callstack, dump_memory);
    info!("finalize_observer: dump variables OK")
}

async fn make_observer(
    regex: &str,
    raw_event_limits: &RawEventLimits,
) -> Result<EmulationObserver, ApplicationError> {
    let pid = get_program_identifier().await?;
    let observer = EmulationObserver::new(
        pid,
        Some(*raw_event_limits),
        Some(0..(u32::MAX as u64)),
        None,
        &SymbolSearchOptions {
            regex_include: ".".into(),
            ..Default::default()
        },
    )
    .await
    .map_err(|e| {
        ApplicationError::InvalidRequest(format!("Error constructing EmulationObserver: {e}"))
    })?;

    observer.align_variables(regex, false);
    info!("Variables aligned:  {}", observer.variable_count());
    Ok(observer)
}

#[inline]
pub async fn emulate_min(
    app_args: &AppArgs,
    emu_args: &CliEmulationArgs,
    raw_event_limit_args: &RawEventLimits,
    cancel_token: CancellationToken,
) -> Result<(), Box<dyn Error>> {
    RESOURCES.start_typhunix().await;

    let svc_exec = SingleEmulationServiceExecutor::from_pbuf_emulation_args(emu_args.clone())?;
    let service_meta: ServiceMetadata = svc_exec.exec()?;
    let mut cli = SingleEmulationServiceClient::connect(service_meta.url()).await?;
    let processor_info = cli.info(Request::new(Empty::default())).await?.into_inner();
    let inpath = service_meta.trace_path.clone();
    eprintln!("{processor_info:?}");
    {
        RESOURCES.pids.lock()?.push(service_meta);
    }
    let request = StartSingleEmulationRequest::default();
    let resp = cli.start(Request::new(request)).await?.into_inner();
    let cancel_token = cancel_token.clone();
    if !resp.ok_or_warn() {
        eprintln!("Error: {:?}", resp.response_status,);
        std::process::exit(1);
    }
    let infile = InputFileArg { inpath };

    analyze_from_file(
        EventFileType::Srb,
        &infile,
        app_args,
        raw_event_limit_args,
        cancel_token,
    )
    .await?;

    info!("analyze_from_file (srb) finished");
    info!("emulate_min finished");
    Ok(())
}

#[inline]
pub async fn launch(
    _: &AppArgs,
    emu_args: &CliEmulationArgs,
    _: &RawEventLimits,
    cancel_token: CancellationToken,
) -> Result<(), Box<dyn Error>> {
    let svc_exec = SingleEmulationServiceExecutor::from_pbuf_emulation_args(emu_args.clone())?;
    let service_meta: ServiceMetadata = svc_exec.exec()?;
    let mut cli = SingleEmulationServiceClient::connect(service_meta.url()).await?;
    let processor_info = cli.info(Request::new(Empty::default())).await?.into_inner();
    // let inpath = service_meta.trace_path.clone();
    eprintln!("{processor_info:?}");
    {
        RESOURCES.pids.lock()?.push(service_meta);
    }
    let request = StartSingleEmulationRequest::default();
    let resp = cli.start(Request::new(request)).await?.into_inner();
    let cancel_token = cancel_token.clone();
    if !resp.ok_or_warn() {
        eprintln!("Error: {:?}", resp.response_status,);
        std::process::exit(1);
    }

    loop {
        match cli.info(Empty {}).await {
            Ok(_) => (),
            Err(e) => {
                eprintln!("{e}");
                break;
            }
        }
        if cancel_token.is_cancelled() {
            break;
        }
        sleep(Duration::from_millis(1000)).await;
    }

    Ok(())
}

#[inline]
async fn emulate_full(
    app_args: &AppArgs,
    emu_args: &CliEmulationArgs,
    raw_event_limits: &RawEventLimits,
    cancel_token: CancellationToken,
) -> Result<(), Box<dyn Error>> {
    let mut emulation_args: EmulationArgs = emu_args.clone().into();
    if emulation_args.trace_plugin_args.is_none() {
        emulation_args.trace_plugin_args = Some(TracePluginArgs {
            insn_event: true,
            write_memory_event: true,
            read_memory_event: true,
            interrupt_event: true,
            block_event: true,
        });
    }
    // fixme - relying on ENV in this case is error prone
    let pid = get_program_identifier().await?;
    let target = emu_args.target();

    let request = InitializeTraceRequest::new(TraceAppSessionArgs::new_emulated(
        Some(ProgramIdentifierArgs::new(&pid.name, &pid.source_id)),
        Some(emulation_args),
        Some(*raw_event_limits),
        Some(SymbolSearchOptions {
            regex_include: app_args.regex.clone(),
            regex_exclude: "".to_string(),
            mem_writes: true,
            mem_reads: false,
            anon_writes: false,
            anon_reads: false,
        }),
    ));
    let (tx, mut rx) = mpsc::channel(100);
    let (etx, mut erx) = mpsc::channel(100);
    let url = std::env::var("WEBAPI_URL")?;
    let url = url.clone();
    let spawn_url = url.clone();
    eprintln!("=> Starting {} ...", &emu_args.target().as_str_name());
    let ct = cancel_token.clone();
    let start_future = tokio::spawn(async move {
        traceapp_service::cli_util::start(&spawn_url, &request, 0, tx, etx, ct).await
    });
    // Wait to receive a session id
    let mut sid: Option<String> = None;
    let ct = cancel_token.clone();

    while sid.is_none() {
        if let Ok(Some(session_id)) = timeout(Duration::from_secs(1), rx.recv()).await {
            println!("SESSION_ID={session_id}");
            sid = Some(session_id.clone());
        }
        if start_future.is_finished() || ct.is_cancelled() {
            break;
        }
    }

    if let Some(session_id) = sid {
        println!("session_id: {session_id}");
        let streamer = EventRepeater::new(cancel_token.clone());
        let event_stream = streamer.events(&mut erx).await?;
        pin_mut!(event_stream);
        app_args
            .analysis_type
            .analyze(
                &app_args.to_owned(),
                cancel_token.clone(),
                &mut event_stream,
            )
            .await;
        // the event processing is complete, stop the, then cleanup
        match match_one_session(&url.clone(), &session_id).await {
            Ok(ref v) => match v.metadata()?.state() {
                styx_emulator::grpc::utils::EmulationState::Running => {
                    eprintln!("=> Stopping {} ...", target.as_str_name());
                    if let Err(e) = traceapp_service::cli_util::stop(&url.clone(), v).await {
                        eprintln!("Failed to stop traceapp session: {e}");
                    }
                    eprintln!("=> Dropping {} ...", target.as_str_name());
                    if let Err(e) = traceapp_service::cli_util::disconnect(&url.clone(), v).await {
                        eprintln!("Failed to drop traceapp session: {e}");
                    }
                }
                styx_emulator::grpc::utils::EmulationState::Stopped => {
                    eprintln!("=> Dropping {} ...", target.as_str_name());
                    if let Err(e) = traceapp_service::cli_util::disconnect(&url.clone(), v).await {
                        eprintln!("Failed to drop traceapp session: {e}");
                    }
                }
                _ => eprintln!("tracapp session in unexpected state: {v:?}"),
            },
            _ => eprintln!("Could not determine session id to stop/drop"),
        }
    }

    let result_string = match start_future.await? {
        Ok(result) => {
            format!("Start task result: (Ok) {result:?}")
        }
        Err(e) => {
            format!("Start task result: (Failed) {e:?}")
        }
    };
    println!("Result: {result_string}");
    Ok(())
}
