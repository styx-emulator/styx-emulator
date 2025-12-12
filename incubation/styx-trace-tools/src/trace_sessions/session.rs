// SPDX-License-Identifier: BSD-2-Clause

//! Session for TraceApp

use super::oob_pri_queue::OOBRequestQueue;
use crate::{
    emu_observer::EmulationObserver,
    event::{AggregateEvent, StreamEndReason},
    send_state_change, service_err,
};
use futures_core::Stream;
use std::{
    fmt::Display,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};
use styx_core::grpc::{
    args::{trace_app_session_args::TraceMode, RawEventLimits, SymbolSearchOptions},
    traceapp::{
        InitializeTraceRequest, InstLimitReached, SessionInfo, SessionStats,
        StartTraceAppSessionResponse,
    },
    typhunix_interop::symbolic::ProgramIdentifier,
    utils::EmuMetadata,
    workspace::TraceSessionState,
};
use styx_core::sync::sync::{
    atomic::Ordering::Relaxed,
    {Arc, Mutex},
};
use styx_core::util::dtutil::UtcDateTime;
use tokio::sync::mpsc::Sender;
use tokio_stream::StreamExt;
use tonic::Status;
use tracing::{debug, error, info, warn};

use super::{oob_pri_queue, session_mgr::TTL_SECONDS};

/// A session gets created for new requests.
pub struct Session {
    /// the session identifier, a stringified [uuid::Uuid] version 4
    id: String,
    /// session type
    mode: TraceMode,
    /// emulation observer
    emu: EmulationObserver,
    /// can the session be reaped?
    reap_ok: AtomicBool,
    /// session created
    pub created_time: UtcDateTime,
    /// last activity on session
    last_activity_time: Arc<Mutex<UtcDateTime>>,
    /// EmuMetadata for live emulations
    pub metadata: Option<EmuMetadata>,
    /// request queue for sessions that are busy running
    pub oob_requests: Arc<OOBRequestQueue>,
    /// session statistics
    pub stats: Arc<Mutex<SessionStats>>,
    /// SymbolSearchOptions
    pub symbol_search_options: SymbolSearchOptions,
}

/// trace emulation session
impl Session {
    /// create a new session, tied to the given [ProgramIdentifier]
    #[allow(clippy::too_many_arguments)]
    pub async fn new(
        session_id: &str,
        mode: TraceMode,
        symbol_search_options: &Option<SymbolSearchOptions>,
        raw_event_limits: &Option<RawEventLimits>,
        pid: ProgramIdentifier,
        metadata: Option<EmuMetadata>,
        oob_request_queue: Arc<OOBRequestQueue>,
    ) -> Result<Session, Status> {
        info!("Constructing session for pid: {}", pid);
        let symbol_search_options = symbol_search_options.clone().unwrap_or_default();
        let mem_range = if let Some(ref metadata) = metadata {
            let md = metadata.clone();
            md.processor_info
                .as_ref()
                .map(|processor_info| processor_info.memory_start..processor_info.memory_end)
        } else {
            None
        };

        let cs = EmulationObserver::new(
            pid,
            *raw_event_limits,
            mem_range,
            Some(&format!("/tmp/ptrace/{session_id}")),
            &symbol_search_options,
        )
        .await
        .map_err(|e| {
            let msg = format!("failed to constrcut EmulationObserver: {e}");
            debug!("{msg}");
            service_err(&msg)
        })?;

        // align variables with memory
        cs.align_variables(&symbol_search_options.regex_include, false);
        info!("watching {} variables", cs.variable_count());
        Ok(Session {
            mode,
            id: session_id.into(),
            emu: cs,
            reap_ok: AtomicBool::new(false),
            created_time: UtcDateTime::now(),
            last_activity_time: Arc::new(Mutex::new(UtcDateTime::now())),
            metadata,
            oob_requests: oob_request_queue.clone(),
            stats: Arc::new(Mutex::new(SessionStats::default())),
            symbol_search_options,
        })
    }

    pub fn oob_request_queue(&self) -> Arc<OOBRequestQueue> {
        self.oob_requests.clone()
    }

    pub fn check_status(&self) -> bool {
        if self.age() >= TTL_SECONDS {
            self.reap_ok.store(true, Relaxed);
        }
        self.reap_ok.load(Relaxed)
    }

    pub async fn snapshot(&self) {
        let dump_vars = true;
        let dump_overflows = true;
        let dump_callstack = true;
        let dump_memory = false;
        self.emu.data_recorder.finalize(
            &self.emu,
            dump_vars,
            dump_overflows,
            dump_callstack,
            dump_memory,
        );
    }

    #[inline]
    pub fn id(&self) -> String {
        self.id.to_string()
    }

    /// get seconds since last session activity [self.last_activity_time]
    pub fn age(&self) -> u64 {
        self.last_activity_time.lock().unwrap().elapsed_secs()
    }

    /// update last activity time to now
    pub fn set_last_active_time(&self) {
        UtcDateTime::now().clone_into(&mut self.last_activity_time.lock().unwrap());
    }

    /// Run the request, write results to the transmit channel
    pub async fn run_request(
        &self,
        tx: Sender<Result<StartTraceAppSessionResponse, tonic::Status>>,
        request: InitializeTraceRequest,
    ) -> Result<StreamEndReason, Status> {
        let args = request.args()?;
        debug!(
            "Session::run_request: mode: {:?}, file: {}",
            args.mode(),
            args.trace_filepath,
        );

        match args.mode() {
            TraceMode::Raw => {
                let events_stream = self
                    .emu
                    .event_stream_from_raw(&args.trace_filepath)
                    .map_err(|e| {
                        info!("event_stream_from_raw failed: {}", e);
                        self.set_last_active_time();
                        service_err(&e.to_string())
                    })?;
                let end_reason = self
                    .process_aggregate_events(events_stream, tx, request)
                    .await?;
                Ok(end_reason)
            }

            TraceMode::Emulated => {
                let events_stream = self
                    .emu
                    .events_stream_from_srb(&args.trace_filepath, Duration::from_millis(1000))
                    .map_err(|e| {
                        error!("events_stream_from_srb failed: {}", e);
                        self.set_last_active_time();
                        service_err(&e.to_string())
                    })?;

                let end_reason = self
                    .process_aggregate_events(events_stream, tx, request)
                    .await?;
                Ok(end_reason)
            }

            TraceMode::Srb => Err(service_err("Operation not supported")),
        }
    }

    /// Consume the stream of [AggregateEvent] events, write results to
    /// [StartTraceAppSessionResponse] stream.
    ///
    /// 1. Read [AggregateEvent]s, pack into response buffer, write to
    ///    the `tx` mpsc channel
    /// 2. Take appropriate action for _control type_ [AggregateEvent]s
    ///    (threshold limits, errors, timeouts, ...)
    /// 3. Monitor inbound (out-of-band) requests by checking `intr_requests`.
    ///    The _out-of-band_ requests are for things like `cancel`, `pause`,
    ///    `get-variable`, ...)
    /// 4. Provide efficient buffering and throttleing. (almost not at present).
    ///    Should do more buffering and throttling based on defaults and/or
    ///    parameters on the request.
    async fn process_aggregate_events(
        &self,
        input_stream: impl Stream<Item = AggregateEvent>,
        output_stream: Sender<Result<StartTraceAppSessionResponse, Status>>,
        request: InitializeTraceRequest,
    ) -> Result<StreamEndReason, Status> {
        debug!("process events ...");
        futures_util::pin_mut!(input_stream);
        let session_args = request.args()?;
        let start_instant = Instant::now();

        // todo - move threshold checking to `EmuObserver` and have it
        // check and yield threshold-reached events.
        let _limits = session_args.get_limits().unwrap_or_default();
        let mut _mem_wr_sent = 0;
        let mut _functions_sent = 0;
        let mut _isr_sent = 0;

        // macro to reduce code tedium and mistakes
        macro_rules! send_response {
            ($TX: ident, $S: expr_2021, $F: ident, $V:expr_2021) => {
                $TX.send(Ok(StartTraceAppSessionResponse {
                    session_id: $S,
                    $F: $V,
                    ..Default::default()
                }))
                .await
                .map_err(|e| send_err!(e, self))
            };
        }
        // macro to reduce code tedium and mistakes
        macro_rules! send_err {
            ($E: ident, $SELF: ident) => {{
                $SELF.set_last_active_time();
                return service_err(&$E.to_string());
            }};
        }

        let mut stats = *self.stats.lock().unwrap();
        let mut cum_inst_count = stats.insn_count;
        const INST_RATE: u64 = 100;
        debug!("In Stats: {:?}", self.stats.lock().unwrap());

        let mut end_reason = StreamEndReason::Unknown;
        while let Some(evt) = input_stream.next().await {
            if let Some(request) = self.oob_requests.pop() {
                match request {
                    oob_pri_queue::OOBRequest::Stop => {
                        debug!("process_event loop: OOBRequest::Stop");
                        end_reason = StreamEndReason::StopRequested;
                        let _ = self.oob_requests.drain();
                        send_state_change!(
                            output_stream,
                            &self.id(),
                            TraceSessionState::StopRequestReceived
                        );

                        break;
                    }
                    oob_pri_queue::OOBRequest::GetVariable => {
                        debug!("(todo) process_event loop: OOBRequest::GetVariable");
                    }
                    oob_pri_queue::OOBRequest::SetState(new_state) => {
                        warn!("(todo) process_event loop: State => {}", new_state);
                    }
                    oob_pri_queue::OOBRequest::GetState => {
                        info!("(todo) process_event loop: State => {}", self);
                    }
                }
            }

            match evt {
                AggregateEvent::Sentinal => (), // ignore sentinal
                AggregateEvent::Instruction(v) => {
                    cum_inst_count += 1;
                    if (cum_inst_count % INST_RATE) == 0 {
                        send_response!(output_stream, self.id(), instructions, vec![v])?;
                        stats.set_stats_values(
                            cum_inst_count,
                            Instant::now().duration_since(start_instant),
                        );
                        send_response!(output_stream, self.id(), cum_session_stats, Some(stats))?;
                    }
                }

                AggregateEvent::Memory(v) => {
                    send_response!(output_stream, self.id(), memory_writes, vec![*v])?;
                    _mem_wr_sent += 1;
                }

                AggregateEvent::Isr(v) => {
                    send_response!(output_stream, self.id(), interrupts, vec![v])?;
                    _isr_sent += 1;
                }
                AggregateEvent::NoMoreEvents(v) => {
                    send_response!(output_stream, self.id(), end_of_events, vec![v])?;
                    end_reason = StreamEndReason::EndOfEvents;
                    break;
                }
                AggregateEvent::Function(v) => {
                    send_response!(output_stream, self.id(), functions, vec![v])?;
                    _functions_sent += 1;
                }
                AggregateEvent::InsnLimitReached(n) => {
                    debug!("Event::InsnLimitReached({})", n);
                    send_response!(
                        output_stream,
                        self.id(),
                        insn_limit_reached,
                        Some(InstLimitReached { insn_num: n })
                    )?;
                    end_reason = StreamEndReason::InsnLimitReached;
                    break;
                }
                AggregateEvent::Block(v) => {
                    debug!("Block({})", v);
                    send_response!(output_stream, self.id(), basic_blocks, vec![v])?;
                }
                AggregateEvent::StopRequested => {
                    debug!("Event::StopRequested");
                    end_reason = StreamEndReason::StopRequested;
                    break;
                }
                AggregateEvent::RawTimeout(v) => {
                    debug!("RawTimeout({})", v);
                    send_response!(output_stream, self.id(), timeout, Some(v))?;
                }
                AggregateEvent::Error(e) => {
                    debug!("Event::Error({})", e);
                    end_reason = StreamEndReason::ErrorEvent;
                    break;
                }
            }
        }
        self.set_last_active_time();
        self.stats.lock().unwrap().merge_from(&stats);
        debug!("Out Stats: {:?}", self.stats.lock().unwrap());
        send_state_change!(output_stream, &self.id(), TraceSessionState::Stopping);
        Ok(end_reason)
    }

    #[inline]
    pub fn mode(&self) -> TraceMode {
        self.mode
    }
}

impl From<&Session> for SessionInfo {
    fn from(value: &Session) -> Self {
        Self {
            metadata: value.metadata.clone(),
            session_id: value.id(),
        }
    }
}

impl Display for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = String::new();
        s.push_str(&format!(
            "{} created: {}, last_activity: {} seconds ago",
            self.id(),
            self.created_time,
            self.age()
        ));
        write!(f, "{s}")
    }
}
