// SPDX-License-Identifier: BSD-2-Clause

// TODO update tonic when available https://github.com/hyperium/tonic/issues/2253
#![allow(clippy::result_large_err)]

//! SessionManager for TraceApp

use super::{oob_pri_queue::InboundOobRequests, session::Session};
use crate::service_err;
use std::{
    collections::{HashMap, HashSet},
    sync::RwLock,
    time::Duration,
};
use styx_core::grpc::{
    args::{trace_app_session_args::TraceMode, TraceAppSessionArgs},
    traceapp::SessionInfo,
    utils::{EmuMetadata, EmulationState, Token},
    workspace::{TraceSession, TraceSessionState},
};
use styx_core::sync::sync::{Arc, Mutex};
use styx_core::util::traits::HasUrl;
use tokio::time::sleep;
use tracing::{debug, error, info, warn};
use workspace_service::cli_util as ws_svc_cli;

/// Session reaper check interval
pub const NAPTIME_SECONDS: u64 = 1;
/// Session time to live with no activity
pub const TTL_SECONDS: u64 = 60 * 5; // 5 mins with no activity
/// Session reaper: debug! log sessions interval (ie every 30 cycles)
pub const DEBUG_INTERVAL: u64 = 30;

/// Manage the running and idle [Session]
/// - `idle_sessions` are not running (stopped, paused, failed, complete, ...)
///
/// - `running_sessions` are actively running and processing in a tight loop,
///   receiving  [TraceableItem](styx_core::tracebus::TraceableItem) events and
///   emitting [AggregateEvent](crate::event::AggregateEvent).
///
/// - `inbound_oob_requests` is a map of session_id to a priority queue to_owned
///   by the [Session]. This is a way to interrupt the event processing loop
///   for requests such as [OOBRequest](super::oob_pri_queue::OOBRequest).
///
pub struct SessionManager {
    /// A map of session_id to [Session] for sessions that are idle (not running)
    idle_sessions: Arc<Mutex<HashMap<String, Session>>>,

    /// A map of session_id to [SessionInfo] for sessions that are Running.
    ///
    /// This provides access to a subset of the information in [Session],
    /// with out having to clone the session
    running_sessions: Arc<Mutex<HashMap<String, SessionInfo>>>,

    /// A set of session IDs for running sessions (if its in the set, its running)
    running: Arc<RwLock<HashSet<String>>>,

    /// inbound oob requests for operations on running sessions. The sessions
    /// are running in a tight processing loop
    pub inbound_oob_requests: InboundOobRequests,
}
macro_rules! pdebug {
    ($prefix:expr_2021, $msg:expr_2021, $($arg:tt)*) => {
        debug!("{}: {}: {}", $prefix, $msg, format!("{}", $($arg)*));
    }
}

macro_rules! pinfo {
    ($prefix:expr_2021, $msg:expr_2021, $($arg:tt)*) => {
        info!("{}: {}: {}", $prefix, $msg, format!("{}", $($arg)*));
    }
}

impl SessionManager {
    pub fn new(sessions: Arc<Mutex<HashMap<String, Session>>>) -> Self {
        Self {
            idle_sessions: sessions,
            running: Arc::new(RwLock::new(HashSet::new())),
            running_sessions: Arc::new(Mutex::new(HashMap::new())),
            inbound_oob_requests: InboundOobRequests::default(),
        }
    }

    pub fn new_id() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    pub fn add_running(&self, session_id: &str) {
        let msg = format!("Running: {:?}", self.running.read().unwrap());
        pdebug!("add_running", session_id, msg);
        self.running.write().unwrap().insert(session_id.to_string());
        let msg = format!("Running: {:?}", self.running.read().unwrap());
        pdebug!("add_running", session_id, msg);
    }

    pub fn remove_running(&self, session_id: &String) -> bool {
        pinfo!("remove_running", session_id, "Remove running session");
        self.running.write().unwrap().remove(session_id)
    }

    pub fn is_running(&self, session_id: &String) -> bool {
        self.running.read().unwrap().contains(session_id)
    }

    pub fn set_state(&self, session_id: &String, state: EmulationState) {
        let mut updated = false;
        // Running sessions
        let arc_running = self.running_sessions();
        let mut running_sessions = arc_running.lock().unwrap();
        if let Some(session) = running_sessions.get_mut(session_id) {
            if let Some(md) = &mut session.metadata {
                pdebug!(
                    "set_state",
                    session_id,
                    format!("set_state: (on running) {} {}", session_id, state)
                );
                updated = true;
                md.state = state.into();
            }
        }
        // Idle sessions
        let arc_idle = self.idle_sessions();
        let mut idle_sessions = arc_idle.lock().unwrap();
        if let Some(session) = idle_sessions.get_mut(session_id) {
            if let Some(md) = &mut session.metadata {
                pdebug!(
                    "set_state",
                    session_id,
                    format!("set_state: (on idle) {} {}", session_id, state)
                );
                updated = true;
                md.state = state.into();
            }
        }
        if !updated {
            warn!(
                "set_state: {} no session or metadata state: {}",
                session_id, state
            );
        }
    }

    pub async fn reaper_task(&self) {
        let mut cycle_count: u64 = 0;
        loop {
            sleep(Duration::from_secs(NAPTIME_SECONDS)).await;
            cycle_count += 1;
            let mut session_string: Vec<String> = vec![];
            let mut kill_list: Vec<String> = vec![];
            for (_, session) in self.idle_sessions.lock().unwrap().iter() {
                session_string.push(session.to_string());
                if session.check_status() {
                    kill_list.push(session.id());
                }
            }
            // Debug log the session list
            if (cycle_count % DEBUG_INTERVAL) == 0 && !session_string.is_empty() {
                pinfo!(
                    "reaper_task",
                    "",
                    format!(
                        "Session count: {}",
                        self.idle_sessions.lock().unwrap().len()
                    )
                );
                let _ = session_string.iter().map(|s| debug!("  - {}", s)).count();
            }
            // Remove the expired sessions
            for k in kill_list.iter() {
                if let Some(s) = self.idle_sessions.lock().unwrap().remove(k) {
                    info!("Reaped session {}", s.id());
                }
            }
        }
    }

    /// return an reference to the sessions
    pub fn idle_sessions(&self) -> Arc<Mutex<HashMap<String, Session>>> {
        self.idle_sessions.clone()
    }

    /// return an reference to the running sessions
    pub fn running_sessions(&self) -> Arc<Mutex<HashMap<String, SessionInfo>>> {
        self.running_sessions.clone()
    }

    pub fn mode_or_err(&self, session_id: &String) -> Result<TraceMode, tonic::Status> {
        let sessions = self.idle_sessions.lock().unwrap();
        if let Some(session) = sessions.get(session_id) {
            Ok(session.mode())
        } else {
            Err(service_err(&format!("No session: {session_id}")))
        }
    }

    pub fn session_id_or_err(&self, session_id: &String) -> Result<String, tonic::Status> {
        let sessions = self.idle_sessions.lock().unwrap();
        if let Some(session) = sessions.get(session_id) {
            Ok(session.id())
        } else {
            Err(service_err(&format!("No session: {session_id}")))
        }
    }

    pub fn token_or_err(&self, session_id: &String) -> Result<Token, tonic::Status> {
        let session_id = self.session_id_or_err(session_id)?;
        if let Some(token) = self.get_token(&session_id) {
            Ok(token)
        } else {
            Err(service_err(&format!("No token for session: {session_id}")))
        }
    }

    pub fn has_session(&self, session_id: &String) -> bool {
        self.idle_sessions.lock().unwrap().contains_key(session_id)
    }

    pub fn get_token(&self, session_id: &String) -> Option<Token> {
        let sessions = self.idle_sessions();
        let md: Option<EmuMetadata> = if let Some(sn) = sessions.lock().unwrap().get(session_id) {
            sn.metadata.clone()
        } else {
            None
        };

        if let Some(mm) = md {
            Some(mm.token.unwrap())
        } else {
            None
        }
    }

    pub async fn debug_session_lists(&self) {
        macro_rules! dbg_map {
            ($Prefix:expr_2021, $Var: expr_2021) => {
                let _s = $Var
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|item| item.0.to_string())
                    .collect::<Vec<String>>();
                dbg_str_vec!($Prefix, _s)
            };
        }
        macro_rules! dbg_str_vec {
            ($Prefix:expr_2021, $Vec:expr_2021) => {
                debug!("{}({}): {}", $Prefix, $Vec.len(), $Vec.join(", "))
            };
        }
        dbg_map!("Idle Sessions", self.idle_sessions);
        dbg_map!("Running Sessions", self.running_sessions);

        #[rustfmt::skip]
        let running_set = self.running.read().unwrap().iter()
            .map(|item| item.to_string()).collect::<Vec<String>>();
        dbg_str_vec!("Running Set", running_set);
        debug!("{}", self.inbound_oob_requests);
    }

    /// Move the session from the idle session list to the running session list
    #[inline]
    pub fn checkout(&self, session_id: &str) -> Session {
        let session = self
            .idle_sessions
            .lock()
            .unwrap()
            .remove(session_id)
            .unwrap();
        let si: SessionInfo = SessionInfo::from(&session);
        self.running_sessions
            .lock()
            .unwrap()
            .insert(si.session_id.clone(), si);
        session.set_last_active_time();
        session
    }

    /// Move the session from the running session list to the idle session list
    #[inline]
    pub fn checkin(&self, mut session: Session, reason_str: &str) {
        let session_id = session.id();
        session.set_last_active_time();
        pdebug!("checkin", session_id, format!("reason: {reason_str}"));

        self.remove_running(&session_id);
        // update state from running session...
        if let Some(session_info) = self.running_sessions().lock().unwrap().remove(&session_id) {
            if let Some(rmd) = session_info.metadata {
                pdebug!(
                    "checkin",
                    session_id,
                    format!("from sessions running map {:?}", rmd.state())
                );
                if let Some(ref mut md) = session.metadata {
                    pdebug!(
                        "checkin",
                        session_id,
                        format!("from metadata: {:?}", md.state())
                    );
                    md.state = rmd.state;
                }
            }
        }

        self.idle_sessions
            .lock()
            .unwrap()
            .insert(session.id(), session);
        debug!("checkin: {}: OK.", session_id);
    }
}

#[derive(Clone, Debug, Default)]
pub struct TraceSessionSync {
    args: Arc<Mutex<TraceAppSessionArgs>>,
    session: Arc<Mutex<TraceSession>>,
    url: String,
}

impl HasUrl for TraceSessionSync {
    fn url(&self) -> String {
        self.url.to_string()
    }
}

impl TraceSessionSync {
    pub fn new(args: &TraceAppSessionArgs, session: &TraceSession) -> Self {
        Self {
            args: Arc::new(Mutex::new(args.clone())),
            session: Arc::new(Mutex::new(session.clone())),
            url: std::env::var("WORKSPACE_URL").unwrap_or("http://localhost:55555".to_string()),
        }
    }

    pub async fn upsert(&self) -> Result<(), tonic::Status> {
        let (mut args, session) = {
            (
                self.args.lock().unwrap().clone(),
                self.session.lock().unwrap().clone(),
            )
        };
        args.session_id = session.session_id.to_string();
        pinfo!("TraceSessionSync:upsert", session.session_id, "");
        let Some(trace_session) = ws_svc_cli::upsert_trace_session(&self.url(), &args, &session)
            .await
            .map_err(|e| {
                error!(
                    "TraceSessionSync:upsert: Failed to create TraceSession: {}: {e}",
                    self.url()
                );
                service_err(&format!(
                    "Could not upsert session_id: {}:  {e}",
                    self.url()
                ))
            })?
            .session
        else {
            return Err(service_err("Failed to save TraceSession"));
        };
        self.args.lock().unwrap().clone_from(&args);
        self.session.lock().unwrap().clone_from(&trace_session);
        Ok(())
    }

    pub async fn update_state(
        &self,
        state: &str,
        ts_state: TraceSessionState,
    ) -> Result<(), tonic::Status> {
        let (args, mut session) = {
            (
                self.args.lock().unwrap().clone(),
                self.session.lock().unwrap().clone(),
            )
        };
        session.state = state.into();
        session.ts_state = ts_state.into();
        self.args.lock().unwrap().clone_from(&args);
        self.session.lock().unwrap().clone_from(&session);
        self.upsert().await?;
        Ok(())
    }
}
