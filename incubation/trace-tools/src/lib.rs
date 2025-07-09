// SPDX-License-Identifier: BSD-2-Clause
//! # Tools and services for analyzing styx trace executions.
//!
//! Trace execution analysis is the interactive process of consuming raw styx
//! trace events and, based on those raw input events, doing some set of the following:
//!
//! - emitting aggregated events and statistics,
//! - creating and emitting visualizations
//! - providing the abiltiy to examine guest state (variables, instruction counters, registers, etc)
//!
//! ## Full Stack
//!
//! The full stack of running services for the webapp or ptrace to work end-to-end is:
//!
//! Process bin Name|Description
//! -|-
//! envoy                  | third party proxy server server to enable browser `gRPC` [https://envoyproxy.io](https://www.envoyproxy.io/)
//! typhunix-server        | [typhunix service](styx_core::grpc::typhunix_interop::typhunix_server::Typhunix) for symbols and datatypes
//! traceapp-svc       | [trace app session service](styx_core::grpc::traceapp::trace_app_session_service_server::TraceAppSessionService) for managing trace sessions
//! emuregsvc-svc| [trace execution service](styx_core::grpc::traceapp::trace_app_session_service_server::TraceAppSessionService)
//!
//! ## Webapp backend
//! webapp: angular frontend tool for running trace analysis sessions
//!
//! Name|Description
//! -|-
//! emuregsvc-svc            | starts `EmulationRegistryService` on default port 10101
//! traceapp-svc                   | starts `TraceAppSessionService` on default port 54321
//! emusvc-svc           | bin that launches SingleEmulationServce process on random port. \[2\]
//! typhunix-server                    | starts Typhunix service on default port 50051
//!
//! Notes:
//!
//! \[2\] Called at runtime from `EmulationRegistryService::initialize()`
//! ## Command-line tools
//!
//! Name|Description
//! -|-
//! ptrace          | cli frontend tool for running trace analysis sessions
//! styx-trace      | (utility) cli that launches a styx emulation (no services involved)
//! traceapp        | (utility) cli for calling TraceAppSessionService `gRPC`
//! trace-exec      | (utility) cli for calling EmulationRegistryService `gRPC`
//! emusvc-cli      | (utility) cli for calling SingleEmulationService `gRPC`
//! typhunix-client | (utility) cli for calling `Typhunix` `gRPC`
//! fsink           | (utility) cli that can consume `.srb` files and write to `.raw` trace event files
//! strace          | (utility) cli for viewing raw events

pub mod analyzers;
pub mod data_recorder;
pub mod emu_observer;
pub mod event;
pub mod identity;
pub mod post_analysis;
pub mod svcutil;
pub mod trace_sessions;
pub mod util;
pub mod variable;

use styx_core::sync::sync::{Arc, Condvar, Mutex};

/// convenience method to construct/return  a Grpc Status
pub fn service_err(msg: &str) -> tonic::Status {
    tonic::Status::new(tonic::Code::Unavailable, msg)
}

/// Return a string representation of the [u8] slice.
/// Very similiar to the `Debug` representation, except that it will collapse
/// sequences of zeros into a `\[0;count\]` format - but only if the size of the
/// slice is greater than 8.
///
/// # Returns
/// An Empty array string `[]` if the indicies are out of bounds
/// # Panic
/// - on array out of bounds
/// - (from > to) attempt to subtract with overflow
/// # Examples
/// ```rust
/// use styx_trace_tools::compact_repr;
/// let slice = &[0, 0, 0, 0, 0, 0, 0, 0, 1];
/// assert_eq!(compact_repr(slice, 0, 1), "[0]");
/// assert_eq!(compact_repr(slice, 0, slice.len()), "[0;8,1]");
/// assert_eq!(compact_repr(&vec![0; 256], 0, 256), "[0;256]");
/// // slice is unaltered if (len < 8)
/// assert_eq!(compact_repr(&[0xf, 0xa, 0x1, 0x0], 0, 4), "[f,a,1,0]");
/// assert_eq!(compact_repr(&[0, 0, 0, 0], 0, 4), "[0,0,0,0]");
/// ```
pub fn compact_repr(v: &[u8], from: usize, to: usize) -> String {
    let sz = to - from;
    if sz <= 8 {
        // No compaction
        format!(
            "[{}]",
            v[from..to]
                .to_vec()
                .iter()
                .map(|v| format!("{:x}", v))
                .collect::<Vec<String>>()
                .join(",")
        )
    } else {
        // compact
        let mut str_vec: Vec<String> = vec![];
        let mut span = 0;
        for val in &v[from..to] {
            if *val == 0 {
                span += 1;
            } else {
                if span > 0 {
                    if span == 1 {
                        str_vec.push("0".to_string());
                    } else {
                        str_vec.push(format!("0;{}", span));
                    }
                    span = 0;
                }
                str_vec.push(format!("{:x}", val));
            }
        }
        if span > 0 {
            str_vec.push(format!("0;{}", span));
        }

        format!(
            "[{}]",
            str_vec
                .iter()
                .map(|v| v.to_string())
                .collect::<Vec<String>>()
                .join(",")
        )
    }
}

#[derive(Debug)]
pub struct ConditionVar {
    pub pair: Arc<(Mutex<bool>, Condvar)>,
    pub pair_clone: Arc<(Mutex<bool>, Condvar)>,
}
impl ConditionVar {
    pub fn get_pair(&self) -> Arc<(Mutex<bool>, Condvar)> {
        Arc::clone(&self.pair_clone)
    }

    pub fn wait_timeout(&self, wait_timeout: std::time::Duration) -> (bool, bool, bool) {
        let (lock, cvar) = &*self.pair_clone;
        let flag = lock.lock().unwrap();
        match cvar.wait_timeout(flag, wait_timeout) {
            Ok(result) => (*result.0, result.1.timed_out(), false),
            Err(_) => (false, false, true),
        }
    }
}

impl Default for ConditionVar {
    fn default() -> Self {
        let v = Arc::new((Mutex::new(false), Condvar::new()));
        let v2 = Arc::clone(&v);
        Self {
            pair: v,
            pair_clone: v2,
        }
    }
}

#[macro_export]
macro_rules! send_state_change {
    ($Tx: expr, $Sid: expr, $New: expr) => {{
        $Tx.send(Ok(StartTraceAppSessionResponse {
            session_id: $Sid.to_string(),
            // must be fully qualified as this is in a macro
            state_change: Some(::styx_core::grpc::traceapp::TraceSessionStateChange {
                state: $New.into(),
            }),
            ..Default::default()
        }))
        .await
        .map_err(|e| $crate::service_err(&e.to_string()))?;
    }};
}

#[cfg(test)]
mod tests {
    use crate::ConditionVar;
    use std::thread;
    use std::thread::JoinHandle;
    use std::time::Duration;
    use test_case::test_case;

    use super::Arc;
    pub fn spawn_delayed(cv: Arc<ConditionVar>, delay: Duration, notify_count: Option<usize>) {
        let pair_clone = cv.get_pair();
        thread::spawn(move || {
            std::thread::sleep(delay);
            let (cndmtx, cvar) = &*pair_clone;
            let mut var = cndmtx.lock().unwrap();
            *var = true;
            match notify_count {
                None => cvar.notify_all(),
                Some(n) => {
                    for _ in 0..n {
                        cvar.notify_one();
                    }
                }
            }
        });
    }

    #[test_case(0,   100, 1, 1,0, Some(1) ; "ok no timeout")]
    #[test_case(250, 100, 1, 0,1, None    ; "timeout")]
    #[test_case(0,   200, 5, 5,4, Some(1) ; "ok 4 timeouts")]
    #[test_case(0,   200, 5, 5,5, Some(0) ; "ok 5 timeouts")]
    #[cfg_attr(miri, ignore)]
    fn test_condition_var_pass_all(
        delay_ms: u64,
        tmout_ms: u64,
        nthreads: usize,
        expected_ok: usize,
        expected_timeout: usize,
        notify_count: Option<usize>,
    ) {
        let my_cvar = super::ConditionVar::default();
        let arc_my_cvar = Arc::new(my_cvar);
        let clones: Vec<Arc<ConditionVar>> = vec![arc_my_cvar.clone(); nthreads];
        // let mut handles: Vec<JoinHandle<(bool, bool, bool)>> = vec![];
        let handles = clones
            .iter()
            .map(|i| {
                let aa = i.clone();
                thread::spawn(move || aa.wait_timeout(Duration::from_millis(tmout_ms)))
            })
            .collect::<Vec<JoinHandle<(bool, bool, bool)>>>();
        assert_eq!(handles.len(), nthreads);
        spawn_delayed(arc_my_cvar, Duration::from_millis(delay_ms), notify_count);
        let mut ok = 0;
        let mut tmout = 0;
        let mut err = 0;
        for h in handles {
            let (v, t, e) = h.join().unwrap();
            if e {
                err += 1;
            }
            if t {
                tmout += 1;
            }
            if v {
                ok += 1;
            }
        }
        eprintln!("OK:      {} {}", ok, expected_ok);
        assert_eq!(ok, expected_ok);
        eprintln!("TIMEOUT: {} {}", tmout, expected_timeout);
        assert_eq!(tmout, expected_timeout);
        eprintln!("ERR:     {} {}", err, 0);
        assert_eq!(err, 0);
    }
}
