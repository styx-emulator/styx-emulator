// SPDX-License-Identifier: BSD-2-Clause

//! Priority Queue for managing out-of-bound (OOB) requests during a trace session's processing
//! loop.
//!
//! The [Session](super::session::Session) processing loop checkcks the queue
//! on each interation of the loop and will service the [OOBRequest] based on
//! its priority.

use std::{
    cmp::Ordering,
    collections::{BinaryHeap, HashMap},
};
use styx_core::grpc::utils::EmulationState;
use styx_core::sync::sync::{Arc, RwLock};
use tracing::info;

/// Manage a map of priority queues: [OOBRequestQueue] - one queue per
/// [Session](super::session::Session). The key to the map is
/// the session's `session_id`.
pub struct InboundOobRequests {
    map: Arc<RwLock<HashMap<String, Arc<OOBRequestQueue>>>>,
}

impl Default for InboundOobRequests {
    fn default() -> Self {
        Self {
            map: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl InboundOobRequests {
    /// Insert the [OOBRequestQueue] for the session_id
    pub fn init(&self, session_id: &str, oob_queue: Arc<OOBRequestQueue>) {
        self.map
            .write()
            .unwrap()
            .insert(session_id.to_string(), oob_queue);
    }

    /// Remove the [OOBRequestQueue] for the session_id
    pub fn remove(&self, session_id: &str) {
        self.map.write().unwrap().remove(session_id);
    }

    /// Insert the [OOBRequest] into the appropriate session - which will
    /// get processed in-band with event processing in the  `process_events` loop.
    ///
    /// Return `true` if the session exists (ie the request was inserted), `false` otherwise.
    pub fn insert(&self, session_id: &str, request_type: OOBRequest) -> bool {
        info!("insert_oob_request {}: {}", session_id, request_type);
        if let Some(item) = self.map.write().unwrap().get_mut(session_id) {
            item.push(request_type);
            true
        } else {
            false
        }
    }
}

impl std::fmt::Display for InboundOobRequests {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sessions = self
            .map
            .read()
            .unwrap()
            .iter()
            .map(|item| item.0.to_string())
            .collect::<Vec<String>>();
        write!(
            f,
            "InboundOobRequests({}): {}",
            sessions.len(),
            sessions.join(", ")
        )
    }
}

/// Request variants. Each variant has a priority determined by
/// [priority](OOBRequest::priority).
///
/// If variants have the same priority, resolution/tie break is FIFO
#[derive(Clone, Eq, PartialEq, Debug)]
pub enum OOBRequest {
    GetState,
    GetVariable,
    SetState(EmulationState),
    Stop,
}

impl std::fmt::Display for OOBRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::Stop => "Stop".to_string(),
            Self::SetState(s) => format!("StateChange({})", s.as_str_name()),
            Self::GetState => "GetState".to_string(),
            Self::GetVariable => "GetVariable".to_string(),
        };
        write!(f, "{s}")
    }
}

impl Ord for OOBRequest {
    fn cmp(&self, other: &Self) -> Ordering {
        other.priority().cmp(&self.priority())
    }
}

impl PartialOrd for OOBRequest {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.priority().cmp(&other.priority()))
    }
}

impl OOBRequest {
    /// Define priorities for each state. *Low numbers have higher priority*.
    pub fn priority(&self) -> usize {
        match self {
            // highest priority
            // ...
            Self::Stop => 10,
            Self::SetState(_) => 20,
            Self::GetState => 30,
            Self::GetVariable => 40,
            //...
            // lowest priority
        }
    }
}

#[derive(Default, Debug)]
/// A `BinaryHeap` of [OOBRequest] items. Implements priority queue semantics
/// based on the priority of the [OOBRequest].
pub struct OOBRequestQueue {
    queue: Arc<RwLock<BinaryHeap<OOBRequest>>>,
}

impl OOBRequestQueue {
    pub fn new(queue: Arc<RwLock<BinaryHeap<OOBRequest>>>) -> Self {
        Self { queue }
    }

    pub fn push(&self, request_type: OOBRequest) {
        self.queue.write().unwrap().push(request_type);
    }

    pub fn drain(&self) -> Vec<OOBRequest> {
        let mut results: Vec<OOBRequest> = Vec::with_capacity(self.len());
        while let Some(request) = self.pop() {
            results.push(request);
        }
        results
    }

    pub fn pop(&self) -> Option<OOBRequest> {
        self.queue.write().unwrap().pop()
    }

    pub fn peek(&self) -> Option<OOBRequest> {
        self.queue
            .read()
            .unwrap()
            .peek()
            .as_ref()
            .map(|request| <&OOBRequest>::clone(request).clone())
    }

    pub fn is_empty(&self) -> bool {
        self.queue.read().unwrap().is_empty()
    }

    pub fn len(&self) -> usize {
        self.queue.read().unwrap().len()
    }
}
