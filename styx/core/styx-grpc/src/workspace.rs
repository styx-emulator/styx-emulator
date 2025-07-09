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
//! Encapsulates `args/args.proto` messages, services, and supporting abstractions

tonic::include_proto!("workspace");
pub use super::args::*;
pub use super::db::*;
pub use super::emulation_registry::*;
pub use super::symbolic::*;
pub use super::utils::*;

pub use prost_wkt_types::Timestamp;
use styx_util::dtutil::UtcDateTime;
use thiserror::Error;

impl TraceAppSessRequest {
    pub fn trace_app_sessions(&self) -> &Vec<TraceAppSessionArgs> {
        &self.trace_app_session_args
    }
}
#[derive(Debug, Error)]
pub enum InvalidMessageError {
    #[error("Expected non-null field `{0}`")]
    MissingField(&'static str),
}

impl TraceSession {
    pub fn new(id: i32, session_id: &str, state: &str) -> Self {
        Self {
            timestamp: Some(UtcDateTime::now().into_inner().into()),
            id,
            session_id: session_id.to_string(),
            state: state.to_string(),
            ts_state: TraceSessionState::default().into(),
            metadata: None,
        }
    }

    pub fn timestamp(&self) -> Result<UtcDateTime, InvalidMessageError> {
        match self.timestamp {
            Some(ref t) => Ok((*t).into()),
            None => Err(InvalidMessageError::MissingField("timestamp")),
        }
    }
}

impl Workspace {
    pub fn created_timestamp_or_now(&self) -> prost_wkt_types::Timestamp {
        match self.created_timestamp {
            Some(ref t) => *t,
            None => UtcDateTime::now().into_inner().into(),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use log::debug;

    #[test]
    fn test_timestamp() -> Result<(), Box<dyn std::error::Error + 'static>> {
        styx_util::logging::init_logging();
        let session = TraceSession::new(0, "session_id", "state");
        let ts = session.timestamp()?;
        assert!(!ts.local_string().is_empty());
        debug!("{}", ts.utc_string());
        debug!("{}", ts.local_string());
        debug!("{}", &ts.local_string()[0..19].to_string());

        debug!("\n=============================================================\n");
        Ok(())
    }
}
