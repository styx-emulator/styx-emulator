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
//! Encapsulates `utils/utils.proto` messages, and supporting abstractions

tonic::include_proto!("utils");

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash)]
pub struct HashableToken(u64);

impl HashableToken {
    pub fn new(v: u64) -> HashableToken {
        HashableToken::from(Token { inner_token: v })
    }

    pub fn token(&self) -> u64 {
        self.0
    }
}

impl From<Token> for HashableToken {
    fn from(value: Token) -> Self {
        Self(value.inner_token)
    }
}

impl From<HashableToken> for Token {
    fn from(value: HashableToken) -> Self {
        Self {
            inner_token: value.token(),
        }
    }
}

impl std::fmt::Display for Token {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.inner_token)
    }
}

impl std::fmt::Display for HashableToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::fmt::Display for EmulationState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Error => write!(f, "Error"),
            Self::Creating => write!(f, "Creating"),
            Self::Created => write!(f, "Created"),
            Self::Initializing => write!(f, "Initializing"),
            Self::Initialized => write!(f, "Initialized"),
            Self::Starting => write!(f, "Starting"),
            Self::Running => write!(f, "Running"),
            Self::Paused => write!(f, "Paused"),
            Self::Stopping => write!(f, "Stopping"),
            Self::Stopped => write!(f, "Stopped"),
            Self::Finalizing => write!(f, "Finalizing"),
            Self::Killing => write!(f, "Killing"),
            Self::Dropped => write!(f, "Dropped"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

impl ResponseStatus {
    pub fn err(msg: &str, state: EmulationState) -> Self {
        Self {
            state: state.into(),
            message: msg.to_string(),
            result: response_status::Result::Err.into(),
        }
    }
    pub fn warn(msg: &str, state: EmulationState) -> Self {
        Self {
            state: state.into(),
            message: msg.to_string(),
            result: response_status::Result::Warn.into(),
        }
    }
    pub fn ok(msg: &str, state: EmulationState) -> Self {
        Self {
            state: state.into(),
            message: msg.to_string(),
            result: response_status::Result::Ok.into(),
        }
    }
    pub fn ok_resp(msg: &str, state: EmulationState) -> tonic::Response<ResponseStatus> {
        tonic::Response::new(ResponseStatus::ok(msg, state))
    }
    pub fn good(state: EmulationState) -> tonic::Response<ResponseStatus> {
        tonic::Response::new(ResponseStatus::ok("", state))
    }
    pub fn warn_resp(msg: &str, state: EmulationState) -> tonic::Response<ResponseStatus> {
        tonic::Response::new(ResponseStatus::warn(msg, state))
    }
    pub fn err_resp(msg: &str, state: EmulationState) -> tonic::Response<ResponseStatus> {
        tonic::Response::new(ResponseStatus::err(msg, state))
    }
    pub fn is_ok(&self) -> bool {
        match self.result() {
            response_status::Result::Ok | response_status::Result::Warn => true,
            response_status::Result::Err => false,
        }
    }
}

impl From<ResponseStatus> for tonic::Response<ResponseStatus> {
    fn from(value: ResponseStatus) -> Self {
        tonic::Response::new(value)
    }
}

impl From<ResponseStatus> for tonic::Status {
    fn from(val: ResponseStatus) -> Self {
        tonic::Status::new(tonic::Code::Unknown, val.message)
    }
}
