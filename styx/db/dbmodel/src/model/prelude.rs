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
// trace_app_session_args::TraceAppSessionArgs

pub use crate::DBIdType;

pub use super::trace_app_session_args::{
    ActiveModel as TraceAppSessionArgsActiveModel, Entity as TraceAppSessionArgsEntity,
    Model as TraceAppSessionArgsModel,
};
pub use styx_core::grpc::args::TraceAppSessionArgs as TraceAppSessionArgsMsg;
pub use styx_core::grpc::args::TraceAppSessionArgs;

// emulation_args::EmulationArgs
pub use super::emulation_args::{
    ActiveModel as EmulationArgsActiveModel, Entity as EmulationArgsEntity,
    Model as EmulationArgsModel,
};
pub use styx_core::grpc::args::EmulationArgs as EmulationArgsMsg;
pub use styx_core::grpc::args::EmulationArgs;

// raw_event_limits::RawEventLimits
pub use super::raw_event_limits::{
    ActiveModel as RawEventLimitsActiveModel, Entity as RawEventLimitsEntity,
    Model as RawEventLimitsModel,
};
pub use styx_core::grpc::args::RawEventLimits as RawEventLimitsMsg;
pub use styx_core::grpc::args::RawEventLimits;

// trace_mode::TraceMode
pub use super::trace_mode::{
    ActiveModel as TraceModeActiveModel, Entity as TraceModeEntity, Model as TraceModeModel,
};
pub use styx_core::grpc::args::trace_app_session_args::TraceMode as TraceModeMsg;
pub use styx_core::grpc::args::trace_app_session_args::TraceMode;

// TraceSessionState
pub use super::trace_session_state::{
    ActiveModel as TraceSessionStateActiveModel, Entity as TraceSessionStateEntity,
    Model as TraceSessionStateModel,
};
pub use styx_core::grpc::workspace::TraceSessionState;

// workspace::Workspace
pub use super::workspace::{
    ActiveModel as WorkspaceActiveModel, Entity as WorkspaceEntity, Model as WorkspaceModel,
};
pub use styx_core::grpc::workspace::Workspace as WorkspaceMsg;
pub use styx_core::grpc::workspace::Workspace;

pub use super::trace_session::{
    ActiveModel as TraceSessionActiveModel, Entity as TraceSessionEntity,
    Model as TraceSessionModel,
};
pub use styx_core::grpc::workspace::TraceSession as TraceSessionMsg;
pub use styx_core::grpc::workspace::TraceSession;

// WsProgram
pub use super::program::{
    ActiveModel as WsProgramActiveModel, Entity as WsProgramEntity, Model as WsProgramModel,
};
pub use styx_core::grpc::workspace::WsProgram;

// TraceEvent
pub use super::trace_event::{
    ActiveModel as TraceEventActiveModel, Entity as TraceEventEntity, Model as TraceEventModel,
};
