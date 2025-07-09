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

/// DEFAULT_IPC_PORT is the default port to communicator with emulation
/// peripherals.
pub const DEFAULT_IPC_PORT: u16 = 16000;

tonic::include_proto!("args");

use self::trace_app_session_args::TraceMode;
pub use super::emulation_registry::SupportedConfig;
use crate::{ToArgVec, Validator};
use clap::{Parser, ValueEnum};
use regex::{RegexSet, RegexSetBuilder};
use styx_errors::styx_grpc::ApplicationError;

impl Validator for EmulationArgs {
    fn is_valid(&self) -> bool {
        !self.firmware_path.is_empty()
    }
}

pub trait AppDefault {
    /// A default that is more akin to a _reasonable_ application default than
    /// a derived default based on individual field results.
    fn app_default() -> Self;
}

impl TraceAppSessionArgs {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        mode: TraceMode,
        session_id: &str,
        resume: bool,
        pid: Option<ProgramIdentifierArgs>,
        trace_filepath: &str,
        raw_trace_args: Option<RawTraceArgs>,
        emulation_args: Option<EmulationArgs>,
        raw_event_limits: Option<RawEventLimits>,
        symbol_options: Option<SymbolSearchOptions>,
    ) -> Self {
        Self {
            id: 0,
            mode: mode.into(),
            session_id: session_id.to_string(),
            resume,
            pid,
            trace_filepath: trace_filepath.to_string(),
            raw_trace_args,
            emulation_args,
            limits: raw_event_limits,
            symbol_options,
            ws_program_id: 0,
        }
    }

    pub fn new_emulated(
        pid: Option<ProgramIdentifierArgs>,
        emulation_args: Option<EmulationArgs>,
        raw_event_limits: Option<RawEventLimits>,
        symbol_options: Option<SymbolSearchOptions>,
    ) -> Self {
        Self {
            id: 0,
            mode: TraceMode::Emulated.into(),
            session_id: "".into(),
            resume: false,
            pid,
            trace_filepath: "".into(),
            raw_trace_args: None,
            emulation_args,
            limits: raw_event_limits,
            symbol_options,
            ws_program_id: 0,
        }
    }

    #[inline]
    pub fn check_max_insn(&self, n: u64) -> bool {
        if let Some(ref limits) = self.limits {
            n >= limits.max_insn
        } else {
            false
        }
    }

    #[inline]
    pub fn check_max_mem_read_events(&self, n: u64) -> bool {
        if let Some(ref limits) = self.limits {
            n >= limits.max_mem_read_events
        } else {
            false
        }
    }

    /// Return a clone of [ProgramIdentifierArgs] an error.
    pub fn pid_args(&self) -> Result<ProgramIdentifierArgs, ApplicationError> {
        if let Some(pid_args) = &self.pid {
            Ok(pid_args.clone())
        } else {
            Err(ApplicationError::MissingRequiredArgs("pid".into()))
        }
    }
}

impl ToArgVec for Target {
    fn arg_vec(&self) -> Vec<String> {
        vec![
            "--target".into(),
            self.to_possible_value().unwrap().get_name().to_string(),
        ]
    }
}

impl ToArgVec for EmuRunLimits {
    fn arg_vec(&self) -> Vec<String> {
        vec![
            "--emu-max-insn".into(),
            self.emu_max_insn.to_string(),
            "--emu-seconds".into(),
            self.emu_seconds.to_string(),
        ]
    }
}

impl ToArgVec for TracePluginArgs {
    fn arg_vec(&self) -> Vec<String> {
        let mut args: Vec<String> = vec![];
        if self.insn_event {
            args.push("--insn-event".into());
        }
        if self.interrupt_event {
            args.push("--interrupt-event".into());
        }
        if self.write_memory_event {
            args.push("--write-memory-event".into());
        }
        if self.read_memory_event {
            args.push("--read-memory-event".into());
        }
        if self.block_event {
            args.push("--block-event".into());
        }
        args
    }
}

impl ToArgVec for RawLoaderArgs {
    fn arg_vec(&self) -> Vec<String> {
        vec![
            "--base-addr".into(),
            self.base_addr.to_string(),
            "--valid-range-min".into(),
            self.valid_range_min.to_string(),
            "--valid-range-max".into(),
            self.valid_range_max.to_string(),
        ]
    }
}

#[derive(clap::ValueEnum, Clone, Debug, serde::Deserialize, serde::Serialize, Default)]
pub enum EmulationLevel {
    #[default]
    Machine,
    Processor,
    Cpu,
}

impl std::fmt::Display for EmulationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Processor => "processor",
                Self::Machine => "machine",
                Self::Cpu => "cpu",
            }
        )
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default)]
pub struct GhidraProgramRef {
    pub source_id: String,
    pub program: String,
}
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default)]
pub struct GhidrProgramArchRef {
    pub processor: String,
    pub variant: String,
    pub bits: u8,
    pub loader: String,
    pub endian: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default)]
pub struct StyxProcessorRef {
    pub cpu: String,
    pub variant: String,
    pub endian: String,
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug, Default)]
pub struct ProcessorMetadataItem {
    pub ghidra_pid: GhidraProgramRef,
    pub ghidra_arch: GhidrProgramArchRef,
    pub styx_processor: StyxProcessorRef,
    pub firmwares: Vec<String>,
}

pub trait HasTarget {
    fn target(&self) -> Target;
}

pub trait HasEmulationOptArgs {
    fn firmware_path(&self) -> String;
    fn ipc_port(&self) -> Option<u16>;
}

pub trait HasTracePluginArgs {
    /// get cloned value of trace_plugin_args
    fn trace_plugin_args(&self) -> Option<TracePluginArgs>;
    /// get cloned value of trace_plugin_args or a default [TracePluginArgs]
    /// if trace_plugin_args.is_none()
    fn trace_plugin_args_or_default(&self) -> TracePluginArgs;
    /// return true if trace_plugin_args.is_some(), false otherwise
    fn has_trace_plugin_args(&self) -> bool;
    /// Return trace_plugin_args or an error. Call this when the ergs are expected
    /// to be present
    fn expect_trace_plugin_args(&self) -> Result<TracePluginArgs, ApplicationError>;
}

impl AppDefault for TracePluginArgs {
    fn app_default() -> Self {
        // reasonable default for TracePluginArgs
        TracePluginArgs {
            insn_event: true,
            interrupt_event: true,
            read_memory_event: false,
            write_memory_event: true,
            block_event: true,
        }
    }
}

pub trait HasEmuRunLimits {
    fn emu_run_limits(&self) -> EmuRunLimits;
    fn has_emu_run_limits(&self) -> bool;
}

pub trait HasRawLoaderArgs {
    fn raw_loader_args(&self) -> RawLoaderArgs;
    fn has_raw_loader_args(&self) -> bool;
}

pub trait HasEmulationArgs:
    HasTarget + HasEmulationOptArgs + HasTracePluginArgs + HasEmuRunLimits + HasRawLoaderArgs
{
    fn as_emulation_args(&self) -> EmulationArgs;
}

impl HasEmulationArgs for EmulationArgs {
    fn as_emulation_args(&self) -> EmulationArgs {
        self.clone()
    }
}
impl HasTarget for EmulationArgs {
    fn target(&self) -> Target {
        self.target()
    }
}

impl HasEmulationOptArgs for EmulationArgs {
    fn firmware_path(&self) -> String {
        self.firmware_path.clone()
    }

    fn ipc_port(&self) -> Option<u16> {
        if self.ipc_port < 0 {
            None
        } else {
            Some(self.ipc_port as u16)
        }
    }
}

impl HasTracePluginArgs for EmulationArgs {
    fn trace_plugin_args_or_default(&self) -> TracePluginArgs {
        self.trace_plugin_args.unwrap_or_default()
    }

    fn trace_plugin_args(&self) -> Option<TracePluginArgs> {
        self.trace_plugin_args
    }

    fn has_trace_plugin_args(&self) -> bool {
        self.trace_plugin_args.is_some()
    }

    fn expect_trace_plugin_args(&self) -> Result<TracePluginArgs, ApplicationError> {
        if let Some(args) = &self.trace_plugin_args {
            Ok(*args)
        } else {
            Err(ApplicationError::MissingRequiredArgs(
                "emulation_args: expected trace_plugin_args".into(),
            ))
        }
    }
}
impl HasRawLoaderArgs for EmulationArgs {
    fn has_raw_loader_args(&self) -> bool {
        self.raw_loader_args.is_some()
    }
    fn raw_loader_args(&self) -> RawLoaderArgs {
        self.raw_loader_args.unwrap_or_default()
    }
}
impl HasEmuRunLimits for EmulationArgs {
    fn emu_run_limits(&self) -> EmuRunLimits {
        self.emu_run_limits.unwrap_or_default()
    }
    fn has_emu_run_limits(&self) -> bool {
        self.emu_run_limits.is_some()
    }
}

impl ProgramIdentifierArgs {
    // future: this mirrors typhunix ProgramIdentifier, which should be
    // centralized into styx-grpc
    pub fn new(program_name: &str, source_id: &str) -> Self {
        Self {
            name: program_name.to_string(),
            source_id: source_id.to_string(),
        }
    }
}

impl SymbolSearchOptions {
    pub fn regex_include(&self) -> Result<RegexSet, ApplicationError> {
        match RegexSetBuilder::new([&self.regex_include])
            .case_insensitive(true)
            .build()
        {
            Ok(rset) => Ok(rset),
            Err(e) => Err(ApplicationError::ArgParseError(e.to_string())),
        }
    }
    pub fn regex_exclude(&self) -> Result<RegexSet, ApplicationError> {
        let regex_str = if self.regex_include.is_empty() {
            ".".to_string()
        } else {
            self.regex_include.to_string()
        };
        match RegexSetBuilder::new([&regex_str])
            .case_insensitive(true)
            .build()
        {
            Ok(rset) => Ok(rset),
            Err(e) => Err(ApplicationError::ArgParseError(e.to_string())),
        }
    }
}

impl SupportedConfig {
    pub fn to_target(&self) -> Option<Target> {
        from_target_enum_value(self.id)
    }
}

/// Return a [Target] if it matches the value
pub fn from_target_enum_value(value: impl TryInto<i32>) -> Option<Target> {
    if let Ok(v) = value.try_into() {
        if let Ok(target) = Target::try_from(v) {
            return Some(target);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use crate::args::*;

    #[test]
    fn test_arg_string() {
        // test that the arg string mechanism works
        assert_eq!(Target::Kinetis21.arg_string(), "--target kinetis21");
    }
}
