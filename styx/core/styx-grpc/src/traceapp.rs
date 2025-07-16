// SPDX-License-Identifier: BSD-2-Clause
//! Encapsulates `traceapp.proto` messages, services, and supporting abstractions

use self::utils::EmuMetadata;
pub use super::utils;
use crate::args::{self, EmulationArgs, TraceAppSessionArgs};
use styx_errors::styx_grpc::ApplicationError;
tonic::include_proto!("traceapp");

impl std::fmt::Display for EndOfEvents {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "EndOfEvents: {}", self.insn_num)
    }
}

impl std::fmt::Display for Timeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Timeout: (Raw) last insn# {}", self.insn_num)
    }
}

impl std::fmt::Display for InstructionExec {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "InstructionExec: {}, pc: {:#10x}, insn: {:#010x}",
            self.insn_num, self.pc, self.insn
        )
    }
}

impl std::fmt::Display for Interrupt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Interrupt: {} [{}] old_pc: {:#08x}, new_pc:{:#08x} #{}, : [{}]",
            self.insn_num,
            match self.entered {
                true => "Enter",
                false => "Exit",
            },
            self.old_pc,
            self.new_pc,
            self.interrupt_num,
            self.stack.len(),
        )
    }
}

impl std::fmt::Display for FunctionGate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let op = {
            if self.entered {
                "(E)"
            } else {
                "(X)"
            }
        };
        let s = format!("{} {}", op, self.function_signature);
        write!(f, "{s}")
    }
}

impl std::fmt::Display for BasicBlock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = format!(
            "start: {}, end: {}, pc: {:#08x}, sz: {}",
            self.is_start, self.is_end, self.pc, self.size
        );
        write!(f, "{s}")
    }
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct StartTraceAppSessionResponseSummary {
    total: usize,
    instruction: usize,
    memchange: usize,
    interrupt: usize,
    function: usize,
    basic_block: usize,
    end: usize,
    timeout: u64,
    insn_limit_reached: u64,
}
impl StartTraceAppSessionResponseSummary {
    pub fn json(&self) -> String {
        serde_json::to_string(self).unwrap()
    }
}

impl From<StartTraceAppSessionResponse> for StartTraceAppSessionResponseSummary {
    fn from(value: StartTraceAppSessionResponse) -> Self {
        Self {
            timeout: match value.timeout {
                Some(ref v) => v.insn_num,
                None => 0,
            },
            insn_limit_reached: match value.insn_limit_reached {
                Some(ref v) => v.insn_num,
                None => 0,
            },

            end: value.end_of_events.len(),
            instruction: value.instructions.len(),
            function: value.functions.len(),
            basic_block: value.basic_blocks.len(),
            interrupt: value.interrupts.len(),
            total: value.total_event_count(),
            memchange: value.memory_writes.len(),
        }
    }
}

impl StartTraceAppSessionResponse {
    #[inline]
    pub fn session_id(&self) -> String {
        self.session_id.to_string()
    }

    #[inline]
    pub fn total_event_count(&self) -> usize {
        self.memory_writes.len()
            + self.end_of_events.len()
            + self.interrupts.len()
            + self.instructions.len()
            + self.functions.len()
            + if self.timeout.is_some() { 1 } else { 0 }
            + if self.insn_limit_reached.is_some() {
                1
            } else {
                0
            }
    }

    #[inline]
    pub fn has_timeout(&self) -> bool {
        self.timeout.is_some()
    }

    #[inline]
    pub fn json_summary() {}
}

impl SessionInfo {
    pub fn trace_file_path(&self) -> Result<String, ApplicationError> {
        Ok(self.metadata()?.trace_file_path)
    }

    pub fn metadata(&self) -> Result<EmuMetadata, ApplicationError> {
        if let Some(ref md) = self.metadata {
            Ok(md.clone())
        } else {
            Err(ApplicationError::MissingData(
                "metadata on SessionInfo".into(),
            ))
        }
    }
}

impl AppSession {
    pub fn new(session_id: &str) -> Self {
        Self {
            session_id: session_id.to_string(),
        }
    }

    pub fn session_id(&self) -> String {
        self.session_id.clone()
    }
}

impl InitializeTraceRequest {
    pub fn new(args: TraceAppSessionArgs) -> Self {
        Self { args: Some(args) }
    }

    /// Return a clone of [TraceAppSessionArgs] from the request or an error.
    pub fn args(&self) -> Result<TraceAppSessionArgs, ApplicationError> {
        if let Some(args) = &self.args {
            Ok(args.clone())
        } else {
            Err(ApplicationError::MissingRequiredArgs("args".into()))
        }
    }

    /// Get the [emulation args](EmulationArgs) or an error. Call this only when we expect
    /// to have emulation_args.
    pub fn emulation_args(&self) -> Result<EmulationArgs, ApplicationError> {
        if let Some(emulation_args) = &self.args()?.emulation_args {
            Ok(emulation_args.clone())
        } else {
            Err(ApplicationError::MissingRequiredArgs(
                "emulation_args".into(),
            ))
        }
    }

    /// Update the args from the request. Return an error if there are no
    /// args on the request. Currently session_id and trace_file_path are the
    /// only fields that mutate at run time.
    pub fn update_args(
        &mut self,
        session_id: String,
        trace_filepath: String,
    ) -> Result<(), ApplicationError> {
        let mut args_clone = self.args()?;
        args_clone.trace_filepath = trace_filepath;
        args_clone.session_id = session_id;
        // replace the args
        self.args = Some(args_clone);
        Ok(())
    }

    pub fn pid_args(&self) -> Result<args::ProgramIdentifierArgs, ApplicationError> {
        self.args()?.pid_args()
    }
}

impl std::fmt::Display for CVarRepr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = format!("({}) {}", self.typename, self.name);
        write!(f, "{s}")
    }
}

impl std::fmt::Display for CStructRepr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let v = if let Some(ref var) = self.var {
            format!("{var}")
        } else {
            "".to_string()
        };
        let s = format!("{} ({} members)", v, self.members.len());
        write!(f, "{s}")
    }
}

impl std::fmt::Display for BasicRepr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let v = if let Some(ref var) = self.var {
            format!("{var}")
        } else {
            "".to_string()
        };
        let s = format!("{v} ");
        write!(f, "{s}")
    }
}

impl MemoryChange {
    #[inline]
    pub fn is_basic(&self) -> bool {
        self.basic_repr.is_some()
    }
    #[inline]
    pub fn is_struct(&self) -> bool {
        self.struct_repr.is_some()
    }
    #[inline]
    pub fn is_array(&self) -> bool {
        self.array_repr.is_some()
    }

    #[inline]
    pub fn datatype_cls(&self) -> String {
        String::from(if self.is_struct() {
            "struct"
        } else if self.is_basic() {
            "basic"
        } else if self.is_array() {
            "array"
        } else {
            "<unhandled>"
        })
    }

    #[inline]
    pub fn desc(&self) -> String {
        String::from(if self.is_read {
            "Memory(R)"
        } else {
            "Memory(W)"
        })
    }

    #[inline]
    pub fn list_display(&self) -> String {
        let dt_cls = self.datatype_cls();
        let mut s = self.desc();
        s.push_str(&format!(", addr:{:#010x}", self.addr));
        s.push_str(&format!(", [{dt_cls}] "));
        s.push_str(&self.val_repr());
        s
    }

    #[inline]
    pub fn val_repr(&self) -> String {
        let mut s = String::from("");
        if let Some(ref _srep) = self.struct_repr {
            if let Some(ref mem) = self.member_var {
                s.push_str(&format!(
                    "    ({}) {}.{} = {}",
                    mem.typename, self.symbol_name, mem.name, self.new_value
                ));
            }
        }

        if let Some(ref vt) = self.basic_repr {
            s.push_str(&format!(
                "    {}",
                if let Some(ref v) = vt.var {
                    format!("({}) {} = {}", v.typename, self.symbol_name, self.new_value)
                } else {
                    "?".to_string()
                },
            ));
        }
        if let Some(ref vt) = self.array_repr {
            s.push_str(&format!(
                "    {}",
                if let Some(ref v) = vt.var {
                    format!("({}) {} = {}", v.typename, self.symbol_name, self.new_value)
                } else {
                    "?".to_string()
                },
            ));
        }
        s
    }
}

impl std::fmt::Display for MemoryChange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let dt_cls = self.datatype_cls();
        let desc = self.desc();
        let mut s = format!("{} {:010}", desc, self.insn_num);
        s.push_str(&format!(" pc:{:#010x}", self.pc));
        s.push_str(&format!(", addr:{:#010x}", self.addr));
        s.push_str(&format!(", size:{}", self.new_value.len()));
        s.push_str(&format!(", [{dt_cls}]"));
        if let Some(ref i) = self.interrupt {
            let ss = format!("  Interrupt: {i}");
            s.push_str(&ss);
        }
        s.push_str(&format!("\n  {}()", self.function_name));
        s.push_str(" {\n");

        if let Some(ref _srep) = self.struct_repr {
            if let Some(ref mem) = self.member_var {
                s.push_str(&format!(
                    "    ({}) {}.{} = {}",
                    mem.typename, self.symbol_name, mem.name, self.new_value
                ));
            }
        }
        if let Some(ref vt) = self.basic_repr {
            s.push_str(&format!(
                "    {}",
                if let Some(ref v) = vt.var {
                    format!("({}) {} = {}", v.typename, self.symbol_name, self.new_value)
                } else {
                    "?".to_string()
                },
            ));
        }
        if let Some(ref vt) = self.array_repr {
            s.push_str(&format!(
                "    {}",
                if let Some(ref v) = vt.var {
                    format!("({}) {} = {}", v.typename, self.symbol_name, self.new_value)
                } else {
                    "?".to_string()
                },
            ));
        }
        s.push_str("\n  }");
        write!(f, "{s}")
    }
}

pub trait RateInsnPerSec {
    fn rate_insn_per_sec(&self) -> u64;
}

impl RateInsnPerSec for SessionStats {
    /// Rough execution rate as instructions per second.
    ///
    /// The `execution_duration` is a `prost_wkt_type::Duration`
    /// composed of:
    /// - pub seconds: i64,
    /// - pub nanos: i32,
    ///
    /// The rough rate is `self.insn_count / self.execution_duration.seconds`.
    /// Zero(0) is returned if the duration is negative, `insn_count` is zero,
    /// or the optional `execution_duration` is not set.
    fn rate_insn_per_sec(&self) -> u64 {
        let Some(wkt_duration) = self.execution_duration else {
            return 0;
        };
        if wkt_duration.seconds <= 0 {
            if wkt_duration.nanos > 0 {
                return 1;
            } else {
                return 0;
            }
        }
        if self.insn_count == 0 {
            return 0;
        }
        self.insn_count / wkt_duration.seconds as u64
    }
}

impl SessionStats {
    pub fn set_stats_values(&mut self, insn_count: u64, duration: std::time::Duration) {
        self.insn_count = insn_count;
        self.execution_duration = Some(duration.try_into().unwrap_or_default());
        let rate = self.rate_insn_per_sec();
        self.rate = rate;
    }

    pub fn duration_as_std(&self) -> std::time::Duration {
        let d = self
            .execution_duration
            .unwrap_or(prost_wkt_types::Duration {
                seconds: 0,
                nanos: 0,
            });
        std::time::Duration::new(
            d.seconds.try_into().unwrap_or(0),
            d.nanos.try_into().unwrap_or(0),
        )
    }

    pub fn merge_from(&mut self, other: &SessionStats) {
        let self_duration = self.duration_as_std();
        let other_duration = other.duration_as_std();
        self.insn_count += other.insn_count;
        let cum_duration = self_duration + other_duration;
        self.execution_duration = Some(cum_duration.try_into().unwrap_or_default());
        self.rate = self.rate_insn_per_sec();
    }
}

#[cfg(test)]
mod tests {
    use log::debug;
    use styx_util::logging::init_logging;

    use super::*;
    #[test]
    fn test_merge_from_stats() {
        init_logging();
        let mut stats = SessionStats::default();
        debug!("{}", serde_json::to_string(&stats).unwrap_or("{}".into()));
        assert!(stats.execution_duration.is_none());
        assert_eq!(stats.rate_insn_per_sec(), 0);
        assert_eq!(stats.insn_count, 0);
        let stats1 = SessionStats {
            insn_count: 10,
            execution_duration: Some(prost_wkt_types::Duration {
                seconds: 10,
                nanos: 0,
            }),
            ..Default::default()
        };

        stats.merge_from(&stats1);
        debug!("{}", serde_json::to_string(&stats).unwrap_or("{}".into()));
        assert_eq!(stats.rate_insn_per_sec(), 1);
        assert_eq!(stats.rate, 1);
        assert_eq!(stats.insn_count, 10);

        stats.merge_from(&stats1);
        debug!("{}", serde_json::to_string(&stats).unwrap_or("{}".into()));
        assert_eq!(stats.rate_insn_per_sec(), 1);
        assert_eq!(stats.rate, 1);
        assert_eq!(stats.insn_count, 20);
    }

    #[test]
    fn test_update_stats() {
        init_logging();
        let mut stats = SessionStats::default();
        debug!("{}", serde_json::to_string(&stats).unwrap_or("{}".into()));
        assert!(stats.execution_duration.is_none());
        assert_eq!(stats.rate_insn_per_sec(), 0);
        assert_eq!(stats.insn_count, 0);
        stats.set_stats_values(10, std::time::Duration::new(10, 0));
        debug!("{}", serde_json::to_string(&stats).unwrap_or("{}".into()));
        assert_eq!(stats.rate_insn_per_sec(), 1);
        assert_eq!(stats.rate, 1);
        assert_eq!(stats.insn_count, 10);

        stats.set_stats_values(20, std::time::Duration::new(20, 0));
        debug!("{}", serde_json::to_string(&stats).unwrap_or("{}".into()));
        assert_eq!(stats.rate_insn_per_sec(), 1);
        assert_eq!(stats.rate, 1);
        assert_eq!(stats.insn_count, 20);
    }
}
