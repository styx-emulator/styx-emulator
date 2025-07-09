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
use super::prelude::*;
use sea_orm::entity::prelude::*;
use sea_orm::ActiveValue::{NotSet, Set};

type Message = TraceAppSessionArgs;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, serde::Serialize, serde::Deserialize)]
#[sea_orm(table_name = "trace_app_session_args")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub mode: i32,
    pub session_id: String,
    pub resume: bool,
    pub pid: Json,
    pub trace_filepath: String,
    pub raw_trace_args: Json,
    pub symbol_options: Json,
    pub ws_program_id: i32,
}

impl Model {
    pub fn aggregate_to_message(
        &self,
        new_emulation_args: &Option<EmulationArgsModel>,
        new_limits: &Option<RawEventLimitsModel>,
    ) -> Message {
        let final_model = self;
        let message = serde_json::to_value(final_model).unwrap();
        let mut message = serde_json::from_value::<Message>(message).unwrap();
        if let Some(ref v) = new_emulation_args {
            message.emulation_args = Some(
                serde_json::from_value::<EmulationArgs>(serde_json::to_value(v).unwrap()).unwrap(),
            )
        }
        if let Some(v) = new_limits {
            message.limits = Some(
                serde_json::from_value::<RawEventLimits>(serde_json::to_value(v).unwrap()).unwrap(),
            )
        }
        message
    }

    pub fn aggregate_to_message_from_children(&self, msg: Message) -> Message {
        let (emu, limits) = {
            (
                if let Some(emulation_args) = msg.emulation_args {
                    let model: EmulationArgsModel = emulation_args.into();
                    Some(model)
                } else {
                    None
                },
                if let Some(limits) = msg.limits {
                    let model: RawEventLimitsModel = limits.into();
                    Some(model)
                } else {
                    None
                },
            )
        };
        self.aggregate_to_message(&emu, &limits)
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_one = "super::emulation_args::Entity")]
    EmulationArgs,
    #[sea_orm(has_one = "super::raw_event_limits::Entity")]
    RawEventLimits,
}

impl Related<RawEventLimitsEntity> for Entity {
    fn to() -> RelationDef {
        Relation::RawEventLimits.def()
    }
}
impl Related<EmulationArgsEntity> for Entity {
    fn to() -> RelationDef {
        Relation::EmulationArgs.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl From<Message> for Model {
    fn from(value: Message) -> Self {
        Model {
            id: value.id,
            mode: value.mode,
            resume: value.resume,
            pid: crate::opt_serde_value!(value.pid),
            session_id: value.session_id,
            trace_filepath: value.trace_filepath,
            raw_trace_args: crate::opt_serde_value!(value.raw_trace_args),
            symbol_options: crate::opt_serde_value!(value.symbol_options),
            ws_program_id: value.ws_program_id,
        }
    }
}

impl Model {
    pub fn from_message(msg: Message) -> Self {
        msg.into()
    }
}

impl From<Message> for ActiveModel {
    fn from(value: Message) -> Self {
        Self {
            id: if value.id > 0 { Set(value.id) } else { NotSet },
            mode: Set(value.mode),
            session_id: Set(value.session_id),
            resume: Set(value.resume),
            pid: Set(crate::opt_serde_value!(value.pid)),
            trace_filepath: Set(value.trace_filepath),
            raw_trace_args: Set(crate::opt_serde_value!(value.raw_trace_args)),
            symbol_options: Set(crate::opt_serde_value!(value.symbol_options)),
            ws_program_id: Set(value.ws_program_id),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;
    #[allow(unused_imports)]
    use tracing::{debug, error, info, trace};
    pub type TestResult = Result<(), Box<dyn std::error::Error + 'static>>;

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn test_serialize() -> TestResult {
        styx_core::util::logging::init_logging();
        let args = Message::default();
        let raw_trace_args = args.raw_trace_args.clone();
        assert!(raw_trace_args.is_none());
        let myval = {
            if let Some(v) = raw_trace_args {
                serde_json::to_value(v)?
            } else {
                serde_json::Value::Null
            }
        };
        assert_eq!(myval, serde_json::Value::Null);
        let raw_trace_args = Some(Message::default());
        assert!(raw_trace_args.is_some());
        let myval = {
            if let Some(v) = raw_trace_args {
                serde_json::to_value(v).unwrap()
            } else {
                serde_json::Value::Null
            }
        };
        assert_ne!(myval, serde_json::Value::Null);
        Ok(())
    }

    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    #[test_case(Message::default()  ; "default")]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    #[test_case(Message {
        emulation_args: Some(EmulationArgs::default()),
        ..Default::default()
    }  ; "has emulation_args")]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    #[test_case(Message {
        limits: Some(RawEventLimits::default()),
        ..Default::default()
    }  ; "has limits")]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    #[test_case(Message {
        limits: Some(RawEventLimits::default()),
        emulation_args: Some(EmulationArgs::default()),
        ..Default::default()
    }  ; "has both")]
    fn test_aggregate(msg: Message) -> TestResult {
        let orig_msg = msg.clone();
        let model: Model = msg.clone().into();
        assert_eq!(msg.id, model.id);
        let aggregate_msg = model.aggregate_to_message_from_children(orig_msg.clone());
        assert_eq!(
            serde_json::to_string(&orig_msg.clone())?,
            serde_json::to_string(&aggregate_msg)?
        );
        Ok(())
    }
}
