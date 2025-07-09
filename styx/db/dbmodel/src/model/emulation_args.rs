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

type Message = EmulationArgs;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, serde::Serialize, serde::Deserialize)]
#[sea_orm(table_name = "emulation_args")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub target: i32,
    pub firmware_path: String,
    pub trace_plugin_args: Json,
    pub emu_run_limits: Json,
    pub raw_loader_args: Json,
    ipc_port: i16,
    // parent relation
    pub trace_app_session_args_id: i32,
}

impl Model {
    pub fn from_message(msg: Message, parent_id: Option<i32>) -> Self {
        let mut model: Model = msg.into();
        model.trace_app_session_args_id = parent_id.unwrap_or_default();
        model
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::trace_app_session_args::Entity"
        from = "Column::TraceAppSessionArgsId",
        to = "super::trace_app_session_args::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    Parent,
}

impl Related<TraceAppSessionArgsEntity> for Entity {
    fn to() -> RelationDef {
        Relation::Parent.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl From<Message> for Model {
    fn from(value: Message) -> Self {
        Model {
            id: value.id,
            target: value.target,
            firmware_path: value.firmware_path,
            ipc_port: value.ipc_port.try_into().unwrap(),
            emu_run_limits: crate::opt_serde_value!(value.emu_run_limits),
            raw_loader_args: crate::opt_serde_value!(value.raw_loader_args),
            trace_plugin_args: crate::opt_serde_value!(value.trace_plugin_args),
            trace_app_session_args_id: 0,
        }
    }
}

impl From<Message> for ActiveModel {
    fn from(value: Message) -> Self {
        Self {
            id: if value.id > 0 { Set(value.id) } else { NotSet },
            target: Set(value.target),
            firmware_path: Set(value.firmware_path),
            ipc_port: Set(value.ipc_port.try_into().unwrap()),
            emu_run_limits: Set(crate::opt_serde_value!(value.emu_run_limits)),
            raw_loader_args: Set(crate::opt_serde_value!(value.raw_loader_args)),
            trace_plugin_args: Set(crate::opt_serde_value!(value.trace_plugin_args)),
            trace_app_session_args_id: NotSet,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use tracing::{debug, error, info, trace};
    pub type TestResult = Result<(), Box<dyn std::error::Error + 'static>>;

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn test_model_from_message() -> TestResult {
        styx_core::util::logging::init_logging();
        let entity_id = 1;
        let parent_id = 2;
        let msg = Message {
            id: entity_id,
            ..Default::default()
        };
        let model = Model::from_message(msg.clone(), Some(parent_id));
        assert_eq!(model.trace_app_session_args_id, parent_id);
        assert_eq!(model.id, entity_id);
        let model = Model::from_message(msg, None);
        assert_eq!(model.trace_app_session_args_id, 0);
        Ok(())
    }
}
