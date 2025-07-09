// SPDX-License-Identifier: BSD-2-Clause
use super::prelude::*;
use sea_orm::entity::prelude::*;
use sea_orm::ActiveValue::{NotSet, Set};

type Message = RawEventLimits;
type PU64 = i64;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, serde::Serialize, serde::Deserialize)]
#[sea_orm(table_name = "raw_event_limits")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub max_insn: PU64,
    pub max_mem_read_events: PU64,
    pub max_mem_write_events: PU64,
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

impl Related<super::trace_app_session_args::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Parent.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl From<Message> for Model {
    fn from(value: Message) -> Self {
        Model {
            id: value.id,
            max_insn: value.max_insn.try_into().unwrap(),
            max_mem_read_events: value.max_mem_read_events.try_into().unwrap(),
            max_mem_write_events: value.max_mem_write_events.try_into().unwrap(),
            trace_app_session_args_id: 0,
        }
    }
}

impl From<Message> for ActiveModel {
    fn from(value: Message) -> Self {
        Self {
            id: if value.id > 0 { Set(value.id) } else { NotSet },
            max_insn: Set(value.max_insn.try_into().unwrap()),
            max_mem_read_events: Set(value.max_mem_read_events.try_into().unwrap()),
            max_mem_write_events: Set(value.max_mem_write_events.try_into().unwrap()),
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
        let model = Model::from_message(msg, Some(parent_id));
        assert_eq!(model.trace_app_session_args_id, parent_id);
        assert_eq!(model.id, entity_id);
        let model = Model::from_message(msg, None);
        assert_eq!(model.trace_app_session_args_id, 0);
        Ok(())
    }
}
