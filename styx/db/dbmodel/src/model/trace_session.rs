// SPDX-License-Identifier: BSD-2-Clause
use super::prelude::*;
use sea_orm::entity::prelude::*;
use sea_orm::ActiveValue::{NotSet, Set};
use styx_core::grpc::utils::EmuMetadata;

type Message = TraceSession;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, serde::Serialize, serde::Deserialize)]
#[sea_orm(table_name = "trace_session")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub session_id: String,
    pub state: String,
    pub ts_state: i32,
    pub timestamp: ChronoDateTimeUtc,
    pub metadata: Json,
    // parent relation
    pub trace_app_session_args_id: i32,
}

impl Model {
    pub fn from_message(msg: Message, parent_id: Option<i32>) -> Self {
        let mut model: Model = msg.into();
        model.trace_app_session_args_id = parent_id.unwrap_or_default();
        model
    }

    pub fn to_message(&self) -> Message {
        Message {
            id: self.id,
            session_id: self.session_id.to_string(),
            state: self.state.clone(),
            ts_state: self.ts_state,
            timestamp: Some(self.timestamp.into()),
            metadata: if self.metadata == serde_json::Value::Null {
                None
            } else {
                Some(serde_json::from_value::<EmuMetadata>(self.metadata.clone()).unwrap())
            },
        }
    }
}

impl ActiveModel {
    pub fn from_message(msg: Message, parent_id: Option<i32>) -> Self {
        let mut active_model: ActiveModel = msg.into();
        let parent_id = parent_id.unwrap_or_default();
        let parent_id = if parent_id == 0 {
            NotSet
        } else {
            Set(parent_id)
        };
        active_model.trace_app_session_args_id = parent_id;
        active_model
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
        let ts = value.timestamp().unwrap();
        Model {
            id: value.id,
            session_id: value.session_id,
            state: value.state,
            ts_state: value.ts_state,
            timestamp: ts.into_inner(),
            metadata: crate::opt_serde_value!(value.metadata),
            trace_app_session_args_id: 0,
        }
    }
}

impl From<Message> for ActiveModel {
    fn from(value: Message) -> Self {
        let timestamp = value.timestamp().unwrap().into_inner();
        Self {
            id: if value.id > 0 { Set(value.id) } else { NotSet },
            session_id: Set(value.session_id),
            state: Set(value.state),
            ts_state: Set(value.ts_state),
            timestamp: Set(timestamp),
            metadata: Set(crate::opt_serde_value!(value.metadata)),
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
            timestamp: Some(std::time::SystemTime::now().into()),
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
