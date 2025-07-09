// SPDX-License-Identifier: BSD-2-Clause
use super::prelude::*;
use sea_orm::entity::prelude::*;

type Message = Workspace;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, serde::Serialize, serde::Deserialize)]
#[sea_orm(table_name = "workspace")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub name: String,
    pub created_timestamp: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::program::Entity")]
    WsProgram,
}

impl Related<WsProgramEntity> for Entity {
    fn to() -> RelationDef {
        Relation::WsProgram.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl From<Message> for Model {
    fn from(value: Message) -> Self {
        Model {
            id: value.id,
            name: value.name.to_string(),
            created_timestamp: value.created_timestamp_or_now().into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use styx_core::util::logging::init_logging;
    #[allow(unused_imports)]
    use tracing::{debug, error, info, trace};
    pub type TestResult = Result<(), Box<dyn std::error::Error + 'static>>;

    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn test_message_to_models() -> TestResult {
        init_logging();
        let msg = Message {
            id: 0,
            name: "ws1".into(),
            created_timestamp: None,
            ws_programs: vec![],
        };
        debug!("{:?}", msg);
        assert!(msg.created_timestamp.is_none());
        let model: Model = msg.into();
        debug!("{:?}", model);
        let am: WorkspaceActiveModel = model.into();
        debug!("{:?}", am);
        Ok(())
    }
}
