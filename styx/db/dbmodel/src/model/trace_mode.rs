// SPDX-License-Identifier: BSD-2-Clause
use super::prelude::*;
use sea_orm::entity::prelude::*;

type MessageEnum = TraceMode;

#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "i32", db_type = "Integer")]
pub enum ModelEnum {
    #[sea_orm(num_value = 0)]
    Emulated,
    #[sea_orm(num_value = 1)]
    Raw,
    #[sea_orm(num_value = 2)]
    Srb,
}

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "trace_mode")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    // Represents a db column using `TraceMode` active enum
    pub trace_mode: ModelEnum,
}

impl From<MessageEnum> for ModelEnum {
    fn from(value: MessageEnum) -> Self {
        match value {
            MessageEnum::Emulated => ModelEnum::Emulated,
            MessageEnum::Raw => ModelEnum::Raw,
            MessageEnum::Srb => ModelEnum::Srb,
        }
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
