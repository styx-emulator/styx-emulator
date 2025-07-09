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

type MessageEnum = TraceSessionState;

#[derive(Debug, Clone, PartialEq, Eq, EnumIter, DeriveActiveEnum)]
#[sea_orm(rs_type = "i32", db_type = "Integer")]
pub enum ModelEnum {
    #[sea_orm(num_value = 3)]
    Created,
    #[sea_orm(num_value = 2)]
    Creating,
    #[sea_orm(num_value = 13)]
    Dropped,
    #[sea_orm(num_value = 12)]
    Dropping,
    #[sea_orm(num_value = 1)]
    Error,
    #[sea_orm(num_value = 5)]
    Initialized,
    #[sea_orm(num_value = 4)]
    Initializing,
    #[sea_orm(num_value = 11)]
    Paused,
    #[sea_orm(num_value = 7)]
    Running,
    #[sea_orm(num_value = 6)]
    Starting,
    #[sea_orm(num_value = 9)]
    StopRequestReceived,
    #[sea_orm(num_value = 10)]
    Stopped,
    #[sea_orm(num_value = 8)]
    Stopping,
    #[sea_orm(num_value = 0)]
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "trace_session_state")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    // Represents a db column using `TraceSessionState` active enum
    pub ts_state: ModelEnum,
}

impl From<MessageEnum> for ModelEnum {
    fn from(value: MessageEnum) -> Self {
        match value {
            MessageEnum::Unknown => ModelEnum::Unknown,
            MessageEnum::Error => ModelEnum::Error,
            MessageEnum::Creating => ModelEnum::Creating,
            MessageEnum::Created => ModelEnum::Created,
            MessageEnum::Initializing => ModelEnum::Initializing,
            MessageEnum::Initialized => ModelEnum::Initialized,
            MessageEnum::Starting => ModelEnum::Starting,
            MessageEnum::Running => ModelEnum::Running,
            MessageEnum::Stopping => ModelEnum::Stopping,
            MessageEnum::StopRequestReceived => ModelEnum::StopRequestReceived,
            MessageEnum::Stopped => ModelEnum::Stopped,
            MessageEnum::Paused => ModelEnum::Paused,
            MessageEnum::Dropping => ModelEnum::Dropping,
            MessageEnum::Dropped => ModelEnum::Dropped,
        }
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
