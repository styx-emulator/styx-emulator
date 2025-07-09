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
use crate::serde_value;
use sea_orm::entity::prelude::*;
use sea_orm::ActiveValue::{NotSet, Set};
use sea_orm::{FromQueryResult, Unchanged};
use styx_core::grpc::db::DbId;

type Message = WsProgram;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, serde::Serialize, serde::Deserialize)]
#[sea_orm(table_name = "ws_program")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub name: String,
    pub file: Json,
    pub data: Vec<u8>,
    pub config: Json,
    pub emulation_args: Json,
    pub limits: Json,
    pub symbol_options: Json,
    pub sym_program: Json,
    pub symbols: Json,
    pub data_types: Json,
    // Parent
    pub workspace_id: i32,
}

/// PartialWsProgram truncates data, symbols, and data_types
#[derive(DerivePartialModel, FromQueryResult)]
#[sea_orm(entity = "WsProgramEntity")]
pub struct PartialWsProgram {
    pub id: i32,
    pub name: String,
    pub file: Json,
    // truncate: pub data: Vec<u8>,
    pub config: Json,
    pub sym_program: Json,
    pub emulation_args: Json,
    pub limits: Json,
    pub symbol_options: Json,
    // truncate: pub symbols: Json,
    // truncate: pub data_types: Json,
    // Parent
    pub workspace_id: i32,
}

impl Model {
    pub fn from_message(msg: Message) -> Self {
        msg.into()
    }
    pub fn into_message(&self) -> Message {
        Message {
            id: self.id,
            name: self.name.to_string(),
            file: serde_value!(self.file.clone()),
            data: self.data.to_vec(),
            config: serde_value!(self.config.clone()),
            emulation_args: serde_value!(self.emulation_args.clone()),
            limits: serde_value!(self.limits.clone()),
            symbol_options: serde_value!(self.symbol_options.clone()),
            sym_program: serde_value!(self.sym_program.clone()),
            data_types: serde_value!(self.data_types.clone()),
            symbols: serde_value!(self.symbols.clone()),
            workspace_id: Some(DbId {
                id: self.workspace_id,
            }),
        }
    }
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::workspace::Entity"
        from = "Column::WorkspaceId",
        to = "super::workspace::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    Parent,
}

impl Related<super::workspace::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Parent.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}

impl From<Message> for Model {
    fn from(value: Message) -> Self {
        Model {
            id: value.id,
            name: value.name.to_string(),
            file: crate::opt_serde_value!(value.file),
            data: value.data.to_vec(),
            config: crate::opt_serde_value!(value.config),
            emulation_args: crate::opt_serde_value!(value.emulation_args),
            limits: crate::opt_serde_value!(value.limits),
            symbol_options: crate::opt_serde_value!(value.symbol_options),
            sym_program: crate::opt_serde_value!(value.sym_program),
            symbols: serde_json::to_value(value.symbols).unwrap(),
            data_types: serde_json::to_value(value.data_types).unwrap(),
            workspace_id: value.workspace_id.unwrap().id,
        }
    }
}

impl PartialWsProgram {
    pub fn into_message(&self) -> Message {
        Message {
            id: self.id,
            name: self.name.to_string(),
            file: serde_value!(self.file.clone()),
            data: vec![],
            config: serde_value!(self.config.clone()),
            emulation_args: serde_value!(self.emulation_args.clone()),
            limits: serde_value!(self.limits.clone()),
            symbol_options: serde_value!(self.symbol_options.clone()),
            sym_program: serde_value!(self.sym_program.clone()),
            data_types: vec![],
            symbols: vec![],
            workspace_id: Some(DbId {
                id: self.workspace_id,
            }),
        }
    }
}

impl From<Model> for Message {
    fn from(value: Model) -> Self {
        Self {
            id: value.id,
            name: value.name.to_string(),
            file: serde_json::from_value(value.file).unwrap(),
            data: value.data,
            config: serde_json::from_value(value.config).unwrap(),
            emulation_args: serde_json::from_value(value.emulation_args).unwrap(),
            limits: serde_json::from_value(value.limits).unwrap(),
            symbol_options: serde_json::from_value(value.symbol_options).unwrap(),
            sym_program: serde_json::from_value(value.sym_program).unwrap(),
            data_types: serde_json::from_value(value.data_types).unwrap(),
            symbols: serde_json::from_value(value.symbols).unwrap(),
            workspace_id: Some(DbId {
                id: value.workspace_id,
            }),
        }
    }
}

impl From<Message> for ActiveModel {
    fn from(value: Message) -> Self {
        Self {
            id: if value.id > 0 { Set(value.id) } else { NotSet },
            name: Set(value.name),
            file: Set(crate::opt_serde_value!(value.file)),
            data: Set(value.data),
            config: Set(crate::opt_serde_value!(value.config)),
            emulation_args: Set(crate::opt_serde_value!(value.emulation_args)),
            limits: Set(crate::opt_serde_value!(value.limits)),
            symbol_options: Set(crate::opt_serde_value!(value.symbol_options)),
            sym_program: Set(crate::opt_serde_value!(value.sym_program)),
            symbols: Set(serde_json::to_value(value.symbols).unwrap()),
            data_types: Set(serde_json::to_value(value.data_types).unwrap()),
            workspace_id: Unchanged(value.workspace_id.unwrap().id),
        }
    }
}
