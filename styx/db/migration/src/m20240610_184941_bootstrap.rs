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
use crate::entity_schema_gen::MigrationScript;
use extension::postgres::Type;
use sea_orm::ActiveModelTrait;
use sea_orm::ActiveValue::NotSet;
use sea_orm::DbBackend;
use sea_orm::Set;
use sea_orm_migration::prelude::*;
use sea_orm_migration::SchemaManager;
use styx_core::util::dtutil::UtcDateTime;
use styx_dbmodel::model::prelude::*;
use tracing::debug;

#[derive(DeriveMigrationName)]
pub struct Migration;
#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let mut script = MigrationScript::default();
        script.generate_schema().await;

        let db = manager.get_connection();
        macro_rules! exec {
            ($db: ident, $sql: expr_2021) => {
                $db.execute_unprepared($sql).await?
            };
        }
        for table in script.tables.iter() {
            debug!("Migration::up: SQL: {}", &table.sql);
            exec!(db, &table.sql);
        }
        match db.get_database_backend() {
            DbBackend::MySql | DbBackend::Sqlite => {}
            DbBackend::Postgres => {
                manager
                    .create_type(
                        Type::create()
                            .as_enum(TraceMode::Enum)
                            .values([TraceMode::Emulated, TraceMode::Raw, TraceMode::Srb])
                            .to_owned(),
                    )
                    .await?;
                manager
                    .create_type(
                        Type::create()
                            .as_enum(TraceSessionState::Enum)
                            .values([
                                TraceSessionState::Unknown,
                                TraceSessionState::Creating,
                                TraceSessionState::Created,
                                TraceSessionState::Initializing,
                                TraceSessionState::Initialized,
                                TraceSessionState::Starting,
                                TraceSessionState::Running,
                                TraceSessionState::Stopping,
                                TraceSessionState::Stopped,
                                TraceSessionState::Paused,
                                TraceSessionState::Finalizing,
                                TraceSessionState::Killing,
                                TraceSessionState::Dropped,
                            ])
                            .to_owned(),
                    )
                    .await?;
            }
        }

        // insert default workspace
        WorkspaceActiveModel {
            id: NotSet,
            name: Set("Default".to_owned()),
            created_timestamp: Set(UtcDateTime::now().into_inner()),
        }
        .insert(db)
        .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let mut script = MigrationScript::default();
        script.generate_schema().await;
        let db = manager.get_connection();
        for table in script.tables.iter().rev() {
            let sql = format!("drop table {}{}{}", r#"""#, table.name, r#"""#);
            debug!("Migration::down: SQL:{}", sql);
            db.execute_unprepared(&sql).await?;
        }
        match db.get_database_backend() {
            DbBackend::MySql | DbBackend::Sqlite => {}
            DbBackend::Postgres => {
                manager
                    .drop_type(Type::drop().name(TraceMode::Enum).to_owned())
                    .await?;
                manager
                    .drop_type(Type::drop().name(TraceSessionState::Enum).to_owned())
                    .await?;
            }
        }
        Ok(())
    }
}

#[derive(DeriveIden)]
pub enum TraceMode {
    #[sea_orm(iden = "Emulated")]
    Emulated,
    #[sea_orm(iden = "trace_mode")]
    Enum,
    #[sea_orm(iden = "Raw")]
    Raw,
    #[sea_orm(iden = "Srb")]
    Srb,
}

#[derive(DeriveIden)]
pub enum TraceSessionState {
    #[sea_orm(ident = "Created")]
    Created,
    #[sea_orm(ident = "Creating")]
    Creating,
    #[sea_orm(ident = "Dropped")]
    Dropped,
    #[sea_orm(iden = "trace_session_state")]
    Enum,
    #[sea_orm(ident = "Finalizing")]
    Finalizing,
    #[sea_orm(ident = "Initialized")]
    Initialized,
    #[sea_orm(ident = "Initializing")]
    Initializing,
    #[sea_orm(ident = "Killing")]
    Killing,
    #[sea_orm(ident = "Paused")]
    Paused,
    #[sea_orm(ident = "Running")]
    Running,
    #[sea_orm(ident = "Starting")]
    Starting,
    #[sea_orm(ident = "Stopped")]
    Stopped,
    #[sea_orm(ident = "Stopping")]
    Stopping,
    #[sea_orm(ident = "Unknown")]
    Unknown,
}
