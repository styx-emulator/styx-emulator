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
use sea_orm_migration::sea_orm::prelude::*;
use sea_orm_migration::sea_orm::Schema;
use styx_dbmodel::model::prelude::*;

#[derive(Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct TableScript {
    pub name: String,
    pub sql: String,
}

impl TableScript {
    pub fn new(name: &str, sql: &str) -> Self {
        Self {
            name: name.to_string(),
            sql: sql.to_string(),
        }
    }
}

#[derive(Default, Clone, serde::Serialize, serde::Deserialize)]
pub struct MigrationScript {
    pub tables: Vec<TableScript>,
}

impl MigrationScript {
    pub async fn _json(&self) -> String {
        serde_json::to_string(&self).unwrap()
    }

    pub async fn add(&mut self, ts: &TableScript) {
        self.tables.push(ts.clone())
    }

    pub async fn generate_schema(&mut self) {
        let pg = sea_orm_migration::sea_orm::DbBackend::Postgres;
        let schema = Schema::new(pg);
        let mut stmts: Vec<TableScript> = vec![];

        macro_rules! table {
            ($entity: expr) => {
                let _tbl = TableScript::new(
                    $entity.as_str(),
                    &pg.build(&schema.create_table_from_entity($entity)).sql,
                );
                stmts.push(_tbl);
            };
        }

        table!(TraceAppSessionArgsEntity);
        table!(RawEventLimitsEntity);
        table!(WorkspaceEntity);
        table!(EmulationArgsEntity);
        table!(TraceSessionEntity);
        table!(WsProgramEntity);
        table!(TraceEventEntity);

        for stmt in stmts.iter() {
            self.add(stmt).await;
        }
    }
}
