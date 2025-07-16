// SPDX-License-Identifier: BSD-2-Clause
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
            ($entity: expr_2021) => {
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
