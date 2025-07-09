// SPDX-License-Identifier: BSD-2-Clause
pub use sea_orm_migration::prelude::*;
pub use sea_orm_migration::MigrationTrait;
mod entity_schema_gen;
mod m20240610_184941_bootstrap;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![Box::new(m20240610_184941_bootstrap::Migration)]
    }
}
