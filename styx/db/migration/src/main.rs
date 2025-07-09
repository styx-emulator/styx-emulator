// SPDX-License-Identifier: BSD-2-Clause

use sea_orm_migration::prelude::*;

#[tokio::main]
async fn main() {
    cli::run_cli(styx_dbmigration::Migrator).await;
}
