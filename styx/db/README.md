# Tonic + gRPC + SeaORM

Simple implementation of gRPC using SeaORM.

run server using

```bash
cargo run --bin server
```

run client using

```bash
cargo run --bin client
```

Run mock test on the service logic crate:

```bash
cd service
cargo test --features mock
```

## SeaORM Starter

- MySQL mysql://root:root@localhost:3306
- PostgreSQL postgres://root:root@localhost:5432
- SQLite (in file) sqlite:./sqlite.db?mode=rwc
- SQLite (in memory) sqlite::memory:

## SQLX

[sqlx-cli](https://github.com/launchbadge/sqlx/blob/main/sqlx-cli/README.md)

```shell
# supports all databases supported by SQLx
$ cargo install sqlx-cli

# only for postgres
$ cargo install sqlx-cli --no-default-features --features native-tls,postgres

# use vendored OpenSSL (build from source)
$ cargo install sqlx-cli --features openssl-vendored

# use Rustls rather than OpenSSL (be sure to add the features for the databases you intend to use!)
$ cargo install sqlx-cli --no-default-features --features rustls
```

## SeaORM Migrations

- [sea-orm-cli](https://www.sea-ql.org/sea-orm-tutorial/ch01-02-migration-cli.html)'

```shell
# Install `sea-orm-cli`
$ cargo install sea-orm-cli
# List all available migration commands that are supported by `sea-orm-cli`
$ sea-orm-cli migrate -h
```

## Cargo.toml

```text
Demo packages:
    "dbdemo/api",
    "dbdemo/dbmodel",
    "dbdemo/migration",
    "dbdemo/programs",
    "dbdemo/service",
```

## Adding new json-based Entity

- dbmodel.rs
- mutation.rs
- query.rs
- migration (create table)
