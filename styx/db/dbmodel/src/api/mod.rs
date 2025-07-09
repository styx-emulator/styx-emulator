// SPDX-License-Identifier: BSD-2-Clause
mod mutation;
mod query;
pub use sea_orm::prelude::*;
pub mod prelude {
    pub use super::mutation::DbApi;
    pub use super::query::DbQuery;
    pub use crate::DBIdType;
    pub use sea_orm::prelude::*;
    pub use sea_orm::{Database, DatabaseConnection};
}
