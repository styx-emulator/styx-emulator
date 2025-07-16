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

use sea_orm::{Database, DatabaseConnection};
use styx_core::errors::styx_grpc::ApplicationError;

pub mod api;
pub mod model;

pub type DBIdType = i32;

#[macro_export]
/// Macro to serialize an `Option<T>` into a `serde_json::Value`
/// into a sea-orm model object value
macro_rules! opt_serde_value {
    ($var: expr_2021) => {
        if let Some(__some_var) = $var {
            serde_json::to_value(__some_var).unwrap()
        } else {
            serde_json::Value::Null
        }
    };
}

#[macro_export]
/// shorthand to deserialize from Value to a message
macro_rules! serde_value {
    ($var: expr_2021) => {
        serde_json::from_value($var).unwrap_or_default()
    };
}

#[macro_export]
/// Macro to link child entities to parent entities and ensure
/// that the proper primary_keys are set
macro_rules! link_optional_child {
    ($db_transaction: expr_2021, $parent: expr_2021, $active_model: ty, $msg: expr_2021) => {
        if let Some(msg) = $msg {
            let id = msg.id;
            let mut am: $active_model = msg.into();
            if id > 0 {
                am = am.reset_all();
            }
            am.trace_app_session_args_id = Set($parent);
            Some(am.save($db_transaction).await?.try_into_model().unwrap())
        } else {
            None
        }
    };
}

/// Get a connection to the database url give by the environment variable
/// `DATABASE_URL`. Return [ApplicationError] if the variable is not set
/// or the connection fails.
pub async fn default_connection() -> Result<DatabaseConnection, ApplicationError> {
    let dburl = std::env::var("DATABASE_URL")
        .map_err(|e| ApplicationError::MissingEnvironmentVar("DATABASE_URL".into(), e))?;
    let cnx = Database::connect(&dburl)
        .await
        .map_err(|e| ApplicationError::DbConnectError(dburl, e.to_string()))?;
    Ok(cnx)
}
