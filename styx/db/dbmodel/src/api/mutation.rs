// SPDX-License-Identifier: BSD-2-Clause

use crate::link_optional_child;
use crate::model::prelude::*;
use sea_orm::*;
use std::time::SystemTime;
use styx_core::grpc::db::DbId;
use styx_core::grpc::utils::EmuMetadata;
use tracing::debug;

pub struct DbApi;

impl DbApi {
    /// Insert or update the trace_sesson::TraceSession.
    pub async fn upsert_trace(
        db: &DatabaseConnection,
        parent: &Option<TraceAppSessionArgs>,
        trace_session: &TraceSession,
    ) -> Result<TraceSession, DbErr> {
        let is_insert = trace_session.id == 0;
        let tx: DatabaseTransaction = db.begin().await.unwrap();
        let parent_id = match parent {
            Some(args) => {
                let (dbid, _) = DbApi::upsert_trace_app_session(db, args, true).await?;
                dbid.id
            }
            _ => trace_session.id,
        };

        let am: TraceSessionActiveModel =
            TraceSessionActiveModel::from_message(trace_session.clone(), Some(parent_id));
        let model = if is_insert {
            am.insert(&tx).await?.try_into_model()?
        } else {
            am.save(&tx).await?.try_into_model()?
        };
        tx.commit().await?;
        let metadata = Some(
            serde_json::from_value::<EmuMetadata>(serde_json::to_value(model.metadata).unwrap())
                .unwrap(),
        );

        Ok(TraceSession {
            id: model.id,
            session_id: model.session_id,
            state: model.state,
            ts_state: model.ts_state,
            timestamp: Some(<SystemTime>::from(model.timestamp).into()),
            metadata,
        })
    }

    /// Insert or update the trace_app_session_args::TraceAppSessionArgs
    pub async fn upsert_trace_app_session(
        db: &DatabaseConnection,
        msg: &TraceAppSessionArgs,
        with_msg: bool,
    ) -> Result<(DbId, Option<TraceAppSessionArgs>), DbErr> {
        let msg = msg.clone();
        let is_insert = msg.id == 0;
        let limits = msg.limits;
        let emulation_args = msg.emulation_args.clone();

        let tx: DatabaseTransaction = db.begin().await.unwrap();
        let am: TraceAppSessionArgsActiveModel = msg.into();
        debug!("upsert: TraceAppSessionArgsActiveModel.id ==> {:?}", am.id);
        let model = if is_insert {
            am.insert(&tx).await?.try_into_model().unwrap()
        } else {
            am.save(&tx).await?.try_into_model().unwrap()
        };
        let parent_id = model.id;
        let (new_limits, new_emulation_args) = (
            link_optional_child!(&tx, parent_id, RawEventLimitsActiveModel, limits),
            link_optional_child!(&tx, parent_id, EmulationArgsActiveModel, emulation_args),
        );

        tx.commit().await?;
        let message = if with_msg {
            Some(model.aggregate_to_message(&new_emulation_args, &new_limits))
        } else {
            None
        };

        Ok((DbId { id: parent_id }, message))
    }

    /// Delete the trace_app_session_args::TraceAppSessionArgs with id
    pub async fn delete_trace_app_session_args(
        db: &DbConn,
        id: DBIdType,
    ) -> Result<DeleteResult, DbErr> {
        let trace_app_session_args: TraceAppSessionArgsActiveModel =
            TraceAppSessionArgsEntity::find_by_id(id)
                .one(db)
                .await?
                .ok_or(DbErr::Custom(
                    "Cannot find trace_app_session_args.".to_owned(),
                ))
                .map(Into::into)?;
        trace_app_session_args.delete(db).await
    }

    /// Delete all trace_app_session_args::TraceAppSessionArgs items
    pub async fn delete_all_trace_app_session_argss(db: &DbConn) -> Result<DeleteResult, DbErr> {
        TraceAppSessionArgsEntity::delete_many().exec(db).await
    }

    /// Insert or update the Workspace
    pub async fn upsert_workspace(db: &DatabaseConnection, msg: Workspace) -> Result<DbId, DbErr> {
        let is_insert = msg.id == 0;
        let mut am: WorkspaceActiveModel = WorkspaceModel::from(msg).into();
        let model = if is_insert {
            am.id = NotSet;
            am.insert(db).await?.try_into_model()?
        } else {
            am = am.reset_all();
            am.save(db).await?.try_into_model()?
        };
        Ok(DbId { id: model.id })
    }

    /// Insert or update the Program
    pub async fn upsert_program(
        db: &DatabaseConnection,
        msg: WsProgram,
    ) -> Result<Option<DbId>, DbErr> {
        let is_insert = msg.id == 0;
        let am: WsProgramActiveModel = msg.into();
        let model = if is_insert {
            am.insert(db).await?.try_into_model()?
        } else {
            am.save(db).await?.try_into_model()?
        };
        Ok(Some(DbId { id: model.id }))
    }

    // delete ws programs by id
    pub async fn delete_ws_program(db: &DatabaseConnection, id: DBIdType) -> Result<u64, DbErr> {
        let r = WsProgramEntity::delete_by_id(id).exec(db).await?;
        Ok(r.rows_affected)
    }
}
