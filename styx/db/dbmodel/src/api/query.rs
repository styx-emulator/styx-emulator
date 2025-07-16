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

use crate::model::program::PartialWsProgram;
use crate::model::{emulation_args, raw_event_limits, trace_app_session_args, workspace};
use crate::model::{prelude::*, trace_session};
use sea_orm::*;
use std::collections::HashMap;
use tokio::join;

pub struct DbQuery;

macro_rules! to_child_objects {
    ($Val: expr_2021, $MsgType: ty) => {
        match $Val {
            Some(v) => {
                if v.get("id").is_none()
                    || v.get("id").unwrap().is_null()
                    || v == serde_json::Value::Null
                {
                    None
                } else {
                    Some(serde_json::from_value::<$MsgType>(v).unwrap())
                }
            }
            _ => None,
        }
    };
}

impl DbQuery {
    /// Find all TraceAppSessionArgs
    ///
    /// no pagination, for now
    pub async fn find_all_trace_app_session_args(
        db: &DbConn,
    ) -> Result<Vec<(TraceAppSessionArgs, Option<TraceSession>)>, DbErr> {
        let fut_limits_models = TraceAppSessionArgsEntity::find()
            .find_also_related(RawEventLimitsEntity)
            .order_by_asc(trace_app_session_args::Column::Id)
            .into_json()
            .all(db);
        let fut_emulation_args = TraceAppSessionArgsEntity::find()
            .find_also_related(EmulationArgsEntity)
            .order_by_asc(trace_app_session_args::Column::Id)
            .into_json()
            .all(db);
        let fut_sessions = TraceSessionEntity::find()
            .order_by_asc(trace_session::Column::Id)
            .all(db);

        let (emulation_args, limits_models, sessions) =
            join!(fut_emulation_args, fut_limits_models, fut_sessions);
        let sessions = {
            let mut hm: HashMap<i32, TraceSession> = HashMap::new();
            for s in sessions?.iter() {
                hm.insert(s.trace_app_session_args_id, s.to_message());
            }
            hm
        };

        let emulation_args_values = emulation_args?;
        let limits_values = limits_models?;
        debug_assert_eq!(emulation_args_values.len(), limits_values.len());

        let mut trace_app_session_args_messages = emulation_args_values
            .iter()
            .map(|v| serde_json::from_value::<TraceAppSessionArgs>(v.0.clone()).unwrap())
            .collect::<Vec<TraceAppSessionArgs>>();

        let mut iter1 = emulation_args_values
            .iter()
            .map(|v| to_child_objects!(v.1.clone(), EmulationArgs));
        let mut iter2 = limits_values
            .iter()
            .map(|v| to_child_objects!(v.1.clone(), RawEventLimits));

        let mut result: Vec<(TraceAppSessionArgs, Option<TraceSession>)> =
            Vec::with_capacity(trace_app_session_args_messages.len());
        trace_app_session_args_messages.iter_mut().for_each(|msg| {
            msg.emulation_args.clone_from(&iter1.next().unwrap());
            msg.limits.clone_from(&iter2.next().unwrap());
            result.push((msg.clone(), sessions.get(&msg.id).cloned()));
        });

        Ok(result)
    }

    /// Find all EmulationArgs
    pub async fn find_all_emulation_args(db: &DbConn) -> Result<Vec<EmulationArgs>, DbErr> {
        Ok(EmulationArgsEntity::find()
            .order_by_asc(emulation_args::Column::Id)
            .into_json()
            .all(db)
            .await?
            .iter()
            .map(|v| serde_json::from_value::<EmulationArgs>(v.clone()).unwrap())
            .collect::<Vec<EmulationArgs>>())
    }

    /// Find all RawEventLimits
    pub async fn find_all_raw_event_limits(db: &DbConn) -> Result<Vec<RawEventLimits>, DbErr> {
        Ok(RawEventLimitsEntity::find()
            .order_by_asc(raw_event_limits::Column::Id)
            .into_json()
            .all(db)
            .await?
            .iter()
            .map(|v| serde_json::from_value::<RawEventLimits>(v.clone()).unwrap())
            .collect::<Vec<RawEventLimits>>())
    }

    pub async fn find_all_trace_app_session_args_by_id(
        db: &DbConn,
        id: DBIdType,
    ) -> Result<Option<TraceAppSessionArgs>, DbErr> {
        let fut_limits_models = TraceAppSessionArgsEntity::find_by_id(id)
            .find_also_related(RawEventLimitsEntity)
            .into_json()
            .one(db);
        let fut_emulation_args = TraceAppSessionArgsEntity::find_by_id(id)
            .find_also_related(EmulationArgsEntity)
            .into_json()
            .one(db);

        let (emulation_args, limits_models) = join!(fut_emulation_args, fut_limits_models);

        let emulation_args_values = emulation_args?;
        let limits_values = limits_models?;

        if let Some((app_session, emuargs)) = emulation_args_values {
            let mut app_session: TraceAppSessionArgs =
                serde_json::from_value::<TraceAppSessionArgs>(app_session.clone()).unwrap();
            app_session
                .emulation_args
                .clone_from(&to_child_objects!(emuargs.clone(), EmulationArgs));
            app_session.limits.clone_from(&to_child_objects!(
                limits_values.unwrap().1.clone(),
                RawEventLimits
            ));
            Ok(Some(app_session))
        } else {
            Ok(None)
        }
    }

    pub async fn find_trace_session_by_session_id(
        db: &DbConn,
        session_id: &str,
    ) -> Result<Option<(TraceAppSessionArgs, TraceSession)>, DbErr> {
        let xx = TraceSessionEntity::find()
            .filter(Condition::all().add(trace_session::Column::SessionId.eq(session_id)))
            .find_also_related(TraceAppSessionArgsEntity)
            .into_json()
            .one(db)
            .await?;

        if let Some((trace_session, Some(trace_app_session_args))) = xx {
            Ok(Some((
                serde_json::from_value::<TraceAppSessionArgs>(trace_app_session_args)
                    .map_err(|e| DbErr::Json(e.to_string()))?,
                serde_json::from_value::<TraceSession>(trace_session)
                    .map_err(|e| DbErr::Json(e.to_string()))?,
            )))
        } else {
            Ok(None)
        }
    }

    pub async fn get_partial_ws_programs(
        dbid: Option<DBIdType>,
        db: &DbConn,
    ) -> Result<Vec<WsProgram>, DbErr> {
        if let Some(dbid) = dbid {
            let mut msgs: Vec<WsProgram> = Vec::with_capacity(1);
            if let Some(model) = WsProgramEntity::find_by_id(dbid)
                .into_model::<PartialWsProgram>()
                .one(db)
                .await?
            {
                msgs.push(model.into_message())
            }

            Ok(msgs)
        } else {
            Ok(WsProgramEntity::find()
                .into_model::<PartialWsProgram>()
                .all(db)
                .await?
                .iter()
                .map(|model| model.into_message())
                .collect::<Vec<WsProgram>>())
        }
    }

    pub async fn get_ws_programs(
        dbid: Option<DBIdType>,
        db: &DbConn,
    ) -> Result<Vec<WsProgram>, DbErr> {
        if let Some(dbid) = dbid {
            let mut msgs: Vec<WsProgram> = Vec::with_capacity(1);
            if let Some(model) = WsProgramEntity::find_by_id(dbid).one(db).await? {
                msgs.push(model.into_message())
            }
            Ok(msgs)
        } else {
            Ok(WsProgramEntity::find()
                .all(db)
                .await?
                .iter()
                .map(|model| model.into_message())
                .collect::<Vec<WsProgram>>())
        }
    }

    pub async fn get_workspaces(
        dbid: Option<DBIdType>,
        db: &DbConn,
    ) -> Result<Vec<Workspace>, DbErr> {
        let base_query = {
            if let Some(dbid) = dbid {
                WorkspaceEntity::find_by_id(dbid)
            } else {
                WorkspaceEntity::find()
            }
        };
        Ok(base_query
            .find_with_related(WsProgramEntity)
            .order_by_asc(workspace::Column::Id)
            .all(db)
            .await?
            .iter()
            .map(|item| Workspace {
                id: item.0.id,
                created_timestamp: Some(item.0.created_timestamp.into()),
                name: item.0.name.to_string(),
                ws_programs: item
                    .1
                    .iter()
                    .map(|wsp_model| wsp_model.into_message())
                    .collect::<Vec<WsProgram>>(),
            })
            .collect::<Vec<Workspace>>())
    }
}
