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
use sea_orm::{ConnectOptions, ConnectionTrait, DatabaseConnection, Statement};
use sea_orm::{Database, DbBackend, DbErr};
use std::time::Duration;
use styx_dbmigration::*;
use testcontainers_modules::testcontainers::TestcontainersError;
use thiserror::Error;
use tracing::{error, warn};
use url::{ParseError, Url};

pub const POSGRES_PORT: u16 = 5432;

pub mod test_nodes;

pub async fn migrate_fresh(dburl: &DbUrl) -> Result<(), DbOpsErr> {
    drop_create(dburl).await?;
    migrate(dburl).await?;
    Ok(())
}

pub async fn migrate(dburl: &DbUrl) -> Result<(), DbOpsErr> {
    let opts = connect_options(dburl.to_string())?;
    let cnx = Database::connect(opts).await?;
    Migrator::up(&cnx, None).await?;
    Ok(())
}

pub fn connect_options<T>(u: T) -> Result<ConnectOptions, DbOpsErr>
where
    T: Into<String>,
{
    let mut opt = ConnectOptions::new(u.into());
    opt.max_connections(100)
        .min_connections(5)
        .connect_timeout(Duration::from_secs(8))
        .acquire_timeout(Duration::from_secs(8))
        .idle_timeout(Duration::from_secs(8))
        .max_lifetime(Duration::from_secs(8))
        .sqlx_logging(true)
        .sqlx_logging_level(log::LevelFilter::Info);

    Ok(opt)
}

pub async fn drop_create(dburl: &DbUrl) -> Result<(), DbOpsErr> {
    let baseurl = dburl.baseurl();
    let dbname = match dburl.dbname() {
        Some(dbname) => Ok(dbname),
        _ => Err(DbOpsErr::NoDatabaseInUrl),
    }?;

    warn!("drop_create: {baseurl}");
    let cnx = Database::connect(connect_options(baseurl)?).await?;
    let drop_stmt = format!("drop database if exists\"{dbname}\";");
    let create_stmt = format!("create database \"{dbname}\";");
    match cnx.get_database_backend() {
        DbBackend::Postgres | DbBackend::MySql => {
            cnx.execute(Statement::from_string(
                cnx.get_database_backend(),
                &drop_stmt,
            ))
            .await?;
            cnx.execute(Statement::from_string(
                cnx.get_database_backend(),
                &create_stmt,
            ))
            .await?;
        }
        DbBackend::Sqlite => (),
    };
    Ok(())
}

#[derive(Debug, Error)]
pub enum DbOpsErr {
    #[error("Data size: `{0}` is not compatible with event: ")]
    DbErr(sea_orm::error::DbErr),
    #[error("ParseError: `{0}`")]
    DbUrlParseError(ParseError),
    #[error("`{0}`")]
    Error(&'static str),
    #[error("database name required in connect string")]
    NoDatabaseInUrl,
    #[error("TestcontainersError: `{0}`")]
    TestcontainersError(TestcontainersError),
}
impl From<DbErr> for DbOpsErr {
    fn from(value: DbErr) -> Self {
        Self::DbErr(value)
    }
}
impl From<TestcontainersError> for DbOpsErr {
    fn from(value: TestcontainersError) -> Self {
        Self::TestcontainersError(value)
    }
}
impl From<ParseError> for DbOpsErr {
    fn from(value: ParseError) -> Self {
        Self::DbUrlParseError(value)
    }
}
#[derive(Debug)]
pub struct DbUtil {
    pub dburl: DbUrl,
}
impl DbUtil {
    pub fn new(dburl: &str) -> Result<Self, DbOpsErr> {
        Ok(Self {
            dburl: DbUrl::try_from(dburl)?,
        })
    }

    pub async fn fresh(dburl: &str) -> Result<Self, DbOpsErr> {
        let me = Self::new(dburl)?;
        me.migrate_schema().await?;
        Ok(me)
    }

    pub async fn connect(&self) -> Result<DatabaseConnection, DbErr> {
        Database::connect(self.dburl.to_string().as_str()).await
    }

    pub async fn migrate_schema(&self) -> Result<(), DbOpsErr> {
        migrate_fresh(&self.dburl).await?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct DbUrl(Url);

impl TryFrom<&str> for DbUrl {
    type Error = ParseError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let u = Url::parse(value)?;
        Ok(DbUrl(u))
    }
}

impl std::fmt::Display for DbUrl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.url())
    }
}

impl DbUrl {
    pub fn from_env() -> Result<DbUrl, ParseError> {
        Self::try_from(std::env::var("DATABASE_URL").unwrap_or_default().as_str())
    }

    pub fn baseurl(&self) -> String {
        let scheme = self.url().scheme();
        let username = self.url().username();
        let password = match self.url().password() {
            Some(p) => format!(":{p}"),
            _ => "".to_string(),
        };
        let host = match self.url().host_str() {
            Some(v) => format!("@{v}"),
            _ => "".to_string(),
        };
        let port = match self.url().port() {
            Some(v) => format!(":{v}"),
            _ => "".to_string(),
        };
        format!("{scheme}://{username}{password}{host}{port}")
    }

    pub fn dbname(&self) -> Option<String> {
        let path = self.url().path().to_string();
        if path.starts_with('/') && path.len() > 1 {
            Some(path[1..].to_string())
        } else {
            None
        }
    }

    pub fn url(&self) -> &Url {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{distributions::Alphanumeric, Rng};
    use std::path::Path;
    use styx_core::grpc::args::{
        EmuRunLimits, EmulationArgs, ProgramIdentifierArgs, RawEventLimits, RawLoaderArgs,
        RawTraceArgs, SymbolSearchOptions, Target, TracePluginArgs,
    };
    use styx_core::tracebus::{MemReadEvent, TraceEventType};
    use styx_core::util::dtutil::UtcDateTime;
    use styx_dbmodel::api::prelude::*;
    use styx_dbmodel::model::prelude::*;
    pub type TestResult = Result<(), Box<dyn std::error::Error + 'static>>;
    use styx_core::grpc::emulation_registry::{
        ArchIdentity, BackendIdentity, EndianIdentity, LoaderIdentity, VariantIdentity,
    };
    use styx_core::grpc::traceapp::InitializeTraceRequest;
    use styx_core::grpc::typhunix_interop::json_util::connect_msg_from_file;
    use styx_core::grpc::utils::{EmulationState, ProcessorInfo};
    use styx_core::grpc::workspace::{Config, FileRef};
    use styx_core::util::logging::init_logging;
    use test_nodes::{PostgesNode, TyphunixSvcNode, WorkspaceSvcNode};
    use tokio::join;
    use tracing::{debug, info};
    use workspace_service::cli_util as ws_svc_cli;
    macro_rules! count {
        ($entity: ty, $cnx: expr_2021) => {
            <$entity>::find().count($cnx).await.unwrap()
        };
    }

    fn random_msg() -> TraceAppSessionArgs {
        TraceAppSessionArgs {
            id: 0,
            mode: TraceMode::Emulated.into(),
            session_id: uuid::Uuid::new_v4().into(),
            resume: false,
            pid: Some(ProgramIdentifierArgs {
                source_id: rand_string("source_id", 20, ""),
                name: rand_string("name", 2, ""),
            }),
            trace_filepath: "/tmp/foo/bar/somedir".into(),
            raw_trace_args: Some(RawTraceArgs::default()),
            emulation_args: Some(EmulationArgs {
                id: 0,
                target: 1,
                firmware_path: "foo".into(),
                trace_plugin_args: Some(TracePluginArgs::default()),
                emu_run_limits: Some(EmuRunLimits::default()),
                raw_loader_args: Some(RawLoaderArgs::default()),
                ipc_port: 0,
            }),
            limits: Some(RawEventLimits::default()),
            symbol_options: Some(SymbolSearchOptions::default()),
            ws_program_id: 0,
        }
    }

    fn rand_string(prefix: &str, nchars: usize, suffix: &str) -> String {
        format!(
            "{}{}{}",
            prefix,
            rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(nchars)
                .map(char::from)
                .collect::<String>(),
            suffix,
        )
    }
    #[test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    fn test_dburl() {
        let dbstr = "postgres://postgres:styx@localhost/styxdb";
        let dburl: DbUrl = dbstr.try_into().unwrap();
        assert_eq!(format!("{dburl}"), String::from(dbstr));
        assert!(dburl.dbname().is_some());
        assert_eq!(dburl.url().scheme(), "postgres");
        assert_eq!(dburl.url().password().unwrap(), "styx");
        assert_eq!(dburl.url().username(), "postgres");
        assert_eq!(dburl.dbname().unwrap(), "styxdb");
        assert_eq!(
            dburl.baseurl().as_str(),
            "postgres://postgres:styx@localhost"
        );
        let dburl2: DbUrl = dburl.baseurl().as_str().try_into().unwrap();
        assert!(dburl2.dbname().is_none());
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    async fn test_service() -> Result<(), Box<dyn std::error::Error + 'static>> {
        init_logging();
        let pg_node = PostgesNode::new(&format!("test-{}", Uuid::new_v4())).await?;
        let ws_node = WorkspaceSvcNode::new(&pg_node.network_name, &pg_node.url).await?;

        let msgs = vec![TraceAppSessionArgs::default(), random_msg()];
        let from_svc_add = ws_svc_cli::upsert_trace_app_session(&ws_node.url, msgs.to_vec())
            .await?
            .trace_app_session_args;
        assert_eq!(from_svc_add.len(), msgs.len());
        let (from_svc, from_db) = {
            let (r1, r2) = join!(
                ws_svc_cli::get_all_trace_app_sess(&ws_node.url),
                DbQuery::find_all_trace_app_session_args(&pg_node.cnx)
            );
            (r1.unwrap().trace_app_session_args, r2.unwrap())
        };
        assert_eq!(from_db.len(), msgs.len());
        let just_the_args = from_db
            .iter()
            .map(|rslt| rslt.0.clone())
            .collect::<Vec<TraceAppSessionArgs>>();
        assert_eq!(just_the_args, from_svc);
        Ok(())
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    async fn test_service_upsert() -> Result<(), Box<dyn std::error::Error + 'static>> {
        init_logging();
        let pg_node = PostgesNode::new(&format!("test-{}", Uuid::new_v4())).await?;
        let ws_node = WorkspaceSvcNode::new(&pg_node.network_name, &pg_node.url).await?;
        assert_eq!(0, count!(TraceAppSessionArgsEntity, &pg_node.cnx));
        assert_eq!(0, count!(TraceSessionEntity, &pg_node.cnx));

        let session_id = "<session_id_value>";
        let msg = TraceAppSessionArgs {
            session_id: session_id.to_string(),
            ..Default::default()
        };
        let msgs = [msg].to_vec();
        let from_svc_add = ws_svc_cli::upsert_trace_app_session(&ws_node.url, msgs.to_vec())
            .await?
            .trace_app_session_args;
        assert_eq!(from_svc_add.len(), msgs.len());

        let (from_svc, from_db) = {
            let (r1, r2) = join!(
                ws_svc_cli::get_all_trace_app_sess(&ws_node.url),
                DbQuery::find_all_trace_app_session_args(&pg_node.cnx)
            );
            (r1.unwrap().trace_app_session_args, r2.unwrap())
        };
        assert_eq!(1, count!(TraceAppSessionArgsEntity, &pg_node.cnx));
        assert_eq!(0, count!(TraceSessionEntity, &pg_node.cnx));
        assert_eq!(from_db.len(), msgs.len());

        let just_the_args = from_db
            .iter()
            .map(|rslt| rslt.0.clone())
            .collect::<Vec<TraceAppSessionArgs>>();
        assert_eq!(just_the_args, from_svc);
        let processor_info = ProcessorInfo {
            arch_name: "ARM".into(),
            target_name: "k21".into(),
            arch_variant: "arch_variant".into(),
            memory_start: 0,
            memory_end: 1024,
        };
        let metadata = styx_core::grpc::utils::EmuMetadata {
            token: Some(styx_core::grpc::utils::Token { inner_token: 1 }),
            trace_file_path: "trace-file-path".into(),
            process_id: 12345,
            port: 6666,
            state: EmulationState::Initialized.into(),
            processor_info: Some(processor_info),
            url: "http://localhost:6666".into(),
        };

        let args = from_db.first().unwrap();

        let trace_session = styx_core::grpc::workspace::TraceSession {
            id: 0,
            session_id: session_id.to_string(),
            state: "Running".into(),
            ts_state: TraceSessionState::Running.into(),
            timestamp: Some(std::time::SystemTime::now().into()),
            metadata: Some(metadata),
        };
        info!("{}", serde_json::to_string_pretty(&trace_session).unwrap());
        info!("{}", serde_json::to_string_pretty(args).unwrap());

        let (args, session) = {
            let upsert_response =
                ws_svc_cli::upsert_trace_session(&ws_node.url, &args.0, &trace_session).await?;
            (
                upsert_response.args.clone().unwrap(),
                upsert_response.session.clone().unwrap(),
            )
        };
        assert_eq!(1, count!(TraceAppSessionArgsEntity, &pg_node.cnx));
        assert_eq!(1, count!(TraceSessionEntity, &pg_node.cnx));

        info!("{}", serde_json::to_string_pretty(&args).unwrap());
        info!("{}", serde_json::to_string_pretty(&session).unwrap());

        let args = args.clone();
        let mut session = session.clone();
        let new_state = "Stopped";
        session.state = new_state.into();

        let (args, session) = {
            let upsert_response =
                ws_svc_cli::upsert_trace_session(&ws_node.url, &args, &session).await?;
            (
                upsert_response.args.clone().unwrap(),
                upsert_response.session.clone().unwrap(),
            )
        };
        assert_eq!(1, count!(TraceAppSessionArgsEntity, &pg_node.cnx));
        assert_eq!(1, count!(TraceSessionEntity, &pg_node.cnx));

        info!("2:{}", serde_json::to_string_pretty(&args).unwrap());
        info!("2:{}", serde_json::to_string_pretty(&session).unwrap());
        assert_eq!(session.id, 1);
        assert_eq!(session.state, new_state);

        let trace_session_models = TraceSessionEntity::find().all(&pg_node.cnx).await?;
        for m in trace_session_models.iter() {
            let j = serde_json::to_string(m).unwrap();
            debug!("TraceSessionModel from query db: {j}");
        }

        Ok(())
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    async fn test_trace_mode() -> TestResult {
        init_logging();
        let pg_node = PostgesNode::new(&format!("test-{}", Uuid::new_v4())).await?;

        let base_item = TraceAppSessionArgs {
            id: i32::default(),
            mode: TraceMode::Emulated.into(),
            session_id: "xx-session-id-xx".into(),
            resume: true,
            pid: None,
            trace_filepath: "/tmp/foo/bar".into(),
            raw_trace_args: Some(RawTraceArgs {
                trace_directory: "/tmp/trace-directory".into(),
                trace_wait_file: true,
            }),
            emulation_args: Some(EmulationArgs::default()),
            limits: Some(RawEventLimits::default()),
            symbol_options: Some(SymbolSearchOptions::default()),
            ws_program_id: i32::default(),
        };
        let emulated_args = base_item.clone();
        let mut raw_args = base_item.clone();
        let mut srb_args = base_item.clone();

        raw_args.mode = TraceMode::Raw.into();
        raw_args.raw_trace_args = None;
        srb_args.mode = TraceMode::Srb.into();
        srb_args.symbol_options = Some(styx_core::grpc::args::SymbolSearchOptions::default());

        DbApi::upsert_trace_app_session(&pg_node.cnx, &emulated_args, false)
            .await
            .unwrap();
        DbApi::upsert_trace_app_session(&pg_node.cnx, &raw_args, false)
            .await
            .unwrap();
        DbApi::upsert_trace_app_session(&pg_node.cnx, &srb_args, false)
            .await
            .unwrap();
        assert_eq!(3, count!(TraceAppSessionArgsEntity, &pg_node.cnx));
        let tas = DbQuery::find_all_trace_app_session_args(&pg_node.cnx)
            .await
            .unwrap();

        assert_eq!(tas.len(), 3);
        let mut iter = tas.iter();

        assert_eq!(iter.next().unwrap().clone().0.mode(), TraceMode::Emulated);
        assert_eq!(iter.next().unwrap().clone().0.mode(), TraceMode::Raw);
        assert_eq!(iter.next().unwrap().clone().0.mode(), TraceMode::Srb);
        Ok(())
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    async fn test_upsert_default() -> TestResult {
        init_logging();
        let pg_node = PostgesNode::new(&format!("test-{}", Uuid::new_v4())).await?;

        assert_eq!(0, count!(TraceAppSessionArgsEntity, &pg_node.cnx));

        let msg = styx_core::grpc::args::TraceAppSessionArgs::default();
        let mut msg_clone = msg.clone();

        // insert
        DbApi::upsert_trace_app_session(&pg_node.cnx, &msg, false).await?;

        // query
        let dbmsgs = DbQuery::find_all_trace_app_session_args(&pg_node.cnx).await?;

        // verify
        assert_eq!(dbmsgs.len(), 1);
        let dbmsg = dbmsgs.first().unwrap().clone();
        msg_clone.id = dbmsg.0.id;
        assert_eq!(dbmsg.0, msg_clone);
        debug!("{}", serde_json::to_string_pretty(&dbmsg)?);
        Ok(())
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    async fn test_active_model() -> TestResult {
        init_logging();
        let pg_node = PostgesNode::new(&format!("test-{}", Uuid::new_v4())).await?;

        let msg = TraceAppSessionArgs {
            id: 0,
            mode: TraceMode::Raw.into(),
            session_id: uuid::Uuid::new_v4().into(),
            resume: true,
            pid: Some(ProgramIdentifierArgs {
                source_id: rand_string("source_id", 20, ""),
                name: rand_string("name", 2, ""),
            }),
            trace_filepath: "/tmp/foo/bar/somedir".into(),
            raw_trace_args: None,
            emulation_args: None,
            limits: None,
            symbol_options: None,
            ws_program_id: 0,
        };

        let (id, inserted_msg) = {
            let result = DbApi::upsert_trace_app_session(&pg_node.cnx, &msg, true).await?;
            (result.0.id, result.1.unwrap())
        };
        assert_eq!(id, inserted_msg.id);
        debug!("{}", serde_json::to_string_pretty(&inserted_msg)?);
        Ok(())
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    async fn test_symbol_opts() -> TestResult {
        init_logging();
        let pg_node = PostgesNode::new(&format!("test-{}", Uuid::new_v4())).await?;

        let msg = styx_core::grpc::args::TraceAppSessionArgs {
            symbol_options: Some(SymbolSearchOptions::default()),
            ..Default::default()
        };
        let mut msg_clone = msg.clone();

        // insert
        DbApi::upsert_trace_app_session(&pg_node.cnx, &msg, false).await?;
        // query
        let dbmsgs = DbQuery::find_all_trace_app_session_args(&pg_node.cnx).await?;

        // verify
        assert_eq!(dbmsgs.len(), 1);
        let dbmsg = dbmsgs.first().unwrap().clone();
        msg_clone.id = dbmsg.0.id;
        assert_eq!(dbmsg.0, msg_clone);
        Ok(())
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    async fn test_emulation_args() -> TestResult {
        init_logging();
        let pg_node = PostgesNode::new(&format!("test-{}", Uuid::new_v4())).await?;
        let msgs = [
            TraceAppSessionArgs::default(),
            TraceAppSessionArgs {
                emulation_args: Some(styx_core::grpc::args::EmulationArgs::default()),
                ..Default::default()
            },
            random_msg(),
        ];

        for msg in msgs.iter() {
            DbApi::upsert_trace_app_session(&pg_node.cnx, &msg.clone(), false).await?;
        }

        // query
        let dbmsgs = DbQuery::find_all_trace_app_session_args(&pg_node.cnx).await?;
        assert_eq!(dbmsgs.len(), msgs.len());
        Ok(())
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    async fn test_emulation_full() -> TestResult {
        init_logging();
        let pg_node = PostgesNode::new(&format!("test-{}", Uuid::new_v4())).await?;

        let msg = random_msg();

        // insert
        DbApi::upsert_trace_app_session(&pg_node.cnx, &msg.clone(), false).await?;

        // query
        let dbmsgs = DbQuery::find_all_trace_app_session_args(&pg_node.cnx).await?;
        for msg in dbmsgs.iter() {
            info!("DBMSG: {}", serde_json::to_string_pretty(msg)?);
            assert_eq!(
                msg.0.clone(),
                DbQuery::find_all_trace_app_session_args_by_id(&pg_node.cnx, msg.0.id)
                    .await?
                    .unwrap()
            );
        }

        assert_eq!(dbmsgs.len(), 1);
        Ok(())
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    async fn test_updates() -> TestResult {
        init_logging();
        let pg_node = PostgesNode::new(&format!("test-{}", Uuid::new_v4())).await?;
        let input_emulation_args = EmulationArgs {
            id: 0,
            target: 1,
            firmware_path: "original path".into(),
            trace_plugin_args: Some(TracePluginArgs::default()),
            emu_run_limits: Some(EmuRunLimits::default()),
            raw_loader_args: Some(RawLoaderArgs::default()),
            ipc_port: 0,
        };

        let mut input_msg = random_msg();
        input_msg.emulation_args = Some(input_emulation_args.clone());

        let (dbid, inserted_msg, inserted_emuargs, inserted_limits) = {
            let (dbid, msg) =
                DbApi::upsert_trace_app_session(&pg_node.cnx, &input_msg, true).await?;
            let msg = msg.unwrap();
            let emuargs = msg.clone().emulation_args.unwrap();
            let limits = msg.clone().limits.unwrap();
            (dbid.id, msg, emuargs, limits)
        };

        assert_eq!(dbid, 1);
        assert_eq!(inserted_msg.id, 1);
        assert_eq!(inserted_msg.emulation_args.clone().unwrap().id, 1);
        assert_eq!(inserted_msg.limits.unwrap().id, 1);
        assert!(!inserted_msg.resume);

        let (fetched_tasa, fetched_emuargs, fetched_limits) = {
            (
                {
                    let mut items = DbQuery::find_all_trace_app_session_args(&pg_node.cnx).await?;
                    assert_eq!(items.len(), 1);
                    let item = items.pop().unwrap().0;
                    assert_eq!(item.id, 1);
                    item
                },
                {
                    let mut items = DbQuery::find_all_emulation_args(&pg_node.cnx).await?;
                    assert_eq!(items.len(), 1);
                    let item = items.pop().unwrap();
                    assert_eq!(item.id, 1);
                    item
                },
                {
                    let mut items = DbQuery::find_all_raw_event_limits(&pg_node.cnx).await?;
                    assert_eq!(items.len(), 1);
                    let item = items.pop().unwrap();
                    assert_eq!(item.id, 1);
                    item
                },
            )
        };

        assert_eq!(inserted_msg, fetched_tasa);
        assert_eq!(inserted_emuargs, fetched_emuargs);
        assert_eq!(inserted_limits, fetched_limits);

        assert_eq!(
            inserted_msg,
            DbQuery::find_all_trace_app_session_args_by_id(&pg_node.cnx, inserted_msg.id)
                .await?
                .unwrap()
        );

        // Update the message
        let mut new_msg = inserted_msg.clone();
        new_msg.resume = true;
        let (updated_id, updated_msg) = {
            let (id, item) = DbApi::upsert_trace_app_session(&pg_node.cnx, &new_msg, true).await?;
            (id.id, item.unwrap())
        };
        assert!(updated_msg.resume);
        assert_eq!(updated_id, 1);
        assert_eq!(updated_msg.id, 1);
        assert_eq!(1, count!(TraceAppSessionArgsEntity, &pg_node.cnx));
        assert_eq!(1, count!(EmulationArgsEntity, &pg_node.cnx));
        assert_eq!(1, count!(RawEventLimitsEntity, &pg_node.cnx));

        // update emulation_args field
        let mut modified_emulation_args = inserted_msg.clone().emulation_args.clone().unwrap();
        modified_emulation_args.firmware_path = "new firmware path".to_string();
        modified_emulation_args.trace_plugin_args = Some(TracePluginArgs {
            insn_event: true,
            block_event: true,
            ..Default::default()
        });
        let mut new_msg = updated_msg.clone();
        new_msg.emulation_args = Some(modified_emulation_args);
        let new_mode: i32 = TraceMode::Raw.into();
        new_msg.mode = new_mode;

        let (updated_id, updated_msg) = {
            let (id, item) = DbApi::upsert_trace_app_session(&pg_node.cnx, &new_msg, true).await?;
            (id.id, item.unwrap())
        };
        assert!(updated_msg.resume);
        assert_eq!(
            updated_msg.clone().emulation_args.unwrap().firmware_path,
            "new firmware path"
        );
        assert_eq!(updated_msg.mode, new_mode);
        assert_eq!(updated_id, 1);
        assert_eq!(updated_msg.id, 1);
        assert_eq!(
            updated_msg
                .clone()
                .emulation_args
                .unwrap()
                .trace_plugin_args,
            new_msg.emulation_args.clone().unwrap().trace_plugin_args
        );
        assert_eq!(1, count!(TraceAppSessionArgsEntity, &pg_node.cnx));
        assert_eq!(1, count!(EmulationArgsEntity, &pg_node.cnx));
        assert_eq!(1, count!(RawEventLimitsEntity, &pg_node.cnx));
        Ok(())
    }

    #[tokio::test]
    #[ignore] // flaky ?
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    async fn test_re_write_trace_request() -> TestResult {
        init_logging();
        let pg_node = PostgesNode::new(&format!("test-{}", Uuid::new_v4())).await?;
        let ws_node = WorkspaceSvcNode::new(&pg_node.network_name, &pg_node.url).await?;
        let ty_node = TyphunixSvcNode::new(&pg_node.network_name, &pg_node.url).await?;

        // setup: use this as test program, symbols, data_types
        let typhunix_connect_msg = {
            let test_data_path = {
                let rel_path = "extensions/typhunix/rust/testdata/connect_message.json";
                let mut from = styx_core::util::styx_root_pathbuf();
                from.push(rel_path);
                from.as_path().to_str().unwrap().to_string()
            };
            connect_msg_from_file(test_data_path).await?
        };
        let config = Some(
            serde_json::from_str::<Config>(
                r#"{
                "arch_iden": {"id": 0, "name": "Arch::Arm"},
                "endian_iden": {"id": 0, "name": "ArchEndian::LittleEndian"},
                "loader_iden": {"id": 0, "name": "Loader::Raw"},
                "backend_iden": {"id": 1, "name": "Backend::Unicorn"},
                "variant_iden": {"id": 8, "name": "ArmVariants::ArmCortexM3"}
                }"#,
            )
            .unwrap(),
        );
        // setup: insert a workspace
        let workspace_id = Some(
            ws_svc_cli::upsert_workspace(
                &ws_node.url.clone(),
                &Workspace {
                    id: 0,
                    name: "ws1".into(),
                    ws_programs: vec![],
                    created_timestamp: Some(std::time::SystemTime::now().into()),
                },
            )
            .await?,
        );
        // setup: create and save a WsProgram
        let input_ws_program = {
            let bin_pgm_siz = 1024;

            let msg = typhunix_connect_msg.clone();

            WsProgram {
                id: 0,
                name: "my-ws-program1".into(),
                file: Some(FileRef {
                    path: "somefile.bin".into(),
                    size: bin_pgm_siz,
                }),
                emulation_args: None,
                limits: None,
                symbol_options: None,
                data: vec![0; 1024],
                config,
                sym_program: msg.program,
                data_types: msg.data_types,
                symbols: msg.symbols,
                workspace_id,
            }
        };
        assert_eq!(0, count!(WsProgramEntity, &pg_node.cnx));
        let saved_ws_program = {
            let response =
                ws_svc_cli::upsert_ws_program(&ws_node.url.clone(), &input_ws_program).await?;
            assert!(response.ws_program_id.is_some());
            let id = response.ws_program_id.unwrap().id;
            assert!(id > 0);
            let rr = ws_svc_cli::get_ws_programs(&ws_node.url.clone(), input_ws_program.id, true)
                .await?;
            assert!(rr.len() == 1);
            let ws_program = rr.first().unwrap().clone();
            assert_eq!(ws_program.data.len(), 1024);
            {
                let (f1, s1, d1, f2, s2, d2) = {
                    let (m1, m2) = { (typhunix_connect_msg.clone(), ws_program.clone()) };
                    (
                        m1.clone().program.unwrap().clone().functions,
                        m1.clone().data_types,
                        m1.clone().symbols,
                        m2.clone().sym_program.unwrap().clone().functions,
                        m2.clone().data_types,
                        m2.clone().symbols,
                    )
                };
                assert_eq!(f1, f2, "Function count matches");
                assert_eq!(s1, s2, "symbol count matches");
                assert_eq!(d1, d2, "datatype count matches");
            };

            ws_program
        };
        assert_eq!(1, count!(WsProgramEntity, &pg_node.cnx));

        // setup: Save TraceAppSessionArgs with ws_program_id set...
        let initialize_trace_request = {
            let args = TraceAppSessionArgs {
                id: 0,
                mode: TraceMode::Emulated.into(),
                session_id: uuid::Uuid::new_v4().into(),
                resume: false,
                pid: Some(ProgramIdentifierArgs {
                    source_id: rand_string("source_id", 20, ""),
                    name: rand_string("name", 2, ""),
                }),
                trace_filepath: "/tmp/foo/bar/somedir".into(),
                raw_trace_args: Some(RawTraceArgs::default()),
                emulation_args: Some(EmulationArgs {
                    id: 0,
                    target: 1,
                    firmware_path: "foo".into(),
                    trace_plugin_args: Some(TracePluginArgs::default()),
                    emu_run_limits: Some(EmuRunLimits::default()),
                    raw_loader_args: Some(RawLoaderArgs::default()),
                    ipc_port: 0,
                }),
                limits: Some(RawEventLimits::default()),
                symbol_options: Some(SymbolSearchOptions::default()),
                ws_program_id: saved_ws_program.id,
            };

            let msgs = ws_svc_cli::upsert_trace_app_session(&ws_node.url.clone(), vec![args])
                .await?
                .trace_app_session_args;
            assert_eq!(msgs.len(), 1);

            tonic::Request::new(InitializeTraceRequest {
                args: Some(msgs.first().unwrap().clone()),
            })
        };
        assert_eq!(1, count!(EmulationArgsEntity, &pg_node.cnx));
        assert_eq!(1, count!(RawEventLimitsEntity, &pg_node.cnx));
        assert_eq!(1, count!(TraceAppSessionArgsEntity, &pg_node.cnx));
        assert_eq!(0, count!(TraceSessionEntity, &pg_node.cnx));
        assert_eq!(2, count!(WorkspaceEntity, &pg_node.cnx));
        assert_eq!(1, count!(WsProgramEntity, &pg_node.cnx));
        assert!(typhunix_client_bin::list_programs(&ty_node.url, false)
            .await?
            .is_empty());

        // the test is setup

        // Re-write the request...
        let new_request = styx_trace_tools::svcutil::re_write_request(
            initialize_trace_request.get_ref(),
            &ws_node.url,
            &ty_node.url,
        )
        .await?;

        // check results...
        assert_eq!(
            new_request
                .args
                .clone()
                .unwrap()
                .emulation_args
                .unwrap()
                .target(),
            Target::Stm32f107
        );
        let ty_programs = typhunix_client_bin::list_programs(&ty_node.url, false).await?;
        assert_eq!(ty_programs.len(), 1);
        let new_fw = new_request
            .args
            .clone()
            .unwrap()
            .emulation_args
            .unwrap()
            .firmware_path;
        assert!(Path::new(&new_fw).exists());
        std::fs::remove_file(Path::new(&new_fw))?;
        assert!(!Path::new(&new_fw).exists());
        Ok(())
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    async fn test_workspace() -> TestResult {
        init_logging();
        let pg_node = PostgesNode::new(&format!("test-{}", Uuid::new_v4())).await?;
        let ws_node = WorkspaceSvcNode::new(&pg_node.network_name, &pg_node.url).await?;
        let test_workspace = Workspace {
            id: 0,
            name: "ws1".into(),
            ws_programs: vec![],
            created_timestamp: Some(std::time::SystemTime::now().into()),
        };
        // no workspaces
        assert_eq!(1, count!(WorkspaceEntity, &pg_node.cnx));
        assert!(
            ws_svc_cli::get_workspaces(None, &ws_node.url.clone())
                .await?
                .len()
                == 1
        );
        // insert a workspace
        let id = ws_svc_cli::upsert_workspace(&ws_node.url.clone(), &test_workspace).await?;
        assert_eq!(2, count!(WorkspaceEntity, &pg_node.cnx));
        assert_ne!(0, id.id);

        let fetched_workspace = {
            let workspaces = ws_svc_cli::get_workspaces(None, &ws_node.url.clone()).await?;
            assert_eq!(workspaces.len(), 2);
            let byname = workspaces
                .iter()
                .filter(|v| v.name == test_workspace.name)
                .cloned()
                .collect::<Vec<Workspace>>();
            assert_eq!(byname.len(), 1);
            byname.first().unwrap().clone()
        };

        // compare name and the create_timestamp (to microsecond res)
        assert_eq!(fetched_workspace.name, test_workspace.name);
        assert_eq!(
            UtcDateTime::from(test_workspace.created_timestamp.unwrap())
                .trunc()
                .into_inner(),
            UtcDateTime::from(fetched_workspace.created_timestamp.unwrap())
                .trunc()
                .into_inner()
        );

        // update a workspace
        let mut modified_workspace = fetched_workspace.clone();
        modified_workspace.name = "updated name".into();
        let new_id =
            ws_svc_cli::upsert_workspace(&ws_node.url.clone(), &modified_workspace).await?;
        // still only one row, IDs are the same
        assert_eq!(2, count!(WorkspaceEntity, &pg_node.cnx), "only one row");
        assert_eq!(id.id, new_id.id, "IDs are the same");
        let fetched_workspace = {
            let workspaces = ws_svc_cli::get_workspaces(None, &ws_node.url.clone()).await?;
            assert_eq!(workspaces.len(), 2);
            let byname = workspaces
                .iter()
                .filter(|v| v.name == modified_workspace.name)
                .cloned()
                .collect::<Vec<Workspace>>();
            assert_eq!(byname.len(), 1);
            byname.first().unwrap().clone()
        };
        assert_eq!(
            "updated name".to_string(),
            fetched_workspace.name,
            "name is updated"
        );

        // find by ID
        assert_eq!(
            ws_svc_cli::get_workspaces(None, &ws_node.url.clone())
                .await?
                .iter()
                .filter(|v| v.name == modified_workspace.name)
                .cloned()
                .collect::<Vec<Workspace>>(),
            ws_svc_cli::get_workspaces(Some(new_id), &ws_node.url.clone()).await?,
            "find by ID works ok"
        );
        Ok(())
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    async fn test_partial_ws_program() -> TestResult {
        init_logging();
        let pg_node = PostgesNode::new(&format!("test-{}", Uuid::new_v4())).await?;
        let ws_node = WorkspaceSvcNode::new(&pg_node.network_name, &pg_node.url).await?;
        // setup: insert a workspace
        let workspace_id = Some(
            ws_svc_cli::upsert_workspace(
                &ws_node.url.clone(),
                &Workspace {
                    id: 0,
                    name: "ws1".into(),
                    ws_programs: vec![],
                    created_timestamp: Some(std::time::SystemTime::now().into()),
                },
            )
            .await?,
        );

        // setup: use this as test program, symbols, data_types
        let typhunix_connect_msg = {
            let test_data_path = {
                let rel_path = "extensions/typhunix/rust/testdata/connect_message.json";
                let mut from = styx_core::util::styx_root_pathbuf();
                from.push(rel_path);
                from.as_path().to_str().unwrap().to_string()
            };
            connect_msg_from_file(test_data_path).await?
        };
        // setup: create and save a WsProgram
        let input_ws_program = {
            let bin_pgm_siz = 1024;

            let msg = typhunix_connect_msg.clone();
            WsProgram {
                id: 0,
                name: "my-ws-program2".into(),
                file: Some(FileRef {
                    path: "somefile.bin".into(),
                    size: bin_pgm_siz,
                }),
                data: vec![0; 1024],
                emulation_args: None,
                limits: None,
                symbol_options: None,

                config: Some(Config {
                    arch_iden: Some(ArchIdentity {
                        id: 0,
                        name: "Arm".into(),
                    }),
                    variant_iden: Some(VariantIdentity {
                        id: 0,
                        name: "Variant".into(),
                    }),
                    endian_iden: Some(EndianIdentity {
                        id: 0,
                        name: "LE".into(),
                    }),
                    loader_iden: Some(LoaderIdentity::default()),
                    backend_iden: Some(BackendIdentity::default()),
                }),
                sym_program: msg.program,
                data_types: msg.data_types,
                symbols: msg.symbols,
                workspace_id,
            }
        };

        assert_eq!(0, count!(WsProgramEntity, &pg_node.cnx));

        let response =
            ws_svc_cli::upsert_ws_program(&ws_node.url.clone(), &input_ws_program).await?;
        assert!(response.ws_program_id.is_some());
        let id = response.ws_program_id.unwrap().id;
        assert!(id > 0);

        // Get the full program
        let rr =
            ws_svc_cli::get_ws_programs(&ws_node.url.clone(), input_ws_program.id, true).await?;
        assert!(rr.len() == 1);
        let ws_program = rr.first().unwrap().clone();
        assert_eq!(ws_program.data.len(), 1024);
        let (f1, s1, d1, f2, s2, d2) = {
            let (m1, m2) = { (typhunix_connect_msg.clone(), ws_program.clone()) };
            (
                m1.clone().program.unwrap().clone().functions,
                m1.clone().data_types,
                m1.clone().symbols,
                m2.clone().sym_program.unwrap().clone().functions,
                m2.clone().data_types,
                m2.clone().symbols,
            )
        };
        assert_eq!(f1, f2, "Function count matches");
        assert_eq!(s1, s2, "symbol count matches");
        assert_eq!(d1, d2, "datatype count matches");

        // partial program
        let rr =
            ws_svc_cli::get_ws_programs(&ws_node.url.clone(), input_ws_program.id, false).await?;
        assert!(rr.len() == 1);
        let ws_program = rr.first().unwrap().clone();
        // data is truncated
        assert_eq!(ws_program.data.len(), 0);

        let (f1, f2, s2, d2) = {
            let (m1, m2) = { (typhunix_connect_msg.clone(), ws_program.clone()) };
            (
                m1.clone().program.unwrap().clone().functions,
                m2.clone().sym_program.unwrap().clone().functions,
                m2.clone().data_types,
                m2.clone().symbols,
            )
        };
        // symbols, datatypes truncated
        assert_eq!(f1.len(), f2.len(), "Function count matches");
        assert!(s2.is_empty(), "symbols truncated");
        assert!(d2.is_empty(), "datatypes truncated");

        Ok(())
    }

    #[tokio::test]
    #[cfg_attr(miri, ignore)]
    #[cfg_attr(asan, ignore)]
    async fn test_trace_event_insert() -> Result<(), Box<dyn std::error::Error + 'static>> {
        init_logging();
        let pg_node = PostgesNode::new(&format!("test-{}", Uuid::new_v4())).await?;
        let event = MemReadEvent {
            event_num: 1,
            etype: TraceEventType::MEM_READ,
            size_bytes: 4,
            pc: 0x0000_DEAD,
            address: 0x0000_FACE,
            value: 0xA,
        };
        let am = TraceEventActiveModel::new(event.into());
        let amclone = am.clone();
        let res = am.insert(&pg_node.cnx).await;
        debug!(">>>>> RESULT: (insert result) {:?}", res);
        assert!(res.is_ok());
        let model = res.unwrap();
        debug!(">>>>> RESULT: model: {:?}", model);
        debug!(">>>>> RESULT:    am: {:?}", amclone);
        assert_eq!(model.id, amclone.id.unwrap());
        assert_eq!(model.event, amclone.event.unwrap());

        Ok(())
    }
}
