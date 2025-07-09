// SPDX-License-Identifier: BSD-2-Clause
//! typhunix grpc symbols server impl

use styx_emulator::grpc::{
    symbolic::{DataType, ProgramsWithSymbols},
    typhunix_interop::{
        json_util::dump_connect_message,
        symbolic::{Program, ProgramFilter, ProgramIdentifier, Symbol},
        symbolic_impl::clean,
        typhunix_server::Typhunix,
        Ack, ConnectMessage, PingRequest, PingResponse, ProgramRef, StopServerRequest,
        StopServerResponse, Validator,
    },
};
use styx_emulator::sync::Arc;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{debug, event, info, warn, Level};
use typhunix_config::AppConfig;
use typhunix_proto::symboldb::{MemoryStore, Subscriber, SymbolsDB, Wildcards};

#[derive(Default)]
pub struct TyphunixImpl {
    db: Arc<SymbolsDB>,
}
impl TyphunixImpl {
    pub async fn new(enable_wildcards: bool, cmsgs: &[ConnectMessage]) -> Self {
        debug!(
            "Construct TyphunixImpl: enable_wildcards: {}, cmsgs.len(): {}",
            enable_wildcards,
            cmsgs.len()
        );
        let item = TyphunixImpl {
            ..Default::default()
        };
        if enable_wildcards {
            item.enable_wildcards();
        }

        for fut in cmsgs.iter().map(|c| async {
            if item.db.save_message(c.to_owned()).await {
                info!("Imported {}", c.program.as_ref().unwrap());
            } else {
                warn!("Could not import {}", c.program.as_ref().unwrap());
            }
        }) {
            fut.await;
        }

        item
    }

    pub fn db(&self) -> Arc<SymbolsDB> {
        self.db.clone()
    }
}

#[tonic::async_trait]
impl Typhunix for TyphunixImpl {
    type GetSymbolsStream = ReceiverStream<Result<Symbol, Status>>;
    type GetDataTypesStream = ReceiverStream<Result<DataType, Status>>;
    type GetProgramsStream = ReceiverStream<Result<Program, Status>>;
    type GetProgramsWithSymbolsStream = ReceiverStream<Result<ProgramsWithSymbols, Status>>;
    type GetProgramsIdentifiersStream = ReceiverStream<Result<ProgramIdentifier, Status>>;

    async fn ping(&self, _: Request<PingRequest>) -> Result<Response<PingResponse>, Status> {
        Ok(Response::new(PingResponse::default()))
    }

    /// Register an open program/project.
    async fn register_new(
        &self,
        request: Request<ConnectMessage>,
    ) -> Result<Response<Ack>, Status> {
        let mut msg = request.into_inner();
        msg = clean(msg).await?;
        info!("==> [Program registered] {}", msg);
        let is_valid = self.db.save_message(msg.to_owned()).await;
        let p = format!(
            "{}/cm-{}-{}.json",
            AppConfig::config_dir(),
            msg.get_program_name(),
            msg.get_source_id()
        );
        let _ = dump_connect_message(p, &msg).await;
        Ok(Response::new(Ack {
            uuid: "todo-uuid".to_owned(),
            success: is_valid,
        }))
    }

    /// A program was opened
    async fn program_opened(&self, request: Request<Program>) -> Result<Response<Ack>, Status> {
        debug!("program_opened {}", request.get_ref());
        Ok(Response::new(Ack {
            uuid: "todo-uuid".to_owned(),
            success: true,
        }))
    }

    /// A program was closed
    async fn program_closed(&self, request: Request<Program>) -> Result<Response<Ack>, Status> {
        debug!("program_closed {}", request.get_ref());
        Ok(Response::new(Ack {
            uuid: "todo-uuid".to_owned(),
            success: true,
        }))
    }

    /// The source (ghidra) updated this symbol
    async fn symbol_update(&self, request: Request<Symbol>) -> Result<Response<Ack>, Status> {
        info!("==> [Symbol update] {}", request.get_ref());
        let rslt = self.db.symbol_change(request.get_ref().to_owned()).await;
        Ok(Response::new(Ack {
            uuid: "".to_owned(),
            success: rslt,
        }))
    }

    /// The source (ghidra) updated this DataType
    async fn data_type_update(&self, request: Request<DataType>) -> Result<Response<Ack>, Status> {
        info!("==> [DataType update] {}", request.get_ref());
        let rslt = self.db.data_type_change(request.get_ref().to_owned()).await;
        Ok(Response::new(Ack {
            uuid: "".to_owned(),
            success: rslt,
        }))
    }

    /// Get a stream of Symbol
    async fn get_symbols(
        &self,
        request: tonic::Request<Program>,
    ) -> Result<tonic::Response<Self::GetSymbolsStream>, tonic::Status> {
        let rq = request.get_ref();
        let (source_id, pname) = (rq.get_source_id(), rq.get_program_name());
        let msg = format!(
            "<<< get_symbols {}: {}, client_uuid: {}), updates_only: {}",
            source_id, pname, rq.client_uuid, rq.updates_only
        );
        match rq.is_valid() {
            true => event!(Level::DEBUG, "{}", msg),
            _ => event!(Level::WARN, "{}", msg),
        };

        let channel_max_buffered_msgs = 4; // todo: understand this better
        let (tx, rx) = mpsc::channel(channel_max_buffered_msgs);
        let syms = self.db.symbols(rq).await;
        tokio::spawn(async move {
            for s in syms {
                tx.send(Ok(s.clone())).await.unwrap();
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    /// Get a stream of DataType
    async fn get_data_types(
        &self,
        request: tonic::Request<Program>,
    ) -> Result<tonic::Response<Self::GetDataTypesStream>, tonic::Status> {
        let rq = request.get_ref();
        let (source_id, pname) = (rq.get_source_id(), rq.get_program_name());
        let msg = format!(
            "<<< get_data_types {}: {}, client_uuid: {}), updates_only: {}",
            source_id, pname, rq.client_uuid, rq.updates_only
        );
        match rq.is_valid() {
            true => event!(Level::DEBUG, "{}", msg),
            _ => event!(Level::WARN, "{}", msg),
        };
        let channel_max_buffered_msgs = 4; // todo: understand this better
        let (tx, rx) = mpsc::channel(channel_max_buffered_msgs);
        let dts = self.db.data_types(request.get_ref()).await;
        tokio::spawn(async move {
            for s in dts {
                tx.send(Ok(s.clone())).await.unwrap();
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    /// Graceully stop the server
    async fn stop_server(
        &self,
        request: Request<StopServerRequest>,
    ) -> Result<Response<StopServerResponse>, Status> {
        info!("stop_server from {:?}", request.remote_addr());
        let response = StopServerResponse {};
        Ok(Response::new(response))
    }

    /// Send a list of Programs that are open
    async fn get_programs(
        &self,
        request: Request<ProgramFilter>,
    ) -> Result<Response<Self::GetProgramsStream>, Status> {
        info!("<<< get_programs");
        let filter = request.get_ref().exact_pids.to_vec();
        let (tx, rx) = mpsc::channel(4);
        let programs = self.db.programs_matching(&filter).await;
        tokio::spawn(async move {
            for s in &programs[..] {
                tx.send(Ok(s.clone())).await.unwrap();
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    /// Retrieve a list of programs + symbols + data types
    async fn get_programs_with_symbols(
        &self,
        request: Request<ProgramFilter>,
    ) -> Result<Response<Self::GetProgramsWithSymbolsStream>, Status> {
        info!("<<< get_programs_with_symbols");
        let filter = request.get_ref().exact_pids.to_vec();
        let (tx, rx) = mpsc::channel(32);
        let db = self.db();
        tokio::spawn(async move {
            let programs = db.programs_matching(&filter).await;
            for program in &programs[..] {
                info!("Get symbols and datatypes for program: {program}");
                let symbols = db.symbols(program).await;
                let data_types = db.data_types(program).await;
                let pws = ProgramsWithSymbols {
                    program: Some(program.to_owned()),
                    symbols,
                    data_types,
                };
                tx.send(Ok(pws)).await.unwrap();
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    /// Send a list of Programs that are open
    async fn get_programs_identifiers(
        &self,
        _request: Request<ProgramFilter>,
    ) -> Result<Response<Self::GetProgramsIdentifiersStream>, Status> {
        info!("<<< get_programs_identifiers");
        let (tx, rx) = mpsc::channel(4);
        let pids = self.db.program_identifiers().await;
        tokio::spawn(async move {
            for s in &pids[..] {
                tx.send(Ok(s.clone())).await.unwrap();
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    /// Subscribe to changes
    async fn subscribe(
        &self,
        request: tonic::Request<Program>,
    ) -> Result<tonic::Response<Ack>, tonic::Status> {
        let (success, uuid) = self.db.subscribe(request.get_ref().to_owned());
        info!(
            "<<< subscribe to {} ==> {:?}",
            request.get_ref(),
            (uuid.to_string(), success)
        );
        Ok(Response::new(Ack { uuid, success }))
    }

    /// Unsubscribe to changes
    async fn un_subscribe(
        &self,
        request: tonic::Request<Program>,
    ) -> Result<tonic::Response<Ack>, tonic::Status> {
        let (success, uuid) = self.db.un_subscribe(request.get_ref().to_owned());

        info!(
            "<<< un-subscribe from {} ==> {:?}",
            request.get_ref(),
            (uuid.to_string(), success)
        );
        Ok(Response::new(Ack { uuid, success }))
    }
}

impl Wildcards for TyphunixImpl {
    fn enable_wildcards(&self) {
        self.db.enable_wildcards();
    }
    fn get_wildcard(&self) -> String {
        self.db.get_wildcard()
    }
    fn is_wildcard_enabled(&self) -> bool {
        self.db.is_wildcard_enabled()
    }
}
