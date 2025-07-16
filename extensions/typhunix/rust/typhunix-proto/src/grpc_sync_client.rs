// SPDX-License-Identifier: BSD-2-Clause
#![allow(clippy::result_large_err)]
use crate::grpc_async_client::{get_data_types, get_programs, get_symbols, GrpcStatus};
use styx_emulator::grpc::typhunix_interop::{
    symbolic::{DataType, Program, ProgramFilter, Symbol},
    typhunix_client::TyphunixClient,
};
use tokio::runtime::{Builder, Runtime};
use tonic::transport::Channel;
use tonic::IntoRequest;

type StdError = Box<dyn std::error::Error + Send + Sync + 'static>;
type Result<T, E = StdError> = ::std::result::Result<T, E>;

// The order of the fields in this struct is important. They must be ordered
// such that when `BlockingClient` is dropped the client is dropped
// before the runtime. Not doing this will result in a deadlock when dropped.
// Rust drops struct fields in declaration order. (ref tonic examples)
pub struct BlockingClient {
    pub client: TyphunixClient<Channel>,
    pub rt: Runtime,
}

impl BlockingClient {
    pub fn connect<D>(dst: D) -> Result<Self, tonic::transport::Error>
    where
        D: TryInto<tonic::transport::Endpoint>,
        D::Error: Into<StdError>,
    {
        let rt = Builder::new_multi_thread().enable_all().build().unwrap();
        let client = rt.block_on(TyphunixClient::connect(dst))?;

        Ok(Self { client, rt })
    }

    pub fn get_programs(
        &mut self,
        _request: impl IntoRequest<ProgramFilter>,
    ) -> Result<Vec<Program>, GrpcStatus> {
        Ok(self
            .rt
            .block_on(get_programs(&mut self.client, ProgramFilter::default()))
            .unwrap())
    }

    pub fn get_symbols(&mut self, program: Program) -> Result<Vec<Symbol>, GrpcStatus> {
        self.rt.block_on(get_symbols(&mut self.client, program))
    }

    pub fn get_data_types(&mut self, program: Program) -> Result<Vec<DataType>, GrpcStatus> {
        self.rt.block_on(get_data_types(&mut self.client, program))
    }
}
